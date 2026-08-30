(* TLS 1.3 handshake message and extension codec (RFC 8446 s.4), string
   based — the control plane is small. Parsers are total and
   GREASE-tolerant: unknown ids ride through as raw (id, payload) pairs. *)

(* handshake message types *)
let ht_client_hello = 1
let ht_server_hello = 2
let ht_new_session_ticket = 4
let ht_encrypted_extensions = 8
let ht_certificate = 11
let ht_certificate_request = 13
let ht_certificate_verify = 15
let ht_finished = 20
let ht_key_update = 24

(* extension ids *)
let ext_server_name = 0
let ext_supported_groups = 10
let ext_signature_algorithms = 13
let ext_alpn = 16
let ext_supported_versions = 43
let ext_cookie = 44
let ext_key_share = 51
let ext_quic_transport_parameters = 0x39

(* named groups *)
let group_x25519 = 0x001d
let group_secp256r1 = 0x0017

let hrr_random =
  "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

(* ---- string cursor ---- *)

type r = { s : string; mutable pos : int; limit : int }

let reader ?(off = 0) ?len s =
  let len = match len with Some l -> l | None -> String.length s - off in
  { s; pos = off; limit = off + len }

let remaining r = r.limit - r.pos

let u8 r =
  if remaining r < 1 then None
  else begin
    let v = Char.code r.s.[r.pos] in
    r.pos <- r.pos + 1;
    Some v
  end

let u16 r =
  if remaining r < 2 then None
  else begin
    let v = (Char.code r.s.[r.pos] lsl 8) lor Char.code r.s.[r.pos + 1] in
    r.pos <- r.pos + 2;
    Some v
  end

let u24 r =
  if remaining r < 3 then None
  else begin
    let v =
      (Char.code r.s.[r.pos] lsl 16)
      lor (Char.code r.s.[r.pos + 1] lsl 8)
      lor Char.code r.s.[r.pos + 2]
    in
    r.pos <- r.pos + 3;
    Some v
  end

let take r n =
  if n < 0 || remaining r < n then None
  else begin
    let v = String.sub r.s r.pos n in
    r.pos <- r.pos + n;
    Some v
  end

let vec8 r = match u8 r with Some n -> take r n | None -> None
let vec16 r = match u16 r with Some n -> take r n | None -> None
let vec24 r = match u24 r with Some n -> take r n | None -> None

let ( let* ) o f = match o with Some v -> f v | None -> Error "tls: underflow"

(* ---- builders ---- *)

let add_u8 = Buffer.add_uint8
let add_u16 = Buffer.add_uint16_be

let add_u24 b v =
  Buffer.add_uint8 b ((v lsr 16) land 0xff);
  Buffer.add_uint8 b ((v lsr 8) land 0xff);
  Buffer.add_uint8 b (v land 0xff)

let add_vec8 b s =
  add_u8 b (String.length s);
  Buffer.add_string b s

let add_vec16 b s =
  add_u16 b (String.length s);
  Buffer.add_string b s

let add_vec24 b s =
  add_u24 b (String.length s);
  Buffer.add_string b s

let message ~typ body =
  let b = Buffer.create (4 + String.length body) in
  add_u8 b typ;
  add_u24 b (String.length body);
  Buffer.add_string b body;
  Buffer.contents b

let extension ~id payload =
  let b = Buffer.create (4 + String.length payload) in
  add_u16 b id;
  add_vec16 b payload;
  Buffer.contents b

let extensions_block exts = String.concat "" exts

(* extension payload builders *)

let server_name_ext host =
  let b = Buffer.create (5 + String.length host) in
  let entry = Buffer.create (3 + String.length host) in
  add_u8 entry 0 (* host_name *);
  add_vec16 entry host;
  add_vec16 b (Buffer.contents entry);
  extension ~id:ext_server_name (Buffer.contents b)

let u16_list_ext ~id values =
  let inner = Buffer.create (2 * List.length values) in
  List.iter (add_u16 inner) values;
  let b = Buffer.create 16 in
  add_vec16 b (Buffer.contents inner);
  extension ~id (Buffer.contents b)

let supported_groups_ext groups = u16_list_ext ~id:ext_supported_groups groups

let signature_algorithms_ext algs =
  u16_list_ext ~id:ext_signature_algorithms algs

let alpn_ext protos =
  let inner = Buffer.create 32 in
  List.iter (add_vec8 inner) protos;
  let b = Buffer.create 32 in
  add_vec16 b (Buffer.contents inner);
  extension ~id:ext_alpn (Buffer.contents b)

let supported_versions_client_ext () =
  let b = Buffer.create 3 in
  add_u8 b 2;
  add_u16 b 0x0304;
  extension ~id:ext_supported_versions (Buffer.contents b)

let supported_versions_server_ext () =
  let b = Buffer.create 2 in
  add_u16 b 0x0304;
  extension ~id:ext_supported_versions (Buffer.contents b)

let key_share_entry ~group ~key =
  let b = Buffer.create (4 + String.length key) in
  add_u16 b group;
  add_vec16 b key;
  Buffer.contents b

let key_share_client_ext entries =
  let inner = String.concat "" entries in
  let b = Buffer.create (2 + String.length inner) in
  add_vec16 b inner;
  extension ~id:ext_key_share (Buffer.contents b)

let key_share_server_ext ~group ~key =
  extension ~id:ext_key_share (key_share_entry ~group ~key)

let quic_transport_parameters_ext tp =
  extension ~id:ext_quic_transport_parameters tp

let cookie_ext cookie =
  let b = Buffer.create (2 + String.length cookie) in
  add_vec16 b cookie;
  extension ~id:ext_cookie (Buffer.contents b)

(* ---- extension parsing ---- *)

let parse_extension_list s =
  let r = reader s in
  let rec go acc =
    if remaining r = 0 then Ok (List.rev acc)
    else
      let* id = u16 r in
      let* payload = vec16 r in
      go ((id, payload) :: acc)
  in
  go []

let find_ext exts id = List.assoc_opt id exts

let parse_u16_list_vec16 s =
  let r = reader s in
  let* inner = vec16 r in
  if remaining r <> 0 then Error "tls: trailing bytes"
  else begin
    let ir = reader inner in
    let rec go acc =
      if remaining ir = 0 then Ok (List.rev acc)
      else match u16 ir with Some v -> go (v :: acc) | None -> Error "tls: u16 list"
    in
    go []
  end

let parse_alpn_payload s =
  let r = reader s in
  let* inner = vec16 r in
  let ir = reader inner in
  let rec go acc =
    if remaining ir = 0 then Ok (List.rev acc)
    else match vec8 ir with Some p -> go (p :: acc) | None -> Error "tls: alpn"
  in
  go []

let parse_key_share_entries s =
  let r = reader s in
  let* inner = vec16 r in
  let ir = reader inner in
  let rec go acc =
    if remaining ir = 0 then Ok (List.rev acc)
    else
      let* group = u16 ir in
      let* key = vec16 ir in
      go ((group, key) :: acc)
  in
  go []

let parse_key_share_server s =
  let r = reader s in
  let* group = u16 r in
  (* HRR carries only the selected group *)
  if remaining r = 0 then Ok (group, None)
  else
    let* key = vec16 r in
    if remaining r <> 0 then Error "tls: key_share trailing"
    else Ok (group, Some key)

let parse_supported_versions_client s =
  let r = reader s in
  let* inner = vec8 r in
  let ir = reader inner in
  let rec go acc =
    if remaining ir = 0 then Ok (List.rev acc)
    else match u16 ir with Some v -> go (v :: acc) | None -> Error "tls: versions"
  in
  go []

let parse_supported_versions_server s =
  if String.length s <> 2 then Error "tls: server versions"
  else Ok ((Char.code s.[0] lsl 8) lor Char.code s.[1])

let parse_cookie s =
  let r = reader s in
  let* c = vec16 r in
  if remaining r <> 0 then Error "tls: cookie trailing" else Ok c

(* ---- ClientHello / ServerHello ---- *)

type client_hello = {
  ch_random : string;
  ch_session_id : string;
  ch_cipher_suites : int list;
  ch_extensions : (int * string) list;
}

type server_hello = {
  sh_random : string;
  sh_session_id : string;
  sh_cipher_suite : int;
  sh_extensions : (int * string) list;
}

let build_client_hello ~random ~session_id ~cipher_suites ~extensions =
  let b = Buffer.create 512 in
  add_u16 b 0x0303;
  Buffer.add_string b random;
  add_vec8 b session_id;
  let suites = Buffer.create 8 in
  List.iter (add_u16 suites) cipher_suites;
  add_vec16 b (Buffer.contents suites);
  add_vec8 b "\x00" (* null compression only *);
  add_vec16 b (extensions_block extensions);
  message ~typ:ht_client_hello (Buffer.contents b)

let build_server_hello ~random ~session_id ~cipher_suite ~extensions =
  let b = Buffer.create 256 in
  add_u16 b 0x0303;
  Buffer.add_string b random;
  add_vec8 b session_id;
  add_u16 b cipher_suite;
  add_u8 b 0 (* null compression *);
  add_vec16 b (extensions_block extensions);
  message ~typ:ht_server_hello (Buffer.contents b)

let parse_client_hello body =
  let r = reader body in
  let* _legacy_version = u16 r in
  let* ch_random = take r 32 in
  let* ch_session_id = vec8 r in
  let* suites_raw = vec16 r in
  let* compressions = vec8 r in
  if not (String.contains compressions '\x00') then
    Error "tls: null compression missing"
  else
    let* exts_raw = vec16 r in
    if remaining r <> 0 then Error "tls: CH trailing bytes"
    else
      let sr = reader suites_raw in
      let rec suites acc =
        if remaining sr = 0 then Ok (List.rev acc)
        else match u16 sr with Some v -> suites (v :: acc) | None -> Error "tls: suites"
      in
      match suites [] with
      | Error e -> Error e
      | Ok ch_cipher_suites -> (
          match parse_extension_list exts_raw with
          | Error e -> Error e
          | Ok ch_extensions ->
              Ok { ch_random; ch_session_id; ch_cipher_suites; ch_extensions })

let parse_server_hello body =
  let r = reader body in
  let* _legacy_version = u16 r in
  let* sh_random = take r 32 in
  let* sh_session_id = vec8 r in
  let* sh_cipher_suite = u16 r in
  let* _compression = u8 r in
  let* exts_raw = vec16 r in
  if remaining r <> 0 then Error "tls: SH trailing bytes"
  else
    match parse_extension_list exts_raw with
    | Error e -> Error e
    | Ok sh_extensions ->
        Ok { sh_random; sh_session_id; sh_cipher_suite; sh_extensions }

(* ---- EncryptedExtensions / Certificate / CertificateVerify ---- *)

let build_encrypted_extensions extensions =
  let b = Buffer.create 128 in
  add_vec16 b (extensions_block extensions);
  message ~typ:ht_encrypted_extensions (Buffer.contents b)

let parse_encrypted_extensions body =
  let r = reader body in
  let* exts_raw = vec16 r in
  if remaining r <> 0 then Error "tls: EE trailing bytes"
  else parse_extension_list exts_raw

let build_certificate ~context ~ders =
  let b = Buffer.create 2048 in
  add_vec8 b context;
  let list_b = Buffer.create 2048 in
  List.iter
    (fun der ->
      add_vec24 list_b der;
      add_u16 list_b 0 (* no per-cert extensions *))
    ders;
  add_vec24 b (Buffer.contents list_b);
  message ~typ:ht_certificate (Buffer.contents b)

let parse_certificate body =
  let r = reader body in
  let* context = vec8 r in
  let* list_raw = vec24 r in
  if remaining r <> 0 then Error "tls: cert trailing bytes"
  else begin
    let lr = reader list_raw in
    let rec go acc =
      if remaining lr = 0 then Ok (context, List.rev acc)
      else
        let* der = vec24 lr in
        let* _exts = vec16 lr in
        go (der :: acc)
    in
    go []
  end

let build_certificate_verify ~scheme ~signature =
  let b = Buffer.create (4 + String.length signature) in
  add_u16 b scheme;
  add_vec16 b signature;
  message ~typ:ht_certificate_verify (Buffer.contents b)

let parse_certificate_verify body =
  let r = reader body in
  let* scheme = u16 r in
  let* signature = vec16 r in
  if remaining r <> 0 then Error "tls: CV trailing bytes"
  else Ok (scheme, signature)

let build_finished verify_data = message ~typ:ht_finished verify_data

let parse_certificate_request body =
  let r = reader body in
  let* context = vec8 r in
  let* _exts = vec16 r in
  if remaining r <> 0 then Error "tls: CR trailing bytes" else Ok context

(* ---- incremental message splitting ---- *)

(* Peels complete [type u8 ^ length u24 ^ body] messages off the front of
   [buf]; returns the consumed prefix as (typ, body, raw) triples. *)
let split_messages buf =
  let s = Buffer.contents buf in
  let len = String.length s in
  let rec go acc pos =
    if len - pos < 4 then (List.rev acc, pos)
    else
      let typ = Char.code s.[pos] in
      let mlen =
        (Char.code s.[pos + 1] lsl 16)
        lor (Char.code s.[pos + 2] lsl 8)
        lor Char.code s.[pos + 3]
      in
      if len - pos - 4 < mlen then (List.rev acc, pos)
      else
        let body = String.sub s (pos + 4) mlen in
        let raw = String.sub s pos (4 + mlen) in
        go ((typ, body, raw) :: acc) (pos + 4 + mlen)
  in
  let msgs, consumed = go [] 0 in
  if consumed > 0 then begin
    let rest = String.sub s consumed (len - consumed) in
    Buffer.clear buf;
    Buffer.add_string buf rest
  end;
  msgs
