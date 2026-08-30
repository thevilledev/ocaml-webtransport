(* The TLS 1.3 key schedule (RFC 8446 s.7.1) and running transcript.
   Verified against the RFC 8448 "Simple 1-RTT" trace. *)

let hash_len (h : Digestif.hash') =
  match h with
  | `SHA256 -> 32
  | `SHA384 -> 48
  | _ -> invalid_arg "Schedule.hash_len: unsupported hash"

let digest (h : Digestif.hash') data =
  match h with
  | `SHA256 -> Digestif.SHA256.(to_raw_string (digest_string data))
  | `SHA384 -> Digestif.SHA384.(to_raw_string (digest_string data))
  | _ -> invalid_arg "Schedule.digest: unsupported hash"

let hmac (h : Digestif.hash') ~key data =
  match h with
  | `SHA256 -> Digestif.SHA256.(to_raw_string (hmac_string ~key data))
  | `SHA384 -> Digestif.SHA384.(to_raw_string (hmac_string ~key data))
  | _ -> invalid_arg "Schedule.hmac: unsupported hash"

let hkdf_label ~label ~context length =
  let full = "tls13 " ^ label in
  let b = Buffer.create (4 + String.length full + String.length context) in
  Buffer.add_uint16_be b length;
  Buffer.add_uint8 b (String.length full);
  Buffer.add_string b full;
  Buffer.add_uint8 b (String.length context);
  Buffer.add_string b context;
  Buffer.contents b

let expand_label ~hash ~secret ~label ~context length =
  Hkdf.expand ~hash ~prk:secret ~info:(hkdf_label ~label ~context length)
    length

let derive_secret ~hash ~secret ~label ~transcript_hash =
  expand_label ~hash ~secret ~label ~context:transcript_hash (hash_len hash)

(* ---- transcript ---- *)

module Transcript = struct
  type ctx = C256 of Digestif.SHA256.ctx | C384 of Digestif.SHA384.ctx

  type t = { buffered : Buffer.t; mutable ctx : ctx option }

  let create () = { buffered = Buffer.create 512; ctx = None }

  let feed t msg =
    match t.ctx with
    | None -> Buffer.add_string t.buffered msg
    | Some (C256 c) -> t.ctx <- Some (C256 (Digestif.SHA256.feed_string c msg))
    | Some (C384 c) -> t.ctx <- Some (C384 (Digestif.SHA384.feed_string c msg))

  (* Called once the cipher suite (hence hash) is known; folds in whatever
     was buffered before that point. *)
  let set_hash t (h : Digestif.hash') =
    assert (t.ctx = None);
    let buffered = Buffer.contents t.buffered
    and () = Buffer.clear t.buffered in
    (match h with
    | `SHA256 ->
        t.ctx <- Some (C256 (Digestif.SHA256.feed_string Digestif.SHA256.empty buffered))
    | `SHA384 ->
        t.ctx <- Some (C384 (Digestif.SHA384.feed_string Digestif.SHA384.empty buffered))
    | _ -> invalid_arg "Transcript.set_hash");
    ()

  let hash t =
    match t.ctx with
    | Some (C256 c) -> Digestif.SHA256.(to_raw_string (get c))
    | Some (C384 c) -> Digestif.SHA384.(to_raw_string (get c))
    | None -> invalid_arg "Transcript.hash: hash not selected yet"

  (* HelloRetryRequest transcript substitution (RFC 8446 s.4.4.1): the
     first ClientHello is replaced by message_hash(CH1). Only legal before
     any post-CH1 message was fed with a live ctx. *)
  let substitute_message_hash t (h : Digestif.hash') =
    assert (t.ctx = None);
    let ch1 = Buffer.contents t.buffered in
    Buffer.clear t.buffered;
    let synthetic =
      let d = digest h ch1 in
      let b = Buffer.create (4 + String.length d) in
      Buffer.add_uint8 b 254;
      Buffer.add_uint8 b 0;
      Buffer.add_uint8 b 0;
      Buffer.add_uint8 b (String.length d);
      Buffer.add_string b d;
      Buffer.contents b
    in
    Buffer.add_string t.buffered synthetic
end

(* ---- secret chain ---- *)

let zeros h = String.make (hash_len h) '\x00'

let early_secret ~hash = Hkdf.extract ~hash ~salt:(zeros hash) (zeros hash)

let handshake_secret ~hash ~early ~ecdh_shared =
  let derived =
    derive_secret ~hash ~secret:early ~label:"derived"
      ~transcript_hash:(digest hash "")
  in
  Hkdf.extract ~hash ~salt:derived ecdh_shared

let master_secret ~hash ~handshake =
  let derived =
    derive_secret ~hash ~secret:handshake ~label:"derived"
      ~transcript_hash:(digest hash "")
  in
  Hkdf.extract ~hash ~salt:derived (zeros hash)

let client_hs_traffic ~hash ~handshake ~transcript_hash =
  derive_secret ~hash ~secret:handshake ~label:"c hs traffic" ~transcript_hash

let server_hs_traffic ~hash ~handshake ~transcript_hash =
  derive_secret ~hash ~secret:handshake ~label:"s hs traffic" ~transcript_hash

let client_app_traffic ~hash ~master ~transcript_hash =
  derive_secret ~hash ~secret:master ~label:"c ap traffic" ~transcript_hash

let server_app_traffic ~hash ~master ~transcript_hash =
  derive_secret ~hash ~secret:master ~label:"s ap traffic" ~transcript_hash

let finished_verify ~hash ~traffic_secret ~transcript_hash =
  let finished_key =
    expand_label ~hash ~secret:traffic_secret ~label:"finished" ~context:""
      (hash_len hash)
  in
  hmac hash ~key:finished_key transcript_hash
