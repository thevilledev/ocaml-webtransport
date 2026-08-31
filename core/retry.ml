(* Stateless Retry support shared by the drivers (RFC 9000 s.8.1.2,
   RFC 9001 s.5.8), backend-independent: address-validation tokens sealed
   with a per-listener AEAD key, and the Retry packet itself.

   Token layout (before sealing): u8 odcid length ^ odcid ^ u8 ip length ^
   ip ^ u16 port ^ i64 expiry (unix ns). Sealed with AES-128-GCM under a
   random per-listener key, a random 12-byte nonce prepended. Tokens bind
   the client address and expire, so a replayed or forwarded token fails
   validation and the handshake falls back to a fresh Retry. *)

type state = { key : Mirage_crypto.AES.GCM.key }

let create () =
  { key = Mirage_crypto.AES.GCM.of_secret (Mirage_crypto_rng.generate 16) }

let lifetime_ns = 30_000_000_000L
let aad = "ocaml-webtransport retry token"

let mint state ~odcid ~peer:(ip, port) ~now =
  let b = Buffer.create 64 in
  Buffer.add_uint8 b (String.length odcid);
  Buffer.add_string b odcid;
  Buffer.add_uint8 b (String.length ip);
  Buffer.add_string b ip;
  Buffer.add_uint16_be b port;
  Buffer.add_int64_be b (Int64.add now lifetime_ns);
  let nonce = Mirage_crypto_rng.generate 12 in
  nonce
  ^ Mirage_crypto.AES.GCM.authenticate_encrypt ~key:state.key ~nonce ~adata:aad
      (Buffer.contents b)

(* [Some odcid] when the token is authentic, unexpired and bound to
   [peer]. *)
let validate state ~token ~peer:(ip, port) ~now =
  if String.length token < 12 + 16 then None
  else begin
    let nonce = String.sub token 0 12 in
    let sealed = String.sub token 12 (String.length token - 12) in
    match
      Mirage_crypto.AES.GCM.authenticate_decrypt ~key:state.key ~nonce
        ~adata:aad sealed
    with
    | None -> None
    | Some plain -> (
        let r = ref 0 in
        let u8 () =
          let v = Char.code plain.[!r] in
          incr r;
          v
        in
        let bytes n =
          let s = String.sub plain !r n in
          r := !r + n;
          s
        in
        try
          let odl = u8 () in
          let odcid = bytes odl in
          let ipl = u8 () in
          let tip = bytes ipl in
          let phi = u8 () in
          let plo = u8 () in
          let tport = (phi lsl 8) lor plo in
          let expiry = bytes 8 in
          let exp =
            String.fold_left
              (fun a c ->
                Int64.logor (Int64.shift_left a 8) (Int64.of_int (Char.code c)))
              0L expiry
          in
          if String.equal tip ip && tport = port && Int64.compare now exp < 0
          then Some odcid
          else None
        with Invalid_argument _ -> None)
  end

(* ---- the Retry packet (RFC 9001 s.5.8 integrity tag) ---- *)

let retry_key =
  "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"

let retry_nonce = "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"

let integrity_tag ~odcid ~pseudo =
  let ad =
    let b = Buffer.create (1 + String.length odcid + String.length pseudo) in
    Buffer.add_uint8 b (String.length odcid);
    Buffer.add_string b odcid;
    Buffer.add_string b pseudo;
    Buffer.contents b
  in
  Mirage_crypto.AES.GCM.authenticate_encrypt
    ~key:(Mirage_crypto.AES.GCM.of_secret retry_key)
    ~nonce:retry_nonce ~adata:ad ""

(* Writes a v1 Retry into [buf]: dcid = the client's SCID, scid = the CID
   the client must target next, plus [token] and the integrity tag over
   the ODCID-prefixed pseudo packet. Returns bytes written. *)
let write ~client_scid ~new_scid ~odcid ~token buf =
  let b = Buffer.create 128 in
  Buffer.add_uint8 b 0xf0;
  Buffer.add_uint8 b 0x00;
  Buffer.add_uint8 b 0x00;
  Buffer.add_uint8 b 0x00;
  Buffer.add_uint8 b 0x01;
  Buffer.add_uint8 b (String.length client_scid);
  Buffer.add_string b client_scid;
  Buffer.add_uint8 b (String.length new_scid);
  Buffer.add_string b new_scid;
  Buffer.add_string b token;
  let pseudo = Buffer.contents b in
  let tag = integrity_tag ~odcid ~pseudo in
  let total = String.length pseudo + String.length tag in
  if Bigstringaf.length buf < total then Error "retry: buffer too small"
  else begin
    Bigstringaf.blit_from_string pseudo ~src_off:0 buf ~dst_off:0
      ~len:(String.length pseudo);
    Bigstringaf.blit_from_string tag ~src_off:0 buf
      ~dst_off:(String.length pseudo) ~len:(String.length tag);
    Ok total
  end
