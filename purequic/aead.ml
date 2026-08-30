(* Packet payload protection (RFC 9001 section 5.3) and the Retry integrity
   tag (section 5.8). Nonce construction and Retry constants follow
   ocaml-quic's lib/crypto.ml (BSD-3-Clause, see THIRD_PARTY.md). *)

type cipher =
  | Aes_gcm of Mirage_crypto.AES.GCM.key
  | Chacha of Mirage_crypto.Chacha20.key

(* One direction's install: AEAD cipher + iv + header protection + the
   traffic secret it came from (kept for key update). *)
type keys = {
  suite : Qsuite.t;
  cipher : cipher;
  iv : string;
  hp : Hp.key;
  secret : string;
}

let of_material ~suite ~secret (m : Qkdf.material) =
  let cipher =
    match (suite : Qsuite.t) with
    | Aes128_gcm_sha256 | Aes256_gcm_sha384 ->
        Aes_gcm (Mirage_crypto.AES.GCM.of_secret m.key)
    | Chacha20_poly1305_sha256 -> Chacha (Mirage_crypto.Chacha20.of_secret m.key)
  in
  { suite; cipher; iv = m.iv; hp = Hp.key ~suite ~hp_key:m.hp; secret }

let of_secret ~suite secret =
  of_material ~suite ~secret (Qkdf.material ~suite ~secret)

let initial_keys ~dcid ~role =
  let client = Qkdf.initial_client_secret ~dcid
  and server = Qkdf.initial_server_secret ~dcid in
  let tx_secret, rx_secret =
    match role with
    | `Client -> (client, server)
    | `Server -> (server, client)
  in
  ( of_secret ~suite:Qsuite.Aes128_gcm_sha256 tx_secret,
    of_secret ~suite:Qsuite.Aes128_gcm_sha256 rx_secret )

(* nonce = iv XOR packet number (left-padded, big endian) *)
let nonce t pn =
  let iv_len = String.length t.iv in
  let b = Bytes.of_string t.iv in
  for i = 0 to 7 do
    let byte = Int64.to_int (Int64.shift_right_logical pn (8 * (7 - i))) land 0xff in
    let pos = iv_len - 8 + i in
    Bytes.set b pos (Char.chr (Char.code (Bytes.get b pos) lxor byte))
  done;
  Bytes.unsafe_to_string b

(* Seal [plaintext]; result is ciphertext with the 16-byte tag appended. *)
let seal t ~pn ~ad plaintext =
  let nonce = nonce t pn in
  match t.cipher with
  | Aes_gcm key ->
      Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce ~adata:ad
        plaintext
  | Chacha key ->
      Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ~adata:ad
        plaintext

let open_ t ~pn ~ad ciphertext =
  let nonce = nonce t pn in
  match t.cipher with
  | Aes_gcm key ->
      Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce ~adata:ad
        ciphertext
  | Chacha key ->
      Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce ~adata:ad
        ciphertext

(* Key update (RFC 9001 section 6): same suite and header protection key;
   only key and iv rotate with the "quic ku" secret chain. *)
let next_generation t =
  let secret = Qkdf.next_secret ~suite:t.suite ~secret:t.secret in
  let m = Qkdf.material ~suite:t.suite ~secret in
  let cipher =
    match t.cipher with
    | Aes_gcm _ -> Aes_gcm (Mirage_crypto.AES.GCM.of_secret m.key)
    | Chacha _ -> Chacha (Mirage_crypto.Chacha20.of_secret m.key)
  in
  { t with cipher; iv = m.iv; secret }

(* ---- Retry integrity (RFC 9001 section 5.8) ---- *)

let retry_key =
  "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"

let retry_nonce = "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"

(* AAD = u8 odcid length ^ odcid ^ retry packet without its final 16 bytes;
   the tag is the AEAD output over the empty plaintext. *)
let retry_tag ~odcid ~pseudo =
  let ad =
    let b = Buffer.create (1 + String.length odcid + String.length pseudo) in
    Buffer.add_uint8 b (String.length odcid);
    Buffer.add_string b odcid;
    Buffer.add_string b pseudo;
    Buffer.contents b
  in
  let key = Mirage_crypto.AES.GCM.of_secret retry_key in
  Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce:retry_nonce ~adata:ad
    ""
