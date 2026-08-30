(* TLS 1.3 cipher suites, as the handshake sees them: the negotiation
   token and the hash it binds. Packet protection lives in the QUIC layer
   (Qsuite/Aead); this module never encrypts. *)

type t = Aes128_gcm_sha256 | Aes256_gcm_sha384 | Chacha20_poly1305_sha256

let to_id = function
  | Aes128_gcm_sha256 -> 0x1301
  | Aes256_gcm_sha384 -> 0x1302
  | Chacha20_poly1305_sha256 -> 0x1303

let of_id = function
  | 0x1301 -> Some Aes128_gcm_sha256
  | 0x1302 -> Some Aes256_gcm_sha384
  | 0x1303 -> Some Chacha20_poly1305_sha256
  | _ -> None

let hash : t -> Digestif.hash' = function
  | Aes128_gcm_sha256 | Chacha20_poly1305_sha256 -> `SHA256
  | Aes256_gcm_sha384 -> `SHA384

let hash_len = function
  | Aes128_gcm_sha256 | Chacha20_poly1305_sha256 -> 32
  | Aes256_gcm_sha384 -> 48

(* our preference order *)
let all = [ Aes128_gcm_sha256; Chacha20_poly1305_sha256; Aes256_gcm_sha384 ]
