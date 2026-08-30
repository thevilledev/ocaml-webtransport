(* The three QUIC v1 AEAD suites (RFC 9001 section 5). *)

type t = Aes128_gcm_sha256 | Aes256_gcm_sha384 | Chacha20_poly1305_sha256

let hash : t -> Digestif.hash' = function
  | Aes128_gcm_sha256 | Chacha20_poly1305_sha256 -> `SHA256
  | Aes256_gcm_sha384 -> `SHA384

let hash_len = function
  | Aes128_gcm_sha256 | Chacha20_poly1305_sha256 -> 32
  | Aes256_gcm_sha384 -> 48

let key_len = function
  | Aes128_gcm_sha256 -> 16
  | Aes256_gcm_sha384 | Chacha20_poly1305_sha256 -> 32

let iv_len (_ : t) = 12
let tag_len (_ : t) = 16
let hp_key_len = key_len
let sample_len (_ : t) = 16

(* TLS 1.3 cipher suite code points, for the TLS layer's negotiation. *)
let to_tls_id = function
  | Aes128_gcm_sha256 -> 0x1301
  | Aes256_gcm_sha384 -> 0x1302
  | Chacha20_poly1305_sha256 -> 0x1303

let of_tls_id = function
  | 0x1301 -> Some Aes128_gcm_sha256
  | 0x1302 -> Some Aes256_gcm_sha384
  | 0x1303 -> Some Chacha20_poly1305_sha256
  | _ -> None

let pp = function
  | Aes128_gcm_sha256 -> "TLS_AES_128_GCM_SHA256"
  | Aes256_gcm_sha384 -> "TLS_AES_256_GCM_SHA384"
  | Chacha20_poly1305_sha256 -> "TLS_CHACHA20_POLY1305_SHA256"
