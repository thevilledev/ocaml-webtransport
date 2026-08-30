(** The three QUIC v1 AEAD suites (RFC 9001 s.5). *)

type t = Aes128_gcm_sha256 | Aes256_gcm_sha384 | Chacha20_poly1305_sha256

val hash : t -> Digestif.hash'
val hash_len : t -> int
val key_len : t -> int
val iv_len : t -> int
val tag_len : t -> int
val hp_key_len : t -> int
val sample_len : t -> int
val to_tls_id : t -> int
val of_tls_id : int -> t option
val pp : t -> string
