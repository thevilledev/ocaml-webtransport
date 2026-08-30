(** TLS 1.3 cipher suites as negotiation tokens (no encryption here). *)

type t = Aes128_gcm_sha256 | Aes256_gcm_sha384 | Chacha20_poly1305_sha256

val to_id : t -> int
val of_id : int -> t option
val hash : t -> Digestif.hash'
val hash_len : t -> int

val all : t list
(** our preference order. *)
