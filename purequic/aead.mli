(** Packet payload protection (RFC 9001 s.5.3) and Retry integrity
    (s.5.8). *)

type keys = private {
  suite : Qsuite.t;
  cipher : cipher;
  iv : string;
  hp : Hp.key;
  secret : string;
}

and cipher

val of_secret : suite:Qsuite.t -> string -> keys
val of_material : suite:Qsuite.t -> secret:string -> Qkdf.material -> keys

val initial_keys : dcid:string -> role:[ `Client | `Server ] -> keys * keys
(** [(tx, rx)] AES-128-GCM Initial keys for this role. *)

val seal : keys -> pn:int64 -> ad:string -> string -> string
(** ciphertext with the 16-byte tag appended. *)

val open_ : keys -> pn:int64 -> ad:string -> string -> string option

val next_generation : keys -> keys
(** rotate key/iv along the "quic ku" chain; header protection unchanged. *)

val retry_tag : odcid:string -> pseudo:string -> string
