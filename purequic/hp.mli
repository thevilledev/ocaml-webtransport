(** Header protection (RFC 9001 s.5.4). *)

type key

val key : suite:Qsuite.t -> hp_key:string -> key

val mask : key -> sample:string -> string
(** 5-byte mask from a 16-byte ciphertext sample. *)
