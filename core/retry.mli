(** Stateless Retry for the drivers (RFC 9000 s.8.1.2): AEAD-sealed
    address-validation tokens under a per-listener key, and the Retry
    packet with its RFC 9001 integrity tag. Backend-independent. *)

type state

val create : unit -> state
(** fresh random token key (requires an initialized mirage-crypto rng). *)

val mint : state -> odcid:string -> peer:string * int -> now:int64 -> string

val validate :
  state -> token:string -> peer:string * int -> now:int64 -> string option
(** [Some odcid] iff authentic, bound to [peer], and unexpired (30 s). *)

val write :
  client_scid:string ->
  new_scid:string ->
  odcid:string ->
  token:string ->
  Bigstringaf.t ->
  (int, string) result
(** compose a v1 Retry packet; returns bytes written. *)
