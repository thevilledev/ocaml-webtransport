(** Per-encryption-level CRYPTO stream state: receive-side offset
    reassembly and a retransmittable send buffer. One [t] per packet
    number space; offsets are absolute within that space's CRYPTO
    stream. *)

type t

val create : unit -> t

val recv :
  t -> off:int -> string -> deliver:(string -> unit) -> (unit, string) result
(** feed one received CRYPTO frame; [deliver] is called with each newly
    contiguous chunk, in order. Pure retransmissions are dropped;
    [Error] once buffered out-of-order bytes exceed a 1 MiB cap
    (hostile peers). *)

val send : t -> string -> unit
(** append handshake bytes and mark them pending. *)

val has_pending : t -> bool

val take : t -> max:int -> (int * string) option
(** lowest contiguous pending span, clipped to [max] bytes; returns
    (offset, data) and marks it in flight. *)

val requeue : t -> lo:int -> hi:int -> unit
(** loss: mark an absolute byte range for retransmission. *)
