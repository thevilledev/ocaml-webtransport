(** Sorted, disjoint, inclusive integer interval sets (ACK tracking,
    reassembly, retransmission bookkeeping). *)

type t

val create : unit -> t
val is_empty : t -> bool
val insert : t -> lo:int -> hi:int -> unit
val contains : t -> int -> bool
val largest : t -> int option
val smallest : t -> int option

val drop_below : t -> int -> unit
(** remove everything strictly below the argument. *)

val next_gap : t -> int -> int
(** smallest integer >= the argument not in the set. *)

val iter_desc : t -> (lo:int -> hi:int -> unit) -> unit
val to_list_desc : t -> (int * int) list
val cardinal_spans : t -> int
