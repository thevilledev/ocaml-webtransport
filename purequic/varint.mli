(** QUIC variable-length integers (RFC 9000 s.16). Values are OCaml [int]s;
    the varint domain [0, 2^62-1] equals [0, max_int] on 64-bit platforms. *)

val max_value : int
val size : int -> int

val get : Bigstringaf.t -> off:int -> len:int -> (int * int) option
(** value and bytes consumed; [None] if the buffer ends mid-varint. *)

val put : Bigstringaf.t -> off:int -> int -> int
(** minimal encoding; returns bytes written. *)

val put_width : Bigstringaf.t -> off:int -> width:int -> int -> int
(** fixed-width encoding (e.g. a backfillable long-header Length). *)

val get_string : string -> pos:int -> (int * int) option
(** value and next position. *)

val add_buffer : Buffer.t -> int -> unit
