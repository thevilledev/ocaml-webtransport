(** Bounds-checked cursor over a Bigstringaf slice, and byte putters.
    Readers return [None] on underflow: parsers must be total. *)

type reader = { buf : Bigstringaf.t; mutable pos : int; limit : int }

val reader : Bigstringaf.t -> off:int -> len:int -> reader
val remaining : reader -> int
val pos : reader -> int
val u8 : reader -> int option
val u16 : reader -> int option
val u32 : reader -> int32 option
val varint : reader -> int option

val bytes : reader -> int -> string option
(** [n] bytes, copied. *)

val slice : reader -> int -> (int * int) option
(** [n] bytes as a zero-copy [(off, len)] view. *)

val skip : reader -> int -> unit option

val put_u8 : Bigstringaf.t -> off:int -> int -> int
val put_u32 : Bigstringaf.t -> off:int -> int32 -> int
val put_string : Bigstringaf.t -> off:int -> string -> int
val put_varint : Bigstringaf.t -> off:int -> int -> int
(** all putters return the offset one past what was written. *)
