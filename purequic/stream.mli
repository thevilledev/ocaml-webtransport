(** Per-stream send/receive state machines (RFC 9000 s.3), including the
    receive side of RESET_STREAM_AT (partial delivery up to the reliable
    size). Flow-control {e limits} live in the connection; this module
    tracks per-stream offsets and credit.

    The [send]/[recv] records are working state shared with [Conn]: the
    dirty/pending flags are how the connection schedules control frames,
    so the fields stay exposed rather than hidden behind accessors. *)

type send = {
  buf : Buffer.t;  (** bytes from [base] upward *)
  mutable base : int;  (** absolute offset of [buf]'s start after compaction *)
  pending : Ranges.t;  (** absolute byte ranges to (re)transmit *)
  acked : Ranges.t;
  mutable fin_queued : bool;
  mutable fin_pending : bool;  (** fin needs (re)transmission *)
  mutable fin_acked : bool;
  mutable reset : (int * int) option;  (** code, final_size *)
  mutable reset_reliable : int option;  (** RESET_STREAM_AT reliable size *)
  mutable reset_pending : bool;  (** RESET_STREAM needs (re)transmission *)
  mutable reset_acked : bool;
  mutable credit : int;  (** peer's MAX_STREAM_DATA for this stream *)
  mutable blocked : bool;  (** app saw [`Would_block] since last writable *)
}

type recv = {
  mutable chunks : (int * string) list;  (** unconsumed data, unordered *)
  received : Ranges.t;
  mutable read_off : int;
  mutable highest : int;  (** largest offset+len seen, for flow accounting *)
  mutable final : int option;
  mutable rreset : (int * int) option;  (** code, final_size *)
  mutable reliable : int;  (** deliver below this even after reset *)
  mutable reset_delivered : bool;
  mutable fin_delivered : bool;
  mutable stop_sent : int option;  (** STOP_SENDING code we queued *)
  mutable stop_pending : bool;  (** STOP_SENDING needs (re)transmission *)
  mutable credit : int;  (** MAX_STREAM_DATA we advertised *)
  mutable credit_dirty : bool;  (** re-advertise needed *)
}

type t = { id : int; send : send option; recv : recv option }
(** a stream: send half, receive half, or both, per its type and origin *)

val create :
  id:int ->
  send_credit:int ->
  recv_credit:int ->
  has_send:bool ->
  has_recv:bool ->
  t

val send_capacity : send -> int
(** bytes the app may still queue against the peer's stream credit;
    0 once reset or fin-queued. *)

val send_queue : send -> string -> unit
val send_fin : send -> unit

val send_reset : ?reliable:int -> send -> code:int -> unit
(** queue RESET_STREAM, or RESET_STREAM_AT with [?reliable]; pending data
    at or above the reliable size stops transmitting. *)

val has_send_pending : send -> bool

val send_take : send -> max:int -> (int * string * bool) option
(** next chunk to transmit: lowest pending contiguous range, clipped to
    [max]. Returns (off, data, fin); a pure-fin chunk has empty data. *)

val send_on_acked : send -> lo:int -> hi:int -> fin:bool -> unit

val send_on_lost : send -> lo:int -> hi:int -> fin:bool -> unit
(** requeue a lost range for retransmission, skipping acked bytes. *)

val send_closed : send -> bool
(** all data + fin acknowledged, or the reset acknowledged. *)

type recv_result = [ `Ok of bool  (** newly readable *) | `Err of string ]

val recv_on_frame : recv -> off:int -> fin:bool -> string -> recv_result
(** [`Err] on final-size violations (FINAL_SIZE_ERROR). *)

val recv_on_reset :
  recv -> code:int -> final_size:int -> reliable:int -> recv_result
(** plain RESET_STREAM is [~reliable:0]; repeated resets may only shrink
    the reliable size. *)

val recv_read :
  recv ->
  Bigstringaf.t ->
  off:int ->
  len:int ->
  (int * bool, [ `Would_block | `Fin | `Reset of int | `Invalid ]) result
(** read at most [len] contiguous bytes into [buf] at [off]; mirrors the
    backend seam's [stream_recv] results. After a reliable reset, data
    below the reliable size is delivered before [`Reset] surfaces. *)

val recv_closed : recv -> bool
