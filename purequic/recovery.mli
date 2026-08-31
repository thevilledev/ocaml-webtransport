(** Loss detection and congestion control (RFC 9002): packet + time
    thresholds, PTO with backoff, NewReno with persistent congestion.
    All times are monotonic nanoseconds supplied by the caller.

    One [t] per connection holds the RTT estimate and congestion window;
    one [space] per packet number space tracks packets awaiting
    acknowledgment. Lost packets are returned as [sent] records and the
    caller regenerates their content from the [retx] descriptors it
    attached at send time. *)

type retx =
  | Rtx_crypto of { space : int; lo : int; hi : int }
  | Rtx_stream of { id : int; lo : int; hi : int; fin : bool }
  | Rtx_flags  (** control frames, re-derived from current state *)
  | Rtx_dgram  (** DATAGRAM: never retransmitted *)
(** what to regenerate if the packet is declared lost *)

type sent = {
  pn : int;
  time_sent : int64;
  size : int;
  ack_eliciting : bool;
  in_flight : bool;
  retx : retx list;
}
(** one sent packet, as recorded via [on_sent] *)

type space = private {
  mutable sent : sent list;  (** awaiting acknowledgment, descending pn *)
  mutable largest_acked : int;  (** -1 = none *)
  mutable loss_time : int64 option;
      (** deadline of the earliest time-threshold loss candidate *)
  mutable last_ae_sent : int64 option;  (** for the PTO timer *)
}

val mk_space : unit -> space

type t

val create : unit -> t

val set_max_ack_delay_ns : t -> int64 -> unit
(** install the peer's max_ack_delay once its transport parameters
    arrive (applied in the application space only). *)

val on_sent : t -> space -> sent -> unit

val can_send : t -> size:int -> bool
(** congestion check: do [size] more in-flight bytes fit the window? *)

val pto_backed_off : t -> is_app:bool -> int64
(** the current PTO duration, including exponential backoff. *)

val on_ack :
  t ->
  space ->
  largest:int ->
  ranges:(int * int) list ->
  ack_delay_ns:int64 ->
  now:int64 ->
  is_app:bool ->
  sent list * sent list
(** process one ACK frame; returns (newly acked, declared lost) and
    feeds the RTT estimator, congestion control and the loss timer. *)

val space_timer : t -> space -> is_app:bool -> int64 option
(** earliest absolute deadline for the space: loss time if armed,
    otherwise PTO. *)

val on_loss_timer : t -> space -> now:int64 -> sent list
(** run time-threshold loss detection; returns the newly lost. *)

val on_pto : t -> unit
(** bump the backoff after a PTO expiry (the caller sends the probes). *)

val discard_space : t -> space -> unit
(** key discard: drop the space's packets from the in-flight count. *)

(** Metric accessors for tracing. *)
val srtt_ns : t -> int64

val cwnd : t -> int
val bytes_in_flight : t -> int
