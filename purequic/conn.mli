(** A QUIC v1 connection: the sans-io engine tying together TLS, packet
    protection, streams, flow control, datagrams (RFC 9221), loss
    recovery, timers and RESET_STREAM_AT.

    One [t] per connection; every entry point takes [now] (monotonic
    nanoseconds) and the module never reads a clock or global RNG — the
    whole connection is a deterministic function of (inputs, [config.rng],
    [now]), which is what makes scripted-clock tests possible.

    Scope per the project plan: QUIC v1, client + server. No Retry
    emission, no stateless reset, no active migration (we advertise
    disable_active_migration and only track the peer's address passively),
    no 0-RTT, no ECN. PATH_CHALLENGE is answered; NEW_CONNECTION_ID is
    honored (including retire_prior_to); key update is supported in both
    directions. *)

type role = [ `Client | `Server ]

type addr = string * int
(** peer address as (host, port); opaque to the connection, echoed back
    with each outgoing datagram. *)

type dir = [ `Uni | `Bidi ]

type config = {
  role : role;
  alpn : string list;
  cert_chain : X509.Certificate.t list;  (** server: leaf first *)
  priv_key : X509.Private_key.t option;  (** required for [`Server] *)
  verify : [ `None | `Anchors of X509.Certificate.t list ];
      (** [`None] skips chain validation but still checks
          CertificateVerify against the presented leaf *)
  time : unit -> Ptime.t option;  (** for certificate validity *)
  rng : int -> string;
  enable_datagrams : bool;
  reliable_reset : bool;  (** offer + use RESET_STREAM_AT when negotiated *)
  initial_max_data : int;
  initial_max_stream_data : int;
  initial_max_streams_bidi : int;
  initial_max_streams_uni : int;
  max_idle_ns : int64;
  max_udp_payload : int;
}

type event =
  | Handshake_done of { alpn : string option; peer_max_dgram : int option }
  | Stream_opened of { id : int; dir : dir }  (** peer-initiated *)
  | Stream_readable of int
  | Stream_writable of int
      (** a send side that returned [`Would_block] has credit again *)
  | Stream_reset of { id : int; code : int }
  | Stream_reset_at of { id : int; code : int; reliable_size : int }
  | Stream_stopped of { id : int; code : int }
  | Stream_credit  (** the peer raised MAX_STREAMS *)
  | Datagram_readable
  | Closed of { local : bool; app : bool; code : int; reason : string }

type 'a rw =
  ( 'a,
    [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
  result
(** stream/datagram call results, mirroring the backend seam. *)

type t

val client :
  config ->
  server_name:string option ->
  scid:string ->
  dcid:string ->
  peer:addr ->
  now:int64 ->
  (t, string) result
(** [dcid] is the random Initial DCID (it keys the Initial secrets). The
    first flight is queued immediately; call [send] to emit it. *)

val server_with_odcid :
  config ->
  scid:string ->
  odcid:string ->
  peer:addr ->
  now:int64 ->
  (t, string) result
(** [odcid] is the DCID of the client's first Initial: it keys the
    Initial secrets and is echoed as original_destination_connection_id.
    Materialize the connection from the first datagram, then [recv] it. *)

val recv : t -> now:int64 -> Bigstringaf.t -> off:int -> len:int -> from:addr -> unit
(** feed one incoming UDP datagram. Undecryptable packets are dropped,
    except 1-RTT packets that beat the application keys, which are
    stashed and replayed once the keys install (RFC 9001 s.5.7). *)

val send : t -> now:int64 -> Bigstringaf.t -> [ `Packet of int * addr | `Done ]
(** fill [buf] with the next outgoing UDP datagram — coalescing packet
    number spaces, padding Initial flights to 1200 bytes and respecting
    congestion, amplification and peer size limits. Call repeatedly until
    [`Done]. [buf] should hold [config.max_udp_payload] bytes. *)

val next_event : t -> event option
(** drain after every [recv]/[on_timeout] and after stream operations. *)

val next_timeout_ns : t -> now:int64 -> int64 option
(** relative delay until the earliest timer (idle, ack-delay, loss/PTO,
    close/drain end); [Some 0L] means fire [on_timeout] now. *)

val on_timeout : t -> now:int64 -> unit
(** fire due timers: idle teardown, loss detection, PTO probes, and the
    end of the closing/draining periods. *)

val is_established : t -> bool

val is_closed : t -> bool
(** fully dead (drained or timed out) — safe to drop the connection. *)

val open_stream : t -> dir:dir -> int rw
(** [`Would_block] when out of peer stream credit (a STREAMS_BLOCKED
    nudge is scheduled; wait for [Stream_credit]). *)

val stream_send :
  t -> id:int -> Bigstringaf.t -> off:int -> len:int -> fin:bool -> int rw
(** queue up to [len] bytes within stream + connection flow control; a
    short write drops [fin]. [`Stopped] after a local reset or the peer's
    STOP_SENDING; [`Fin] once the fin is queued. *)

val stream_recv :
  t -> id:int -> Bigstringaf.t -> off:int -> len:int -> (int * bool) rw
(** returns (bytes read, fin) and replenishes the stream and connection
    receive windows as data is consumed. *)

val stream_capacity : t -> id:int -> int rw
(** bytes [stream_send] would accept right now. *)

val stream_finish : t -> id:int -> unit rw
val stream_reset : t -> id:int -> code:int -> unit rw

val supports_reset_at : t -> bool
(** the peer advertised reliable-reset support. *)

val stream_reset_at : t -> id:int -> code:int -> reliable_size:int -> unit rw
(** RESET_STREAM_AT when negotiated on both sides, degrading to a plain
    RESET_STREAM otherwise. *)

val stream_stop_sending : t -> id:int -> code:int -> unit rw

val dgram_send : t -> Bigstringaf.t -> off:int -> len:int -> unit rw
(** [`Invalid] when the peer accepts no datagrams or [len] exceeds
    [dgram_max_len]; [`Would_block] when the send queue is full. *)

val dgram_recv : t -> Bigstringaf.t -> off:int -> int rw

val dgram_max_len : t -> int option
(** largest datagram payload currently sendable; [None] when the peer
    accepts none. *)

val peer_cert_der : t -> string option
(** the peer's leaf certificate, DER-encoded. *)

val app_close : t -> now:int64 -> app:bool -> code:int -> reason:string -> unit
(** start the closing handshake (CONNECTION_CLOSE); keep pumping [send]
    and timers until [is_closed]. *)

val set_trace : t -> (string -> unit) -> unit
(** install a qlog sink: called once per event with the JSON event body
    (packet_sent / packet_received / packet_dropped / metrics_updated);
    framing (JSON-SEQ record separators, the file header) is the sink's
    concern. *)

module For_testing : sig
  val initiate_key_update : t -> unit
  (** spontaneously step the send keys to the next generation. *)
end
