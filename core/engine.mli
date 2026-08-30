(** The sans-io HTTP/3 + WebTransport engine.

    Owns the minimal HTTP/3 a WebTransport endpoint needs — control streams,
    SETTINGS, QPACK (static-only), extended CONNECT — plus WebTransport
    session state: capsules (inside DATA frames on the CONNECT stream, per
    RFC 9297), close/drain, session flow control, and 0x54/0x41 data-stream
    dispatch with bounded parking for streams that outrun their session.

    The engine drives a {!Quic_backend.S} connection directly (backend calls
    are non-blocking, pure state mutations — no sockets, clocks or fibers
    here). Drivers feed packets into the backend, call {!process}, dispatch
    the returned notifications, and flush outgoing packets. *)

type backend_conn =
  | C : (module Quic_backend.S with type t = 'c) * 'c -> backend_conn

type dir = [ `Uni | `Bidi ]

type request = {
  authority : string;
  path : string;
  origin : string option;
  protocol : string;  (** the [:protocol] token the peer used *)
  headers : (string * string) list;  (** non-pseudo request headers *)
}

type notification =
  | Incoming_session of { sid : int; req : request }
      (** server: awaiting {!accept_session}/{!reject_session} *)
  | Session_established of { sid : int }
  | Session_rejected of { sid : int; status : int }  (** client *)
  | Session_peer_closed of {
      sid : int;
      code : int;
      message : string;
      abrupt : bool;
    }
  | Session_peer_drain of { sid : int }
  | Wt_datagram of { sid : int; payload : string }
  | Wt_stream_opened of { sid : int; stream_id : int; dir : dir }
  | Wt_stream_readable of { stream_id : int }
  | Wt_stream_writable of { stream_id : int }
  | Goaway
  | Conn_closed of { code : int; reason : string; remote : bool }

type session_state = [ `Requested | `Connecting | `Open | `Closed ]
type role = [ `Client | `Server ]
type t

(** [fc] advertises WebTransport session flow control as
    [(max_data, max_streams_uni, max_streams_bidi)]; it activates only when
    both endpoints advertise non-zero limits (browsers never do). Without
    negotiated flow control, a server allows one concurrent session. *)
val create :
  ?wt_max_sessions:int ->
  ?fc:int * int * int ->
  ?parked_cap:int ->
  ?parked_timeout_ns:int64 ->
  role:role ->
  backend_conn ->
  t

(** Drains backend events, runs the protocol, returns notifications for the
    driver to dispatch. [now] is a monotonic timestamp in nanoseconds (used
    to expire parked streams). *)
val process : t -> now:int64 -> notification list

val accept_session : t -> sid:int -> unit
val reject_session : t -> sid:int -> status:int -> unit

(** Client: queues an extended CONNECT; it is sent once the peer's SETTINGS
    arrive (choosing the [:protocol] token they support). The outcome arrives
    as {!Session_established} or {!Session_rejected}. At most one request may
    be pending. *)
val connect_session :
  t ->
  ?origin:string ->
  ?headers:(string * string) list ->
  authority:string ->
  path:string ->
  unit ->
  unit

val close_session : t -> sid:int -> code:int -> message:string -> unit
val drain_session : t -> sid:int -> unit

(** Opens a WT data stream and writes its signal prefix. [`Would_block] when
    out of QUIC or session stream credit. *)
val open_wt_stream :
  t -> sid:int -> dir:dir -> (int, [ `Would_block | `Invalid ]) result

(** Application writes on WT streams: buffered behind the signal prefix and
    clamped by session flow control at flush time. *)
val write_stream : t -> id:int -> string -> unit

val finish_stream : t -> id:int -> unit

(** Bytes buffered locally for [id]; drivers use this for backpressure. *)
val outbuf_len : t -> id:int -> int

(** Abrupt terminations, with WebTransport application error codes (mapped
    into the reserved HTTP/3 range on the wire). *)
val reset_wt_stream : t -> id:int -> code:int -> unit

val stop_wt_stream : t -> id:int -> code:int -> unit

(** Sends a WebTransport datagram (quarter-stream-id prefix + payload);
    [false] when the session is not open or the queue is full. *)
val send_datagram : t -> sid:int -> string -> bool

(** Reads from a WT data stream, draining any bytes the engine buffered
    while parsing the signal prefix. Drivers use this instead of the backend
    for attached streams. *)
val read_attached :
  t ->
  id:int ->
  Bigstringaf.t ->
  off:int ->
  len:int ->
  ( int * bool,
    [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
  result

val session_state : t -> sid:int -> session_state option
val session_request : t -> sid:int -> request option
