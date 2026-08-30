(** Eio driver for the webtransport stack.

    {!Wt} is the WebTransport API: servers {!Wt.listen}, clients
    {!Wt.connect}, both work with {!Wt.Session} and {!Wt.Stream}. {!Raw}
    exposes plain QUIC connections (no HTTP/3) — mainly for tests.

    The QUIC engine is pluggable: pack any {!Webtransport.Quic_backend.S}
    implementation and its configuration into a {!backend} value. *)

type backend =
  | Backend :
      (module Webtransport.Quic_backend.S with type t = 'c and type config = 'k)
      * 'k
      -> backend

type close_info = { code : int; reason : string; remote : bool; app : bool }

exception Connection_closed of close_info

exception Stream_reset_by_peer of int
(** carries the WebTransport application error code *)

exception Stream_stopped_by_peer of int
exception Session_closed of int * string
exception Session_rejected of int

(** Raw QUIC connections: streams and datagrams, no HTTP/3. *)
module Raw : sig
  type conn

  val established : conn -> unit
  val closed : conn -> close_info
  val accept_stream : conn -> int
  val open_stream : conn -> dir:[ `Uni | `Bidi ] -> int

  val read :
    conn -> id:int -> Bigstringaf.t -> off:int -> len:int ->
    [ `Data of int | `Fin ]

  val write : conn -> id:int -> string -> unit
  val finish : conn -> id:int -> unit
  val reset : conn -> id:int -> code:int -> unit
  val stop_sending : conn -> id:int -> code:int -> unit
  val send_dgram : conn -> string -> unit
  val recv_dgram : conn -> string
  val close : conn -> code:int -> reason:string -> unit

  val listen :
    sw:Eio.Switch.t ->
    net:'a Eio.Net.t ->
    clock:'b Eio.Time.Mono.t ->
    backend:backend ->
    port:int ->
    handler:(conn -> unit) ->
    unit

  val connect :
    sw:Eio.Switch.t ->
    net:'a Eio.Net.t ->
    clock:'b Eio.Time.Mono.t ->
    backend:backend ->
    ?server_name:string ->
    peer:string * int ->
    unit ->
    conn
end

(** WebTransport sessions and streams. *)
module Wt : sig
  type session

  module Session : sig
    val request : session -> Webtransport.Engine.request
    val path : session -> string
    val authority : session -> string
    val origin : session -> string option

    val close : ?code:int -> ?message:string -> session -> unit
    (** Sends WT_CLOSE_SESSION and finishes the CONNECT stream. *)

    val closed : session -> int * string
    (** Awaits session end; returns the close code and message. *)

    val drain : session -> unit
    (** Asks the peer to stop opening new streams (WT_DRAIN_SESSION). *)

    val draining : session -> unit
    (** Resolves when the peer asks us to drain. *)

    val send_datagram : session -> string -> bool
    (** [false] when the datagram was dropped (queue full / not open). *)

    val recv_datagram : session -> string
    (** @raise Session_closed once the session ends. *)
  end

  module Stream : sig
    type t

    val id : t -> int
    val session : t -> session

    val read :
      t -> Bigstringaf.t -> off:int -> len:int -> [ `Data of int | `Fin ]
    (** @raise Stream_reset_by_peer on a peer RESET (WebTransport code). *)

    val read_all : t -> string

    val write : t -> string -> unit
    (** Blocking; backpressured by QUIC and session flow control. *)

    val close_write : t -> unit
    val reset : t -> code:int -> unit
    val stop_sending : t -> code:int -> unit

    (** Eio.Flow views, so WebTransport streams compose with the wider Eio
        ecosystem ([Eio.Buf_read], [Eio.Flow.copy], ...). *)

    val to_flow : t -> Eio.Flow.two_way_ty Eio.Resource.t
    val to_source : t -> Eio.Flow.source_ty Eio.Resource.t
    val to_sink : t -> Eio.Flow.sink_ty Eio.Resource.t
  end

  val open_bidi : session -> Stream.t
  val open_uni : session -> Stream.t
  val accept_bidi : session -> Stream.t
  val accept_uni : session -> Stream.t

  (** Runs a WebTransport server. [accept] decides per extended-CONNECT
      request (default: accept everything); it runs on the connection's
      service path and must not block. [handler] is forked per established
      session. [fc] advertises session flow control — see
      {!Webtransport.Engine.create}. *)
  val listen :
    sw:Eio.Switch.t ->
    net:'a Eio.Net.t ->
    clock:'b Eio.Time.Mono.t ->
    backend:backend ->
    port:int ->
    ?accept:(Webtransport.Engine.request -> [ `Accept | `Reject of int ]) ->
    ?fc:int * int * int ->
    handler:(session -> unit) ->
    unit ->
    unit

  (** Establishes a WebTransport session; returns once the server accepted.
      @raise Session_rejected on a non-2xx response.
      @raise Connection_closed if the connection dies first. *)
  val connect :
    sw:Eio.Switch.t ->
    net:'a Eio.Net.t ->
    clock:'b Eio.Time.Mono.t ->
    backend:backend ->
    ?origin:string ->
    ?headers:(string * string) list ->
    ?server_name:string ->
    ?fc:int * int * int ->
    peer:string * int ->
    authority:string ->
    path:string ->
    unit ->
    session
end
