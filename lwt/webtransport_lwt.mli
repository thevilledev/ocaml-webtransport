(** Lwt driver for the webtransport stack: the same engine and backends as
    the Eio driver, glued to Lwt_unix sockets and promises. *)

type backend =
  | Backend :
      (module Webtransport.Quic_backend.S with type t = 'c and type config = 'k)
      * 'k
      -> backend

type close_info = { code : int; reason : string; remote : bool; app : bool }

exception Connection_closed of close_info
exception Session_closed of int * string
exception Session_rejected of int

exception Stream_reset_by_peer of int
(** carries the WebTransport application error code *)

exception Stream_stopped_by_peer of int

module Wt : sig
  type session

  module Session : sig
    val request : session -> Webtransport.Engine.request
    val path : session -> string
    val authority : session -> string
    val close : ?code:int -> ?message:string -> session -> unit Lwt.t
    val closed : session -> (int * string) Lwt.t
    val send_datagram : session -> string -> bool Lwt.t
    val recv_datagram : session -> string Lwt.t
  end

  module Stream : sig
    type t

    val id : t -> int

    val read :
      t -> Bigstringaf.t -> off:int -> len:int ->
      [ `Data of int | `Fin ] Lwt.t

    val read_all : t -> string Lwt.t
    val write : t -> string -> unit Lwt.t
    val close_write : t -> unit Lwt.t
    val reset : t -> code:int -> unit Lwt.t
    val stop_sending : t -> code:int -> unit Lwt.t
  end

  val open_bidi : session -> Stream.t Lwt.t
  val open_uni : session -> Stream.t Lwt.t
  val accept_bidi : session -> Stream.t Lwt.t
  val accept_uni : session -> Stream.t Lwt.t

  (** Runs a WebTransport server (the promise never resolves). *)
  val listen :
    backend:backend ->
    port:int ->
    ?accept:(Webtransport.Engine.request -> [ `Accept | `Reject of int ]) ->
    ?fc:int * int * int ->
    handler:(session -> unit Lwt.t) ->
    unit ->
    unit Lwt.t

  val connect :
    backend:backend ->
    ?server_name:string ->
    ?origin:string ->
    ?headers:(string * string) list ->
    ?fc:int * int * int ->
    peer:string * int ->
    authority:string ->
    path:string ->
    unit ->
    session Lwt.t
end
