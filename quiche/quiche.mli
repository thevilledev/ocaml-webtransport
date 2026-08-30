(** OCaml bindings to Cloudflare's libquiche.

    Thin, faithful layer over the C API: poll-style, non-blocking, no
    callbacks. Buffers are {!Bigstringaf.t}; addresses are raw [(ip, port)]
    pairs with the IP as 4 or 16 network-order bytes; stream ids and error
    codes are OCaml [int]s (QUIC varints fit [max_int] on 64-bit). *)

type config
type conn

type addr = string * int
(** Raw 4/16-byte IP in network order, and port. *)

val protocol_version : int32
val max_conn_id_len : int

type err =
  | Done
  | Buffer_too_short
  | Unknown_version
  | Invalid_frame
  | Invalid_packet
  | Invalid_state
  | Invalid_stream_state
  | Invalid_transport_param
  | Crypto_fail
  | Tls_fail
  | Flow_control
  | Stream_limit
  | Final_size
  | Congestion_control
  | Stream_stopped of int  (** peer STOP_SENDING error code *)
  | Stream_reset of int  (** peer RESET_STREAM error code *)
  | Id_limit
  | Out_of_identifiers
  | Key_update
  | Crypto_buffer_exceeded
  | Invalid_ack_range
  | Optimistic_ack_detected
  | Invalid_dcid
  | Unknown of int

val err_of_code : ?stream_code:int -> int -> err
val err_to_string : err -> string
val version : unit -> string

module Config : sig
  type t = config

  val create : ?version:int32 -> unit -> t

  val free : t -> unit
  (** Idempotent; a finalizer backs it up. *)

  val load_cert_chain : t -> pem_file:string -> (unit, err) result
  val load_priv_key : t -> pem_file:string -> (unit, err) result
  val load_verify_locations : t -> ca_file:string -> (unit, err) result
  val verify_peer : t -> bool -> unit
  val set_application_protos : t -> string list -> (unit, err) result
  val set_max_idle_timeout : t -> int64 -> unit
  (** milliseconds; 0 = no timeout *)

  val set_max_recv_udp_payload_size : t -> int -> unit
  val set_max_send_udp_payload_size : t -> int -> unit
  val set_initial_max_data : t -> int -> unit
  val set_initial_max_stream_data_bidi_local : t -> int -> unit
  val set_initial_max_stream_data_bidi_remote : t -> int -> unit
  val set_initial_max_stream_data_uni : t -> int -> unit
  val set_initial_max_streams_bidi : t -> int -> unit
  val set_initial_max_streams_uni : t -> int -> unit
  val enable_dgram : t -> bool -> int -> int -> unit
  (** [enable_dgram t enabled recv_queue_len send_queue_len] *)

  val grease : t -> bool -> unit
end

type header = {
  version : int32;
  ty : int;  (** raw quiche packet type; [initial_type] for Initial *)
  scid : string;
  dcid : string;
  token : string;
}

val initial_type : int

val header_info :
  Bigstringaf.t -> off:int -> len:int -> dcil:int -> (header, err) result

val negotiate_version :
  scid:string -> dcid:string -> Bigstringaf.t -> off:int -> len:int ->
  (int, err) result

val connect :
  ?server_name:string ->
  scid:string -> local:addr -> peer:addr -> config -> conn
(** @raise Failure when quiche refuses the connection setup. *)

val accept : ?odcid:string -> scid:string -> local:addr -> peer:addr -> config -> conn

val conn_free : conn -> unit
(** Idempotent; a finalizer backs it up. *)

val recv :
  conn -> Bigstringaf.t -> off:int -> len:int -> from:addr -> to_:addr ->
  (int, err) result

val send :
  conn -> Bigstringaf.t -> off:int -> len:int ->
  [ `Packet of int * addr | `Done | `Error of err ]

val timeout_as_nanos : conn -> int64 option
val on_timeout : conn -> unit
val is_established : conn -> bool
val is_closed : conn -> bool
val is_draining : conn -> bool
val close : conn -> app:bool -> code:int -> reason:string -> (unit, err) result

val stream_recv :
  conn -> id:int -> Bigstringaf.t -> off:int -> len:int ->
  (int * bool, err) result
(** [Ok (bytes_read, fin)] *)

val stream_send :
  conn -> id:int -> Bigstringaf.t -> off:int -> len:int -> fin:bool ->
  (int, err) result

val stream_capacity : conn -> id:int -> (int, err) result
val stream_shutdown :
  conn -> id:int -> [ `Read | `Write ] -> code:int -> (unit, err) result

val stream_readable_next : conn -> int option
val stream_writable_next : conn -> int option
val stream_writable : conn -> id:int -> len:int -> (bool, err) result
val stream_finished : conn -> int -> bool
val peer_streams_left_bidi : conn -> int
val peer_streams_left_uni : conn -> int

val readable_ids : conn -> int array
(** Snapshot of streams with pending data. *)

val writable_ids : conn -> int array

val dgram_recv_queue_len : conn -> int
val dgram_send : conn -> Bigstringaf.t -> off:int -> len:int -> (unit, err) result
val dgram_recv : conn -> Bigstringaf.t -> off:int -> len:int -> (int, err) result

val dgram_max_writable_len : conn -> int option
(** [None] when the peer does not accept DATAGRAM frames. *)

val application_proto : conn -> string option
val peer_cert : conn -> string option
(** DER of the peer's leaf certificate. *)

type conn_error = { is_app : bool; code : int; reason : string }

val peer_error : conn -> conn_error option
val local_error : conn -> conn_error option

val set_qlog_path :
  conn -> path:string -> title:string -> description:string -> bool
(** [false] when qlog support is compiled out of libquiche (Homebrew
    bottle). *)
