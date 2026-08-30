(* OCaml bindings to Cloudflare's libquiche.

   Thin, faithful layer over the C API: poll-style, non-blocking, no
   callbacks. Buffers are [Bigstringaf.t]; addresses are raw [(ip, port)]
   pairs with the IP as 4 or 16 network-order bytes; stream ids and error
   codes are OCaml [int]s (QUIC varints fit [max_int] on 64-bit). *)

type config
type conn

(* Raw 4/16-byte IP in network order, and port. *)
type addr = string * int

let protocol_version = 1l
let max_conn_id_len = 20

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
  | Stream_stopped of int  (* peer STOP_SENDING error code *)
  | Stream_reset of int  (* peer RESET_STREAM error code *)
  | Id_limit
  | Out_of_identifiers
  | Key_update
  | Crypto_buffer_exceeded
  | Invalid_ack_range
  | Optimistic_ack_detected
  | Invalid_dcid
  | Unknown of int

let err_of_code ?(stream_code = 0) c =
  match c with
  | -1 -> Done
  | -2 -> Buffer_too_short
  | -3 -> Unknown_version
  | -4 -> Invalid_frame
  | -5 -> Invalid_packet
  | -6 -> Invalid_state
  | -7 -> Invalid_stream_state
  | -8 -> Invalid_transport_param
  | -9 -> Crypto_fail
  | -10 -> Tls_fail
  | -11 -> Flow_control
  | -12 -> Stream_limit
  | -13 -> Final_size
  | -14 -> Congestion_control
  | -15 -> Stream_stopped stream_code
  | -16 -> Stream_reset stream_code
  | -17 -> Id_limit
  | -18 -> Out_of_identifiers
  | -19 -> Key_update
  | -20 -> Crypto_buffer_exceeded
  | -21 -> Invalid_ack_range
  | -22 -> Optimistic_ack_detected
  | -23 -> Invalid_dcid
  | c -> Unknown c

let err_to_string = function
  | Done -> "done"
  | Buffer_too_short -> "buffer too short"
  | Unknown_version -> "unknown QUIC version"
  | Invalid_frame -> "invalid frame"
  | Invalid_packet -> "invalid packet"
  | Invalid_state -> "invalid connection state"
  | Invalid_stream_state -> "invalid stream state"
  | Invalid_transport_param -> "invalid transport parameter"
  | Crypto_fail -> "crypto failure"
  | Tls_fail -> "TLS handshake failure"
  | Flow_control -> "flow control violation"
  | Stream_limit -> "stream limit violation"
  | Final_size -> "final size violation"
  | Congestion_control -> "congestion control error"
  | Stream_stopped c -> Printf.sprintf "stream stopped by peer (code %d)" c
  | Stream_reset c -> Printf.sprintf "stream reset by peer (code %d)" c
  | Id_limit -> "connection id limit"
  | Out_of_identifiers -> "out of connection ids"
  | Key_update -> "key update error"
  | Crypto_buffer_exceeded -> "crypto buffer exceeded"
  | Invalid_ack_range -> "invalid ACK range"
  | Optimistic_ack_detected -> "optimistic ACK detected"
  | Invalid_dcid -> "invalid DCID"
  | Unknown c -> Printf.sprintf "unknown quiche error %d" c

let check rc = if rc >= 0 then Ok rc else Error (err_of_code rc)
let check_unit rc = if rc >= 0 then Ok () else Error (err_of_code rc)

external version : unit -> string = "ocaml_quiche_version"

module Config = struct
  type t = config

  external config_new : int32 -> config = "ocaml_quiche_config_new"
  external free : config -> unit = "ocaml_quiche_config_free"

  external load_cert_chain_stub : config -> string -> int
    = "ocaml_quiche_config_load_cert_chain"

  external load_priv_key_stub : config -> string -> int
    = "ocaml_quiche_config_load_priv_key"

  external load_verify_locations_stub : config -> string -> int
    = "ocaml_quiche_config_load_verify_locations"

  external verify_peer : config -> bool -> unit
    = "ocaml_quiche_config_verify_peer"

  external set_application_protos_stub : config -> string -> int
    = "ocaml_quiche_config_set_application_protos"

  external set_max_idle_timeout : config -> int64 -> unit
    = "ocaml_quiche_config_set_max_idle_timeout"
  (* milliseconds; 0 = no timeout *)

  external set_max_recv_udp_payload_size : config -> int -> unit
    = "ocaml_quiche_config_set_max_recv_udp_payload_size"

  external set_max_send_udp_payload_size : config -> int -> unit
    = "ocaml_quiche_config_set_max_send_udp_payload_size"

  external set_initial_max_data : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_data"

  external set_initial_max_stream_data_bidi_local : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_stream_data_bidi_local"

  external set_initial_max_stream_data_bidi_remote : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_stream_data_bidi_remote"

  external set_initial_max_stream_data_uni : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_stream_data_uni"

  external set_initial_max_streams_bidi : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_streams_bidi"

  external set_initial_max_streams_uni : config -> int -> unit
    = "ocaml_quiche_config_set_initial_max_streams_uni"

  external enable_dgram : config -> bool -> int -> int -> unit
    = "ocaml_quiche_config_enable_dgram"

  external grease : config -> bool -> unit = "ocaml_quiche_config_grease"

  let create ?(version = protocol_version) () = config_new version
  let load_cert_chain t ~pem_file = check_unit (load_cert_chain_stub t pem_file)
  let load_priv_key t ~pem_file = check_unit (load_priv_key_stub t pem_file)

  let load_verify_locations t ~ca_file =
    check_unit (load_verify_locations_stub t ca_file)

  (* ALPN wire format: length-prefixed protocol names, concatenated. *)
  let set_application_protos t protos =
    let wire =
      String.concat ""
        (List.map
           (fun p ->
             let n = String.length p in
             if n = 0 || n > 255 then invalid_arg "ALPN protocol length";
             String.make 1 (Char.chr n) ^ p)
           protos)
    in
    check_unit (set_application_protos_stub t wire)
end

type header = {
  version : int32;
  ty : int;  (* raw quiche packet type; [initial_type] for Initial *)
  scid : string;
  dcid : string;
  token : string;
}

let initial_type = 1

external header_info_stub :
  Bigstringaf.t -> int -> int -> int -> int * int32 * int * string * string * string
  = "ocaml_quiche_header_info"

let header_info buf ~off ~len ~dcil =
  let rc, version, ty, scid, dcid, token = header_info_stub buf off len dcil in
  if rc < 0 then Error (err_of_code rc)
  else Ok { version; ty; scid; dcid; token }

external negotiate_version_stub :
  string -> string -> Bigstringaf.t -> int -> int -> int
  = "ocaml_quiche_negotiate_version"

let negotiate_version ~scid ~dcid buf ~off ~len =
  check (negotiate_version_stub scid dcid buf off len)

external connect_stub :
  string option -> string -> addr -> addr -> config -> conn
  = "ocaml_quiche_connect"

external accept_stub : string -> string option -> addr -> addr -> config -> conn
  = "ocaml_quiche_accept"

let connect ?server_name ~scid ~local ~peer config =
  connect_stub server_name scid local peer config

let accept ?odcid ~scid ~local ~peer config =
  accept_stub scid odcid local peer config

external conn_free : conn -> unit = "ocaml_quiche_conn_free"

external recv_stub : conn -> Bigstringaf.t -> int -> int -> addr -> addr -> int
  = "ocaml_quiche_conn_recv_bytecode" "ocaml_quiche_conn_recv_native"

let recv t buf ~off ~len ~from ~to_ = check (recv_stub t buf off len from to_)

external send_stub : conn -> Bigstringaf.t -> int -> int -> int * addr
  = "ocaml_quiche_conn_send"

let send t buf ~off ~len =
  let rc, addr = send_stub t buf off len in
  if rc >= 0 then `Packet (rc, addr)
  else match err_of_code rc with Done -> `Done | e -> `Error e

external timeout_as_nanos_stub : conn -> int64
  = "ocaml_quiche_conn_timeout_as_nanos"

(* quiche returns u64::MAX when no timeout is armed. *)
let timeout_as_nanos t =
  let ns = timeout_as_nanos_stub t in
  if Int64.equal ns (-1L) then None else Some ns

external on_timeout : conn -> unit = "ocaml_quiche_conn_on_timeout"
external is_established : conn -> bool = "ocaml_quiche_conn_is_established"
external is_closed : conn -> bool = "ocaml_quiche_conn_is_closed"
external is_draining : conn -> bool = "ocaml_quiche_conn_is_draining"

external close_stub : conn -> bool -> int -> string -> int
  = "ocaml_quiche_conn_close"

let close t ~app ~code ~reason =
  match check_unit (close_stub t app code reason) with
  | Ok () -> Ok ()
  | Error Done -> Ok ()  (* already closed/closing: not an error for us *)
  | Error e -> Error e

external stream_recv_stub :
  conn -> int -> Bigstringaf.t -> int -> int -> int * bool * int
  = "ocaml_quiche_conn_stream_recv"

(* Ok (bytes_read, fin) *)
let stream_recv t ~id buf ~off ~len =
  let rc, fin, ec = stream_recv_stub t id buf off len in
  if rc >= 0 then Ok (rc, fin) else Error (err_of_code ~stream_code:ec rc)

external stream_send_stub :
  conn -> int -> Bigstringaf.t -> int -> int -> bool -> int * int
  = "ocaml_quiche_conn_stream_send_bytecode" "ocaml_quiche_conn_stream_send_native"

let stream_send t ~id buf ~off ~len ~fin =
  let rc, ec = stream_send_stub t id buf off len fin in
  if rc >= 0 then Ok rc else Error (err_of_code ~stream_code:ec rc)

external stream_capacity_stub : conn -> int -> int
  = "ocaml_quiche_conn_stream_capacity"

let stream_capacity t ~id = check (stream_capacity_stub t id)

external stream_shutdown_stub : conn -> int -> int -> int -> int
  = "ocaml_quiche_conn_stream_shutdown"

let stream_shutdown t ~id dir ~code =
  let d = match dir with `Read -> 0 | `Write -> 1 in
  check_unit (stream_shutdown_stub t id d code)

external stream_readable_next_stub : conn -> int
  = "ocaml_quiche_conn_stream_readable_next"

let stream_readable_next t =
  let id = stream_readable_next_stub t in
  if id < 0 then None else Some id

external stream_writable_next_stub : conn -> int
  = "ocaml_quiche_conn_stream_writable_next"

let stream_writable_next t =
  let id = stream_writable_next_stub t in
  if id < 0 then None else Some id

external stream_writable_stub : conn -> int -> int -> int
  = "ocaml_quiche_conn_stream_writable"

(* Ok true when [len] bytes fit the stream's send capacity now. *)
let stream_writable t ~id ~len =
  let rc = stream_writable_stub t id len in
  if rc >= 0 then Ok (rc = 1) else Error (err_of_code rc)

external stream_finished : conn -> int -> bool
  = "ocaml_quiche_conn_stream_finished"

external peer_streams_left_bidi : conn -> int
  = "ocaml_quiche_conn_peer_streams_left_bidi"

external peer_streams_left_uni : conn -> int
  = "ocaml_quiche_conn_peer_streams_left_uni"

(* Snapshot of streams with pending data / writable capacity. *)
external readable_ids : conn -> int array = "ocaml_quiche_conn_readable_ids"
external writable_ids : conn -> int array = "ocaml_quiche_conn_writable_ids"

external dgram_recv_queue_len : conn -> int
  = "ocaml_quiche_conn_dgram_recv_queue_len"

external dgram_send_stub : conn -> Bigstringaf.t -> int -> int -> int
  = "ocaml_quiche_conn_dgram_send"

let dgram_send t buf ~off ~len = check_unit (dgram_send_stub t buf off len)

external dgram_recv_stub : conn -> Bigstringaf.t -> int -> int -> int
  = "ocaml_quiche_conn_dgram_recv"

let dgram_recv t buf ~off ~len = check (dgram_recv_stub t buf off len)

external dgram_max_writable_len_stub : conn -> int
  = "ocaml_quiche_conn_dgram_max_writable_len"

(* None when the peer does not accept DATAGRAM frames. *)
let dgram_max_writable_len t =
  let n = dgram_max_writable_len_stub t in
  if n < 0 then None else Some n

external application_proto_stub : conn -> string
  = "ocaml_quiche_conn_application_proto"

let application_proto t =
  match application_proto_stub t with "" -> None | s -> Some s

external peer_cert_stub : conn -> string = "ocaml_quiche_conn_peer_cert"

let peer_cert t = match peer_cert_stub t with "" -> None | der -> Some der

external peer_error_stub : conn -> bool * bool * int * string
  = "ocaml_quiche_conn_peer_error"

external local_error_stub : conn -> bool * bool * int * string
  = "ocaml_quiche_conn_local_error"

type conn_error = { is_app : bool; code : int; reason : string }

let conn_error_of = function
  | false, _, _, _ -> None
  | true, is_app, code, reason -> Some { is_app; code; reason }

let peer_error t = conn_error_of (peer_error_stub t)
let local_error t = conn_error_of (local_error_stub t)

external set_qlog_path_stub : conn -> string -> string -> string -> bool
  = "ocaml_quiche_conn_set_qlog_path"

(* false when qlog support is compiled out of libquiche (Homebrew bottle). *)
let set_qlog_path t ~path ~title ~description =
  set_qlog_path_stub t path title description
