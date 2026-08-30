(** QUIC transport parameters (RFC 9000 s.18), max_datagram_frame_size
    (RFC 9221) and the reliable-reset parameter (both draft-10's 0x1d and
    the pre-draft-08 codepoint). Unknown parameters are ignored. *)

val id_reliable_reset : int
val id_reliable_reset_legacy : int
val id_max_datagram_frame_size : int

type t = {
  original_dcid : string option;
  max_idle_timeout_ms : int;
  stateless_reset_token : string option;
  max_udp_payload_size : int;
  initial_max_data : int;
  initial_max_stream_data_bidi_local : int;
  initial_max_stream_data_bidi_remote : int;
  initial_max_stream_data_uni : int;
  initial_max_streams_bidi : int;
  initial_max_streams_uni : int;
  ack_delay_exponent : int;
  max_ack_delay_ms : int;
  disable_active_migration : bool;
  active_connection_id_limit : int;
  initial_scid : string option;
  retry_scid : string option;
  max_datagram_frame_size : int option;
  reliable_reset : bool;
}

val default : t
val encode : t -> string
val decode : string -> (t, string) result
