(* HTTP/3 and WebTransport wire constants.

   Sources: RFC 9114 (H3), RFC 9204 (QPACK), RFC 9220 (extended CONNECT),
   RFC 9297 (HTTP datagrams), draft-ietf-webtrans-http3 (-02 through -16;
   the data-plane codepoints have been stable since -02). *)

module Frame = struct
  let data = 0x0
  let headers = 0x1
  let settings = 0x4
  let goaway = 0x7

  (* Not a real framed type: no length field follows, only a session id. *)
  let wt_stream = 0x41
end

module Uni_stream = struct
  let control = 0x0
  let push = 0x1
  let qpack_encoder = 0x2
  let qpack_decoder = 0x3
  let wt = 0x54
end

module Setting = struct
  let qpack_max_table_capacity = 0x1
  let max_field_section_size = 0x6
  let qpack_blocked_streams = 0x7
  let enable_connect_protocol = 0x8 (* RFC 9220 *)
  let h3_datagram = 0x33 (* RFC 9297 *)
  let enable_webtransport = 0x2b603742 (* draft-02: what browsers require *)
  let webtransport_max_sessions_draft07 = 0xc671706a (* draft-07..12 *)
  let wt_max_sessions = 0x14e9cd29 (* draft-13/14: Safari wants this *)
  let wt_enabled = 0x2c7cf000 (* draft-15/16 *)
  let wt_initial_max_data = 0x2b61
  let wt_initial_max_streams_uni = 0x2b64
  let wt_initial_max_streams_bidi = 0x2b65
end

module Capsule_type = struct
  let wt_close_session = 0x2843
  let wt_drain_session = 0x78ae
  let wt_max_data = 0x190B4D3D
  let wt_max_streams_bidi = 0x190B4D3F
  let wt_max_streams_uni = 0x190B4D40
  let wt_data_blocked = 0x190B4D41
  let wt_streams_blocked_bidi = 0x190B4D43
  let wt_streams_blocked_uni = 0x190B4D44
end

(* Accepted [:protocol] tokens: browsers send the draft-02..14 token, spec
   peers the draft-15+ one. *)
let protocol_token_legacy = "webtransport"
let protocol_token = "webtransport-h3"
