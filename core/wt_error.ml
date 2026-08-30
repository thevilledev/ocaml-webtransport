(* Error codes.

   WebTransport application error codes (u32) map into a reserved range of the
   HTTP/3 error space, skipping the HTTP/3 GREASE codepoints
   (draft-ietf-webtrans-http3-16, section 4.4). All codes are OCaml [int]s;
   the H3 error space is a QUIC varint, which fits [max_int] exactly. *)

let first = 0x52e4a40fa8db
let last = 0x52e5ac983162

(* WebTransport-defined HTTP/3 error codes (draft-16, section 9.5). *)
let wt_buffered_stream_rejected = 0x3994bd84
let wt_session_gone = 0x170d7b68
let wt_flow_control_error = 0x045d4487
let wt_application_error_first = first
let wt_application_error_last = last

(* RFC 9114 / RFC 9297 error codes the engine needs. *)
let h3_no_error = 0x100
let h3_general_protocol_error = 0x101
let h3_stream_creation_error = 0x103
let h3_closed_critical_stream = 0x104
let h3_frame_error = 0x106
let h3_id_error = 0x108
let h3_settings_error = 0x109
let h3_request_rejected = 0x10b
let h3_message_error = 0x10e
let h3_datagram_error = 0x33
let qpack_decompression_failed = 0x200

(* WebTransport application error code (u32) -> HTTP/3 error code. *)
let to_h3 n =
  if n < 0 || n > 0xffff_ffff then invalid_arg "Wt_error.to_h3: not a u32";
  first + n + (n / 0x1e)

(* HTTP/3 error code -> WebTransport application error code. [None] when the
   code is outside the reserved range or is an H3 GREASE codepoint. *)
let of_h3 h =
  if h < first || h > last then None
  else if (h - 0x21) mod 0x1f = 0 then None
  else
    let shifted = h - first in
    Some (shifted - (shifted / 0x1f))
