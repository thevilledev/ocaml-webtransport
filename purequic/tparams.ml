(* QUIC transport parameters (RFC 9000 s.18), plus max_datagram_frame_size
   (RFC 9221) and the reliable-reset parameter
   (draft-ietf-quic-reliable-stream-reset-10: 0x1d, and the pre-draft-08
   codepoint 0x17f7586d2cb571 — we send and accept both, mirroring
   quic-go). Unknown parameters are ignored, as required. *)

let id_reliable_reset = 0x1d
let id_reliable_reset_legacy = 0x17f7586d2cb571
let id_max_datagram_frame_size = 0x20

type t = {
  original_dcid : string option;  (* server only *)
  max_idle_timeout_ms : int;
  stateless_reset_token : string option;  (* server only, 16 bytes *)
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
  retry_scid : string option;  (* server only, after Retry *)
  max_datagram_frame_size : int option;  (* RFC 9221 *)
  reliable_reset : bool;  (* either codepoint received / to be sent *)
}

let default =
  {
    original_dcid = None;
    max_idle_timeout_ms = 0;
    stateless_reset_token = None;
    max_udp_payload_size = 65527;
    initial_max_data = 0;
    initial_max_stream_data_bidi_local = 0;
    initial_max_stream_data_bidi_remote = 0;
    initial_max_stream_data_uni = 0;
    initial_max_streams_bidi = 0;
    initial_max_streams_uni = 0;
    ack_delay_exponent = 3;
    max_ack_delay_ms = 25;
    disable_active_migration = false;
    active_connection_id_limit = 2;
    initial_scid = None;
    retry_scid = None;
    max_datagram_frame_size = None;
    reliable_reset = false;
  }

(* ---- encoding ---- *)

let add_param b id value =
  Varint.add_buffer b id;
  Varint.add_buffer b (String.length value);
  Buffer.add_string b value

let add_varint_param b id v =
  let vb = Buffer.create 8 in
  Varint.add_buffer vb v;
  add_param b id (Buffer.contents vb)

let add_flag_param b id = add_param b id ""

let encode t =
  let b = Buffer.create 128 in
  Option.iter (add_param b 0x00) t.original_dcid;
  if t.max_idle_timeout_ms > 0 then add_varint_param b 0x01 t.max_idle_timeout_ms;
  Option.iter (add_param b 0x02) t.stateless_reset_token;
  add_varint_param b 0x03 t.max_udp_payload_size;
  if t.initial_max_data > 0 then add_varint_param b 0x04 t.initial_max_data;
  if t.initial_max_stream_data_bidi_local > 0 then
    add_varint_param b 0x05 t.initial_max_stream_data_bidi_local;
  if t.initial_max_stream_data_bidi_remote > 0 then
    add_varint_param b 0x06 t.initial_max_stream_data_bidi_remote;
  if t.initial_max_stream_data_uni > 0 then
    add_varint_param b 0x07 t.initial_max_stream_data_uni;
  if t.initial_max_streams_bidi > 0 then
    add_varint_param b 0x08 t.initial_max_streams_bidi;
  if t.initial_max_streams_uni > 0 then
    add_varint_param b 0x09 t.initial_max_streams_uni;
  if t.ack_delay_exponent <> 3 then add_varint_param b 0x0a t.ack_delay_exponent;
  if t.max_ack_delay_ms <> 25 then add_varint_param b 0x0b t.max_ack_delay_ms;
  if t.disable_active_migration then add_flag_param b 0x0c;
  if t.active_connection_id_limit <> 2 then
    add_varint_param b 0x0e t.active_connection_id_limit;
  Option.iter (add_param b 0x0f) t.initial_scid;
  Option.iter (add_param b 0x10) t.retry_scid;
  Option.iter (add_varint_param b id_max_datagram_frame_size)
    t.max_datagram_frame_size;
  if t.reliable_reset then begin
    add_flag_param b id_reliable_reset;
    add_flag_param b id_reliable_reset_legacy
  end;
  Buffer.contents b

(* ---- decoding ---- *)

let varint_value s =
  match Varint.get_string s ~pos:0 with
  | Some (v, n) when n = String.length s -> Some v
  | _ -> None

(* Decode; unknown ids are skipped. [Error] only on structural garbage or
   RFC-invalid values. *)
let decode s =
  let len = String.length s in
  let rec go acc pos =
    if pos >= len then Ok acc
    else
      match Varint.get_string s ~pos with
      | None -> Error "tparams: bad id"
      | Some (id, pos) -> (
          match Varint.get_string s ~pos with
          | None -> Error "tparams: bad length"
          | Some (plen, pos) ->
              if pos + plen > len then Error "tparams: truncated"
              else
                let v = String.sub s pos plen in
                let next = pos + plen in
                let vi () = varint_value v in
                let res =
                  match id with
                  | 0x00 -> Ok { acc with original_dcid = Some v }
                  | 0x01 -> (
                      match vi () with
                      | Some ms -> Ok { acc with max_idle_timeout_ms = ms }
                      | None -> Error "tparams: idle")
                  | 0x02 ->
                      if plen <> 16 then Error "tparams: reset token"
                      else Ok { acc with stateless_reset_token = Some v }
                  | 0x03 -> (
                      match vi () with
                      | Some n when n >= 1200 ->
                          Ok { acc with max_udp_payload_size = n }
                      | _ -> Error "tparams: udp payload")
                  | 0x04 -> (
                      match vi () with
                      | Some n -> Ok { acc with initial_max_data = n }
                      | None -> Error "tparams: max data")
                  | 0x05 -> (
                      match vi () with
                      | Some n ->
                          Ok { acc with initial_max_stream_data_bidi_local = n }
                      | None -> Error "tparams: msd bl")
                  | 0x06 -> (
                      match vi () with
                      | Some n ->
                          Ok { acc with initial_max_stream_data_bidi_remote = n }
                      | None -> Error "tparams: msd br")
                  | 0x07 -> (
                      match vi () with
                      | Some n -> Ok { acc with initial_max_stream_data_uni = n }
                      | None -> Error "tparams: msd u")
                  | 0x08 -> (
                      match vi () with
                      | Some n when n <= 1 lsl 60 ->
                          Ok { acc with initial_max_streams_bidi = n }
                      | _ -> Error "tparams: max streams bidi")
                  | 0x09 -> (
                      match vi () with
                      | Some n when n <= 1 lsl 60 ->
                          Ok { acc with initial_max_streams_uni = n }
                      | _ -> Error "tparams: max streams uni")
                  | 0x0a -> (
                      match vi () with
                      | Some n when n <= 20 ->
                          Ok { acc with ack_delay_exponent = n }
                      | _ -> Error "tparams: ack exp")
                  | 0x0b -> (
                      match vi () with
                      | Some n when n < 1 lsl 14 ->
                          Ok { acc with max_ack_delay_ms = n }
                      | _ -> Error "tparams: max ack delay")
                  | 0x0c ->
                      if plen <> 0 then Error "tparams: dam"
                      else Ok { acc with disable_active_migration = true }
                  | 0x0d -> Ok acc (* preferred_address: ignored *)
                  | 0x0e -> (
                      match vi () with
                      | Some n when n >= 2 ->
                          Ok { acc with active_connection_id_limit = n }
                      | _ -> Error "tparams: cid limit")
                  | 0x0f -> Ok { acc with initial_scid = Some v }
                  | 0x10 -> Ok { acc with retry_scid = Some v }
                  | id when id = id_max_datagram_frame_size -> (
                      match vi () with
                      | Some n -> Ok { acc with max_datagram_frame_size = Some n }
                      | None -> Error "tparams: dgram size")
                  | id
                    when id = id_reliable_reset || id = id_reliable_reset_legacy
                    ->
                      (* empty per draft-10; tolerate a varint payload from
                         older peers *)
                      Ok { acc with reliable_reset = true }
                  | _ -> Ok acc (* unknown: ignore *)
                in
                match res with Ok acc -> go acc next | Error _ as e -> e)
  in
  go default 0
