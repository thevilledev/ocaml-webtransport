(* HTTP/3 SETTINGS encoding/decoding, with the WebTransport compatibility
   view of a peer's settings. *)

type t = {
  enable_connect_protocol : bool;
  h3_datagram : bool;
  enable_webtransport : bool;  (* legacy 0x2b603742 *)
  wt_enabled : bool;  (* 0x2c7cf000 *)
  wt_max_sessions : int;  (* max of the draft-07 and draft-13 variants *)
  qpack_max_table_capacity : int;
  qpack_blocked_streams : int;
  max_field_section_size : int option;
  wt_initial_max_data : int;
  wt_initial_max_streams_uni : int;
  wt_initial_max_streams_bidi : int;
  raw : (int * int) list;
}

let default =
  {
    enable_connect_protocol = false;
    h3_datagram = false;
    enable_webtransport = false;
    wt_enabled = false;
    wt_max_sessions = 0;
    qpack_max_table_capacity = 0;
    qpack_blocked_streams = 0;
    max_field_section_size = None;
    wt_initial_max_data = 0;
    wt_initial_max_streams_uni = 0;
    wt_initial_max_streams_bidi = 0;
    raw = [];
  }

(* Encodes a SETTINGS frame payload (identifier/value varint pairs). *)
let encode entries =
  let buf = Buffer.create 64 in
  List.iter
    (fun (id, v) ->
      Varint.add_buffer buf id;
      Varint.add_buffer buf v)
    entries;
  Buffer.contents buf

(* Decodes a SETTINGS frame payload. Enforces the MUST-be-boolean rules that
   browsers also enforce (RFC 9297 for 0x33, draft-16 for WT_ENABLED). *)
let decode payload =
  let ( let* ) = Result.bind in
  let rec pairs pos acc =
    if pos >= String.length payload then Ok (List.rev acc)
    else
      let* id, pos =
        match Varint.get_string payload ~pos with
        | Some r -> Ok r
        | None -> Error "truncated setting id"
      in
      let* v, pos =
        match Varint.get_string payload ~pos with
        | Some r -> Ok r
        | None -> Error "truncated setting value"
      in
      pairs pos ((id, v) :: acc)
  in
  let* raw = pairs 0 [] in
  let bool_setting name v =
    if v = 0 then Ok false
    else if v = 1 then Ok true
    else Error (name ^ " must be 0 or 1")
  in
  List.fold_left
    (fun acc (id, v) ->
      let* t = acc in
      if id = Wire.Setting.enable_connect_protocol then
        let* b = bool_setting "ENABLE_CONNECT_PROTOCOL" v in
        Ok { t with enable_connect_protocol = b }
      else if id = Wire.Setting.h3_datagram then
        let* b = bool_setting "H3_DATAGRAM" v in
        Ok { t with h3_datagram = b }
      else if id = Wire.Setting.enable_webtransport then
        let* b = bool_setting "ENABLE_WEBTRANSPORT" v in
        Ok { t with enable_webtransport = b }
      else if id = Wire.Setting.wt_enabled then
        let* b = bool_setting "WT_ENABLED" v in
        Ok { t with wt_enabled = b }
      else if
        id = Wire.Setting.wt_max_sessions
        || id = Wire.Setting.webtransport_max_sessions_draft07
      then Ok { t with wt_max_sessions = max t.wt_max_sessions v }
      else if id = Wire.Setting.qpack_max_table_capacity then
        Ok { t with qpack_max_table_capacity = v }
      else if id = Wire.Setting.qpack_blocked_streams then
        Ok { t with qpack_blocked_streams = v }
      else if id = Wire.Setting.max_field_section_size then
        Ok { t with max_field_section_size = Some v }
      else if id = Wire.Setting.wt_initial_max_data then
        Ok { t with wt_initial_max_data = v }
      else if id = Wire.Setting.wt_initial_max_streams_uni then
        Ok { t with wt_initial_max_streams_uni = v }
      else if id = Wire.Setting.wt_initial_max_streams_bidi then
        Ok { t with wt_initial_max_streams_bidi = v }
      else Ok t)
    (Ok { default with raw })
    raw

(* The single server SETTINGS block that reaches Chrome (draft-02), Firefox
   (draft-02), Safari (draft-13/14) and spec-current peers (draft-15/16)
   simultaneously. *)
let for_server ?(wt_max_sessions = 1024) ?(max_field_section_size = 16_384)
    ?(fc = (0, 0, 0)) () =
  let data, uni, bidi = fc in
  [
    (Wire.Setting.qpack_max_table_capacity, 0);
    (Wire.Setting.qpack_blocked_streams, 0);
    (Wire.Setting.max_field_section_size, max_field_section_size);
    (Wire.Setting.enable_connect_protocol, 1);
    (Wire.Setting.h3_datagram, 1);
    (Wire.Setting.enable_webtransport, 1);
    (Wire.Setting.wt_enabled, 1);
    (Wire.Setting.wt_max_sessions, wt_max_sessions);
  ]
  @ (if data > 0 then [ (Wire.Setting.wt_initial_max_data, data) ] else [])
  @ (if uni > 0 then [ (Wire.Setting.wt_initial_max_streams_uni, uni) ] else [])
  @
  if bidi > 0 then [ (Wire.Setting.wt_initial_max_streams_bidi, bidi) ] else []

let for_client ?(max_field_section_size = 16_384) ?(fc = (0, 0, 0)) () =
  let data, uni, bidi = fc in
  [
    (Wire.Setting.qpack_max_table_capacity, 0);
    (Wire.Setting.qpack_blocked_streams, 0);
    (Wire.Setting.max_field_section_size, max_field_section_size);
    (Wire.Setting.h3_datagram, 1);
    (Wire.Setting.enable_webtransport, 1);
    (Wire.Setting.wt_enabled, 1);
  ]
  @ (if data > 0 then [ (Wire.Setting.wt_initial_max_data, data) ] else [])
  @ (if uni > 0 then [ (Wire.Setting.wt_initial_max_streams_uni, uni) ] else [])
  @
  if bidi > 0 then [ (Wire.Setting.wt_initial_max_streams_bidi, bidi) ] else []

(* Client-side: can WebTransport sessions be attempted against this server? *)
let server_supports_webtransport t =
  t.enable_connect_protocol && t.h3_datagram
  && (t.enable_webtransport || t.wt_enabled || t.wt_max_sessions > 0)

(* Which [:protocol] token to send: prefer the draft-15+ token iff the server
   advertised WT_ENABLED. *)
let protocol_token_for t =
  if t.wt_enabled then Wire.protocol_token else Wire.protocol_token_legacy
