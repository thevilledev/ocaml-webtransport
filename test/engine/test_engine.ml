(* Deterministic engine tests over the mock backend: the test plays "peer",
   injecting handshake, streams and bytes, and asserts on notifications and
   on what the engine wrote. *)

module E = Webtransport.Engine
module Settings = Webtransport.Settings
module Capsule = Webtransport.Capsule
module Wire = Webtransport.Wire
module Varint = Webtransport.Varint
module Fs = Wt_qpack.Field_section
module M = Wt_mock.Mock_backend

let frame ty payload =
  let b = Buffer.create 16 in
  Varint.add_buffer b ty;
  Varint.add_buffer b (String.length payload);
  Buffer.add_string b payload;
  Buffer.contents b

let vstr v =
  let b = Buffer.create 4 in
  Varint.add_buffer b v;
  Buffer.contents b

let mk role =
  let m = M.make role in
  let eng = E.create ~role (E.C ((module M), m)) in
  (m, eng)

(* Parses the engine's control-stream output: uni type + SETTINGS frame. *)
let parse_control_out sent =
  match Varint.get_string sent ~pos:0 with
  | Some (ty, pos) when ty = Wire.Uni_stream.control -> (
      match Varint.get_string sent ~pos with
      | Some (fty, pos) when fty = Wire.Frame.settings -> (
          match Varint.get_string sent ~pos with
          | Some (len, pos) -> Settings.decode (String.sub sent pos len)
          | None -> Error "no settings length")
      | _ -> Error "first frame not SETTINGS")
  | _ -> Error "not a control stream"

(* Parses one HEADERS frame at [pos]; returns fields and end position. *)
let parse_headers_frame sent ~pos =
  match Varint.get_string sent ~pos with
  | Some (fty, pos) when fty = Wire.Frame.headers -> (
      match Varint.get_string sent ~pos with
      | Some (len, pos) -> (
          match Fs.decode (String.sub sent pos len) with
          | Ok fields -> Ok (fields, pos + len)
          | Error e -> Error e)
      | None -> Error "no headers length")
  | _ -> Error "not a HEADERS frame"

let client_settings = Settings.encode (Settings.for_client ())
let server_settings = Settings.encode (Settings.for_server ())

let connect_fields =
  [
    (":method", "CONNECT");
    (":protocol", "webtransport");
    (":scheme", "https");
    (":authority", "example.com:4433");
    (":path", "/echo");
    ("origin", "https://example.com");
    ("sec-webtransport-http3-draft02", "1");
  ]

(* Drives a server engine to the point where session [sid=0] is requested. *)
let server_with_request () =
  let m, eng = mk `Server in
  M.establish m;
  let n1 = E.process eng in
  Alcotest.(check int) "no notifications yet" 0 (List.length n1);
  (* Engine opened its control stream (first server uni id = 3). *)
  (match parse_control_out (M.sent m ~id:3) with
  | Ok s ->
      Alcotest.(check bool) "settings: ecp" true s.Settings.enable_connect_protocol;
      Alcotest.(check bool) "settings: legacy wt" true s.Settings.enable_webtransport;
      Alcotest.(check bool) "settings: wt_enabled" true s.Settings.wt_enabled
  | Error e -> Alcotest.fail ("control out: " ^ e));
  (* Peer control stream with client SETTINGS. *)
  M.peer_open m ~id:2 ~dir:`Uni;
  M.peer_data m ~id:2 (vstr Wire.Uni_stream.control ^ frame Wire.Frame.settings client_settings);
  ignore (E.process eng);
  (* Extended CONNECT on bidi stream 0. *)
  M.peer_open m ~id:0 ~dir:`Bidi;
  M.peer_data m ~id:0 (frame Wire.Frame.headers (Fs.encode connect_fields));
  let notifs = E.process eng in
  (m, eng, notifs)

let test_server_accept () =
  let m, eng, notifs = server_with_request () in
  (match notifs with
  | [ E.Incoming_session { sid = 0; req } ] ->
      Alcotest.(check string) "authority" "example.com:4433" req.E.authority;
      Alcotest.(check string) "path" "/echo" req.E.path;
      Alcotest.(check (option string)) "origin" (Some "https://example.com") req.E.origin;
      Alcotest.(check string) "protocol" "webtransport" req.E.protocol
  | _ -> Alcotest.fail "expected Incoming_session");
  E.accept_session eng ~sid:0;
  (match E.process eng with
  | [ E.Session_established { sid = 0 } ] -> ()
  | _ -> Alcotest.fail "expected Session_established");
  (match parse_headers_frame (M.sent m ~id:0) ~pos:0 with
  | Ok (fields, _) ->
      Alcotest.(check (list (pair string string)))
        "response"
        [ (":status", "200"); ("sec-webtransport-http3-draft", "draft02") ]
        fields
  | Error e -> Alcotest.fail e);
  Alcotest.(check bool) "no fin on connect stream" false (M.sent_fin m ~id:0);
  (m, eng)

let test_server_accept_unit () = ignore (test_server_accept ())

let test_server_reject () =
  let m, eng, _ = server_with_request () in
  E.reject_session eng ~sid:0 ~status:403;
  ignore (E.process eng);
  (match parse_headers_frame (M.sent m ~id:0) ~pos:0 with
  | Ok (fields, _) ->
      Alcotest.(check (list (pair string string))) "403" [ (":status", "403") ] fields
  | Error e -> Alcotest.fail e);
  Alcotest.(check bool) "fin after reject" true (M.sent_fin m ~id:0)

let test_server_non_wt_request () =
  let m, eng = mk `Server in
  M.establish m;
  ignore (E.process eng);
  M.peer_open m ~id:0 ~dir:`Bidi;
  let get_fields =
    [ (":method", "GET"); (":scheme", "https"); (":authority", "x"); (":path", "/") ]
  in
  M.peer_data m ~id:0 (frame Wire.Frame.headers (Fs.encode get_fields));
  let notifs = E.process eng in
  Alcotest.(check int) "no session notif" 0 (List.length notifs);
  (match parse_headers_frame (M.sent m ~id:0) ~pos:0 with
  | Ok (fields, _) ->
      Alcotest.(check (list (pair string string))) "404" [ (":status", "404") ] fields
  | Error e -> Alcotest.fail e);
  Alcotest.(check bool) "fin" true (M.sent_fin m ~id:0)

let test_peer_close_capsule () =
  let m, eng = test_server_accept () in
  let capsule = Capsule.encode_close ~code:7 ~message:"kthxbye" in
  M.peer_data m ~id:0 (frame Wire.Frame.data capsule);
  match E.process eng with
  | [ E.Session_peer_closed { sid = 0; code = 7; message = "kthxbye"; abrupt = false } ] -> ()
  | _ -> Alcotest.fail "expected Session_peer_closed(7)"

let test_peer_clean_fin () =
  let m, eng = test_server_accept () in
  M.peer_data m ~id:0 "" ~fin:true;
  match E.process eng with
  | [ E.Session_peer_closed { sid = 0; code = 0; message = ""; abrupt = false } ] -> ()
  | _ -> Alcotest.fail "expected clean close(0)"

let test_local_close () =
  let m, eng = test_server_accept () in
  E.close_session eng ~sid:0 ~code:42 ~message:"done";
  ignore (E.process eng);
  let sent = M.sent m ~id:0 in
  (* Skip the response HEADERS frame, then expect DATA(close capsule) + fin. *)
  (match parse_headers_frame sent ~pos:0 with
  | Error e -> Alcotest.fail e
  | Ok (_, pos) -> (
      match Varint.get_string sent ~pos with
      | Some (fty, pos) when fty = Wire.Frame.data -> (
          match Varint.get_string sent ~pos with
          | Some (len, pos) -> (
              let capsule = String.sub sent pos len in
              let p = Capsule.create_parser () in
              Capsule.feed p capsule;
              match Capsule.next p with
              | `Capsule (ty, payload) ->
                  Alcotest.(check int) "capsule type" Wire.Capsule_type.wt_close_session ty;
                  (match Capsule.decode_close payload with
                  | Ok (42, "done") -> ()
                  | _ -> Alcotest.fail "bad close payload")
              | _ -> Alcotest.fail "no capsule in DATA")
          | None -> Alcotest.fail "no DATA length")
      | _ -> Alcotest.fail "expected DATA frame"));
  Alcotest.(check bool) "fin sent" true (M.sent_fin m ~id:0)

let test_datagram_routing () =
  let m, eng = test_server_accept () in
  M.peer_dgram m (vstr 0 ^ "hello-dgram");
  (match E.process eng with
  | [ E.Wt_datagram { sid = 0; payload = "hello-dgram" } ] -> ()
  | _ -> Alcotest.fail "expected Wt_datagram");
  (* Datagram for an unknown session is dropped. *)
  M.peer_dgram m (vstr 3 ^ "nope");
  match E.process eng with
  | [] -> ()
  | _ -> Alcotest.fail "unknown-session datagram not dropped"

let test_wt_stream_attach () =
  let m, eng = test_server_accept () in
  (* Client opens a WT bidi stream for session 0: 0x41 varint + sid + data. *)
  M.peer_open m ~id:4 ~dir:`Bidi;
  M.peer_data m ~id:4 (vstr Wire.Frame.wt_stream ^ vstr 0 ^ "early");
  (match E.process eng with
  | [ E.Wt_stream_opened { sid = 0; stream_id = 4; dir = `Bidi };
      E.Wt_stream_readable { stream_id = 4 } ] -> ()
  | _ -> Alcotest.fail "expected open+readable");
  (* The engine consumed the prefix; buffered app bytes come back through
     read_attached. *)
  let buf = Bigstringaf.create 64 in
  (match E.read_attached eng ~id:4 buf ~off:0 ~len:64 with
  | Ok (5, false) ->
      Alcotest.(check string) "early bytes" "early" (Bigstringaf.substring buf ~off:0 ~len:5)
  | _ -> Alcotest.fail "read_attached");
  (* A uni WT stream too. *)
  M.peer_open m ~id:6 ~dir:`Uni;
  M.peer_data m ~id:6 (vstr Wire.Uni_stream.wt ^ vstr 0 ^ "u") ~fin:true;
  match E.process eng with
  | [ E.Wt_stream_opened { sid = 0; stream_id = 6; dir = `Uni };
      E.Wt_stream_readable { stream_id = 6 } ] -> ()
  | _ -> Alcotest.fail "expected uni open+readable"

let test_qpack_streams_drained () =
  let m, eng = mk `Server in
  M.establish m;
  ignore (E.process eng);
  M.peer_open m ~id:2 ~dir:`Uni;
  M.peer_data m ~id:2 (vstr Wire.Uni_stream.qpack_encoder ^ "garbage-instructions");
  M.peer_open m ~id:6 ~dir:`Uni;
  M.peer_data m ~id:6 (vstr Wire.Uni_stream.qpack_decoder ^ "more");
  let notifs = E.process eng in
  Alcotest.(check int) "silently drained" 0 (List.length notifs);
  Alcotest.(check (option int)) "no reset enc" None (M.reset_code m ~id:2);
  Alcotest.(check (option int)) "no reset dec" None (M.reset_code m ~id:6)

let test_client_flow () =
  let m, eng = mk `Client in
  M.establish m;
  ignore (E.process eng);
  (* Client control stream is uni id 2. *)
  (match parse_control_out (M.sent m ~id:2) with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("client control: " ^ e));
  (* Request queued before server SETTINGS: nothing sent yet. *)
  E.connect_session eng ~origin:"https://app.example"
    ~authority:"example.com:4433" ~path:"/echo" ();
  ignore (E.process eng);
  Alcotest.(check string) "no CONNECT yet" "" (M.sent m ~id:0);
  (* Server SETTINGS arrive (modern block => webtransport-h3 token). *)
  M.peer_open m ~id:3 ~dir:`Uni;
  M.peer_data m ~id:3 (vstr Wire.Uni_stream.control ^ frame Wire.Frame.settings server_settings);
  ignore (E.process eng);
  (match parse_headers_frame (M.sent m ~id:0) ~pos:0 with
  | Ok (fields, _) ->
      let get n = List.assoc_opt n fields in
      Alcotest.(check (option string)) "method" (Some "CONNECT") (get ":method");
      Alcotest.(check (option string)) "protocol" (Some "webtransport-h3") (get ":protocol");
      Alcotest.(check (option string)) "authority" (Some "example.com:4433") (get ":authority");
      Alcotest.(check (option string)) "path" (Some "/echo") (get ":path");
      Alcotest.(check (option string)) "origin" (Some "https://app.example") (get "origin")
  | Error e -> Alcotest.fail e);
  (* 200 response -> established. *)
  M.peer_data m ~id:0 (frame Wire.Frame.headers (Fs.encode [ (":status", "200") ]));
  (match E.process eng with
  | [ E.Session_established { sid = 0 } ] -> ()
  | _ -> Alcotest.fail "expected established");
  (* Close from our side. *)
  E.close_session eng ~sid:0 ~code:1 ~message:"bye";
  Alcotest.(check bool) "fin" true (M.sent_fin m ~id:0)

let test_client_rejected () =
  let m, eng = mk `Client in
  M.establish m;
  ignore (E.process eng);
  E.connect_session eng ~authority:"example.com" ~path:"/" ();
  M.peer_open m ~id:3 ~dir:`Uni;
  M.peer_data m ~id:3 (vstr Wire.Uni_stream.control ^ frame Wire.Frame.settings server_settings);
  ignore (E.process eng);
  M.peer_data m ~id:0 (frame Wire.Frame.headers (Fs.encode [ (":status", "403") ]));
  match E.process eng with
  | [ E.Session_rejected { sid = 0; status = 403 } ] -> ()
  | _ -> Alcotest.fail "expected rejection"

let test_split_delivery () =
  (* The whole request arriving one byte at a time must still parse. *)
  let m, eng = mk `Server in
  M.establish m;
  ignore (E.process eng);
  M.peer_open m ~id:0 ~dir:`Bidi;
  let bytes = frame Wire.Frame.headers (Fs.encode connect_fields) in
  let got = ref [] in
  String.iter
    (fun c ->
      M.peer_data m ~id:0 (String.make 1 c);
      got := !got @ E.process eng)
    bytes;
  match !got with
  | [ E.Incoming_session { sid = 0; _ } ] -> ()
  | _ -> Alcotest.fail "split delivery failed"

let () =
  Alcotest.run "engine"
    [
      ( "server",
        [
          Alcotest.test_case "accept flow" `Quick test_server_accept_unit;
          Alcotest.test_case "reject flow" `Quick test_server_reject;
          Alcotest.test_case "non-WT request -> 404" `Quick test_server_non_wt_request;
          Alcotest.test_case "peer close capsule" `Quick test_peer_close_capsule;
          Alcotest.test_case "peer clean fin" `Quick test_peer_clean_fin;
          Alcotest.test_case "local close" `Quick test_local_close;
          Alcotest.test_case "datagram routing" `Quick test_datagram_routing;
          Alcotest.test_case "wt stream attach" `Quick test_wt_stream_attach;
          Alcotest.test_case "qpack streams drained" `Quick test_qpack_streams_drained;
          Alcotest.test_case "split delivery" `Quick test_split_delivery;
        ] );
      ( "client",
        [
          Alcotest.test_case "connect flow" `Quick test_client_flow;
          Alcotest.test_case "rejected" `Quick test_client_rejected;
        ] );
    ]
