module Varint = Webtransport.Varint
module Wt_error = Webtransport.Wt_error

let bs s = Bigstringaf.of_string ~off:0 ~len:(String.length s) s

(* RFC 9000, appendix A.1 vectors. *)
let rfc9000_vectors =
  [
    ("\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 151288809941952652, 8);
    ("\x9d\x7f\x3e\x7d", 494878333, 4);
    ("\x7b\xbd", 15293, 2);
    ("\x25", 37, 1);
    ("\x40\x25", 37, 2) (* non-minimal encoding of 37 *);
  ]

let test_varint_decode () =
  List.iter
    (fun (bytes, value, consumed) ->
      let buf = bs bytes in
      match Varint.get buf ~off:0 ~len:(String.length bytes) with
      | Some (v, n) ->
          Alcotest.(check int) "value" value v;
          Alcotest.(check int) "consumed" consumed n
      | None -> Alcotest.fail "unexpected None")
    rfc9000_vectors

let test_varint_truncated () =
  let buf = bs "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c" in
  for len = 0 to 7 do
    match Varint.get buf ~off:0 ~len with
    | None -> ()
    | Some _ -> Alcotest.fail (Printf.sprintf "len=%d should be short" len)
  done;
  Alcotest.(check bool) "empty" true (Varint.get buf ~off:8 ~len:0 = None)

let boundaries =
  [
    0; 1; 63; 64; 16383; 16384;
    (1 lsl 30) - 1; 1 lsl 30;
    Varint.max_value - 1; Varint.max_value;
  ]

let test_varint_roundtrip () =
  let buf = Bigstringaf.create 8 in
  let check v =
    let n = Varint.put buf ~off:0 v in
    Alcotest.(check int) "size" (Varint.size v) n;
    match Varint.get buf ~off:0 ~len:n with
    | Some (v', n') ->
        Alcotest.(check int) "roundtrip value" v v';
        Alcotest.(check int) "roundtrip consumed" n n'
    | None -> Alcotest.fail "roundtrip decode failed"
  in
  List.iter check boundaries;
  Random.init 0xc0ffee;
  for _ = 1 to 100_000 do
    check (Random.full_int Varint.max_value)
  done

let test_varint_to_string () =
  Alcotest.(check string) "0" "\x00" (Varint.to_string 0);
  Alcotest.(check string) "37" "\x25" (Varint.to_string 37);
  (* The WT stream-type codepoints exceed 0x3f, so on the wire they are
     2-byte varints — an easy detail to get wrong in a dispatch parser. *)
  Alcotest.(check string) "0x54" "\x40\x54" (Varint.to_string 0x54);
  Alcotest.(check string) "0x41" "\x40\x41" (Varint.to_string 0x41);
  Alcotest.(check string) "0x2843" "\x68\x43" (Varint.to_string 0x2843)

let test_error_constants () =
  Alcotest.(check int) "first" 0x52e4a40fa8db (Wt_error.to_h3 0);
  Alcotest.(check int) "last" 0x52e5ac983162 (Wt_error.to_h3 0xffff_ffff);
  Alcotest.(check (option int)) "of first" (Some 0) (Wt_error.of_h3 Wt_error.first);
  Alcotest.(check (option int))
    "of last" (Some 0xffff_ffff) (Wt_error.of_h3 Wt_error.last)

let test_error_range () =
  Alcotest.(check (option int)) "below" None (Wt_error.of_h3 (Wt_error.first - 1));
  Alcotest.(check (option int)) "above" None (Wt_error.of_h3 (Wt_error.last + 1));
  Alcotest.(check (option int)) "zero" None (Wt_error.of_h3 0);
  (* H3 GREASE codepoints (0x1f * n + 0x21) inside the range decode to None. *)
  let g = ref (Wt_error.first + (0x1f - ((Wt_error.first - 0x21) mod 0x1f))) in
  for _ = 0 to 99 do
    Alcotest.(check (option int)) "grease" None (Wt_error.of_h3 !g);
    g := !g + 0x1f
  done

let test_error_roundtrip () =
  let check n =
    let h = Wt_error.to_h3 n in
    if h < Wt_error.first || h > Wt_error.last then
      Alcotest.fail (Printf.sprintf "to_h3 %d out of range" n);
    (* Mapped codes must never land on a GREASE codepoint. *)
    if (h - 0x21) mod 0x1f = 0 then
      Alcotest.fail (Printf.sprintf "to_h3 %d hit GREASE 0x%x" n h);
    match Wt_error.of_h3 h with
    | Some n' when n' = n -> ()
    | Some n' -> Alcotest.fail (Printf.sprintf "roundtrip %d -> %d" n n')
    | None -> Alcotest.fail (Printf.sprintf "roundtrip %d -> None" n)
  in
  List.iter check [ 0; 1; 0x1d; 0x1e; 0x1f; 29; 30; 31; 0xffff; 0xffff_fffe; 0xffff_ffff ];
  Random.init 42;
  for _ = 1 to 200_000 do
    check (Random.full_int 0x1_0000_0000)
  done

let test_error_monotonic () =
  (* Strictly increasing => injective. *)
  let prev = ref (-1) in
  for n = 0 to 10_000 do
    let h = Wt_error.to_h3 n in
    if h <= !prev then Alcotest.fail "not strictly increasing";
    prev := h
  done

module Settings = Webtransport.Settings
module Capsule = Webtransport.Capsule
module Wire = Webtransport.Wire

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let test_settings_server_block () =
  let enc = Settings.encode (Settings.for_server ~wt_max_sessions:1024 ()) in
  (* Golden fragments: the exact wire encodings browsers look for. *)
  Alcotest.(check bool) "legacy ENABLE_WEBTRANSPORT=1" true
    (contains ~sub:"\xab\x60\x37\x42\x01" enc);
  Alcotest.(check bool) "WT_ENABLED=1" true
    (contains ~sub:"\xac\x7c\xf0\x00\x01" enc);
  Alcotest.(check bool) "ENABLE_CONNECT_PROTOCOL=1" true
    (contains ~sub:"\x08\x01" enc);
  Alcotest.(check bool) "WT_MAX_SESSIONS" true
    (contains ~sub:"\x94\xe9\xcd\x29" enc);
  match Settings.decode enc with
  | Error e -> Alcotest.fail e
  | Ok t ->
      Alcotest.(check bool) "ecp" true t.Settings.enable_connect_protocol;
      Alcotest.(check bool) "dgram" true t.Settings.h3_datagram;
      Alcotest.(check bool) "legacy wt" true t.Settings.enable_webtransport;
      Alcotest.(check bool) "wt_enabled" true t.Settings.wt_enabled;
      Alcotest.(check int) "max sessions" 1024 t.Settings.wt_max_sessions;
      Alcotest.(check int) "qpack cap" 0 t.Settings.qpack_max_table_capacity;
      Alcotest.(check (option int)) "mfss" (Some 16384)
        t.Settings.max_field_section_size;
      Alcotest.(check bool) "supports wt" true
        (Settings.server_supports_webtransport t)

let test_settings_validation () =
  (match Settings.decode "\x33\x02" with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "H3_DATAGRAM=2 accepted");
  (match Settings.decode "\x08" with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "truncated accepted");
  (* Unknown settings are ignored but retained raw. *)
  match Settings.decode "\x21\x2a" with
  | Ok t -> Alcotest.(check int) "raw kept" 1 (List.length t.Settings.raw)
  | Error e -> Alcotest.fail e

let test_settings_protocol_token () =
  Alcotest.(check string) "legacy" "webtransport"
    (Settings.protocol_token_for Settings.default);
  Alcotest.(check string) "modern" "webtransport-h3"
    (Settings.protocol_token_for { Settings.default with Settings.wt_enabled = true })

let feed_bytewise p s =
  String.iter (fun c -> Capsule.feed p (String.make 1 c)) s

let test_capsule_close_roundtrip () =
  let enc = Capsule.encode_close ~code:42 ~message:"bye" in
  let p = Capsule.create_parser () in
  feed_bytewise p enc;
  (match Capsule.next p with
  | `Capsule (ty, payload) ->
      Alcotest.(check int) "type" Wire.Capsule_type.wt_close_session ty;
      (match Capsule.decode_close payload with
      | Ok (code, msg) ->
          Alcotest.(check int) "code" 42 code;
          Alcotest.(check string) "msg" "bye" msg
      | Error e -> Alcotest.fail e)
  | _ -> Alcotest.fail "expected capsule");
  Alcotest.(check bool) "drained" true (Capsule.next p = `Need_more)

let test_capsule_stream () =
  let p = Capsule.create_parser () in
  Capsule.feed p (Capsule.encode_drain () ^ Capsule.encode_max_data 999);
  (match Capsule.next p with
  | `Capsule (ty, "") ->
      Alcotest.(check int) "drain" Wire.Capsule_type.wt_drain_session ty
  | _ -> Alcotest.fail "expected drain");
  (match Capsule.next p with
  | `Capsule (ty, payload) ->
      Alcotest.(check int) "max_data" Wire.Capsule_type.wt_max_data ty;
      (match Capsule.decode_varint_capsule payload with
      | Ok 999 -> ()
      | _ -> Alcotest.fail "bad max_data value")
  | _ -> Alcotest.fail "expected max_data");
  (* Unknown capsule types pass through for the engine to skip. *)
  Capsule.feed p (Capsule.encode 0x1234 "xyz");
  (match Capsule.next p with
  | `Capsule (0x1234, "xyz") -> ()
  | _ -> Alcotest.fail "unknown capsule");
  (* Oversized length is rejected. *)
  let b = Buffer.create 8 in
  Webtransport.Varint.add_buffer b Wire.Capsule_type.wt_close_session;
  Webtransport.Varint.add_buffer b (2 * 1024 * 1024);
  Capsule.feed p (Buffer.contents b);
  match Capsule.next p with
  | `Error _ -> ()
  | _ -> Alcotest.fail "oversized capsule accepted"

let () =
  Alcotest.run "webtransport-core"
    [
      ( "varint",
        [
          Alcotest.test_case "rfc9000 vectors" `Quick test_varint_decode;
          Alcotest.test_case "truncated" `Quick test_varint_truncated;
          Alcotest.test_case "roundtrip" `Quick test_varint_roundtrip;
          Alcotest.test_case "to_string" `Quick test_varint_to_string;
        ] );
      ( "wt_error",
        [
          Alcotest.test_case "constants" `Quick test_error_constants;
          Alcotest.test_case "range & grease" `Quick test_error_range;
          Alcotest.test_case "roundtrip" `Quick test_error_roundtrip;
          Alcotest.test_case "monotonic" `Quick test_error_monotonic;
        ] );
      ( "settings",
        [
          Alcotest.test_case "server block" `Quick test_settings_server_block;
          Alcotest.test_case "validation" `Quick test_settings_validation;
          Alcotest.test_case "protocol token" `Quick test_settings_protocol_token;
        ] );
      ( "capsule",
        [
          Alcotest.test_case "close roundtrip" `Quick test_capsule_close_roundtrip;
          Alcotest.test_case "stream" `Quick test_capsule_stream;
        ] );
    ]
