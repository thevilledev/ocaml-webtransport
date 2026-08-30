module P = Wt_qpack.Prefix_int
module H = Wt_qpack.Huffman
module St = Wt_qpack.Static_table
module Fs = Wt_qpack.Field_section

let hex s =
  let s = String.concat "" (String.split_on_char ' ' s) in
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

(* --- prefix integers: RFC 7541 appendix C.1 --- *)

let enc ~prefix ~high_bits v =
  let b = Buffer.create 8 in
  P.encode b ~prefix ~high_bits v;
  Buffer.contents b

let test_prefix_vectors () =
  Alcotest.(check string) "10/5" "\x0a" (enc ~prefix:5 ~high_bits:0 10);
  Alcotest.(check string) "1337/5" "\x1f\x9a\x0a" (enc ~prefix:5 ~high_bits:0 1337);
  Alcotest.(check string) "42/8" "\x2a" (enc ~prefix:8 ~high_bits:0 42);
  List.iter
    (fun (s, v) ->
      match P.decode s ~pos:0 ~prefix:5 with
      | Some (v', p) ->
          Alcotest.(check int) "value" v v';
          Alcotest.(check int) "consumed" (String.length s) p
      | None -> Alcotest.fail "decode failed")
    [ ("\x0a", 10); ("\x1f\x9a\x0a", 1337) ]

let test_prefix_roundtrip () =
  Random.init 7;
  for _ = 1 to 50_000 do
    let prefix = 1 + Random.int 8 in
    let v = Random.int 10_000_000 in
    let s = enc ~prefix ~high_bits:0 v in
    match P.decode s ~pos:0 ~prefix with
    | Some (v', p) when v' = v && p = String.length s -> ()
    | _ -> Alcotest.fail (Printf.sprintf "roundtrip %d/%d" v prefix)
  done;
  (* truncated continuation *)
  Alcotest.(check bool) "truncated" true (P.decode "\x1f" ~pos:0 ~prefix:5 = None)

(* --- Huffman: RFC 7541 appendix C vectors --- *)

let test_huffman_vectors () =
  List.iter
    (fun (h, expect) ->
      match H.decode (hex h) with
      | Ok s -> Alcotest.(check string) expect expect s
      | Error e -> Alcotest.fail e)
    [
      ("f1e3 c2e5 f23a 6ba0 ab90 f4ff", "www.example.com");
      ("a8eb 1064 9cbf", "no-cache");
      ("25a8 49e9 5ba9 7d7f", "custom-key");
      ("25a8 49e9 5bb8 e8b4 bf", "custom-value");
      ("6402", "302");
      ("aec3 771a 4b", "private");
      ("d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
       "Mon, 21 Oct 2013 20:13:21 GMT");
      ("9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3", "https://www.example.com");
    ]

let test_huffman_errors () =
  (* 32 one-bits: EOS (30 bits) is reached -> error. *)
  (match H.decode "\xff\xff\xff\xff" with
  | Error _ -> ()
  | Ok s -> Alcotest.fail ("EOS accepted: " ^ String.escaped s));
  (* Valid string with its padding corrupted (a zero bit in padding). *)
  (match H.decode (hex "f1e3 c2e5 f23a 6ba0 ab90 f4fe") with
  | Error _ -> ()
  | Ok s -> Alcotest.fail ("bad padding accepted: " ^ String.escaped s));
  (* Empty input is a valid empty string. *)
  match H.decode "" with
  | Ok "" -> ()
  | _ -> Alcotest.fail "empty huffman"

(* --- static table --- *)

let test_static_table () =
  Alcotest.(check int) "size" 99 St.size;
  Alcotest.(check (option (pair string string)))
    "entry 0"
    (Some (":authority", ""))
    (St.get 0);
  Alcotest.(check (option (pair string string)))
    "entry 1" (Some (":path", "/")) (St.get 1);
  Alcotest.(check (option (pair string string)))
    "entry 15"
    (Some (":method", "CONNECT"))
    (St.get 15);
  Alcotest.(check (option (pair string string)))
    "entry 17"
    (Some (":method", "GET"))
    (St.get 17);
  Alcotest.(check (option int)) "find CONNECT" (Some 15)
    (St.find_exact ~name:":method" ~value:"CONNECT");
  Alcotest.(check (option int)) "find name" (Some 0) (St.find_name ":authority");
  Alcotest.(check (option int)) "missing" None
    (St.find_exact ~name:"x-nope" ~value:"1");
  Alcotest.(check (option (pair string string))) "oob" None (St.get 99)

(* --- field sections --- *)

let connect_headers =
  [
    (":method", "CONNECT");
    (":protocol", "webtransport");
    (":scheme", "https");
    (":authority", "example.com:4433");
    (":path", "/echo");
    ("origin", "https://example.com");
    ("sec-webtransport-http3-draft02", "1");
  ]

let test_field_roundtrip () =
  let enc = Fs.encode connect_headers in
  match Fs.decode enc with
  | Ok fields ->
      Alcotest.(check (list (pair string string))) "roundtrip" connect_headers fields
  | Error e -> Alcotest.fail e

let test_field_decode_static () =
  (* 0x00 0x00 prefix, then indexed static 15 (:method CONNECT) = 11 001111 *)
  match Fs.decode "\x00\x00\xcf" with
  | Ok [ (":method", "CONNECT") ] -> ()
  | Ok _ -> Alcotest.fail "wrong decode"
  | Error e -> Alcotest.fail e

let test_field_decode_huffman_value () =
  (* Literal with name ref to :authority (idx 0): 0101 0000, then a
     Huffman-coded value "www.example.com". *)
  let value = hex "f1e3 c2e5 f23a 6ba0 ab90 f4ff" in
  let s =
    "\x00\x00\x50"
    ^ String.make 1 (Char.chr (0x80 lor String.length value))
    ^ value
  in
  match Fs.decode s with
  | Ok [ (":authority", "www.example.com") ] -> ()
  | Ok _ -> Alcotest.fail "wrong decode"
  | Error e -> Alcotest.fail e

let test_field_rejects_dynamic () =
  let expect_err s ctx =
    match Fs.decode s with
    | Error _ -> ()
    | Ok _ -> Alcotest.fail (ctx ^ ": dynamic reference accepted")
  in
  expect_err "\x01\x00\xcf" "nonzero RIC";
  expect_err "\x00\x00\x80" "dynamic indexed";
  expect_err "\x00\x00\x40\x01\x61" "dynamic name ref";
  expect_err "\x00\x00\x10" "post-base"

let () =
  Alcotest.run "qpack"
    [
      ( "prefix_int",
        [
          Alcotest.test_case "rfc7541 vectors" `Quick test_prefix_vectors;
          Alcotest.test_case "roundtrip" `Quick test_prefix_roundtrip;
        ] );
      ( "huffman",
        [
          Alcotest.test_case "rfc7541 vectors" `Quick test_huffman_vectors;
          Alcotest.test_case "errors" `Quick test_huffman_errors;
        ] );
      ( "static_table",
        [ Alcotest.test_case "entries" `Quick test_static_table ] );
      ( "field_section",
        [
          Alcotest.test_case "roundtrip" `Quick test_field_roundtrip;
          Alcotest.test_case "indexed static" `Quick test_field_decode_static;
          Alcotest.test_case "huffman value" `Quick test_field_decode_huffman_value;
          Alcotest.test_case "rejects dynamic" `Quick test_field_rejects_dynamic;
        ] );
    ]
