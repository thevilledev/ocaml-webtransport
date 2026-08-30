(* Unit tests for the purequic codec + crypto foundation.

   The packet-protection cases are the RFC 9001 Appendix A vectors; the hex
   constants were ported from ocaml-quic's lib_test/test_packet_protection.ml
   (Copyright (c) 2020 António Nuno Monteiro, BSD-3-Clause) and checked
   against the RFC text. *)

let unhex s =
  let n = String.length s in
  assert (n mod 2 = 0);
  String.init (n / 2) (fun i ->
      Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let hex s =
  String.concat "" (List.init (String.length s) (fun i ->
      Printf.sprintf "%02x" (Char.code s.[i])))

let check_hex what expected got = Alcotest.(check string) what expected (hex got)

let bs_of_string s = Bigstringaf.of_string s ~off:0 ~len:(String.length s)

(* ---- varint / wire / ranges ---- *)

let test_varint () =
  let cases = [ (0, 1); (63, 1); (64, 2); (16383, 2); (16384, 4); ((1 lsl 30) - 1, 4); (1 lsl 30, 8); (Purequic.Varint.max_value, 8) ] in
  List.iter
    (fun (v, n) ->
      Alcotest.(check int) "size" n (Purequic.Varint.size v);
      let buf = Bigstringaf.create 8 in
      let w = Purequic.Varint.put buf ~off:0 v in
      Alcotest.(check int) "written" n w;
      match Purequic.Varint.get buf ~off:0 ~len:w with
      | Some (v', n') ->
          Alcotest.(check int) "roundtrip" v v';
          Alcotest.(check int) "consumed" n n'
      | None -> Alcotest.fail "decode failed")
    cases;
  (* RFC 9000 s.16 example: 0xc2197c5eff14e88c = 151288809941952652 *)
  let buf = bs_of_string (unhex "c2197c5eff14e88c") in
  (match Purequic.Varint.get buf ~off:0 ~len:8 with
  | Some (v, 8) -> Alcotest.(check int) "rfc example" 151288809941952652 v
  | _ -> Alcotest.fail "rfc example decode")

let test_ranges () =
  let r = Purequic.Ranges.create () in
  Purequic.Ranges.insert r ~lo:0 ~hi:0;
  Purequic.Ranges.insert r ~lo:2 ~hi:3;
  Alcotest.(check int) "two spans" 2 (Purequic.Ranges.cardinal_spans r);
  Purequic.Ranges.insert r ~lo:1 ~hi:1;
  Alcotest.(check int) "merged" 1 (Purequic.Ranges.cardinal_spans r);
  Alcotest.(check (option int)) "largest" (Some 3) (Purequic.Ranges.largest r);
  Purequic.Ranges.insert r ~lo:10 ~hi:20;
  Alcotest.(check bool) "contains 15" true (Purequic.Ranges.contains r 15);
  Alcotest.(check bool) "not 5" false (Purequic.Ranges.contains r 5);
  Alcotest.(check int) "gap after 0" 4 (Purequic.Ranges.next_gap r 0);
  Alcotest.(check int) "gap after 10" 21 (Purequic.Ranges.next_gap r 10);
  Purequic.Ranges.drop_below r 12;
  Alcotest.(check (option int)) "smallest after drop" (Some 12)
    (Purequic.Ranges.smallest r)

(* ---- RFC 9001 A.1: initial secrets ---- *)

let dcid = unhex "8394c8f03e515708"

let test_initial_secrets () =
  check_hex "initial secret"
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
    (Purequic.Qkdf.initial_secret ~dcid);
  let client = Purequic.Qkdf.initial_client_secret ~dcid in
  check_hex "client in"
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" client;
  let m = Purequic.Qkdf.material ~suite:Purequic.Qsuite.Aes128_gcm_sha256 ~secret:client in
  check_hex "client key" "1f369613dd76d5467730efcbe3b1a22d" m.Purequic.Qkdf.key;
  check_hex "client iv" "fa044b2f42a3fd3b46fb255c" m.Purequic.Qkdf.iv;
  check_hex "client hp" "9f50449e04a0e810283a1e9933adedd2" m.Purequic.Qkdf.hp;
  let server = Purequic.Qkdf.initial_server_secret ~dcid in
  check_hex "server in"
    "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" server;
  let m = Purequic.Qkdf.material ~suite:Purequic.Qsuite.Aes128_gcm_sha256 ~secret:server in
  check_hex "server key" "cf3a5331653c364c88f0f379b6067e37" m.Purequic.Qkdf.key;
  check_hex "server iv" "0ac1493ca1905853b0bba03e" m.Purequic.Qkdf.iv;
  check_hex "server hp" "c206b8d9b9f0f37644430b490eeaa314" m.Purequic.Qkdf.hp

(* ---- RFC 9001 A.2/A.3: client and server Initial protection ---- *)

let client_initial_frames =
  unhex
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"

let client_initial_payload =
  client_initial_frames
  ^ String.make (1162 - String.length client_initial_frames) '\x00'

let client_initial_header = unhex "c300000001088394c8f03e5157080000449e00000002"

let client_initial_protected =
  unhex
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934"

let test_client_initial () =
  let tx, _rx = Purequic.Aead.initial_keys ~dcid ~role:`Client in
  let sealed =
    Purequic.Packet.seal ~keys:tx ~pn:2L ~pn_len:4
      ~header:client_initial_header client_initial_payload
  in
  check_hex "protected client initial" (hex client_initial_protected) sealed;
  (* now unprotect it through the parser, as a server would *)
  let buf = bs_of_string client_initial_protected in
  let _, srx = Purequic.Aead.initial_keys ~dcid ~role:`Server in
  match
    Purequic.Packet.parse buf ~off:0
      ~len:(String.length client_initial_protected) ~short_dcid_len:16
  with
  | Error e -> Alcotest.fail e
  | Ok located -> (
      (match located.Purequic.Packet.hdr with
      | Purequic.Packet.Long { kind = Initial; version = 1l; dcid = d; _ } ->
          check_hex "parsed dcid" (hex dcid) d
      | _ -> Alcotest.fail "not an initial");
      match Purequic.Packet.open_ ~keys:srx ~largest:None buf located with
      | Some (pn, plaintext) ->
          Alcotest.(check int) "pn" 2 pn;
          check_hex "plaintext" (hex client_initial_payload) plaintext
      | None -> Alcotest.fail "unprotect failed")

let test_server_initial () =
  let server_payload =
    unhex
      "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"
  in
  let header = unhex "c1000000010008f067a5502a4262b50040750001" in
  let expected =
    unhex
      "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"
  in
  let tx, _ = Purequic.Aead.initial_keys ~dcid ~role:`Server in
  let sealed =
    Purequic.Packet.seal ~keys:tx ~pn:1L ~pn_len:2 ~header server_payload
  in
  check_hex "protected server initial" (hex expected) sealed;
  let buf = bs_of_string expected in
  let _, crx = Purequic.Aead.initial_keys ~dcid ~role:`Client in
  match
    Purequic.Packet.parse buf ~off:0 ~len:(String.length expected)
      ~short_dcid_len:16
  with
  | Error e -> Alcotest.fail e
  | Ok located -> (
      match Purequic.Packet.open_ ~keys:crx ~largest:None buf located with
      | Some (pn, plaintext) ->
          Alcotest.(check int) "pn" 1 pn;
          check_hex "plaintext" (hex server_payload) plaintext
      | None -> Alcotest.fail "unprotect failed")

(* ---- RFC 9001 A.4: retry integrity ---- *)

let test_retry () =
  let packet =
    unhex
      "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
  in
  let buf = bs_of_string packet in
  match
    Purequic.Packet.parse buf ~off:0 ~len:(String.length packet)
      ~short_dcid_len:16
  with
  | Ok ({ hdr = Purequic.Packet.Long { kind = Retry; token; _ }; _ } as located)
    ->
      Alcotest.(check string) "token" "token" token;
      Alcotest.(check bool) "tag valid" true
        (Purequic.Packet.retry_valid ~odcid:dcid buf located);
      Alcotest.(check bool) "tag invalid for wrong odcid" false
        (Purequic.Packet.retry_valid ~odcid:"nope" buf located)
  | Ok _ -> Alcotest.fail "not parsed as retry"
  | Error e -> Alcotest.fail e

(* ---- RFC 9001 A.5: ChaCha20-Poly1305 short header ---- *)

let test_chacha () =
  let secret =
    unhex "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
  in
  let suite = Purequic.Qsuite.Chacha20_poly1305_sha256 in
  let m = Purequic.Qkdf.material ~suite ~secret in
  check_hex "key" "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"
    m.Purequic.Qkdf.key;
  check_hex "iv" "e0459b3474bdd0e44a41c144" m.Purequic.Qkdf.iv;
  check_hex "hp" "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
    m.Purequic.Qkdf.hp;
  check_hex "ku" "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"
    (Purequic.Qkdf.next_secret ~suite ~secret);
  let keys = Purequic.Aead.of_secret ~suite secret in
  let header = unhex "4200bff4" in
  let sealed =
    Purequic.Packet.seal ~keys ~pn:654360564L ~pn_len:3 ~header (unhex "01")
  in
  check_hex "protected chacha packet" "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"
    sealed;
  (* and back: parse as a short-header packet with a 3-byte dcid of "" —
     the test packet has a zero-length dcid, so short_dcid_len:0 *)
  let buf = bs_of_string sealed in
  match
    Purequic.Packet.parse buf ~off:0 ~len:(String.length sealed)
      ~short_dcid_len:0
  with
  | Error e -> Alcotest.fail e
  | Ok located -> (
      match
        Purequic.Packet.open_ ~keys ~largest:(Some 654360563) buf located
      with
      | Some (pn, plaintext) ->
          Alcotest.(check int) "pn" 654360564 pn;
          check_hex "plaintext" "01" plaintext
      | None -> Alcotest.fail "unprotect failed")

(* key update chain: sealing with the next generation still roundtrips *)
let test_key_update_chain () =
  let secret =
    unhex "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
  in
  let keys = Purequic.Aead.of_secret ~suite:Purequic.Qsuite.Chacha20_poly1305_sha256 secret in
  let next = Purequic.Aead.next_generation keys in
  check_hex "next secret"
    "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"
    next.Purequic.Aead.secret;
  let sealed = Purequic.Aead.seal next ~pn:7L ~ad:"hdr" "payload" in
  match Purequic.Aead.open_ next ~pn:7L ~ad:"hdr" sealed with
  | Some p -> Alcotest.(check string) "roundtrip" "payload" p
  | None -> Alcotest.fail "ku roundtrip failed"

(* ---- packet number coding (RFC 9000 A.2/A.3 examples) ---- *)

let test_pn_coding () =
  (* A.3 example: largest 0xa82f30ea, truncated 0x9b32 (2 bytes) ->
     0xa82f9b32 *)
  Alcotest.(check int) "decode"
    0xa82f9b32
    (Purequic.Packet.pn_decode ~largest:0xa82f30ea ~pn_len:2 0x9b32);
  (* A.2 example: largest acked 0xabe8b3, next 0xac5c02 -> 2 bytes *)
  Alcotest.(check int) "encode len" 2
    (Purequic.Packet.pn_encode_len ~largest_acked:(Some 0xabe8b3) 0xac5c02);
  Alcotest.(check int) "encode len 3" 3
    (Purequic.Packet.pn_encode_len ~largest_acked:(Some 0xabe8b3) 0xace8fe)

(* ---- frame codec roundtrips ---- *)

let frames_for_roundtrip =
  let p = Purequic.Frame.payload_of_string in
  [
    Purequic.Frame.Ping;
    Purequic.Frame.Handshake_done;
    Purequic.Frame.Padding 5;
    Purequic.Frame.Ack
      { largest = 1000; delay = 17; ranges = [ (950, 1000); (10, 900); (0, 3) ]; ecn = None };
    Purequic.Frame.Ack
      { largest = 9; delay = 0; ranges = [ (0, 9) ]; ecn = Some (1, 2, 3) };
    Purequic.Frame.Reset_stream { id = 4; code = 77; final_size = 12345 };
    Purequic.Frame.Reset_stream_at
      { id = 4; code = 77; final_size = 12345; reliable_size = 100 };
    Purequic.Frame.Stop_sending { id = 8; code = 1 };
    Purequic.Frame.Crypto { off = 42; data = p "hello crypto" };
    Purequic.Frame.New_token { token = p "tok" };
    Purequic.Frame.Stream { id = 3; off = 0; fin = false; data = p "abc" };
    Purequic.Frame.Stream { id = 3; off = 999; fin = true; data = p "xyz" };
    Purequic.Frame.Max_data 100000;
    Purequic.Frame.Max_stream_data { id = 5; max = 4096 };
    Purequic.Frame.Max_streams_bidi 100;
    Purequic.Frame.Max_streams_uni 3;
    Purequic.Frame.Data_blocked 5000;
    Purequic.Frame.Stream_data_blocked { id = 9; max = 100 };
    Purequic.Frame.Streams_blocked_bidi 10;
    Purequic.Frame.Streams_blocked_uni 20;
    Purequic.Frame.New_connection_id
      { seq = 2; retire_prior_to = 1; cid = "0123456789abcdef";
        reset_token = String.make 16 '\x7f' };
    Purequic.Frame.Retire_connection_id 1;
    Purequic.Frame.Path_challenge "12345678";
    Purequic.Frame.Path_response "87654321";
    Purequic.Frame.Connection_close
      { app = false; code = 0x0a; frame_type = 0x06; reason = p "tls" };
    Purequic.Frame.Connection_close
      { app = true; code = 42; frame_type = 0; reason = p "done" };
    Purequic.Frame.Datagram { data = p "dgram!" };
  ]

let frame_equal a b =
  (* structural equality modulo payload representation *)
  let norm = function
    | Purequic.Frame.Crypto { off; data } ->
        `Crypto (off, Purequic.Frame.payload_to_string data)
    | Stream { id; off; fin; data } ->
        `Stream (id, off, fin, Purequic.Frame.payload_to_string data)
    | New_token { token } -> `Tok (Purequic.Frame.payload_to_string token)
    | Connection_close { app; code; frame_type; reason } ->
        `Close (app, code, frame_type, Purequic.Frame.payload_to_string reason)
    | Datagram { data } -> `Dgram (Purequic.Frame.payload_to_string data)
    | f -> `Other f
  in
  norm a = norm b

let test_frame_roundtrip () =
  let buf = Bigstringaf.create 4096 in
  List.iter
    (fun f ->
      let n = Purequic.Frame.encode buf ~off:0 f in
      Alcotest.(check int) "size agrees" (Purequic.Frame.size f) n;
      match Purequic.Frame.parse_all buf ~off:0 ~len:n with
      | Ok [ f' ] ->
          Alcotest.(check bool) "roundtrip" true (frame_equal f f')
      | Ok fs ->
          Alcotest.failf "expected 1 frame, got %d" (List.length fs)
      | Error e -> Alcotest.fail e)
    frames_for_roundtrip

(* ---- transport parameters ---- *)

let test_tparams_roundtrip () =
  let t =
    {
      Purequic.Tparams.default with
      original_dcid = Some "abcd";
      max_idle_timeout_ms = 30000;
      initial_max_data = 10_000_000;
      initial_max_stream_data_bidi_local = 1_000_000;
      initial_max_stream_data_bidi_remote = 1_000_000;
      initial_max_stream_data_uni = 1_000_000;
      initial_max_streams_bidi = 100;
      initial_max_streams_uni = 100;
      disable_active_migration = true;
      initial_scid = Some "0123456789abcdef";
      max_datagram_frame_size = Some 65527;
      reliable_reset = true;
    }
  in
  let s = Purequic.Tparams.encode t in
  match Purequic.Tparams.decode s with
  | Error e -> Alcotest.fail e
  | Ok t' ->
      Alcotest.(check bool) "roundtrip" true (t = t');
      (* unknown params are skipped *)
      let unknown =
        let b = Buffer.create 8 in
        Purequic.Varint.add_buffer b 0x7777;
        Purequic.Varint.add_buffer b 3;
        Buffer.add_string b "xyz";
        Buffer.contents b
      in
      let with_unknown = s ^ unknown in
      (match Purequic.Tparams.decode with_unknown with
      | Ok t'' -> Alcotest.(check bool) "unknown ignored" true (t = t'')
      | Error e -> Alcotest.fail e)

let test_tparams_legacy_reliable_reset () =
  (* only the legacy codepoint, with a varint payload (older drafts) *)
  let b = Buffer.create 32 in
  Purequic.Varint.add_buffer b Purequic.Tparams.id_reliable_reset_legacy;
  Purequic.Varint.add_buffer b 1;
  Buffer.add_char b '\x01';
  match Purequic.Tparams.decode (Buffer.contents b) with
  | Ok t -> Alcotest.(check bool) "legacy accepted" true t.Purequic.Tparams.reliable_reset
  | Error e -> Alcotest.fail e

(* ---- version negotiation writer ---- *)

let test_vneg () =
  let buf = Bigstringaf.create 256 in
  match Purequic.Packet.write_vneg buf ~client_dcid:"DDDDDDDD" ~client_scid:"SSSSSSSS" with
  | Error e -> Alcotest.fail e
  | Ok n -> (
      match Purequic.Packet.parse buf ~off:0 ~len:n ~short_dcid_len:16 with
      | Ok { hdr = Purequic.Packet.Vneg { dcid; scid; versions }; _ } ->
          Alcotest.(check string) "dcid = client scid" "SSSSSSSS" dcid;
          Alcotest.(check string) "scid = client dcid" "DDDDDDDD" scid;
          Alcotest.(check (list int32)) "versions" [ 1l ] versions
      | Ok _ -> Alcotest.fail "not parsed as vneg"
      | Error e -> Alcotest.fail e)

let () =
  Alcotest.run "purequic"
    [
      ( "codec",
        [
          ("varint", `Quick, test_varint);
          ("ranges", `Quick, test_ranges);
          ("frame roundtrip", `Quick, test_frame_roundtrip);
          ("tparams roundtrip", `Quick, test_tparams_roundtrip);
          ("tparams legacy reliable reset", `Quick, test_tparams_legacy_reliable_reset);
          ("version negotiation", `Quick, test_vneg);
          ("packet number coding", `Quick, test_pn_coding);
        ] );
      ( "rfc9001",
        [
          ("A.1 initial secrets", `Quick, test_initial_secrets);
          ("A.2 client initial", `Quick, test_client_initial);
          ("A.3 server initial", `Quick, test_server_initial);
          ("A.4 retry integrity", `Quick, test_retry);
          ("A.5 chacha20 short header", `Quick, test_chacha);
          ("key update chain", `Quick, test_key_update_chain);
        ] );
    ]
