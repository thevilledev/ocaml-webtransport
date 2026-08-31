(* Unit coverage for the token machinery: authentic tokens validate for
   the right peer only, forged/expired/wrong-address tokens fail, and the
   Retry packet round-trips through the seam's parse_header. *)

module R = Webtransport.Retry
module P = Webtransport_purequic

let () = Mirage_crypto_rng_unix.use_default ()

let test_token_roundtrip () =
  let rs = R.create () in
  let peer = ("\127\000\000\001", 4433) in
  let odcid = "0123456789abcdef" in
  let now = 1_000_000_000L in
  let token = R.mint rs ~odcid ~peer ~now in
  Alcotest.(check (option string)) "authentic" (Some odcid)
    (R.validate rs ~token ~peer ~now:(Int64.add now 1_000_000_000L));
  Alcotest.(check (option string)) "wrong address" None
    (R.validate rs ~token ~peer:("\010\000\000\001", 4433) ~now);
  Alcotest.(check (option string)) "wrong port" None
    (R.validate rs ~token ~peer:("\127\000\000\001", 5555) ~now);
  Alcotest.(check (option string)) "expired" None
    (R.validate rs ~token ~peer ~now:(Int64.add now 40_000_000_000L));
  let other = R.create () in
  Alcotest.(check (option string)) "forged (other key)" None
    (R.validate other ~token ~peer ~now);
  Alcotest.(check (option string)) "truncated" None
    (R.validate rs ~token:(String.sub token 0 10) ~peer ~now)

let test_retry_packet () =
  let buf = Bigstringaf.create 256 in
  let odcid = "abcdefghijklmnop" in
  match
    R.write ~client_scid:"CLIENTSC" ~new_scid:"NEWSCID000000000" ~odcid
      ~token:"tok" buf
  with
  | Error e -> Alcotest.fail e
  | Ok len -> (
      (* the seam parses it as a long header with a token *)
      match P.parse_header buf ~off:0 ~len with
      | Ok hdr ->
          Alcotest.(check bool) "long" true hdr.P.is_long;
          Alcotest.(check string) "dcid = client scid" "CLIENTSC" hdr.P.dcid;
          Alcotest.(check string) "scid = new scid" "NEWSCID000000000"
            hdr.P.scid
      | Error e -> Alcotest.fail e)

let () =
  Alcotest.run "retry_unit"
    [
      ( "tokens",
        [
          ("token roundtrip", `Quick, test_token_roundtrip);
          ("retry packet parses", `Quick, test_retry_packet);
        ] );
    ]
