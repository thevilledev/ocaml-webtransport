(* TLS subsystem tests: RFC 8448 "Simple 1-RTT" key-schedule vectors,
   a fully deterministic in-memory client<->server handshake, and
   fail-closed negative cases. *)

module T = Purequic_tls.Tls
module Sched = Purequic_tls.Schedule
module Cipher = Purequic_tls.Cipher

let unhex s =
  let s =
    String.concat ""
      (String.split_on_char ' ' (String.concat "" (String.split_on_char '\n' s)))
  in
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let hex s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let check_hex what expected got = Alcotest.(check string) what expected (hex got)

(* ---- RFC 8448 section 3 ---- *)

let rfc8448_ch =
  unhex
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"

let rfc8448_sh =
  unhex
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

let rfc8448_shared =
  unhex "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"

let test_rfc8448_schedule () =
  let hash = `SHA256 in
  let early = Sched.early_secret ~hash in
  check_hex "early secret"
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a" early;
  let hs =
    Sched.handshake_secret ~hash ~early ~ecdh_shared:rfc8448_shared
  in
  check_hex "handshake secret"
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac" hs;
  let tr = Sched.Transcript.create () in
  Sched.Transcript.feed tr rfc8448_ch;
  Sched.Transcript.set_hash tr hash;
  Sched.Transcript.feed tr rfc8448_sh;
  let th = Sched.Transcript.hash tr in
  check_hex "transcript CH..SH"
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8" th;
  let c_hs = Sched.client_hs_traffic ~hash ~handshake:hs ~transcript_hash:th in
  check_hex "c hs traffic"
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21" c_hs;
  let s_hs = Sched.server_hs_traffic ~hash ~handshake:hs ~transcript_hash:th in
  check_hex "s hs traffic"
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38" s_hs;
  let master = Sched.master_secret ~hash ~handshake:hs in
  check_hex "master secret"
    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919" master

let rfc8448_server_flight =
  (* EE (40) ^ Certificate (445) ^ CertificateVerify (136) from the trace *)
  [
    unhex
      "080000240022000a00140012001d00170018001901000101010201030104001c00024001\
       00000000";
    unhex
      "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000";
    unhex
      "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3";
  ]

let test_rfc8448_finished () =
  let hash = `SHA256 in
  let hs =
    Sched.handshake_secret ~hash ~early:(Sched.early_secret ~hash)
      ~ecdh_shared:rfc8448_shared
  in
  let tr = Sched.Transcript.create () in
  Sched.Transcript.feed tr rfc8448_ch;
  Sched.Transcript.set_hash tr hash;
  Sched.Transcript.feed tr rfc8448_sh;
  let th_sh = Sched.Transcript.hash tr in
  let s_hs = Sched.server_hs_traffic ~hash ~handshake:hs ~transcript_hash:th_sh in
  List.iter (Sched.Transcript.feed tr) rfc8448_server_flight;
  let fin =
    Sched.finished_verify ~hash ~traffic_secret:s_hs
      ~transcript_hash:(Sched.Transcript.hash tr)
  in
  check_hex "server finished verify_data"
    "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718" fin;
  (* app secrets bind the transcript through server Finished *)
  Sched.Transcript.feed tr
    (unhex "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
  let th_fin = Sched.Transcript.hash tr in
  check_hex "transcript CH..server Fin"
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13" th_fin;
  let master = Sched.master_secret ~hash ~handshake:hs in
  check_hex "c ap traffic"
    "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
    (Sched.client_app_traffic ~hash ~master ~transcript_hash:th_fin);
  check_hex "s ap traffic"
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
    (Sched.server_app_traffic ~hash ~master ~transcript_hash:th_fin)

(* ---- deterministic self-handshake ---- *)

(* xorshift-based deterministic rng for tests *)
let mk_rng seed =
  let state = ref seed in
  fun n ->
    String.init n (fun _ ->
        state := (!state * 2862933555777941757) + 3037000493;
        Char.chr ((!state lsr 33) land 0xff))

(* ECDSA signing pulls nonce randomness from the stateful default
   generator; reseeding it makes whole handshakes reproducible. *)
let reseed_rng () =
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:"purequic-tls-test"
       (module Mirage_crypto_rng.Fortuna))

let test_cert () =
  (* deterministic P-256 self-signed certificate *)
  reseed_rng ();
  let key = X509.Private_key.generate ~seed:"purequic-test-cert" `P256 in
  let dn =
    X509.Distinguished_name.
      [ Relative_distinguished_name.singleton (CN "purequic-test") ]
  in
  let csr =
    match X509.Signing_request.create dn ~digest:`SHA256 key with
    | Ok c -> c
    | Error (`Msg m) -> failwith m
  in
  let valid_from = Ptime.epoch in
  let valid_until =
    match Ptime.of_date (2099, 1, 1) with Some t -> t | None -> assert false
  in
  let extensions =
    X509.Extension.(
      empty
      |> add Subject_alt_name
           (false, X509.General_name.(singleton DNS [ "localhost" ])))
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from ~valid_until ~digest:`SHA256
        ~extensions key dn
    with
    | Ok c -> c
    | Error e ->
        failwith
          (Format.asprintf "%a" X509.Validation.pp_signature_error e)
  in
  (cert, key)

let drain_events tls other_handle =
  (* deliver Send events into [other_handle]; collect the rest *)
  let collected = ref [] in
  let rec go () =
    match T.next_event tls with
    | None -> ()
    | Some (T.Send { level; data }) ->
        other_handle ~level data;
        go ()
    | Some e ->
        collected := e :: !collected;
        go ()
  in
  go ();
  List.rev !collected

let run_handshake ?(client_alpn = [ "h3" ]) ?(server_alpn = [ "h3" ])
    ?(corrupt = fun ~level:_ s -> s) () =
  let cert, key = test_cert () in
  reseed_rng ();
  let ccfg =
    Result.get_ok
      (T.client_config ~server_name:"localhost" ~alpn:client_alpn
         ~transport_params:"CPARAMS" ~rng:(mk_rng 1) ())
  in
  let scfg =
    Result.get_ok
      (T.server_config ~cert_chain:[ cert ] ~priv_key:key ~alpn:server_alpn
         ~transport_params:"SPARAMS" ~rng:(mk_rng 2) ())
  in
  let client = T.create ccfg and server = T.create scfg in
  T.start client;
  (* pump both directions until quiescent *)
  let events_c = ref [] and events_s = ref [] in
  let rec pump n =
    if n = 0 then failwith "handshake did not converge";
    let moved = ref false in
    let deliver src dst acc =
      let evs =
        drain_events src (fun ~level data ->
            moved := true;
            T.handle dst ~level (corrupt ~level data))
      in
      acc := !acc @ evs
    in
    deliver client server events_c;
    deliver server client events_s;
    if !moved then pump (n - 1)
  in
  pump 10;
  (client, server, !events_c, !events_s)

let find_fatal evs =
  List.find_map
    (function T.Fatal { alert; reason } -> Some (alert, reason) | _ -> None)
    evs

let test_self_handshake () =
  let client, server, evs_c, evs_s = run_handshake () in
  Alcotest.(check bool) "client connected" true (T.is_connected client);
  Alcotest.(check bool) "server connected" true (T.is_connected server);
  let alpn_of evs =
    List.find_map
      (function T.Handshake_complete { alpn } -> Some alpn | _ -> None)
      evs
  in
  Alcotest.(check (option string)) "client alpn" (Some "h3") (alpn_of evs_c);
  Alcotest.(check (option string)) "server alpn" (Some "h3") (alpn_of evs_s);
  let tp_of evs =
    List.find_map
      (function T.Peer_transport_params tp -> Some tp | _ -> None)
      evs
  in
  Alcotest.(check (option string)) "client sees server params" (Some "SPARAMS")
    (tp_of evs_c);
  Alcotest.(check (option string)) "server sees client params" (Some "CPARAMS")
    (tp_of evs_s);
  (* both sides derived matching secrets at every level *)
  let secrets dir evs =
    List.filter_map
      (function
        | T.Rx_secret { level; secret; _ } when dir = `Rx -> Some (level, secret)
        | T.Tx_secret { level; secret; _ } when dir = `Tx -> Some (level, secret)
        | _ -> None)
      evs
  in
  Alcotest.(check bool) "client rx = server tx" true
    (secrets `Rx evs_c = secrets `Tx evs_s);
  Alcotest.(check bool) "client tx = server rx" true
    (secrets `Tx evs_c = secrets `Rx evs_s);
  Alcotest.(check int) "client certs seen" 1 (List.length (T.peer_certs client))

let test_determinism () =
  let _, _, evs_c1, _ = run_handshake () in
  let _, _, evs_c2, _ = run_handshake () in
  Alcotest.(check bool) "handshake fully deterministic" true (evs_c1 = evs_c2)

let test_alpn_mismatch () =
  let client, server, evs_c, evs_s =
    run_handshake ~client_alpn:[ "h3" ] ~server_alpn:[ "smtp" ] ()
  in
  Alcotest.(check bool) "client not connected" false (T.is_connected client);
  Alcotest.(check bool) "server not connected" false (T.is_connected server);
  ignore evs_c;
  match find_fatal evs_s with
  | Some (120, _) -> ()
  | Some (a, r) -> Alcotest.failf "wrong alert %d (%s)" a r
  | None -> Alcotest.fail "expected no_application_protocol"

(* corrupt one byte of the server CertificateVerify signature *)
let test_bad_cert_verify () =
  let saw_cv = ref false in
  let corrupt ~level s =
    if level = T.Handshake && (not !saw_cv) && String.length s > 200 then begin
      saw_cv := true;
      let b = Bytes.of_string s in
      (* server flight = EE ^ Cert ^ CV ^ Fin; flip a byte near the end of
         CV's signature region (fin is 4+hashlen from the end) *)
      let off = Bytes.length b - 40 in
      Bytes.set b off (Char.chr (Char.code (Bytes.get b off) lxor 0xff));
      Bytes.to_string b
    end
    else s
  in
  let client, _, evs_c, _ = run_handshake ~corrupt () in
  Alcotest.(check bool) "client not connected" false (T.is_connected client);
  match find_fatal evs_c with
  | Some (51, _) | Some (50, _) -> ()
  | Some (a, r) -> Alcotest.failf "wrong alert %d (%s)" a r
  | None -> Alcotest.fail "expected decrypt_error"

let test_truncated_fails_closed () =
  (* truncating the CH must not crash the server, and must not connect *)
  let cert, key = test_cert () in
  let scfg =
    Result.get_ok
      (T.server_config ~cert_chain:[ cert ] ~priv_key:key ~alpn:[ "h3" ]
         ~transport_params:"S" ~rng:(mk_rng 2) ())
  in
  let server = T.create scfg in
  let ccfg =
    Result.get_ok
      (T.client_config ~alpn:[ "h3" ] ~transport_params:"C" ~rng:(mk_rng 1) ())
  in
  let client = T.create ccfg in
  T.start client;
  let ch =
    match T.next_event client with
    | Some (T.Send { data; _ }) -> data
    | _ -> Alcotest.fail "no CH"
  in
  (* deliver a truncated message body: the splitter must just buffer it *)
  T.handle server ~level:T.Initial (String.sub ch 0 (String.length ch - 5));
  Alcotest.(check bool) "no events on partial CH" true
    (T.next_event server = None);
  (* deliver garbage claiming a huge length: still no crash *)
  T.handle server ~level:T.Initial "\x01\xff\xff\xff";
  Alcotest.(check bool) "server survives" true (T.next_event server = None)

let () =
  Alcotest.run "purequic_tls"
    [
      ( "rfc8448",
        [
          ("key schedule", `Quick, test_rfc8448_schedule);
          ("finished + app secrets", `Quick, test_rfc8448_finished);
        ] );
      ( "handshake",
        [
          ("self handshake", `Quick, test_self_handshake);
          ("deterministic", `Quick, test_determinism);
          ("alpn mismatch", `Quick, test_alpn_mismatch);
          ("bad certificate_verify", `Quick, test_bad_cert_verify);
          ("truncated input fails closed", `Quick, test_truncated_fails_closed);
        ] );
    ]
