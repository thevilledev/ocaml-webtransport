(* P2 gate: the in-tree TLS 1.3 handshake completes against
   quiche/BoringSSL in BOTH orientations, over real QUIC packets built by
   the minimal Hs_pump harness — including certificate delivery both
   ways. *)

module T = Purequic_tls.Tls
module Tp = Purequic.Tparams

let alpn = "pq-interop"
let caddr = ("\127\000\000\001", 1111)
let saddr = ("\127\000\000\001", 4433)

let mk_rng seed =
  let state = ref seed in
  fun n ->
    String.init n (fun _ ->
        state := (!state * 2862933555777941757) + 3037000493;
        Char.chr ((!state lsr 33) land 0xff))

let reseed_default_rng () =
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:"cross-pair-test"
       (module Mirage_crypto_rng.Fortuna))

let base_tparams ~scid =
  {
    Tp.default with
    initial_scid = Some scid;
    initial_max_data = 1_000_000;
    initial_max_stream_data_bidi_local = 100_000;
    initial_max_stream_data_bidi_remote = 100_000;
    initial_max_stream_data_uni = 100_000;
    initial_max_streams_bidi = 16;
    initial_max_streams_uni = 16;
    max_idle_timeout_ms = 30_000;
    max_udp_payload_size = 65527;
  }

let quiche_config ~server =
  let cfg = Quiche.Config.create () in
  (match Quiche.Config.set_application_protos cfg [ alpn ] with
  | Ok () -> ()
  | Error e -> Alcotest.fail (Quiche.err_to_string e));
  Quiche.Config.verify_peer cfg false;
  Quiche.Config.set_max_idle_timeout cfg 30_000L;
  Quiche.Config.set_initial_max_data cfg 1_000_000;
  Quiche.Config.set_initial_max_stream_data_bidi_local cfg 100_000;
  Quiche.Config.set_initial_max_stream_data_bidi_remote cfg 100_000;
  Quiche.Config.set_initial_max_stream_data_uni cfg 100_000;
  Quiche.Config.set_initial_max_streams_bidi cfg 16;
  Quiche.Config.set_initial_max_streams_uni cfg 16;
  if server then begin
    let certs = Wt_certs.generate () in
    Wt_certs.with_temp_files certs (fun ~cert_file ~key_file ->
        (match Quiche.Config.load_cert_chain cfg ~pem_file:cert_file with
        | Ok () -> ()
        | Error e -> Alcotest.fail (Quiche.err_to_string e));
        match Quiche.Config.load_priv_key cfg ~pem_file:key_file with
        | Ok () -> ()
        | Error e -> Alcotest.fail (Quiche.err_to_string e));
    (cfg, Some certs)
  end
  else (cfg, None)

let buf = Bigstringaf.create 4096

(* quiche -> pump: move every pending quiche packet into the pump *)
let quiche_to_pump conn pump =
  let rec go () =
    match Quiche.send conn buf ~off:0 ~len:1350 with
    | `Done -> ()
    | `Error e -> Alcotest.fail (Quiche.err_to_string e)
    | `Packet (n, _) ->
        Hs_pump.recv_datagram pump (Bigstringaf.substring buf ~off:0 ~len:n);
        go ()
  in
  go ()

(* pump -> quiche *)
let pump_to_quiche pump conn ~from ~to_ =
  let rec go () =
    match Hs_pump.poll_datagram pump with
    | None -> ()
    | Some d ->
        let db = Bigstringaf.of_string d ~off:0 ~len:(String.length d) in
        (match Quiche.recv conn db ~off:0 ~len:(String.length d) ~from ~to_ with
        | Ok _ -> ()
        | Error e -> Alcotest.fail ("quiche recv: " ^ Quiche.err_to_string e));
        go ()
  in
  go ()

let test_purequic_client_vs_quiche_server () =
  reseed_default_rng ();
  let scid_c = String.init 16 (fun i -> Char.chr (0x10 + i)) in
  let initial_dcid = String.init 16 (fun i -> Char.chr (0xa0 + i)) in
  let scid_qs = String.init 16 (fun i -> Char.chr (0x60 + i)) in
  let tls =
    T.create
      (Result.get_ok
         (T.client_config ~server_name:"localhost" ~alpn:[ alpn ]
            ~transport_params:(Tp.encode (base_tparams ~scid:scid_c))
            ~rng:(mk_rng 7) ()))
  in
  let pump = Hs_pump.create ~role:`Client ~tls ~scid:scid_c ~dcid:initial_dcid in
  let scfg, certs = quiche_config ~server:true in
  let server = Quiche.accept ~scid:scid_qs ~local:saddr ~peer:caddr scfg in
  let rec drive n =
    if n = 0 then Alcotest.fail "handshake did not converge";
    (match pump.Hs_pump.failure with
    | Some f -> Alcotest.fail f
    | None -> ());
    if pump.Hs_pump.tls_done && Quiche.is_established server then ()
    else begin
      pump_to_quiche pump server ~from:caddr ~to_:saddr;
      quiche_to_pump server pump;
      drive (n - 1)
    end
  in
  drive 50;
  Alcotest.(check bool) "purequic client done" true pump.Hs_pump.tls_done;
  Alcotest.(check bool) "quiche server established" true
    (Quiche.is_established server);
  Alcotest.(check (option string)) "alpn on quiche" (Some alpn)
    (Quiche.application_proto server);
  (* certificate flowed quiche -> purequic *)
  let certs = Option.get certs in
  (match T.peer_certs tls with
  | leaf :: _ ->
      Alcotest.(check bool) "server cert DER matches" true
        (String.equal
           (X509.Certificate.encode_der leaf)
           certs.Wt_certs.cert_der)
  | [] -> Alcotest.fail "no peer certs");
  (* the server's transport parameters authenticate our original dcid *)
  match pump.Hs_pump.peer_tp with
  | None -> Alcotest.fail "no peer transport params"
  | Some tp -> (
      match Tp.decode tp with
      | Error e -> Alcotest.fail ("peer tparams: " ^ e)
      | Ok t ->
          Alcotest.(check (option string)) "odcid authenticated"
            (Some initial_dcid) t.Tp.original_dcid;
          Alcotest.(check (option string)) "server initial_scid"
            (Some scid_qs) t.Tp.initial_scid)

let test_quiche_client_vs_purequic_server () =
  reseed_default_rng ();
  let scid_qc = String.init 16 (fun i -> Char.chr (0x21 + i)) in
  let ccfg, _ = quiche_config ~server:false in
  let client =
    Quiche.connect ~server_name:"localhost" ~scid:scid_qc ~local:caddr
      ~peer:saddr ccfg
  in
  (* pull the first flight to learn the client's chosen initial DCID *)
  let first =
    match Quiche.send client buf ~off:0 ~len:1350 with
    | `Packet (n, _) -> Bigstringaf.substring buf ~off:0 ~len:n
    | `Done -> Alcotest.fail "quiche client sent nothing"
    | `Error e -> Alcotest.fail (Quiche.err_to_string e)
  in
  let fb = Bigstringaf.of_string first ~off:0 ~len:(String.length first) in
  let initial_dcid =
    match
      Purequic.Packet.parse fb ~off:0 ~len:(String.length first)
        ~short_dcid_len:16
    with
    | Ok { hdr = Purequic.Packet.Long { kind = Initial; dcid; _ }; _ } -> dcid
    | _ -> Alcotest.fail "could not parse quiche client initial"
  in
  let scid_s = String.init 16 (fun i -> Char.chr (0x80 + i)) in
  let certs = Wt_certs.generate () in
  let tparams =
    { (base_tparams ~scid:scid_s) with original_dcid = Some initial_dcid }
  in
  let tls =
    T.create
      (Result.get_ok
         (T.server_config
            ~cert_chain:[ certs.Wt_certs.cert ]
            ~priv_key:certs.Wt_certs.key ~alpn:[ alpn ]
            ~transport_params:(Tp.encode tparams) ~rng:(mk_rng 9) ()))
  in
  let pump = Hs_pump.create ~role:`Server ~tls ~scid:scid_s ~dcid:"" in
  Hs_pump.recv_datagram pump first;
  let rec drive n =
    if n = 0 then Alcotest.fail "handshake did not converge";
    (match pump.Hs_pump.failure with
    | Some f -> Alcotest.fail f
    | None -> ());
    if pump.Hs_pump.tls_done && Quiche.is_established client then ()
    else begin
      pump_to_quiche pump client ~from:saddr ~to_:caddr;
      quiche_to_pump client pump;
      drive (n - 1)
    end
  in
  drive 50;
  Alcotest.(check bool) "purequic server done" true pump.Hs_pump.tls_done;
  Alcotest.(check bool) "quiche client established" true
    (Quiche.is_established client);
  Alcotest.(check (option string)) "alpn on quiche client" (Some alpn)
    (Quiche.application_proto client);
  (* certificate flowed purequic -> quiche: our devcert's DER *)
  Alcotest.(check (option string)) "client saw our cert DER"
    (Some certs.Wt_certs.cert_der)
    (Quiche.peer_cert client)

let () =
  Alcotest.run "cross_pair_tls"
    [
      ( "handshake",
        [
          ( "purequic client vs quiche server",
            `Quick,
            test_purequic_client_vs_quiche_server );
          ( "quiche client vs purequic server",
            `Quick,
            test_quiche_client_vs_purequic_server );
        ] );
    ]
