(* Fuzz targets for the purequic codecs (crowbar; deterministic QuickCheck
   mode under dune runtest, coverage-guided under afl-fuzz).

   Invariants: parsers are total on arbitrary bytes; encode/parse
   round-trips; sizes agree with encoders. *)

module P = Purequic

let bs_of_string s = Bigstringaf.of_string s ~off:0 ~len:(String.length s)

(* A deterministically established pure<->pure pair, built once; the
   hostile-datagram target injects into it and asserts survival. *)
let established_pair =
  lazy
    (Mirage_crypto_rng.set_default_generator
       (Mirage_crypto_rng.create ~seed:"fuzz-pair"
          (module Mirage_crypto_rng.Fortuna));
     let key = X509.Private_key.generate ~seed:"fuzz-cert" `P256 in
     let dn =
       X509.Distinguished_name.
         [ Relative_distinguished_name.singleton (CN "fuzz") ]
     in
     let csr = Result.get_ok (X509.Signing_request.create dn ~digest:`SHA256 key) in
     let cert =
       Result.get_ok
         (X509.Signing_request.sign csr ~valid_from:Ptime.epoch
            ~valid_until:
              (match Ptime.of_date (2099, 1, 1) with
              | Some t -> t
              | None -> assert false)
            ~digest:`SHA256 key dn)
     in
     let rng seed =
       let state = ref seed in
       fun n ->
         String.init n (fun _ ->
             state := (!state * 2862933555777941757) + 3037000493;
             Char.chr ((!state lsr 33) land 0xff))
     in
     let base role priv =
       {
         P.Conn.role;
         alpn = [ "fz" ];
         cert_chain = (if role = `Server then [ cert ] else []);
         priv_key = priv;
         verify = `None;
         time = (fun () -> None);
         rng = rng (match role with `Client -> 11 | `Server -> 22);
         enable_datagrams = true;
         reliable_reset = true;
         initial_max_data = 1_000_000;
         initial_max_stream_data = 100_000;
         initial_max_streams_bidi = 16;
         initial_max_streams_uni = 16;
         max_idle_ns = 3_600_000_000_000L;
         max_udp_payload = 1350;
       }
     in
     let now = ref 1_000_000_000L in
     let dcid = String.make 16 'd' in
     let client =
       Result.get_ok
         (P.Conn.client (base `Client None) ~server_name:(Some "fuzz")
            ~scid:(String.make 16 'c') ~dcid ~peer:("\001\002\003\004", 1)
            ~now:!now)
     in
     let server =
       Result.get_ok
         (P.Conn.server_with_odcid (base `Server (Some key))
            ~scid:(String.make 16 's') ~odcid:dcid
            ~peer:("\004\003\002\001", 2) ~now:!now)
     in
     let buf = Bigstringaf.create 2048 in
     let pump src dst =
       let moved = ref false in
       let rec go () =
         match P.Conn.send src ~now:!now buf with
         | `Done -> ()
         | `Packet (n, _) ->
             moved := true;
             P.Conn.recv dst ~now:!now buf ~off:0 ~len:n
               ~from:("\009\009\009\009", 9);
             go ()
       in
       go ();
       !moved
     in
     let rec drive i =
       if i > 0 && not (P.Conn.is_established client && P.Conn.is_established server)
       then begin
         let m1 = pump client server and m2 = pump server client in
         if (not m1) && not m2 then now := Int64.add !now 30_000_000L;
         drive (i - 1)
       end
     in
     drive 200;
     assert (P.Conn.is_established client && P.Conn.is_established server);
     (client, server, now))

let () =
  Crowbar.add_test ~name:"varint decode total" [ Crowbar.bytes ] (fun s ->
      let buf = bs_of_string s in
      match P.Varint.get buf ~off:0 ~len:(String.length s) with
      | Some (v, n) -> Crowbar.check (v >= 0 && n >= 1 && n <= 8)
      | None -> Crowbar.check true);
  Crowbar.add_test ~name:"packet header parse total"
    [ Crowbar.bytes; Crowbar.range 21 ]
    (fun s dcid_len ->
      let buf = bs_of_string s in
      match
        P.Packet.parse buf ~off:0 ~len:(String.length s)
          ~short_dcid_len:dcid_len
      with
      | Ok located ->
          Crowbar.check
            (located.P.Packet.last <= String.length s
            && located.P.Packet.pn_off >= 0)
      | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"coalesced iteration terminates" [ Crowbar.bytes ]
    (fun s ->
      let buf = bs_of_string s in
      let count = ref 0 in
      P.Packet.iter buf ~off:0 ~len:(String.length s) ~short_dcid_len:16
        (fun _ -> incr count);
      Crowbar.check (!count <= String.length s + 1));
  Crowbar.add_test ~name:"frame parse total" [ Crowbar.bytes ] (fun s ->
      let buf = bs_of_string s in
      match P.Frame.parse_all buf ~off:0 ~len:(String.length s) with
      | Ok fs -> Crowbar.check (List.length fs <= String.length s + 1)
      | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"tparams decode total" [ Crowbar.bytes ] (fun s ->
      match P.Tparams.decode s with
      | Ok _ | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"pn decode within window"
    [ Crowbar.range (1 lsl 30); Crowbar.range 4; Crowbar.range (1 lsl 16) ]
    (fun largest pn_len_minus truncated ->
      let pn_len = 1 + (pn_len_minus mod 4) in
      let truncated = truncated land ((1 lsl (pn_len * 8)) - 1) in
      let v = P.Packet.pn_decode ~largest ~pn_len truncated in
      if not (v >= 0 && v <= P.Varint.max_value) then
        Crowbar.fail
          (Printf.sprintf "pn_decode largest=%d pn_len=%d trunc=%d -> %d"
             largest pn_len truncated v));
  (* structured roundtrip: generate frames, encode, parse, compare *)
  let payload_gen =
    Crowbar.map [ Crowbar.bytes ] (fun s ->
        P.Frame.payload_of_string (if String.length s > 512 then String.sub s 0 512 else s))
  in
  let id_gen = Crowbar.range (1 lsl 20) in
  let v_gen = Crowbar.range (1 lsl 30) in
  let frame_gen =
    Crowbar.choose
      [
        Crowbar.const P.Frame.Ping;
        Crowbar.const P.Frame.Handshake_done;
        Crowbar.map [ v_gen ] (fun v -> P.Frame.Max_data v);
        Crowbar.map [ id_gen; v_gen ] (fun id max ->
            P.Frame.Max_stream_data { id; max });
        Crowbar.map [ id_gen; v_gen; v_gen ] (fun id code final_size ->
            P.Frame.Reset_stream { id; code; final_size });
        Crowbar.map [ id_gen; v_gen; v_gen; v_gen ]
          (fun id code final_size extra ->
            P.Frame.Reset_stream_at
              {
                id;
                code;
                final_size = final_size + extra;
                reliable_size = final_size;
              });
        Crowbar.map [ id_gen; v_gen ] (fun id code ->
            P.Frame.Stop_sending { id; code });
        Crowbar.map [ v_gen; payload_gen ] (fun off data ->
            P.Frame.Crypto { off; data });
        Crowbar.map [ id_gen; v_gen; Crowbar.bool; payload_gen ]
          (fun id off fin data -> P.Frame.Stream { id; off; fin; data });
        Crowbar.map [ payload_gen ] (fun data -> P.Frame.Datagram { data });
        Crowbar.map [ v_gen ] (fun v -> P.Frame.Retire_connection_id v);
        Crowbar.map [ v_gen; payload_gen ] (fun code reason ->
            P.Frame.Connection_close { app = true; code; frame_type = 0; reason });
      ]
  in
  Crowbar.add_test ~name:"frame encode/parse roundtrip" [ frame_gen ]
    (fun f ->
      let sz = P.Frame.size f in
      let buf = Bigstringaf.create (sz + 8) in
      let n = P.Frame.encode buf ~off:0 f in
      if n <> sz then Crowbar.fail "size mismatch"
      else
        match P.Frame.parse_all buf ~off:0 ~len:n with
        | Ok [ f' ] ->
            let norm = function
              | P.Frame.Crypto { off; data } ->
                  `C (off, P.Frame.payload_to_string data)
              | P.Frame.Stream { id; off; fin; data } ->
                  `S (id, off, fin, P.Frame.payload_to_string data)
              | P.Frame.Datagram { data } -> `D (P.Frame.payload_to_string data)
              | P.Frame.Connection_close { app; code; frame_type; reason } ->
                  `CC (app, code, frame_type, P.Frame.payload_to_string reason)
              | f -> `O f
            in
            Crowbar.check (norm f = norm f')
        | Ok _ -> Crowbar.fail "frame count"
        | Error e -> Crowbar.fail e);
  (* CRYPTO reassembly: random segmentation/duplication/reordering of a
     known transcript reassembles to the original *)
  Crowbar.add_test ~name:"crypto reassembly"
    [ Crowbar.list (Crowbar.pair (Crowbar.range 200) (Crowbar.range 50)) ]
    (fun cuts ->
      let original = String.init 256 (fun i -> Char.chr (i land 0xff)) in
      let cs = P.Crypto_stream.create () in
      let out = Buffer.create 256 in
      let deliver s = Buffer.add_string out s in
      (* deliver shuffled, overlapping segments, then the whole thing *)
      List.iter
        (fun (off, len) ->
          let off = min off (String.length original - 1) in
          let len = min (len + 1) (String.length original - off) in
          match
            P.Crypto_stream.recv cs ~off (String.sub original off len) ~deliver
          with
          | Ok () | Error _ -> ())
        cuts;
      (match P.Crypto_stream.recv cs ~off:0 original ~deliver with
      | Ok () | Error _ -> ());
      let got = Buffer.contents out in
      Crowbar.check
        (String.length got >= String.length original
        && String.sub got 0 (String.length original) = original));
  (* TLS handshake-message feeding is total on hostile bytes *)
  Crowbar.add_test ~name:"tls handle total"
    [ Crowbar.range 3; Crowbar.bytes ]
    (fun lvl s ->
      let cfg =
        Result.get_ok
          (Purequic_tls.Tls.client_config ~alpn:[ "x" ] ~transport_params:"tp"
             ~rng:(fun n -> String.make n 'r')
             ())
      in
      let t = Purequic_tls.Tls.create cfg in
      Purequic_tls.Tls.start t;
      let level =
        match lvl with
        | 0 -> Purequic_tls.Tls.Initial
        | 1 -> Purequic_tls.Tls.Handshake
        | _ -> Purequic_tls.Tls.Application
      in
      Purequic_tls.Tls.handle t ~level s;
      let rec drain n =
        if n > 0 then
          match Purequic_tls.Tls.next_event t with
          | Some _ -> drain (n - 1)
          | None -> ()
      in
      drain 1000;
      Crowbar.check true);
  (* hostile datagrams into an established connection: never raises,
     event drain terminates, connection survives garbage (undecryptable
     input must be dropped silently) *)
  Crowbar.add_test ~name:"established conn survives hostile datagrams"
    [ Crowbar.bytes ]
    (fun s ->
      let _, server, now = Lazy.force established_pair in
      let b = bs_of_string s in
      P.Conn.recv server ~now:!now b ~off:0 ~len:(String.length s)
        ~from:("\066\066\066\066", 666);
      let rec drain n =
        if n > 0 then
          match P.Conn.next_event server with
          | Some _ -> drain (n - 1)
          | None -> ()
      in
      drain 10_000;
      Crowbar.check (not (P.Conn.is_closed server)));
  Crowbar.add_test ~name:"tparams encode/decode roundtrip"
    [ v_gen; v_gen; v_gen; Crowbar.bool; Crowbar.bool ]
    (fun max_data msd streams dam rr ->
      let t =
        {
          P.Tparams.default with
          initial_max_data = max_data;
          initial_max_stream_data_bidi_local = msd;
          initial_max_streams_bidi = streams mod ((1 lsl 60) + 1);
          disable_active_migration = dam;
          reliable_reset = rr;
          initial_scid = Some "0123456789abcdef";
        }
      in
      match P.Tparams.decode (P.Tparams.encode t) with
      | Ok t' -> Crowbar.check (t = t')
      | Error e -> Crowbar.fail e)
