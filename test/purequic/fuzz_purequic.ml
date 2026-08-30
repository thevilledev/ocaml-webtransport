(* Fuzz targets for the purequic codecs (crowbar; deterministic QuickCheck
   mode under dune runtest, coverage-guided under afl-fuzz).

   Invariants: parsers are total on arbitrary bytes; encode/parse
   round-trips; sizes agree with encoders. *)

module P = Purequic

let bs_of_string s = Bigstringaf.of_string s ~off:0 ~len:(String.length s)

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
