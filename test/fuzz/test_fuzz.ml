(* Fuzz targets (crowbar). In normal runs crowbar exercises each target with
   random data (deterministic QuickCheck mode); under afl-fuzz the same
   binary becomes a coverage-guided fuzzer.

   Invariants: no decoder ever raises on arbitrary input; encoders round-trip;
   the engine survives arbitrary wire bytes from a hostile peer. *)

module W = Webtransport
module E = W.Engine
module M = Wt_mock.Mock_backend

let () =
  Crowbar.add_test ~name:"varint decode total" [ Crowbar.bytes ] (fun s ->
      (match W.Varint.get_string s ~pos:0 with
      | Some (v, n) ->
          Crowbar.check (v >= 0 && n >= 1 && n <= 8 && n <= String.length s)
      | None -> Crowbar.check true));
  Crowbar.add_test ~name:"varint roundtrip"
    [ Crowbar.range ((1 lsl 30) + 1000) ]
    (fun v ->
      let b = Buffer.create 8 in
      W.Varint.add_buffer b v;
      match W.Varint.get_string (Buffer.contents b) ~pos:0 with
      | Some (v', n) -> Crowbar.check (v = v' && n = Buffer.length b)
      | None -> Crowbar.fail "roundtrip decode");
  Crowbar.add_test ~name:"settings decode total" [ Crowbar.bytes ] (fun s ->
      match W.Settings.decode s with
      | Ok _ | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"capsule parser total"
    [ Crowbar.list Crowbar.bytes ]
    (fun chunks ->
      let p = W.Capsule.create_parser () in
      List.iter
        (fun c ->
          W.Capsule.feed p c;
          let rec drain n =
            if n > 0 then
              match W.Capsule.next p with
              | `Capsule _ -> drain (n - 1)
              | `Need_more | `Error _ -> ()
          in
          drain 64)
        chunks;
      Crowbar.check true);
  Crowbar.add_test ~name:"close capsule roundtrip"
    [ Crowbar.range 0xffff; Crowbar.bytes ]
    (fun code message ->
      let message =
        if String.length message > 1024 then String.sub message 0 1024
        else message
      in
      let enc = W.Capsule.encode_close ~code ~message in
      let p = W.Capsule.create_parser () in
      W.Capsule.feed p enc;
      match W.Capsule.next p with
      | `Capsule (ty, payload) when ty = W.Wire.Capsule_type.wt_close_session
        -> (
          match W.Capsule.decode_close payload with
          | Ok (c, m) -> Crowbar.check (c = code && m = message)
          | Error e -> Crowbar.fail e)
      | _ -> Crowbar.fail "no capsule");
  Crowbar.add_test ~name:"huffman decode total" [ Crowbar.bytes ] (fun s ->
      match Wt_qpack.Huffman.decode s with
      | Ok _ | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"field section decode total" [ Crowbar.bytes ]
    (fun s ->
      match Wt_qpack.Field_section.decode s with
      | Ok _ | Error _ -> Crowbar.check true);
  Crowbar.add_test ~name:"field section roundtrip"
    [ Crowbar.list (Crowbar.pair Crowbar.bytes Crowbar.bytes) ]
    (fun fields ->
      let enc = Wt_qpack.Field_section.encode fields in
      match Wt_qpack.Field_section.decode enc with
      | Ok fields' -> Crowbar.check_eq fields fields'
      | Error e -> Crowbar.fail e);
  (* The engine as a server facing a peer that sends arbitrary bytes on
     arbitrary streams: must never raise, whatever arrives. *)
  Crowbar.add_test ~name:"engine survives hostile peer"
    [
      Crowbar.list
        (Crowbar.choose
           [
             Crowbar.map [ Crowbar.range 8; Crowbar.bool ] (fun i b ->
                 `Open (i, b));
             Crowbar.map
               [ Crowbar.range 8; Crowbar.bytes; Crowbar.bool ]
               (fun i data fin -> `Data (i, data, fin));
             Crowbar.map [ Crowbar.bytes ] (fun d -> `Dgram d);
             Crowbar.const `Tick;
           ]);
    ]
    (fun script ->
      let m = M.make `Server in
      let eng = E.create ~role:`Server ~fc:(4096, 4, 4) (E.C ((module M), m)) in
      M.establish m;
      let now = ref 0L in
      let proc () =
        now := Int64.add !now 1_000_000_000L;
        ignore (E.process eng ~now:!now)
      in
      proc ();
      List.iter
        (fun op ->
          (match op with
          | `Open (i, bidi) ->
              (* peer-initiated ids: bidi 0,4,..; uni 2,6,.. *)
              let id = (i * 4) + if bidi then 0 else 2 in
              M.peer_open m ~id ~dir:(if bidi then `Bidi else `Uni)
          | `Data (i, data, fin) ->
              let id = (i * 4) + (i land 2) in
              M.peer_data m ~id data ~fin
          | `Dgram d -> M.peer_dgram m d
          | `Tick -> ());
          proc ())
        script;
      proc ();
      Crowbar.check true)
