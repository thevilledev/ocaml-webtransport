(* Throughput smoke: 64 MiB through an in-memory pair on each engine.
   Not a race between backends — the purequic floor exists to catch
   accidental O(n^2) buffering or per-packet allocation storms, nothing
   more. Run manually or from the CI bench step:

     dune exec test/bench/bench_pair.exe            # both engines
     dune exec test/bench/bench_pair.exe -- pure    # purequic + floor *)

let total_bytes = 64 * 1024 * 1024
let chunk = String.init 65536 (fun i -> Char.chr (i land 0xff))
let floor_mb_s = 20.0

(* ---- purequic: seam-level pair, virtual clock ---- *)

module B = Webtransport_purequic

let get = function Ok v -> v | Error m -> failwith m

let bench_pure () =
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:"bench" (module Mirage_crypto_rng.Fortuna));
  let certs = Wt_certs.generate () in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:[ "bench" ]
         ~cert_chain_pem:certs.Wt_certs.cert_pem
         ~priv_key_pem:certs.Wt_certs.key_pem
         ~initial_max_data:(64 * 1024 * 1024)
         ~initial_max_stream_data:(64 * 1024 * 1024)
         ())
  in
  let ccfg =
    get
      (B.config ~role:`Client ~alpn:[ "bench" ] ~verify:`None
         ~initial_max_data:(64 * 1024 * 1024)
         ~initial_max_stream_data:(64 * 1024 * 1024)
         ())
  in
  let now = ref 1_000_000_000L in
  let client =
    get
      (B.connect ccfg ~server_name:(Some "localhost")
         ~scid:(String.make 16 'c')
         ~peer:("\127\000\000\001", 1)
         ~local:("\000\000\000\000", 0)
         ~now:!now)
  in
  let server =
    get
      (B.accept scfg ~scid:(String.make 16 's')
         ~peer:("\127\000\000\001", 2)
         ~local:("\000\000\000\000", 0)
         ~now:!now)
  in
  let buf = Bigstringaf.create 4096 in
  let pump src dst =
    let moved = ref false in
    let rec go () =
      match B.send src ~now:!now buf with
      | `Done -> ()
      | `Error e -> failwith e
      | `Packet (n, _) ->
          moved := true;
          ignore
            (B.recv dst ~now:!now buf ~off:0 ~len:n
               ~from:("\127\000\000\001", 9)
               ~to_:("\000\000\000\000", 0));
          go ()
    in
    go ();
    !moved
  in
  let drain side =
    let rec go () = match B.next_event side with Some _ -> go () | None -> () in
    go ()
  in
  let tick () =
    let d1 = B.next_timeout_ns client and d2 = B.next_timeout_ns server in
    let d =
      match (d1, d2) with
      | Some a, Some b -> Int64.min a b
      | (Some _ as x), None | None, (Some _ as x) -> Option.get x
      | None, None -> 1_000_000L
    in
    now := Int64.add !now (Int64.max d 1L);
    B.on_timeout client ~now:!now;
    B.on_timeout server ~now:!now
  in
  let rec until cond n =
    if n = 0 then failwith "bench: stalled";
    if not (cond ()) then begin
      let m1 = pump client server and m2 = pump server client in
      drain client;
      drain server;
      if (not m1) && not m2 then tick ();
      until cond (n - 1)
    end
  in
  until (fun () -> B.is_established client && B.is_established server) 200;
  let id =
    match B.open_stream client ~dir:`Uni with
    | Ok id -> id
    | Error _ -> failwith "open"
  in
  let cb = Bigstringaf.of_string chunk ~off:0 ~len:(String.length chunk) in
  let sent = ref 0 and received = ref 0 in
  let tmp = Bigstringaf.create 65536 in
  let t0 = Unix.gettimeofday () in
  until
    (fun () ->
      (* feed the sender *)
      let rec feed () =
        if !sent < total_bytes then
          match
            B.stream_send client ~id cb ~off:0
              ~len:(min 65536 (total_bytes - !sent))
              ~fin:(total_bytes - !sent <= 65536)
          with
          | Ok n when n > 0 ->
              sent := !sent + n;
              feed ()
          | Ok _ | Error `Would_block -> ()
          | Error _ -> failwith "send"
      in
      feed ();
      (* drain the receiver *)
      let rec read () =
        match B.stream_recv server ~id tmp ~off:0 ~len:65536 with
        | Ok (n, fin) ->
            received := !received + n;
            if not fin then read ()
        | Error `Fin | Error `Would_block -> ()
        | Error `Invalid -> () (* stream not seen server-side yet *)
        | Error _ -> failwith "recv"
      in
      read ();
      !received >= total_bytes)
    2_000_000;
  let dt = Unix.gettimeofday () -. t0 in
  let mb_s = float_of_int total_bytes /. 1_048_576. /. dt in
  Printf.printf "purequic: %.1f MiB in %.2fs = %.1f MiB/s (virtual clock)\n%!"
    (float_of_int total_bytes /. 1_048_576.)
    dt mb_s;
  if mb_s < floor_mb_s then begin
    Printf.printf "FAIL: below the %.0f MiB/s floor\n%!" floor_mb_s;
    exit 1
  end

(* ---- quiche: bindings-level pair, for a reference number ---- *)

let bench_quiche () =
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:"bench" (module Mirage_crypto_rng.Fortuna));
  let certs = Wt_certs.generate () in
  let mk_cfg server =
    let c = Quiche.Config.create () in
    (match Quiche.Config.set_application_protos c [ "bench" ] with
    | Ok () -> ()
    | Error e -> failwith (Quiche.err_to_string e));
    Quiche.Config.verify_peer c false;
    Quiche.Config.set_initial_max_data c (64 * 1024 * 1024);
    Quiche.Config.set_initial_max_stream_data_bidi_local c (64 * 1024 * 1024);
    Quiche.Config.set_initial_max_stream_data_bidi_remote c (64 * 1024 * 1024);
    Quiche.Config.set_initial_max_stream_data_uni c (64 * 1024 * 1024);
    Quiche.Config.set_initial_max_streams_uni c 16;
    Quiche.Config.set_initial_max_streams_bidi c 16;
    if server then
      Wt_certs.with_temp_files certs (fun ~cert_file ~key_file ->
          (match Quiche.Config.load_cert_chain c ~pem_file:cert_file with
          | Ok () -> ()
          | Error e -> failwith (Quiche.err_to_string e));
          match Quiche.Config.load_priv_key c ~pem_file:key_file with
          | Ok () -> ()
          | Error e -> failwith (Quiche.err_to_string e));
    c
  in
  let caddr = ("\127\000\000\001", 1111) and saddr = ("\127\000\000\001", 4433) in
  let client =
    Quiche.connect ~server_name:"localhost" ~scid:(String.make 16 'c')
      ~local:caddr ~peer:saddr (mk_cfg false)
  in
  let server =
    Quiche.accept ~scid:(String.make 16 's') ~local:saddr ~peer:caddr
      (mk_cfg true)
  in
  let buf = Bigstringaf.create 2048 in
  let pump src dst ~from ~to_ =
    let rec go moved =
      match Quiche.send src buf ~off:0 ~len:1350 with
      | `Done -> moved
      | `Error e -> failwith (Quiche.err_to_string e)
      | `Packet (n, _) ->
          (match Quiche.recv dst buf ~off:0 ~len:n ~from ~to_ with
          | Ok _ -> ()
          | Error e -> failwith (Quiche.err_to_string e));
          go true
    in
    go false
  in
  let rec until cond n =
    if n = 0 then failwith "bench(quiche): stalled";
    if not (cond ()) then begin
      let m1 = pump client server ~from:caddr ~to_:saddr in
      let m2 = pump server client ~from:saddr ~to_:caddr in
      if (not m1) && not m2 then Unix.sleepf 0.001;
      until cond (n - 1)
    end
  in
  until (fun () -> Quiche.is_established client && Quiche.is_established server) 2000;
  let id = 2 (* first client uni *) in
  let sent = ref 0 and received = ref 0 in
  let tmp = Bigstringaf.create 65536 in
  let cb = Bigstringaf.of_string chunk ~off:0 ~len:(String.length chunk) in
  let t0 = Unix.gettimeofday () in
  until
    (fun () ->
      (let rec feed () =
         if !sent < total_bytes then
           match
             Quiche.stream_send client ~id cb ~off:0
               ~len:(min 65536 (total_bytes - !sent))
               ~fin:(total_bytes - !sent <= 65536)
           with
           | Ok n when n > 0 ->
               sent := !sent + n;
               feed ()
           | Ok _ | Error Quiche.Done -> ()
           | Error e -> failwith (Quiche.err_to_string e)
       in
       feed ());
      (let rec read () =
         match Quiche.stream_recv server ~id tmp ~off:0 ~len:65536 with
         | Ok (n, fin) ->
             received := !received + n;
             if not fin then read ()
         | Error Quiche.Done | Error Quiche.Invalid_stream_state -> ()
         | Error e -> failwith (Quiche.err_to_string e)
       in
       read ());
      !received >= total_bytes)
    2_000_000;
  let dt = Unix.gettimeofday () -. t0 in
  Printf.printf "quiche:   %.1f MiB in %.2fs = %.1f MiB/s (reference)\n%!"
    (float_of_int total_bytes /. 1_048_576.)
    dt
    (float_of_int total_bytes /. 1_048_576. /. dt)

let () =
  let which = if Array.length Sys.argv > 1 then Sys.argv.(1) else "both" in
  if which = "pure" || which = "both" then bench_pure ();
  if which = "quiche" || which = "both" then bench_quiche ()
