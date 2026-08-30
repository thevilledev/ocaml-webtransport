(* Two real quiche connections pumped through an in-memory (optionally lossy)
   pipe: full TLS handshake via vendored BoringSSL, stream + datagram
   exchange, close. This is the bindings' realism test — no sockets. *)

let caddr = ("\127\000\000\001", 1111)
let saddr = ("\127\000\000\001", 4433)
let alpn = "wt-pair-test"

let fail_err ctx e = Alcotest.fail (ctx ^ ": " ^ Quiche.err_to_string e)

let make_configs () =
  let certs = Wt_certs.generate () in
  let ccfg = Quiche.Config.create () in
  (match Quiche.Config.set_application_protos ccfg [ alpn ] with
  | Ok () -> ()
  | Error e -> fail_err "client alpn" e);
  Quiche.Config.verify_peer ccfg false;
  Quiche.Config.set_max_idle_timeout ccfg 30_000L;
  Quiche.Config.set_initial_max_data ccfg 1_000_000;
  Quiche.Config.set_initial_max_stream_data_bidi_local ccfg 100_000;
  Quiche.Config.set_initial_max_stream_data_bidi_remote ccfg 100_000;
  Quiche.Config.set_initial_max_stream_data_uni ccfg 100_000;
  Quiche.Config.set_initial_max_streams_bidi ccfg 16;
  Quiche.Config.set_initial_max_streams_uni ccfg 16;
  Quiche.Config.enable_dgram ccfg true 64 64;
  let scfg = Quiche.Config.create () in
  Wt_certs.with_temp_files certs (fun ~cert_file ~key_file ->
      (match Quiche.Config.load_cert_chain scfg ~pem_file:cert_file with
      | Ok () -> ()
      | Error e -> fail_err "load cert" e);
      match Quiche.Config.load_priv_key scfg ~pem_file:key_file with
      | Ok () -> ()
      | Error e -> fail_err "load key" e);
  (match Quiche.Config.set_application_protos scfg [ alpn ] with
  | Ok () -> ()
  | Error e -> fail_err "server alpn" e);
  Quiche.Config.verify_peer scfg false;
  Quiche.Config.set_max_idle_timeout scfg 30_000L;
  Quiche.Config.set_initial_max_data scfg 1_000_000;
  Quiche.Config.set_initial_max_stream_data_bidi_local scfg 100_000;
  Quiche.Config.set_initial_max_stream_data_bidi_remote scfg 100_000;
  Quiche.Config.set_initial_max_stream_data_uni scfg 100_000;
  Quiche.Config.set_initial_max_streams_bidi scfg 16;
  Quiche.Config.set_initial_max_streams_uni scfg 16;
  Quiche.Config.enable_dgram scfg true 64 64;
  (ccfg, scfg, certs)

(* Moves every packet [src] has pending into [dst]; [loss] drops some. *)
let pump ?rng ?(loss = 0.) src ~src_addr dst ~dst_addr buf =
  let rec loop moved =
    match Quiche.send src buf ~off:0 ~len:1350 with
    | `Done -> moved
    | `Error e -> fail_err "pump send" e
    | `Packet (n, _to) ->
        let dropped =
          match rng with
          | Some st -> Random.State.float st 1.0 < loss
          | None -> false
        in
        if not dropped then begin
          match
            Quiche.recv dst buf ~off:0 ~len:n ~from:src_addr ~to_:dst_addr
          with
          | Ok _ -> ()
          | Error e -> fail_err "pump recv" e
        end;
        loop true
  in
  loop false

(* Pumps both directions until [until ()] holds, sleeping on quiche timers
   when the exchange stalls (loss recovery is wall-clock in quiche). *)
let drive ?rng ?(loss = 0.) ?(budget_s = 30.) ~until client server =
  let buf = Bigstringaf.create 2048 in
  let deadline = Unix.gettimeofday () +. budget_s in
  let rec go () =
    if until () then ()
    else begin
      let m1 =
        pump ?rng ~loss client ~src_addr:caddr server ~dst_addr:saddr buf
      in
      let m2 =
        pump ?rng ~loss server ~src_addr:saddr client ~dst_addr:caddr buf
      in
      if until () then ()
      else if m1 || m2 then go ()
      else begin
        if Unix.gettimeofday () > deadline then
          Alcotest.fail "drive: time budget exceeded";
        let next =
          match (Quiche.timeout_as_nanos client, Quiche.timeout_as_nanos server)
          with
          | Some a, Some b -> Some (min a b)
          | (Some _ as t), None | None, (Some _ as t) -> t
          | None, None -> None
        in
        match next with
        | None -> Alcotest.fail "drive: stalled with no timers armed"
        | Some ns ->
            Unix.sleepf ((Int64.to_float ns /. 1e9) +. 0.002);
            let fire conn =
              match Quiche.timeout_as_nanos conn with
              | Some ns when Int64.compare ns 2_000_000L <= 0 ->
                  Quiche.on_timeout conn
              | _ -> ()
            in
            fire client;
            fire server;
            go ()
      end
    end
  in
  go ()

let read_all conn ~id buf =
  let data = Buffer.create 64 in
  let fin = ref false in
  let rec loop () =
    match Quiche.stream_recv conn ~id buf ~off:0 ~len:(Bigstringaf.length buf) with
    | Ok (n, f) ->
        Buffer.add_string data (Bigstringaf.substring buf ~off:0 ~len:n);
        if f then fin := true else loop ()
    | Error Quiche.Done -> ()
    | Error e -> fail_err "read_all" e
  in
  loop ();
  (Buffer.contents data, !fin)

let run_exchange ?rng ?(loss = 0.) () =
  let ccfg, scfg, certs = make_configs () in
  let scid_c = String.init 16 (fun i -> Char.chr (i lxor 0xa5)) in
  let scid_s = String.init 16 (fun i -> Char.chr (i lxor 0x5a)) in
  let client =
    Quiche.connect ~server_name:"localhost" ~scid:scid_c ~local:caddr
      ~peer:saddr ccfg
  in
  let server = Quiche.accept ~scid:scid_s ~local:saddr ~peer:caddr scfg in
  drive ?rng ~loss client server ~until:(fun () ->
      Quiche.is_established client && Quiche.is_established server);
  Alcotest.(check (option string))
    "client alpn" (Some alpn)
    (Quiche.application_proto client);
  Alcotest.(check (option string))
    "server alpn" (Some alpn)
    (Quiche.application_proto server);
  (* The client sees the server's leaf cert: exactly what hash pinning needs. *)
  (match Quiche.peer_cert client with
  | Some der ->
      Alcotest.(check string) "leaf cert der" certs.Wt_certs.cert_der der
  | None -> Alcotest.fail "client has no peer cert");
  let buf = Bigstringaf.create 4096 in

  (* Zero-length send creates a stream (the open_stream trick). *)
  (match Quiche.stream_capacity client ~id:8 with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "stream 8 should not exist yet");
  (match Quiche.stream_send client ~id:8 Bigstringaf.empty ~off:0 ~len:0 ~fin:false with
  | Ok 0 -> ()
  | Ok n -> Alcotest.fail (Printf.sprintf "zero-len send wrote %d" n)
  | Error e -> fail_err "zero-len send" e);
  (match Quiche.stream_capacity client ~id:8 with
  | Ok _ -> ()
  | Error e -> fail_err "stream 8 should exist after zero-len send" e);

  (* Client -> server on bidi stream 0, echo back. *)
  let msg = "hello over QUIC from OCaml" in
  Bigstringaf.blit_from_string msg ~src_off:0 buf ~dst_off:0
    ~len:(String.length msg);
  (match
     Quiche.stream_send client ~id:0 buf ~off:0 ~len:(String.length msg)
       ~fin:true
   with
  | Ok n when n = String.length msg -> ()
  | Ok n -> Alcotest.fail (Printf.sprintf "partial send %d" n)
  | Error e -> fail_err "stream_send" e);
  let got = ref "" in
  drive ?rng ~loss client server ~until:(fun () ->
      match Quiche.stream_recv server ~id:0 buf ~off:0 ~len:4096 with
      | Ok (n, fin) ->
          got := !got ^ Bigstringaf.substring buf ~off:0 ~len:n;
          fin
      | Error Quiche.Done -> false
      | Error Quiche.Invalid_stream_state -> false (* not created yet *)
      | Error e -> fail_err "server read" e);
  Alcotest.(check string) "server received" msg !got;

  (* Echo back. *)
  Bigstringaf.blit_from_string !got ~src_off:0 buf ~dst_off:0
    ~len:(String.length !got);
  (match
     Quiche.stream_send server ~id:0 buf ~off:0 ~len:(String.length !got)
       ~fin:true
   with
  | Ok _ -> ()
  | Error e -> fail_err "server echo" e);
  let echoed = ref "" in
  let efin = ref false in
  drive ?rng ~loss client server ~until:(fun () ->
      let s, fin = read_all client ~id:0 buf in
      echoed := !echoed ^ s;
      if fin then efin := true;
      !efin);
  Alcotest.(check string) "client echo" msg !echoed;

  (* Datagrams. *)
  Bigstringaf.blit_from_string "ping" ~src_off:0 buf ~dst_off:0 ~len:4;
  (match Quiche.dgram_send client buf ~off:0 ~len:4 with
  | Ok () -> ()
  | Error e -> fail_err "dgram_send" e);
  drive ?rng ~loss client server ~until:(fun () ->
      Quiche.dgram_recv_queue_len server > 0);
  (match Quiche.dgram_recv server buf ~off:0 ~len:4096 with
  | Ok 4 -> Alcotest.(check string) "dgram" "ping" (Bigstringaf.substring buf ~off:0 ~len:4)
  | Ok n -> Alcotest.fail (Printf.sprintf "dgram len %d" n)
  | Error e -> fail_err "dgram_recv" e);

  (* Close: server should observe the client's application close. *)
  (match Quiche.close client ~app:true ~code:42 ~reason:"bye" with
  | Ok () -> ()
  | Error e -> fail_err "close" e);
  drive ?rng ~loss client server ~until:(fun () ->
      Quiche.peer_error server <> None);
  (match Quiche.peer_error server with
  | Some e ->
      Alcotest.(check bool) "app close" true e.Quiche.is_app;
      Alcotest.(check int) "close code" 42 e.Quiche.code;
      Alcotest.(check string) "close reason" "bye" e.Quiche.reason
  | None -> Alcotest.fail "no peer error on server");
  Quiche.conn_free client;
  Quiche.conn_free server

let test_clean () = run_exchange ()

let test_lossy () =
  let rng = Random.State.make [| 0xbeef |] in
  run_exchange ~rng ~loss:0.05 ()

let () =
  Alcotest.run "quiche-pair"
    [
      ( "pair",
        [
          Alcotest.test_case "handshake+streams+dgrams+close" `Quick test_clean;
          Alcotest.test_case "same under 5% loss" `Slow test_lossy;
        ] );
    ]
