(* Two purequic backends through an in-memory pipe under a scripted
   clock: fully deterministic handshake, stream echo, datagrams, close,
   idle timeout and loss recovery — no sockets, no wall time. This is the
   pure analog of test/quiche_pair (which needs real timers because
   quiche keeps an internal clock). *)

module B = Webtransport_purequic

let caddr = ("\127\000\000\001", 1111)
let saddr = ("\127\000\000\001", 4433)
let alpn = "pp-test"

let reseed () =
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:"pure-pair" (module Mirage_crypto_rng.Fortuna))

let get = function Ok v -> v | Error m -> Alcotest.fail m

let mk_pair ?(loss = fun _ -> false) ?(client_dgrams = true) () =
  reseed ();
  let certs = Wt_certs.generate () in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:[ alpn ]
         ~cert_chain_pem:certs.Wt_certs.cert_pem
         ~priv_key_pem:certs.Wt_certs.key_pem ~enable_datagrams:true
         ~max_idle_ns:5_000_000_000L ())
  in
  let ccfg =
    get
      (B.config ~role:`Client ~alpn:[ alpn ] ~verify:`None
         ~enable_datagrams:client_dgrams ~max_idle_ns:5_000_000_000L ())
  in
  let now = ref 1_000_000_000L in
  let scid_c = String.init 16 (fun i -> Char.chr (0x30 + i)) in
  let scid_s = String.init 16 (fun i -> Char.chr (0x90 + i)) in
  let client =
    get (B.connect ccfg ~server_name:(Some "localhost") ~scid:scid_c ~peer:saddr
           ~local:("\000\000\000\000", 0) ~now:!now)
  in
  let server =
    get (B.accept scfg ~scid:scid_s ~peer:caddr ~local:("\000\000\000\000", 0)
           ~now:!now)
  in
  (certs, now, client, server, loss)

let buf = Bigstringaf.create 4096
let scratch = Bigstringaf.create 65536

(* Move every pending datagram from [src] to [dst]; returns whether
   anything moved. *)
let pump ~now ~loss src dst ~from =
  ignore scratch;
  let moved = ref false in
  let rec go () =
    match B.send src ~now buf with
    | `Done -> ()
    | `Error e -> Alcotest.fail ("send: " ^ e)
    | `Packet (n, _) ->
        moved := true;
        if not (loss n) then
          ignore (B.recv dst ~now buf ~off:0 ~len:n ~from ~to_:("\000\000\000\000", 0));
        go ()
  in
  go ();
  !moved

let drain side f =
  let rec go () =
    match B.next_event side with
    | None -> ()
    | Some e ->
        f e;
        go ()
  in
  go ()

(* Advance the virtual clock to the earliest pending timeout. *)
let tick now client server =
  let d1 = B.next_timeout_ns client and d2 = B.next_timeout_ns server in
  let d =
    match (d1, d2) with
    | Some a, Some b -> Some (Int64.min a b)
    | (Some _ as x), None | None, (Some _ as x) -> x
    | None, None -> None
  in
  match d with
  | None -> false
  | Some d ->
      now := Int64.add !now (Int64.max d 1L);
      B.on_timeout client ~now:!now;
      B.on_timeout server ~now:!now;
      true

let drive ?(max_iters = 500) ~now ~loss ~client ~server ~on_event until =
  let rec go n =
    if until () then ()
    else if n = 0 then Alcotest.fail "drive: did not converge"
    else begin
      let m1 = pump ~now:!now ~loss client server ~from:caddr in
      let m2 = pump ~now:!now ~loss server client ~from:saddr in
      drain client (on_event `Client);
      drain server (on_event `Server);
      if (not m1) && not m2 && not (until ()) then
        if not (tick now client server) then
          Alcotest.fail "drive: stalled with no timers"
        else begin
          drain client (on_event `Client);
          drain server (on_event `Server)
        end;
      go (n - 1)
    end
  in
  go max_iters

(* Accumulating reader: safe to poll repeatedly from a [drive] condition. *)
let read_all side ~id =
  let acc = Buffer.create 256 in
  let tmp = Bigstringaf.create 4096 in
  fun () ->
    let rec go () =
      match B.stream_recv side ~id tmp ~off:0 ~len:4096 with
      | Ok (n, fin) ->
          Buffer.add_string acc (Bigstringaf.substring tmp ~off:0 ~len:n);
          if fin then `Fin (Buffer.contents acc) else go ()
      | Error `Fin -> `Fin (Buffer.contents acc)
      | Error `Would_block -> `More (Buffer.contents acc)
      | Error (`Reset c) -> `Reset c
      | Error (`Stopped _) | Error `Invalid -> Alcotest.fail "read_all: invalid"
    in
    go ()

let write_str side ~id ?(fin = false) s =
  let bs = Bigstringaf.of_string s ~off:0 ~len:(String.length s) in
  match B.stream_send side ~id bs ~off:0 ~len:(String.length s) ~fin with
  | Ok n when n = String.length s -> ()
  | Ok n -> Alcotest.failf "short write %d/%d" n (String.length s)
  | Error _ -> Alcotest.fail "write failed"

(* ---- scenarios ---- *)

let handshake ?(loss = fun _ -> false) () =
  let certs, now, client, server, _ = mk_pair ~loss () in
  let c_hs = ref None and s_hs = ref None in
  let on_event side e =
    match (side, e) with
    | `Client, B.Handshake_done { alpn; _ } -> c_hs := alpn
    | `Server, B.Handshake_done { alpn; _ } -> s_hs := alpn
    | _ -> ()
  in
  drive ~now ~loss ~client ~server ~on_event (fun () ->
      B.is_established client && B.is_established server);
  Alcotest.(check (option string)) "client alpn" (Some alpn) !c_hs;
  Alcotest.(check (option string)) "server alpn" (Some alpn) !s_hs;
  (certs, now, client, server, loss)

let test_handshake () =
  let certs, _, client, _, _ = handshake () in
  match B.peer_cert_der client with
  | Some der ->
      Alcotest.(check bool) "server cert der" true
        (String.equal der certs.Wt_certs.cert_der)
  | None -> Alcotest.fail "client has no peer cert"

let test_echo () =
  let _, now, client, server, loss = handshake () in
  let opened = ref None and readable = ref false in
  let on_event side e =
    match (side, e) with
    | `Server, B.Stream_opened { id; dir = `Bidi } -> opened := Some id
    | `Server, B.Stream_readable _ -> readable := true
    | _ -> ()
  in
  let id =
    match B.open_stream client ~dir:`Bidi with
    | Ok id -> id
    | Error _ -> Alcotest.fail "open_stream"
  in
  let msg = String.init 20_000 (fun i -> Char.chr (i land 0xff)) in
  write_str client ~id ~fin:true msg;
  let reader = ref None in
  let got = ref "" in
  drive ~now ~loss ~client ~server ~on_event (fun () ->
      match !opened with
      | Some sid -> (
          let r =
            match !reader with
            | Some r -> r
            | None ->
                let r = read_all server ~id:sid in
                reader := Some r;
                r
          in
          match r () with
          | `Fin data ->
              got := data;
              true
          | `More _ -> false
          | `Reset _ -> Alcotest.fail "unexpected reset")
      | None -> false);
  Alcotest.(check int) "server got all" (String.length msg) (String.length !got);
  Alcotest.(check bool) "payload intact" true (String.equal !got msg);
  (* echo back *)
  let sid = Option.get !opened in
  write_str server ~id:sid ~fin:true msg;
  let back = read_all client ~id in
  let echoed = ref "" in
  drive ~now ~loss ~client ~server
    ~on_event:(fun _ _ -> ())
    (fun () ->
      match back () with
      | `Fin data ->
          echoed := data;
          true
      | `More _ -> false
      | `Reset _ -> Alcotest.fail "unexpected reset");
  Alcotest.(check bool) "echo intact" true (String.equal !echoed msg)

let test_datagrams () =
  let _, now, client, server, loss = handshake () in
  (match B.dgram_max_len client with
  | Some n -> Alcotest.(check bool) "dgram max sane" true (n > 1000)
  | None -> Alcotest.fail "datagrams unsupported");
  let payload = "dgram-ping" in
  let bs = Bigstringaf.of_string payload ~off:0 ~len:(String.length payload) in
  (match B.dgram_send client bs ~off:0 ~len:(String.length payload) with
  | Ok () -> ()
  | Error _ -> Alcotest.fail "dgram_send");
  let got = ref None in
  drive ~now ~loss ~client ~server
    ~on_event:(fun _ _ -> ())
    (fun () ->
      let tmp = Bigstringaf.create 2048 in
      match B.dgram_recv server tmp ~off:0 with
      | Ok n ->
          got := Some (Bigstringaf.substring tmp ~off:0 ~len:n);
          true
      | Error `Would_block -> false
      | Error _ -> Alcotest.fail "dgram_recv");
  Alcotest.(check (option string)) "datagram echoed" (Some payload) !got

let test_close () =
  let _, now, client, server, loss = handshake () in
  let closed = ref None in
  B.close client ~app:true ~code:42 ~reason:"done";
  drive ~now ~loss ~client ~server
    ~on_event:(fun side e ->
      match (side, e) with
      | `Server, B.Closed { code; app; local; reason } ->
          closed := Some (code, app, local, reason)
      | _ -> ())
    (fun () -> !closed <> None);
  (match !closed with
  | Some (code, app, local, reason) ->
      Alcotest.(check int) "code" 42 code;
      Alcotest.(check bool) "app" true app;
      Alcotest.(check bool) "remote" false local;
      Alcotest.(check string) "reason" "done" reason
  | None -> assert false);
  (* both ends drain to Dead within 3 PTOs of virtual time *)
  drive ~now ~loss ~client ~server
    ~on_event:(fun _ _ -> ())
    (fun () -> B.is_closed client && B.is_closed server)

let test_idle_timeout () =
  let _, now, client, server, _ = handshake () in
  (* the network goes dark: outgoing packets vanish, nothing arrives *)
  let closed = ref false in
  let void () =
    let rec go () =
      match B.send client ~now:!now buf with
      | `Packet _ -> go ()
      | `Done | `Error _ -> ()
    in
    go ()
  in
  let rec go n =
    if n = 0 then Alcotest.fail "no idle timeout";
    void ();
    (match B.next_timeout_ns client with
    | Some d -> now := Int64.add !now (Int64.max d 1L)
    | None -> now := Int64.add !now 1_000_000_000L);
    B.on_timeout client ~now:!now;
    drain client (fun e ->
        match e with
        | B.Closed { code = 0; app = false; local = true; _ } -> closed := true
        | _ -> ());
    if B.is_closed client then () else go (n - 1)
  in
  go 100;
  ignore server;
  Alcotest.(check bool) "idle close event" true !closed

let test_loss_recovery () =
  (* deterministic 20% loss both directions, seeded *)
  let st = Random.State.make [| 0x1055 |] in
  let loss _ = Random.State.float st 1.0 < 0.2 in
  let _, now, client, server, _ = handshake ~loss () in
  let opened = ref None in
  let id =
    match B.open_stream client ~dir:`Bidi with
    | Ok id -> id
    | Error _ -> Alcotest.fail "open_stream"
  in
  let msg = String.init 50_000 (fun i -> Char.chr ((i * 7) land 0xff)) in
  write_str client ~id ~fin:true msg;
  let reader = ref None in
  drive ~max_iters:5000 ~now ~loss ~client ~server
    ~on_event:(fun side e ->
      match (side, e) with
      | `Server, B.Stream_opened { id; _ } -> opened := Some id
      | _ -> ())
    (fun () ->
      match !opened with
      | Some sid -> (
          let r =
            match !reader with
            | Some r -> r
            | None ->
                let r = read_all server ~id:sid in
                reader := Some r;
                r
          in
          match r () with
          | `Fin data -> String.equal data msg
          | `More _ -> false
          | `Reset _ -> Alcotest.fail "reset under loss")
      | None -> false)

let test_key_update () =
  let _, now, client, server, loss = handshake () in
  let id =
    match B.open_stream client ~dir:`Bidi with
    | Ok id -> id
    | Error _ -> Alcotest.fail "open"
  in
  write_str client ~id "before-update";
  let opened = ref None in
  drive ~now ~loss ~client ~server
    ~on_event:(fun side e ->
      match (side, e) with
      | `Server, B.Stream_opened { id; _ } -> opened := Some id
      | _ -> ())
    (fun () -> !opened <> None);
  B.For_testing.initiate_key_update client;
  write_str client ~id ~fin:true "-after-update";
  let sid = Option.get !opened in
  let r = read_all server ~id:sid in
  drive ~now ~loss ~client ~server
    ~on_event:(fun _ _ -> ())
    (fun () ->
      match r () with
      | `Fin data -> String.equal data "before-update-after-update"
      | `More _ -> false
      | `Reset _ -> Alcotest.fail "reset");
  ()

let test_reset () =
  let _, now, client, server, loss = handshake () in
  let id =
    match B.open_stream client ~dir:`Uni with
    | Ok id -> id
    | Error _ -> Alcotest.fail "open uni"
  in
  write_str client ~id "partial";
  let opened = ref None and reset_code = ref None in
  drive ~now ~loss ~client ~server
    ~on_event:(fun side e ->
      match (side, e) with
      | `Server, B.Stream_opened { id; dir = `Uni } -> opened := Some id
      | `Server, B.Stream_reset { code; _ } -> reset_code := Some code
      | _ -> ())
    (fun () -> !opened <> None);
  (match B.stream_reset client ~id ~code:77 with
  | Ok () -> ()
  | Error _ -> Alcotest.fail "stream_reset");
  drive ~now ~loss ~client ~server
    ~on_event:(fun side e ->
      match (side, e) with
      | `Server, B.Stream_reset { code; _ } -> reset_code := Some code
      | _ -> ())
    (fun () -> !reset_code <> None);
  Alcotest.(check (option int)) "reset code" (Some 77) !reset_code

let test_reset_at () =
  let _, now, client, server, loss = handshake () in
  Alcotest.(check bool) "peer negotiated reliable reset" true
    (B.supports_reset_at client);
  let id =
    match B.open_stream client ~dir:`Uni with
    | Ok id -> id
    | Error _ -> Alcotest.fail "open uni"
  in
  (* queue data and reset before anything is pumped: the sender must
     transmit only the reliable prefix *)
  write_str client ~id "reliable-prefix|and-junk-after";
  let reliable = String.length "reliable-prefix|" in
  (match B.stream_reset_at client ~id ~code:99 ~reliable_size:reliable with
  | Ok () -> ()
  | Error _ -> Alcotest.fail "stream_reset_at");
  let opened = ref None in
  let seen_event = ref None in
  let watch side e =
    match (side, e) with
    | `Server, B.Stream_opened { id; dir = `Uni } -> opened := Some id
    | `Server, B.Stream_reset_at { code; reliable_size; _ } ->
        seen_event := Some (code, reliable_size)
    | _ -> ()
  in
  drive ~now ~loss ~client ~server ~on_event:watch (fun () -> !opened <> None);
  let sid = Option.get !opened in
  let acc = Buffer.create 64 in
  let tmp = Bigstringaf.create 256 in
  let outcome = ref None in
  drive ~now ~loss ~client ~server ~on_event:watch (fun () ->
      let rec go () =
        match B.stream_recv server ~id:sid tmp ~off:0 ~len:256 with
        | Ok (n, _) ->
            Buffer.add_string acc (Bigstringaf.substring tmp ~off:0 ~len:n);
            go ()
        | Error (`Reset c) ->
            outcome := Some c;
            true
        | Error `Would_block -> false
        | Error `Fin -> Alcotest.fail "unexpected clean fin"
        | Error _ -> Alcotest.fail "unexpected read error"
      in
      go ());
  Alcotest.(check (option int)) "reset code delivered" (Some 99) !outcome;
  Alcotest.(check (option (pair int int))) "reset_at event" (Some (99, reliable))
    !seen_event;
  Alcotest.(check string) "reliable prefix delivered" "reliable-prefix|"
    (Buffer.contents acc)

let () =
  Alcotest.run "pure_pair"
    [
      ( "pair",
        [
          ("handshake + cert", `Quick, test_handshake);
          ("bidi echo 20k", `Quick, test_echo);
          ("datagrams", `Quick, test_datagrams);
          ("close code", `Quick, test_close);
          ("idle timeout", `Quick, test_idle_timeout);
          ("loss recovery 20%", `Quick, test_loss_recovery);
          ("key update", `Quick, test_key_update);
          ("stream reset", `Quick, test_reset);
          ("reliable reset (RESET_STREAM_AT)", `Quick, test_reset_at);
        ] );
    ]
