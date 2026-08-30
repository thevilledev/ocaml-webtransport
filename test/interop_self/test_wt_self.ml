(* WebTransport session self-interop over real UDP: OCaml client <-> OCaml
   server, both on the quiche backend. Exercises the whole M2 stack: control
   streams, SETTINGS, QPACK, extended CONNECT, accept/reject hooks, session
   datagrams, close capsules inside DATA frames. *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let () =
  Random.self_init ();
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.mono_clock env in
  let certs = Wt_certs.generate () in
  Wt_certs.with_temp_files certs @@ fun ~cert_file ~key_file ->
  let module B = (val Wt_test_backend.select ()) in
  let get = function Ok v -> v | Error m -> failwith m in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:[ "h3" ] ~cert_chain_pem_file:cert_file
         ~priv_key_pem_file:key_file ~enable_datagrams:true ())
  in
  let ccfg =
    get (B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None ~enable_datagrams:true ())
  in
  let seen_paths = ref [] in
  let handler session =
    seen_paths := Wt.Session.path session :: !seen_paths;
    Switch.run @@ fun hsw ->
    (* Datagram echo. *)
    Fiber.fork ~sw:hsw (fun () ->
        try
          while true do
            ignore
              (Wt.Session.send_datagram session
                 (Wt.Session.recv_datagram session))
          done
        with Webtransport_eio.Session_closed _ -> ());
    (* Uni: echo each incoming uni stream's payload on a fresh outgoing uni. *)
    Fiber.fork ~sw:hsw (fun () ->
        try
          while true do
            let st = Wt.accept_uni session in
            Fiber.fork ~sw:hsw (fun () ->
                try
                  let data = Wt.Stream.read_all st in
                  let out = Wt.open_uni session in
                  Wt.Stream.write out data;
                  Wt.Stream.close_write out
                with Webtransport_eio.Session_closed _ -> ())
          done
        with Webtransport_eio.Session_closed _ -> ());
    (* Bidi: echo on the same stream. *)
    try
      while true do
        let st = Wt.accept_bidi session in
        Fiber.fork ~sw:hsw (fun () ->
            try
              let data = Wt.Stream.read_all st in
              Wt.Stream.write st data;
              Wt.Stream.close_write st
            with Webtransport_eio.Session_closed _ -> ())
      done
    with Webtransport_eio.Session_closed _ -> ()
  in
  let accept req =
    if req.Webtransport.Engine.path = "/forbidden" then `Reject 403 else `Accept
  in
  let rec bind_port tries =
    let port = 20000 + Random.int 30000 in
    match
      Wt.listen ~sw ~net ~clock
        ~backend:(Webtransport_eio.Backend ((module B), scfg))
        ~port ~accept ~handler ()
    with
    | () -> port
    | exception _ when tries > 0 -> bind_port (tries - 1)
  in
  let port = bind_port 5 in

  (* Established session with datagram echo and clean close. *)
  let session =
    Wt.connect ~sw ~net ~clock
      ~backend:(Webtransport_eio.Backend ((module B), ccfg))
      ~server_name:"localhost" ~origin:"https://test.example"
      ~peer:("\127\000\000\001", port)
      ~authority:(Printf.sprintf "localhost:%d" port)
      ~path:"/echo" ()
  in
  assert (Wt.Session.path session = "/echo");
  assert (Wt.Session.origin session = Some "https://test.example");
  let rec dgram_roundtrip tries =
    (* Datagrams are unreliable even on loopback (quiche queue timing):
       retry a few times. *)
    ignore (Wt.Session.send_datagram session "ping-1");
    match
      Fiber.first
        (fun () -> Some (Wt.Session.recv_datagram session))
        (fun () ->
          Eio.Time.Mono.sleep clock 0.5;
          None)
    with
    | Some d ->
        assert (d = "ping-1");
        ()
    | None when tries > 0 -> dgram_roundtrip (tries - 1)
    | None -> failwith "datagram echo timed out"
  in
  dgram_roundtrip 5;

  (* Bidi stream echo (server echoes on the same stream). *)
  let bidi = Wt.open_bidi session in
  Wt.Stream.write bidi "bidi-ping";
  Wt.Stream.close_write bidi;
  assert (Wt.Stream.read_all bidi = "bidi-ping");

  (* A bigger transfer across many chunks. *)
  let big = String.concat "," (List.init 20_000 string_of_int) in
  let bidi2 = Wt.open_bidi session in
  Fiber.both
    (fun () ->
      Wt.Stream.write bidi2 big;
      Wt.Stream.close_write bidi2)
    (fun () -> assert (Wt.Stream.read_all bidi2 = big));

  (* Uni: send on ours, receive the echo on a server-initiated uni. *)
  let uni = Wt.open_uni session in
  Wt.Stream.write uni "uni-ping";
  Wt.Stream.close_write uni;
  let incoming = Wt.accept_uni session in
  assert (Wt.Stream.read_all incoming = "uni-ping");

  (* The same stream surface through the Eio.Flow view. *)
  let bidi3 = Wt.open_bidi session in
  let flow = Wt.Stream.to_flow bidi3 in
  Eio.Flow.copy_string "flow-ping" flow;
  Eio.Flow.shutdown flow `Send;
  let br = Eio.Buf_read.of_flow ~max_size:1024 flow in
  assert (Eio.Buf_read.take_all br = "flow-ping");

  Wt.Session.close ~code:0 session;

  (* Rejected session. *)
  (match
     Wt.connect ~sw ~net ~clock
       ~backend:(Webtransport_eio.Backend ((module B), ccfg))
       ~server_name:"localhost"
       ~peer:("\127\000\000\001", port)
       ~authority:(Printf.sprintf "localhost:%d" port)
       ~path:"/forbidden" ()
   with
  | exception Webtransport_eio.Session_rejected 403 -> ()
  | exception e -> raise e
  | _ -> failwith "expected rejection");

  assert (List.mem "/echo" !seen_paths);
  assert (not (List.mem "/forbidden" !seen_paths));
  print_endline "wt session self-interop: OK"
