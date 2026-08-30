(* End-to-end raw QUIC echo over real UDP sockets: Eio server and client in
   one process, quiche backend, streams + datagrams. *)

open Eio.Std
module Raw = Webtransport_eio.Raw

let read_all conn ~id =
  let buf = Bigstringaf.create 4096 in
  let b = Buffer.create 64 in
  let rec loop () =
    match Raw.read conn ~id buf ~off:0 ~len:4096 with
    | `Data n ->
        Buffer.add_string b (Bigstringaf.substring buf ~off:0 ~len:n);
        loop ()
    | `Fin -> Buffer.contents b
  in
  loop ()

let echo_handler conn =
  Switch.run @@ fun sw ->
  Fiber.fork ~sw (fun () ->
      try
        while true do
          Raw.send_dgram conn (Raw.recv_dgram conn)
        done
      with Webtransport_eio.Connection_closed _ -> ());
  try
    while true do
      let id = Raw.accept_stream conn in
      Fiber.fork ~sw (fun () ->
          try
            let data = read_all conn ~id in
            Raw.write conn ~id data;
            Raw.finish conn ~id
          with Webtransport_eio.Connection_closed _ -> ())
    done
  with Webtransport_eio.Connection_closed _ -> ()

let () =
  Random.self_init ();
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.mono_clock env in
  let certs = Wt_certs.generate () in
  Wt_certs.with_temp_files certs @@ fun ~cert_file ~key_file ->
  let module B = Webtransport_quiche in
  let get = function Ok v -> v | Error m -> failwith m in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:[ "wt-raw" ] ~cert_chain_pem_file:cert_file
         ~priv_key_pem_file:key_file ~enable_datagrams:true ())
  in
  let ccfg =
    get
      (B.config ~role:`Client ~alpn:[ "wt-raw" ] ~verify:`None
         ~enable_datagrams:true ())
  in
  let rec bind_port tries =
    let port = 20000 + Random.int 30000 in
    match
      Raw.listen ~sw ~net ~clock
        ~backend:(Webtransport_eio.Backend ((module B), scfg))
        ~port ~handler:echo_handler
    with
    | () -> port
    | exception _ when tries > 0 -> bind_port (tries - 1)
  in
  let port = bind_port 5 in
  let conn =
    Raw.connect ~sw ~net ~clock
      ~backend:(Webtransport_eio.Backend ((module B), ccfg))
      ~server_name:"localhost"
      ~peer:("\127\000\000\001", port)
      ()
  in
  (* Bidi stream echo. *)
  let id = Raw.open_stream conn ~dir:`Bidi in
  let msg = "hello eio quic" in
  Raw.write conn ~id msg;
  Raw.finish conn ~id;
  let echoed = read_all conn ~id in
  assert (echoed = msg);
  (* A second stream, to exercise accept dispatch repeatedly. *)
  let id2 = Raw.open_stream conn ~dir:`Bidi in
  let msg2 = String.concat "-" (List.init 500 string_of_int) in
  Raw.write conn ~id:id2 msg2;
  Raw.finish conn ~id:id2;
  assert (read_all conn ~id:id2 = msg2);
  (* Datagram echo. *)
  Raw.send_dgram conn "dgram-ping";
  assert (Raw.recv_dgram conn = "dgram-ping");
  Raw.close conn ~code:0 ~reason:"done";
  print_endline "eio raw echo: OK"
