(* P0 spike: quiche-backed raw QUIC echo server on a fixed port.
   Prints ESTABLISHED on handshake and CLOSE code=... on connection end,
   then exits, so the spike driver can assert on its output. *)

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
  Raw.established conn;
  Printf.printf "ESTABLISHED\n%!";
  Fiber.fork ~sw (fun () ->
      try
        while true do
          Raw.send_dgram conn (Raw.recv_dgram conn)
        done
      with Webtransport_eio.Connection_closed _ -> ());
  Fiber.fork ~sw (fun () ->
      let info = Raw.closed conn in
      Printf.printf "CLOSE code=%d remote=%b app=%b reason=%S\n%!" info.code
        info.remote info.app info.reason;
      exit 0);
  try
    while true do
      let id = Raw.accept_stream conn in
      Fiber.fork ~sw (fun () ->
          try
            let data = read_all conn ~id in
            Printf.printf "STREAM id=%d bytes=%d\n%!" id (String.length data);
            Raw.write conn ~id data;
            Raw.finish conn ~id
          with Webtransport_eio.Connection_closed _ -> ())
    done
  with Webtransport_eio.Connection_closed _ -> ()

let () =
  let port = int_of_string Sys.argv.(1) in
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
      (B.config ~role:`Server ~alpn:[ "h3" ] ~cert_chain_pem_file:cert_file
         ~priv_key_pem_file:key_file ~enable_datagrams:true ())
  in
  Raw.listen ~sw ~net ~clock
    ~backend:(Webtransport_eio.Backend ((module B), scfg))
    ~port ~handler:echo_handler;
  Printf.printf "LISTENING port=%d\n%!" port;
  Fiber.await_cancel ()
