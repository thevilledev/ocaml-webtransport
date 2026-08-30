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
  let module B = Webtransport_quiche in
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
    (* Echo datagrams until the session ends. *)
    try
      while true do
        Wt.Session.send_datagram session (Wt.Session.recv_datagram session)
        |> ignore
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
