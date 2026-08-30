(* A WebTransport echo client:

     dune exec examples/echo_client.exe [HOST] [PORT] [MESSAGE]

   Opens a session to https://HOST:PORT/echo (certificate verification off:
   this is a dev tool), echoes MESSAGE over a bidi stream and a datagram. *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let () =
  let arg i d = if Array.length Sys.argv > i then Sys.argv.(i) else d in
  let host = arg 1 "127.0.0.1" in
  let port = int_of_string (arg 2 "4433") in
  let message = arg 3 "hello from ocaml" in
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  (* WT_BACKEND=pure selects the pure-OCaml QUIC engine. *)
  let module B =
    (val match Sys.getenv_opt "WT_BACKEND" with
         | None | Some "quiche" -> (module Webtransport_quiche : Webtransport.Quic_backend.S)
         | Some "pure" -> (module Webtransport_purequic)
         | Some other -> failwith ("unknown WT_BACKEND: " ^ other))
  in
  let cfg =
    match
      B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None
        ~enable_datagrams:true ()
    with
    | Ok c -> c
    | Error m -> failwith m
  in
  let ip =
    match Ipaddr.of_string host with
    | Ok (Ipaddr.V4 v4) -> Ipaddr.V4.to_octets v4
    | Ok (Ipaddr.V6 v6) -> Ipaddr.V6.to_octets v6
    | Error _ -> failwith "HOST must be an IP literal"
  in
  let session =
    Wt.connect ~sw
      ~net:(Eio.Stdenv.net env)
      ~clock:(Eio.Stdenv.mono_clock env)
      ~backend:(Webtransport_eio.Backend ((module B), cfg))
      ~server_name:host
      ~peer:(ip, port)
      ~authority:(Printf.sprintf "%s:%d" host port)
      ~path:"/echo" ()
  in
  traceln "session established";
  let st = Wt.open_bidi session in
  Wt.Stream.write st message;
  Wt.Stream.close_write st;
  traceln "stream echo: %S" (Wt.Stream.read_all st);
  ignore (Wt.Session.send_datagram session message);
  (match
     Fiber.first
       (fun () -> Some (Wt.Session.recv_datagram session))
       (fun () ->
         Eio.Time.Mono.sleep (Eio.Stdenv.mono_clock env) 1.0;
         None)
   with
  | Some d -> traceln "datagram echo: %S" d
  | None -> traceln "datagram echo: (lost — datagrams are unreliable)");
  Wt.Session.close session
