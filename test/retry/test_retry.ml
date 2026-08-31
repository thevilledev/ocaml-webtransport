(* End-to-end Retry over real UDP with the pure backend: a server started
   with ~retry:true forces every client through a Retry round-trip before
   the handshake completes, exercising the driver's stateless-Retry path,
   the engine's client-side Retry handling, and the odcid/retry_scid
   transport-parameter authentication. *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let handler session =
  Switch.run @@ fun sw ->
  try
    while true do
      let st = Wt.accept_bidi session in
      Fiber.fork ~sw (fun () ->
          try
            let data = Wt.Stream.read_all st in
            Wt.Stream.write st data;
            Wt.Stream.close_write st
          with _ -> ())
    done
  with _ -> ()

let () =
  Mirage_crypto_rng_unix.use_default ();
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  let net = Eio.Stdenv.net env in
  let mono = Eio.Stdenv.mono_clock env in
  let certs = Wt_certs.generate () in
  let module B = Webtransport_purequic in
  let get = function Ok v -> v | Error m -> failwith m in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:[ "h3" ]
         ~cert_chain_pem:certs.Wt_certs.cert_pem
         ~priv_key_pem:certs.Wt_certs.key_pem ())
  in
  let ccfg = get (B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None ()) in
  let rec bind_port tries =
    let port = 20000 + Random.int 30000 in
    match
      Wt.listen ~sw ~net ~clock:mono
        ~backend:(Webtransport_eio.Backend ((module B), scfg))
        ~retry:true ~port ~handler ()
    with
    | () -> port
    | exception _ when tries > 0 -> bind_port (tries - 1)
  in
  let port = bind_port 5 in
  let session =
    Wt.connect ~sw ~net ~clock:mono
      ~backend:(Webtransport_eio.Backend ((module B), ccfg))
      ~server_name:"localhost"
      ~peer:("\127\000\000\001", port)
      ~authority:(Printf.sprintf "localhost:%d" port)
      ~path:"/echo" ()
  in
  let st = Wt.open_bidi session in
  Wt.Stream.write st "retry-echo";
  Wt.Stream.close_write st;
  assert (Wt.Stream.read_all st = "retry-echo");
  Wt.Session.close ~code:0 session;
  print_endline "retry interop: OK"
