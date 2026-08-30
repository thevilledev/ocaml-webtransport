(* A WebTransport echo server: echoes datagrams, echoes bidi streams in
   place, and answers each incoming uni stream on a fresh server-initiated
   uni stream.

     dune exec examples/echo_server.exe [PORT]

   It prints the certificate hash to paste into a browser client:

     const wt = new WebTransport("https://127.0.0.1:PORT/echo", {
       serverCertificateHashes: [{ algorithm: "sha-256",
         value: Uint8Array.from(atob("<hash>"), c => c.charCodeAt(0)) }] });
*)

open Eio.Std
module Wt = Webtransport_eio.Wt

let handler session =
  traceln "session: %s from %s" (Wt.Session.path session)
    (Option.value ~default:"-" (Wt.Session.origin session));
  Switch.run @@ fun sw ->
  Fiber.fork ~sw (fun () ->
      try
        while true do
          ignore
            (Wt.Session.send_datagram session (Wt.Session.recv_datagram session))
        done
      with Webtransport_eio.Session_closed _ -> ());
  Fiber.fork ~sw (fun () ->
      try
        while true do
          let st = Wt.accept_uni session in
          Fiber.fork ~sw (fun () ->
              try
                let data = Wt.Stream.read_all st in
                let out = Wt.open_uni session in
                Wt.Stream.write out data;
                Wt.Stream.close_write out
              with Webtransport_eio.Session_closed _ -> ())
        done
      with Webtransport_eio.Session_closed _ -> ());
  try
    while true do
      let st = Wt.accept_bidi session in
      Fiber.fork ~sw (fun () ->
          try
            let data = Wt.Stream.read_all st in
            Wt.Stream.write st data;
            Wt.Stream.close_write st
          with Webtransport_eio.Session_closed _ -> ())
    done
  with Webtransport_eio.Session_closed (code, msg) ->
    traceln "session closed: code=%d %S" code msg

let () =
  let port =
    if Array.length Sys.argv > 1 then int_of_string Sys.argv.(1) else 4433
  in
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  let certs = Wt_certs.generate () in
  Wt_certs.with_temp_files certs @@ fun ~cert_file ~key_file ->
  let module B = Webtransport_quiche in
  let cfg =
    match
      B.config ~role:`Server ~alpn:[ "h3" ] ~cert_chain_pem_file:cert_file
        ~priv_key_pem_file:key_file ~enable_datagrams:true ()
    with
    | Ok c -> c
    | Error m -> failwith m
  in
  Wt.listen ~sw
    ~net:(Eio.Stdenv.net env)
    ~clock:(Eio.Stdenv.mono_clock env)
    ~backend:(Webtransport_eio.Backend ((module B), cfg))
    ~port ~handler ();
  traceln "webtransport echo server on https://127.0.0.1:%d/echo" port;
  traceln "certificate hash (b64): %s" (Wt_certs.hash_b64 certs);
  traceln "valid until %a (regenerate by restarting)"
    (Ptime.pp_rfc3339 ()) certs.Wt_certs.not_after;
  Fiber.await_cancel ()
