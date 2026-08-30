(* WebTransport self-interop on the Lwt driver: sessions, streams (bidi +
   uni + a large transfer, with flow control negotiated), datagrams, close.
   Runtime parity check with the Eio suite. *)

open Lwt.Infix
module Wt = Webtransport_lwt.Wt

let ( let* ) = Lwt.bind

let handler session =
  (* Datagram echo. *)
  Lwt.async (fun () ->
      Lwt.catch
        (fun () ->
          let rec loop () =
            Wt.Session.recv_datagram session >>= fun d ->
            Wt.Session.send_datagram session d >>= fun _ -> loop ()
          in
          loop ())
        (fun _ -> Lwt.return_unit));
  (* Uni echo on a fresh server-initiated stream. *)
  Lwt.async (fun () ->
      Lwt.catch
        (fun () ->
          let rec loop () =
            Wt.accept_uni session >>= fun st ->
            Lwt.async (fun () ->
                Lwt.catch
                  (fun () ->
                    Wt.Stream.read_all st >>= fun data ->
                    Wt.open_uni session >>= fun out ->
                    Wt.Stream.write out data >>= fun () ->
                    Wt.Stream.close_write out)
                  (fun _ -> Lwt.return_unit));
            loop ()
          in
          loop ())
        (fun _ -> Lwt.return_unit));
  (* Bidi echo on the same stream. *)
  Lwt.catch
    (fun () ->
      let rec loop () =
        Wt.accept_bidi session >>= fun st ->
        Lwt.async (fun () ->
            Lwt.catch
              (fun () ->
                Wt.Stream.read_all st >>= fun data ->
                Wt.Stream.write st data >>= fun () -> Wt.Stream.close_write st)
              (fun _ -> Lwt.return_unit));
        loop ()
      in
      loop ())
    (fun _ -> Lwt.return_unit)

let () =
  Printexc.register_printer (function
    | Webtransport_lwt.Connection_closed { code; reason; remote; app } ->
        Some
          (Printf.sprintf
             "Connection_closed { code = 0x%x; reason = %S; remote = %b; app = %b }"
             code reason remote app)
    | _ -> None)

let main () =
  Random.self_init ();
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
    get
      (B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None
         ~enable_datagrams:true ())
  in
  let port = 20000 + Random.int 30000 in
  (* Small data window: the large transfer below forces several rounds of
     WT_MAX_DATA grants in both directions. *)
  let fc = Some (65_536, 64, 64) in
  Lwt.async (fun () ->
      Wt.listen
        ~backend:(Webtransport_lwt.Backend ((module B), scfg))
        ~port ?fc ~handler ());
  let* () = Lwt_unix.sleep 0.05 in
  let* session =
    Wt.connect
      ~backend:(Webtransport_lwt.Backend ((module B), ccfg))
      ~server_name:"localhost" ?fc
      ~peer:("\127\000\000\001", port)
      ~authority:(Printf.sprintf "localhost:%d" port)
      ~path:"/lwt-echo" ()
  in
  assert (Wt.Session.path session = "/lwt-echo");
  (* Datagram echo with retry (unreliable by design). *)
  let rec dgram_roundtrip tries =
    let* _ = Wt.Session.send_datagram session "lwt-ping" in
    Lwt.pick
      [
        (Wt.Session.recv_datagram session >|= fun d -> Some d);
        (Lwt_unix.sleep 0.5 >|= fun () -> None);
      ]
    >>= function
    | Some d ->
        assert (d = "lwt-ping");
        Lwt.return_unit
    | None when tries > 0 -> dgram_roundtrip (tries - 1)
    | None -> Lwt.fail_with "datagram echo timed out"
  in
  let* () = dgram_roundtrip 5 in
  (* Bidi echo. *)
  let* bidi = Wt.open_bidi session in
  let* () = Wt.Stream.write bidi "bidi-ping" in
  let* () = Wt.Stream.close_write bidi in
  let* echoed = Wt.Stream.read_all bidi in
  assert (echoed = "bidi-ping");
  (* Large transfer: crosses the session flow-control window repeatedly. *)
  let big = String.concat "," (List.init 30_000 string_of_int) in
  let* bidi2 = Wt.open_bidi session in
  let* () =
    Lwt.join
      [
        (Wt.Stream.write bidi2 big >>= fun () -> Wt.Stream.close_write bidi2);
        (Wt.Stream.read_all bidi2 >|= fun echoed -> assert (echoed = big));
      ]
  in
  (* Uni out, echoed back on a server-initiated uni. *)
  let* uni = Wt.open_uni session in
  let* () = Wt.Stream.write uni "uni-ping" in
  let* () = Wt.Stream.close_write uni in
  let* incoming = Wt.accept_uni session in
  let* uni_echo = Wt.Stream.read_all incoming in
  assert (uni_echo = "uni-ping");
  let* () = Wt.Session.close ~code:0 session in
  print_endline "lwt session self-interop: OK";
  Lwt.return_unit

let () = Lwt_main.run (main ())
