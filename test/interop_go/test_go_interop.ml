(* Interop against quic-go/webtransport-go (draft-16), both directions:
   the Go client speaks to our Eio server, then our Eio client speaks to the
   Go server. Opt-in (needs a Go toolchain + module downloads):

     WT_GO=1 dune exec test/interop_go/test_go_interop.exe *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let go_dir () =
  match Sys.getenv_opt "WT_GO_DIR" with
  | Some d -> d
  | None -> (
      (* dune exec runs from the project root; dune runtest from the test's
         _build directory. *)
      let candidates =
        [
          "interop/go";
          Filename.concat (Sys.getcwd ()) "../../../../interop/go";
        ]
      in
      match List.find_opt Sys.file_exists candidates with
      | Some d -> d
      | None -> failwith "cannot locate interop/go (set WT_GO_DIR)")

let echo_handler session =
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
  with Webtransport_eio.Session_closed _ -> ()

let () =
  match Sys.getenv_opt "WT_GO" with
  | None -> print_endline "go interop: skipped (set WT_GO=1 to run)"
  | Some _ ->
      Random.self_init ();
      Eio_main.run @@ fun env ->
      Switch.run @@ fun sw ->
      let net = Eio.Stdenv.net env in
      let mono = Eio.Stdenv.mono_clock env in
      let clock = Eio.Stdenv.clock env in
      let proc = Eio.Stdenv.process_mgr env in
      let fs = Eio.Stdenv.fs env in
      let godir = go_dir () in
      let bin = Filename.temp_file "wtinterop" ".bin" in
      Eio.Process.run proc ~cwd:Eio.Path.(fs / godir)
        [ "go"; "build"; "-o"; bin; "." ];
      print_endline "go peer built";

      (* --- Part A: Go client -> our server --- *)
      let certs = Wt_certs.generate () in
      Wt_certs.with_temp_files certs @@ fun ~cert_file ~key_file ->
      let module B = Webtransport_quiche in
      let get = function Ok v -> v | Error m -> failwith m in
      let scfg =
        get
          (B.config ~role:`Server ~alpn:[ "h3" ] ~cert_chain_pem_file:cert_file
             ~priv_key_pem_file:key_file ~enable_datagrams:true ())
      in
      let sessions_seen = ref 0 in
      let rec bind_port tries =
        let port = 20000 + Random.int 30000 in
        match
          Wt.listen ~sw ~net ~clock:mono
            ~backend:(Webtransport_eio.Backend ((module B), scfg))
            ~port
            ~fc:(1 lsl 20, 64, 64)
            ~handler:(fun s ->
              incr sessions_seen;
              echo_handler s)
            ()
        with
        | () -> port
        | exception _ when tries > 0 -> bind_port (tries - 1)
      in
      let port = bind_port 5 in
      Eio.Process.run proc
        [
          bin; "-mode"; "client"; "-url";
          Printf.sprintf "https://127.0.0.1:%d/echo" port;
        ];
      assert (!sessions_seen = 1);
      print_endline "go-client -> ocaml-server: OK";

      (* --- Part B: our client -> Go server --- *)
      let r, w = Eio.Process.pipe ~sw proc in
      let server_proc =
        Eio.Process.spawn ~sw proc ~stdout:w [ bin; "-mode"; "server" ]
      in
      Eio.Flow.close w;
      let br = Eio.Buf_read.of_flow ~max_size:4096 r in
      let line = Eio.Buf_read.line br in
      let go_port = Scanf.sscanf line "PORT=%d" Fun.id in
      Printf.printf "go server on port %d\n%!" go_port;
      let ccfg =
        get
          (B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None
             ~enable_datagrams:true ())
      in
      let session =
        Wt.connect ~sw ~net ~clock:mono
          ~backend:(Webtransport_eio.Backend ((module B), ccfg))
          ~server_name:"localhost"
          ~fc:(1 lsl 20, 64, 64)
          ~peer:("\127\000\000\001", go_port)
          ~authority:(Printf.sprintf "127.0.0.1:%d" go_port)
          ~path:"/echo" ()
      in
      (* Bidi echo. *)
      let st = Wt.open_bidi session in
      Wt.Stream.write st "ocaml-bidi-ping";
      Wt.Stream.close_write st;
      assert (Wt.Stream.read_all st = "ocaml-bidi-ping");
      (* Uni out, echo on a go-initiated uni. *)
      let uni = Wt.open_uni session in
      Wt.Stream.write uni "ocaml-uni-ping";
      Wt.Stream.close_write uni;
      let incoming = Wt.accept_uni session in
      assert (Wt.Stream.read_all incoming = "ocaml-uni-ping");
      (* Datagram echo with retry. *)
      let rec dgram_roundtrip tries =
        ignore (Wt.Session.send_datagram session "ocaml-dgram");
        match
          Fiber.first
            (fun () -> Some (Wt.Session.recv_datagram session))
            (fun () ->
              Eio.Time.Mono.sleep mono 0.5;
              None)
        with
        | Some d ->
            assert (d = "ocaml-dgram")
        | None when tries > 0 -> dgram_roundtrip (tries - 1)
        | None -> failwith "datagram echo timed out"
      in
      dgram_roundtrip 5;
      Wt.Session.close ~code:0 session;
      print_endline "ocaml-client -> go-server: OK";
      (try Eio.Process.signal server_proc Sys.sigkill with _ -> ());
      (try Sys.remove bin with _ -> ());
      ignore clock;
      print_endline "go interop: PASS"
