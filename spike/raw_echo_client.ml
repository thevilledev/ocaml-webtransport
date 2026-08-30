(* P0 spike: quiche-backed raw QUIC client for the reverse-direction test.
   Connects to 127.0.0.1:PORT, echoes 10 KiB over a bidi stream, then
   closes with application code 42. *)

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

let () =
  let port = int_of_string Sys.argv.(1) in
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.mono_clock env in
  let module B = Webtransport_quiche in
  let get = function Ok v -> v | Error m -> failwith m in
  let ccfg =
    get (B.config ~role:`Client ~alpn:[ "h3" ] ~verify:`None ())
  in
  let conn =
    Raw.connect ~sw ~net ~clock
      ~backend:(Webtransport_eio.Backend ((module B), ccfg))
      ~server_name:"localhost"
      ~peer:("\127\000\000\001", port)
      ()
  in
  Raw.established conn;
  Printf.printf "CLIENT(quiche): established\n%!";
  Fiber.fork ~sw (fun () ->
      try
        let info = Raw.closed conn in
        Printf.printf "CLIENT(quiche): CLOSE code=%d remote=%b app=%b reason=%S\n%!"
          info.code info.remote info.app info.reason
      with _ -> ());
  let id = Raw.open_stream conn ~dir:`Bidi in
  let msg = String.init 10240 (fun i -> Char.chr (i land 0xff)) in
  Raw.write conn ~id msg;
  Raw.finish conn ~id;
  let echoed =
    try read_all conn ~id
    with e ->
      Printf.printf "CLIENT(quiche): read raised %s\n%!" (Printexc.to_string e);
      Eio.Time.Mono.sleep clock 1.0;
      raise e
  in
  if String.equal echoed msg then
    Printf.printf "CLIENT(quiche): echo OK bytes=%d\n%!" (String.length echoed)
  else (
    Printf.printf "CLIENT(quiche): echo MISMATCH got=%d\n%!"
      (String.length echoed);
    exit 1);
  Raw.close conn ~code:42 ~reason:"done";
  Printf.printf "CLIENT(quiche): closed code=42\n%!"
