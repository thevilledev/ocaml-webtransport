(* wt-devcert: development certificates for browser WebTransport.

   Generates an ECDSA P-256 self-signed certificate within the browsers'
   14-day validity cap and prints the SHA-256 certificate hash that a page
   passes to the WebTransport constructor as serverCertificateHashes. *)

let run out_dir hosts days =
  let t = Wt_certs.generate ~hosts ~validity_days:days () in
  let write name contents =
    let path = Filename.concat out_dir name in
    let oc = open_out path in
    output_string oc contents;
    close_out oc;
    path
  in
  let cert_path = write "cert.pem" t.Wt_certs.cert_pem in
  let key_path = write "key.pem" t.Wt_certs.key_pem in
  Printf.printf "wrote %s and %s\n" cert_path key_path;
  Printf.printf "valid until:  %s\n"
    (Format.asprintf "%a" (Ptime.pp_rfc3339 ()) t.Wt_certs.not_after);
  Printf.printf "hash (hex):   %s\n" (Wt_certs.hash_hex t);
  Printf.printf "hash (b64):   %s\n" (Wt_certs.hash_b64 t);
  Printf.printf
    "\nserverCertificateHashes: [{ algorithm: 'sha-256',\n\
    \  value: Uint8Array.from(atob('%s'), c => c.charCodeAt(0)) }]\n"
    (Wt_certs.hash_b64 t)

open Cmdliner

let out_dir =
  Arg.(value & opt string "." & info [ "o"; "out" ] ~docv:"DIR" ~doc:"Output directory.")

let hosts =
  Arg.(
    value
    & opt (list string) [ "localhost" ]
    & info [ "hosts" ] ~docv:"HOSTS" ~doc:"Comma-separated SAN host names.")

let days =
  Arg.(
    value & opt int 13
    & info [ "days" ] ~docv:"N"
        ~doc:"Validity in days (1-13; browsers cap custom certs at 14).")

let cmd =
  Cmd.v
    (Cmd.info "wt-devcert" ~doc:"Generate a browser-acceptable WebTransport dev certificate")
    Term.(const run $ out_dir $ hosts $ days)

let () = exit (Cmd.eval cmd)
