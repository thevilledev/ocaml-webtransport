(* Development certificates for browser WebTransport.

   Browsers accept a self-signed certificate through
   [serverCertificateHashes] only if it is ECDSA P-256 (never RSA), X.509v3,
   and valid for at most 14 days. The hash the browser checks is the SHA-256
   of the DER encoding of the whole certificate — not of the public key. *)

let ensure_rng = lazy (Mirage_crypto_rng_unix.use_default ())

type t = {
  cert : X509.Certificate.t;
  key : X509.Private_key.t;
  cert_pem : string;
  key_pem : string;
  cert_der : string;
  hash : string;  (* raw 32-byte SHA-256 of [cert_der] *)
  not_before : Ptime.t;
  not_after : Ptime.t;
}

let localhost_v4 = "\127\000\000\001"
let localhost_v6 = String.init 16 (fun i -> if i = 15 then '\001' else '\000')

let span_s s = Ptime.Span.of_int_s s

let generate ?(hosts = [ "localhost" ]) ?(validity_days = 13) ?seed () =
  Lazy.force ensure_rng;
  if validity_days < 1 || validity_days > 13 then
    invalid_arg "Wt_certs.generate: validity_days must be in 1..13 (browser cap is 14)";
  let key = X509.Private_key.generate ?seed `P256 in
  let dn =
    X509.Distinguished_name.
      [ Relative_distinguished_name.singleton (CN "ocaml-webtransport dev cert") ]
  in
  let now = Ptime_clock.now () in
  (* One hour of backdating for clock skew; still well under the 14-day cap. *)
  let not_before =
    match Ptime.sub_span now (span_s 3600) with Some t -> t | None -> now
  in
  let not_after =
    match Ptime.add_span not_before (span_s (validity_days * 86_400)) with
    | Some t -> t
    | None -> invalid_arg "Wt_certs.generate: validity overflow"
  in
  let san =
    X509.General_name.(
      singleton DNS hosts |> add IP [ localhost_v4; localhost_v6 ])
  in
  let extensions =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature ])
      |> add Ext_key_usage (true, [ `Server_auth ])
      |> add Subject_alt_name (false, san))
  in
  let csr =
    match X509.Signing_request.create dn ~digest:`SHA256 key with
    | Ok csr -> csr
    | Error (`Msg m) -> failwith ("Wt_certs: CSR creation failed: " ^ m)
  in
  match
    X509.Signing_request.sign csr ~valid_from:not_before ~valid_until:not_after
      ~digest:`SHA256 ~extensions key dn
  with
  | Error e ->
      failwith
        (Format.asprintf "Wt_certs: self-signing failed: %a"
           X509.Validation.pp_signature_error e)
  | Ok cert ->
      {
        cert;
        key;
        cert_pem = X509.Certificate.encode_pem cert;
        key_pem = X509.Private_key.encode_pem key;
        cert_der = X509.Certificate.encode_der cert;
        hash = X509.Certificate.fingerprint `SHA256 cert;
        not_before;
        not_after;
      }

let hash_hex t =
  let b = Buffer.create 64 in
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c))) t.hash;
  Buffer.contents b

let base64 s =
  let tbl =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  in
  let n = String.length s in
  let out = Buffer.create (((n + 2) / 3) * 4) in
  let i = ref 0 in
  while !i + 2 < n do
    let x =
      (Char.code s.[!i] lsl 16)
      lor (Char.code s.[!i + 1] lsl 8)
      lor Char.code s.[!i + 2]
    in
    Buffer.add_char out tbl.[(x lsr 18) land 0x3f];
    Buffer.add_char out tbl.[(x lsr 12) land 0x3f];
    Buffer.add_char out tbl.[(x lsr 6) land 0x3f];
    Buffer.add_char out tbl.[x land 0x3f];
    i := !i + 3
  done;
  (match n - !i with
  | 1 ->
      let x = Char.code s.[!i] lsl 16 in
      Buffer.add_char out tbl.[(x lsr 18) land 0x3f];
      Buffer.add_char out tbl.[(x lsr 12) land 0x3f];
      Buffer.add_string out "=="
  | 2 ->
      let x = (Char.code s.[!i] lsl 16) lor (Char.code s.[!i + 1] lsl 8) in
      Buffer.add_char out tbl.[(x lsr 18) land 0x3f];
      Buffer.add_char out tbl.[(x lsr 12) land 0x3f];
      Buffer.add_char out tbl.[(x lsr 6) land 0x3f];
      Buffer.add_char out '='
  | _ -> ());
  Buffer.contents out

(* Base64 of the certificate hash: what a page feeds to
   serverCertificateHashes after atob(). *)
let hash_b64 t = base64 t.hash

(* Writes cert/key PEMs to temp files (needed by TLS stacks that load from
   disk, e.g. quiche) and cleans them up afterwards. *)
let with_temp_files t f =
  let write suffix contents =
    let path, oc = Filename.open_temp_file "wt-dev" suffix in
    output_string oc contents;
    close_out oc;
    path
  in
  let cert_file = write "-cert.pem" t.cert_pem in
  let key_file = write "-key.pem" t.key_pem in
  Fun.protect
    ~finally:(fun () ->
      (try Sys.remove cert_file with Sys_error _ -> ());
      try Sys.remove key_file with Sys_error _ -> ())
    (fun () -> f ~cert_file ~key_file)
