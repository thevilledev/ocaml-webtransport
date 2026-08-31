(* quic-interop-runner WebTransport endpoint (pure backend).

   Contract (quic-interop/quic-interop-runner webtransport.md):
   - ROLE = server | client
   - PROTOCOLS: space-separated ALPN list
   - REQUESTS: space-separated URLs (client) / endpoint/file paths (server)
   - /www/<endpoint>/<file> holds served files; /downloads mirrors fetches
   - TESTCASE selects the case; exit 127 if unsupported
   - server SHOULD accept a single QUIC connection
   Transfer protocol: client opens a stream / sends a datagram carrying
   "GET <file>"; server answers "PUSH <file>\n" + contents (uni/datagram)
   or the raw contents (bidi). *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let getenv d k = Option.value ~default:d (Sys.getenv_opt k)

(* the runner mounts /www and /downloads; overridable for local tests *)
let www = getenv "/www" "WT_WWW"
let downloads = getenv "/downloads" "WT_DOWNLOADS"

let testcase () = getenv "" "TESTCASE"

let supported =
  [
    "handshake";
    "transfer";
    "transfer-unidirectional-send";
    "transfer-bidirectional-send";
    "transfer-datagram-send";
  ]

let alpns () =
  match Sys.getenv_opt "PROTOCOLS" with
  | Some s when String.trim s <> "" -> String.split_on_char ' ' (String.trim s)
  | _ -> [ "webtransport" ]

(* endpoint + file from a URL or a bare endpoint/file path *)
let split_path url =
  let path =
    match String.index_opt url ':' with
    | Some _ -> (
        (* https://host/endpoint/file -> /endpoint/file *)
        match Str.bounded_split (Str.regexp "/") url 4 with
        | [ _; _; _; rest ] -> "/" ^ rest
        | _ -> url)
    | None -> if String.length url > 0 && url.[0] = '/' then url else "/" ^ url
  in
  path

let read_file p =
  try Some (In_channel.with_open_bin p In_channel.input_all)
  with Sys_error _ -> None

(* ---- server ---- *)

let serve_stream_bidi st =
  let req = Wt.Stream.read_all st in
  match String.split_on_char ' ' (String.trim req) with
  | [ "GET"; path ] -> (
      match read_file (Filename.concat www (split_path path)) with
      | Some data ->
          Wt.Stream.write st data;
          Wt.Stream.close_write st
      | None -> Wt.Stream.reset st ~code:404)
  | _ -> Wt.Stream.reset st ~code:400

let serve_stream_uni session st =
  let req = Wt.Stream.read_all st in
  match String.split_on_char ' ' (String.trim req) with
  | [ "GET"; path ] -> (
      match read_file (Filename.concat www (split_path path)) with
      | Some data ->
          let out = Wt.open_uni session in
          Wt.Stream.write out (Printf.sprintf "PUSH %s\n%s" path data);
          Wt.Stream.close_write out
      | None -> ())
  | _ -> ()

let serve session =
  Switch.run @@ fun sw ->
  (* datagrams *)
  Fiber.fork ~sw (fun () ->
      try
        while true do
          let d = Wt.Session.recv_datagram session in
          match String.split_on_char ' ' (String.trim d) with
          | [ "GET"; path ] -> (
              match read_file (Filename.concat www (split_path path)) with
              | Some data ->
                  ignore
                    (Wt.Session.send_datagram session
                       (Printf.sprintf "PUSH %s\n%s" path data))
              | None -> ())
          | _ -> ()
        done
      with _ -> ());
  (* uni streams *)
  Fiber.fork ~sw (fun () ->
      try
        while true do
          let st = Wt.accept_uni session in
          Fiber.fork ~sw (fun () -> try serve_stream_uni session st with _ -> ())
        done
      with _ -> ());
  (* bidi streams *)
  try
    while true do
      let st = Wt.accept_bidi session in
      Fiber.fork ~sw (fun () -> try serve_stream_bidi st with _ -> ())
    done
  with _ -> ()

let run_server env ~sw =
  let net = Eio.Stdenv.net env in
  let mono = Eio.Stdenv.mono_clock env in
  let certs =
    (* the runner mounts a cert/key; fall back to a generated devcert *)
    match
      (read_file "/certs/cert.pem", read_file "/certs/priv.key")
    with
    | Some c, Some k -> `Pem (c, k)
    | _ -> `Gen (Wt_certs.generate ())
  in
  let module B = Webtransport_purequic in
  let get = function Ok v -> v | Error m -> failwith m in
  let cert_pem, key_pem =
    match certs with
    | `Pem (c, k) -> (c, k)
    | `Gen g -> (g.Wt_certs.cert_pem, g.Wt_certs.key_pem)
  in
  let scfg =
    get
      (B.config ~role:`Server ~alpn:(alpns ())
         ~cert_chain_pem:cert_pem ~priv_key_pem:key_pem
         ~enable_datagrams:true ())
  in
  (* the runner always uses 443; WT_PORT overrides it for local smoke
     tests without privilege *)
  let port = int_of_string (getenv "443" "WT_PORT") in
  Wt.listen ~sw ~net ~clock:mono
    ~backend:(Webtransport_eio.Backend ((module B), scfg))
    ~port ~handler:serve ();
  Fiber.await_cancel ()

(* ---- client ---- *)

let requests () =
  match Sys.getenv_opt "REQUESTS" with
  | Some s -> List.filter (fun x -> x <> "") (String.split_on_char ' ' (String.trim s))
  | None -> []

let save path contents =
  let full = Filename.concat downloads (split_path path) in
  (try Unix.mkdir (Filename.dirname full) 0o755 with _ -> ());
  Out_channel.with_open_bin full (fun oc -> Out_channel.output_string oc contents)

let strip_push path s =
  let prefix = Printf.sprintf "PUSH %s\n" path in
  if String.length s >= String.length prefix
     && String.sub s 0 (String.length prefix) = prefix
  then String.sub s (String.length prefix) (String.length s - String.length prefix)
  else s

(* https://host:port/endpoint/file -> (host, port, "/endpoint/file") *)
let parse_url url =
  let rest =
    match Str.bounded_split (Str.regexp_string "//") url 2 with
    | [ _; r ] -> r
    | _ -> url
  in
  let hostport, path =
    match String.index_opt rest '/' with
    | Some i -> (String.sub rest 0 i, String.sub rest i (String.length rest - i))
    | None -> (rest, "/")
  in
  let host, port =
    match String.index_opt hostport ':' with
    | Some i ->
        ( String.sub hostport 0 i,
          int_of_string
            (String.sub hostport (i + 1) (String.length hostport - i - 1)) )
    | None -> (hostport, 443)
  in
  (host, port, path)

let resolve env host =
  match Eio.Net.getaddrinfo_datagram (Eio.Stdenv.net env) ~service:"443" host with
  | `Udp (ip, _) :: _ -> (ip :> string)
  | _ -> "\127\000\000\001"
  | exception _ -> "\127\000\000\001"

let run_client env ~sw =
  let net = Eio.Stdenv.net env in
  let mono = Eio.Stdenv.mono_clock env in
  let module B = Webtransport_purequic in
  let get = function Ok v -> v | Error m -> failwith m in
  let ccfg = get (B.config ~role:`Client ~alpn:(alpns ()) ~verify:`None
                    ~enable_datagrams:true ()) in
  let tc = testcase () in
  List.iter
    (fun url ->
      let host, port, path = parse_url url in
      let session =
        Wt.connect ~sw ~net ~clock:mono
          ~backend:(Webtransport_eio.Backend ((module B), ccfg))
          ~server_name:host
          ~peer:(resolve env host, port)
          ~authority:(Printf.sprintf "%s:%d" host port)
          ~path ()
      in
      if tc = "handshake" then
        Out_channel.with_open_bin
          (Filename.concat downloads "negotiated_protocol.txt")
          (fun oc ->
            Out_channel.output_string oc (List.hd (alpns ())))
      else begin
        let file = path in
        (match tc with
        | "transfer-datagram-send" ->
            ignore (Wt.Session.send_datagram session ("GET " ^ file));
            let d = Wt.Session.recv_datagram session in
            save file (strip_push file d)
        | "transfer-unidirectional-send" ->
            let st = Wt.open_uni session in
            Wt.Stream.write st ("GET " ^ file);
            Wt.Stream.close_write st;
            let incoming = Wt.accept_uni session in
            save file (strip_push file (Wt.Stream.read_all incoming))
        | _ (* transfer / transfer-bidirectional-send *) ->
            let st = Wt.open_bidi session in
            Wt.Stream.write st ("GET " ^ file);
            Wt.Stream.close_write st;
            save file (Wt.Stream.read_all st))
      end;
      Wt.Session.close ~code:0 session)
    (requests ())

let () =
  Mirage_crypto_rng_unix.use_default ();
  if not (List.mem (testcase ()) supported) then exit 127;
  Eio_main.run @@ fun env ->
  Switch.run @@ fun sw ->
  match getenv "server" "ROLE" with
  | "client" -> run_client env ~sw
  | _ -> run_server env ~sw
