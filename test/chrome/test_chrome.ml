(* Headless-Chrome interop harness — the v1 interop bar.

   All-OCaml: a WebTransport server, a tiny HTTP/1.0 page server, and a
   verdict endpoint. Headless Chrome loads the page from http://127.0.0.1
   (a secure context), the page opens a WebTransport session using
   serverCertificateHashes, echoes a datagram, closes with code 42, and
   POSTs its verdict back. The harness asserts both the page verdict and the
   server-side observations.

   Skipped unless WT_CHROME=1 (needs a Chrome binary). Run manually with:
     WT_CHROME=1 dune exec test/chrome/test_chrome.exe *)

open Eio.Std
module Wt = Webtransport_eio.Wt

let page ~log_prefix =
  Printf.sprintf
    {|<!doctype html><meta charset="utf-8"><title>ocaml-webtransport interop</title>
<pre id="log"></pre>
<script>
const log = m => { document.getElementById('log').textContent += m + "\n"; console.log("%s" + m); };
const post = async obj => { try { await fetch('/result', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(obj)}); } catch (e) {} };
(async () => {
  const steps = [];
  try {
    const info = await (await fetch('/hash.json')).json();
    steps.push('fetched-info');
    const bytes = Uint8Array.from(atob(info.hash_b64), c => c.charCodeAt(0));
    const wt = new WebTransport(info.url, { serverCertificateHashes: [{ algorithm: 'sha-256', value: bytes }] });
    await wt.ready;
    steps.push('ready');
    log('session ready');
    const writer = wt.datagrams.writable.getWriter();
    const reader = wt.datagrams.readable.getReader();
    const payload = new TextEncoder().encode('browser-ping');
    let done = false;
    const readP = reader.read().then(r => { done = true; return r.value; });
    for (let i = 0; i < 20 && !done; i++) {
      await writer.write(payload);
      await new Promise(res => setTimeout(res, 250));
    }
    const got = await Promise.race([
      readP,
      new Promise((_, rej) => setTimeout(() => rej(new Error('datagram timeout')), 3000)),
    ]);
    const text = new TextDecoder().decode(got);
    if (text !== 'browser-ping') throw new Error('bad echo: ' + text);
    steps.push('datagram-echo');
    log('datagram echoed');
    // Bidi stream echo on the same stream.
    const readAll = async stream => {
      const chunks = [];
      const r = stream.getReader();
      for (;;) {
        const { value, done } = await r.read();
        if (value) chunks.push(...value);
        if (done) break;
      }
      return new TextDecoder().decode(new Uint8Array(chunks));
    };
    const bidi = await wt.createBidirectionalStream();
    const bw = bidi.writable.getWriter();
    await bw.write(new TextEncoder().encode('stream-ping'));
    await bw.close();
    const echoedStream = await readAll(bidi.readable);
    if (echoedStream !== 'stream-ping') throw new Error('bad bidi echo: ' + echoedStream);
    steps.push('bidi-echo');
    log('bidi stream echoed');
    // Uni: send on ours; the server answers on a server-initiated uni.
    const uni = await wt.createUnidirectionalStream();
    const uw = uni.getWriter();
    await uw.write(new TextEncoder().encode('uni-ping'));
    await uw.close();
    const incoming = wt.incomingUnidirectionalStreams.getReader();
    const { value: inStream } = await Promise.race([
      incoming.read(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('uni timeout')), 5000)),
    ]);
    const uniEchoed = await readAll(inStream);
    if (uniEchoed !== 'uni-ping') throw new Error('bad uni echo: ' + uniEchoed);
    steps.push('uni-echo');
    log('uni stream echoed');
    // Server-initiated close on a second session.
    const wt2 = new WebTransport(info.url.replace('/echo', '/close-me'),
      { serverCertificateHashes: [{ algorithm: 'sha-256', value: bytes }] });
    await wt2.ready;
    const closeInfo = await Promise.race([
      wt2.closed,
      new Promise((_, rej) => setTimeout(() => rej(new Error('server close timeout')), 5000)),
    ]);
    if (closeInfo.closeCode !== 7 || closeInfo.reason !== 'server-close')
      throw new Error('bad server close: ' + JSON.stringify(closeInfo));
    steps.push('server-close');
    log('server-initiated close observed');
    await wt.close({ closeCode: 42, reason: 'done' });
    steps.push('closed');
    await post({ pass: true, steps });
    log('PASS');
  } catch (e) {
    steps.push('error: ' + (e && e.message ? e.message : String(e)));
    await post({ pass: false, steps });
    log('FAIL ' + e);
  }
})();
</script>
|}
    log_prefix

let respond flow ~status ~ctype body =
  let hdr =
    Printf.sprintf
      "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: \
       close\r\n\r\n"
      status ctype (String.length body)
  in
  Eio.Flow.copy_string (hdr ^ body) flow

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let chrome_bin () =
  match Sys.getenv_opt "CHROME_BIN" with
  | Some c -> c
  | None ->
      let candidates =
        [
          "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
          "/usr/bin/google-chrome";
          "/usr/bin/google-chrome-stable";
          "/opt/google/chrome/chrome";
          "/usr/bin/chromium-browser";
          "/usr/bin/chromium";
        ]
      in
      (match List.find_opt Sys.file_exists candidates with
      | Some c -> c
      | None -> "google-chrome")

let firefox_bin () =
  match Sys.getenv_opt "FIREFOX_BIN" with
  | Some c -> c
  | None ->
      let candidates =
        [
          "/Applications/Firefox.app/Contents/MacOS/firefox";
          "/usr/bin/firefox";
          "/snap/bin/firefox";
          "/usr/lib/firefox/firefox";
        ]
      in
      (match List.find_opt Sys.file_exists candidates with
      | Some c -> c
      | None -> "firefox")

(* Firefox reads prefs from user.js in the profile directory. WebTransport
   and its datagrams default to enabled in current releases; setting them
   explicitly keeps the harness stable across channels. *)
let write_firefox_prefs profile =
  let oc = open_out (Filename.concat profile "user.js") in
  output_string oc
    {|user_pref("network.webtransport.enabled", true);
user_pref("network.webtransport.datagrams.enabled", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
|};
  close_out oc

let () =
  let browser =
    if Sys.getenv_opt "WT_CHROME" <> None then Some `Chrome
    else if Sys.getenv_opt "WT_FIREFOX" <> None then Some `Firefox
    else None
  in
  match browser with
  | None ->
      print_endline
        "browser interop: skipped (set WT_CHROME=1 or WT_FIREFOX=1 to run)"
  | Some browser ->
      Random.self_init ();
      Eio_main.run @@ fun env ->
      Switch.run @@ fun sw ->
      let net = Eio.Stdenv.net env in
      let mono = Eio.Stdenv.mono_clock env in
      let clock = Eio.Stdenv.clock env in
      let proc = Eio.Stdenv.process_mgr env in
      let certs = Wt_certs.generate () in
      Wt_certs.with_temp_files certs @@ fun ~cert_file ~key_file ->
      let module B = (val Wt_test_backend.select ()) in
      let get = function Ok v -> v | Error m -> failwith m in
      let scfg =
        get
          (B.config ~role:`Server ~alpn:[ "h3" ]
             ~cert_chain_pem_file:cert_file ~priv_key_pem_file:key_file
             ~enable_datagrams:true ())
      in
      (* Server-side observations. *)
      let established = ref 0 in
      let close_seen = ref None in
      let handler session =
        incr established;
        if Wt.Session.path session = "/close-me" then begin
          Eio.Time.Mono.sleep mono 0.1;
          Wt.Session.close ~code:7 ~message:"server-close" session
        end
        else
        Switch.run @@ fun hsw ->
        Fiber.fork ~sw:hsw (fun () ->
            try
              while true do
                let st = Wt.accept_bidi session in
                Fiber.fork ~sw:hsw (fun () ->
                    try
                      let data = Wt.Stream.read_all st in
                      Wt.Stream.write st data;
                      Wt.Stream.close_write st
                    with Webtransport_eio.Session_closed _ -> ())
              done
            with Webtransport_eio.Session_closed _ -> ());
        Fiber.fork ~sw:hsw (fun () ->
            try
              while true do
                let st = Wt.accept_uni session in
                Fiber.fork ~sw:hsw (fun () ->
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
            ignore
              (Wt.Session.send_datagram session
                 (Wt.Session.recv_datagram session))
          done
        with Webtransport_eio.Session_closed (code, msg) ->
          close_seen := Some (code, msg)
      in
      let rec bind_wt tries =
        let port = 20000 + Random.int 30000 in
        match
          Wt.listen ~sw ~net ~clock:mono
            ~backend:(Webtransport_eio.Backend ((module B), scfg))
            ~port ~handler ()
        with
        | () -> port
        | exception _ when tries > 0 -> bind_wt (tries - 1)
      in
      let wt_port = bind_wt 5 in
      let hash_json =
        Printf.sprintf {|{"url":"https://127.0.0.1:%d/echo","hash_b64":"%s"}|}
          wt_port (Wt_certs.hash_b64 certs)
      in
      (* Verdict from the page. *)
      let verdict_p, verdict_r = Promise.create () in
      let html = page ~log_prefix:"[page] " in
      let handle_http flow _addr =
        let br = Eio.Buf_read.of_flow ~max_size:1_000_000 flow in
        let reqline = Eio.Buf_read.line br in
        let rec headers cl =
          match Eio.Buf_read.line br with
          | "" | "\r" -> cl
          | line -> (
              match String.index_opt line ':' with
              | Some i
                when String.lowercase_ascii (String.sub line 0 i)
                     = "content-length" ->
                  headers
                    (int_of_string
                       (String.trim
                          (String.sub line (i + 1)
                             (String.length line - i - 1))))
              | _ -> headers cl)
        in
        let cl = headers 0 in
        if contains ~sub:"POST /result" reqline then begin
          let body = Eio.Buf_read.take cl br in
          print_endline ("page verdict: " ^ body);
          if not (Promise.is_resolved verdict_p) then
            Promise.resolve verdict_r (contains ~sub:{|"pass":true|} body);
          respond flow ~status:"204 No Content" ~ctype:"text/plain" ""
        end
        else if contains ~sub:"GET /hash.json" reqline then
          respond flow ~status:"200 OK" ~ctype:"application/json" hash_json
        else respond flow ~status:"200 OK" ~ctype:"text/html" html
      in
      let rec bind_http tries =
        let port = 20000 + Random.int 30000 in
        match
          Eio.Net.listen ~sw ~backlog:16 ~reuse_addr:true net
            (`Tcp (Eio.Net.Ipaddr.V4.loopback, port))
        with
        | lsock -> (lsock, port)
        | exception _ when tries > 0 -> bind_http (tries - 1)
      in
      let lsock, http_port = bind_http 5 in
      Fiber.fork_daemon ~sw (fun () ->
          let rec loop () =
            Eio.Net.accept_fork ~sw lsock
              ~on_error:(fun _ -> ())
              handle_http;
            loop ()
          in
          loop ());
      (* Launch the headless browser. *)
      let url = Printf.sprintf "http://127.0.0.1:%d/" http_port in
      let profile = Filename.temp_dir "wt-browser" "" in
      let label, argv =
        match browser with
        | `Chrome ->
            let netlog_args =
              match Sys.getenv_opt "WT_NETLOG" with
              | Some path ->
                  [ "--log-net-log=" ^ path; "--net-log-capture-mode=Everything" ]
              | None -> []
            in
            ( "chrome",
              [
                chrome_bin ();
                "--headless=new";
                "--user-data-dir=" ^ profile;
                "--no-first-run";
                "--no-default-browser-check";
                "--disable-gpu";
                "--enable-logging=stderr";
              ]
              @ netlog_args @ [ url ] )
        | `Firefox ->
            write_firefox_prefs profile;
            ( "firefox",
              [
                firefox_bin ();
                "--headless";
                "--no-remote";
                "--new-instance";
                "--profile";
                profile;
                url;
              ] )
      in
      Printf.printf "launching %s -> %s (wt port %d)\n%!" (List.hd argv) url
        wt_port;
      Fiber.fork_daemon ~sw (fun () ->
          (try Eio.Process.run proc argv with _ -> ());
          `Stop_daemon);
      (* Wait for the verdict. *)
      let result =
        Eio.Time.with_timeout clock 30.0 (fun () ->
            Ok (Promise.await verdict_p))
      in
      (match result with
      | Error `Timeout -> failwith (label ^ " interop: timed out waiting for page verdict")
      | Ok page_pass ->
          if not page_pass then failwith (label ^ " interop: page reported FAIL");
          (* Give the close capsule a moment to be observed server-side. *)
          let rec wait_close tries =
            match !close_seen with
            | Some _ -> ()
            | None when tries > 0 ->
                Eio.Time.sleep clock 0.1;
                wait_close (tries - 1)
            | None -> ()
          in
          wait_close 20;
          Printf.printf "established sessions: %d\n" !established;
          (match !close_seen with
          | Some (code, msg) ->
              Printf.printf "server observed close: code=%d msg=%S\n" code msg;
              if code <> 42 then failwith "expected close code 42"
          | None -> failwith "server never observed session close");
          Printf.printf "%s interop: PASS\n" label)
