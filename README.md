# ocaml-webtransport

[WebTransport](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) for
OCaml: reliable streams and unreliable datagrams over HTTP/3 + QUIC, built for
interoperability with browsers.

**Status: early development — but already speaks to Chrome and
webtransport-go.** Targets draft-ietf-webtrans-http3-16 semantics with the
draft-02 compatibility surface that shipping browsers (Chrome, Firefox,
Safari) actually speak. Working today: session establishment (extended
CONNECT, both `:protocol` tokens), bidirectional and unidirectional
WebTransport streams (including server-initiated), datagrams, close/drain
capsules, and negotiated session flow control — verified against headless
Chrome (both close directions), against quic-go/webtransport-go in both
roles, and in Eio/Lwt self-interop. Streams also expose `Eio.Flow` views,
so they compose with `Eio.Buf_read`, `Eio.Flow.copy` and friends.

Both an **Eio** driver (`webtransport-eio`) and an **Lwt** driver
(`webtransport-lwt`) ship over the same sans-io engine.

## Try it against Chrome

```
WT_CHROME=1 dune exec test/chrome/test_chrome.exe
```

This starts a WebTransport echo server plus a small page server, launches
headless Chrome (override the binary with `CHROME_BIN`), and runs a
session/streams/datagrams/close suite from the browser using
`serverCertificateHashes` — no flags, no trusted CA needed. Set
`WT_NETLOG=/tmp/netlog.json` to capture a Chrome netlog and `WT_DEBUG=1`
for engine traces.

## Architecture

```
webtransport-eio / webtransport-lwt   runtimes: UDP sockets, timers, fibers/promises
webtransport                          sans-io core: extended CONNECT, WT sessions,
                                      streams/datagrams/capsules, minimal HTTP/3 + QPACK
webtransport-quiche                   Quic_backend.S adapter (default engine)
quiche                                raw bindings to Cloudflare's libquiche
```

The QUIC engine sits behind `Webtransport.Quic_backend.S`, so a pure-OCaml
QUIC implementation can replace the C-backed one without changing the public
API.

## Requirements

- OCaml >= 5.2
- libquiche: `brew install cloudflare-quiche` (macOS), or build
  [cloudflare/quiche](https://github.com/cloudflare/quiche) with
  `cargo build --release --features ffi,qlog,pkg-config-meta` and add the
  build directory to `PKG_CONFIG_PATH` (or set
  `QUICHE_INCLUDE_DIR`/`QUICHE_LIB_DIR`).

## Quick start

Run the echo server and point a browser (or the example client) at it:

```
dune exec examples/echo_server.exe
```

```
dune exec examples/echo_client.exe -- 127.0.0.1 4433 "hello"
```

`wt-devcert` generates browser-acceptable dev certificates (ECDSA P-256,
13-day validity) and prints the `serverCertificateHashes` value.

## Development

```
dune build @all
dune runtest
```

Opt-in interop suites:

- `WT_CHROME=1 dune exec test/chrome/test_chrome.exe` — headless Chrome
  runs session/streams/datagrams/close against the server.
- `WT_GO=1 dune exec test/interop_go/test_go_interop.exe` — both directions
  against quic-go/webtransport-go (pinned to v0.9: v0.10+ requires
  RESET_STREAM_AT, which libquiche does not implement yet).
- `WT_QLOG_DIR=/tmp dune exec ...` — per-connection qlog traces (needs a
  libquiche built with the qlog feature; the Homebrew bottle omits it).
- `WT_DEBUG=1` — engine event traces on stderr.

## License

MIT.
