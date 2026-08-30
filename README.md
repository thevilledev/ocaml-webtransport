# ocaml-webtransport

[WebTransport](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) for
OCaml: reliable streams and unreliable datagrams over HTTP/3 + QUIC, built for
interoperability with browsers.

**Status: early development.** Targets draft-ietf-webtrans-http3-16 semantics
with the draft-02 compatibility surface that shipping browsers (Chrome,
Firefox, Safari) actually speak.

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

## Development

```
dune build @all
dune runtest
```

## License

MIT.
