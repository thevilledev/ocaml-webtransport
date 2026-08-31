# Changes

## 0.1.0 (unreleased)

Initial release: the first WebTransport-over-HTTP/3 implementation for
OCaml.

- `webtransport`: sans-io protocol core — HTTP/3 extended CONNECT
  session establishment (draft-ietf-webtrans-http3, draft-02 compat
  surface with draft-16 semantics), WebTransport streams, datagrams,
  capsules, session flow control, and the minimal HTTP/3 + QPACK subset
  WebTransport needs. No sockets, clocks or concurrency.
- `webtransport-eio` / `webtransport-lwt`: runtime drivers (UDP,
  timers, fibers/promises) with a Session/Stream API; Eio exposes
  streams as `Eio.Flow` values. Both drivers are parameterized over any
  QUIC backend.
- `quiche` + `webtransport-quiche`: C bindings to Cloudflare's
  libquiche and the default `Quic_backend.S` engine.
- `purequic` + `webtransport-purequic`: a sans-io QUIC v1 engine
  (RFC 9000/9001/9002, RFC 9221 datagrams, reliable stream resets per
  draft-ietf-quic-reliable-stream-reset) with its own minimal TLS 1.3,
  written on mirage-crypto — no C library or Rust toolchain. Fully
  deterministic under a scripted clock; supports key update both
  directions and RESET_STREAM_AT, which libquiche lacks. Reliable
  resets track draft-ietf-quic-reliable-stream-reset-10 (on the IESG
  telechat of 2026-09-03 with enough positions to pass); the codepoints
  we emit (transport parameter 0x1d plus the pre-draft-08 legacy value,
  frame 0x24) match that revision.
- Interop: headless Chrome (session establishment via
  `serverCertificateHashes`, datagram/bidi/uni echo, close-code round
  trips) and quic-go/webtransport-go in both directions — v0.9 on both
  backends, v0.13 (which hard-requires RESET_STREAM_AT) on purequic.
- Conformance: RFC 9001 Appendix A and RFC 8448 vectors byte-exact;
  crowbar fuzz targets over every decoder, TLS message handling and
  established connections; deterministic loss/PTO/idle/key-update
  scenarios in `test/pure_pair`.
- Stateless Retry / address validation (`?retry` on `Wt.listen`):
  AEAD-sealed, address-bound, expiring tokens and the RFC 9001 Retry
  integrity tag; the purequic client handles a server Retry and both
  backends thread tokens through the seam.
- Tooling: `wt-devcert` for browser-acceptable dev certificates; qlog
  capture (`WT_QLOG_DIR`) on both backends (native, dependency-free on
  purequic); `WT_BACKEND=quiche|pure` backend selection across tests
  and examples.

### Not yet supported

- **0-RTT / session resumption.** WebTransport runs correctly over
  1-RTT (every browser and webtransport-go does), so this latency
  optimization — TLS session tickets, early data, and its replay
  protection — is deferred to a later release rather than widening the
  TLS attack surface for the first version.
- QUIC connection migration (the initiating side), stateless-reset
  emission, and ECN are likewise out of scope; the engine tolerates a
  peer's use of the features it needs to (passive path/NAT rebinding,
  NEW_CONNECTION_ID) without initiating them.
