(lang dune 3.16)
(name webtransport)

(generate_opam_files true)

(source (github thevilledev/ocaml-webtransport))
(authors "Ville Vesilehto <ville@vesilehto.fi>")
(maintainers "Ville Vesilehto <ville@vesilehto.fi>")
(license MIT)

(package
 (name quiche)
 (synopsis "Bindings to the Cloudflare quiche QUIC library")
 (description
  "Thin, hand-written C stub bindings to libquiche, Cloudflare's QUIC\nimplementation. Requires the quiche C library: `brew install\ncloudflare-quiche` on macOS, or build cloudflare/quiche with `cargo build\n--release --features ffi,qlog,pkg-config-meta` and point PKG_CONFIG_PATH at\nthe build directory (or set QUICHE_INCLUDE_DIR/QUICHE_LIB_DIR).")
 (depends
  (ocaml (>= 5.2))
  dune
  bigstringaf
  dune-configurator
  (conf-pkg-config :build)))

(package
 (name webtransport)
 (synopsis "WebTransport over HTTP/3: sans-io protocol core")
 (description
  "A sans-io implementation of WebTransport over HTTP/3\n(draft-ietf-webtrans-http3): session establishment via HTTP/3 extended\nCONNECT, WebTransport streams and datagrams, capsules, and the minimal\nHTTP/3 + QPACK subset WebTransport needs. Contains no sockets, clocks or\nconcurrency; pair it with webtransport-eio or webtransport-lwt and a QUIC\nbackend such as webtransport-quiche.")
 (depends
  (ocaml (>= 5.2))
  dune
  bigstringaf
  x509
  mirage-crypto
  mirage-crypto-ec
  mirage-crypto-rng
  ptime
  digestif
  cmdliner
  (alcotest :with-test)
  (crowbar :with-test)))

(package
 (name webtransport-quiche)
 (synopsis "Quiche QUIC backend for webtransport")
 (description
  "Implements the webtransport Quic_backend.S interface on top of the quiche\nbindings. This is the default QUIC engine for webtransport-eio and\nwebtransport-lwt.")
 (depends
  (ocaml (>= 5.2))
  dune
  quiche
  webtransport))

(package
 (name webtransport-eio)
 (synopsis "Eio runtime for webtransport")
 (description
  "Eio-based driver for the webtransport sans-io core: UDP socket handling,\ntimers, fibers, and a Session/Stream API where WebTransport streams are\nexposed as Eio flows.")
 (depends
  (ocaml (>= 5.2))
  dune
  webtransport
  (webtransport-quiche :with-test)
  (eio (>= 1.2))
  (eio_main :with-test)
  mtime))

(package
 (name webtransport-lwt)
 (synopsis "Lwt runtime for webtransport")
 (description
  "Lwt-based driver for the webtransport sans-io core: UDP socket handling,\ntimers, and a Session/Stream API mirroring webtransport-eio.")
 (depends
  (ocaml (>= 5.2))
  dune
  webtransport
  (webtransport-quiche :with-test)
  (lwt (>= 5.7))
  bigstringaf
  mtime
  ipaddr))

(package
 (name purequic)
 (synopsis "Pure-OCaml QUIC v1 engine, sans-io (unreleased)")
 (description
  "A sans-io implementation of QUIC version 1 (RFC 9000/9001/9002) with\nunreliable datagrams (RFC 9221) and reliable stream resets\n(draft-ietf-quic-reliable-stream-reset), written in OCaml on\nmirage-crypto. No sockets, clocks, effects or C library dependencies;\ndrive it from any runtime. Unreleased while interop hardening is in\nprogress.")
 (depends
  (ocaml (>= 5.2))
  dune
  bigstringaf
  digestif
  kdf
  mirage-crypto
  mirage-crypto-ec
  mirage-crypto-pk
  mirage-crypto-rng
  x509
  eqaf
  ptime
  (alcotest :with-test)
  (crowbar :with-test)))

(package
 (name webtransport-purequic)
 (synopsis "Pure-OCaml QUIC backend for webtransport (unreleased)")
 (description
  "Implements the webtransport Quic_backend.S interface on top of the\npurequic engine: a QUIC backend with no C library or Rust toolchain\nrequirement. Unreleased while interop hardening is in progress.")
 (depends
  (ocaml (>= 5.2))
  dune
  purequic
  webtransport
  mirage-crypto-rng
  ca-certs
  ptime))
