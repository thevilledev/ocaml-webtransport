# quic-interop-runner endpoint

A [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
WebTransport endpoint for ocaml-webtransport, running on the pure-OCaml
`purequic` backend (no C QUIC library, no Rust).

## Build

```
docker build -f interop/runner/Dockerfile -t ocaml-webtransport-interop .
```

## What it implements

`wt_interop` is both the client and the server, selected by `ROLE`. It
reads the runner's environment (`TESTCASE`, `PROTOCOLS`, `REQUESTS`) and
serves files from `/www`, writing fetched files to `/downloads`, per
`webtransport.md`. Supported test cases: `handshake`, `transfer`,
`transfer-unidirectional-send`, `transfer-bidirectional-send`,
`transfer-datagram-send`. Any other `TESTCASE` exits 127.

qlog for each run is written under `/logs/qlog` (JSON-SEQ, qvis-loadable).

## Status

Prepared and locally buildable ahead of a submission to the
quic-interop-runner `implementations.json`. Not part of the default
`dune build`/CI (the endpoint targets the simulator's Docker base image).
