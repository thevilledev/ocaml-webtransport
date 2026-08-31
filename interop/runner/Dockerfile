# quic-interop-runner endpoint for ocaml-webtransport (pure backend).
#
#   docker build -f interop/runner/Dockerfile -t ocaml-webtransport-interop .
#
# The pure backend needs no C QUIC library or Rust toolchain, so the build
# is a plain opam install of the in-tree packages.

FROM ocaml/opam:debian-12-ocaml-5.2 AS build
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgmp-dev pkg-config m4 && rm -rf /var/lib/apt/lists/*
USER opam
WORKDIR /src
COPY --chown=opam:opam . .
RUN opam install -y --deps-only ./purequic.opam ./webtransport.opam \
      ./webtransport-purequic.opam ./webtransport-eio.opam
RUN opam exec -- dune build --profile release \
      interop/runner/wt_interop.exe
RUN cp _build/default/interop/runner/wt_interop.exe /tmp/wt_interop

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=build /tmp/wt_interop /usr/local/bin/wt_interop
COPY interop/runner/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
