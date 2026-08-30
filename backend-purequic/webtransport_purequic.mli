(** Pure-OCaml QUIC backend for webtransport, built on {!Purequic}.

    Work in progress: the stateless demux helpers work; [connect]/[accept]
    return an error until the engine's connection layer lands. No C library
    or Rust toolchain is required. *)

include Webtransport.Quic_backend.S
