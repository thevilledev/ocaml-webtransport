(** Pure-OCaml QUIC backend for webtransport, built on {!Purequic}. No C
    library or Rust toolchain required.

    Servers materialize their connection from the first Initial packet
    (the seam's [accept] does not carry the client's initial DCID); until
    then the handle reports not-established and sends nothing. *)

include Webtransport.Quic_backend.S

(** Test hooks. *)
module For_testing : sig
  val initiate_key_update : t -> unit
end
