(** QUIC key derivation (RFC 9001 s.5): TLS 1.3 HKDF-Expand-Label and the
    v1 initial secrets. Verified against RFC 9001 Appendix A. *)

val expand_label :
  hash:Digestif.hash' ->
  secret:string ->
  ?context:string ->
  label:string ->
  int ->
  string

val initial_salt_v1 : string
val initial_secret : dcid:string -> string
val initial_client_secret : dcid:string -> string
val initial_server_secret : dcid:string -> string

type material = { key : string; iv : string; hp : string }

val material : suite:Qsuite.t -> secret:string -> material

val next_secret : suite:Qsuite.t -> secret:string -> string
(** the "quic ku" next-generation traffic secret (RFC 9001 s.6). *)
