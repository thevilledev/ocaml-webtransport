(** CertificateVerify construction, signing and verification
    (RFC 8446 s.4.4.3), on x509/mirage-crypto. *)

val server_context : string

val client_context : string
(** the context strings mixed into the signed content. *)

val verify_schemes : int list
(** signature scheme ids we can verify — the signature_algorithms
    offer: ECDSA P-256/384/521, RSA-PSS, Ed25519. *)

val pick_sign_scheme : X509.Private_key.t -> offered:int list -> int option
(** the scheme this private key signs with, if the peer offered it. *)

val sign :
  key:X509.Private_key.t ->
  scheme:int ->
  context:string ->
  transcript_hash:string ->
  (string, string) result

val verify :
  cert:X509.Certificate.t ->
  scheme:int ->
  signature:string ->
  context:string ->
  transcript_hash:string ->
  (unit, string) result
