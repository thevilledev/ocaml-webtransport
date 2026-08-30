(** Development certificates for browser WebTransport.

    Browsers accept a self-signed certificate through
    [serverCertificateHashes] only if it is ECDSA P-256 (never RSA), X.509v3,
    and valid for at most 14 days. The hash the browser checks is the SHA-256
    of the DER encoding of the whole certificate. *)

type t = {
  cert : X509.Certificate.t;
  key : X509.Private_key.t;
  cert_pem : string;
  key_pem : string;
  cert_der : string;
  hash : string;  (** raw 32-byte SHA-256 of [cert_der] *)
  not_before : Ptime.t;
  not_after : Ptime.t;
}

(** Generates a browser-acceptable self-signed certificate.
    @param hosts DNS SANs (default [["localhost"]]); the loopback IPs are
    always included.
    @param validity_days 1..13 (default 13; the browser cap is 14).
    @param seed deterministic key generation, for a stable hash. *)
val generate :
  ?hosts:string list -> ?validity_days:int -> ?seed:string -> unit -> t

val hash_hex : t -> string

(** Base64 of the certificate hash: what a page feeds to
    [serverCertificateHashes] after [atob()]. *)
val hash_b64 : t -> string

val base64 : string -> string

(** Writes cert/key PEMs to temp files (for TLS stacks that load from disk)
    and removes them afterwards. *)
val with_temp_files :
  t -> (cert_file:string -> key_file:string -> 'a) -> 'a
