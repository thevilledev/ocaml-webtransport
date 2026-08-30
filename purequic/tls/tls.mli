(** A minimal TLS 1.3 handshake engine for QUIC (RFC 8446 + RFC 9001): no
    record layer, raw handshake messages per encryption level, secrets (not
    keys) exported, quic_transport_parameters carried opaquely.

    Scope: TLS 1.3 only; AES-128/256-GCM and ChaCha20-Poly1305 suites;
    x25519 + secp256r1 (cookie HRRs honored client-side, HRR never emitted
    server-side); no PSK/resumption/0-RTT/tickets/client certificates;
    NewSessionTicket discarded; TLS KeyUpdate fatal per RFC 9001 s.8.4. *)

type level = Initial | Handshake | Application

type event =
  | Send of { level : level; data : string }
      (** handshake bytes for CRYPTO frames at [level] *)
  | Rx_secret of { level : level; cipher : Cipher.t; secret : string }
  | Tx_secret of { level : level; cipher : Cipher.t; secret : string }
      (** install packet protection; QUIC derives key/iv/hp itself *)
  | Peer_transport_params of string
  | Handshake_complete of { alpn : string }
  | Fatal of { alert : int; reason : string }
      (** map to a CONNECTION_CLOSE with error 0x0100 + alert *)

type config

val client_config :
  ?verify:[ `None | `Anchors of X509.Certificate.t list ] ->
  ?time:(unit -> Ptime.t option) ->
  ?server_name:string ->
  alpn:string list ->
  transport_params:string ->
  rng:(int -> string) ->
  unit ->
  (config, string) result
(** [`None] skips chain validation but still verifies CertificateVerify. *)

val server_config :
  cert_chain:X509.Certificate.t list ->
  priv_key:X509.Private_key.t ->
  alpn:string list ->
  transport_params:string ->
  rng:(int -> string) ->
  unit ->
  (config, string) result

type t

val create : config -> t

val start : t -> unit
(** client: queues the ClientHello flight. No-op for servers. *)

val handle : t -> level:level -> string -> unit
(** feed contiguous CRYPTO bytes received at [level] (QUIC does the
    offset reassembly). Never raises; failures surface as [Fatal]. *)

val next_event : t -> event option
(** drain after every [start]/[handle]. *)

val peer_certs : t -> X509.Certificate.t list
(** leaf first; populated even under [`None] verification. *)

val is_connected : t -> bool
