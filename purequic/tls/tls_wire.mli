(** TLS 1.3 handshake message and extension codec (RFC 8446 s.4), string
    based — the control plane is small. Parsers are total and
    GREASE-tolerant: unknown extensions ride through as raw (id, payload)
    pairs, and malformed input yields [Error], never an exception.

    Extension builders return complete encoded extensions (id + length +
    payload); message builders return complete handshake messages
    (type + u24 length + body). *)

(** {2 Wire constants} *)

val ht_client_hello : int
val ht_server_hello : int
val ht_new_session_ticket : int
val ht_encrypted_extensions : int
val ht_certificate : int
val ht_certificate_request : int
val ht_certificate_verify : int
val ht_finished : int
val ht_key_update : int

val ext_signature_algorithms : int
val ext_alpn : int
val ext_supported_versions : int
val ext_cookie : int
val ext_key_share : int
val ext_quic_transport_parameters : int
(** 0x39, RFC 9001. *)

val group_x25519 : int
val group_secp256r1 : int

val hrr_random : string
(** the fixed ServerHello.random value marking a HelloRetryRequest. *)

(** {2 Extension builders} *)

val server_name_ext : string -> string
(** SNI with a single host_name entry. *)

val supported_groups_ext : int list -> string
val signature_algorithms_ext : int list -> string
val alpn_ext : string list -> string
val supported_versions_client_ext : unit -> string
(** offers 1.3 only. *)

val supported_versions_server_ext : unit -> string
val key_share_entry : group:int -> key:string -> string

val key_share_client_ext : string list -> string
(** over encoded [key_share_entry] blobs. *)

val key_share_server_ext : group:int -> key:string -> string
val quic_transport_parameters_ext : string -> string
val cookie_ext : string -> string

(** {2 Message builders} *)

val build_client_hello :
  random:string ->
  session_id:string ->
  cipher_suites:int list ->
  extensions:string list ->
  string

val build_server_hello :
  random:string ->
  session_id:string ->
  cipher_suite:int ->
  extensions:string list ->
  string

val build_encrypted_extensions : string list -> string

val build_certificate : context:string -> ders:string list -> string
(** no per-certificate extensions. *)

val build_certificate_verify : scheme:int -> signature:string -> string

val build_finished : string -> string
(** over the verify_data. *)

(** {2 Parsers} *)

type client_hello = {
  ch_random : string;
  ch_session_id : string;
  ch_cipher_suites : int list;
  ch_extensions : (int * string) list;
}

type server_hello = {
  sh_random : string;
  sh_session_id : string;
  sh_cipher_suite : int;
  sh_extensions : (int * string) list;
}

val parse_client_hello : string -> (client_hello, string) result
val parse_server_hello : string -> (server_hello, string) result

val find_ext : (int * string) list -> int -> string option

val parse_encrypted_extensions : string -> ((int * string) list, string) result

val parse_certificate : string -> (string * string list, string) result
(** (request context, certificate DERs leaf first). *)

val parse_certificate_verify : string -> (int * string, string) result
(** (signature scheme, signature). *)

val parse_certificate_request : string -> (string, string) result
(** the request context; extensions are dropped. *)

val parse_u16_list_vec16 : string -> (int list, string) result
(** e.g. a signature_algorithms payload. *)

val parse_alpn_payload : string -> (string list, string) result

val parse_key_share_entries : string -> ((int * string) list, string) result
(** ClientHello key_share: (group, key exchange) entries. *)

val parse_key_share_server : string -> (int * string option, string) result
(** ServerHello/HRR key_share; the key is [None] on an HRR. *)

val parse_supported_versions_client : string -> (int list, string) result
val parse_supported_versions_server : string -> (int, string) result
val parse_cookie : string -> (string, string) result

val split_messages : Buffer.t -> (int * string * string) list
(** peel complete messages off the front of [buf], consuming them;
    returns (type, body, raw message incl. header) triples. Partial
    trailing data stays buffered. *)
