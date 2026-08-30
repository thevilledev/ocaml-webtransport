(** TLS 1.3 key schedule and running transcript (RFC 8446 s.7.1), verified
    against the RFC 8448 traces. *)

val hash_len : Digestif.hash' -> int
val digest : Digestif.hash' -> string -> string
val hmac : Digestif.hash' -> key:string -> string -> string

val expand_label :
  hash:Digestif.hash' ->
  secret:string ->
  label:string ->
  context:string ->
  int ->
  string

val derive_secret :
  hash:Digestif.hash' ->
  secret:string ->
  label:string ->
  transcript_hash:string ->
  string

module Transcript : sig
  type t

  val create : unit -> t
  val feed : t -> string -> unit

  val set_hash : t -> Digestif.hash' -> unit
  (** select the hash once the suite is known; folds buffered messages. *)

  val hash : t -> string

  val substitute_message_hash : t -> Digestif.hash' -> unit
  (** HelloRetryRequest: replace the buffered CH1 with message_hash(CH1). *)
end

val early_secret : hash:Digestif.hash' -> string
val handshake_secret : hash:Digestif.hash' -> early:string -> ecdh_shared:string -> string
val master_secret : hash:Digestif.hash' -> handshake:string -> string
val client_hs_traffic : hash:Digestif.hash' -> handshake:string -> transcript_hash:string -> string
val server_hs_traffic : hash:Digestif.hash' -> handshake:string -> transcript_hash:string -> string
val client_app_traffic : hash:Digestif.hash' -> master:string -> transcript_hash:string -> string
val server_app_traffic : hash:Digestif.hash' -> master:string -> transcript_hash:string -> string
val finished_verify : hash:Digestif.hash' -> traffic_secret:string -> transcript_hash:string -> string
