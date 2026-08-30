(** QUIC v1 packet headers, packet-number coding, header + payload
    protection, Version Negotiation and Retry (RFC 9000 s.17, RFC 9001
    s.5). Parsers are total. *)

val max_cid_len : int

type long_kind = Initial | Zero_rtt | Handshake | Retry

type header =
  | Long of {
      kind : long_kind;
      version : int32;
      dcid : string;
      scid : string;
      token : string;  (** Initial only; [""] otherwise *)
    }
  | Short of { dcid : string }
  | Vneg of { dcid : string; scid : string; versions : int32 list }

type located = { hdr : header; off : int; pn_off : int; last : int }
(** a packet found inside a datagram; [last] is one past its end. *)

val parse :
  Bigstringaf.t ->
  off:int ->
  len:int ->
  short_dcid_len:int ->
  (located, string) result

val iter :
  Bigstringaf.t ->
  off:int ->
  len:int ->
  short_dcid_len:int ->
  (located -> unit) ->
  unit
(** all coalesced packets of one datagram; stops at malformed remainder. *)

val pn_encode_len : largest_acked:int option -> int -> int
val pn_decode : largest:int -> pn_len:int -> int -> int

val seal :
  keys:Aead.keys -> pn:int64 -> pn_len:int -> header:string -> string -> string
(** protect one packet given its unprotected header bytes (packet number in
    the clear, Length already counting payload + tag); returns the full
    protected packet. *)

val open_ :
  keys:Aead.keys ->
  largest:int option ->
  Bigstringaf.t ->
  located ->
  (int * string) option
(** remove header protection and open the payload; [None] when
    undecryptable. Returns the full packet number and plaintext. *)

val write_vneg :
  Bigstringaf.t -> client_dcid:string -> client_scid:string -> (int, string) result

val retry_valid : odcid:string -> Bigstringaf.t -> located -> bool
