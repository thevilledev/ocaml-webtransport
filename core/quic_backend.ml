(* The QUIC engine seam.

   Everything above this interface (HTTP/3, WebTransport, the runtime drivers)
   is backend-agnostic. The default implementation wraps Cloudflare quiche
   (webtransport-quiche); tests use a deterministic mock; a pure-OCaml engine
   can slot in later without public API change.

   Conventions:
   - The embedder owns the UDP socket and the clock. Packets are fed in with
     [recv] and pulled out with [send]; [now] is a monotonic timestamp in
     nanoseconds. Backends that keep internal clocks (quiche) may ignore
     [now] on individual calls; the mock backend honors it, which is what
     makes deterministic tests possible against the same signature.
   - Stream ids and error codes are OCaml [int]s: both are QUIC varints,
     whose domain [0, 2^62-1] is exactly [0, max_int] on 64-bit platforms.
   - Calls never block and never run effects; drivers translate [`Would_block]
     into fiber/promise waits. *)

module type S = sig
  type t
  type config

  (* Raw 4/16-byte IP in network order, and port. Matches what both the
     quiche C API and Eio's Ipaddr representation use, so packets cross the
     seam without address conversions. *)
  type addr = string * int

  type dir = [ `Uni | `Bidi ]

  val config :
    role:[ `Client | `Server ] ->
    alpn:string list ->
    ?cert_chain_pem_file:string ->
    ?priv_key_pem_file:string ->
    ?verify:[ `Ca_file of string | `None ] ->
    ?enable_datagrams:bool ->
    ?initial_max_data:int ->
    ?initial_max_stream_data:int ->
    ?initial_max_streams_bidi:int ->
    ?initial_max_streams_uni:int ->
    ?max_idle_ns:int64 ->
    ?max_udp_payload:int ->
    unit ->
    (config, string) result

  (* Stateless helpers for the driver's demux loop. *)
  type header = {
    version : int32;
    dcid : string;
    scid : string;
    is_long : bool;
    is_initial : bool;
  }

  val parse_header :
    Bigstringaf.t -> off:int -> len:int -> (header, string) result

  (* Writes a Version Negotiation packet into the buffer; returns its length. *)
  val negotiate_version :
    scid:string -> dcid:string -> Bigstringaf.t -> (int, string) result

  val connect :
    config ->
    server_name:string option ->
    scid:string ->
    peer:addr ->
    local:addr ->
    now:int64 ->
    (t, string) result

  val accept :
    config ->
    scid:string ->
    peer:addr ->
    local:addr ->
    now:int64 ->
    (t, string) result

  val close : t -> app:bool -> code:int -> reason:string -> unit
  val is_established : t -> bool

  (* Once true, the handle may be dropped; resources are released. *)
  val is_closed : t -> bool

  val recv :
    t ->
    now:int64 ->
    Bigstringaf.t ->
    off:int ->
    len:int ->
    from:addr ->
    to_:addr ->
    (int, string) result

  val send :
    t ->
    now:int64 ->
    Bigstringaf.t ->
    [ `Packet of int * addr | `Done | `Error of string ]

  (* Duration until the next timeout, if any; [on_timeout] fires it. *)
  val next_timeout_ns : t -> int64 option
  val on_timeout : t -> now:int64 -> unit

  type event =
    | Handshake_done of { alpn : string option; peer_max_dgram : int option }
    | Stream_opened of { id : int; dir : dir }  (* peer-initiated *)
    | Stream_readable of int
    | Stream_writable of int
    | Stream_reset of { id : int; code : int }  (* peer sent RESET_STREAM *)
    | Stream_stopped of { id : int; code : int }  (* peer sent STOP_SENDING *)
    | Stream_credit  (* peer raised MAX_STREAMS: blocked opens may retry *)
    | Datagram_readable
    | Closed of { local : bool; app : bool; code : int; reason : string }

  (* Drain after every [recv]/[on_timeout]/mutating call until [None]. *)
  val next_event : t -> event option

  type 'a rw =
    ( 'a,
      [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
    result

  val open_stream : t -> dir:dir -> int rw
  val stream_recv :
    t -> id:int -> Bigstringaf.t -> off:int -> len:int -> (int * bool) rw
  val stream_send :
    t -> id:int -> Bigstringaf.t -> off:int -> len:int -> fin:bool -> int rw
  val stream_capacity : t -> id:int -> int rw
  val stream_finish : t -> id:int -> unit rw
  val stream_reset : t -> id:int -> code:int -> unit rw
  val stream_stop_sending : t -> id:int -> code:int -> unit rw

  val dgram_send : t -> Bigstringaf.t -> off:int -> len:int -> unit rw
  val dgram_recv : t -> Bigstringaf.t -> off:int -> int rw

  (* Max datagram payload the peer accepts; [None] if unsupported. *)
  val dgram_max_len : t -> int option

  (* DER of the peer's leaf certificate (for hash pinning). *)
  val peer_cert_der : t -> string option
end
