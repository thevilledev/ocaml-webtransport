(* Quic_backend.S implemented on the purequic engine.

   P1 status: the stateless demux helpers ([parse_header],
   [negotiate_version]) are real; connection machinery arrives with the
   engine's connection layer (plan milestone P3). Until then [connect] and
   [accept] return an error, so drivers fail fast rather than misbehave. *)

module Qb = Webtransport.Quic_backend

module Impl = struct
  (* No connections exist yet; the type is a placeholder that P3 replaces
     with the engine connection. *)
  type t = |

  (* Fields become live when the connection layer lands (P3). *)
  type config = {
    role : [ `Client | `Server ];
    alpn : string list;
    cert_chain_pem_file : string option;
    priv_key_pem_file : string option;
    cert_chain_pem : string option;
    priv_key_pem : string option;
    verify : [ `Ca_file of string | `None ] option;
    enable_datagrams : bool;
    initial_max_data : int;
    initial_max_stream_data : int;
    initial_max_streams_bidi : int;
    initial_max_streams_uni : int;
    max_idle_ns : int64;
    max_udp_payload : int;
  }
  [@@warning "-69"]

  type addr = string * int
  type dir = [ `Uni | `Bidi ]

  let config ~role ~alpn ?cert_chain_pem_file ?priv_key_pem_file
      ?cert_chain_pem ?priv_key_pem ?verify ?(enable_datagrams = false)
      ?(initial_max_data = 10_000_000) ?(initial_max_stream_data = 1_000_000)
      ?(initial_max_streams_bidi = 100) ?(initial_max_streams_uni = 100)
      ?(max_idle_ns = 30_000_000_000L) ?(max_udp_payload = 1350) () =
    Ok
      {
        role;
        alpn;
        cert_chain_pem_file;
        priv_key_pem_file;
        cert_chain_pem;
        priv_key_pem;
        verify;
        enable_datagrams;
        initial_max_data;
        initial_max_stream_data;
        initial_max_streams_bidi;
        initial_max_streams_uni;
        max_idle_ns;
        max_udp_payload;
      }

  type header = {
    version : int32;
    dcid : string;
    scid : string;
    is_long : bool;
    is_initial : bool;
  }

  (* Drivers hand us whole datagrams and route on 16-byte short-header
     DCIDs (the demux convention shared with the quiche backend). *)
  let parse_header buf ~off ~len =
    match Purequic.Packet.parse buf ~off ~len ~short_dcid_len:16 with
    | Error e -> Error e
    | Ok { hdr; _ } -> (
        match hdr with
        | Purequic.Packet.Long { kind; version; dcid; scid; _ } ->
            Ok
              {
                version;
                dcid;
                scid;
                is_long = true;
                is_initial = kind = Purequic.Packet.Initial;
              }
        | Purequic.Packet.Short { dcid } ->
            Ok { version = 1l; dcid; scid = ""; is_long = false; is_initial = false }
        | Purequic.Packet.Vneg { dcid; scid; _ } ->
            Ok { version = 0l; dcid; scid; is_long = true; is_initial = false })

  (* The seam passes the fields of the client's header; the packet writer
     swaps them per RFC 9000 s.17.2.1. *)
  let negotiate_version ~scid ~dcid buf =
    Purequic.Packet.write_vneg buf ~client_dcid:dcid ~client_scid:scid

  let not_yet = "webtransport-purequic: connection layer not implemented yet"
  let connect _ ~server_name:_ ~scid:_ ~peer:_ ~local:_ ~now:_ = Error not_yet
  let accept _ ~scid:_ ~peer:_ ~local:_ ~now:_ = Error not_yet
  let close (t : t) ~app:_ ~code:_ ~reason:_ = ( match t with _ -> . )
  let is_established (t : t) = match t with _ -> .
  let is_closed (t : t) = match t with _ -> .
  let recv (t : t) ~now:_ _ ~off:_ ~len:_ ~from:_ ~to_:_ = match t with _ -> .
  let send (t : t) ~now:_ _ = match t with _ -> .
  let next_timeout_ns (t : t) = match t with _ -> .
  let on_timeout (t : t) ~now:_ = match t with _ -> .

  type event =
    | Handshake_done of { alpn : string option; peer_max_dgram : int option }
    | Stream_opened of { id : int; dir : dir }
    | Stream_readable of int
    | Stream_writable of int
    | Stream_reset of { id : int; code : int }
    | Stream_stopped of { id : int; code : int }
    | Stream_credit
    | Datagram_readable
    | Closed of { local : bool; app : bool; code : int; reason : string }

  let next_event (t : t) = match t with _ -> .

  type 'a rw =
    ( 'a,
      [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
    result

  let open_stream (t : t) ~dir:_ = match t with _ -> .
  let stream_recv (t : t) ~id:_ _ ~off:_ ~len:_ = match t with _ -> .
  let stream_send (t : t) ~id:_ _ ~off:_ ~len:_ ~fin:_ = match t with _ -> .
  let stream_capacity (t : t) ~id:_ = match t with _ -> .
  let stream_finish (t : t) ~id:_ = match t with _ -> .
  let stream_reset (t : t) ~id:_ ~code:_ = match t with _ -> .
  let stream_stop_sending (t : t) ~id:_ ~code:_ = match t with _ -> .
  let dgram_send (t : t) _ ~off:_ ~len:_ = match t with _ -> .
  let dgram_recv (t : t) _ ~off:_ = match t with _ -> .
  let dgram_max_len (t : t) = match t with _ -> .
  let peer_cert_der (t : t) = match t with _ -> .
end

include Impl
module _ = (Impl : Qb.S)
