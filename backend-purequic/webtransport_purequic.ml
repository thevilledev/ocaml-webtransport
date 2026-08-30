(* Quic_backend.S implemented on the purequic engine.

   The seam's [accept] does not carry the client's initial DCID, but the
   engine needs it before TLS exists (initial keys + the
   original_destination_connection_id transport parameter). Server handles
   therefore start in a [Waiting] state and materialize the connection
   from the first Initial packet — mirroring when quiche does the same
   work.

   The seam's [next_timeout_ns] is a duration with no [now] argument; the
   adapter tracks the engine's last-seen timestamp (drivers call
   recv/send/on_timeout with [now] far more often than the 500 ms poll
   cap, so the drift is bounded and harmless). *)

module Qb = Webtransport.Quic_backend
module Conn = Purequic.Conn

let ensure_rng = lazy (Mirage_crypto_rng_unix.use_default ())

let debug = lazy (Sys.getenv_opt "WT_PURE_DEBUG" <> None)

let dbg fmt =
  if Lazy.force debug then Printf.eprintf ("[pure] " ^^ fmt ^^ "\n%!")
  else Printf.ifprintf stderr fmt

module Impl = struct
  type live = { conn : Conn.t; mutable now : int64 }

  type state =
    | Waiting of { cfg : Conn.config; scid : string; peer : string * int }
    | Live of live
    | Broken of string

  type t = { mutable st : state }

  type config = Conn.config

  type addr = string * int
  type dir = [ `Uni | `Bidi ]

  let read_file path =
    try Ok (In_channel.with_open_bin path In_channel.input_all)
    with Sys_error e -> Error e

  let pem_source ~file ~inline ~what =
    match (file, inline) with
    | Some _, Some _ ->
        Error (Printf.sprintf "config: %s given both as file and in-memory" what)
    | Some f, None -> Result.map Option.some (read_file f)
    | None, Some pem -> Ok (Some pem)
    | None, None -> Ok None

  let config ~role ~alpn ?cert_chain_pem_file ?priv_key_pem_file
      ?cert_chain_pem ?priv_key_pem ?verify ?(enable_datagrams = false)
      ?(initial_max_data = 10_000_000) ?(initial_max_stream_data = 1_000_000)
      ?(initial_max_streams_bidi = 100) ?(initial_max_streams_uni = 100)
      ?(max_idle_ns = 30_000_000_000L) ?(max_udp_payload = 1350) () =
    Lazy.force ensure_rng;
    let ( let* ) = Result.bind in
    let* cert_pem =
      pem_source ~file:cert_chain_pem_file ~inline:cert_chain_pem
        ~what:"certificate chain"
    in
    let* key_pem =
      pem_source ~file:priv_key_pem_file ~inline:priv_key_pem
        ~what:"private key"
    in
    let* cert_chain =
      match cert_pem with
      | None -> Ok []
      | Some pem -> (
          match X509.Certificate.decode_pem_multiple pem with
          | Ok cs -> Ok cs
          | Error (`Msg m) -> Error ("certificate chain: " ^ m))
    in
    let* priv_key =
      match key_pem with
      | None -> Ok None
      | Some pem -> (
          match X509.Private_key.decode_pem pem with
          | Ok k -> Ok (Some k)
          | Error (`Msg m) -> Error ("private key: " ^ m))
    in
    let* verify =
      match verify with
      | Some `None -> Ok `None
      | Some (`Ca_file f) -> (
          let* pem = read_file f in
          match X509.Certificate.decode_pem_multiple pem with
          | Ok anchors -> Ok (`Anchors anchors)
          | Error (`Msg m) -> Error ("ca file: " ^ m))
      | None -> (
          match role with
          | `Server -> Ok `None
          | `Client -> (
              (* parity with quiche: clients verify by default, against the
                 system trust store *)
              match Ca_certs.trust_anchors () with
              | Ok pem -> (
                  match X509.Certificate.decode_pem_multiple pem with
                  | Ok anchors -> Ok (`Anchors anchors)
                  | Error (`Msg m) -> Error ("system trust store: " ^ m))
              | Error (`Msg m) -> Error ("system trust store: " ^ m)))
    in
    Ok
      {
        Conn.role;
        alpn;
        cert_chain;
        priv_key;
        verify;
        time = (fun () -> Some (Ptime_clock.now ()));
        rng = Mirage_crypto_rng.generate;
        enable_datagrams;
        reliable_reset = true;
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
            Ok
              { version = 1l; dcid; scid = ""; is_long = false; is_initial = false }
        | Purequic.Packet.Vneg { dcid; scid; _ } ->
            Ok { version = 0l; dcid; scid; is_long = true; is_initial = false })

  let negotiate_version ~scid ~dcid buf =
    Purequic.Packet.write_vneg buf ~client_dcid:dcid ~client_scid:scid

  let connect cfg ~server_name ~scid ~peer ~local:_ ~now =
    if cfg.Conn.role <> `Client then Error "connect with a server config"
    else begin
      Lazy.force ensure_rng;
      let dcid = Mirage_crypto_rng.generate 16 in
      match Conn.client cfg ~server_name ~scid ~dcid ~peer ~now with
      | Ok conn -> Ok { st = Live { conn; now } }
      | Error e -> Error e
    end

  let accept cfg ~scid ~peer ~local:_ ~now:_ =
    if cfg.Conn.role <> `Server then Error "accept with a client config"
    else Ok { st = Waiting { cfg; scid; peer } }

  let live_opt t = match t.st with Live l -> Some l | _ -> None

  let close t ~app ~code ~reason =
    match t.st with
    | Live l -> Conn.app_close l.conn ~now:l.now ~app ~code ~reason
    | Waiting _ -> t.st <- Broken "closed before first packet"
    | Broken _ -> ()

  let is_established t =
    match live_opt t with
    | Some l -> Conn.is_established l.conn
    | None -> false

  let is_closed t =
    match t.st with
    | Live l -> Conn.is_closed l.conn
    | Waiting _ -> false
    | Broken _ -> true

  let recv t ~now buf ~off ~len ~from ~to_:_ =
    match t.st with
    | Broken e -> Error e
    | Live l ->
        l.now <- now;
        dbg "recv %d bytes" len;
        Conn.recv l.conn ~now buf ~off ~len ~from;
        Ok len
    | Waiting { cfg; scid; peer } -> (
        (* materialize the server connection from the first Initial *)
        match Purequic.Packet.parse buf ~off ~len ~short_dcid_len:16 with
        | Error e -> Error e
        | Ok { hdr = Purequic.Packet.Long { kind = Initial; version = 1l; dcid; _ }; _ }
          -> (
            match Conn.server_with_odcid cfg ~scid ~odcid:dcid ~peer ~now with
            | Error e ->
                t.st <- Broken e;
                Error e
            | Ok conn ->
                t.st <- Live { conn; now };
                Conn.recv conn ~now buf ~off ~len ~from;
                Ok len)
        | Ok _ -> Ok len (* not a v1 Initial: drop until one arrives *))

  let send t ~now buf =
    match t.st with
    | Live l ->
        l.now <- now;
        (match Conn.send l.conn ~now buf with
        | `Packet (n, addr) ->
            dbg "send %d bytes" n;
            `Packet (n, addr)
        | `Done -> `Done)
    | Waiting _ -> `Done
    | Broken e -> `Error e

  let next_timeout_ns t =
    match t.st with
    | Live l -> Conn.next_timeout_ns l.conn ~now:l.now
    | _ -> None

  let on_timeout t ~now =
    match t.st with
    | Live l ->
        l.now <- now;
        Conn.on_timeout l.conn ~now
    | _ -> ()

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

  let next_event t =
    match live_opt t with
    | None -> None
    | Some l -> (
        match Conn.next_event l.conn with
        | None -> None
        | Some e ->
            (match e with
            | Conn.Stream_opened { id; _ } -> dbg "event stream_opened %d" id
            | Conn.Stream_readable id -> dbg "event readable %d" id
            | Conn.Stream_writable id -> dbg "event writable %d" id
            | Conn.Handshake_done _ -> dbg "event handshake_done"
            | Conn.Closed { code; _ } -> dbg "event closed 0x%x" code
            | _ -> ());
            Some
              (match e with
              | Conn.Handshake_done { alpn; peer_max_dgram } ->
                  Handshake_done { alpn; peer_max_dgram }
              | Conn.Stream_opened { id; dir } -> Stream_opened { id; dir }
              | Conn.Stream_readable id -> Stream_readable id
              | Conn.Stream_writable id -> Stream_writable id
              | Conn.Stream_reset { id; code } -> Stream_reset { id; code }
              | Conn.Stream_stopped { id; code } -> Stream_stopped { id; code }
              | Conn.Stream_credit -> Stream_credit
              | Conn.Datagram_readable -> Datagram_readable
              | Conn.Closed { local; app; code; reason } ->
                  Closed { local; app; code; reason }))

  type 'a rw =
    ( 'a,
      [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
    result

  let rw_default : 'a rw = Error `Invalid

  let open_stream t ~dir =
    match live_opt t with
    | Some l -> Conn.open_stream l.conn ~dir
    | None -> rw_default

  let stream_recv t ~id buf ~off ~len =
    match live_opt t with
    | Some l ->
        let r = Conn.stream_recv l.conn ~id buf ~off ~len in
        dbg "stream_recv id=%d -> %s" id
          (match r with
          | Ok (n, fin) -> Printf.sprintf "%d fin=%b" n fin
          | Error `Would_block -> "would_block"
          | Error `Fin -> "fin"
          | Error (`Reset _) -> "reset"
          | Error (`Stopped _) -> "stopped"
          | Error `Invalid -> "invalid");
        r
    | None -> rw_default

  let stream_send t ~id buf ~off ~len ~fin =
    match live_opt t with
    | Some l ->
        let r = Conn.stream_send l.conn ~id buf ~off ~len ~fin in
        dbg "stream_send id=%d len=%d fin=%b -> %s" id len fin
          (match r with
          | Ok n -> string_of_int n
          | Error `Would_block -> "would_block"
          | Error `Fin -> "fin"
          | Error (`Reset _) -> "reset"
          | Error (`Stopped _) -> "stopped"
          | Error `Invalid -> "invalid");
        r
    | None -> rw_default

  let stream_capacity t ~id =
    match live_opt t with
    | Some l -> Conn.stream_capacity l.conn ~id
    | None -> rw_default

  let stream_finish t ~id =
    match live_opt t with
    | Some l -> Conn.stream_finish l.conn ~id
    | None -> rw_default

  let stream_reset t ~id ~code =
    match live_opt t with
    | Some l -> Conn.stream_reset l.conn ~id ~code
    | None -> rw_default

  let stream_stop_sending t ~id ~code =
    match live_opt t with
    | Some l -> Conn.stream_stop_sending l.conn ~id ~code
    | None -> rw_default

  let dgram_send t buf ~off ~len =
    match live_opt t with
    | Some l -> Conn.dgram_send l.conn buf ~off ~len
    | None -> rw_default

  let dgram_recv t buf ~off =
    match live_opt t with
    | Some l -> Conn.dgram_recv l.conn buf ~off
    | None -> rw_default

  let dgram_max_len t =
    match live_opt t with Some l -> Conn.dgram_max_len l.conn | None -> None

  let peer_cert_der t =
    match live_opt t with Some l -> Conn.peer_cert_der l.conn | None -> None
end

include Impl
module _ = (Impl : Qb.S)

module For_testing = struct
  let initiate_key_update t =
    match t.Impl.st with
    | Impl.Live l -> Purequic.Conn.For_testing.initiate_key_update l.conn
    | _ -> ()
end
