(* A QUIC v1 connection: the sans-io engine tying together TLS, packet
   protection, streams, flow control, datagrams, loss recovery and
   timers. One [t] per connection; every entry point takes [now] (monotonic
   nanoseconds) and the module never reads a clock or global RNG — the
   whole connection is a deterministic function of (inputs, config.rng,
   now), which is what makes scripted-clock tests possible.

   Scope per the project plan: QUIC v1, client + server. No Retry
   emission, no stateless reset, no active migration (we advertise
   disable_active_migration and only track the peer's address passively),
   no 0-RTT, no ECN. PATH_CHALLENGE is answered; NEW_CONNECTION_ID is
   honored (including retire_prior_to); key update is supported in both
   directions. *)

module Tls = Purequic_tls.Tls
module Cipher = Purequic_tls.Cipher

type role = [ `Client | `Server ]
type addr = string * int
type dir = [ `Uni | `Bidi ]

type config = {
  role : role;
  alpn : string list;
  cert_chain : X509.Certificate.t list;
  priv_key : X509.Private_key.t option;
  verify : [ `None | `Anchors of X509.Certificate.t list ];
  time : unit -> Ptime.t option;
  rng : int -> string;
  enable_datagrams : bool;
  reliable_reset : bool;
  initial_max_data : int;
  initial_max_stream_data : int;
  initial_max_streams_bidi : int;
  initial_max_streams_uni : int;
  max_idle_ns : int64;
  max_udp_payload : int;
}

type event =
  | Handshake_done of { alpn : string option; peer_max_dgram : int option }
  | Stream_opened of { id : int; dir : dir }
  | Stream_readable of int
  | Stream_writable of int
  | Stream_reset of { id : int; code : int }
  | Stream_reset_at of { id : int; code : int; reliable_size : int }
  | Stream_stopped of { id : int; code : int }
  | Stream_credit
  | Datagram_readable
  | Closed of { local : bool; app : bool; code : int; reason : string }

type 'a rw =
  ( 'a,
    [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
  result

type space = {
  ix : int;  (* 0 = Initial, 1 = Handshake, 2 = Application *)
  mutable tx_keys : Aead.keys option;
  mutable rx_keys : Aead.keys option;
  mutable next_pn : int;
  crypto : Crypto_stream.t;
  rx_pns : Ranges.t;
  mutable largest_rx : int;  (* -1 *)
  mutable ae_rx_unacked : int;
  mutable ack_deadline : int64 option;
  mutable ack_now : bool;
  mutable probe : int;
  rec_space : Recovery.space;
}

let mk_space ix =
  {
    ix;
    tx_keys = None;
    rx_keys = None;
    next_pn = 0;
    crypto = Crypto_stream.create ();
    rx_pns = Ranges.create ();
    largest_rx = -1;
    ae_rx_unacked = 0;
    ack_deadline = None;
    ack_now = false;
    probe = 0;
    rec_space = Recovery.mk_space ();
  }

type close_state =
  | Open
  | Closing of int64  (* drop dead at this time *)
  | Draining of int64
  | Dead

type t = {
  cfg : config;
  mutable peer : addr;
  scid : string;
  mutable dcid : string;
  mutable dcid_locked : bool;  (* client: adopted the server's SCID *)
  original_dcid : string;  (* client: its initial DCID, for tparam auth *)
  mutable dcid_seq : int;
  tls : Tls.t;
  spaces : space array;
  recovery : Recovery.t;
  events : event Queue.t;
  mutable established : bool;
  mutable hs_confirmed : bool;
  mutable handshake_event_sent : bool;
  mutable peer_params : Tparams.t option;
  mutable peer_ack_delay_exp : int;
  (* streams *)
  streams : (int, Stream.t) Hashtbl.t;
  mutable next_bidi : int;
  mutable next_uni : int;
  mutable peer_max_streams_bidi : int;
  mutable peer_max_streams_uni : int;
  mutable opened_bidi : int;
  mutable opened_uni : int;
  mutable local_max_bidi : int;
  mutable local_max_uni : int;
  mutable peer_opened_bidi : int;
  mutable peer_opened_uni : int;
  mutable closed_bidi : int;  (* fully-closed peer streams since last raise *)
  mutable closed_uni : int;
  mutable max_streams_dirty : bool;
  mutable streams_blocked : dir option;
  (* connection flow control *)
  mutable peer_max_data : int;
  mutable queued_data : int;  (* bytes accepted for sending *)
  mutable local_max_data : int;
  mutable recv_data : int;  (* sum of per-stream highest offsets *)
  mutable consumed_data : int;  (* sum of per-stream read offsets *)
  mutable max_data_dirty : bool;
  mutable data_blocked : bool;
  (* datagrams *)
  dgram_rx : string Queue.t;
  dgram_tx : string Queue.t;
  mutable peer_max_dgram : int option;
  (* connection ids from the peer *)
  ncids : (int, string) Hashtbl.t;
  mutable retire_queue : int list;
  (* path *)
  mutable path_responses : string list;
  mutable hs_done_pending : bool;
  mutable hs_done_acked : bool;
  (* closing *)
  mutable state : close_state;
  mutable close_frame : (bool * int * string) option;
  mutable close_tx_pending : bool;
  mutable closed_event_sent : bool;
  mutable idle_deadline : int64;
  (* anti-amplification (server, pre-validation) *)
  mutable addr_validated : bool;
  mutable bytes_received : int;
  mutable bytes_sent : int;
  (* key update *)
  mutable tx_phase : bool;
  mutable rx_phase : bool;
  mutable prev_rx_keys : Aead.keys option;
  (* 1-RTT datagrams that arrived before the application keys (typically
     coalesced with the peer's final handshake flight); replayed once the
     keys install (RFC 9001 s.5.7). *)
  mutable early_app_stash : (string * addr) list;
  mutable replaying : bool;
  (* qlog sink: receives one JSON event text per call (no framing) *)
  mutable trace : (string -> unit) option;
}

let emit t e = Queue.add e t.events
let next_event t = Queue.take_opt t.events

(* ---- qlog (draft-qlog JSON-SEQ event bodies; framing is the sink's job) *)

let set_trace t f = t.trace <- Some f

let frame_qname (f : Frame.t) =
  match f with
  | Frame.Padding _ -> "padding"
  | Frame.Ping -> "ping"
  | Frame.Ack _ -> "ack"
  | Frame.Reset_stream _ -> "reset_stream"
  | Frame.Reset_stream_at _ -> "reset_stream_at"
  | Frame.Stop_sending _ -> "stop_sending"
  | Frame.Crypto _ -> "crypto"
  | Frame.New_token _ -> "new_token"
  | Frame.Stream _ -> "stream"
  | Frame.Max_data _ -> "max_data"
  | Frame.Max_stream_data _ -> "max_stream_data"
  | Frame.Max_streams_bidi _ | Frame.Max_streams_uni _ -> "max_streams"
  | Frame.Data_blocked _ -> "data_blocked"
  | Frame.Stream_data_blocked _ -> "stream_data_blocked"
  | Frame.Streams_blocked_bidi _ | Frame.Streams_blocked_uni _ ->
      "streams_blocked"
  | Frame.New_connection_id _ -> "new_connection_id"
  | Frame.Retire_connection_id _ -> "retire_connection_id"
  | Frame.Path_challenge _ -> "path_challenge"
  | Frame.Path_response _ -> "path_response"
  | Frame.Connection_close _ -> "connection_close"
  | Frame.Handshake_done -> "handshake_done"
  | Frame.Datagram _ -> "datagram"

let space_qname ix =
  match ix with 0 -> "initial" | 1 -> "handshake" | _ -> "1RTT"

let qlog t ~now name data =
  match t.trace with
  | None -> ()
  | Some sink ->
      sink
        (Printf.sprintf {|{"time":%.3f,"name":"%s","data":%s}|}
           (Int64.to_float now /. 1e6)
           name data)

let qlog_packet t ~now ~dir ~ix ~pn ~size frames =
  if t.trace <> None then
    qlog t ~now
      (if dir = `Tx then "transport:packet_sent" else "transport:packet_received")
      (Printf.sprintf
         {|{"header":{"packet_type":"%s","packet_number":%d},"raw":{"length":%d},"frames":[%s]}|}
         (space_qname ix) pn size
         (String.concat ","
            (List.map
               (fun f -> Printf.sprintf {|{"frame_type":"%s"}|} (frame_qname f))
               frames)))

let qlog_dropped t ~now ~ix ~reason =
  if t.trace <> None then
    qlog t ~now "transport:packet_dropped"
      (Printf.sprintf {|{"header":{"packet_type":"%s"},"trigger":"%s"}|}
         (space_qname ix) reason)

let qlog_metrics t ~now =
  if t.trace <> None then
    qlog t ~now "recovery:metrics_updated"
      (Printf.sprintf
         {|{"smoothed_rtt":%.3f,"congestion_window":%d,"bytes_in_flight":%d}|}
         (Int64.to_float (Recovery.srtt_ns t.recovery) /. 1e6)
         (Recovery.cwnd t.recovery)
         (Recovery.bytes_in_flight t.recovery))

let sp_initial t = t.spaces.(0)
let sp_handshake t = t.spaces.(1)
let sp_app t = t.spaces.(2)

let is_established t = t.established

let is_closed t =
  match t.state with
  | Dead -> true
  | _ -> false

(* ---- transport parameters ---- *)

let our_params ~(cfg : config) ~scid ~odcid =
  {
    Tparams.default with
    original_dcid = (if cfg.role = `Server then Some odcid else None);
    initial_scid = Some scid;
    max_idle_timeout_ms = Int64.to_int (Int64.div cfg.max_idle_ns 1_000_000L);
    max_udp_payload_size = 65527;
    initial_max_data = cfg.initial_max_data;
    initial_max_stream_data_bidi_local = cfg.initial_max_stream_data;
    initial_max_stream_data_bidi_remote = cfg.initial_max_stream_data;
    initial_max_stream_data_uni = cfg.initial_max_stream_data;
    initial_max_streams_bidi = cfg.initial_max_streams_bidi;
    initial_max_streams_uni = cfg.initial_max_streams_uni;
    disable_active_migration = true;
    max_datagram_frame_size =
      (if cfg.enable_datagrams then Some 65527 else None);
    reliable_reset = cfg.reliable_reset;
  }

(* ---- closing ---- *)

let pto_total t =
  Int64.mul 3L (Recovery.pto_backed_off t.recovery ~is_app:true)

let start_closing t ~now ~app ~code ~reason =
  match t.state with
  | Open ->
      t.close_frame <- Some (app, code, reason);
      t.close_tx_pending <- true;
      t.state <- Closing (Int64.add now (pto_total t))
  | _ -> ()

let close t ~now ~app ~code ~reason =
  if not t.closed_event_sent then begin
    t.closed_event_sent <- true;
    emit t (Closed { local = true; app; code; reason })
  end;
  start_closing t ~now ~app ~code ~reason

(* transport-level close from inside the machinery *)
let protocol_close t ~now ~code ~reason =
  close t ~now ~app:false ~code ~reason

(* ---- TLS event pump ---- *)

let level_space t (lvl : Tls.level) =
  match lvl with
  | Tls.Initial -> sp_initial t
  | Tls.Handshake -> sp_handshake t
  | Tls.Application -> sp_app t

let suite_of_cipher c = Option.get (Qsuite.of_tls_id (Cipher.to_id c))

let apply_peer_params t ~now params =
  t.peer_params <- Some params;
  t.peer_ack_delay_exp <- params.Tparams.ack_delay_exponent;
  Recovery.set_max_ack_delay_ns t.recovery
    (Int64.mul (Int64.of_int params.Tparams.max_ack_delay_ms) 1_000_000L);
  t.peer_max_data <- params.Tparams.initial_max_data;
  t.peer_max_streams_bidi <- params.Tparams.initial_max_streams_bidi;
  t.peer_max_streams_uni <- params.Tparams.initial_max_streams_uni;
  t.peer_max_dgram <- params.Tparams.max_datagram_frame_size;
  (* authenticate the handshake CIDs (RFC 9000 s.7.3) *)
  let auth_ok =
    match t.cfg.role with
    | `Server -> params.Tparams.initial_scid = Some t.dcid
    | `Client ->
        (* dcid holds the server's chosen SCID by the time EE arrives *)
        params.Tparams.initial_scid = Some t.dcid
        && params.Tparams.original_dcid = Some t.original_dcid
  in
  if not auth_ok then
    protocol_close t ~now ~code:0x08 ~reason:"transport parameter cid mismatch"

let rec drain_tls t ~now =
  match Tls.next_event t.tls with
  | None -> ()
  | Some ev ->
      (match ev with
      | Tls.Send { level; data } ->
          Crypto_stream.send (level_space t level).crypto data
      | Tls.Rx_secret { level; cipher; secret } ->
          let sp = level_space t level in
          sp.rx_keys <-
            Some (Aead.of_secret ~suite:(suite_of_cipher cipher) secret)
      | Tls.Tx_secret { level; cipher; secret } ->
          let sp = level_space t level in
          sp.tx_keys <-
            Some (Aead.of_secret ~suite:(suite_of_cipher cipher) secret)
      | Tls.Peer_transport_params raw -> (
          match Tparams.decode raw with
          | Ok params -> apply_peer_params t ~now params
          | Error e ->
              protocol_close t ~now ~code:0x08 ~reason:("bad tparams: " ^ e))
      | Tls.Handshake_complete { alpn } ->
          t.established <- true;
          if t.cfg.role = `Server then begin
            (* server: handshake confirmed on completion *)
            t.hs_confirmed <- true;
            t.hs_done_pending <- true
          end;
          if not t.handshake_event_sent then begin
            t.handshake_event_sent <- true;
            let peer_max_dgram =
              if t.cfg.enable_datagrams then t.peer_max_dgram else None
            in
            emit t (Handshake_done { alpn = Some alpn; peer_max_dgram })
          end
      | Tls.Fatal { alert; reason } ->
          protocol_close t ~now ~code:(0x100 lor alert) ~reason);
      drain_tls t ~now

(* ---- construction ---- *)

let create ~cfg ~peer ~scid ~dcid ~server_name ~odcid_for_params ~now =
  let tparams =
    Tparams.encode (our_params ~cfg ~scid ~odcid:odcid_for_params)
  in
  let tls_cfg =
    match cfg.role with
    | `Client ->
        Tls.client_config ~verify:cfg.verify ~time:cfg.time ?server_name
          ~alpn:cfg.alpn ~transport_params:tparams ~rng:cfg.rng ()
    | `Server -> (
        match cfg.priv_key with
        | None -> Error "server config requires a private key"
        | Some priv_key ->
            Tls.server_config ~cert_chain:cfg.cert_chain ~priv_key
              ~alpn:cfg.alpn ~transport_params:tparams ~rng:cfg.rng ())
  in
  match tls_cfg with
  | Error e -> Error e
  | Ok tls_cfg ->
      let t =
        {
          cfg;
          peer;
          scid;
          dcid;
          dcid_locked = false;
          original_dcid = (if cfg.role = `Client then dcid else odcid_for_params);
          dcid_seq = 0;
          tls = Tls.create tls_cfg;
          spaces = [| mk_space 0; mk_space 1; mk_space 2 |];
          recovery = Recovery.create ();
          events = Queue.create ();
          established = false;
          hs_confirmed = false;
          handshake_event_sent = false;
          peer_params = None;
          peer_ack_delay_exp = 3;
          streams = Hashtbl.create 16;
          next_bidi = (if cfg.role = `Client then 0 else 1);
          next_uni = (if cfg.role = `Client then 2 else 3);
          peer_max_streams_bidi = 0;
          peer_max_streams_uni = 0;
          opened_bidi = 0;
          opened_uni = 0;
          local_max_bidi = cfg.initial_max_streams_bidi;
          local_max_uni = cfg.initial_max_streams_uni;
          peer_opened_bidi = 0;
          peer_opened_uni = 0;
          closed_bidi = 0;
          closed_uni = 0;
          max_streams_dirty = false;
          streams_blocked = None;
          peer_max_data = 0;
          queued_data = 0;
          local_max_data = cfg.initial_max_data;
          recv_data = 0;
          consumed_data = 0;
          max_data_dirty = false;
          data_blocked = false;
          dgram_rx = Queue.create ();
          dgram_tx = Queue.create ();
          peer_max_dgram = None;
          ncids = Hashtbl.create 4;
          retire_queue = [];
          path_responses = [];
          hs_done_pending = false;
          hs_done_acked = false;
          state = Open;
          close_frame = None;
          close_tx_pending = false;
          closed_event_sent = false;
          idle_deadline = Int64.add now cfg.max_idle_ns;
          addr_validated = cfg.role = `Client;
          bytes_received = 0;
          bytes_sent = 0;
          tx_phase = false;
          rx_phase = false;
          prev_rx_keys = None;
          early_app_stash = [];
          replaying = false;
          trace = None;
        }
      in
      Ok t

let client cfg ~server_name ~scid ~dcid ~peer ~now =
  if cfg.role <> `Client then Error "config role is not `Client"
  else
    match
      create ~cfg ~peer ~scid ~dcid ~server_name ~odcid_for_params:"" ~now
    with
    | Error e -> Error e
    | Ok t ->
        let itx, irx = Aead.initial_keys ~dcid ~role:`Client in
        (sp_initial t).tx_keys <- Some itx;
        (sp_initial t).rx_keys <- Some irx;
        Tls.start t.tls;
        drain_tls t ~now;
        Ok t

let server_with_odcid cfg ~scid ~odcid ~peer ~now =
  if cfg.role <> `Server then Error "config role is not `Server"
  else
    match
      create ~cfg ~peer ~scid ~dcid:"" ~server_name:None
        ~odcid_for_params:odcid ~now
    with
    | Error e -> Error e
    | Ok t ->
        let itx, irx = Aead.initial_keys ~dcid:odcid ~role:`Server in
        (sp_initial t).tx_keys <- Some itx;
        (sp_initial t).rx_keys <- Some irx;
        Ok t

(* ---- streams: id/table helpers ---- *)

let is_peer_initiated t id =
  match t.cfg.role with `Client -> id land 1 = 1 | `Server -> id land 1 = 0

let is_uni id = id land 2 = 2

let peer_send_credit t ~id =
  (* the peer's advertised per-stream credit for OUR send side *)
  match t.peer_params with
  | None -> 0
  | Some p ->
      if is_uni id then p.Tparams.initial_max_stream_data_uni
      else if is_peer_initiated t id then
        p.Tparams.initial_max_stream_data_bidi_local
      else p.Tparams.initial_max_stream_data_bidi_remote

let get_stream t id = Hashtbl.find_opt t.streams id

(* register a peer-initiated stream (and any implicitly opened lower ids) *)
let ensure_peer_stream t id ~now =
  match get_stream t id with
  | Some s -> Some s
  | None ->
      if not (is_peer_initiated t id) then None
      else begin
        let uni = is_uni id in
        let index = id lsr 2 in
        let limit = if uni then t.local_max_uni else t.local_max_bidi in
        if index >= limit then begin
          protocol_close t ~now ~code:0x04 ~reason:"stream limit exceeded";
          None
        end
        else begin
          let base = (if uni then 2 else 0) lor (if t.cfg.role = `Client then 1 else 0) in
          let opened = if uni then t.peer_opened_uni else t.peer_opened_bidi in
          for i = opened to index do
            let sid = (i lsl 2) lor base in
            if not (Hashtbl.mem t.streams sid) then begin
              let s =
                Stream.create ~id:sid
                  ~send_credit:(peer_send_credit t ~id:sid)
                  ~recv_credit:t.cfg.initial_max_stream_data
                  ~has_send:(not uni) ~has_recv:true
              in
              Hashtbl.replace t.streams sid s;
              emit t
                (Stream_opened { id = sid; dir = (if uni then `Uni else `Bidi) })
            end
          done;
          if uni then t.peer_opened_uni <- max t.peer_opened_uni (index + 1)
          else t.peer_opened_bidi <- max t.peer_opened_bidi (index + 1);
          get_stream t id
        end
      end

let stream_fully_closed (s : Stream.t) =
  let send_done =
    match s.Stream.send with Some snd -> Stream.send_closed snd | None -> true
  in
  let recv_done =
    match s.Stream.recv with Some rcv -> Stream.recv_closed rcv | None -> true
  in
  send_done && recv_done

let note_peer_stream_closed t id =
  if is_peer_initiated t id then begin
    if is_uni id then begin
      t.closed_uni <- t.closed_uni + 1;
      if t.closed_uni >= max 1 (t.cfg.initial_max_streams_uni / 2) then begin
        t.local_max_uni <- t.local_max_uni + t.closed_uni;
        t.closed_uni <- 0;
        t.max_streams_dirty <- true
      end
    end
    else begin
      t.closed_bidi <- t.closed_bidi + 1;
      if t.closed_bidi >= max 1 (t.cfg.initial_max_streams_bidi / 2) then begin
        t.local_max_bidi <- t.local_max_bidi + t.closed_bidi;
        t.closed_bidi <- 0;
        t.max_streams_dirty <- true
      end
    end
  end

(* ---- frame handling ---- *)

let ack_delay_to_ns t raw =
  (* raw is in units of 2^exponent microseconds *)
  Int64.mul (Int64.of_int (raw lsl t.peer_ack_delay_exp)) 1_000L

let requeue_lost t (lost : Recovery.sent list) =
  List.iter
    (fun (s : Recovery.sent) ->
      List.iter
        (fun (r : Recovery.retx) ->
          match r with
          | Recovery.Rtx_crypto { space; lo; hi } ->
              Crypto_stream.requeue t.spaces.(space).crypto ~lo ~hi
          | Recovery.Rtx_stream { id; lo; hi; fin } -> (
              match get_stream t id with
              | Some { Stream.send = Some snd; _ } ->
                  Stream.send_on_lost snd ~lo ~hi ~fin
              | _ -> ())
          | Recovery.Rtx_flags ->
              (* over-approximate: refresh all control state *)
              t.max_data_dirty <- true;
              t.max_streams_dirty <- true;
              if t.hs_done_pending || not t.hs_done_acked then
                t.hs_done_pending <- t.cfg.role = `Server && t.established
                                     && not t.hs_done_acked;
              Hashtbl.iter
                (fun _ (s : Stream.t) ->
                  match s.Stream.send with
                  | Some snd when snd.Stream.reset <> None
                                  && not snd.Stream.reset_acked ->
                      snd.Stream.reset_pending <- true
                  | _ -> ())
                t.streams
          | Recovery.Rtx_dgram -> ())
        s.Recovery.retx)
    lost

let on_acked_descriptors t (acked : Recovery.sent list) =
  List.iter
    (fun (s : Recovery.sent) ->
      List.iter
        (fun (r : Recovery.retx) ->
          match r with
          | Recovery.Rtx_stream { id; lo; hi; fin } -> (
              match get_stream t id with
              | Some ({ Stream.send = Some snd; _ } as st) ->
                  Stream.send_on_acked snd ~lo ~hi ~fin;
                  (match snd.Stream.reset with
                  | Some _ -> snd.Stream.reset_acked <- true
                  | None -> ());
                  if stream_fully_closed st then note_peer_stream_closed t id
              | _ -> ())
          | Recovery.Rtx_flags -> t.hs_done_acked <- true
          | _ -> ())
        s.Recovery.retx)
    acked

exception Proto_violation of int * string

let handle_frame t sp ~now (f : Frame.t) =
  match f with
  | Frame.Padding _ | Frame.Ping -> ()
  | Frame.Ack { largest; delay; ranges; ecn = _ } ->
      if largest >= sp.next_pn then
        raise (Proto_violation (0x0a, "ack for unsent packet"))
      else begin
        let acked, lost =
          Recovery.on_ack t.recovery sp.rec_space ~largest ~ranges
            ~ack_delay_ns:(ack_delay_to_ns t delay)
            ~now ~is_app:(sp.ix = 2)
        in
        on_acked_descriptors t acked;
        requeue_lost t lost;
        if acked <> [] then qlog_metrics t ~now;
        (* cwnd/credit may have opened: wake blocked streams *)
        if acked <> [] then
          Hashtbl.iter
            (fun id (s : Stream.t) ->
              match s.Stream.send with
              | Some snd when snd.Stream.blocked ->
                  snd.Stream.blocked <- false;
                  emit t (Stream_writable id)
              | _ -> ())
            t.streams
      end
  | Frame.Crypto { off; data } -> (
      let level : Tls.level =
        match sp.ix with 0 -> Tls.Initial | 1 -> Tls.Handshake | _ -> Tls.Application
      in
      match
        Crypto_stream.recv sp.crypto ~off (Frame.payload_to_string data)
          ~deliver:(fun chunk ->
            Tls.handle t.tls ~level chunk;
            drain_tls t ~now)
      with
      | Ok () -> ()
      | Error e -> raise (Proto_violation (0x0d, e)))
  | Frame.Stream { id; off; fin; data } -> (
      match
        match get_stream t id with
        | Some s -> Some s
        | None -> ensure_peer_stream t id ~now
      with
      | None ->
          (* our own id we never opened, or a closed-and-forgotten one *)
          if not (is_peer_initiated t id) && not (Hashtbl.mem t.streams id)
          then raise (Proto_violation (0x05, "stream frame on unopened id"))
      | Some s -> (
          match s.Stream.recv with
          | None -> raise (Proto_violation (0x05, "stream frame on send-only id"))
          | Some rcv -> (
              let before_high = rcv.Stream.highest in
              let payload = Frame.payload_to_string data in
              match Stream.recv_on_frame rcv ~off ~fin payload with
              | `Err e -> raise (Proto_violation (0x06, e))
              | `Ok readable ->
                  t.recv_data <- t.recv_data + (rcv.Stream.highest - before_high);
                  if t.recv_data > t.local_max_data then
                    raise (Proto_violation (0x03, "connection flow control"))
                  else if rcv.Stream.highest > rcv.Stream.credit then
                    raise (Proto_violation (0x03, "stream flow control"))
                  else if readable then emit t (Stream_readable id))))
  | Frame.Reset_stream { id; code; final_size } -> (
      match
        match get_stream t id with
        | Some s -> Some s
        | None -> ensure_peer_stream t id ~now
      with
      | None -> ()
      | Some s -> (
          match s.Stream.recv with
          | None -> raise (Proto_violation (0x05, "reset on send-only id"))
          | Some rcv -> (
              let before_high = rcv.Stream.highest in
              match
                Stream.recv_on_reset rcv ~code ~final_size ~reliable:0
              with
              | `Err e -> raise (Proto_violation (0x06, e))
              | `Ok _ ->
                  t.recv_data <-
                    t.recv_data + (max final_size before_high - before_high);
                  emit t (Stream_reset { id; code });
                  if stream_fully_closed s then note_peer_stream_closed t id)))
  | Frame.Reset_stream_at { id; code; final_size; reliable_size } -> (
      match
        match get_stream t id with
        | Some s -> Some s
        | None -> ensure_peer_stream t id ~now
      with
      | None -> ()
      | Some s -> (
          match s.Stream.recv with
          | None -> raise (Proto_violation (0x05, "reset_at on send-only id"))
          | Some rcv -> (
              match
                Stream.recv_on_reset rcv ~code ~final_size
                  ~reliable:reliable_size
              with
              | `Err e -> raise (Proto_violation (0x06, e))
              | `Ok _ ->
                  emit t (Stream_reset_at { id; code; reliable_size });
                  emit t (Stream_readable id))))
  | Frame.Stop_sending { id; code } -> (
      match get_stream t id with
      | None -> ()
      | Some s -> (
          match s.Stream.send with
          | None -> raise (Proto_violation (0x05, "stop_sending on recv-only"))
          | Some snd ->
              (* RFC 9000 s.3.5: respond with RESET_STREAM *)
              Stream.send_reset snd ~code;
              emit t (Stream_stopped { id; code })))
  | Frame.Max_data v ->
      if v > t.peer_max_data then begin
        t.peer_max_data <- v;
        t.data_blocked <- false;
        Hashtbl.iter
          (fun id (s : Stream.t) ->
            match s.Stream.send with
            | Some snd when snd.Stream.blocked ->
                snd.Stream.blocked <- false;
                emit t (Stream_writable id)
            | _ -> ())
          t.streams
      end
  | Frame.Max_stream_data { id; max } -> (
      match get_stream t id with
      | None -> ()
      | Some s -> (
          match s.Stream.send with
          | None -> ()
          | Some snd ->
              if max > snd.Stream.credit then begin
                snd.Stream.credit <- max;
                if snd.Stream.blocked then begin
                  snd.Stream.blocked <- false;
                  emit t (Stream_writable id)
                end
              end))
  | Frame.Max_streams_bidi v ->
      if v > t.peer_max_streams_bidi then begin
        t.peer_max_streams_bidi <- v;
        emit t Stream_credit
      end
  | Frame.Max_streams_uni v ->
      if v > t.peer_max_streams_uni then begin
        t.peer_max_streams_uni <- v;
        emit t Stream_credit
      end
  | Frame.Data_blocked _ -> t.max_data_dirty <- true
  | Frame.Stream_data_blocked { id; _ } -> (
      match get_stream t id with
      | Some { Stream.recv = Some rcv; _ } -> rcv.Stream.credit_dirty <- true
      | _ -> ())
  | Frame.Streams_blocked_bidi _ | Frame.Streams_blocked_uni _ ->
      t.max_streams_dirty <- true
  | Frame.New_connection_id { seq; retire_prior_to; cid; reset_token = _ } ->
      Hashtbl.replace t.ncids seq cid;
      if retire_prior_to > t.dcid_seq then begin
        (* switch to the lowest usable sequence and retire the old ones *)
        let best =
          Hashtbl.fold
            (fun s c acc ->
              if s >= retire_prior_to then
                match acc with
                | Some (s', _) when s' <= s -> acc
                | _ -> Some (s, c)
              else acc)
            t.ncids None
        in
        (match best with
        | Some (s, c) ->
            t.dcid <- c;
            t.dcid_seq <- s
        | None -> ());
        Hashtbl.iter
          (fun s _ ->
            if s < retire_prior_to then
              t.retire_queue <- s :: t.retire_queue)
          t.ncids;
        Hashtbl.filter_map_inplace
          (fun s c -> if s < retire_prior_to then None else Some c)
          t.ncids
      end
  | Frame.Retire_connection_id _ ->
      (* we never issue extra CIDs, so there is nothing to retire; a
         conforming peer only retires what exists. Ignore. *)
      ()
  | Frame.Path_challenge data ->
      t.path_responses <- data :: t.path_responses
  | Frame.Path_response _ -> ()
  | Frame.New_token _ -> ()
  | Frame.Handshake_done ->
      if t.cfg.role = `Server then
        raise (Proto_violation (0x0a, "client sent HANDSHAKE_DONE"))
      else t.hs_confirmed <- true
  | Frame.Datagram { data } ->
      if Queue.length t.dgram_rx < 1024 then begin
        Queue.add (Frame.payload_to_string data) t.dgram_rx;
        emit t Datagram_readable
      end
  | Frame.Connection_close { app; code; reason; _ } ->
      if not t.closed_event_sent then begin
        t.closed_event_sent <- true;
        emit t
          (Closed
             {
               local = false;
               app;
               code;
               reason = Frame.payload_to_string reason;
             })
      end;
      (match t.state with
      | Open | Closing _ -> t.state <- Draining (Int64.add now (pto_total t))
      | _ -> ())

(* ---- receive path ---- *)

let discard_initial t =
  let sp = sp_initial t in
  sp.tx_keys <- None;
  sp.rx_keys <- None;
  Recovery.discard_space t.recovery sp.rec_space

let space_for_packet t (located : Packet.located) =
  match located.Packet.hdr with
  | Packet.Long { kind = Packet.Initial; _ } -> Some (sp_initial t)
  | Packet.Long { kind = Packet.Handshake; _ } -> Some (sp_handshake t)
  | Packet.Short _ -> Some (sp_app t)
  | _ -> None

let try_open t sp buf located =
  match sp.rx_keys with
  | None -> None
  | Some keys -> (
      match
        Packet.open_ ~keys
          ~largest:(if sp.largest_rx < 0 then None else Some sp.largest_rx)
          buf located
      with
      | Some r -> Some (r, `Current)
      | None when sp.ix = 2 -> (
          (* key update: try the next generation, then the previous *)
          let next = Aead.next_generation keys in
          match
            Packet.open_ ~keys:next
              ~largest:(if sp.largest_rx < 0 then None else Some sp.largest_rx)
              buf located
          with
          | Some r -> Some (r, `Next next)
          | None -> (
              match t.prev_rx_keys with
              | Some prev -> (
                  match
                    Packet.open_ ~keys:prev
                      ~largest:
                        (if sp.largest_rx < 0 then None else Some sp.largest_rx)
                      buf located
                  with
                  | Some r -> Some (r, `Prev)
                  | None -> None)
              | None -> None))
      | None -> None)

let rec recv t ~now buf ~off ~len ~from =
  match t.state with
  | Dead | Draining _ -> ()
  | Closing _ ->
      (* every incoming datagram re-arms one close retransmission *)
      t.close_tx_pending <- true
  | Open ->
      t.bytes_received <- t.bytes_received + len;
      Packet.iter buf ~off ~len ~short_dcid_len:(String.length t.scid)
        (fun located ->
          match space_for_packet t located with
          | None -> ()
          | Some sp -> (
              (* stash 1-RTT packets that beat the application keys *)
              if
                sp.ix = 2 && sp.rx_keys = None && (not t.replaying)
                && List.length t.early_app_stash < 8
              then
                t.early_app_stash <-
                  ( Bigstringaf.substring buf ~off:located.Packet.off
                      ~len:(located.Packet.last - located.Packet.off),
                    from )
                  :: t.early_app_stash;
              match try_open t sp buf located with
              | None ->
                  qlog_dropped t ~now ~ix:sp.ix
                    ~reason:
                      (if sp.rx_keys = None then "key_unavailable"
                       else "decrypt_error")
              | Some ((pn, plaintext), key_gen) ->
                  (* adopt the peer's source CID for our outgoing headers:
                     the server learns the client's SCID from its Initial;
                     the client switches to the server's chosen SCID with
                     the first authenticated reply *)
                  (match located.Packet.hdr with
                  | Packet.Long { scid; kind; _ } ->
                      if
                        t.cfg.role = `Server && t.dcid = ""
                        && kind = Packet.Initial
                      then t.dcid <- scid
                      else if t.cfg.role = `Client && not t.dcid_locked then begin
                        t.dcid <- scid;
                        t.dcid_locked <- true
                      end
                  | _ -> ());
                  (* rotate keys on a successful next-generation open *)
                  (match key_gen with
                  | `Next next ->
                      t.prev_rx_keys <- sp.rx_keys;
                      sp.rx_keys <- Some next;
                      t.rx_phase <- not t.rx_phase;
                      (* our sends must move to the new generation too *)
                      (match sp.tx_keys with
                      | Some txk ->
                          sp.tx_keys <- Some (Aead.next_generation txk);
                          t.tx_phase <- not t.tx_phase
                      | None -> ())
                  | `Prev | `Current -> ());
                  (* server: a decrypted Handshake packet validates the
                     address and retires Initial keys *)
                  if sp.ix = 1 && t.cfg.role = `Server then begin
                    t.addr_validated <- true;
                    if (sp_initial t).rx_keys <> None then discard_initial t
                  end;
                  t.peer <- from;
                  t.idle_deadline <- Int64.add now t.cfg.max_idle_ns;
                  sp.largest_rx <- max sp.largest_rx pn;
                  let fresh = not (Ranges.contains sp.rx_pns pn) in
                  Ranges.insert sp.rx_pns ~lo:pn ~hi:pn;
                  if fresh then begin
                    let pbuf =
                      Bigstringaf.of_string plaintext ~off:0
                        ~len:(String.length plaintext)
                    in
                    match
                      Frame.parse_all pbuf ~off:0 ~len:(String.length plaintext)
                    with
                    | Error e ->
                        protocol_close t ~now ~code:0x07
                          ~reason:("frame encoding: " ^ e)
                    | Ok frames -> (
                        try
                          qlog_packet t ~now ~dir:`Rx ~ix:sp.ix ~pn
                            ~size:(located.Packet.last - located.Packet.off)
                            frames;
                          let ack_eliciting =
                            List.exists Frame.is_ack_eliciting frames
                          in
                          List.iter (handle_frame t sp ~now) frames;
                          if ack_eliciting then begin
                            sp.ae_rx_unacked <- sp.ae_rx_unacked + 1;
                            if sp.ix < 2 then sp.ack_now <- true
                            else if sp.ae_rx_unacked >= 2 || pn < sp.largest_rx
                            then sp.ack_now <- true
                            else if sp.ack_deadline = None then
                              sp.ack_deadline <-
                                Some (Int64.add now 25_000_000L)
                          end
                        with Proto_violation (code, reason) ->
                          protocol_close t ~now ~code ~reason)
                  end));
      (* replay stashed 1-RTT datagrams once the keys are in *)
      if
        (not t.replaying)
        && (sp_app t).rx_keys <> None
        && t.early_app_stash <> []
      then begin
        let stash = List.rev t.early_app_stash in
        t.early_app_stash <- [];
        t.replaying <- true;
        Fun.protect
          ~finally:(fun () -> t.replaying <- false)
          (fun () ->
            List.iter
              (fun (datagram, from) ->
                let b =
                  Bigstringaf.of_string datagram ~off:0
                    ~len:(String.length datagram)
                in
                recv t ~now b ~off:0 ~len:(String.length datagram) ~from)
              stash)
      end

(* ---- send path ---- *)

let dgram_overhead = 1 + 8 + 3 (* frame type + max varint + slack *)

let peer_udp_limit t =
  match t.peer_params with
  | Some p -> min t.cfg.max_udp_payload p.Tparams.max_udp_payload_size
  | None -> t.cfg.max_udp_payload

(* Build the frames for one packet in [sp]; returns [] when silent.
   [allow_ae] gates ack-eliciting content (congestion control): when
   false, only ACKs go out. *)
let build_frames t sp ~now ~budget ~allow_ae =
  let frames = ref [] and used = ref 0 and ack_eliciting = ref false in
  let retx = ref [] in
  let push ?(ae = true) ?r f =
    let sz = Frame.size f in
    if (ae && not allow_ae) || !used + sz > budget then false
    else begin
      frames := f :: !frames;
      used := !used + sz;
      if ae then ack_eliciting := true;
      (match r with Some d -> retx := d :: !retx | None -> ());
      true
    end
  in
  (* ACK first *)
  let want_ack =
    (not (Ranges.is_empty sp.rx_pns))
    && (sp.ack_now
       || (match sp.ack_deadline with
          | Some d -> d <= now
          | None -> false))
  in
  if want_ack then begin
    let ranges =
      let l = Ranges.to_list_desc sp.rx_pns in
      List.filteri (fun i _ -> i < 32) l
    in
    if
      push ~ae:false
        (Frame.Ack
           {
             largest = Option.get (Ranges.largest sp.rx_pns);
             delay = 0;
             ranges;
             ecn = None;
           })
    then begin
      sp.ack_now <- false;
      sp.ack_deadline <- None;
      sp.ae_rx_unacked <- 0
    end
  end;
  (* CRYPTO *)
  let rec crypto_loop () =
    if Crypto_stream.has_pending sp.crypto && budget - !used > 20 && allow_ae
    then
      match Crypto_stream.take sp.crypto ~max:(budget - !used - 12) with
      | Some (off, data) ->
          if
            push
              ~r:
                (Recovery.Rtx_crypto
                   { space = sp.ix; lo = off; hi = off + String.length data - 1 })
              (Frame.Crypto { off; data = Frame.payload_of_string data })
          then crypto_loop ()
          else Crypto_stream.requeue sp.crypto ~lo:off
                 ~hi:(off + String.length data - 1)
      | None -> ()
  in
  crypto_loop ();
  (* application-space control and data *)
  if sp.ix = 2 && t.state = Open && allow_ae then begin
    List.iter
      (fun data ->
        if push (Frame.Path_response data) then
          t.path_responses <- List.filter (fun d -> d <> data) t.path_responses)
      t.path_responses;
    if t.hs_done_pending then
      if push ~r:Recovery.Rtx_flags Frame.Handshake_done then
        t.hs_done_pending <- false;
    List.iter
      (fun seq ->
        if push (Frame.Retire_connection_id seq) then
          t.retire_queue <- List.filter (fun s -> s <> seq) t.retire_queue)
      t.retire_queue;
    if t.max_data_dirty then begin
      (* grow the window from consumption *)
      t.local_max_data <- t.consumed_data + t.cfg.initial_max_data;
      if push ~r:Recovery.Rtx_flags (Frame.Max_data t.local_max_data) then
        t.max_data_dirty <- false
    end;
    if t.max_streams_dirty then begin
      let ok1 =
        push ~r:Recovery.Rtx_flags (Frame.Max_streams_bidi t.local_max_bidi)
      in
      let ok2 =
        push ~r:Recovery.Rtx_flags (Frame.Max_streams_uni t.local_max_uni)
      in
      if ok1 && ok2 then t.max_streams_dirty <- false
    end;
    (match t.streams_blocked with
    | Some `Bidi ->
        if push (Frame.Streams_blocked_bidi t.peer_max_streams_bidi) then
          t.streams_blocked <- None
    | Some `Uni ->
        if push (Frame.Streams_blocked_uni t.peer_max_streams_uni) then
          t.streams_blocked <- None
    | None -> ());
    if t.data_blocked then
      if push (Frame.Data_blocked t.peer_max_data) then t.data_blocked <- false;
    (* per-stream: resets, credit updates, then data *)
    Hashtbl.iter
      (fun id (s : Stream.t) ->
        (match s.Stream.send with
        | Some snd when snd.Stream.reset_pending -> (
            match snd.Stream.reset with
            | Some (code, final_size) ->
                let frame =
                  match snd.Stream.reset_reliable with
                  | Some reliable_size ->
                      Frame.Reset_stream_at
                        { id; code; final_size; reliable_size }
                  | None -> Frame.Reset_stream { id; code; final_size }
                in
                if push ~r:Recovery.Rtx_flags frame then
                  snd.Stream.reset_pending <- false
            | None -> ())
        | _ -> ());
        (match s.Stream.recv with
        | Some rcv when rcv.Stream.stop_pending -> (
            match rcv.Stream.stop_sent with
            | Some code ->
                if push ~r:Recovery.Rtx_flags (Frame.Stop_sending { id; code })
                then rcv.Stream.stop_pending <- false
            | None -> ())
        | _ -> ());
        match s.Stream.recv with
        | Some rcv when rcv.Stream.stop_sent <> None && rcv.Stream.credit_dirty
          ->
            rcv.Stream.credit_dirty <- false
        | Some rcv when rcv.Stream.credit_dirty ->
            rcv.Stream.credit <-
              rcv.Stream.read_off + t.cfg.initial_max_stream_data;
            if
              push ~r:Recovery.Rtx_flags
                (Frame.Max_stream_data { id; max = rcv.Stream.credit })
            then rcv.Stream.credit_dirty <- false
        | _ -> ())
      t.streams;
    (* stream data, round-robin-ish via Hashtbl order *)
    let continue = ref true in
    while !continue do
      continue := false;
      Hashtbl.iter
        (fun id (s : Stream.t) ->
          match s.Stream.send with
          | Some snd when Stream.has_send_pending snd && budget - !used > 24 ->
              let max_bytes = budget - !used - 16 in
              (match Stream.send_take snd ~max:max_bytes with
              | Some (off, data, fin) ->
                  if
                    push
                      ~r:
                        (Recovery.Rtx_stream
                           {
                             id;
                             lo = off;
                             hi = off + String.length data - 1;
                             fin;
                           })
                      (Frame.Stream
                         { id; off; fin; data = Frame.payload_of_string data })
                  then continue := true
                  else begin
                    (* did not fit: put it back *)
                    Stream.send_on_lost snd ~lo:off
                      ~hi:(off + String.length data - 1)
                      ~fin
                  end
              | None -> ())
          | _ -> ())
        t.streams
    done;
    (* datagrams *)
    let rec dgrams () =
      match Queue.peek_opt t.dgram_tx with
      | Some d
        when Frame.size (Frame.Datagram { data = Frame.payload_of_string d })
             <= budget - !used ->
          ignore
            (push ~r:Recovery.Rtx_dgram
               (Frame.Datagram { data = Frame.payload_of_string d }));
          ignore (Queue.pop t.dgram_tx);
          dgrams ()
      | _ -> ()
    in
    dgrams ()
  end;
  (* probes: guarantee something ack-eliciting *)
  if sp.probe > 0 && not !ack_eliciting then
    (if push Frame.Ping then sp.probe <- sp.probe - 1)
  else if sp.probe > 0 && !ack_eliciting then sp.probe <- sp.probe - 1;
  (List.rev !frames, !used, !ack_eliciting, !retx)

let scratch = Bigstringaf.create 65536

let long_header_bytes t ~kind ~pn ~pn_len ~payload_len =
  let b = Buffer.create 64 in
  let kind_bits = match kind with `I -> 0 | `H -> 2 in
  Buffer.add_uint8 b (0xc0 lor (kind_bits lsl 4) lor (pn_len - 1));
  Buffer.add_uint8 b 0;
  Buffer.add_uint8 b 0;
  Buffer.add_uint8 b 0;
  Buffer.add_uint8 b 1;
  Buffer.add_uint8 b (String.length t.dcid);
  Buffer.add_string b t.dcid;
  Buffer.add_uint8 b (String.length t.scid);
  Buffer.add_string b t.scid;
  if kind = `I then Buffer.add_uint8 b 0;
  let length = pn_len + payload_len + 16 in
  Buffer.add_uint8 b (0x40 lor ((length lsr 8) land 0x3f));
  Buffer.add_uint8 b (length land 0xff);
  for i = pn_len - 1 downto 0 do
    Buffer.add_uint8 b ((pn lsr (8 * i)) land 0xff)
  done;
  Buffer.contents b

let short_header_bytes t ~pn ~pn_len =
  let b = Buffer.create 32 in
  let phase = if t.tx_phase then 0x04 else 0 in
  Buffer.add_uint8 b (0x40 lor phase lor (pn_len - 1));
  Buffer.add_string b t.dcid;
  for i = pn_len - 1 downto 0 do
    Buffer.add_uint8 b ((pn lsr (8 * i)) land 0xff)
  done;
  Buffer.contents b

(* Build at most one packet for [sp]; returns protected bytes. *)
let build_packet t sp ~now ~budget =
  match sp.tx_keys with
  | None -> None
  | Some keys ->
      (* congestion pre-check: ack-eliciting content only within cwnd
         (probes bypass, ACK-only always allowed) *)
      let allow_ae =
        sp.probe > 0 || Recovery.can_send t.recovery ~size:(min budget 1200)
      in
      let frames, payload_len, ack_eliciting, retx =
        build_frames t sp ~now ~budget ~allow_ae
      in
      if frames = [] then None
      else begin
        (match Sys.getenv_opt "WT_PURE_DEBUG" with
        | Some _ ->
            let name (f : Frame.t) =
              match f with
              | Frame.Padding _ -> "pad"
              | Frame.Ping -> "ping"
              | Frame.Ack _ -> "ack"
              | Frame.Crypto _ -> "crypto"
              | Frame.Stream { id; off; fin; data } ->
                  Printf.sprintf "stream(%d,%d,%d,%b)" id off data.Frame.len fin
              | Frame.Max_data v -> Printf.sprintf "max_data(%d)" v
              | Frame.Max_stream_data { id; max } ->
                  Printf.sprintf "msd(%d,%d)" id max
              | Frame.Datagram _ -> "dgram"
              | Frame.Handshake_done -> "hs_done"
              | Frame.Connection_close _ -> "close"
              | _ -> "other"
            in
            Printf.eprintf "[conn %s] sp%d pn%d: %s\n%!"
              (match t.cfg.role with `Client -> "C" | `Server -> "S")
              sp.ix sp.next_pn
              (String.concat " " (List.map name frames))
        | None -> ());
        begin
          let pn = sp.next_pn in
          sp.next_pn <- pn + 1;
          let pn_len = 2 in
          (* pad tiny payloads so header protection has its sample *)
          let payload_len = max payload_len (4 - pn_len + 3) in
          let woff = ref 0 in
          List.iter
            (fun f -> woff := !woff + Frame.encode scratch ~off:!woff f)
            frames;
          while !woff < payload_len do
            Bigstringaf.set scratch !woff '\x00';
            incr woff
          done;
          let payload = Bigstringaf.substring scratch ~off:0 ~len:!woff in
          let header =
            match sp.ix with
            | 0 -> long_header_bytes t ~kind:`I ~pn ~pn_len ~payload_len:!woff
            | 1 -> long_header_bytes t ~kind:`H ~pn ~pn_len ~payload_len:!woff
            | _ -> short_header_bytes t ~pn ~pn_len
          in
          let pkt = Packet.seal ~keys ~pn:(Int64.of_int pn) ~pn_len ~header payload in
          qlog_packet t ~now ~dir:`Tx ~ix:sp.ix ~pn ~size:(String.length pkt)
            frames;
          Recovery.on_sent t.recovery sp.rec_space
            {
              Recovery.pn;
              time_sent = now;
              size = String.length pkt;
              ack_eliciting;
              in_flight = ack_eliciting;
              retx;
            };
          (* client: sending at Handshake level retires Initial keys *)
          if sp.ix = 1 && t.cfg.role = `Client && (sp_initial t).tx_keys <> None
          then discard_initial t;
          Some pkt
        end
      end

let send t ~now buf =
  match t.state with
  | Dead -> `Done
  | Draining _ -> `Done
  | Closing _ when not t.close_tx_pending -> `Done
  | Closing _ -> (
      t.close_tx_pending <- false;
      match t.close_frame with
      | None -> `Done
      | Some (app, code, reason) ->
          (* send in the highest available space *)
          let sp =
            if (sp_app t).tx_keys <> None then sp_app t
            else if (sp_handshake t).tx_keys <> None then sp_handshake t
            else sp_initial t
          in
          (match sp.tx_keys with
          | None -> `Done
          | Some keys ->
              (* pre-handshake app closes become transport closes *)
              let app, code, reason =
                if app && sp.ix < 2 then (false, 0x0c, "") else (app, code, reason)
              in
              let f =
                Frame.Connection_close
                  {
                    app;
                    code;
                    frame_type = 0;
                    reason = Frame.payload_of_string reason;
                  }
              in
              let payload_len = max (Frame.size f) 5 in
              let pn = sp.next_pn in
              sp.next_pn <- pn + 1;
              let pn_len = 2 in
              let woff = Frame.encode scratch ~off:0 f in
              let woff = ref woff in
              while !woff < payload_len do
                Bigstringaf.set scratch !woff '\x00';
                incr woff
              done;
              let payload = Bigstringaf.substring scratch ~off:0 ~len:!woff in
              let header =
                match sp.ix with
                | 0 -> long_header_bytes t ~kind:`I ~pn ~pn_len ~payload_len:!woff
                | 1 -> long_header_bytes t ~kind:`H ~pn ~pn_len ~payload_len:!woff
                | _ -> short_header_bytes t ~pn ~pn_len
              in
              let pkt =
                Packet.seal ~keys ~pn:(Int64.of_int pn) ~pn_len ~header payload
              in
              let n = String.length pkt in
              Bigstringaf.blit_from_string pkt ~src_off:0 buf ~dst_off:0 ~len:n;
              `Packet (n, t.peer)))
  | Open ->
      (* fire due ack-delays implicitly *)
      let limit = min (peer_udp_limit t) (Bigstringaf.length buf) in
      let parts = ref [] and total = ref 0 and has_initial = ref false in
      Array.iter
        (fun sp ->
          if !total < limit - 60 then
            let budget = limit - !total - 60 in
            match build_packet t sp ~now ~budget with
            | Some pkt ->
                if sp.ix = 0 then has_initial := true;
                parts := pkt :: !parts;
                total := !total + String.length pkt
            | None -> ())
        t.spaces;
      (match !parts with
      | [] -> `Done
      | parts ->
          let d = String.concat "" (List.rev parts) in
          let d =
            if !has_initial && String.length d < 1200 then
              d ^ String.make (1200 - String.length d) '\x00'
            else d
          in
          let n = String.length d in
          (* anti-amplification *)
          if
            t.cfg.role = `Server && (not t.addr_validated)
            && t.bytes_sent + n > 3 * t.bytes_received
          then `Done
          else begin
            t.bytes_sent <- t.bytes_sent + n;
            Bigstringaf.blit_from_string d ~src_off:0 buf ~dst_off:0 ~len:n;
            `Packet (n, t.peer)
          end)

(* ---- timers ---- *)

let next_timeout_ns t ~now =
  match t.state with
  | Dead -> None
  | Closing deadline | Draining deadline ->
      Some (Int64.max 0L (Int64.sub deadline now))
  | Open ->
      let deadlines = ref [] in
      let add d = deadlines := d :: !deadlines in
      add t.idle_deadline;
      Array.iter
        (fun sp ->
          (match sp.ack_deadline with Some d -> add d | None -> ());
          if sp.ack_now && not (Ranges.is_empty sp.rx_pns) then add now;
          match Recovery.space_timer t.recovery sp.rec_space ~is_app:(sp.ix = 2) with
          | Some d -> add d
          | None -> ())
        t.spaces;
      (* client anti-deadlock before confirmation *)
      if
        t.cfg.role = `Client && not t.hs_confirmed
        && ((sp_handshake t).tx_keys <> None || (sp_initial t).tx_keys <> None)
      then
        add (Int64.add now (Recovery.pto_backed_off t.recovery ~is_app:false));
      (match !deadlines with
      | [] -> None
      | ds ->
          let d = List.fold_left Int64.min Int64.max_int ds in
          Some (Int64.max 0L (Int64.sub d now)))

let on_timeout t ~now =
  match t.state with
  | Dead -> ()
  | Closing deadline | Draining deadline ->
      if now >= deadline then t.state <- Dead
  | Open ->
      if now >= t.idle_deadline then begin
        if not t.closed_event_sent then begin
          t.closed_event_sent <- true;
          emit t (Closed { local = true; app = false; code = 0; reason = "idle timeout" })
        end;
        t.state <- Dead
      end
      else begin
        (* loss timers *)
        Array.iter
          (fun sp ->
            match Recovery.space_timer t.recovery sp.rec_space ~is_app:(sp.ix = 2) with
            | Some d when d <= now -> (
                match sp.rec_space.Recovery.loss_time with
                | Some _ ->
                    let lost = Recovery.on_loss_timer t.recovery sp.rec_space ~now in
                    requeue_lost t lost
                | None ->
                    (* PTO *)
                    Recovery.on_pto t.recovery;
                    sp.probe <- 2)
            | _ -> ())
          t.spaces;
        (* client anti-deadlock probe *)
        if t.cfg.role = `Client && not t.hs_confirmed then begin
          let sp =
            if (sp_handshake t).tx_keys <> None then sp_handshake t
            else sp_initial t
          in
          if
            not
              (List.exists
                 (fun (s : Recovery.sent) -> s.Recovery.ack_eliciting)
                 sp.rec_space.Recovery.sent)
          then sp.probe <- max sp.probe 1
        end
      end

(* ---- application API ---- *)

let open_stream t ~dir : int rw =
  if t.state <> Open then Error `Invalid
  else begin
    let uni = dir = `Uni in
    let opened = if uni then t.opened_uni else t.opened_bidi in
    let limit = if uni then t.peer_max_streams_uni else t.peer_max_streams_bidi in
    if opened >= limit then begin
      t.streams_blocked <- Some dir;
      Error `Would_block
    end
    else begin
      let id = if uni then t.next_uni else t.next_bidi in
      if uni then begin
        t.next_uni <- id + 4;
        t.opened_uni <- opened + 1
      end
      else begin
        t.next_bidi <- id + 4;
        t.opened_bidi <- opened + 1
      end;
      let s =
        Stream.create ~id
          ~send_credit:(peer_send_credit t ~id)
          ~recv_credit:t.cfg.initial_max_stream_data ~has_send:true
          ~has_recv:(not uni)
      in
      Hashtbl.replace t.streams id s;
      Ok id
    end
  end

let with_send t ~id f : 'a rw =
  match get_stream t id with
  | None -> Error `Invalid
  | Some s -> (
      match s.Stream.send with
      | None -> Error `Invalid
      | Some snd -> f s snd)

let stream_send t ~id buf ~off ~len ~fin : int rw =
  if t.state <> Open then Error `Invalid
  else
    with_send t ~id (fun _ snd ->
        match snd.Stream.reset with
        | Some (code, _) -> Error (`Stopped code)
        | None ->
            if snd.Stream.fin_queued then Error `Fin
            else begin
              let stream_room = Stream.send_capacity snd in
              let conn_room = max 0 (t.peer_max_data - t.queued_data) in
              let n = min len (min stream_room conn_room) in
              if n = 0 && len > 0 then begin
                snd.Stream.blocked <- true;
                if conn_room = 0 then t.data_blocked <- true;
                Error `Would_block
              end
              else begin
                Stream.send_queue snd (Bigstringaf.substring buf ~off ~len:n);
                t.queued_data <- t.queued_data + n;
                if fin && n = len then Stream.send_fin snd;
                Ok n
              end
            end)

let stream_recv t ~id buf ~off ~len : (int * bool) rw =
  match get_stream t id with
  | None -> Error `Invalid
  | Some s -> (
      match s.Stream.recv with
      | None -> Error `Invalid
      | Some rcv -> (
          match Stream.recv_read rcv buf ~off ~len with
          | Ok (n, fin) ->
              t.consumed_data <- t.consumed_data + n;
              (* replenish windows *)
              if
                t.consumed_data
                >= t.local_max_data - (t.cfg.initial_max_data / 2)
              then t.max_data_dirty <- true;
              if
                rcv.Stream.read_off
                >= rcv.Stream.credit - (t.cfg.initial_max_stream_data / 2)
              then rcv.Stream.credit_dirty <- true;
              if fin || Stream.recv_closed rcv then begin
                if stream_fully_closed s then note_peer_stream_closed t id
              end;
              Ok (n, fin)
          | Error `Fin ->
              if stream_fully_closed s then note_peer_stream_closed t id;
              Error `Fin
          | Error (`Reset c) ->
              if stream_fully_closed s then note_peer_stream_closed t id;
              Error (`Reset c)
          | Error `Would_block -> Error `Would_block
          | Error `Invalid -> Error `Invalid))

let stream_capacity t ~id : int rw =
  with_send t ~id (fun _ snd ->
      Ok (min (Stream.send_capacity snd) (max 0 (t.peer_max_data - t.queued_data))))

let stream_finish t ~id : unit rw =
  with_send t ~id (fun _ snd ->
      match snd.Stream.reset with
      | Some (code, _) -> Error (`Stopped code)
      | None ->
          Stream.send_fin snd;
          Ok ())

let stream_reset t ~id ~code : unit rw =
  with_send t ~id (fun _ snd ->
      Stream.send_reset snd ~code;
      Ok ())

let supports_reset_at t =
  match t.peer_params with
  | Some p -> p.Tparams.reliable_reset
  | None -> false

let stream_reset_at t ~id ~code ~reliable_size : unit rw =
  with_send t ~id (fun _ snd ->
      if supports_reset_at t && t.cfg.reliable_reset then
        Stream.send_reset ~reliable:reliable_size snd ~code
      else Stream.send_reset snd ~code;
      Ok ())

let stream_stop_sending t ~id ~code : unit rw =
  match get_stream t id with
  | None -> Error `Invalid
  | Some s -> (
      match s.Stream.recv with
      | None -> Error `Invalid
      | Some rcv ->
          if rcv.Stream.stop_sent = None then begin
            rcv.Stream.stop_sent <- Some code;
            rcv.Stream.stop_pending <- true
          end;
          Ok ())

let dgram_send t buf ~off ~len : unit rw =
  match t.peer_max_dgram with
  | None -> Error `Invalid
  | Some limit ->
      if len + dgram_overhead > min limit (peer_udp_limit t) then Error `Invalid
      else if Queue.length t.dgram_tx >= 1024 then Error `Would_block
      else begin
        Queue.add (Bigstringaf.substring buf ~off ~len) t.dgram_tx;
        Ok ()
      end

let dgram_recv t buf ~off : int rw =
  match Queue.take_opt t.dgram_rx with
  | None -> Error `Would_block
  | Some d ->
      let len = String.length d in
      if off + len > Bigstringaf.length buf then Error `Invalid
      else begin
        Bigstringaf.blit_from_string d ~src_off:0 buf ~dst_off:off ~len;
        Ok len
      end

let dgram_max_len t =
  match t.peer_max_dgram with
  | None -> None
  | Some limit -> Some (max 0 (min limit (peer_udp_limit t) - dgram_overhead))

let peer_cert_der t =
  match Tls.peer_certs t.tls with
  | leaf :: _ -> Some (X509.Certificate.encode_der leaf)
  | [] -> None

let app_close t ~now ~app ~code ~reason = close t ~now ~app ~code ~reason

module For_testing = struct
  let initiate_key_update t =
    let sp = sp_app t in
    match sp.tx_keys with
    | Some keys ->
        sp.tx_keys <- Some (Aead.next_generation keys);
        t.tx_phase <- not t.tx_phase
    | None -> ()
end
