(* The sans-io HTTP/3 + WebTransport engine.

   Owns the minimal HTTP/3 a WebTransport endpoint needs — control streams,
   SETTINGS, QPACK (static-only), extended CONNECT — plus WebTransport
   session state: capsules (inside DATA frames on the CONNECT stream, per
   RFC 9297's data-stream mapping), close/drain semantics, and dispatch of
   incoming 0x54/0x41 WebTransport data streams.

   The engine drives a Quic_backend.S connection directly (backend calls are
   non-blocking, pure state mutations — no sockets, clocks or fibers here).
   Drivers feed packets into the backend, call [process], dispatch the
   returned notifications to application fibers, and flush outgoing packets.
   Deterministic tests substitute a mock backend. *)

module Qb = Quic_backend

type backend_conn = C : (module Qb.S with type t = 'c) * 'c -> backend_conn
type dir = [ `Uni | `Bidi ]

type request = {
  authority : string;
  path : string;
  origin : string option;
  protocol : string;
  headers : (string * string) list;  (* non-pseudo request headers *)
}

type notification =
  | Incoming_session of { sid : int; req : request }  (* server: awaiting accept *)
  | Session_established of { sid : int }
  | Session_rejected of { sid : int; status : int }  (* client *)
  | Session_peer_closed of {
      sid : int;
      code : int;
      message : string;
      abrupt : bool;
    }
  | Session_peer_drain of { sid : int }
  | Wt_datagram of { sid : int; payload : string }
  | Wt_stream_opened of { sid : int; stream_id : int; dir : dir }
  | Wt_stream_readable of { stream_id : int }
  | Wt_stream_writable of { stream_id : int }
  | Goaway
  | Conn_closed of { code : int; reason : string; remote : bool }

type session_state = [ `Requested | `Connecting | `Open | `Closed ]

type session = {
  sid : int;
  mutable sstate : session_state;
  capsules : Capsule.parser;
  mutable req : request option;
  mutable draft02 : bool;  (* request carried sec-webtransport-http3-draft02 *)
  mutable data_streams : int list;  (* attached WT streams *)
  (* Session-level flow control (draft-12+). Active only when both sides
     advertised non-zero limits; browsers never do, so it stays off for
     them. Stream signal prefixes are excluded from the data accounting. *)
  mutable fc_on : bool;
  mutable send_max_data : int;  (* peer-granted absolute limit *)
  mutable sent_data : int;
  mutable send_max_bidi : int;
  mutable send_max_uni : int;
  mutable opened_bidi : int;
  mutable opened_uni : int;
  mutable recv_window : int;  (* our configured data window *)
  mutable recv_max_data : int;  (* absolute limit we granted *)
  mutable consumed_data : int;
  mutable recv_bidi_window : int;
  mutable recv_max_bidi : int;
  mutable accepted_bidi : int;
  mutable recv_uni_window : int;
  mutable recv_max_uni : int;
  mutable accepted_uni : int;
}

type frames_ctx = {
  fk_request : bool;  (* request/CONNECT stream (vs control stream) *)
  mutable cur :
    [ `Frame_header | `Headers of int | `Data of int | `Skip of int ];
  mutable got_headers : bool;
  headers_acc : Buffer.t;
}

type rstate =
  | Peek_uni
  | Peek_bidi
  | Wt_session_id of dir
  | Control_start
  | Frames of frames_ctx
  | Drain
  | Parked of { claimed_sid : int; dir : dir; since : int64 }
    (* WT stream whose session isn't established: left unread so QUIC flow
       control holds the peer; bounded, expired, attached on establishment *)
  | Attached of int  (* WT data stream attached to session [sid] *)
  | Dead

type rstream = {
  rid : int;
  rbuf : Bytebuf.t;
  mutable rstate : rstate;
  mutable rfin : bool;
}

type wstream = {
  wid : int;
  wout : Bytebuf.t;
  mutable wfin : bool;  (* fin requested after wout drains *)
  mutable wfin_sent : bool;
  mutable wsid : int option;  (* owning WT session, for data accounting *)
}

type role = [ `Client | `Server ]

type t = {
  bc : backend_conn;
  role : role;
  wt_max_sessions : int;
  fc : int * int * int;  (* advertised WT flow control (data, uni, bidi); 0 = off *)
  parked_cap : int;
  parked_timeout_ns : int64;
  notif : notification Queue.t;
  rstreams : (int, rstream) Hashtbl.t;
  wstreams : (int, wstream) Hashtbl.t;
  sessions : (int, session) Hashtbl.t;
  closed_ring : int array;  (* recently closed session ids, -1 = empty *)
  mutable closed_ring_pos : int;
  mutable parked_count : int;
  scratch : Bigstringaf.t;
  mutable started : bool;  (* control stream opened, SETTINGS sent *)
  mutable peer_settings : Settings.t option;
  mutable control_out : int option;
  mutable control_in : int option;
  mutable pending_connect :
    (string * string * string option * (string * string) list) option;
  mutable conn_dead : bool;
  mutable now : int64;  (* last timestamp given to [process] *)
}

let create ?(wt_max_sessions = 1024) ?(fc = (0, 0, 0)) ?(parked_cap = 64)
    ?(parked_timeout_ns = 5_000_000_000L) ~role bc =
  {
    bc;
    role;
    wt_max_sessions;
    fc;
    parked_cap;
    parked_timeout_ns;
    notif = Queue.create ();
    rstreams = Hashtbl.create 16;
    wstreams = Hashtbl.create 16;
    sessions = Hashtbl.create 4;
    closed_ring = Array.make 16 (-1);
    closed_ring_pos = 0;
    parked_count = 0;
    scratch = Bigstringaf.create 65_536;
    started = false;
    peer_settings = None;
    control_out = None;
    control_in = None;
    pending_connect = None;
    conn_dead = false;
    now = 0L;
  }

let notify t n = Queue.add n t.notif

let debug =
  match Sys.getenv_opt "WT_DEBUG" with
  | Some ("1" | "true") -> fun s -> prerr_endline ("[wt] " ^ Lazy.force s)
  | _ -> fun _ -> ()

(* ---- outgoing stream writes (buffered against flow control) ---- *)

let wstream t id =
  match Hashtbl.find_opt t.wstreams id with
  | Some w -> w
  | None ->
      let wsid =
        match Hashtbl.find_opt t.rstreams id with
        | Some { rstate = Attached sid; _ } -> Some sid
        | _ -> None
      in
      let w =
        {
          wid = id;
          wout = Bytebuf.create ();
          wfin = false;
          wfin_sent = false;
          wsid;
        }
      in
      Hashtbl.add t.wstreams id w;
      w

let try_flush_wstream t w =
  let (C ((module B), h)) = t.bc in
  let fc_session () =
    match w.wsid with
    | None -> None
    | Some sid -> (
        match Hashtbl.find_opt t.sessions sid with
        | Some s when s.fc_on -> Some s
        | _ -> None)
  in
  let rec go () =
    let n = Bytebuf.length w.wout in
    if n > 0 then begin
      let allowance =
        match fc_session () with
        | Some s -> max 0 (s.send_max_data - s.sent_data)
        | None -> max_int
      in
      let chunk = min (min n (Bigstringaf.length t.scratch)) allowance in
      if chunk > 0 then begin
        let data, pos = Bytebuf.view w.wout in
        Bigstringaf.blit_from_string data ~src_off:pos t.scratch ~dst_off:0
          ~len:chunk;
        let fin = w.wfin && chunk = n in
        match B.stream_send h ~id:w.wid t.scratch ~off:0 ~len:chunk ~fin with
        | Ok written ->
            Bytebuf.advance w.wout written;
            (match fc_session () with
            | Some s -> s.sent_data <- s.sent_data + written
            | None -> ());
            if written = chunk && fin then w.wfin_sent <- true;
            if written > 0 then go ()
        | Error `Would_block -> ()
        | Error _ -> w.wfin_sent <- true (* stream gone; drop buffered bytes *)
      end
    end
    else if w.wfin && not w.wfin_sent then
      match B.stream_finish h ~id:w.wid with
      | Ok () | Error _ -> w.wfin_sent <- true
  in
  go ()

(* Retry buffered writers of a session after its send window grew. *)
let flush_session_wstreams t sid =
  Hashtbl.iter
    (fun _ w -> if w.wsid = Some sid then try_flush_wstream t w)
    t.wstreams

let write t ~id ?(fin = false) s =
  let w = wstream t id in
  Bytebuf.add w.wout s;
  if fin then w.wfin <- true;
  try_flush_wstream t w

(* ---- frame/stream helpers ---- *)

let frame_header ty len =
  let b = Buffer.create 8 in
  Varint.add_buffer b ty;
  Varint.add_buffer b len;
  Buffer.contents b

let send_headers t ~id ?(fin = false) fields =
  let payload = Wt_qpack.Field_section.encode fields in
  write t ~id (frame_header Wire.Frame.headers (String.length payload) ^ payload)
    ~fin

let send_capsule t ~id ?(fin = false) capsule =
  write t ~id (frame_header Wire.Frame.data (String.length capsule) ^ capsule)
    ~fin

let mk_frames ~request =
  Frames
    {
      fk_request = request;
      cur = `Frame_header;
      got_headers = false;
      headers_acc = Buffer.create 256;
    }

let reset_stream t ~id ~h3_code =
  let (C ((module B), h)) = t.bc in
  ignore (B.stream_reset h ~id ~code:h3_code);
  ignore (B.stream_stop_sending h ~id ~code:h3_code)

(* ---- session lifecycle ---- *)

let session t sid = Hashtbl.find_opt t.sessions sid

let mk_session t sid state =
  let s =
    {
      sid;
      sstate = state;
      capsules = Capsule.create_parser ();
      req = None;
      draft02 = false;
      data_streams = [];
      fc_on = false;
      send_max_data = 0;
      sent_data = 0;
      send_max_bidi = 0;
      send_max_uni = 0;
      opened_bidi = 0;
      opened_uni = 0;
      recv_window = 0;
      recv_max_data = 0;
      consumed_data = 0;
      recv_bidi_window = 0;
      recv_max_bidi = 0;
      accepted_bidi = 0;
      recv_uni_window = 0;
      recv_max_uni = 0;
      accepted_uni = 0;
    }
  in
  Hashtbl.add t.sessions sid s;
  s

let fc_configured t =
  let d, u, b = t.fc in
  d > 0 || u > 0 || b > 0

let peer_fc_advertised t =
  match t.peer_settings with
  | Some ps ->
      ps.Settings.wt_initial_max_data > 0
      || ps.Settings.wt_initial_max_streams_uni > 0
      || ps.Settings.wt_initial_max_streams_bidi > 0
  | None -> false

(* Activate session flow control iff both sides advertised limits. *)
let setup_fc t s =
  if fc_configured t && peer_fc_advertised t then begin
    let d, u, b = t.fc in
    let ps = Option.get t.peer_settings in
    s.fc_on <- true;
    s.send_max_data <- ps.Settings.wt_initial_max_data;
    s.send_max_uni <- ps.Settings.wt_initial_max_streams_uni;
    s.send_max_bidi <- ps.Settings.wt_initial_max_streams_bidi;
    s.recv_window <- d;
    s.recv_max_data <- d;
    s.recv_uni_window <- u;
    s.recv_max_uni <- u;
    s.recv_bidi_window <- b;
    s.recv_max_bidi <- b
  end

let recently_closed t sid = Array.exists (fun x -> x = sid) t.closed_ring

let end_session t s ~notification =
  if s.sstate <> `Closed then begin
    s.sstate <- `Closed;
    t.closed_ring.(t.closed_ring_pos) <- s.sid;
    t.closed_ring_pos <- (t.closed_ring_pos + 1) mod Array.length t.closed_ring;
    (match notification with Some n -> notify t n | None -> ());
    (* Tear down associated WT data streams. *)
    List.iter
      (fun id -> reset_stream t ~id ~h3_code:Wt_error.wt_session_gone)
      s.data_streams;
    s.data_streams <- []
  end

let handle_capsule t s (ty, payload) =
  if ty = Wire.Capsule_type.wt_close_session then
    match Capsule.decode_close payload with
    | Ok (code, message) ->
        end_session t s
          ~notification:
            (Some (Session_peer_closed { sid = s.sid; code; message; abrupt = false }))
    | Error _ ->
        end_session t s
          ~notification:
            (Some
               (Session_peer_closed
                  { sid = s.sid; code = 0; message = ""; abrupt = true }))
  else if ty = Wire.Capsule_type.wt_drain_session then
    notify t (Session_peer_drain { sid = s.sid })
  else if ty = Wire.Capsule_type.wt_max_data then (
    match Capsule.decode_varint_capsule payload with
    | Ok v when v > s.send_max_data ->
        s.send_max_data <- v;
        flush_session_wstreams t s.sid
    | _ -> ())
  else if ty = Wire.Capsule_type.wt_max_streams_bidi then (
    match Capsule.decode_varint_capsule payload with
    | Ok v when v > s.send_max_bidi -> s.send_max_bidi <- v
    | _ -> ())
  else if ty = Wire.Capsule_type.wt_max_streams_uni then (
    match Capsule.decode_varint_capsule payload with
    | Ok v when v > s.send_max_uni -> s.send_max_uni <- v
    | _ -> ())
  else () (* unknown capsule types are ignored *)

(* Attach a WT data stream to its session, updating stream-count flow
   control and granting more credit when half the window is consumed. *)
let attach_stream t s (r : rstream) dir =
  s.data_streams <- r.rid :: s.data_streams;
  r.rstate <- Attached s.sid;
  (match Hashtbl.find_opt t.wstreams r.rid with
  | Some w -> w.wsid <- Some s.sid
  | None -> ());
  if s.fc_on then begin
    match dir with
    | `Bidi ->
        s.accepted_bidi <- s.accepted_bidi + 1;
        if s.recv_max_bidi - s.accepted_bidi < s.recv_bidi_window / 2 then begin
          s.recv_max_bidi <- s.accepted_bidi + s.recv_bidi_window;
          send_capsule t ~id:s.sid
            (Capsule.encode_max_streams ~dir:`Bidi s.recv_max_bidi)
        end
    | `Uni ->
        s.accepted_uni <- s.accepted_uni + 1;
        if s.recv_max_uni - s.accepted_uni < s.recv_uni_window / 2 then begin
          s.recv_max_uni <- s.accepted_uni + s.recv_uni_window;
          send_capsule t ~id:s.sid
            (Capsule.encode_max_streams ~dir:`Uni s.recv_max_uni)
        end
  end;
  notify t (Wt_stream_opened { sid = s.sid; stream_id = r.rid; dir });
  if Bytebuf.length r.rbuf > 0 || r.rfin then
    notify t (Wt_stream_readable { stream_id = r.rid })

(* Attach any parked streams claiming this (now established) session. *)
let attach_parked t s =
  Hashtbl.iter
    (fun _ r ->
      match r.rstate with
      | Parked { claimed_sid; dir; _ } when claimed_sid = s.sid ->
          t.parked_count <- t.parked_count - 1;
          attach_stream t s r dir
      | _ -> ())
    t.rstreams

let expire_parked t =
  if Int64.compare t.now 0L > 0 then
    Hashtbl.iter
      (fun _ r ->
        match r.rstate with
        | Parked { since; _ }
          when Int64.compare (Int64.sub t.now since) t.parked_timeout_ns > 0 ->
            t.parked_count <- t.parked_count - 1;
            reset_stream t ~id:r.rid
              ~h3_code:Wt_error.wt_buffered_stream_rejected;
            r.rstate <- Dead
        | _ -> ())
      t.rstreams

let drain_session_capsules t s =
  let rec go () =
    match Capsule.next s.capsules with
    | `Capsule c ->
        handle_capsule t s c;
        go ()
    | `Need_more -> ()
    | `Error _ ->
        end_session t s
          ~notification:
            (Some
               (Session_peer_closed
                  { sid = s.sid; code = 0; message = ""; abrupt = true }))
  in
  go ()

(* ---- request / response handling ---- *)

let split_headers fields =
  let pseudo = Hashtbl.create 8 in
  let regular = ref [] in
  List.iter
    (fun (n, v) ->
      if String.length n > 0 && n.[0] = ':' then
        (if not (Hashtbl.mem pseudo n) then Hashtbl.add pseudo n v)
      else regular := (n, v) :: !regular)
    fields;
  (pseudo, List.rev !regular)

let handle_request t (r : rstream) fields =
  let pseudo, regular = split_headers fields in
  let get n = Hashtbl.find_opt pseudo n in
  match (get ":method", get ":protocol") with
  | Some "CONNECT", Some protocol
    when protocol = Wire.protocol_token
         || protocol = Wire.protocol_token_legacy -> (
      match (get ":authority", get ":path") with
      | Some authority, Some path
        when (not (fc_configured t && peer_fc_advertised t))
             && Hashtbl.fold
                  (fun _ s acc ->
                    acc || s.sstate = `Open || s.sstate = `Requested)
                  t.sessions false ->
          (* Without negotiated session flow control, only one concurrent
             session per connection (draft-16 section 5.6.1 semantics). *)
          ignore (authority, path);
          reset_stream t ~id:r.rid ~h3_code:Wt_error.h3_request_rejected;
          r.rstate <- Dead
      | Some authority, Some path ->
          let s = mk_session t r.rid `Requested in
          let origin = List.assoc_opt "origin" regular in
          s.draft02 <-
            List.mem_assoc "sec-webtransport-http3-draft02" regular;
          let req = { authority; path; origin; protocol; headers = regular } in
          s.req <- Some req;
          debug (lazy (Printf.sprintf "incoming CONNECT sid=%d %s" r.rid path));
          notify t (Incoming_session { sid = r.rid; req })
      | _ ->
          send_headers t ~id:r.rid [ (":status", "400") ] ~fin:true)
  | Some "CONNECT", Some _ ->
      send_headers t ~id:r.rid [ (":status", "501") ] ~fin:true
  | _ ->
      (* Not a WebTransport request: minimal static answer. *)
      send_headers t ~id:r.rid [ (":status", "404") ] ~fin:true

let handle_response t (r : rstream) fields =
  match session t r.rid with
  | Some s when s.sstate = `Connecting -> (
      let pseudo, _ = split_headers fields in
      match Hashtbl.find_opt pseudo ":status" with
      | Some st
        when String.length st > 0 && st.[0] = '2' ->
          s.sstate <- `Open;
          setup_fc t s;
          debug (lazy (Printf.sprintf "session %d established" r.rid));
          notify t (Session_established { sid = r.rid });
          attach_parked t s
      | Some st ->
          let status = try int_of_string st with _ -> 0 in
          s.sstate <- `Closed;
          notify t (Session_rejected { sid = r.rid; status })
      | None ->
          s.sstate <- `Closed;
          notify t (Session_rejected { sid = r.rid; status = 0 }))
  | _ -> ()

(* ---- stream byte parsing ---- *)

let rec parse_stream t (r : rstream) =
  match r.rstate with
  | Dead | Parked _ -> ()
  | Attached _ -> ()
  | Drain ->
      ignore (Bytebuf.take_all r.rbuf)
  | Peek_uni -> (
      match Bytebuf.get_varint r.rbuf with
      | None -> ()
      | Some ty ->
          if ty = Wire.Uni_stream.control then
            if t.control_in <> None then begin
              (* duplicate critical stream *)
              r.rstate <- Drain;
              parse_stream t r
            end
            else begin
              t.control_in <- Some r.rid;
              r.rstate <- Control_start;
              parse_stream t r
            end
          else if
            ty = Wire.Uni_stream.qpack_encoder
            || ty = Wire.Uni_stream.qpack_decoder
          then begin
            r.rstate <- Drain;
            parse_stream t r
          end
          else if ty = Wire.Uni_stream.wt then begin
            r.rstate <- Wt_session_id `Uni;
            parse_stream t r
          end
          else begin
            reset_stream t ~id:r.rid ~h3_code:Wt_error.h3_stream_creation_error;
            r.rstate <- Dead
          end)
  | Peek_bidi -> (
      let data, pos = Bytebuf.view r.rbuf in
      match Varint.get_string data ~pos with
      | None -> ()
      | Some (v, pos') ->
          if v = Wire.Frame.wt_stream then begin
            Bytebuf.advance r.rbuf (pos' - pos);
            r.rstate <- Wt_session_id `Bidi;
            parse_stream t r
          end
          else if t.role = `Server then begin
            r.rstate <- mk_frames ~request:true;
            parse_stream t r
          end
          else begin
            (* Servers must not open non-WT bidi streams towards us. *)
            reset_stream t ~id:r.rid ~h3_code:Wt_error.h3_stream_creation_error;
            r.rstate <- Dead
          end)
  | Wt_session_id dir -> (
      match Bytebuf.get_varint r.rbuf with
      | None -> ()
      | Some sid ->
          if recently_closed t sid then begin
            reset_stream t ~id:r.rid
              ~h3_code:Wt_error.wt_buffered_stream_rejected;
            r.rstate <- Dead
          end
          else (
            match session t sid with
            | Some s when s.sstate = `Open -> attach_stream t s r dir
            | Some _ | None ->
                (* Session not (yet) established: park unread — QUIC flow
                   control bounds the peer; a cap and timeout bound us. *)
                if t.parked_count >= t.parked_cap then begin
                  reset_stream t ~id:r.rid
                    ~h3_code:Wt_error.wt_buffered_stream_rejected;
                  r.rstate <- Dead
                end
                else begin
                  t.parked_count <- t.parked_count + 1;
                  r.rstate <- Parked { claimed_sid = sid; dir; since = t.now }
                end))
  | Control_start -> (
      let data, pos = Bytebuf.view r.rbuf in
      match Varint.get_string data ~pos with
      | None -> ()
      | Some (ty, pos1) ->
          if ty <> Wire.Frame.settings then begin
            (* First control frame MUST be SETTINGS. *)
            debug (lazy "control stream did not start with SETTINGS");
            r.rstate <- Drain;
            parse_stream t r
          end
          else (
            match Varint.get_string data ~pos:pos1 with
            | None -> ()
            | Some (len, pos2) ->
                if String.length data - pos2 < len then ()
                else begin
                  Bytebuf.advance r.rbuf (pos2 - pos);
                  let payload = Bytebuf.take r.rbuf len in
                  (match Settings.decode payload with
                  | Ok s ->
                      t.peer_settings <- Some s;
                      debug (lazy "peer SETTINGS received");
                      maybe_send_pending_connect t
                  | Error e ->
                      debug (lazy ("bad SETTINGS: " ^ e));
                      let (C ((module B), h)) = t.bc in
                      B.close h ~app:false ~code:Wt_error.h3_settings_error
                        ~reason:"malformed SETTINGS");
                  r.rstate <- mk_frames ~request:false;
                  parse_stream t r
                end))
  | Frames fc -> (
      match fc.cur with
      | `Frame_header -> (
          let data, pos = Bytebuf.view r.rbuf in
          match Varint.get_string data ~pos with
          | None -> check_fin t r
          | Some (ty, pos1) -> (
              match Varint.get_string data ~pos:pos1 with
              | None -> check_fin t r
              | Some (len, pos2) ->
                  Bytebuf.advance r.rbuf (pos2 - pos);
                  if ty = Wire.Frame.headers then
                    if len > 65_536 then begin
                      reset_stream t ~id:r.rid
                        ~h3_code:Wt_error.h3_general_protocol_error;
                      r.rstate <- Dead
                    end
                    else begin
                      fc.cur <- `Headers len;
                      parse_stream t r
                    end
                  else if ty = Wire.Frame.data then begin
                    fc.cur <- `Data len;
                    parse_stream t r
                  end
                  else if ty = Wire.Frame.goaway then begin
                    notify t Goaway;
                    fc.cur <- `Skip len;
                    parse_stream t r
                  end
                  else begin
                    fc.cur <- `Skip len;
                    parse_stream t r
                  end))
      | `Headers remaining ->
          let avail = Bytebuf.length r.rbuf in
          let take = min avail remaining in
          Buffer.add_string fc.headers_acc (Bytebuf.take r.rbuf take);
          if take = remaining then begin
            let payload = Buffer.contents fc.headers_acc in
            Buffer.clear fc.headers_acc;
            fc.cur <- `Frame_header;
            (match Wt_qpack.Field_section.decode payload with
            | Error e ->
                debug (lazy ("qpack decode failed: " ^ e));
                let (C ((module B), h)) = t.bc in
                B.close h ~app:false ~code:Wt_error.qpack_decompression_failed
                  ~reason:"qpack"
            | Ok fields ->
                if not fc.got_headers then begin
                  fc.got_headers <- true;
                  if fc.fk_request then
                    if t.role = `Server then handle_request t r fields
                    else handle_response t r fields
                end
                (* trailers: ignored *));
            parse_stream t r
          end
          else fc.cur <- `Headers (remaining - take)
      | `Data remaining ->
          if not (fc.fk_request && fc.got_headers) then begin
            reset_stream t ~id:r.rid ~h3_code:Wt_error.h3_frame_error;
            r.rstate <- Dead
          end
          else begin
            let avail = Bytebuf.length r.rbuf in
            let take = min avail remaining in
            (if take > 0 then
               let chunk = Bytebuf.take r.rbuf take in
               match session t r.rid with
               | Some s ->
                   Capsule.feed s.capsules chunk;
                   drain_session_capsules t s
               | None -> ());
            if take = remaining then begin
              fc.cur <- `Frame_header;
              parse_stream t r
            end
            else begin
              fc.cur <- `Data (remaining - take);
              check_fin t r
            end
          end
      | `Skip remaining ->
          let avail = Bytebuf.length r.rbuf in
          let take = min avail remaining in
          if take > 0 then ignore (Bytebuf.take r.rbuf take);
          if take = remaining then begin
            fc.cur <- `Frame_header;
            parse_stream t r
          end
          else fc.cur <- `Skip (remaining - take))

and check_fin t (r : rstream) =
  (* Called when parsing stalls: handle a clean peer FIN on a CONNECT
     stream (session end, code 0 when no CLOSE capsule arrived). *)
  if r.rfin && Bytebuf.length r.rbuf = 0 then begin
    (match r.rstate with
    | Frames fc when fc.fk_request -> (
        match session t r.rid with
        | Some s when s.sstate = `Open || s.sstate = `Connecting ->
            end_session t s
              ~notification:
                (Some
                   (Session_peer_closed
                      { sid = r.rid; code = 0; message = ""; abrupt = false }))
        | _ -> ())
    | _ -> ());
    r.rstate <- Dead
  end

and maybe_send_pending_connect t =
  match (t.pending_connect, t.peer_settings) with
  | Some (authority, path, origin, extra), Some ps ->
      if not (Settings.server_supports_webtransport ps) then begin
        t.pending_connect <- None;
        notify t (Session_rejected { sid = -1; status = 0 })
      end
      else begin
        t.pending_connect <- None;
        let (C ((module B), h)) = t.bc in
        match B.open_stream h ~dir:`Bidi with
        | Error _ -> notify t (Session_rejected { sid = -1; status = 0 })
        | Ok sid ->
            let token = Settings.protocol_token_for ps in
            let s = mk_session t sid `Connecting in
            s.req <-
              Some
                { authority; path; origin; protocol = token; headers = extra };
            let fields =
              [
                (":method", "CONNECT");
                (":protocol", token);
                (":scheme", "https");
                (":authority", authority);
                (":path", path);
              ]
              @ (match origin with Some o -> [ ("origin", o) ] | None -> [])
              @ (if token = Wire.protocol_token_legacy then
                   [ ("sec-webtransport-http3-draft02", "1") ]
                 else [])
              @ extra
            in
            (* Register the CONNECT stream for response parsing. *)
            let r =
              {
                rid = sid;
                rbuf = Bytebuf.create ();
                rstate = mk_frames ~request:true;
                rfin = false;
              }
            in
            Hashtbl.replace t.rstreams sid r;
            debug (lazy (Printf.sprintf "sent CONNECT sid=%d %s" sid path));
            send_headers t ~id:sid fields
      end
  | _ -> ()

(* ---- start / backend event pump ---- *)

let start t =
  if not t.started then begin
    t.started <- true;
    let (C ((module B), h)) = t.bc in
    match B.open_stream h ~dir:`Uni with
    | Error _ -> debug (lazy "cannot open control stream yet")
    | Ok id ->
        t.control_out <- Some id;
        let entries =
          match t.role with
          | `Server ->
              Settings.for_server ~wt_max_sessions:t.wt_max_sessions ~fc:t.fc ()
          | `Client -> Settings.for_client ~fc:t.fc ()
        in
        let payload = Settings.encode entries in
        let b = Buffer.create 64 in
        Varint.add_buffer b Wire.Uni_stream.control;
        Buffer.add_string b
          (frame_header Wire.Frame.settings (String.length payload));
        Buffer.add_string b payload;
        write t ~id (Buffer.contents b);
        debug (lazy "control stream opened, SETTINGS sent")
  end

let pull_stream_bytes t (r : rstream) =
  let (C ((module B), h)) = t.bc in
  let rec go () =
    match
      B.stream_recv h ~id:r.rid t.scratch ~off:0
        ~len:(Bigstringaf.length t.scratch)
    with
    | Ok (n, fin) ->
        if n > 0 then
          Bytebuf.add r.rbuf (Bigstringaf.substring t.scratch ~off:0 ~len:n);
        if fin then r.rfin <- true else go ()
    | Error `Fin -> r.rfin <- true
    | Error `Would_block -> ()
    | Error (`Reset _) | Error (`Stopped _) | Error `Invalid -> (
        (* Peer reset: a CONNECT stream reset kills its session. *)
        match session t r.rid with
        | Some s when s.sstate <> `Closed ->
            end_session t s
              ~notification:
                (Some
                   (Session_peer_closed
                      { sid = r.rid; code = 0; message = ""; abrupt = true }));
            r.rstate <- Dead
        | _ -> r.rstate <- Dead)
  in
  go ()

let on_readable t id =
  match Hashtbl.find_opt t.rstreams id with
  | None -> ()
  | Some r -> (
      match r.rstate with
      | Parked _ -> () (* park-don't-read: QUIC flow control holds the peer *)
      | Attached _ -> notify t (Wt_stream_readable { stream_id = id })
      | Dead -> ()
      | _ ->
          pull_stream_bytes t r;
          parse_stream t r;
          if r.rfin then check_fin t r)

let drain_datagrams t =
  let (C ((module B), h)) = t.bc in
  let rec go () =
    match B.dgram_recv h t.scratch ~off:0 with
    | Ok n ->
        (match Varint.get_string (Bigstringaf.substring t.scratch ~off:0 ~len:n) ~pos:0 with
        | Some (qsid, pos) -> (
            let sid = qsid * 4 in
            match session t sid with
            | Some s when s.sstate = `Open ->
                let payload =
                  Bigstringaf.substring t.scratch ~off:pos ~len:(n - pos)
                in
                notify t (Wt_datagram { sid; payload })
            | _ -> () (* unknown session: dropped *))
        | None -> ());
        go ()
    | Error _ -> ()
  in
  go ()

let process t ~now =
  t.now <- now;
  expire_parked t;
  let (C ((module B), h)) = t.bc in
  let rec drain_events () =
    match B.next_event h with
    | None -> ()
    | Some e ->
        (match e with
        | B.Handshake_done _ ->
            debug (lazy "handshake done");
            start t
        | B.Stream_opened { id; dir } ->
            debug
              (lazy
                (Printf.sprintf "peer opened stream %d (%s)" id
                   (match dir with `Uni -> "uni" | `Bidi -> "bidi")));
            let st = match dir with `Uni -> Peek_uni | `Bidi -> Peek_bidi in
            if not (Hashtbl.mem t.rstreams id) then
              Hashtbl.add t.rstreams id
                { rid = id; rbuf = Bytebuf.create (); rstate = st; rfin = false }
        | B.Stream_readable id -> on_readable t id
        | B.Stream_writable id -> (
            (match Hashtbl.find_opt t.wstreams id with
            | Some w -> try_flush_wstream t w
            | None -> ());
            match Hashtbl.find_opt t.rstreams id with
            | Some { rstate = Attached _; _ } ->
                notify t (Wt_stream_writable { stream_id = id })
            | _ -> ())
        | B.Stream_credit -> if not t.started then start t
        | B.Stream_reset { id; _ } | B.Stream_stopped { id; _ } -> (
            match session t id with
            | Some s when s.sstate <> `Closed ->
                end_session t s
                  ~notification:
                    (Some
                       (Session_peer_closed
                          { sid = id; code = 0; message = ""; abrupt = true }))
            | _ -> ())
        | B.Datagram_readable -> drain_datagrams t
        | B.Closed { code; reason; local; _ } ->
            if not t.conn_dead then begin
              t.conn_dead <- true;
              notify t (Conn_closed { code; reason; remote = not local })
            end);
        drain_events ()
  in
  (* If the handshake was already complete before this engine attached (or
     events were consumed elsewhere), start anyway. *)
  if (not t.started) && B.is_established h then start t;
  drain_events ();
  let out = List.of_seq (Queue.to_seq t.notif) in
  Queue.clear t.notif;
  out

(* ---- application commands ---- *)

let accept_session t ~sid =
  match session t sid with
  | Some s when s.sstate = `Requested ->
      s.sstate <- `Open;
      setup_fc t s;
      let extra =
        if s.draft02 then [ ("sec-webtransport-http3-draft", "draft02") ]
        else []
      in
      send_headers t ~id:sid ((":status", "200") :: extra);
      notify t (Session_established { sid });
      attach_parked t s
  | _ -> invalid_arg "accept_session: not a pending session"

let reject_session t ~sid ~status =
  match session t sid with
  | Some s when s.sstate = `Requested ->
      s.sstate <- `Closed;
      send_headers t ~id:sid [ (":status", string_of_int status) ] ~fin:true
  | _ -> invalid_arg "reject_session: not a pending session"

let connect_session t ?origin ?(headers = []) ~authority ~path () =
  if t.role <> `Client then invalid_arg "connect_session: not a client";
  if t.pending_connect <> None then
    invalid_arg "connect_session: request already pending";
  t.pending_connect <- Some (authority, path, origin, headers);
  maybe_send_pending_connect t

let close_session t ~sid ~code ~message =
  match session t sid with
  | Some s when s.sstate = `Open || s.sstate = `Requested ->
      send_capsule t ~id:sid (Capsule.encode_close ~code ~message) ~fin:true;
      end_session t s ~notification:None
  | _ -> ()

let drain_session t ~sid =
  match session t sid with
  | Some s when s.sstate = `Open ->
      send_capsule t ~id:sid (Capsule.encode_drain ())
  | _ -> ()

(* Opens a WebTransport data stream on a session and writes its signal
   prefix (0x54/0x41 varint + session id). All application writes to WT
   streams must go through [write]/[write_fin] so they order behind the
   (possibly buffered) prefix. *)
let open_wt_stream t ~sid ~dir =
  match session t sid with
  | Some s when s.sstate = `Open -> (
      let credit_ok =
        (not s.fc_on)
        ||
        match dir with
        | `Bidi -> s.opened_bidi < s.send_max_bidi
        | `Uni -> s.opened_uni < s.send_max_uni
      in
      if not credit_ok then Error `Would_block
      else
        let (C ((module B), h)) = t.bc in
        match B.open_stream h ~dir with
        | Ok id ->
            if s.fc_on then (
              match dir with
              | `Bidi -> s.opened_bidi <- s.opened_bidi + 1
              | `Uni -> s.opened_uni <- s.opened_uni + 1);
            s.data_streams <- id :: s.data_streams;
            (* Write the signal prefix before the stream is marked as
               session-owned: prefixes are excluded from data flow control. *)
            let b = Buffer.create 8 in
            Varint.add_buffer b
              (match dir with
              | `Bidi -> Wire.Frame.wt_stream
              | `Uni -> Wire.Uni_stream.wt);
            Varint.add_buffer b sid;
            write t ~id (Buffer.contents b);
            (wstream t id).wsid <- Some sid;
            (match dir with
            | `Bidi ->
                (* Track for reads: the peer answers on the same stream. *)
                Hashtbl.replace t.rstreams id
                  {
                    rid = id;
                    rbuf = Bytebuf.create ();
                    rstate = Attached sid;
                    rfin = false;
                  }
            | `Uni -> ());
            Ok id
        | Error `Would_block -> Error `Would_block
        | Error _ -> Error `Invalid)
  | _ -> Error `Invalid

(* Application writes on WT streams (buffered against flow control). *)
let write_stream t ~id data = write t ~id data
let finish_stream t ~id = write t ~id "" ~fin:true

(* Bytes buffered locally for [id]; drivers use this for backpressure. *)
let outbuf_len t ~id =
  match Hashtbl.find_opt t.wstreams id with
  | Some w -> Bytebuf.length w.wout
  | None -> 0

(* Abrupt stream termination with WebTransport application error codes
   (mapped into the reserved HTTP/3 range on the wire). *)
let reset_wt_stream t ~id ~code =
  let (C ((module B), h)) = t.bc in
  (match Hashtbl.find_opt t.wstreams id with
  | Some w ->
      ignore (Bytebuf.take_all w.wout);
      w.wfin_sent <- true
  | None -> ());
  ignore (B.stream_reset h ~id ~code:(Wt_error.to_h3 code))

let stop_wt_stream t ~id ~code =
  let (C ((module B), h)) = t.bc in
  ignore (B.stream_stop_sending h ~id ~code:(Wt_error.to_h3 code))

(* Sends a WebTransport datagram: quarter-stream-id prefix + payload.
   Returns false when the session is not open or the queue is full. *)
let send_datagram t ~sid payload =
  match session t sid with
  | Some s when s.sstate = `Open ->
      ignore s;
      let b = Buffer.create (String.length payload + 4) in
      Varint.add_buffer b (sid / 4);
      Buffer.add_string b payload;
      let data = Buffer.contents b in
      let len = String.length data in
      let (C ((module B), h)) = t.bc in
      let buf = Bigstringaf.of_string ~off:0 ~len data in
      (match B.dgram_send h buf ~off:0 ~len with
      | Ok () -> true
      | Error _ -> false)
  | _ -> false

let session_state t ~sid =
  match session t sid with Some s -> Some s.sstate | None -> None

let session_request t ~sid =
  match session t sid with Some s -> s.req | None -> None

(* Session receive-side data accounting; grants more credit at half-window. *)
let account_read t ~id n =
  if n > 0 then
    match Hashtbl.find_opt t.rstreams id with
    | Some { rstate = Attached sid; _ } -> (
        match session t sid with
        | Some s when s.fc_on && s.sstate = `Open ->
            s.consumed_data <- s.consumed_data + n;
            if s.recv_max_data - s.consumed_data < s.recv_window / 2 then begin
              s.recv_max_data <- s.consumed_data + s.recv_window;
              send_capsule t ~id:sid (Capsule.encode_max_data s.recv_max_data)
            end
        | _ -> ())
    | _ -> ()

(* Reads from an engine-tracked stream, draining any bytes the engine pulled
   before the stream was attached to its session. Drivers use this instead of
   calling the backend directly for WT data streams. *)
let read_attached t ~id buf ~off ~len =
  let (C ((module B), h)) = t.bc in
  match Hashtbl.find_opt t.rstreams id with
  | Some r -> (
      let buffered = Bytebuf.length r.rbuf in
      if buffered > 0 then begin
        let n = min buffered len in
        let s = Bytebuf.take r.rbuf n in
        Bigstringaf.blit_from_string s ~src_off:0 buf ~dst_off:off ~len:n;
        account_read t ~id n;
        Ok (n, r.rfin && Bytebuf.length r.rbuf = 0)
      end
      else if r.rfin then Error `Fin
      else
        match B.stream_recv h ~id buf ~off ~len with
        | Ok (n, fin) ->
            if fin then r.rfin <- true;
            account_read t ~id n;
            Ok (n, fin)
        | e -> e)
  | None -> B.stream_recv h ~id buf ~off ~len
