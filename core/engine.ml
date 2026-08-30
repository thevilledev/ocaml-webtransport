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
  | Parked  (* WT stream for an unknown session: left unread (M3: timeout) *)
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
}

type role = [ `Client | `Server ]

type t = {
  bc : backend_conn;
  role : role;
  wt_max_sessions : int;
  fc : int * int * int;  (* advertised WT flow-control settings; 0 = off *)
  notif : notification Queue.t;
  rstreams : (int, rstream) Hashtbl.t;
  wstreams : (int, wstream) Hashtbl.t;
  sessions : (int, session) Hashtbl.t;
  scratch : Bigstringaf.t;
  mutable started : bool;  (* control stream opened, SETTINGS sent *)
  mutable peer_settings : Settings.t option;
  mutable control_out : int option;
  mutable control_in : int option;
  mutable pending_connect :
    (string * string * string option * (string * string) list) option;
  mutable conn_dead : bool;
}

let create ?(wt_max_sessions = 1024) ?(fc = (0, 0, 0)) ~role bc =
  {
    bc;
    role;
    wt_max_sessions;
    fc;
    notif = Queue.create ();
    rstreams = Hashtbl.create 16;
    wstreams = Hashtbl.create 16;
    sessions = Hashtbl.create 4;
    scratch = Bigstringaf.create 65_536;
    started = false;
    peer_settings = None;
    control_out = None;
    control_in = None;
    pending_connect = None;
    conn_dead = false;
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
      let w =
        { wid = id; wout = Bytebuf.create (); wfin = false; wfin_sent = false }
      in
      Hashtbl.add t.wstreams id w;
      w

let try_flush_wstream t w =
  let (C ((module B), h)) = t.bc in
  let rec go () =
    let n = Bytebuf.length w.wout in
    if n > 0 then begin
      let chunk = min n (Bigstringaf.length t.scratch) in
      let data, pos = Bytebuf.view w.wout in
      Bigstringaf.blit_from_string data ~src_off:pos t.scratch ~dst_off:0
        ~len:chunk;
      let fin = w.wfin && chunk = n in
      match B.stream_send h ~id:w.wid t.scratch ~off:0 ~len:chunk ~fin with
      | Ok written ->
          Bytebuf.advance w.wout written;
          if written = chunk && fin then w.wfin_sent <- true;
          if written > 0 then go ()
      | Error `Would_block -> ()
      | Error _ -> w.wfin_sent <- true (* stream gone; drop buffered bytes *)
    end
    else if w.wfin && not w.wfin_sent then
      match B.stream_finish h ~id:w.wid with
      | Ok () | Error _ -> w.wfin_sent <- true
  in
  go ()

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
    }
  in
  Hashtbl.add t.sessions sid s;
  s

let end_session t s ~notification =
  if s.sstate <> `Closed then begin
    s.sstate <- `Closed;
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
  else () (* unknown and flow-control capsules: ignored for now *)

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
          debug (lazy (Printf.sprintf "session %d established" r.rid));
          notify t (Session_established { sid = r.rid })
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
  | Dead | Parked -> ()
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
      | Some sid -> (
          match session t sid with
          | Some s when s.sstate = `Open ->
              s.data_streams <- r.rid :: s.data_streams;
              r.rstate <- Attached sid;
              notify t (Wt_stream_opened { sid; stream_id = r.rid; dir });
              if Bytebuf.length r.rbuf > 0 || r.rfin then
                notify t (Wt_stream_readable { stream_id = r.rid })
          | Some _ | None ->
              (* Unknown or not-yet-established session: park unread.
                 (M3: bounded buffer + timeout + closed-session ring.) *)
              r.rstate <- Parked))
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
      | Parked -> () (* park-don't-read: QUIC flow control holds the peer *)
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

let process t =
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
      let extra =
        if s.draft02 then [ ("sec-webtransport-http3-draft", "draft02") ]
        else []
      in
      send_headers t ~id:sid ((":status", "200") :: extra);
      notify t (Session_established { sid })
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
        Ok (n, r.rfin && Bytebuf.length r.rbuf = 0)
      end
      else if r.rfin then Error `Fin
      else
        match B.stream_recv h ~id buf ~off ~len with
        | Ok (n, fin) ->
            if fin then r.rfin <- true;
            Ok (n, fin)
        | e -> e)
  | None -> B.stream_recv h ~id buf ~off ~len
