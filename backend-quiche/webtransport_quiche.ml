(* The default Quic_backend.S implementation, backed by Cloudflare quiche.

   quiche's C API is poll-based, which maps almost one-to-one onto the
   backend signature. The adapter's real work is event synthesis: quiche has
   no event queue, so after every mutating call we mark the connection dirty
   and, on the next [next_event] drain, diff quiche's state (readable /
   writable snapshots, stream-credit counters, handshake / close flags) into
   discrete events. Peer-sent RESET_STREAM / STOP_SENDING surface as [`Reset]
   / [`Stopped] errors from stream operations rather than as events — the
   glue layer handles both paths. *)

module Q = Quiche
module Qb = Webtransport.Quic_backend

module Impl = struct
  type addr = string * int
  type dir = [ `Uni | `Bidi ]

  type config = { qc : Q.Config.t; role : [ `Client | `Server ] }

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

  type t = {
    q : Q.conn;
    role : [ `Client | `Server ];
    pending : event Queue.t;
    known : (int, unit) Hashtbl.t;
    mutable hs_reported : bool;
    mutable closed_reported : bool;
    mutable left_bidi : int;
    mutable left_uni : int;
    mutable next_bidi : int;
    mutable next_uni : int;
    mutable dirty : bool;
  }

  let poke t = t.dirty <- true

  let config ~role ~alpn ?cert_chain_pem_file ?priv_key_pem_file ?verify
      ?(enable_datagrams = false) ?(initial_max_data = 10_000_000)
      ?(initial_max_stream_data = 1_000_000) ?(initial_max_streams_bidi = 100)
      ?(initial_max_streams_uni = 100) ?(max_idle_ns = 30_000_000_000L)
      ?(max_udp_payload = 1350) () =
    let ( let* ) = Result.bind in
    let qerr r = Result.map_error Q.err_to_string r in
    let qc = Q.Config.create () in
    let* () = qerr (Q.Config.set_application_protos qc alpn) in
    let* () =
      match cert_chain_pem_file with
      | None -> Ok ()
      | Some f -> qerr (Q.Config.load_cert_chain qc ~pem_file:f)
    in
    let* () =
      match priv_key_pem_file with
      | None -> Ok ()
      | Some f -> qerr (Q.Config.load_priv_key qc ~pem_file:f)
    in
    let* () =
      match verify with
      | Some `None ->
          Q.Config.verify_peer qc false;
          Ok ()
      | Some (`Ca_file f) ->
          let* () = qerr (Q.Config.load_verify_locations qc ~ca_file:f) in
          Q.Config.verify_peer qc true;
          Ok ()
      | None ->
          (* Verify by default on the client; servers don't ask for client
             certs. Client users must opt out explicitly. *)
          Q.Config.verify_peer qc (role = `Client);
          Ok ()
    in
    Q.Config.set_max_idle_timeout qc (Int64.div max_idle_ns 1_000_000L);
    Q.Config.set_max_send_udp_payload_size qc max_udp_payload;
    Q.Config.set_max_recv_udp_payload_size qc 65527;
    Q.Config.set_initial_max_data qc initial_max_data;
    Q.Config.set_initial_max_stream_data_bidi_local qc initial_max_stream_data;
    Q.Config.set_initial_max_stream_data_bidi_remote qc initial_max_stream_data;
    Q.Config.set_initial_max_stream_data_uni qc initial_max_stream_data;
    Q.Config.set_initial_max_streams_bidi qc initial_max_streams_bidi;
    Q.Config.set_initial_max_streams_uni qc initial_max_streams_uni;
    if enable_datagrams then Q.Config.enable_dgram qc true 1024 1024;
    Q.Config.grease qc true;
    Ok { qc; role }

  type header = {
    version : int32;
    dcid : string;
    scid : string;
    is_long : bool;
    is_initial : bool;
  }

  let parse_header buf ~off ~len =
    if len < 1 then Error "empty packet"
    else
      (* The header form bit is spec-level: don't depend on quiche's type
         numbering for long-vs-short. *)
      let is_long = Char.code (Bigstringaf.get buf off) land 0x80 <> 0 in
      match Q.header_info buf ~off ~len ~dcil:16 with
      | Error e -> Error (Q.err_to_string e)
      | Ok h ->
          Ok
            {
              version = h.Q.version;
              dcid = h.Q.dcid;
              scid = h.Q.scid;
              is_long;
              is_initial = is_long && h.Q.ty = Q.initial_type;
            }

  let negotiate_version ~scid ~dcid buf =
    match
      Q.negotiate_version ~scid ~dcid buf ~off:0 ~len:(Bigstringaf.length buf)
    with
    | Ok n -> Ok n
    | Error e -> Error (Q.err_to_string e)

  (* Opt-in qlog capture: set WT_QLOG_DIR to a directory and build libquiche
     with the qlog feature (the Homebrew bottle has it compiled out, in which
     case this silently does nothing). *)
  let maybe_enable_qlog q role =
    match Sys.getenv_opt "WT_QLOG_DIR" with
    | None -> ()
    | Some dir ->
        let label = match role with `Client -> "client" | `Server -> "server" in
        let path =
          Filename.concat dir
            (Printf.sprintf "wt-%s-%x%x.qlog" label (Random.bits ())
               (Random.bits ()))
        in
        ignore
          (Q.set_qlog_path q ~path ~title:("ocaml-webtransport " ^ label)
             ~description:"ocaml-webtransport qlog")

  let mk role q =
    maybe_enable_qlog q role;
    {
      q;
      role;
      pending = Queue.create ();
      known = Hashtbl.create 16;
      hs_reported = false;
      closed_reported = false;
      left_bidi = 0;
      left_uni = 0;
      next_bidi = (match role with `Client -> 0 | `Server -> 1);
      next_uni = (match role with `Client -> 2 | `Server -> 3);
      dirty = true;
    }

  let connect (cfg : config) ~server_name ~scid ~peer ~local ~now:_ =
    if cfg.role <> `Client then Error "config role is not `Client"
    else
      match Q.connect ?server_name ~scid ~local ~peer cfg.qc with
      | q -> Ok (mk `Client q)
      | exception Failure m -> Error m

  let accept (cfg : config) ~scid ~peer ~local ~now:_ =
    if cfg.role <> `Server then Error "config role is not `Server"
    else
      match Q.accept ~scid ~local ~peer cfg.qc with
      | q -> Ok (mk `Server q)
      | exception Failure m -> Error m

  let close t ~app ~code ~reason =
    ignore (Q.close t.q ~app ~code ~reason);
    poke t

  let is_established t = Q.is_established t.q
  let is_closed t = Q.is_closed t.q

  let recv t ~now:_ buf ~off ~len ~from ~to_ =
    poke t;
    Result.map_error Q.err_to_string (Q.recv t.q buf ~off ~len ~from ~to_)

  let send t ~now:_ buf =
    match Q.send t.q buf ~off:0 ~len:(Bigstringaf.length buf) with
    | `Packet (n, addr) -> `Packet (n, addr)
    | `Done -> `Done
    | `Error e ->
        poke t;
        `Error (Q.err_to_string e)

  let next_timeout_ns t = Q.timeout_as_nanos t.q

  let on_timeout t ~now:_ =
    Q.on_timeout t.q;
    poke t

  (* Peer-initiated stream ids have the opposite initiator bit. *)
  let peer_initiated t id =
    id land 1 = (match t.role with `Client -> 1 | `Server -> 0)

  let refresh t =
    let push e = Queue.add e t.pending in
    if (not t.hs_reported) && Q.is_established t.q then begin
      t.hs_reported <- true;
      push
        (Handshake_done
           {
             alpn = Q.application_proto t.q;
             peer_max_dgram = Q.dgram_max_writable_len t.q;
           })
    end;
    let lb = Q.peer_streams_left_bidi t.q and lu = Q.peer_streams_left_uni t.q in
    if lb > t.left_bidi || lu > t.left_uni then push Stream_credit;
    t.left_bidi <- lb;
    t.left_uni <- lu;
    Array.iter
      (fun id ->
        if not (Hashtbl.mem t.known id) then begin
          Hashtbl.add t.known id ();
          if peer_initiated t id then
            push
              (Stream_opened
                 { id; dir = (if id land 2 = 2 then `Uni else `Bidi) })
        end;
        push (Stream_readable id))
      (Q.readable_ids t.q);
    Array.iter (fun id -> push (Stream_writable id)) (Q.writable_ids t.q);
    if Q.dgram_recv_queue_len t.q > 0 then push Datagram_readable;
    if (not t.closed_reported) && Q.is_closed t.q then begin
      t.closed_reported <- true;
      let local, err =
        match Q.peer_error t.q with
        | Some e -> (false, Some e)
        | None -> (true, Q.local_error t.q)
      in
      let app, code, reason =
        match err with
        | Some e -> (e.Q.is_app, e.Q.code, e.Q.reason)
        | None -> (false, 0, "")
      in
      push (Closed { local; app; code; reason })
    end

  let next_event t =
    if t.dirty then begin
      t.dirty <- false;
      refresh t
    end;
    Queue.take_opt t.pending

  type 'a rw =
    ( 'a,
      [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
    result

  let rw_error : Q.err -> [> `Would_block | `Reset of int | `Stopped of int | `Invalid ]
      = function
    | Q.Done | Q.Stream_limit | Q.Flow_control -> `Would_block
    | Q.Stream_reset c -> `Reset c
    | Q.Stream_stopped c -> `Stopped c
    | _ -> `Invalid

  (* quiche creates streams implicitly; a zero-length send reserves the id
     (or fails with Stream_limit when out of credit). *)
  let open_stream t ~dir =
    let id = match dir with `Bidi -> t.next_bidi | `Uni -> t.next_uni in
    match Q.stream_send t.q ~id Bigstringaf.empty ~off:0 ~len:0 ~fin:false with
    | Ok _ ->
        (match dir with
        | `Bidi -> t.next_bidi <- id + 4
        | `Uni -> t.next_uni <- id + 4);
        Hashtbl.replace t.known id ();
        poke t;
        Ok id
    | Error e -> Error (rw_error e)

  let stream_recv t ~id buf ~off ~len =
    poke t;
    match Q.stream_recv t.q ~id buf ~off ~len with
    | Ok (n, fin) -> Ok (n, fin)
    | Error Q.Done ->
        if Q.stream_finished t.q id then Error `Fin else Error `Would_block
    | Error e -> Error (rw_error e)

  let stream_send t ~id buf ~off ~len ~fin =
    poke t;
    match Q.stream_send t.q ~id buf ~off ~len ~fin with
    | Ok n -> Ok n
    | Error e -> Error (rw_error e)

  let stream_capacity t ~id =
    match Q.stream_capacity t.q ~id with
    | Ok n -> Ok n
    | Error e -> Error (rw_error e)

  let stream_finish t ~id =
    poke t;
    match Q.stream_send t.q ~id Bigstringaf.empty ~off:0 ~len:0 ~fin:true with
    | Ok _ -> Ok ()
    | Error e -> Error (rw_error e)

  let stream_reset t ~id ~code =
    poke t;
    match Q.stream_shutdown t.q ~id `Write ~code with
    | Ok () -> Ok ()
    | Error Q.Done -> Ok ()
    | Error e -> Error (rw_error e)

  let stream_stop_sending t ~id ~code =
    poke t;
    match Q.stream_shutdown t.q ~id `Read ~code with
    | Ok () -> Ok ()
    | Error Q.Done -> Ok ()
    | Error e -> Error (rw_error e)

  let dgram_send t buf ~off ~len =
    poke t;
    match Q.dgram_send t.q buf ~off ~len with
    | Ok () -> Ok ()
    | Error Q.Buffer_too_short -> Error `Invalid
    | Error e -> Error (rw_error e)

  let dgram_recv t buf ~off =
    poke t;
    match Q.dgram_recv t.q buf ~off ~len:(Bigstringaf.length buf - off) with
    | Ok n -> Ok n
    | Error e -> Error (rw_error e)

  let dgram_max_len t = Q.dgram_max_writable_len t.q
  let peer_cert_der t = Q.peer_cert t.q
end

include Impl
module _ = (Impl : Qb.S)
