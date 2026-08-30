(* Eio driver for the webtransport stack.

   [Raw] exposes plain QUIC connections (streams + datagrams, no HTTP/3) —
   used by tests and as the substrate the higher layers share. [Wt] runs the
   sans-io H3/WebTransport engine on top and exposes sessions.

   Concurrency model (one QUIC connection):
   - one mutex guards the backend handle and engine; every touch happens
     under it, followed by [service] (fire due timer, drain, flush packets,
     broadcast progress);
   - a pump fiber owns timer deadlines (interruptible via [kick]);
   - blocking user ops loop attempt-await-retry on [progress].
   Backend and engine calls never block and never run effects, so nothing
   can suspend mid-operation while the mutex is held. *)

open Eio.Std
module Qb = Webtransport.Quic_backend
module Engine = Webtransport.Engine

type backend =
  | Backend :
      (module Qb.S with type t = 'c and type config = 'k) * 'k
      -> backend

type close_info = { code : int; reason : string; remote : bool; app : bool }

exception Connection_closed of close_info
exception Stream_reset_by_peer of int
exception Stream_stopped_by_peer of int
exception Session_closed of int * string
exception Session_rejected of int

(* ---- shared helpers ---- *)

let rng = lazy (Random.State.make_self_init ())

let random_scid () =
  let st = Lazy.force rng in
  String.init 16 (fun _ -> Char.chr (Random.State.int st 256))

let sockaddr_to_raw : Eio.Net.Sockaddr.datagram -> string * int = function
  | `Udp (ip, port) -> ((ip :> string), port)
  | `Unix _ -> invalid_arg "unix datagram socket"

let make_sock_send sock ~dst:(ip, port) cs =
  Eio.Net.send sock ~dst:(`Udp (Eio.Net.Ipaddr.of_raw ip, port)) [ cs ]

let make_clock_fns clock =
  let now_ns () = Mtime.to_uint64_ns (Eio.Time.Mono.now clock) in
  let sleep_until_ns ns =
    Eio.Time.Mono.sleep_until clock (Mtime.of_uint64_ns ns)
  in
  (now_ns, sleep_until_ns)

(* ---- generic per-connection machinery ---- *)

module Core_conn = struct
  type t = {
    mutex : Eio.Mutex.t;
    progress : Eio.Condition.t;
    kick : Eio.Condition.t;
    established_p : unit Promise.t;
    established_r : unit Promise.u;
    closed_p : close_info Promise.t;
    closed_r : close_info Promise.u;
    send_buf : Bigstringaf.t;
    wbuf : Bigstringaf.t;
    scratch : Bigstringaf.t;
    sock_send : dst:(string * int) -> Cstruct.t -> unit;
    now_ns : unit -> int64;
    sleep_until_ns : int64 -> unit;
    mutable dead : bool;
    (* installed per layer/backend after construction *)
    mutable drain : unit -> unit;
    mutable fire_timeout : unit -> unit;
    mutable flush : unit -> unit;
    mutable next_deadline : unit -> int64 option;  (* remaining ns *)
    mutable feed_pkt : Bigstringaf.t -> len:int -> from:(string * int) -> unit;
    mutable backend_closed : unit -> bool;
  }

  let mk ~sock_send ~now_ns ~sleep_until_ns =
    let established_p, established_r = Promise.create () in
    let closed_p, closed_r = Promise.create () in
    {
      mutex = Eio.Mutex.create ();
      progress = Eio.Condition.create ();
      kick = Eio.Condition.create ();
      established_p;
      established_r;
      closed_p;
      closed_r;
      send_buf = Bigstringaf.create 1500;
      wbuf = Bigstringaf.create 16_384;
      scratch = Bigstringaf.create 65_536;
      sock_send;
      now_ns;
      sleep_until_ns;
      dead = false;
      drain = (fun () -> ());
      fire_timeout = (fun () -> ());
      flush = (fun () -> ());
      next_deadline = (fun () -> None);
      feed_pkt = (fun _ ~len:_ ~from:_ -> ());
      backend_closed = (fun () -> false);
    }

  (* Installs the backend-generic closures (drain stays per layer). *)
  let install_backend (type c) (module B : Qb.S with type t = c) (h : c) st
      ~local =
    st.fire_timeout <-
      (fun () ->
        match B.next_timeout_ns h with
        | Some d when Int64.compare d 1_000_000L <= 0 ->
            B.on_timeout h ~now:(st.now_ns ())
        | _ -> ());
    st.flush <-
      (fun () ->
        let rec go () =
          match B.send h ~now:(st.now_ns ()) st.send_buf with
          | `Packet (n, addr) ->
              st.sock_send ~dst:addr
                (Cstruct.of_bigarray ~off:0 ~len:n st.send_buf);
              go ()
          | `Done -> ()
          | `Error _ -> ()
        in
        go ());
    st.next_deadline <- (fun () -> B.next_timeout_ns h);
    st.backend_closed <- (fun () -> B.is_closed h);
    st.feed_pkt <-
      (fun buf ~len ~from ->
        match
          B.recv h ~now:(st.now_ns ()) buf ~off:0 ~len ~from ~to_:local
        with
        | Ok _ | Error _ -> ())

  (* Must run under [mutex]. *)
  let service st =
    st.fire_timeout ();
    st.drain ();
    st.flush ();
    Eio.Condition.broadcast st.progress

  let with_lock st f = Eio.Mutex.use_rw ~protect:false st.mutex f

  let mark_dead st ci =
    st.dead <- true;
    if not (Promise.is_resolved st.closed_p) then Promise.resolve st.closed_r ci;
    Eio.Condition.broadcast st.progress

  let closed_exn st =
    match Promise.peek st.closed_p with
    | Some ci -> Connection_closed ci
    | None ->
        Connection_closed
          { code = 0; reason = "closed"; remote = false; app = false }

  (* Under the mutex: retry [f] until it yields, waking on [progress]. *)
  let rec block_until st f =
    match f () with
    | Some v -> v
    | None ->
        if st.dead then raise (closed_exn st);
        Eio.Condition.await st.progress st.mutex;
        block_until st f

  let locked_op st f =
    let r =
      with_lock st (fun () ->
          let r = block_until st f in
          service st;
          r)
    in
    Eio.Condition.broadcast st.kick;
    r

  (* A non-blocking command + service + kick. *)
  let command st f =
    let r =
      with_lock st (fun () ->
          let r = f () in
          service st;
          r)
    in
    Eio.Condition.broadcast st.kick;
    r

  let feed st buf ~len ~from =
    with_lock st (fun () ->
        st.feed_pkt buf ~len ~from;
        service st);
    Eio.Condition.broadcast st.kick

  let pump ~sw st ~on_dead =
    Fiber.fork_daemon ~sw (fun () ->
        let rec loop () =
          let dead =
            with_lock st (fun () ->
                service st;
                st.dead || st.backend_closed ())
          in
          if dead then begin
            with_lock st (fun () ->
                mark_dead st
                  { code = 0; reason = ""; remote = false; app = false });
            on_dead ();
            `Stop_daemon
          end
          else begin
            let now = st.now_ns () in
            let deadline =
              match st.next_deadline () with
              | Some dur -> Int64.add now dur
              | None -> Int64.add now 60_000_000_000L
            in
            let cap = Int64.add now 500_000_000L in
            let deadline =
              if Int64.compare deadline cap > 0 then cap else deadline
            in
            Fiber.first
              (fun () -> Eio.Condition.await_no_mutex st.kick)
              (fun () -> st.sleep_until_ns deadline);
            loop ()
          end
        in
        loop ())
end

(* Generic UDP endpoint plumbing: server demux loop and client socket.
   [on_new_conn] runs for each accepted connection and returns the conn's
   Core_conn state so packets can be fed to it. *)

let server_recv_loop (type c k) ~sw ~sock
    (module B : Qb.S with type t = c and type config = k) (cfg : k) ~local
    ~now_ns ~(on_new_conn : c -> string -> Core_conn.t option) =
  let table : (string, Core_conn.t) Hashtbl.t = Hashtbl.create 16 in
  Fiber.fork_daemon ~sw (fun () ->
      let rbuf = Bigstringaf.create 65_536 in
      let rcs = Cstruct.of_bigarray rbuf in
      let vn_buf = Bigstringaf.create 256 in
      let sock_send = make_sock_send sock in
      let rec loop () =
        let addr, n = Eio.Net.recv sock rcs in
        let from = sockaddr_to_raw addr in
        (match B.parse_header rbuf ~off:0 ~len:n with
        | Error _ -> ()
        | Ok hdr -> (
            match Hashtbl.find_opt table hdr.B.dcid with
            | Some st -> Core_conn.feed st rbuf ~len:n ~from
            | None ->
                if hdr.B.is_long && hdr.B.version <> 1l then (
                  match
                    B.negotiate_version ~scid:hdr.B.scid ~dcid:hdr.B.dcid vn_buf
                  with
                  | Ok vn ->
                      sock_send ~dst:from
                        (Cstruct.of_bigarray ~off:0 ~len:vn vn_buf)
                  | Error _ -> ())
                else if hdr.B.is_initial then (
                  (* Generate our own fixed-length (16-byte) SCID: short-header
                     packets carry it as DCID and [parse_header] reads DCIDs
                     as 16 bytes. Map both the client's initial DCID (for the
                     rest of its first flights) and our SCID to the conn. *)
                  let scid = random_scid () in
                  match
                    B.accept cfg ~scid ~peer:from ~local ~now:(now_ns ())
                  with
                  | Error _ -> ()
                  | Ok h -> (
                      match on_new_conn h scid with
                      | None -> ()
                      | Some st ->
                          let dcid = hdr.B.dcid in
                          Hashtbl.add table dcid st;
                          Hashtbl.add table scid st;
                          Fiber.fork_daemon ~sw (fun () ->
                              ignore (Promise.await st.Core_conn.closed_p);
                              Hashtbl.remove table dcid;
                              Hashtbl.remove table scid;
                              `Stop_daemon);
                          Core_conn.feed st rbuf ~len:n ~from))));
        loop ()
      in
      ignore (fun key -> Hashtbl.remove table key);
      loop ())
  |> fun () ->
  table

let client_recv_loop ~sw ~sock st ~local:_ =
  Fiber.fork_daemon ~sw (fun () ->
      let rbuf = Bigstringaf.create 65_536 in
      let rcs = Cstruct.of_bigarray rbuf in
      let rec loop () =
        let addr, n = Eio.Net.recv sock rcs in
        let from = sockaddr_to_raw addr in
        Core_conn.feed st rbuf ~len:n ~from;
        loop ()
      in
      loop ())

(* ---------------------------------------------------------------- *)
(* Raw QUIC connections                                             *)
(* ---------------------------------------------------------------- *)

module Raw = struct
  type conn =
    | Conn : {
        b : (module Qb.S with type t = 'c);
        h : 'c;
        st : Core_conn.t;
        accept_q : int Eio.Stream.t;
        dgram_q : string Eio.Stream.t;
      }
        -> conn

  (* Installs the Raw event-drain closure. *)
  let install_drain (type c) (module B : Qb.S with type t = c) (h : c)
      (st : Core_conn.t) ~accept_q ~dgram_q =
    let dgram_cap = 128 in
    st.Core_conn.drain <-
      (fun () ->
        let rec go () =
          match B.next_event h with
          | None -> ()
          | Some e ->
              (match e with
              | B.Handshake_done _ ->
                  if not (Promise.is_resolved st.Core_conn.established_p) then
                    Promise.resolve st.Core_conn.established_r ()
              | B.Stream_opened { id; _ } -> Eio.Stream.add accept_q id
              | B.Datagram_readable ->
                  let rec dloop () =
                    match B.dgram_recv h st.Core_conn.scratch ~off:0 with
                    | Ok n ->
                        let s =
                          Bigstringaf.substring st.Core_conn.scratch ~off:0
                            ~len:n
                        in
                        if Eio.Stream.length dgram_q >= dgram_cap then
                          ignore (Eio.Stream.take_nonblocking dgram_q);
                        Eio.Stream.add dgram_q s;
                        dloop ()
                    | Error _ -> ()
                  in
                  dloop ()
              | B.Closed { code; reason; local; app } ->
                  Core_conn.mark_dead st
                    { code; reason; remote = not local; app }
              | B.Stream_readable _ | B.Stream_writable _ | B.Stream_credit
              | B.Stream_reset _ | B.Stream_stopped _ ->
                  ());
              go ()
        in
        go ())

  (* [Core_conn.install_backend] must already have run on [st]. *)
  let mk_conn (type c) (module B : Qb.S with type t = c) (h : c) st =
    let accept_q = Eio.Stream.create max_int in
    let dgram_q = Eio.Stream.create 1024 in
    install_drain (module B) h st ~accept_q ~dgram_q;
    Conn { b = (module B); h; st; accept_q; dgram_q }

  (* ---- user operations ---- *)

  let established (Conn { st; _ }) =
    Fiber.first
      (fun () -> Promise.await st.Core_conn.established_p)
      (fun () -> raise (Connection_closed (Promise.await st.Core_conn.closed_p)))

  let closed (Conn { st; _ }) = Promise.await st.Core_conn.closed_p

  let accept_stream (Conn { st; accept_q; _ }) =
    Fiber.first
      (fun () -> Eio.Stream.take accept_q)
      (fun () -> raise (Connection_closed (Promise.await st.Core_conn.closed_p)))

  let open_stream (Conn { b = (module B); h; st; _ }) ~dir =
    Core_conn.locked_op st (fun () ->
        match B.open_stream h ~dir with
        | Ok id -> Some id
        | Error `Would_block -> None
        | Error _ -> invalid_arg "open_stream")

  let read (Conn { b = (module B); h; st; _ }) ~id buf ~off ~len =
    Core_conn.locked_op st (fun () ->
        match B.stream_recv h ~id buf ~off ~len with
        | Ok (n, fin) -> if n = 0 && fin then Some `Fin else Some (`Data n)
        | Error `Would_block -> None
        | Error `Fin -> Some `Fin
        | Error (`Reset code) -> raise (Stream_reset_by_peer code)
        | Error (`Stopped code) -> raise (Stream_stopped_by_peer code)
        | Error `Invalid -> invalid_arg "read: invalid stream")

  let write (Conn { b = (module B); h; st; _ }) ~id data =
    let len = String.length data in
    let pos = ref 0 in
    while !pos < len do
      let n = min (len - !pos) (Bigstringaf.length st.Core_conn.wbuf) in
      Bigstringaf.blit_from_string data ~src_off:!pos st.Core_conn.wbuf
        ~dst_off:0 ~len:n;
      let wrote =
        Core_conn.locked_op st (fun () ->
            match
              B.stream_send h ~id st.Core_conn.wbuf ~off:0 ~len:n ~fin:false
            with
            | Ok 0 -> None
            | Ok w -> Some w
            | Error `Would_block -> None
            | Error (`Reset code) -> raise (Stream_reset_by_peer code)
            | Error (`Stopped code) -> raise (Stream_stopped_by_peer code)
            | Error `Fin | Error `Invalid -> invalid_arg "write: invalid stream")
      in
      pos := !pos + wrote
    done

  let finish (Conn { b = (module B); h; st; _ }) ~id =
    Core_conn.locked_op st (fun () ->
        match B.stream_finish h ~id with
        | Ok () -> Some ()
        | Error `Would_block -> None
        | Error _ -> invalid_arg "finish")

  let reset (Conn { b = (module B); h; st; _ }) ~id ~code =
    Core_conn.command st (fun () -> ignore (B.stream_reset h ~id ~code))

  let stop_sending (Conn { b = (module B); h; st; _ }) ~id ~code =
    Core_conn.command st (fun () -> ignore (B.stream_stop_sending h ~id ~code))

  let send_dgram (Conn { b = (module B); h; st; _ }) data =
    let len = String.length data in
    if len > Bigstringaf.length st.Core_conn.wbuf then
      invalid_arg "datagram too large";
    Core_conn.locked_op st (fun () ->
        Bigstringaf.blit_from_string data ~src_off:0 st.Core_conn.wbuf
          ~dst_off:0 ~len;
        match B.dgram_send h st.Core_conn.wbuf ~off:0 ~len with
        | Ok () -> Some ()
        | Error `Would_block -> None
        | Error _ -> invalid_arg "send_dgram")

  let recv_dgram (Conn { st; dgram_q; _ }) =
    Fiber.first
      (fun () -> Eio.Stream.take dgram_q)
      (fun () -> raise (Connection_closed (Promise.await st.Core_conn.closed_p)))

  let close (Conn { b = (module B); h; st; _ }) ~code ~reason =
    Core_conn.command st (fun () -> B.close h ~app:true ~code ~reason)

  (* ---- endpoints ---- *)

  let listen ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ~port
      ~handler =
    let sock =
      Eio.Net.datagram_socket ~sw ~reuse_addr:true net
        (`Udp (Eio.Net.Ipaddr.V4.any, port))
    in
    let local = ("\000\000\000\000", port) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    ignore
      (server_recv_loop ~sw ~sock (module B) cfg ~local ~now_ns
         ~on_new_conn:(fun h _key ->
           let st = Core_conn.mk ~sock_send ~now_ns ~sleep_until_ns in
           Core_conn.install_backend (module B) h st ~local;
           let c = mk_conn (module B) h st in
           Core_conn.pump ~sw st ~on_dead:(fun () -> ());
           Fiber.fork_daemon ~sw (fun () ->
               (try handler c with
               | Connection_closed _ | Stream_reset_by_peer _
               | Stream_stopped_by_peer _ ->
                   ());
               `Stop_daemon);
           Some st))

  let connect ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ?server_name
      ~peer () =
    let sock =
      Eio.Net.datagram_socket ~sw net (`Udp (Eio.Net.Ipaddr.V4.any, 0))
    in
    let local = ("\000\000\000\000", 0) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    let scid = random_scid () in
    match B.connect cfg ~server_name ~scid ~peer ~local ~now:(now_ns ()) with
    | Error e -> failwith ("connect: " ^ e)
    | Ok h ->
        let st = Core_conn.mk ~sock_send ~now_ns ~sleep_until_ns in
        Core_conn.install_backend (module B) h st ~local;
        let c = mk_conn (module B) h st in
        client_recv_loop ~sw ~sock st ~local;
        Core_conn.pump ~sw st ~on_dead:(fun () -> ());
        Core_conn.command st (fun () -> ());
        established c;
        c
end

(* ---------------------------------------------------------------- *)
(* WebTransport sessions                                            *)
(* ---------------------------------------------------------------- *)

module Wt = struct
  type session = {
    sid : int;
    req : Engine.request;
    st : Core_conn.t;
    eng : Engine.t;
    s_closed_p : (int * string) Promise.t;
    s_closed_r : (int * string) Promise.u;
    draining_p : unit Promise.t;
    draining_r : unit Promise.u;
    dgrams : string Eio.Stream.t;
    bidi_q : int Eio.Stream.t;  (* peer-opened WT bidi streams *)
    uni_q : int Eio.Stream.t;  (* peer-opened WT uni streams *)
  }

  let dgram_cap = 128

  type conn_ctx = {
    c_st : Core_conn.t;
    c_eng : Engine.t;
    sessions : (int, session) Hashtbl.t;
    ready : session Eio.Stream.t;  (* server: established sessions *)
    mutable client_r : ((session, exn) result Promise.u) option;
    accept_cb : Engine.request -> [ `Accept | `Reject of int ];
  }

  let mk_session ctx sid =
    let req =
      match Engine.session_request ctx.c_eng ~sid with
      | Some r -> r
      | None ->
          {
            Engine.authority = "";
            path = "";
            origin = None;
            protocol = "";
            headers = [];
          }
    in
    let s_closed_p, s_closed_r = Promise.create () in
    let draining_p, draining_r = Promise.create () in
    {
      sid;
      req;
      st = ctx.c_st;
      eng = ctx.c_eng;
      s_closed_p;
      s_closed_r;
      draining_p;
      draining_r;
      dgrams = Eio.Stream.create 1024;
      bidi_q = Eio.Stream.create max_int;
      uni_q = Eio.Stream.create max_int;
    }

  let end_session_local s ~code ~message =
    if not (Promise.is_resolved s.s_closed_p) then
      Promise.resolve s.s_closed_r (code, message)

  (* Runs under the connection mutex: must never block. *)
  let dispatch ctx = function
    | Engine.Incoming_session { sid; req } -> (
        match ctx.accept_cb req with
        | `Accept -> Engine.accept_session ctx.c_eng ~sid
        | `Reject status -> Engine.reject_session ctx.c_eng ~sid ~status)
    | Engine.Session_established { sid } -> (
        let s = mk_session ctx sid in
        Hashtbl.replace ctx.sessions sid s;
        match ctx.client_r with
        | Some r ->
            ctx.client_r <- None;
            Promise.resolve r (Ok s)
        | None -> Eio.Stream.add ctx.ready s)
    | Engine.Session_rejected { status; _ } -> (
        match ctx.client_r with
        | Some r ->
            ctx.client_r <- None;
            Promise.resolve r (Error (Session_rejected status))
        | None -> ())
    | Engine.Session_peer_closed { sid; code; message; _ } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s ->
            Hashtbl.remove ctx.sessions sid;
            end_session_local s ~code ~message
        | None -> ())
    | Engine.Session_peer_drain { sid } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s ->
            if not (Promise.is_resolved s.draining_p) then
              Promise.resolve s.draining_r ()
        | None -> ())
    | Engine.Wt_datagram { sid; payload } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s ->
            if Eio.Stream.length s.dgrams >= dgram_cap then
              ignore (Eio.Stream.take_nonblocking s.dgrams);
            Eio.Stream.add s.dgrams payload
        | None -> ())
    | Engine.Wt_stream_opened { sid; stream_id; dir } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s -> (
            match dir with
            | `Bidi -> Eio.Stream.add s.bidi_q stream_id
            | `Uni -> Eio.Stream.add s.uni_q stream_id)
        | None -> ())
    | Engine.Wt_stream_readable _ | Engine.Wt_stream_writable _ ->
        (* progress is broadcast by [service]; blocked readers/writers
           re-check *)
        ()
    | Engine.Goaway -> ()
    | Engine.Conn_closed { code; reason; remote } ->
        Hashtbl.iter
          (fun _ s -> end_session_local s ~code:0 ~message:"connection closed")
          ctx.sessions;
        Hashtbl.reset ctx.sessions;
        Core_conn.mark_dead ctx.c_st { code; reason; remote; app = true }

  let mk_ctx (type c) (module B : Qb.S with type t = c) (h : c) st ~accept_cb
      ~fc =
    let eng = Engine.create ~role:`Server ?fc (Engine.C ((module B), h)) in
    let ctx =
      {
        c_st = st;
        c_eng = eng;
        sessions = Hashtbl.create 4;
        ready = Eio.Stream.create max_int;
        client_r = None;
        accept_cb;
      }
    in
    ctx

  let install_wt_drain ctx =
    ctx.c_st.Core_conn.drain <-
      (fun () ->
        List.iter (dispatch ctx)
          (Engine.process ctx.c_eng ~now:(ctx.c_st.Core_conn.now_ns ())))

  (* ---- session API ---- *)

  module Session = struct
    let request s = s.req
    let path s = s.req.Engine.path
    let authority s = s.req.Engine.authority
    let origin s = s.req.Engine.origin

    let close ?(code = 0) ?(message = "") s =
      Core_conn.command s.st (fun () ->
          Engine.close_session s.eng ~sid:s.sid ~code ~message);
      end_session_local s ~code ~message

    let closed s = Promise.await s.s_closed_p

    (* Ask the peer to stop opening new streams (WT_DRAIN_SESSION). *)
    let drain s =
      Core_conn.command s.st (fun () ->
          Engine.drain_session s.eng ~sid:s.sid)

    (* Resolves when the peer asks us to drain. *)
    let draining s = Promise.await s.draining_p

    let send_datagram s payload =
      Core_conn.command s.st (fun () ->
          Engine.send_datagram s.eng ~sid:s.sid payload)

    let recv_datagram s =
      Fiber.first
        (fun () -> Eio.Stream.take s.dgrams)
        (fun () ->
          let code, message = Promise.await s.s_closed_p in
          raise (Session_closed (code, message)))
  end

  module Stream = struct
    type t = { s : session; id : int; dir : Engine.dir }

    let id t = t.id
    let session t = t.s

    let wt_code_of_h3 h3 =
      match Webtransport.Wt_error.of_h3 h3 with Some c -> c | None -> h3

    (* Blocking read; [`Fin] at clean end of stream. *)
    let read t buf ~off ~len =
      Core_conn.locked_op t.s.st (fun () ->
          match Engine.read_attached t.s.eng ~id:t.id buf ~off ~len with
          | Ok (n, fin) -> if n = 0 && fin then Some `Fin else Some (`Data n)
          | Error `Fin -> Some `Fin
          | Error `Would_block -> None
          | Error (`Reset h3) -> raise (Stream_reset_by_peer (wt_code_of_h3 h3))
          | Error (`Stopped h3) ->
              raise (Stream_stopped_by_peer (wt_code_of_h3 h3))
          | Error `Invalid -> invalid_arg "Stream.read")

    let read_all t =
      let buf = Bigstringaf.create 16_384 in
      let b = Buffer.create 256 in
      let rec loop () =
        match read t buf ~off:0 ~len:16_384 with
        | `Data n ->
            Buffer.add_string b (Bigstringaf.substring buf ~off:0 ~len:n);
            loop ()
        | `Fin -> Buffer.contents b
      in
      loop ()

    (* Blocking write through the engine's per-stream buffer (so bytes order
       behind the WT signal prefix), with a high-watermark for backpressure. *)
    let high_watermark = 262_144

    let write t data =
      let len = String.length data in
      let pos = ref 0 in
      while !pos < len do
        let chunk = min (len - !pos) 16_384 in
        let piece = String.sub data !pos chunk in
        Core_conn.locked_op t.s.st (fun () ->
            if Engine.outbuf_len t.s.eng ~id:t.id > high_watermark then None
            else begin
              Engine.write_stream t.s.eng ~id:t.id piece;
              Some ()
            end);
        pos := !pos + chunk
      done

    let close_write t =
      Core_conn.command t.s.st (fun () ->
          Engine.finish_stream t.s.eng ~id:t.id)

    let reset t ~code =
      Core_conn.command t.s.st (fun () ->
          Engine.reset_wt_stream t.s.eng ~id:t.id ~code)

    let stop_sending t ~code =
      Core_conn.command t.s.st (fun () ->
          Engine.stop_wt_stream t.s.eng ~id:t.id ~code)
  end

  let open_stream_blocking (s : session) ~dir =
    let id =
      Core_conn.locked_op s.st (fun () ->
          match Engine.open_wt_stream s.eng ~sid:s.sid ~dir with
          | Ok id -> Some id
          | Error `Would_block -> None
          | Error _ ->
              let c, m =
                match Promise.peek s.s_closed_p with
                | Some ci -> ci
                | None -> (0, "session not open")
              in
              raise (Session_closed (c, m)))
    in
    { Stream.s; id; dir }

  let accept_stream_blocking (s : session) q dir =
    Fiber.first
      (fun () ->
        let id = Eio.Stream.take q in
        { Stream.s; id; dir })
      (fun () ->
        let code, message = Promise.await s.s_closed_p in
        raise (Session_closed (code, message)))

  let open_bidi s = open_stream_blocking s ~dir:`Bidi
  let open_uni s = open_stream_blocking s ~dir:`Uni
  let accept_bidi s = accept_stream_blocking s s.bidi_q `Bidi
  let accept_uni s = accept_stream_blocking s s.uni_q `Uni

  (* ---- endpoints ---- *)

  let listen ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ~port
      ?(accept = fun _ -> `Accept) ?fc ~handler () =
    let sock =
      Eio.Net.datagram_socket ~sw ~reuse_addr:true net
        (`Udp (Eio.Net.Ipaddr.V4.any, port))
    in
    let local = ("\000\000\000\000", port) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    ignore
      (server_recv_loop ~sw ~sock (module B) cfg ~local ~now_ns
         ~on_new_conn:(fun h _key ->
           let st = Core_conn.mk ~sock_send ~now_ns ~sleep_until_ns in
           Core_conn.install_backend (module B) h st ~local;
           let ctx = mk_ctx (module B) h st ~accept_cb:accept ~fc in
           install_wt_drain ctx;
           Core_conn.pump ~sw st ~on_dead:(fun () -> ());
           (* Per-connection acceptor: hand established sessions to the
              application handler. *)
           Fiber.fork_daemon ~sw (fun () ->
               let rec loop () =
                 let s =
                   Fiber.first
                     (fun () -> Some (Eio.Stream.take ctx.ready))
                     (fun () ->
                       ignore (Promise.await st.Core_conn.closed_p);
                       None)
                 in
                 match s with
                 | None -> `Stop_daemon
                 | Some s ->
                     Fiber.fork_daemon ~sw (fun () ->
                         (try handler s with
                         | Session_closed _ | Connection_closed _ -> ());
                         `Stop_daemon);
                     loop ()
               in
               loop ());
           Some st))

  let connect ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ?origin
      ?(headers = []) ?server_name ?fc ~peer ~authority ~path () =
    let sock =
      Eio.Net.datagram_socket ~sw net (`Udp (Eio.Net.Ipaddr.V4.any, 0))
    in
    let local = ("\000\000\000\000", 0) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    let scid = random_scid () in
    match B.connect cfg ~server_name ~scid ~peer ~local ~now:(now_ns ()) with
    | Error e -> failwith ("connect: " ^ e)
    | Ok h ->
        let st = Core_conn.mk ~sock_send ~now_ns ~sleep_until_ns in
        Core_conn.install_backend (module B) h st ~local;
        let eng = Engine.create ~role:`Client ?fc (Engine.C ((module B), h)) in
        let ctx =
          {
            c_st = st;
            c_eng = eng;
            sessions = Hashtbl.create 1;
            ready = Eio.Stream.create max_int;
            client_r = None;
            accept_cb = (fun _ -> `Accept);
          }
        in
        install_wt_drain ctx;
        let p, r = Promise.create () in
        ctx.client_r <- Some r;
        client_recv_loop ~sw ~sock st ~local;
        Core_conn.pump ~sw st ~on_dead:(fun () -> ());
        Core_conn.command st (fun () ->
            Engine.connect_session eng ?origin ~headers ~authority ~path ());
        let result =
          Fiber.first
            (fun () -> Promise.await p)
            (fun () ->
              Error (Connection_closed (Promise.await st.Core_conn.closed_p)))
        in
        (match result with Ok s -> s | Error e -> raise e)
end
