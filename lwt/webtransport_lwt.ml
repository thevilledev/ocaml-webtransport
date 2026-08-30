(* Lwt driver for the webtransport stack: the same engine and backend as the
   Eio driver, glued to Lwt_unix sockets, Lwt conditions and promises. All
   protocol logic lives in Webtransport.Engine; this file is IO plumbing.

   Single-Lwt-engine-thread assumption: engine/backend calls run atomically
   between yield points; no locks are needed. *)

open Lwt.Infix
module Qb = Webtransport.Quic_backend
module Engine = Webtransport.Engine

type backend =
  | Backend :
      (module Qb.S with type t = 'c and type config = 'k) * 'k
      -> backend

type close_info = { code : int; reason : string; remote : bool; app : bool }

exception Connection_closed of close_info
exception Session_closed of int * string
exception Session_rejected of int
exception Stream_reset_by_peer of int
exception Stream_stopped_by_peer of int

let rng = lazy (Random.State.make_self_init ())

let random_scid () =
  let st = Lazy.force rng in
  String.init 16 (fun _ -> Char.chr (Random.State.int st 256))

let raw_of_sockaddr = function
  | Unix.ADDR_INET (a, p) ->
      let ip =
        match Ipaddr_unix.of_inet_addr a with
        | Ipaddr.V4 v4 -> Ipaddr.V4.to_octets v4
        | Ipaddr.V6 v6 -> Ipaddr.V6.to_octets v6
      in
      (ip, p)
  | Unix.ADDR_UNIX _ -> invalid_arg "unix-domain datagram socket"

let sockaddr_of_raw (ip, p) =
  let addr =
    if String.length ip = 4 then Ipaddr.V4 (Ipaddr.V4.of_octets_exn ip)
    else Ipaddr.V6 (Ipaddr.V6.of_octets_exn ip)
  in
  Unix.ADDR_INET (Ipaddr_unix.to_inet_addr addr, p)

let now_ns () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())

module Core = struct
  type t = {
    progress : unit Lwt_condition.t;
    kick : unit Lwt_condition.t;
    closed_p : close_info Lwt.t;
    closed_r : close_info Lwt.u;
    send_buf : Bigstringaf.t;
    sock : Lwt_unix.file_descr;
    mutable dead : bool;
    mutable drain : unit -> unit;
    mutable fire_timeout : unit -> unit;
    mutable next_deadline : unit -> int64 option;
    mutable feed_pkt : Bigstringaf.t -> len:int -> from:(string * int) -> unit;
    mutable backend_closed : unit -> bool;
    mutable pending_sends : (int * (string * int)) list;  (* len, dst *)
  }

  let mk ~sock =
    let closed_p, closed_r = Lwt.wait () in
    {
      progress = Lwt_condition.create ();
      kick = Lwt_condition.create ();
      closed_p;
      closed_r;
      send_buf = Bigstringaf.create 1500;
      sock;
      dead = false;
      drain = (fun () -> ());
      fire_timeout = (fun () -> ());
      next_deadline = (fun () -> None);
      feed_pkt = (fun _ ~len:_ ~from:_ -> ());
      backend_closed = (fun () -> false);
      pending_sends = [];
    }

  let install_backend (type c) (module B : Qb.S with type t = c) (h : c) st
      ~local =
    st.fire_timeout <-
      (fun () ->
        match B.next_timeout_ns h with
        | Some d when Int64.compare d 1_000_000L <= 0 ->
            B.on_timeout h ~now:(now_ns ())
        | _ -> ());
    st.next_deadline <- (fun () -> B.next_timeout_ns h);
    st.backend_closed <- (fun () -> B.is_closed h);
    st.feed_pkt <-
      (fun buf ~len ~from ->
        match B.recv h ~now:(now_ns ()) buf ~off:0 ~len ~from ~to_:local with
        | Ok _ | Error _ -> ());
    (* Packet emission: collect synchronously (backend is not reentrant
       across yields mid-drain), then send asynchronously in [service]. *)
    st.drain <- (fun () -> ());
    ()

  (* Collects and sends every packet the backend has pending. *)
  let flush (type c) (module B : Qb.S with type t = c) (h : c) st =
    let rec go () =
      match B.send h ~now:(now_ns ()) st.send_buf with
      | `Packet (n, addr) ->
          let payload = Bigstringaf.substring st.send_buf ~off:0 ~len:n in
          let dst = sockaddr_of_raw addr in
          Lwt.catch
            (fun () ->
              Lwt_unix.sendto st.sock (Bytes.unsafe_of_string payload) 0 n []
                dst
              >|= fun _ -> ())
            (fun _ -> Lwt.return_unit)
          >>= go
      | `Done -> Lwt.return_unit
      | `Error _ -> Lwt.return_unit
    in
    go ()

  let closed_exn st =
    match Lwt.state st.closed_p with
    | Lwt.Return ci -> Connection_closed ci
    | _ ->
        Connection_closed
          { code = 0; reason = "closed"; remote = false; app = false }

  let mark_dead st ci =
    st.dead <- true;
    (match Lwt.state st.closed_p with
    | Lwt.Sleep -> Lwt.wakeup_later st.closed_r ci
    | _ -> ());
    Lwt_condition.broadcast st.progress ()
end

module Wt = struct
  type session = {
    sid : int;
    req : Engine.request;
    ctx : conn_ctx;
    s_closed_p : (int * string) Lwt.t;
    s_closed_r : (int * string) Lwt.u;
    dgrams : string Lwt_stream.t;
    push_dgram : string option -> unit;
    bidi_q : int Lwt_stream.t;
    push_bidi : int option -> unit;
    uni_q : int Lwt_stream.t;
    push_uni : int option -> unit;
  }

  and conn_ctx = {
    st : Core.t;
    eng : Engine.t;
    flush : unit -> unit Lwt.t;
    sessions : (int, session) Hashtbl.t;
    ready : session Lwt_stream.t;
    push_ready : session option -> unit;
    mutable client_r : (session, exn) result Lwt.u option;
    accept_cb : Engine.request -> [ `Accept | `Reject of int ];
  }

  let mk_session ctx sid =
    let req =
      match Engine.session_request ctx.eng ~sid with
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
    let s_closed_p, s_closed_r = Lwt.wait () in
    let dgrams, push_dgram = Lwt_stream.create () in
    let bidi_q, push_bidi = Lwt_stream.create () in
    let uni_q, push_uni = Lwt_stream.create () in
    {
      sid;
      req;
      ctx;
      s_closed_p;
      s_closed_r;
      dgrams;
      push_dgram;
      bidi_q;
      push_bidi;
      uni_q;
      push_uni;
    }

  let end_session_local s ~code ~message =
    match Lwt.state s.s_closed_p with
    | Lwt.Sleep -> Lwt.wakeup_later s.s_closed_r (code, message)
    | _ -> ()

  let dispatch ctx = function
    | Engine.Incoming_session { sid; req } -> (
        match ctx.accept_cb req with
        | `Accept -> Engine.accept_session ctx.eng ~sid
        | `Reject status -> Engine.reject_session ctx.eng ~sid ~status)
    | Engine.Session_established { sid } -> (
        let s = mk_session ctx sid in
        Hashtbl.replace ctx.sessions sid s;
        match ctx.client_r with
        | Some r ->
            ctx.client_r <- None;
            Lwt.wakeup_later r (Ok s)
        | None -> ctx.push_ready (Some s))
    | Engine.Session_rejected { status; _ } -> (
        match ctx.client_r with
        | Some r ->
            ctx.client_r <- None;
            Lwt.wakeup_later r (Error (Session_rejected status))
        | None -> ())
    | Engine.Session_peer_closed { sid; code; message; _ } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s ->
            Hashtbl.remove ctx.sessions sid;
            end_session_local s ~code ~message
        | None -> ())
    | Engine.Session_peer_drain _ -> ()
    | Engine.Wt_datagram { sid; payload } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s -> s.push_dgram (Some payload)
        | None -> ())
    | Engine.Wt_stream_opened { sid; stream_id; dir } -> (
        match Hashtbl.find_opt ctx.sessions sid with
        | Some s -> (
            match dir with
            | `Bidi -> s.push_bidi (Some stream_id)
            | `Uni -> s.push_uni (Some stream_id))
        | None -> ())
    | Engine.Wt_stream_readable _ | Engine.Wt_stream_writable _
    | Engine.Goaway ->
        ()
    | Engine.Conn_closed { code; reason; remote } ->
        Hashtbl.iter
          (fun _ s -> end_session_local s ~code:0 ~message:"connection closed")
          ctx.sessions;
        Hashtbl.reset ctx.sessions;
        Core.mark_dead ctx.st { code; reason; remote; app = true }

  (* Fire timers, run the engine, dispatch, flush packets, wake waiters. *)
  let service ctx =
    ctx.st.Core.fire_timeout ();
    List.iter (dispatch ctx) (Engine.process ctx.eng ~now:(now_ns ()));
    ctx.flush () >|= fun () ->
    Lwt_condition.broadcast ctx.st.Core.progress ()

  let command ctx f =
    let r = f () in
    service ctx >|= fun () ->
    Lwt_condition.broadcast ctx.st.Core.kick ();
    r

  let rec block_until ctx f =
    match f () with
    | Some v ->
        service ctx >|= fun () ->
        Lwt_condition.broadcast ctx.st.Core.kick ();
        v
    | None ->
        if ctx.st.Core.dead then Lwt.fail (Core.closed_exn ctx.st)
        else Lwt_condition.wait ctx.st.Core.progress >>= fun () ->
          block_until ctx f

  let rec pump ctx =
    service ctx >>= fun () ->
    if ctx.st.Core.dead || ctx.st.Core.backend_closed () then begin
      Core.mark_dead ctx.st { code = 0; reason = ""; remote = false; app = false };
      Lwt.return_unit
    end
    else begin
      let delay_s =
        match ctx.st.Core.next_deadline () with
        | Some ns -> min 0.5 (Int64.to_float ns /. 1e9)
        | None -> 0.5
      in
      Lwt.pick
        [ Lwt_unix.sleep delay_s; Lwt_condition.wait ctx.st.Core.kick ]
      >>= fun () -> pump ctx
    end

  let feed ctx buf ~len ~from =
    ctx.st.Core.feed_pkt buf ~len ~from;
    service ctx >|= fun () -> Lwt_condition.broadcast ctx.st.Core.kick ()

  (* ---- session + stream API ---- *)

  module Session = struct
    let path s = s.req.Engine.path
    let authority s = s.req.Engine.authority
    let request s = s.req

    let close ?(code = 0) ?(message = "") s =
      command s.ctx (fun () ->
          Engine.close_session s.ctx.eng ~sid:s.sid ~code ~message)
      >|= fun () -> end_session_local s ~code ~message

    let closed s = s.s_closed_p

    let send_datagram s payload =
      command s.ctx (fun () -> Engine.send_datagram s.ctx.eng ~sid:s.sid payload)

    let recv_datagram s =
      Lwt.pick
        [
          Lwt_stream.next s.dgrams;
          (s.s_closed_p >>= fun (c, m) -> Lwt.fail (Session_closed (c, m)));
        ]
  end

  module Stream = struct
    type t = { s : session; id : int }

    let id t = t.id

    let wt_code_of_h3 h3 =
      match Webtransport.Wt_error.of_h3 h3 with Some c -> c | None -> h3

    let read t buf ~off ~len =
      block_until t.s.ctx (fun () ->
          match Engine.read_attached t.s.ctx.eng ~id:t.id buf ~off ~len with
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
        read t buf ~off:0 ~len:16_384 >>= function
        | `Data n ->
            Buffer.add_string b (Bigstringaf.substring buf ~off:0 ~len:n);
            loop ()
        | `Fin -> Lwt.return (Buffer.contents b)
      in
      loop ()

    let high_watermark = 262_144

    let write t data =
      let len = String.length data in
      let rec go pos =
        if pos >= len then Lwt.return_unit
        else begin
          let chunk = min (len - pos) 16_384 in
          let piece = String.sub data pos chunk in
          block_until t.s.ctx (fun () ->
              if Engine.outbuf_len t.s.ctx.eng ~id:t.id > high_watermark then
                None
              else begin
                Engine.write_stream t.s.ctx.eng ~id:t.id piece;
                Some ()
              end)
          >>= fun () -> go (pos + chunk)
        end
      in
      go 0

    let close_write t =
      command t.s.ctx (fun () -> Engine.finish_stream t.s.ctx.eng ~id:t.id)

    let reset t ~code =
      command t.s.ctx (fun () ->
          Engine.reset_wt_stream t.s.ctx.eng ~id:t.id ~code)

    let stop_sending t ~code =
      command t.s.ctx (fun () ->
          Engine.stop_wt_stream t.s.ctx.eng ~id:t.id ~code)
  end

  let open_stream s ~dir =
    block_until s.ctx (fun () ->
        match Engine.open_wt_stream s.ctx.eng ~sid:s.sid ~dir with
        | Ok id -> Some id
        | Error `Would_block -> None
        | Error _ -> raise (Session_closed (0, "session not open")))
    >|= fun id -> { Stream.s; id }

  let open_bidi s = open_stream s ~dir:`Bidi
  let open_uni s = open_stream s ~dir:`Uni

  let accept_stream s q =
    Lwt.pick
      [
        (Lwt_stream.next q >|= fun id -> { Stream.s; id });
        (s.s_closed_p >>= fun (c, m) -> Lwt.fail (Session_closed (c, m)));
      ]

  let accept_bidi s = accept_stream s s.bidi_q
  let accept_uni s = accept_stream s s.uni_q

  (* ---- endpoints ---- *)

  let mk_ctx (type c k) (module B : Qb.S with type t = c and type config = k)
      (h : c) ~sock ~local ~role ~accept_cb ~fc =
    let st = Core.mk ~sock in
    Core.install_backend (module B) h st ~local;
    let eng = Engine.create ~role ?fc (Engine.C ((module B), h)) in
    let ready, push_ready = Lwt_stream.create () in
    let ctx =
      {
        st;
        eng;
        flush = (fun () -> Core.flush (module B) h st);
        sessions = Hashtbl.create 4;
        ready;
        push_ready;
        client_r = None;
        accept_cb;
      }
    in
    ctx

  let listen (type c k) ~backend:(Backend ((module B), cfg)) ~port
      ?(accept = fun _ -> `Accept) ?fc ~handler () =
    ignore (fun (x : c) -> x);
    ignore (fun (x : k) -> x);
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true;
    Lwt_unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, port))
    >>= fun () ->
    let local = ("\000\000\000\000", port) in
    let table : (string, conn_ctx) Hashtbl.t = Hashtbl.create 16 in
    let rbuf = Bigstringaf.create 65_536 in
    let rec loop () =
      Lwt_bytes.recvfrom sock rbuf 0 65_536 [] >>= fun (n, sockaddr) ->
      let from = raw_of_sockaddr sockaddr in
      (match B.parse_header rbuf ~off:0 ~len:n with
      | Error _ -> Lwt.return_unit
      | Ok hdr -> (
          match Hashtbl.find_opt table hdr.B.dcid with
          | Some ctx -> feed ctx rbuf ~len:n ~from
          | None ->
              if hdr.B.is_long && hdr.B.version <> 1l then (
                let vn = Bigstringaf.create 256 in
                match B.negotiate_version ~scid:hdr.B.scid ~dcid:hdr.B.dcid vn with
                | Ok len ->
                    Lwt_unix.sendto sock
                      (Bytes.unsafe_of_string
                         (Bigstringaf.substring vn ~off:0 ~len))
                      0 len [] sockaddr
                    >|= fun _ -> ()
                | Error _ -> Lwt.return_unit)
              else if hdr.B.is_initial then (
                let scid = random_scid () in
                match B.accept cfg ~scid ~peer:from ~local ~now:(now_ns ()) with
                | Error _ -> Lwt.return_unit
                | Ok h ->
                    let ctx =
                      mk_ctx (module B) h ~sock ~local ~role:`Server
                        ~accept_cb:accept ~fc
                    in
                    let dcid = hdr.B.dcid in
                    Hashtbl.add table dcid ctx;
                    Hashtbl.add table scid ctx;
                    Lwt.async (fun () ->
                        ctx.st.Core.closed_p >|= fun _ ->
                        Hashtbl.remove table dcid;
                        Hashtbl.remove table scid);
                    Lwt.async (fun () -> pump ctx);
                    Lwt.async (fun () ->
                        let rec accept_loop () =
                          Lwt.pick
                            [
                              (Lwt_stream.next ctx.ready >|= fun s -> Some s);
                              (ctx.st.Core.closed_p >|= fun _ -> None);
                            ]
                          >>= function
                          | None -> Lwt.return_unit
                          | Some s ->
                              Lwt.async (fun () ->
                                  Lwt.catch
                                    (fun () -> handler s)
                                    (fun _ -> Lwt.return_unit));
                              accept_loop ()
                        in
                        accept_loop ());
                    feed ctx rbuf ~len:n ~from)
              else Lwt.return_unit))
      >>= loop
    in
    loop ()

  let connect (type c k) ~backend:(Backend ((module B), cfg)) ?server_name
      ?origin ?(headers = []) ?fc ~peer ~authority ~path () =
    ignore (fun (x : c) -> x);
    ignore (fun (x : k) -> x);
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    Lwt_unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, 0)) >>= fun () ->
    let local = ("\000\000\000\000", 0) in
    let scid = random_scid () in
    match B.connect cfg ~server_name ~scid ~peer ~local ~now:(now_ns ()) with
    | Error e -> Lwt.fail_with ("connect: " ^ e)
    | Ok h ->
        let ctx =
          mk_ctx (module B) h ~sock ~local ~role:`Client
            ~accept_cb:(fun _ -> `Accept)
            ~fc
        in
        let p, r = Lwt.wait () in
        ctx.client_r <- Some r;
        let rbuf = Bigstringaf.create 65_536 in
        Lwt.async (fun () ->
            let rec loop () =
              Lwt_bytes.recvfrom sock rbuf 0 65_536 [] >>= fun (n, sockaddr) ->
              feed ctx rbuf ~len:n ~from:(raw_of_sockaddr sockaddr) >>= loop
            in
            loop ());
        Lwt.async (fun () -> pump ctx);
        command ctx (fun () ->
            Engine.connect_session ctx.eng ?origin ~headers ~authority ~path ())
        >>= fun () ->
        Lwt.pick
          [
            p;
            (ctx.st.Core.closed_p >|= fun ci -> Error (Connection_closed ci));
          ]
        >>= function
        | Ok s -> Lwt.return s
        | Error e -> Lwt.fail e
end
