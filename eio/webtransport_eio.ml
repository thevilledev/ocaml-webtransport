(* Eio driver for the webtransport stack.

   M1 exposes [Raw]: QUIC connections, raw streams and datagrams over a
   pluggable Quic_backend — no HTTP/3 yet. The HTTP/3 + WebTransport session
   layers (M2/M3) will reuse the same socket/pump machinery.

   Concurrency model (one QUIC connection):
   - one mutex guards the backend handle; every touch of the backend happens
     under it, followed by [service] (fire due timer, drain events, flush
     packets, broadcast progress);
   - a pump fiber owns timer deadlines: it sleeps until the next backend
     deadline (capped, and interruptible via [kick]) and services;
   - blocking user ops loop attempt-await-retry on the [progress] condition.
   The backend never blocks and never runs effects, so no backend call can
   suspend while the mutex is held mid-operation. *)

open Eio.Std
module Qb = Webtransport.Quic_backend

module Raw = struct
  type backend =
    | Backend :
        (module Qb.S with type t = 'c and type config = 'k) * 'k
        -> backend

  type close_info = { code : int; reason : string; remote : bool; app : bool }

  exception Connection_closed of close_info
  exception Stream_reset_by_peer of int
  exception Stream_stopped_by_peer of int

  type state = {
    mutex : Eio.Mutex.t;
    progress : Eio.Condition.t;
    kick : Eio.Condition.t;
    established_p : unit Promise.t;
    established_r : unit Promise.u;
    closed_p : close_info Promise.t;
    closed_r : close_info Promise.u;
    accept_q : int Eio.Stream.t;
    dgram_q : string Eio.Stream.t;
    dgram_cap : int;
    send_buf : Bigstringaf.t;
    wbuf : Bigstringaf.t;
    scratch : Bigstringaf.t;
    sock_send : dst:(string * int) -> Cstruct.t -> unit;
    now_ns : unit -> int64;
    sleep_until_ns : int64 -> unit;
    mutable dead : bool;
  }

  type conn =
    | Conn : {
        b : (module Qb.S with type t = 'c);
        h : 'c;
        st : state;
      } -> conn

  let state_of (Conn { st; _ }) = st

  let mk_state ~sock_send ~now_ns ~sleep_until_ns =
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
      accept_q = Eio.Stream.create max_int;
      dgram_q = Eio.Stream.create 1024;
      dgram_cap = 128;
      send_buf = Bigstringaf.create 1500;
      wbuf = Bigstringaf.create 16_384;
      scratch = Bigstringaf.create 65_536;
      sock_send;
      now_ns;
      sleep_until_ns;
      dead = false;
    }

  let closed_exn st =
    match Promise.peek st.closed_p with
    | Some ci -> Connection_closed ci
    | None ->
        Connection_closed { code = 0; reason = "closed"; remote = false; app = false }

  (* Must run under [st.mutex]. *)
  let service (Conn { b = (module B); h; st }) =
    (match B.next_timeout_ns h with
    | Some d when Int64.compare d 1_000_000L <= 0 ->
        B.on_timeout h ~now:(st.now_ns ())
    | _ -> ());
    let rec drain () =
      match B.next_event h with
      | None -> ()
      | Some e ->
          (match e with
          | B.Handshake_done _ ->
              if not (Promise.is_resolved st.established_p) then
                Promise.resolve st.established_r ()
          | B.Stream_opened { id; _ } -> Eio.Stream.add st.accept_q id
          | B.Datagram_readable ->
              let rec dloop () =
                match B.dgram_recv h st.scratch ~off:0 with
                | Ok n ->
                    let s = Bigstringaf.substring st.scratch ~off:0 ~len:n in
                    if Eio.Stream.length st.dgram_q >= st.dgram_cap then
                      ignore (Eio.Stream.take_nonblocking st.dgram_q);
                    Eio.Stream.add st.dgram_q s;
                    dloop ()
                | Error _ -> ()
              in
              dloop ()
          | B.Closed { code; reason; local; app } ->
              st.dead <- true;
              if not (Promise.is_resolved st.closed_p) then
                Promise.resolve st.closed_r
                  { code; reason; remote = not local; app }
          | B.Stream_readable _ | B.Stream_writable _ | B.Stream_credit
          | B.Stream_reset _ | B.Stream_stopped _ ->
              ());
          drain ()
    in
    drain ();
    let rec flush () =
      match B.send h ~now:(st.now_ns ()) st.send_buf with
      | `Packet (n, addr) ->
          st.sock_send ~dst:addr (Cstruct.of_bigarray ~off:0 ~len:n st.send_buf);
          flush ()
      | `Done -> ()
      | `Error _ -> () (* fatal conditions surface via the Closed event *)
    in
    flush ();
    Eio.Condition.broadcast st.progress

  let with_lock st f = Eio.Mutex.use_rw ~protect:false st.mutex f

  (* Under the mutex: retry [f] until it yields, waking on [progress]. *)
  let rec block_until st f =
    match f () with
    | Some v -> v
    | None ->
        if st.dead then raise (closed_exn st);
        Eio.Condition.await st.progress st.mutex;
        block_until st f

  let locked_op (Conn { st; _ } as c) f =
    let r =
      with_lock st (fun () ->
          let r = block_until st f in
          service c;
          r)
    in
    Eio.Condition.broadcast st.kick;
    r

  (* Feed one received UDP datagram into the connection. *)
  let feed (Conn { b = (module B); h; st } as c) buf ~len ~from ~local =
    with_lock st (fun () ->
        (match B.recv h ~now:(st.now_ns ()) buf ~off:0 ~len ~from ~to_:local with
        | Ok _ -> ()
        | Error _ -> () (* invalid packets are dropped, not fatal *));
        service c);
    Eio.Condition.broadcast st.kick

  let pump ~sw (Conn { b = (module B); h; st } as c) ~on_dead =
    Fiber.fork_daemon ~sw (fun () ->
        let rec loop () =
          let dead = with_lock st (fun () -> service c; st.dead) in
          if dead || B.is_closed h then begin
            with_lock st (fun () ->
                st.dead <- true;
                if not (Promise.is_resolved st.closed_p) then
                  Promise.resolve st.closed_r
                    { code = 0; reason = ""; remote = false; app = false };
                Eio.Condition.broadcast st.progress);
            on_dead ();
            `Stop_daemon
          end
          else begin
            let now = st.now_ns () in
            let deadline =
              match B.next_timeout_ns h with
              | Some dur -> Int64.add now dur
              | None -> Int64.add now 60_000_000_000L
            in
            let cap = Int64.add now 500_000_000L in
            let deadline = if Int64.compare deadline cap > 0 then cap else deadline in
            Fiber.first
              (fun () -> Eio.Condition.await_no_mutex st.kick)
              (fun () -> st.sleep_until_ns deadline);
            loop ()
          end
        in
        loop ())

  (* ---- user operations ---- *)

  let established (Conn { st; _ }) =
    Fiber.first
      (fun () -> Promise.await st.established_p)
      (fun () ->
        let ci = Promise.await st.closed_p in
        raise (Connection_closed ci))

  let closed c = Promise.await (state_of c).closed_p

  let accept_stream (Conn { st; _ }) =
    Fiber.first
      (fun () -> Eio.Stream.take st.accept_q)
      (fun () ->
        let ci = Promise.await st.closed_p in
        raise (Connection_closed ci))

  let open_stream (Conn { b = (module B); h; _ } as c) ~dir =
    locked_op c (fun () ->
        match B.open_stream h ~dir with
        | Ok id -> Some id
        | Error `Would_block -> None
        | Error _ -> invalid_arg "open_stream")

  let read (Conn { b = (module B); h; _ } as c) ~id buf ~off ~len =
    locked_op c (fun () ->
        match B.stream_recv h ~id buf ~off ~len with
        | Ok (n, fin) -> if n = 0 && fin then Some `Fin else Some (`Data n)
        | Error `Would_block -> None
        | Error `Fin -> Some `Fin
        | Error (`Reset code) -> raise (Stream_reset_by_peer code)
        | Error (`Stopped code) -> raise (Stream_stopped_by_peer code)
        | Error `Invalid -> invalid_arg "read: invalid stream")

  let write (Conn { b = (module B); h; st } as c) ~id data =
    let len = String.length data in
    let pos = ref 0 in
    while !pos < len do
      let n = min (len - !pos) (Bigstringaf.length st.wbuf) in
      Bigstringaf.blit_from_string data ~src_off:!pos st.wbuf ~dst_off:0 ~len:n;
      let wrote =
        locked_op c (fun () ->
            match B.stream_send h ~id st.wbuf ~off:0 ~len:n ~fin:false with
            | Ok 0 -> None
            | Ok w -> Some w
            | Error `Would_block -> None
            | Error (`Reset code) -> raise (Stream_reset_by_peer code)
            | Error (`Stopped code) -> raise (Stream_stopped_by_peer code)
            | Error `Fin | Error `Invalid -> invalid_arg "write: invalid stream")
      in
      pos := !pos + wrote
    done

  let finish (Conn { b = (module B); h; _ } as c) ~id =
    locked_op c (fun () ->
        match B.stream_finish h ~id with
        | Ok () -> Some ()
        | Error `Would_block -> None
        | Error _ -> invalid_arg "finish")

  let reset (Conn { b = (module B); h; _ } as c) ~id ~code =
    locked_op c (fun () ->
        match B.stream_reset h ~id ~code with
        | Ok () | Error _ -> Some ())

  let stop_sending (Conn { b = (module B); h; _ } as c) ~id ~code =
    locked_op c (fun () ->
        match B.stream_stop_sending h ~id ~code with
        | Ok () | Error _ -> Some ())

  let send_dgram (Conn { b = (module B); h; st } as c) data =
    let len = String.length data in
    if len > Bigstringaf.length st.wbuf then invalid_arg "datagram too large";
    locked_op c (fun () ->
        Bigstringaf.blit_from_string data ~src_off:0 st.wbuf ~dst_off:0 ~len;
        match B.dgram_send h st.wbuf ~off:0 ~len with
        | Ok () -> Some ()
        | Error `Would_block -> None
        | Error _ -> invalid_arg "send_dgram")

  let recv_dgram (Conn { st; _ }) =
    Fiber.first
      (fun () -> Eio.Stream.take st.dgram_q)
      (fun () ->
        let ci = Promise.await st.closed_p in
        raise (Connection_closed ci))

  let close (Conn { b = (module B); h; st } as c) ~code ~reason =
    with_lock st (fun () ->
        B.close h ~app:true ~code ~reason;
        service c);
    Eio.Condition.broadcast st.kick

  (* ---- endpoints ---- *)

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

  let listen ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ~port ~handler
      =
    let sock =
      Eio.Net.datagram_socket ~sw ~reuse_addr:true net
        (`Udp (Eio.Net.Ipaddr.V4.any, port))
    in
    let local = ("\000\000\000\000", port) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    let table : (string, conn) Hashtbl.t = Hashtbl.create 16 in
    Fiber.fork_daemon ~sw (fun () ->
        let rbuf = Bigstringaf.create 65_536 in
        let rcs = Cstruct.of_bigarray rbuf in
        let vn_buf = Bigstringaf.create 256 in
        let rec loop () =
          let addr, n = Eio.Net.recv sock rcs in
          let from = sockaddr_to_raw addr in
          (match B.parse_header rbuf ~off:0 ~len:n with
          | Error _ -> ()
          | Ok hdr -> (
              match Hashtbl.find_opt table hdr.B.dcid with
              | Some c -> feed c rbuf ~len:n ~from ~local
              | None ->
                  if hdr.B.is_long && hdr.B.version <> 1l then (
                    match
                      B.negotiate_version ~scid:hdr.B.scid ~dcid:hdr.B.dcid
                        vn_buf
                    with
                    | Ok vn ->
                        sock_send ~dst:from
                          (Cstruct.of_bigarray ~off:0 ~len:vn vn_buf)
                    | Error _ -> ())
                  else if hdr.B.is_initial then (
                    (* scid := client's dcid, so every later packet of this
                       connection demuxes through this single table entry. *)
                    match
                      B.accept cfg ~scid:hdr.B.dcid ~peer:from ~local
                        ~now:(now_ns ())
                    with
                    | Error _ -> ()
                    | Ok h ->
                        let st = mk_state ~sock_send ~now_ns ~sleep_until_ns in
                        let c = Conn { b = (module B); h; st } in
                        let key = hdr.B.dcid in
                        Hashtbl.add table key c;
                        pump ~sw c ~on_dead:(fun () -> Hashtbl.remove table key);
                        Fiber.fork_daemon ~sw (fun () ->
                            (try handler c with
                            | Connection_closed _ -> ()
                            | Stream_reset_by_peer _ | Stream_stopped_by_peer _
                              ->
                                ());
                            `Stop_daemon);
                        feed c rbuf ~len:n ~from ~local)))
          ;
          loop ()
        in
        loop ())

  let connect ~sw ~net ~clock ~backend:(Backend ((module B), cfg)) ?server_name
      ~peer () =
    let sock =
      Eio.Net.datagram_socket ~sw net (`Udp (Eio.Net.Ipaddr.V4.any, 0))
    in
    let local = ("\000\000\000\000", 0) in
    let now_ns, sleep_until_ns = make_clock_fns clock in
    let sock_send = make_sock_send sock in
    let scid = random_scid () in
    match
      B.connect cfg ~server_name ~scid ~peer ~local ~now:(now_ns ())
    with
    | Error e -> failwith ("connect: " ^ e)
    | Ok h ->
        let st = mk_state ~sock_send ~now_ns ~sleep_until_ns in
        let c = Conn { b = (module B); h; st } in
        (* Client packets arrive with dcid = our scid; single connection per
           socket, so just feed everything. *)
        Fiber.fork_daemon ~sw (fun () ->
            let rbuf = Bigstringaf.create 65_536 in
            let rcs = Cstruct.of_bigarray rbuf in
            let rec loop () =
              let addr, n = Eio.Net.recv sock rcs in
              let from = sockaddr_to_raw addr in
              feed c rbuf ~len:n ~from ~local;
              loop ()
            in
            loop ());
        pump ~sw c ~on_dead:(fun () -> ());
        with_lock st (fun () -> service c);
        Eio.Condition.broadcast st.kick;
        established c;
        c
end
