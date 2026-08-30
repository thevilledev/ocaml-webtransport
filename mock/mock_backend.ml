(* A deterministic in-memory Quic_backend.S for engine and driver tests.

   Tests act as "the peer": they inject handshake completion, streams, bytes
   and datagrams, and inspect what the engine wrote. No packets, no clocks,
   no loss — pure logic. *)

module Qb = Webtransport.Quic_backend
module Bytebuf = Webtransport.Bytebuf

module Impl = struct
  type addr = string * int
  type dir = [ `Uni | `Bidi ]

  type stream = {
    rdata : Bytebuf.t;  (* peer -> engine *)
    mutable rfin : bool;
    sdata : Buffer.t;  (* engine -> peer *)
    mutable sfin : bool;
    mutable send_blocked : bool;
  }

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
    role : [ `Client | `Server ];
    streams : (int, stream) Hashtbl.t;
    events : event Queue.t;
    dgrams_in : string Queue.t;
    dgrams_out : string Queue.t;
    resets : (int, int) Hashtbl.t;  (* our RESET_STREAM: id -> code *)
    stops : (int, int) Hashtbl.t;  (* our STOP_SENDING: id -> code *)
    mutable established : bool;
    mutable closed : bool;
    mutable close_info : (bool * int * string) option;
    mutable next_bidi : int;
    mutable next_uni : int;
  }

  type config = [ `Client | `Server ]

  let config ~role ~alpn:_ ?cert_chain_pem_file:_ ?priv_key_pem_file:_
      ?verify:_ ?enable_datagrams:_ ?initial_max_data:_
      ?initial_max_stream_data:_ ?initial_max_streams_bidi:_
      ?initial_max_streams_uni:_ ?max_idle_ns:_ ?max_udp_payload:_ () =
    Ok role

  type header = {
    version : int32;
    dcid : string;
    scid : string;
    is_long : bool;
    is_initial : bool;
  }

  let parse_header _ ~off:_ ~len:_ = Error "mock backend has no packets"
  let negotiate_version ~scid:_ ~dcid:_ _ = Error "mock backend has no packets"

  let make role =
    {
      role;
      streams = Hashtbl.create 16;
      events = Queue.create ();
      dgrams_in = Queue.create ();
      dgrams_out = Queue.create ();
      resets = Hashtbl.create 4;
      stops = Hashtbl.create 4;
      established = false;
      closed = false;
      close_info = None;
      next_bidi = (match role with `Client -> 0 | `Server -> 1);
      next_uni = (match role with `Client -> 2 | `Server -> 3);
    }

  let connect role ~server_name:_ ~scid:_ ~peer:_ ~local:_ ~now:_ =
    Ok (make role)

  let accept role ~scid:_ ~peer:_ ~local:_ ~now:_ = Ok (make role)

  let close t ~app ~code ~reason =
    if not t.closed then begin
      t.closed <- true;
      t.close_info <- Some (app, code, reason);
      Queue.add (Closed { local = true; app; code; reason }) t.events
    end

  let is_established t = t.established
  let is_closed t = t.closed
  let recv _ ~now:_ _ ~off:_ ~len:_ ~from:_ ~to_:_ = Error "mock: no packets"
  let send _ ~now:_ _ = `Done
  let next_timeout_ns _ = None
  let on_timeout _ ~now:_ = ()
  let next_event t = Queue.take_opt t.events

  type 'a rw =
    ( 'a,
      [ `Would_block | `Fin | `Reset of int | `Stopped of int | `Invalid ] )
    result

  let stream t id =
    match Hashtbl.find_opt t.streams id with
    | Some s -> s
    | None ->
        let s =
          {
            rdata = Bytebuf.create ();
            rfin = false;
            sdata = Buffer.create 64;
            sfin = false;
            send_blocked = false;
          }
        in
        Hashtbl.add t.streams id s;
        s

  let open_stream t ~dir =
    let id =
      match dir with
      | `Bidi ->
          let id = t.next_bidi in
          t.next_bidi <- id + 4;
          id
      | `Uni ->
          let id = t.next_uni in
          t.next_uni <- id + 4;
          id
    in
    ignore (stream t id);
    Ok id

  let stream_recv t ~id buf ~off ~len =
    let s = stream t id in
    let avail = Bytebuf.length s.rdata in
    if avail = 0 then if s.rfin then Error `Fin else Error `Would_block
    else begin
      let n = min avail len in
      let chunk = Bytebuf.take s.rdata n in
      Bigstringaf.blit_from_string chunk ~src_off:0 buf ~dst_off:off ~len:n;
      Ok (n, s.rfin && Bytebuf.length s.rdata = 0)
    end

  let stream_send t ~id buf ~off ~len ~fin =
    let s = stream t id in
    if s.send_blocked then Error `Would_block
    else begin
      Buffer.add_string s.sdata (Bigstringaf.substring buf ~off ~len);
      if fin then s.sfin <- true;
      Ok len
    end

  let stream_capacity t ~id =
    let s = stream t id in
    if s.send_blocked then Ok 0 else Ok 1_000_000

  let stream_finish t ~id =
    let s = stream t id in
    s.sfin <- true;
    Ok ()

  let stream_reset t ~id ~code =
    Hashtbl.replace t.resets id code;
    Ok ()

  let stream_stop_sending t ~id ~code =
    Hashtbl.replace t.stops id code;
    Ok ()

  let dgram_send t buf ~off ~len =
    Queue.add (Bigstringaf.substring buf ~off ~len) t.dgrams_out;
    Ok ()

  let dgram_recv t buf ~off =
    match Queue.take_opt t.dgrams_in with
    | None -> Error `Would_block
    | Some d ->
        Bigstringaf.blit_from_string d ~src_off:0 buf ~dst_off:off
          ~len:(String.length d);
        Ok (String.length d)

  let dgram_max_len _ = Some 1200
  let peer_cert_der _ = None

  (* ---- test-side controls ---- *)

  let establish t =
    t.established <- true;
    Queue.add (Handshake_done { alpn = Some "h3"; peer_max_dgram = Some 1200 })
      t.events

  let peer_open t ~id ~dir =
    ignore (stream t id);
    Queue.add (Stream_opened { id; dir }) t.events

  let peer_data t ~id ?(fin = false) data =
    let s = stream t id in
    Bytebuf.add s.rdata data;
    if fin then s.rfin <- true;
    Queue.add (Stream_readable id) t.events

  let peer_dgram t data =
    Queue.add data t.dgrams_in;
    Queue.add Datagram_readable t.events

  let sent t ~id = Buffer.contents (stream t id).sdata
  let sent_fin t ~id = (stream t id).sfin
  let reset_code t ~id = Hashtbl.find_opt t.resets id
  let stop_code t ~id = Hashtbl.find_opt t.stops id
  let sent_dgrams t = List.of_seq (Queue.to_seq t.dgrams_out)
  let block_sends t ~id v = (stream t id).send_blocked <- v
end

include Impl
module _ = (Impl : Qb.S)
