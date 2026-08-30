(* Per-stream send/receive state machines (RFC 9000 s.3), including the
   receive side of RESET_STREAM_AT (partial delivery up to the reliable
   size). Flow-control *limits* live in the connection; this module tracks
   per-stream offsets and credit. *)

type send = {
  buf : Buffer.t;  (* bytes from [base] upward *)
  mutable base : int;  (* absolute offset of buf.[0] after compaction *)
  pending : Ranges.t;  (* absolute byte ranges to (re)transmit *)
  acked : Ranges.t;
  mutable fin_queued : bool;
  mutable fin_pending : bool;  (* fin needs (re)transmission *)
  mutable fin_acked : bool;
  mutable reset : (int * int) option;  (* code, final_size *)
  mutable reset_reliable : int option;  (* RESET_STREAM_AT reliable size *)
  mutable reset_pending : bool;  (* RESET_STREAM needs (re)transmission *)
  mutable reset_acked : bool;
  mutable credit : int;  (* peer's MAX_STREAM_DATA for this stream *)
  mutable blocked : bool;  (* app saw `Would_block since last writable *)
}

type recv = {
  mutable chunks : (int * string) list;
  received : Ranges.t;
  mutable read_off : int;
  mutable highest : int;  (* largest offset+len seen, for flow accounting *)
  mutable final : int option;
  mutable rreset : (int * int) option;  (* code, final_size *)
  mutable reliable : int;  (* deliver below this even after reset *)
  mutable reset_delivered : bool;
  mutable fin_delivered : bool;
  mutable stop_sent : int option;
  mutable stop_pending : bool;  (* STOP_SENDING needs (re)transmission *)
  mutable credit : int;  (* MAX_STREAM_DATA we advertised *)
  mutable credit_dirty : bool;  (* re-advertise needed *)
}

type t = { id : int; send : send option; recv : recv option }

let mk_send ~credit =
  {
    buf = Buffer.create 256;
    base = 0;
    pending = Ranges.create ();
    acked = Ranges.create ();
    fin_queued = false;
    fin_pending = false;
    fin_acked = false;
    reset = None;
    reset_reliable = None;
    reset_pending = false;
    reset_acked = false;
    credit;
    blocked = false;
  }

let mk_recv ~credit =
  {
    chunks = [];
    received = Ranges.create ();
    read_off = 0;
    highest = 0;
    final = None;
    rreset = None;
    reliable = max_int;
    reset_delivered = false;
    fin_delivered = false;
    stop_sent = None;
    stop_pending = false;
    credit;
    credit_dirty = false;
  }

let create ~id ~send_credit ~recv_credit ~has_send ~has_recv =
  {
    id;
    send = (if has_send then Some (mk_send ~credit:send_credit) else None);
    recv = (if has_recv then Some (mk_recv ~credit:recv_credit) else None);
  }

(* ---- send side ---- *)

let send_end s = s.base + Buffer.length s.buf

(* Bytes the app may still queue against the peer's stream credit. *)
let send_capacity s =
  if s.reset <> None || s.fin_queued then 0 else max 0 (s.credit - send_end s)

let send_queue s data =
  let lo = send_end s in
  Buffer.add_string s.buf data;
  if String.length data > 0 then
    Ranges.insert s.pending ~lo ~hi:(lo + String.length data - 1)

let send_fin s =
  if not s.fin_queued then begin
    s.fin_queued <- true;
    s.fin_pending <- true
  end

let send_reset ?reliable s ~code =
  if s.reset = None then begin
    s.reset <- Some (code, send_end s);
    s.reset_reliable <- reliable;
    s.reset_pending <- true;
    (* only bytes below the reliable size (if any) still transmit *)
    match reliable with
    | None -> Ranges.drop_below s.pending max_int
    | Some r ->
        let keep = Ranges.create () in
        Ranges.iter_desc s.pending (fun ~lo ~hi ->
            if lo < r then Ranges.insert keep ~lo ~hi:(min hi (r - 1)));
        Ranges.drop_below s.pending max_int;
        Ranges.iter_desc keep (fun ~lo ~hi -> Ranges.insert s.pending ~lo ~hi)
  end

(* Transmittable data remains after a reliable reset, below its size. *)
let data_allowed s =
  match (s.reset, s.reset_reliable) with
  | None, _ -> true
  | Some _, Some _ -> true
  | Some _, None -> false

let has_send_pending s =
  s.reset_pending
  || (data_allowed s
     && ((not (Ranges.is_empty s.pending))
        || (s.reset = None && s.fin_pending && s.fin_queued)))

(* Next chunk to transmit: lowest pending contiguous range, clipped to
   [max]. Returns (off, data, fin). A pure-fin chunk has empty data. *)
let send_take s ~max =
  if not (data_allowed s) then None
  else
    match Ranges.smallest s.pending with
    | Some lo when max > 0 ->
        let hi_bound = Ranges.next_gap s.pending lo - 1 in
        let hi = min hi_bound (lo + max - 1) in
        Ranges.drop_below s.pending (hi + 1);
        let data = Buffer.sub s.buf (lo - s.base) (hi - lo + 1) in
        let fin =
          s.reset = None && s.fin_queued && s.fin_pending
          && hi + 1 = send_end s
          && Ranges.is_empty s.pending
        in
        if fin then s.fin_pending <- false;
        Some (lo, data, fin)
    | Some _ -> None
    | None ->
        if s.reset = None && s.fin_queued && s.fin_pending then begin
          s.fin_pending <- false;
          Some (send_end s, "", true)
        end
        else None

let send_on_acked s ~lo ~hi ~fin =
  if hi >= lo then Ranges.insert s.acked ~lo ~hi;
  if fin then s.fin_acked <- true;
  (* compact long acked prefixes *)
  let covered = Ranges.next_gap s.acked 0 in
  if covered - s.base >= 16_384 then begin
    let keep = Buffer.length s.buf - (covered - s.base) in
    let tail = Buffer.sub s.buf (covered - s.base) keep in
    Buffer.clear s.buf;
    Buffer.add_string s.buf tail;
    s.base <- covered
  end

let send_on_lost s ~lo ~hi ~fin =
  if data_allowed s then begin
    let hi =
      match s.reset_reliable with Some r -> min hi (r - 1) | None -> hi
    in
    if hi >= lo then begin
      (* requeue only what is not already acked *)
      let rec requeue lo =
        if lo <= hi then begin
          if Ranges.contains s.acked lo then requeue (Ranges.next_gap s.acked lo)
          else begin
            let stop = min hi (Ranges.next_gap s.pending lo - 1) in
            ignore stop;
            (* insert byte range up to next acked byte *)
            let rec upper x = if x < hi && not (Ranges.contains s.acked (x + 1)) then upper (x + 1) else x in
            let u = upper lo in
            Ranges.insert s.pending ~lo ~hi:u;
            requeue (u + 1)
          end
        end
      in
      requeue lo
    end;
    if fin && not s.fin_acked then s.fin_pending <- true
  end

let send_closed s =
  (match s.reset with Some _ -> s.reset_acked | None -> false)
  || (s.fin_acked && Ranges.next_gap s.acked 0 >= send_end s)

(* ---- receive side ---- *)

type recv_result = [ `Ok of bool (* newly readable *) | `Err of string ]

let recv_on_frame r ~off ~fin data : recv_result =
  let len = String.length data in
  let end_off = off + len in
  (* final size consistency (FINAL_SIZE_ERROR) *)
  let final_check =
    match r.final with
    | Some f when end_off > f -> Error "data beyond final size"
    | Some f when fin && f <> end_off -> Error "conflicting final sizes"
    | None when fin -> (
        if end_off < r.highest then Error "final below received data"
        else begin
          r.final <- Some end_off;
          Ok ()
        end)
    | _ -> Ok ()
  in
  match final_check with
  | Error e -> `Err e
  | Ok () ->
      r.highest <- max r.highest end_off;
      let before = Ranges.next_gap r.received r.read_off in
      if len > 0 && end_off > r.read_off then begin
        (* stash, trimmed below read_off *)
        let off, data =
          if off < r.read_off then
            (r.read_off, String.sub data (r.read_off - off) (end_off - r.read_off))
          else (off, data)
        in
        if not (Ranges.contains r.received off) || off + String.length data > Ranges.next_gap r.received off
        then r.chunks <- (off, data) :: r.chunks;
        Ranges.insert r.received ~lo:off ~hi:(off + String.length data - 1)
      end;
      let after = Ranges.next_gap r.received r.read_off in
      let newly_contiguous = after > before in
      let fin_now =
        match r.final with
        | Some f -> after >= f && not r.fin_delivered
        | None -> false
      in
      `Ok (newly_contiguous || fin_now)

let recv_on_reset r ~code ~final_size ~reliable : recv_result =
  match r.final with
  | Some f when f <> final_size -> `Err "reset final size conflict"
  | _ ->
      if final_size < r.highest then `Err "reset final below received"
      else begin
        r.final <- Some final_size;
        (match r.rreset with
        | None ->
            r.rreset <- Some (code, final_size);
            r.reliable <- reliable
        | Some _ ->
            (* multiple resets: reliable size may only shrink *)
            r.reliable <- min r.reliable reliable);
        if r.reliable <= r.read_off then r.chunks <- [];
        `Ok true
      end

(* Read into (buf, off, len): mirrors the seam's stream_recv results. *)
let recv_read r buf ~off ~len :
    (int * bool, [ `Would_block | `Fin | `Reset of int | `Invalid ]) result =
  match r.rreset with
  | Some (code, _) when r.read_off >= r.reliable || r.reset_delivered ->
      r.reset_delivered <- true;
      Error (`Reset code)
  | _ -> (
      let deliverable =
        let contig = Ranges.next_gap r.received r.read_off in
        let contig =
          match r.rreset with
          | Some _ -> min contig r.reliable
          | None -> contig
        in
        contig - r.read_off
      in
      if deliverable <= 0 then begin
        match (r.final, r.rreset) with
        | _, Some (code, _) ->
            r.reset_delivered <- true;
            Error (`Reset code)
        | Some f, None when r.read_off >= f ->
            r.fin_delivered <- true;
            Error `Fin
        | _ -> Error `Would_block
      end
      else begin
        let n = min deliverable len in
        (* copy out of the chunk list *)
        let copied = ref 0 in
        while !copied < n do
          let target = r.read_off + !copied in
          match
            List.find_opt
              (fun (o, d) -> o <= target && target < o + String.length d)
              r.chunks
          with
          | None -> (* invariant break *) copied := n
          | Some (o, d) ->
              let start = target - o in
              let avail = min (String.length d - start) (n - !copied) in
              Bigstringaf.blit_from_string d ~src_off:start buf
                ~dst_off:(off + !copied) ~len:avail;
              copied := !copied + avail
        done;
        r.read_off <- r.read_off + n;
        (* drop fully consumed chunks *)
        r.chunks <-
          List.filter
            (fun (o, d) -> o + String.length d > r.read_off)
            r.chunks;
        let fin =
          match r.final with
          | Some f when r.read_off >= f && r.rreset = None ->
              r.fin_delivered <- true;
              true
          | _ -> false
        in
        Ok (n, fin)
      end)

let recv_closed r =
  r.fin_delivered || r.reset_delivered
  || (match r.rreset with Some _ -> r.read_off >= r.reliable | None -> false)
