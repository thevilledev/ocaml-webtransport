(* Loss detection and congestion control (RFC 9002): packet + time
   thresholds, PTO with backoff, NewReno with persistent congestion.
   Written against RFC 9002 appendices A/B, with ocaml-quic's recovery
   as a behavioural reference (see THIRD_PARTY.md). All times are
   monotonic nanoseconds supplied by the caller. *)

let k_packet_threshold = 3
let k_granularity_ns = 1_000_000L (* 1 ms *)
let k_initial_rtt_ns = 333_000_000L
let mtu = 1200
let k_minimum_window = 2 * mtu
let initial_window = min (10 * mtu) (max (2 * mtu) 14720)

(* What to regenerate if a packet is declared lost. Control frames are
   re-derived from current state ([Rtx_flags]) rather than replayed. *)
type retx =
  | Rtx_crypto of { space : int; lo : int; hi : int }
  | Rtx_stream of { id : int; lo : int; hi : int; fin : bool }
  | Rtx_flags
  | Rtx_dgram

type sent = {
  pn : int;
  time_sent : int64;
  size : int;
  ack_eliciting : bool;
  in_flight : bool;
  retx : retx list;
}

type space = {
  mutable sent : sent list;  (* descending pn *)
  mutable largest_acked : int;  (* -1 = none *)
  mutable loss_time : int64 option;
  mutable last_ae_sent : int64 option;  (* for the PTO timer *)
}

let mk_space () =
  { sent = []; largest_acked = -1; loss_time = None; last_ae_sent = None }

type t = {
  mutable srtt : int64;
  mutable rttvar : int64;
  mutable min_rtt : int64;
  mutable has_rtt : bool;
  mutable pto_count : int;
  mutable cwnd : int;
  mutable ssthresh : int;
  mutable bytes_in_flight : int;
  mutable recovery_start : int64;  (* -1 = never *)
  mutable max_ack_delay_ns : int64;  (* peer's, application space *)
}

let create () =
  {
    srtt = k_initial_rtt_ns;
    rttvar = Int64.div k_initial_rtt_ns 2L;
    min_rtt = Int64.max_int;
    has_rtt = false;
    pto_count = 0;
    cwnd = initial_window;
    ssthresh = max_int;
    bytes_in_flight = 0;
    recovery_start = -1L;
    max_ack_delay_ns = 25_000_000L;
  }

let ( +^ ) = Int64.add
let ( -^ ) = Int64.sub

let on_sent t sp (s : sent) =
  sp.sent <- s :: sp.sent;
  if s.in_flight then t.bytes_in_flight <- t.bytes_in_flight + s.size;
  if s.ack_eliciting then sp.last_ae_sent <- Some s.time_sent

let can_send t ~size = t.bytes_in_flight + size <= t.cwnd

(* PTO duration for one space, without backoff. *)
let pto_base t ~is_app =
  let base = t.srtt +^ Int64.max (Int64.mul 4L t.rttvar) k_granularity_ns in
  if is_app then base +^ t.max_ack_delay_ns else base

let pto_backed_off t ~is_app =
  Int64.shift_left (pto_base t ~is_app) (min t.pto_count 20)

let loss_delay t =
  (* 9/8 * max(srtt, latest ~ srtt), floored at granularity *)
  let d = Int64.div (Int64.mul 9L t.srtt) 8L in
  Int64.max d k_granularity_ns

let update_rtt t ~latest ~ack_delay ~is_app =
  t.min_rtt <- Int64.min t.min_rtt latest;
  let ack_delay =
    if is_app then Int64.min ack_delay t.max_ack_delay_ns else 0L
  in
  let adjusted =
    if latest -^ ack_delay >= t.min_rtt then latest -^ ack_delay else latest
  in
  if not t.has_rtt then begin
    t.has_rtt <- true;
    t.srtt <- adjusted;
    t.rttvar <- Int64.div adjusted 2L
  end
  else begin
    let diff = Int64.abs (t.srtt -^ adjusted) in
    t.rttvar <- Int64.div (Int64.mul 3L t.rttvar +^ diff) 4L;
    t.srtt <- Int64.div (Int64.mul 7L t.srtt +^ adjusted) 8L
  end

let in_recovery t time_sent =
  t.recovery_start >= 0L && time_sent <= t.recovery_start

let on_congestion_event t ~now ~time_sent =
  if not (in_recovery t time_sent) then begin
    t.recovery_start <- now;
    t.ssthresh <- max (t.cwnd / 2) k_minimum_window;
    t.cwnd <- t.ssthresh
  end

let detect_persistent_congestion t ~lost =
  (* collapse only with an RTT sample and a lost span exceeding 3*PTO *)
  if t.has_rtt then begin
    let ae = List.filter (fun s -> s.ack_eliciting && s.in_flight) lost in
    match ae with
    | [] -> ()
    | _ ->
        let times = List.map (fun s -> s.time_sent) ae in
        let oldest = List.fold_left Int64.min Int64.max_int times in
        let newest = List.fold_left Int64.max Int64.min_int times in
        let duration =
          Int64.mul 3L (pto_base t ~is_app:true)
        in
        if newest -^ oldest >= duration then t.cwnd <- k_minimum_window
  end

(* Declare losses for one space given the current largest_acked; returns
   the lost packets and updates the space's loss_time. *)
let detect_losses t sp ~now =
  if sp.largest_acked < 0 then []
  else begin
    let delay = loss_delay t in
    let threshold_time = now -^ delay in
    let lost, kept, loss_time =
      List.fold_left
        (fun (lost, kept, lt) s ->
          if s.pn > sp.largest_acked then (lost, s :: kept, lt)
          else if
            s.pn <= sp.largest_acked - k_packet_threshold
            || s.time_sent <= threshold_time
          then (s :: lost, kept, lt)
          else
            (* still awaited: candidate for the loss timer *)
            let cand = s.time_sent +^ delay in
            let lt =
              match lt with None -> Some cand | Some x -> Some (Int64.min x cand)
            in
            (lost, s :: kept, lt))
        ([], [], None) sp.sent
    in
    sp.sent <- List.rev kept;
    sp.loss_time <- loss_time;
    List.iter
      (fun s ->
        if s.in_flight then t.bytes_in_flight <- t.bytes_in_flight - s.size)
      lost;
    (match
       List.fold_left
         (fun acc s ->
           if not s.in_flight then acc
           else
             match acc with
             | None -> Some s
             | Some m -> if s.time_sent > m.time_sent then Some s else acc)
         None lost
     with
    | Some newest -> on_congestion_event t ~now ~time_sent:newest.time_sent
    | None -> ());
    detect_persistent_congestion t ~lost;
    lost
  end

(* Process an ACK frame. Returns (newly_acked, lost). *)
let on_ack t sp ~largest ~ranges ~ack_delay_ns ~now ~is_app =
  let in_ranges pn = List.exists (fun (lo, hi) -> pn >= lo && pn <= hi) ranges in
  let newly_acked, kept =
    List.partition (fun s -> s.pn <= largest && in_ranges s.pn) sp.sent
  in
  if newly_acked = [] then ([], [])
  else begin
    sp.sent <- kept;
    sp.largest_acked <- max sp.largest_acked largest;
    (* RTT sample from the largest acked, if newly acked and ack-eliciting *)
    (match List.find_opt (fun s -> s.pn = largest) newly_acked with
    | Some s when s.ack_eliciting ->
        update_rtt t ~latest:(now -^ s.time_sent) ~ack_delay:ack_delay_ns
          ~is_app
    | _ -> ());
    let acked_bytes =
      List.fold_left
        (fun a s ->
          if s.in_flight then begin
            t.bytes_in_flight <- t.bytes_in_flight - s.size;
            a + s.size
          end
          else a)
        0 newly_acked
    in
    (* NewReno growth for bytes sent outside recovery *)
    (match
       List.find_opt
         (fun s -> s.in_flight && not (in_recovery t s.time_sent))
         newly_acked
     with
    | Some _ ->
        if t.cwnd < t.ssthresh then t.cwnd <- t.cwnd + acked_bytes
        else t.cwnd <- t.cwnd + (mtu * acked_bytes / t.cwnd)
    | None -> ());
    t.pto_count <- 0;
    let lost = detect_losses t sp ~now in
    (newly_acked, lost)
  end

(* Earliest timer for a space: loss time takes precedence over PTO. *)
let space_timer t sp ~is_app =
  match sp.loss_time with
  | Some lt -> Some lt
  | None -> (
      match sp.last_ae_sent with
      | Some ts when List.exists (fun s -> s.ack_eliciting) sp.sent ->
          Some (ts +^ pto_backed_off t ~is_app)
      | _ -> None)

let on_loss_timer t sp ~now = detect_losses t sp ~now

let on_pto t = t.pto_count <- t.pto_count + 1

(* Drop a whole space's accounting (key discard). *)
let discard_space t sp =
  List.iter
    (fun s ->
      if s.in_flight then t.bytes_in_flight <- t.bytes_in_flight - s.size)
    sp.sent;
  sp.sent <- [];
  sp.loss_time <- None;
  sp.last_ae_sent <- None
