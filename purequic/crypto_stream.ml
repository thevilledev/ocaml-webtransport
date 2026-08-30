(* Per-encryption-level CRYPTO stream state: receive-side offset
   reassembly and a retransmittable send buffer. *)

type t = {
  (* rx *)
  mutable rx_expected : int;
  mutable rx_stash : (int * string) list;  (* out-of-order chunks *)
  (* tx: all queued bytes, absolute offsets; [tx_pending] holds ranges not
     currently in flight (new data and loss requeues) *)
  tx_buf : Buffer.t;
  tx_pending : Ranges.t;
}

let create () =
  {
    rx_expected = 0;
    rx_stash = [];
    tx_buf = Buffer.create 256;
    tx_pending = Ranges.create ();
  }

(* cap on buffered out-of-order handshake bytes (hostile peers) *)
let max_stash_bytes = 1 lsl 20

let stash_size stash =
  List.fold_left (fun a (_, d) -> a + String.length d) 0 stash

(* Feed a received CRYPTO frame; [deliver] is called with each newly
   contiguous chunk, in order. Returns [Error] on overflow. *)
let recv t ~off data ~deliver =
  if off + String.length data <= t.rx_expected then Ok () (* pure re-tx *)
  else begin
    let stash = (off, data) :: t.rx_stash in
    if stash_size stash > max_stash_bytes then Error "crypto buffer overflow"
    else begin
      let rec go stash =
        match
          List.find_opt
            (fun (o, d) ->
              o <= t.rx_expected && o + String.length d > t.rx_expected)
            stash
        with
        | Some ((o, d) as entry) ->
            let skip = t.rx_expected - o in
            let fresh = String.sub d skip (String.length d - skip) in
            t.rx_expected <- t.rx_expected + String.length fresh;
            deliver fresh;
            go (List.filter (fun e -> e != entry) stash)
        | None -> stash
      in
      t.rx_stash <-
        go
          (List.filter
             (fun (o, d) -> o + String.length d > t.rx_expected)
             stash);
      Ok ()
    end
  end

(* ---- tx ---- *)

let send t data =
  if String.length data > 0 then begin
    let lo = Buffer.length t.tx_buf in
    Buffer.add_string t.tx_buf data;
    Ranges.insert t.tx_pending ~lo ~hi:(Buffer.length t.tx_buf - 1)
  end

let has_pending t = not (Ranges.is_empty t.tx_pending)

(* Take up to [max] contiguous pending bytes; returns (off, data). *)
let take t ~max =
  match Ranges.smallest t.tx_pending with
  | None -> None
  | Some lo ->
      let hi_bound = Ranges.next_gap t.tx_pending lo - 1 in
      let hi = min hi_bound (lo + max - 1) in
      if hi < lo then None
      else begin
        Ranges.drop_below t.tx_pending (hi + 1);
        (* drop_below removes everything < hi+1 including other low spans:
           next_gap guarantees [lo..hi] is the lowest contiguous span, so
           nothing below it exists and this is exact *)
        Some (lo, Buffer.sub t.tx_buf lo (hi - lo + 1))
      end

(* Loss: requeue a byte range for retransmission. *)
let requeue t ~lo ~hi =
  if hi >= lo && lo < Buffer.length t.tx_buf then
    Ranges.insert t.tx_pending ~lo ~hi:(min hi (Buffer.length t.tx_buf - 1))
