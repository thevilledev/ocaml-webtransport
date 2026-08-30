(* Sorted, disjoint, inclusive integer interval sets.

   Shared by ACK tracking (received packet numbers), stream/CRYPTO
   reassembly (received byte ranges) and retransmission bookkeeping.
   Stored as a descending-sorted list of [(lo, hi)] pairs; QUIC keeps these
   sets small (ACK frames carry a few dozen ranges at most, reassembly gaps
   are short-lived), so list operations are fine. *)

type t = { mutable spans : (int * int) list (* descending by [lo] *) }

let create () = { spans = [] }
let is_empty t = t.spans = []

(* Insert [lo..hi] (inclusive), merging with any overlapping or adjacent
   spans. *)
let insert t ~lo ~hi =
  if lo > hi then invalid_arg "Ranges.insert: lo > hi";
  let rec go = function
    | [] -> [ (lo, hi) ]
    | (l, h) :: rest when lo > h + 1 -> (lo, hi) :: (l, h) :: rest
    | (l, h) :: rest when hi + 1 < l -> (l, h) :: go rest
    | (l, h) :: rest ->
        (* overlap or adjacency: merge and keep merging leftward *)
        let merged_lo = min lo l and merged_hi = max hi h in
        merge merged_lo merged_hi rest
  and merge mlo mhi = function
    | (l, h) :: rest when mlo <= h + 1 -> merge (min mlo l) (max mhi h) rest
    | rest -> (mlo, mhi) :: rest
  in
  t.spans <- go t.spans

let contains t v =
  List.exists (fun (l, h) -> l <= v && v <= h) t.spans

let largest t = match t.spans with [] -> None | (_, h) :: _ -> Some h

let smallest t =
  match t.spans with
  | [] -> None
  | spans ->
      let rec last = function [ (l, _) ] -> l | _ :: r -> last r | [] -> 0 in
      Some (last spans)

(* Remove everything strictly below [v]. *)
let drop_below t v =
  t.spans <-
    List.filter_map
      (fun (l, h) -> if h < v then None else Some (max l v, h))
      t.spans

(* First gap at or above [v]: the smallest integer >= [v] not in the set.
   Used by reassembly to find the read watermark. *)
let next_gap t v =
  let rec go acc = function
    | [] -> acc
    | (l, h) :: rest -> if l <= acc && acc <= h then go (h + 1) rest else go acc rest
  in
  (* spans are descending; scan from the smallest upward *)
  go v (List.rev t.spans)

(* Descending iteration, as ACK frames want. *)
let iter_desc t f = List.iter (fun (l, h) -> f ~lo:l ~hi:h) t.spans
let to_list_desc t = t.spans
let cardinal_spans t = List.length t.spans
