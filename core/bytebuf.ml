(* A tiny consume-from-the-front byte accumulator for incremental parsers on
   the control plane. *)

type t = { mutable data : string; mutable pos : int }

let create () = { data = ""; pos = 0 }

let add t chunk =
  if chunk <> "" then
    if t.pos = 0 then t.data <- t.data ^ chunk
    else begin
      t.data <- String.sub t.data t.pos (String.length t.data - t.pos) ^ chunk;
      t.pos <- 0
    end

let length t = String.length t.data - t.pos
let advance t n = t.pos <- t.pos + n

(* Unconsumed view; parse with [pos] as the starting offset in [data]. *)
let view t = (t.data, t.pos)

let take t n =
  let s = String.sub t.data t.pos n in
  advance t n;
  s

let take_all t =
  let s = String.sub t.data t.pos (length t) in
  t.data <- "";
  t.pos <- 0;
  s

let get_varint t =
  match Varint.get_string t.data ~pos:t.pos with
  | Some (v, pos') ->
      t.pos <- pos';
      Some v
  | None -> None
