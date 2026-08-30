(* Bounds-checked cursor over a Bigstringaf slice, and byte putters.

   Readers return [None] on underflow instead of raising: packet and frame
   parsers must be total on hostile input. *)

type reader = { buf : Bigstringaf.t; mutable pos : int; limit : int }

let reader buf ~off ~len = { buf; pos = off; limit = off + len }
let remaining r = r.limit - r.pos
let pos r = r.pos

let u8 r =
  if remaining r < 1 then None
  else begin
    let v = Char.code (Bigstringaf.get r.buf r.pos) in
    r.pos <- r.pos + 1;
    Some v
  end

let u16 r =
  if remaining r < 2 then None
  else begin
    let v = Bigstringaf.get_int16_be r.buf r.pos in
    r.pos <- r.pos + 2;
    Some v
  end

let u32 r =
  if remaining r < 4 then None
  else begin
    let v = Bigstringaf.get_int32_be r.buf r.pos in
    r.pos <- r.pos + 4;
    Some v
  end

let varint r =
  match Varint.get r.buf ~off:r.pos ~len:(remaining r) with
  | Some (v, n) ->
      r.pos <- r.pos + n;
      Some v
  | None -> None

(* [n] bytes as a string (copies; use for short control data like CIDs). *)
let bytes r n =
  if n < 0 || remaining r < n then None
  else begin
    let s = Bigstringaf.substring r.buf ~off:r.pos ~len:n in
    r.pos <- r.pos + n;
    Some s
  end

(* [n] bytes as a zero-copy slice view. *)
let slice r n =
  if n < 0 || remaining r < n then None
  else begin
    let off = r.pos in
    r.pos <- r.pos + n;
    Some (off, n)
  end

let skip r n =
  if n < 0 || remaining r < n then None
  else begin
    r.pos <- r.pos + n;
    Some ()
  end

(* ---- putters (unchecked: callers size their buffers) ---- *)

let put_u8 buf ~off v =
  Bigstringaf.set buf off (Char.chr (v land 0xff));
  off + 1

let put_u32 buf ~off v =
  Bigstringaf.set_int32_be buf off v;
  off + 4

let put_string buf ~off s =
  Bigstringaf.blit_from_string s ~src_off:0 buf ~dst_off:off
    ~len:(String.length s);
  off + String.length s

let put_varint buf ~off v = off + Varint.put buf ~off v
