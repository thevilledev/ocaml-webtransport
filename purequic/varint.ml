(* QUIC variable-length integers (RFC 9000, section 16).

   Same conventions as the webtransport core's Varint (of which this is a
   copy, kept separate so purequic has no dependency on webtransport):
   values are OCaml [int]s; the varint domain [0, 2^62-1] is exactly
   [0, max_int] on 64-bit platforms. 32-bit platforms are unsupported. *)

let max_value = (1 lsl 62) - 1

let size v =
  if v < 0 then invalid_arg "Varint.size: negative"
  else if v < 1 lsl 6 then 1
  else if v < 1 lsl 14 then 2
  else if v < 1 lsl 30 then 4
  else 8

let get buf ~off ~len =
  if len < 1 then None
  else
    let b0 = Char.code (Bigstringaf.get buf off) in
    let n = 1 lsl (b0 lsr 6) in
    if len < n then None
    else begin
      let v = ref (b0 land 0x3f) in
      for i = 1 to n - 1 do
        v := (!v lsl 8) lor Char.code (Bigstringaf.get buf (off + i))
      done;
      Some (!v, n)
    end

let put buf ~off v =
  if v < 0 || v > max_value then invalid_arg "Varint.put: out of range";
  let n = size v in
  let prefix = match n with 1 -> 0x00 | 2 -> 0x40 | 4 -> 0x80 | _ -> 0xc0 in
  for i = 0 to n - 1 do
    let byte = (v lsr (8 * (n - 1 - i))) land 0xff in
    let byte = if i = 0 then byte lor prefix else byte in
    Bigstringaf.set buf (off + i) (Char.chr byte)
  done;
  n

(* Encode with a forced width (2 for the Length field of long headers so the
   value can be backfilled after the payload is sealed, 4 when a peer requires
   room). [n] must be a legal varint size that fits [v]. *)
let put_width buf ~off ~width v =
  if v < 0 || v > max_value then invalid_arg "Varint.put_width: out of range";
  if size v > width then invalid_arg "Varint.put_width: value too wide";
  let prefix =
    match width with
    | 1 -> 0x00
    | 2 -> 0x40
    | 4 -> 0x80
    | 8 -> 0xc0
    | _ -> invalid_arg "Varint.put_width: bad width"
  in
  for i = 0 to width - 1 do
    let byte = (v lsr (8 * (width - 1 - i))) land 0xff in
    let byte = if i = 0 then byte lor prefix else byte in
    Bigstringaf.set buf (off + i) (Char.chr byte)
  done;
  width

let get_string s ~pos =
  let len = String.length s in
  if pos >= len then None
  else
    let b0 = Char.code s.[pos] in
    let n = 1 lsl (b0 lsr 6) in
    if len - pos < n then None
    else begin
      let v = ref (b0 land 0x3f) in
      for i = 1 to n - 1 do
        v := (!v lsl 8) lor Char.code s.[pos + i]
      done;
      Some (!v, pos + n)
    end

let add_buffer buf v =
  if v < 0 || v > max_value then invalid_arg "Varint.add_buffer: out of range";
  let n = size v in
  let prefix = match n with 1 -> 0x00 | 2 -> 0x40 | 4 -> 0x80 | _ -> 0xc0 in
  for i = 0 to n - 1 do
    let byte = (v lsr (8 * (n - 1 - i))) land 0xff in
    Buffer.add_char buf (Char.chr (if i = 0 then byte lor prefix else byte))
  done
