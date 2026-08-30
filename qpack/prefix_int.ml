(* HPACK/QPACK N-bit prefix integers (RFC 7541, section 5.1). *)

(* Reads the integer whose prefix occupies the low [prefix] bits of
   [s.[pos]]; returns (value, next_pos), or [None] on truncation/overflow. *)
let decode s ~pos ~prefix =
  let len = String.length s in
  if pos >= len then None
  else
    let mask = (1 lsl prefix) - 1 in
    let first = Char.code s.[pos] land mask in
    if first < mask then Some (first, pos + 1)
    else
      let rec loop v shift p =
        if p >= len || shift > 56 then None
        else
          let b = Char.code s.[p] in
          let v = v + ((b land 0x7f) lsl shift) in
          if b land 0x80 = 0 then Some (v, p + 1)
          else loop v (shift + 7) (p + 1)
      in
      loop mask 0 (pos + 1)

(* Writes [v] with [high_bits] set in the bits above the prefix. *)
let encode buf ~prefix ~high_bits v =
  let mask = (1 lsl prefix) - 1 in
  if v < mask then Buffer.add_char buf (Char.chr (high_bits lor v))
  else begin
    Buffer.add_char buf (Char.chr (high_bits lor mask));
    let v = ref (v - mask) in
    while !v >= 0x80 do
      Buffer.add_char buf (Char.chr (0x80 lor (!v land 0x7f)));
      v := !v lsr 7
    done;
    Buffer.add_char buf (Char.chr !v)
  end
