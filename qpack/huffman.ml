(* Huffman decoding for HPACK/QPACK string literals (RFC 7541, section 5.2
   and appendix B). Decode-only: this stack always emits raw literals, but
   browsers Huffman-encode, so decoding is mandatory. *)

type child = Empty | Node of node | Leaf of int
and node = { mutable zero : child; mutable one : child }

let build () =
  let root = { zero = Empty; one = Empty } in
  Array.iteri
    (fun sym code ->
      let len = Huffman_table.lengths.(sym) in
      let n = ref root in
      for i = len - 1 downto 0 do
        let bit = (code lsr i) land 1 in
        if i = 0 then
          if bit = 0 then !n.zero <- Leaf sym else !n.one <- Leaf sym
        else begin
          let next =
            match if bit = 0 then !n.zero else !n.one with
            | Node m -> m
            | Empty ->
                let m = { zero = Empty; one = Empty } in
                if bit = 0 then !n.zero <- Node m else !n.one <- Node m;
                m
            | Leaf _ -> assert false (* the code is prefix-free *)
          in
          n := next
        end
      done)
    Huffman_table.codes;
  root

let tree = lazy (build ())

exception Bad of string

let decode s =
  let root = Lazy.force tree in
  let out = Buffer.create (String.length s * 8 / 5) in
  let node = ref root in
  let depth = ref 0 in
  (* bits since the last completed symbol *)
  let ones = ref true in
  try
    String.iter
      (fun c ->
        let b = Char.code c in
        for i = 7 downto 0 do
          let bit = (b lsr i) land 1 in
          incr depth;
          if bit = 0 then ones := false;
          match if bit = 0 then !node.zero else !node.one with
          | Empty -> raise (Bad "invalid Huffman code")
          | Leaf 256 -> raise (Bad "EOS inside Huffman string")
          | Leaf sym ->
              Buffer.add_char out (Char.chr sym);
              node := root;
              depth := 0;
              ones := true
          | Node n -> node := n
        done)
      s;
    (* Trailing padding must be a strict prefix of EOS: all ones, < 8 bits. *)
    if !depth > 7 then raise (Bad "Huffman padding longer than 7 bits");
    if !depth > 0 && not !ones then raise (Bad "invalid Huffman padding");
    Ok (Buffer.contents out)
  with Bad m -> Error m
