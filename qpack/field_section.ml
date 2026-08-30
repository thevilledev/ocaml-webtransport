(* QPACK encoded field sections, static-table-only (RFC 9204, section 4.5).

   This stack advertises QPACK_MAX_TABLE_CAPACITY = 0, which contractually
   forbids the peer from using the dynamic table; any dynamic reference is a
   protocol violation and decodes to [Error] (the connection should be closed
   with QPACK_DECOMPRESSION_FAILED). Encoding uses static-table references
   plus raw literals and never Huffman-encodes. *)

let ( let* ) = Result.bind

let read_string s ~pos ~prefix ~h_bit =
  if pos >= String.length s then Error "truncated string"
  else
    let huff = Char.code s.[pos] land h_bit <> 0 in
    match Prefix_int.decode s ~pos ~prefix with
    | None -> Error "bad string length"
    | Some (len, p) ->
        if p + len > String.length s then Error "truncated string"
        else
          let raw = String.sub s p len in
          let* v = if huff then Huffman.decode raw else Ok raw in
          Ok (v, p + len)

let decode s =
  let* ric, pos =
    match Prefix_int.decode s ~pos:0 ~prefix:8 with
    | Some r -> Ok r
    | None -> Error "truncated field section prefix"
  in
  let* () =
    if ric = 0 then Ok ()
    else Error "field section requires the dynamic table (RIC != 0)"
  in
  let* _base, pos =
    match Prefix_int.decode s ~pos ~prefix:7 with
    | Some r -> Ok r
    | None -> Error "truncated delta base"
  in
  let rec fields pos acc =
    if pos >= String.length s then Ok (List.rev acc)
    else
      let b = Char.code s.[pos] in
      if b land 0x80 <> 0 then
        (* Indexed Field Line: 1 T index(6+) *)
        if b land 0x40 = 0 then Error "indexed field references dynamic table"
        else
          let* idx, pos =
            match Prefix_int.decode s ~pos ~prefix:6 with
            | Some r -> Ok r
            | None -> Error "bad field index"
          in
          (match Static_table.get idx with
          | Some (n, v) -> fields pos ((n, v) :: acc)
          | None -> Error "static table index out of range")
      else if b land 0x40 <> 0 then
        (* Literal Field Line With Name Reference: 01 N T index(4+) *)
        if b land 0x10 = 0 then Error "name reference to dynamic table"
        else
          let* idx, pos =
            match Prefix_int.decode s ~pos ~prefix:4 with
            | Some r -> Ok r
            | None -> Error "bad name index"
          in
          let* name =
            match Static_table.get idx with
            | Some (n, _) -> Ok n
            | None -> Error "static table index out of range"
          in
          let* value, pos = read_string s ~pos ~prefix:7 ~h_bit:0x80 in
          fields pos ((name, value) :: acc)
      else if b land 0x20 <> 0 then
        (* Literal Field Line With Literal Name: 001 N H namelen(3+) *)
        let* name, pos = read_string s ~pos ~prefix:3 ~h_bit:0x08 in
        let* value, pos = read_string s ~pos ~prefix:7 ~h_bit:0x80 in
        fields pos ((name, value) :: acc)
      else Error "post-base reference (dynamic table required)"
  in
  fields pos []

let encode fields =
  let buf = Buffer.create 128 in
  (* Required Insert Count = 0, S = 0, Delta Base = 0. *)
  Buffer.add_char buf '\x00';
  Buffer.add_char buf '\x00';
  let add_value v =
    Prefix_int.encode buf ~prefix:7 ~high_bits:0x00 (String.length v);
    Buffer.add_string buf v
  in
  List.iter
    (fun (name, value) ->
      match Static_table.find_exact ~name ~value with
      | Some idx -> Prefix_int.encode buf ~prefix:6 ~high_bits:0xc0 idx
      | None -> (
          match Static_table.find_name name with
          | Some idx ->
              Prefix_int.encode buf ~prefix:4 ~high_bits:0x50 idx;
              add_value value
          | None ->
              Prefix_int.encode buf ~prefix:3 ~high_bits:0x20
                (String.length name);
              Buffer.add_string buf name;
              add_value value))
    fields;
  Buffer.contents buf
