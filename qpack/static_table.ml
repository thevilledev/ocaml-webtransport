(* The QPACK static table (RFC 9204, appendix A), plus lookup maps for
   encoding. With the dynamic table disabled, this is the whole of QPACK
   header compression. *)

let entries = Static_table_data.entries
let size = Array.length entries
let get i = if i >= 0 && i < size then Some entries.(i) else None

let exact_tbl =
  lazy
    (let h = Hashtbl.create 128 in
     Array.iteri
       (fun i (n, v) -> if not (Hashtbl.mem h (n, v)) then Hashtbl.add h (n, v) i)
       entries;
     h)

let name_tbl =
  lazy
    (let h = Hashtbl.create 128 in
     Array.iteri
       (fun i (n, _) -> if not (Hashtbl.mem h n) then Hashtbl.add h n i)
       entries;
     h)

let find_exact ~name ~value = Hashtbl.find_opt (Lazy.force exact_tbl) (name, value)
let find_name name = Hashtbl.find_opt (Lazy.force name_tbl) name
