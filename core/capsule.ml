(* Capsule protocol (RFC 9297): the byte stream on a CONNECT request stream
   after the HEADERS, carrying WebTransport session signals. *)

(* Anything bigger is nonsense for the capsule types we speak. *)
let max_capsule_len = 1 lsl 20

type parser = { mutable data : string; mutable pos : int }

let create_parser () = { data = ""; pos = 0 }

let feed p chunk =
  if chunk <> "" then
    if p.pos = 0 then p.data <- p.data ^ chunk
    else begin
      p.data <- String.sub p.data p.pos (String.length p.data - p.pos) ^ chunk;
      p.pos <- 0
    end

let next p =
  match Varint.get_string p.data ~pos:p.pos with
  | None -> `Need_more
  | Some (ty, pos) -> (
      match Varint.get_string p.data ~pos with
      | None -> `Need_more
      | Some (len, pos) ->
          if len > max_capsule_len then `Error "capsule too large"
          else if String.length p.data - pos < len then `Need_more
          else begin
            let payload = String.sub p.data pos len in
            p.pos <- pos + len;
            `Capsule (ty, payload)
          end)

let encode ty payload =
  let buf = Buffer.create (16 + String.length payload) in
  Varint.add_buffer buf ty;
  Varint.add_buffer buf (String.length payload);
  Buffer.add_string buf payload;
  Buffer.contents buf

(* WT_CLOSE_SESSION: u32 application error code + UTF-8 message <= 1024B. *)
let encode_close ~code ~message =
  if code < 0 || code > 0xffff_ffff then invalid_arg "close code must be a u32";
  if String.length message > 1024 then invalid_arg "close message > 1024 bytes";
  let payload = Bytes.create (4 + String.length message) in
  Bytes.set_uint8 payload 0 ((code lsr 24) land 0xff);
  Bytes.set_uint8 payload 1 ((code lsr 16) land 0xff);
  Bytes.set_uint8 payload 2 ((code lsr 8) land 0xff);
  Bytes.set_uint8 payload 3 (code land 0xff);
  Bytes.blit_string message 0 payload 4 (String.length message);
  encode Wire.Capsule_type.wt_close_session (Bytes.to_string payload)

let decode_close payload =
  let n = String.length payload in
  if n < 4 then Error "WT_CLOSE_SESSION shorter than 4 bytes"
  else if n > 4 + 1024 then Error "WT_CLOSE_SESSION message > 1024 bytes"
  else
    let b i = Char.code payload.[i] in
    let code = (b 0 lsl 24) lor (b 1 lsl 16) lor (b 2 lsl 8) lor b 3 in
    Ok (code, String.sub payload 4 (n - 4))

let encode_drain () = encode Wire.Capsule_type.wt_drain_session ""

let encode_varint_capsule ty v =
  let buf = Buffer.create 16 in
  Varint.add_buffer buf v;
  encode ty (Buffer.contents buf)

let encode_max_data v = encode_varint_capsule Wire.Capsule_type.wt_max_data v

let encode_max_streams ~dir v =
  let ty =
    match dir with
    | `Bidi -> Wire.Capsule_type.wt_max_streams_bidi
    | `Uni -> Wire.Capsule_type.wt_max_streams_uni
  in
  encode_varint_capsule ty v

let decode_varint_capsule payload =
  match Varint.get_string payload ~pos:0 with
  | Some (v, pos) when pos = String.length payload -> Ok v
  | _ -> Error "malformed varint capsule"
