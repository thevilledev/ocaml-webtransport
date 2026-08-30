(* QUIC v1 frames (RFC 9000 s.19), plus DATAGRAM (RFC 9221) and
   RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-10).

   Parsing is total; payloads are zero-copy views into the parse buffer,
   copied only at their sink. *)

type payload = { buf : Bigstringaf.t; off : int; len : int }

let payload_of_string s =
  { buf = Bigstringaf.of_string s ~off:0 ~len:(String.length s);
    off = 0;
    len = String.length s;
  }

let payload_to_string p = Bigstringaf.substring p.buf ~off:p.off ~len:p.len
let empty_payload = payload_of_string ""

type t =
  | Padding of int  (* run length *)
  | Ping
  | Ack of {
      largest : int;
      delay : int;  (* raw, pre-exponent *)
      ranges : (int * int) list;  (* (lo, hi) inclusive, descending *)
      ecn : (int * int * int) option;  (* ect0, ect1, ce *)
    }
  | Reset_stream of { id : int; code : int; final_size : int }
  | Stop_sending of { id : int; code : int }
  | Crypto of { off : int; data : payload }
  | New_token of { token : payload }
  | Stream of { id : int; off : int; fin : bool; data : payload }
  | Max_data of int
  | Max_stream_data of { id : int; max : int }
  | Max_streams_bidi of int
  | Max_streams_uni of int
  | Data_blocked of int
  | Stream_data_blocked of { id : int; max : int }
  | Streams_blocked_bidi of int
  | Streams_blocked_uni of int
  | New_connection_id of {
      seq : int;
      retire_prior_to : int;
      cid : string;
      reset_token : string;  (* 16 bytes *)
    }
  | Retire_connection_id of int
  | Path_challenge of string  (* 8 bytes *)
  | Path_response of string  (* 8 bytes *)
  | Connection_close of {
      app : bool;
      code : int;
      frame_type : int;  (* 0 for app closes *)
      reason : payload;
    }
  | Handshake_done
  | Datagram of { data : payload }
  | Reset_stream_at of {
      id : int;
      code : int;
      final_size : int;
      reliable_size : int;
    }

(* Everything except ACK, PADDING and CONNECTION_CLOSE (RFC 9002 s.2). *)
let is_ack_eliciting = function
  | Ack _ | Padding _ | Connection_close _ -> false
  | _ -> true

(* ---- parsing ---- *)

let ( let* ) o f = match o with Some v -> f v | None -> Error "underflow"

let parse_ack r ~ecn =
  let* largest = Wire.varint r in
  let* delay = Wire.varint r in
  let* count = Wire.varint r in
  let* first = Wire.varint r in
  if first > largest then Error "ack: bad first range"
  else begin
    let ranges = ref [ (largest - first, largest) ] in
    let smallest = ref (largest - first) in
    let rec go n =
      if n = 0 then Ok ()
      else
        let* gap = Wire.varint r in
        let* len = Wire.varint r in
        let hi = !smallest - gap - 2 in
        let lo = hi - len in
        if lo < 0 then Error "ack: negative range"
        else begin
          ranges := (lo, hi) :: !ranges;
          smallest := lo;
          go (n - 1)
        end
    in
    match go count with
    | Error e -> Error e
    | Ok () -> (
        let ecn_counts =
          if not ecn then Some None
          else begin
            let e0 = Wire.varint r in
            let e1 = Wire.varint r in
            let ce = Wire.varint r in
            match (e0, e1, ce) with
            | Some e0, Some e1, Some ce -> Some (Some (e0, e1, ce))
            | _ -> None
          end
        in
        match ecn_counts with
        | None -> Error "underflow"
        | Some ecn ->
            Ok (Ack { largest; delay; ranges = List.rev !ranges; ecn }))
  end

let parse_one (r : Wire.reader) =
  let* ftype = Wire.varint r in
  match ftype with
  | 0x00 ->
      (* coalesce the whole padding run *)
      let n = ref 1 in
      let continue = ref true in
      while !continue && Wire.remaining r > 0 do
        if Bigstringaf.get r.Wire.buf (Wire.pos r) = '\x00' then begin
          ignore (Wire.u8 r);
          incr n
        end
        else continue := false
      done;
      Ok (Padding !n)
  | 0x01 -> Ok Ping
  | 0x02 -> parse_ack r ~ecn:false
  | 0x03 -> parse_ack r ~ecn:true
  | 0x04 ->
      let* id = Wire.varint r in
      let* code = Wire.varint r in
      let* final_size = Wire.varint r in
      Ok (Reset_stream { id; code; final_size })
  | 0x05 ->
      let* id = Wire.varint r in
      let* code = Wire.varint r in
      Ok (Stop_sending { id; code })
  | 0x06 ->
      let* off = Wire.varint r in
      let* len = Wire.varint r in
      let* doff, dlen = Wire.slice r len in
      if dlen > Varint.max_value - off then Error "crypto: offset overflow"
      else
        Ok (Crypto { off; data = { buf = r.Wire.buf; off = doff; len = dlen } })
  | 0x07 ->
      let* len = Wire.varint r in
      if len = 0 then Error "new_token: empty"
      else
        let* toff, tlen = Wire.slice r len in
        Ok (New_token { token = { buf = r.Wire.buf; off = toff; len = tlen } })
  | t when t >= 0x08 && t <= 0x0f ->
      let has_off = t land 0x04 <> 0 in
      let has_len = t land 0x02 <> 0 in
      let fin = t land 0x01 <> 0 in
      let* id = Wire.varint r in
      let* off = if has_off then Wire.varint r else Some 0 in
      let* len = if has_len then Wire.varint r else Some (Wire.remaining r) in
      let* doff, dlen = Wire.slice r len in
      if dlen > Varint.max_value - off then Error "stream: offset overflow"
      else
        Ok
          (Stream
             { id; off; fin; data = { buf = r.Wire.buf; off = doff; len = dlen } })
  | 0x10 ->
      let* v = Wire.varint r in
      Ok (Max_data v)
  | 0x11 ->
      let* id = Wire.varint r in
      let* max = Wire.varint r in
      Ok (Max_stream_data { id; max })
  | 0x12 ->
      let* v = Wire.varint r in
      if v > 1 lsl 60 then Error "max_streams: too large" else Ok (Max_streams_bidi v)
  | 0x13 ->
      let* v = Wire.varint r in
      if v > 1 lsl 60 then Error "max_streams: too large" else Ok (Max_streams_uni v)
  | 0x14 ->
      let* v = Wire.varint r in
      Ok (Data_blocked v)
  | 0x15 ->
      let* id = Wire.varint r in
      let* max = Wire.varint r in
      Ok (Stream_data_blocked { id; max })
  | 0x16 ->
      let* v = Wire.varint r in
      Ok (Streams_blocked_bidi v)
  | 0x17 ->
      let* v = Wire.varint r in
      Ok (Streams_blocked_uni v)
  | 0x18 ->
      let* seq = Wire.varint r in
      let* retire_prior_to = Wire.varint r in
      let* cid_len = Wire.u8 r in
      if cid_len < 1 || cid_len > Packet.max_cid_len then Error "ncid: bad len"
      else if retire_prior_to > seq then Error "ncid: retire > seq"
      else
        let* cid = Wire.bytes r cid_len in
        let* reset_token = Wire.bytes r 16 in
        Ok (New_connection_id { seq; retire_prior_to; cid; reset_token })
  | 0x19 ->
      let* seq = Wire.varint r in
      Ok (Retire_connection_id seq)
  | 0x1a ->
      let* data = Wire.bytes r 8 in
      Ok (Path_challenge data)
  | 0x1b ->
      let* data = Wire.bytes r 8 in
      Ok (Path_response data)
  | 0x1c | 0x1d ->
      let app = ftype = 0x1d in
      let* code = Wire.varint r in
      let* frame_type = if app then Some 0 else Wire.varint r in
      let* rlen = Wire.varint r in
      let* roff, rl = Wire.slice r rlen in
      Ok
        (Connection_close
           { app; code; frame_type; reason = { buf = r.Wire.buf; off = roff; len = rl } })
  | 0x1e -> Ok Handshake_done
  | 0x30 | 0x31 ->
      let has_len = ftype land 0x01 <> 0 in
      let* len = if has_len then Wire.varint r else Some (Wire.remaining r) in
      let* doff, dlen = Wire.slice r len in
      Ok (Datagram { data = { buf = r.Wire.buf; off = doff; len = dlen } })
  | 0x24 ->
      let* id = Wire.varint r in
      let* code = Wire.varint r in
      let* final_size = Wire.varint r in
      let* reliable_size = Wire.varint r in
      if reliable_size > final_size then Error "reset_stream_at: reliable > final"
      else Ok (Reset_stream_at { id; code; final_size; reliable_size })
  | t -> Error (Printf.sprintf "unknown frame type 0x%x" t)

(* Parse a whole plaintext payload into frames. *)
let parse_all buf ~off ~len =
  let r = Wire.reader buf ~off ~len in
  let rec go acc =
    if Wire.remaining r = 0 then Ok (List.rev acc)
    else match parse_one r with Ok f -> go (f :: acc) | Error e -> Error e
  in
  go []

(* ---- encoding ---- *)

let put_payload buf ~off (p : payload) =
  Bigstringaf.blit p.buf ~src_off:p.off buf ~dst_off:off ~len:p.len;
  off + p.len

(* Encoded size in bytes. *)
let size = function
  | Padding n -> n
  | Ping | Handshake_done -> 1
  | Ack { largest; delay; ranges; ecn } ->
      let base =
        match ranges with
        | (lo, hi) :: rest ->
            let rest_size, _ =
              List.fold_left
                (fun (acc, prev_lo) (lo, hi) ->
                  let gap = prev_lo - hi - 2 and len = hi - lo in
                  (acc + Varint.size gap + Varint.size len, lo))
                (0, lo) rest
            in
            1 + Varint.size largest + Varint.size delay
            + Varint.size (List.length rest)
            + Varint.size (hi - lo) + rest_size
        | [] -> invalid_arg "Ack: no ranges"
      in
      base
      + (match ecn with
        | None -> 0
        | Some (a, b, c) -> Varint.size a + Varint.size b + Varint.size c)
  | Reset_stream { id; code; final_size } ->
      1 + Varint.size id + Varint.size code + Varint.size final_size
  | Stop_sending { id; code } -> 1 + Varint.size id + Varint.size code
  | Crypto { off; data } ->
      1 + Varint.size off + Varint.size data.len + data.len
  | New_token { token } -> 1 + Varint.size token.len + token.len
  | Stream { id; off; data; _ } ->
      1 + Varint.size id
      + (if off > 0 then Varint.size off else 0)
      + Varint.size data.len + data.len
  | Max_data v | Data_blocked v -> 1 + Varint.size v
  | Max_streams_bidi v | Max_streams_uni v -> 1 + Varint.size v
  | Streams_blocked_bidi v | Streams_blocked_uni v -> 1 + Varint.size v
  | Max_stream_data { id; max } | Stream_data_blocked { id; max } ->
      1 + Varint.size id + Varint.size max
  | New_connection_id { seq; retire_prior_to; cid; _ } ->
      1 + Varint.size seq + Varint.size retire_prior_to + 1
      + String.length cid + 16
  | Retire_connection_id seq -> 1 + Varint.size seq
  | Path_challenge _ | Path_response _ -> 1 + 8
  | Connection_close { app; code; frame_type; reason } ->
      1 + Varint.size code
      + (if app then 0 else Varint.size frame_type)
      + Varint.size reason.len + reason.len
  | Datagram { data } ->
      (* always encoded with an explicit length (type 0x31) *)
      1 + Varint.size data.len + data.len
  | Reset_stream_at { id; code; final_size; reliable_size } ->
      1 + Varint.size id + Varint.size code + Varint.size final_size
      + Varint.size reliable_size

let encode buf ~off frame =
  let start = off in
  let vp = Wire.put_varint in
  let off =
    match frame with
    | Padding n ->
        for i = 0 to n - 1 do
          Bigstringaf.set buf (off + i) '\x00'
        done;
        off + n
    | Ping -> vp buf ~off 0x01
    | Handshake_done -> vp buf ~off 0x1e
    | Ack { largest; delay; ranges; ecn } -> (
        match ranges with
        | [] -> invalid_arg "Ack: no ranges"
        | (lo, hi) :: rest ->
            let off = vp buf ~off (match ecn with None -> 0x02 | Some _ -> 0x03) in
            let off = vp buf ~off largest in
            let off = vp buf ~off delay in
            let off = vp buf ~off (List.length rest) in
            let off = vp buf ~off (hi - lo) in
            let off, _ =
              List.fold_left
                (fun (off, prev_lo) (lo, hi) ->
                  let off = vp buf ~off (prev_lo - hi - 2) in
                  let off = vp buf ~off (hi - lo) in
                  (off, lo))
                (off, lo) rest
            in
            (match ecn with
            | None -> off
            | Some (a, b, c) ->
                let off = vp buf ~off a in
                let off = vp buf ~off b in
                vp buf ~off c))
    | Reset_stream { id; code; final_size } ->
        let off = vp buf ~off 0x04 in
        let off = vp buf ~off id in
        let off = vp buf ~off code in
        vp buf ~off final_size
    | Stop_sending { id; code } ->
        let off = vp buf ~off 0x05 in
        let off = vp buf ~off id in
        vp buf ~off code
    | Crypto { off = coff; data } ->
        let off = vp buf ~off 0x06 in
        let off = vp buf ~off coff in
        let off = vp buf ~off data.len in
        put_payload buf ~off data
    | New_token { token } ->
        let off = vp buf ~off 0x07 in
        let off = vp buf ~off token.len in
        put_payload buf ~off token
    | Stream { id; off = soff; fin; data } ->
        let t = 0x08 lor (if soff > 0 then 0x04 else 0) lor 0x02 lor Bool.to_int fin in
        let off = vp buf ~off t in
        let off = vp buf ~off id in
        let off = if soff > 0 then vp buf ~off soff else off in
        let off = vp buf ~off data.len in
        put_payload buf ~off data
    | Max_data v ->
        let off = vp buf ~off 0x10 in
        vp buf ~off v
    | Max_stream_data { id; max } ->
        let off = vp buf ~off 0x11 in
        let off = vp buf ~off id in
        vp buf ~off max
    | Max_streams_bidi v ->
        let off = vp buf ~off 0x12 in
        vp buf ~off v
    | Max_streams_uni v ->
        let off = vp buf ~off 0x13 in
        vp buf ~off v
    | Data_blocked v ->
        let off = vp buf ~off 0x14 in
        vp buf ~off v
    | Stream_data_blocked { id; max } ->
        let off = vp buf ~off 0x15 in
        let off = vp buf ~off id in
        vp buf ~off max
    | Streams_blocked_bidi v ->
        let off = vp buf ~off 0x16 in
        vp buf ~off v
    | Streams_blocked_uni v ->
        let off = vp buf ~off 0x17 in
        vp buf ~off v
    | New_connection_id { seq; retire_prior_to; cid; reset_token } ->
        let off = vp buf ~off 0x18 in
        let off = vp buf ~off seq in
        let off = vp buf ~off retire_prior_to in
        let off = Wire.put_u8 buf ~off (String.length cid) in
        let off = Wire.put_string buf ~off cid in
        Wire.put_string buf ~off reset_token
    | Retire_connection_id seq ->
        let off = vp buf ~off 0x19 in
        vp buf ~off seq
    | Path_challenge data ->
        let off = vp buf ~off 0x1a in
        Wire.put_string buf ~off data
    | Path_response data ->
        let off = vp buf ~off 0x1b in
        Wire.put_string buf ~off data
    | Connection_close { app; code; frame_type; reason } ->
        let off = vp buf ~off (if app then 0x1d else 0x1c) in
        let off = vp buf ~off code in
        let off = if app then off else vp buf ~off frame_type in
        let off = vp buf ~off reason.len in
        put_payload buf ~off reason
    | Datagram { data } ->
        let off = vp buf ~off 0x31 in
        let off = vp buf ~off data.len in
        put_payload buf ~off data
    | Reset_stream_at { id; code; final_size; reliable_size } ->
        let off = vp buf ~off 0x24 in
        let off = vp buf ~off id in
        let off = vp buf ~off code in
        let off = vp buf ~off final_size in
        vp buf ~off reliable_size
  in
  off - start
