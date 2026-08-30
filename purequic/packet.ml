(* QUIC v1 packet headers, packet number coding, header + payload
   protection, Version Negotiation and Retry (RFC 9000 s.17, RFC 9001 s.5).

   Parsers are total: any malformed input yields [Error]/[None], never an
   exception. All functions take explicit offsets into caller-owned
   Bigstringaf buffers. *)

let max_cid_len = 20

type long_kind = Initial | Zero_rtt | Handshake | Retry

type header =
  | Long of {
      kind : long_kind;
      version : int32;
      dcid : string;
      scid : string;
      token : string;  (* Initial only; "" otherwise *)
    }
  | Short of { dcid : string }
  | Vneg of { dcid : string; scid : string; versions : int32 list }

(* One packet located inside a datagram. [pn_off] is the offset of the
   protected packet number field; [last] is the offset one past the packet's
   end (the next coalesced packet, or the datagram end). For Retry/Vneg,
   [pn_off] = [last]. *)
type located = { hdr : header; off : int; pn_off : int; last : int }

let long_kind_of_bits = function
  | 0 -> Initial
  | 1 -> Zero_rtt
  | 2 -> Handshake
  | _ -> Retry

(* Parse the packet starting at [off]; [len] bytes of datagram remain.
   [short_dcid_len] is the fixed connection id length this endpoint uses for
   short headers (the drivers' demux convention: 16). *)
let parse buf ~off ~len ~short_dcid_len =
  if len < 1 then Error "empty"
  else
    let r = Wire.reader buf ~off ~len in
    let ( let* ) o f = match o with Some v -> f v | None -> Error "underflow" in
    let* first = Wire.u8 r in
    if first land 0x80 = 0 then
      (* Short header: 1-RTT. The DCID length is not self-describing. *)
      let* dcid = Wire.bytes r short_dcid_len in
      Ok { hdr = Short { dcid }; off; pn_off = Wire.pos r; last = off + len }
    else
      let* version = Wire.u32 r in
      let* dcid_len = Wire.u8 r in
      if dcid_len > max_cid_len then Error "dcid too long"
      else
        let* dcid = Wire.bytes r dcid_len in
        let* scid_len = Wire.u8 r in
        if scid_len > max_cid_len then Error "scid too long"
        else
          let* scid = Wire.bytes r scid_len in
          if version = 0l then begin
            (* Version Negotiation: list of u32s to the end of the datagram. *)
            let rec vs acc =
              match Wire.u32 r with Some v -> vs (v :: acc) | None -> List.rev acc
            in
            let versions = vs [] in
            let last = off + len in
            Ok { hdr = Vneg { dcid; scid; versions }; off; pn_off = last; last }
          end
          else
            let kind = long_kind_of_bits ((first lsr 4) land 0x03) in
            match kind with
            | Retry ->
                (* token = rest minus the 16-byte integrity tag *)
                let rest = Wire.remaining r in
                if rest < 16 then Error "retry too short"
                else
                  let* token = Wire.bytes r (rest - 16) in
                  let last = off + len in
                  Ok
                    {
                      hdr = Long { kind; version; dcid; scid; token };
                      off;
                      pn_off = last;
                      last;
                    }
            | Initial | Zero_rtt | Handshake ->
                let* token =
                  if kind = Initial then
                    match Wire.varint r with
                    | Some tlen -> Wire.bytes r tlen
                    | None -> None
                  else Some ""
                in
                let* length = Wire.varint r in
                let pn_off = Wire.pos r in
                if length < 4 (* smallest pn + tag cannot fit below this *)
                   || pn_off + length > off + len
                then Error "bad length"
                else
                  Ok
                    {
                      hdr = Long { kind; version; dcid; scid; token };
                      off;
                      pn_off;
                      last = pn_off + length;
                    }

(* Iterate the coalesced packets of one datagram; stops at the first
   malformed remainder. *)
let iter buf ~off ~len ~short_dcid_len f =
  let rec go off remaining =
    if remaining > 0 then
      match parse buf ~off ~len:remaining ~short_dcid_len with
      | Error _ -> ()
      | Ok p ->
          f p;
          let consumed = p.last - off in
          if consumed <= 0 then () else go p.last (remaining - consumed)
  in
  go off len

(* ---- packet number coding (RFC 9000 appendix A) ---- *)

(* Length (bytes) needed to encode [pn] given the largest acked. *)
let pn_encode_len ~largest_acked pn =
  let unacked =
    match largest_acked with None -> pn + 1 | Some la -> pn - la
  in
  if unacked < 1 lsl 7 then 1
  else if unacked < 1 lsl 15 then 2
  else if unacked < 1 lsl 23 then 3
  else 4

let pn_decode ~largest ~pn_len truncated =
  let expected = largest + 1 in
  let win = 1 lsl (pn_len * 8) in
  let hwin = win lsr 1 in
  let mask = win - 1 in
  let candidate = expected land lnot mask lor truncated in
  (* 2^62 - win, kept in the representable range: max varint is 2^62 - 1 *)
  let upper = Varint.max_value - win + 1 in
  if candidate <= expected - hwin && candidate < upper then candidate + win
  else if candidate > expected + hwin && candidate >= win then candidate - win
  else candidate

(* ---- header/payload protection ---- *)

(* Seals one packet whose unprotected header bytes (packet number already
   encoded in the clear, Length already counting payload + tag) are
   [header]; returns the full protected packet. [pn_len] is the encoded
   packet number length recorded in the header's low bits. *)
let seal ~keys ~pn ~pn_len ~header payload =
  let sealed = Aead.seal keys ~pn ~ad:header payload in
  let sample = String.sub sealed (4 - pn_len) 16 in
  let mask = Hp.mask keys.Aead.hp ~sample in
  let hlen = String.length header in
  let out = Bytes.create (hlen + String.length sealed) in
  Bytes.blit_string header 0 out 0 hlen;
  Bytes.blit_string sealed 0 out hlen (String.length sealed);
  let first = Char.code header.[0] in
  let first_mask = if first land 0x80 <> 0 then 0x0f else 0x1f in
  Bytes.set out 0 (Char.chr (first lxor (Char.code mask.[0] land first_mask)));
  for i = 0 to pn_len - 1 do
    let pos = hlen - pn_len + i in
    Bytes.set out pos
      (Char.chr (Char.code (Bytes.get out pos) lxor Char.code mask.[i + 1]))
  done;
  Bytes.unsafe_to_string out

(* Removes header protection and opens the payload of a located packet.
   [largest] is the largest packet number seen in this packet's number
   space (for PN reconstruction). Returns the full packet number and the
   plaintext, or [None] (undecryptable: wrong keys, forgery, or garbage). *)
let open_ ~keys ~largest buf (p : located) =
  let plen = p.last - p.pn_off in
  if plen < 4 + 16 then None
  else
    let sample = Bigstringaf.substring buf ~off:(p.pn_off + 4) ~len:16 in
    let mask = Hp.mask keys.Aead.hp ~sample in
    let first = Char.code (Bigstringaf.get buf p.off) in
    let first_mask = if first land 0x80 <> 0 then 0x0f else 0x1f in
    let first = first lxor (Char.code mask.[0] land first_mask) in
    let pn_len = (first land 0x03) + 1 in
    if plen < pn_len + 16 then None
    else begin
      let truncated = ref 0 in
      for i = 0 to pn_len - 1 do
        let b =
          Char.code (Bigstringaf.get buf (p.pn_off + i))
          lxor Char.code mask.[i + 1]
        in
        truncated := (!truncated lsl 8) lor b
      done;
      let pn =
        pn_decode ~largest:(Option.value largest ~default:(-1)) ~pn_len
          !truncated
      in
      (* associated data: the unprotected header bytes *)
      let hlen = p.pn_off - p.off + pn_len in
      let ad = Bytes.create hlen in
      Bigstringaf.blit_to_bytes buf ~src_off:p.off ad ~dst_off:0 ~len:hlen;
      Bytes.set ad 0 (Char.chr first);
      for i = 0 to pn_len - 1 do
        let b =
          Char.code (Bigstringaf.get buf (p.pn_off + i))
          lxor Char.code mask.[i + 1]
        in
        Bytes.set ad (hlen - pn_len + i) (Char.chr b)
      done;
      let ciphertext =
        Bigstringaf.substring buf ~off:(p.pn_off + pn_len)
          ~len:(p.last - p.pn_off - pn_len)
      in
      match
        Aead.open_ keys ~pn:(Int64.of_int pn) ~ad:(Bytes.unsafe_to_string ad)
          ciphertext
      with
      | Some plaintext -> Some (pn, plaintext)
      | None -> None
    end

(* ---- version negotiation (server -> client) ---- *)

(* [client_dcid]/[client_scid] are the fields of the client's long header;
   the response echoes them swapped. Returns bytes written. *)
let write_vneg buf ~client_dcid ~client_scid =
  let need =
    1 + 4 + 1 + String.length client_scid + 1 + String.length client_dcid + 4
  in
  if Bigstringaf.length buf < need then Error "buffer too small"
  else begin
    let off = Wire.put_u8 buf ~off:0 0xc0 in
    let off = Wire.put_u32 buf ~off 0l in
    let off = Wire.put_u8 buf ~off (String.length client_scid) in
    let off = Wire.put_string buf ~off client_scid in
    let off = Wire.put_u8 buf ~off (String.length client_dcid) in
    let off = Wire.put_string buf ~off client_dcid in
    let off = Wire.put_u32 buf ~off 1l in
    Ok off
  end

(* ---- retry integrity ---- *)

(* Validates the integrity tag of a located Retry packet against the
   original DCID the client sent (RFC 9001 s.5.8). *)
let retry_valid ~odcid buf (p : located) =
  let len = p.last - p.off in
  if len < 16 then false
  else
    let pseudo = Bigstringaf.substring buf ~off:p.off ~len:(len - 16) in
    let tag = Bigstringaf.substring buf ~off:(p.off + len - 16) ~len:16 in
    Eqaf.equal (Aead.retry_tag ~odcid ~pseudo) tag
