(* QUIC key derivation (RFC 9001 section 5): TLS 1.3 HKDF-Expand-Label and
   the v1 initial secrets.

   Label construction and derivation structure follow ocaml-quic's
   lib/crypto.ml (Copyright (c) 2020 António Nuno Monteiro, BSD-3-Clause;
   see THIRD_PARTY.md), rewritten against the kdf/digestif APIs. Verified
   byte-exact against RFC 9001 Appendix A. *)

(* HkdfLabel: u16 length ^ u8-prefixed ("tls13 " ^ label) ^ u8-prefixed ctx *)
let hkdf_label ~label ~context length =
  let full = "tls13 " ^ label in
  let b = Buffer.create (4 + String.length full + String.length context) in
  Buffer.add_uint16_be b length;
  Buffer.add_uint8 b (String.length full);
  Buffer.add_string b full;
  Buffer.add_uint8 b (String.length context);
  Buffer.add_string b context;
  Buffer.contents b

let expand_label ~hash ~secret ?(context = "") ~label length =
  Hkdf.expand ~hash ~prk:secret ~info:(hkdf_label ~label ~context length)
    length

(* RFC 9001 section 5.2. *)
let initial_salt_v1 =
  "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

let initial_secret ~dcid = Hkdf.extract ~hash:`SHA256 ~salt:initial_salt_v1 dcid

let initial_client_secret ~dcid =
  expand_label ~hash:`SHA256 ~secret:(initial_secret ~dcid) ~label:"client in"
    32

let initial_server_secret ~dcid =
  expand_label ~hash:`SHA256 ~secret:(initial_secret ~dcid) ~label:"server in"
    32

(* Per-direction packet protection material from a traffic secret. *)
type material = { key : string; iv : string; hp : string }

let material ~suite ~secret =
  let hash = Qsuite.hash suite in
  {
    key = expand_label ~hash ~secret ~label:"quic key" (Qsuite.key_len suite);
    iv = expand_label ~hash ~secret ~label:"quic iv" (Qsuite.iv_len suite);
    hp = expand_label ~hash ~secret ~label:"quic hp" (Qsuite.hp_key_len suite);
  }

(* Key update: the next generation of the traffic secret (RFC 9001 s.6). *)
let next_secret ~suite ~secret =
  expand_label ~hash:(Qsuite.hash suite) ~secret ~label:"quic ku"
    (Qsuite.hash_len suite)
