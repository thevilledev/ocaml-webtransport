(* Header protection (RFC 9001 section 5.4). *)

type key =
  | Aes_hp of Mirage_crypto.AES.ECB.key
  | Chacha_hp of Mirage_crypto.Chacha20.key

let key ~suite ~hp_key =
  match (suite : Qsuite.t) with
  | Aes128_gcm_sha256 | Aes256_gcm_sha384 ->
      Aes_hp (Mirage_crypto.AES.ECB.of_secret hp_key)
  | Chacha20_poly1305_sha256 ->
      Chacha_hp (Mirage_crypto.Chacha20.of_secret hp_key)

(* [sample] is 16 bytes taken 4 bytes past the packet number offset; the
   result is a 5-byte mask. *)
let mask key ~sample =
  match key with
  | Aes_hp k -> String.sub (Mirage_crypto.AES.ECB.encrypt ~key:k sample) 0 5
  | Chacha_hp k ->
      (* counter = first 4 sample bytes (little endian), nonce = rest *)
      let ctr =
        Int64.of_int
          (Char.code sample.[0]
          lor (Char.code sample.[1] lsl 8)
          lor (Char.code sample.[2] lsl 16)
          lor (Char.code sample.[3] lsl 24))
      in
      let nonce = String.sub sample 4 12 in
      Mirage_crypto.Chacha20.crypt ~key:k ~nonce ~ctr (String.make 5 '\x00')
