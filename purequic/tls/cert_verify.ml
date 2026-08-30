(* CertificateVerify construction, signing and verification
   (RFC 8446 s.4.4.3), on x509/mirage-crypto. *)

let server_context = "TLS 1.3, server CertificateVerify"
let client_context = "TLS 1.3, client CertificateVerify"

let content ~context ~transcript_hash =
  String.make 64 '\x20' ^ context ^ "\x00" ^ transcript_hash

(* signature scheme ids we speak *)
let ecdsa_secp256r1_sha256 = 0x0403
let ecdsa_secp384r1_sha384 = 0x0503
let ecdsa_secp521r1_sha512 = 0x0603
let rsa_pss_rsae_sha256 = 0x0804
let rsa_pss_rsae_sha384 = 0x0805
let rsa_pss_rsae_sha512 = 0x0806
let ed25519 = 0x0807

let verify_schemes =
  [
    ecdsa_secp256r1_sha256;
    ecdsa_secp384r1_sha384;
    ecdsa_secp521r1_sha512;
    rsa_pss_rsae_sha256;
    rsa_pss_rsae_sha384;
    rsa_pss_rsae_sha512;
    ed25519;
  ]

let params_of_scheme :
    int -> (Digestif.hash' * X509.Key_type.signature_scheme) option = function
  | 0x0403 -> Some (`SHA256, `ECDSA)
  | 0x0503 -> Some (`SHA384, `ECDSA)
  | 0x0603 -> Some (`SHA512, `ECDSA)
  | 0x0804 -> Some (`SHA256, `RSA_PSS)
  | 0x0805 -> Some (`SHA384, `RSA_PSS)
  | 0x0806 -> Some (`SHA512, `RSA_PSS)
  | 0x0807 -> Some (`SHA512, `ED25519)
  | _ -> None

(* the scheme this private key signs with, if the peer offered it *)
let pick_sign_scheme (key : X509.Private_key.t) ~offered =
  let candidates =
    match X509.Private_key.key_type key with
    | `P256 -> [ ecdsa_secp256r1_sha256 ]
    | `P384 -> [ ecdsa_secp384r1_sha384 ]
    | `P521 -> [ ecdsa_secp521r1_sha512 ]
    | `RSA -> [ rsa_pss_rsae_sha256; rsa_pss_rsae_sha384; rsa_pss_rsae_sha512 ]
    | `ED25519 -> [ ed25519 ]
  in
  List.find_opt (fun s -> List.mem s offered) candidates

let sign ~key ~scheme ~context ~transcript_hash =
  match params_of_scheme scheme with
  | None -> Error "unsupported signature scheme"
  | Some (hash, sch) -> (
      match
        X509.Private_key.sign hash ~scheme:sch key
          (`Message (content ~context ~transcript_hash))
      with
      | Ok s -> Ok s
      | Error (`Msg m) -> Error m)

let verify ~cert ~scheme ~signature ~context ~transcript_hash =
  match params_of_scheme scheme with
  | None -> Error "unsupported signature scheme"
  | Some (hash, sch) -> (
      match
        X509.Public_key.verify hash ~scheme:sch ~signature
          (X509.Certificate.public_key cert)
          (`Message (content ~context ~transcript_hash))
      with
      | Ok () -> Ok ()
      | Error (`Msg m) -> Error m)
