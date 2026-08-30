(* A minimal TLS 1.3 handshake engine for QUIC (RFC 8446 + RFC 9001):
   no record layer — raw handshake messages ride QUIC CRYPTO streams per
   encryption level; secrets (not keys) are exported; quic_transport_
   parameters is carried as an opaque extension.

   Scope: TLS 1.3 only; suites 0x1301/0x1302/0x1303; groups x25519 +
   secp256r1 (both offered with shares, so a group-selecting HRR is
   illegal_parameter; cookie HRRs are honored); server never emits HRR or
   tickets or CertificateRequest; client answers a CertificateRequest with
   an empty Certificate; no PSK/resumption/0-RTT; NewSessionTicket is
   validated and discarded; TLS KeyUpdate is fatal (RFC 9001 s.8.4 — key
   update happens at the QUIC layer). Alerts are surfaced as [Fatal]
   events for the QUIC layer to map onto 0x0100+alert connection closes;
   alerts are never received (peers close at the QUIC layer). *)

module W = Tls_wire

type level = Initial | Handshake | Application

type event =
  | Send of { level : level; data : string }
  | Rx_secret of { level : level; cipher : Cipher.t; secret : string }
  | Tx_secret of { level : level; cipher : Cipher.t; secret : string }
  | Peer_transport_params of string
  | Handshake_complete of { alpn : string }
  | Fatal of { alert : int; reason : string }

(* alert codes we emit *)
let a_unexpected_message = 10
let a_handshake_failure = 40
let a_bad_certificate = 42
let a_illegal_parameter = 47
let a_decode_error = 50
let a_decrypt_error = 51
let a_internal_error = 80
let a_protocol_version = 70
let a_missing_extension = 109
let a_no_application_protocol = 120

type config = {
  role : [ `Client | `Server ];
  alpn : string list;  (* client: offers in order; server: supported, in
                          preference order *)
  transport_params : string;
  rng : int -> string;
  (* client side *)
  verify : [ `None | `Anchors of X509.Certificate.t list ];
  time : unit -> Ptime.t option;
  server_name : string option;
  (* server side *)
  cert_chain : X509.Certificate.t list;
  priv_key : X509.Private_key.t option;
}

let client_config ?(verify = `None) ?(time = fun () -> None) ?server_name
    ~alpn ~transport_params ~rng () =
  if alpn = [] then Error "client_config: alpn required"
  else
    Ok
      {
        role = `Client;
        alpn;
        transport_params;
        rng;
        verify;
        time;
        server_name;
        cert_chain = [];
        priv_key = None;
      }

let server_config ~cert_chain ~priv_key ~alpn ~transport_params ~rng () =
  if alpn = [] then Error "server_config: alpn required"
  else if cert_chain = [] then Error "server_config: certificate required"
  else
    Ok
      {
        role = `Server;
        alpn;
        transport_params;
        rng;
        verify = `None;
        time = (fun () -> None);
        server_name = None;
        cert_chain;
        priv_key = Some priv_key;
      }

type dh = {
  x25519 : Mirage_crypto_ec.X25519.secret;
  x25519_pub : string;
  p256 : Mirage_crypto_ec.P256.Dh.secret;
  p256_pub : string;
}

type state =
  | Start
  | C_wait_sh
  | C_wait_ee
  | C_wait_cert_cr
  | C_wait_cert
  | C_wait_cv
  | C_wait_fin
  | S_wait_fin
  | Connected
  | Failed

type t = {
  cfg : config;
  events : event Queue.t;
  initial_buf : Buffer.t;
  hs_buf : Buffer.t;
  app_buf : Buffer.t;
  transcript : Schedule.Transcript.t;
  mutable state : state;
  mutable cipher : Cipher.t option;
  mutable dh : dh option;
  mutable retried : bool;
  mutable hs_secret : string;
  mutable c_hs : string;
  mutable s_hs : string;
  mutable master : string;
  mutable c_ap : string;
  mutable s_ap : string;
  mutable expected_peer_fin : string;  (* server: precomputed *)
  mutable peer_certs : X509.Certificate.t list;
  mutable alpn : string;
  mutable cert_req_context : string option;
}

let create cfg =
  {
    cfg;
    events = Queue.create ();
    initial_buf = Buffer.create 512;
    hs_buf = Buffer.create 2048;
    app_buf = Buffer.create 64;
    transcript = Schedule.Transcript.create ();
    state = Start;
    cipher = None;
    dh = None;
    retried = false;
    hs_secret = "";
    c_hs = "";
    s_hs = "";
    master = "";
    c_ap = "";
    s_ap = "";
    expected_peer_fin = "";
    peer_certs = [];
    alpn = "";
    cert_req_context = None;
  }

let next_event t = Queue.take_opt t.events
let emit t e = Queue.add e t.events

let fatal t alert reason =
  t.state <- Failed;
  emit t (Fatal { alert; reason })

let peer_certs t = t.peer_certs
let is_connected t = t.state = Connected

(* ---- key material helpers ---- *)

let gen_dh t =
  let x25519, x25519_pub =
    match Mirage_crypto_ec.X25519.secret_of_octets (t.cfg.rng 32) with
    | Ok sp -> sp
    | Error _ ->
        (* x25519 accepts any 32 bytes; only a length bug lands here *)
        invalid_arg "x25519 secret generation"
  in
  let rec p256_gen tries =
    if tries = 0 then invalid_arg "p256 secret generation"
    else
      match Mirage_crypto_ec.P256.Dh.secret_of_octets (t.cfg.rng 32) with
      | Ok sp -> sp
      | Error _ -> p256_gen (tries - 1)
  in
  let p256, p256_pub = p256_gen 64 in
  t.dh <- Some { x25519; x25519_pub; p256; p256_pub }

let shared_for t ~group ~peer_key =
  match t.dh with
  | None -> Error "no dh secrets"
  | Some dh ->
      if group = W.group_x25519 then
        match Mirage_crypto_ec.X25519.key_exchange dh.x25519 peer_key with
        | Ok s -> Ok s
        | Error _ -> Error "x25519 key exchange"
      else if group = W.group_secp256r1 then
        match Mirage_crypto_ec.P256.Dh.key_exchange dh.p256 peer_key with
        | Ok s -> Ok s
        | Error _ -> Error "p256 key exchange"
      else Error "unknown group"

let install_hs_secrets t ~cipher ~shared =
  let hash = Cipher.hash cipher in
  let early = Schedule.early_secret ~hash in
  t.hs_secret <- Schedule.handshake_secret ~hash ~early ~ecdh_shared:shared;
  let th = Schedule.Transcript.hash t.transcript in
  t.c_hs <- Schedule.client_hs_traffic ~hash ~handshake:t.hs_secret ~transcript_hash:th;
  t.s_hs <- Schedule.server_hs_traffic ~hash ~handshake:t.hs_secret ~transcript_hash:th

let derive_app_secrets t ~cipher =
  (* transcript must be at "through server Finished" *)
  let hash = Cipher.hash cipher in
  t.master <- Schedule.master_secret ~hash ~handshake:t.hs_secret;
  let th = Schedule.Transcript.hash t.transcript in
  t.c_ap <- Schedule.client_app_traffic ~hash ~master:t.master ~transcript_hash:th;
  t.s_ap <- Schedule.server_app_traffic ~hash ~master:t.master ~transcript_hash:th

(* ---- client ---- *)

let client_extensions t =
  let sn =
    match t.cfg.server_name with
    | Some host -> [ W.server_name_ext host ]
    | None -> []
  in
  let dh = match t.dh with Some d -> d | None -> assert false in
  sn
  @ [
      W.supported_groups_ext [ W.group_x25519; W.group_secp256r1 ];
      W.alpn_ext t.cfg.alpn;
      W.signature_algorithms_ext Cert_verify.verify_schemes;
      W.supported_versions_client_ext ();
      W.key_share_client_ext
        [
          W.key_share_entry ~group:W.group_x25519 ~key:dh.x25519_pub;
          W.key_share_entry ~group:W.group_secp256r1 ~key:dh.p256_pub;
        ];
      W.quic_transport_parameters_ext t.cfg.transport_params;
    ]

let start t =
  match (t.cfg.role, t.state) with
  | `Client, Start ->
      gen_dh t;
      let ch =
        W.build_client_hello ~random:(t.cfg.rng 32) ~session_id:""
          ~cipher_suites:(List.map Cipher.to_id Cipher.all)
          ~extensions:(client_extensions t)
      in
      Schedule.Transcript.feed t.transcript ch;
      emit t (Send { level = Initial; data = ch });
      t.state <- C_wait_sh
  | `Server, Start -> ()
  | _ -> invalid_arg "Tls.start: already started"

let client_on_hrr t (sh : W.server_hello) raw =
  if t.retried then fatal t a_unexpected_message "second HelloRetryRequest"
  else
    match Cipher.of_id sh.sh_cipher_suite with
    | None -> fatal t a_illegal_parameter "HRR: unknown cipher suite"
    | Some cipher -> (
        match W.find_ext sh.sh_extensions W.ext_key_share with
        | Some _ ->
            (* we offered shares for every group we support *)
            fatal t a_illegal_parameter "HRR selected an offered group"
        | None -> (
            match W.find_ext sh.sh_extensions W.ext_cookie with
            | None -> fatal t a_illegal_parameter "HRR without cookie"
            | Some cookie_raw -> (
                match W.parse_cookie cookie_raw with
                | Error e -> fatal t a_decode_error e
                | Ok cookie ->
                    t.retried <- true;
                    t.cipher <- Some cipher;
                    (* transcript: CH1 -> message_hash(CH1), then HRR *)
                    Schedule.Transcript.substitute_message_hash t.transcript
                      (Cipher.hash cipher);
                    Schedule.Transcript.feed t.transcript raw;
                    let ch2 =
                      W.build_client_hello ~random:(t.cfg.rng 32)
                        ~session_id:""
                        ~cipher_suites:(List.map Cipher.to_id Cipher.all)
                        ~extensions:(client_extensions t @ [ W.cookie_ext cookie ])
                    in
                    Schedule.Transcript.feed t.transcript ch2;
                    emit t (Send { level = Initial; data = ch2 }))))

let client_on_sh t body raw =
  match W.parse_server_hello body with
  | Error e -> fatal t a_decode_error e
  | Ok sh ->
      if String.equal sh.sh_random W.hrr_random then client_on_hrr t sh raw
      else begin
        let version =
          match W.find_ext sh.sh_extensions W.ext_supported_versions with
          | Some v -> W.parse_supported_versions_server v
          | None -> Error "SH without supported_versions"
        in
        match version with
        | Error e -> fatal t a_protocol_version e
        | Ok v when v <> 0x0304 -> fatal t a_protocol_version "not TLS 1.3"
        | Ok _ -> (
            match Cipher.of_id sh.sh_cipher_suite with
            | None -> fatal t a_illegal_parameter "unknown cipher suite"
            | Some cipher ->
                if not (String.equal sh.sh_session_id "") then
                  fatal t a_illegal_parameter "unexpected legacy_session_id"
                else begin
                  match W.find_ext sh.sh_extensions W.ext_key_share with
                  | None -> fatal t a_missing_extension "SH without key_share"
                  | Some ks_raw -> (
                      match W.parse_key_share_server ks_raw with
                      | Error e -> fatal t a_decode_error e
                      | Ok (_, None) ->
                          fatal t a_illegal_parameter "SH key_share without key"
                      | Ok (group, Some peer_key) -> (
                          match shared_for t ~group ~peer_key with
                          | Error e -> fatal t a_illegal_parameter e
                          | Ok shared ->
                              if
                                t.retried
                                && t.cipher <> None
                                && t.cipher <> Some cipher
                              then
                                fatal t a_illegal_parameter
                                  "SH cipher differs from HRR"
                              else begin
                              t.cipher <- Some cipher;
                              (* ctx is still unset in both the direct and
                                 the post-HRR path (the substituted
                                 transcript sits in the buffer) *)
                              Schedule.Transcript.set_hash t.transcript
                                (Cipher.hash cipher);
                              Schedule.Transcript.feed t.transcript raw;
                              install_hs_secrets t ~cipher ~shared;
                              emit t
                                (Rx_secret
                                   { level = Handshake; cipher; secret = t.s_hs });
                              emit t
                                (Tx_secret
                                   { level = Handshake; cipher; secret = t.c_hs });
                              t.state <- C_wait_ee
                              end))
                end)
      end

let client_on_ee t body raw =
  match W.parse_encrypted_extensions body with
  | Error e -> fatal t a_decode_error e
  | Ok exts -> (
      let alpn =
        match W.find_ext exts W.ext_alpn with
        | None ->
            Error
              (Printf.sprintf "EE without ALPN (extensions: %s)"
                 (String.concat ","
                    (List.map (fun (id, _) -> string_of_int id) exts)))
        | Some raw -> (
            match W.parse_alpn_payload raw with
            | Ok [ proto ] when List.mem proto t.cfg.alpn -> Ok proto
            | Ok _ -> Error "ALPN mismatch"
            | Error e -> Error e)
      in
      match alpn with
      | Error e -> fatal t a_no_application_protocol e
      | Ok proto -> (
          match W.find_ext exts W.ext_quic_transport_parameters with
          | None ->
              fatal t a_missing_extension "EE without quic_transport_parameters"
          | Some tp ->
              t.alpn <- proto;
              emit t (Peer_transport_params tp);
              Schedule.Transcript.feed t.transcript raw;
              t.state <- C_wait_cert_cr))

let client_on_certificate t body raw =
  match W.parse_certificate body with
  | Error e -> fatal t a_decode_error e
  | Ok (context, ders) ->
      if not (String.equal context "") then
        fatal t a_illegal_parameter "server Certificate with context"
      else begin
        let certs =
          List.fold_left
            (fun acc der ->
              match acc with
              | Error _ as e -> e
              | Ok cs -> (
                  match X509.Certificate.decode_der der with
                  | Ok c -> Ok (c :: cs)
                  | Error (`Msg m) -> Error m))
            (Ok []) ders
        in
        match certs with
        | Error e -> fatal t a_bad_certificate e
        | Ok [] -> fatal t a_bad_certificate "empty certificate list"
        | Ok rev_certs ->
            t.peer_certs <- List.rev rev_certs;
            Schedule.Transcript.feed t.transcript raw;
            t.state <- C_wait_cv
      end

let client_on_cv t body raw =
  match W.parse_certificate_verify body with
  | Error e -> fatal t a_decode_error e
  | Ok (scheme, signature) -> (
      let th = Schedule.Transcript.hash t.transcript in
      let leaf = List.hd t.peer_certs in
      match
        Cert_verify.verify ~cert:leaf ~scheme ~signature
          ~context:Cert_verify.server_context ~transcript_hash:th
      with
      | Error e -> fatal t a_decrypt_error ("CertificateVerify: " ^ e)
      | Ok () -> (
          (* chain validation per configured mode *)
          let chain_ok =
            match t.cfg.verify with
            | `None -> Ok ()
            | `Anchors anchors -> (
                let host =
                  match t.cfg.server_name with
                  | None -> None
                  | Some n -> (
                      match Domain_name.of_string n with
                      | Ok d -> (
                          match Domain_name.host d with
                          | Ok h -> Some h
                          | Error _ -> None)
                      | Error _ -> None)
                in
                match
                  X509.Validation.verify_chain_of_trust ~host ~time:t.cfg.time
                    ~anchors t.peer_certs
                with
                | Ok _ -> Ok ()
                | Error ve ->
                    Error
                      (Format.asprintf "%a" X509.Validation.pp_validation_error
                         ve))
          in
          match chain_ok with
          | Error e -> fatal t a_bad_certificate e
          | Ok () ->
              Schedule.Transcript.feed t.transcript raw;
              t.state <- C_wait_fin))

let client_on_finished t body raw =
  let cipher = Option.get t.cipher in
  let hash = Cipher.hash cipher in
  let th = Schedule.Transcript.hash t.transcript in
  let expected =
    Schedule.finished_verify ~hash ~traffic_secret:t.s_hs ~transcript_hash:th
  in
  if not (Eqaf.equal expected body) then
    fatal t a_decrypt_error "server Finished verification failed"
  else begin
    Schedule.Transcript.feed t.transcript raw;
    (* application secrets bind the transcript through server Finished *)
    derive_app_secrets t ~cipher;
    (* client flight: (empty Certificate if requested) + Finished *)
    let flight = Buffer.create 128 in
    (match t.cert_req_context with
    | Some context ->
        let empty_cert = W.build_certificate ~context ~ders:[] in
        Schedule.Transcript.feed t.transcript empty_cert;
        Buffer.add_string flight empty_cert
    | None -> ());
    let th' = Schedule.Transcript.hash t.transcript in
    let fin =
      W.build_finished
        (Schedule.finished_verify ~hash ~traffic_secret:t.c_hs
           ~transcript_hash:th')
    in
    Schedule.Transcript.feed t.transcript fin;
    Buffer.add_string flight fin;
    emit t (Send { level = Handshake; data = Buffer.contents flight });
    emit t (Tx_secret { level = Application; cipher; secret = t.c_ap });
    emit t (Rx_secret { level = Application; cipher; secret = t.s_ap });
    emit t (Handshake_complete { alpn = t.alpn });
    t.state <- Connected
  end

(* ---- server ---- *)

let rec server_on_ch t body raw =
  match W.parse_client_hello body with
  | Error e -> fatal t a_decode_error e
  | Ok ch -> (
      let versions =
        match W.find_ext ch.ch_extensions W.ext_supported_versions with
        | None -> Error "CH without supported_versions"
        | Some v -> W.parse_supported_versions_client v
      in
      match versions with
      | Error e -> fatal t a_protocol_version e
      | Ok vs when not (List.mem 0x0304 vs) ->
          fatal t a_protocol_version "TLS 1.3 not offered"
      | Ok _ -> (
          let cipher =
            List.find_opt
              (fun c -> List.mem (Cipher.to_id c) ch.ch_cipher_suites)
              Cipher.all
          in
          match cipher with
          | None -> fatal t a_handshake_failure "no common cipher suite"
          | Some cipher -> (
              let shares =
                match W.find_ext ch.ch_extensions W.ext_key_share with
                | None -> Error "CH without key_share"
                | Some raw -> W.parse_key_share_entries raw
              in
              match shares with
              | Error e -> fatal t a_decode_error e
              | Ok entries -> (
                  let pick group =
                    List.find_opt (fun (g, _) -> g = group) entries
                  in
                  match
                    (pick W.group_x25519, pick W.group_secp256r1)
                  with
                  | None, None ->
                      (* we do not emit HRR; treat as failure *)
                      fatal t a_handshake_failure "no usable key share"
                  | x25519_entry, p256_entry -> (
                      let group, peer_key =
                        match (x25519_entry, p256_entry) with
                        | Some (g, k), _ -> (g, k)
                        | None, Some (g, k) -> (g, k)
                        | None, None -> assert false
                      in
                      let alpn =
                        match W.find_ext ch.ch_extensions W.ext_alpn with
                        | None -> Error "CH without ALPN"
                        | Some raw -> (
                            match W.parse_alpn_payload raw with
                            | Error e -> Error e
                            | Ok offers -> (
                                match
                                  List.find_opt
                                    (fun p -> List.mem p offers)
                                    t.cfg.alpn
                                with
                                | Some p -> Ok p
                                | None -> Error "no common ALPN protocol"))
                      in
                      match alpn with
                      | Error e -> fatal t a_no_application_protocol e
                      | Ok alpn -> (
                          let sig_scheme =
                            match
                              W.find_ext ch.ch_extensions
                                W.ext_signature_algorithms
                            with
                            | None -> Error "CH without signature_algorithms"
                            | Some raw -> (
                                match W.parse_u16_list_vec16 raw with
                                | Error e -> Error e
                                | Ok offered -> (
                                    match
                                      Cert_verify.pick_sign_scheme
                                        (Option.get t.cfg.priv_key)
                                        ~offered
                                    with
                                    | Some s -> Ok s
                                    | None ->
                                        Error
                                          "peer accepts none of our signature \
                                           schemes"))
                          in
                          match sig_scheme with
                          | Error e -> fatal t a_handshake_failure e
                          | Ok sig_scheme -> (
                              match
                                W.find_ext ch.ch_extensions
                                  W.ext_quic_transport_parameters
                              with
                              | None ->
                                  fatal t a_missing_extension
                                    "CH without quic_transport_parameters"
                              | Some tp -> (
                                  match shared_for t ~group ~peer_key with
                                  | Error e -> fatal t a_illegal_parameter e
                                  | Ok shared ->
                                      emit t (Peer_transport_params tp);
                                      t.cipher <- Some cipher;
                                      t.alpn <- alpn;
                                      let hash = Cipher.hash cipher in
                                      Schedule.Transcript.set_hash t.transcript
                                        hash;
                                      Schedule.Transcript.feed t.transcript raw;
                                      server_flights t ~cipher ~group ~shared
                                        ~session_id:ch.ch_session_id ~sig_scheme))))))))

and server_flights t ~cipher ~group ~shared ~session_id ~sig_scheme =
  let dh = match t.dh with Some d -> d | None -> assert false in
  let our_share =
    if group = W.group_x25519 then dh.x25519_pub else dh.p256_pub
  in
  let sh =
    W.build_server_hello ~random:(t.cfg.rng 32) ~session_id
      ~cipher_suite:(Cipher.to_id cipher)
      ~extensions:
        [
          W.supported_versions_server_ext ();
          W.key_share_server_ext ~group ~key:our_share;
        ]
  in
  Schedule.Transcript.feed t.transcript sh;
  emit t (Send { level = Initial; data = sh });
  install_hs_secrets t ~cipher ~shared;
  emit t (Tx_secret { level = Handshake; cipher; secret = t.s_hs });
  emit t (Rx_secret { level = Handshake; cipher; secret = t.c_hs });
  let hash = Cipher.hash cipher in
  let flight = Buffer.create 4096 in
  let ee =
    W.build_encrypted_extensions
      [
        W.alpn_ext [ t.alpn ];
        W.quic_transport_parameters_ext t.cfg.transport_params;
      ]
  in
  Schedule.Transcript.feed t.transcript ee;
  Buffer.add_string flight ee;
  let cert =
    W.build_certificate ~context:""
      ~ders:(List.map X509.Certificate.encode_der t.cfg.cert_chain)
  in
  Schedule.Transcript.feed t.transcript cert;
  Buffer.add_string flight cert;
  let cv_result =
    Cert_verify.sign
      ~key:(Option.get t.cfg.priv_key)
      ~scheme:sig_scheme ~context:Cert_verify.server_context
      ~transcript_hash:(Schedule.Transcript.hash t.transcript)
  in
  match cv_result with
  | Error e -> fatal t a_internal_error ("signing failed: " ^ e)
  | Ok signature ->
      let cv = W.build_certificate_verify ~scheme:sig_scheme ~signature in
      Schedule.Transcript.feed t.transcript cv;
      Buffer.add_string flight cv;
      let fin =
        W.build_finished
          (Schedule.finished_verify ~hash ~traffic_secret:t.s_hs
             ~transcript_hash:(Schedule.Transcript.hash t.transcript))
      in
      Schedule.Transcript.feed t.transcript fin;
      Buffer.add_string flight fin;
      emit t (Send { level = Handshake; data = Buffer.contents flight });
      (* application secrets bind the transcript through server Finished;
         the client's Finished is over that same transcript (no client
         certificate: we never send CertificateRequest) *)
      derive_app_secrets t ~cipher;
      t.expected_peer_fin <-
        Schedule.finished_verify ~hash ~traffic_secret:t.c_hs
          ~transcript_hash:(Schedule.Transcript.hash t.transcript);
      emit t (Tx_secret { level = Application; cipher; secret = t.s_ap });
      t.state <- S_wait_fin

let server_on_finished t body raw =
  if not (Eqaf.equal t.expected_peer_fin body) then
    fatal t a_decrypt_error "client Finished verification failed"
  else begin
    Schedule.Transcript.feed t.transcript raw;
    let cipher = Option.get t.cipher in
    emit t (Rx_secret { level = Application; cipher; secret = t.c_ap });
    emit t (Handshake_complete { alpn = t.alpn });
    t.state <- Connected
  end

(* ---- dispatch ---- *)

let dispatch t ~level ~typ ~body ~raw =
  if t.state = Failed then ()
  else
    match (t.cfg.role, t.state, level, typ) with
    (* client *)
    | `Client, C_wait_sh, Initial, x when x = W.ht_server_hello ->
        client_on_sh t body raw
    | `Client, C_wait_ee, Handshake, x when x = W.ht_encrypted_extensions ->
        client_on_ee t body raw
    | `Client, C_wait_cert_cr, Handshake, x when x = W.ht_certificate_request
      -> (
        match W.parse_certificate_request body with
        | Error e -> fatal t a_decode_error e
        | Ok context ->
            t.cert_req_context <- Some context;
            Schedule.Transcript.feed t.transcript raw;
            t.state <- C_wait_cert)
    | `Client, (C_wait_cert_cr | C_wait_cert), Handshake, x
      when x = W.ht_certificate ->
        client_on_certificate t body raw
    | `Client, C_wait_cv, Handshake, x when x = W.ht_certificate_verify ->
        client_on_cv t body raw
    | `Client, C_wait_fin, Handshake, x when x = W.ht_finished ->
        client_on_finished t body raw
    | `Client, Connected, Application, x when x = W.ht_new_session_ticket ->
        (* parsed by the splitter; content discarded *)
        ()
    (* server *)
    | `Server, Start, Initial, x when x = W.ht_client_hello ->
        gen_dh t;
        server_on_ch t body raw
    | `Server, S_wait_fin, Handshake, x when x = W.ht_finished ->
        server_on_finished t body raw
    (* both *)
    | _, _, _, x when x = W.ht_key_update ->
        fatal t a_unexpected_message "TLS KeyUpdate is forbidden in QUIC"
    | _ ->
        fatal t a_unexpected_message
          (Printf.sprintf "unexpected message %d in this state" typ)

let handle t ~level data =
  if t.state = Failed then ()
  else begin
    let buf =
      match level with
      | Initial -> t.initial_buf
      | Handshake -> t.hs_buf
      | Application -> t.app_buf
    in
    Buffer.add_string buf data;
    let msgs = Tls_wire.split_messages buf in
    List.iter
      (fun (typ, body, raw) ->
        if t.state <> Failed then dispatch t ~level ~typ ~body ~raw)
      msgs
  end
