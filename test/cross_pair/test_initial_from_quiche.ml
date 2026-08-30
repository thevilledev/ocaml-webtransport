(* Cross-implementation check: purequic removes the packet protection of a
   live Initial produced by quiche/BoringSSL and reads the ClientHello out
   of its CRYPTO frames. Proves header parsing, initial key derivation,
   header protection removal and AEAD open against a foreign sender —
   before purequic has any TLS or connection machinery of its own. *)

let test_unprotect_live_initial () =
  let ccfg = Quiche.Config.create () in
  (match Quiche.Config.set_application_protos ccfg [ "h3" ] with
  | Ok () -> ()
  | Error e -> Alcotest.fail (Quiche.err_to_string e));
  Quiche.Config.verify_peer ccfg false;
  let scid = String.init 16 (fun i -> Char.chr (i * 7 land 0xff)) in
  let client =
    Quiche.connect ~server_name:"localhost" ~scid
      ~local:("\127\000\000\001", 1111)
      ~peer:("\127\000\000\001", 4433)
      ccfg
  in
  let buf = Bigstringaf.create 2048 in
  match Quiche.send client buf ~off:0 ~len:1350 with
  | `Done -> Alcotest.fail "quiche produced no initial packet"
  | `Error e -> Alcotest.fail (Quiche.err_to_string e)
  | `Packet (n, _) -> (
      Alcotest.(check bool) "client initial is padded to >= 1200" true
        (n >= 1200);
      match Purequic.Packet.parse buf ~off:0 ~len:n ~short_dcid_len:16 with
      | Error e -> Alcotest.fail ("purequic parse: " ^ e)
      | Ok located -> (
          let dcid =
            match located.Purequic.Packet.hdr with
            | Purequic.Packet.Long
                { kind = Purequic.Packet.Initial; version = 1l; dcid; scid = s; _ }
              ->
                Alcotest.(check string) "scid echoed" scid s;
                dcid
            | _ -> Alcotest.fail "not parsed as a v1 initial"
          in
          let _, rx = Purequic.Aead.initial_keys ~dcid ~role:`Server in
          match Purequic.Packet.open_ ~keys:rx ~largest:None buf located with
          | None -> Alcotest.fail "purequic could not unprotect the packet"
          | Some (pn, plaintext) -> (
              Alcotest.(check int) "first packet number" 0 pn;
              let pbuf =
                Bigstringaf.of_string plaintext ~off:0
                  ~len:(String.length plaintext)
              in
              match
                Purequic.Frame.parse_all pbuf ~off:0
                  ~len:(String.length plaintext)
              with
              | Error e -> Alcotest.fail ("frame parse: " ^ e)
              | Ok frames -> (
                  (* collect CRYPTO data in offset order; expect a
                     ClientHello at the front *)
                  let crypto =
                    List.filter_map
                      (function
                        | Purequic.Frame.Crypto { off; data } ->
                            Some (off, Purequic.Frame.payload_to_string data)
                        | _ -> None)
                      frames
                    |> List.sort compare
                  in
                  match crypto with
                  | (0, ch) :: _ ->
                      Alcotest.(check bool) "has crypto data" true
                        (String.length ch > 4);
                      Alcotest.(check int) "TLS handshake type = ClientHello" 1
                        (Char.code ch.[0]);
                      let msg_len =
                        (Char.code ch.[1] lsl 16)
                        lor (Char.code ch.[2] lsl 8)
                        lor Char.code ch.[3]
                      in
                      Alcotest.(check bool) "clienthello length sane" true
                        (msg_len > 100 && msg_len < 4096)
                  | _ -> Alcotest.fail "no CRYPTO frame at offset 0"))))

let () =
  Alcotest.run "cross_pair"
    [
      ( "initial",
        [ ("unprotect live quiche initial", `Quick, test_unprotect_live_initial) ]
      );
    ]
