(* Smoke test for the quiche bindings: link, create a client connection,
   produce a real Initial packet, and parse its header back. *)

let localhost = "\127\000\000\001"
let scid = String.init 16 (fun i -> Char.chr (i * 7 land 0xff))

let make_config () =
  let cfg = Quiche.Config.create () in
  (match Quiche.Config.set_application_protos cfg [ "h3" ] with
  | Ok () -> ()
  | Error e -> Alcotest.fail (Quiche.err_to_string e));
  Quiche.Config.verify_peer cfg false;
  Quiche.Config.set_max_idle_timeout cfg 30_000L;
  Quiche.Config.set_initial_max_data cfg 1_000_000;
  Quiche.Config.set_initial_max_stream_data_bidi_local cfg 100_000;
  Quiche.Config.set_initial_max_stream_data_bidi_remote cfg 100_000;
  Quiche.Config.set_initial_max_stream_data_uni cfg 100_000;
  Quiche.Config.set_initial_max_streams_bidi cfg 16;
  Quiche.Config.set_initial_max_streams_uni cfg 16;
  Quiche.Config.enable_dgram cfg true 16 16;
  cfg

let test_version () =
  let v = Quiche.version () in
  if String.length v = 0 then Alcotest.fail "empty quiche version";
  Printf.printf "libquiche %s\n%!" v

let test_client_initial () =
  let cfg = make_config () in
  let conn =
    Quiche.connect ~server_name:"localhost" ~scid ~local:(localhost, 5555)
      ~peer:(localhost, 4433) cfg
  in
  let buf = Bigstringaf.create 2048 in
  (match Quiche.send conn buf ~off:0 ~len:1350 with
  | `Packet (n, (ip, port)) ->
      Alcotest.(check bool) "initial >= 1200" true (n >= 1200);
      Alcotest.(check string) "dest ip" localhost ip;
      Alcotest.(check int) "dest port" 4433 port;
      (match Quiche.header_info buf ~off:0 ~len:n ~dcil:16 with
      | Ok h ->
          Alcotest.(check int32) "version" 1l h.Quiche.version;
          Alcotest.(check int) "type is Initial" Quiche.initial_type h.Quiche.ty;
          Alcotest.(check string) "our scid" scid h.Quiche.scid;
          Alcotest.(check int) "dcid len" 16 (String.length h.Quiche.dcid)
      | Error e -> Alcotest.fail (Quiche.err_to_string e))
  | `Done -> Alcotest.fail "no packet produced"
  | `Error e -> Alcotest.fail (Quiche.err_to_string e));
  (* A fresh client with an in-flight Initial must have a timer armed. *)
  Alcotest.(check bool) "timeout armed" true (Quiche.timeout_as_nanos conn <> None);
  Alcotest.(check bool) "not established" false (Quiche.is_established conn);
  (* Explicit free is idempotent; the finalizer is only a backstop. *)
  Quiche.conn_free conn;
  Quiche.conn_free conn;
  Quiche.Config.free cfg;
  Quiche.Config.free cfg

let test_use_after_free () =
  let cfg = make_config () in
  Quiche.Config.free cfg;
  match Quiche.Config.set_application_protos cfg [ "h3" ] with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument on use-after-free"

let () =
  Alcotest.run "quiche-smoke"
    [
      ( "smoke",
        [
          Alcotest.test_case "version" `Quick test_version;
          Alcotest.test_case "client initial" `Quick test_client_initial;
          Alcotest.test_case "use after free" `Quick test_use_after_free;
        ] );
    ]
