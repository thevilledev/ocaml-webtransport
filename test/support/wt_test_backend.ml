(* Runtime backend selection for the backend-dependent test suites.
   Both backends link into every test binary; WT_BACKEND picks one per
   run, so CI exercises the same executables twice. *)

let name () =
  match Sys.getenv_opt "WT_BACKEND" with
  | None -> "quiche"
  | Some s -> s

let select () : (module Webtransport.Quic_backend.S) =
  match name () with
  | "quiche" -> (module Webtransport_quiche)
  | "pure" -> (module Webtransport_purequic)
  | other -> failwith ("unknown WT_BACKEND (want quiche|pure): " ^ other)
