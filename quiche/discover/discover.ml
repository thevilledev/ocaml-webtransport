module C = Configurator.V1

let install_hint =
  "libquiche not found. Install it with `brew install cloudflare-quiche` \
   (macOS), or build https://github.com/cloudflare/quiche with `cargo build \
   --release --features ffi,qlog,pkg-config-meta` and add the build directory \
   to PKG_CONFIG_PATH, or set QUICHE_INCLUDE_DIR and QUICHE_LIB_DIR."

let () =
  C.main ~name:"quiche" (fun c ->
      let cflags, libs =
        match
          (Sys.getenv_opt "QUICHE_INCLUDE_DIR", Sys.getenv_opt "QUICHE_LIB_DIR")
        with
        | Some inc, Some lib -> ([ "-I" ^ inc ], [ "-L" ^ lib; "-lquiche" ])
        | _ -> (
            match C.Pkg_config.get c with
            | None -> C.die "pkg-config is not available. %s" install_hint
            | Some pc -> (
                match C.Pkg_config.query pc ~package:"quiche" with
                | None -> C.die "%s" install_hint
                | Some conf -> (conf.cflags, conf.libs)))
      in
      (* The Homebrew bottle is built without the qlog feature: quiche.h
         declares quiche_conn_set_qlog_path but the symbol is absent. Probe at
         link time and expose it only when it exists. *)
      let has_qlog =
        C.c_test c ~c_flags:cflags ~link_flags:libs
          {|
#include <quiche.h>
int main(void) {
  void *p = (void *)&quiche_conn_set_qlog_path;
  return p == 0;
}
|}
      in
      let cflags = if has_qlog then "-DWT_HAVE_QLOG" :: cflags else cflags in
      C.Flags.write_sexp "c_flags.sexp" cflags;
      C.Flags.write_sexp "c_library_flags.sexp" libs)
