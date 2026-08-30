/* Hand-written stubs for libquiche.
 *
 * Safety rules (see the project plan):
 * - No stub ever calls back into OCaml (quiche's only callback, debug
 *   logging, is not exposed), so OCaml 5 effects can never meet a C frame.
 * - The OCaml runtime lock is held throughout: every quiche call here is
 *   non-blocking CPU work on in-memory state.
 * - All packet/stream/datagram buffers are bigarrays (Bigstringaf.t): their
 *   data lives outside the OCaml heap and is never moved by the GC.
 * - quiche_config / quiche_conn are custom blocks with idempotent explicit
 *   free plus a finalizer backstop.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <caml/alloc.h>
#include <caml/bigarray.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#include <quiche.h>

/* ---------- handle wrappers ---------- */

typedef struct { quiche_config *ptr; } wt_config;
typedef struct { quiche_conn *ptr; } wt_conn;

#define Config_wrap(v) ((wt_config *)Data_custom_val(v))
#define Conn_wrap(v) ((wt_conn *)Data_custom_val(v))

static void wt_config_finalize(value v) {
  wt_config *w = Config_wrap(v);
  if (w->ptr != NULL) {
    quiche_config_free(w->ptr);
    w->ptr = NULL;
  }
}

static void wt_conn_finalize(value v) {
  wt_conn *w = Conn_wrap(v);
  if (w->ptr != NULL) {
    quiche_conn_free(w->ptr);
    w->ptr = NULL;
  }
}

static struct custom_operations wt_config_ops = {
  "webtransport.quiche.config", wt_config_finalize,
  custom_compare_default,       custom_hash_default,
  custom_serialize_default,     custom_deserialize_default,
  custom_compare_ext_default,   custom_fixed_length_default
};

static struct custom_operations wt_conn_ops = {
  "webtransport.quiche.conn",  wt_conn_finalize,
  custom_compare_default,      custom_hash_default,
  custom_serialize_default,    custom_deserialize_default,
  custom_compare_ext_default,  custom_fixed_length_default
};

static quiche_config *config_ptr(value v) {
  quiche_config *p = Config_wrap(v)->ptr;
  if (p == NULL) caml_invalid_argument("quiche: config used after free");
  return p;
}

static quiche_conn *conn_ptr(value v) {
  quiche_conn *p = Conn_wrap(v)->ptr;
  if (p == NULL) caml_invalid_argument("quiche: conn used after free");
  return p;
}

static uint8_t *ba_ptr(value v_buf, value v_off) {
  return (uint8_t *)Caml_ba_data_val(v_buf) + Long_val(v_off);
}

/* addr = (string * int): raw 4/16-byte IP in network order, port. */
static socklen_t build_sockaddr(value v_addr, struct sockaddr_storage *ss) {
  value v_ip = Field(v_addr, 0);
  int port = Int_val(Field(v_addr, 1));
  size_t n = caml_string_length(v_ip);
  memset(ss, 0, sizeof(*ss));
  if (n == 4) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
#ifdef SIN6_LEN
    sin->sin_len = sizeof(*sin);
#endif
    memcpy(&sin->sin_addr, String_val(v_ip), 4);
    sin->sin_port = htons((uint16_t)port);
    return (socklen_t)sizeof(*sin);
  } else if (n == 16) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    sin6->sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sin6->sin6_len = sizeof(*sin6);
#endif
    memcpy(&sin6->sin6_addr, String_val(v_ip), 16);
    sin6->sin6_port = htons((uint16_t)port);
    return (socklen_t)sizeof(*sin6);
  }
  caml_invalid_argument("quiche: address must be 4 or 16 raw bytes");
}

static value alloc_addr(const struct sockaddr_storage *ss) {
  CAMLparam0();
  CAMLlocal2(v_ip, v_res);
  int port = 0;
  if (ss->ss_family == AF_INET) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
    v_ip = caml_alloc_initialized_string(4, (const char *)&sin->sin_addr);
    port = ntohs(sin->sin_port);
  } else if (ss->ss_family == AF_INET6) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
    v_ip = caml_alloc_initialized_string(16, (const char *)&sin6->sin6_addr);
    port = ntohs(sin6->sin6_port);
  } else {
    v_ip = caml_alloc_string(0);
  }
  v_res = caml_alloc_tuple(2);
  Store_field(v_res, 0, v_ip);
  Store_field(v_res, 1, Val_int(port));
  CAMLreturn(v_res);
}

/* ---------- misc ---------- */

CAMLprim value ocaml_quiche_version(value v_unit) {
  CAMLparam1(v_unit);
  CAMLreturn(caml_copy_string(quiche_version()));
}

/* ---------- config ---------- */

CAMLprim value ocaml_quiche_config_new(value v_ver) {
  CAMLparam1(v_ver);
  CAMLlocal1(v_res);
  quiche_config *cfg = quiche_config_new((uint32_t)Int32_val(v_ver));
  if (cfg == NULL) caml_failwith("quiche_config_new returned NULL");
  v_res = caml_alloc_custom(&wt_config_ops, sizeof(wt_config), 0, 1);
  Config_wrap(v_res)->ptr = cfg;
  CAMLreturn(v_res);
}

CAMLprim value ocaml_quiche_config_free(value v) {
  CAMLparam1(v);
  wt_config_finalize(v);
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quiche_config_load_cert_chain(value v_cfg, value v_path) {
  CAMLparam2(v_cfg, v_path);
  int rc = quiche_config_load_cert_chain_from_pem_file(config_ptr(v_cfg),
                                                       String_val(v_path));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_config_load_priv_key(value v_cfg, value v_path) {
  CAMLparam2(v_cfg, v_path);
  int rc = quiche_config_load_priv_key_from_pem_file(config_ptr(v_cfg),
                                                     String_val(v_path));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_config_load_verify_locations(value v_cfg,
                                                         value v_path) {
  CAMLparam2(v_cfg, v_path);
  int rc = quiche_config_load_verify_locations_from_file(config_ptr(v_cfg),
                                                         String_val(v_path));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_config_verify_peer(value v_cfg, value v_b) {
  CAMLparam2(v_cfg, v_b);
  quiche_config_verify_peer(config_ptr(v_cfg), Bool_val(v_b));
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quiche_config_set_application_protos(value v_cfg,
                                                          value v_wire) {
  CAMLparam2(v_cfg, v_wire);
  int rc = quiche_config_set_application_protos(
      config_ptr(v_cfg), (const uint8_t *)String_val(v_wire),
      caml_string_length(v_wire));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_config_set_max_idle_timeout(value v_cfg,
                                                        value v_ms) {
  CAMLparam2(v_cfg, v_ms);
  quiche_config_set_max_idle_timeout(config_ptr(v_cfg),
                                     (uint64_t)Int64_val(v_ms));
  CAMLreturn(Val_unit);
}

#define CONFIG_SET_SIZE(name, fn)                                            \
  CAMLprim value name(value v_cfg, value v_n) {                              \
    CAMLparam2(v_cfg, v_n);                                                  \
    fn(config_ptr(v_cfg), (size_t)Long_val(v_n));                            \
    CAMLreturn(Val_unit);                                                    \
  }

#define CONFIG_SET_U64(name, fn)                                             \
  CAMLprim value name(value v_cfg, value v_n) {                              \
    CAMLparam2(v_cfg, v_n);                                                  \
    fn(config_ptr(v_cfg), (uint64_t)Long_val(v_n));                          \
    CAMLreturn(Val_unit);                                                    \
  }

CONFIG_SET_SIZE(ocaml_quiche_config_set_max_recv_udp_payload_size,
                quiche_config_set_max_recv_udp_payload_size)
CONFIG_SET_SIZE(ocaml_quiche_config_set_max_send_udp_payload_size,
                quiche_config_set_max_send_udp_payload_size)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_data,
               quiche_config_set_initial_max_data)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_stream_data_bidi_local,
               quiche_config_set_initial_max_stream_data_bidi_local)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_stream_data_bidi_remote,
               quiche_config_set_initial_max_stream_data_bidi_remote)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_stream_data_uni,
               quiche_config_set_initial_max_stream_data_uni)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_streams_bidi,
               quiche_config_set_initial_max_streams_bidi)
CONFIG_SET_U64(ocaml_quiche_config_set_initial_max_streams_uni,
               quiche_config_set_initial_max_streams_uni)

CAMLprim value ocaml_quiche_config_enable_dgram(value v_cfg, value v_on,
                                                value v_rq, value v_sq) {
  CAMLparam4(v_cfg, v_on, v_rq, v_sq);
  quiche_config_enable_dgram(config_ptr(v_cfg), Bool_val(v_on),
                             (size_t)Long_val(v_rq), (size_t)Long_val(v_sq));
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_quiche_config_grease(value v_cfg, value v_b) {
  CAMLparam2(v_cfg, v_b);
  quiche_config_grease(config_ptr(v_cfg), Bool_val(v_b));
  CAMLreturn(Val_unit);
}

/* ---------- stateless packet helpers ---------- */

/* Returns (rc, version, type, scid, dcid, token). */
CAMLprim value ocaml_quiche_header_info(value v_buf, value v_off, value v_len,
                                        value v_dcil) {
  CAMLparam4(v_buf, v_off, v_len, v_dcil);
  CAMLlocal4(v_scid, v_dcid, v_token, v_res);
  uint32_t version = 0;
  uint8_t type = 0;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  size_t scid_len = sizeof(scid);
  uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t dcid_len = sizeof(dcid);
  uint8_t token[256];
  size_t token_len = sizeof(token);
  int rc = quiche_header_info(ba_ptr(v_buf, v_off), (size_t)Long_val(v_len),
                              (size_t)Long_val(v_dcil), &version, &type, scid,
                              &scid_len, dcid, &dcid_len, token, &token_len);
  if (rc < 0) {
    scid_len = 0;
    dcid_len = 0;
    token_len = 0;
  }
  v_scid = caml_alloc_initialized_string(scid_len, (const char *)scid);
  v_dcid = caml_alloc_initialized_string(dcid_len, (const char *)dcid);
  v_token = caml_alloc_initialized_string(token_len, (const char *)token);
  v_res = caml_alloc_tuple(6);
  Store_field(v_res, 0, Val_int(rc));
  Store_field(v_res, 1, caml_copy_int32((int32_t)version));
  Store_field(v_res, 2, Val_int(type));
  Store_field(v_res, 3, v_scid);
  Store_field(v_res, 4, v_dcid);
  Store_field(v_res, 5, v_token);
  CAMLreturn(v_res);
}

CAMLprim value ocaml_quiche_negotiate_version(value v_scid, value v_dcid,
                                              value v_buf, value v_off,
                                              value v_len) {
  CAMLparam5(v_scid, v_dcid, v_buf, v_off, v_len);
  ssize_t rc = quiche_negotiate_version(
      (const uint8_t *)String_val(v_scid), caml_string_length(v_scid),
      (const uint8_t *)String_val(v_dcid), caml_string_length(v_dcid),
      ba_ptr(v_buf, v_off), (size_t)Long_val(v_len));
  CAMLreturn(Val_long(rc));
}

/* ---------- connection lifecycle ---------- */

static value alloc_conn(quiche_conn *conn) {
  CAMLparam0();
  CAMLlocal1(v_res);
  v_res = caml_alloc_custom(&wt_conn_ops, sizeof(wt_conn), 0, 1);
  Conn_wrap(v_res)->ptr = conn;
  CAMLreturn(v_res);
}

CAMLprim value ocaml_quiche_connect(value v_sn, value v_scid, value v_local,
                                    value v_peer, value v_cfg) {
  CAMLparam5(v_sn, v_scid, v_local, v_peer, v_cfg);
  struct sockaddr_storage local, peer;
  socklen_t local_len = build_sockaddr(v_local, &local);
  socklen_t peer_len = build_sockaddr(v_peer, &peer);
  const char *sn = Is_none(v_sn) ? NULL : String_val(Some_val(v_sn));
  quiche_conn *conn = quiche_connect(
      sn, (const uint8_t *)String_val(v_scid), caml_string_length(v_scid),
      (struct sockaddr *)&local, local_len, (struct sockaddr *)&peer, peer_len,
      config_ptr(v_cfg));
  if (conn == NULL) caml_failwith("quiche_connect failed");
  CAMLreturn(alloc_conn(conn));
}

CAMLprim value ocaml_quiche_accept(value v_scid, value v_odcid, value v_local,
                                   value v_peer, value v_cfg) {
  CAMLparam5(v_scid, v_odcid, v_local, v_peer, v_cfg);
  struct sockaddr_storage local, peer;
  socklen_t local_len = build_sockaddr(v_local, &local);
  socklen_t peer_len = build_sockaddr(v_peer, &peer);
  const uint8_t *odcid = NULL;
  size_t odcid_len = 0;
  if (Is_some(v_odcid)) {
    odcid = (const uint8_t *)String_val(Some_val(v_odcid));
    odcid_len = caml_string_length(Some_val(v_odcid));
  }
  quiche_conn *conn = quiche_accept(
      (const uint8_t *)String_val(v_scid), caml_string_length(v_scid), odcid,
      odcid_len, (struct sockaddr *)&local, local_len, (struct sockaddr *)&peer,
      peer_len, config_ptr(v_cfg));
  if (conn == NULL) caml_failwith("quiche_accept failed");
  CAMLreturn(alloc_conn(conn));
}

CAMLprim value ocaml_quiche_conn_free(value v) {
  CAMLparam1(v);
  wt_conn_finalize(v);
  CAMLreturn(Val_unit);
}

/* ---------- packet I/O ---------- */

CAMLprim value ocaml_quiche_conn_recv_native(value v_conn, value v_buf,
                                             value v_off, value v_len,
                                             value v_from, value v_to) {
  CAMLparam5(v_conn, v_buf, v_off, v_len, v_from);
  CAMLxparam1(v_to);
  struct sockaddr_storage from, to;
  quiche_recv_info info;
  info.from_len = build_sockaddr(v_from, &from);
  info.from = (struct sockaddr *)&from;
  info.to_len = build_sockaddr(v_to, &to);
  info.to = (struct sockaddr *)&to;
  ssize_t rc = quiche_conn_recv(conn_ptr(v_conn), ba_ptr(v_buf, v_off),
                                (size_t)Long_val(v_len), &info);
  CAMLreturn(Val_long(rc));
}

CAMLprim value ocaml_quiche_conn_recv_bytecode(value *argv, int argn) {
  (void)argn;
  return ocaml_quiche_conn_recv_native(argv[0], argv[1], argv[2], argv[3],
                                       argv[4], argv[5]);
}

/* Returns (rc, (ip, port)). On rc < 0 the address is ("", 0). */
CAMLprim value ocaml_quiche_conn_send(value v_conn, value v_buf, value v_off,
                                      value v_len) {
  CAMLparam4(v_conn, v_buf, v_off, v_len);
  CAMLlocal2(v_addr, v_res);
  quiche_send_info info;
  memset(&info, 0, sizeof(info));
  ssize_t rc = quiche_conn_send(conn_ptr(v_conn), ba_ptr(v_buf, v_off),
                                (size_t)Long_val(v_len), &info);
  if (rc >= 0) {
    v_addr = alloc_addr(&info.to);
  } else {
    v_addr = caml_alloc_tuple(2);
    Store_field(v_addr, 0, caml_alloc_string(0));
    Store_field(v_addr, 1, Val_int(0));
  }
  v_res = caml_alloc_tuple(2);
  Store_field(v_res, 0, Val_long(rc));
  Store_field(v_res, 1, v_addr);
  CAMLreturn(v_res);
}

/* ---------- timers ---------- */

CAMLprim value ocaml_quiche_conn_timeout_as_nanos(value v_conn) {
  CAMLparam1(v_conn);
  uint64_t ns = quiche_conn_timeout_as_nanos(conn_ptr(v_conn));
  CAMLreturn(caml_copy_int64((int64_t)ns));
}

CAMLprim value ocaml_quiche_conn_on_timeout(value v_conn) {
  CAMLparam1(v_conn);
  quiche_conn_on_timeout(conn_ptr(v_conn));
  CAMLreturn(Val_unit);
}

/* ---------- state ---------- */

#define CONN_BOOL(name, fn)                                                  \
  CAMLprim value name(value v_conn) {                                        \
    CAMLparam1(v_conn);                                                      \
    CAMLreturn(Val_bool(fn(conn_ptr(v_conn))));                              \
  }

CONN_BOOL(ocaml_quiche_conn_is_established, quiche_conn_is_established)
CONN_BOOL(ocaml_quiche_conn_is_closed, quiche_conn_is_closed)
CONN_BOOL(ocaml_quiche_conn_is_draining, quiche_conn_is_draining)

CAMLprim value ocaml_quiche_conn_close(value v_conn, value v_app, value v_code,
                                       value v_reason) {
  CAMLparam4(v_conn, v_app, v_code, v_reason);
  int rc = quiche_conn_close(conn_ptr(v_conn), Bool_val(v_app),
                             (uint64_t)Long_val(v_code),
                             (const uint8_t *)String_val(v_reason),
                             caml_string_length(v_reason));
  CAMLreturn(Val_int(rc));
}

/* ---------- streams ---------- */

/* Returns (rc, fin, err_code). */
CAMLprim value ocaml_quiche_conn_stream_recv(value v_conn, value v_id,
                                             value v_buf, value v_off,
                                             value v_len) {
  CAMLparam5(v_conn, v_id, v_buf, v_off, v_len);
  CAMLlocal1(v_res);
  bool fin = false;
  uint64_t ec = 0;
  ssize_t rc = quiche_conn_stream_recv(
      conn_ptr(v_conn), (uint64_t)Long_val(v_id), ba_ptr(v_buf, v_off),
      (size_t)Long_val(v_len), &fin, &ec);
  v_res = caml_alloc_tuple(3);
  Store_field(v_res, 0, Val_long(rc));
  Store_field(v_res, 1, Val_bool(fin));
  Store_field(v_res, 2, Val_long((long)ec));
  CAMLreturn(v_res);
}

/* Returns (rc, err_code). */
CAMLprim value ocaml_quiche_conn_stream_send_native(value v_conn, value v_id,
                                                    value v_buf, value v_off,
                                                    value v_len, value v_fin) {
  CAMLparam5(v_conn, v_id, v_buf, v_off, v_len);
  CAMLxparam1(v_fin);
  CAMLlocal1(v_res);
  uint64_t ec = 0;
  ssize_t rc = quiche_conn_stream_send(
      conn_ptr(v_conn), (uint64_t)Long_val(v_id), ba_ptr(v_buf, v_off),
      (size_t)Long_val(v_len), Bool_val(v_fin), &ec);
  v_res = caml_alloc_tuple(2);
  Store_field(v_res, 0, Val_long(rc));
  Store_field(v_res, 1, Val_long((long)ec));
  CAMLreturn(v_res);
}

CAMLprim value ocaml_quiche_conn_stream_send_bytecode(value *argv, int argn) {
  (void)argn;
  return ocaml_quiche_conn_stream_send_native(argv[0], argv[1], argv[2],
                                              argv[3], argv[4], argv[5]);
}

CAMLprim value ocaml_quiche_conn_stream_capacity(value v_conn, value v_id) {
  CAMLparam2(v_conn, v_id);
  ssize_t rc =
      quiche_conn_stream_capacity(conn_ptr(v_conn), (uint64_t)Long_val(v_id));
  CAMLreturn(Val_long(rc));
}

CAMLprim value ocaml_quiche_conn_stream_shutdown(value v_conn, value v_id,
                                                 value v_dir, value v_err) {
  CAMLparam4(v_conn, v_id, v_dir, v_err);
  enum quiche_shutdown dir =
      Int_val(v_dir) == 0 ? QUICHE_SHUTDOWN_READ : QUICHE_SHUTDOWN_WRITE;
  int rc = quiche_conn_stream_shutdown(conn_ptr(v_conn),
                                       (uint64_t)Long_val(v_id), dir,
                                       (uint64_t)Long_val(v_err));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_conn_stream_readable_next(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(Val_long(quiche_conn_stream_readable_next(conn_ptr(v_conn))));
}

CAMLprim value ocaml_quiche_conn_stream_writable_next(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(Val_long(quiche_conn_stream_writable_next(conn_ptr(v_conn))));
}

CAMLprim value ocaml_quiche_conn_stream_writable(value v_conn, value v_id,
                                                 value v_len) {
  CAMLparam3(v_conn, v_id, v_len);
  int rc = quiche_conn_stream_writable(conn_ptr(v_conn),
                                       (uint64_t)Long_val(v_id),
                                       (size_t)Long_val(v_len));
  CAMLreturn(Val_int(rc));
}

CAMLprim value ocaml_quiche_conn_stream_finished(value v_conn, value v_id) {
  CAMLparam2(v_conn, v_id);
  CAMLreturn(Val_bool(quiche_conn_stream_finished(conn_ptr(v_conn),
                                                  (uint64_t)Long_val(v_id))));
}

CAMLprim value ocaml_quiche_conn_peer_streams_left_bidi(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(Val_long((long)quiche_conn_peer_streams_left_bidi(
      conn_ptr(v_conn))));
}

CAMLprim value ocaml_quiche_conn_peer_streams_left_uni(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(
      Val_long((long)quiche_conn_peer_streams_left_uni(conn_ptr(v_conn))));
}

/* Collects a snapshot stream-id iterator into an int array. */
static value collect_stream_ids(quiche_stream_iter *iter) {
  CAMLparam0();
  CAMLlocal1(v_arr);
  size_t cap = 16, n = 0;
  uint64_t stack_ids[16];
  uint64_t *ids = stack_ids;
  uint64_t id;
  while (quiche_stream_iter_next(iter, &id)) {
    if (n == cap) {
      size_t new_cap = cap * 2;
      uint64_t *nids = malloc(new_cap * sizeof(uint64_t));
      if (nids == NULL) {
        if (ids != stack_ids) free(ids);
        quiche_stream_iter_free(iter);
        caml_failwith("quiche: out of memory collecting stream ids");
      }
      memcpy(nids, ids, n * sizeof(uint64_t));
      if (ids != stack_ids) free(ids);
      ids = nids;
      cap = new_cap;
    }
    ids[n++] = id;
  }
  quiche_stream_iter_free(iter);
  if (n == 0) {
    if (ids != stack_ids) free(ids);
    CAMLreturn(Atom(0));
  }
  v_arr = caml_alloc(n, 0);
  for (size_t i = 0; i < n; i++) Store_field(v_arr, i, Val_long((long)ids[i]));
  if (ids != stack_ids) free(ids);
  CAMLreturn(v_arr);
}

CAMLprim value ocaml_quiche_conn_readable_ids(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(collect_stream_ids(quiche_conn_readable(conn_ptr(v_conn))));
}

CAMLprim value ocaml_quiche_conn_writable_ids(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(collect_stream_ids(quiche_conn_writable(conn_ptr(v_conn))));
}

/* ---------- datagrams ---------- */

CAMLprim value ocaml_quiche_conn_dgram_send(value v_conn, value v_buf,
                                            value v_off, value v_len) {
  CAMLparam4(v_conn, v_buf, v_off, v_len);
  ssize_t rc = quiche_conn_dgram_send(conn_ptr(v_conn), ba_ptr(v_buf, v_off),
                                      (size_t)Long_val(v_len));
  CAMLreturn(Val_long(rc));
}

CAMLprim value ocaml_quiche_conn_dgram_recv(value v_conn, value v_buf,
                                            value v_off, value v_len) {
  CAMLparam4(v_conn, v_buf, v_off, v_len);
  ssize_t rc = quiche_conn_dgram_recv(conn_ptr(v_conn), ba_ptr(v_buf, v_off),
                                      (size_t)Long_val(v_len));
  CAMLreturn(Val_long(rc));
}

CAMLprim value ocaml_quiche_conn_dgram_max_writable_len(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(Val_long(quiche_conn_dgram_max_writable_len(conn_ptr(v_conn))));
}

CAMLprim value ocaml_quiche_conn_dgram_recv_queue_len(value v_conn) {
  CAMLparam1(v_conn);
  CAMLreturn(Val_long(quiche_conn_dgram_recv_queue_len(conn_ptr(v_conn))));
}

/* ---------- handshake results ---------- */

CAMLprim value ocaml_quiche_conn_application_proto(value v_conn) {
  CAMLparam1(v_conn);
  const uint8_t *out = NULL;
  size_t out_len = 0;
  quiche_conn_application_proto(conn_ptr(v_conn), &out, &out_len);
  CAMLreturn(caml_alloc_initialized_string(out_len, (const char *)out));
}

CAMLprim value ocaml_quiche_conn_peer_cert(value v_conn) {
  CAMLparam1(v_conn);
  const uint8_t *out = NULL;
  size_t out_len = 0;
  quiche_conn_peer_cert(conn_ptr(v_conn), &out, &out_len);
  CAMLreturn(caml_alloc_initialized_string(out_len, (const char *)out));
}

/* Returns (has_error, is_app, code, reason). */
static value alloc_conn_error(bool has, bool is_app, uint64_t code,
                              const uint8_t *reason, size_t reason_len) {
  CAMLparam0();
  CAMLlocal2(v_reason, v_res);
  v_reason =
      caml_alloc_initialized_string(has ? reason_len : 0, (const char *)reason);
  v_res = caml_alloc_tuple(4);
  Store_field(v_res, 0, Val_bool(has));
  Store_field(v_res, 1, Val_bool(is_app));
  Store_field(v_res, 2, Val_long((long)code));
  Store_field(v_res, 3, v_reason);
  CAMLreturn(v_res);
}

CAMLprim value ocaml_quiche_conn_peer_error(value v_conn) {
  CAMLparam1(v_conn);
  bool is_app = false;
  uint64_t code = 0;
  const uint8_t *reason = NULL;
  size_t reason_len = 0;
  bool has = quiche_conn_peer_error(conn_ptr(v_conn), &is_app, &code, &reason,
                                    &reason_len);
  CAMLreturn(alloc_conn_error(has, is_app, code, reason, reason_len));
}

CAMLprim value ocaml_quiche_conn_local_error(value v_conn) {
  CAMLparam1(v_conn);
  bool is_app = false;
  uint64_t code = 0;
  const uint8_t *reason = NULL;
  size_t reason_len = 0;
  bool has = quiche_conn_local_error(conn_ptr(v_conn), &is_app, &code, &reason,
                                     &reason_len);
  CAMLreturn(alloc_conn_error(has, is_app, code, reason, reason_len));
}

/* ---------- qlog ---------- */

CAMLprim value ocaml_quiche_conn_set_qlog_path(value v_conn, value v_path,
                                               value v_title, value v_desc) {
  CAMLparam4(v_conn, v_path, v_title, v_desc);
#ifdef WT_HAVE_QLOG
  bool ok = quiche_conn_set_qlog_path(conn_ptr(v_conn), String_val(v_path),
                                      String_val(v_title), String_val(v_desc));
  CAMLreturn(Val_bool(ok));
#else
  (void)v_conn;
  (void)v_path;
  (void)v_title;
  (void)v_desc;
  CAMLreturn(Val_false);
#endif
}
