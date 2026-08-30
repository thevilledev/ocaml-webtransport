# P0 spike verdict: pure-OCaml QUIC backend — SCRATCH (with targeted ports)

Date: 2026-08-30. Subject: anmonteiro/ocaml-quic @ `baaa52e` (2026-03-16), evaluated
as a fork candidate for the `Quic_backend.S` pure-OCaml backend
(plan: `~/.claude/plans/pure-ocaml-quic-backend-behind-partitioned-kitten.md`).

## Verdict

**Write the engine from scratch** (`purequic/`), and **port these proven pieces**
from ocaml-quic with BSD-3 attribution (header comments + `purequic/THIRD_PARTY.md`):

| Port | Why | Budget |
|---|---|---|
| `lib/recovery.ml` (736 L) + `lib_test/test_rfc9002.ml` | Real RFC 9002 (PTO, persistent congestion, NewReno), threads `~now_ms` everywhere, zero clock reads, only dep of substance is `Frame` | ~1 d + frame-type parameterization |
| `lib/crypto.ml` structure + `lib_test/test_packet_protection.ml` | RFC 9001 packet protection proven against BoringSSL in this spike; takes raw string secrets (~15 lines of `Tls.Ciphersuite` coupling to replace) | ~1–2 d |
| `lib/transport_parameters.ml` | Pure codec; note its `is_known` drops ids > 0x10 (we need 0x20 + reliable-reset ids) | ~0.5 d |
| `lib/frame.ml` + `lib/serialize.ml` + `lib/fast_parse.ml` (~1.9 kL) as **reference**, not verbatim | Codec shapes and varint/PN tricks; our codecs stay Bigstringaf-slice-based (their RX copies every STREAM/CRYPTO payload to `string`) | folded into P1 |
| Branch commit `13c536e` (frame-validity-by-encryption-level table) | Applies clean; saves re-deriving the RFC 9000 §12.4 table | ~0.5 d |

Decision rule from the plan: FORK required *all* PASS criteria + coupling "liftable" +
adaptation < scratch P2+P3. Result: PASS criteria essentially met, but coupling =
**moderate** and fork ≈ **25–40 days** vs scratch P2+P3 ≈ 15–18 days. Ties (and
worse) break to SCRATCH.

## Interop evidence (the surprising part — it PASSED)

Setup: this repo's quiche/BoringSSL stack on one side (spike/raw_echo_{server,client}.ml,
ALPN `h3`, P-256 devcert), ocaml-quic on the other (their `quic-eio` runtime; crypto
flipped to `` `Legacy `` = mirage-crypto; their `?should_drop` hook for seeded 5% loss).

| Direction | Clean | 5% loss (both dirs) |
|---|---|---|
| ocaml-quic client → quiche server | handshake + 10 KiB bidi echo, 0.017 s | 0.164 s, intact |
| quiche client → ocaml-quic server | handshake + 10 KiB bidi echo; server processed our app CONNECTION_CLOSE code 42 (`close_app: done 42`) | intact |

- Builds unmodified on OCaml **5.4.1** with opam deps (mirage-crypto 2.4, tls 2.1.2 era
  vendored fork); patch bill: 1 sanctioned line (`lib/crypto.ml:46` → `` `Legacy ``),
  7 test-only lines (`Frame.payload` variant drift), `--profile release` (warnings-as-errors).
- Their own suite: **116/116 green under mirage-crypto** (incl. RFC 9001 vectors ×50,
  RFC 9002 ×47).
- So the "never proven against a foreign peer" debt is retired for the paths exercised:
  packet protection, handshake TLS glue (both roles — server cert flight + CertificateVerify
  signing worked against BoringSSL verification-side), loss recovery, stream happy path,
  close receive-side.

Caveats that keep this from flipping the verdict: `Transport.shutdown` sends **nothing**
on the wire (no public connection-level close-with-code; the only public path to a
CONNECTION_CLOSE app frame is per-stream `Stream.report_application_error`, empty reason
forced); their client also hangs after `shutdown` (needed SIGALRM once).

## Spike side-catch: real bug in OUR eio driver (fixed)

`Webtransport_eio.Raw.read` dropped the fin flag when the backend returned data+fin in
one call (`Ok (n>0, true)` → `` `Data n ``). The next read hit quiche after stream
collection → `InvalidStreamState` → `Invalid_argument "read: invalid stream"` + poisoned
pump mutex. Never fired quiche↔quiche (quiche peers ack lazily enough that the follow-up
read gets `Done`+`stream_finished` → `` `Fin ``); ocaml-quic acks promptly and exposed it.
Engine paths were already safe (`rfin` tracking in `read_attached`); lwt has no raw-read
path. Fix: `fin_pending` table in the Raw conn. Full suite + Chrome interop green after.

Lesson institutionalized in the plan: the P1+ `cross_pair` suite (pure↔quiche in-process)
exists precisely to catch ack-timing-dependent divergence like this.

## Fork-cost checklist (abridged; full numbers in the session notes)

1. **Endpoint→connection lift: moderate.** `Connection.t` already owns writer/recovery/
   spaces/streams; but ~350 lines of per-connection control flow live at the `Transport`
   level (`on_timeout` 80 L, `packet_handler` 200 L, …), one shared `Reader.t` whose
   decrypt callback does CID lookups mid-parse, and endpoint-level mutable
   `current_peer_address`. 7 entanglement points.
2. **Callbacks → event queue: the real bill (12–15 d).** ~27 sites, but `lib/stream.ml`
   (942 L) *is* a Faraday callback protocol (mutable `on_read`/`on_eof`, re-entrant
   `do_execute_read`, dual-mode producer, flush-callback queue). Rewrite, not rewire.
3. **recovery.ml: port-worthy.** Clean `~now_ms` threading; callers = transport only.
4. **Packet protection: near-portable.** Raw string secrets; ~15 provider-specific lines.
5. **Datagrams (RFC 9221): absent**; ~20 edits across 6 files incl. a missing TX packet
   packer (`send_frames` fixes frames at enqueue time) and `transport_parameters.is_known`
   dropping 0x20. 3–5 d in their tree.
6. **Determinism: good.** Zero wall-clock reads in `lib/`; one global-RNG site
   (`cID.ml:51`); `now_ms` pulled via closure at ~6 spots rather than threaded.
7. **Buffers:** RX bigstring end-to-end but STREAM/CRYPTO payloads copied to `string`
   per frame; TX ≥2 copies/packet; `Frame.payload` 3-way variant papers over it.
8. **Fix branches:** the four `codex/quic-*` branches are one nested stack (7 real
   commits + 6 unrelated), 72 commits stale, conflicting in `transport.ml`;
   `fix/quic-key-update-state-sync` is dead (targets deleted `parse.ml`). Only
   `13c536e` applies clean.
9. **Missing-feature bill:** key update **absent** (KDF primitive has zero callers; key
   phase bit unread and marked TODO), anti-amplification **absent**, VN emission
   **absent** (serializer has zero callers), stateless-reset detection **absent**,
   closing/draining **absent** on master, NEW_CONNECTION_ID **partial** (sets dest_cid,
   no CID set/RETIRE emission, stray debug eprintf), ECN dead code, Retry emission
   absent (client RX works). Idle timeout and PATH_CHALLENGE response: present.

**Fork ≈ 25–40 d** (lift 4 + events 12–15 + datagrams 4 + close API 2 + absent
protocol machinery ~8) to end up rewriting exactly the two files (`transport.ml`,
`stream.ml`) the seam shape dislikes most — vs **~4–6 d of ports** that capture the
proven 2.3 kL under the scratch plan whose P2+P3 ≈ 15–18 d.

## Consequences for the plan

- P1/P2/P3 proceed as written (scratch branch). Port budget lands in P1 (codecs,
  crypto vectors harness) and P3 (recovery).
- The pure engine must return `` `Fin `` forever on post-fin `stream_recv` (never
  `` `Invalid `` after clean end) — quiche's collection behavior is the leak that hid
  the driver bug.
- Add to P3 checklist: prompt-ACK behavior like ocaml-quic's is a good default *and*
  a cross_pair scenario (ack timing changes peer-visible stream collection).
- Spike harness (`spike/` here + `spike/` in the scratch ocaml-quic checkout) is
  throwaway; not committed. Reproduction: clone ocaml-quic @ `baaa52e`, flip
  `lib/crypto.ml:46` to `` `Legacy ``, `dune build --profile release eio/ spike/`,
  run against `spike/raw_echo_server.exe`.
