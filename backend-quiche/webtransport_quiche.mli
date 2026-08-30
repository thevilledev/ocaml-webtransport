(** The default {!Webtransport.Quic_backend.S} implementation, backed by
    Cloudflare quiche.

    Set [WT_QLOG_DIR] to capture per-connection qlog traces (requires a
    libquiche built with the qlog feature; the Homebrew bottle has it
    compiled out, in which case the setting is silently ignored). *)

include Webtransport.Quic_backend.S
