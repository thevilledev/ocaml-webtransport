#!/bin/bash
# quic-interop-runner endpoint entrypoint. The simulator's setup.sh
# installs the network routing; then we run the WebTransport endpoint,
# which reads ROLE / TESTCASE / PROTOCOLS / REQUESTS from the environment
# and exits 127 on an unsupported TESTCASE.
set -e

/setup.sh

export QLOGDIR="${QLOGDIR:-/logs/qlog}"
mkdir -p "$QLOGDIR"
export WT_QLOG_DIR="$QLOGDIR"

if [ "$ROLE" == "client" ]; then
    /wait-for-it.sh sim:57832 -s -t 30
    wt_interop 2>&1 | tee /logs/client.log
else
    wt_interop 2>&1 | tee /logs/server.log
fi
