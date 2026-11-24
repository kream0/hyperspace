#!/usr/bin/env bash
# End-to-end transport test with the real binaries: the host replays an
# encoded stream, a headless client receives and validates it.
#   scripts/e2e.sh [BIN_DIR]     (default: target/release)
set -euo pipefail
BIN=${1:-target/release}
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
LOGS=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

run_case() { # name stream host_port client_port extra_client_args...
  local name=$1 stream=$2 hport=$3 cport=$4; shift 4
  echo "=== $name"
  "$BIN/hyperspace-host" --file "$stream" --once --port "$hport" >"$LOGS/$name.host.log" 2>&1 &
  local host=$!
  sleep 0.5
  if ! "$BIN/hyperspace-client" "127.0.0.1:$cport" --headless --stats "$@" 2>&1 | tee "$LOGS/$name.client.log" | tail -4; then
    echo "--- host log"; cat "$LOGS/$name.host.log"; exit 1
  fi
  grep -q "CLIENT OK" "$LOGS/$name.client.log" || { echo "FAILED: $name"; cat "$LOGS/$name.host.log"; exit 1; }
  # Clean disconnect: the host must see the BYE and exit by itself (--once).
  for _ in $(seq 50); do kill -0 $host 2>/dev/null || break; sleep 0.1; done
  if kill -0 $host 2>/dev/null; then echo "FAILED: host did not end the session"; exit 1; fi
  grep -q "disconnected: peer quit" "$LOGS/$name.host.log" || { echo "FAILED: no clean disconnect"; cat "$LOGS/$name.host.log"; exit 1; }
  tail -1 "$LOGS/$name.host.log"
}

run_case h264 testdata/testsrc_720p.h264 45901 45901 --frames 180 --test-input
run_case hevc testdata/testsrc_720p.h265 45902 45902 --frames 180 --test-input
run_case small-packets testdata/testsrc_720p.h265 45903 45903 --frames 120 --packet-size 600
run_case forced-keyframes testdata/testsrc_720p.h264 45904 45904 --frames 120 --test-keyframes

if command -v python3 >/dev/null; then
  for loss in 2 10; do
    python3 scripts/lossy_relay.py $((45910 + loss)) $((45930 + loss)) $loss 2>"$LOGS/relay$loss.log" &
    sleep 0.3
    run_case "loss-${loss}pct" testdata/testsrc_720p.h264 $((45930 + loss)) $((45910 + loss)) --frames 300 --test-input
    grep -E "nacks" "$LOGS/loss-${loss}pct.client.log" | tail -1 || true
  done
fi
echo "ALL E2E TESTS PASSED"
