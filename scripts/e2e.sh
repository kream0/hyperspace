#!/usr/bin/env bash
# End-to-end transport test with the real binaries: the host replays an
# encoded stream, a headless client pairs with it, receives and validates it.
#   scripts/e2e.sh [BIN_DIR]     (default: target/release)
set -euo pipefail
BIN=${1:-target/release}
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
LOGS=$(mktemp -d)
HOSTCFG="$LOGS/host-config"
CLIENTCFG="$LOGS/client-config"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
HOST_PID=

start_host() { # name stream port
  "$BIN/hyperspace-host" --file "$2" --once --port "$3" --no-upnp --no-dht --config-dir "$HOSTCFG" >"$LOGS/$1.host.log" 2>&1 &
  HOST_PID=$!
  for _ in $(seq 50); do [ -s "$HOSTCFG/pairing.txt" ] && grep -q "listening" "$LOGS/$1.host.log" && break; sleep 0.1; done
}

run_case() { # name stream host_port client_port extra_client_args...
  local name=$1 stream=$2 hport=$3 cport=$4; shift 4
  echo "=== $name"
  start_host "$name" "$stream" "$hport"
  if [ ! -s "$CLIENTCFG/host.txt" ]; then
    "$BIN/hyperspace-client" pair "$(cat "$HOSTCFG/pairing.txt")" --config-dir "$CLIENTCFG"
  fi
  if ! "$BIN/hyperspace-client" "127.0.0.1:$cport" --headless --stats --config-dir "$CLIENTCFG" "$@" 2>&1 | tee "$LOGS/$name.client.log" | tail -4; then
    echo "--- host log"; cat "$LOGS/$name.host.log"; exit 1
  fi
  grep -q "CLIENT OK" "$LOGS/$name.client.log" || { echo "FAILED: $name"; cat "$LOGS/$name.host.log"; exit 1; }
  # Clean disconnect: the host must see the BYE and exit by itself (--once).
  for _ in $(seq 50); do kill -0 $HOST_PID 2>/dev/null || break; sleep 0.1; done
  if kill -0 $HOST_PID 2>/dev/null; then echo "FAILED: host did not end the session"; exit 1; fi
  grep -q "disconnected: peer quit" "$LOGS/$name.host.log" || { echo "FAILED: no clean disconnect"; cat "$LOGS/$name.host.log"; exit 1; }
  tail -1 "$LOGS/$name.host.log"
}

run_case h264 testdata/testsrc_720p.h264 45901 45901 --frames 180 --test-input
run_case hevc testdata/testsrc_720p.h265 45902 45902 --frames 180 --test-input
run_case small-packets testdata/testsrc_720p.h265 45903 45903 --frames 120 --packet-size 600
run_case forced-keyframes testdata/testsrc_720p.h264 45904 45904 --frames 120 --test-keyframes

echo "=== wrong-key (a client without the pairing key must get no answer at all)"
start_host wrong-key testdata/testsrc_720p.h264 45905
mkdir -p "$LOGS/stranger"
# Same address, different key.
"$BIN/hyperspace-client" pair "hs1.$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n').127.0.0.1/45905" --config-dir "$LOGS/stranger" >/dev/null
if "$BIN/hyperspace-client" --headless --frames 1 --no-lookup --connect-timeout 2 --config-dir "$LOGS/stranger" >"$LOGS/wrong-key.client.log" 2>&1; then
  echo "FAILED: a client with the wrong key connected"; exit 1
fi
grep -q "no answer from the host" "$LOGS/wrong-key.client.log" || { echo "FAILED: unexpected error"; cat "$LOGS/wrong-key.client.log"; exit 1; }
sed -n '/Addresses tried/,$p' "$LOGS/wrong-key.client.log" | head -3
if grep -q "connected" "$LOGS/wrong-key.host.log"; then echo "FAILED: host accepted a stranger"; exit 1; fi
echo "ignored, as it should be"
# The rightful client still gets in afterwards.
"$BIN/hyperspace-client" 127.0.0.1:45905 --headless --frames 30 --config-dir "$CLIENTCFG" 2>&1 | tail -1
wait $HOST_PID 2>/dev/null || true

if grep -q '\.[0-9A-Za-z_-]*\..*[0-9]/45906' <(start_host saved testdata/testsrc_720p.h264 45906; cat "$HOSTCFG/pairing.txt"; kill $HOST_PID 2>/dev/null); then
  echo "=== saved-host (connect with no address, racing the addresses in the pairing string)"
  start_host saved testdata/testsrc_720p.h264 45906
  "$BIN/hyperspace-client" pair "$(cat "$HOSTCFG/pairing.txt")" --config-dir "$LOGS/saved" >/dev/null
  "$BIN/hyperspace-client" --headless --frames 60 --no-lookup --config-dir "$LOGS/saved" 2>&1 | tee "$LOGS/saved.client.log" | tail -2
  grep -q "CLIENT OK" "$LOGS/saved.client.log" || { echo "FAILED: saved-host"; cat "$LOGS/saved.host.log"; exit 1; }
  wait $HOST_PID 2>/dev/null || true
fi

if command -v python3 >/dev/null; then
  echo "=== port-forwarding (the host asks a stand-in UPnP router to forward its port)"
  python3 scripts/fake_router.py 45960 45961 203.0.113.7 "$LOGS/router.log" &
  ROUTER=$!
  sleep 0.5
  rm -f "$HOSTCFG/pairing.txt"
  HYPERSPACE_UPNP_SEARCH=127.0.0.1:45960 HYPERSPACE_PROBE_VIA=127.0.0.1 "$BIN/hyperspace-host" --file testdata/testsrc_720p.h264 --once --port 45962 \
    --no-dht --config-dir "$HOSTCFG" >"$LOGS/upnp.host.log" 2>&1 &
  HOST_PID=$!
  for _ in $(seq 100); do [ -s "$HOSTCFG/pairing.txt" ] && break; sleep 0.1; done
  grep -q "reachable from the internet at 203.0.113.7:45962.*came back in" "$LOGS/upnp.host.log" || { echo "FAILED: no verified mapping"; cat "$LOGS/upnp.host.log" "$LOGS/router.log"; exit 1; }
  grep -q "203.0.113.7/45962" "$HOSTCFG/pairing.txt" || { echo "FAILED: public address missing from the pairing string"; cat "$HOSTCFG/pairing.txt"; exit 1; }
  grep -q "AddPortMapping.*NewExternalPort=45962.*NewInternalPort=45962.*NewProtocol=UDP" "$LOGS/router.log" || { echo "FAILED: wrong mapping"; cat "$LOGS/router.log"; exit 1; }
  "$BIN/hyperspace-client" 127.0.0.1:45962 --headless --frames 30 --config-dir "$CLIENTCFG" 2>&1 | tail -1
  wait $HOST_PID 2>/dev/null || true
  grep -q "DeletePortMapping.*NewExternalPort=45962" "$LOGS/router.log" || { echo "FAILED: mapping not removed on exit"; cat "$LOGS/router.log"; exit 1; }
  echo "mapped, advertised, and removed on exit"
  kill $ROUTER 2>/dev/null || true

  echo "=== unverified forward (router maps the port but the self-test packet never returns: say so, give the firewall command)"
  python3 scripts/fake_router.py 45966 45967 203.0.113.9 "$LOGS/router3.log" &
  ROUTER=$!
  sleep 0.5
  rm -f "$HOSTCFG/pairing.txt"
  HYPERSPACE_UPNP_SEARCH=127.0.0.1:45966 "$BIN/hyperspace-host" --file testdata/testsrc_720p.h264 --port 45968 \
    --no-dht --config-dir "$HOSTCFG" >"$LOGS/unverified.host.log" 2>&1 &
  HOST_PID=$!
  for _ in $(seq 100); do [ -s "$HOSTCFG/pairing.txt" ] && break; sleep 0.1; done
  grep -q "did not come back in" "$LOGS/unverified.host.log" && grep -q "netsh advfirewall.*localport=45968" "$LOGS/unverified.host.log" \
    || { echo "FAILED: unverified forward not reported"; cat "$LOGS/unverified.host.log"; exit 1; }
  grep -q "203.0.113.9/45968" "$HOSTCFG/pairing.txt" || { echo "FAILED: mapped address missing"; exit 1; }
  echo "reported"
  kill $HOST_PID $ROUTER 2>/dev/null || true

  echo "=== carrier-grade NAT (router's WAN address is not public: must be reported, not advertised)"
  python3 scripts/fake_router.py 45963 45964 100.72.3.4 "$LOGS/router2.log" &
  ROUTER=$!
  sleep 0.5
  rm -f "$HOSTCFG/pairing.txt"
  HYPERSPACE_UPNP_SEARCH=127.0.0.1:45963 "$BIN/hyperspace-host" --file testdata/testsrc_720p.h264 --port 45965 \
    --no-dht --config-dir "$HOSTCFG" >"$LOGS/cgnat.host.log" 2>&1 &
  HOST_PID=$!
  for _ in $(seq 100); do [ -s "$HOSTCFG/pairing.txt" ] && break; sleep 0.1; done
  grep -q "carrier-grade NAT" "$LOGS/cgnat.host.log" || { echo "FAILED: CGNAT not detected"; cat "$LOGS/cgnat.host.log"; exit 1; }
  if grep -q "100.72.3.4" "$HOSTCFG/pairing.txt"; then echo "FAILED: unreachable address advertised"; exit 1; fi
  echo "detected"
  kill $HOST_PID $ROUTER 2>/dev/null || true
  rm -f "$HOSTCFG/pairing.txt"

  for loss in 2 10; do
    python3 scripts/lossy_relay.py $((45910 + loss)) $((45930 + loss)) $loss 2>"$LOGS/relay$loss.log" &
    sleep 0.3
    run_case "loss-${loss}pct" testdata/testsrc_720p.h264 $((45930 + loss)) $((45910 + loss)) --frames 300 --test-input
    grep -E "nacks" "$LOGS/loss-${loss}pct.client.log" | tail -1 || true
  done
fi
echo "ALL E2E TESTS PASSED"
