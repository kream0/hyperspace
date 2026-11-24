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

start_forwarder() { # log listen_port host_port loss_percent: until it is bound (sets FWD_PID)
  python3 scripts/lossy_relay.py "$2" "$3" "$4" 2>"$1" &
  FWD_PID=$!
  for _ in $(seq 100); do
    grep -q "listening on 127.0.0.1:$2" "$1" && return 0
    kill -0 $FWD_PID 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
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
    start_forwarder "$LOGS/relay$loss.log" $((45910 + loss)) $((45930 + loss)) $loss \
      || { echo "FAILED: the forwarder did not start"; cat "$LOGS/relay$loss.log"; exit 1; }
    run_case "loss-${loss}pct" testdata/testsrc_720p.h264 $((45930 + loss)) $((45910 + loss)) --frames 300 --test-input
    grep -E "nacks" "$LOGS/loss-${loss}pct.client.log" | tail -1 || true
  done
fi

# ---- Relay fallback: host and client each reach a relay on loopback (cases a-k).
# Port 47800 is left alone (the CI smoke test and a live relay use it).
# Failures are collected, each with both logs, so one run shows them all.
RELAY_PORT=47811
RELAY="ws://127.0.0.1:$RELAY_PORT"
DEAD=192.0.2.1/45800 # a documentation address: never answers
RHOST="$LOGS/relay-host"
"$BIN/hyperspace-host" --relay-id --config-dir "$RHOST" >"$LOGS/relay.allow" 2>/dev/null
: >"$LOGS/relay-empty.allow"
KEY=$(cut -d. -f2 "$RHOST/host.key")
RELAY_FAILED=
ERRS=
RELAY_PID=

expect() { # file ERE what
  grep -qE -- "$2" "$1" || ERRS+="  $(basename "$1"): missing $3"$'\n'
}
reject() { # file ERE what
  if grep -qE -- "$2" "$1"; then ERRS+="  $(basename "$1"): unexpected $3"$'\n'; fi
}
in_order() { # file what ERE...: each pattern on a line after the last one's
  local f=$1 what=$2 at=0 n pat
  shift 2
  for pat in "$@"; do
    n=$(tail -n +$((at + 1)) "$f" | grep -nE -m1 -- "$pat" | cut -d: -f1 || true)
    if [ -z "$n" ]; then
      ERRS+="  $(basename "$f"): $what: no \"$pat\" after line $at"$'\n'
      return 0
    fi
    at=$((at + n))
  done
}
end_case() { # name logs...
  local name=$1 f; shift
  for f in "$@"; do
    case $f in *client*) if grep -qF -- "$KEY" "$f"; then ERRS+="  $(basename "$f"): shows the pairing key"$'\n'; fi ;; esac
  done
  if [ -n "$ERRS" ]; then
    echo "FAILED: $name"; printf '%s' "$ERRS"
    for f in "$@"; do echo "--- $(basename "$f")"; cat "$f" 2>/dev/null || true; done
    RELAY_FAILED+=" $name"
  else
    echo "ok"
  fi
  ERRS=
}
stop_pid() { [ -n "${1:-}" ] || return 0; kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
start_relay() { # log port allow-file [relay options]; retries the bind (after a kill -9, say)
  local log=$1 port=$2 allow=$3
  shift 3
  for _ in $(seq 20); do
    "$BIN/hyperspace-relay" --listen "127.0.0.1:$port" --allow "$allow" "$@" >"$log" 2>&1 &
    RELAY_PID=$!
    for _ in $(seq 20); do
      grep -q "listening on 127.0.0.1:$port" "$log" && return 0
      kill -0 $RELAY_PID 2>/dev/null || break
      sleep 0.1
    done
    stop_pid $RELAY_PID
    sleep 0.3
  done
  ERRS+="  $(basename "$log"): the relay did not start"$'\n'
  return 1
}
start_rhost() { # name port [relay]: a host with the relay set, until its link is up
  "$BIN/hyperspace-host" --file testdata/testsrc_720p.h264 --port "$2" --no-upnp --no-dht --relay "${3:-$RELAY}" \
    --config-dir "$RHOST" >"$LOGS/$1.host.log" 2>&1 &
  HOST_PID=$!
  for _ in $(seq 100); do grep -q "relay: connected to" "$LOGS/$1.host.log" && return 0; sleep 0.1; done
  ERRS+="  $1.host.log: the host's relay link did not come up"$'\n'
  return 1
}
rpair() { # dir pairing-string
  mkdir -p "$LOGS/$1"
  "$BIN/hyperspace-client" pair "$2" --config-dir "$LOGS/$1" >/dev/null
}
rclient() { # seconds log dir args...: the exit code lands in RC
  local secs=$1 log=$2 dir=$3; shift 3
  RC=0
  timeout "$secs" "$BIN/hyperspace-client" --headless --no-lookup --config-dir "$LOGS/$dir" "$@" >"$LOGS/$log" 2>&1 || RC=$?
}

start_relay "$LOGS/relay.log" $RELAY_PORT "$LOGS/relay.allow" || true
MAIN_RELAY=$RELAY_PID

echo "=== relay-a (the host's address does not answer: the session goes through the relay)"
start_rhost relay-a 45971 || true
rpair rc-a "hs1.$KEY.$DEAD,relay=$RELAY/v1"
rclient 40 relay-a.client.log rc-a --frames 120 --test-input --stats
[ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
expect "$LOGS/relay-a.client.log" "CLIENT OK" "CLIENT OK"
expect "$LOGS/relay-a.client.log" "authenticated with the host through the relay" "the relay as the winner"
expect "$LOGS/relay-a.client.log" "connected through the relay: [0-9]+x[0-9]+" "the connected line"
expect "$LOGS/relay-a.client.log" "via relay" "the relay in the stats line"
expect "$LOGS/relay-a.client.log" "relay link: up [0-9]+ s, 0 reconnects, last close: none, in [0-9.]+ MB / out [0-9.]+ MB, dropped" "the relay link stats at exit"
for _ in $(seq 50); do grep -q "disconnected: peer quit" "$LOGS/relay-a.host.log" && break; sleep 0.1; done
expect "$LOGS/relay-a.host.log" "client .* connected through the relay" "the relayed client"
expect "$LOGS/relay-a.host.log" "disconnected: peer quit" "a clean goodbye through the relay"
grep -h -E "authenticated|connected through|relay link: " "$LOGS/relay-a.client.log" || true
end_case relay-a "$LOGS/relay-a.client.log" "$LOGS/relay-a.host.log" "$LOGS/relay.log"

echo "=== relay-b (the host answers directly too: the direct path wins, the relay link closes)"
rpair rc-b "hs1.$KEY.127.0.0.1/45971,relay=$RELAY/v1"
rclient 40 relay-b.client.log rc-b --frames 60
[ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
expect "$LOGS/relay-b.client.log" "CLIENT OK" "CLIENT OK"
expect "$LOGS/relay-b.client.log" "authenticated with 127.0.0.1:45971" "the direct winner"
expect "$LOGS/relay-b.client.log" "relay link closed: the host answered directly" "the relay link closing"
expect "$LOGS/relay-b.client.log" "connected directly at 127.0.0.1:45971" "the connected line"
reject "$LOGS/relay-b.client.log" "authenticated with the host through the relay" "a relayed session"
grep -h -E "authenticated|answered directly" "$LOGS/relay-b.client.log" || true
# A relay entry this client cannot use: one line, then the direct path as usual.
rpair rc-b2 "hs1.$KEY.127.0.0.1/45971,relay=ftp://relay.example"
rclient 40 relay-b2.client.log rc-b2 --frames 30
[ $RC = 0 ] || ERRS+="  client exited with $RC (bad relay entry)"$'\n'
expect "$LOGS/relay-b2.client.log" "CLIENT OK" "CLIENT OK despite a bad relay entry"
expect "$LOGS/relay-b2.client.log" "ignoring the relay in the pairing string: the relay address must start with wss://" "the bad relay entry's line"
grep -h "ignoring the relay" "$LOGS/relay-b2.client.log" || true
stop_pid $HOST_PID
end_case relay-b "$LOGS/relay-b.client.log" "$LOGS/relay-b2.client.log" "$LOGS/relay-a.host.log"

echo "=== relay-c (the relay does not allow this PC: say who can fix it)"
start_relay "$LOGS/relay-c.relay.log" 47812 "$LOGS/relay-empty.allow" || true
C_PID=$RELAY_PID RELAY_PID=$MAIN_RELAY
rpair rc-c "hs1.$KEY.$DEAD,relay=ws://127.0.0.1:47812/v1"
rclient 20 relay-c.client.log rc-c --frames 1 --connect-timeout 4
[ $RC = 1 ] || ERRS+="  client exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-c.client.log" "this relay does not serve this PC yet: its operator must add the PC.s relay id .hyperspace-host --relay-id prints it.\." "the not-allowed line"
grep -h "relay ws" "$LOGS/relay-c.client.log" || true
stop_pid $C_PID
end_case relay-c "$LOGS/relay-c.client.log" "$LOGS/relay-c.relay.log"

echo "=== relay-d (the PC is not connected to the relay)"
rpair rc-d "hs1.$KEY.$DEAD,relay=$RELAY/v1"
rclient 20 relay-d.client.log rc-d --frames 1 --connect-timeout 4
[ $RC = 1 ] || ERRS+="  client exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-d.client.log" "the PC is not connected to the relay .host not running, older than 0\.3\.0, or started without --relay.\." "the host-offline line"
grep -h "relay ws" "$LOGS/relay-d.client.log" || true
end_case relay-d "$LOGS/relay-d.client.log" "$LOGS/relay.log"

echo "=== relay-e (a client with the wrong key gets nowhere through the relay either)"
start_rhost relay-e 45972 || true
STRANGER=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
rpair rc-e "hs1.$STRANGER.$DEAD,relay=$RELAY/v1"
rclient 20 relay-e.client.log rc-e --frames 1 --connect-timeout 4
[ $RC = 1 ] || ERRS+="  client exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-e.client.log" "this relay does not serve this PC yet" "the not-allowed line"
expect "$LOGS/relay-e.client.log" "this is the pairing string it printed" "the pairing string hint"
reject "$LOGS/relay-e.host.log" "client .* connected" "an accepted stranger"
stop_pid $HOST_PID
end_case relay-e "$LOGS/relay-e.client.log" "$LOGS/relay-e.host.log"

echo "=== relay-f (the relay restarts mid-session: the links come back and the stream goes on)"
start_rhost relay-f 45973 || true
rpair rc-f "hs1.$KEY.$DEAD,relay=$RELAY/v1"
timeout 90 "$BIN/hyperspace-client" --headless --no-lookup --stats --frames 900 --config-dir "$LOGS/rc-f" >"$LOGS/relay-f.client.log" 2>&1 &
CLIENT_PID=$!
for _ in $(seq 150); do grep -q "via relay" "$LOGS/relay-f.client.log" && break; sleep 0.1; done
kill -9 $RELAY_PID 2>/dev/null || true
wait $RELAY_PID 2>/dev/null || true
sleep 0.5
start_relay "$LOGS/relay-f.relay.log" $RELAY_PORT "$LOGS/relay.allow" || true
RC=0
wait $CLIENT_PID || RC=$?
[ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
expect "$LOGS/relay-f.client.log" "CLIENT OK" "CLIENT OK"
expect "$LOGS/relay-f.client.log" "relay link reconnected \([0-9]+ reconnects so far\); it had closed: " "the reconnect line"
expect "$LOGS/relay-f.client.log" "relay link: up [0-9]+ s, [1-9][0-9]* reconnects, last close: " "the reconnect count at exit"
[ "$(grep -c "relay: connected to" "$LOGS/relay-f.host.log")" -ge 2 ] || ERRS+="  relay-f.host.log: the host's relay link did not come back"$'\n'
# Whichever side gets back to the relay first: if the client's link sees the
# host come online, it makes a second session over the same link (and so the
# same local socket); if the host was back first, the session carries on and
# the host moves it to its new socket for this client. Video goes on either way.
if [ "$(grep -c "authenticated with the host through the relay" "$LOGS/relay-f.client.log")" -lt 2 ] \
  && ! grep -qE "client moved to .*through the relay" "$LOGS/relay-f.host.log"; then
  ERRS+="  relay-f: neither a second session nor the session moving to the new link"$'\n'
fi
in_order "$LOGS/relay-f.client.log" "video after the reconnect" \
  "relay link reconnected" "\] [1-9][0-9]* fps  [0-9.]+ Mbit/s.*via relay" "CLIENT OK"
reject "$LOGS/relay-f.client.log" "starting a new relay link" "a new relay link"
grep -h -E "relay link|connecting again|authenticated" "$LOGS/relay-f.client.log" || true
grep -h -E "client moved to|connected through" "$LOGS/relay-f.host.log" || true
end_case relay-f "$LOGS/relay-f.client.log" "$LOGS/relay-f.host.log" "$LOGS/relay-f.relay.log"

echo "=== relay-g (a pairing without a relay: --relay once, then plain runs use it; --relay off; --relay-check)"
rpair rc-g "hs1.$KEY.$DEAD"
rclient 40 relay-g1.client.log rc-g --frames 60 --relay "$RELAY"
[ $RC = 0 ] || ERRS+="  first client exited with $RC"$'\n'
expect "$LOGS/relay-g1.client.log" "relay setting saved to" "the saved setting"
expect "$LOGS/relay-g1.client.log" "CLIENT OK" "CLIENT OK"
grep -qx "ws://127.0.0.1:$RELAY_PORT/v1" "$LOGS/rc-g/relay.txt" || ERRS+="  relay.txt does not hold the relay"$'\n'
rclient 40 relay-g2.client.log rc-g --frames 60
[ $RC = 0 ] || ERRS+="  plain client exited with $RC"$'\n'
expect "$LOGS/relay-g2.client.log" "authenticated with the host through the relay" "the relay, remembered"
expect "$LOGS/relay-g2.client.log" "CLIENT OK" "CLIENT OK"
rclient 20 relay-g3.client.log rc-g --frames 1 --connect-timeout 2 --relay off
[ $RC = 1 ] || ERRS+="  --relay off client exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-g3.client.log" "relay off .saved in .*--relay URL turns it back on" "the relay-off line"
reject "$LOGS/relay-g3.client.log" "through the relay" "the relay, though off"
rclient 20 relay-g4.client.log rc-g --frames 1 --connect-timeout 2
[ $RC = 1 ] || ERRS+="  client after --relay off exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-g4.client.log" "relay off .set in " "the remembered relay-off line"
code=0; timeout 20 "$BIN/hyperspace-client" --relay-check "$RELAY" >"$LOGS/relay-g5.client.log" 2>&1 || code=$?
[ $code = 0 ] || ERRS+="  --relay-check on a live relay exited with $code"$'\n'
expect "$LOGS/relay-g5.client.log" "relay reachable" "the check line"
code=0; timeout 20 "$BIN/hyperspace-client" --relay-check ws://127.0.0.1:47819 >"$LOGS/relay-g6.client.log" 2>&1 || code=$?
[ $code = 1 ] || ERRS+="  --relay-check on no relay exited with $code, expected 1"$'\n'
reject "$LOGS/relay-g6.client.log" "os error" "an OS error number"
# A relay that is not there: the plain reason, with nothing repeated.
rpair rc-g7 "hs1.$KEY.$DEAD,relay=ws://127.0.0.1:47819/v1"
rclient 20 relay-g7.client.log rc-g7 --frames 1 --connect-timeout 2
[ $RC = 1 ] || ERRS+="  client with no relay there exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-g7.client.log" "the relay is not reachable: cannot connect to 127\.0\.0\.1 port 47819: Connection refused\. On a company network, ask IT to allow 127\.0\.0\.1\.$" "the not-reachable line"
reject "$LOGS/relay-g7.client.log" "not reachable.*(os error|47819 \()" "an OS error number or a repeated address"
cat "$LOGS/relay-g5.client.log" "$LOGS/relay-g6.client.log"
grep -h "not reachable" "$LOGS/relay-g7.client.log" || true
stop_pid $HOST_PID
end_case relay-g "$LOGS"/relay-g[1-7].client.log "$LOGS/relay-f.host.log" "$LOGS/relay-f.relay.log"

echo "=== relay-h (the host restarts mid-session: the client connects again over the same relay link)"
start_rhost relay-h1 45974 || true
rpair rc-h "hs1.$KEY.$DEAD,relay=$RELAY/v1"
timeout 90 "$BIN/hyperspace-client" --headless --no-lookup --stats --frames 600 --config-dir "$LOGS/rc-h" >"$LOGS/relay-h.client.log" 2>&1 &
CLIENT_PID=$!
for _ in $(seq 150); do grep -q "via relay" "$LOGS/relay-h.client.log" && break; sleep 0.1; done
kill -9 $HOST_PID 2>/dev/null || true
wait $HOST_PID 2>/dev/null || true
sleep 0.5
start_rhost relay-h2 45974 || true
RC=0
wait $CLIENT_PID || RC=$?
[ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
expect "$LOGS/relay-h.client.log" "CLIENT OK" "CLIENT OK"
[ "$(grep -c "authenticated with the host through the relay" "$LOGS/relay-h.client.log")" -ge 2 ] \
  || ERRS+="  relay-h.client.log: no second session through the relay"$'\n'
expect "$LOGS/relay-h.client.log" "relay link: up [0-9]+ s, 0 reconnects, " "the same link at exit"
reject "$LOGS/relay-h.client.log" "starting a new relay link" "a new relay link"
expect "$LOGS/relay-h2.host.log" "client .* connected through the relay" "the second session at the host"
grep -h -E "relay|connecting again|authenticated" "$LOGS/relay-h.client.log" | grep -v "fps " || true
stop_pid $HOST_PID
end_case relay-h "$LOGS/relay-h.client.log" "$LOGS/relay-h1.host.log" "$LOGS/relay-h2.host.log" "$LOGS/relay-f.relay.log"

echo "=== relay-i (the direct path is cut mid-session: the client connects again, through a new relay link)"
if command -v python3 >/dev/null; then
  # The direct path runs through a forwarder (no loss), so it can be cut
  # while the host, its relay link and its session stay up.
  start_rhost relay-i 45975 || true
  # Bound before the client starts: it tries the relay 600 ms in, so a slow
  # python start would let the relay win the first session.
  start_forwarder "$LOGS/relay-i.forward.log" 45977 45975 0 \
    || ERRS+="  relay-i.forward.log: the forwarder did not start"$'\n'
  rpair rc-i "hs1.$KEY.127.0.0.1/45977,relay=$RELAY/v1"
  timeout 90 "$BIN/hyperspace-client" --headless --no-lookup --stats --frames 600 --config-dir "$LOGS/rc-i" >"$LOGS/relay-i.client.log" 2>&1 &
  CLIENT_PID=$!
  for _ in $(seq 150); do grep -q "connected directly" "$LOGS/relay-i.client.log" && break; sleep 0.1; done
  grep -q "connected directly" "$LOGS/relay-i.client.log" \
    || ERRS+="  relay-i.client.log: no direct session within 15 s (through the forwarder on 45977)"$'\n'
  sleep 1
  stop_pid $FWD_PID
  RC=0
  wait $CLIENT_PID || RC=$?
  [ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
  in_order "$LOGS/relay-i.client.log" "direct, then the relay" \
    "relay link closed: the host answered directly" "connected directly at 127\.0\.0\.1:45977" \
    "lost contact with the host; connecting again" "relay: connected to ws://127\.0\.0\.1:$RELAY_PORT" \
    "authenticated with the host through the relay" "connected through the relay: [0-9]+x[0-9]+" "CLIENT OK"
  reject "$LOGS/relay-i.client.log" "starting a new relay link" "a stopped relay link"
  in_order "$LOGS/relay-i.host.log" "direct, then the relay" \
    "client 127\.0\.0\.1:[0-9]+ connected \(fps" "client [^ ]+ connected through the relay"
  grep -h -E "relay|directly|connecting again|authenticated" "$LOGS/relay-i.client.log" | grep -v "fps " || true
  stop_pid $HOST_PID
  end_case relay-i "$LOGS/relay-i.client.log" "$LOGS/relay-i.host.log" "$LOGS/relay-i.forward.log" "$LOGS/relay-f.relay.log"
else
  echo "skipped (no python3 for the forwarder)"
fi

echo "=== relay-j (the client drops its session: the live host takes a second handshake over the same link)"
start_rhost relay-j 45978 || true
rpair rc-j "hs1.$KEY.$DEAD,relay=$RELAY/v1"
# 360 frames: the first session is cut after 2 s (about 120 at 60 fps), so
# CLIENT OK needs video on the second one too; the stats line after the
# second handshake shows it arriving.
rclient 60 relay-j.client.log rc-j --stats --frames 360 --test-reconnect
[ $RC = 0 ] || ERRS+="  client exited with $RC"$'\n'
in_order "$LOGS/relay-j.client.log" "two sessions over one link, video on both" \
  "authenticated with the host through the relay" "\] [1-9][0-9]* fps  [0-9.]+ Mbit/s" \
  "test: dropped the session without a goodbye \(--test-reconnect\); connecting again" \
  "authenticated with the host through the relay" "\] [1-9][0-9]* fps  [0-9.]+ Mbit/s" "CLIENT OK"
expect "$LOGS/relay-j.client.log" "relay link: up [0-9]+ s, 0 reconnects, " "the same link at exit"
reject "$LOGS/relay-j.client.log" "starting a new relay link|lost contact" "a new link or a lost session"
# The second handshake comes from the same relayed address while the first
# session is still live, and replaces it.
pair=$(sed -nE '/new client .* replaces /{s/.*new client ([^ ]+) replaces ([^ ]+)$/\1 \2/p;q}' "$LOGS/relay-j.host.log")
if [ -z "$pair" ]; then
  ERRS+="  relay-j.host.log: missing the new session replacing the live one"$'\n'
elif [ "${pair% *}" != "${pair#* }" ]; then
  ERRS+="  relay-j.host.log: the second session came from another address ($pair)"$'\n'
fi
[ "$(grep -c "client .* connected through the relay" "$LOGS/relay-j.host.log")" -ge 2 ] \
  || ERRS+="  relay-j.host.log: no second session at the host"$'\n'
[ "$(grep -c "joined through the relay" "$LOGS/relay-j.host.log")" = 1 ] \
  || ERRS+="  relay-j.host.log: the client did not stay on one relay link"$'\n'
grep -h -E "relay|connecting again|authenticated|frames \(" "$LOGS/relay-j.client.log" | grep -v "fps  " || true
grep -h -E "replaces|connected through|session [0-9]+ ended" "$LOGS/relay-j.host.log" || true
stop_pid $HOST_PID
stop_pid $RELAY_PID
end_case relay-j "$LOGS/relay-j.client.log" "$LOGS/relay-j.host.log" "$LOGS/relay-f.relay.log"

echo "=== relay-k (the relay's room for this PC is full: say so, and retry with a growing wait)"
start_relay "$LOGS/relay-k.relay.log" 47815 "$LOGS/relay.allow" --max-clients 1 || true
start_rhost relay-k 45979 ws://127.0.0.1:47815 || true
rpair rc-k1 "hs1.$KEY.$DEAD,relay=ws://127.0.0.1:47815/v1"
rpair rc-k2 "hs1.$KEY.$DEAD,relay=ws://127.0.0.1:47815/v1"
# The first client takes the room's one seat and keeps it past the second's run.
timeout 60 "$BIN/hyperspace-client" --headless --no-lookup --frames 720 --config-dir "$LOGS/rc-k1" >"$LOGS/relay-k1.client.log" 2>&1 &
CLIENT_PID=$!
for _ in $(seq 150); do grep -q "connected through the relay" "$LOGS/relay-k1.client.log" && break; sleep 0.1; done
rclient 30 relay-k2.client.log rc-k2 --frames 1 --connect-timeout 6
[ $RC = 1 ] || ERRS+="  second client exited with $RC, expected 1"$'\n'
expect "$LOGS/relay-k2.client.log" "relay ws://127\.0\.0\.1:47815/v1: the relay refused the connection: too many clients are already connected to this host through the relay\.$" "the room-full line"
# Quick retries at 0.25, 0.5, 1, 2 s (and 4 s, then a minute): a handful in
# 6 s, not one every few milliseconds.
n=$(grep -c "refused client for room" "$LOGS/relay-k.relay.log" || true)
[ "$n" -ge 3 ] && [ "$n" -le 8 ] || ERRS+="  relay-k.relay.log: $n refusals in 6 s, expected 3 to 8"$'\n'
RC=0
wait $CLIENT_PID || RC=$?
[ $RC = 0 ] || ERRS+="  first client exited with $RC"$'\n'
expect "$LOGS/relay-k1.client.log" "CLIENT OK" "CLIENT OK for the client in the seat"
grep -h "relay ws" "$LOGS/relay-k2.client.log" || true
echo "$n refusals"
stop_pid $HOST_PID
stop_pid $RELAY_PID
end_case relay-k "$LOGS/relay-k1.client.log" "$LOGS/relay-k2.client.log" "$LOGS/relay-k.host.log" "$LOGS/relay-k.relay.log"

if [ -n "$RELAY_FAILED" ]; then echo "FAILED relay cases:$RELAY_FAILED"; exit 1; fi
echo "ALL E2E TESTS PASSED"
