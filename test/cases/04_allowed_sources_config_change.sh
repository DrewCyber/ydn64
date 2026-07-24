#!/bin/sh
# Demonstrates the "change config, restart, re-verify" workflow the wider
# test suite is built around: tighten AllowedSources so B's own address no
# longer matches, confirm DNS64, NAT64 TCP, and NAT64 ICMP all now refuse
# B's traffic, then restore the original config so a repeat `run.sh test` is
# unaffected.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

aaaa_file="$RUN_DIR/target-aaaa.txt"
[ -s "$aaaa_file" ] || fail "no synthesised AAAA recorded — run 02_dns64_synth.sh first"
target_addr=$(cat "$aaaa_file")

cp "$RUN_DIR/ydn64.conf" "$RUN_DIR/ydn64.conf.bak"
cleanup() { rm -f "$RUN_DIR/ydn64.conf.bak" "$RUN_DIR/ydn64.env.tmp"; }
trap cleanup EXIT

log "restarting A with AllowedSources that excludes B's address space..."
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -allowed-sources="fd00::/8" \
    -dns64-default="${IP_TARGET}:53" \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
$PODMAN restart "$CT_A" >/dev/null
sleep 2

answer=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA target.test +short +time=3 +tries=1 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
log "dig after AllowedSources tightened -> '${answer}'"
[ -z "$answer" ] || fail "FAIL: DNS64 answered a query from a source excluded by AllowedSources (got: $answer)"
log "PASS: DNS64 correctly blocked a non-matching source"

curl_body=$($PODMAN exec "$CT_B" curl -6 -s --max-time 5 "http://[${target_addr}]/" 2>&1 || true)
log "curl after AllowedSources tightened -> '${curl_body}'"
assert_not_contains "$curl_body" "nat64-target-ok" "NAT64 TCP correctly blocked a non-matching source"

ping_out=$($PODMAN exec "$CT_B" ping6 -c 2 -W 2 "$target_addr" 2>&1 || true)
log "ping6 after AllowedSources tightened ->\n$ping_out"
assert_not_contains "$ping_out" " 0% packet loss" "NAT64 ICMP correctly blocked a non-matching source"

log "restoring original AllowedSources config..."
cp "$RUN_DIR/ydn64.conf.bak" "$RUN_DIR/ydn64.conf"
$PODMAN restart "$CT_A" >/dev/null
sleep 2
# 60s: yggdrasil-go's peer reconnect backoff, combined with the two rapid
# restarts this case performs, means re-peering time is variable — shorter
# budgets (15s, then 30s) were both observed to occasionally time out even
# though B eventually reconnects a bit later (transient podman bridge-
# networking hiccup on the macOS podman-machine VM after a restart, see
# AGENTS.md).
wait_for 60 "B re-peered with restored A" \
  sh -c "$PODMAN exec $CT_B yggdrasilctl -json getpeers | grep -q '\"up\": true'"

log "PASS: AllowedSources correctly blocked a non-matching source (DNS64 + NAT64 TCP + NAT64 ICMP)"
