#!/bin/sh
# Demonstrates the "change config, restart, re-verify" workflow the wider
# test suite is built around: tighten AllowedSources so B's own address no
# longer matches, confirm DNS64 now refuses to answer B, then restore the
# original config so a repeat `run.sh test` is unaffected.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

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
blocked=0
[ -z "$answer" ] && blocked=1

log "restoring original AllowedSources config..."
cp "$RUN_DIR/ydn64.conf.bak" "$RUN_DIR/ydn64.conf"
$PODMAN restart "$CT_A" >/dev/null
# 30s: yggdrasil-go's peer reconnect backoff, combined with the two rapid
# restarts this case performs, means re-peering time is variable — a 15s
# budget was observed to occasionally time out even though B eventually
# reconnects a few seconds later.
wait_for 30 "B re-peered with restored A" \
  sh -c "$PODMAN exec $CT_B yggdrasilctl -json getpeers | grep -q '\"up\": true'"

[ "$blocked" -eq 1 ] || fail "FAIL: DNS64 answered a query from a source excluded by AllowedSources"
log "PASS: AllowedSources correctly blocked a non-matching source"
