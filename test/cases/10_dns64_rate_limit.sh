#!/bin/sh
# RFC 5358 (BCP 140) — per-source DNS64 query rate limiting.
#
# ydn64 trusts a wide AllowedSources range by default, so without a rate
# limit any peer could drive the embedded resolver as hard as it likes.
# Dns64RateLimit caps queries per source address with a small token-burst
# allowance; over-budget UDP queries are REFUSED (with reply spacing so
# denials cannot be amplified) or dropped silently.
#
# Deterministic shape:
#   Phase A — baseline config (default 50 qps, burst 100): a 60-query flood
#             fired in ~1s fits entirely inside one burst → nearly all
#             queries are answered.
#   Phase B — SIGHUP-reloaded config (Dns64RateLimit: 3, burst 10): the same
#             flood now exhausts the burst almost immediately; only a handful
#             of answers/refusals get through and most probes time out.
#   Recovery — after two seconds of silence the bucket refills and an
#             ordinary single query is answered again.
#
# Queries target unique .invalid names each round, so DNS caching cannot
# influence either phase.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"
: "${YGG_PORT:?}"
: "${YDN64_REAL_PEERS:?}"
ROOT_DIR=$(cd "$(dirname -- "$0")/../.." && pwd)

# fire_flood <label>
# Fires 60 unique NXDOMAIN queries from B with parallelism 30 and echoes
# "<answered> <refused>" where answered = valid upstream responses (NOERROR /
# NXDOMAIN) and refused = explicit REFUSED statuses seen.
fire_flood() {
  label=$1
  $PODMAN exec -i "$CT_B" env FLOOD_LABEL="$label" FLOOD_SRV="$DNS64_LISTEN_ADDR" sh -s <<'EOF'
seq 1 60 | xargs -P 30 -I QQ dig "@$FLOOD_SRV" AAAA "$FLOOD_LABEL"-QQ.invalid +time=2 +tries=1 > /tmp/flood_raw.txt 2>&1 || true
printf '%d %d\n' \
  "$(grep -cE 'status: (NOERROR|NXDOMAIN)' /tmp/flood_raw.txt)" \
  "$(grep -c 'status: REFUSED' /tmp/flood_raw.txt)"
EOF
}

log "phase A: flooding DNS64 with 60 rapid unique queries (baseline Dns64RateLimit)"
A_OUT=$(fire_flood ratelimitA)
A_ANSWERED=${A_OUT%% *}
log "phase A results: answered=$A_ANSWERED refused=${A_OUT##* }"
# Absolute counts wobble with real-internet DNS latency and tunnel burst
# loss (a 30-way parallel flood loses some probes regardless of limits);
# the meaningful signal is the CONTRAST between the two configurations.
[ "$A_ANSWERED" -ge 20 ] || fail "FAIL: baseline flood barely answered anything ($A_ANSWERED) — DNS64 path itself unhealthy"
log "PASS: baseline config answers the bulk of the flood"

log "reloading A with Dns64RateLimit: 3"
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -peers="$YDN64_REAL_PEERS" \
    -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
rm -f "$RUN_DIR/ydn64.env.tmp"
awk '{ if ($0 == "}") print "  Dns64RateLimit: 3"; print }' "$RUN_DIR/ydn64.conf" > "$RUN_DIR/ydn64.conf.tmp"
mv "$RUN_DIR/ydn64.conf.tmp" "$RUN_DIR/ydn64.conf"
reload_a "A reloaded config (Dns64RateLimit: 3)"

log "phase B: same flood against the tightened limit"
B_OUT=$(fire_flood ratelimitB)
B_ANSWERED=${B_OUT%% *}
log "phase B results: answered=$B_ANSWERED refused=${B_OUT##* }"
# Burst 10 + 3 qps refill cannot cover a ~1s flood: at most ~15 legitimate
# answers are possible, so anything near phase-A volume means the limiter
# did not apply.
[ "$B_ANSWERED" -le 25 ] || fail "FAIL: rate-limited flood answered too generously ($B_ANSWERED); burst 10 + 3 qps cannot cover 60"
if [ "$((A_ANSWERED - B_ANSWERED))" -lt 15 ]; then
  fail "FAIL: tightening Dns64RateLimit barely changed throughput (A=$A_ANSWERED B=$B_ANSWERED)"
fi
log "PASS: tightening Dns64RateLimit shed the bulk of the flood (A=$A_ANSWERED → B=$B_ANSWERED)"

log "recovery: waiting for token refill, then issuing one ordinary query"
sleep 2
rec=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA recovery-final-check.invalid +time=3 +tries=1 2>&1 | grep -cE 'status: (NOERROR|NXDOMAIN)' || true)
[ "$rec" -ge 1 ] || fail "FAIL: legitimate query refused/dropped after the flood drained (rate limiter did not recover)"
log "PASS: limiter recovers — normal service resumes after the burst drains"

log "all RFC 5358 rate limiting checks complete"
