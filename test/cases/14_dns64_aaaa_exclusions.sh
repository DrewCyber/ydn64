#!/bin/sh
# RFC 6147 §5.1.4 — special exclusion set for AAAA records.
#
# Dns64AAAAExcludedSubnets strips real AAAA answers inside the listed IPv6
# subnets, regardless of zone flags — the standards-blessed way to say "my
# clients cannot reach these addresses". Synthesized answers are exempt.
#
# Flow (all live via SIGHUP reloads; run_case restores the baseline after):
#   1. Baseline: the .ygg zone (present by default in the harness config,
#      see test/gen -ygg-zone) returns REAL Yggdrasil-native AAAA records
#      for howto.ygg from a real Alfis forwarder — case 03's mechanism.
#   2. Reload with Dns64AAAAExcludedSubnets = ["200::/7"]: the same query
#      must now return NO AAAA at all (the real record is stripped and no
#      A record exists to synthesize from), while ordinary synthesis
#      (dns.google → pool6 AAAA) keeps working — exclusions are not a
#      general answer-killer.
#   3. Reload with the exclusion lifted: real .ygg AAAAs pass through again
#      (modulo cache TTL — use a fresh query name per phase so cached
#      entries can't mask the change).
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

reload_with() {
  extra_flag=$1   # "" or -dns64-exclude="..."
  desc=$2
  if [ -n "$extra_flag" ]; then
    ( cd "$ROOT_DIR" && go run ./test/gen \
        -role=ydn64 \
        -listen="tcp://0.0.0.0:${YGG_PORT}" \
        -peers="$YDN64_REAL_PEERS" \
        -allowed-sources="200::/7" \
        -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
        "$extra_flag" \
        -out="$RUN_DIR/ydn64.conf" \
        -envout="$RUN_DIR/ydn64.env.tmp" )
  else
    ( cd "$ROOT_DIR" && go run ./test/gen \
        -role=ydn64 \
        -listen="tcp://0.0.0.0:${YGG_PORT}" \
        -peers="$YDN64_REAL_PEERS" \
        -allowed-sources="200::/7" \
        -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
        -out="$RUN_DIR/ydn64.conf" \
        -envout="$RUN_DIR/ydn64.env.tmp" )
  fi
  rm -f "$RUN_DIR/ydn64.env.tmp"
  reload_a "$desc"
}

# dig_aaaa <name> — short-answer AAAA lookup from B, retried briefly since
# the Alfis .ygg path crosses the real Yggdrasil network (see case 03).
dig_aaaa() {
  name=$1
  n=0
  while [ "$n" -lt 10 ]; do
    ans=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA "$name" +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
    [ -n "$ans" ] && { echo "$ans"; return 0; }
    n=$((n + 1))
    sleep 1
  done
  return 1
}

assert_no_ygg_leak() {
  ans=$1; phase=$2
  for addr in $ans; do
    first_group=$(printf '%s' "$addr" | cut -d: -f1)
    val=$(printf '%d' "0x$first_group" 2>/dev/null) || continue
    if [ "$val" -ge 512 ] && [ "$val" -le 1023 ]; then
      fail "$phase: real 200::/7 AAAA leaked through the exclusion set ($addr)"
    fi
  done
}

log "Phase 1: baseline passes real .ygg AAAAs through"
ans=$(dig_aaaa howto.ygg || fail "could not resolve howto.ygg AAAA in baseline config")
first=$(printf '%s' "$ans" | head -n1)
fg=$(printf '%s' "$first" | cut -d: -f1)
v=$(printf '%d' "0x$fg") || fail "non-hex answer: $first"
[ "$v" -ge 512 ] && [ "$v" -le 1023 ] || fail "baseline answer not in 200::/7: $first"
log "PASS: baseline returns real 200::/7 AAAA ($first)"

log "reloading A with Dns64AAAAExcludedSubnets = 200::/7..."
reload_with '-dns64-exclude=200::/7' "A reloaded config (200::/7 AAAA exclusion)"

# Phase 2 deliberately re-queries the SAME name: the pre-exclusion cache
# entry (CNAME + real AAAA) must be filtered AT SERVE TIME by the new set,
# yielding no AAAA (the CNAME alone may still print via +short).
log "Phase 2: excluded range produces no AAAA"
ans2=""
for attempt in 1 2 3; do
  ans2=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA howto.ygg +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
  # Success criterion is absence of 200::/7 AAAA; an empty or CNAME-only
  # reply both qualify. One clean round suffices.
  if ! printf '%s' "$ans2" | grep -q ':'; then
    break
  fi
  sleep 1
done
assert_no_ygg_leak "${ans2:-}" "phase 2"

log "checking ordinary synthesis still works under exclusions"
gans=""
for attempt in 1 2 3; do
  gans=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA dns.google +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
  [ -n "$gans" ] && break
  sleep 1
done
[ -n "$gans" ] || fail "synthesized resolution broke while exclusions active"
log "PASS: excluded range yields no AAAA; synthesized answers unaffected"

log "reloading A with the exclusion list emptied..."
reload_with '' "A reloaded config (exclusion lifted)"

log "Phase 3: real .ygg AAAAs pass through again"
ans3=$(dig_aaaa howto.ygg || fail "howto.ygg stopped resolving after lifting the exclusion")
found=0
for addr in $ans3; do
  fg=$(printf '%s' "$addr" | cut -d: -f1)
  v=$(printf '%d' "0x$fg" 2>/dev/null) || continue
  if [ "$v" -ge 512 ] && [ "$v" -le 1023 ]; then
    found=1
    log "PASS: real 200::/7 AAAA returned again ($addr)"
    break
  fi
done
[ "$found" = 1 ] || fail "no real 200::/7 AAAA after lifting the exclusion (got: ${ans3:-none})"

log "PASS: DNS64 AAAA exclusion set working correctly (RFC 6147 §5.1.4)"
