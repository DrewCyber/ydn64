#!/bin/sh
# Demonstrates the "change config, reload via SIGHUP, re-verify" workflow the
# wider test suite is built around: tighten AllowedSources so B's own
# address no longer matches, confirm DNS64 and NAT64 ICMP both now refuse
# B's traffic, using a real-world dns.google lookup/synthesised address
# obtained from A's default (baseline) config at the start of this case.
#
# AllowedSources is reloaded live via SIGHUP (see reloadConfig() in
# cmd/ydn64/main.go) instead of restarting A's container — this avoids
# tearing down A's Yggdrasil peering with B entirely, so there's no
# re-peering wait and none of the podman-restart re-peering flakiness
# documented in AGENTS.md.
#
# No manual config restore at the end: run.sh's run_case() diffs A's config
# against the baseline snapshot and restores+reloads automatically once this
# script exits, regardless of pass/fail — see lib.sh. Kept as the last case
# in the suite by convention (it's the most invasive config change), though
# nothing about test ordering is actually required anymore.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

# Resolve dns.google under the default/baseline AllowedSources (200::/7,
# which matches B) to get a real NAT64-translated address to test against
# once AllowedSources is tightened below.
n=0
target_addr=""
while [ "$n" -lt 10 ]; do
  target_addr=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA dns.google +short +time=5 +tries=2 | grep -v '^;' | grep -v '^$' | tail -1)
  [ -n "$target_addr" ] && break
  n=$((n + 1))
  sleep 2
done
[ -n "$target_addr" ] || fail "FAIL: no AAAA answer from DNS64 for dns.google (real internet DNS required)"
log "dig AAAA dns.google (baseline AllowedSources) -> $target_addr"

log "reloading A with AllowedSources that excludes B's address space..."
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -peers="$YDN64_REAL_PEERS" \
    -allowed-sources="fd00::/8" \
    -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
rm -f "$RUN_DIR/ydn64.env.tmp"
reload_a "A reloaded config (tightened AllowedSources)"

answer=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA dns.google +short +time=3 +tries=1 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
log "dig after AllowedSources tightened -> '${answer}'"
[ -z "$answer" ] || fail "FAIL: DNS64 answered a query from a source excluded by AllowedSources (got: $answer)"
log "PASS: DNS64 correctly blocked a non-matching source"

ping_out=$($PODMAN exec "$CT_B" ping6 -c 2 -W 2 "$target_addr" 2>&1 || true)
log "ping6 after AllowedSources tightened ->\n$ping_out"
assert_not_contains "$ping_out" " 0% packet loss" "NAT64 ICMP correctly blocked a non-matching source"

log "PASS: AllowedSources correctly blocked a non-matching source (DNS64 + NAT64 ICMP)"
