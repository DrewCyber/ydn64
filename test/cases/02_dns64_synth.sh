#!/bin/sh
# DNS64 synthesis: B asks A's DNS64 listener for target.test (an IPv4-only
# name, per the fake `target` container's dnsmasq), and must get back a
# synthesised AAAA record inside A's Nat64Pool prefix.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}" "${NAT64_POOL_PREFIX:?}"

answer=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA target.test +short +time=3 +tries=2 | grep -v '^;' | grep -v '^$' | tail -1)
log "dig AAAA target.test -> $answer"

[ -n "$answer" ] || fail "FAIL: no AAAA answer from DNS64 for target.test"

prefix_prefix=$(printf '%s' "$NAT64_POOL_PREFIX" | cut -d: -f1-4)
assert_contains "$answer" "$prefix_prefix" "synthesised AAAA falls under NAT64 pool prefix ($prefix_prefix)"

echo "$answer" >"$RUN_DIR/target-aaaa.txt"
