#!/bin/sh
# Real-world sanity check, exercising actual internet egress from A instead
# of the hermetic fake `target` container: B resolves the well-known name
# `dns.google` through A's DNS64 (forwarded to the real 8.8.8.8 resolver, see
# test/gen's "dns.google" zone), confirms the synthesised AAAA embeds the
# real 8.8.8.8 answer, then ping6's that pool6 address from B to exercise
# NAT64's ICMPv6<->ICMPv4 Echo translation against a real IPv4 host.
#
# This case requires real internet DNS/ICMP egress from the A container's
# targetnet interface. If A's environment has no internet access, this case
# will fail — that is expected and intentional (it is a required case, same
# as 01-04), not a flake to be relaxed.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}" "${NAT64_POOL_PREFIX:?}"

# This case typically runs right after 04's container restarts. A's
# targetnet egress can take a couple of seconds to settle post-restart (the
# same class of transient podman/VM networking delay documented in
# AGENTS.md), so retry the initial lookup a few times before treating an
# empty answer as a real failure.
answer=""
n=0
while [ "$n" -lt 5 ]; do
  answer=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA dns.google +short +time=5 +tries=2 | grep -v '^;' | grep -v '^$' | tail -1)
  [ -n "$answer" ] && break
  n=$((n + 1))
  sleep 2
done
log "dig AAAA dns.google -> $answer"
[ -n "$answer" ] || fail "FAIL: no AAAA answer from DNS64 for dns.google (real internet DNS required)"

prefix_prefix=$(printf '%s' "$NAT64_POOL_PREFIX" | cut -d: -f1-4)
assert_contains "$answer" "$prefix_prefix" "synthesised AAAA falls under NAT64 pool prefix ($prefix_prefix)"
# dns.google resolves to two real A records (8.8.8.8 and 8.8.4.4); which one
# lands last in dig's answer section (and thus gets picked by `tail -1`) can
# vary between queries, so accept either synthesised embedding.
case "$answer" in
*808:808* | *808:404*) : ;;
*) fail "FAIL: synthesised AAAA does not embed a known dns.google address (8.8.8.8/8.8.4.4): $answer" ;;
esac
log "synthesised AAAA embeds a real dns.google answer (8.8.8.8 or 8.8.4.4)"

ping_out=$($PODMAN exec "$CT_B" ping6 -c 3 -W 3 "$answer" 2>&1) || fail "FAIL: ping6 to NAT64-translated 8.8.8.8 failed:\n$ping_out"
log "ping6 $answer ->\n$ping_out"
assert_contains "$ping_out" " 0% packet loss" "NAT64 ICMP translation delivers echo replies (0% packet loss)"
