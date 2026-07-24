#!/bin/sh
# Real-world DNS64 + NAT64 ICMP check, using A's default (baseline) config:
# B resolves the well-known name `dns.google` through A's DNS64 (forwarded
# to a real public resolver per the default "." zone — see test/gen),
# confirms the synthesised AAAA embeds a real dns.google answer, then
# ping6's that pool6 address from B to exercise NAT64's ICMPv6<->ICMPv4
# Echo translation against a real IPv4 host.
#
# This case requires real internet DNS/ICMP egress from A's egressnet
# interface. If A's environment has no internet access, this case will
# fail — that is expected and intentional, not a flake to be relaxed.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}" "${NAT64_POOL_PREFIX:?}"

# B's yggnet peering being "up" doesn't guarantee the UDP path to A's DNS64
# listener through the gVisor netstack is immediately ready right after a
# fresh container start — retry a few times before failing.
answer=""
n=0
while [ "$n" -lt 10 ]; do
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
