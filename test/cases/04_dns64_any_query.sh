#!/bin/sh
# ANY-query DNS64 handling: proxy.handle() treats DNS type ANY (255) the
# same as AAAA (synthesis/filtering per zone rules) instead of blindly
# passing the raw upstream ANY answer through — otherwise results would
# depend entirely on unrelated upstream ANY quirks (e.g. RFC 8482 HINFO
# responses), not on ydn64's own DNS64 behavior.
#
# 1. howto.ygg (.ygg zone, forwarder = real Alfis DNS, no prefix,
#    return-ipv6-addresses: true) — an ANY query must answer with AAAA
#    record(s) only.
# 2. dns.google (falls into the default "." catch-all zone;
#    return-ipv4-addresses is false and a prefix is configured) — an ANY
#    query must answer with synthesised AAAA record(s) only, never a real
#    A record.
#
# This case requires real internet + real Yggdrasil network egress from the
# A container (same as case 02/03) and runs against A's default/baseline
# config (no config changes made).
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}" "${NAT64_POOL_PREFIX:?}"

# assert_only_aaaa <dig-answer-section> <desc>
# Fails if any non-AAAA/CNAME record type shows up in a `dig +noall +answer`
# answer section, and if no AAAA record is present at all.
assert_only_aaaa() {
  dig_answer=$1; desc=$2
  bad=$(printf '%s\n' "$dig_answer" | awk '$4!="AAAA" && $4!="CNAME" {print}')
  [ -z "$bad" ] || fail "FAIL: $desc: unexpected non-AAAA record(s) in answer:\n$bad"
  aaaa_count=$(printf '%s\n' "$dig_answer" | awk '$4=="AAAA"' | wc -l | tr -d ' ')
  [ "$aaaa_count" -gt 0 ] || fail "FAIL: $desc: no AAAA record present in answer:\n$dig_answer"
  log "PASS: $desc (only AAAA record(s) present)"
}

# dig_any_retry <name> — retries an ANY query a few times, same pattern as
# other real-world cases for network convergence right after container
# start. dig writes its own connection-error diagnostics (e.g. "connection
# refused", "no servers could be reached", or — when +tries=2's first UDP
# attempt times out but the retransmit succeeds — "communications error ...
# timed out") to stdout rather than stderr, interleaved with any real answer
# lines. So a plain non-empty-string check on `+noall +answer` output isn't
# enough: it must also (a) check dig's own exit status, since a transient
# "DNS64 UDP path not ready yet right after start" error must not be
# mistaken for a (bogus) successful answer, and (b) strip dig's own ";;"
# diagnostic/comment lines even on success, since dig can print a stale
# "timed out" warning for an earlier retransmit attempt even though the
# overall query ultimately succeeded (exit 0) with a real answer.
#
# +notcp forces UDP: dig defaults to TCP for type ANY queries specifically
# (unlike every other type), and ydn64's DNS64 service only ever implements
# a UDP listener (see src/dns64/server.go) — without +notcp every ANY query
# gets a bare TCP RST ("connection refused"), unrelated to DNS64/zone logic.
dig_any_retry() {
  name=$1
  n=0
  dig_answer=""
  while [ "$n" -lt 10 ]; do
    if raw=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" ANY "$name" +notcp +noall +answer +time=5 +tries=2 2>/dev/null); then
      dig_answer=$(printf '%s\n' "$raw" | grep -v '^;;' || true)
      [ -n "$dig_answer" ] && break
    fi
    dig_answer=""
    n=$((n + 1))
    sleep 2
  done
}

dig_any_retry howto.ygg
log "dig ANY howto.ygg ->\n${dig_answer}"
[ -n "$dig_answer" ] || fail "FAIL: no answer from DNS64 for ANY howto.ygg (real Yggdrasil network egress required)"
assert_only_aaaa "$dig_answer" "ANY howto.ygg (.ygg zone)"

dig_any_retry dns.google
log "dig ANY dns.google ->\n${dig_answer}"
[ -n "$dig_answer" ] || fail "FAIL: no answer from DNS64 for ANY dns.google (real internet DNS required)"
assert_only_aaaa "$dig_answer" "ANY dns.google (\".\" zone)"

prefix_prefix=$(printf '%s' "$NAT64_POOL_PREFIX" | cut -d: -f1-4)
assert_contains "$dig_answer" "$prefix_prefix" "synthesised AAAA for dns.google falls under NAT64 pool prefix ($prefix_prefix)"

log "PASS: ANY queries return AAAA-only answers for both .ygg and \".\" zones"
