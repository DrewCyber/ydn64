#!/bin/sh
# RFC 8200 §4.5 + RFC 6146 §3.4 — fragmented ICMPv6 through NAT64.
#
# The NIC-intercepted ICMPv6 path used to assume a fixed Next Header offset
# and handled only unfragmented datagrams, so any ping whose payload exceeded
# the tunnel MTU (kernel-fragmented by B) died silently: the fragments fell
# through to gVisor, which has no route for pool6 addresses. The interceptor
# now walks the extension-header chain, reassembles fragments in a bounded
# table, translates the complete request, and emits oversized replies as
# proper IPv6 fragments.
#
#   1. ping6 -s 2000 / -s 4000 toward pool6::127.0.0.1 — deterministic: A's
#      loopback answers directly (lo has a jumbo MTU, so the v4 leg stays
#      unfragmented); every other pipeline stage (B-side fragmentation,
#      reassembly, reply synthesis, reply fragmentation, B-side
#      reassembly) is exercised end to end.
#   2. Informational: ping6 -s 2000 toward real dns.google — additionally
#      exercises IPv4-side kernel fragmentation on the egress leg; kept
#      non-fatal because the real internet remains path-dependent.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

LOOP_TARGET="${NAT64_POOL_PREFIX}7f00:1"
INET_TARGET="${NAT64_POOL_PREFIX}808:808"

try_ping() { # <target> <size> <retries> — echoes last output, rc=0 on success
  target=$1; size=$2; retries=$3
  n=0
  while [ "$n" -lt "$retries" ]; do
    out=$(exec_b ping6 -c 2 -W 3 -s "$size" "$target" 2>&1 || true)
    case "$out" in
      *" 0% packet loss"*)
        log "PASS: ping6 -s $size $target round trip intact:"
        printf '%s\n' "$out" | grep -E "bytes from|packet loss" | while IFS= read -r line; do log "  $line"; done
        return 0
        ;;
    esac
    n=$((n + 1))
  done
  return 1
}

# ── 1/2. Oversized loopback pings (deterministic) ──────────────────────────
if ! try_ping "$LOOP_TARGET" 2000 5; then
  fail "FAIL: fragmented ping (-s 2000) through NAT64 never completed:\n$out"
fi
if ! try_ping "$LOOP_TARGET" 4000 5; then
  fail "FAIL: fragmented ping (-s 4000, multi-fragment) through NAT64 never completed:\n$out"
fi

# ── 3. Real-internet oversized ping (informational) ────────────────────────
if try_ping "$INET_TARGET" 2000 3; then
  log "real-internet oversized ping also succeeded"
else
  warn "real-internet ping -s 2000 did not complete (path-dependent; loopback proof above):\n$out"
fi

log "all fragmented-ICMP checks complete"
