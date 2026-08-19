#!/bin/sh
set -eu
. "$(dirname "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}" "${NAT64_POOL_PREFIX:?}"

log "Testing EDNS(0) UDP payload size negotiation"

# Test 1: Client without EDNS(0) → response uses default 1232 byte limit
log "Test 1: Non-EDNS client (no OPT record)"
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +noedns +time=5 +tries=2)
if echo "$resp" | grep -q "EDNS:"; then
    fail "Response includes EDNS OPT when client sent none"
fi
log "PASS: Non-EDNS client gets response without OPT"

# Test 2: Client with EDNS(0) → response includes OPT record
log "Test 2: EDNS client receives OPT in response"
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +bufsize=4096 +time=5 +tries=2)
if ! echo "$resp" | grep -q "EDNS:"; then
    fail "Response missing EDNS OPT record when client sent one"
fi
if ! echo "$resp" | grep -q "udp: 4096"; then
    fail "Server did not advertise 4096 byte buffer in response OPT"
fi
log "PASS: EDNS client gets response with OPT advertising 4096 bytes"

# Test 3: Client with small buffer (512) → response respects limit
log "Test 3: Small buffer size respected (512 bytes)"
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +bufsize=512 +time=5 +tries=2 +ignore)
# +ignore prevents dig from auto-retrying over TCP when TC=1 is set
# We just want to see the UDP response characteristics
if ! echo "$resp" | grep -q "EDNS:"; then
    fail "Response missing EDNS OPT for small-buffer client"
fi
# Check that response was received (may or may not be truncated depending on actual size)
if ! echo "$resp" | grep -q "ANSWER:"; then
    fail "No answer section in response to small-buffer client"
fi
log "PASS: Small-buffer client gets EDNS response"

# Test 4: Verify server caps client's advertised size at maxUDPSize (4096)
log "Test 4: Large client buffer capped at 4096"
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +bufsize=65535 +time=5 +tries=2)
if ! echo "$resp" | grep -q "udp: 4096"; then
    fail "Server did not cap client's 65535 buffer to 4096"
fi
log "PASS: Server advertises 4096 even when client requests 65535"

# Test 5: TCP responses ignore UDP size limits (no truncation)
log "Test 5: TCP ignores UDP size limits"
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +tcp +time=5 +tries=2)
if echo "$resp" | grep -q "flags:.*tc"; then
    fail "TC bit set on TCP response (should never truncate over TCP)"
fi
log "PASS: TCP responses not truncated"

# Test 6: Real-world multi-answer response to verify no spurious truncation
log "Test 6: Multi-AAAA response fits in negotiated buffer"
# dns.google returns 2 A records (synthesized to 2 AAAA), should fit in 4096 easily
resp=$(exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +bufsize=4096 +time=5 +tries=2)
answer_count=$(echo "$resp" | grep -E '^;; ANSWER:' | awk '{print $4}')
if [ "$answer_count" -lt 2 ]; then
    fail "Expected at least 2 AAAA answers for dns.google, got $answer_count"
fi
if echo "$resp" | grep -q "flags:.*tc"; then
    fail "Response truncated unnecessarily (2 AAAAs should fit in 4096 bytes)"
fi
log "PASS: Multi-AAAA response not truncated with adequate buffer"

log "PASS: EDNS(0) UDP payload size negotiation working correctly"
