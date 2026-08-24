#!/bin/sh
# NAT64 UDP port parity preservation (RFC 4787 REQ-3, the default
# Nat64PortParity=preserve behaviour).
#
# Real-time media stacks pair flows by port parity: RTP/RTCP endpoint pairs
# (RFC 4961) and several games expect even/odd port relationships to survive
# the NAT, so ydn64 must allocate a client's NAT-assigned external UDP port
# with the SAME parity as its source port — even stays even, odd stays odd.
#
# Flow:
#   For an EVEN and then an ODD client source port on B:
#     1. B sends one datagram from the pinned source port through NAT64 to a
#        tagged echo server on A's loopback (pool6::127.0.0.1).
#     2. The tagged reply reports the external (NAT-assigned) port the echo
#        server observed; the payload must be intact.
#     3. The external port's parity must match the pinned client port.
#
# The two probes use different source ports, so they create two independent
# BIB entries — both allocations are checked. The complementary
# Nat64PortParity=do-not-preserve mode has no observable guarantee to assert
# black-box (any port is allowed) and is covered by unit tests instead.
#
# Payload files travel through the shared .run mount (/work inside both
# containers). No config changes are made: the harness baseline runs in
# preserve mode by default.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

PORT1=4461                                     # tagged echo server on 127.0.0.1 (mapping probe)
SPORT_EVEN=40000                               # pinned even client source port on B
SPORT_ODD=40001                                # pinned odd client source port on B
TARGET1="[${NAT64_POOL_PREFIX}7f00:1]:$PORT1"  # pool6::127.0.0.1 (echo server)

cleanup() {
  $PODMAN exec "$CT_A" sh -c 'kill $(pidof udpecho) 2>/dev/null || true' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

$PODMAN exec "$CT_A" sh -c "udpecho -tag-client 127.0.0.1:$PORT1 >> /work/udpecho-parity.log 2>&1 &" >/dev/null
HEX_PORT1=$(printf '%04X' "$PORT1")
wait_for 5 "UDP echo listener bound on A :$PORT1" \
  $PODMAN exec "$CT_A" grep -qi ":$HEX_PORT1" /proc/net/udp

yes 'ydn64-port-parity-probe-' | tr -d '\n' | head -c 120 >"$RUN_DIR/parity-payload.bin"

# probe_parity <stem> <client-sport>
# Sends ONE datagram from B with the pinned source port and checks that the
# external mapping reported by the tagged echo server has matching parity.
# Retried a few times: the very first datagram across a fresh Yggdrasil link
# can race session setup (see AGENTS.md).
probe_parity() {
  stem=$1; sport=$2
  : >"$RUN_DIR/parity-$stem.log"
  rm -f "$RUN_DIR/parity-$stem.bin"
  n=0
  while [ "$n" -lt 3 ]; do
    exec_b sh -c \
      "udpecho -once -sport '$sport' '$TARGET1' /work/parity-payload.bin /work/parity-$stem.bin >> /work/parity-$stem.log 2>&1" \
      && break
    n=$((n + 1))
    sleep 1
  done
  grep -q "round trip OK" "$RUN_DIR/parity-$stem.log" ||
    fail "probe $stem (sport $sport): no intact reply after retries (see parity-$stem.log)"

  bib_port=$(sed -n 's/.*client=127\.0\.0\.1:\([0-9]*\).*/\1/p' "$RUN_DIR/parity-$stem.log")
  [ -n "$bib_port" ] || fail "could not parse the external mapping port from parity-$stem.log"

  cmp -s "$RUN_DIR/parity-$stem.bin" "$RUN_DIR/parity-payload.bin" ||
    fail "probe $stem: delivered payload mismatch"

  if [ $((bib_port % 2)) -ne $((sport % 2)) ]; then
    fail "FAIL: client port $sport mapped to external port $bib_port — parity not preserved"
  fi
  log "PASS: client port $sport → external port $bib_port (parity preserved)"
}

log "Test: even client port keeps an even external port"
probe_parity even "$SPORT_EVEN"

log "Test: odd client port keeps an odd external port"
probe_parity odd "$SPORT_ODD"

log "PASS: UDP port parity preserved end to end (RFC 4787 REQ-3)"
