#!/bin/sh
# NAT64 UDP fragmentation / oversized-datagram regression (RFC 6146 §3.4).
#
# The client container B runs with a realistic 1500-byte TUN MTU (test/gen
# -ifmtu, applied to both generated configs), so a UDP datagram larger than
# ~1472 bytes MUST be fragmented by B's kernel into multiple IPv6 packets.
# Only the first fragment carries next-header=17 (UDP) in the fixed IPv6
# header; later fragments carry a 44 (Fragment Header). Before the gVisor
# udp.NewForwarder migration, ydn64's NIC-level interceptor matched on that
# fixed offset: the first fragment created a raw UDP session whose payload
# was only the first fragment's data, and every later fragment fell through
# to gVisor (which had no endpoint for it) and was dropped. Fragmented UDP
# exchanges simply timed out.
#
# Post-migration, gVisor reassembles the fragments before its transport
# demuxer ever sees a datagram; the forwarder relays the complete payload to
# the real IPv4 destination and pumps the reply back through netstack.
#
# Deterministic topology for this case: a UDP echo server (test/tools/udpecho,
# baked into A's image) bound to 127.0.0.1 inside A. The harness config
# deliberately empties IgnoredDstSubnets so loopback is a valid embedded-IPv4
# target through the pool6 prefix. Payloads are pattern-generated on B and
# compared with sha256 + byte counts, so truncation or reassembly damage
# cannot pass. (busybox nc cannot be used as the echo endpoint: its fixed
# receive buffer truncates datagrams well below the fragmentation threshold.)

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

TARGET="[${NAT64_POOL_PREFIX}7f00:1]:4446" # [pool6::127.0.0.1]:4446 — echo server inside A
PORT=4446

HEX_PORT=$(printf '%04X' "$PORT")

cleanup() {
  $PODMAN exec "$CT_A" sh -c 'kill $(pidof udpecho) 2>/dev/null || true' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# ── Start + verify the UDP echo server on A ──────────────────────────────
# udpecho (test/tools, baked into A's image) echoes datagrams of any size;
# busybox nc's fixed receive buffer truncates well below the 1472-byte
# fragmentation threshold and cannot serve as the echo endpoint here.
$PODMAN exec -d "$CT_A" sh -c "exec udpecho 127.0.0.1:$PORT" >/dev/null
wait_for 5 "UDP echo listener bound on A :$PORT" \
  $PODMAN exec "$CT_A" grep -qi ":$HEX_PORT" /proc/net/udp

# udp_roundtrip <payload_bytes> <description>
#
# Retries like every other first-flow-sensitive check in this harness: the
# very first datagram across a freshly booted Yggdrasil link occasionally
# races session/key setup on the peering (same rationale as the dig retries
# in 02_dns_google_icmp.sh).
udp_roundtrip() {
  size=$1
  desc=$2

  $PODMAN exec "$CT_B" sh -c "
    yes 'ydn64-udp-fragmentation-test-pattern-' | tr -d '\n' | head -c $size > /tmp/p.bin"
  sent=$($PODMAN exec "$CT_B" sha256sum /tmp/p.bin | cut -d' ' -f1)

  ok=""
  for attempt in 1 2 3 4 5; do
    if $PODMAN exec "$CT_B" udpecho -once "$TARGET" /tmp/p.bin /tmp/r.bin >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 2
  done
  [ -n "$ok" ] || fail "FAIL: $desc — no intact reply within timeout"

  # NOTE: both reads must run INSIDE container B — an unconditional
  # "< /tmp/r.bin" here would be a redirect on the host, not the container.
  rhash=$($PODMAN exec "$CT_B" sha256sum /tmp/r.bin | cut -d' ' -f1)
  rsize=$($PODMAN exec "$CT_B" sh -c 'wc -c < /tmp/r.bin' | tr -d ' ')

  if [ "$rhash" != "$sent" ] || [ "$rsize" != "$size" ]; then
    fail "FAIL: $desc — reply mismatch ($rsize bytes, hash ${rhash:-none}, want $size/$sent)"
  fi
  log "PASS: $desc ($size bytes intact)"
}

# Small exchange: single unfragmented datagram in both directions.
udp_roundtrip 64 "small unfragmented UDP exchange"

# Oversized exchanges: >1472 bytes forces B's kernel to emit multiple IPv6
# fragments outbound; pre-forwarder ydn64 dropped every fragment after the
# first, so these exchanges could never complete.
udp_roundtrip 2000 "two-fragment UDP datagram survives reassembly"
udp_roundtrip 4000 "three-fragment UDP datagram survives reassembly"

# ── Direct DNS over NAT64 UDP (real internet target) ────────────────────
# Queries 8.8.8.8 directly through the pool6 mapping. This exercises the
# forwarder path for unmatched flows while DNS64's own bound endpoint on the
# node address keeps working (gVisor demuxes registered endpoints before the
# transport handler), i.e. both UDP consumers coexist on one stack.
answer=""
n=0
while [ "$n" -lt 10 ]; do
  answer=$($PODMAN exec "$CT_B" dig "@${NAT64_POOL_PREFIX}808:808" +time=3 +tries=1 A dns.google +short 2>/dev/null | grep -v '^;' | grep -v '^$' | tail -1)
  [ -n "$answer" ] && break
  n=$((n + 1))
  sleep 2
done
[ -n "$answer" ] || fail "FAIL: no DNS answer from 8.8.8.8 through NAT64 UDP"
log "dig A dns.google via NAT64 -> $answer"
log "PASS: direct DNS over NAT64 UDP works alongside DNS64"
