#!/bin/sh
# NAT64 UDP endpoint-independent mapping (RFC 4787 REQ-1 / RFC 6146 §3.1/§5.2).
#
# One client socket on B talks to TWO different IPv4 destinations inside A
# (two udpecho servers bound to 127.0.0.1 and 127.0.0.2 — the harness config
# deliberately empties IgnoredDstSubnets so loopback is a valid embedded-IPv4
# target through the pool6 prefix). Both servers run with -tag-client, so
# their replies reveal the external (post-NAT) source address each of them
# observed. The -eim client mode asserts both observations are IDENTICAL:
#
#   same client socket → same external ip:port regardless of destination
#
# which is exactly endpoint-independent mapping. Before EIM was implemented,
# every destination tuple got its own connected DialUDP socket with its own
# ephemeral port, so the two servers always observed different ports and this
# case failed.
#
# Second half: flip Nat64UdpFiltering to "address-and-port-dependent" via a
# live SIGHUP reload (test/gen -udp-filtering) and verify exact-tuple traffic
# still flows under the stricter policy.
#
# No manual config restore at the end: run_case() in lib.sh restores A's
# baseline config and reloads automatically once this script exits.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

PORT1=4446
PORT2=4447
TARGET1="[${NAT64_POOL_PREFIX}7f00:1]:$PORT1" # pool6::127.0.0.1
TARGET2="[${NAT64_POOL_PREFIX}7f00:2]:$PORT2" # pool6::127.0.0.2

HEX_PORT1=$(printf '%04X' "$PORT1")
HEX_PORT2=$(printf '%04X' "$PORT2")

cleanup() {
  $PODMAN exec "$CT_A" sh -c 'kill $(pidof udpecho) 2>/dev/null || true' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# ── Start + verify the two tagged echo servers on A ──────────────────────
# Backgrounded INSIDE the container shell (orphaned to PID 1): newer podman
# reaps `podman exec -d` sessions shortly after the client exits, which
# would silently kill the responders mid-case.
$PODMAN exec "$CT_A" sh -c "udpecho -tag-client 127.0.0.1:$PORT1 >> /work/udpecho-eim.log 2>&1 &" >/dev/null
$PODMAN exec "$CT_A" sh -c "udpecho -tag-client 127.0.0.2:$PORT2 >> /work/udpecho-eim.log 2>&1 &" >/dev/null
wait_for 5 "UDP echo listener bound on A :$PORT1" \
  $PODMAN exec "$CT_A" grep -qi ":$HEX_PORT1" /proc/net/udp
wait_for 5 "UDP echo listener bound on A :$PORT2" \
  $PODMAN exec "$CT_A" grep -qi ":$HEX_PORT2" /proc/net/udp

# ── EIM probe: one client socket → both destinations ─────────────────────
$PODMAN exec "$CT_B" sh -c \
  "yes 'ydn64-eim-probe-pattern-' | tr -d '\n' | head -c 200 > /tmp/eim.bin"

ok=""
for attempt in 1 2 3 4 5; do
  # Exits non-zero unless BOTH replies arrive intact AND carry the identical
  # observed client address (the EIM assertion itself).
  if $PODMAN exec "$CT_B" udpecho -eim "$TARGET1" "$TARGET2" /tmp/eim.bin /tmp/eim-r1.bin /tmp/eim-r2.bin; then
    ok=1
    break
  fi
  sleep 2
done
[ -n "$ok" ] || fail "FAIL: EIM probe failed — destinations saw different external mappings or no replies"

# Payload integrity through both paths (tag stripped by the tool before
# writing), belt-and-braces alongside the tool's own check.
for r in /tmp/eim-r1.bin /tmp/eim-r2.bin; do
  rhash=$($PODMAN exec "$CT_B" sha256sum "$r" | cut -d' ' -f1)
  sent=$($PODMAN exec "$CT_B" sha256sum /tmp/eim.bin | cut -d' ' -f1)
  [ "$rhash" = "$sent" ] || fail "FAIL: EIM reply payload mismatch ($r)"
done
log "PASS: endpoint-independent mapping — one client socket, one external mapping across two destinations"

# ── Stricter filtering still passes exact-tuple traffic after SIGHUP ─────
log "reloading A with Nat64UdpFiltering = address-and-port-dependent..."
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -peers="$YDN64_REAL_PEERS" \
    -allowed-sources="200::/7" \
    -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
    -udp-filtering="address-and-port-dependent" \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
rm -f "$RUN_DIR/ydn64.env.tmp"
reload_a "A reloaded config (address-and-port-dependent filtering)"

ok=""
for attempt in 1 2 3 4 5; do
  if $PODMAN exec "$CT_B" udpecho -once "$TARGET1" /tmp/eim.bin /tmp/eim-r3.bin >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
[ -n "$ok" ] || fail "FAIL: exact-tuple exchange broke under address-and-port-dependent filtering"
rhash=$($PODMAN exec "$CT_B" sha256sum /tmp/eim-r3.bin | cut -d' ' -f1)
sent=$($PODMAN exec "$CT_B" sha256sum /tmp/eim.bin | cut -d' ' -f1)
[ "$rhash" = "$sent" ] || fail "FAIL: reply payload mismatch under address-and-port-dependent filtering"
log "PASS: exact-tuple UDP exchange works under address-and-port-dependent filtering"
