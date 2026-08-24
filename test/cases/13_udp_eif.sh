#!/bin/sh
# NAT64 UDP endpoint-independent filtering (RFC 4787 REQ-8, the delivery
# counterpart of case 09's endpoint-independent mapping).
#
# Under the default address-dependent filtering a datagram arriving at a
# client's NAT-assigned port from an IPv4 address it never contacted is
# dropped: no per-tuple session exists to relay it into. With
# Nat64UdpFiltering=endpoint-independent (SIGHUP-reloadable), such datagrams
# must be delivered — ydn64 synthesises them as IPv6/UDP sourced from
# pool6::sender and injects them onto the Yggdrasil leg — so a peer that has
# learned a client's external mapping can punch inbound without prior
# contact (the missing half of STUN/ICE traversal).
#
# Flow:
#   1. Baseline negative check. B's -eif socket probes its mapping via a
#      tagged echo server on 127.0.0.1, then waits for an unsolicited
#      datagram fired from 127.0.0.2 (a "never-contacted" source). It must
#      NOT arrive; B times out.
#   2. SIGHUP-reload A with endpoint-independent filtering.
#   3. Same probe again: this time the unsolicited datagram MUST arrive,
#      payload intact, reported as coming from pool6::7f00:2 (the translated
#      sender) — proof of synthesised-packet injection.
#
# Payload files travel through the shared .run mount (/work inside both
# containers). No manual config restore at the end: run_case() in lib.sh
# restores A's baseline config and reloads automatically once this script
# exits.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

PORT1=4450                       # tagged echo server on 127.0.0.1 (mapping probe)
EIF_WAIT=5                       # seconds B waits for the unsolicited datagram
TARGET1="[${NAT64_POOL_PREFIX}7f00:1]:$PORT1" # pool6::127.0.0.1 (echo server)
EXPECT_SRC="${NAT64_POOL_PREFIX}7f00:2"       # translated form of 127.0.0.2

cleanup() {
  $PODMAN exec "$CT_A" sh -c 'kill $(pidof udpecho) 2>/dev/null || true' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

$PODMAN exec "$CT_A" sh -c "udpecho -tag-client 127.0.0.1:$PORT1 >> /work/udpecho-eif.log 2>&1 &" >/dev/null
HEX_PORT1=$(printf '%04X' "$PORT1")
wait_for 5 "UDP echo listener bound on A :$PORT1" \
  $PODMAN exec "$CT_A" grep -qi ":$HEX_PORT1" /proc/net/udp

yes 'ydn64-eif-unsolicited-pattern-' | tr -d '\n' | head -c 200 >"$RUN_DIR/eif-payload.bin"

# poll_log <file> <pattern> <timeout_seconds>
# Waits until <pattern> appears in <file> (a shared-mount log written by a
# backgrounded process inside a container).
poll_log() {
  file=$1; pattern=$2; tmo=$3
  n=0
  while [ "$n" -lt "$tmo" ]; do
    if grep -q "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    n=$((n + 1))
    sleep 1
  done
  fail "timed out after ${tmo}s waiting for '$pattern' in $(basename "$file")"
}

# run_eif_phase <stem>
# Runs one probe/receive round on B in the background, aims an unsolicited
# datagram from 127.0.0.2 at the discovered external port once the MAPPING
# line appears. The receiver runs INSIDE the container shell (backgrounded
# to PID 1) for the same podman-exec lifetime reason as the echo servers.
run_eif_phase() {
  stem=$1
  : >"$RUN_DIR/eif-$stem.log"
  rm -f "$RUN_DIR/eif-$stem.bin"
  $PODMAN exec "$CT_B" sh -c \
    "udpecho -eif '$TARGET1' $EIF_WAIT /work/eif-payload.bin /work/eif-$stem.bin >> /work/eif-$stem.log 2>&1 &" \
    >/dev/null
  poll_log "$RUN_DIR/eif-$stem.log" "MAPPING client=" "$((EIF_WAIT + 10))"

  bib_port=$(sed -n 's/.*client=127\.0\.0\.1:\([0-9]*\).*/\1/p' "$RUN_DIR/eif-$stem.log")
  [ -n "$bib_port" ] || fail "could not parse the external mapping port from eif-$stem.log"
  log "external mapping observed by the echo server: 127.0.0.1:$bib_port"

  $PODMAN exec "$CT_A" udpecho -send -bind 127.0.0.2 \
    "127.0.0.1:$bib_port" /work/eif-payload.bin >/dev/null
}

log "Test 1: baseline address-dependent filtering drops the unknown sender"
run_eif_phase neg
poll_log "$RUN_DIR/eif-neg.log" "no unsolicited datagram" "$((EIF_WAIT + 5))"
[ ! -s "$RUN_DIR/eif-neg.bin" ] || fail "unsolicited datagram WAS delivered under address-dependent filtering"
log "PASS: unsolicited datagram from a never-contacted sender dropped by default"

log "reloading A with Nat64UdpFiltering = endpoint-independent..."
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -peers="$YDN64_REAL_PEERS" \
    -allowed-sources="200::/7" \
    -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
    -udp-filtering="endpoint-independent" \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
rm -f "$RUN_DIR/ydn64.env.tmp"
reload_a "A reloaded config (endpoint-independent filtering)"

log "Test 2: endpoint-independent filtering delivers the same datagram"
run_eif_phase pos
poll_log "$RUN_DIR/eif-pos.log" "EIFRECV from=" "$((EIF_WAIT + 5))"
grep -q "from=\[$EXPECT_SRC\]:" "$RUN_DIR/eif-pos.log" ||
  fail "delivered datagram does not originate from [$EXPECT_SRC] (see eif-pos.log)"

cmp -s "$RUN_DIR/eif-pos.bin" "$RUN_DIR/eif-payload.bin" ||
  fail "FAIL: delivered payload mismatch"
log "PASS: unsolicited datagram delivered from [$EXPECT_SRC] with intact payload"

log "PASS: UDP endpoint-independent filtering working correctly (RFC 4787 REQ-8)"
