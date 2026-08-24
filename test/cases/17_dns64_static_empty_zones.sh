#!/bin/sh
# Dns64Static local authoritative answers + blocked ("empty") zones.
# (Zone semantics originally specified in context/dns64-parameters.txt, now
# documented in README's "Local answers" section.)
#
#   Dns64Static maps exact names to literal IPv4/IPv6 addresses served
#   locally and authoritatively: A records for v4 values, AAAA records for
#   v6 values, NO NAT64 synthesis, never contacting a forwarder. Static
#   entries win over every zone rule. Querying the other family yields
#   NODATA (empty NOERROR), because the name exists without that type.
#
#   An "empty" zone — no prefix and no return flags — cannot produce a
#   usable answer for ANY query type, so it answers a local authoritative
#   NXDOMAIN for its whole domain subtree without any upstream contact.
#
# Flow (all via SIGHUP reloads; run_case restores the baseline after):
#   1. Reload with -dns64-static and -dns64-empty-zone.
#   2. dig A  pin.test.example   -> exactly the configured IPv4 (not synthesized)
#      dig AAAA v6.test.example  -> exactly the configured IPv6
#      dig AAAA pin.test.example -> NODATA (NOERROR, zero answers)
#      dig <random>.empty.test (A/AAAA/TXT) -> NXDOMAIN status each time
#   3. Control: ordinary synthesis for dns.google still works alongside.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

reload_with_static() {
  desc=$1
  ( cd "$ROOT_DIR" && go run ./test/gen \
      -role=ydn64 \
      -listen="tcp://0.0.0.0:${YGG_PORT}" \
      -peers="$YDN64_REAL_PEERS" \
      -allowed-sources="200::/7" \
      -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
      -dns64-static="pin.test.example=198.51.100.7,v6.test.example=2001:db8::42" \
      -dns64-empty-zone \
      -out="$RUN_DIR/ydn64.conf" \
      -envout="$RUN_DIR/ydn64.env.tmp" )
  rm -f "$RUN_DIR/ydn64.env.tmp"
  reload_a "$desc"
}

# dig_full <type> <name> — full dig output from B (status + answer section).
dig_full() {
  $PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" "$1" "$2" +time=5 +tries=2 +noall +comments +answer 2>/dev/null || true
}

log "reloading A with Dns64Static entries + blocked empty.test zone..."
reload_with_static "A reloaded config (static entries + empty.test zone)"

log "Test 1: static IPv4 value answers A queries literally"
got=""
n=0
while [ "$n" -lt 5 ]; do
  got=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" A pin.test.example +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
  [ "$got" = "198.51.100.7" ] && break
  n=$((n + 1)); sleep 1
done
[ "$got" = "198.51.100.7" ] || fail "FAIL: static A answer = '$got', want exactly 198.51.100.7"
log "PASS: A pin.test.example -> 198.51.100.7"

log "Test 2: static IPv6 value answers AAAA queries literally"
got=""
n=0
while [ "$n" -lt 5 ]; do
  got=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA v6.test.example +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
  [ "$got" = "2001:db8::42" ] && break
  n=$((n + 1)); sleep 1
done
[ "$got" = "2001:db8::42" ] || fail "FAIL: static AAAA answer = '$got', want exactly 2001:db8::42"
log "PASS: AAAA v6.test.example -> 2001:db8::42"

log "Test 3: wrong family on a static name is NODATA, not synthesis"
out=$(dig_full AAAA pin.test.example)
case "$out" in
  *"status: NOERROR"*) : ;;
  *) fail "FAIL: wrong-family probe status not NOERROR:\n$out" ;;
esac
case "$out" in
  *"IN	AAAA"*) fail "FAIL: AAAA query for an IPv4-only static name returned an AAAA record:\n$out" ;;
  *) log "PASS: AAAA pin.test.example -> NOERROR with no answer (NODATA)" ;;
esac

log "Test 4: blocked empty.test zone answers NXDOMAIN locally"
for qtype in A AAAA TXT; do
  out=""
  n=0
  while [ "$n" -lt 5 ]; do
    out=$(dig_full "$qtype" "probe$((RANDOM)).empty.test")
    case "$out" in *"status:"*) break ;; esac
    n=$((n + 1)); sleep 1
  done
  case "$out" in
    *"status: NXDOMAIN"*) : ;;
    *) fail "FAIL: empty.test $qtype probe not NXDOMAIN:\n$out" ;;
  esac
done
log "PASS: A/AAAA/TXT under empty.test all return NXDOMAIN"

log "Test 5: ordinary synthesis unaffected alongside static/blocked config"
gans=""
n=0
while [ "$n" -lt 5 ]; do
  gans=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA dns.google +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
  [ -n "$gans" ] && break
  n=$((n + 1)); sleep 1
done
[ -n "$gans" ] || fail "FAIL: dns.google stopped resolving while static/blocked config active"
first=$(printf '%s' "$gans" | head -n1)
case "$first" in
  "${NAT64_POOL_PREFIX:?}"*) log "PASS: normal DNS64 synthesis still works ($first)" ;;
  *) fail "FAIL: dns.google answer $first is not synthesised under $NAT64_POOL_PREFIX" ;;
esac

log "PASS: Dns64Static local answers and blocked zones working correctly"
