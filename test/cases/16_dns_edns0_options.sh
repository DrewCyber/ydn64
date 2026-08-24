#!/bin/sh
# EDNS(0) option passthrough (RFC 6891; RFC 7873 DNS COOKIE, RFC 7871
# CLIENT-SUBNET).
#
# ydn64 terminates the client-facing DNS exchange, so it owns the response
# OPT record. It rebuilds it (UDPSize advertisement, DO bit) but must carry
# the EDNS(0) OPTIONS across the proxy hop:
#   - options on the upstream response are relayed verbatim — a client
#     COOKIE reaches ydn64's real-internet upstream (8.8.8.8 in the
#     harness), whose server-cookie comes straight back and is echoed
#     upstream again on later queries;
#   - ECS responses flow back the same way;
#   - non-EDNS clients still never receive an OPT.
#
# Flow (all from B against A's DNS64 listener):
#   1. dig +cookie  -> reply carries a COOKIE option. The harness upstream
#      (8.8.8.8) does NOT issue server cookies, so dig reports "(echoed)" —
#      ydn64's RFC 7873 §5.2 responding-server echo. The assertion is that
#      the cookie SURVIVES the DNS64 round trip at all (older builds stripped
#      every option).
#   2. dig +subnet  -> reply carries a CLIENT-SUBNET option echoed by the
#      upstream (verified live: 8.8.8.8 echoes family/mask/scope). ydn64
#      never generates ECS itself, so its presence proves verbatim relay of
#      upstream OPT options through the synthesised-answer path.
#   3. dig +noedns  -> reply contains no OPT pseudo-section at all (any
#      resolvable name works; cache state is irrelevant here).
#
# Tests 1-2 use names no other case queries: a cache hit is served without
# an upstream exchange, so its Extra carries no upstream options to relay
# (the client COOKIE echo would still appear, masking a broken relay).
#
# Each probe is retried briefly: peering being up does not guarantee the
# upstream forwarder path is settled (see AGENTS.md). Failed upstream
# attempts are never cached, so retries always re-hit the live path.

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

DIG_COMMON="+time=5 +tries=2"
COOKIE_NAME=a.root-servers.net    # not queried by any other case
ECS_NAME=www.google.com           # ditto

# dig_probe <expect-substring> <description> <name> <dig-args...>
# Runs dig from B with the given args, retrying until its full output
# contains <expect-substring>.
dig_probe() {
  expect=$1; desc=$2; name=$3; shift 3
  n=0
  out=""
  while [ "$n" -lt 4 ]; do
    out=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" "$name" AAAA "$@" 2>&1 || true)
    case "$out" in
      *"$expect"* ) log "PASS: $desc"; return 0 ;;
    esac
    n=$((n + 1))
    sleep 1
  done
  fail "FAIL: $desc\n  expected '$expect' in dig output:\n$out"
}

log "Test 1: DNS COOKIE survives the DNS64 round trip"
dig_probe "; COOKIE:" "client cookie echoed/relayed in the reply (+cookie)" \
  "$COOKIE_NAME" "+cookie" $DIG_COMMON

log "Test 2: CLIENT-SUBNET response option is relayed back"
dig_probe "CLIENT-SUBNET:" "upstream ECS response option present (+subnet)" \
  "$ECS_NAME" "+subnet=192.0.2.0/24" $DIG_COMMON

log "Test 3: non-EDNS client receives no OPT pseudo-section"
n=0
while [ "$n" -lt 4 ]; do
  out=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +noedns $DIG_COMMON 2>&1 || true)
  # A successful answer proves the query went through; absence of the
  # OPT section proves we stripped any relayed OPT for classic clients.
  case "$out" in
    *"status: NOERROR"* )
      case "$out" in
        *"OPT PSEUDOSECTION"*) fail "FAIL: classic client received an OPT record:\n$out" ;;
        *) log "PASS: NOERROR answer without OPT for a non-EDNS query"; break ;;
      esac ;;
  esac
  n=$((n + 1))
  sleep 1
  [ "$n" -lt 4 ] || fail "FAIL: non-EDNS probe never produced a clean NOERROR answer:\n$out"
done

log "PASS: EDNS(0) option passthrough working correctly (RFC 6891 / RFC 7873 / RFC 7871)"
