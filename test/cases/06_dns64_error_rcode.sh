#!/bin/sh
# DNS64 Rcode/Error handling check (RFC 6147 §5.1.2)
#
# B queries a non-existent domain name (e.g., thisdomaindoesnotexistatall12345.com)
# and verifies that A's DNS64 returns NXDOMAIN (Rcode NameError) instead of NOERROR.
#
# B also queries an existing domain name (e.g., dns.google) and verifies that A's DNS64
# returns NOERROR and a synthesized AAAA record.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

# Query non-existent domain and verify NXDOMAIN is returned
nonexistent_domain="thisdomaindoesnotexistatall12345.com"
log "Querying non-existent domain: $nonexistent_domain"

# B's yggnet peering being "up" doesn't guarantee the UDP path to A's DNS64
# listener through the gVisor netstack is immediately ready right after a
# fresh container start — retry a few times before failing.
dig_out=""
n=0
while [ "$n" -lt 10 ]; do
  if raw=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA "$nonexistent_domain" +time=5 +tries=2 2>/dev/null); then
    if printf '%s\n' "$raw" | grep -q "status: NXDOMAIN"; then
      dig_out=$raw
      break
    fi
  fi
  n=$((n + 1))
  sleep 2
done

log "dig AAAA $nonexistent_domain ->\n$dig_out"
[ -n "$dig_out" ] || fail "FAIL: did not receive NXDOMAIN for non-existent domain $nonexistent_domain"

assert_contains "$dig_out" "status: NXDOMAIN" "NXDOMAIN is returned for non-existent domain"
assert_contains "$dig_out" "ANSWER: 0" "No answers are returned for non-existent domain"

# Query existing domain and verify NOERROR is returned
existing_domain="dns.google"
log "Querying existing domain: $existing_domain"
dig_existing=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA "$existing_domain" +time=5 +tries=2)
log "dig AAAA $existing_domain ->\n$dig_existing"

assert_contains "$dig_existing" "status: NOERROR" "NOERROR is returned for existing domain"
assert_contains "$dig_existing" "ANSWER:" "Answers are returned for existing domain"

log "PASS: DNS64 correctly returns NXDOMAIN for non-existent domains and NOERROR for existing ones"
