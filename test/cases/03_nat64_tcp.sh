#!/bin/sh
# NAT64 connectivity: B fetches http://[synthesised-AAAA]/ from the previous
# case, which is only reachable at all because A is translating the request
# to real IPv4 traffic on targetnet — B itself has no IPv4 route whatsoever.
set -eu
. "$(dirname -- "$0")/../lib.sh"

aaaa_file="$RUN_DIR/target-aaaa.txt"
[ -s "$aaaa_file" ] || fail "no synthesised AAAA recorded — run 02_dns64_synth.sh first"
addr=$(cat "$aaaa_file")

body=$($PODMAN exec "$CT_B" curl -6 -s --max-time 10 "http://[${addr}]/")
log "curl http://[$addr]/ -> $body"
assert_contains "$body" "nat64-target-ok" "NAT64 TCP connectivity reaches the IPv4-only target"
