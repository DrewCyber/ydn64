#!/bin/sh
# Code review 2026-08-24 finding #2 — DNS-over-TCP queries must be proxied
# upstream over TCP (RFC 7766 §8.2), and a TC-flagged upstream UDP answer
# must be retried over TCP rather than relayed as a dead end.
#
# Probe: resolve the root zone's DNSKEY RRset through A's DNS64 over TCP
# WITHOUT EDNS0 (+noedns). The real answer is well above 512 bytes (two or
# more DNSKEY records), so:
#   - the old behaviour (TCP client -> hardcoded UDP upstream, no EDNS)
#     relays a TC-flagged 512-byte-capped message back over the TCP leg;
#   - correct behaviour fetches the full answer upstream (directly over TCP,
#     matching the client transport) and delivers it complete, TC clear.
#
# Requires real internet DNS egress from A (like case 02).
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

log "RFC 7766 §8.2: large DNSKEY answer delivered complete over TCP"

ok=""
n=0
while [ "$n" -lt 5 ]; do
    out=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" . DNSKEY +tcp +noedns +time=5 +tries=2 2>&1 || true)
    log "dig . DNSKEY +tcp attempt $((n + 1)):\n$out"

    header=$(printf '%s\n' "$out" | grep 'flags:' | head -1)
    status=$(printf '%s\n' "$out" | grep 'status:' | head -1)
    keys=$(printf '%s\n' "$out" | grep -c 'DNSKEY' || true)

    if [ -n "$status" ] \
        && printf '%s' "$status" | grep -q 'NOERROR' \
        && [ -n "$header" ] \
        && ! printf '%s' "$header" | grep -q ' tc' \
        && [ "$keys" -ge 2 ]; then
        ok=1
        break
    fi

    n=$((n + 1))
    warn "attempt $((n)) incomplete (status='$status' flags='$header' dnskey_rrs=$keys) — retrying"
    sleep 2
done

[ -n "$ok" ] || fail "FAIL: root DNSKEY over TCP never arrived complete+untruncated (TC fallback / RFC 7766 §8.2 regression?)"

log "PASS: DNSKEY RRset (>512 B) served complete over TCP with TC clear"
