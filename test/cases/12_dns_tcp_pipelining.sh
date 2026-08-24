#!/bin/sh
# RFC 7766 §6.2.1.1 / §7 — DNS-over-TCP query pipelining.
#
# ydn64 must process pipelined TCP queries concurrently and may answer out of
# order. Two probes via test/tools/dnspipe (stdlib helper baked into B):
#
#   1. Overtake probe: an AAAA query for a RANDOM subdomain of dns.google
#      (unique per run, so it always misses ydn64's cache and needs a real
#      upstream round-trip ending in NXDOMAIN) is sent first, followed
#      immediately by ipv4only.arpa, which ydn64 answers locally without any
#      network I/O. Only a concurrently-processing server can let the
#      later-sent local response overtake the earlier-sent remote one; a
#      serialising server deterministically fails this.
#   2. Bulk probe: N distinct pipelined queries on one connection must all be
#      answered with their original Message IDs (nothing dropped or mismatched).
set -eu
. "$(dirname "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

log "RFC 7766 §6.2.1.1: concurrent processing of pipelined DNS-over-TCP queries"

# Warm the resolver path — the first datagram across a fresh Yggdrasil link
# can race key/session setup (see AGENTS.md), and the overtake probe compares
# arrival order, so both queries must run against an already-working path.
exec_b dig "@${DNS64_LISTEN_ADDR}" dns.google AAAA +tcp +time=5 +tries=3 >/dev/null

log "Test 1: later-sent local query overtakes earlier-sent remote query"
attempt=0
while ! exec_b dnspipe -server "${DNS64_LISTEN_ADDR}" -overtake '*.dns.google,ipv4only.arpa' -timeout 20; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 3 ]; then
        fail "pipelined queries not processed concurrently after $attempt attempts (serialised processing or upstream unreachable)"
    fi
    warn "overtake attempt $attempt failed — retrying (transient podman/upstream hiccup?)"
    sleep 2
done

log "Test 2: 24 pipelined queries on one connection all answered"
attempt=0
while ! exec_b dnspipe -server "${DNS64_LISTEN_ADDR}" -n 24 -base dns.google -timeout 60; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 3 ]; then
        fail "not all pipelined queries answered with matching IDs after $attempt attempts"
    fi
    warn "bulk attempt $attempt failed — retrying (transient podman/upstream hiccup?)"
    sleep 2
done

log "PASS: DNS-over-TCP pipelining handled concurrently (RFC 7766 §6.2.1.1)"
