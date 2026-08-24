#!/bin/sh
# NAT64 ICMP error translation (RFC 7915 §4.2/§4.3, RFC 5508 REQ-3/REQ-4,
# RFC 4443 §3.1).
#
# Before this feature ydn64 translated only Echo Request/Reply; every ICMPv4
# error about traffic it had sent toward real IPv4 destinations was dropped,
# so traceroute through NAT64 showed only timeouts and IPv6 clients never
# learned about too-small IPv4 path MTUs or closed UDP ports.
#
# This case proves, deterministically and on loopback (no dependence on
# real-internet routers emitting errors), that B now receives the translated
# ICMPv6 errors for three v4-side failure classes:
#
#   1. Time Exceeded — icmperr (-mode timeexceeded) answers a UDP probe with
#      a crafted ICMPv4 11/0 quoting it; B must receive an ICMPv6 Hop Limit
#      Exceeded (type 3).
#   2. Destination Unreachable / port unreachable — a probe to a CLOSED UDP
#      port makes A's own kernel emit a REAL ICMPv4 3/3; B must receive
#      ICMPv6 Destination Unreachable code 4 (port unreachable).
#   3. Packet Too Big — icmperr (-mode ptb) advertises MTU 1000; B must
#      receive ICMPv6 Packet Too Big (type 2) with the RFC 7915-adjusted
#      MTU max(1280, min(1000+20, link MTU)) = 1280.
#
# Ground truth is tcpdump on B's ygg0 interface: assertions key on what
# actually arrives over the Yggdrasil tunnel, not on any particular probe
# utility's reply-matching heuristics (stateful NAT64 replaces the quoted
# packet's client source port with the NAT-assigned one, so userspace tools
# like traceroute may decline to match replies their kernel did deliver —
# an inherent stateful-NAT64 limitation, not a translation bug).
#
# A final informational check probes a real internet target through NAT64.
# It is retried but deliberately non-fatal: whether any given internet path
# produces usable ICMP depends entirely on the probed network, and classic
# hop-by-hop traceroute cannot resolve through ydn64 anyway because flows
# are re-originated with a fresh IPv4 TTL (see section 4 below).

set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${NAT64_POOL_PREFIX:?}"

TE_PORT=33435     # icmperr in timeexceeded mode
PTB_PORT=33436    # icmperr in ptb mode
CLOSED_PORT=33441 # nothing listens here on A's loopback

TE_TARGET="[${NAT64_POOL_PREFIX}7f00:1]:$TE_PORT"
PTB_TARGET="[${NAT64_POOL_PREFIX}7f00:1]:$PTB_PORT"

cleanup() {
  $PODMAN exec "$CT_A" sh -c 'kill $(pidof icmperr) 2>/dev/null || true' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

hex_port() { printf '%04X' "$1"; }

# B's yggdrasil TUN interface is generated with IfName "auto"; resolve its
# actual name instead of assuming one (the only netdev that is neither the
# loopback nor the podman eth bridge).
B_IF=$(exec_b sh -c 'for d in /sys/class/net/*; do i=${d##*/}; case $i in lo|eth*) continue ;; esac; echo "$i"; break; done')
[ -n "$B_IF" ] || fail "FAIL: no TUN interface found on B"
log "sniffing on B interface $B_IF"

# start_sniff <name> <tcpdump-filter>
# Starts tcpdump on B writing matching packets' text output to /tmp/<name>,
# and BLOCKS until tcpdump is actually attached (its banner appears in the
# output file): a detached podman exec can take many seconds to start, and
# probes fired before attachment are simply never seen.
start_sniff() {
  name=$1; filter=$2
  $PODMAN exec "$CT_B" rm -f "/tmp/$name" >/dev/null 2>&1 || true
  $PODMAN exec "$CT_B" sh -c "tcpdump -ni $B_IF -l -c 1 '$filter' > /tmp/$name 2>&1 &"
  n=0
  while [ "$n" -lt 15 ]; do
    if $PODMAN exec "$CT_B" grep -q "listening on" "/tmp/$name" 2>/dev/null; then
      return 0
    fi
    sleep 1
    n=$((n + 1))
  done
  fail "FAIL: sniff tcpdump never attached (filter: $filter)"
}

# udp_probe <target> [payloadfile] — one datagram from B via the harness UDP
# client. The probe tools time out (responders answer with ICMP, not UDP
# echoes); exit status is irrelevant, the assertions are the sniffed packets.
# udpecho always prints SOMETHING when it actually ran (a timeout notice or
# a result), so an empty capture means the podman exec itself silently
# failed — the documented transient hiccup — and the caller must retry.
udp_probe() {
  target=$1; payload=${2:-/etc/hostname}
  PROBE_OUT=$($PODMAN exec "$CT_B" udpecho -once "$target" "$payload" "/tmp/probe.out.$$" 2>&1 || true)
  [ -n "$PROBE_OUT" ] && log "probe: $PROBE_OUT"
}

# sniff_and_probe <name> <filter> <target> <expect-text> <description> [payload]
# Two full attempts, each gated on tcpdump attachment and a verified probe,
# because every individual step can independently swallow work.
sniff_and_probe() {
  name=$1; filter=$2; target=$3; expect=$4; desc=$5; payload=${6:-/etc/hostname}
  attempt=1
  while [ "$attempt" -le 2 ]; do
    start_sniff "$name" "$filter"
    udp_probe "$target" "$payload"
    n=0
    while [ "$n" -lt 15 ]; do
      out=$($PODMAN exec "$CT_B" cat "/tmp/$name" 2>/dev/null || true)
      # tcpdump prints "ICMP6" upper-case; matching stays case-insensitive.
      if printf '%s' "$out" | grep -qi "icmp6"; then
        if [ -z "$expect" ] || printf '%s' "$out" | grep -q -- "$expect"; then
          log "PASS: $desc ($out)"
          return 0
        fi
      fi
      sleep 1
      n=$((n + 1))
    done
    log "$desc not captured on attempt $attempt${PROBE_OUT:+ (probe ran)}; retrying"
    attempt=$((attempt + 1))
  done
  fail "FAIL: $desc — expected ICMPv6 never captured on B:\n$out"
}

# start_responder <mode> <port> <logname>
# Launches icmperr inside A and waits for ITS OWN "listening on" log line —
# printed only after both its sockets are bound. The process is backgrounded
# INSIDE the container shell (orphaned to PID 1) rather than via
# `podman exec -d`: newer podman reaps detached exec sessions shortly after
# the client exits, which silently kills the responder mid-case. Detached
# execs also fail outright every so often, and /proc/net/udp greps can match
# coincidental ephemeral ports of other sockets — so the log line plus
# retries are what actually prove liveness.
start_responder() {
  mode=$1; port=$2; logname=$3
  n=0
  while [ "$n" -lt 3 ]; do
    $PODMAN exec "$CT_A" rm -f "/work/$logname" >/dev/null 2>&1 || true
    $PODMAN exec "$CT_A" sh -c "icmperr -mode $mode -listen 127.0.0.1:$port >> /work/$logname 2>&1 &"
    m=0
    while [ "$m" -lt 5 ]; do
      if $PODMAN exec "$CT_A" grep -q "listening on" "/work/$logname" 2>/dev/null; then
        log "icmperr $mode responder ready on :$port"
        return 0
      fi
      sleep 1
      m=$((m + 1))
    done
    log "icmperr $mode did not come up (attempt $((n + 1))); retrying"
    n=$((n + 1))
  done
  fail "FAIL: icmperr $mode responder never became ready:\n$($PODMAN exec "$CT_A" cat "/work/$logname" 2>/dev/null || echo '(no log)')"
}

# ── Start + verify both icmperr responders on A ───────────────────────────
start_responder timeexceeded $TE_PORT icmperr-te.log
start_responder ptb $PTB_PORT icmperr-ptb.log

# ── 1. Time Exceeded → ICMPv6 type 3 ──────────────────────────────────────
log "probing $TE_TARGET expecting translated Time Exceeded on B"
sniff_and_probe te 'ip6[40] == 3' "$TE_TARGET" "" \
  "ICMPv6 Hop Limit Exceeded delivered to B (RFC 7915 §4.2: type 11 → 3)"

# ── 2. Closed port → kernel-generated ICMPv4 3/3 → ICMPv6 1/4 ────────────
log "probing closed UDP port $CLOSED_PORT on A expecting translated Port Unreachable on B"
sniff_and_probe pu 'ip6[40] == 1 and ip6[41] == 4' "[${NAT64_POOL_PREFIX}7f00:1]:$CLOSED_PORT" "" \
  "ICMPv6 Destination Unreachable/port-unreachable delivered to B (RFC 4443 §3.1)"

# ── 3. Packet Too Big → ICMPv6 type 2 with adjusted MTU ───────────────────
log "probing $PTB_TARGET with an oversized datagram expecting translated Packet Too Big (MTU 1280) on B"
$PODMAN exec "$CT_B" sh -c "
  yes 'ydn64-ptb-test-pattern-' | tr -d '\n' | head -c 1400 > /tmp/big.bin"
# udpecho sends /tmp/big.bin as one datagram (fragmented by B's kernel
# across the tunnel as needed).
sniff_and_probe ptb 'ip6[40] == 2' "$PTB_TARGET" "1280" \
  "ICMPv6 Packet Too Big delivered to B with RFC 7915 §4.2-adjusted MTU" /tmp/big.bin

# ── 4. Informational: real-internet error path ────────────────────────────
# Probes toward pool6::8.8.8.8 traverse ydn64 onto the real internet. This
# check is deliberately non-fatal and expected to stay silent on many paths:
#
#   * Whether any given network emits ICMP for probes is entirely
#     path-dependent (Google's edge, for instance, ignores closed-port
#     UDP probes on 8.8.8.8).
#   * Classic hop-by-hop traceroute cannot resolve through ydn64 at all:
#     flows are terminated and re-originated with a fresh IPv4 TTL, so
#     the client's small hop limits never expire an intermediate IPv4
#     router (see README "Architectural limitations"). Errors that ARE
#     produced against a tracked flow — server port-unreachables, tunnel
#     PTBs, admin prohibitions — translate normally, as proven above.
trace=""
n=0
while [ "$n" -lt 3 ]; do
  trace=$(exec_b traceroute6 -n -w 2 -q 1 -m 6 "${NAT64_POOL_PREFIX}808:808" 2>/dev/null || true)
  # A resolved hop = a line whose hop number is followed by an address
  # (no asterisks), e.g. " 2  2001:db8::1  12.3 ms".
  if printf '%s\n' "$trace" | awk '$1 ~ /^[0-9]+$/ && $2 !~ /\*/ { found=1 } END { exit !found }'; then
    log "PASS: internet traceroute resolved ≥1 intermediate router through NAT64:"
    printf '%s\n' "$trace" | while IFS= read -r line; do log "  $line"; done
    HOPS_OK=1
    break
  fi
  n=$((n + 1))
done
if [ "${HOPS_OK:-}" != "1" ]; then
  warn "internet traceroute resolved no intermediate hops (expected on most paths; see case header):\n$trace"
fi

log "all ICMP error translation checks complete"
