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
# Starts tcpdump on B writing matching packets' text output to /tmp/<name>.
# The trailing settle delay keeps slow podman-exec attachment from racing
# the probe that follows.
start_sniff() {
  name=$1; filter=$2
  $PODMAN exec "$CT_B" rm -f "/tmp/$name" >/dev/null 2>&1 || true
  $PODMAN exec -d "$CT_B" sh -c "exec tcpdump -ni $B_IF -l -c 1 '$filter' > /tmp/$name 2>&1" >/dev/null
  sleep 2
}

# poll_sniff <name> <timeout> <description> [expect-text]
poll_sniff() {
  name=$1; timeout=$2; desc=$3; expect=${4:-}
  n=0
  while [ "$n" -lt "$timeout" ]; do
    out=$($PODMAN exec "$CT_B" cat "/tmp/$name" 2>/dev/null || true)
    if printf '%s' "$out" | grep -qi "icmp6"; then
      if [ -n "$expect" ]; then
        if printf '%s' "$out" | grep -q "$expect"; then
          log "PASS: $desc ($out)"
          return 0
        fi
      else
        log "PASS: $desc ($out)"
        return 0
      fi
    fi
    sleep 1
    n=$((n + 1))
  done
  fail "FAIL: $desc — expected ICMPv6 not captured on B:\n$out"
}

# udp_probe <target> — one datagram from B via the harness UDP client.
# The probe tools time out (responders answer with ICMP, not UDP echoes);
# exit status is irrelevant, the assertions are the sniffed packets.
udp_probe() {
  target=$1
  $PODMAN exec "$CT_B" udpecho -once "$target" /etc/hostname "/tmp/probe.out.$$" >/dev/null 2>&1 || true
}

# ── Start + verify both icmperr responders on A ───────────────────────────
$PODMAN exec -d "$CT_A" sh -c "exec icmperr -mode timeexceeded -listen 127.0.0.1:$TE_PORT" >/dev/null
wait_for 5 "icmperr timeexceeded listener bound on A :$TE_PORT" \
  $PODMAN exec "$CT_A" grep -qi ":$(hex_port $TE_PORT)" /proc/net/udp

$PODMAN exec -d "$CT_A" sh -c "exec icmperr -mode ptb -mtu 1000 -listen 127.0.0.1:$PTB_PORT" >/dev/null
wait_for 5 "icmperr ptb listener bound on A :$PTB_PORT" \
  $PODMAN exec "$CT_A" grep -qi ":$(hex_port $PTB_PORT)" /proc/net/udp

# ── 1. Time Exceeded → ICMPv6 type 3 ──────────────────────────────────────
log "probing $TE_TARGET expecting translated Time Exceeded on B"
start_sniff te 'ip6[40] == 3'
udp_probe "$TE_TARGET"
poll_sniff te 15 "ICMPv6 Hop Limit Exceeded delivered to B (RFC 7915 §4.2: type 11 → 3)"

# ── 2. Closed port → kernel-generated ICMPv4 3/3 → ICMPv6 1/4 ────────────
log "probing closed UDP port $CLOSED_PORT on A expecting translated Port Unreachable on B"
start_sniff pu 'ip6[40] == 1 and ip6[41] == 4'
udp_probe "[${NAT64_POOL_PREFIX}7f00:1]:$CLOSED_PORT"
poll_sniff pu 15 "ICMPv6 Destination Unreachable/port-unreachable delivered to B (RFC 4443 §3.1)"

# ── 3. Packet Too Big → ICMPv6 type 2 with adjusted MTU ───────────────────
log "probing $PTB_TARGET with an oversized datagram expecting translated Packet Too Big (MTU 1280) on B"
start_sniff ptb 'ip6[40] == 2'
$PODMAN exec "$CT_B" sh -c "
  yes 'ydn64-ptb-test-pattern-' | tr -d '\n' | head -c 1400 > /tmp/big.bin"
udp_probe_ptb() {
  # udpecho -once sends /tmp/big.bin as one datagram (fragmented by B's
  # kernel across ygg0 as needed).
  $PODMAN exec "$CT_B" udpecho -once "$PTB_TARGET" /tmp/big.bin /tmp/ptb.out >/dev/null 2>&1 || true
}
udp_probe_ptb
poll_sniff ptb 15 "ICMPv6 Packet Too Big delivered to B with RFC 7915 §4.2-adjusted MTU" "1280"

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
