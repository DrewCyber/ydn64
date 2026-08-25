# Code Review — ydn64 (2026-08-24)

> **Status (2026-08-25): ALL findings addressed.** Fix commits, in order:
>
> | Finding | Commit | Notes |
> |---|---|---|
> | #1 (P0) | `0ace043` | bounds fixes + regression tests + recover() containment in netstack's interceptor hook |
> | #2 (P1) | `779f1e3` | upstream transport follows client transport; TC-fallback over TCP; black-box case 18 |
> | #3 (P1) | `249c6c5` | keepalive budget mirrored on IPv4 leg via net.KeepAliveConfig; USER_TIMEOUT deferred (no stdlib knob) |
> | #4 (P2) | `d0f8568` | 64 KiB relay read buffers pooled |
> | #5 (P2) | `36ee657` | errLim spent only after session demux (injectICMPv6) |
> | #6 (P2) | `ede3ae0` | eifLim token bucket on EIF injection (100/s, burst 200); limiter parameterised |
> | #7 (P2) | `5c1d6f2` | SIGHUP warnings for Nat64MaxTCPConnections / Dns64MaxConcurrentQueries (+genconf comment note, +tests) |
> | #8–#17 (P3) | `7076aad` | half-close, icmpReplyLoop back-off, egress-truncation log, stderr logf fallback, -loglevel warning, MRU demux, CD+DO rationale comment, ANY→static, reload deny-all warning, Drain/cleanup comments |
>
> Two deviations from the letter of the review: #3's TCP_USER_TIMEOUT is
> deferred (net.KeepAliveConfig has no such field; Count-based detection kept,
> as the review itself allowed), and #17's `n.core.Stop()` item was incorrect —
> the vendored `Core.Stop()` returns nothing. Verified end-of-day: full unit
> suite with `-race`, `./build`, and the complete podman black-box harness
> (`test/run.sh all`, all 18 cases incl. new `18_dns_tcp_large_answers.sh`).

Scope: full read of all production Go code (`cmd/ydn64`, `src/config`, `src/netstack`,
`src/nat64`, `src/dns64`, `tools/`), plus the test harness (`test/`), Dockerfile,
entrypoint and CI. Every finding below was verified against the pinned gVisor
(`v0.0.0-20250812171554-968e93457fe6`) and miekg/dns (`v1.1.62`) sources where
behaviour depended on a vendored library.

Verification baseline: `go build ./...`, `go vet ./...` and
`go test -race -count=1 ./...` all pass at commit `6531c4d`.

Findings deliberately **not** re-reported (already tracked as accepted deferrals
in AGENTS.md): `YggdrasilNIC.dispatcher` Attach/Close synchronisation, per-source
token buckets via `golang.org/x/time/rate`, plumbing `context.Context` into
upstream dials, configurable TCP keepalive window, hot-path optimisations gated
on profiling.

---

## Priority summary

| # | Priority | Area | Finding |
|---|----------|------|---------|
| 1 | **P0 — Critical** | nat64 ICMP interceptor | Two confirmed remote-crash panics: index-out-of-range on zero-length upper-layer payload behind extension headers / fragments |
| 2 | P1 — High | dns64 upstream transport | DNS-over-TCP client queries are always proxied upstream over UDP; truncated answers relayed over TCP |
| 3 | P1 — High | nat64 TCP proxy | IPv4 leg has no keepalive / user timeout; dead v4 peer pins slots for up to Nat64TcpTimeout (2h04m default) |
| 4 | P2 — Medium | nat64 UDP memory | 64 KiB buffer per session forward loop + per BIB reply loop → ~256 MiB worst case at default caps |
| 5 | P2 — Medium | nat64 ICMP errors | Rate-limiter budget consumed by unrelated host ICMP noise before session demux |
| 6 | P2 — Medium | nat64 UDP EIF | Unsolicited-datagram injection path is unrate-limited |
| 7 | P2 — Medium | config reload | Restart-required settings (`Nat64MaxTCPConnections`, `Dns64MaxConcurrentQueries`) change silently on SIGHUP, unlike Enable/Pool6/Listen which warn |
| 8 | P3 — Low | nat64 TCP proxy | Half-close not preserved: first EOF closes both legs instead of `CloseWrite` |
| 9–17 | P3 — Low / nits | various | See detailed list |

---

## P0 — Critical

### 1. Remote crash: index-out-of-range panic in the NIC packet-interceptor

**Files:** `src/nat64/icmp.go:133` (non-fragmented path) and `src/nat64/icmp.go:150`
(fragmented path).

**Both sites reproduced with scratch tests against this tree** — each panics with
`runtime error: index out of range [0] with length 0`. The interceptor runs inside
the single NIC read-loop goroutine that feeds all of gVisor; an unrecovered panic
there kills the entire process. Any peer within `AllowedSources` can trigger it
with a single crafted frame whenever NAT64 is enabled *and* the raw ICMP socket
opened successfully (i.e. `CAP_NET_RAW` present — the common case in Docker
per README/test harness).

**Trigger A — non-fragmented path (`msg[0]`, icmp.go:133):** a 48-byte IPv6 frame
whose header chain ends exactly at end-of-frame:

```
IPv6 header: plen = 8, NextHeader = 60 (Dst Options), src ∈ AllowedSources, dst ∈ pool6
8-byte Destination Options header: HdrExtLen = 0, NextHeader = 58 (ICMPv6)
(no ICMPv6 bytes follow)
```

`parseIPv6HeaderChain` returns `chainICMPv6` with `l4Offset == 48`; the plen check
(`plen < 8 || len(pkt)-40 != plen`) passes (8 == 48−40); then `msg := pkt[48:]` is
empty and `msg[0] != 128` panics.

**Trigger B — fragmented path (`frag[0]`, icmp.go:150):** same frame shape but with
NextHeader = 44 (Fragment) carrying offset 0 (M=0 or M=1), ident arbitrary, and no
bytes after the Fragment header. `frag := pkt[info.l4Offset:]` is empty;
`info.fragOffset == 0 && frag[0] != 128` evaluates `frag[0]`.

Note the guard order makes this reachable only after the pool6/src/allowlist/
ignored-dst/plen checks — but every one of those passes for an *allowed* sender,
which is exactly who this service exists to serve.

**Recommended fix** (both sites):

```go
if !info.isFrag {
    msg := pkt[info.l4Offset:]
    if len(msg) < 8 { // echo header minimum (type..seq)
        return true   // consumed (dropped): malformed/truncated L4
    }
    if msg[0] != 128 { ... }
...
frag := pkt[info.l4Offset:]
if len(frag) == 0 || (info.fragOffset == 0 && frag[0] != 128) { ... }
```

Zero-length non-first fragments are already rejected safely inside
`reasmTable.add` (`len(frag)==0 → cancel`), so guarding the two index sites is
sufficient. Add both frames above as regression tests (they are ~20 lines each
using the existing `fakeICMPConn`).

**Hardening worth doing in the same pass:** the read loop is the one goroutine
whose death is fatal for all traffic. Consider either (a) a `recover()` in
`deliverInbound` that logs + drops the frame (a malformed frame should cost one
packet, not the process), or (b) a fuzz target for `interceptPacket` (see "Test
gaps") so no third unguarded index ships later. The parser
(`parseIPv6HeaderChain`) itself is bounds-clean — the risk lives at the
*consumers* of `l4Offset`.

---

## P1 — High

### 2. DNS-over-TCP queries are proxied upstream over UDP, always

**File:** `src/dns64/proxy.go:297-308` (`lookupUpstream` hardcodes
`dns.Client{Net: "udp"}`); reached from every handler including the TCP-serving
paths (`serveTCPConn → handle/passThrough`).

Consequences:

- A client querying over TCP without EDNS gets its upstream answer capped at 512
  bytes even though the ydn64↔client leg is TCP and could carry the full answer.
- When the upstream sets TC on the UDP answer, ydn64 relays the truncated, TC-flagged
  message back **over TCP**. Clients are already on their retry transport; most
  will not re-retry, so large answers (big TXT, DNSKEY passthrough, ANY-ish
  replies) fail only on the DoT path.
- RFC 7766 §8.2 recommends recursive resolvers that accept TCP queries also use
  TCP toward upstreams when the original query arrived via TCP.

The receive-buffer mechanics themselves are sound — I verified in miekg/dns
v1.1.62 that `ExchangeWithConnContext` sizes the UDP receive buffer from the
relayed OPT (or 512 when absent), so there is no truncation bug *within* the UDP
path; the issue is purely transport selection.

**Recommendation:** thread the incoming transport into `proxy.handle` (or hang it
off a per-query context) and pick `"tcp"` for TCP-originated queries; optionally
retry once over TCP when a UDP upstream answer carries TC. The netstack forwarder
path (`lookupViaNetstack`) needs the same treatment for 200::/7 zone forwarders.

### 3. Proxied TCP's IPv4 leg has no dead-peer detection

**File:** `src/nat64/tcp.go` — `applyTCPKeepalive` tunes only the gVisor leg; the
OS-side `conn4` from `net.DialTimeout` runs on system defaults (typically keepalive
idle 2h, disabled entirely on some platforms since Go doesn't enable it by
default, and no `TCP_USER_TIMEOUT`).

Failure mode: the IPv4 peer vanishes silently mid-idle while the client leg stays
up. Neither copy loop sees traffic, `lastSeen` goes stale, and the connection —
holding one global slot (`Nat64MaxTCPConnections`, default 1024) and one
per-source slot — survives until `reapIdleTCP` fires at `Nat64TcpTimeout`
(default **2h04m**). Under repeated vanishing peers one client can hold a large
fraction of the global pool for hours despite the per-source ceiling.

**Recommendation:** mirror the gVisor-leg budget on `conn4`. On Go ≥ 1.23 the
stdlib does this cleanly:

```go
if tcp4 := conn4.(*net.TCPConn); tcp4 != nil {
    _ = tcp4.SetKeepAliveConfig(net.KeepAliveConfig{
        Enable: true, Idle: tcpKeepaliveIdle,
        Interval: tcpKeepaliveInterval, Count: tcpKeepaliveCount,
    })
    // UserTimeout requires a raw SetsockoptOption via syscall on some platforms;
    // golang.org/x/net keeps SetKeepAliveConfig parity — or rely on Count alone.
}
```

(If `net.KeepAliveConfig.UserTimeout` is unavailable/portable-enough for the
release targets, `Count`-based detection ≈165 s already fixes the worst case.)

---

## P2 — Medium

### 4. Worst-case memory bound of the UDP relay path (~256 MiB + BIB loops)

**Files:** `src/nat64/udp.go` — `udpForwardLoop` allocates
`make([]byte, maxUDPDatagramSize)` (65535) per session; `udpReplyLoop` allocates
the same per BIB. With defaults (`Nat64MaxUDPSessions=4096`,
`Nat64MaxUDPSessionsPerSrc=256`) a single busy client can drive ~4096 × 64 KiB ≈
256 MiB of forward-loop buffers plus up to 256 × 64 KiB of reply-loop buffers —
before counting gVisor endpoint receive queues. This is *bounded*, but the bound
is far above what real traffic needs (datagrams above ~1.5 KB are rare and arrive
only post-reassembly).

**Recommendation:** pool the read buffers (`sync.Pool` keyed on nothing — all
buffers are the same size), or start at the path MTU and only grow after a
short-read is detected (gonet truncates like recvmsg, so growth-on-demand needs a
heuristic such as tracking gVisor's `GetSockOpt` receive-queue length; pooling is
simpler and preserves exact semantics).

### 5. Translated-ICMP-error budget drained by unrelated host ICMP noise

**File:** `src/nat64/icmperr.go:332` — `handleICMPv4Error` consumes an
`errLim.allow()` token **before** demuxing the quoted packet against live
sessions. The raw socket receives *every* ICMPv4 message the host sees
(ping responses to other processes' probes, neighbor/router noise on a busy
host); all of it parses structurally fine and burns budget at up to 50/s, so
during noisy periods genuine PMTUD / Time-Exceeded translations for live flows can
be starved exactly when they matter.

**Recommendation:** move the `errLim.allow()` check to just before
`injectICMPv6` (after a session matched), keeping a cheap pre-check if you want to
avoid building packets for misses. Two separate small buckets (translated vs.
generated) would also work but is probably overkill.

### 6. Endpoint-independent-filtering injection has no rate limit

**File:** `src/nat64/udp.go:585-588, 604-624` (`injectUnsolicitedUDP`). Once a
client has a BIB mapping under `endpoint-independent` filtering, any IPv4 host on
the real internet that knows (or brute-forces) the mapped ip:port can flood
unsolicited datagrams; each is rebuilt as IPv6, fragmented and injected onto the
Yggdrasil leg with no limiter on this path (`errLim` covers only ICMPv6 errors).
The exposure window is bounded by the mapping lifetime and the attacker must know
the external port, but this is the one outbound synthesis path with no budget at
all.

**Recommendation:** apply a token bucket here too (per-BIB or global; the global
`errRateLimiter` shape can be reused directly with its own constants). Note the
amplification ratio is ≤1 (one inbound datagram → one outbound datagram), so a
modest rate suffices.

### 7. SIGHUP silently ignores restart-required NAT/DNS capacity settings

**File:** `cmd/ydn64/main.go:398-455` (`reloadConfig`) warns about changes to
`Nat64Enable`, `Nat64Pool`, `Dns64Enable`, `Dns64Listen` — but not
`Nat64MaxTCPConnections` (sem-sized at construction, `src/nat64/service.go:159`)
nor `Dns64MaxConcurrentQueries` (`querySem`, `src/dns64/server.go:206-208`).
An operator raising these in the file and reloading gets silence, then confusion.

**Recommendation:** add the two comparisons alongside the existing four warnings.
(The generated-config comments already document restart-required semantics; the
runtime warning closes the loop.)

---

## P3 — Low / nits

8. **Half-close not preserved through the TCP proxy** — `proxyTCP`
   (`src/nat64/tcp.go:257-268`) fully closes the destination on source EOF.
   Protocols that rely on client half-close (shutdown-write then read) break
   through the translator. Using `CloseWrite` on the peer direction (both legs
   are `*net.TCPConn`/gonet TCP conns supporting it) preserves semantics; fall
   back to full close for gonet if needed.

9. **Hot-spin risk in `icmpReplyLoop`** — `src/nat64/icmp.go:301-342`: the 1 s
   read deadline bounds idle polling, but a *persistent immediate* error (not
   deadline-caused) before close returns instantly each iteration. Not reachable
   today except transiently, but cheap insurance: track consecutive errors and
   sleep briefly (e.g. 100 ms) after N non-timeout failures.

10. **Silent truncation in `writePacket`** — `src/netstack/yggdrasil.go:248`:
    `vv.Read(buf)` reads at most MTU bytes with no error when the frame is
    larger; an oversized egress frame would be silently cut. gVisor segments
    before egress given the configured NIC MTU, so this shouldn't happen — a
    one-line `if n == len(buf) && vv.Len() > 0 { log }` turns a future silent
    corruption class into a visible diagnostic.

11. **Supervision attach race leaves earliest read errors unlogged** — the read
    loop starts inside `NewYggdrasilNIC` but `logf`/`cancelRoot` are stored only
    when main calls `SuperviseReadLoop` microseconds later
    (`src/netstack/yggdrasil.go:154-159` skips logging while nil). Pre-wiring a
    stderr fallback in `CreateYdn64Netstack` removes the window.

12. **Unknown `-loglevel` values are silently treated as info** —
    `cmd/ydn64/main.go:53-67`. Warn on unmatched level strings.

13. **Address-dependent demux picks an arbitrary flow** — `demuxUDPReply`
    (`src/nat64/udp.go:650-663`) ranges the flow map and takes the first match
    for the server IP; map order randomization means multiple flows to the same
    IP receive address-dependent deliveries unpredictably. Choosing the
    most-recently-used matching flow is more deterministic and defensible.

14. **`dnssecValidatingClient` requires CD **and** DO** — `src/dns64/proxy.go:352-358`.
    RFC 6147 §5.5 keys the no-synthesis rule off CD; a validator that sets CD
    without EDNS/DO (legal, unusual) still gets synthesized AAAA. Practically
    harmless (real validators set DO), worth a comment or loosening to CD-only.

15. **Dns64Static is bypassed for ANY (and other-type) queries** —
    `staticAnswer` (`src/dns64/proxy.go:141-169`) returns nil unless Qtype is A
    or AAAA, so a statically-served name queried with type ANY falls through to
    zone logic/upstream. Either document the exact-name/A/AAAA-only scope or
    route ANY through static too (mirroring the ANY→AAAA rewrite used elsewhere).

16. **Empty AllowedSources after reload logs nothing** — the loud deny-all
    warning (`cmd/ydn64/main.go:195-198`) runs only at startup; `reloadConfig`
    happily applies an emptied list silently. Repeat the warning on reload.

17. **Small hygiene items** — `n.core.Stop()` error ignored
    (`cmd/ydn64/main.go:380`); `Drain`'s watcher goroutine leaks past deadline
    until flows finish (bounded, benign — worth a comment);
    `cleanupSessions` computes its ticker interval from startup timeouts only
    (fine today because icmpSessionTimeout/2 = 30 s dominates; revisit if the
    ICMP timeout ever becomes configurable).

---

## Test gaps worth closing

1. **Regression tests for finding #1** — the two crash frames belong in
   `icmp_test.go`/`icmp_validation_test.go` using the existing `fakeICMPConn`;
   they are deterministic, fast, and lock the fix in.
2. **Fuzz targets for untrusted-input parsers** — `parseIPv6HeaderChain`,
   `interceptPacket` (end-to-end incl. consumers), `parseICMPv4InnerPacket`,
   `ptrToIPv6`, `ParsePref64`/`Extract`. All are pure functions over bytes;
   native `go test -fuzz` targets cost ~30 lines each and would have caught #1.
   Run them locally/on demand rather than in CI if fuzz time is a concern.
3. **Black-box case for large answers over DNS-over-TCP** (finding #2) — e.g.
   resolve a name whose response exceeds 512 B via `dig +tcp +noedns` through A
   and assert the answer is complete, not TC'd.
4. **Harness case for half-idle TCP teardown** (finding #3) — establish a proxied
   connection, blackhole the IPv4 side, assert the slot frees in minutes, not at
   Nat64TcpTimeout (measurable via the stats-line `tcpEst` gauge).

## Additional considerations (beyond the strict review ask)

- **Observability of the new crash class:** when #1 is fixed, consider bumping
  the periodic stats line with `nicCtrlDrops` (already tracked via
  `CtrlPacketsDropped()` but never surfaced outside tests) — it's the other
  counter that distinguishes "healthy" from "silently lossy".
- **Metrics endpoint:** admin socket is deliberately disabled, and the stats log
  line covers most needs; if external monitoring is ever wanted, a tiny
  opt-in Prometheus text exporter on a localhost port would fit the architecture
  without touching Yggdrasil. Flagging as a possible future request, not a gap.
- **Docs:** README's Configuration section matches `-genconf` output as of this
  revision (checked key-by-key). If finding #7's warnings are added, mention in
  the generated comments which keys warn vs. apply on SIGHUP — the split is
  currently only implied by grouping.
- **Supply chain:** dependency posture is unchanged since the last review; the
  gVisor pin rationale remains valid (post-2025-08-20 releases don't build via
  plain modules). No new dependencies proposed by any recommendation above —
  finding #3 uses only the stdlib.
- **What's notably good** (so it survives refactors): the atomic-pointer
  settings/config swaps with `CompareAndDelete` lifecycle discipline in
  `sessions`/`bibs`/flows bookkeeping are correct under adversarial interleaving
  (I traced the supersede/expiry races specifically); the pref64 canonical-form
  enforcement closes the classic ambiguous-u-octet injection hole; EDNS COOKIE/ECS
  relay handling and the 0x20 health-tracking degradation are more careful than
  most production resolvers; and the harness's MTU-1500 realism genuinely
  exercises fragmentation paths the unit tests can't.

---

*Review performed by ox-alpha. Findings #1A/#1B verified empirically on this tree
(scratch tests, since removed); library-behaviour claims (finding #2's UDP receive
sizing, the tcp.Forwarder rcvWnd=0 default) verified against the pinned module
sources.*
