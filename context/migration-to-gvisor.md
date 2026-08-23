# Migration to gVisor — sub-agent task list

Task breakdown for moving ydn64 functionality that is hand-rolled today onto
capabilities already provided by the vendored gVisor netstack
(`gvisor.dev/gvisor v0.0.0-20250812171554-968e93457fe6`, see `go.mod`). Each
task is written to be executable by an autonomous sub-agent without further
context beyond this repo (read `AGENTS.md` first — it is authoritative).

All API names cited below were verified against the exact vendored version.

## Task index

| ID  | Title                                                        | Priority | Depends on | Status |
|-----|--------------------------------------------------------------|----------|------------|--------|
| T1  | Migrate NAT64 UDP to gVisor `udp.NewForwarder`               | P0       | —          | DONE   |
| T2  | TCP keepalive / user-timeout on NAT64 proxied connections    | P1       | —          | DONE   |
| T3  | Integration verification + fragmented-UDP test case          | P1       | T1         | DONE   |
| T4  | Stack & per-flow stats exposure                              | P2       | —          | DONE   |
| T5  | Packet tap (multi-listener) via `RegisterPacketEndpoint`     | P2       | —          | DONE   |
| T6  | Spike: congestion control / MTU probing tunables             | P3       | —          | DONE   |
| T7  | Spike: IPTables/nftables-based `AllowedSources`              | P3       | —          | DONE   |

---

## Shared ground rules (apply to every task)

1. **Never enable `HandleLocal`.** It must stay false (the default) in
   `src/netstack/netstack.go`; combined with promiscuous mode it makes gVisor
   drop all inbound traffic as martian-sourced.
2. **Promiscuous + spoofing are both required and both already enabled** for
   NIC 1 when pool6 is configured (`CreateYdn64Netstack`). Do not remove or
   gate either flag; NAT64 receive *and* reply paths depend on them.
3. **Zero-payload TCP packets are not just RSTs** — any change touching the
   zero-payload branch in the custom `YggdrasilNIC.WritePackets`
   (`src/netstack/yggdrasil.go`) must keep handling SYN, SYN-ACK, ACK, FIN,
   and RST.
4. **Only one `SetPacketInterceptor` slot exists.** Tasks that add packet
   observation must NOT register a second interceptor; use the tap mechanism
   from T5 instead.
5. **Two logging destinations**: stdlib `log` → stderr (`podman logs`);
   injected `*log.Logger` (gologme) → `-logto` file only, never visible in
   `podman logs`. Use the injected logger in service code, like existing code.
6. Build/verify after every task:
   ```sh
   go build ./...
   go vet ./...
   ```
   Integration verification uses the podman harness (`cd test && ./run.sh …`,
   see AGENTS.md). Rebuild images before re-testing; artifacts go to
   git-ignored `tmp/` and `test/.run/`, never the repo root.
7. **Config schema changes** (any new key in `AppConfig`) require ALL of:
   field + json tag in `src/config/config.go`, validation in
   `AppConfig.validate()`, generated template update in
   `src/config/generate.go` (preserve HJSON comments), README "Configuration"
   section update. Avoid schema changes unless the task explicitly calls for
   one.
8. No comments-in-code policy does not apply here: this codebase documents
   heavily with comments explaining gVisor behavior — follow the local style
   and explain *why* next to every non-obvious gVisor interaction.
9. Do not commit. Leave changes in the working tree. Do not touch
   `CHANGELOG.md` unless explicitly asked.

---

## T1 — Migrate NAT64 UDP to gVisor `udp.NewForwarder`

**Priority:** P0 (highest value: deletes the most custom code and fixes
fragmentation correctness).

### Current behavior

NAT64 UDP is fully hand-rolled outside gVisor:

- `Service.interceptPacket` (`src/nat64/service.go:148`) inspects raw IPv6
  bytes from the NIC read path (`pkt[6] == 17`) and dispatches UDP packets to
  `interceptUDPPacket` (`src/nat64/udp.go:32`).
- Sessions live in `Service.sessions sync.Map` keyed by a 4-tuple
  (`sessionKey`), each holding a connected `net.UDPConn` ("udp4") plus manual
  `lastSeenNs` idle tracking, expired by `cleanupSessions`.
- Replies are synthesised byte-by-byte by `buildIPv6UDPPacket`
  (`src/nat64/packet.go:12`) with a hand-written pseudo-header checksum
  (`ipv6UpperLayerChecksum`), then injected with
  `YggdrasilNetstack.WritePacket`.

Known correctness gaps being fixed:

- **Fragmented datagrams break**: only the first fragment has `pkt[6] == 17`;
  later fragments fall through to gVisor (which has no endpoint for them).
  IPv6 fragment headers (and any extension headers) make the fixed-offset
  header parsing wrong.
- **Oversized replies**: raw replies larger than the Ygg MTU cannot be
  fragmented by the raw write path.
- Duplicated logic gVisor already owns: checksums, demux, port-unreachable
  signalling.

### Target behavior

UDP follows the same architecture TCP already uses (`src/nat64/tcp.go`):
gVisor terminates the IPv6 leg inside netstack; Go sockets handle the IPv4
leg; a small relay pumps between them.

### Implementation steps

1. In `Service.Start` (`src/nat64/service.go`), next to the existing TCP
   forwarder registration, add:

   ```go
   udpFwd := udp.NewForwarder(s.ns.Stack(), s.handleUDPForward)
   s.ns.Stack().SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
   ```

   (`udp.NewForwarder` takes no backlog argument, unlike the TCP one.)

2. Implement `handleUDPForward(req *udp.ForwarderRequest) bool`. The handler
   runs synchronously in gVisor's packet path — do the cheap filtering inline,
   spawn goroutines for everything else.

3. **Filtering (mirror `handleTCP` semantics exactly):**
   - `id := req.ID()` — `LocalAddress` = pool6::IPv4 destination,
     `RemoteAddress` = Yggdrasil client.
   - Destination not in `s.pool6Net` → return `true` (consumed/silent drop).
     Do NOT return `false`: returning false makes the stack emit an ICMPv6
     port-unreachable sourced from the packet's destination address, which
     must never happen for addresses we don't own.
   - Source in pool6 subnet (RFC 6146 §3.5/§5.4) or `!s.isAllowed(src)` →
     return `true` (preserves today's silent-drop behavior for disallowed
     sources).
   - Embedded IPv4 = last 4 bytes of `LocalAddress`; `s.isIgnoredDst(...)` →
     return `true`.
   - Valid flow but endpoint creation fails (see below) → returning `false`
     is acceptable and RFC-like (port unreachable); decide based on which
     error occurred.

4. **Session handling — critical detail.** The UDP forwarder has NO request
   deduplication: *every inbound datagram* produces a fresh
   `ForwarderRequest`. A naive `req.CreateEndpoint` per datagram fails with
   `ErrPortInUse` once the tuple is registered. Keep the existing
   `sessions sync.Map` keyed by `sessionKey`:
   - First datagram for a tuple: create `waiter.Queue`, call
     `ep, tcpErr := req.CreateEndpoint(&wq)`; wrap with
     `gonet.NewUDPConn(wq, ep)` (two-argument signature in this vendored
     version). Store session, spawn relay goroutines, `LoadOrStore` race
     pattern as today (close the losing endpoint).
   - **Do not manually forward the first datagram's payload**: `CreateEndpoint`
     already queues the triggering packet into the endpoint (`ep.HandlePacket`
     at the end of `udp.ForwarderRequest.CreateEndpoint`). Manually writing it
     too would duplicate the datagram toward the IPv4 server.
   - Subsequent datagrams for an existing tuple: read nothing from the
     request; just `conn.Write(payload)` into the existing `*gonet.UDPConn`
     (a connected endpoint rejects foreign peers anyway). Copy the payload out
     of the PacketBuffer before returning — it belongs to gVisor.

5. **Reply path:** the v4→v6 direction reads from the connected "udp4"
   socket (as `udpReplyLoop` does today) but writes into the `gonet.UDPConn`
   instead of building raw packets. gVisor routes the reply from
   `pool6::IPv4` back to the client using the same promiscuous/spoofing
   machinery as TCP SYN-ACKs (the pool6 route added by `addPool6Route`
   covers egress). Checksums and outbound IPv6 fragmentation are handled by
   netstack.

6. **Idle timeout:** keep `cleanupSessions` (`service.go`) and the rolling
   deadline pattern: refresh `lastSeenNs` around reads/writes on BOTH legs;
   expiry closes the gonet conn + udp4 conn; relay loops exit on close and
   delete the map key. The v4-side read deadline (`SetReadDeadline`) stays.

7. Narrow the interceptor: in `interceptPacket`, delete the `case 17` branch;
   keep only ICMPv6 (`case 58`). Update its doc comment.

8. Delete now-dead code: `buildIPv6UDPPacket`,
   `ipv6UpperLayerChecksum`'s UDP usage (ICMP builder still needs it),
   `udpReplyLoop`'s raw-write body, unused `udpSession` fields. Keep
   `YggdrasilNetstack.WritePacket` (still used by `icmp.go`).

9. Update documentation claims:
   - `Service` doc comment in `src/nat64/service.go:19-29` ("UDP — intercepted
     at NIC level…").
   - AGENTS.md netstack gotcha about the shared dispatcher mentioning
     `interceptUDPPacket (17)` — rewrite to reflect interceptor == ICMP-only.
   - Grep README.md and `context/improvement.txt` references for stale claims.

### Key APIs (verified in vendored version)

- `udp.NewForwarder(*stack.Stack, ForwarderHandler)` — handler signature
  `func(*ForwarderRequest) bool` (bool = handled; false ⇒ stack sends ICMPv6
  port unreachable).
- `udp.ForwarderRequest`: `ID() stack.TransportEndpointID`,
  `CreateEndpoint(*waiter.Queue) (tcpip.Endpoint, tcpip.Error)` — binds to
  (dst=pool6 addr, LocalPort), connects to (src client), pre-queues the
  triggering packet.
- `gonet.NewUDPConn(wq *waiter.Queue, ep tcpip.Endpoint) *gonet.UDPConn`
  (`pkg/tcpip/adapters/gonet/gonet.go:555`).

### Gotchas

- DNS64 coexistence: `dns64/server.go` binds a real UDP endpoint via
  `gonetListenUDP`. gVisor's demuxer checks bound endpoints BEFORE the
  transport protocol handler, so DNS64 traffic is unaffected; the forwarder
  only sees unmatched flows. Verify explicitly (existing harness DNS cases +
  NAT64 UDP case).
- DNS64's outbound queries (`lookupViaNetstack`, `dns64/proxy.go`) dial UDP
  through the same stack; outbound packets never hit the transport handler,
  so no interference — but confirm upstream-query round-trips still work in
  the harness.
- Promiscuous mode means ANY unmatched inbound UDP reaches the handler,
  including non-pool6 destinations — hence the mandatory pool6 filter before
  anything else.
- The handler must be fast; heavy work (dialing, relaying) goes to
  goroutines, exactly like `handleTCP`.

### Verification

- `go build ./... && go vet ./...`.
- Harness: `./run.sh all` — all cases must pass unchanged, especially DNS
  (DNS64 shares the UDP demux space) and case 05 (real-world dig/ping).
- Manual harness checks from container B against a pool6 address:
  - ordinary UDP exchange works;
  - a response large enough to exceed the path MTU arrives fragmented and
    reassembles (this previously failed);
  - disallowed source (temporarily narrow `AllowedSources`) is silently
    dropped — B sees timeout, NOT ICMPv6 port-unreachable;
  - unknown pool6 port gets ICMPv6 port-unreachable (new RFC-ish behavior).

### Out of scope

ICMP translation (stays on the raw-socket path — the IPv4 side genuinely
needs a host socket), config schema changes, TCP behavior changes (T2).

---

## T2 — TCP keepalive / user-timeout on NAT64 proxied connections

**Priority:** P1. Independent of T1.

### Problem

`handleTCP` (`src/nat64/tcp.go:18`) proxies between a gVisor TCP endpoint and
an OS "tcp4" socket with plain `io.Copy`. If the Yggdrasil peer vanishes
silently (client crash, network partition) mid-transfer-idle, the gVisor
endpoint can linger forever: no keepalives are configured, so dead peers are
only reaped by gVisor's very long internal retransmit timeouts (~2 min per
SYN-ACK attempt; established-flow stall recovery is far longer).

### Target behavior

Enable TCP keepalives (and optionally user timeout) on the gVisor side of
every NAT64 proxied connection, with conservative defaults; optionally
config-exposable.

### Implementation steps

1. In `handleTCP`, immediately after `req.CreateEndpoint(&wq)` succeeds and
   before starting the proxy goroutine, set socket options on `ep`:

   ```go
   ep.SetSockOptBool(tcpip.KeepaliveEnabledOption(true))
   ep.SetSockOpt(tcpip.KeepaliveIdleOption(75 * time.Second))
   ep.SetSockOpt(tcpip.KeepaliveIntervalOption(10 * time.Second))
   ep.SetSockOptInt(tcpip.KeepaliveCountOption, 9)
   ```

   All option names verified in `pkg/tcpip/tcpip.go` of the vendored version
   (`KeepaliveIdleOption` :1278, `TCPUserTimeoutOption` :1295,
   `CongestionControlOption` :1303; `KeepaliveCountOption` is a
   `tcpip.SockOptInt`).

2. Decide defaults so a dead peer is detected in roughly 75+9×10 ≈ 165s.
   Document the arithmetic in a comment.

3. Optionally also set `ep.SetSockOpt(tcpip.TCPUserTimeoutOption(d))`
   (retransmit-driven abort for established flows). If set, pick a value ≥
   the keepalive budget and document interplay.

4. Config exposure is OPTIONAL. If adding keys (e.g. `Nat64TCPKeepaliveSec`),
   follow ground rule 7 end-to-end. Prefer hard-coded constants + TODO note
   if the config addition would bloat this task.

### Verification

- Build/vet.
- Harness full run unchanged.
- Behavioral spot-check: establish a long-lived TCP connection B→target
  through NAT64, kill container B's networking (`podman pause b`), observe
  the connection teardown in `.run/ydn64.log` within ~3 minutes instead of
  lingering.

### Out of scope

Changing `proxyTCP`, dial timeouts, or the IPv4 leg's own keepalives (OS
defaults apply there).

---

## T3 — Integration verification + fragmented-UDP regression case

**Priority:** P1. Depends on T1.

### Goal

Lock in T1's correctness wins with a permanent black-box test case and a
regression checklist run.

### Steps

1. Add `test/cases/06_udp_fragmented_datagrams.sh` (match the conventions of
   existing cases in `test/cases/` and helpers in `test/lib.sh`):
   - From container B, send a UDP payload to a pool6-mapped target such that
     the *reply* exceeds the Ygg MTU (e.g. DNS query with large EDNS0 answer,
     or `nc -u` bulk send) forcing IPv6 fragmentation on the v6 reply path.
   - Assert the full reply is received intact by B (pre-T1 this fails:
     oversized raw replies were dropped/unfragmentable).
   - Also assert a normal small UDP exchange still works.
2. Run the FULL suite: `./run.sh down && ./run.sh all` (not just `test` —
   ensure images are rebuilt from current `src/`).
3. Watch for known harness flakes documented in AGENTS.md (case-04 restart
   flake ~1-in-3; hung `podman exec`; allow generous `wait_for 30` budgets).
   Re-run before diagnosing as a code failure.
4. Confirm ICMP NAT64 unaffected: case 05 (`ping6` to dns.google through the
   pool) passes — T1 must not have touched the ICMP interceptor contract.
5. Record results (pass/fail, timings, flake notes) appended to THIS file
   under "T3 execution log".

### Out of scope

New harness topology changes; CI wiring.

---

## T4 — Stack & per-flow stats exposure

**Priority:** P2. Independent.

### Goal

Operational visibility using counters gVisor maintains anyway — no packet
counting code of our own.

### Implementation steps

1. Add a periodic debug-stats logger in NAT64 service startup (goroutine on
   the service `ctx`), logging every 60s at Debug level via the injected
   logger:
   - `s.ns.Stack().Stats()` → `tcpip.Stats` (`pkg/tcpip/tcpip.go:2481`;
     `TCPStats` :2164, `ICMPv6Stats` :1854) — log deltas since previous tick
     for the interesting counters (IP.PacketsSent/Received,
     TCP.Active/Opened/Established.../SegmentsSent|Received|ResetsSent,
     ICMP v6 echo counts). Counter values come from `StatCounter.Value()`.
   - Session counts: approximate via `sync.Map` iteration length (UDP/ICMP
     sessions; post-T1 these shrink).
2. Also trigger an immediate stats dump on SIGHUP alongside the existing
   reload path if trivially reachable from `main.go`; otherwise skip.
3. Keep the log line compact single-line-per-tick, greppable prefix
   (`netstack stats:`).

### Verification

Build/vet; run binary locally with `-loglevel debug` against the harness
(`run.sh logs a` + `.run/ydn64.log`) and confirm plausible counter movement
during case runs.

### Out of scope

Prometheus/metrics endpoints, per-endpoint RTT extraction (possible future
work via `ep.Stats()` → `tcp.StatsInfo`).

---

## T5 — Packet tap via `stack.RegisterPacketEndpoint`

**Priority:** P2. Independent (do not combine with T1 in one change set).

### Goal

A debug/diagnostics packet tap that coexists with the NAT64 interceptor —
demonstrating the escape hatch from the single-interceptor limitation
(ground rule 4) for future observability features.

### Implementation steps

1. Implement a minimal `stack.PacketEndpoint` (interface at
   `pkg/tcpip/stack/registration.go:164`: `HandlePacket(nicID, route, pkt)`
   plus embedded LinkEndpoint methods — WritePackets etc. can be no-ops).
   Treat received `pkt` as immutable; copy `pkt.ToView()` data before
   queueing downstream.
2. Register with
   `stack.RegisterPacketEndpoint(1, header.IPv6ProtocolNumber, tap)`
   (`stack.go:2050`); deregister on shutdown.
3. Wire behind a CLI/env-gated debug switch (e.g. `YDN64_DEBUG_PCAP=path`),
   NOT a new config-schema key unless rule 7 is followed. When enabled, write
   a libpcap-format file (LINKTYPE_RAW / DLT_RAW = 101, IPv6 packets) with a
   simple writer in `src/netstack/` — no third-party dependency.
4. Document in code comments AND this file: the tap sees what gVisor delivers
   AFTER the NAT64 interceptor consumed UDP/ICMP echoes — i.e., post-T1 it
   observes forwarded TCP/UDP, not intercepted packets. It complements, not
   replaces, the interceptor.

### Verification

Run harness with the env var set; open the pcap in Wireshark/tshark and
confirm parseable IPv6 TCP streams for NAT64 flows.

### Out of scope

Ring buffers, rotation, filtering DSL.

---

## T6 — Spike: congestion control & MTU probing tunables

**Priority:** P3 (exploration; may legitimately conclude "skip").

### Goal

Determine whether exposing gVisor's built-in TCP tuning knobs adds value for
long-fat Yggdrasil tunnels, and implement only what pays off.

### Investigation checklist

1. Enumerate available algorithms at runtime:
   `stack.GetTransportProtocolOption(s, tcp.ProtocolNumber,
   &tcpip.TCPAvailableCongestionControlOption{})` — vendored protocol.go
   exposes `availableCongestionControl` (cubic and reno expected).
2. Try switching: `SetTransportProtocolOption(tcp.ProtocolNumber,
   tcpip.CongestionControlOption("cubic"))` in `Start()`; benchmark a bulk
   TCP transfer B→target through NAT64 (harness, e.g. dd over nc) vs reno
   default. Note: measure BEFORE deciding to expose a config knob.
3. Evaluate `tcpip.MTUProbingOption(true)` (black-hole detection) — relevant
   given Yggdrasil MTU variability across peer paths.
4. Deliverable: implement whichever knobs measurably help (following rule 7
   for any new config keys), and append findings + numbers + decision to this
   file under "T6 findings". If nothing helps, record why and close.

### Out of scope

Per-connection algorithm selection; buffer size auto-tuning experiments.

---

## T7 — Spike: IPTables/nftables-based `AllowedSources`

**Priority:** P3 (exploration; likely conclusion: keep manual checks).

### Context

The stack ships both IPTables (`Stack.IPTables()`, options `IPTables` /
`DefaultIPTables` in `stack.Options`) and a newer nftables implementation
(`pkg/tcpip/nftables`). Today `AllowedSources` filtering is manual per-service
(`isAllowed` in nat64 + dns64), atomically reloadable via
`settings.Store(...)`.

### Evaluation criteria

1. Runtime reload: current hot-reload (SIGHUP) swaps rules atomically with
   in-flight traffic. Verify whether gVisor iptables rules can be safely
   replaced post-construction in this version; if reload requires rebuilding
   the whole stack, that alone is disqualifying (breaks SIGHUP semantics).
2. Coverage: rules must cover forwarder-delivered TCP/UDP AND the NIC-level
   ICMP interceptor path (which bypasses gVisor delivery entirely) — meaning
   the manual check survives for ICMP regardless, weakening the "single
   enforcement point" argument.
3. Silent-drop semantics: firewall DROP must remain silent (no RST/ICMP
   error) to preserve current behavior for disallowed sources.
4. Deliverable: short design note appended under "T7 findings" with a
   recommendation (adopt/reject + reasons). Only implement if adoption is
   clearly justified.

---

## Execution log

(Append findings, decisions, and verification results here as tasks complete.)

### T1 — DONE (2026-08-23)

Implementation notes that differ from / refine the task text:

- **Subsequent datagrams never reach the handler at all.** gVisor's transport
  demuxer matches registered endpoints *before* calling the transport-protocol
  handler (`transport_demuxer.go: deliverPacket`). Since
  `ForwarderRequest.CreateEndpoint` registers the connected endpoint
  synchronously inside the (single-threaded) NIC read loop, every later
  datagram of a tuple is delivered straight into the endpoint's receive queue.
  There is therefore no per-datagram session lookup or manual payload
  forwarding in the hot path — `Service.sessions` is bookkeeping only (idle
  expiry + wiring the two relay pumps). This supersedes step 4's "read nothing
  from the request; just conn.Write(payload)" sketch: there is no public way
  to read the payload of a non-first request anyway (`udp.ForwarderRequest`
  has no payload accessor), and none is needed.
- **Dropping requests without `CreateEndpoint` is safe.** The cloned
  PacketBuffer of an abandoned request is simply left to the GC; chunks are
  pooled Go objects, not manually freed memory. Policy-filtered flows are
  dropped before endpoint creation. A genuine endpoint-creation failure for a
  policy-valid flow returns `false` → stack emits ICMPv6 port-unreachable.
- **Stale-session replacement**: after idle expiry closes an endpoint but
  before its relay loops delete the map entry, a new datagram for the tuple
  creates a new session whose entry replaces the stale one unconditionally;
  relay-loop deletes use `sync.Map.CompareAndDelete` so superseded loops can
  never remove the live entry.
- **Read buffers are 65535 bytes**, not MTU-sized: reassembled datagrams can
  exceed the path MTU and `gonet.UDPConn.Read` silently truncates oversized
  datagrams to the buffer size (recvmsg semantics).
- **Race fix included**: `cleanupSessions` now reads `lastSeenNs` with
  `atomic.LoadInt64` on both UDP and ICMP sessions (stores were already
  atomic); found by `-race` once tests actually exercised expiry concurrently
  with traffic.
- `nat64.NetStack` interface introduced (satisfied by
  `*netstack.YggdrasilNetstack`) so unit tests can drive a real gVisor stack
  without a Yggdrasil core.

Tests added (`src/nat64/udp_test.go`):

- `TestParseUDPFlowFiltering` — table-driven coverage of the filter matrix
  (valid flow, non-pool6 dst, spoofed pool6 src, disallowed src, ignored dst,
  non-16-byte addresses).
- `TestNAT64UDPRelayEndToEnd` — full relay through a real gVisor stack
  (synthetic promiscuous+spoofing NIC): first datagram creates the flow,
  second datagram proves demuxer-direct delivery, reply framing/checksum
  verified against `ipv6UpperLayerChecksum`.
- `TestNAT64UDPDisallowedSourceSilentDrop` — no outbound packet, no session.
- `TestNAT64UDPSessionIdleExpiry` — cleanup goroutine expires the session,
  then the same tuple re-registers successfully.

Verification: `go build ./... && go vet ./...` clean; `go test -race ./...`
clean; podman harness `./run.sh all`: all cases passed (first run hit the
documented case-04/05 restart flake twice — second full run green).
Docs updated: AGENTS.md interceptor + demux-order gotchas, README fragmented-
packet claim, RFCs.txt (6146 §3.4 → PARTIAL, 8200 §8.1/§4 notes).

### T2 — DONE (2026-08-23)

Implementation notes that differ from / refine the task text:

- **API correction**: this vendored gVisor has neither
  `tcpip.KeepaliveEnabledOption` nor `Endpoint.SetSockOptBool`. Keepalive is
  enabled via `ep.SocketOptions().SetKeepAlive(true)` (the SO_KEEPALIVE flag
  consumed by `tcp.keepaliveTimerExpired` in `transport/tcp/connect.go`);
  idle/interval/count/user-timeout are set exactly as the task listed. The
  task's claim that all names were verified against this version was wrong on
  that one option.
- Defaults chosen: idle 75s + count 9 × interval 10s ≈ 165s dead-peer budget;
  `TCPUserTimeout` = 5 min (≥ keepalive budget) so it only ever bounds
  *stalled transfers* (data outstanding, nothing ACKed), never idle probing.
  Hard-coded constants in `src/nat64/tcp.go`; no config-schema change
  (permitted by step 4). Failures are non-fatal (debug log + proxy anyway).
- Options are applied after `CreateEndpoint` and are safe there: the
  endpoint's keepalive timer is initialized at construction, so the
  `resetKeepaliveTimer` panic path is unreachable.

Tests added (`src/nat64/tcp_test.go`):

- `TestApplyTCPKeepalive` — applies the helper to a real gVisor TCP endpoint
  and reads every knob back (`GetSockOpt`/`GetSockOptInt`/
  `SocketOptions().GetKeepAlive()`), plus an assertion that the user timeout
  can never fire before the keepalive detection budget.

Verification:

- Build/vet clean; `go test -race ./...` clean; podman harness full run: all
  cases passed first try.
- Behavioral spot-check (pause B mid-flow): **inconclusive by topology, not
  by regression.** A held-open NAT64 TCP connection B→dns.google(:443, then
  :53) was torn down ~15 s after `podman pause b`, but a control experiment
  showed the same teardown with B fully alive: Google's endpoints FIN idle
  connections that send no data within seconds-to-tens-of-seconds, which
  propagates through `proxyTCP`'s half-close handling (B lands in
  CLOSE_WAIT; A's v4 leg closes last → TIME_WAIT). Public targets cannot
  isolate a ~165 s keepalive window in this harness. Deterministic timing
  would need an IPv4 listener container (topology change — out of scope
  here); the knobs themselves are unit-verified against real gVisor options,
  and normal traffic is unaffected per the full-suite pass.

### T3 — DONE (2026-08-23)

Deviations from the task text and discoveries made while executing it:

- **Case numbered `08`, not `06`**: cases 06/07 were already taken by the
  DNS64 rcode/EDNS cases; the glob-based runner picks the file up regardless.
- **The harness had to become fragmentation-capable first.** With yggdrasil's
  default IfMTU=65535 on both nodes, no UDP datagram could ever exceed the
  path MTU, so neither the pre-T1 bug nor its fix was exercisable. Changes:
  - `test/gen -ifmtu` (default **1500**) applied to both generated configs —
    B's TUN actually segments at that size, forcing real client-side IPv6
    fragmentation.
  - Harness config emits `"IgnoredDstSubnets": []` explicitly (production
    defaults ignore RFC1918+loopback, which would make every A-local test
    target undialable through NAT64). No existing case relied on defaults.
  - New test-only helper `test/tools/udpecho` (server + one-shot client)
    baked into BOTH images: busybox `nc` truncates UDP datagrams to a small
    fixed buffer in both directions — it failed a plain loopback 2000-byte
    echo inside container A, independent of ydn64.
- **Real production bug found and fixed** (`src/netstack`,
  `cmd/ydn64/main.go`): `ipv6rwc.ReadWriteCloser` defaults its internal MTU
  to 1280 AND enforces it on inbound frames by dropping them with an ICMPv6
  Packet Too Big reply. Upstream nodes call `SetMTU(IfMTU)` when wiring their
  TUN; TUN-less ydn64 never did, so the node silently PTB'd every client
  frame above 1280 regardless of configuration. Observed live as a flaky
  "message too long" on B's socket for the first oversized exchange (PMTU
  converged to 1280 after one PTB round-trip; later attempts passed).
  `CreateYdn64Netstack(ygg, ifMTU, pool6CIDR)` now applies `rwc.SetMTU`
  before anything sizes buffers off it. This also makes gVisor fragment
  oversized *outbound* datagrams at the configured MTU, i.e. case 08 now
  exercises both reassembly (B→A) and egress fragmentation (A→B).
- Case script details: bracketed IPv6 literals are mandatory for Go's
  `net.ResolveUDPAddr` (`[v6]:port`); roundtrips retry up to 5× because the
  first datagram across a freshly booted link can race session setup.

Test case added:

- `test/cases/08_udp_fragmented_datagrams.sh`: 64 B unfragmented exchange,
  2000 B (2 fragments) and 4000 B (3 fragments) exchanges verified by
  sha256+length end-to-end through NAT64 against an echo server on A's
  loopback, plus a direct `dig @pool6::808:808` query proving forwarder flows
  coexist with DNS64's bound endpoint on the same stack.

Verification: full suite `./run.sh down && ./run.sh all` — **all cases
passed**, including case 02 (ICMP interceptor contract intact) and the new
case 08. `go build ./... && go vet ./...` clean, `go test -race ./...` clean.
Docs updated: AGENTS.md (IfMTU/SetMTU gotcha rewritten — the old text claimed
IfMTU was never read; harness section documents udpecho, the 1500 MTU and the
empty IgnoredDstSubnets; stale restart-flake notes replaced with the current
SIGHUP-reload reality), RFCs.txt unchanged this round (§3.4 wording already
updated by T1).

### T4 — DONE (2026-08-23)

Implementation notes:

- `src/nat64/stats.go`: `statSnapshot` copies the interesting counters
  (`tcpip.Stack().Stats()`); `statsLoop` ticks every 60s on the service ctx
  and logs ONE compact line at Debug level via the injected logger, prefix
  `netstack stats:`. Deltas for counters, absolute values for gauges
  (`tcpEst`, `sessUdp`, `sessIcmp`). Counters covered: ip rx/tx; tcp
  active/passive openings, established gauge, valid segs rx, segs tx,
  resets sent, retransmits, established-timed-out (keepalive/user-timeout
  aborts from T2 are visible here); udp rx/tx/unknown-port/buffer-errors;
  icmpv6 echo request received / echo reply sent.
- **API correction vs task text**: `tcpip.Stats` has no top-level `ICMPv6`
  field in this vendored version — ICMP counters live under
  `Stats.ICMP.V6` (`ICMPStats{V4, V6}`); `Stack.Stats()` returns a VALUE not
  a pointer.
- SIGHUP dump implemented (step 2): `Service.DumpStats` shares the delta
  baseline with the periodic loop under a mutex, so reload-triggered lines
  and ticker lines partition time without double-counting. Wired into
  `reloadConfig` after a successful NAT64 reload.

Tests added (`src/nat64/stats_test.go`):

- `TestTakeStatSnapshot` — every tracked counter read off a populated
  tcpip.Stats.
- `TestFormatStatsDelta` — exact delta/gauge semantics in the output line
  (unchanged counter → 0, gauge absolute, session counts included).
- `TestCountSyncMap` — trivial helper coverage.
- `TestStatsLoopLogsDeltas` — real loop against a live gVisor stack with
  20ms interval: ≥2 well-formed debug lines, then one UDP relay exchange and
  a subsequent tick whose `udpRx` delta is positive. Uses a mutex-guarded
  buffer because gologme writes from the loop goroutine while the test reads
  (found by -race).

Verification: build/vet clean; `go test -race ./...` clean; full podman suite
green; SIGHUP dump + periodic lines confirmed in `.run/ydn64.log` with
plausible counter movement during case runs.

### T5 — DONE (2026-08-23)

Deviations from the task text (verified against the vendored source, several
of the task's API claims were stale):

- **`stack.PacketEndpoint` is a one-method interface** in this version:
  `HandlePacket(nicID, netProto, pkt)` — no embedded LinkEndpoint methods to
  stub (`pkg/tcpip/stack/registration.go:164`).
- **Packet endpoints only fire when `NICOptions.DeliverLinkPackets` is set**
  at `CreateNICWithOptions` time. Production now sets it in
  `NewYggdrasilNIC`; with no endpoints registered the cost is negligible.
- **Direction capture depends on registration flavor.** Matching Linux
  AF_PACKET semantics, `nic.DeliverLinkPacket` skips protocol-specific
  endpoints for outbound packets (`PktType == PacketOutgoing`), while an
  `header.EthernetProtocolAll` (ETH_P_ALL) registration receives every packet
  exactly once in each direction. The tap therefore registers as ETH_P_ALL —
  the task's suggested IPv6-only registration would have captured inbound
  only.
- **The tap point is BEFORE destination matching and BEFORE egress
  fragmentation**: promiscuous mode is not required for capture, and oversized
  egress datagrams appear as their post-fragmentation pieces (ipv6
  handleFragments feeds fragments through nic.WritePacket individually).
- Interceptor relationship documented in code: packets consumed by
  `nat64.Service.interceptPacket` (ICMPv6 echoes) never reach gVisor and are
  invisible to the tap; forwarded TCP/UDP and DNS64 traffic are visible.

Implementation:

- `src/netstack/pcap.go` — dependency-free libpcap writer (LE magic,
  v2.4, LINKTYPE_RAW=101), mutex-guarded.
- `src/netstack/tap.go` — `PacketTap`: copies packet bytes off gVisor's
  PacketBuffer in `HandlePacket`, queues to a bounded channel (drop-on-full;
  a debug tap must never block the data path), background writer goroutine;
  `Close` unregisters, drains, closes. Env-gated via `YDN64_DEBUG_PCAP=path`
  in main.go; failure is a warning, never fatal.

Tests added:

- `src/netstack/pcap_test.go` — byte-level global-header and record-format
  validation, multi-record file layout.
- `src/netstack/tap_test.go` — live mini-stack: two inbound injections plus
  one real UDP-endpoint egress write all appear in the pcap; after Close the
  tap is unregistered (no further records, no panic on racing delivery).

Verification: build/vet clean; `go test -race ./...` clean; full podman suite
green (one run hit external-dependency flake on cases 03/04 — real-world
Alfis `.ygg` resolver transiently unreachable; resolved without changes).
End-to-end: container A restarted with `YDN64_DEBUG_PCAP=/work/tap.pcap`,
case 08 traffic driven from B, resulting 13 KB capture parsed on the host:
valid pcap header, 14 IPv6 records including port-53 DNS exchanges and
≤1496-byte gVisor egress fragments of the 4000-byte reply.

### T6 findings — DONE (2026-08-23), decision: switch to CUBIC, no knobs

- **Available algorithms** (runtime query via
  `TCPAvailableCongestionControlOption`): `reno cubic`. The gVisor default
  factory (`tcp.NewProtocol`, used by ydn64 until now) selects **Reno**;
  CUBIC requires `tcp.NewProtocolCUBIC` or a runtime
  `SetTransportProtocolOption`.
- **Benchmark** (harness: B → NAT64 TCP → loopback sink in A, 98 MB per run,
  5 runs per variant, millisecond wall clock):
  - Reno (freshly rebuilt image): 808 / 837 / 854 / 905 / 827 ms
  - CUBIC (freshly rebuilt image): 861 / 867 / 807 / 805 / 799 ms
  - **Parity.** ~115–120 MB/s either way. An earlier "Reno is 1.65 s" reading
    was a first-boot measurement artifact (warm-up of the fresh environment),
    disproven by the rebuilt control — a good reminder to re-baseline before
    crediting an algorithm change.
  - Lossless-path parity matches theory: without loss both algorithms spend
    their time in slow start and steady-state AIMD; CUBIC's advantage only
    materializes after congestion events. Simulating loss would need netem +
    CAP_NET_ADMIN inside container A, i.e. harness topology changes that this
    spike deliberately avoided.
- **Decision: switch the transport factory to `NewProtocolCUBIC`
  unconditionally, expose NO config knob.**
  Rationale: zero measured downside on lossless paths; strictly better
  post-loss behavior on high-BDP paths (the shape of real multi-hop
  Yggdrasil tunnels, where loss does occur); it is the Linux default since
  2008 so it matches what the far end (the IPv4 server side of proxied flows)
  itself runs; and a config knob for a choice with no user-measurable effect
  on our benchmark would be knob bloat (ground rule 7 discourages schema
  changes without payoff).
- **MTU probing: not available in this vendored gVisor version.**
  `tcpip.MTUProbingOption` does not exist anywhere in
  `gvisor.dev/gvisor@v0.0.0-20250812171554-968e93457fe6` (verified by grep
  over the module). The task text's claim was stale. Black-hole detection is
  therefore impossible today; PMTUD relies on in-band ICMPv6 Packet Too Big
  messages, which ydn64's netstack emits on egress (observed live during T3's
  ipv6rwc MTU investigation). Revisit if/when gVisor lands MTU probing.

Tests added: `src/netstack/netstack_test.go` —
`TestCreateYdn64NetstackUsesCubic` drives the REAL constructor path with an
offline-generated Yggdrasil core (no peers/listeners) and asserts the active
congestion control is `cubic` while both `reno` and `cubic` remain available.

Verification: build/vet clean; `go test -race ./...` clean; full podman suite
green on the CUBIC build.

### T7 findings — DONE (2026-08-23), decision: REJECT, keep manual checks

Evaluation against the task's criteria, all verified against
`gvisor.dev/gvisor@v0.0.0-20250812171554-968e93457fe6` source:

1. **Runtime reload — possible.** `IPTables.ForceReplaceTable(id, table,
   ipv6)` (`stack/iptables.go`) swaps a table under the iptables mutex,
   atomically with in-flight traffic, and initializes conntrack + reaper on
   first modification. A SIGHUP handler could rebuild the FILTER INPUT table
   from new AllowedSources (per-CIDR ACCEPT rules via `IPHeaderFilter`
   Src/SrcMask, then an unconditional DROP) and hot-swap it. Not disqualifying
   by itself.
2. **Coverage — disqualifying gap.** The NAT64 ICMP path never reaches
   gVisor: `interceptICMPPacket` consumes echo requests inside the YggdrasilNIC
   read loop (pre-delivery), so neither IPTables nor nftables can ever see
   them. The manual `isAllowed` check must survive for ICMP regardless, so
   migrating TCP/UDP to iptables would leave TWO enforcement mechanisms with
   two separate code paths and two sets of edge cases — the opposite of the
   "single enforcement point" motivation. Additionally, iptables INPUT only
   runs inside `deliverPacketLocally`, i.e. after gVisor accepts the packet;
   promiscuous-received junk for non-local addresses is dropped before any
   hook, which is fine but means hooks see a narrower stream than today's
   checks.
3. **Silent-drop semantics — satisfiable.** `RuleDrop` makes `CheckInput`
   return false and `deliverPacketLocally` silently discards; no RST or ICMP
   error is generated by the drop itself, preserving today's disallowed-source
   behavior (client sees timeout).
4. **nftables — disqualified outright.** `pkg/tcpip/nftables` in this version
   is an unwired implementation: `NFTables.CheckInput/...` exist but nothing
   in `nic.go`/`ipv6.go` invokes them, there is no runtime rule-update API,
   and no construction/integration point in `stack.Options`. It is
   experimental upstream work-in-progress.

**Recommendation: REJECT adoption.** Keep the current per-service manual
`isAllowed` checks swapped atomically via `settings.Store`. Rationale: the
coverage argument fails (criterion 2), nftables isn't integrated (criterion 4
moot), and what remains is a wash — atomic hot-reload already works today,
silent-drop semantics are identical, and adopting iptables would add conntrack
goroutines plus a rule-encoding layer to maintain for zero behavioral gain.
No production code changed as part of this spike.
