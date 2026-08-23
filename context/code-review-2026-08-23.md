# ydn64 — Consolidated Code Review

**Date:** 2026-08-23. Merges and replaces `code-audit-2026-07-25.md` +
`code-review-ox-alpha-2026-08-22.md` (both deleted; original reviews were
against commit `ebd4c60`). Every open finding below was **re-verified
against the current tree** after the 2026-08 gVisor migration (T1–T7).
Line numbers are indicative; re-grep before editing.

Scope split: **protocol-conformance status lives in [RFCs.txt](RFCs.txt)** —
this file tracks engineering defects only. Items whose tracking exists there
(ICMP error translation, extension-header walking, EIM/BIB, port parity,
DNSSEC CD=1&&DO=1, AAAA exclusion set, pipelined DNS-over-TCP, hairpinning)
are not repeated here.

Severity: **P0** fix now · **P1** fix soon · **P2** should fix · **P3** polish.

---

## 1. Fixed since the original reviews — do not re-report

- Destination filtering (`IgnoredDstSubnets`) in all three NAT64 paths AND
  DNS64 synthesis; default bogon list.
- UDP zero-checksum → 0xFFFF (now owned by gVisor anyway); EDNS(0)
  negotiation + truncation/TC; synthetic TTL = min(A, SOA); NXDOMAIN
  passthrough; CNAME-chain preservation with owner name from the A record;
  non-IN qclass pass-through; `ipv4only.arpa.` answered locally (RFC 7050);
  Pref64-source drop enforced on all three paths; UDP lifetime default
  300 s / floor 120 s in `Validate()`.
- **UDP moved to gVisor's `udp.NewForwarder`** (T1): fragment reassembly,
  extension-header walking, checksum validation and outbound fragmentation
  for TCP+UDP are inherited; oversized replies use 64 KiB buffers.
- ipv6rwc IfMTU plumbing (T3): PTB/PMTUD works on the Yggdrasil leg; the
  harness exercises fragmentation end-to-end.
- TCP keepalives + user timeout on proxied connections (T2): silently-dead
  peers are reaped in ≈165 s instead of lingering forever.
- `lastSeenNs` data race fixed (atomic loads in `cleanupSessions`, T1).
- Periodic stack-stats logging + SIGHUP dump (T4) — partial observability.
- Packet tap (`YDN64_DEBUG_PCAP`) + netstack unit tests exist (tap, pcap,
  netstack constructor/CUBIC).
- Docs refreshed: AGENTS.md test guidance/context inventory/harness topology,
  README deviations wording.
- **[2026-08-23] R1 + R3 fixed** in `src/netstack/yggdrasil.go`: the shared
  `writeBuf` scratch field was replaced by a `sync.Pool` of MTU-sized buffers
  acquired inside `writePacket` for the duration of one call (concurrent
  gVisor TCP-timer / DNS64-answer / ctrlPackets-flusher writers can no longer
  interleave on shared memory), and `WritePackets` now keeps an explicit
  `written` counter — success returns the packet count, failure returns
  written-so-far + error (never `-1`); async-queued control frames count as
  written once accepted into `ctrlPackets`,   queue-full drops are not counted.
  Covered by `src/netstack/yggdrasil_test.go`: `TestWritePacketsConcurrentNoRace`
  (8 goroutines × 250 batches vs. the flusher — reproduces a `DATA RACE` in
  `WritePackets` under `-race` against the old code), plus contract tests for
  success counts, `(0, err)` first-packet failure, partial counts on mid-batch
  failure, and queue-full drop accounting (all fail against the old code).
- **[2026-08-23] R2 fixed** (commit `e4fa656`, verified present at
  `src/dns64/proxy.go` `lookup`: upstream queries use `dns.Id()`; client ID
  restored on return paths).
- **[2026-08-23] R5 fixed** (commit `23a35c0`): NAT-assigned outbound ICMP
  identifiers mapped back to `(client, destination, clientID)`,
  `LoadOrStore` semantics and bounded table in `src/nat64/icmp.go`.
- **[2026-08-23] R7 fixed**: `src/nat64/service.go` `Start()` opens and
  publishes `icmpConn` BEFORE installing the packet interceptor
  (`SetPacketInterceptor` runs last among the ICMP steps).
- **[2026-08-23] R8 fixed**: `.github/workflows/ci.yml` added — push-to-main
  + PR gates: build, vet, `go test -race ./...` (Go from go.mod via
  actions/setup-go) and shellcheck over all repo shell scripts at error
  severity.
- **[2026-08-23] R4b fixed** in `src/dns64/cache.go`: entries now expire at
  `min(smallest RR TTL in the answer, Dns64CacheExpiration)` instead of
  living exactly `Dns64CacheExpiration` regardless of upstream TTL, and hits
  return copies with TTLs decremented by time spent in the cache (clamped at
  zero) instead of re-serving undecremented values. Covered by
  `src/dns64/cache_test.go` (upstream-TTL expiry, config clamping,
  decrement-on-hit + copy independence, disabled-cache legacy behaviour).
- **[2026-08-23] R4 stages 1–3 fixed** (stage 4 per-source token buckets
  still open):
  - *Stage 1* — new `Dns64MaxCacheEntries` (default 4096); cache keyed by
    `{name, qtype}` (`cacheKey`, killing the latent name-only collision) with
    expired-first-then-random eviction at capacity
    (`dnsCache.makeRoomLocked`). Reloadable via SIGHUP.
  - *Stage 2* — new `Dns64MaxConcurrentQueries` (default 512): shedding
    semaphore around DNS64 query handling (UDP queries over the limit get an
    immediate SERVFAIL, excess DNS-over-TCP connections are closed) and new
    `Nat64MaxTCPConnections` (default 1024): `handleTCP` sheds with
    `Complete(true)`/RST instead of queueing unbounded proxy goroutines.
    Semaphore sizes are applied at startup (documented restart-only).
  - *Stage 3* — new `Nat64MaxUDPSessions` (default 4096, reloadable):
    admission control before endpoint creation evicts the
    least-recently-active session via a strictly-paired
    insert/removal-counter (`udpSessions`) whose increments/decrements track
    actual map occupancy through stale-entry replacement and CAS-deletes;
    flows are dropped when the bound cannot be met. The ICMP echo-session
    table was already bounded (`maxICMPSessions = 4096`).
  - Config plumbing end-to-end: `AppConfig.Validate()` defaults,
    `-genconf` template comments (incl. restart-only notes), README
    "Resource limits" table. Tests: `src/nat64/limits_test.go`
    (end-to-end eviction through the synthetic stack, drop-when-unbounded-
    impossible, TCP shed), `src/dns64/shed_test.go` (slot semaphore +
    SERVFAIL shape), `cache_test.go` capacity/eviction/qtype-key tests.
- **[2026-08-23] R9 fixed** in `src/config/config.go` `Validate()` (applies
  to both startup and SIGHUP reloads, which go through `config.Load`):
  - `Nat64Pool` must be a `/96` — a hand-edited /64 previously misbehaved
    silently because embedded-v4 extraction, synthesis and reverse-PTR all
    hard-code the well-known format (variable-length RFC 6052 prefixes
    remain tracked as a deviation in RFCs.txt).
  - Zone `prefix` must be an IPv6 address whose last four bytes are zero
    (a true /96 network): synthesis overwrites those bytes with the
    embedded IPv4, so host bits set there would silently produce garbage.
  - Forwarders (`Dns64Default`, zone `forwarder`) must be `host:port` with
    a numeric port in 1–65535; empty-host/missing-port/non-numeric/out-of-
    range are rejected at load. Hostnames stay allowed for the OS-dialled
    path; Yggdrasil-native forwarders must remain numeric IPv6 literals.
  - An empty `AllowedSources` (silent deny-all) now logs a loud warning at
    startup at default log level (`cmd/ydn64/main.go`, after env-var
    overrides so env-only configs are covered too), plus a README note.
  Covered by new tests incl. `TestGenconfOutputPassesValidation`, which
  round-trips `-genconf` output through hjson + `Validate()` to guard
  against template drift.
- **[2026-08-23] R10 fixed** in `src/dns64/server.go`: negotiation logic
  extracted into `negotiateUDPSize(clientOPT)` and given RFC 6891 §6.2.5
  semantics — classic non-OPT queries are now answered within 512 bytes
  (TC beyond; previously ydn64 assumed 1232 for them), advertised sizes
  below 512 are treated as 512 instead of honoured literally, and larger
  advertisements clamp at 4096 as before. TC/truncation behaviour is
  unchanged. The three tests that duplicated the production logic inline
  (`TestEDNS0UDPSizeNegotiation`, `TestEDNS0Truncation`,
  `TestEDNS0EdgeCases`) now call the real function (new floor cases:
  0/1/100/511 → 512); RFCs.txt RFC 6891 entry updated. Harness case 07
  passes unchanged.
- **[2026-08-23] R16 fixed** in `src/nat64/icmp.go` `interceptICMPPacket`:
  before anything is relayed to the IPv4 internet, the IPv6 payload-length
  header field must match the actual frame size exactly and the ICMPv6
  checksum must verify against the real pseudo-header (via the existing
  `ipv6UpperLayerChecksum`, verification form); malformed frames are
  consumed/dropped. Covered by `src/nat64/icmp_validation_test.go`
  (valid-request control + corrupted/zeroed checksums + length mismatches).
- **[2026-08-23] R11 fixed** in `src/netstack/yggdrasil.go`: the NIC read
  loop no longer exits permanently on its first Read error. Errors are
  retried with bounded exponential backoff (10 ms → 1 s cap), logged via a
  pluggable logger (`YggdrasilNetstack.SuperviseReadLoop(cancel, logf,
  grace)` — main.go wires the service logger and root-context cancel), and
  when reads stay broken past the grace period (default
  `DefaultReadFailGrace` = 30 s) the loop cancels the process context so a
  supervisor restarts a visibly dead node instead of a deaf zombie. The
  transport is now an injectable `packetRW` interface, enabling the new
  deterministic tests: cancel-after-grace and survive-transient-errors.
  The loop also nil-checks the dispatcher before delivery, closing the
  Close-vs-read-loop nil-deref risk noted under R17.
- **[2026-08-23] R12 fixed**: queue-full `ctrlPackets` drops are now
  counted (`YggdrasilNetstack.CtrlPacketsDropped()`) and produce a
  rate-limited warning (one per 30 s window) instead of vanishing
  silently. Covered by `TestCtrlDropsCountedAndWarnedOnce`.

---

## 2. Open findings

### P0

#### R1 · ~~Data race on the shared `writeBuf` corrupts outbound packets~~ — FIXED 2026-08-23 (see §1)

#### R2 · ~~Upstream DNS queries reuse the client-supplied transaction ID~~ — FIXED 2026-08-23 (commit `e4fa656`, see §1)

#### R3 · ~~`WritePackets` violates its contract: returns 0 on success, −1 possible on failure~~ — FIXED 2026-08-23 (see §1, fixed together with R1)

### P1

#### R4 · Resource bounds — PARTIALLY FIXED 2026-08-23 (stages 1–3 done, see §1; stage 4 per-source token bucket `golang.org/x/time/rate` still open)
Unbounded today: DNS64 goroutine per UDP datagram (`serveUDP`), DoT connections,
concurrent upstream queries, NAT64 TCP proxy pairs, UDP sessions (socket +
relay goroutines + 2×64 KiB buffers each), ICMP sessions, DNS cache entries
(name-only key — latent collision if A/PTR caching is ever added).
Staged fix: (1) `Dns64MaxCacheEntries` w/ expired-then-random eviction, change
cache key to `{name, qtype}` first; (2) buffered-channel semaphores around
DNS64 query handling and NAT64 `handleTCP` bodies — shed, don't queue;
(3) `Nat64MaxUDPSessions` (evict oldest-idle); (4) per-source token bucket
(`golang.org/x/time/rate`). Session caps are also the prerequisite for the
deferred EIM/BIB work (see RFCs.txt RFC 6146 §3.1).

#### R4b · ~~Cache TTL semantics ignore upstream TTL~~ — FIXED 2026-08-23 (see §1; entry-count caps remain open under R4)

#### R5 · ~~ICMP echo sessions hijackable via client-chosen identifier~~ — FIXED 2026-08-23 (commit `23a35c0`, see §1)

#### R7 · ~~`icmpConn` published AFTER the interceptor that reads it~~ — FIXED 2026-08-23 (see §1)

### P2

#### R9 · ~~Config validation gaps (silent misconfiguration at runtime)~~ — FIXED 2026-08-23 (see §1)

Previously open: `Nat64Pool` CIDR length unenforced, zone `prefix` accepted
any IPv6 address, forwarders never format-checked, empty `AllowedSources`
silent deny-all logged only at Debug. All four closed; see §1 for details.
The RFC 6052 variable-length alternative remains tracked in RFCs.txt.

#### R10 · ~~EDNS(0) deviations from RFC 6891~~ — FIXED 2026-08-23 (see §1)

#### R11 · ~~NIC read loop exits permanently and near-silently on first error~~ — FIXED 2026-08-23 (see §1)

#### R12 · ~~Control-packet drops are invisible when `ctrlPackets` fills~~ — FIXED 2026-08-23 (see §1)

#### R13 · ~~Silent error swallowing patterns~~ — FIXED 2026-08-23 (see §1)
All five closed 2026-08-23: writePacket's recover logs value+stack and
returns ErrAborted; deadline errors marked `_ =`; dns.NewRR error sites no
longer append nil records; main.go's logger fallback includes the cause;
parseIA names the Dns64InvalidAddress key.

#### R14 · Dangerous allowlist examples in user-facing docs
README Docker examples and the generated-config comment show
`YDN64_ALLOWED_SOURCES="200::/7"` (= entire public Yggdrasil network as an
open relay). Replace with a concrete /128 example plus one explicit warning
sentence.

#### R15 · ~~Container/packaging hardening~~ — FIXED 2026-08-23 (see §1); HEALTHCHECK deliberately skipped: ydn64 exposes no health endpoint, and since R11 a dead netstack cancels the process, so Docker/podman restart policy covers liveness.

#### R16 · ~~Remaining inbound-validation gap: the ICMP interceptor path~~ — FIXED 2026-08-23 (see §1)

#### R17 · Small robustness batch — MOSTLY FIXED 2026-08-23 (see §1)
- [FIXED] Graceful shutdown: nat64/dns64 gained WaitGroup-based `Drain(d)`;
  main.go drains both services for up to 5 s between ctx cancellation and
  core stop.
- [FIXED] `fmt.Sscan` port parsing → `strconv.ParseUint(10, 16)` via
  `parseListenPort` (+ table test).
- [FIXED] `serveTCPConn` now sets a write deadline too (and both deadline
  errors are explicitly ignored by intent).
- [FIXED] `proxyTCP` half-closes (`CloseWrite`) on one-sided EOF instead of
  killing both directions.
- [FIXED] `reloadConfig` applies DNS64 before NAT64 so a rejected new config
  aborts before any mutation (a brief mixed-policy window between the two
  swaps remains — cross-service atomicity not worth the plumbing).
- [FIXED] Dead `GenerateOverrides.IgnoredDstSubnets` field removed;
  unlocked `dnsCache.purgeInterval` field removed entirely (janitor reads
  only its ticker).
- [DEFERRED] Full Attach/Close synchronisation of `dispatcher`
  (the nil-deref half was closed with R11's dispatcher check).
- [DEFERRED] Configurable keepalive idle window (keepalives already reap
  dead peers in ~165 s).
- [WONTFIX] `cleanupSessions` ticker cadence frozen at startup — cosmetic;
  per-session deadlines do the real work.

#### R18 · Docs/polish batch — MOSTLY FIXED 2026-08-23 (see §1)
- [FIXED] `matchZone` doc now states CONFIG-ORDER precedence (catch-all
  demoted), pinned by TestMatchZonePrecedence /
  TestMatchZoneOrderBeatsSpecificity.
- [FIXED] Denied DNS64 queries get a rate-limited REFUSED (500 ms global
  window) so misconfigured clients fail over fast; harness case 05 unchanged.
- [FIXED] `DefaultIgnoredDstSubnets` extended with `192.0.0.0/24`,
  `198.18.0.0/15`, `192.88.99.0/24`.
- [FIXED] Peer URIs are quoted in `-genconf` output (`#` starts an HJSON
  comment; `{}` breaks object parsing).
- [DEFERRED] Hot-path niceties (lowercase-once, netip.Prefix allowlists,
  minimal upstream messages, per-reply buffer pool) — profiling-gated.
- [DEFERRED] `context.Context` plumbing into upstream dials so shutdown
  doesn't wait out timeouts (mitigated by the bounded Drain).

---

## 3. Suggested order of attack

| Step | Items | Why | Effort |
|---|---|---|---|
| 1 | ~~R8 (CI) + R1 + R3~~ (done 2026-08-23) | Gates first; the two netstack bugs in one pass; R1 needs its -race test to matter | small–medium |
| 2 | ~~R2 (TXID)~~ (done, commit e4fa656) | ~10 lines, closes the top security hole | small |
| 3 | ~~R7 + lastSeenNs-style mechanical races~~ (done; R7 publish order + atomic lastSeenNs in tree) | trivial, removes all known races | small |
| 4 | R4 staged (~~cache caps → semaphores → session caps~~ done 2026-08-23; per-source token buckets open) + ~~R4b~~ (TTL semantics done 2026-08-23) | biggest stability win under adversarial load | medium |
| 5 | ~~R9 (/96 + forwarder validation + empty-allowlist warning)~~ (done 2026-08-23) | silent misconfigs become startup errors | small |
| 6 | ~~R10 (EDNS normalisation + real-function test)~~ (done 2026-08-23) | interop correctness | small |
| 7 | ~~R5 (ICMP ID rewrite), R16 (ICMP-path validation), R11/R12~~ (all done 2026-08-23) | robustness | medium |
| 8 | ~~R13–R15, R17, R18~~ (done 2026-08-23; a few explicitly deferred sub-items remain, marked in §2) | hygiene sweep | medium |
