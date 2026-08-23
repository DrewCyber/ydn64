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

#### R9 · Config validation gaps (silent misconfiguration at runtime)
- `Nat64Pool` CIDR length not enforced — everything hard-codes /96
  (embedded-v4 extraction at byte 12, synthesis, reversePTR); a hand-edited
  /64 pool misbehaves with zero errors. Enforce /96 (or implement RFC 6052
  variable lengths — see RFCs.txt RFC 6052).
- Zone `prefix` accepted as any IPv6 address; same /96 requirement applies.
- Forwarders (`Dns64Default`, zone `forwarder`) never format-checked — parse
  `host:port` at load; reject empty default when DNS64 enabled.
- Empty `AllowedSources` = silent deny-all, logged only at Debug. Warn loudly
  at startup; add a troubleshooting note in README.

#### R10 · EDNS(0) deviations from RFC 6891
`server.go`: non-EDNS clients get up-to-1232-byte responses (classic limit is
512+TC; BIND/Unbound cap at 512); sub-512 client advertisements honoured
literally (MUST treat <512 as 512); `TestEDNS0EdgeCases` duplicates production
negotiation logic inline instead of testing the real function. Extract
`negotiateUDPSize(clientOPT) int`: no OPT→512; <512→512; else clamp
[client,4096]. Keep existing TC/truncate behaviour.

#### R11 · NIC read loop exits permanently and near-silently on first error
`yggdrasil.go`: one transient `ipv6rwc.Read` error logs to stderr (stdlib log —
invisible in the service log file) and `break`s; node keeps running deaf.
Retry transients with backoff; on terminal errors cancel the root context so
the supervisor restarts a visibly-dead process instead of a zombie. Requires
plumbing a logger into netstack.

#### R12 · Control-packet drops are invisible when `ctrlPackets` fills
The `default: pkt.DecRef()` path discards SYN-ACK/FIN/RST with no signal — the
historically catastrophic failure mode documented in this very file. Add a
dropped counter + rate-limited warning; reconsider queue necessity once R1's
per-call buffers land.

#### R13 · Silent error swallowing patterns
Bare `recover()` hides panics and reports success (log value+stack, return
`&tcpip.ErrAborted{}`); ignored deadline errors; discarded `dns.NewRR` errors
in synthesis/PTR paths; logger fallback drops the cause; `parseIA` error text
says `invalid_address` but the config key is `Dns64InvalidAddress`.

#### R14 · Dangerous allowlist examples in user-facing docs
README Docker examples and the generated-config comment show
`YDN64_ALLOWED_SOURCES="200::/7"` (= entire public Yggdrasil network as an
open relay). Replace with a concrete /128 example plus one explicit warning
sentence.

#### R15 · Container/packaging hardening
Image runs as root (binary needs nothing beyond optional CAP_NET_RAW) — add a
non-root USER; entrypoint writes the config non-atomically and world-readable
(generate to `.tmp`, `chmod 600`, `mv`); consider HEALTHCHECK.

#### R16 · Remaining inbound-validation gap: the ICMP interceptor path
After T1, forwarded TCP/UDP are structurally validated by gVisor (checksums,
lengths). The raw-socket ICMP echo path still trusts the client frame:
no IPv6 payload-length cross-check, no ICMPv6 checksum verification before
relaying to the v4 internet. Cheap to add using the existing
`ipv6UpperLayerChecksum`.

#### R17 · Small robustness batch
- `dispatcher` field written/read without synchronisation (Attach/Close vs
  read loop) — atomic pointer; Close-vs-read-loop nil deref risk.
- Graceful shutdown: services have no Stop()/drain; in-flight work is killed
  at ctx cancellation. Add WaitGroup-based drain with bounded deadline.
- `cleanupSessions` ticker cadence frozen at startup (cosmetic; per-session
  deadlines do the real work).
- `fmt.Sscan` port parsing accepts signs/out-of-range then truncates — use
  `strconv.ParseUint(_, 10, 16)`.
- `serveTCPConn` sets read but no write deadline.
- `proxyTCP` closes both directions on one-sided EOF — use `CloseWrite()` for
  half-close protocols; make the (keepalive-backed) idle window configurable
  alongside `Nat64UdpTimeout`.
- `reloadConfig` applies NAT64 then DNS64 sequentially (brief mixed-policy
  window; validate-then-swap atomically).
- `GenerateOverrides.IgnoredDstSubnets` is dead (no env wiring/caller) — wire
  or delete. `dnsCache.purgeInterval` written unlocked by Reload — guard/delete.

#### R18 · Docs/polish batch
- `matchZone` doc claims most-specific-first; implementation is config-order
  (only catch-all demoted). Sort by label count or fix comment + test.
- Denied DNS64 queries are silently dropped; a rate-limited REFUSED would help
  clients fall back faster (defensible either way).
- Hot-path niceties when profiling justifies: lowercase-once invariant in DNS
  path, `netip.Prefix` for `isAllowed`/`pool6Net`, minimal upstream messages
  instead of `req.CopyTo` deep copies, `sync.Pool` for per-reply buffers.
- Plumb `context.Context` into dials/upstream lookups so shutdown doesn't wait
  out 5–10 s timeouts.
- Consider extending `DefaultIgnoredDstSubnets` with `192.0.0.0/24`,
  `198.18.0.0/15`, `192.88.99.0/24`.
- Quote peer URIs defensively in `-genconf` output (`#`/`{}` break HJSON).

---

## 3. Suggested order of attack

| Step | Items | Why | Effort |
|---|---|---|---|
| 1 | ~~R8 (CI) + R1 + R3~~ (done 2026-08-23) | Gates first; the two netstack bugs in one pass; R1 needs its -race test to matter | small–medium |
| 2 | ~~R2 (TXID)~~ (done, commit e4fa656) | ~10 lines, closes the top security hole | small |
| 3 | ~~R7 + lastSeenNs-style mechanical races~~ (done; R7 publish order + atomic lastSeenNs in tree) | trivial, removes all known races | small |
| 4 | R4 staged (~~cache caps → semaphores → session caps~~ done 2026-08-23; per-source token buckets open) + ~~R4b~~ (TTL semantics done 2026-08-23) | biggest stability win under adversarial load | medium |
| 5 | R9 (/96 + forwarder validation + empty-allowlist warning) | silent misconfigs become startup errors | small |
| 6 | R10 (EDNS normalisation + real-function test) | interop correctness | small |
| 7 | R5 (ICMP ID rewrite), R16 (ICMP-path validation), R11/R12 | robustness | medium |
| 8 | R13–R15, R17, R18 | hygiene sweep | medium |
