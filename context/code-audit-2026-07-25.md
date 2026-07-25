# ydn64 — Comprehensive Code Audit

**Date:** 2026-07-25
**Scope:** `cmd/ydn64`, `src/config`, `src/dns64`, `src/nat64`, `src/netstack`, `Dockerfile`, `docker-entrypoint.sh`, `ydn64.service`
**Nature:** Recommendations only — no code changed. Each finding is written to be actionable by an independent implementing agent.

---

## Executive summary

`ydn64` is a well-structured, well-commented codebase with unusually good institutional knowledge captured in `AGENTS.md`. The architecture (single gVisor stack, atomic-pointer config reload, shared `AllowedSources`) is sound.

The most important gaps are:

1. **No destination filtering in NAT64** — the service is a full IPv4 open proxy for any allowed source, including RFC1918, loopback, and cloud metadata (`169.254.169.254`). This is the single highest-risk finding.
2. **Upstream DNS queries reuse the client-supplied transaction ID**, materially weakening off-path cache-poisoning resistance.
3. **A confirmed data race on `YggdrasilNIC.writeBuf`** shared across all gVisor writer goroutines and the control-packet flusher.
4. **`WritePackets` always returns `0`** due to variable shadowing — it violates gVisor's `LinkEndpoint` contract.
5. **No resource bounds anywhere** — sessions, goroutines, DNS cache entries, and TCP proxy lifetimes are all unbounded.
6. **Zero unit tests**, despite a large surface of trivially testable pure functions (checksums, PTR parsing, zone matching, config validation).

Severity legend: **P0** = fix now / exploitable or corrupting · **P1** = fix soon · **P2** = should fix · **P3** = polish.

---

## 1. Security

### 1.1 [P0] NAT64 has no destination address filtering (SSRF / open relay)

**Files:** [src/nat64/tcp.go](src/nat64/tcp.go), [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/icmp.go](src/nat64/icmp.go)

The only access control is `isAllowed(srcIP)`. Once a peer passes that check, the embedded IPv4 from `pool6::<v4>` is dialled **verbatim** with no destination policy:

- `net.DialTimeout("tcp4", dstAddr, ...)` in `handleTCP`
- `net.DialUDP("udp4", nil, dstUDPAddr)` in `forwardUDP`
- `s.icmpConn.WriteTo(b, &net.IPAddr{IP: ...})` in `forwardICMP`

A remote Yggdrasil peer can therefore reach, **through the ydn64 host**:

| Range | Impact |
|---|---|
| `169.254.169.254/32` | Cloud IMDS — credential theft (classic SSRF) |
| `127.0.0.0/8` | Every loopback-bound service on the host |
| `10/8`, `172.16/12`, `192.168/16` | The operator's entire private LAN |
| `100.64/10` | CGNAT / carrier infrastructure |
| `224.0.0.0/4`, `255.255.255.255` | Multicast / broadcast amplification |
| `0.0.0.0/8`, `240.0.0.0/4` | Undefined behaviour on the host stack |

This is also non-compliant with RFC 6052 §3.1, which requires that non-global IPv4 addresses not be represented in NAT64 prefixes.

**Recommendation**
- Add a shared `destinationAllowed(net.IP) bool` gate in `src/nat64`, called from **all three** forwarders before dialling.
- Default-deny the ranges above (a built-in "bogon" list), so secure-by-default requires no config.
- Add config keys `Nat64DeniedDestinations []string` (defaults applied when unset) and optionally `Nat64AllowedDestinations []string` (allowlist mode, overrides deny list).
- Mirror the filter in `src/dns64/proxy.go`'s `synthesiseFromA` so DNS64 never even synthesises an AAAA pointing at a forbidden IPv4 — defence in depth, and it produces a clean "no answer" instead of a silently dropped connection.
- Log denials at `Debugf` with a counter, not per-packet at `Info`.

### 1.2 [P0] Upstream DNS queries reuse the client's transaction ID

**File:** [src/dns64/proxy.go](src/dns64/proxy.go)

Every upstream path builds its query with `req.CopyTo(upReq)`, which copies `req.Id`. `dns.Client.Exchange` sends `upReq.Id` as-is. Therefore **an attacker who can send a query to ydn64 chooses the transaction ID ydn64 uses toward the upstream resolver.**

Combined with no DNSSEC validation and no 0x20 name randomisation, this collapses the off-path spoofing search space from 32 bits (ID + source port) to ~16 bits (source port only), and lets an attacker pre-position spoofed responses.

Affected: `handleAAAA` (both the AAAA and the A sub-query), `handleA`, `handlePTR`, `passThrough`.

**Recommendation**
- In `proxy.lookup` (single choke point), always overwrite `req.Id = dns.Id()` before sending upstream.
- Preserve the client's ID separately and restore it on the response returned to the client (`resp.Id = clientID`), or rely on the existing `resp.SetReply`/`CopyTo` construction — verify each return path.
- Additionally implement DNS 0x20 (randomise the case of the upstream QNAME, compare case-insensitively on response) — cheap, no protocol negotiation needed.
- Consider adding optional DoT/DoH upstream support (`dns.Client{Net: "tcp-tls"}`) as the real long-term fix; the current UDP-only forwarder is the weakest link in the chain.

### 1.3 [P1] ICMP echo sessions are demultiplexed on a client-controlled identifier

**File:** [src/nat64/icmp.go](src/nat64/icmp.go)

`icmpSessionKey{dstAddr, id}` uses the **client's** ICMPv6 Echo Identifier verbatim; `forwardICMP` unconditionally `Store`s, overwriting any existing session.

Consequence: two different Yggdrasil peers pinging the same IPv4 host with the same echo ID (very common — Linux `ping` uses the PID, `ping -f` from containers frequently collides) will have their replies delivered **to the wrong peer**, leaking the other peer's echo payload and the fact that they are probing that host. It is also trivially abusable: a malicious peer can deliberately squat on another peer's `(dst, id)` pair to hijack its replies.

A real NAT64 rewrites the ICMP Identifier to a NAT-allocated value (RFC 6146 §3.5.3).

**Recommendation**
- Allocate an internal 16-bit identifier per `(yggSrc, dstIPv4, clientID)` tuple, write it into the outbound ICMPv4 Echo, key `icmpSessions` on the **allocated** ID, and restore the client's original ID when synthesising the ICMPv6 reply.
- Use `LoadOrStore` + refresh rather than blind `Store` so an in-flight session's `lastSeenNs` isn't reset by an unrelated writer.
- Bound the identifier table (see §4.3).

### 1.4 [P1] No rate limiting or per-source quotas (DoS / amplification)

**Files:** [src/nat64/tcp.go](src/nat64/tcp.go), [src/nat64/udp.go](src/nat64/udp.go), [src/dns64/server.go](src/dns64/server.go)

Nothing bounds:
- concurrent NAT64 TCP proxies (goroutine pair + 2 sockets each, no idle timeout — see §5.4)
- NAT64 UDP sessions (each: a real UDP socket, a goroutine, an MTU-sized buffer)
- ICMP sessions
- concurrent DNS64 query goroutines (`serveUDP` spawns one per datagram, unconditionally)
- concurrent DNS-over-TCP connections (`serveTCP` spawns one per accept, unconditionally)
- concurrent in-flight **upstream** DNS queries

If `AllowedSources` is set broadly (e.g. `200::/7`, which the generated config's comment literally shows as an example: `# AllowedSources: ["200::/7"]`), a single peer can exhaust file descriptors and memory, and ydn64 becomes a DNS amplification reflector for the whole Yggdrasil network.

**Recommendation**
- Add a semaphore (buffered channel) capping concurrent NAT64 TCP proxies and DNS64 query handlers; shed load rather than queueing.
- Add hard caps: `Nat64MaxSessions`, `Dns64MaxConcurrentQueries`, `Dns64MaxTCPConns`, with sane defaults.
- Add a per-source token-bucket limiter (`golang.org/x/time/rate`, already an indirect dependency) keyed on the /128 or /64 of the source.
- Change the `-genconf` comment so the suggested example is a **single /128**, not `200::/7`, and add an explicit warning that a broad `AllowedSources` turns the node into an open relay.

### 1.5 [P1] DNS cache is unbounded — "water torture" memory exhaustion

**File:** [src/dns64/cache.go](src/dns64/cache.go)

`dnsCache.items` is a plain map with no maximum entry count. Random-subdomain queries (`<random>.example.com`) — a standard DNS attack pattern — insert an entry per query, evicted only by TTL. With `Dns64CacheExpiration: 300` and even modest query rates this is an unbounded memory growth path.

Secondary issue: the cache key is `q.Name` **only** — no qtype, no qclass. Today only `handleAAAA` writes to it, so there is no direct collision, but any future caching of A/PTR results will silently collide. This is a latent correctness landmine.

**Recommendation**
- Add `Dns64CacheMaxEntries` (default e.g. 10 000) with LRU or random eviction on insert.
- Change the cache key to a struct `{name string; qtype, qclass uint16}` now, before another caller is added.
- Store the upstream TTL alongside the value and expire at `min(upstreamTTL, Dns64CacheExpiration)` — currently a 60-second upstream record is served for 300 seconds, and clients are handed the **original, non-decremented** TTL from the upstream answer (RFC 6147 §5.1.7 requires TTL handling).

### 1.6 [P1] DNS64 UDP responses are never truncated (no EDNS0 handling)

**File:** [src/dns64/server.go](src/dns64/server.go) — `serveUDP`

The response is `resp.Pack()`ed and written directly. There is no check against the client's advertised EDNS0 UDP payload size (or the 512-byte default when no OPT record is present), and no `TC` (truncated) bit is ever set.

Consequences: oversized answers are either silently dropped by the netstack/path MTU, or exceed the MTU and get truncated at the IP layer (see §5.7) producing a malformed DNS message. Clients never learn to retry over TCP because `TC` is not set. This also means ydn64 will never gracefully degrade for large answer sets.

**Recommendation**
- Read the client's OPT RR (`req.IsEdns0()`); compute `size = max(512, advertisedUDPSize)`, capped at the netstack MTU minus IPv6+UDP headers.
- Call `resp.Truncate(size)` before packing — `miekg/dns` sets the `TC` bit correctly.
- Echo an OPT RR in the response advertising ydn64's own supported size.

### 1.7 [P2] Private key handling and config file permissions

**Files:** [docker-entrypoint.sh](docker-entrypoint.sh), [cmd/ydn64/main.go](cmd/ydn64/main.go), [src/config/config.go](src/config/config.go)

- `ydn64 -genconf > "$CONFIG_PATH"` writes the file containing `PrivateKey` under the default umask — typically `0644`, world-readable.
- `YDN64_PRIVATE_KEY` passes the node identity through the process environment, where it is visible in `/proc/<pid>/environ`, `docker inspect`, and container orchestrator UIs/logs.
- `Load()` does not warn if the config file is group/world-readable.
- The log file is opened `0644`.

**Recommendation**
- In the entrypoint: `umask 077` before generating, or generate to a temp file, `chmod 600`, then `mv` into place (this also fixes the partial-write problem — see §3.6).
- Support `YDN64_PRIVATE_KEY_FILE` (read from a Docker/Kubernetes secret mount) as the preferred alternative, keeping the env var for compatibility.
- Zero the decoded private key material and the hex string where practical after `core.New` (best-effort in Go, but worth doing for the hex `string` → use `[]byte`).
- Log a warning in `config.Load` if `stat.Mode().Perm()&0o077 != 0`.
- Open the log file `0640`.

### 1.8 [P2] Container runs as root

**File:** [Dockerfile](Dockerfile)

No `USER` directive. The process only needs `CAP_NET_RAW` (and only for ICMP translation, which is already best-effort/optional). The `ydn64.service` unit is exemplary in this regard — the container should match it.

**Recommendation**
- Add a non-root user, `chown` `/data`, and `USER ydn64`.
- Document that `--cap-add=NET_RAW` (not `--privileged`) is the only capability required.
- Pin `alpine:3.20` by digest, add a `HEALTHCHECK`, and consider `FROM scratch` + `ca-certificates` copied in, since the binary is `CGO_ENABLED=0`.

### 1.9 [P2] `AllowedSources` empty means silent deny-all with no warning

**File:** [src/config/config.go](src/config/config.go)

`ParseAllowedNets(nil)` returns `nil`, and both `isAllowed` implementations then reject everything. `Validate()` does not require a non-empty `AllowedSources` when NAT64 or DNS64 is enabled, so the services start, log `sources=[]`, and silently drop 100% of traffic — a confusing failure mode.

**Recommendation:** in `Validate()`, error (or at minimum log a prominent warning) when `Nat64Enable || Dns64Enable` and `len(AllowedSources) == 0`.

### 1.10 [P3] `handleA` leaks filtered records via the Additional/Authority sections

**File:** [src/dns64/proxy.go](src/dns64/proxy.go)

When `!z.returnIPv4Addresses`, only `resp.Answer` is blanked. `resp.Ns` and `resp.Extra` are returned verbatim and routinely contain glue A records. Same pattern in `filterAAAA`'s caller — only `Answer` is filtered.

**Recommendation:** apply the same zone filter to `resp.Ns` and `resp.Extra`, or strip them entirely for filtered zones.

---

## 2. Concurrency correctness

### 2.1 [P0] Data race on `YggdrasilNIC.writeBuf`

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

```go
func (e *YggdrasilNIC) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	vv := pkt.ToView()
	n, err := vv.Read(e.writeBuf)          // shared, unsynchronised
	...
	e.ipv6rwc.Write(e.writeBuf[:n])
}
```

`writePacket` is called from:
- `WritePackets`, which gVisor invokes concurrently from **many** goroutines (one per TCP/UDP endpoint's send path), and
- the single `ctrlPackets` flush goroutine.

This is a textbook data race: two writers interleave into the same buffer, and `e.ipv6rwc.Write(e.writeBuf[:n])` can emit a packet composed of fragments of two different packets. Symptoms would be intermittent, unreproducible corruption — exactly the class of bug that is nearly impossible to diagnose after the fact.

**Recommendation**
- Simplest correct fix: allocate the buffer per call (`buf := make([]byte, e.MTU())`) — one allocation per outbound packet, negligible next to the syscall.
- Better: a `sync.Pool` of MTU-sized buffers.
- Acceptable but throughput-limiting: guard `writePacket` with a `sync.Mutex`.
- **Verify with `go test -race`** once tests exist; also worth running the black-box harness against a `-race` build.

### 2.2 [P0] `WritePackets` always returns 0 (variable shadowing)

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

```go
var i int
var tcpErr tcpip.Error
for i, pkt := range list.AsSlice() {   // ← `i` here SHADOWS the outer `i`
	...
	return i - 1, tcpErr               // ← off-by-one; returns -1 when i == 0
}
return i, nil                          // ← outer `i`, always 0
```

gVisor's `LinkEndpoint.WritePackets` contract is "return the number of packets written". Returning `0` on success tells the stack nothing was transmitted; returning `-1` on the first-packet error is out of contract entirely. This is likely contributing to retransmit/stall behaviour under load.

**Recommendation**
- Use a distinct counter name (`written`), increment per successful write, `return written, nil` and `return written, tcpErr`.
- Enable shadow detection in CI: `go vet -vettool=$(which shadow) ./...` or `golangci-lint` with the `govet.shadow` check enabled — this class of bug is otherwise invisible.

### 2.3 [P1] `dispatcher` is written and read without synchronisation

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

`Attach` sets `e.dispatcher`, the read-loop goroutine dereferences it (`nic.dispatcher.DeliverNetworkPacket`), `IsAttached` reads it, and `Close` sets it to `nil` — all unsynchronised. `Close` racing with the read loop is a nil-pointer panic, not just a race.

**Recommendation:** store the dispatcher in an `atomic.Pointer[stack.NetworkDispatcher]` (or guard with the existing `YggdrasilNetstack.mu`), and have the read loop load-and-nil-check once per packet.

### 2.4 [P1] `lastSeenNs` written atomically, read non-atomically

**Files:** [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/icmp.go](src/nat64/icmp.go), [src/nat64/service.go](src/nat64/service.go)

Writes use `atomic.StoreInt64(&sess.lastSeenNs, ...)`; `cleanupSessions` reads the field directly (`sess.lastSeenNs < cutoff`). Mixed atomic/non-atomic access to the same word is undefined behaviour under the Go memory model and will be flagged by `-race`.

**Recommendation:** change the field type to `atomic.Int64` on both `udpSession` and `icmpSession` and use `.Store()` / `.Load()` throughout. This makes the correct usage unmissable.

### 2.5 [P1] `icmpConn` is published after the interceptor is installed

**File:** [src/nat64/service.go](src/nat64/service.go) — `Start`

Order of operations:
1. `s.ns.SetPacketInterceptor(s.interceptPacket)` — the NIC read goroutine can now call `interceptICMPPacket`, which reads `s.icmpConn`.
2. `s.icmpConn = conn` — plain field write.

This is an unsynchronised write racing with a read, plus a functional window where early ICMP packets are dropped as "ICMP unavailable".

**Recommendation:** open the raw socket **before** installing the interceptor, and store it in an `atomic.Pointer[icmp.PacketConn]` so the read path is race-free. Consolidate with `icmpClosed` into a single atomic pointer that is niled on shutdown.

### 2.6 [P2] NIC read loop dies silently and permanently

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

```go
rx, err := nic.ipv6rwc.Read(nic.readBuf)
if err != nil {
	log.Println("yggdrasil NIC read error:", err)
	break            // ← loop exits forever
}
```

One transient read error permanently stops **all** inbound packet processing. The process keeps running, the health of the node looks fine externally, and every service silently stops working. Note also that this uses the *stdlib* logger (stderr) — per `AGENTS.md`, this will not appear in the service log file, making diagnosis harder still.

**Recommendation**
- Distinguish fatal (closed) from transient errors; retry with backoff on transient ones.
- On genuinely fatal errors, cancel the root context so the process exits and the supervisor (`Restart=on-failure` / container restart policy) restarts it. A dead node that exits is far better than a dead node that pretends to be alive.
- Add a liveness signal (last-packet-received timestamp) exposed via a health endpoint or log heartbeat.

### 2.7 [P2] Silent control-packet drops when `ctrlPackets` is full

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

```go
select {
case e.ctrlPackets <- pkt:
default:
	pkt.DecRef()   // silently dropped
}
```

A full 100-entry queue silently discards SYN-ACKs, FINs, and RSTs — the exact failure mode `AGENTS.md` documents as historically catastrophic and near-undiagnosable. Under load this will manifest as random connection failures with no log line anywhere.

**Recommendation:** increment a dropped-control-packet counter and log at `Warnf` with rate limiting. Consider whether the async queue is still necessary at all now that the buffer race (§2.1) would be fixed — a direct write with a per-call buffer may remove the need for the queue entirely. Also close `ctrlPackets` in `Close()` so the flusher goroutine terminates.

### 2.8 [P2] Cleanup ticker interval is fixed at startup

**File:** [src/nat64/service.go](src/nat64/service.go) — `cleanupSessions`

`interval` is derived once from the initial `udpTimeout()`. A SIGHUP lowering `Nat64UdpTimeout` from 300s to 5s leaves the sweeper running every 15s.

**Recommendation:** recompute the interval each tick and `ticker.Reset()` when it changes (the same pattern already used correctly in `dnsCache.Reload`).

### 2.9 [P2] `reloadConfig` applies changes non-atomically across services

**File:** [cmd/ydn64/main.go](cmd/ydn64/main.go)

```go
nat64Svc.Reload(...)                  // applied
if err := dns64Svc.Reload(...); err != nil {
	logger.Warnf(...); return         // DNS64 NOT applied → split-brain config
}
```

`dns64.Service.Reload` can fail on `parseIA`, leaving NAT64 on the new `AllowedSources` and DNS64 on the old ones.

Separately, `runningNat64Cfg` / `runningDNS64Cfg` are captured by value at startup and never updated, so the "requires a restart" comparisons drift: after the operator edits `Nat64Pool` and reverts it, the warning keeps firing (or stops firing when it shouldn't).

**Recommendation**
- Validate-then-apply: parse and build *all* new state (`parseIA`, `buildZones`, `ParseAllowedNets`) up front, and only swap the atomic pointers once everything succeeds.
- Keep the "running" config in an `atomic.Pointer[config.AppConfig]` updated after each successful reload, and compare against that.
- Note that `config.Load` calls `Validate()`, which **mutates** the config (fills defaults) — reload correctness depends on this being idempotent. See §3.5.

### 2.10 [P3] No graceful shutdown / drain

**File:** [cmd/ydn64/main.go](cmd/ydn64/main.go)

After `<-ctx.Done()`, `main` stops multicast/admin/core and returns. Neither service has a `Stop()`/`Wait()`; in-flight proxied TCP connections and DNS queries are killed mid-flight, and `sessions`/`ctrlPackets` goroutines are abandoned.

**Recommendation:** add `Stop(ctx)` to both services returning after their goroutines drain (a `sync.WaitGroup` per service), with a bounded drain deadline (~5s) in `main` before hard exit.

---

## 3. Error handling & configuration validation

### 3.1 [P1] Config validation gaps

**File:** [src/config/config.go](src/config/config.go) — `Validate()`

Not validated:

| Field | Gap | Consequence |
|---|---|---|
| `Nat64Pool` | CIDR parsed, but **prefix length not checked to be /96** | `reversePTR` and the interceptors hard-code a 12-byte prefix; a /64 pool silently misbehaves |
| `Dns64Listen` | Not parsed at all until `Service.Start` | Late failure after the core is already up |
| `Dns64Default` | Not checked as `host:port` | Runtime `SplitHostPort` failures per query |
| `Dns64Zones[].Forwarder` | Never validated | Same |
| `Dns64Zones[].Prefix` | `net.ParseIP` accepts **IPv4** (`"1.2.3.4"` passes) | `makeSynthesisedAAAA` produces garbage addresses |
| `Dns64Zones[].Domains` | Entries not validated as plausible domain names | Silent non-matching zones |
| Zone overlap | Multiple `["."]` catch-alls silently allowed | Last-writer-wins, order-dependent |

**Recommendation:** tighten `Validate()` for all of the above; specifically require `ones == 96` for `Nat64Pool`, require `To4() == nil` for zone prefixes, and run `net.SplitHostPort` + port-range checks on every forwarder/listen address at load time. Fail fast at load, not at first query.

### 3.2 [P2] `fmt.Sscan` used for port parsing

**Files:** [src/dns64/server.go](src/dns64/server.go), [src/dns64/proxy.go](src/dns64/proxy.go)

```go
if _, err := fmt.Sscan(portStr, &port); err != nil { ... }
...
Port: uint16(port),
```

`Sscan` accepts negative values and values above 65535, which are then silently truncated by `uint16(port)` — `70000` becomes `4464`, binding a wildly unexpected port with no error.

**Recommendation:** replace with `strconv.Atoi` + explicit `1 <= port <= 65535` range check (or `net.LookupPort("udp", portStr)`), in both locations.

### 3.3 [P2] Pervasive silent error discard

Representative sites:

- `_, _ = sess.outConn.Write(payload)` — [src/nat64/udp.go](src/nat64/udp.go)
- `_, _ = s.ns.WritePacket(pkt)` — [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/icmp.go](src/nat64/icmp.go)
- `_, _ = s.icmpConn.WriteTo(...)` — [src/nat64/icmp.go](src/nat64/icmp.go)
- `io.Copy(dst, src) //nolint:errcheck` — [src/nat64/tcp.go](src/nat64/tcp.go)
- `rr, _ := dns.NewRR(...)` — [src/dns64/proxy.go](src/dns64/proxy.go) (two sites; a malformed name silently yields no record)
- `conn.SetReadDeadline(...)` unchecked — [src/dns64/server.go](src/dns64/server.go)
- `continue` on `icmp.ParseMessage` error — [src/nat64/icmp.go](src/nat64/icmp.go)

Individually defensible; collectively they mean a misbehaving deployment produces **no diagnostic output at all**.

**Recommendation:** log at `Debugf`/`Tracef` with rate limiting, and back each with a counter (see §6.2). At minimum, do not discard errors from `WritePacket` — that is the final egress path and its failure means user-visible packet loss.

### 3.4 [P2] Bare `recover()` swallows all panics

**File:** [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)

```go
defer func() { recover() }() //nolint:errcheck
```

This hides genuine bugs (nil derefs, slice bounds) as well as the malformed-packet panic it targets, and the function then returns `nil` (success) after a panic, telling gVisor the packet was sent.

**Recommendation:** capture the recovered value, log it with a stack trace at `Warnf` (rate-limited), and return `&tcpip.ErrAborted{}` so the stack knows the write failed. Better still: identify and fix the underlying parser panic so the recover can be removed.

### 3.5 [P3] `Validate()` mutates its receiver

**File:** [src/config/config.go](src/config/config.go)

`Validate()` assigns defaults (`Nat64UdpTimeout = 30`, `Dns64CacheExpiration = 300`, ...). It is called from `Load`, again after each env override, and again on every SIGHUP reload. It happens to be idempotent today, but a validation function with side effects is a trap.

**Recommendation:** split into `applyDefaults()` and a pure `validate() error`; call defaults exactly once in `Load`.

### 3.6 [P2] Entrypoint can leave a truncated config on failure

**File:** [docker-entrypoint.sh](docker-entrypoint.sh)

`ydn64 -genconf > "$CONFIG_PATH"` truncates the target **before** the command runs. If generation fails (or the container is killed mid-write), a zero-length or partial config persists; because the file now "exists", the next start skips regeneration and fails to parse — a permanently wedged volume.

**Recommendation:** generate to `"$CONFIG_PATH.tmp"`, verify non-empty / parseable, `chmod 600`, then `mv` atomically into place. Combine with the `umask 077` fix from §1.7.

### 3.7 [P3] Logger construction discards the underlying error

**File:** [cmd/ydn64/main.go](cmd/ydn64/main.go)

Both the `syslog` and file branches use `if x, err := ...; err == nil` and drop `err`. The operator sees only `logging destination unavailable, falling back to stdout` with no cause (permission denied? no syslog socket?).

**Recommendation:** print the actual error to stderr before falling back.

### 3.8 [P3] Misleading error text in `parseIA`

**File:** [src/dns64/zones.go](src/dns64/zones.go) — `unknown invalid_address value %q`. The config key is `Dns64InvalidAddress`; there is no `invalid_address` key (that name is from the stale `context/improvement.txt` TOML design). Rename for greppability.

---

## 4. Memory management & resource lifecycle

### 4.1 [P1] Goroutine-per-UDP-datagram in the NIC hot path

**File:** [src/nat64/udp.go](src/nat64/udp.go) — `interceptUDPPacket`

Every inbound NAT64 UDP datagram triggers:
1. a `make([]byte, len(pkt)-48)` allocation, and
2. `go s.forwardUDP(...)`

even when the session already exists and the work is a single non-blocking `Write`. Two additional consequences beyond cost:

- **Packet reordering.** Independent goroutines race to `sess.outConn.Write`, so datagrams can be delivered to the IPv4 destination out of order. This breaks protocols that assume best-effort-but-mostly-ordered delivery (e.g. some VPN/media protocols, DNS-over-UDP retry logic).
- **Unbounded goroutine growth** under a packet flood.

**Recommendation**
- Fast path: `sessions.Load(key)` synchronously inside the interceptor; if the session exists, write directly (the socket write is non-blocking for UDP) — no goroutine, no allocation beyond what the write needs.
- Slow path (session creation, which may block on `DialUDP`): dispatch to a **bounded** worker pool.
- If ordering matters, give each session a small buffered channel and a single writer goroutine.
- Use a `sync.Pool` for payload buffers.

### 4.2 [P2] Per-session MTU buffers and per-reply allocations

**Files:** [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/packet.go](src/nat64/packet.go)

`udpReplyLoop` allocates `make([]byte, MTU)` per session (held for the session's lifetime), and `buildIPv6UDPPacket` / `buildIPv6ICMPEchoReplyPacket` allocate a fresh packet for **every** reply. At 10 000 sessions with a ~65 KB Yggdrasil MTU this is hundreds of MB of idle buffer.

**Recommendation:** `sync.Pool` for both the read buffers and the synthesised packet buffers; size read buffers to the actual MTU rather than assuming worst case.

### 4.3 [P2] Unbounded session tables

`s.sessions`, `s.icmpSessions` (both `sync.Map`) and `dnsCache.items` have no maximum size. Eviction is purely time-based, so the peak is `arrival_rate × timeout`, entirely attacker-controlled.

**Recommendation:** hard caps with a documented eviction policy (reject-new or evict-oldest), plus a logged warning on first saturation. Expose current sizes as metrics (§6.2).

### 4.4 [P3] `sync.Map` may be the wrong data structure

`sync.Map` is optimised for read-mostly, stable key sets. NAT64 sessions are write-heavy and churn constantly — a sharded `map` + `RWMutex` (e.g. 32 shards keyed on a hash of the tuple) will typically outperform `sync.Map` here and makes bounding (§4.3) trivial.

**Recommendation:** benchmark before changing; treat as an optimisation, not a correctness fix.

### 4.5 [P3] `dns.Msg.CopyTo` deep-copies on every hop

**File:** [src/dns64/proxy.go](src/dns64/proxy.go)

`handleAAAA` alone can perform 5+ `CopyTo` deep copies per query (request → upstream AAAA req → response, → upstream A req → response). Each copies all RRs.

**Recommendation:** construct minimal upstream `dns.Msg` values (`new(dns.Msg).SetQuestion(...)` + copy only the OPT RR) rather than deep-copying the client request.

---

## 5. Protocol correctness (NAT64 / DNS64)

### 5.1 [P1] UDP checksum of `0x0000` is not converted to `0xFFFF`

**File:** [src/nat64/packet.go](src/nat64/packet.go)

```go
return ^uint16(sum)
```

Per RFC 768 and RFC 8200 §8.1, a computed UDP checksum of zero **must be transmitted as `0xFFFF`**, because `0x0000` in an IPv6 UDP header means "no checksum", which is illegal for IPv6 and causes receivers to discard the datagram. Roughly 1 in 65 536 synthesised reply packets will be silently dropped by the peer — an intermittent, essentially undebuggable packet-loss bug.

Note this applies to the **UDP** builder only; `0x0000` is a valid ICMPv6 checksum, so `buildIPv6ICMPEchoReplyPacket` is correct as-is.

**Recommendation:** in `buildIPv6UDPPacket`, after computing `cs`, `if cs == 0 { cs = 0xFFFF }`. Add a unit test that constructs a payload producing a zero checksum.

### 5.2 [P1] IPv6 extension headers and fragments are not handled

**File:** [src/nat64/service.go](src/nat64/service.go) — `interceptPacket`

```go
switch pkt[6] {          // Next Header of the *fixed* header only
case 17: ...             // UDP
case 58: ...             // ICMPv6
default: return false    // → falls through to gVisor, which has no pool6 route
}
```

Any packet carrying a Hop-by-Hop (0), Routing (43), Fragment (44), or Destination Options (60) header has a different Next Header value and is handed to gVisor, which will drop it (no registered pool6 address). Consequently:

- **Fragmented UDP to a pool6 destination never works.** RFC 6146 §3.4 explicitly requires a NAT64 to reassemble fragments.
- There is no ICMPv6 **Packet Too Big** generation, so **Path MTU Discovery is broken** in the IPv6→IPv4 direction.

**Recommendation**
- Walk the extension-header chain to find the real upper-layer protocol and payload offset.
- Explicitly handle (or explicitly and loudly drop, with a counter) Fragment headers rather than silently misrouting them.
- Generate ICMPv6 Packet Too Big when a translated packet would exceed the IPv4 path MTU.

### 5.3 [P1] ICMP error messages are not translated

**File:** [src/nat64/icmp.go](src/nat64/icmp.go)

Only Echo Request (128) is intercepted and only Echo Reply is translated back. RFC 6146 §3.5 requires translating ICMPv4 errors (Destination Unreachable, Time Exceeded, Packet Too Big, Parameter Problem) into their ICMPv6 equivalents, including the embedded original packet.

Consequences: `traceroute` through the NAT64 does not work; connection failures to unreachable IPv4 hosts hang until timeout instead of failing fast; PMTUD is broken in both directions.

**Recommendation:** extend `icmpReplyLoop` to recognise ICMPv4 error types, extract the embedded IPv4 header to identify the originating session, and synthesise the corresponding ICMPv6 error. This is a meaningful chunk of work — scope it as its own task.

### 5.4 [P1] NAT64 TCP proxy has no idle timeout

**File:** [src/nat64/tcp.go](src/nat64/tcp.go)

```go
func proxyTCP(a, b net.Conn) {
	// io.Copy in both directions, no deadlines
}
```

An established connection with no traffic is held open indefinitely: 2 goroutines, 2 sockets, gVisor endpoint state. A peer that opens connections and then goes silent leaks resources permanently — there is no equivalent of the UDP session sweeper for TCP.

Additionally, `cp` calls `dst.Close()` on EOF in one direction, tearing down **both** directions. Protocols that legitimately half-close (some HTTP/1.0 patterns, `nc -N`, several RPC frameworks) will lose data still in flight the other way.

**Recommendation**
- Wrap both conns so every successful `Read`/`Write` refreshes a rolling `SetDeadline` (e.g. `Nat64TcpTimeout`, default 300s).
- Use `CloseWrite()` (available on `*net.TCPConn` and `gonet.TCPConn`) instead of `Close()` on EOF, to support half-close.
- Track live proxy count and enforce the cap from §1.4.

### 5.5 [P2] Inbound packets are parsed without verifying lengths or checksums

**Files:** [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/icmp.go](src/nat64/icmp.go)

- The **UDP Length** field (`pkt[44:46]`) is never read; the payload is taken as `pkt[48:]`, i.e. everything the IP layer delivered. A packet with trailing padding, or with a UDP length shorter than the IP payload length, forwards extra attacker-chosen bytes to the IPv4 destination.
- The IPv6 **Payload Length** field (`pkt[4:6]`) is never cross-checked against `len(pkt)`.
- Inbound UDP and ICMPv6 checksums are never verified, so corrupt packets are faithfully relayed onto the IPv4 internet.

**Recommendation:** validate `payloadLen == len(pkt)-40`, derive the payload from the UDP Length field, and verify the upper-layer checksum before forwarding. These are attacker-facing parsers — see the fuzzing recommendation in §6.1.

### 5.6 [P2] `reversePTR` hard-codes a /96 prefix

**File:** [src/dns64/proxy.go](src/dns64/proxy.go)

```go
for i := 0; i < 12; i++ { if ip6[i] != pfx[i] { ... } }
```

The 12-byte comparison assumes every zone prefix is a /96. Nothing validates that (see §3.1), and RFC 6052 defines five legal prefix lengths (32/40/48/56/96).

**Recommendation:** either enforce /96 at config validation time and document the restriction explicitly, or implement full RFC 6052 prefix-length support in `makeSynthesisedAAAA`, `reversePTR`, and the pool6 extraction in `tcp.go`/`udp.go`/`icmp.go` (which all hard-code `dstSlice[12:16]`).

### 5.7 [P2] Synthesised reply packets can exceed the MTU

**Files:** [src/nat64/udp.go](src/nat64/udp.go), [src/nat64/packet.go](src/nat64/packet.go)

`udpReplyLoop` reads into an MTU-sized buffer, so an IPv4 datagram larger than the MTU is **silently truncated** by the read and then forwarded as a valid-looking but corrupt UDP payload. `buildIPv6UDPPacket` adds 40+8 bytes on top, so even a full-MTU read produces an over-MTU IPv6 packet.

**Recommendation:** size the read buffer to `MTU - 48`; on a short read that fills the buffer exactly, either fragment properly or drop and emit ICMPv6 Packet Too Big rather than delivering corrupt data.

### 5.8 [P3] DNS64 TTL handling does not follow RFC 6147

Synthesised AAAA records are created via `dns.NewRR(fmt.Sprintf("%s IN AAAA %s", ...))` with **no TTL specified**, so `miekg/dns` uses its default (3600s) regardless of the upstream A record's TTL. Cached answers likewise return the original TTL rather than a decremented one.

**Recommendation:** carry the source A record's TTL onto the synthesised AAAA (`hdr.Ttl = a.Hdr.Ttl`), and decrement TTLs on cache hits by the elapsed cached time.

### 5.9 [P3] `matchZone` "most specific" claim is not implemented

**File:** [src/dns64/zones.go](src/dns64/zones.go)

The doc comment says "finds the most-specific zone ... (most specific first)", but the implementation returns the **first** zone in config order whose domain matches. With zones `["example.com"]` and `["sub.example.com"]` in that order, a query for `a.sub.example.com` matches the first, not the more specific one.

**Recommendation:** either sort matches by descending domain-label count and return the longest, or fix the comment to state that config order is authoritative. Add a unit test either way.

---

## 6. Testing, observability, and tooling

### 6.1 [P0] There are no unit tests

The repo has a good black-box podman harness but **zero `_test.go` files**. The following are pure, dependency-free functions with high bug density and near-zero test cost:

| Function | File |
|---|---|
| `ipv6UpperLayerChecksum`, `buildIPv6UDPPacket`, `buildIPv6ICMPEchoReplyPacket` | [src/nat64/packet.go](src/nat64/packet.go) |
| `ptrToIPv6`, `nibbleVal`, `reversePTR`, `containsAAAA` | [src/dns64/proxy.go](src/dns64/proxy.go) |
| `matchZone`, `buildZones`, `makeSynthesisedAAAA`, `parseIA` | [src/dns64/zones.go](src/dns64/zones.go) |
| `AppConfig.Validate`, `ParseAllowedNets`, `ParsePrivateKeyHex`, `DeriveFromPrivateKey` | [src/config](src/config) |
| `splitEnvList`, `setLogLevel` | [cmd/ydn64/main.go](cmd/ydn64/main.go) |

Several findings in this report (§5.1 zero-checksum, §5.9 zone specificity, §3.2 port truncation) would be caught immediately by a handful of table-driven tests.

**Recommendation**
- Add table-driven unit tests for every function above; validate checksums against known-good packet captures.
- Add **fuzz targets** (`go test -fuzz`) for the attacker-facing parsers: `ptrToIPv6`, `interceptPacket`/`interceptUDPPacket`/`interceptICMPPacket`, and `config.Load`.
- Add a CI workflow running `go vet ./...`, `go test -race ./...`, `golangci-lint`, and `govulncheck` on every push — currently only `release.yml` exists.
- Run the existing black-box harness against a `-race`-built binary at least in CI nightly; §2.1 and §2.4 would surface immediately.

### 6.2 [P1] No metrics or operational visibility

There is no way to answer "how many NAT64 sessions are open", "what is the DNS64 cache hit rate", "how many packets are being dropped and why" without attaching a debugger.

**Recommendation:** add counters (plain `atomic.Int64` behind an optional Prometheus endpoint on the Yggdrasil address, so it is reachable only over the mesh) for at least:

- NAT64: active TCP proxies, active UDP sessions, active ICMP sessions, dials attempted/failed, packets dropped by source filter, packets dropped by destination filter, session-table saturation events
- DNS64: queries by qtype, cache hits/misses/evictions, upstream failures/timeouts by forwarder, responses truncated, queries denied by source filter
- Netstack: NIC read errors, write errors, control packets dropped (§2.7), last-packet-received timestamp

### 6.3 [P2] Hard-coded timeouts and magic numbers

Scattered, undocumented, and unconfigurable:

| Value | Location |
|---|---|
| `5 * time.Second` DNS upstream timeout (×2) | [src/dns64/proxy.go](src/dns64/proxy.go) |
| `10 * time.Second` TCP dial timeout | [src/nat64/tcp.go](src/nat64/tcp.go) |
| `10 * time.Second` DNS TCP idle | [src/dns64/server.go](src/dns64/server.go) |
| `30 * time.Second` ICMP session timeout | [src/nat64/service.go](src/nat64/service.go) |
| `1 * time.Second` ICMP read poll | [src/nat64/icmp.go](src/nat64/icmp.go) |
| `0, 65535` TCP forwarder window | [src/nat64/service.go](src/nat64/service.go) |
| `100` control-packet queue depth | [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go) |
| Magic offsets `40`/`48`, `pkt[6]`, `pkt[40]`, `pkt[24:40]` | throughout `src/nat64` |

**Recommendation:** promote to named constants in one place per package; make the user-visible ones (`Nat64TcpTimeout`, `Dns64UpstreamTimeout`, `Dns64TcpIdleTimeout`) configurable and reloadable. Replace raw byte offsets with named constants (`ipv6HeaderLen`, `nextHeaderOffset`, `udpHeaderLen`, ...) or with `gvisor.dev/gvisor/pkg/tcpip/header` accessors, which are already a dependency.

### 6.4 [P2] `context.Context` is not propagated into network operations

Neither `net.DialTimeout` (NAT64 TCP), `dns.Client.Exchange` (DNS64 upstream), nor the ICMP reply loop accepts the root context. On shutdown, in-flight dials and lookups run to their full timeout; there is also no per-query deadline, so a `handleAAAA` that performs two sequential 5s lookups can take 10s while the client gave up after 2s.

**Recommendation**
- `(&net.Dialer{Timeout: ...}).DialContext(ctx, "tcp4", dstAddr)` in `handleTCP`.
- `dns.Client.ExchangeContext(ctx, ...)` in `proxy.lookup`, with a single per-query deadline established in `proxy.handle` and threaded through.
- Give `icmpReplyLoop` the context and select on `ctx.Done()` rather than polling `icmpClosed` with a 1s read deadline.

### 6.5 [P3] Redundant string work in the DNS hot path

**Files:** [src/dns64/proxy.go](src/dns64/proxy.go), [src/dns64/zones.go](src/dns64/zones.go)

`handle` computes `strings.ToLower(q.Name)`; `matchZone` then calls `strings.ToLower(fqdn)` again and `strings.ToLower(d)` on domains that `buildZones` already lower-cased. Three redundant allocating lowercase operations per query.

**Recommendation:** lowercase once at the entry point, document the invariant, and drop the redundant calls. Consider `strings.EqualFold` where a comparison is all that's needed.

### 6.6 [P3] Consider migrating hot paths to `net/netip`

`net.IP`/`net.IPNet` are slice-based and allocation-prone. `netip.Addr` / `netip.Prefix` are value types with no allocation, and `Prefix.Contains` is significantly faster — relevant for `isAllowed`, called on **every** intercepted packet, and `pool6Net.Contains`.

**Recommendation:** migrate `nat64.Service.pool6Net`, `nat64Settings.allowedNets`, and `dns64.Service.allowedNets` to `[]netip.Prefix`. For large allowlists, `go4.org/netipx.IPSet` provides O(log n) lookups. Treat as an optimisation after correctness work lands.

---

## 7. Prioritised implementation plan

Suggested batching for independent agents; batches are ordered by risk and are largely independent of one another.

**Batch A — Correctness bugs (do first; small, self-contained, high value)**
- §2.1 `writeBuf` data race
- §2.2 `WritePackets` shadowing / return value
- §2.4 `lastSeenNs` atomic access
- §2.5 `icmpConn` publication order
- §5.1 UDP checksum `0x0000` → `0xFFFF`
- §3.2 `fmt.Sscan` port parsing

**Batch B — Security hardening**
- §1.1 NAT64 destination filtering (largest single item; consider its own task)
- §1.2 upstream DNS transaction ID randomisation + 0x20
- §1.3 ICMP identifier rewriting
- §1.7 config/key file permissions, `YDN64_PRIVATE_KEY_FILE`
- §1.8 non-root container
- §3.6 atomic config generation in the entrypoint

**Batch C — Resource bounds & DoS resistance**
- §1.4 rate limiting and concurrency caps
- §1.5 bounded DNS cache + qtype-aware key
- §4.3 bounded session tables
- §5.4 NAT64 TCP idle timeout + half-close

**Batch D — Test & CI foundation (can run in parallel with A–C)**
- §6.1 unit tests, fuzz targets, CI workflow with `-race` / `vet` / `govulncheck`
- §6.2 metrics and counters

**Batch E — Protocol completeness (largest scope, lowest urgency)**
- §5.2 extension headers, fragments, PMTUD
- §5.3 ICMP error translation
- §5.6 RFC 6052 prefix lengths
- §1.6 / §5.8 EDNS0 truncation and RFC 6147 TTL handling

**Batch F — Robustness & polish**
- §2.6 NIC read-loop recovery
- §2.7 control-packet drop visibility
- §2.9 atomic config reload
- §2.10 graceful shutdown
- §3.1 config validation gaps
- §3.3 / §3.4 error handling and `recover()`
- §6.3–§6.6 constants, context propagation, hot-path optimisation

---

## 8. What is already good (do not regress)

- `AGENTS.md` and the inline comments capture hard-won gVisor knowledge (`HandleLocal`, Promiscuous vs Spoofing, zero-payload TCP frames) with unusual precision. Any change under `src/netstack/` should re-read those notes first.
- The `atomic.Pointer` config-reload pattern (`nat64Settings`, `proxyConfig`, `allowedNets`) is the right design — lock-free on the query path, correct under concurrent reload.
- `dnsCache.Reload` flushing the whole cache on config change is a genuinely subtle correctness fix; keep it.
- `ydn64.service` is thoroughly hardened (`NoNewPrivileges`, `ProtectSystem=strict`, `SystemCallFilter`, minimal `CapabilityBoundingSet`) — the container image should be brought up to this standard, not the reverse.
- The Dockerfile's `$BUILDPLATFORM` cross-compilation avoids QEMU emulation of the Go toolchain — correct and fast.
- The black-box podman harness with per-case config snapshot/restore and SIGHUP-based reload testing is a strong foundation; unit tests should complement it, not replace it.
