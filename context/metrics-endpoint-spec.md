# Spec: Metrics endpoint (`MetricsListen`)

**Status:** Design — implement as described.
**Scope:** new package `src/metrics`, wiring in `cmd/ydn64/main.go`, small
instrumentation additions in `src/nat64` and `src/dns64`, config plumbing,
docs. No protocol-behaviour changes anywhere.

---

## 1. Goals

1. Expose runtime/service metrics over HTTP in **Prometheus text exposition
   format v0.0.4** for scraping by an external monitoring system.
2. Zero new third-party dependencies: stdlib `net/http`, `sync/atomic`,
   `strings`/`fmt` only. The text format is rendered by hand (~100 lines);
   do **not** import any Prometheus client library.
3. Disabled by default; opt-in via one new config key, `MetricsListen`.
4. Lock-free hot paths: increments are `atomic.AddInt64`; gauge values are
   computed at scrape time from already-available state (gVisor
   `stack.Stats()`, session maps, cache internals).

## 2. Non-goals

- Authentication/TLS on the endpoint (operator binds loopback or uses a sidecar).
- OpenMetrics format, histograms, pushgateways.
- Serving metrics over the **gVisor/Yggdrasil-facing** stack (only the host
  OS network stack is used — this keeps the node's Yggdrasil attack surface
  unchanged).
- Changing the existing log-based debug stats path (`nat64.statsLoop`,
  `DumpStats`) — it stays as-is.
- Dockerfile changes (operators publish the port explicitly if they want it;
  you may *mention* this in README, nothing more).
- CHANGELOG entry (repo rule: only on explicit request).

## 3. Repo constraints (binding)

- Licence is **0BSD**: no GPL code, no vendoring Apache-2.0 source. Stdlib only.
- Config keys are **PascalCase** HJSON with `json:"..."` tags; comments in
  generated configs are load-bearing documentation — preserve style/tone.
- Services take a `context.Context` for cancellation; startup errors are
  returned (or `logger.Fatalf` in main), not silently swallowed.
- Logging goes through the `*log.Logger` (gologme) passed into components;
  never use stdlib `log` in new code under `src/metrics`.
- Tests live beside the code as `_test.go`; the suite must pass with
  `go vet ./... && go test -race -count=1 ./...`.

---

## 4. Configuration

### 4.1 New key: `MetricsListen`

Add to `AppConfig` in `src/config/config.go` (after `Dns64Zones`):

```go
MetricsListen string `json:"MetricsListen"`
```

Semantics (mirrors upstream Yggdrasil's `AdminListen` convention):

| Value | Meaning |
|---|---|
| absent / `""` | **disabled** (default) |
| `"none"` | explicitly disabled |
| `"host:port"` | serve on the **host OS** network stack at that address |

Validation in `AppConfig.validate()`:

- `""` and `"none"` pass through.
- Anything else MUST parse via `net.SplitHostPort` and have a numeric port
  in 1–65535. Reject otherwise with an error naming the key
  (`MetricsListen: ...`), matching the existing error style.

**Not SIGHUP-reloadable.** In `reloadConfig` (`cmd/ydn64/main.go`), follow
the exact pattern of the `Dns64Listen` check: if the new value differs from
the running one, `logger.Warnf("config reload: MetricsListen change (%q → %q)
requires a restart, ignoring", old, new)` and continue.

### 4.2 Generated-config template (`src/config/generate.go`)

In `buildConf`, after the DNS64 section, emit:

```hjson
  # Optional Prometheus metrics endpoint on the HOST network stack
  # (not reachable from Yggdrasil peers). Disabled unless set.
  # Recommended: loopback only — the endpoint is unauthenticated.
  # MetricsListen: "127.0.0.1:9107"
```

Commented-out = absent = disabled. Do not emit the key itself.

### 4.3 Sample config + README

- Add the same commented block to the checked-in `ydn64.conf` sample.
- Add a short subsection to README's "Configuration" section: what it is,
  default-off, loopback recommendation, scrape target
  `<MetricsListen>/metrics`, and that it binds the host OS stack (so inside
  containers the port must be published deliberately).

---

## 5. Package design: `src/metrics`

Two files plus tests. No globals shared across registries.

### 5.1 `src/metrics/metrics.go` — registry

```go
type GaugeFunc func() float64

type Registry struct {
    mu     sync.Mutex
    order  []string          // registration order; render sorted by name regardless
    named  map[string]metric // name → counter/counterVec/gaugeFunc (first registration wins)
}

func NewRegistry() *Registry
func (r *Registry) NewCounter(name, help string) *Counter        // idempotent by name
func (r *Registry) NewCounterVec(name, help string, labelNames ...string) *CounterVec
func (r *Registry) AddGaugeFunc(name, help string, fn GaugeFunc)
func (r *Registry) RenderPrometheus(w io.Writer) error
```

- `Counter`: `func (c *Counter) Add(delta float64)` implemented as
  `atomic.AddUint64` on an internal uint64 counting whole units (all ydn64
  counters are integral; document that fractional deltas truncate).
- `CounterVec`: `func (v *CounterVec) WithLabelValues(vals ...string) *Counter`
  — lazily creates series under an internal mutex keyed on the joined label
  values. **Cardinality cap:** refuse (return nil and log-free no-op increment;
  increment a built-in `ydn64_metrics_series_overflow_total`) beyond 64 series
  per vec. All current label dimensions are bounded well below this; the cap is
  defence against future misuse.
- Validate metric names at registration: `^[a-zA-Z_:][a-zA-Z0-9_:]*$`;
  panic (programmer error) on violation — registration happens at startup only.
- `RenderPrometheus`: deterministic output — sort by metric name, then label
  values; emit `# HELP`/`# TYPE` once per name; escape `\`, `"` and newline in
  help strings and label values. Counters render as `type: counter` with the
  conventional `_total` suffix **included in the registered name** (callers
  pass full names); gauges as `type: gauge`.

### 5.2 `src/metrics/server.go` — HTTP server

```go
func Serve(ctx context.Context, reg *Registry, listenAddr string, logger *log.Logger) error
```

- `net.Listen("tcp", listenAddr)`; on error return a wrapped error
  (`fmt.Errorf("metrics: listen %s: %w", ...)`) — main will `Fatalf`.
- Handler: only `/metrics` (exact match). GET/HEAD → 200 with body /
  empty body; anything else → `405 Method Not Allowed` or `404`.
- Response header: `Content-Type: text/plain; version=0.0.4; charset=utf-8`.
- Render errors → 500 with plain-text message.
- On `ctx.Done()`: graceful `http.Server.Shutdown` with a 5 s timeout, then
  return. Log one line each way, matching repo tone:
  `logger.Printf("Metrics endpoint listening on %s", addr)` and
  `logger.Println("metrics endpoint stopped")`.
- Never register on the gVisor stack; this is purely a host-OS listener.

---

## 6. Metric inventory (authoritative names)

Prefix everything with `ydn64_`. Register full names including `_total` for
counters. Help strings: one sentence, sentence case.

### 6.1 Build info (register in main)

| Name | Type | Labels | Source |
|---|---|---|---|
| `ydn64_build_info` | gauge | `version` | `buildVersion` var; value `1` |

### 6.2 gVisor netstack (`ydn64_netstack_*`)

All computed **at scrape time** via `Registry.AddGaugeFunc` reading
`s.ns.Stack().Stats()` (same `.Value()` calls as `takeStatSnapshot` in
`src/nat64/stats.go` — reuse those field selections, but expose cumulative
values, not deltas):

| Name | Type | Source field |
|---|---|---|
| `ydn64_netstack_ip_packets_received_total` | counter | `IP.PacketsReceived` |
| `ydn64_netstack_ip_packets_sent_total` | counter | `IP.PacketsSent` |
| `ydn64_netstack_tcp_active_openings_total` | counter | `TCP.ActiveConnectionOpenings` |
| `ydn64_netstack_tcp_passive_openings_total` | counter | `TCP.PassiveConnectionOpenings` |
| `ydn64_netstack_tcp_current_established` | gauge | `TCP.CurrentEstablished` |
| `ydn64_netstack_tcp_valid_segments_received_total` | counter | `TCP.ValidSegmentsReceived` |
| `ydn64_netstack_tcp_segments_sent_total` | counter | `TCP.SegmentsSent` |
| `ydn64_netstack_tcp_resets_sent_total` | counter | `TCP.ResetsSent` |
| `ydn64_netstack_tcp_retransmits_total` | counter | `TCP.Retransmits` |
| `ydn64_netstack_tcp_established_timedout_total` | counter | `TCP.EstablishedTimedout` |
| `ydn64_netstack_udp_packets_received_total` | counter | `UDP.PacketsReceived` |
| `ydn64_netstack_udp_packets_sent_total` | counter | `UDP.PacketsSent` |
| `ydn64_netstack_udp_unknown_port_errors_total` | counter | `UDP.UnknownPortErrors` |
| `ydn64_netstack_udp_receive_buffer_errors_total` | counter | `UDP.ReceiveBufferErrors` |
| `ydn64_netstack_icmpv6_echo_requests_received_total` | counter | `ICMP.V6.PacketsReceived.EchoRequest` |
| `ydn64_netstack_icmpv6_echo_replies_sent_total` | counter | `ICMP.V6.PacketsSent.EchoReply` |

Registered from wherever the stack handle lives at wiring time (main passes
`ns.Stack()`-backed funcs; see §7 wiring).

### 6.3 NAT64 (`ydn64_nat64_*`) — via new method `(*Service).RegisterMetrics(r)`

| Name | Type | Labels | Instrumentation point |
|---|---|---|---|
| `ydn64_nat64_enabled` | gauge | – | 1 always when service started (registration implies enabled) |
| `ydn64_nat64_udp_sessions` | gauge | – | `countSyncMap(&s.sessions)` at scrape |
| `ydn64_nat64_icmp_sessions` | gauge | – | `countSyncMap(&s.icmpSessions)` at scrape |
| `ydn64_nat64_icmp_translation_active` | gauge | – | 1 if `s.icmpConn != nil`, else 0 (CAP_NET_RAW caveat visibility) |
| `ydn64_nat64_dial_errors_total` | counter | `proto` ∈ {tcp, udp} | error branches of `net.DialTimeout` in `tcp.go:handleTCP` and `net.DialUDP` in `udp.go:handleUDPForward`'s goroutine |
| `ydn64_nat64_policy_drops_total` | counter | `reason` ∈ {pool_dst, pool_src, not_allowed, ignored_dst} | the four early-return sites in `parseUDPFlow` and their counterparts in `handleTCP` |

Notes:
- Drop-reason labels map to existing checks: `pool_dst` = destination outside
  `pool6Net`; `pool_src` = RFC 6146 §5.4 source check; `not_allowed` =
  `isAllowed` false; `ignored_dst` = `isIgnoredDst` true. TCP and UDP share
  the same counters (no transport label needed; keep cardinality minimal).
- Do **not** add per-peer/per-destination labels anywhere.

### 6.4 DNS64 (`ydn64_dns64_*`) — via new method `(*Service).RegisterMetrics(r)`

Instrument `src/dns64/server.go` wrappers (around the `proxy.handle` call in
`serveUDP` and `serveTCPConn`), plus `proxy.go` internals. Counters live on
the `Service`/`proxy` struct as `*metrics.Counter` fields set during
`RegisterMetrics`; when metrics are disabled they are nil and call sites skip
via a tiny helper (`if c != nil { c.Add(1) }` — wrap in one-line methods on
proxy to avoid scattering nil checks).

| Name | Type | Labels | Point |
|---|---|---|---|
| `ydn64_dns64_queries_total` | counter | `transport` ∈ {udp, tcp} | dispatch wrapper in `serveUDP` / `serveTCPConn` |
| `ydn64_dns64_responses_total` | counter | `rcode` ∈ {NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, OTHER} | same wrapper, classify `resp.Rcode` (map numerically; unknown → OTHER) |
| `ydn64_dns64_synthesised_records_total` | counter | – | per AAAA appended inside `synthesiseFromA` |
| `ydn64_dns64_ipv4only_local_answers_total` | counter | – | both local-answer branches (`handleAAAA`, `handlePTR`… specifically the `ipv4only.arpa.` intercepts in `proxy.go` `handleAAAA`/`handleA`) |
| `ydn64_dns64_cache_hits_total` | counter | – | hit path of `dnsCache.get` (`cache.go:69`) |
| `ydn64_dns64_cache_misses_total` | counter | – | miss path of `dnsCache.get` |
| `ydn64_dns64_cache_entries` | gauge | – | len of cache map at scrape (add a size accessor to `dnsCache`) |
| `ydn64_dns64_upstream_queries_total` | counter | – | top of `proxy.lookup` |

The rcode label set is fixed and bounded — never emit the raw numeric rcode
as a label value outside the listed set.

---

## 7. Wiring in `cmd/ydn64/main.go`

Order (after NAT64/DNS64 services are constructed and started):

1. `reg := metrics.NewRegistry()`; register `ydn64_build_info{version}`.
2. Register netstack gauge funcs (§6.2).
3. If NAT64 enabled: `nat64Svc.RegisterMetrics(reg)`.
4. If DNS64 enabled: `dns64Svc.RegisterMetrics(reg)`.
5. If `appCfg.MetricsListen` is set and != "none":
   `go`-free — call `err := metrics.Serve(ctx, reg, appCfg.MetricsListen, logger)`
   in a goroutine; `logger.Fatalf` on immediate bind error (surface it via a
   one-shot error channel so startup fails fast like the other listeners).

Teardown: nothing extra required — `Serve` returns on ctx cancellation; the
existing ordered shutdown (services → multicast → admin → core) is
unaffected. Do not gate core shutdown on the metrics server.

Keep `DumpStats`/SIGHUP behaviour untouched.

---

## 8. Testing requirements (`go test -race -count=1 ./...`)

1. `src/metrics/metrics_test.go`
   - Concurrent `Counter.Add` from many goroutines equals expected total.
   - `RenderPrometheus`: exact-string test covering sorting, HELP/TYPE
     emission, label escaping (`\`, `"`, `\n`), gauge vs counter types.
   - `NewCounter` idempotence (second call returns the same instance).
   - `CounterVec` cardinality cap produces overflow counter, no panic, no leak.
2. `src/metrics/server_test.go` — drive the handler via `httptest` (no real
   bind): GET `/metrics` → 200 + correct Content-Type; POST → 405;
   unknown path → 404.
3. `src/nat64/service_test.go` (extend) — `RegisterMetrics` on a synthetic
   `NetStack` registers without panic; seeded `sessions`/`icmpSessions` maps
   show up in gauges after a render.
4. `src/dns64` — extend existing tests minimally: counters stay nil-safe when
   `RegisterMetrics` was never called; one test asserting query/response
   counters increment through `proxy.handle`.
5. Full suite green under `-race`; `go vet ./...` clean.

## 9. Acceptance checklist

- [ ] `MetricsListen` absent ⇒ zero new listeners, zero behavioural change.
- [ ] `./build && ./ydn64 -useconffile <conf with MetricsListen>` serves
      valid v0.0.4 text at `/metrics` (validate with `promtool check metrics`
      if available; otherwise eyeball against the format doc).
- [ ] Scraping repeatedly shows monotonic counters and correct gauges while
      harness traffic runs (`cd test && ./run.sh test` cases still pass).
- [ ] SIGHUP changing `MetricsListen` logs the warn-and-ignore line.
- [ ] `-genconf` output contains only the commented example.
- [ ] README + `ydn64.conf` sample updated; one line added to AGENTS.md's
      repo-layout listing for `src/metrics/`.
- [ ] `go vet ./...` clean; `go test -race -count=1 ./...` green.
