# AGENTS.md — ydn64

Guidance for AI coding agents working in this repository.

## What this is

`ydn64` is a single Go binary that runs a **TUN-less, userspace Yggdrasil node**
(no root required) and exposes two services to the Yggdrasil network:

- **NAT64** (`src/nat64`) — stateful IPv6→IPv4 translation for allowed
  Yggdrasil peers, using a `Nat64Pool` prefix derived from the node's own
  `300::/64` subnet. Covers TCP (`tcp.go`), UDP (`udp.go`), and ICMP Echo
  (`icmp.go` — translates ICMPv6 Echo Request/Reply to/from real ICMPv4 via a
  raw socket, so `ping6` to a pool6 address works end-to-end against a real
  IPv4 host).
- **DNS64** (`src/dns64`) — a caching DNS64 resolver/proxy that synthesises
  AAAA records from A records (with per-zone forwarding/pass-through rules).

Both services run on top of a single **gVisor netstack** (`src/netstack`)
attached to the Yggdrasil core via `ipv6rwc.ReadWriteCloser` — there is no OS
TUN device anywhere in this stack.

Yggdrasil networking itself is provided by the vendored
`github.com/yggdrasil-network/yggdrasil-go` module (`core`, `admin`,
`multicast`, `config` packages) — do not reimplement peering/crypto/routing,
just wire into that library's public API.

## Build / run

```sh
./build                 # shell script: go build with -X main.buildVersion=<git describe>, outputs ./ydn64
go build ./...           # plain build without version stamping, still fine for iteration
go vet ./...
```

Unit tests live beside the code as `_test.go` files (`src/config`,
`src/dns64`, `src/nat64`, `src/netstack`) and run with:

```sh
go test -race -count=1 ./...
```

The race detector matters here: services spawn goroutines (relays, cleanup
tickers, stats loops) and past data races were caught only with `-race`.

`./build` is a **shell script**, not a directory — don't confuse it with a
`build/` output directory. The compiled binary is written to `./ydn64` in the
repo root (git-ignored).

Run the binary directly:

```sh
./ydn64 -genconf > ./tmp/ydn64.conf   # -genconf prints a new config to stdout (same as yggdrasil-go); redirect to save it
./ydn64 -useconffile ./tmp/ydn64.conf # run the node + services
```

Use the repo-local `tmp/` directory (git-ignored) for any generated configs,
scratch binaries, or logs produced while testing — **never write test
artifacts to the system temp dir or the repo root**.

## Configuration — single merged file

As of the current design, **`-genconf` prints a single merged HJSON config
to stdout** (see the inline comments in
[src/config/generate.go](src/config/generate.go), or the "Configuration"
section of [README.md](README.md)) — it does not write any file itself;
redirect stdout (e.g. `> ydn64.conf`) to save it, matching upstream
yggdrasil-go's own `-genconf` behavior. There is no separate `yggdrasil.conf`
/ `ydn64.toml` split — that was an earlier iteration and has been merged.

The single file is decoded **twice** from the same bytes in
[src/config/config.go](src/config/config.go):

1. Into `ygconfig.NodeConfig` (upstream Yggdrasil struct, via
   `ygCfg.ReadFrom(...)`) — covers `PrivateKey`, `Peers`, `Listen`,
   `MulticastInterfaces`, `AdminListen`, `IfName`, etc. Only fields understood
   by that struct are read; the ydn64-specific keys are simply ignored by it.
2. Into `config.AppConfig` (this repo, via `hjson.Unmarshal`) — covers
   `AllowedSources`, `Nat64*`, `Dns64*`. Yggdrasil keys are ignored here.

Both decodes are lenient/non-strict, so overlapping the two key sets in one
file is safe. `config.Load(path)` returns `(*ygconfig.NodeConfig,
*config.AppConfig, error)`.

`AppConfig.NAT64()` / `AppConfig.DNS64()` project the merged config down into
the narrower `NAT64Config` / `DNS64Config` views consumed by
`nat64.NewService` / `dns64.NewService`. `AllowedSources` is shared between
both services (not duplicated per-service).

`AdminListen` and `IfName` are always force-overridden to `"none"` in
`main.go` regardless of what's in the config file — this app never uses an
admin socket or a TUN interface by design. Because of that, both keys are
intentionally omitted from the generated template (`src/config/generate.go`)
and the checked-in sample [ydn64.conf](ydn64.conf) — they'd be dead/no-op if
present. `ygconfig.NodeConfig` still recognizes them if an old config sets
them explicitly (harmlessly overridden right after `Load`), but new configs
shouldn't include them.

**`IfMTU` is the one TUN-related key that IS read**: it is passed to
`netstack.CreateYdn64Netstack`, which applies it to the `ipv6rwc.ReadWriteCloser`
via `SetMTU`. This matters because ipv6rwc defaults its internal MTU to a
conservative **1280** and *enforces* it on the inbound path — frames larger
than that are silently dropped with an ICMPv6 Packet Too Big reply — until
someone calls `SetMTU`. A TUN-based node wires its TUN's MTU; ydn64 has no
TUN, so without this plumbing clients with larger interface MTUs hit spurious
PTB round-trips on their first big packet. The value also feeds gVisor's NIC
MTU (egress segmentation for oversized UDP datagrams) and the NAT64 raw-packet
buffer sizes. It's still omitted from generated configs (the upstream default
65535 is fine), but don't remove the `CreateYdn64Netstack` parameter.

When changing the config schema:
- Add the field to `AppConfig` in [src/config/config.go](src/config/config.go)
  with a `json:"..."` tag (hjson respects json tags).
- Add validation in `AppConfig.validate()`.
- Update the generated template in
  [src/config/generate.go](src/config/generate.go) so `-genconf` output stays
  in sync.
- Update the "Configuration" section of [README.md](README.md) if the change
  affects what users need to edit by hand.

## Repo layout

```
cmd/ydn64/main.go       CLI entry point, wiring: core → admin → multicast → netstack → nat64/dns64
src/config/             config.go (load/validate), generate.go (-genconf template)
src/netstack/           gVisor stack wrapper bound to Yggdrasil's ipv6rwc; tap.go+pcap.go (debug packet tap)
src/nat64/              NAT64 service: packet.go, service.go, tcp.go, udp.go, icmp.go, stats.go
src/dns64/              DNS64 service: server.go, proxy.go, cache.go, zones.go
test/                   podman black-box harness (see below); test/gen (config generator), test/tools/udpecho
tools/                  dev utilities: licenses (third-party licence notice generator used by release.yml/Dockerfile)
context/                design notes — see caveat below
tmp/                    git-ignored scratch space for local test runs
Dockerfile              production multi-arch image (not test/Containerfile.ydn64, which is test-harness-only)
docker-entrypoint.sh    generates ydn64.conf on first run if $YDN64_CONFIG is missing
.github/workflows/      release.yml: on vX.Y.Z tags, builds + pushes multi-arch ghcr.io
                        images AND builds Linux/Windows/macOS binaries (amd64/arm64,
                        plus linux/arm and linux/386) published to a GitHub Release
```

### Container env var overrides

`cmd/ydn64/main.go` applies `YDN64_PRIVATE_KEY` / `YDN64_PEERS` /
`YDN64_ALLOWED_SOURCES` as overrides on top of the loaded config file,
immediately after `config.Load(...)` and before the Yggdrasil core is
constructed; `-genconf` reads the same three via `config.GenerateOverrides`.
User-facing behavior is documented in README's "Running with Docker" — here
only the mechanics that matter when changing code:

- `YDN64_PRIVATE_KEY` (hex ed25519) replaces `ygCfg.PrivateKey`, then MUST be
  followed by `GenerateSelfSignedCertificate()` — the `tls.Certificate`
  passed to `core.New` determines node identity, not `PrivateKey` alone — and
  `AppConfig.ApplyPrivateKeyOverride(...)` to recompute `Nat64Pool`,
  `Dns64Listen`, and reset `Dns64Zones` (addresses derive via
  `config.DeriveFromPrivateKey`, shared with `-genconf`).
- `YDN64_PEERS` must be set before `core.New`; `YDN64_ALLOWED_SOURCES` is
  re-validated via `AppConfig.Validate()`. List values are comma/whitespace
  separated (`splitEnvList` in main.go).
- If you add more overridable fields, follow this pattern rather than shelling
  out to sed against the mounted HJSON file.

### `context/` contents

- [RFCs.txt](context/RFCs.txt) — authoritative per-requirement RFC conformance
  status (referenced by README's "Standards conformance" section).
- [gvisor-notes.md](context/gvisor-notes.md) — condensed outcomes of the 2026-08
  gVisor migration: CUBIC decision + benchmarks, T7 firewall rejection
  rationale, and why gVisor upgrades are blocked upstream.
- [sighup-reload.md](context/sighup-reload.md) — design note for the SIGHUP
  live config reload path.
- The consolidated code review of 2026-08-23 (formerly
  `context/code-review-2026-08-23.md`) is CLOSED and the file removed: every
  finding is fixed (git history documents each fix) except these deliberate
  deferrals — per-source token-bucket rate limiting via `golang.org/x/time/rate`
  (fairness only; all structures are already bounded by the `Dns64/Nat64Max*`
  caps), full Attach/Close synchronisation of `YggdrasilNIC.dispatcher`,
  plumbing `context.Context` into upstream dials (mitigated by the 5 s
  service `Drain`), a configurable TCP keepalive window, and hot-path
  optimisations gated on profiling. Revisit on demand. Protocol-conformance
  status lives ONLY in RFCs.txt above.
- The code review of 2026-08-24 (formerly `context/code-review-2026-08-24.md`)
  is CLOSED and the file removed: all 17 findings fixed on 2026-08-25 (git
  history documents each fix; commits `0ace043`…`4365ca9`). Remaining
  deliberate deferrals / follow-up ideas:
  - TCP_USER_TIMEOUT on NAT64's OS-dialled IPv4 leg: `net.KeepAliveConfig`
    has no such field (Go 1.25); would need build-tagged raw setsockopt.
    Count-based keepalive detection (~165 s) covers idle-dead peers; only
    stalled-transfer aborts still rely on OS retransmission defaults.
  - Fuzz targets for the untrusted-input parsers (`parseIPv6HeaderChain`,
    `interceptPacket`, `parseICMPv4InnerPacket`, `ptrToIPv6`,
    `ParsePref64`/Extract) — pure functions over bytes, ~30 lines each;
    run on demand, not in CI.
  - Black-box case for half-idle TCP teardown (dead v4 peer frees slots in
    minutes) needs a controllable IPv4 sink container; the harness topology
    deliberately has none. Revisit with any topology extension.
  - Optional observability ideas (never findings): surface `nicCtrlDrops`
    in the periodic stats line; a tiny opt-in Prometheus exporter.

  Library gotchas learned while fixing #1–#3 that aren't obvious from the
  diffs: miekg/dns's `Server.ActivateAndServe` serves PacketConn XOR
  Listener — dual-transport test mocks need two `dns.Server` instances
  sharing one handler; gologme disables warn/error/etc. by default, so
  tests capturing warnings must call `EnableLevel("warn")`; and don't pin
  short artificial time windows in tests asserted against wall-clock
  behaviour — under `-race` with the full suite running they get outlived
  legitimately (pin state directly instead).


## Changelog

[CHANGELOG.md](CHANGELOG.md) is a **manually maintained** file of
user/contributor-facing highlights — it is not auto-generated from commits.
Do not update it automatically as part of unrelated tasks. Only add an entry
when the user explicitly asks to log/record a change (or clearly confirms
one should be added), and add it under the `## [Unreleased]` heading.

## Conventions

- Go module: `github.com/DrewCyber/ydn64`, Go 1.25.5.
- **Licence policy — keep it as open as possible, but ask before changing**:
  ydn64's own code is 0BSD and should stay that way; prefer permissive
  dependencies so no relicensing is ever forced. GPL-3.0 code must never be
  copied, even in fragments; weak-copyleft modules (yggdrasil-go is
  LGPL-3.0) may be linked via their public API but their source must never be
  copied into this tree; for Apache-2.0/MIT/BSD references (e.g. CoreDNS),
  read the algorithm and reimplement rather than vendor, so the tree stays
  uniformly 0BSD. If a module with stricter terms would **drastically improve
  the code**, adopting it (and changing ydn64's own licence accordingly) is
  acceptable — but that decision belongs to the maintainer: **propose it and
  get explicit approval BEFORE adding the dependency or touching LICENSE**;
  never relicense unilaterally.
- **Distributed artefacts carry third-party licence obligations**: release
  binaries and the production image embed dependency code (notably
  `gvisor.dev/gvisor` under Apache-2.0 and `yggdrasil-go` under LGPL-3.0).
  Every GitHub Release archive therefore ships `LICENSE` +
  `THIRD-PARTY-NOTICES.txt`, generated by
  `go run ./tools/licenses -o <file>` (scans everything linked into
  `./cmd/ydn64` across linux/darwin/windows and fails on missing licence
  files); regenerate after any `go.mod` change. The Dockerfile copies both
  into `/usr/local/share/doc/ydn64/`. Do not drop these files or the workflow
  steps that produce them.
- Config format is **HJSON** (`github.com/hjson/hjson-go/v4`), not JSON/TOML/YAML — comments in config files are load-bearing documentation, preserve them when regenerating templates.
- Config keys use `PascalCase` (matching upstream Yggdrasil's own config style), not `snake_case` or `camelCase`.
- Logging via `github.com/gologme/log`, levels: error/warn/info/debug/trace, set with `-loglevel`.
- Services (`nat64.Service`, `dns64.Service`) take a `context.Context` for cancellation and are started after the netstack and Yggdrasil core are up.
- **Two independent logging destinations, easy to mix up when debugging**: the
  stdlib `log` package (plain `import "log"`, used e.g. in
  [src/netstack/yggdrasil.go](src/netstack/yggdrasil.go)) writes to stderr —
  visible via `podman logs <container>`. The `*log.Logger` passed as a
  `logger` parameter into service code (`gologme`-based) writes *only* to the
  file given via `-logto` (e.g. `.run/ydn64.log` in the test harness) — it is
  **never** captured by `podman logs`. Always check the matching destination
  before concluding a code path "never ran" from missing log output.

## Black-box test harness (`test/`)

A podman-based black-box integration test harness lives in `test/` (not
covered by `go test`). Topology: an `A` container running this repo's
`ydn64` binary on two networks — an `--internal` Yggdrasil-only `yggnet`
where a `B` container runs upstream `yggdrasil-go` with a real TUN device
(simulating a real client with only Yggdrasil connectivity), plus an
egressnet NAT'd bridge giving only A real internet reachability (real DNS
forwarders, real Yggdrasil peers, real-world targets like dns.google). There
is no local fake IPv4 target container.

```sh
cd test
./run.sh all      # build images, start containers, wait for peering, run every script in cases/
./run.sh test      # same, skipping an explicit rebuild if images already exist
./run.sh down      # stop + remove containers (run before re-testing after code changes)
./run.sh logs a    # tail podman logs (stderr) for container a or b
```

- Generated configs/logs live in `test/.run/` (git-ignored) — e.g.
  `.run/ydn64.log` (A's file-based service log), `.run/yggclient.log` (B's
  stdlib log, also in `podman logs`), `.run/ydn64.env` (shell-sourceable
  vars: `NODE_ADDR`, `DNS64_LISTEN_ADDR`, `NAT64_POOL_PREFIX`, ...).
- The harness runs with a realistic **1500-byte IfMTU** on both nodes
  (`test/gen -ifmtu`, default 1500) instead of yggdrasil's 65535 default, so
  oversized-datagram paths (IPv6 fragmentation/reassembly through gVisor,
  PMTUD interactions) are actually exercised — see
  `test/cases/08_udp_fragmented_datagrams.sh`.
- `test/tools/udpecho` is a test-only Go helper baked into BOTH container
  images: a UDP echo server plus a one-shot client (`udpecho -once`). It
  exists because busybox `nc` truncates UDP datagrams to a small fixed
  receive buffer in both directions, far below the 1472-byte fragmentation
  threshold. The harness config also empties `IgnoredDstSubnets` so cases can
  target loopback-embedded IPv4 addresses inside A deterministically.
- After any change to `src/`, rebuild the binary/image before retesting: the
  test images bake in the compiled binary, they don't mount source live.
- Config-change cases (e.g. `test/cases/05_allowed_sources_config_change.sh`)
  use the live SIGHUP reload path (`reload_a` in `test/lib.sh`), NOT container
  restarts — earlier harness generations restarted `A` for config changes,
  which added re-peering waits and podman-restart flakiness; keep using
  `reload_a`. B's peer URI in `test/run.sh` still
  sets `?maxbackoff=5s` (yggdrasil-go's hard minimum — bare `maxbackoff=5` is
  invalid, it's parsed with `time.ParseDuration` and needs a unit) so any
  re-peer stays fast if a restart is ever reintroduced.
- **Transient podman-VM hiccups can still hit any case**, even without
  restarts: occasionally a `podman exec` produces literally zero output (not
  even from a plain `date`) for far longer than expected, or a B→A TCP dial
  times out for 30+ seconds while A is confirmed up and listening — then the
  exact same command succeeds sub-200ms moments later. This is a macOS
  podman-machine (gvproxy/vfkit) networking convergence hiccup, not ydn64.
  Re-run before diagnosing as a code failure, and prefer retry loops in cases
  over single-shot assertions on freshly booted environments (the first
  datagram across a new Yggdrasil link can also race key/session setup).
- **`test/cases/02_dns_google_icmp.sh`** (real-world DNS64+NAT64-ICMP check
  against `dns.google`/8.8.8.8) requires real internet DNS/ICMP egress from
  A's egressnet interface and retries its initial `dig` a few times (~10s)
  rather than asserting on the first attempt, because B's peering being up
  doesn't guarantee A's UDP forwarder path is fully settled yet.

## gVisor netstack gotchas (`src/netstack/`)

This app drives a raw gVisor userspace `stack.Stack` directly (no TUN), so it
hits several non-obvious gVisor API footguns that are easy to reintroduce.
Read this before touching `src/netstack/netstack.go` or
`src/netstack/yggdrasil.go`.

- **`HandleLocal` must stay disabled.** `HandleLocal: true` combined with
  Promiscuous mode caused gVisor to treat/drop inbound traffic as
  martian-sourced, silently breaking ICMP and DNS64 UDP. The custom
  `YggdrasilNIC` isn't a real L2/ARP NIC, so `HandleLocal`'s assumptions don't
  apply here.
- **`Promiscuous` and `Spoofing` are separate, independently-gated NIC
  flags** — NAT64 needs *both*:
  - `stack.SetPromiscuousMode(nicID, true)` — required to *receive* packets
    addressed to the pool6::IPv4 destination range, which is never a real
    registered NIC address.
  - `stack.SetSpoofing(nicID, true)` — required to *send* replies (e.g. TCP
    SYN-ACKs) *from* a pool6 source address, since that's also never a real
    registered NIC address. Checked via `Stack.FindRoute()` →
    `nic.findEndpoint(..., spoofing)`. Missing this causes NAT64 TCP SYN-ACKs
    to silently fail to route, with no error until the forwarder's
    `CreateEndpoint`/`performHandshake` eventually times out (~2 minutes —
    gVisor's internal SYN-ACK retransmit backoff), long after any client has
    given up.
- **Zero-payload TCP packets are not just RSTs.** In the custom
  `YggdrasilNIC.WritePackets`, a check like `if pkt.Data().Size() == 0 { ...
  }` catches SYN, SYN-ACK, pure ACK, and FIN as well as RST — all of these
  carry no payload. A prior fix that special-cased *only* RST packets for
  writing (routing them through the async `ctrlPackets` channel) and silently
  `continue`d past everything else caused NAT64 TCP SYN-ACKs to vanish with
  zero errors anywhere. Any future change to this zero-payload branch must
  keep handling *all* TCP control packets, not just RST.
- When a NAT64/DNS64 forwarder callback (`handleTCP`, `handleUDP`, etc.)
  appears to silently not run or not produce expected output, prefer reading
  gVisor's actual vendored source
  (`$(go env GOPATH)/pkg/mod/gvisor.dev/gvisor@<version>/pkg/tcpip/...`) over
  guessing from symptoms — e.g. `transport/tcp/forwarder.go` and
  `transport/tcp/accept.go` (`performHandshake`) make the blocking/timeout
  behavior explicit.
- **The gVisor pin is deliberate.** The TCP transport factory is
  `NewProtocolCUBIC` (not the gVisor Reno default). Do not bump
  `gvisor.dev/gvisor` casually: releases after 2025-08-20 don't compile via
  plain Go modules (missing Bazel-generated files + a bad test-package name
  in `pkg/tcpip/stack`) — see [context/gvisor-notes.md](context/gvisor-notes.md)
  for the assessment and options.
- `SetPacketInterceptor` on the netstack only supports **one** registered
  callback. NAT64's interceptor (`Service.interceptPacket` in
  `src/nat64/service.go`) handles **ICMPv6 only** (next-header byte
  `pkt[6] == 58` → `interceptICMPPacket`). UDP is *not* intercepted anymore:
  it goes through gVisor's `udp.NewForwarder` registered on the transport
  handler in `Service.Start`, which gives gVisor ownership of checksums,
  demuxing, reassembly and outbound fragmentation for that protocol. Don't
  try to register a second interceptor — for observation use the packet-tap
  pattern instead (`src/netstack/tap.go`, the reference implementation behind
  `YDN64_DEBUG_PCAP`), which registers a `stack.PacketEndpoint` as an
  ETH_P_ALL-style listener; arbitrarily many of those can coexist with the
  interceptor.
- **UDP forwarder demux order matters**: gVisor's transport demuxer checks
  registered endpoints BEFORE calling the transport-protocol handler
  (`transport_demuxer.go: deliverPacket`). So only the *first* datagram of a
  flow reaches `handleUDPForward`; once `ForwarderRequest.CreateEndpoint`
  registers the connected endpoint, later datagrams of the tuple are delivered
  straight into it and are read off the `gonet.UDPConn`. The `sessions`
  sync.Map is bookkeeping only (idle expiry + reply-loop wiring), never a demux
  table. Also note `udp.ForwarderRequest` has **no payload accessor and no
  Complete()**: dropping a request without CreateEndpoint just abandons its
  cloned PacketBuffer to the GC (safe — chunks are pooled Go objects), which is
  why policy-filtered flows must be dropped before endpoint creation, not after.
- **Raw ICMPv4 sockets need `CAP_NET_RAW`**, and it is **not** granted by
  podman's default capability set — `icmp.ListenPacket("ip4:icmp", "0.0.0.0")`
  fails with `operation not permitted` unless the container is started with
  `--cap-add=NET_RAW` (see `test/run.sh`, container A). ICMP NAT64 opening
  the raw socket is best-effort/non-fatal: if it fails, NAT64 logs a warning
  (`NAT64 ICMP disabled ...`) and TCP/UDP continue working normally; check
  for `icmp=true` vs `icmp=false` in the startup log line to confirm whether
  ICMP translation is actually active.
