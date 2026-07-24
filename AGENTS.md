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

There are currently **no `_test.go` files** in this repo. If you add tests,
run them with `go test ./...`.

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
admin socket or a TUN interface by design. Because of that, both keys (plus
`IfMTU`, which only affects a real TUN interface's MTU and is never read
anywhere in this codebase) are intentionally omitted from the generated
template (`src/config/generate.go`) and the checked-in sample
[ydn64.conf](ydn64.conf) — they'd be dead/no-op if present. `ygconfig.NodeConfig`
still recognizes them if an old config sets them explicitly (harmlessly
overridden right after `Load`), but new configs shouldn't include them.

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
src/netstack/           gVisor stack wrapper bound to Yggdrasil's ipv6rwc
src/nat64/              NAT64 service: packet.go, service.go, tcp.go, udp.go, icmp.go
src/dns64/              DNS64 service: server.go, proxy.go, cache.go, zones.go
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
`YDN64_ALLOWED_SOURCES` environment variables as overrides on top of the
loaded config file, immediately after `config.Load(...)` and before the
Yggdrasil core is constructed. `YDN64_PRIVATE_KEY` (hex-encoded ed25519
private key) is applied first: it replaces `ygCfg.PrivateKey`, regenerates
`ygCfg.Certificate` via `GenerateSelfSignedCertificate()` (required — the
`tls.Certificate` passed to `core.New` is what actually determines node
identity, not `PrivateKey` alone), and calls
`AppConfig.ApplyPrivateKeyOverride(...)` (in
[src/config/config.go](src/config/config.go)) to recompute `Nat64Pool` and
`Dns64Listen` and reset `Dns64Zones` to the single default synthesis zone —
addresses are derived via `config.DeriveFromPrivateKey` (in
[src/config/generate.go](src/config/generate.go), shared with `-genconf`).
`YDN64_PEERS` must be set before `core.New`; `YDN64_ALLOWED_SOURCES` is
re-validated via `AppConfig.Validate()`. This exists specifically for the
Docker image (see [docker-entrypoint.sh](docker-entrypoint.sh) and README's
"Running with Docker" section) so a container can boot from a freshly
`-genconf`'d file — or with no config file/volume at all when all three vars
are set — without hand-editing a mounted config. Values are comma/whitespace
separated for the list-valued vars (`splitEnvList` in main.go). `-genconf`
itself also reads these same three env vars (via
`config.GenerateOverrides`) to bake them directly into the generated file.
If you add more overridable fields, follow the same pattern rather than
shelling out to sed against the mounted HJSON file.

### `context/` caveat

- [context/improvement.txt](context/improvement.txt) — **stale**: an early DNS64/NAT64 design note using a sectioned TOML (`[nat64]`/`[dns64]`/`[dns64.<zone>]`) layout with `snake_case` keys. The actual config is a single flat HJSON file with `PascalCase` keys and a `Dns64Zones` array (see [src/config/generate.go](src/config/generate.go) or [README.md](README.md)). Useful for the *behavioral* intent (NXDOMAIN fallback, zone matching rules) but don't follow its config syntax.
- This is currently the only file under `context/` — earlier drafts of this
  doc referenced `context/general-idea.txt` and `context/ydn64.conf.example`,
  but those have since been removed from the repo; the authoritative config
  reference now lives in `src/config/generate.go`'s inline comments and
  README.md's "Configuration" section.


## Changelog

[CHANGELOG.md](CHANGELOG.md) is a **manually maintained** file of
user/contributor-facing highlights — it is not auto-generated from commits.
Do not update it automatically as part of unrelated tasks. Only add an entry
when the user explicitly asks to log/record a change (or clearly confirms
one should be added), and add it under the `## [Unreleased]` heading.

## Conventions

- Go module: `github.com/DrewCyber/ydn64`, Go 1.25.5.
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
covered by `go test`). Topology: an IPv4-only `target` container, an `A`
container running this repo's `ydn64` binary (bridged to both networks), and
a `B` container running upstream `yggdrasil-go` with a real TUN device on an
`--internal` (no-egress) Yggdrasil-only network — simulating a real client
that only has Yggdrasil connectivity and must reach the IPv4 target through
A's NAT64/DNS64.

```sh
cd test
./run.sh all      # build images, start containers, wait for peering, run every script in cases/
./run.sh test      # same, skipping an explicit rebuild if images already exist
./run.sh down      # stop + remove containers (run before re-testing after code changes)
./run.sh logs a    # tail podman logs (stderr) for container a/b/target
```

- Generated configs/logs live in `test/.run/` (git-ignored) — e.g.
  `.run/ydn64.log` (A's file-based service log), `.run/yggclient.log` (B's
  stdlib log, also in `podman logs`), `.run/ydn64.env` (shell-sourceable
  vars: `NODE_ADDR`, `DNS64_LISTEN_ADDR`, `NAT64_POOL_PREFIX`, ...).
- After any change to `src/`, rebuild the binary/image before retesting: the
  test images bake in the compiled binary, they don't mount source live.
- Test cases restart the `A` container to exercise config-reload behavior
  (see `test/cases/04_allowed_sources_config_change.sh`); each restart
  currently generates a **new random Yggdrasil identity** (no private key
  persistence across restarts in the harness), which is expected — B just
  needs to re-peer, not recognize the same key.
- Peer re-establishment after a container restart is not instant — allow a
  generous timeout (`wait_for 30 ...` in `test/lib.sh`) rather than a tight
  one; yggdrasil-go's reconnect backoff timing is variable enough that a 15s
  budget across two rapid restarts was observed to flake. B's peer URI in
  `test/run.sh` sets `?maxbackoff=5s` (yggdrasil-go's hard minimum — bare
  `maxbackoff=5` is invalid, it's parsed with `time.ParseDuration` and needs a
  unit) so the reconnect backoff itself stays small; this makes most re-peers
  land in ~1s instead of occasionally waiting much longer.
- **Residual flake, not fixed by `maxbackoff`**: occasionally (~1-in-3
  observed) `test/cases/04_allowed_sources_config_change.sh`'s second
  `podman restart` of `A` is followed by B's yggdrasil logging repeated
  `dial tcp 10.90.0.2:9993: i/o timeout` for 30+ seconds even though A is
  confirmed up and listening in its own log, and `nc -zv` from B to A
  succeeds again once the flake clears. This is a transient podman
  bridge-networking hiccup on the macOS podman-machine VM (gvproxy/vfkit)
  after a container restart recreates the veth — the TCP SYN itself is not
  getting a response, so no amount of yggdrasil-level backoff tuning helps.
  If this test starts flaking persistently, look at host/VM networking
  convergence delay after `podman restart`, not at `src/` or the peering
  config.
- **Same flake can manifest as a hung `podman exec` itself**, not just a B→A
  TCP dial timeout — observed once as a `podman exec ydn64-test-a ...`
  command producing literally zero output (not even output from a plain
  `date` run before it in the same loop) for far longer than expected,
  immediately after reproducing the case 04 restart flake. Retrying the same
  `podman exec` a bit later succeeded in under 200ms, confirming it was the
  transient VM-networking hiccup clearing on its own, not a real hang in
  ydn64 or a stuck shell. If a `podman exec` seems to hang with no output at
  all, check `podman ps`/`podman machine` health and just wait/retry rather
  than assuming ydn64 itself is stuck.
- **`test/cases/05_real_world_icmp.sh`** (real-world DNS64+NAT64-ICMP check
  against `dns.google`/8.8.8.8) runs immediately after case 04's restarts.
  `wait_for` after case 04 only confirms B's yggnet peering is back, not that
  A's targetnet egress path is fully settled — so case 05's initial `dig`
  retries a few times (up to ~10s) before failing, rather than asserting on
  the first attempt.

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
- `SetPacketInterceptor` on the netstack only supports **one** registered
  callback. NAT64's UDP and ICMP paths share a single dispatcher
  (`Service.interceptPacket` in `src/nat64/service.go`), which inspects the
  IPv6 next-header byte (`pkt[6]`) and routes to `interceptUDPPacket` (17) or
  `interceptICMPPacket` (58). Don't try to register a second interceptor —
  extend the dispatcher instead.
- **Raw ICMPv4 sockets need `CAP_NET_RAW`**, and it is **not** granted by
  podman's default capability set — `icmp.ListenPacket("ip4:icmp", "0.0.0.0")`
  fails with `operation not permitted` unless the container is started with
  `--cap-add=NET_RAW` (see `test/run.sh`, container A). ICMP NAT64 opening
  the raw socket is best-effort/non-fatal: if it fails, NAT64 logs a warning
  (`NAT64 ICMP disabled ...`) and TCP/UDP continue working normally; check
  for `icmp=true` vs `icmp=false` in the startup log line to confirm whether
  ICMP translation is actually active.
