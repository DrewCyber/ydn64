# AGENTS.md — ydn64

Guidance for AI coding agents working in this repository.

## What this is

`ydn64` is a single Go binary that runs a **TUN-less, userspace Yggdrasil node**
(no root required) and exposes two services to the Yggdrasil network:

- **NAT64** (`src/nat64`) — stateful IPv6→IPv4 translation for allowed
  Yggdrasil peers, using a `Nat64Pool` prefix derived from the node's own
  `300::/64` subnet.
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
to stdout** (see [context/ydn64.conf.example](context/ydn64.conf.example) for
the annotated reference) — it does not write any file itself; redirect
stdout (e.g. `> ydn64.conf`) to save it, matching upstream yggdrasil-go's own
`-genconf` behavior. There is no separate `yggdrasil.conf` / `ydn64.toml`
split — that was an earlier iteration and has been merged.

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
admin socket or a TUN interface by design.

When changing the config schema:
- Add the field to `AppConfig` in [src/config/config.go](src/config/config.go)
  with a `json:"..."` tag (hjson respects json tags).
- Add validation in `AppConfig.validate()`.
- Update the generated template in
  [src/config/generate.go](src/config/generate.go) so `-genconf` output stays
  in sync.
- Update [context/ydn64.conf.example](context/ydn64.conf.example) (the
  human-facing annotated reference).

## Repo layout

```
cmd/ydn64/main.go       CLI entry point, wiring: core → admin → multicast → netstack → nat64/dns64
src/config/             config.go (load/validate), generate.go (-genconf template)
src/netstack/           gVisor stack wrapper bound to Yggdrasil's ipv6rwc
src/nat64/              NAT64 service: packet.go, service.go, tcp.go, udp.go
src/dns64/              DNS64 service: server.go, proxy.go, cache.go, zones.go
context/                design notes — see caveat below
tmp/                    git-ignored scratch space for local test runs
```

### `context/` caveat

- [context/general-idea.txt](context/general-idea.txt) — original design brief, still broadly accurate for intent/motivation.
- [context/old/improvement.txt](context/old/improvement.txt) — **stale**: an early DNS64/NAT64 design note using a sectioned TOML (`[nat64]`/`[dns64]`/`[dns64.<zone>]`) layout with `snake_case` keys. The actual config is a single flat HJSON file with `PascalCase` keys and a `Dns64Zones` array (see [context/ydn64.conf.example](context/ydn64.conf.example)). Useful for the *behavioral* intent (NXDOMAIN fallback, zone matching rules) but don't follow its config syntax.
- [context/ydn64.conf.example](context/ydn64.conf.example) — the current, authoritative annotated config reference; keep it in sync with `config.go`/`generate.go`.


## Conventions

- Go module: `github.com/yggdrasil-network/ydn64`, Go 1.25.5.
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
  budget across two rapid restarts was observed to flake.

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
