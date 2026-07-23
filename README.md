# ydn64

`ydn64` (**y**ggstack + **d**ns64 + **n**at64) is a single Go binary that
runs a **TUN-less, userspace Yggdrasil node** (no root required) and exposes
two services to the Yggdrasil network:

- **NAT64** (`src/nat64`) — stateful IPv6→IPv4 translation for allowed
  Yggdrasil peers, using a `Nat64Pool` prefix derived from the node's own
  `300::/64` subnet. Covers TCP, UDP, and ICMP Echo (translates ICMPv6 Echo
  Request/Reply to/from real ICMPv4 via a raw socket, so `ping6` to a pool6
  address works end-to-end against a real IPv4 host).
- **DNS64** (`src/dns64`) — a caching DNS64 resolver/proxy that synthesises
  AAAA records from A records (with per-zone forwarding/pass-through rules).

Both services run on top of a single gVisor userspace netstack attached to
the Yggdrasil core — there is no OS TUN device anywhere in this stack.

## Build / run

```sh
./build                              # build with version stamping, outputs ./ydn64
go build -o ./ydn64 ./cmd/ydn64      # plain build without version stamping

./ydn64 -genconf > ./tmp/ydn64.conf   # print a new config to stdout, redirect to save it
./ydn64 -useconffile ./tmp/ydn64.conf # run the node + services
```

## Configuration

`-genconf` generates a complete, ready-to-run config — private key, NAT64
pool, DNS64 listen address, etc. are all pre-derived automatically. In
practice you only need to edit two fields before running:

- **`Peers`** — add at least one outbound Yggdrasil peer connection string
  (e.g. `tcp://a.b.c.d:e`) so your node can actually reach the network.
- **`AllowedSources`** — replace the placeholder `/128` address with the
  Yggdrasil address(es) you want permitted to use this node's NAT64/DNS64
  services (see below).

Everything else is configured with secure, working defaults out of the box.

## Running with Docker

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to
`ghcr.io/drewcyber/ydn64` on every version tag (`vX.Y.Z`), plus a rolling
`latest` tag. See [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml).

The image's entrypoint ([docker-entrypoint.sh](docker-entrypoint.sh)) will
generate a fresh config with `ydn64 -genconf` on first run if none exists at
`$YDN64_CONFIG` (default `/data/ydn64.conf`). **Mount `/data` as a volume** so
the generated `PrivateKey` (and the `Nat64Pool`/`Dns64Listen` addresses
derived from it) stay stable across container restarts — without it, every
restart gets a brand new Yggdrasil identity.

The two fields you normally must set — `Peers` and `AllowedSources` — can be
supplied as environment variables instead of editing the mounted config file,
as a comma and/or whitespace separated list. `ydn64` applies them as
overrides on top of the loaded config at startup:

```sh
docker run -d \
  --name ydn64 \
  -v ydn64-data:/data \
  -e YDN64_PEERS="tls://a.b.c.d:e, tls://f.g.h.i:j" \
  -e YDN64_ALLOWED_SOURCES="200::/7" \
  --cap-add=NET_RAW \
  ghcr.io/drewcyber/ydn64:latest
```

`--cap-add=NET_RAW` is optional but recommended — see below.

## ICMP NAT64 and `CAP_NET_RAW`

NAT64's ICMP Echo translation opens a raw ICMPv4 socket
(`icmp.ListenPacket("ip4:icmp", "0.0.0.0")` in
[src/nat64/service.go](src/nat64/service.go)), which requires `CAP_NET_RAW`
(or running as root). Without it:

- Opening the socket fails with `operation not permitted`.
- This is handled as **best-effort/non-fatal** — a warning is logged
  (`NAT64 ICMP disabled (raw socket unavailable, needs CAP_NET_RAW): ...`),
  and the service continues running with TCP and UDP NAT64 fully
  functional. Only ICMP Echo (ping) translation is skipped.
- You can confirm which mode you're in from the startup log line: `icmp=true`
  vs `icmp=false`.

If running under podman/Docker, grant the capability explicitly, e.g.:

```sh
podman run --cap-add=NET_RAW ...
```

### Planned: unprivileged ICMP fallback

Linux supports **unprivileged ICMP** via `SOCK_DGRAM`/`IPPROTO_ICMP` sockets
(no `CAP_NET_RAW` needed) when the process's GID falls within the
`net.ipv4.ping_group_range` sysctl — this is how e.g. `ping` works
unprivileged in some containers. `golang.org/x/net/icmp` supports this mode
via the `"udp4"` network string instead of `"ip4:icmp"`.

This is **not yet implemented** — `ydn64` currently always requests a true
raw socket, so `CAP_NET_RAW` (or root) is the only way to get ICMP NAT64
working today. A planned improvement is to fall back to `"udp4"` when the
raw socket fails to open, to support unprivileged environments where
`ping_group_range` is configured but `CAP_NET_RAW` isn't granted.

## More

See [AGENTS.md](AGENTS.md) for detailed guidance on the codebase,
configuration format, and the black-box test harness under `test/`.
