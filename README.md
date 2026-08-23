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

## 1. Build / Download

```sh
./build                              # build with version stamping, outputs ./ydn64
go build -o ./ydn64 ./cmd/ydn64      # plain build without version stamping
```

## 2. Configuration

```sh
./ydn64 -genconf > ./ydn64.conf   # print a new config to stdout, redirect to save it
```

`-genconf` generates a complete, almost ready-to-run config — private key, NAT64
pool, DNS64 listen address, etc. are all pre-derived automatically. In
practice you only need to edit two fields before running:

- **`Peers`** — add at least one outbound Yggdrasil peer connection string
  (e.g. `tcp://a.b.c.d:e`) so your node can actually reach the network.
- **`AllowedSources`** — replace the placeholder `/128` address with the
  Yggdrasil address(es) you want permitted to use this node's NAT64/DNS64
  services (see below).

```
  Peers: [tcp://xx.xx.xx.xx:XXXX]
  AllowedSources: ["201:aaaa:bbbb:cccc:dddd:eeee:ffff:1234/128"]
```

Everything else is configured with secure, working defaults out of the box.

### Resource limits

Any allowed peer can generate unbounded load, so the services are bounded by
default. All four keys accept any positive integer; unset or non-positive
values fall back to these defaults:

| Key | Default | Behaviour at the limit | Reloadable |
|---|---|---|---|
| `Nat64MaxTCPConnections` | 1024 | new connections refused (RST) | no — restart |
| `Nat64MaxUDPSessions` | 4096 | least-recently-active session evicted | yes |
| `Dns64MaxCacheEntries` | 4096 | expired entries purged, else random eviction | yes |
| `Dns64MaxConcurrentQueries` | 512 | excess UDP queries → SERVFAIL, TCP conns closed | no — restart |

An **empty `AllowedSources`** is accepted but denies every client: NAT64 and
DNS64 log a loud warning at startup and silently drop all traffic. If clients
get no answers at all, check `AllowedSources` first. Forwarders
(`Dns64Default`, zone `forwarder`) must be in `host:port` form with a numeric
port, `Nat64Pool` must be a `/96`, and zone `prefix` values must be `/96`
networks (last four bytes zero) — misformatted values are rejected at startup
instead of misbehaving silently.

## 3. Run

```sh
./ydn64 -useconffile ./ydn64.conf # run the node + services
```

Use node ip or config `Dns64Listen` value as DNS for yggdrasil clients:

```
  Dns64Listen: "[200:aaaa:bbbb:cccc:dddd:eeee:ffff:1234]:53"
```

## Running with Docker

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to
`ghcr.io/drewcyber/ydn64` on every version tag (`vX.Y.Z`), plus a rolling
`latest` tag. The same workflow also cross-compiles standalone binaries for
Linux (`amd64`, `arm64`, `arm` (armv7), `386`), Windows (`amd64`, `arm64`),
and macOS (`amd64`, `arm64`), archived (`.tar.gz` for Linux/macOS, `.zip`
for Windows) and attached to the GitHub Release for that tag. See
[.github/workflows/release.yml](.github/workflows/release.yml).

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

### Running with no config file/volume at all

A third variable, `YDN64_PRIVATE_KEY`, overrides the node's identity itself
(a hex-encoded ed25519 private key, e.g. copied from the `PrivateKey` line of
a previously generated config). When it's set, `Nat64Pool`, `Dns64Listen`,
and `Dns64Zones` are automatically recomputed to match — any custom
`Dns64Zones` in the mounted config are replaced with the single default
synthesis zone in this case, so use a persisted config file instead if you
need custom DNS64 zones.

With all three variables set, you can run a fully working node with no
mounted config file or volume at all — [docker-entrypoint.sh](docker-entrypoint.sh)
will generate one in-container via `ydn64 -genconf` (which also bakes these
same env vars into the generated file) and immediately apply the same
overrides at startup:

```sh
docker run -d \
  --name ydn64 \
  -e YDN64_PRIVATE_KEY="<64-byte hex private key>" \
  -e YDN64_PEERS="tls://a.b.c.d:e, tls://f.g.h.i:j" \
  -e YDN64_ALLOWED_SOURCES="200::/7" \
  --cap-add=NET_RAW \
  ghcr.io/drewcyber/ydn64:latest
```

If a config file already exists at `$YDN64_CONFIG`, the entrypoint leaves it
as-is (env var overrides still apply on top of it) — this only matters for
the very first run.

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

## Standards conformance and deliberate deviations

**`ydn64`'s design goal is to work well for Yggdrasil clients — not to be a
strictly conformant NAT64/DNS64 implementation.** Where the two conflict,
`ydn64` chooses the behaviour that works for a client whose *only*
connectivity is Yggdrasil (no global IPv6 route, no IPv4 at all).

This section documents where `ydn64` knowingly departs from the relevant
RFCs, so the behaviour isn't mistaken for a bug.

### Relevant RFCs

| RFC | Title |
|---|---|
| [6146](https://www.rfc-editor.org/rfc/rfc6146) | Stateful NAT64 |
| [6147](https://www.rfc-editor.org/rfc/rfc6147) | DNS64 |
| [6052](https://www.rfc-editor.org/rfc/rfc6052) | IPv6 Addressing of IPv4/IPv6 Translators |
| [7915](https://www.rfc-editor.org/rfc/rfc7915) | IP/ICMP Translation Algorithm (obsoletes 6145) |
| [4787](https://www.rfc-editor.org/rfc/rfc4787) / [5382](https://www.rfc-editor.org/rfc/rfc5382) / [5508](https://www.rfc-editor.org/rfc/rfc5508) | NAT behavioural requirements for UDP / TCP / ICMP |
| [7050](https://www.rfc-editor.org/rfc/rfc7050) / [8880](https://www.rfc-editor.org/rfc/rfc8880) | NAT64 prefix discovery via `ipv4only.arpa` |
| [8781](https://www.rfc-editor.org/rfc/rfc8781) | Discovering PREF64 in Router Advertisements |

The full list — including the DNS protocol RFCs pulled in by RFC 6147 §5.4,
and a per-requirement implementation status — is kept in
[context/RFCs.txt](context/RFCs.txt).

### Deliberate DNS64 deviations

**1. AAAA records are synthesised even when real AAAA records exist.**
RFC 6147 §5.1.1 says a DNS64 *"MUST NOT synthesize AAAA RRs when real AAAA
RRs exist"* by default. `ydn64`'s default catch-all zone does the opposite,
because a real `2000::/3` address is **unreachable** for a client whose only
transport is Yggdrasil — returning it would just make connections hang.
RFC 6147 **Appendix A** explicitly anticipates this as an administrator
choice; `ydn64` simply makes it the default. Set
`return-ipv6-addresses: true` on a zone to get the conformant behaviour
(this is what the `.ygg` zone does — those addresses *are* reachable).

**2. A records are suppressed for zones with `return-ipv4-addresses: false`.**
RFC 6147 §5.3.3 says *"All other RRs MUST be returned unchanged. This
includes responses to queries for A RRs."* An IPv4 address is useless to an
IPv6-only Yggdrasil client, and returning it invites the client to attempt a
connection that cannot succeed. Set `return-ipv4-addresses: true` per zone to
pass A records through.

**3. `ANY` queries are answered from the AAAA synthesis path.**
RFC 8482 recommends answering `ANY` minimally (e.g. a single `HINFO`).
`ydn64` instead rewrites `ANY` to `AAAA` upstream and applies the zone's
normal synthesis/filter rules, so an `ANY` query returns something the client
can actually use rather than whatever the upstream happens to do.

**4. `PTR` for a Pref64 address is resolved, not delegated.**
RFC 6147 §5.3.1 offers two conformant strategies (answer authoritatively for
the Pref64, or synthesise a `CNAME` into `in-addr.arpa`). `ydn64` does
neither: it rewrites the `ip6.arpa` query into the corresponding
`in-addr.arpa` query, resolves it itself, and returns the real `PTR` data
under the original name. This gives the client useful reverse data in one
round trip.

**5. A query matching no configured zone returns `NXDOMAIN`.**
`Dns64Zones` acts as an allow-list. If you want a transparent catch-all, keep
the `["."]` zone that `-genconf` produces.

### Architectural limitations

These follow from `ydn64` being a **TUN-less userspace transport proxy**
rather than a packet translator. TCP and UDP are terminated inside the gVisor
netstack and re-originated over ordinary OS sockets; ICMP Echo is translated
via a raw socket. There is no IP-header translation anywhere in the path.

- **No RFC 7915 header translation.** Traffic Class/DSCP, ECN, and Hop
  Limit ↔ TTL are not carried across the translator; synthesised IPv6 replies
  use a fixed Hop Limit.
- **ICMP errors are not translated** — only Echo/Echo Reply. As a result
  `traceroute` through NAT64 does not work, and Path MTU Discovery is not
  supported in either direction.
- **No IPv4-initiated flows.** `ydn64` has no inbound IPv4 listener, so only
  the "IPv6 client → IPv4 server" direction of RFC 6144 is supported.
- **Fragmented IPv6 packets are handled for TCP and UDP** — gVisor reassembles
  inbound fragments and fragments oversized outbound datagrams. The raw-socket
  ICMP Echo path still only sees unfragmented echo requests (RFC 6146 §3.4).
- **Mapping is address-and-port-dependent ("symmetric NAT").** RFC 6146 §5.2
  requires Endpoint-Independent Mapping; `ydn64` opens a separate outbound
  socket per destination, so a client's external port differs per peer. This
  means **STUN/ICE-based NAT traversal (WebRTC, most P2P) does not currently
  work through `ydn64`.**
- **No DNSSEC validation.** `ydn64` is a security-oblivious DNS64 in the
  RFC 6147 §3 sense; synthesised answers cannot be validated by the client.
  Validating clients are handled per RFC 6147 §5.5: queries carrying both
  CD=1 and DO=1 are relayed upstream verbatim (no synthesis, no cache), and
  `ydn64` never asserts the AD bit on responses it generates or modifies.
- **No RFC 8781 PREF64 discovery.** A TUN-less node has no L2 presence and
  cannot emit Router Advertisements, so clients that prefer RA-based
  discovery (recent iOS/Android) must use RFC 7050 (`ipv4only.arpa`) or be
  configured manually.

## Licence

ydn64's own code is licensed under the [BSD Zero Clause License](LICENSE).
The distributed binaries and container images bundle third-party Go modules,
notably [gVisor](https://gvisor.dev) (Apache-2.0) and
[yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) (LGPL-3.0);
the full licence texts of every bundled component ship in
`THIRD-PARTY-NOTICES.txt` inside each release archive (and at
`/usr/local/share/doc/ydn64/` in the Docker image).

## More

See [AGENTS.md](AGENTS.md) for detailed guidance on the codebase,
configuration format, and the black-box test harness under `test/`.
