# Changelog

All notable changes to `ydn64` are recorded here. This file is updated
manually (not auto-generated) whenever a change is worth calling out to
users or future contributors — new features, behavior changes, config
schema changes, fixed bugs with user-visible impact. Not every commit needs
an entry; skip pure refactors, typo fixes, or internal test harness changes
unless they affect users.

Entries are grouped under an unreleased heading until a release is cut, then
moved under the corresponding version heading.

## [0.7.0] - 2026-08-24

**Full RFC coverage milestone.** Every requirement ydn64 can honour across
the covered RFCs (NAT behavioural BCPs, Stateful NAT64, DNS64 and the DNS
protocol RFCs they cite) is now implemented and verified; whatever remains
open in [context/RFCs.txt](context/RFCs.txt) is a deliberate deviation or
an architectural N/A, each documented with rationale. The black-box podman
suite grew to 16 end-to-end cases exercising every behaviour below.

### NAT64 now behaves like a real stateful NAT gateway (RFC 4787 / RFC 5382 / RFC 5508 / RFC 6146)

- **UDP endpoint-independent mapping (RFC 4787 REQ-1, RFC 6146 §3.1/§5.2)** —
  one client source socket keeps ONE external `ip:port` across ALL its IPv4
  destinations (a single shared outbound socket per client). STUN/ICE-based
  traversal (WebRTC, QUIC, P2P hole punching) works through the translator;
  replies from any contacted server reach the client on the same mapping.
- **UDP port parity preservation (RFC 4787 REQ-3)** — the NAT-assigned
  external port keeps the client source port's even/odd parity by default,
  which RTP/RTCP-style media flow pairs expect. New `Nat64PortParity` key
  (`preserve` | `do-not-preserve`, default `preserve`, SIGHUP-reloadable).
- **UDP endpoint-independent filtering (RFC 4787 REQ-8)** —
  `Nat64UdpFiltering: endpoint-independent` delivers unsolicited inbound
  IPv4 datagrams to any mapped client, even senders it never contacted:
  they are re-originated as IPv6/UDP (`pool6::sender`) and injected onto the
  Yggdrasil leg without creating session state. This completes hole
  punching: after a peer learns the client's external mapping it can punch
  inbound. Off by default (widens the inbound surface); `address-dependent`
  remains the mandated default, `address-and-port-dependent` stays available.
- **Proxied-TCP idle expiry (RFC 5382 REQ-5)** — idle-but-alive proxied TCP
  connections are expired after `Nat64TcpTimeout` (validation floor 7440 s =
  2h04m), closing both legs and freeing global/per-source slots. Refreshed
  by payload traffic only, never by keepalives.
- **ICMPv4 error translation (RFC 7915 §4.2/§4.3, RFC 5508 REQ-3/REQ-4)** —
  Destination Unreachable, Time Exceeded, Parameter Problem and Packet Too
  Big messages about tracked flows are translated per the type/code tables
  (with RFC 1191 plateau MTU fallback) and delivered to the client with the
  quoted packet rebuilt to its original tuple. IPv6-side PMTUD now converges
  for UDP flows; closed v4 ports fail fast instead of hanging. ydn64 also
  generates ICMPv6 Destination Unreachables for undialable flows and v4
  port-refusals (RFC 4443 §3.1). Synthesised errors are rate-limited and
  truncated to the 1280-byte budget; TCP is deliberately excluded because
  proxied connections terminate twice and the OS consumes those errors.
- **Fragmented ICMPv6 through NAT64 (RFC 8200 §4.5, RFC 6146 §3.4)** — the
  intercepted ICMPv6 path walks extension-header chains properly, reassembles
  fragmented Echo Requests in a strictly bounded table (≤64 datagrams,
  ≤16 fragments, ≤64 KiB, 30 s; overlap cancels per RFC 5722) and emits
  oversized replies as proper IPv6 fragments. `ping6 -s 2000/-s 4000`
  completes end to end, including toward real internet hosts.
- **NAT-assigned Echo identifiers** start from an unpredictable value, and
  ICMP sessions carry a 60-second lifetime floor.
- **Anti-abuse ceilings (RFC 5358, RFC 6146 §5.3)** — new SIGHUP-reloadable
  keys `Dns64RateLimit` (50 qps/source, REFUSED with strict reply spacing),
  `Nat64MaxUDPSessionsPerSource` (256) and `Nat64MaxTCPConnectionsPerSource`
  (128) stop one allowed peer from monopolising resolver or translator
  state. NAT64 UDP session lifetimes are refreshed only by the client's own
  outbound datagrams (RFC 4787 REQ-5), so pointing one datagram at a chatty
  server cannot pin an outbound socket indefinitely.

### DNS64 hardened to standards-complete (RFC 6147 / RFC 6891 / RFC 6052 / RFC 7766)

- **EDNS(0) option passthrough (RFC 6891)** — response OPT records are
  rebuilt on both UDP and TCP paths while carrying OPTIONS across the proxy
  hop: upstream server cookies round-trip to the real-internet forwarder
  (transparent DNS COOKIE support, RFC 7873) and ECS responses flow back
  (RFC 7871), locally generated answers echo the client COOKIE, and classic
  non-EDNS clients never receive an OPT. Size advertisement is unchanged:
  client-advertised values honoured up to the 4096-byte cap — with the
  legacy floor tightened so non-EDNS queries are answered within 512 bytes
  (+TC beyond), per RFC 6891 §6.2.5.
- **DNSSEC minimum viable subset (RFC 6147 §5.5)** — validating clients
  sending CD=1+DO=1 get their queries relayed upstream verbatim (no
  synthesis, no caching); ydn64 never asserts the AD bit on answers it
  generates or modifies.
- **AAAA special exclusion set (RFC 6147 §5.1.4)** — new SIGHUP-reloadable
  `Dns64AAAAExcludedSubnets` key strips real AAAA answers inside configured
  prefixes (the standards-blessed "my clients can't reach these" list);
  synthesised records are never affected.
- **All RFC 6052 §2.2 prefix layouts accepted** — `Nat64Pool` and zone
  `prefix` values may be `/32`, `/40`, `/48`, `/56`, `/64` or `/96`,
  validated including the u-octet rules; addresses with dirty bits are
  rejected at startup instead of misbehaving silently.
- **Cache honours upstream TTLs** instead of a fixed value; expired entries
  are purged first under memory pressure (`Dns64MaxCacheEntries`).
- **Pipelined DNS-over-TCP processed concurrently (RFC 7766 §6.2.1.1/§7)** —
  queries on one connection are dispatched immediately and answered out of
  order, so a slow upstream lookup no longer head-of-line-blocks later
  queries; bounded per-connection fan-out and idle-timeout resets follow
  §6.2.2–§6.2.4.

### Forgery resistance (RFC 5452)

- Upstream exchanges carry a **randomly chosen transaction ID** — the
  client's own ID never leaves the node, so an allowed client cannot dictate
  the ID an off-path spoofer must guess.
- **0x20 query-name randomisation (RFC 5452 §9.1)** — every upstream query
  name carries random per-character case and the answer must echo it
  byte-for-byte or be discarded; the client's original casing is restored on
  request and response. Forwarders failing the check repeatedly are treated
  as 0x20-incapable and temporarily exempted, degrading hardening rather
  than availability.

### Robustness, safety and packaging

- **Broken configs fail loudly**: validation now rejects invalid
  combinations at load instead of misbehaving silently, and an empty
  `AllowedSources` produces a prominent warning (it denies every client).
- **Bounded resources by default**: NAT64 UDP sessions, proxied TCP
  connections, DNS cache entries and concurrent DNS64 queries all carry
  configurable caps (`Nat64Max*`, `Dns64Max*`); overflow sheds work instead
  of exhausting memory.
- Netstack robustness: fixed a shared-buffer data race in the NIC write
  path, hardened the inbound ICMP path, and the netstack read loop is now
  supervised (restart-on-exit with drop counters surfaced in stats).
- Release artefacts ship licence obligations: every archive/image carries
  `LICENSE` + generated `THIRD-PARTY-NOTICES.txt`; GitHub Actions now build
  multi-arch container images and cross-platform binaries on version tags,
  with a CI pipeline on every push/PR.

## [0.6.0] - 2026-08-23

gVisor netstack hardening (UDP fragmentation, MTU fix, TCP robustness)
and DNS64 EDNS(0) support.

- **RFC 6891 (EDNS(0))** — DNS64 now negotiates UDP payload sizes over
  EDNS(0): responses longer than the client's advertised payload size
  are truncated, with a 1232-byte safe default for clients that send no
  OPT record and a 4096-byte cap even when the client advertises more;
  replies carry an OPT record whenever the query did.
- **RFC 6146 §3.4 — NAT64 UDP moved onto gVisor's UDP forwarder** — the
  hand-rolled NIC-level UDP interceptor was replaced with gVisor's
  `udp.NewForwarder`, so the stack now owns UDP checksums, demuxing,
  IPv6 reassembly and outbound fragmentation. Fragmented datagrams and
  oversized replies now traverse NAT64 end-to-end. Policy-rejected
  flows remain silently dropped, while endpoint-creation failures now
  answer ICMPv6 port-unreachable instead of nothing.
- **Fixed oversized-packet drops — `IfMTU` is now honoured** — the
  underlying Yggdrasil `ipv6rwc` layer defaults its internal MTU to
  1280 and enforces it on inbound frames; because ydn64 has no TUN
  device, nothing ever called `SetMTU`, so every client frame above
  1280 bytes was dropped with an ICMPv6 Packet Too Big reply
  regardless of configuration. The configured `IfMTU` is now applied
  to the netstack (also driving egress segmentation and buffer sizes);
  it stays omitted from `-genconf` output, where the upstream default
  works fine. This supersedes the 0.1.0 claim that the key is inert.
- **TCP keepalive + user timeout on NAT64 connections** — the gVisor
  leg of every proxied connection now enables keepalives (idle 75 s +
  9×10 s probes, ~165 s detection budget) plus a 5-minute user timeout
  that only bounds stalled transfers with unacknowledged data, so
  connections into dead Yggdrasil peers are reclaimed promptly instead
  of lingering until the stack's far longer internal retransmit
  timeouts expire.
- **CUBIC congestion control** — the netstack's TCP transport now uses
  CUBIC (Linux's default since 2008) instead of gVisor's Reno default:
  parity on lossless paths, better recovery on lossy Yggdrasil tunnels.
  No configuration knob.
- **Netstack stats logging** — NAT64 emits one compact, greppable
  `netstack stats:` line at debug level every 60 s (IP/TCP/UDP/ICMPv6
  counters, established connections, live NAT sessions); a `SIGHUP`
  reload now also triggers an immediate stats dump.
- **New `YDN64_DEBUG_PCAP` packet tap** — setting this environment
  variable to a file path captures all traffic crossing the netstack
  to a libpcap file for offline analysis (best-effort: failure to open
  the capture only logs a warning and never blocks startup).

## [0.5.0] - 2026-08-14

RFC compliance hardening across NAT64 and DNS64.

- **RFC 6147 §5.1.2** — DNS64 now returns NXDOMAIN immediately when the
  upstream AAAA query responds with NXDOMAIN. Any other upstream error is
  treated as an empty success and falls through to A-record-based synthesis,
  whose result (including its own error or empty answer) becomes the final
  response.
- **RFC 6146 §3.5 / §5.4** — Inbound source filter: NAT64 now drops inbound
  UDP, TCP, and ICMPv6 packets whose IPv6 source address falls within the
  configured `Nat64Pool` prefix, preventing spoofed loopback through the
  translator.
- **RFC 6146 §3.5.1 / §4** — UDP session lifetime floor: `Nat64UdpTimeout`
  is now validated to be at least 120 s; values below that (or 0 / unset)
  are silently raised. The generated config default remains 300 s.
- **RFC 8880** — DNS64 now answers `ipv4only.arpa.` queries locally without
  forwarding to the upstream resolver. A queries return the two well-known
  addresses (192.0.0.170 / 192.0.0.171); AAAA queries synthesise responses
  using the configured zone prefix where applicable.
- **RFC 8200 §8.1** — NAT64 now sets UDP checksum to `0xFFFF` instead of
  `0x0000` when the computed checksum for an outbound IPv6 UDP packet would
  otherwise be zero, as required by the spec.
- **RFC 6147 §5.1 (Qclass / TTL)** — DNS64 passes through queries with a
  non-IN Qclass unchanged (no synthesis). Synthetic AAAA TTL is now
  calculated as `min(A TTL, SOA TTL)` from the upstream negative AAAA
  response; when no SOA RR is present the fallback cap is 600 s.
- **RFC 6147 §5.1.5 / §5.1.7 (CNAME / owner name)** — When synthesising
  AAAA records for a CNAME-chained name, the owner name on the synthetic
  record now matches the A record's owner name (the final CNAME target)
  rather than the original query name, and non-A RRs (CNAMEs) are preserved
  in the synthesised answer and cache entry.
- **New config option `IgnoredDstSubnets`** (RFC 6147 §5.1.7) — A list of
  IPv4 prefixes for which NAT64 and DNS64 synthesis are suppressed. Defaults
  to RFC-defined private/reserved ranges (10/8, 172.16/12, 192.168/16,
  127/8, 169.254/16, multicast, reserved). The list is reloadable via
  `SIGHUP` without restart.

## [0.4.1] - 2026-07-28

- Github rebuild

## [0.4.0] - 2026-07-28

- Upgraded the vendored upstream `yggdrasil-network/yggdrasil-go` from
  v0.5.13 to **v0.5.14**.
- **New config option `GroupPassword`** (from upstream v0.5.14): traffic is
  only allowed to/from nodes sharing the same group password, letting you
  form a private sub-network. Empty/unset (the default) keeps public
  connectivity; if set, the node will no longer be able to reach public
  services or hosts. It does not affect peering connections or routing.
  Included in `-genconf` output and applied at startup; like the other
  Yggdrasil-core settings it is **not** reloadable via `SIGHUP` and
  requires a restart.

## [0.3.0] - 2026-07-24

- **Fixed a DNS64 bug causing `DNS_PROBE_FINISHED_BAD_CONFIG`-style failures
  for CNAME-chained domains** (e.g. `passport.ya.ru` → CNAME →
  `passport.yandex.ru`, which has a real AAAA record). `handleAAAA()` in
  `src/dns64/proxy.go` treated any non-empty filtered answer as a
  successful AAAA response, but `filterAAAA()` passes CNAME records through
  unconditionally even in prefix-synthesis zones where real AAAA records
  are intentionally dropped — so a CNAME-only answer was wrongly returned
  as "done", giving clients a response with a CNAME and no address at all.
  Fixed by requiring at least one real AAAA record (not just any RR) before
  short-circuiting, so CNAME-only answers now correctly fall through to
  A-record-based DNS64 synthesis.
- Test harness (`test/`) reworked: removed the fake `target`
  container/network in favor of real internet/Yggdrasil egress from `A` for
  all lookups; cases renumbered/renamed
  (`01_peering.sh`, `02_dns_google_icmp.sh`, `03_ygg_zone_resolution.sh`,
  `04_dns64_any_query.sh`, `05_allowed_sources_config_change.sh`); added a
  `./run.sh case <name>` command for standalone case debugging with
  automatic config snapshot/restore between runs.

## [0.2.0] - 2026-07-24

- DNS64 now handles query type `ANY` explicitly: it's treated like `AAAA`
  (synthesis/filtering per the zone's `return-ipv4-addresses` /
  `return-ipv6-addresses` / `prefix` rules) instead of being blindly passed
  through to the upstream resolver, whose raw `ANY` behavior varies widely
  (e.g. some upstreams reply with a bare RFC 8482 HINFO record).
- DNS64 now also listens on **TCP**, in addition to UDP, on the same
  configured listen address/port — matching how mature DNS servers (BIND,
  Unbound, etc.) serve both transports by default. This is needed because
  some clients (e.g. `dig`) send certain query types, like `ANY`, over TCP
  by default; such queries previously got a bare TCP connection refusal
  since only UDP was served.

## [0.1.1] - 2026-07-24

- **Removed the 200::/7 special-case** in DNS64: zones no longer get
  implicit Yggdrasil-native AAAA pass-through behavior based on the
  forwarder/answer address falling in `200::/7`. A zone must now opt in
  explicitly via `return-ipv6-addresses: true` to pass through real AAAA
  answers, regardless of whether they happen to be Yggdrasil addresses.
- **Renamed config keys** (clean break, no aliases): `ReturnPublicIPv4` /
  `ReturnPublicIPv6` (`return-public-ipv4` / `return-public-ipv6`) →
  `ReturnIPv4Addresses` / `ReturnIPv6Addresses` (`return-ipv4-addresses` /
  `return-ipv6-addresses`). Existing config files using the old keys must be
  updated by hand; the old keys are silently ignored otherwise.
- The `.ygg` zone block in [ydn64.conf](ydn64.conf) now reads
  `return-ipv6-addresses: true` with an updated comment (no longer claims
  special 200::/7 handling — it passes through AAAA answers because it's
  explicitly configured to, like any other zone).
- `-genconf` now generates the `.ygg` zone as an active (uncommented) entry
  in `Dns64Zones` by default, instead of a commented-out example — new
  nodes resolve `.ygg` names out of the box.

## [0.1.0] - 2026-07-24

- Removed `AdminListen`, `IfName`, and `IfMTU` from the `-genconf` template
  and the sample `ydn64.conf`. All three are dead in this app: `AdminListen`
  and `IfName` are always force-overridden to `"none"` (no admin socket, no
  TUN interface by design), and `IfMTU` only affects a real TUN device's
  MTU, which is never read anywhere in the codebase. Existing config files
  that still set these keys continue to work unchanged (harmlessly ignored
  or overridden).
- Changed the default `MulticastInterfaces` entry generated by `-genconf`
  to `Beacon: false`, so nodes no longer
  announce themselves via multicast by default. `Listen: true` is unchanged,
  so the node still discovers other nodes that do announce.
- Added a `YDN64_PRIVATE_KEY` environment variable override alongside the
  existing `YDN64_PEERS` / `YDN64_ALLOWED_SOURCES`. Setting it replaces the
  node's identity at runtime and automatically recomputes `Nat64Pool` and
  `Dns64Listen` to match, resetting `Dns64Zones` to the single default
  synthesis zone with the correct prefix (custom zones require a persisted
  config file instead). `-genconf` also honors all three variables now, so
  a container can run with a fully working identity/peers/allowlist from
  environment variables alone, with no config file or volume required.

