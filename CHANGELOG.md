# Changelog

All notable changes to `ydn64` are recorded here. This file is updated
manually (not auto-generated) whenever a change is worth calling out to
users or future contributors — new features, behavior changes, config
schema changes, fixed bugs with user-visible impact. Not every commit needs
an entry; skip pure refactors, typo fixes, or internal test harness changes
unless they affect users.

Entries are grouped under an unreleased heading until a release is cut, then
moved under the corresponding version heading.

## [Unreleased]

ICMP error translation: traceroute and PMTUD now work through NAT64.

- **RFC 7915 §4.2/§4.3 + RFC 5508 REQ-3/REQ-4 — ICMPv4 error translation**.
  ydn64 no longer discards ICMPv4 errors about traffic it sent toward real
  IPv4 destinations. Destination Unreachable, Time Exceeded and Parameter
  Problem messages are demuxed against live NAT64 sessions (UDP tuples and
  allocated Echo identifiers), translated per the RFC 7915 §4.2 type/code
  tables (including Packet Too Big MTU adjustment with RFC 1191 plateau
  fallback), and injected back to the originating Yggdrasil client with the
  quoted packet reconstructed to its original tuple. **IPv6-side PMTUD now
  converges for UDP flows, closed v4 ports fail fast instead of hanging,
  and every ICMPv4 error the IPv4 path produces for a tracked flow reaches
  the client as translated ICMPv6.** (Classic hop-by-hop `traceroute`
  remains limited: re-originated datagrams start with a fresh IPv4 TTL, so
  early-hop Time Exceeded replies cannot occur.) Synthesised errors are
  rate-limited and truncated to the 1280-byte minimum-IPv6-MTU budget;
  TCP is deliberately excluded because proxied connections terminate twice
  and the OS stack consumes v4-side TCP errors itself.
- **RFC 4443 §3.1 — generated Destination Unreachables**: UDP flows whose
  outbound dial fails, or whose OS socket surfaces a kernel-received v4
  Port Unreachable, are reported to the client as ICMPv6 Destination
  Unreachable instead of silently blackholing.

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

