# gVisor migration & upgrade notes (condensed record)

Durable outcomes of the 2026-08 gVisor migration plan (tasks T1–T7). All
tasks are DONE and merged; implementation details live in the code, AGENTS.md
gotchas, and git history. This file keeps only facts not recorded elsewhere:
benchmark data, rejected-alternative rationale, and the upstream-upgrade
blocker assessment.

## T6 — congestion control decision

- gVisor's default TCP factory (`tcp.NewProtocol`) selects **Reno**;
  `NewProtocolCUBIC` selects CUBIC; runtime switching is also possible via
  `SetTransportProtocolOption`. ydn64 uses CUBIC.
- Harness benchmark (B → NAT64 TCP → loopback sink in A, 98 MB × 5 runs per
  variant, freshly built images): Reno 808–905 ms, CUBIC 799–867 ms —
  **parity** (~115 MB/s) as theory predicts for lossless paths. The switch is
  a bet on lossy high-BDP Yggdrasil tunnels where CUBIC's post-loss recovery
  dominates; it is also the Linux default since 2008. No config knob was
  added (no measurable user-facing effect to expose).
- Measurement lesson: an initial "Reno = 1.65 s" reading was a fresh-boot
  warm-up artifact disproven by a rebuilt control — re-baseline before
  crediting an algorithm change.
- **`tcpip.MTUProbingOption` does not exist** in any gVisor version we ship
  or assessed (verified by grep over pinned + latest trees). Black-hole
  detection is impossible today; PMTUD relies on in-band ICMPv6 Packet Too
  Big, which the netstack does emit.

## T7 — IPTables/nftables for AllowedSources: REJECTED (re-checked vs latest)

- **iptables**: hot-reload would work (`IPTables.ForceReplaceTable` swaps
  tables under a mutex), silent-drop semantics match today's behavior, but it
  adds conntrack machinery and a rule-encoding layer for zero coverage win.
- **nftables**: wired into delivery since ~2025H2 (`stack.SetNFTables`,
  input/forward/output/NAT hooks consulted from ipv6.go) with full rule
  mutation APIs — but the package doc still states "**not yet thread-safe**"
  (TODO b/345684870: "must be done before the package is used in
  production"), rules are managed via raw netlink attribute encoding
  (`nlmsg`), and there is no simple programmatic API. Disqualifying until the
  thread-safety TODO lands.
- **Version-independent blocker**: NAT64's ICMP interceptor consumes packets
  inside the YggdrasilNIC read loop BEFORE gVisor delivery, so no firewall
  layer can ever cover ICMP — manual `isAllowed` checks must survive
  regardless, leaving two enforcement mechanisms either way.
- Re-revisit if: upstream lands nftables thread-safety, or AllowedSources
  policy grows features that genuinely need firewall semantics (conntrack,
  port ranges, rate limiting).

## gVisor upgrade assessment (2026-08-23)

Pinned version `v0.0.0-20250812171554-968e93457fe6` (2025-08-12) is
effectively the **last Go-module-consumable gVisor release**. Every later
snapshot/tag fails plain `go build ./...` for importers of
`pkg/tcpip/stack`, for two independent upstream reasons:

1. **Missing Bazel-generated files**: since `release-20250820.0`, the module
   no longer ships stateify/go_generics outputs (`view_list.go`,
   `chunk_refs.go`, `*_state_autogen.go` — ~484 files in our tree vs ~33 in
   new ones). Core packages fail with `undefined: ViewList / waiterEntry /
   chunkRefs ...`.
2. **Invalid test package name**: `pkg/tcpip/stack/bridge_test.go` declares
   `package bridge_test` inside the `stack` package directory ("found
   packages stack and bridge" toolchain error). Present in every release
   since `release-20251020.0`; known upstream (issues #11511/#11531, fix PRs
   #10593/#11699 closed unmerged) because Bazel CI never scans it.

Verified empirically across proxy and direct-from-VCS downloads of 15+ tags.
The new `stateify` binary does build standalone, so both tools are runnable —
the cost is replicating the pipeline over every imported package.

Options when a newer netstack is needed:

- **(a) In-repo fork**: source under `third_party/gvisor`, run codegen, fix
  the package name, wire via `replace`. Hermetic; upgrades repeat the
  procedure.
- **(b) Vendor + post-vendor codegen script**: `go mod vendor` strips dep
  `_test.go` files automatically (fixes #2); run the codegen tools into
  `vendor/` afterwards (fixes #1). Needs a wrapper script for repeatability.
- **(c) Stay pinned**, watch issues #11531/#11699 until upstream restores
  module completeness. Cheapest; current pin is stable and well understood.

## API corrections vs the original task text (keep for future upgrades)

The migration task list claimed APIs were "verified against the vendored
version", but several were wrong — always re-check against actual module
source before coding:

- No `tcpip.KeepaliveEnabledOption` and no `Endpoint.SetSockOptBool`;
  keepalive is enabled via `Endpoint.SocketOptions().SetKeepAlive(true)`.
- No `tcpip.MTUProbingOption` (see T6 above).
- `udp.ForwarderRequest` has no payload accessor and no `Complete()`
  (documented in AGENTS.md too).
- `PacketEndpoint` is a one-method interface (no LinkEndpoint methods);
  packet endpoints require `NICOptions.DeliverLinkPackets`, and only
  ETH_P_ALL-style registrations see outbound packets.
- `Stack.Stats()` returns a value; ICMP counters live under `Stats.ICMP.V6`.
