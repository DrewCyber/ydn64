# ydn64 — RFC Conformance Assessment: Stateful NAT64 & DNS64

**Date:** 2026-07-25
**Scope:** `src/nat64`, `src/dns64`, `src/netstack`, `src/config`
**Nature:** Assessment only — no code changed, nothing implemented.
**Companion document:** [tmp/code-audit-2026-07-25.md](tmp/code-audit-2026-07-25.md) (general code audit; some findings overlap and are cross-referenced).

---

## 1. Method and framing

Each normative requirement is classified as:

| Mark | Meaning |
|---|---|
| ✅ **Full** | Implemented and conformant |
| 🟡 **Partial** | Implemented for a subset of cases, or behaviourally close but not per spec |
| ❌ **Missing** | Not implemented; a conformant implementation would need it |
| ⚠️ **Deviation** | Implemented differently *on purpose*; conflicts with a MUST/SHOULD but is arguably justified by ydn64's use case |
| **N/A** | Out of scope for ydn64's architecture or deployment model |

### 1.1 The single most important framing point

**RFC 6146 specifies a *packet translator*. ydn64 is a *transport-layer proxy* for TCP, and a *socket-based relay* for UDP and ICMP Echo.**

| | RFC 6146 NAT64 | ydn64 |
|---|---|---|
| TCP | Translates each IPv6 segment into an IPv4 segment; one end-to-end TCP connection | Terminates TCP inside gVisor (`tcp.NewForwarder`), opens a **separate** OS TCP connection, copies bytes (`proxyTCP`) |
| UDP | Translates each datagram | Terminates at the NIC interceptor, re-originates via `net.DialUDP`, synthesises a fresh IPv6 reply packet |
| ICMP Echo | Translates the packet, rewriting the Identifier | Re-originates via a raw ICMPv4 socket, synthesises a fresh ICMPv6 Echo Reply |
| Address/port mapping | Explicit BIB + session tables owned by the NAT64 | Implicit — the host OS ephemeral port allocator |

This is a legitimate and pragmatic design for a userspace, no-root, TUN-less node — but it means **an entire class of RFC 6146 / RFC 7915 requirements is architecturally unreachable without a rewrite**, not merely unimplemented. Sections 4, 6 and 8 below distinguish "not yet done" from "not possible in this architecture".

Practically, the proxy architecture loses end-to-end: TCP sequence numbers, TCP options (MSS, SACK, window scale, Fast Open), Hop Limit ↔ TTL semantics, Traffic Class ↔ DSCP, ECN, the DF bit, and IPsec AH/ESP-transport (the last is lost by *any* NAT64 — RFC 6146 §5.1).

---

## 2. RFC reference list

**The canonical, status-annotated list now lives in [context/RFCs.txt](context/RFCs.txt)** — it was updated on 2026-07-25 from this assessment and carries a `[DONE]` / `[PARTIAL]` / `[TODO]` / `[DEVIATION]` / `[DEFERRED]` / `[N/A]` mark per RFC and per requirement. Keep the two in sync: this section is the rationale, `context/RFCs.txt` is the working checklist.

The original version of that file was accurate but incomplete in two respects, both of which matter materially for ydn64: it omitted the **behavioural-requirements BCPs that RFC 6146 references normatively** (RFC 4787 / 5382 / 5508 — these are where the actual mapping/filtering/timer MUSTs live), and it omitted the **DNS protocol RFCs** that RFC 6147 §5.4 pulls in by reference. Both groups are now present; `context/RFCs.txt` §F records the full set of corrections.

### 2.1 Core normative — must implement against

| RFC | Title | Status | Relevance to ydn64 |
|---|---|---|---|
| **RFC 6146** | Stateful NAT64 | Standards Track | **Primary NAT64 spec** |
| **RFC 6147** | DNS64 | Standards Track | **Primary DNS64 spec** |
| **RFC 6052** | IPv6 Addressing of IPv4/IPv6 Translators | Standards Track | Address format; `Nat64Pool`, `makeSynthesisedAAAA`, `reversePTR` |
| **RFC 7915** | IP/ICMP Translation Algorithm | Standards Track | Obsoletes RFC 6145; header translation. RFC 6146 §3.7 defers to it |
| **RFC 8200** | IPv6 Specification | Internet Standard | §8.1 upper-layer checksums (pseudo-header, zero-checksum rule) |
| **RFC 4443** | ICMPv6 | Internet Standard | Echo, Packet Too Big, Destination Unreachable |

> Note: the original `context/RFCs.txt` listed RFC 6145 as current. It was **obsoleted by RFC 7915** (2016) — corrected in the updated file. RFC 6146 §3.7 still textually references 6145; read that as 7915.

### 2.2 Behavioural requirements — normatively referenced by RFC 6146 (missing from the original list)

| RFC | Title | Why it matters |
|---|---|---|
| **RFC 4787** (BCP 127) | NAT Behavioral Requirements for Unicast UDP | Endpoint-Independent Mapping, UDP timer floors, port-preservation. RFC 6146 §5.2 makes EIM a **MUST** by reference |
| **RFC 5382** (BCP 142) | NAT Behavioral Requirements for TCP | TCP_EST / TCP_TRANS / TCP_INCOMING_SYN timer values |
| **RFC 5508** (BCP 148) | NAT Behavioral Requirements for ICMP | ICMP Query mapping, ICMP_DEFAULT = 60 s, ICMP error handling |
| **RFC 5389 / RFC 8489** | STUN | Context: why EIM matters (ICE/WebRTC) |

### 2.3 DNS protocol RFCs pulled in by RFC 6147 §5.4 (missing from the original list)

| RFC | Title | Relevance |
|---|---|---|
| **RFC 1034 / 1035** | DNS concepts / implementation | Message format, 512-byte UDP limit, TC bit, TCP framing |
| **RFC 3596** | DNS Extensions to Support IPv6 | AAAA RR; §2.5 `ip6.arpa` nibble format (implemented in `ptrToIPv6`) |
| **RFC 6891** | EDNS(0) | Obsoletes RFC 2671, which RFC 6147 §5.4 cites. Requestor payload size |
| **RFC 2308** | Negative Caching of DNS Queries | SOA TTL, used by RFC 6147 §5.1.7's TTL rule |
| **RFC 5452** | Making DNS Resilient against Forged Answers | Query ID + source-port randomisation |
| **RFC 7766** | DNS Transport over TCP | TCP is a **MUST** for DNS servers; idle-timeout guidance |
| **RFC 4074** | Common Misbehavior Against DNS Queries for IPv6 Addresses | Motivates RFC 6147 §5.1.2's RCODE handling |
| **RFC 4033/4034/4035** | DNSSEC | RFC 6147 §5.5 |
| **RFC 8482** | Minimal Responses to DNS ANY | Relevant to ydn64's ANY→AAAA rewrite |
| **RFC 5358** (BCP 140) | Preventing Use of Recursive Nameservers in Reflector Attacks | Directly applicable — see audit §1.4 |
| **RFC 7873 / 9018** | DNS Cookies | Optional anti-spoofing/amplification defence |
| **RFC 7871** | EDNS Client Subnet | Optional; affects CDN geolocation through the forwarder |

### 2.4 Prefix discovery & client-side integration

| RFC | Title | Applicability to ydn64 |
|---|---|---|
| **RFC 7050** | Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis | Via `ipv4only.arpa` — see §11.1 |
| **RFC 8880** | Special Use Domain Name `ipv4only.arpa` | Updates 7050; local answering |
| **RFC 8781** | Discovering PREF64 in Router Advertisements | Preferred by modern iOS/Android. **N/A** — TUN-less ydn64 sends no RAs |
| **RFC 7225** | Discovering NAT64 Prefixes with PCP | Not implemented |
| **RFC 6877** | 464XLAT | Context for CLAT-equipped clients |
| **RFC 8305** | Happy Eyeballs v2 | Client-side; §7 covers DNS64/NAT64 interaction |

### 2.5 Informational / operational (no implementation obligations)

RFC 6144 (Framework), RFC 6889 (NAT64 operational implications), RFC 7269 (deployment experience), RFC 6586 (IPv6-only experiences), RFC 6384 (FTP ALG for NAT64 — optional, not implemented), RFC 6219 & RFC 7757 (stateless/IVI/EAM — **N/A**, ydn64 is stateful).

---

## 3. Executive summary

### NAT64 (RFC 6146)

| Verdict | Count | Highlights |
|---|---|---|
| ✅ Full | 3 | Pref64 receive-side matching, `/96` address extraction, ICMPv6 Echo Reply checksum |
| 🟡 Partial | 6 | Session tables (no BIB), UDP handling, ICMP Query handling, address generation, outgoing tuple |
| ❌ Missing | 8 | Fragment handling, hairpinning, Pref64-source drop, TCP state machine, ICMP error translation & generation, port-allocation rules, EIM |
| ⚠️ Deviation | 2 | Proxy-instead-of-translate; connected-socket filtering (stricter than RECOMMENDED) |

**Hard MUST violations (NAT64):**
1. **RFC 6146 §5.2 / §1.1 — Endpoint-Independent Mapping is a MUST; ydn64 provides Address-and-Port-Dependent Mapping.** Breaks ICE/STUN/WebRTC/P2P.
2. **RFC 6146 §3.5 / §5.4 — "the NAT64 MUST silently discard all incoming IPv6 packets containing a source address that contains the Pref64::/n"**, to prevent hairpinning loops. Not implemented.
3. **RFC 6146 §3.4 — "The NAT64 MUST handle fragments"** (including out-of-order). Not implemented.
4. **RFC 6146 §3.5.1 + §4 — UDP session lifetime "MUST NOT be less than UDP_MIN" (2 minutes).** `Nat64UdpTimeout` defaults to **30 s** and permits any positive value.
5. **RFC 8200 §8.1 — a computed UDP checksum of zero MUST be transmitted as `0xFFFF`.** `ipv6UpperLayerChecksum` returns `^sum` unconditionally.

### DNS64 (RFC 6147)

| Verdict | Count | Highlights |
|---|---|---|
| ✅ Full | 5 | Timeout→SERVFAIL, RFC 6052 `/96` synthesis, non-Pref64 PTR pass-through, sequential querying, TCP transport |
| 🟡 Partial | 7 | CNAME handling, PTR, response assembly, error handling, prefix algorithm |
| ❌ Missing | 6 | Per-IPv4-range prefix selection, TTL rule, exclusion set, additional-section pass-through, EDNS0/truncation, DNSSEC |
| ⚠️ Deviation | 3 | Synthesis-when-real-AAAA-exists as default; A-record suppression; zone-miss NXDOMAIN |

**Hard MUST violations (DNS64):**
1. **RFC 6147 §5.1.7 — the synthetic AAAA's NAME "is set to the NAME field from the A record".** `synthesiseFromA` uses the *queried* name and discards the CNAME chain (CNAME flattening).
2. **RFC 6147 §5.1.7 — TTL "MUST be set to the minimum of the TTL of the original A RR and the SOA RR".** ydn64 emits `miekg/dns`'s default (3600 s) for every synthetic record.
3. **RFC 6147 §5.1.7 — "The DNS64 MUST check each A RR against configured IPv4 address ranges and select the corresponding IPv6 prefix".** No IPv4-range checking exists. (Same root cause as audit §1.1.)
4. **RFC 6147 §5.1.2 — NXDOMAIN (RCODE=3) is handled per normal DNS operation, i.e. returned to the client.** ydn64 converts NXDOMAIN into NOERROR with an empty answer, breaking negative caching.
5. **RFC 6147 §5.3.2 / §5.4 — the authority and additional sections MUST be passed/copied from the upstream response.** `handleAAAA` builds its response from the *request* and discards both sections.
6. **RFC 6147 §5.3.3 — "All other RRs MUST be returned unchanged. This includes responses to queries for A RRs."** `handleA` blanks the Answer when `return-ipv4-addresses: false`. *(⚠️ deliberate)*
7. **RFC 6147 §5.1 — "DNS64 operation for classes other than IN is undefined, and a DNS64 MUST behave as though no DNS64 function is configured."** `qclass` is never inspected.
8. **RFC 5452 §9.2 — upstream query IDs must be unpredictable.** ydn64 forwards the client's transaction ID upstream verbatim. (Audit §1.2.)

---

## 4. RFC 6146 — Stateful NAT64, section by section

### 4.1 §3 preamble — required data structures

> "A NAT64 uses the following conceptual dynamic data structures: UDP BIB, UDP Session Table, TCP BIB, TCP Session Table, ICMP Query BIB, ICMP Query Session Table … NAT64 implementations are free to use different data structures but they MUST store all the required information, and the externally visible outcome MUST be the same."

| Structure | ydn64 | Verdict |
|---|---|---|
| UDP Session Table | `Service.sessions` (`sessionKey` = src6+srcPort+dst4+dstPort) | 🟡 Partial — session-only, no BIB |
| UDP BIB | none | ❌ Missing |
| TCP Session Table | Implicit in gVisor endpoint + OS socket | 🟡 Partial |
| TCP BIB | none | ❌ Missing |
| ICMP Query Session Table | `Service.icmpSessions` (`{dstAddr, id}`) | 🟡 Partial — keyed on the *client's* ID, not an allocated one |
| ICMP Query BIB | none | ❌ Missing |

The escape clause ("free to use different data structures") does **not** rescue this, because the *externally visible outcome* differs: without a BIB there is no endpoint-independent mapping (§4.6).

### 4.2 §3.4 — Determining the incoming tuple

| Requirement | ydn64 | Verdict |
|---|---|---|
| 5-tuple for un-fragmented TCP/UDP | `interceptUDPPacket` extracts src6/srcPort/dst6/dstPort; TCP via gVisor `ForwarderRequest.ID()` | ✅ Full |
| 3-tuple for ICMP Query | `interceptICMPPacket` extracts src6/dst6/Identifier | ✅ Full |
| 5-tuple from **embedded** packet in an ICMP error | Not implemented | ❌ Missing |
| **"The NAT64 MUST handle fragments"**, incl. out-of-order, with a bounded resource budget and ≥ FRAGMENT_MIN (2 s) reassembly window | Fragment headers (NH 44) aren't even recognised — `interceptPacket` switches on `pkt[6]` only, so a fragmented packet falls through to gVisor and is dropped | ❌ **Missing (MUST)** |
| MAY require the L4 header in the offset-0 fragment | N/A | N/A |
| IPv4 UDP with zero checksum MUST be reassembled and checksummed | Handled by the host kernel (ydn64 uses OS sockets) | N/A |
| Non-TCP/UDP/ICMPv6 last Next Header → SHOULD discard **and SHOULD send ICMPv6 Dest Unreachable Code 4 (Port Unreachable)** | Falls through to gVisor, which drops it silently; no ICMPv6 error | 🟡 Partial |

> **Note on extension headers generally:** `interceptPacket` reads only the fixed header's Next Header byte. A packet carrying Hop-by-Hop (0), Routing (43), Fragment (44), or Destination Options (60) is never recognised as UDP/ICMPv6. Also cross-referenced as audit §5.2.

### 4.3 §3.5 — Filtering and updating binding/session information

| Requirement | ydn64 | Verdict |
|---|---|---|
| **"MUST silently discard all incoming IPv6 packets containing a source address that contains the Pref64::/n"** (anti-hairpin-loop, per §5.4) | No such check anywhere. A peer sending from `pool6::<v4>` is only stopped incidentally, if that address happens to fall outside `AllowedSources` | ❌ **Missing (MUST)** — see §4.9 |
| "MUST only process incoming IPv6 packets that contain a destination address that contains Pref64::/n" | `s.pool6Net.Contains(dstIP)` in all three interceptors | ✅ Full |
| "MUST only process incoming IPv4 packets that contain a destination address that belongs to the IPv4 pool" | Enforced by the OS socket layer (connected sockets / bound raw socket) | ✅ Full (by delegation) |

### 4.4 §3.5.1 / §3.5.1.1 — UDP session handling and address allocation

| Requirement | ydn64 | Verdict |
|---|---|---|
| Create/refresh session on each IPv6→IPv4 packet | `forwardUDP` + `atomic.StoreInt64(&sess.lastSeenNs, …)` | ✅ Full |
| Session lifetime **MAY be configurable** | `Nat64UdpTimeout` | ✅ Full |
| Default **SHOULD be at least UDP_DEFAULT (5 min)** | Default **30 s** | ❌ **Violation** |
| Lifetime **MUST NOT be less than UDP_MIN (2 min)** | 30 s default; `Validate()` accepts any value > 0 | ❌ **Violation (MUST)** |
| Inbound IPv4 with no BIB entry → drop, MAY send ICMP Type 3 | Connected socket drops it; no ICMP sent | 🟡 Partial |
| §3.5.1.1: reuse the same IPv4 address `T` for all sessions from the same `S'` | Every session gets an independent `net.DialUDP` socket | ❌ Missing |
| §3.5.1.1: SHOULD preserve the well-known/ephemeral **port range** | OS-assigned ephemeral port, always in 32768–60999 | ❌ Missing |
| §3.5.1.1: SHOULD preserve **port parity** (RFC 4787 §4.2.2) | Not attempted | ❌ Missing |
| Allocated `(T,t)` MUST be unique in the BIB | Guaranteed by the OS | ✅ Full (by delegation) |
| On allocation failure, SHOULD send ICMPv6 Dest Unreachable Code 3 | `DialUDP` error → silent `return` | ❌ Missing |

### 4.5 §3.5.2 — TCP session handling

RFC 6146 §3.5.2.2 mandates a **7-state machine** (CLOSED, V4 INIT, V6 INIT, ESTABLISHED, V4 FIN RCV, V6 FIN RCV, V6+V4 FIN RCV, TRANS) driven by observed SYN/FIN/RST segments.

| Requirement | ydn64 | Verdict |
|---|---|---|
| Full TCP state machine | **None.** gVisor terminates the IPv6 side; the IPv4 side is an independent OS connection. Neither side's flags are inspected | ❌ Missing (architectural) |
| V6-initiated connections | Works | ✅ Full (behaviourally) |
| V4-initiated connections (V4 INIT state, simultaneous open, TCP_INCOMING_SYN=6 s packet storage) | Not supported — there is no inbound IPv4 listener | ❌ Missing |
| ESTABLISHED lifetime ≥ TCP_EST (2 h) | Effectively infinite (no idle timeout at all) | 🟡 Partial — satisfies the floor, but is a resource leak (audit §5.4) |
| TRANS lifetime = TCP_TRANS (4 min) after RST | No RST tracking | ❌ Missing |
| Probe packet on lifetime expiry | Not implemented | ❌ Missing |
| §3.5.2.3 allocation rules (address reuse, port range, uniqueness) | Same as UDP — delegated to the OS | ❌ Missing |

> **Consequence worth calling out:** ydn64 cannot support *any* IPv4-initiated flow, even with pre-existing state. That rules out the "IPv6 Internet to an IPv4 network" scenario of RFC 6144, and rules out ICE/STUN hole-punching entirely (compounding §4.6).

### 4.6 §5.2 / §1.1 — Mapping behaviour (Endpoint-Independent Mapping)

> RFC 6146 §5.2: *"a NAT64 **MUST** offer 'Endpoint-Independent Mapping'. This means: For any IPv6 packet with source (S'1,s1) and destination (Pref64::D1,d1) that creates an external mapping to (S1,s1v4),(D1,d1), for any subsequent packet from (S'1,s1) to (Pref64::D2,d2) that creates an external mapping to (S2,s2v4),(D2,d2), within a given binding timer window, **(S1,s1v4) = (S2,s2v4)** for all values of D2,d2."*

ydn64 keys `sessionKey` on `{srcAddr, srcPort, dstAddr, dstPort}` and calls `net.DialUDP(…, nil, dstUDPAddr)` per session. The same internal `(S',s)` sending to two different IPv4 destinations gets **two different ephemeral source ports**.

**Verdict: ❌ MUST violation.** ydn64 exhibits *Address-and-Port-Dependent Mapping* (classic "symmetric NAT"). Consequences:

- STUN reports a different reflexive transport address per STUN server → ICE (RFC 8445) cannot form candidate pairs.
- WebRTC, most P2P/VoIP, and NAT-traversal-dependent protocols fail through ydn64.
- RFC 6146 §1.1's headline claim — *"NAT64 is compatible with current NAT traversal techniques, such as ICE"* — does not hold for ydn64.

**Fixing this requires the BIB from §4.1**: a managed pool of source ports bound once per `(S',s)` and reused across destinations, plus an unconnected socket per BIB entry (or a raw socket). It is a substantial rework, and it interacts with the destination-filter work in audit §1.1.

### 4.7 §3.5.3 — ICMP Query session handling

| Requirement | ydn64 | Verdict |
|---|---|---|
| ICMPv6 Informational → ICMPv4 Query translation | Echo Request (128) → ICMPv4 Echo (8); Echo Reply (0) → ICMPv6 Echo Reply (129) | 🟡 Partial — Echo only; other Informational types unhandled |
| **BIB maps `(X',i1) <--> (T,i2)` — a NAT64-allocated ICMPv4 Identifier `i2`** | The client's Identifier is used verbatim as `i2` and as the session key | ❌ **Missing** — see audit §1.3 for the resulting cross-peer reply hijack |
| Reuse of the same `T` as other BIBs for the same `X'` | N/A (no BIB) | ❌ Missing |
| Session lifetime default **ICMP_DEFAULT = 60 s** | Hardcoded **30 s** (`icmpSessionTimeout` in `service.go`) | ❌ Violation |
| Maximum lifetime **SHOULD be configurable** | Not configurable | ❌ Missing |
| Inbound ICMPv4 with no BIB entry → drop, MAY send ICMP Type 3 Code 1 | Silently ignored in `icmpReplyLoop` | 🟡 Partial |
| Local policy MAY filter ICMPv6 Informational | Covered by `AllowedSources` | ✅ Full |

### 4.8 §3.5.4 / RFC 6052 — Address representation

| Requirement | ydn64 | Verdict |
|---|---|---|
| Algorithm MUST be reversible | `pool6 ‖ v4` ↔ `dstSlice[12:16]`, and `reversePTR` | ✅ Full |
| Input limited to IPv4 address + Pref64::/n | Yes | ✅ Full |
| `n` MUST be ≤ 96 | `/96` (derived from the node's Yggdrasil `/64` in `DeriveFromPrivateKey`) | ✅ Full |
| "MUST support the algorithm … defined in Section 2.3 of [RFC6052]" | Only the `/96` case of RFC 6052 §2.2. `/32`, `/40`, `/48`, `/56`, `/64` unimplemented; the `12` in `reversePTR` and `dstSlice[12:16]` in tcp/udp/icmp are hardcoded | 🟡 Partial |
| If no prefix configured, SHOULD use the WKP `64:ff9b::/96` | Not supported; an NSP is always required (`Validate()` rejects an empty `Nat64Pool`) | ❌ Missing (SHOULD) |
| RFC 6052 §3.2 — an NSP must come from the operator's own address space | The pool is derived from the node's own `300::/64` Yggdrasil subnet | ✅ Full — **a genuinely elegant property of ydn64's design** |
| RFC 6052 §3.1 — the WKP MUST NOT represent non-global IPv4 addresses | Technically **N/A** (NSP in use), but the *spirit* is violated: nothing prevents `pool6::10.0.0.1` or `pool6::169.254.169.254` | ⚠️ See audit §1.1 |

### 4.9 §3.8 / §5.4 — Hairpinning

| Requirement | ydn64 | Verdict |
|---|---|---|
| §3.8 — if the translated packet's IPv4 destination is an address assigned to the NAT64 itself, re-inject it as an incoming packet | Not implemented; such a packet is dialled out to the host's own IPv4 address, hitting local services (audit §1.1) | ❌ Missing |
| §5.4 — **MUST drop IPv6 packets whose source address is in Pref64::/n** | Not implemented | ❌ **Missing (MUST)** |

> **Concrete exposure:** because §5.4's source check is absent *and* because ydn64's Pref64 is derived from its own `/64`, a peer can craft a packet with source `pool6::<v4>` and destination `pool6::<v4'>`. `isAllowed()` is the only gate. If `AllowedSources` includes `200::/7` (which the generated config's own comment suggests as an example), the check passes and the packet is relayed — the exact loop RFC 6146 §5.4 exists to prevent.

### 4.10 §4 — Protocol constants

| Constant | RFC 6146 §4 | ydn64 | Verdict |
|---|---|---|---|
| `UDP_MIN` | 2 min (floor) | `Nat64UdpTimeout` accepts any value > 0 | ❌ No floor enforced |
| `UDP_DEFAULT` | 5 min (default) | **30 s** | ❌ Violation |
| `TCP_TRANS` | 4 min | Not implemented | ❌ Missing |
| `TCP_EST` | 2 h | Infinite (no idle timeout) | 🟡 Above the floor, but unbounded |
| `TCP_INCOMING_SYN` | 6 s | N/A — no inbound IPv4 SYN handling | ❌ Missing |
| `FRAGMENT_MIN` | 2 s | N/A — no fragment handling | ❌ Missing |
| `ICMP_DEFAULT` | 60 s | **30 s**, hardcoded | ❌ Violation |

### 4.11 §5.3 — Attacks on NAT64

> *"NAT64 devices **MUST** implement proper protection against such attacks, for instance, allocating a limited amount of memory for fragmented packet storage."*

ydn64 has no session cap, no per-source quota, no memory budget (audit §1.4, §4.3). **❌ MUST violation.**

RFC 6146 §5.3 also notes a NAT64 **MAY** decline to extend a session's lifetime on packets arriving from the external interface, to resist keep-alive attacks. `udpReplyLoop` currently refreshes `lastSeenNs` on every inbound IPv4 datagram — the exact behaviour the RFC warns about. Worth an explicit configuration knob.

---

## 5. RFC 7915 — IP/ICMP Translation Algorithm

RFC 6146 §3.7 delegates all packet translation to RFC 7915 (as RFC 6145 at the time of writing). ydn64 **does not translate packets — it re-originates them**, so this entire RFC is architecturally bypassed.

| RFC 7915 requirement | ydn64 | Verdict |
|---|---|---|
| §4.1 IPv4→IPv6 header translation (Traffic Class ← ToS/DSCP, Hop Limit ← TTL−1, Payload Length, Next Header) | Synthesised headers use **fixed** Traffic Class 0, **fixed** Hop Limit 64, Flow Label 0 (`buildIPv6UDPPacket`, `buildIPv6ICMPEchoReplyPacket`) | ❌ Not translated |
| §5.1 IPv6→IPv4 header translation | The OS builds the IPv4 header from scratch | ❌ Not translated |
| Hop Limit / TTL decrement across the translator | Never propagated | ❌ Missing |
| ECN codepoint preservation | Lost | ❌ Missing |
| DF bit / MTU handling; **ICMPv6 Packet Too Big generation** | Not implemented | ❌ Missing |
| §4.2 / §5.2 ICMP translation (Dest Unreachable, Time Exceeded, Parameter Problem, PTB — including the embedded packet) | **Echo/Echo Reply only** | ❌ Missing |
| Upper-layer checksum recomputation for the IPv6 pseudo-header | `ipv6UpperLayerChecksum` — correct construction per RFC 8200 §8.1 | ✅ Full, **except** the zero→`0xFFFF` rule (see §7) |

**User-visible consequences:**
- `traceroute` / `tracepath` through NAT64 does not work (no Time Exceeded translation).
- Path MTU Discovery is broken in both directions (no PTB).
- Connections to unreachable IPv4 hosts hang until timeout instead of failing fast (no Destination Unreachable).
- DSCP-based QoS markings are erased.

---

## 6. RFC 4787 / 5382 / 5508 — Behavioural requirements

These BCPs are normative references of RFC 6146, so their REQs are binding.

### 6.1 RFC 4787 (UDP)

| REQ | Requirement | ydn64 | Verdict |
|---|---|---|---|
| REQ-1 | UDP mapping MUST be "Endpoint Independent" | Address-and-port-dependent | ❌ **Violation** |
| REQ-3 | SHOULD preserve port parity / range | Not attempted | ❌ Missing |
| REQ-5 | UDP mapping timer MUST NOT expire in < 2 min; default SHOULD be ≥ 5 min | 30 s default | ❌ **Violation** |
| REQ-6 | SHOULD support configurable timers | `Nat64UdpTimeout` (SIGHUP-reloadable) | ✅ Full |
| REQ-8 | Filtering SHOULD be Endpoint-Independent (or Address-Dependent if stringency is needed) | Connected `net.DialUDP` gives **Address-and-Port-Dependent Filtering** — stricter than either | ⚠️ Deviation (fail-safe direction, but blocks NAT traversal) |
| REQ-9 | NAT MUST support hairpinning | Not implemented | ❌ Missing |

### 6.2 RFC 5382 (TCP)

| REQ | Requirement | ydn64 | Verdict |
|---|---|---|---|
| REQ-1 | TCP mapping MUST be Endpoint-Independent | Address-and-port-dependent | ❌ Violation |
| REQ-2 | MUST support all valid TCP packet exchanges, incl. simultaneous open | No state machine | ❌ Missing |
| REQ-3 | Inbound SYN for a non-existent mapping MUST be silently dropped **or** held ≥ 6 s | No inbound path | ❌ Missing |
| REQ-5 | Established-connection idle timeout ≥ 2 h 4 min | Infinite | 🟡 Above floor, unbounded |
| REQ-8 | MUST support hairpinning | Not implemented | ❌ Missing |

### 6.3 RFC 5508 (ICMP)

| REQ | Requirement | ydn64 | Verdict |
|---|---|---|---|
| REQ-1 | ICMP Query mapping with a **NAT-assigned** Identifier | Client's Identifier used verbatim | ❌ Violation |
| REQ-2 | ICMP Query session timeout ≥ 60 s | 30 s | ❌ Violation |
| REQ-3/4 | ICMP **error** messages MUST be translated and forwarded | Not implemented | ❌ Missing |
| REQ-10 | MUST support ICMP Query hairpinning | Not implemented | ❌ Missing |

---

## 7. RFC 8200 / RFC 4443 — IPv6 and ICMPv6

| Requirement | ydn64 | Verdict |
|---|---|---|
| RFC 8200 §8.1 — UDP checksum over the IPv6 pseudo-header is **mandatory** | Computed in `buildIPv6UDPPacket` | ✅ Full |
| RFC 8200 §8.1 — **"if that computation yields a result of zero, it MUST be changed to hex FFFF for placement in the UDP header"** | `return ^uint16(sum)` — no special case | ❌ **Violation** (≈1 in 65 536 reply packets discarded by the peer) |
| RFC 4443 §4.2 — ICMPv6 Echo Reply construction (Type 129, Identifier/Sequence/Data echoed) | `buildIPv6ICMPEchoReplyPacket` | ✅ Full |
| RFC 4443 — ICMPv6 checksum over the pseudo-header (zero is *valid* here) | Correct | ✅ Full |
| RFC 4443 §3.2 — **Packet Too Big** generation when a packet exceeds the next-hop MTU | Never generated; oversize replies are silently truncated by the MTU-sized read buffer | ❌ Missing |
| RFC 4443 §3.1 — **Destination Unreachable** generation (Code 3 Address Unreachable, Code 4 Port Unreachable) | Never generated | ❌ Missing |
| Inbound IPv6 Payload Length / UDP Length field validation | Never checked | ❌ Missing (audit §5.5) |

---

## 8. RFC 6147 — DNS64, section by section

### 8.1 §5 preamble

| Requirement | ydn64 | Verdict |
|---|---|---|
| "DNS64 operation for classes other than IN is undefined, and a DNS64 **MUST** behave as though no DNS64 function is configured" | `q.Qclass` is never inspected; a CH/HS query is synthesised like an IN query | ❌ **Violation (MUST)** |
| "SHOULD support mapping of separate IPv4 address ranges to separate IPv6 prefixes … to allow handling of special-use IPv4 addresses" | Prefixes are selected per **domain zone**, never per IPv4 range | ❌ Missing (SHOULD) |

### 8.2 §5.1.1 — Answer when AAAA data is available

> *"By default, DNS64 implementations **MUST NOT** synthesize AAAA RRs when real AAAA RRs exist."*

ydn64's generated default zone is `{domains: ["."], return-ipv4-addresses: false, prefix: <pool6>}`. `filterAAAA` **discards** every real AAAA when `returnIPv6Addresses == false`, and `handleAAAA` then synthesises from A records.

**Verdict: ⚠️ Deliberate deviation, non-conformant as a *default*.**

This is *explicitly anticipated* by RFC 6147 **Appendix A** ("Motivations and Implications of Synthesizing AAAA Resource Records when Real AAAA Resource Records Exist"), which describes it as something *"the administrator of a DNS64 service may want to enable"*. And ydn64's justification is strong: its clients reach the network only via Yggdrasil and typically have **no global IPv6 route**, so a real `2000::/3` AAAA is unusable to them.

The gap is that RFC 6147 permits this as an **opt-in**, whereas ydn64 makes it the **default and only** behaviour for the catch-all zone. Recommended resolution: keep the behaviour, but document it explicitly in README as a deliberate RFC 6147 §5.1.1 deviation with the Appendix A rationale, and make the conformant mode reachable via configuration.

### 8.3 §5.1.2 — Answer when there is an error

| Requirement | ydn64 | Verdict |
|---|---|---|
| **RCODE=3 (Name Error) handled per normal DNS operation — i.e. returned to the client** | `handleAAAA` ignores `upResp.Rcode`; an NXDOMAIN yields an empty Answer, falls through to the A query, and returns a response whose Rcode is inherited from the *request* (**0 / NOERROR**) | ❌ **Violation (MUST)** — NXDOMAIN is silently converted to NODATA, defeating client-side negative caching (RFC 2308) |
| Any other RCODE treated as RCODE=0 with an empty answer section | Achieved incidentally (Rcode is ignored) | ✅ Full |

### 8.4 §5.1.3 — Dealing with timeouts

| Requirement | ydn64 | Verdict |
|---|---|---|
| No answer before timeout → treat as RCODE=2 (Server failure) | `proxy.handle`: `if err != nil || resp == nil { r.SetRcode(req, dns.RcodeServerFailure) }` | ✅ Full |

### 8.5 §5.1.4 — Special exclusion set for AAAA records

| Requirement | ydn64 | Verdict |
|---|---|---|
| SHOULD provide a mechanism to specify IPv6 prefix ranges treated as an empty answer | No exclusion-set mechanism; `return-ipv6-addresses: false` is an all-or-nothing switch | ❌ Missing |
| SHOULD include `::ffff:0:0/96` in that range by default | Not implemented | ❌ Missing |
| MUST NOT return excluded AAAA records | Vacuously satisfied when synthesising; violated for `return-ipv6-addresses: true` zones (e.g. `.ygg`), which pass everything through including `::ffff:0:0/96` | 🟡 Partial |

> Worth noting: an exclusion set is the *conformant* mechanism to express exactly what ydn64 wants ("drop AAAA that my Yggdrasil-only clients can't reach"). Adding `Dns64ExcludedPrefixes` — defaulting to `::ffff:0:0/96` plus, optionally, `2000::/3` — would let ydn64 achieve its goal **within** RFC 6147 rather than by deviating from §5.1.1.

### 8.6 §5.1.5 — Dealing with CNAME and DNAME

| Requirement | ydn64 | Verdict |
|---|---|---|
| Follow the CNAME/DNAME chain to the first terminating A or AAAA | The upstream resolver returns the full chain; ydn64 re-queries the *original* name for A, which yields the chain again | 🟡 Partial (works, by delegation) |
| **"any chains of CNAME or DNAME RRs are included as part of the answer along with the synthetic AAAA"** | `synthesiseFromA` iterates only `*dns.A` and `continue`s past CNAMEs — the chain is **discarded** | ❌ **Violation** — CNAME flattening |

> Historical context: the repo memory records a real bug in this area (`passport.ya.ru` returning a bare CNAME with no address), fixed via `containsAAAA`. The fix was correct, but the resulting behaviour — return a synthetic AAAA at the queried name with the CNAME removed — is *flattening*, not RFC 6147 §5.1.5 chain preservation. It works for browsers; it will surprise anything that inspects the chain (some CDN tooling, DNSSEC-aware clients, `dig +trace` users).

### 8.7 §5.1.6 — Data for the answer when performing synthesis

| Requirement | ydn64 | Verdict |
|---|---|---|
| On empty AAAA answer, query A for the same name | `handleAAAA` does exactly this | ✅ Full |
| "If this new A RR query results in an empty answer or in an error, then **the empty result or error is used as the basis for the answer** returned to the querying client" | An A-query error → `return nil, err` → SERVFAIL (correct); an A-query **NXDOMAIN** → empty synthesis → NOERROR/empty (incorrect) | 🟡 Partial |
| "removing the A records that form the basis of the synthesis" | `synthesiseFromA` builds a fresh slice containing only AAAA | ✅ Full |

### 8.8 §5.1.7 — Performing the synthesis

| Field | RFC 6147 requirement | ydn64 | Verdict |
|---|---|---|---|
| NAME | **"set to the NAME field from the A record"** | `fmt.Sprintf("%s IN AAAA %s", name, …)` where `name` is `q.Name`, the **queried** name | ❌ **Violation** (differs whenever a CNAME is involved) |
| TYPE | 28 (AAAA) | ✅ | ✅ Full |
| CLASS | 1 (IN) | Hardcoded `IN` in the RR string | ✅ Full (but see §8.1 — qclass unchecked) |
| TTL | **min(TTL of the original A RR, TTL of the SOA RR); fallback min(A TTL, 600 s)** | Not set → `miekg/dns` default **3600 s** for every synthetic record | ❌ **Violation (MUST)** |
| RDLENGTH | 16 | ✅ | ✅ Full |
| RDATA | IPv6 representation per RFC 6052 | `makeSynthesisedAAAA` | ✅ Full (`/96` only) |
| — | **"The DNS64 MUST check each A RR against configured IPv4 address ranges and select the corresponding IPv6 prefix"** | No IPv4-range check exists; the zone's single prefix is applied to every A record, including RFC 1918 / loopback / `169.254.169.254` | ❌ **Violation (MUST)** — same root cause as audit §1.1 |

### 8.9 §5.1.8 — Querying in parallel

| Requirement | ydn64 | Verdict |
|---|---|---|
| MAY query AAAA and A in parallel | Sequential (AAAA, then A on miss) | ✅ Full (the RFC's own suggested trade-off) — but note the latency cost, audit §6.4 |

### 8.10 §5.2 — Generation of IPv6 representations

| Requirement | ydn64 | Verdict |
|---|---|---|
| Same algorithm as the paired NAT64 | Both derive from the same `Nat64Pool` / zone `prefix` | ✅ Full |
| Reversible | `reversePTR` | ✅ Full |
| `n` MUST be ≤ 96 | `/96` | ✅ Full |
| **MUST support the RFC 6052 §2 algorithm and it MUST be the default** | `/96` only | 🟡 Partial |
| If no prefix configured, MUST use the WKP `64:ff9b::/96` | Zones with no prefix return an empty answer instead | ❌ Missing |

### 8.11 §5.3.1 — PTR resource records

RFC 6147 offers exactly two conformant strategies and says *"A DNS64 server MUST provide one of these, and SHOULD NOT provide both."*

- **Option 1:** answer authoritatively for the Pref64 with locally appropriate RDATA.
- **Option 2:** synthesise a CNAME mapping the `ip6.arpa` name to the corresponding `in-addr.arpa` name.

ydn64's `handlePTR` implements **neither**: it rewrites the query to the real `in-addr.arpa` PTR, resolves it upstream itself, and returns the resulting PTR RDATA under the *original* `ip6.arpa` owner name.

**Verdict: 🟡 Partial.** Functionally this is the most useful of the three (the client gets real reverse data without a CNAME chain), and it is arguably *better* than Option 2. But it is not one of the two specified alternatives, and a DNSSEC-aware client will find an unsigned PTR at a name that should be either locally authoritative or a CNAME.

| Sub-requirement | ydn64 | Verdict |
|---|---|---|
| Strip `IP6.ARPA`, reverse per RFC 3596 §2.5 | `ptrToIPv6` | ✅ Full |
| Match against configured Pref64::/n | `reversePTR` iterates zone prefixes | ✅ Full |
| Also match **any** Pref64 used at the site, not just the locally configured one | Only locally configured zone prefixes | 🟡 Partial |
| Non-matching prefix → process as any other query | `passThrough` | ✅ Full |

### 8.12 §5.3.2 — Handling the additional section

| Requirement | ydn64 | Verdict |
|---|---|---|
| "DNS64 synthesis **MUST NOT** be performed on any records in the additional section" | No synthesis into Additional | ✅ Full |
| **"The DNS64 MUST pass the additional section unchanged"** | `handleAAAA` builds its response via `req.CopyTo(resp)` and sets only `resp.Answer` — the upstream `Ns` and `Extra` sections are **dropped entirely**, not passed through | ❌ **Violation (MUST)** |

### 8.13 §5.3.3 — Other resource records

| Requirement | ydn64 | Verdict |
|---|---|---|
| **"All other RRs MUST be returned unchanged. This includes responses to queries for A RRs."** | `handleA` sets `resp.Answer = []dns.RR{}` when `!z.returnIPv4Addresses` (the generated default) | ⚠️ **Deliberate deviation (MUST)** — justified: an IPv4 answer is unusable to an IPv6-only Yggdrasil client, and returning it invites the client to attempt an unroutable connection. Should be documented as a deviation |
| Unhandled qtypes forwarded verbatim | `passThrough` | ✅ Full |
| ANY (qtype 255) | Rewritten to AAAA, synthesised, then the question's Qtype restored to ANY | ⚠️ Deviation — see §9.5 |

### 8.14 §5.4 — Assembling a synthesized response

| Requirement | ydn64 | Verdict |
|---|---|---|
| Header fields set per usual recursive-server rules | `RecursionAvailable = true`, `Response = true`; **`Rcode` inherited from the request**, `Authoritative` never set | 🟡 Partial |
| Question section copied from the original query | `req.CopyTo(resp)` then `resp.Question[0].Qtype` forced to AAAA | ✅ Full |
| Answer section per §5.1.7 | Yes | 🟡 Partial (see §8.8) |
| **"The authority and additional sections are copied from the response to the final query that the DNS64 performed"** | Dropped | ❌ **Violation (MUST)** |
| **"subject to all the standard DNS rules, including truncation [RFC1035] and EDNS0 handling"** | No OPT parsing, no payload-size check, no `TC` bit, no `resp.Truncate()` | ❌ **Violation (MUST)** — audit §1.6 |

### 8.15 §5.5 / §6.2 — DNSSEC

ydn64 performs no DNSSEC validation and is best classified as RFC 6147 §3 **case 2/3: a security-oblivious (or security-aware, non-validating) DNS64**.

| Scenario (RFC 6147 §3) | Required behaviour | ydn64 | Verdict |
|---|---|---|---|
| DO=0 | DNSSEC not a concern; synthesis fine | Synthesises | ✅ Full |
| DO=1, CD=0, non-validating | Passes through; client is "out of luck" | Synthesises and returns unsigned data | 🟡 Acknowledged by the RFC as a known limitation |
| **DO=1, CD=1** | §5.5(3): *"MUST NOT perform synthesis. It MUST return the data to the query initiator."* | Synthesises regardless — `req.CopyTo(upReq)` forwards DO/CD upstream, then the answer is rewritten. A downstream validator will mark the data **bogus** | ❌ **Violation** |
| §5.5(1) | When validating with DO clear, MUST NOT set AD | ydn64 never validates; `handleAAAA` builds from the request so AD is 0. **But** `handleA`/`passThrough` return the upstream message verbatim, propagating the upstream's **AD bit** for data ydn64 did not validate | ❌ Violation (AD must not be asserted) |

**Minimum remediation without implementing DNSSEC:** honour `CD=1 && DO=1` by disabling synthesis and passing the upstream response through unmodified, and unconditionally clear the AD bit on any response ydn64 did not itself validate.

---

## 9. General DNS protocol conformance

| RFC | Requirement | ydn64 | Verdict |
|---|---|---|---|
| **RFC 1035 §4.2.1** | UDP messages > 512 B must be truncated with TC set | No truncation, no TC bit | ❌ Violation |
| **RFC 6891** | Honour the requestor's advertised UDP payload size; echo an OPT RR | No OPT handling at all | ❌ Missing |
| **RFC 7766 §3** | DNS servers **MUST** support TCP | `serveTCP`/`serveTCPConn` with `dns.Conn` length-prefix framing | ✅ Full |
| **RFC 7766 §6.2.1** | Servers SHOULD apply an idle timeout to TCP connections | `dnsTCPIdleTimeout` = 10 s | ✅ Full |
| **RFC 7766 §6.2.1.1** | Servers SHOULD process pipelined queries concurrently and MAY answer out of order | `serveTCPConn` serialises strictly | 🟡 Partial (SHOULD) |
| **RFC 2308** | Negative responses SHOULD carry an SOA for negative caching | No SOA in the authority section (dropped per §8.12) | ❌ Missing |
| **RFC 5452 §9.2** | Query ID and source port MUST be unpredictable | Source port random (OS ephemeral) ✅; **query ID is the client's, verbatim** ❌ | ❌ **Violation** — audit §1.2 |
| **RFC 5452** | DNS 0x20 name randomisation (optional hardening) | Not implemented | ❌ Missing |
| **RFC 5358** (BCP 140) | Recursive servers should not be open reflectors | Gated only by `AllowedSources`; no rate limiting or RRL | 🟡 Partial — audit §1.4 |
| **RFC 8482** | Minimal responses to ANY (e.g. HINFO) | ANY is rewritten to AAAA and synthesised | ⚠️ Deviation — pragmatic for IPv6-only clients; not RFC 8482 behaviour |
| **RFC 7873 / 9018** | DNS Cookies | Not implemented | ❌ Missing (optional) |
| **RFC 7871** | EDNS Client Subnet | Not implemented; may degrade CDN geolocation through the forwarder | ❌ Missing (optional) |
| **RFC 3596 §2.5** | `ip6.arpa` nibble encoding | `ptrToIPv6` — correct, incl. length and nibble validation | ✅ Full |

---

## 10. What ydn64 already gets right

Worth recording explicitly so it isn't regressed:

- **RFC 6052 §3.2 NSP selection** — deriving Pref64 from the node's own Yggdrasil `/64` (`DeriveFromPrivateKey`) is exactly the "assigned from the organization's own address space" property the RFC wants, achieved with zero configuration and guaranteed globally unique per node. This is a genuinely elegant fit.
- **RFC 8200 §8.1 pseudo-header checksum construction** — `ipv6UpperLayerChecksum` implements the pseudo-header layout correctly for both UDP (NH 17) and ICMPv6 (NH 58), with correct odd-length handling and carry folding. Only the zero→`0xFFFF` special case is missing.
- **RFC 6147 §5.1.3** — timeout → SERVFAIL is handled correctly.
- **RFC 6147 §5.1.8** — the sequential AAAA-then-A strategy is exactly the trade-off the RFC's own note recommends.
- **RFC 7766** — dual UDP + TCP listeners with correct RFC 1035 §4.2.2 length-prefix framing and an idle timeout. Many small DNS64 implementations skip TCP entirely.
- **RFC 3596 §2.5** — the `ip6.arpa` PTR parser validates nibble count and character range rather than assuming well-formed input.
- **RFC 6146 §3.5 destination check** — `pool6Net.Contains(dstIP)` is applied consistently across TCP, UDP and ICMP interceptors.

---

## 11. Discovery mechanisms

### 11.1 RFC 7050 / RFC 8880 — `ipv4only.arpa`

RFC 7050 lets a client discover Pref64 by querying `AAAA ipv4only.arpa` and inspecting the synthesised addresses (the real A records are the fixed `192.0.0.170` / `192.0.0.171`).

**ydn64 appears to satisfy this incidentally**: the catch-all `["."]` zone has a prefix and `return-ipv6-addresses: false`, so an `AAAA ipv4only.arpa` query is forwarded upstream, returns no AAAA, falls through to the A query, and is synthesised as `pool6::192.0.0.170` / `pool6::192.0.0.171` — precisely what an RFC 7050 client expects.

**Verdict: 🟡 Partial (incidental).** Caveats:
- It depends entirely on upstream resolving `ipv4only.arpa`; RFC 8880 §7.1 says the resolver SHOULD answer locally rather than querying.
- It breaks if a user reconfigures the catch-all zone.
- No explicit test case covers it.

**Recommendation:** promote this to intentional — answer `ipv4only.arpa` locally with the two synthesised addresses and add a test case. It is the single cheapest thing ydn64 can do to improve client compatibility, since RFC 7050 is what iOS/Android/`getaddrinfo`-based CLAT implementations actually probe.

### 11.2 RFC 8781 — PREF64 in Router Advertisements

**N/A.** ydn64 is deliberately TUN-less and has no L2 presence, so it cannot emit RAs. Modern iOS and Android prefer RA-based PREF64 discovery over RFC 7050 — this is a **deployment-model limitation**, not a code gap, and should be documented in README so users understand why some clients need manual configuration.

### 11.3 RFC 7225 — PCP-based discovery

Not implemented. Low priority; PCP deployment is rare and it would require a PCP server on the Yggdrasil-facing side.

---

## 12. Consolidated remediation roadmap

Ordered by *user-visible impact per unit of work*, not by RFC section number.

### Tier 1 — Small, high-value, no architectural change

| # | Item | RFC |
|---|---|---|
| 1 | UDP checksum `0x0000` → `0xFFFF` | RFC 8200 §8.1 |
| 2 | Drop inbound IPv6 packets with a source in Pref64::/n | RFC 6146 §3.5, §5.4 |
| 3 | Raise `Nat64UdpTimeout` default to 300 s and enforce a 120 s floor in `Validate()` | RFC 6146 §3.5.1, §4; RFC 4787 REQ-5 |
| 4 | Raise the ICMP session timeout to 60 s and make it configurable | RFC 6146 §3.5.3, §4; RFC 5508 REQ-2 |
| 5 | Preserve the upstream RCODE (especially NXDOMAIN) in DNS64 responses | RFC 6147 §5.1.2 |
| 6 | Set the synthetic AAAA TTL to `min(A TTL, SOA TTL)`, fallback `min(A TTL, 600 s)` | RFC 6147 §5.1.7 |
| 7 | Randomise the upstream DNS query ID; restore the client's ID on the response | RFC 5452 §9.2 |
| 8 | Reject non-IN qclass queries (behave as if no DNS64 were configured) | RFC 6147 §5.1 |
| 9 | Clear the AD bit on any response ydn64 did not validate | RFC 6147 §5.5, RFC 4035 |
| 10 | Answer `ipv4only.arpa` locally with synthesised addresses; add a test case | RFC 7050, RFC 8880 |

### Tier 2 — Moderate; correctness and interoperability

| # | Item | RFC |
|---|---|---|
| 11 | EDNS(0) OPT parsing + `resp.Truncate()` + TC bit | RFC 6891, RFC 1035 §4.2.1, RFC 6147 §5.4 |
| 12 | Preserve the upstream authority + additional sections in synthesised responses (enables SOA-based negative caching) | RFC 6147 §5.3.2, §5.4, RFC 2308 |
| 13 | Preserve the CNAME/DNAME chain; set the synthetic AAAA owner name to the A record's NAME | RFC 6147 §5.1.5, §5.1.7 |
| 14 | Per-IPv4-range prefix selection + exclusion of special-use IPv4 ranges | RFC 6147 §5, §5.1.7; RFC 6052 §3.1 — **also closes audit §1.1** |
| 15 | `Dns64ExcludedPrefixes` (default `::ffff:0:0/96`) — the conformant way to express ydn64's existing intent | RFC 6147 §5.1.4 |
| 16 | Honour `CD=1 && DO=1` by disabling synthesis and passing through | RFC 6147 §5.5(3) |
| 17 | Rewrite the ICMP Identifier to a NAT-allocated value; key sessions on it | RFC 6146 §3.5.3; RFC 5508 REQ-1 — **also closes audit §1.3** |
| 18 | Session/BIB caps and per-source quotas | RFC 6146 §5.3 (MUST) — **also closes audit §1.4** |
| 19 | TCP idle timeout (`TCP_EST` 2 h / `TCP_TRANS` 4 min semantics) | RFC 5382 REQ-5 — **also closes audit §5.4** |
| 20 | Walk the IPv6 extension-header chain in `interceptPacket` | RFC 8200 §4; prerequisite for #21 |

### Tier 3 — Large; substantial new subsystems

| # | Item | RFC |
|---|---|---|
| 21 | IPv6 fragment reassembly with a bounded resource budget and ≥ 2 s window | RFC 6146 §3.4 (MUST), §5.3 |
| 22 | ICMP **error** translation (Dest Unreachable, Time Exceeded, Parameter Problem, PTB) incl. embedded-packet rewriting — restores `traceroute` and fast-fail | RFC 6146 §3.6.1/§3.6.2, RFC 7915 §4.2/§5.2, RFC 5508 REQ-3/4 |
| 23 | ICMPv6 **Packet Too Big** generation; PMTUD support | RFC 4443 §3.2, RFC 7915 |
| 24 | Full RFC 6052 prefix-length support (`/32`–`/64`) | RFC 6052 §2.2, RFC 6146 §3.5.4 |
| 25 | RFC 6147-conformant PTR strategy (pick Option 1 or Option 2) | RFC 6147 §5.3.1 |
| 26 | DNSSEC validation (vDNS64 mode) | RFC 6147 §5.5 |

### Tier 4 — Architectural; requires reworking the proxy model

| # | Item | RFC | Notes |
|---|---|---|---|
| 27 | **Binding Information Bases + managed IPv4 port pool → Endpoint-Independent Mapping** — 🕒 **DEFERRED, do not action** | RFC 6146 §3.1, §5.2 (MUST); RFC 4787 REQ-1; RFC 5382 REQ-1 | The single biggest conformance gap. Unblocks ICE/STUN/WebRTC. **UDP-only EIM is materially smaller than this row implies** — it needs only a BIB keyed on `(src6, srcPort)` plus one *unconnected* `net.ListenUDP` socket per BIB entry (replacing `net.DialUDP` per destination) and inbound demultiplexing by real source address. **No extra capabilities and no root are required**, so ydn64's TUN-less/no-root property is preserved. Must land together with #18 (session caps). TCP EIM is a separate, genuinely Tier-4-sized job — see #28. **See §13.1 for the full analysis and open sub-questions.** |
| 28 | TCP state machine per RFC 6146 §3.5.2.2 | RFC 6146 §3.5.2 | Requires observing TCP flags, i.e. abandoning the gVisor-terminating forwarder in favour of true translation |
| 29 | Hairpinning (§3.8) + hairpin-loop prevention | RFC 6146 §3.8, §5.4; RFC 4787 REQ-9 | Depends on #27 |
| 30 | True RFC 7915 header translation (Traffic Class↔DSCP, Hop Limit↔TTL, ECN, DF) | RFC 7915 §4.1, §5.1 | Depends on #28. Fundamentally incompatible with the current socket-based re-origination |

---

## 13. Open questions

I need answers to these before the roadmap above can be turned into concrete tasks — several items are only worth doing under certain answers.

1. ~~**Is RFC conformance actually a goal, or is "works well for Yggdrasil clients" the goal?**~~
   **✅ ANSWERED (2026-07-25): "works for Yggdrasil clients" is the goal.** The deliberate deviations (§8.2 synthesis-over-real-AAAA, §8.13 A-record suppression, §8.11 PTR strategy, §8.13 ANY rewrite, zone-miss NXDOMAIN) stay as-is and are now documented in README's *"Standards conformance and deliberate deviations"* section. **Consequence for this roadmap:** items whose only justification is conformance are deprioritised; items that fix *user-visible breakage* keep their priority. Specifically:
   - Tier 1 #5 (NXDOMAIN preservation) — still worth doing: this is about **upstream** NXDOMAIN being masked as NOERROR, which breaks client negative caching. It is *not* the same as the deliberate zone-miss NXDOMAIN policy.
   - Tier 2 #12 (authority/additional sections) — keep, it's what makes #5 useful (SOA-based negative caching).
   - Tier 2 #13 (CNAME chain) — keep, real clients and `dig` users are affected.
   - Tier 3 #25 (conformant PTR strategy) — **drop**; the current behaviour is better for the use case.
   - Tier 2 #15 (`Dns64ExcludedPrefixes`) — demote to "nice to have"; it was primarily a route back to conformance, and the deviation is now sanctioned.

2. ~~**Is Endpoint-Independent Mapping (Tier 4 #27) in scope?**~~
   **✅ ANSWERED (2026-07-25): P2P/WebRTC support is desirable but 🕒 DEFERRED — not scheduled for implementation now.** The analysis is retained in §13.1 for when this is picked up. **Consequence for this roadmap:** Tier 4 #27 is parked; Tier 1 and Tier 2 proceed first. Note that Tier 2 #18 (session/BIB caps) is a prerequisite for #27 and is worth doing on its own merits regardless (RFC 6146 §5.3 MUST, audit §1.4) — design its data structures so a future BIB keyed on `(src6, srcPort)` can slot in without another rewrite. The sub-questions in §13.1 remain open and must be answered before #27 is scoped.

3. **Is the "proxy, not translator" architecture fixed?**
   If yes, Tier 4 #28/#30 (TCP state machine, RFC 7915 header translation) should be formally declared out of scope and documented in README rather than tracked as gaps. If it's open to revisit, that changes the priority of #20/#21/#22 considerably.

4. **Should DNSSEC be in scope at all (Tier 3 #26)?**
   Full vDNS64 is a large piece of work. The minimal alternative — honour `CD=1 && DO=1` by passing through unmodified, and clear the AD bit (Tier 1 #9, Tier 2 #16) — costs very little and removes the worst of the misbehaviour. Is minimal sufficient?

5. **Should the DNS64 exclusion-set mechanism (Tier 2 #15) replace the current `return-ipv6-addresses: false` semantics, or sit alongside it?**
   `Dns64ExcludedPrefixes` is the RFC-blessed way to express "drop AAAA my clients can't reach". It could subsume the existing flag, but that would be a breaking config change.

6. **Are there deployments relying on the current 30 s `Nat64UdpTimeout` default?**
   Raising it to the RFC-mandated 300 s multiplies steady-state session-table size by ~10×. That interacts directly with the session-cap work (Tier 2 #18) — the cap should probably land first or at the same time.

7. **Is `traceroute` through NAT64 (Tier 3 #22) something users have asked for?**
   It's the most-requested NAT64 feature in most deployments, but it's also the largest Tier 3 item. Knowing whether it's wanted determines whether #22 or #21 goes first.

8. **Should conformance be tracked continuously?**
   If so, the black-box harness in `test/` is well placed to grow RFC-conformance cases (NXDOMAIN preservation, TTL bounds, CNAME chain presence, `ipv4only.arpa` synthesis, UDP checksum edge case, Pref64-source drop). Worth a dedicated `test/cases/` group, or better as Go unit tests (audit §6.1)?

---

### 13.1 Expansion of Q2 — Endpoint-Independent Mapping and P2P/WebRTC

> **Status: 🕒 DEFERRED (2026-07-25).** P2P/WebRTC support is wanted but is not being implemented now. This section is retained in full so the work can be picked up later without re-deriving the analysis. Nothing below should be actioned yet.

#### What the problem actually is

When a Yggdrasil client sends UDP to two different IPv4 servers, ydn64 today creates **two independent OS sockets**:

```go
// src/nat64/udp.go — sessionKey includes the DESTINATION
type sessionKey struct {
    srcAddr [16]byte // yggdrasil source
    srcPort uint16
    dstAddr [4]byte  // <-- destination is part of the key
    dstPort uint16
}
...
conn, err := net.DialUDP("udp4", nil, dstUDPAddr) // <-- new ephemeral port per destination
```

So the client's *external* address, as seen by the outside world, is:

| Client flow | External source seen by the server |
|---|---|
| `[ygg]:5000` → STUN server A | `<host-v4>:41001` |
| `[ygg]:5000` → STUN server B | `<host-v4>:52777` |
| `[ygg]:5000` → the actual peer | `<host-v4>:39412` |

This is textbook **symmetric NAT** (RFC 4787 terminology: *Address-and-Port-Dependent Mapping*). RFC 6146 §5.2 makes the opposite a hard MUST:

> *"a NAT64 MUST offer 'Endpoint-Independent Mapping' … (S1,s1v4) = (S2,s2v4) for all values of D2,d2."*

#### Why it breaks WebRTC / P2P

ICE (RFC 8445) works by having each side ask a STUN server *"what source address do you see me coming from?"*, then advertising that as a **server-reflexive candidate** and having the remote peer send directly to it.

Under ydn64's current behaviour that whole mechanism collapses:

1. Client asks STUN server → learns `<host-v4>:41001`.
2. Client advertises `<host-v4>:41001` to the remote peer.
3. Remote peer sends to `<host-v4>:41001` — but ydn64 has **no session for `(peer-ip, peer-port)`**, only for `(stun-server-ip, stun-port)`. The packet is dropped by the connected socket.
4. ICE falls back to a **TURN relay**, or fails entirely if none is configured.

So today: WebRTC video/audio through ydn64 either doesn't connect, or silently degrades to TURN (extra latency, extra bandwidth, requires a TURN server the user must supply). BitTorrent, WireGuard roaming, and most game netcode are affected the same way.

Additionally, ydn64's **filtering** is address-and-port-dependent too (a side effect of `net.DialUDP` connecting the socket), which is *stricter* than RFC 4787 REQ-8's RECOMMENDED endpoint-independent filtering. Even with EIM fixed, unsolicited inbound from a peer that the client hasn't yet sent to would still be dropped — ICE's hole-punching handles this correctly *provided* the mapping is stable, but it's a second knob to get right.

#### What a fix requires

The fix is the RFC 6146 §3.1 **Binding Information Base** that ydn64 currently doesn't have:

1. **Split the single table into BIB + session table.** BIB is keyed on `(srcAddr6, srcPort)` → `(hostV4, allocatedPort)`, *independent of destination*. The session table stays keyed on the full 5-tuple, but only for lifetime tracking and reverse lookup.
2. **One unconnected socket per BIB entry**, not per destination. `net.ListenUDP("udp4", nil)` instead of `net.DialUDP`, then `WriteToUDP`/`ReadFromUDP` and demultiplex inbound datagrams by their real source address against the session table.
3. **Filtering policy becomes explicit** rather than a side effect of socket connectedness — endpoint-independent or address-dependent, per RFC 4787 REQ-8, ideally configurable.
4. **Resource caps become mandatory** (RFC 6146 §5.3, Tier 2 #18): unconnected sockets accept traffic from anywhere, so per-source session limits must land at the same time, not later.
5. **Same rework for TCP** if P2P TCP matters (rarer — most P2P is UDP).

**Good news for a TUN-less/no-root deployment:** steps 1–4 need **no additional privileges**. `net.ListenUDP` on an ephemeral port is unprivileged. My earlier note that this "probably needs raw sockets / `CAP_NET_ADMIN`" was over-cautious — that only becomes true if you also want to control the *source IPv4 address* (multiple pool addresses) or do true RFC 7915 translation. For a single-host-IPv4 NAT64, an unconnected `net.ListenUDP` socket per BIB entry is sufficient and keeps the current "no root required" property intact.

#### Remaining sub-questions — to be answered when this is un-deferred

- **2a.** Is **UDP-only** EIM acceptable, or is TCP EIM (RFC 5382 REQ-1) also needed? UDP-only covers WebRTC, QUIC, BitTorrent DHT/uTP, WireGuard, and most game traffic, and is *far* smaller — it can be done inside the existing `src/nat64/udp.go` design. TCP EIM requires the gVisor-terminating forwarder to be replaced, which is Tier 4 territory.
- **2b.** ICE also needs the client to *reach* a STUN server. Do you intend to point Yggdrasil clients at public STUN servers via NAT64 (`stun.l.google.com:19302` → `pool6::…`), or run a STUN server on the ydn64 node itself? The latter would let ydn64 report the mapping authoritatively and is much more robust — but it's a new service, not a NAT64 fix.
- **2c.** Endpoint-independent **filtering** (RFC 4787 REQ-8) is a separate decision from mapping, and it is a genuine security loosening: an unconnected socket will accept datagrams from any source. Options: (i) endpoint-independent — best traversal, weakest filtering; (ii) address-dependent — accept from any port of an IPv4 address the client has already contacted, which is enough for most ICE cases and much safer; (iii) keep address-and-port-dependent and rely on ICE's own connectivity checks to open the pinhole first. Which do you want as the default?
- **2d.** Are there other Yggdrasil-side concerns? A client behind ydn64 already has a *stable, publicly routable* Yggdrasil address — for peer-to-peer **between two Yggdrasil nodes**, NAT64 isn't involved at all and P2P already works. EIM only matters for P2P between a Yggdrasil client and a **legacy IPv4 peer**. Is that the actual use case (e.g. joining a public WebRTC/BitTorrent swarm), or is Yggdrasil-to-Yggdrasil P2P what you had in mind?
- **2e.** Priority relative to Tier 1? Tier 1 is ~10 small fixes with immediate benefit. EIM is a focused but non-trivial rework of `src/nat64/udp.go` plus session caps. Should Tier 1 land first, or is P2P support the headline feature to chase?
