# ydn64 Implementation Plan

## Overview

`ydn64` is a userspace NAT64 daemon for Yggdrasil networks. It embeds
Yggdrasil-ng (no TUN, no root required) and performs stateful IPv6→IPv4
translation for allowed yggdrasil peers using a configured Pool6 prefix.

**Language:** Rust  
**Foundation:** Yggdrasil-ng (local path dep), smoltcp for userspace TCP/UDP  
**Reference:** yggstack-ng (architecture reference only — not fully stable)

---

## 1. Workspace & Crate Structure

```
ydn64/
├── Cargo.toml            (workspace root)
├── Cargo.lock
├── .gitignore
├── tmp/                  (local scratch, git-ignored)
├── context/
│   ├── general-idea.txt
│   └── implementation-plan.md
└── crates/
    └── ydn64/
        ├── Cargo.toml
        └── src/
            ├── main.rs           CLI entry point
            ├── lib.rs
            ├── config.rs         Extended config struct
            └── nat64/
                ├── mod.rs        Engine: packet dispatch loop
                ├── pool6.rs      Pool6 prefix helpers + auto-generation
                ├── session.rs    Session table (DashMap, timeouts, GC)
                └── translate.rs  IPv6↔IPv4 header + checksum rewriting
```

---

## 2. Config (`config.rs`)

Flat extension of `yggdrasil::config::Config` — ydn64 wraps it in its own struct.

```toml
# All standard yggdrasil fields ...
private_key = "..."
peers = ["tcp://..."]
if_name = "none"          # always forced to none

# ydn64-specific additions (flat, same level)
pool6 = "0300:xxxx:xxxx:xxxx::/96"   # auto-derived at genconf
allowed_nat64_sources = []            # ["0200::/7", "0200:aabb::1/128"]
```

- `allowed_nat64_sources`: `Vec<String>` in TOML, parsed to `Vec<Ipv6Net>` at startup.
  Invalid CIDR entries are hard errors (fail fast).
- `pool6`: parsed to `Ipv6Net` (/96 required). Hard error if not /96.
- `if_name` is always overridden to `"none"` after load.

---

## 3. Pool6 Auto-Generation (`pool6.rs`)

At `--genconf` time, derive pool6 from the node's /64 subnet:

```
private_key → public_key → subnet_for_key() → [u8; 8] subnet prefix
pool6 = <subnet_64bit_prefix>:<zeros_32bit>::/96
```

Example: node subnet `0300:aabb:ccdd:eeff::/64` → pool6 = `0300:aabb:ccdd:eeff::/96`

**IPv4 extraction** from a destination IPv6 address:
```rust
let ipv4 = Ipv4Addr::from(<[u8;4]>::try_from(&dst_ipv6.octets()[12..16]).unwrap());
```

---

## 4. NAT64 Engine (`nat64/mod.rs`)

**Packet receive loop** (tokio task):

```
ReadWriteCloser.recv() → raw IPv6 packet
  │
  ├─ source in AllowedNat64Sources? → NO → drop silently
  │
  ├─ destination has pool6 prefix?  → NO → drop (not for us)
  │
  ├─ extract IPv4 = dst[12..16]
  │
  ├─ protocol = TCP  → smoltcp path
  ├─ protocol = UDP  → direct socket path
  └─ protocol = ICMP → tracing::debug!("ICMP not yet supported"), drop
                       // TODO(icmp): RFC 6146 §3.5
```

---

## 5. TCP Path

Reuse yggstack-ng's `YggDevice` + `smoltcp::Interface` pattern for the IPv6 side:

```
smoltcp TCP socket (IPv6-side, smoltcp-managed)
        ↕  tokio::io::copy (bidirectional relay)
tokio::net::TcpStream (IPv4 system socket → real internet)
```

Per connection flow:
1. smoltcp accepts incoming TCP SYN from yggdrasil peer
2. Spawn tokio task: connect `TcpStream` to `Ipv4Addr:port`
3. Two async copy loops: smoltcp socket ↔ system TCP socket
4. Session entry dropped on FIN/RST/timeout

---

## 6. UDP Path

No smoltcp needed — direct socket path:

```
IPv6 UDP packet (from yggdrasil)
  → validate source, extract IPv4 dst
  → look up / create session (src6, src_port, dst4, dst_port)
  → translate headers → tokio::net::UdpSocket.send_to(dst4:port)
  → response → translate back → ReadWriteCloser.send(src6_ygg, packet)
```

Session timeout: 30 s. Background GC task sweeps every 30 s.

---

## 7. Session Table (`session.rs`)

```rust
#[derive(Hash, Eq, PartialEq)]
struct SessionKey {
    proto: u8,
    src6: [u8; 16],
    src_port: u16,
    dst4: [u8; 4],
    dst_port: u16,
}

struct Session {
    last_seen: Instant,
    // UDP: Arc<UdpSocket>, TCP: JoinHandle
}
```

- `DashMap<SessionKey, Session>` — concurrent reads, shard-level locking.
- Max sessions cap (65535): new connections beyond cap are dropped with tracing warning.
- GC: background tokio task, sweeps every 30 s.

---

## 8. Header Translation (`translate.rs`)

### IPv6 → IPv4 (outbound to internet)
1. Skip 40-byte IPv6 fixed header (+ any extension headers)
2. Write 20-byte IPv4 header:
   - `src4`: outbound system IP (OS picks via routing)
   - `dst4`: `dst_ipv6.octets()[12..16]`
   - TTL: copy `hop_limit`
   - Protocol: copy next_header (6=TCP, 17=UDP)
3. Recompute TCP/UDP checksum with IPv4 pseudo-header

### IPv4 → IPv6 (response from internet)
1. Skip 20-byte IPv4 header
2. Write 40-byte IPv6 header:
   - `src6`: pool6_prefix + src4 (last 4 bytes)
   - `dst6`: original yggdrasil source (from session table)
   - `hop_limit`: copy TTL
3. Recompute TCP/UDP checksum with IPv6 pseudo-header

---

## 9. CLI Interface

```
ydn64 --genconf                    generate default config with auto-derived pool6
ydn64 --useconffile FILE           start from file
ydn64 --useconf                    read config from stdin
ydn64 --normaliseconf              dump normalised config (use with --useconf/--useconffile)
ydn64 --address                    print yggdrasil IPv6 address
ydn64 --subnet                     print /64 subnet
ydn64 --pool6                      print active NAT64 pool6 prefix
ydn64 --loglevel LEVEL             error / warn / info / debug / trace
ydn64 --version                    print version
```

---

## 10. Dependencies

| Crate | Purpose |
|---|---|
| `yggdrasil` (local `../Yggdrasil-ng/crates/yggdrasil`) | Core + ReadWriteCloser |
| `tokio` (full) | Async runtime |
| `smoltcp 0.11` | Userspace IPv6 TCP/UDP (IPv6-facing smoltcp device) |
| `ipnet` | CIDR matching for AllowedNat64Sources + Pool6 |
| `dashmap` | Concurrent session table |
| `ed25519-dalek`, `rand`, `hex` | Key generation |
| `getopts`, `serde`, `toml` | CLI + config |
| `tracing`, `tracing-subscriber` | Structured logging |
| `thiserror` | Error types |

---

## 11. Implementation Order

1. Workspace + `Cargo.toml` scaffolding
2. `config.rs` — load/save/genconf with pool6 auto-derive
3. `pool6.rs` + `translate.rs` — pure functions, unit-testable
4. `session.rs` — DashMap table + GC task
5. UDP NAT path (simpler, validates the translate layer end-to-end)
6. TCP NAT path (smoltcp integration, modelled on yggstack-ng netstack)
7. CLI wiring in `main.rs`

---

## 12. Deferred (post-MVP)

- ICMP echo (ping) — `// TODO(icmp): RFC 6146 §3.5` comments in place
- Per-source rate limiting
- Admin socket (`--admin`) for live session table inspection
- Android/iOS build targets (mobile crate pattern from yggdrasil-ng)
- DNS64 (out of scope — clients handle DNS themselves)
