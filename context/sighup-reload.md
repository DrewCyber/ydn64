# SIGHUP live config reload — design notes & tech debt

This documents the complexity breakdown that was used to scope the SIGHUP
live-reload feature (no process restart needed to apply certain config
changes), what tier was actually implemented, and the known tech debt/
follow-ups left behind. Kept separate from [TODO.md](../TODO.md) because the
"done" line there (`SIGHUP support for config reload`) only covers Tier 1 —
this file is the detail behind that line.


## Complexity tiers considered

When scoping the feature, every `AppConfig`/`ygconfig.NodeConfig` field was
bucketed by how hard it would be to apply without restarting the process:

- **Tier 1 — cheap, atomic swap.** Field only feeds a read path that already
  goes through a service struct reachable from the SIGHUP handler; no
  sockets, routes, or NIC state need to change. Implementable with an
  `atomic.Pointer[T]`/`atomic.Int64` swap read by the hot path.
- **Tier 2 — moderate, requires recreating a sub-resource.** Field changes
  what a long-lived sub-object listens on/advertises (e.g. multicast
  interface list, Yggdrasil peers), but the vendored `yggdrasil-go` library
  exposes *some* live API for it (`core.AddPeer`/`RemovePeer`), or the
  sub-object supports `Stop()` + re-`New()` recreation in place
  (`multicast.Multicast`). Feasible but was out of scope for this pass.
- **Tier 3 — hard/unsupported by upstream, effectively requires a restart.**
  Either there's no live setter anywhere in `yggdrasil-go@v0.5.13`'s public
  API (node identity/`PrivateKey`, `NodeInfo`, `AllowedPublicKeys`), or the
  field determines something bound once at construction in this repo's own
  code (`Listen` — admin socket, forced to `"none"` anyway; `Nat64Pool` —
  bakes into the gVisor route/NIC setup; `Dns64Listen` — bound listener
  socket; `Nat64Enable`/`Dns64Enable` — whole service goroutines
  started/not-started at boot).

The user selected **"Tier 1 only"** for this pass:
`AllowedSources` (shared by NAT64+DNS64), DNS64's `Default` forwarder,
`Zones`, `InvalidAddress`, `CacheExpiration`/`CachePurge`, and NAT64's
`UdpTimeout`.

## What was implemented (Tier 1)

- `cmd/ydn64/main.go`: `signal.Notify(reloadCh, syscall.SIGHUP)` + a
  goroutine that calls `reloadConfig(...)` on each signal. `reloadConfig`
  re-reads the config file from disk via `config.Load`, re-applies the
  `YDN64_ALLOWED_SOURCES` env override if set, warns-and-ignores any change
  to a non-reloadable field (see list below), then calls
  `nat64Svc.Reload(...)` and `dns64Svc.Reload(...)`.
- `nat64.Service`: reloadable settings (`allowedNets`, `udpTimeout`) moved
  behind a single `atomic.Pointer[nat64Settings]`; `Service.Reload(cfg,
  allowedSources)` swaps it in one atomic store, so `isAllowed()` /
  `cleanupSessions()` / `udpReplyLoop()` never take a lock.
- `dns64.Service`: `allowedNets` behind `atomic.Pointer[[]*net.IPNet]`;
  `Service.Reload(cfg, allowedSources)` updates it and delegates to
  `proxy.reload(...)` and `cache.Reload(...)`.
- `dns64.proxy`: zones/default-forwarder/invalid-address behind a single
  `atomic.Pointer[proxyConfig]`, swapped by `proxy.reload(...)`.
- `dns64.dnsCache`: `defaultExp` is an `atomic.Int64`; `Reload(defaultExp,
  purgeInterval)` also **flushes all cached entries** (see bug below) and
  resets the purge ticker interval if a janitor is already running.
- `config.ParseAllowedNets(sources []string) []*net.IPNet` factored out so
  both services parse `AllowedSources` identically at construction and
  reload time.
- Test harness: `test/lib.sh`'s `reload_a <description>` helper
  (`podman kill --signal HUP` + wait for `"config reloaded"` in the
  service log) replaces `podman restart` + re-peering `wait_for` in
  [test/cases/04_allowed_sources_config_change.sh](../test/cases/04_allowed_sources_config_change.sh)
  and
  [test/cases/06_ygg_zone_resolution.sh](../test/cases/06_ygg_zone_resolution.sh).
  Both cases went from a restart-based multi-second/flaky re-peering wait to
  a ~0s deterministic reload.

## Bug found and fixed during this work

`dnsCache` caches AAAA answers keyed only by question name, and
`proxy.handleAAAA` returns a cache hit **before** applying any zone
filtering. A full process restart always wiped the cache, so this was never
observable pre-SIGHUP. With live reload, removing/changing a DNS64 zone left
previously-cached answers being served under the *old* zone's rules until
their TTL naturally expired — a reload that silently didn't take effect for
already-queried names. Fixed by having `dnsCache.Reload()` unconditionally
flush all entries, not just update `defaultExp`/`purgeInterval` for future
entries.

## Known tech debt / not done

- **`Reload()` always flushes the entire DNS64 cache**, even when the
  reload only changed `AllowedSources` (which has no bearing on cached
  answers). Coarse but safe; a more surgical fix would diff old vs new
  `Zones`/`Default`/`InvalidAddress` and only flush when one of those
  actually changed.
- **`reloadConfig`'s "already-running config" snapshot is captured once at
  process startup** (`nat64Cfg`, `dns64Cfg` passed in from `main()`) and is
  **never updated after a successful reload**. This means the
  Tier-3-field-changed warning check (`Nat64Enable`/`Nat64Pool`/
  `Dns64Enable`/`Dns64Listen`) always diffs the *newly loaded* config
  against the *boot-time* config, not the *previous* reload's config. A
  second SIGHUP that reverts a Tier-3 field back to its boot-time value
  would stop warning (falsely looks unchanged), and diffs against
  intermediate reloads are lost entirely. Low impact today since those
  fields are ignored either way, but would matter if this logic is ever
  used for anything beyond a log warning.
- **No live peer reload (Tier 2, not implemented).** Vendored
  `yggdrasil-go@v0.5.13`'s `core.Core` exposes `AddPeer`/`RemovePeer(*url.URL,
  sintf string) error`, which could support diffing `Peers`/`InterfacePeers`
  on SIGHUP. Not implemented — `Peers` changes are silently ignored (not
  even a warning is logged for `Peers`/`MulticastInterfaces` specifically,
  unlike the four Tier-3 fields that do get a warning).
- **No live multicast interface reload (Tier 2, not implemented).**
  `multicast.Multicast` has no public interface-update method
  (`_updateInterfaces` is private), but `Stop()` + reconstruct-via-`New()`
  is possible in principle. Not implemented.
- **No live re-key / `NodeInfo` / `AllowedPublicKeys` reload (Tier 3, no
  upstream API).** Would require constructing a new `core.Core` in place,
  effectively a restart in all but name.
- **`config.Load` failure aborts the reload silently-ish** (logs a warning,
  keeps running on the old in-memory config) — there's no separate
  validation-only/dry-run mode, so a syntax error in the file is only
  discovered when someone actually sends SIGHUP.
- **No reload success/failure metrics or counters** — only log lines
  (`"config reloaded  sources=..."` / `"config reload aborted: ..."` /
  per-field warnings). Fine for the current test harness (which greps the
  log file), but would matter for any future observability work.
- **Case 06's first real-world `.ygg` dig (unrelated to reload code) is a
  pre-existing flake**, not fixed as part of this work: right after
  container startup, real Yggdrasil-network convergence to the distant
  `YDN64_REAL_PEER` node sometimes takes longer than the existing retry
  budget, even though real internet egress itself works (case 05's
  `dns.google` lookup succeeds). Once containers are warmed up, re-running
  case 06 standalone always passes, including its reload assertions.
