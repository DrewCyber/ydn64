package nat64

import "sync"

// Per-source live-resource tracking (RFC 6146 §5.3): global caps alone let
// a single allowed peer occupy every NAT64 slot and starve all others.
// srcTracker maintains live UDP-session and proxied-TCP counts per client
// address so admission can shed per source before the global limits ever
// come into play.
//
// Accounting deliberately mirrors the exact lifecycle of the structures it
// tracks, which keeps it race-free without extra coordination:
//
//   - UDP entries are added where udpSessions is incremented (after a new
//     session tuple is stored) and removed in deleteSession's
//     CompareAndDelete-success branch — the same two points that keep
//     udpSessions consistent. The transient window between admission
//     (pre-dial) and registration can therefore overshoot the cap by the
//     number of concurrently dialing flows only.
//   - TCP slots are added synchronously next to tryAcquireTCP and removed
//     at every releaseTCP call site.

type srcKind int

const (
	srcUDP srcKind = iota
	srcTCP

	srcKindCount
)

type srcTracker struct {
	mu     sync.Mutex
	counts map[[16]byte][srcKindCount]int64
}

func newSrcTracker() srcTracker {
	return srcTracker{counts: make(map[[16]byte][srcKindCount]int64)}
}

// add records one live resource of the given kind for src.
func (t *srcTracker) add(src [16]byte, kind srcKind) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.counts[src]
	c[kind]++
	t.counts[src] = c
}

// remove drops one live resource; entries with nothing left are pruned so
// the map stays bounded by actually-active sources.
func (t *srcTracker) remove(src [16]byte, kind srcKind) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.counts[src]
	if !ok || c[kind] <= 0 {
		return // defensive: never go negative on bookkeeping races
	}
	c[kind]--
	if c[srcUDP] == 0 && c[srcTCP] == 0 {
		delete(t.counts, src)
		return
	}
	t.counts[src] = c
}

// count returns the current live count for src/kind.
func (t *srcTracker) count(src [16]byte, kind srcKind) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counts[src][kind]
}
