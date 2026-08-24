package nat64

import (
	"sync"
	"time"
)

// IPv6 fragment reassembly for intercepted Echo Requests (RFC 8200 §4.5,
// RFC 6146 §3.4): a client pinging with a payload above the tunnel MTU
// emits fragmented ICMPv6, which the interceptor must reassemble before the
// request can be translated.
//
// The table is deliberately tiny and sheds aggressively — reassembly state
// is pure attack surface otherwise:
//
//	≤ maxReassemblies       concurrent datagrams
//	≤ maxFragmentsPerDgram  fragments per datagram (a 64 KiB datagram needs ≤ 8192; real pings need 2–3)
//	≤ maxReasmBytes         total buffered bytes across all datagrams
//	maxReasmAge             per-datagram lifetime, well below RFC 2460's 60 s
//
// Policy checks (AllowedSources, anti-hairpin, ignored destinations) all
// operate on the per-fragment fixed header and therefore run BEFORE any
// buffering, so traffic that would be shed anyway never pins memory. Over-
// lapping fragments cancel the whole datagram (RFC 5722).

const (
	maxReassemblies      = 64
	maxFragmentsPerDgram = 16
	maxReasmBytes        = 64 << 10
	maxReasmAge          = 30 * time.Second
)

type reasmKey struct {
	src, dst [16]byte
	ident    uint32
}

type reasmEntry struct {
	createdAt time.Time
	frags     map[uint16][]byte // offset in 8-byte units → fragment bytes
	bytes     int               // total buffered bytes for this datagram
	haveLast  bool              // saw the M=0 fragment
}

// reasmTable holds partially reassembled datagrams. All access is from the
// NIC read loop (single-threaded), but the mutex keeps the type safe for
// future callers and for tests.
type reasmTable struct {
	mu      sync.Mutex
	entries map[reasmKey]*reasmEntry
	bufByte int
}

func newReasmTable() *reasmTable {
	return &reasmTable{entries: make(map[reasmKey]*reasmEntry)}
}

// add stores one fragment and returns the fully reassembled upper-layer PDU
// once the last fragment completes it — nil while incomplete or when the
// fragment was shed.
func (t *reasmTable) add(key reasmKey, offsetUnits uint16, more bool, frag []byte, now time.Time) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)

	// Middle fragments must be multiples of 8 (RFC 8200 §4.5); the last one
	// may be any length. Anything else is garbage that would poison the
	// datagram.
	if len(frag) == 0 || (more && len(frag)%8 != 0) {
		t.cancelLocked(key)
		return nil
	}
	if t.bufByte+len(frag) > maxReasmBytes {
		return nil // global byte budget exhausted: shed silently
	}

	e := t.entries[key]
	if e == nil {
		if len(t.entries) >= maxReassemblies {
			return nil // table full of live datagrams: shed (expiry swept first)
		}
		e = &reasmEntry{createdAt: now, frags: make(map[uint16][]byte)}
		t.entries[key] = e
	}
	start := int(offsetUnits) * 8
	end := start + len(frag)
	if start >= 1<<16 || (!more && end > 1<<16) {
		t.cancelLocked(key) // offsets beyond an IPv6 maximum datagram are garbage
		return nil
	}
	// Overlap check against every stored fragment's byte range.
	for off, f := range e.frags {
		fs := int(off) * 8
		fe := fs + len(f)
		if start < fe && fs < end {
			t.releaseEntryLocked(key, e)
			return nil // overlapping fragment: drop whole datagram (RFC 5722)
		}
	}
	if len(e.frags) >= maxFragmentsPerDgram {
		t.releaseEntryLocked(key, e)
		return nil
	}

	cp := make([]byte, len(frag))
	copy(cp, frag)
	e.frags[offsetUnits] = cp
	e.bytes += len(cp)
	t.bufByte += len(cp)
	if !more {
		e.haveLast = true
	}
	if !e.haveLast {
		return nil
	}

	total := t.contiguousLen(e)
	if total < 0 {
		return nil // gaps remain
	}

	full := make([]byte, total)
	at := 0
	for off := uint16(0); at < total; off++ {
		f := e.frags[off]
		n := copy(full[at:], f)
		at += n
	}
	t.releaseEntryLocked(key, e)
	return full
}

// cancel drops a partial datagram (e.g. a non-echo first fragment arriving
// after its middle fragments were already buffered). Reports whether an
// entry existed.
func (t *reasmTable) cancel(key reasmKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cancelLocked(key)
}

// expire sweeps datagrams older than maxReasmAge. Callers hold t.mu.
func (t *reasmTable) expireLocked(now time.Time) {
	cutoff := now.Add(-maxReasmAge)
	for k, e := range t.entries {
		if e.createdAt.Before(cutoff) {
			t.releaseEntryLocked(k, e)
		}
	}
}

func (t *reasmTable) cancelLocked(key reasmKey) bool {
	e, ok := t.entries[key]
	if !ok {
		return false
	}
	t.releaseEntryLocked(key, e)
	return true
}

func (t *reasmTable) releaseEntryLocked(key reasmKey, e *reasmEntry) {
	delete(t.entries, key)
	t.bufByte -= e.bytes
	if t.bufByte < 0 {
		t.bufByte = 0 // defensive
	}
}

// contiguousLen returns the assembled length if [0,total) has no gaps,
// else -1. Requires haveLast.
func (t *reasmTable) contiguousLen(e *reasmEntry) int {
	var end int
	for off, f := range e.frags {
		if fe := int(off)*8 + len(f); fe > end {
			end = fe
		}
	}
	at := 0
	for at < end {
		unit := uint16(at / 8)
		f, ok := e.frags[unit]
		if !ok || len(f) == 0 {
			return -1
		}
		at += len(f)
	}
	return end
}

// pending reports how many datagrams are currently buffered (tests/metrics).
func (t *reasmTable) pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// buffered reports total bytes currently held across partial datagrams.
func (t *reasmTable) buffered() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bufByte
}
