package nat64

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// statsInterval is how often the periodic debug-stats logger dumps deltas.
const statsInterval = time.Minute

// statSnapshot is a flat copy of the interesting gVisor stack counters at one
// instant. The stats loop logs deltas between consecutive snapshots rather
// than raw monotonically increasing values, so each line answers "what
// happened since the last tick".
//
// Counters not listed here are deliberately omitted to keep every line
// compact and greppable; extend the struct when something new needs eyes.
type statSnapshot struct {
	ipRx, ipTx                uint64
	tcpActive, tcpPassive     uint64
	tcpEst                    uint64 // gauge: currently established connections
	tcpSegRx, tcpSegTx        uint64
	tcpResets                 uint64
	tcpRetransmits            uint64
	tcpTimedout               uint64 // keepalive/user-timeout driven aborts
	udpRx, udpTx              uint64
	udpUnknownPort, udpBufErr uint64
	icmp6EchoReqRx            uint64
	icmp6EchoRepTx            uint64
}

// takeStatSnapshot copies the current values of the tracked counters.
func takeStatSnapshot(st tcpip.Stats) statSnapshot {
	return statSnapshot{
		ipRx:           st.IP.PacketsReceived.Value(),
		ipTx:           st.IP.PacketsSent.Value(),
		tcpActive:      st.TCP.ActiveConnectionOpenings.Value(),
		tcpPassive:     st.TCP.PassiveConnectionOpenings.Value(),
		tcpEst:         st.TCP.CurrentEstablished.Value(),
		tcpSegRx:       st.TCP.ValidSegmentsReceived.Value(),
		tcpSegTx:       st.TCP.SegmentsSent.Value(),
		tcpResets:      st.TCP.ResetsSent.Value(),
		tcpRetransmits: st.TCP.Retransmits.Value(),
		tcpTimedout:    st.TCP.EstablishedTimedout.Value(),
		udpRx:          st.UDP.PacketsReceived.Value(),
		udpTx:          st.UDP.PacketsSent.Value(),
		udpUnknownPort: st.UDP.UnknownPortErrors.Value(),
		udpBufErr:      st.UDP.ReceiveBufferErrors.Value(),
		icmp6EchoReqRx: st.ICMP.V6.PacketsReceived.EchoRequest.Value(),
		icmp6EchoRepTx: st.ICMP.V6.PacketsSent.EchoReply.Value(),
	}
}

// formatStatsDelta renders one compact greppable line: deltas of all counted
// metrics plus absolute gauges (established connections, live NAT sessions).
func formatStatsDelta(prev, cur statSnapshot, sessUDP, sessICMP int) string {
	var b strings.Builder
	b.WriteString("netstack stats:")
	fmt.Fprintf(&b, " ipRx=%d", cur.ipRx-prev.ipRx)
	fmt.Fprintf(&b, " ipTx=%d", cur.ipTx-prev.ipTx)
	fmt.Fprintf(&b, " tcpAct=%d", cur.tcpActive-prev.tcpActive)
	fmt.Fprintf(&b, " tcpPas=%d", cur.tcpPassive-prev.tcpPassive)
	fmt.Fprintf(&b, " tcpEst=%d", cur.tcpEst)
	fmt.Fprintf(&b, " tcpSegRx=%d", cur.tcpSegRx-prev.tcpSegRx)
	fmt.Fprintf(&b, " tcpSegTx=%d", cur.tcpSegTx-prev.tcpSegTx)
	fmt.Fprintf(&b, " tcpRst=%d", cur.tcpResets-prev.tcpResets)
	fmt.Fprintf(&b, " tcpRe=%d", cur.tcpRetransmits-prev.tcpRetransmits)
	fmt.Fprintf(&b, " tcpTO=%d", cur.tcpTimedout-prev.tcpTimedout)
	fmt.Fprintf(&b, " udpRx=%d", cur.udpRx-prev.udpRx)
	fmt.Fprintf(&b, " udpTx=%d", cur.udpTx-prev.udpTx)
	fmt.Fprintf(&b, " udpNoPort=%d", cur.udpUnknownPort-prev.udpUnknownPort)
	fmt.Fprintf(&b, " udpBufErr=%d", cur.udpBufErr-prev.udpBufErr)
	fmt.Fprintf(&b, " icmp6EchoReqRx=%d", cur.icmp6EchoReqRx-prev.icmp6EchoReqRx)
	fmt.Fprintf(&b, " icmp6EchoRepTx=%d", cur.icmp6EchoRepTx-prev.icmp6EchoRepTx)
	fmt.Fprintf(&b, " sessUdp=%d", sessUDP)
	fmt.Fprintf(&b, " sessIcmp=%d", sessICMP)
	return b.String()
}

// countSyncMap returns the number of entries in m.
func countSyncMap(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// logStatsDelta takes a fresh snapshot and logs its delta against the
// previous one (updating the stored baseline). Safe to call concurrently:
// the periodic loop and the SIGHUP-triggered dump share the same baseline so
// their lines always partition time without overlap.
func (s *Service) logStatsDelta(logger *log.Logger) {
	cur := takeStatSnapshot(s.ns.Stack().Stats())

	s.statsMu.Lock()
	prev := s.lastStatSnap
	s.lastStatSnap = cur
	s.statsMu.Unlock()

	logger.Debugf("%s", formatStatsDelta(
		prev, cur,
		countSyncMap(&s.sessions),
		countSyncMap(&s.icmpSessions),
	))
}

// DumpStats logs one stats line on demand. Wired into main.go's SIGHUP
// config-reload path alongside the periodic logger.
func (s *Service) DumpStats(logger *log.Logger) {
	s.logStatsDelta(logger)
}

// statsLoop periodically logs gVisor stack statistics at Debug level until
// ctx is cancelled. All counters come from the stack itself — no packet
// counting of our own.
func (s *Service) statsLoop(ctx context.Context, logger *log.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logStatsDelta(logger)
		}
	}
}
