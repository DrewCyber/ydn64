package netstack

import (
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// PacketTap is a debug stack.PacketEndpoint that mirrors packets into a
// libpcap file. It exists to demonstrate the escape hatch from the
// single-SetPacketInterceptor limitation (see AGENTS.md): unlike the
// interceptor, arbitrarily many packet endpoints can be registered, and
// registering one never changes packet flow — it is pure observation.
//
// What the tap sees, and what it does not:
//
//   - It requires stack.Options.DeliverLinkPackets (enabled by
//     CreateYdn64Netstack): gVisor then routes both inbound deliveries
//     (DeliverNetworkPacket) and egress writes (writeRawPacket) through
//     DeliverLinkPacket. The tap registers as an ETH_P_ALL-style listener
//     (header.EthernetProtocolAll) because — matching Linux AF_PACKET
//     semantics (see nic.DeliverLinkPacket) — protocol-specific endpoints do
//     NOT receive outbound packets, while an ETH_P_ALL registration receives
//     every packet exactly once in each direction. Outbound records carry
//     pkt.PktType == tcpip.PacketOutgoing; inbound ones PacketHost.
//   - Packets consumed by the NAT64 NIC-level interceptor
//     (nat64.Service.interceptPacket — ICMPv6 echo request/reply) never
//     reach gVisor at all: the interceptor runs in the YggdrasilNIC read
//     loop, before delivery. They are invisible to the tap.
//   - Everything else that traverses the stack is visible: NAT64-forwarded
//     TCP and UDP (terminated by gVisor's forwarders), DNS64 queries and
//     upstream replies, NDP, and any junk promiscuous mode lets through.
//
// It complements, never replaces, the interceptor.
type PacketTap struct {
	stack  *stack.Stack
	nicID  tcpip.NICID
	writer *pcapWriter

	// ch carries copied packet bytes to the writer goroutine. The channel
	// deliberately has no close: HandlePacket could still race with Close()
	// during unregistration, and sending on a closed channel would panic.
	// Shutdown is signalled via stopping instead, and the writer drains.
	ch       chan []byte
	stopping chan struct{}
}

// tapQueueLen bounds how many packets may be queued for the writer goroutine.
// A debug tap must never slow the data path: when the queue is full, packets
// are dropped rather than blocking gVisor's delivery.
const tapQueueLen = 1024

// StartPacketTap registers a PacketTap on the stack's NIC and starts its
// background writer. The caller must eventually Close it (on shutdown) to
// unregister from the stack and flush the capture file.
func StartPacketTap(st *stack.Stack, nicID tcpip.NICID, path string) (*PacketTap, error) {
	writer, err := openPcap(path)
	if err != nil {
		return nil, err
	}
	t := &PacketTap{
		stack:    st,
		nicID:    nicID,
		writer:   writer,
		ch:       make(chan []byte, tapQueueLen),
		stopping: make(chan struct{}),
	}
	if tcpErr := st.RegisterPacketEndpoint(nicID, header.EthernetProtocolAll, t); tcpErr != nil {
		writer.close()
		return nil, fmt.Errorf("registering packet tap: %s", tcpErr.String())
	}
	go t.writeLoop()
	return t, nil
}

// HandlePacket implements stack.PacketEndpoint. It runs inside gVisor's
// delivery path, so it only copies the packet (the PacketBuffer belongs to
// gVisor and is recycled after this call) and queues it; all file I/O happens
// on the writer goroutine. pkt is treated as immutable.
func (t *PacketTap) HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	vv := pkt.ToView()
	b := make([]byte, vv.Size())
	if _, err := vv.Read(b); err != nil {
		return
	}
	select {
	case t.ch <- b:
	default: // queue full: drop rather than block the data path
	}
}

// Close unregisters the tap from the stack and flushes/closes the capture
// file. Safe to call once; further HandlePacket calls (racing unregistration)
// only enqueue into the channel buffer, which the final drain discards if
// unwritten.
func (t *PacketTap) Close() {
	t.stack.UnregisterPacketEndpoint(t.nicID, header.EthernetProtocolAll, t)
	close(t.stopping)
}

// writeLoop writes queued packets until Close is called, then drains whatever
// was already queued (unregistration guarantees no new packets arrive) and
// closes the file.
func (t *PacketTap) writeLoop() {
	for {
		select {
		case b := <-t.ch:
			_ = t.writer.writePacket(time.Now(), b)
		case <-t.stopping:
			for {
				select {
				case b := <-t.ch:
					_ = t.writer.writePacket(time.Now(), b)
				default:
					_ = t.writer.close()
					return
				}
			}
		}
	}
}

// StartDebugPacketTap is the env-var-gated entry point used by main.go:
// YDN64_DEBUG_PCAP=path starts an inbound-only libpcap tap on NIC 1. Any
// error is reported to the caller for logging; the tap is strictly optional
// diagnostics and must never prevent startup.
func StartDebugPacketTap(st *stack.Stack, path string) (*PacketTap, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	return StartPacketTap(st, 1, path)
}
