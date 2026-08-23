package netstack

import (
	"net"
	"sync"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// packetRW abstracts the frame transport (Read/Write) so tests can inject
// failing transports; *ipv6rwc.ReadWriteCloser is the production impl.
type packetRW interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
}

var _ packetRW = (*ipv6rwc.ReadWriteCloser)(nil)

// YggdrasilNIC is a gVisor LinkEndpoint that routes packets through the
// Yggdrasil network via ipv6rwc.
type YggdrasilNIC struct {
	netstack   *YggdrasilNetstack
	rwc        packetRW
	mtu        uint32
	dispatcher stack.NetworkDispatcher
	readBuf    []byte
	// writeBufs hands out private MTU-sized scratch buffers to writePacket.
	// WritePackets is called concurrently (gVisor TCP timer paths, forwarder
	// answer goroutines, the ctrlPackets flusher below), so a single shared
	// scratch field would interleave and corrupt outbound frames; buffers are
	// exclusively owned by one writePacket call at a time instead.
	writeBufs sync.Pool
	// ctrlPackets queues zero-payload TCP control frames for asynchronous
	// writing — see the comment in WritePackets for why.
	ctrlPackets chan *stack.PacketBuffer
	// readStop is closed exactly once when the NIC is removed, unblocking
	// the read loop's retry backoff.
	readStop     chan struct{}
	readStopOnce sync.Once
}

// NewYggdrasilNIC creates the Yggdrasil NIC, attaches it to the gVisor stack,
// applies the intended path MTU, adds the 200::/7 route, and registers the
// node's own address as local. See CreateYdn64Netstack for why ifMTU must be
// applied to the ipv6rwc explicitly.
func (s *YggdrasilNetstack) NewYggdrasilNIC(ygg *core.Core, ifMTU uint64) tcpip.Error {
	rwc := ipv6rwc.NewReadWriteCloser(ygg)
	// Apply the configured MTU BEFORE anything sizes buffers off rwc.MTU()
	// (the read/write buffers below, and gVisor's NIC route MTU). SetMTU
	// clamps into [1280, core max].
	rwc.SetMTU(ifMTU)
	s.rwc = rwc // expose for direct raw-packet writes (e.g. NAT64 ICMP replies)
	mtu := rwc.MTU()
	nic := &YggdrasilNIC{
		netstack:    s,
		rwc:         rwc,
		mtu:         uint32(mtu),
		readBuf:     make([]byte, mtu),
		ctrlPackets: make(chan *stack.PacketBuffer, 100),
		readStop:    make(chan struct{}),
	}
	nic.initWriteBufs(int(mtu))

	// DeliverLinkPackets makes the NIC hand raw packets — both inbound
	// deliveries and egress writes — to registered stack.PacketEndpoints,
	// which the optional debug packet tap (YDN64_DEBUG_PCAP, see PacketTap)
	// requires. With no packet endpoints registered the cost is one empty-list
	// check per packet, so leaving it always-on is harmless.
	if err := s.stack.CreateNICWithOptions(1, nic, stack.NICOptions{
		DeliverLinkPackets: true,
	}); err != nil {
		return err
	}

	// Packet receive loop: Yggdrasil network → gVisor stack.
	go s.readLoop(nic)

	// Control packet flush loop: zero-payload TCP frames (SYN, SYN-ACK, ACK,
	// FIN, RST) are queued here from WritePackets and written out
	// asynchronously — see the comment in WritePackets for why.
	go func() {
		for pkt := range nic.ctrlPackets {
			if pkt == nil {
				continue
			}
			_ = nic.writePacket(pkt)
			pkt.DecRef()
		}
	}()

	// Add route: 200::/7 → NIC1 (all yggdrasil node-to-node addresses).
	_, yggNet, err := net.ParseCIDR("0200::/7")
	if err != nil {
		return &tcpip.ErrBadAddress{}
	}
	yggSubnet, tcpErr := tcpip.NewSubnet(
		tcpip.AddrFromSlice(yggNet.IP.To16()),
		tcpip.MaskFrom(string(yggNet.Mask)),
	)
	if tcpErr != nil {
		return &tcpip.ErrBadAddress{}
	}
	s.stack.AddRoute(tcpip.Route{Destination: yggSubnet, NIC: 1})

	// Register the node's own address so gVisor delivers packets addressed to it.
	ip := ygg.Address()
	if addErr := s.stack.AddProtocolAddress(
		1,
		tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.To16()).WithPrefix(),
		},
		stack.AddressProperties{},
	); addErr != nil {
		return addErr
	}

	return nil
}

// readLoop delivers inbound frames from the Yggdrasil transport into the
// gVisor stack. A single transient Read error used to terminate this loop
// permanently (logged only to stderr, invisible in the service log), leaving
// the node running but deaf; instead, errors are now retried with bounded
// exponential backoff, and when reads stay broken for the configured grace
// period the process context is cancelled so a supervisor restarts an
// obviously dead node rather than keeping a zombie alive.
func (s *YggdrasilNetstack) readLoop(nic *YggdrasilNIC) {
	backoff := readRetryInitialBackoff
	brokenFor := time.Duration(0)
	for {
		rx, err := nic.rwc.Read(nic.readBuf)
		if err == nil {
			backoff, brokenFor = readRetryInitialBackoff, 0
			s.deliverInbound(nic, rx)
			continue
		}

		select {
		case <-nic.readStop:
			return
		default:
		}
		s.mu.RLock()
		logf, cancelRoot, grace := s.logf, s.cancelRoot, s.grace
		s.mu.RUnlock()
		if logf != nil {
			logf("yggdrasil NIC read error (retrying in %v, broken for %v so far): %v", backoff, brokenFor+backoff, err)
		}
		if brokenFor+backoff >= grace {
			if logf != nil {
				logf("yggdrasil NIC read loop giving up after ~%v of consecutive failures; cancelling process context", brokenFor)
			}
			if cancelRoot != nil {
				cancelRoot()
			}
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-nic.readStop:
			timer.Stop()
			return
		case <-timer.C:
		}
		brokenFor += backoff
		backoff *= 2
		if backoff > readRetryMaxBackoff {
			backoff = readRetryMaxBackoff
		}
	}
}

// deliverInbound hands one raw frame to the pre-gVisor interceptor (NAT64
// ICMP) and then to the gVisor dispatcher. The dispatcher is nil between
// Attach() and NIC removal — e.g. during shutdown races with Close() — in
// which case the frame is dropped instead of dereferencing nil.
func (s *YggdrasilNetstack) deliverInbound(nic *YggdrasilNIC, rx int) {
	s.mu.RLock()
	interceptor := s.interceptor
	d := nic.dispatcher
	s.mu.RUnlock()
	if interceptor != nil && interceptor(nic.readBuf[:rx]) {
		return // packet was consumed by the interceptor
	}
	if d == nil {
		return
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(nic.readBuf[:rx]),
	})
	d.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
	pkb.DecRef()
}

// initWriteBufs seeds the writeBufs pool with MTU-sized scratch buffers.
func (e *YggdrasilNIC) initWriteBufs(mtu int) {
	e.writeBufs.New = func() any {
		buf := make([]byte, mtu)
		return &buf
	}
}

// ── gVisor LinkEndpoint interface ────────────────────────────────────────────

func (e *YggdrasilNIC) Attach(dispatcher stack.NetworkDispatcher) { e.dispatcher = dispatcher }

func (e *YggdrasilNIC) IsAttached() bool { return e.dispatcher != nil }

func (e *YggdrasilNIC) MTU() uint32 { return e.mtu }

func (e *YggdrasilNIC) SetMTU(uint32) {}

func (*YggdrasilNIC) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }

func (*YggdrasilNIC) MaxHeaderLength() uint16 { return 40 }

func (*YggdrasilNIC) LinkAddress() tcpip.LinkAddress { return "" }

func (*YggdrasilNIC) SetLinkAddress(tcpip.LinkAddress) {}

func (*YggdrasilNIC) Wait() {}

func (e *YggdrasilNIC) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	// The packet parser may panic on malformed zero-payload packets.
	defer func() { recover() }() //nolint:errcheck
	bufp := e.writeBufs.Get().(*[]byte)
	defer e.writeBufs.Put(bufp)
	buf := *bufp
	vv := pkt.ToView()
	n, err := vv.Read(buf)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	if _, err := e.rwc.Write(buf[:n]); err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (e *YggdrasilNIC) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	for _, pkt := range list.AsSlice() {
		if pkt.Data().Size() == 0 && pkt.Network().TransportProtocol() == tcp.ProtocolNumber {
			// Zero-payload TCP control packets (SYN, SYN-ACK, pure ACK, FIN,
			// RST) are queued to a background writer instead of being written
			// synchronously here, since WritePackets can be invoked from deep
			// inside gVisor's packet-dispatch call path (e.g. when the TCP
			// forwarder issues an RST while handling an inbound segment).
			// Previously only RST frames were queued this way; every other
			// zero-payload control packet (crucially, SYN-ACK) was silently
			// dropped here, which broke the TCP handshake for NAT64.
			pkt.IncRef()
			select {
			case e.ctrlPackets <- pkt:
				// Ownership moved to the flusher; count as written, matching
				// how a driver reports frames handed off to a TX ring.
				written++
			default:
				pkt.DecRef()
				// Dropped because the queue was full: not written. This was
				// historically a catastrophic silent failure mode, so it is
				// counted and warned about (rate-limited).
				e.netstack.noteCtrlDrop()
			}
			continue
		}
		if tcpErr := e.writePacket(pkt); tcpErr != nil {
			e.netstack.logfLocked("yggdrasil NIC write error: %v", tcpErr)
			return written, tcpErr
		}
		written++
	}
	return written, nil
}

// noteCtrlDrop counts a control-frame drop and emits a warning at most once
// per warn interval so a flood of drops cannot flood the log.
func (s *YggdrasilNetstack) noteCtrlDrop() {
	total := s.ctrlDrops.Add(1)
	now := time.Now().UnixNano()
	last := s.ctrlLastWarn.Load()
	if last != 0 && now-last < ctrlDropWarnIntervalSecs*int64(time.Second) {
		return
	}
	if !s.ctrlLastWarn.CompareAndSwap(last, now) {
		return // another goroutine just warned
	}
	s.logfLocked("yggdrasil NIC ctrl queue full: %d control packets dropped in total; TCP handshake/teardown frames may be lost", total)
}

// logfLocked routes diagnostics to the supervised logger (stderr fallback).
func (s *YggdrasilNetstack) logfLocked(format string, args ...interface{}) {
	s.mu.RLock()
	logf := s.logf
	s.mu.RUnlock()
	if logf != nil {
		logf(format, args...)
	}
}

func (e *YggdrasilNIC) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	panic("WriteRawPacket: not implemented")
}

func (*YggdrasilNIC) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *YggdrasilNIC) AddHeader(*stack.PacketBuffer) {}

func (e *YggdrasilNIC) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *YggdrasilNIC) Close() {
	e.netstack.stack.RemoveNIC(1)
	e.readStopOnce.Do(func() { close(e.readStop) })
	e.dispatcher = nil
}

func (e *YggdrasilNIC) SetOnCloseAction(func()) {}
