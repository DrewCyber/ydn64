package netstack

import (
	"log"
	"net"
	"sync"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// YggdrasilNIC is a gVisor LinkEndpoint that routes packets through the
// Yggdrasil network via ipv6rwc.
type YggdrasilNIC struct {
	netstack   *YggdrasilNetstack
	ipv6rwc    *ipv6rwc.ReadWriteCloser
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
		ipv6rwc:     rwc,
		readBuf:     make([]byte, mtu),
		ctrlPackets: make(chan *stack.PacketBuffer, 100),
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
	go func() {
		for {
			rx, err := nic.ipv6rwc.Read(nic.readBuf)
			if err != nil {
				log.Println("yggdrasil NIC read error:", err)
				break
			}
			// Pre-gVisor interception hook (used by NAT64 for UDP packets).
			nic.netstack.mu.RLock()
			interceptor := nic.netstack.interceptor
			nic.netstack.mu.RUnlock()
			if interceptor != nil && interceptor(nic.readBuf[:rx]) {
				continue // packet was consumed by the interceptor
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(nic.readBuf[:rx]),
			})
			nic.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
			pkb.DecRef()
		}
	}()

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

func (e *YggdrasilNIC) MTU() uint32 { return uint32(e.ipv6rwc.MTU()) }

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
	if _, err := e.ipv6rwc.Write(buf[:n]); err != nil {
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
				// Dropped because the queue was full: not written.
			}
			continue
		}
		if tcpErr := e.writePacket(pkt); tcpErr != nil {
			log.Println("yggdrasil NIC write error:", tcpErr)
			return written, tcpErr
		}
		written++
	}
	return written, nil
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
	e.dispatcher = nil
}

func (e *YggdrasilNIC) SetOnCloseAction(func()) {}
