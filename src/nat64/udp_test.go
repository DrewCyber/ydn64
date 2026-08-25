package nat64

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/DrewCyber/ydn64/src/config"
)

// ── parseUDPFlow: pure filtering logic ───────────────────────────────────────

func udpFlowID(src string, srcPort uint16, dst string, dstPort uint16) stack.TransportEndpointID {
	return stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP(src).To16()),
		RemotePort:    srcPort,
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP(dst).To16()),
		LocalPort:     dstPort,
	}
}

func TestParseUDPFlowFiltering(t *testing.T) {
	// Pool6 is a /96 here so the last 4 bytes of the address are the embedded
	// IPv4 destination (RFC 6052 /96 layout), same as production configs.
	s, err := NewService(
		config.NAT64Config{Pool6: "300:1:2:3::/96", UDPTimeout: 300},
		[]string{"200:a:b:c::/64"},
		[]string{"10.0.0.0/8"},
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create NAT64 service: %v", err)
	}

	// 300:1:2:3::102:0304 embeds 1.2.3.4; ::a00:1 embeds 10.0.0.1 (ignored).
	valid := udpFlowID("200:a:b:c::1", 40000, "300:1:2:3::102:0304", 53)
	outsideDst := udpFlowID("200:a:b:c::1", 40000, "400::1", 53)
	spoofedSrc := udpFlowID("300:1:2:3::5678", 40000, "300:1:2:3::102:0304", 53)
	disallowedSrc := udpFlowID("200:e:f::1", 40000, "300:1:2:3::102:0304", 53)
	ignoredDst := udpFlowID("200:a:b:c::1", 40000, "300:1:2:3::a00:1", 53)

	t.Run("valid flow", func(t *testing.T) {
		flow, ok := s.parseUDPFlow(valid)
		if !ok {
			t.Fatalf("expected valid flow to be accepted")
		}
		var wantSrc [16]byte
		copy(wantSrc[:], net.ParseIP("200:a:b:c::1").To16())
		var wantPool6 [16]byte
		copy(wantPool6[:], net.ParseIP("300:1:2:3::102:0304").To16())
		if flow.key.srcAddr != wantSrc {
			t.Errorf("srcAddr = %v, want %v", net.IP(flow.key.srcAddr[:]), net.IP(wantSrc[:]))
		}
		if flow.key.srcPort != 40000 || flow.key.dstPort != 53 {
			t.Errorf("ports = %d→%d, want 40000→53", flow.key.srcPort, flow.key.dstPort)
		}
		if got := net.IP(flow.key.dstAddr[:]); !got.Equal(net.IPv4(1, 2, 3, 4)) {
			t.Errorf("embedded IPv4 = %v, want 1.2.3.4", got)
		}
		if flow.pool6Src != wantPool6 {
			t.Errorf("pool6Src = %v, want %v", net.IP(flow.pool6Src[:]), net.IP(wantPool6[:]))
		}
	})

	t.Run("destination outside pool6 is dropped", func(t *testing.T) {
		if _, ok := s.parseUDPFlow(outsideDst); ok {
			t.Errorf("expected flow with non-pool6 destination to be dropped")
		}
	})

	t.Run("source inside pool6 (spoofed) is dropped", func(t *testing.T) {
		if _, ok := s.parseUDPFlow(spoofedSrc); ok {
			t.Errorf("expected spoofed source to be dropped (RFC 6146 §3.5/§5.4)")
		}
	})

	t.Run("disallowed source is dropped", func(t *testing.T) {
		if _, ok := s.parseUDPFlow(disallowedSrc); ok {
			t.Errorf("expected disallowed source to be dropped")
		}
	})

	t.Run("ignored destination IPv4 is dropped", func(t *testing.T) {
		if _, ok := s.parseUDPFlow(ignoredDst); ok {
			t.Errorf("expected ignored destination subnet to be dropped")
		}
	})

	t.Run("non-IPv6 address lengths are dropped", func(t *testing.T) {
		id := valid
		id.LocalAddress = tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
		if _, ok := s.parseUDPFlow(id); ok {
			t.Errorf("expected 4-byte local address to be dropped")
		}
		id = valid
		id.RemoteAddress = tcpip.AddrFrom4([4]byte{5, 6, 7, 8})
		if _, ok := s.parseUDPFlow(id); ok {
			t.Errorf("expected 4-byte remote address to be dropped")
		}
	})
}

// ── End-to-end UDP relay through a real gVisor stack ─────────────────────────

// chanLinkEndpoint is a minimal stack.LinkEndpoint: it accepts an attached
// dispatcher (so packets can be injected into the stack exactly like the
// YggdrasilNIC read loop does) and captures outbound packets for inspection.
type chanLinkEndpoint struct {
	dispatcher stack.NetworkDispatcher
	outbound   chan []byte
	mtu        uint32
}

func newChanLinkEndpoint(mtu uint32) *chanLinkEndpoint {
	return &chanLinkEndpoint{outbound: make(chan []byte, 32), mtu: mtu}
}

func (e *chanLinkEndpoint) Attach(d stack.NetworkDispatcher) { e.dispatcher = d }
func (e *chanLinkEndpoint) IsAttached() bool                 { return e.dispatcher != nil }
func (e *chanLinkEndpoint) MTU() uint32                      { return e.mtu }
func (*chanLinkEndpoint) SetMTU(uint32)                      {}
func (*chanLinkEndpoint) MaxHeaderLength() uint16            { return 0 }
func (*chanLinkEndpoint) LinkAddress() tcpip.LinkAddress     { return "" }
func (*chanLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)   {}
func (*chanLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (*chanLinkEndpoint) Wait()                                   {}
func (*chanLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*chanLinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (*chanLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (*chanLinkEndpoint) Close()                                  {}
func (*chanLinkEndpoint) SetOnCloseAction(func())                 {}

func (e *chanLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range list.AsSlice() {
		vv := pkt.ToView()
		b := make([]byte, vv.Size())
		if _, err := vv.Read(b); err != nil {
			continue
		}
		select {
		case e.outbound <- b:
		default: // never block the stack's write path in tests
		}
		n++
	}
	return n, nil
}

// fakeNetStack adapts a bare gVisor stack to the nat64.NetStack interface.
type fakeNetStack struct {
	st           *stack.Stack
	intercepting bool
}

func (f *fakeNetStack) Stack() *stack.Stack                 { return f.st }
func (f *fakeNetStack) MTU() uint64                         { return 1500 }
func (f *fakeNetStack) WritePacket(pkt []byte) (int, error) { return len(pkt), nil }

// SetPacketInterceptor mirrors the production hook; the synthetic stack has
// no NIC read loop, so the callback is merely recorded.
func (f *fakeNetStack) SetPacketInterceptor(fn func([]byte) bool) { f.intercepting = fn != nil }

// buildIPv6UDPTestPacket builds a syntactically valid IPv6+UDP packet with a
// correct pseudo-header checksum (RFC 8200 §8.1), suitable for injection into
// a gVisor stack. Production code no longer synthesises UDP packets (gVisor
// owns the UDP path), so this helper exists only in tests; it reuses
// ipv6UpperLayerChecksum, which doubles as a cross-check of that function
// against gVisor's own checksum validation.
func buildIPv6UDPTestPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 40+udpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17 // Next header = UDP
	pkt[7] = 64 // Hop limit
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	copy(pkt[48:], payload)
	cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 17, pkt[40:40+udpLen])
	if cs == 0 {
		cs = 0xFFFF // RFC 8200 §8.1: a computed UDP checksum of zero is transmitted as 0xFFFF
	}
	binary.BigEndian.PutUint16(pkt[46:48], cs)
	return pkt
}

// udpTestEnv wires a NAT64 service onto a synthetic gVisor stack with
// promiscuous+spoofing NIC (mirroring CreateYdn64Netstack) and a loopback
// UDP echo server standing in for the real IPv4 destination.
type udpTestEnv struct {
	svc      *Service
	nic      *chanLinkEndpoint
	cap      *capturingNetStack // records raw injections (WritePacket)
	stack    *stack.Stack
	echoPort uint16
}

func newUDPTestEnv(t *testing.T, udpTimeout int) *udpTestEnv {
	t.Helper()

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	nic := newChanLinkEndpoint(1500)
	if err := st.CreateNIC(1, nic); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	// Both flags are mandatory, exactly as in CreateYdn64Netstack: promiscuous
	// mode accepts pool6 destinations, spoofing lets replies originate from
	// the pool6 source address.
	if err := st.SetPromiscuousMode(1, true); err != nil {
		t.Fatalf("SetPromiscuousMode: %v", err)
	}
	if err := st.SetSpoofing(1, true); err != nil {
		t.Fatalf("SetSpoofing: %v", err)
	}
	for _, cidr := range []string{"200::/7", "300:1:2:3::/96"} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		subnet, tcpErr := tcpip.NewSubnet(
			tcpip.AddrFromSlice(ipnet.IP.To16()),
			tcpip.MaskFrom(string(ipnet.Mask)),
		)
		if tcpErr != nil {
			t.Fatalf("NewSubnet(%q): %v", cidr, err)
		}
		st.AddRoute(tcpip.Route{Destination: subnet, NIC: 1})
	}

	// Loopback UDP echo server plays the "real IPv4 server" role.
	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { echoConn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := echoConn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	ns := &capturingNetStack{fakeNetStack: fakeNetStack{st: st}}
	svc, err := NewService(
		config.NAT64Config{Pool6: "300:1:2:3::/96", UDPTimeout: udpTimeout},
		[]string{"200:a:b:c::/64"},
		nil, // no ignored subnets: the echo server lives on 127.0.0.1
		ns,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	logger := log.New(io.Discard, "", 0)
	logger.EnableLevel("debug")
	udpFwd := udp.NewForwarder(st, func(req *udp.ForwarderRequest) bool {
		return svc.handleUDPForward(req, logger)
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return &udpTestEnv{
		svc:      svc,
		nic:      nic,
		cap:      ns,
		stack:    st,
		echoPort: uint16(echoConn.LocalAddr().(*net.UDPAddr).Port),
	}
}

// inject delivers a synthetic inbound IPv6+UDP datagram aimed at the
// loopback IPv4 destination the same way the YggdrasilNIC read loop
// delivers real ones.
func (env *udpTestEnv) inject(t *testing.T, src net.IP, srcPort uint16, dstPort uint16, payload []byte) {
	t.Helper()
	env.injectTo(t, src, srcPort, "127.0.0.1", dstPort, payload)
}

// injectTo is inject with an explicit embedded IPv4 destination (the last
// four bytes of the pool6 address). dstV4 must be a loopback address the
// test host can actually reach.
func (env *udpTestEnv) injectTo(t *testing.T, src net.IP, srcPort uint16, dstV4 string, dstPort uint16, payload []byte) {
	t.Helper()
	pool6Dst := make(net.IP, 16)
	copy(pool6Dst, net.ParseIP("300:1:2:3::").To16())
	copy(pool6Dst[12:], net.ParseIP(dstV4).To4())
	pkt := buildIPv6UDPTestPacket(src, pool6Dst, srcPort, dstPort, payload)
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	env.nic.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
	pkb.DecRef()
}

// readOutbound waits for the next packet written out through the NIC.
func (env *udpTestEnv) readOutbound(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-env.nic.outbound:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an outbound packet")
		return nil
	}
}

// assertNoOutbound fails the test if any packet leaves the NIC within d.
func (env *udpTestEnv) assertNoOutbound(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case b := <-env.nic.outbound:
		t.Fatalf("unexpected outbound packet: %x", b)
	case <-time.After(d):
	}
}

// parseOutboundUDP validates the IPv6+UDP framing of a captured outbound
// packet and returns the reply payload.
func parseOutboundUDP(t *testing.T, pkt []byte, wantSrc, wantDst net.IP, wantSrcPort, wantDstPort uint16) []byte {
	t.Helper()
	if len(pkt) < 48 {
		t.Fatalf("outbound packet too short: %d bytes", len(pkt))
	}
	if pkt[0]>>4 != 6 {
		t.Fatalf("outbound packet is not IPv6: version %d", pkt[0]>>4)
	}
	if got := net.IP(pkt[8:24]); !got.Equal(wantSrc.To16()) {
		t.Errorf("reply src = %v, want %v", got, wantSrc)
	}
	if got := net.IP(pkt[24:40]); !got.Equal(wantDst.To16()) {
		t.Errorf("reply dst = %v, want %v", got, wantDst)
	}
	if got := binary.BigEndian.Uint16(pkt[40:42]); got != wantSrcPort {
		t.Errorf("reply sport = %d, want %d", got, wantSrcPort)
	}
	if got := binary.BigEndian.Uint16(pkt[42:44]); got != wantDstPort {
		t.Errorf("reply dport = %d, want %d", got, wantDstPort)
	}
	if got := binary.BigEndian.Uint16(pkt[4:6]); int(got) != len(pkt)-40 {
		t.Errorf("payload length = %d, want %d", got, len(pkt)-40)
	}
	udpSeg := pkt[40 : 40+binary.BigEndian.Uint16(pkt[4:6])]
	if cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 17, udpSeg); cs != 0 {
		t.Errorf("reply UDP checksum invalid (verification checksum = 0x%04x)", cs)
	}
	return udpSeg[8:]
}

func TestNAT64UDPRelayEndToEnd(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	client := net.ParseIP("200:a:b:c::1").To16()
	pool6Src := net.ParseIP("300:1:2:3::7f00:0001").To16()

	// First datagram of a tuple: forwarder creates the endpoint (which also
	// queues this very datagram), the relay dials the echo server, and the
	// reply comes back out through the NIC as a synthesised-by-gVisor packet.
	env.inject(t, client, 40000, env.echoPort, []byte("hello"))
	reply := env.readOutbound(t)
	got := parseOutboundUDP(t, reply, pool6Src, client, env.echoPort, 40000)
	if string(got) != "hello" {
		t.Errorf("reply payload = %q, want %q", got, "hello")
	}

	// Second datagram on the SAME tuple must be demuxed by gVisor's transport
	// demuxer straight into the registered endpoint (the forwarder handler is
	// not consulted again), relayed, and answered.
	env.inject(t, client, 40000, env.echoPort, []byte("second datagram"))
	reply = env.readOutbound(t)
	got = parseOutboundUDP(t, reply, pool6Src, client, env.echoPort, 40000)
	if string(got) != "second datagram" {
		t.Errorf("second reply payload = %q, want %q", got, "second datagram")
	}

	// Exactly one session should now be tracked.
	if n := countSessions(env.svc); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
}

func TestNAT64UDPDisallowedSourceSilentDrop(t *testing.T) {
	env := newUDPTestEnv(t, 30)

	// Disallowed source: the forwarder handler must consume the datagram
	// silently — no relay, no outbound packet, and crucially no ICMPv6
	// port-unreachable emitted by the stack.
	disallowed := net.ParseIP("200:e:f::1").To16()
	env.inject(t, disallowed, 40001, env.echoPort, []byte("should drop"))
	env.assertNoOutbound(t, 300*time.Millisecond)

	if n := countSessions(env.svc); n != 0 {
		t.Errorf("sessions = %d, want 0 after disallowed flow", n)
	}
}

func TestNAT64UDPSessionIdleExpiry(t *testing.T) {
	env := newUDPTestEnv(t, 1) // 1s idle timeout; cleanup ticks every 500ms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go env.svc.cleanupSessions(ctx)

	client := net.ParseIP("200:a:b:c::1").To16()
	pool6Src := net.ParseIP("300:1:2:3::7f00:0001").To16()

	env.inject(t, client, 41000, env.echoPort, []byte("first"))
	got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 41000)
	if string(got) != "first" {
		t.Errorf("reply payload = %q, want %q", got, "first")
	}

	// After ~2× the idle timeout with no traffic the session must be gone:
	// cleanup closes both legs, both relay loops exit and delete the key.
	deadline := time.Now().Add(6 * time.Second)
	for countSessions(env.svc) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("session not expired after idle timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A new datagram for the same tuple must start a fresh session: the old
	// endpoint was unregistered from the demuxer on close, so the forwarder
	// handler runs again and CreateEndpoint re-registers the tuple.
	env.inject(t, client, 41000, env.echoPort, []byte("after expiry"))
	got = parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 41000)
	if string(got) != "after expiry" {
		t.Errorf("reply payload after expiry = %q, want %q", got, "after expiry")
	}
}

func countSessions(s *Service) int {
	n := 0
	s.sessions.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// TestUDPBufPoolRecycles pins the buffer-pool contract the UDP relay loops
// rely on (code-review-2026-08-24 #4): Get always yields a full-size buffer,
// and buffers are reusable after Put. Reuse is only sound because every
// consumer of a read (WriteToUDP, conn6.Write, injectUnsolicitedUDP) copies
// the payload synchronously before its loop returns the buffer — if a future
// consumer ever retains a slice past that point, it must copy first.
func TestUDPBufPoolRecycles(t *testing.T) {
	buf := udpBufPool.Get().([]byte)
	if len(buf) != maxUDPDatagramSize {
		t.Fatalf("pooled buffer len = %d, want %d", len(buf), maxUDPDatagramSize)
	}
	for i := range buf {
		buf[i] = 0xAA
	}
	udpBufPool.Put(buf)

	next := udpBufPool.Get().([]byte)
	if len(next) != maxUDPDatagramSize {
		t.Fatalf("recycled buffer len = %d, want %d", len(next), maxUDPDatagramSize)
	}
	if &buf[0] != &next[0] {
		t.Log("pool handed out a different backing array (valid but means GC ran between Get calls)")
	}
}
