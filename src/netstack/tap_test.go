package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// testLinkEndpoint is a minimal stack.LinkEndpoint for tap tests: it accepts
// an attached dispatcher (so packets can be injected) and records outbound
// packets (to prove the tap does NOT capture egress).
type testLinkEndpoint struct {
	dispatcher stack.NetworkDispatcher
	outbound   chan []byte
}

func (e *testLinkEndpoint) Attach(d stack.NetworkDispatcher) { e.dispatcher = d }
func (e *testLinkEndpoint) IsAttached() bool                 { return e.dispatcher != nil }
func (e *testLinkEndpoint) MTU() uint32                      { return 1500 }
func (*testLinkEndpoint) SetMTU(uint32)                      {}
func (*testLinkEndpoint) MaxHeaderLength() uint16            { return 0 }
func (*testLinkEndpoint) LinkAddress() tcpip.LinkAddress     { return "" }
func (*testLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)   {}
func (*testLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (*testLinkEndpoint) Wait()                                   {}
func (*testLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*testLinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (*testLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (*testLinkEndpoint) Close()                                  {}
func (*testLinkEndpoint) SetOnCloseAction(func())                 {}

func (e *testLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range list.AsSlice() {
		vv := pkt.ToView()
		b := make([]byte, vv.Size())
		_, _ = vv.Read(b)
		select {
		case e.outbound <- b:
		default:
		}
		n++
	}
	return n, nil
}

// buildTestIPv6Packet assembles a minimal valid IPv6 header + payload.
func buildTestIPv6Packet(src, dst net.IP, nextHeader byte, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = nextHeader
	pkt[7] = 64
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	copy(pkt[40:], payload)
	return pkt
}

// readAllPackets parses every pcap record from the file.
func readAllPackets(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if len(raw) < pcapGlobalHeaderLen {
		t.Fatalf("pcap too short: %d", len(raw))
	}
	var out [][]byte
	for off := pcapGlobalHeaderLen; off < len(raw); {
		if off+16 > len(raw) {
			t.Fatalf("truncated record header at %d", off)
		}
		incl := binary.LittleEndian.Uint32(raw[off+8 : off+12])
		off += 16
		if off+int(incl) > len(raw) {
			t.Fatalf("truncated record data at %d", off)
		}
		out = append(out, raw[off:off+int(incl)])
		off += int(incl)
	}
	return out
}

func TestPacketTapCapturesBothDirections(t *testing.T) {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	ep := &testLinkEndpoint{outbound: make(chan []byte, 8)}
	// DeliverLinkPackets is what routes packets (both directions) to packet
	// endpoints in this gVisor version; it is a per-NIC option, set exactly
	// like production sets it in NewYggdrasilNIC.
	if err := st.CreateNICWithOptions(1, ep, stack.NICOptions{
		DeliverLinkPackets: true,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions: %v", err)
	}

	// Route for the egress destination (200::/7 covers 200:1::/32 test addrs).
	if _, ipnet, err := net.ParseCIDR("200::/7"); err == nil {
		subnet, tcpErr := tcpip.NewSubnet(
			tcpip.AddrFromSlice(ipnet.IP.To16()),
			tcpip.MaskFrom(string(ipnet.Mask)),
		)
		if tcpErr != nil {
			t.Fatalf("NewSubnet: %v", tcpErr)
		}
		st.AddRoute(tcpip.Route{Destination: subnet, NIC: 1})
	}

	path := t.TempDir() + "/tap.pcap"
	tap, err := StartPacketTap(st, 1, path)
	if err != nil {
		t.Fatalf("StartPacketTap: %v", err)
	}

	// Inject two inbound packets with different payloads.
	in1 := buildTestIPv6Packet(net.ParseIP("200:1::1"), net.ParseIP("200:1::2"), 59, []byte("inbound-one"))
	in2 := buildTestIPv6Packet(net.ParseIP("200:1::3"), net.ParseIP("200:1::2"), 17, []byte("inbound-two"))
	for _, pkt := range [][]byte{in1, in2} {
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		ep.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
		pkb.DecRef()
	}

	// Produce OUTBOUND traffic through the stack's real egress path: a
	// connected UDP endpoint writing a datagram. The tap must see this too,
	// because DeliverLinkPackets hooks egress (nic.writeRawPacket) as well.
	if err := st.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(net.ParseIP("200:1::2").To16()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	var wq waiter.Queue
	udpEp, terr := st.NewEndpoint(header.UDPProtocolNumber, ipv6.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatalf("NewEndpoint: %v", terr)
	}
	defer udpEp.Close()
	if terr := udpEp.Connect(tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.ParseIP("200:1::1").To16()),
		Port: 53,
	}); terr != nil {
		t.Fatalf("Connect: %v", terr)
	}
	if _, terr := udpEp.Write(bytes.NewReader([]byte("outbound")), tcpip.WriteOptions{}); terr != nil {
		t.Fatalf("Write: %v", terr)
	}

	// Egress is asynchronous (the endpoint queues the datagram and a worker
	// writes it out); wait until all three packets have been written.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if len(readAllPackets(t, path)) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for 3 captured packets, got %d", len(readAllPackets(t, path)))
		}
		time.Sleep(20 * time.Millisecond)
	}

	tap.Close()

	got := readAllPackets(t, path)
	if len(got) != 3 {
		t.Fatalf("captured %d packets, want 3 (2 inbound + 1 outbound)", len(got))
	}
	var payloads []string
	for _, p := range got {
		payloads = append(payloads, string(p[40:]))
	}
	for _, want := range []string{"inbound-one", "inbound-two", "outbound"} {
		found := false
		for _, gotPayload := range payloads {
			if strings.Contains(gotPayload, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("captured %v; missing %q payload", payloads, want)
		}
	}

	// After Close, the tap must be unregistered: new inbound packets are not
	// captured and HandlePacket cannot panic the stack.
	pkbAfter := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(in1)})
	ep.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkbAfter)
	pkbAfter.DecRef()
	if got2 := readAllPackets(t, path); len(got2) != 3 {
		t.Errorf("captured %d packets after Close, want 3 (unregistered)", len(got2))
	}
}

func TestStartDebugPacketTapRequiresPath(t *testing.T) {
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocol},
	})
	_, err := StartDebugPacketTap(st, "")
	if err == nil {
		t.Fatalf("StartDebugPacketTap with empty path: err=nil, want error")
	}
	if !errors.Is(err, os.ErrInvalid) {
		t.Errorf("err = %v, want os.ErrInvalid", err)
	}
}
