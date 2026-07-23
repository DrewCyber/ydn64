package netstack

import (
	"fmt"
	"net"
	"sync"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// YggdrasilNetstack wraps a gVisor network stack connected to the
// Yggdrasil network via a custom LinkEndpoint (YggdrasilNIC).
type YggdrasilNetstack struct {
	stack *stack.Stack
	rwc   *ipv6rwc.ReadWriteCloser // direct write path for raw packet injection

	mu          sync.RWMutex
	interceptor func([]byte) bool // called per-packet before gVisor delivery; true = packet consumed
}

// Stack returns the underlying gVisor stack (used by NAT64 to install TCP forwarder).
func (s *YggdrasilNetstack) Stack() *stack.Stack { return s.stack }

// MTU returns the Yggdrasil network MTU, usable as a read-buffer size.
func (s *YggdrasilNetstack) MTU() uint64 { return s.rwc.MTU() }

// WritePacket injects a raw IPv6 packet into the Yggdrasil network.
// Used by NAT64 to send synthesised UDP reply packets without going through gVisor.
func (s *YggdrasilNetstack) WritePacket(pkt []byte) (int, error) { return s.rwc.Write(pkt) }

// SetPacketInterceptor installs a pre-gVisor packet hook.
// fn is called for every incoming packet; returning true means the packet was
// consumed and must NOT be delivered to gVisor.
// Safe to call at any time; concurrent NIC reads use RLock.
func (s *YggdrasilNetstack) SetPacketInterceptor(fn func([]byte) bool) {
	s.mu.Lock()
	s.interceptor = fn
	s.mu.Unlock()
}

// CreateYdn64Netstack builds the gVisor stack, attaches the Yggdrasil NIC,
// and — when pool6CIDR is non-empty (e.g. "301:363a:9499:c858::/96") —
// enables promiscuous mode so gVisor's TCP forwarder can accept packets
// destined to any address in the pool6 range.
func CreateYdn64Netstack(ygg *core.Core, pool6CIDR string) (*YggdrasilNetstack, error) {
	// NOTE: HandleLocal is intentionally left false (the default). gVisor's
	// HandleLocal mode is meant for same-stack loopback shortcutting, which
	// ydn64 never needs (it only ever talks to remote Yggdrasil peers). When
	// HandleLocal is true AND promiscuous mode is enabled on the NIC (as NAT64
	// does below for pool6 destinations), gVisor's IPv6 HandlePacket() treats
	// every remote sender's address as "one of our own" (since promiscuous
	// mode makes AcquireAssignedAddress auto-provision a temporary address for
	// any address queried) and drops ALL inbound traffic as a martian/local
	// source. Keeping HandleLocal false avoids that gVisor foot-gun entirely.
	s := &YggdrasilNetstack{
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6},
		}),
	}

	if tcpErr := s.NewYggdrasilNIC(ygg); tcpErr != nil {
		return nil, fmt.Errorf("creating Yggdrasil NIC: %s", tcpErr.String())
	}

	if pool6CIDR != "" {
		// Add a routing entry for the pool6 subnet so outgoing NAT64 reply
		// packets (source = pool6::IPv4) are routed through the Yggdrasil NIC.
		if err := s.addPool6Route(pool6CIDR); err != nil {
			return nil, fmt.Errorf("registering NAT64 pool6 route: %w", err)
		}
		// Enable promiscuous mode so gVisor accepts TCP SYNs whose destination
		// is pool6::IPv4 (an address range, not a single registered address).
		if tcpErr := s.stack.SetPromiscuousMode(1, true); tcpErr != nil {
			return nil, fmt.Errorf("enabling promiscuous mode for NAT64: %s", tcpErr.String())
		}
		// Enable spoofing so gVisor allows *outgoing* packets (e.g. TCP SYN-ACK
		// replies) to use a pool6::IPv4 source address, since that address is
		// never actually registered on the NIC (only matched via promiscuous
		// mode on receive). Without this, FindRoute's source-address lookup
		// (nic.findEndpoint, gated on Spoofing — a separate flag from
		// Promiscuous) fails and NAT64 TCP replies are silently dropped.
		if tcpErr := s.stack.SetSpoofing(1, true); tcpErr != nil {
			return nil, fmt.Errorf("enabling spoofing for NAT64: %s", tcpErr.String())
		}
	}

	return s, nil
}

// addPool6Route installs a routing entry for pool6CIDR → NIC1 so that
// packets originating from pool6::IPv4 (NAT64 replies) are sent via the
// Yggdrasil NIC.  A protocol address is NOT registered here because we rely
// on promiscuous mode for gVisor to accept inbound traffic to the range.
func (s *YggdrasilNetstack) addPool6Route(pool6CIDR string) error {
	_, ipnet, err := net.ParseCIDR(pool6CIDR)
	if err != nil {
		return fmt.Errorf("parsing pool6 CIDR %q: %w", pool6CIDR, err)
	}
	pool6Addr := tcpip.AddrFromSlice(ipnet.IP.To16())

	pool6Subnet, tcpErr := tcpip.NewSubnet(
		pool6Addr,
		tcpip.MaskFrom(string(ipnet.Mask)),
	)
	if tcpErr != nil {
		return fmt.Errorf("creating pool6 subnet route: %s", tcpErr)
	}
	s.stack.AddRoute(tcpip.Route{Destination: pool6Subnet, NIC: 1})
	return nil
}
