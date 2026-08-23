package nat64

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestApplyTCPKeepalive verifies that applyTCPKeepalive sets every knob it
// claims to, by reading them back off a real gVisor TCP endpoint. Options are
// settable on an endpoint in any state, so no handshake is needed.
func TestApplyTCPKeepalive(t *testing.T) {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	var wq waiter.Queue
	ep, err := st.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()

	if err := applyTCPKeepalive(ep); err != nil {
		t.Fatalf("applyTCPKeepalive: %v", err)
	}

	if !ep.SocketOptions().GetKeepAlive() {
		t.Errorf("keepalive not enabled (SocketOptions().GetKeepAlive() = false)")
	}

	var idle tcpip.KeepaliveIdleOption
	if err := ep.GetSockOpt(&idle); err != nil {
		t.Fatalf("GetSockOpt(KeepaliveIdleOption): %v", err)
	}
	if got := time.Duration(idle); got != tcpKeepaliveIdle {
		t.Errorf("keepalive idle = %v, want %v", got, tcpKeepaliveIdle)
	}

	var interval tcpip.KeepaliveIntervalOption
	if err := ep.GetSockOpt(&interval); err != nil {
		t.Fatalf("GetSockOpt(KeepaliveIntervalOption): %v", err)
	}
	if got := time.Duration(interval); got != tcpKeepaliveInterval {
		t.Errorf("keepalive interval = %v, want %v", got, tcpKeepaliveInterval)
	}

	count, err2 := ep.GetSockOptInt(tcpip.KeepaliveCountOption)
	if err2 != nil {
		t.Fatalf("GetSockOptInt(KeepaliveCountOption): %v", err2)
	}
	if count != tcpKeepaliveCount {
		t.Errorf("keepalive count = %d, want %d", count, tcpKeepaliveCount)
	}

	var userTimeout tcpip.TCPUserTimeoutOption
	if err := ep.GetSockOpt(&userTimeout); err != nil {
		t.Fatalf("GetSockOpt(TCPUserTimeoutOption): %v", err)
	}
	gotUT := time.Duration(userTimeout)
	if gotUT != tcpKeepaliveUserTimeout {
		t.Errorf("user timeout = %v, want %v", gotUT, tcpKeepaliveUserTimeout)
	}

	// The user timeout must never fire before the keepalive budget has been
	// exhausted: it exists for stalled transfers, not idle probing.
	if tcpKeepaliveUserTimeout < time.Duration(tcpKeepaliveIdle+time.Duration(tcpKeepaliveCount)*tcpKeepaliveInterval) {
		t.Errorf("user timeout (%v) is below keepalive detection budget (%v); dead-idle peers could be mis-aborted",
			tcpKeepaliveUserTimeout,
			tcpKeepaliveIdle+time.Duration(tcpKeepaliveCount)*tcpKeepaliveInterval)
	}
}
