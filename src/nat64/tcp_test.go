package nat64

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
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

// TestApplyTCPOSKeepalive verifies the OS-side IPv4 leg gets the same
// dead-peer budget as the gVisor leg (code-review-2026-08-24 #3): the config
// applies cleanly to a real TCPConn. Reading the underlying socket options
// back would require per-platform getsockopt calls, so this pins the
// non-fatal contract plus the budget arithmetic instead.
func TestApplyTCPOSKeepalive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- acceptResult{nil, err}
			return
		}
		accepted <- acceptResult{c.(*net.TCPConn), nil}
	}()

	dialed, err := net.DialTimeout("tcp4", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()
	tcp4 := dialed.(*net.TCPConn)

	if err := applyTCPOSKeepalive(tcp4); err != nil {
		t.Fatalf("applyTCPOSKeepalive: %v", err)
	}

	res := <-accepted
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	defer res.conn.Close()

	// Detection budget sanity: identical to the gVisor leg's ≈165s.
	want := tcpKeepaliveIdle + time.Duration(tcpKeepaliveCount)*tcpKeepaliveInterval
	if want > 3*time.Minute {
		t.Errorf("OS-leg dead-peer detection budget = %v; slots would outlive reasonable reaping", want)
	}
}

// newTCPTimeoutService builds a Service with the given proxied-TCP idle
// timeout in seconds. NewService takes raw values without running
// AppConfig.Validate, so sub-floor values can be injected for fast tests.
func newTCPTimeoutService(t *testing.T, tcpTimeoutSecs int) *Service {
	t.Helper()
	s, err := NewService(config.NAT64Config{
		Pool6:      "300:1:2:3::/96",
		UDPTimeout: 300,
		TCPTimeout: tcpTimeoutSecs,
	}, []string{"200::/7"}, nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

// pipeClosed reports whether c is closed/errored by reading it in a
// goroutine and giving it d to either return (closed) or keep blocking
// (still open). net.Pipe conns do not support deadlines, hence this dance.
func pipeClosed(t *testing.T, c net.Conn, d time.Duration) bool {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		errCh <- err
	}()
	select {
	case <-errCh:
		return true
	case <-time.After(d):
		return false
	}
}

const pipeProbeDelay = 200 * time.Millisecond

func TestActivityConnTouchesPairStamp(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	pair := &tcpPair{a: c1, b: c2}
	stale := time.Now().Add(-time.Hour).UnixNano()
	pair.lastSeen.Store(stale)

	ac := &activityConn{Conn: c1, pair: pair}

	// Read path: far end writes, our wrapper read must refresh the stamp.
	go func() { c2.Write([]byte("ping")) }() //nolint:errcheck
	buf := make([]byte, 4)
	n, err := ac.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("Read = (%d, %v), want (4, nil)", n, err)
	}
	if got := pair.lastSeen.Load(); got == stale {
		t.Error("successful Read did not refresh the pair's last-seen stamp")
	}

	// Write path: far end reads what we write through the wrapper.
	before := pair.lastSeen.Load()
	readN := make(chan int, 1)
	go func() {
		b := make([]byte, 4)
		n, _ := c2.Read(b)
		readN <- n
	}()
	if _, err := ac.Write([]byte("pong")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n := <-readN; n != 4 {
		t.Fatalf("far end read %d bytes, want 4", n)
	}
	if got := pair.lastSeen.Load(); got == before {
		t.Error("successful Write did not refresh the pair's last-seen stamp")
	}
}

func TestReapIdleTCPClosesBothLegs(t *testing.T) {
	s := newTCPTimeoutService(t, 1) // 1s idle timeout

	idleA, idleB := net.Pipe()
	freshA, freshB := net.Pipe()
	defer func() { idleA.Close(); idleB.Close() }()
	defer func() { freshA.Close(); freshB.Close() }()

	pIdle := s.trackTCP(idleA, idleB, "idle")
	pFresh := s.trackTCP(freshA, freshB, "fresh")

	time.Sleep(1200 * time.Millisecond) // let the idle pair age past the timeout
	pFresh.touch()                      // the fresh pair stays active right up to the reap

	s.reapIdleTCP()

	if !pipeClosed(t, idleA, pipeProbeDelay) {
		t.Error("idle pair leg A was not closed by reapIdleTCP")
	}
	if !pipeClosed(t, idleB, pipeProbeDelay) {
		t.Error("idle pair leg B was not closed by reapIdleTCP")
	}
	if pipeClosed(t, freshA, pipeProbeDelay) {
		t.Error("active pair leg A was wrongly reaped")
	}
	if pipeClosed(t, freshB, pipeProbeDelay) {
		t.Error("active pair leg B was wrongly reaped")
	}

	// Production untracks via defer when the proxy goroutine exits; mimic
	// that here and confirm only the surviving pair remains tracked.
	s.untrackTCP(pIdle)
	if got := s.trackedTCPCount(); got != 1 {
		t.Errorf("trackedTCPCount after untrack = %d, want 1", got)
	}
	_ = pFresh // still tracked; closing happens via defers above
}

func TestCleanupSessionsShutdownClosesTrackedTCP(t *testing.T) {
	s := newTCPTimeoutService(t, 300)

	a, b := net.Pipe()
	defer func() { a.Close(); b.Close() }()
	s.trackTCP(a, b, "shutdown")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.cleanupSessions(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // let the loop reach its select

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupSessions did not exit on context cancellation")
	}

	if !pipeClosed(t, a, pipeProbeDelay) || !pipeClosed(t, b, pipeProbeDelay) {
		t.Error("shutdown did not close both legs of the tracked TCP connection")
	}
}

func TestReloadUpdatesTCPTimeout(t *testing.T) {
	s := newTCPTimeoutService(t, config.DefaultNat64TcpTimeout)
	if got := s.tcpTimeout(); got != 7440*time.Second {
		t.Fatalf("initial tcpTimeout = %v, want 7440s", got)
	}
	s.Reload(config.NAT64Config{
		Pool6:      "300:1:2:3::/96",
		UDPTimeout: 300,
		TCPTimeout: 8000,
	}, []string{"200::/7"}, nil)
	if got := s.tcpTimeout(); got != 8000*time.Second {
		t.Errorf("tcpTimeout after Reload = %v, want 8000s", got)
	}
}

// TestProxyTCPPreservesHalfClose pins the code-review-2026-08-24 #8 fix: a
// clean EOF on one leg must half-close that direction (CloseWrite) instead of
// tearing down both legs, so protocols relying on shutdown-write-then-read
// keep working through the translator.
func TestProxyTCPPreservesHalfClose(t *testing.T) {
	// makeLeg builds one loopback TCP pair: `proxyEnd` is what proxyTCP
	// sees, `peer` is the remote endpoint (client or server) in the test.
	makeLeg := func(t *testing.T) (proxyEnd, peer net.Conn) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		type result struct {
			c   net.Conn
			err error
		}
		accepted := make(chan result, 1)
		go func() {
			c, err := ln.Accept()
			accepted <- result{c, err}
		}()

		peer, err = net.DialTimeout("tcp4", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { peer.Close() })

		res := <-accepted
		if res.err != nil {
			t.Fatalf("accept: %v", res.err)
		}
		return res.c, peer
	}

	clientEnd, clientPeer := makeLeg(t)
	serverEnd, serverPeer := makeLeg(t)

	go proxyTCP(clientEnd, serverEnd)
	t.Cleanup(func() { clientEnd.Close(); serverEnd.Close() })

	// Client sends data then half-closes its write side.
	if _, err := clientPeer.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if tcp, ok := clientPeer.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
	}

	// Server reads the data, then must observe a clean EOF — proof the
	// half-close crossed both copy loops instead of closing the leg.
	buf := make([]byte, 5)
	if _, err := io.ReadFull(serverPeer, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("server read %q, want %q", buf, "hello")
	}
	_ = serverPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := serverPeer.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("server read after client EOF = (%d, %v), want (0, io.EOF)", n, err)
	}

	// The reverse direction must still be open: the server replies now.
	if _, err := serverPeer.Write([]byte("world")); err != nil {
		t.Fatalf("server write after receiving EOF: %v", err)
	}
	if tcp, ok := serverPeer.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("server CloseWrite: %v", err)
		}
	}

	// Client receives the reply and then its own clean EOF.
	_ = clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	out := make([]byte, 0, 5)
	for len(out) < len("world") {
		n, err := clientPeer.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			t.Fatalf("client read: %v (after %q)", err, out)
		}
	}
	if string(out) != "world" {
		t.Fatalf("client read %q, want %q", out, "world")
	}
	if n, err := clientPeer.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("client read after server EOF = (%d, %v), want (0, io.EOF)", n, err)
	}
}
