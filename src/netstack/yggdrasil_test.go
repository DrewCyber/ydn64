package netstack

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// newTestNIC builds a YggdrasilNIC backed by an offline core (no peers), so
// writePacket succeeds for any frame whose source address is the node's own
// address. When startFlusher is true, a production-style control-packet
// flusher drains nic.ctrlPackets until the returned cleanup runs.
func newTestNIC(t *testing.T, mtu int, startFlusher bool) (*YggdrasilNIC, tcpip.Address, func()) {
	t.Helper()
	ygg := newTestCore(t)
	rwc := ipv6rwc.NewReadWriteCloser(ygg)
	rwc.SetMTU(uint64(mtu))
	ns := &YggdrasilNetstack{}
	ns.logf = func(string, ...interface{}) {} // keep test output clean
	nic := &YggdrasilNIC{
		netstack:    ns,
		rwc:         rwc,
		mtu:         uint32(mtu),
		readBuf:     make([]byte, mtu),
		ctrlPackets: make(chan *stack.PacketBuffer, 100),
		readStop:    make(chan struct{}),
	}
	nic.initWriteBufs(mtu)

	var flushDone chan struct{}
	if startFlusher {
		flushDone = make(chan struct{})
		go func() {
			defer close(flushDone)
			for pkt := range nic.ctrlPackets {
				if pkt == nil {
					continue
				}
				_ = nic.writePacket(pkt)
				pkt.DecRef()
			}
		}()
	}

	nodeAddrBytes := rwc.Address()
	nodeAddr := tcpip.AddrFromSlice(nodeAddrBytes[:])
	cleanup := func() {
		if flushDone != nil {
			close(nic.ctrlPackets)
			<-flushDone
		}
	}
	return nic, nodeAddr, cleanup
}

// yggDest returns an arbitrary 200::/7 destination address derived from seed.
func yggDest(seed byte) tcpip.Address {
	var a [16]byte
	a[0] = 0x02
	a[1] = seed
	a[15] = seed
	return tcpip.AddrFrom16(a)
}

// bogusSrcAddr is a source address that is neither the node's own address nor
// inside its subnet; ipv6rwc.Write rejects such frames synchronously.
var bogusSrcAddr = tcpip.AddrFromSlice(net.ParseIP("2001:db8::1").To16())

func newUDPPacket(src, dst tcpip.Address, srcPort, dstPort uint16, payload []byte) *stack.PacketBuffer {
	udpLen := header.UDPMinimumSize + len(payload)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + udpLen,
	})
	pkt.NetworkProtocolNumber = ipv6.ProtocolNumber
	pkt.TransportProtocolNumber = udp.ProtocolNumber

	u := header.UDP(pkt.TransportHeader().Push(udpLen))
	u.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(u.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLen))
	u.SetChecksum(^u.CalculateChecksum(xsum))

	hdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	hdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	return pkt
}

func newTCPControlPacket(src, dst tcpip.Address, srcPort, dstPort uint16, flags header.TCPFlags, seq uint32) *stack.PacketBuffer {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + header.TCPMinimumSize,
	})
	pkt.NetworkProtocolNumber = ipv6.ProtocolNumber
	pkt.TransportProtocolNumber = tcp.ProtocolNumber

	th := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	th.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 0xFFFF,
	})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, header.TCPMinimumSize)
	th.SetChecksum(^th.CalculateChecksum(xsum))

	hdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	hdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: tcp.ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	return pkt
}

func decRefAll(list stack.PacketBufferList) {
	for _, pkt := range list.AsSlice() {
		pkt.DecRef()
	}
}

func TestWritePacketsCountsWritten(t *testing.T) {
	nic, node, cleanup := newTestNIC(t, 1500, true)
	defer cleanup()

	dst := yggDest(0x42)
	list := stack.PacketBufferList{}
	list.PushBack(newUDPPacket(node, dst, 1000, 2000, []byte("payload one")))
	list.PushBack(newTCPControlPacket(node, dst, 1000, 2000, header.TCPFlagSyn, 1))
	list.PushBack(newUDPPacket(node, dst, 1000, 2000, []byte("payload two")))
	list.PushBack(newTCPControlPacket(node, dst, 1000, 2000, header.TCPFlagAck, 2))
	list.PushBack(newUDPPacket(node, dst, 1000, 2000, []byte("payload three")))

	// Regression for R3: success must report the number of packets in the
	// batch (the old code returned the last index, i.e. len-1).
	n, err := nic.WritePackets(list)
	if err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if want := list.Len(); n != want {
		t.Errorf("WritePackets wrote %d packets, want %d", n, want)
	}
	decRefAll(list)

	empty := stack.PacketBufferList{}
	if n, err := nic.WritePackets(empty); n != 0 || err != nil {
		t.Errorf("WritePackets(empty) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestWritePacketsErrorReturnsWrittenSoFar(t *testing.T) {
	nic, node, cleanup := newTestNIC(t, 1500, true)
	defer cleanup()

	dst := yggDest(0x43)
	// A source address that is neither the node's address nor inside its
	// subnet makes ipv6rwc.Write fail synchronously ("incorrect source
	// address"), which writePacket surfaces as ErrAborted.
	list := stack.PacketBufferList{}
	list.PushBack(newUDPPacket(node, dst, 1000, 2000, []byte("good")))
	list.PushBack(newUDPPacket(bogusSrcAddr, dst, 1000, 2000, []byte("bad")))
	list.PushBack(newUDPPacket(node, dst, 1000, 2000, []byte("never reached")))

	n, err := nic.WritePackets(list)
	if err == nil {
		t.Fatal("WritePackets with failing packet: got nil error, want error")
	}
	if n != 1 {
		t.Errorf("WritePackets wrote %d packets before failure, want 1", n)
	}
	decRefAll(list)

	// Regression for R3: if the FIRST packet fails, the old code returned
	// -1; the contract requires 0 written + error.
	solo := stack.PacketBufferList{}
	solo.PushBack(newUDPPacket(bogusSrcAddr, dst, 1000, 2000, []byte("bad")))
	n, err = nic.WritePackets(solo)
	if err == nil {
		t.Fatal("WritePackets single failing packet: got nil error, want error")
	}
	if n != 0 {
		t.Errorf("WritePackets first-packet failure wrote %d, want 0", n)
	}
	decRefAll(solo)
}

func TestWritePacketsControlQueueFullNotCounted(t *testing.T) {
	nic, node, cleanup := newTestNIC(t, 1500, false) // no flusher: queue stays full
	defer cleanup()

	q := make(chan *stack.PacketBuffer, 1)
	nic.ctrlPackets = q

	dst := yggDest(0x44)
	list := stack.PacketBufferList{}
	for i := 0; i < 5; i++ {
		list.PushBack(newTCPControlPacket(node, dst, 1000, 2000, header.TCPFlagAck, uint32(i+1)))
	}

	// Queue holds 1; the other four are dropped and MUST NOT be counted as
	// written.
	n, err := nic.WritePackets(list)
	if err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if n != 1 {
		t.Errorf("WritePackets counted %d control packets, want 1 (queue capacity)", n)
	}

	select {
	case pkt := <-q:
		pkt.DecRef()
	default:
		t.Fatal("expected one queued control packet")
	}
	decRefAll(list)
}

// TestWritePacketsConcurrentNoRace is the R1 regression test: WritePackets is
// called concurrently from several goroutines while the control-packet
// flusher writes from its own goroutine — exactly the interleaving (gVisor
// TCP timers, forwarder answer paths, flusher) that used to race on the
// shared writeBuf scratch field. Run under `go test -race`.
func TestWritePacketsConcurrentNoRace(t *testing.T) {
	const writers = 8
	const iters = 250

	nic, node, cleanup := newTestNIC(t, 1500, true)
	defer cleanup()

	errs := make(chan tcpip.Error, writers)
	totalWritten := make(chan int, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			srcPort := uint16(20000 + w)
			written := 0
			for i := 0; i < iters; i++ {
				dst := yggDest(byte(w + 1))
				payload := []byte{byte(w), byte(i)}
				list := stack.PacketBufferList{}
				list.PushBack(newUDPPacket(node, dst, srcPort, 9000, payload))
				list.PushBack(newTCPControlPacket(node, dst, srcPort, 9000, header.TCPFlagAck, uint32(i)))
				list.PushBack(newUDPPacket(node, dst, srcPort, 9000, payload))

				n, err := nic.WritePackets(list)
				decRefAll(list)
				if err != nil {
					errs <- err
					return
				}
				if n < 2 {
					t.Errorf("writer %d iter %d: wrote %d packets, want at least the 2 payload packets", w, i, n)
					return
				}
				written += n
			}
			totalWritten <- written
		}(w)
	}
	wg.Wait()
	close(errs)
	close(totalWritten)

	for err := range errs {
		t.Errorf("concurrent WritePackets failed: %v", err)
	}
	sum := 0
	for n := range totalWritten {
		sum += n
	}
	// Every payload packet is always counted; control packets only when the
	// queue accepts them, so the sum is bounded by [writers*iters*2,
	// writers*iters*3].
	if min := writers * iters * 2; sum < min {
		t.Errorf("total written packets = %d, want >= %d", sum, min)
	}
}

// scriptedRW is a packetRW whose Read fails failN times, then parks until
// release is closed (subsequent Reads return an error afterwards). It lets
// tests drive the supervised read loop through transient-failure and
// permanent-failure scenarios deterministically.
type scriptedRW struct {
	mu        sync.Mutex
	failN     int
	alwaysErr bool // true: never park, always fail
	err       error
	release   chan struct{}
	reads     atomic.Int32
}

func (f *scriptedRW) Read(p []byte) (int, error) {
	f.reads.Add(1)
	f.mu.Lock()
	fn := f.failN
	if fn > 0 {
		f.failN--
	}
	err := f.err
	always := f.alwaysErr
	f.mu.Unlock()
	if fn > 0 || always {
		return 0, err
	}
	<-f.release
	return 0, err
}

func (f *scriptedRW) Write(p []byte) (int, error) { return len(p), nil }

type logSpy struct {
	mu   sync.Mutex
	line []string
}

func (l *logSpy) Printf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line = append(l.line, format)
}

func (l *logSpy) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.line)
}

// TestReadLoopCancelsAfterGracePeriod: with reads failing forever, the loop
// must retry with backoff, keep logging, and finally invoke the supervised
// cancel func instead of dying silently or spinning.
func TestReadLoopCancelsAfterGracePeriod(t *testing.T) {
	ns := &YggdrasilNetstack{}
	spy := &logSpy{}
	ns.logf = spy.Printf
	ns.grace = 100 * time.Millisecond

	cancelled := make(chan struct{})
	var once sync.Once
	ns.cancelRoot = func() { once.Do(func() { close(cancelled) }) }

	rw := &scriptedRW{alwaysErr: true, err: errors.New("transport dead"), release: make(chan struct{})}
	nic := &YggdrasilNIC{
		netstack: ns,
		rwc:      rw,
		readBuf:  make([]byte, 128),
		readStop: make(chan struct{}),
	}
	go ns.readLoop(nic)

	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("read loop did not cancel the process context within the grace period")
	}
	if spy.count() < 3 {
		t.Errorf("expected multiple error logs during retries, got %d", spy.count())
	}
}

// TestReadLoopSurvivesTransientErrors: a couple of failed reads followed by
// a parked transport must NOT trigger cancellation; the loop stays alive.
func TestReadLoopSurvivesTransientErrors(t *testing.T) {
	ns := &YggdrasilNetstack{}
	ns.logf = (&logSpy{}).Printf
	ns.grace = 30 * time.Second

	cancelled := make(chan struct{})
	var once sync.Once
	ns.cancelRoot = func() { once.Do(func() { close(cancelled) }) }

	release := make(chan struct{})
	rw := &scriptedRW{failN: 2, err: errors.New("transient"), release: release}
	nic := &YggdrasilNIC{
		netstack: ns,
		rwc:      rw,
		readBuf:  make([]byte, 128),
		readStop: make(chan struct{}),
	}
	go ns.readLoop(nic)

	// Wait until the third Read (parked after two failures).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && rw.reads.Load() < 3 {
		time.Sleep(2 * time.Millisecond)
	}
	if rw.reads.Load() < 3 {
		t.Fatalf("reads = %d, want >= 3 (two transient failures + one parked)", rw.reads.Load())
	}
	select {
	case <-cancelled:
		t.Fatal("process context cancelled although reads recovered")
	case <-time.After(300 * time.Millisecond):
	}

	// Cleanup: unblock the parked Read with an error and stop the loop.
	close(release)
	close(nic.readStop)
}

// TestCtrlDropsCountedAndWarnedOnce: queue-full control-frame drops are
// counted and produce exactly one rate-limited warning per window.
func TestCtrlDropsCountedAndWarnedOnce(t *testing.T) {
	nic, node, cleanup := newTestNIC(t, 1500, false)
	defer cleanup()

	spy := &logSpy{}
	nic.netstack.logf = spy.Printf

	q := make(chan *stack.PacketBuffer, 1)
	nic.ctrlPackets = q

	dst := yggDest(0x45)
	sendBatch := func(n int) int {
		list := stack.PacketBufferList{}
		for i := 0; i < n; i++ {
			list.PushBack(newTCPControlPacket(node, dst, 1000, 2000, header.TCPFlagAck, uint32(i+1)))
		}
		written, err := nic.WritePackets(list)
		if err != nil {
			t.Fatalf("WritePackets: %v", err)
		}
		decRefAll(list)
		return written
	}

	if got := sendBatch(5); got != 1 {
		t.Fatalf("written = %d, want 1 (queue capacity)", got)
	}
	if got := nic.netstack.CtrlPacketsDropped(); got != 4 {
		t.Fatalf("dropped = %d, want 4", got)
	}

	if got := sendBatch(2); got != 0 {
		t.Fatalf("written = %d, want 0 (queue still full)", got)
	}
	if got := nic.netstack.CtrlPacketsDropped(); got != 6 {
		t.Fatalf("dropped = %d, want 6", got)
	}

	// The rate limiter must have emitted exactly one warning so far.
	if got := spy.count(); got != 1 {
		t.Fatalf("warnings = %d, want exactly 1 within the rate-limit window", got)
	}
}
