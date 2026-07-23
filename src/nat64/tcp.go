package nat64

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// handleTCP is called by tcp.NewForwarder for every inbound TCP SYN.
// It runs synchronously inside gVisor's packet processing path, so
// CreateEndpoint must complete here; the dial and proxy run in a goroutine.
func (s *Service) handleTCP(req *tcp.ForwarderRequest, logger *log.Logger) {
	id := req.ID()

	// Only serve pool6 destinations; RST everything else.
	dstSlice := id.LocalAddress.AsSlice()
	dstIP := net.IP(dstSlice)
	if !s.pool6Net.Contains(dstIP) {
		req.Complete(true)
		return
	}

	// Source filter.
	srcSlice := id.RemoteAddress.AsSlice()
	srcIP := net.IP(srcSlice)
	if !s.isAllowed(srcIP) {
		req.Complete(true)
		return
	}

	// Extract embedded IPv4 from the last 4 bytes of the pool6 destination.
	ipv4 := net.IP(dstSlice[12:16])
	dstAddr := fmt.Sprintf("%s:%d", ipv4.String(), id.LocalPort)

	// CreateEndpoint completes the three-way handshake synchronously.
	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)

	yggConn := gonet.NewTCPConn(&wq, ep)

	go func() {
		defer yggConn.Close()

		conn4, err := net.DialTimeout("tcp4", dstAddr, 10*time.Second)
		if err != nil {
			logger.Debugf("NAT64 TCP dial %s: %v", dstAddr, err)
			return
		}
		defer conn4.Close()

		logger.Debugf("NAT64 TCP %s → %s", srcIP, dstAddr)
		proxyTCP(yggConn, conn4)
	}()
}

// proxyTCP copies data bidirectionally between two net.Conn until both
// directions reach EOF.  Each half-close triggers closure of that direction.
func proxyTCP(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src) //nolint:errcheck
		dst.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
