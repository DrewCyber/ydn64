// Command udpecho is a black-box test helper. It is NOT part of the ydn64
// binary — it is baked into both test-harness container images and used by
// test/cases/ to exercise NAT64 UDP with payloads that busybox nc cannot
// handle (its fixed receive buffer truncates datagrams well below the
// 1472-byte IPv6 fragmentation threshold, in both directions).
//
// Server mode (default):
//
//	udpecho <listen-addr>        e.g. udpecho 127.0.0.1:4446
//
// Listens on a UDP port and echoes every received datagram back to its
// sender, preserving payload bytes exactly (no size limit beyond UDP's own
// 65535-byte maximum).
//
// One-shot client mode:
//
//	udpecho -once <server-addr> <infile> <outfile>
//
// Sends the contents of infile as ONE datagram to server-addr, waits up to
// 10 seconds for a reply, writes it verbatim to outfile, and exits non-zero
// on any failure (timeout, short reply, write error). Cases then compare
// checksums/lengths of infile vs outfile to prove end-to-end integrity
// across fragmented datagrams.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"
)

const replyTimeout = 10 * time.Second

func runServer(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("udpecho: listen %s: %v", addr, err)
	}
	log.Printf("udpecho: listening on %s", addr)

	buf := make([]byte, 65535)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("udpecho: read: %v", err)
		}
		if _, err := conn.WriteTo(buf[:n], client); err != nil {
			log.Printf("udpecho: write %d bytes to %s: %v", n, client, err)
		}
	}
}

func runClient(server, inFile, outFile string) {
	payload, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("udpecho: read %s: %v", inFile, err)
	}
	if len(payload) > 65507 {
		log.Fatalf("udpecho: payload of %d bytes exceeds the UDP maximum", len(payload))
	}

	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		log.Fatalf("udpecho: resolve %s: %v", server, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatalf("udpecho: dial %s: %v", server, err)
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		log.Fatalf("udpecho: send %d bytes: %v", len(payload), err)
	}

	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(replyTimeout))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("udpecho: no reply within %v: %v", replyTimeout, err)
	}
	if n != len(payload) {
		log.Fatalf("udpecho: short reply: got %d bytes, want %d", n, len(payload))
	}
	if err := os.WriteFile(outFile, buf[:n], 0644); err != nil {
		log.Fatalf("udpecho: write %s: %v", outFile, err)
	}
	log.Printf("udpecho: round trip OK (%d bytes)", n)
}

func main() {
	once := flag.Bool("once", false, "one-shot client mode")
	flag.Parse()

	switch {
	case !*once && flag.NArg() == 1:
		runServer(flag.Arg(0))
	case *once && flag.NArg() == 3:
		runClient(flag.Arg(0), flag.Arg(1), flag.Arg(2))
	default:
		flag.Usage()
		os.Exit(2)
	}
}
