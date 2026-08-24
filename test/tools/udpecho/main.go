// Command udpecho is a black-box test helper. It is NOT part of the ydn64
// binary — it is baked into both test-harness container images and used by
// test/cases/ to exercise NAT64 UDP with payloads that busybox nc cannot
// handle (its fixed receive buffer truncates datagrams well below the 1472-byte
// IPv6 fragmentation threshold, in both directions).
//
// Server mode (default):
//
//	udpecho <listen-addr>        e.g. udpecho 127.0.0.1:4446
//	udpecho -tag-client <addr>   additionally prefix replies with the observed client address
//
// Listens on a UDP port and echoes every received datagram back to its
// sender, preserving payload bytes exactly (no size limit beyond UDP's own
// 65535-byte maximum). With -tag-client each reply becomes
//
//	client=<ip>:<port>|<original payload>
//
// so a client can learn which external (NAT) source address the server
// observed; used by the endpoint-independent-mapping case.
//
// One-shot client mode:
//
//	udpecho -once <server-addr> <infile> <outfile>
//
// Sends the contents of infile as ONE datagram to server-addr, waits up to
// 10 seconds for a reply, writes it verbatim to outfile, and exits non-zero
// on any failure (timeout, short reply, write error). Cases then compare
// checksums/lengths of infile vs outfile to prove end-to-end integrity
// across fragmented datagrams. (A -tag-client prefix is tolerated and
// stripped before writing.)
//
// EIM probe client mode (endpoint-independent mapping check):
//
//	udpecho -eim <server-addr-1> <server-addr-2> <infile> <outfile-1> <outfile-2>
//
// Sends the SAME payload from ONE socket to two different servers (which
// must run with -tag-client), waits for both tagged replies, verifies both
// payloads are intact, and asserts that BOTH servers observed the identical
// client ip:port — the definition of endpoint-independent mapping (RFC 4787
// REQ-1). Exits non-zero if the mappings differ or any reply is missing.
//
// EIF probe/receiver mode (endpoint-independent filtering check):
//
//	udpecho -eif <server-addr> <wait-seconds> <infile> <outfile>
//
// Phase 1 sends infile to server-addr from ONE long-lived socket and waits
// for the tagged echo, printing
//
//	MAPPING client=<ip>:<port>
//
// — the external (NAT-assigned) identity of the socket as seen by the
// server. Phase 2 keeps the SAME socket open and waits up to <wait-seconds>
// for an UNSOLICITED datagram (a hole punch arriving at the mapped port
// from a never-contacted sender). On receipt it writes the payload verbatim
// to outfile, prints
//
//	EIFRECV from=<ip>:<port> bytes=<n>
//
// and exits 0. If nothing arrives it exits non-zero (the negative test:
// under address-dependent/default filtering the datagram must be dropped).
//
// Fire-and-forget sender mode:
//
//	udpecho -send [-bind <ip>] <target-addr> <infile>
//
// Sends infile as one datagram to target-addr from an ephemeral port (or
// the -bind address) and exits immediately without waiting for any reply —
// plays the "never-contacted peer" in the EIF case.
package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const replyTimeout = 10 * time.Second

// tagPrefix marks a -tag-client reply; format: "client=<ip>:<port>|<payload>".
var tagPrefix = []byte("client=")

func splitTag(p []byte) (tag string, body []byte, ok bool) {
	if !bytes.HasPrefix(p, tagPrefix) {
		return "", nil, false
	}
	sep := bytes.IndexByte(p, '|')
	if sep < 0 {
		return "", nil, false
	}
	return string(p[:sep]), p[sep+1:], true
}

func runServer(addr string, tagClient bool) {
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
		out := buf[:n]
		if tagClient {
			tag := append(append([]byte{}, tagPrefix...), []byte(client.String())...)
			out = append(append(tag, '|'), out...)
		}
		if _, err := conn.WriteTo(out, client); err != nil {
			log.Printf("udpecho: write %d bytes to %s: %v", len(out), client, err)
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
		log.Fatalf("udpecho: dial: %v", err)
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
	body := buf[:n]
	if _, b, ok := splitTag(body); ok {
		body = b // tolerate a tagged responder in plain mode too
	}
	if len(body) != len(payload) {
		log.Fatalf("udpecho: short reply: got %d bytes, want %d", len(body), len(payload))
	}
	if err := os.WriteFile(outFile, body, 0644); err != nil {
		log.Fatalf("udpecho: write %s: %v", outFile, err)
	}
	log.Printf("udpecho: round trip OK (%d bytes)", n)
}

func runEIMClient(serverA, serverB, inFile, outFileA, outFileB string) {
	payload, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("udpecho: read %s: %v", inFile, err)
	}

	raddrA, err := net.ResolveUDPAddr("udp", serverA)
	if err != nil {
		log.Fatalf("udpecho: resolve %s: %v", serverA, err)
	}
	raddrB, err := net.ResolveUDPAddr("udp", serverB)
	if err != nil {
		log.Fatalf("udpecho: resolve %s: %v", serverB, err)
	}

	// One UNCONNECTED socket for both destinations: every datagram it sends
	// shares one local port by construction, so any mapping difference seen
	// by the servers is attributable to the NAT under test alone.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		log.Fatalf("udpecho: listen: %v", err)
	}
	defer conn.Close()

	for _, dst := range []*net.UDPAddr{raddrA, raddrB} {
		if _, err := conn.WriteToUDP(payload, dst); err != nil {
			log.Fatalf("udpecho: send to %s: %v", dst, err)
		}
	}

	type reply struct {
		got bool
		tag string
	}
	replies := map[*net.UDPAddr]*reply{raddrA: {}, raddrB: {}}
	buf := make([]byte, 65535)

	for i := 0; i < 2 && !(replies[raddrA].got && replies[raddrB].got); i++ {
		_ = conn.SetReadDeadline(time.Now().Add(replyTimeout))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalf("udpecho: no reply within %v: %v", replyTimeout, err)
		}
		var r *reply
		switch from.Port {
		case raddrA.Port:
			r = replies[raddrA]
		case raddrB.Port:
			r = replies[raddrB]
		default:
			log.Fatalf("udpecho: reply from unexpected source %s", from)
		}
		tag, body, ok := splitTag(buf[:n])
		if !ok {
			log.Fatalf("udpecho: reply from %s lacks client tag (run the servers with -tag-client)", from)
		}
		if !bytes.Equal(body, payload) {
			log.Fatalf("udpecho: reply payload mismatch from %s (%d bytes)", from, len(body))
		}
		r.got = true
		r.tag = tag
		switch from.Port {
		case raddrA.Port:
			_ = os.WriteFile(outFileA, body, 0644)
		case raddrB.Port:
			_ = os.WriteFile(outFileB, body, 0644)
		}
	}

	a, b := replies[raddrA], replies[raddrB]
	if !a.got || !b.got {
		log.Fatalf("udpecho: missing replies (A=%v B=%v)", a.got, b.got)
	}
	if a.tag != b.tag {
		log.Fatalf("udpecho: EIM VIOLATION: %s saw %s but %s saw %s (endpoint-dependent mapping)",
			serverA, a.tag, serverB, b.tag)
	}
	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("udpecho: EIM OK — both destinations observed %s (local port %d, %d bytes intact)",
		a.tag, localPort, len(payload))
}

func main() {
	once := flag.Bool("once", false, "one-shot client mode")
	eim := flag.Bool("eim", false, "EIM probe client mode: <srv1> <srv2> <infile> <out1> <out2>")
	eif := flag.Bool("eif", false, "EIF probe+receiver mode: <server> <wait-secs> <infile> <outfile>")
	send := flag.Bool("send", false, "fire-and-forget sender: [-bind ip] <target> <infile>")
	bind := flag.String("bind", "", "send mode: bind the source socket to this IPv4 address")
	tagClient := flag.Bool("tag-client", false, "server mode: prefix replies with the observed client address")
	flag.Parse()

	switch {
	case !*once && !*eim && !*eif && !*send && flag.NArg() == 1:
		runServer(flag.Arg(0), *tagClient)
	case *once && flag.NArg() == 3:
		runClient(flag.Arg(0), flag.Arg(1), flag.Arg(2))
	case *eim && flag.NArg() == 5:
		runEIMClient(flag.Arg(0), flag.Arg(1), flag.Arg(2), flag.Arg(3), flag.Arg(4))
	case *eif && flag.NArg() == 4:
		waitSecs, err := strconv.Atoi(flag.Arg(1))
		if err != nil || waitSecs <= 0 {
			log.Fatalf("udpecho: -eif wait-seconds must be a positive integer, got %q", flag.Arg(1))
		}
		runEIFClient(flag.Arg(0), waitSecs, flag.Arg(2), flag.Arg(3))
	case *send && flag.NArg() == 2:
		runSend(*bind, flag.Arg(0), flag.Arg(1))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// runEIFClient implements the endpoint-independent-filtering probe: phase 1
// learns the socket's external mapping from a tagged echo server, phase 2
// waits on the same socket for an unsolicited datagram (see the -eif docs).
func runEIFClient(probeServer string, waitSecs int, inFile, outFile string) {
	payload, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("udpecho: read %s: %v", inFile, err)
	}
	raddr, err := net.ResolveUDPAddr("udp", probeServer)
	if err != nil {
		log.Fatalf("udpecho: resolve %s: %v", probeServer, err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		log.Fatalf("udpecho: listen: %v", err)
	}
	defer conn.Close()

	// Phase 1: create the mapping and learn its external identity.
	if _, err := conn.WriteToUDP(payload, raddr); err != nil {
		log.Fatalf("udpecho: probe send: %v", err)
	}
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(replyTimeout))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("udpecho: no mapping reply within %v: %v", replyTimeout, err)
	}
	tag, body, ok := splitTag(buf[:n])
	if !ok {
		log.Fatalf("udpecho: mapping reply lacks client tag (run the server with -tag-client)")
	}
	if !bytes.Equal(body, payload) {
		log.Fatalf("udpecho: mapping reply payload mismatch (%d bytes)", len(body))
	}
	mapping := strings.TrimPrefix(tag, "client=")
	log.Printf("udpecho: MAPPING client=%s", mapping)

	// Phase 2: same socket, now waiting for an unsolicited datagram.
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(waitSecs) * time.Second))
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("udpecho: no unsolicited datagram within %ds: %v", waitSecs, err)
	}
	if err := os.WriteFile(outFile, buf[:n], 0644); err != nil {
		log.Fatalf("udpecho: write %s: %v", outFile, err)
	}
	log.Printf("udpecho: EIFRECV from=%s bytes=%d", from.String(), n)
}

// runSend fires one datagram at target and exits; used as the
// never-contacted peer in the EIF case.
func runSend(bindIP, target, inFile string) {
	payload, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("udpecho: read %s: %v", inFile, err)
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Fatalf("udpecho: resolve %s: %v", target, err)
	}
	laddr := &net.UDPAddr{}
	if bindIP != "" {
		ip := net.ParseIP(bindIP)
		if ip == nil || ip.To4() == nil {
			log.Fatalf("udpecho: -bind wants an IPv4 address, got %q", bindIP)
		}
		laddr = &net.UDPAddr{IP: ip}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatalf("udpecho: listen %s: %v", bindIP, err)
	}
	defer conn.Close()
	if _, err := conn.WriteToUDP(payload, raddr); err != nil {
		log.Fatalf("udpecho: send: %v", err)
	}
	log.Printf("udpecho: sent %d bytes to %s from %s", len(payload), target, conn.LocalAddr())
}
