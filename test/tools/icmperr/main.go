// Command icmperr is a black-box test helper. It is NOT part of the ydn64
// binary — it is baked into the ydn64 test-harness container image (A) and
// used by test/cases/ to exercise NAT64 ICMP error translation (RFC 7915
// §4.2/§4.3, RFC 5508 REQ-3/4) deterministically against loopback, without
// depending on real-internet routers emitting errors.
//
// It listens on a UDP port and answers every received datagram with a
// crafted ICMPv4 error message quoting the datagram, exactly as an IPv4
// router or host would when a probe dies in transit:
//
//	icmperr -mode timeexceeded -listen 127.0.0.1:33435
//	    replies ICMPv4 Time Exceeded (type 11, code 0) — the message
//	    traceroute relies on.
//
//	icmperr -mode ptb -mtu 1000 -listen 127.0.0.1:33436
//	    replies ICMPv4 Destination Unreachable / Fragmentation Needed
//	    (type 3, code 4) advertising -mtu bytes — the message PMTUD
//	    relies on.
//
// The quoted packet is reconstructed from the received datagram: inner IPv4
// src/dst mirror the loopback exchange and the inner UDP header is rebuilt
// from the endpoint tuples (a UDP socket delivers payload only), followed by
// up to -quote payload bytes from what arrived.
//
// Requires CAP_NET_RAW for the raw ICMP socket (container A runs with it).
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"time"
)

func main() {
	mode := flag.String("mode", "timeexceeded", "error type to emit: timeexceeded | ptb")
	listen := flag.String("listen", "127.0.0.1:33435", "UDP listen address")
	mtu := flag.Int("mtu", 1000, "advertised MTU for -mode ptb (ICMPv4 semantics)")
	quote := flag.Int("quote", 576, "maximum quoted payload bytes after the UDP header")
	flag.Parse()

	var (
		errType, errCode byte
		mtuWord          uint16
	)
	switch *mode {
	case "timeexceeded":
		errType, errCode = 11, 0
	case "ptb":
		errType, errCode = 3, 4
		if *mtu < 0 || *mtu > 65535 {
			log.Fatalf("icmperr: invalid -mtu %d", *mtu)
		}
		mtuWord = uint16(*mtu)
	default:
		log.Fatalf("icmperr: unknown -mode %q", *mode)
	}

	raw, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("icmperr: raw ICMP socket (needs CAP_NET_RAW): %v", err)
	}
	go drainRaw(raw)

	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("icmperr: listen %s: %v", *listen, err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	log.Printf("icmperr: listening on %s, mode=%s mtu=%d", local, *mode, *mtu)

	buf := make([]byte, 65535)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("icmperr: read: %v", err)
		}
		// A UDP socket delivers payload only — the UDP header must be
		// synthesized from the endpoint tuples: source = the sender's
		// address/port as reported by ReadFrom, destination = our own
		// listener address. This reproduces the datagram exactly as it
		// appeared on the wire toward us.
		msg := buildError(errType, errCode, mtuWord, local, client.(*net.UDPAddr), buf[:n], *quote)
		dst := &net.IPAddr{IP: client.(*net.UDPAddr).IP.To4()}
		if _, err := raw.WriteTo(msg, dst); err != nil {
			log.Printf("icmperr: write ICMP to %s: %v", dst, err)
			continue
		}
		log.Printf("icmperr: %s → %s (%d/%d) quoting %d bytes", client, dst, errType, errCode, n)
	}
}

// buildError marshals a complete ICMPv4 error message: 8-byte header
// (type/code/checksum/unused-or-MTU word), then the quoted packet — an IPv4
// header whose src/dst pair mirrors the loopback exchange, followed by a
// reconstructed UDP header and up to maxQuote payload bytes.
func buildError(typ, code byte, mtuWord uint16, local *net.UDPAddr, client *net.UDPAddr, payload []byte, maxQuote int) []byte {
	p := payload
	if len(p) > maxQuote {
		p = p[:maxQuote]
	}

	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], uint16(client.Port))
	binary.BigEndian.PutUint16(udpHdr[2:4], uint16(local.Port))
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(p)))

	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x40 | 5 // version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+len(udpHdr)+len(p)))
	ipHdr[8] = 64 // TTL of the (fictional) offending probe
	ipHdr[9] = 17 // protocol UDP
	copy(ipHdr[12:16], local.IP.To4())
	copy(ipHdr[16:20], client.IP.To4())

	quoted := append(ipHdr, udpHdr...)
	quoted = append(quoted, p...)

	msg := make([]byte, 8+len(quoted))
	msg[0], msg[1] = typ, code
	if typ == 3 && code == 4 {
		binary.BigEndian.PutUint16(msg[6:8], mtuWord)
	}
	copy(msg[8:], quoted)
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
	return msg
}

// checksum computes the standard 16-bit one's-complement Internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// drainRaw keeps the raw socket's receive queue empty so its send path never
// stalls; the tool never reads inbound ICMP itself.
func drainRaw(conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		if _, _, err := conn.ReadFrom(buf); err != nil {
			time.Sleep(time.Second)
		}
	}
}
