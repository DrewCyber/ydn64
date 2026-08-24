// Command dnspipe pipelines DNS queries over a single TCP connection to
// exercise RFC 7766 §6.2.1.1 server-side concurrent processing of pipelined
// queries. It is a black-box test helper for the podman harness (see
// test/cases/12_dns_tcp_pipelining.sh) and is deliberately stdlib-only so it
// builds against the minimal standalone module used by the yggclient image,
// like udpecho.
//
// Two modes:
//
//	dnspipe -server HOST[:PORT] -overtake REMOTE_NAME,LOCAL_NAME
//
// Sends an AAAA query for REMOTE_NAME followed immediately by one for
// LOCAL_NAME on the same connection. A '*' in REMOTE_NAME is replaced with a
// random label per run so the query always misses the server's cache and
// really goes upstream (e.g. "*.dns.google" → NXDOMAIN after a full upstream
// round-trip). Exits 0 only if both are answered and
// the later-sent LOCAL query's response arrives first — proof that the
// server processes pipelined queries concurrently and returns them out of
// order (REMOTE must take at least one upstream round-trip; LOCAL is
// answered locally by DNS64, so a serialising server can never overtake).
// Exit code 3 means responses arrived in send order (serialised processing).
//
//	dnspipe -server HOST[:PORT] -n N [-base BASE_NAME]
//
// Pipelines N AAAA queries for "<i>.<BASE>" (default base dns.google, so
// upstreams answer fast authoritative NXDOMAINs), then requires every
// response back with its original Message ID — nothing dropped or
// duplicated under pipelining.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const exitUsage = 1
const exitTransport = 2
const exitSerialized = 3

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dnspipe -server HOST[:PORT] (-overtake REMOTE,LOCAL | -n N [-base NAME]) [-timeout SECONDS]")
	os.Exit(exitUsage)
}

// normalizeServer accepts "host", "host:port", "[v6]:port" or bare IPv6 and
// returns a dialable host:port (default port 53).
func normalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty -server")
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil // already host:port / [v6]:port
	}
	if strings.Contains(s, ":") { // bare IPv6 literal
		return "[" + s + "]:53", nil
	}
	return s + ":53", nil
}

// normalizeName lowercases and guarantees exactly one trailing dot.
func normalizeName(name string) error {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return fmt.Errorf("empty name")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("bad label %q in %q", label, name)
		}
	}
	if len(name)+1 > 255 {
		return fmt.Errorf("name too long")
	}
	return nil
}

// buildQuery encodes one AAAA question as wire bytes (RFC 1035 §4.1).
func buildQuery(id uint16, name string) ([]byte, error) {
	name = strings.ToLower(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	qname := make([]byte, 0, len(name)+2)
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return nil, fmt.Errorf("bad label %q", l)
		}
		qname = append(qname, byte(len(l)))
		qname = append(qname, l...)
	}
	qname = append(qname, 0)

	msg := make([]byte, 0, 12+len(qname)+4)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	msg = append(msg, hdr[:]...)
	msg = append(msg, qname...)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], 28) // AAAA
	binary.BigEndian.PutUint16(qt[2:4], 1)  // IN
	msg = append(msg, qt[:]...)
	return msg, nil
}

// writeFramed sends one length-prefixed message in a single write so the
// length prefix and body hit the socket together (RFC 7766 §8).
func writeFramed(conn net.Conn, body []byte) error {
	if len(body) > 0xffff {
		return fmt.Errorf("message too large")
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out, uint16(len(body)))
	copy(out[2:], body)
	_, err := conn.Write(out)
	return err
}

// readFramed reads one length-prefixed message.
func readFramed(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	if len(buf) < 12 {
		return nil, fmt.Errorf("short DNS message (%d bytes)", len(buf))
	}
	return buf, nil
}

// respInfo extracts what the assertions need from a raw response.
type respInfo struct {
	id      uint16
	isResp  bool
	rcode   int
	answers int
}

func parseResp(raw []byte) respInfo {
	return respInfo{
		id:      binary.BigEndian.Uint16(raw[0:2]),
		isResp:  raw[2]&0x80 != 0,
		rcode:   int(raw[3] & 0x0f),
		answers: int(binary.BigEndian.Uint16(raw[6:8])),
	}
}

func main() {
	server := flag.String("server", "", "DNS64 listen address (host[:port] or bare IPv6)")
	overtake := flag.String("overtake", "", "REMOTE,LOCAL names for the out-of-order probe")
	n := flag.Int("n", 0, "number of pipelined queries (bulk mode)")
	base := flag.String("base", "dns.google", "base name for bulk-mode queries (<i>.<base>)")
	timeout := flag.Int("timeout", 30, "overall deadline in seconds")
	flag.Parse()

	addr, err := normalizeServer(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: %v\n", err)
		usage()
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: dial %s: %v\n", addr, err)
		os.Exit(exitTransport)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Duration(*timeout) * time.Second)
	_ = conn.SetDeadline(deadline)

	switch {
	case *overtake != "":
		runOvertake(conn, *overtake)
	case *n > 0:
		runBulk(conn, *n, *base)
	default:
		usage()
	}
}

// uniqueLabel replaces every '*' in a name with 8 hex chars of randomness so
// callers can force a cache-miss on the server under test (e.g.
// "*.dns.google" → "3f9a1c0b.dns.google"). Without this, a warmed-up cache
// would turn the REMOTE query into a local answer too and destroy the
// latency gap the overtake assertion relies on.
func uniqueLabel(name string) (string, error) {
	if !strings.Contains(name, "*") {
		return name, nil
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return strings.ReplaceAll(name, "*", fmt.Sprintf("%x", b)), nil
}

func runOvertake(conn net.Conn, spec string) {
	names := strings.Split(spec, ",")
	if len(names) != 2 {
		fmt.Fprintln(os.Stderr, "dnspipe: -overtake wants REMOTE,LOCAL")
		usage()
	}
	remoteName, err := uniqueLabel(names[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: randomizing REMOTE name: %v\n", err)
		os.Exit(exitUsage)
	}
	localName := names[1]
	if err := normalizeName(remoteName); err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: bad -overtake REMOTE: %v\n", err)
		usage()
	}
	if err := normalizeName(localName); err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: bad -overtake LOCAL: %v\n", err)
		usage()
	}

	const (
		remoteID = 0x0a0b
		localID  = 0x0c0d
	)
	for _, q := range []struct {
		id   uint16
		name string
	}{{remoteID, remoteName}, {localID, localName}} {
		body, err := buildQuery(q.id, q.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: %v\n", err)
			usage()
		}
		if err := writeFramed(conn, body); err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: send %s: %v\n", q.name, err)
			os.Exit(exitTransport)
		}
	}

	arrival := make(map[uint16]time.Duration)
	start := time.Now()
	for len(arrival) < 2 {
		raw, err := readFramed(conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: read response %d: %v\n", len(arrival)+1, err)
			os.Exit(exitTransport)
		}
		r := parseResp(raw)
		if !r.isResp {
			continue // not an answer; keep reading
		}
		if r.id != remoteID && r.id != localID {
			fmt.Fprintf(os.Stderr, "dnspipe: unexpected response id %#x\n", r.id)
			os.Exit(exitTransport)
		}
		if _, seen := arrival[r.id]; seen {
			continue // duplicate (e.g. retried upstream); wait for the other
		}
		arrival[r.id] = time.Since(start)
	}

	localFirst, ok := arrival[localID]
	remoteAt := arrival[remoteID]
	fmt.Printf("OVERTAKE local=%v remote=%v local_first=%v\n", localFirst, remoteAt, ok && localFirst <= remoteAt)
	if localFirst <= remoteAt {
		fmt.Println("PASS: later-sent local query's response arrived before the earlier-sent remote query's (concurrent out-of-order processing)")
		return
	}
	fmt.Printf("FAIL: responses arrived in send order — pipelined queries appear to be processed serially (local after %v, remote after %v)\n", localFirst, remoteAt)
	os.Exit(exitSerialized)
}

func runBulk(conn net.Conn, n int, baseName string) {
	if err := normalizeName(baseName); err != nil {
		fmt.Fprintf(os.Stderr, "dnspipe: bad -base: %v\n", err)
		usage()
	}
	base := strings.TrimSuffix(strings.ToLower(baseName), ".")

	type sent struct {
		id      uint16
		sendIdx int
	}
	byID := make(map[uint16]sent, n)
	for i := 0; i < n; i++ {
		id := uint16(i*7 + 3)
		body, err := buildQuery(id, fmt.Sprintf("%d.%s.", i, base))
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: %v\n", err)
			usage()
		}
		if err := writeFramed(conn, body); err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: send query %d: %v\n", i, err)
			os.Exit(exitTransport)
		}
		byID[id] = sent{id: id, sendIdx: i}
	}

	start := time.Now()
	answered := make(map[uint16]int, n) // id -> rcode
	for len(answered) < n {
		raw, err := readFramed(conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnspipe: read response %d/%d: %v\n", len(answered)+1, n, err)
			os.Exit(exitTransport)
		}
		r := parseResp(raw)
		s, known := byID[r.id]
		if !r.isResp || !known {
			continue
		}
		if _, seen := answered[r.id]; seen {
			continue // duplicate; wait for the rest
		}
		answered[r.id] = r.rcode
		if r.answers == 0 && r.rcode == 0 {
			// NXDOMAIN and NOERROR-without-answers both count as answered;
			// note the latter for diagnostics only.
			fmt.Printf("note: %d.%s answered NOERROR with 0 answers\n", s.sendIdx, base)
		}
	}
	total := time.Since(start)
	nx := 0
	for _, rc := range answered {
		if rc == 3 {
			nx++
		}
	}
	fmt.Printf("PIPELINE sent=%d answered=%d nxdomain=%d total_ms=%d\n", n, len(answered), nx, total.Milliseconds())
	fmt.Printf("PASS: all %d pipelined queries answered on one connection with matching IDs\n", n)
}
