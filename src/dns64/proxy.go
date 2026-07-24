package dns64

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/DrewCyber/ydn64/src/netstack"
)

// proxy implements the DNS64 translation logic.
type proxy struct {
	cache          *dnsCache
	zones          []zone
	defaultForward string
	ia             InvalidAddress
	ns             *netstack.YggdrasilNetstack // used to dial Yggdrasil-native (200::/7) forwarders
}

// yggdrasilRange is the Yggdrasil node address space (200::/7). Forwarders
// whose address falls in this range are only reachable through the
// embedded gVisor netstack (they're not real host-routable addresses), so
// lookups to them must be dialled via the Yggdrasil NIC instead of the
// host OS network stack.
var yggdrasilRange = func() *net.IPNet {
	_, n, err := net.ParseCIDR("0200::/7")
	if err != nil {
		panic(err)
	}
	return n
}()

// lookup performs a UDP DNS query and returns the response. Forwarders in
// the Yggdrasil address range (200::/7) are dialled through the embedded
// gVisor netstack; everything else uses the host OS network stack.
func (p *proxy) lookup(server string, req *dns.Msg) (*dns.Msg, error) {
	host, _, err := net.SplitHostPort(server)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil && p.ns != nil && yggdrasilRange.Contains(ip) {
			return p.lookupViaNetstack(server, ip, req)
		}
	}

	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(req, server)
	return resp, err
}

// lookupViaNetstack dials the forwarder through the embedded gVisor stack
// (the same one connected to the Yggdrasil Core), since Yggdrasil-native
// addresses aren't reachable via the host OS network stack.
func (p *proxy) lookupViaNetstack(server string, ip net.IP, req *dns.Msg) (*dns.Msg, error) {
	_, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	var port int
	if _, err := fmt.Sscan(portStr, &port); err != nil {
		return nil, fmt.Errorf("forwarder port %q: %w", portStr, err)
	}

	raddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.To16()),
		Port: uint16(port),
	}
	conn, tcpErr := gonet.DialUDP(p.ns.Stack(), nil, raddr, ipv6.ProtocolNumber)
	if tcpErr != nil {
		return nil, fmt.Errorf("dialling %s via yggdrasil netstack: %w", server, tcpErr)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	c := &dns.Client{Net: "udp"}
	resp, _, err := c.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	return resp, err
}

// getForwarder returns the forwarder for the matched zone, or the default.
func (p *proxy) getForwarder(z *zone) string {
	if z != nil && z.forwarder != "" {
		return z.forwarder
	}
	return p.defaultForward
}

// handle processes a single DNS request and returns a response message.
func (p *proxy) handle(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
		return resp
	}
	q := req.Question[0]
	fqdn := strings.ToLower(q.Name)

	z := matchZone(p.zones, fqdn)
	if z == nil {
		// No matching zone and no catch-all → NXDOMAIN.
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNameError)
		return resp
	}
	server := p.getForwarder(z)

	var resp *dns.Msg
	var err error

	switch q.Qtype {
	case dns.TypeAAAA:
		resp, err = p.handleAAAA(req, &q, z, server)
	case dns.TypeA:
		resp, err = p.handleA(req, &q, z, server)
	case dns.TypePTR:
		resp, err = p.handlePTR(req, &q, z, server)
	default:
		resp, err = p.passThrough(req, server)
	}

	if err != nil || resp == nil {
		r := new(dns.Msg)
		r.SetRcode(req, dns.RcodeServerFailure)
		return r
	}
	resp.RecursionAvailable = true
	return resp
}

// handleAAAA implements DNS64 AAAA synthesis:
//  1. Check cache.
//  2. Query upstream for AAAA — pass through real AAAA if zone.returnIPv6Addresses.
//  3. If no usable AAAA, query A and synthesise from prefix (if configured).
func (p *proxy) handleAAAA(req *dns.Msg, q *dns.Question, z *zone, server string) (*dns.Msg, error) {
	// Cache hit?
	if cached, ok := p.cache.get(q.Name); ok {
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Answer = cached.([]dns.RR)
		resp.Question[0].Qtype = dns.TypeAAAA
		resp.Response = true
		return resp, nil
	}

	// Query upstream AAAA.
	upReq := new(dns.Msg)
	req.CopyTo(upReq)
	upReq.Question = []dns.Question{*q}
	upResp, err := p.lookup(server, upReq)
	if err != nil {
		return nil, err
	}

	answer := p.filterAAAA(upResp.Answer, z)
	if len(answer) > 0 {
		p.cache.set(q.Name, answer)
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Answer = answer
		resp.Question[0].Qtype = dns.TypeAAAA
		resp.Response = true
		return resp, nil
	}

	// No usable AAAA — try synthesising from A records.
	if z.prefix == nil {
		// Zone has no prefix configured → return empty answer (not NXDOMAIN,
		// just no AAAA records).
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Answer = []dns.RR{}
		resp.Question[0].Qtype = dns.TypeAAAA
		resp.Response = true
		return resp, nil
	}

	aReq := new(dns.Msg)
	req.CopyTo(aReq)
	aReq.Question = []dns.Question{{Name: q.Name, Qtype: dns.TypeA, Qclass: q.Qclass}}
	aResp, err := p.lookup(server, aReq)
	if err != nil {
		return nil, err
	}

	answer = p.synthesiseFromA(aResp.Answer, q.Name, z)
	if len(answer) > 0 {
		p.cache.set(q.Name, answer)
	}

	resp := new(dns.Msg)
	req.CopyTo(resp)
	resp.Answer = answer
	resp.Question[0].Qtype = dns.TypeAAAA
	resp.Response = true
	return resp, nil
}

// filterAAAA selects AAAA records from rrs according to zone rules:
//   - Unspecified (::) is handled by InvalidAddress policy.
//   - AAAA passes through only if zone.returnIPv6Addresses (this covers
//     Yggdrasil-native 200::/7 addresses too — there is no special-casing
//     for that range, it's just another IPv6 answer gated by the flag).
//   - Mutually exclusive: zone.prefix and zone.returnIPv6Addresses are
//     validated at config load time.
func (p *proxy) filterAAAA(rrs []dns.RR, z *zone) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		a, ok := rr.(*dns.AAAA)
		if !ok {
			out = append(out, rr) // pass non-AAAA records through unchanged
			continue
		}
		ip := a.AAAA

		if ip.IsUnspecified() {
			switch p.ia {
			case IADiscard:
				continue
			case IAIgnore:
				continue // drop [::] in AAAA context
			case IAProcess:
				out = append(out, rr) // return as-is
			}
			continue
		}

		if z.returnIPv6Addresses {
			out = append(out, rr)
		}
		// If zone has a prefix instead, this AAAA is skipped here;
		// synthesis happens via A records in handleAAAA.
	}
	return out
}

// synthesiseFromA converts A records into synthesised AAAA records using
// zone.prefix + the embedded IPv4.
func (p *proxy) synthesiseFromA(rrs []dns.RR, name string, z *zone) []dns.RR {
	out := make([]dns.RR, 0)
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ipv4 := a.A

		if ipv4.IsUnspecified() {
			switch p.ia {
			case IADiscard:
				continue
			case IAIgnore:
				// treat 0.0.0.0 like a normal address → synthesise pool6::0.0.0.0
			case IAProcess:
				// 0.0.0.0 → translate to [::]
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN AAAA ::", name))
				out = append(out, rr)
				continue
			}
		}

		synth := makeSynthesisedAAAA(z.prefix, ipv4)
		rr, _ := dns.NewRR(fmt.Sprintf("%s IN AAAA %s", name, synth.String()))
		if rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// handleA returns A records only if zone.returnIPv4Addresses is set.
func (p *proxy) handleA(req *dns.Msg, q *dns.Question, z *zone, server string) (*dns.Msg, error) {
	upReq := new(dns.Msg)
	req.CopyTo(upReq)
	upReq.Question = []dns.Question{*q}
	resp, err := p.lookup(server, upReq)
	if err != nil {
		return nil, err
	}
	if !z.returnIPv4Addresses {
		resp.Answer = []dns.RR{}
	}
	return resp, nil
}

// handlePTR reverses a pool6::IPv4 PTR query back to a real IPv4 PTR query.
// For PTR queries that don't fall in the pool6 range, pass through.
func (p *proxy) handlePTR(req *dns.Msg, q *dns.Question, z *zone, server string) (*dns.Msg, error) {
	// Try to find a zone with a prefix; if we can reverse-map the PTR to IPv4
	// via that prefix, rewrite the query.
	ipv4, matched := p.reversePTR(q.Name)
	if matched {
		// Rewrite to the real IPv4 PTR.
		realPTR, err := dns.ReverseAddr(ipv4.String())
		if err != nil {
			return nil, err
		}
		upReq := new(dns.Msg)
		req.CopyTo(upReq)
		origQuestion := upReq.Question
		upReq.Question = []dns.Question{{Name: realPTR, Qtype: dns.TypePTR, Qclass: q.Qclass}}
		resp, err := p.lookup(server, upReq)
		if err != nil {
			return nil, err
		}
		// Rewrite the question back to the original pool6 PTR.
		resp.Question = origQuestion
		answer := make([]dns.RR, 0, len(resp.Answer))
		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				newRR, _ := dns.NewRR(origQuestion[0].Name + " IN PTR " + ptr.Ptr)
				if newRR != nil {
					answer = append(answer, newRR)
				}
			}
		}
		resp.Answer = answer
		resp.Question[0].Qtype = dns.TypePTR
		return resp, nil
	}
	return p.passThrough(req, server)
}

// reversePTR checks whether the PTR name (e.g. "1.0.0.0.f.f.0.0...ip6.arpa.")
// maps to one of our zone prefixes.  Returns the embedded IPv4 and true if so.
func (p *proxy) reversePTR(ptrName string) (net.IP, bool) {
	ip6, err := ptrToIPv6(ptrName)
	if err != nil {
		return nil, false
	}
	for _, z := range p.zones {
		if z.prefix == nil {
			continue
		}
		pfx := z.prefix.To16()
		// The prefix occupies the first 12 bytes; the last 4 are the IPv4.
		match := true
		for i := 0; i < 12; i++ {
			if ip6[i] != pfx[i] {
				match = false
				break
			}
		}
		if match {
			return net.IP(ip6[12:16]), true
		}
	}
	return nil, false
}

// ptrToIPv6 converts an ip6.arpa. PTR name to a net.IP (16 bytes).
func ptrToIPv6(ptr string) (net.IP, error) {
	ptr = strings.ToLower(ptr)
	suffix := ".ip6.arpa."
	if !strings.HasSuffix(ptr, suffix) {
		return nil, fmt.Errorf("not an ip6.arpa PTR")
	}
	nibbles := strings.Split(strings.TrimSuffix(ptr, suffix), ".")
	if len(nibbles) != 32 {
		return nil, fmt.Errorf("invalid ip6 PTR nibble count")
	}
	var raw [16]byte
	for i, nb := range nibbles {
		if len(nb) != 1 {
			return nil, fmt.Errorf("invalid nibble %q", nb)
		}
		v := nibbleVal(nb[0])
		if v < 0 {
			return nil, fmt.Errorf("invalid nibble %q", nb)
		}
		byteIdx := 15 - i/2
		if i%2 == 0 {
			raw[byteIdx] |= byte(v)
		} else {
			raw[byteIdx] |= byte(v) << 4
		}
	}
	return raw[:], nil
}

func nibbleVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

// passThrough forwards the request as-is and returns the upstream response.
func (p *proxy) passThrough(req *dns.Msg, server string) (*dns.Msg, error) {
	upReq := new(dns.Msg)
	req.CopyTo(upReq)
	return p.lookup(server, upReq)
}
