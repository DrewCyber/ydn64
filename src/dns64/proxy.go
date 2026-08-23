package dns64

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/DrewCyber/ydn64/src/netstack"
)

// proxyConfig holds the reloadable subset of DNS64 behaviour (Dns64Default,
// Dns64Zones, Dns64InvalidAddress, IgnoredDstSubnets). It is swapped atomically by
// proxy.reload() so query-handling goroutines never need to take a lock.
type proxyConfig struct {
	zones          []zone
	defaultForward string
	ia             InvalidAddress
	ignoredDstNets []*net.IPNet
}

// proxy implements the DNS64 translation logic.
type proxy struct {
	cache *dnsCache
	cfg   atomic.Pointer[proxyConfig]
	ns    *netstack.YggdrasilNetstack // used to dial Yggdrasil-native (200::/7) forwarders
}

// reload atomically replaces the zone table, default forwarder,
// InvalidAddress policy, and ignored destination subnets. Safe to call concurrently with in-flight queries.
func (p *proxy) reload(defaultForward string, ia InvalidAddress, zones []zone, ignoredDstNets []*net.IPNet) {
	p.cfg.Store(&proxyConfig{zones: zones, defaultForward: defaultForward, ia: ia, ignoredDstNets: ignoredDstNets})
}

// isIgnoredDst reports whether dstIPv4 is in one of the configured ignored destination subnets.
func (p *proxy) isIgnoredDst(ip net.IP) bool {
	cfg := p.cfg.Load()
	if cfg == nil {
		return false
	}
	for _, n := range cfg.ignoredDstNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

// ipv4OnlyARPAIPs are the two IPv4 addresses specified in RFC 7050 / RFC 8880
// for local lookup and prefix discovery.
var ipv4OnlyARPAIPs = []net.IP{
	net.ParseIP("192.0.0.170"),
	net.ParseIP("192.0.0.171"),
}

// lookup performs a UDP DNS query and returns the response. Forwarders in
// the Yggdrasil address range (200::/7) are dialled through the embedded
// gVisor netstack; everything else uses the host OS network stack.
//
// RFC 5452 §9.2: the transaction ID used upstream is chosen randomly by
// ydn64, never relayed from the client's query — an allowed client must not
// be able to dictate the ID an off-path spoofer has to guess. The DNS
// library discards any upstream answer whose ID does not match the one sent,
// and the client's original ID is restored on the response before it is
// returned (several handlers forward the upstream response object itself).
func (p *proxy) lookup(server string, req *dns.Msg) (*dns.Msg, error) {
	origID := req.Id
	req.Id = dns.Id()
	defer func() { req.Id = origID }()

	resp, err := p.lookupUpstream(server, req)
	if resp != nil {
		resp.Id = origID
	}
	return resp, err
}

// lookupUpstream sends req to the configured forwarder unchanged.
func (p *proxy) lookupUpstream(server string, req *dns.Msg) (*dns.Msg, error) {
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
	return p.cfg.Load().defaultForward
}

// dnssecValidatingClient reports whether the request carries both the DNSSEC
// OK (DO) and Checking Disabled (CD) bits — i.e. the client performs DNSSEC
// validation itself and must receive upstream data unsynthesised
// (RFC 6147 §5.5, implementing the RFC 4033–4035 requirements).
func dnssecValidatingClient(req *dns.Msg) bool {
	if !req.CheckingDisabled {
		return false
	}
	opt := req.IsEdns0()
	return opt != nil && opt.Do()
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

	z := matchZone(p.cfg.Load().zones, fqdn)
	if z == nil {
		// No matching zone and no catch-all → NXDOMAIN.
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNameError)
		return resp
	}
	server := p.getForwarder(z)

	var resp *dns.Msg
	var err error
	// proxied marks responses relayed untouched from upstream on behalf of a
	// DNSSEC-validating client (RFC 6147 §5.5): their header flags — including
	// an AD bit asserted by a validating upstream — belong to the upstream and
	// are passed through as-is. Every other response is stripped of AD.
	proxied := false

	if q.Qclass != dns.ClassINET {
		resp, err = p.passThrough(req, server)
	} else {
		switch q.Qtype {
		case dns.TypeAAAA:
			if dnssecValidatingClient(req) {
				// RFC 4033–4035 via RFC 6147 §5.5: a validating client
				// (CD=1 && DO=1) gets the upstream answer verbatim — no
				// synthesis, no filtering, no cache.
				proxied = true
				resp, err = p.passThrough(req, server)
			} else {
				resp, err = p.handleAAAA(req, &q, z, server)
			}
		case dns.TypeANY:
			if dnssecValidatingClient(req) {
				// Validating clients must not receive synthesised data; relay
				// the ANY query itself instead of rewriting it to AAAA.
				proxied = true
				resp, err = p.passThrough(req, server)
			} else {
				// ydn64 only ever serves IPv6-only clients, so a raw ANY answer
				// containing real A records would be unusable to them anyway.
				// Reuse the AAAA synthesis/filter path (respecting the zone's
				// return-ipv4-addresses/return-ipv6-addresses/prefix rules)
				// instead of blindly passing through whatever the upstream
				// resolver returns for ANY (which varies wildly — some upstreams
				// apply RFC 8482 and reply with a bare HINFO record). The upstream
				// query itself must ask for AAAA, not ANY — handleAAAA uses q's
				// Qtype verbatim when building its upstream query, so an
				// unmodified ANY question here would leak straight through as an
				// upstream ANY query instead of triggering real AAAA synthesis.
				aaaaQ := q
				aaaaQ.Qtype = dns.TypeAAAA
				resp, err = p.handleAAAA(req, &aaaaQ, z, server)
				if resp != nil {
					resp.Question[0].Qtype = dns.TypeANY
				}
			}
		case dns.TypeA:
			resp, err = p.handleA(req, &q, z, server)
		case dns.TypePTR:
			resp, err = p.handlePTR(req, &q, z, server)
		default:
			resp, err = p.passThrough(req, server)
		}
	}

	if err != nil || resp == nil {
		r := new(dns.Msg)
		r.SetRcode(req, dns.RcodeServerFailure)
		return r
	}
	resp.RecursionAvailable = true
	if !proxied {
		// RFC 6147 §5.5 / RFC 4035: ydn64 never validates DNSSEC, so it must
		// never assert the AD bit on data it generated, filtered, cached, or
		// rewrote — nor echo a query's own AD flag back to the client.
		resp.AuthenticatedData = false
	}
	return resp
}

// handleAAAA implements DNS64 AAAA synthesis:
//  1. Check cache.
//  2. Query upstream for AAAA — pass through real AAAA if zone.returnIPv6Addresses.
//  3. If no usable AAAA, query A and synthesise from prefix (if configured).
func (p *proxy) handleAAAA(req *dns.Msg, q *dns.Question, z *zone, server string) (*dns.Msg, error) {
	// Intercept ipv4only.arpa. queries and answer locally per RFC 7050 & RFC 8880.
	if strings.ToLower(q.Name) == "ipv4only.arpa." {
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Question[0].Qtype = dns.TypeAAAA
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess

		if z.prefix != nil {
			for _, ip4 := range ipv4OnlyARPAIPs {
				synth := makeSynthesisedAAAA(z.prefix, ip4)
				rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", q.Name, synth.String()))
				if err == nil && rr != nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
		}
		return resp, nil
	}

	// Cache hit?
	if cached, ok := p.cache.get(cacheKeyFor(q)); ok {
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Answer = cached
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

	// RFC 6147 §5.1.2: A result with RCODE=3 (Name Error / NXDOMAIN) is returned to the client immediately.
	if upResp.Rcode == dns.RcodeNameError {
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Rcode = dns.RcodeNameError
		resp.Ns = upResp.Ns
		resp.Extra = upResp.Extra
		resp.Question[0].Qtype = dns.TypeAAAA
		resp.Response = true
		return resp, nil
	}

	var answer []dns.RR

	// If the AAAA response RCODE is 0 (No error condition), filter and check for usable AAAA.
	// Any other RCODE is treated as though the RCODE were 0 and the answer section were empty (falling through to A lookup).
	if upResp.Rcode == dns.RcodeSuccess {
		answer = p.filterAAAA(upResp.Answer, z)
		if containsAAAA(answer) {
			p.cache.set(cacheKeyFor(q), answer)
			resp := new(dns.Msg)
			req.CopyTo(resp)
			resp.Answer = answer
			resp.Question[0].Qtype = dns.TypeAAAA
			resp.Response = true
			return resp, nil
		}
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

	// RFC 6147 §5.1.7: Synthetic TTL = min(A TTL, SOA TTL from negative AAAA response).
	// If no SOA RR was delivered with the negative response to the AAAA query,
	// use min(A TTL, 600 seconds).
	maxTTL := uint32(600)
	if upResp != nil {
		for _, rr := range upResp.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				maxTTL = soa.Header().Ttl
				break
			}
		}
	}

	answer = p.synthesiseFromA(aResp.Answer, q.Name, z, maxTTL)

	resp := new(dns.Msg)
	req.CopyTo(resp)

	// RFC 6147 §5.1.6: If the A RR query results in an empty answer or in an error,
	// then the empty result or error is used as the basis for the answer returned to the client.
	if aResp.Rcode != dns.RcodeSuccess || len(answer) == 0 {
		resp.Rcode = aResp.Rcode
		// Filter out A records but preserve any other records (e.g. CNAMEs/DNAMEs)
		var nonARecords []dns.RR
		for _, rr := range aResp.Answer {
			if _, ok := rr.(*dns.A); !ok {
				nonARecords = append(nonARecords, rr)
			}
		}
		resp.Answer = nonARecords
	} else {
		resp.Rcode = dns.RcodeSuccess
		// Preserve CNAMEs/DNAMEs in the response along with synthetic AAAA records
		var answerWithCNAMEs []dns.RR
		for _, rr := range aResp.Answer {
			if _, ok := rr.(*dns.A); !ok {
				answerWithCNAMEs = append(answerWithCNAMEs, rr)
			}
		}
		answerWithCNAMEs = append(answerWithCNAMEs, answer...)
		resp.Answer = answerWithCNAMEs
		p.cache.set(cacheKeyFor(q), resp.Answer)
	}

	resp.Ns = aResp.Ns
	resp.Extra = aResp.Extra
	resp.Question[0].Qtype = dns.TypeAAAA
	resp.Response = true
	return resp, nil
}

// containsAAAA reports whether rrs contains at least one actual AAAA
// record (as opposed to only accompanying records like CNAME). A CNAME
// chain with no usable AAAA at the end is not a real answer — handleAAAA
// must fall through to A-record synthesis in that case rather than
// returning the bare CNAME as if it were a successful DNS64 answer.
func containsAAAA(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.AAAA); ok {
			return true
		}
	}
	return false
}

// filterAAAA selects AAAA records from rrs according to zone rules:
//   - Unspecified (::) is handled by InvalidAddress policy.
//   - AAAA passes through only if zone.returnIPv6Addresses (this covers
//     Yggdrasil-native 200::/7 addresses too — there is no special-casing
//     for that range, it's just another IPv6 answer gated by the flag).
//   - Mutually exclusive: zone.prefix and zone.returnIPv6Addresses are
//     validated at config load time.
//   - Non-AAAA records (e.g. CNAME) are passed through unchanged, but a
//     CNAME alone (in a prefix-synthesis zone where the real AAAA is
//     intentionally filtered out) does NOT count as a usable answer — see
//     containsAAAA, used by the caller to decide whether to fall through
//     to A-record synthesis.
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
			switch p.cfg.Load().ia {
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
// zone.prefix + the embedded IPv4, capping TTL at maxTTL per RFC 6147 §5.1.7.
// Per RFC 6147 §5.1.5/5.1.7, the owner name of each synthetic AAAA record
// is taken from the owner name of the corresponding target A record.
func (p *proxy) synthesiseFromA(rrs []dns.RR, fallbackName string, z *zone, maxTTL uint32) []dns.RR {
	out := make([]dns.RR, 0)
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ownerName := a.Header().Name
		if ownerName == "" {
			ownerName = fallbackName
		}
		ipv4 := a.A
		ttl := a.Header().Ttl
		if ttl > maxTTL {
			ttl = maxTTL
		}

		if ipv4.IsUnspecified() {
			switch p.cfg.Load().ia {
			case IADiscard:
				continue
			case IAIgnore:
				// treat 0.0.0.0 like a normal address → synthesise pool6::0.0.0.0
			case IAProcess:
				// 0.0.0.0 → translate to [::]
				rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN AAAA ::", ownerName, ttl))
				out = append(out, rr)
				continue
			}
		}

		if p.isIgnoredDst(ipv4) {
			continue
		}

		synth := makeSynthesisedAAAA(z.prefix, ipv4)
		rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", ownerName, ttl, synth.String()))
		if rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// handleA returns A records only if zone.returnIPv4Addresses is set.
func (p *proxy) handleA(req *dns.Msg, q *dns.Question, z *zone, server string) (*dns.Msg, error) {
	// Intercept ipv4only.arpa. queries and answer locally per RFC 8880.
	if strings.ToLower(q.Name) == "ipv4only.arpa." {
		resp := new(dns.Msg)
		req.CopyTo(resp)
		resp.Question[0].Qtype = dns.TypeA
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess
		for _, ip4 := range ipv4OnlyARPAIPs {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip4.String()))
			if err == nil && rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
		return resp, nil
	}

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
	for _, z := range p.cfg.Load().zones {
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
