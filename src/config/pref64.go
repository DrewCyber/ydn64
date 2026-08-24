package config

import (
	"bytes"
	"fmt"
	"net"
)

// Pref64 describes a validated RFC 6052 §2.2 NAT64 prefix together with the
// byte offsets of its embedded IPv4 address.
//
// Per Figure 1 of RFC 6052, an IPv4-embedded IPv6 address is laid out as
//
//	| prefix (n bits) | IPv4 (32 bits) | u (8 bits) | suffix |
//
// where the boundaries land so that — expressed in whole octets, the only
// lengths the RFC defines — the u octet is ALWAYS octet 8 and the four IPv4
// octets sit at these positions:
//
//	/32 → 4,5,6,7   /40 → 5,6,7,9   /48 → 6,7,9,10
//	/56 → 7,9,10,11 /64 → 9,10,11,12 /96 → 12,13,14,15 (no u octet)
//
// The u octet MUST be zero (RFC 6052 §2.2), and so must the trailing suffix,
// for an address to be an unambiguous member of the pool.
type Pref64 struct {
	Net  *net.IPNet
	Bits int
}

// pref64UByte is the fixed position of the u octet for every supported
// prefix length below /96.
const pref64UByte = 8

// pref64V4Offsets returns the four byte indices holding the embedded IPv4
// address for the given prefix length.
func pref64V4Offsets(bits int) ([4]int, bool) {
	switch bits {
	case 32:
		return [4]int{4, 5, 6, 7}, true
	case 40:
		return [4]int{5, 6, 7, 9}, true
	case 48:
		return [4]int{6, 7, 9, 10}, true
	case 56:
		return [4]int{7, 9, 10, 11}, true
	case 64:
		return [4]int{9, 10, 11, 12}, true
	case 96:
		return [4]int{12, 13, 14, 15}, true
	}
	return [4]int{}, false
}

// ParsePref64 parses and fully validates an RFC 6052 §2.2 NAT64 prefix in
// CIDR notation. The prefix length must be one of /32, /40, /48, /56, /64
// or /96 (whole octets, the only lengths the RFC defines), and the address
// itself must have all bits outside the prefix and the embedded-IPv4 region
// (i.e. the u octet and the trailing suffix) equal to zero, so that the
// network form of the prefix is unambiguous.
func ParsePref64(s string) (*Pref64, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid CIDR prefix", s)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("%q must be an IPv6 prefix", s)
	}
	ones, _ := ipnet.Mask.Size()
	if _, ok := pref64V4Offsets(ones); !ok {
		return nil, fmt.Errorf("%q has unsupported prefix length /%d (RFC 6052 supports /32, /40, /48, /56, /64 and /96)", s, ones)
	}
	// All allowed lengths are multiples of eight, so the mask covers whole
	// octets; everything that is neither prefix nor embedded IPv4 must be
	// zero in the network address.
	pfx, offs := ones/8, mustOffsets(ones)
	addr := ip.To16()
	for i := 0; i < 16; i++ {
		if i < pfx {
			continue
		}
		inV4 := false
		for _, o := range offs {
			if o == i {
				inV4 = true
				break
			}
		}
		if inV4 {
			continue
		}
		if addr[i] != 0 {
			return nil, fmt.Errorf("%q has non-zero bits outside the prefix and embedded IPv4 region (u octet and suffix must be zero)", s)
		}
	}
	return &Pref64{Net: ipnet, Bits: ones}, nil
}

// ParsePref64Addr parses a NAT64 prefix written as a bare address. Without a
// length suffix the RFC 6052 /96 format is implied — the historical ydn64
// zone-prefix form, where the last four octets name the embedded-IPv4
// region and therefore must be zero. An explicit "/n" suffix switches to the
// variable-length forms accepted by ParsePref64.
func ParsePref64Addr(s string) (*Pref64, error) {
	if idx := indexSlash(s); idx >= 0 {
		return ParsePref64(s)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%q is not a valid IPv6 address", s)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("%q must be an IPv6 address", s)
	}
	if p := ip.To16(); !bytes.Equal(p[12:], make([]byte, 4)) {
		return nil, fmt.Errorf("%q must be a /96 network (its last four bytes must be zero) or carry an explicit /n length", s)
	}
	_, ipnet, err := net.ParseCIDR(s + "/96")
	if err != nil {
		return nil, err
	}
	return &Pref64{Net: ipnet, Bits: 96}, nil
}

func indexSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func mustOffsets(bits int) [4]int {
	offs, ok := pref64V4Offsets(bits)
	if !ok {
		panic(fmt.Sprintf("config: unsupported pref64 length %d reached runtime paths", bits))
	}
	return offs
}

// Extract pulls the embedded IPv4 address out of an IPv4-embedded IPv6
// address. It reports false unless addr belongs to this pool AND is in
// canonical form: the u octet (for lengths below /96) and every suffix bit
// are zero, so the mapping back to IPv4 is unambiguous (RFC 6052 §2.2/§2.3).
func (p *Pref64) Extract(addr net.IP) ([4]byte, bool) {
	var v4 [4]byte
	a := addr.To16()
	if a == nil || !p.Net.Contains(a) {
		return v4, false
	}
	offs := mustOffsets(p.Bits)
	for i, o := range offs {
		v4[i] = a[o]
	}
	if !bytes.Equal(a, p.embedInto(make([]byte, 16), v4[:])) {
		return [4]byte{}, false
	}
	return v4, true
}

// Embed builds the IPv4-embedded IPv6 address for v4 under this prefix,
// leaving the u octet and suffix zero (canonical form, RFC 6052 §2.3).
func (p *Pref64) Embed(v4 net.IP) net.IP {
	out := p.embedInto(make(net.IP, 16), v4.To4())
	return out
}

func (p *Pref64) embedInto(out []byte, v4 []byte) []byte {
	copy(out, p.Net.IP.To16())
	if p.Bits < 96 {
		out[pref64UByte] = 0
	}
	offs := mustOffsets(p.Bits)
	for i, o := range offs {
		out[o] = v4[i]
	}
	return out
}
