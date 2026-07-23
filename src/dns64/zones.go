package dns64

import (
	"fmt"
	"net"
	"strings"

	"github.com/yggdrasil-network/ydn64/src/config"
)

// InvalidAddress controls how unspecified addresses (0.0.0.0 / ::) are handled.
type InvalidAddress int

const (
	// IAIgnore: 0.0.0.0 → synthesise as pool6::0.0.0.0 (i.e. drop; unspecified),
	// [::] → drop.  Default behaviour from yggdns64.
	IAIgnore InvalidAddress = iota
	// IAProcess: 0.0.0.0 → translate to [::]; [::] → return as-is.
	IAProcess
	// IADiscard: drop both 0.0.0.0 and [::].
	IADiscard
)

func parseIA(s string) (InvalidAddress, error) {
	switch strings.ToLower(s) {
	case "ignore", "":
		return IAIgnore, nil
	case "process":
		return IAProcess, nil
	case "discard":
		return IADiscard, nil
	default:
		return IAIgnore, fmt.Errorf("unknown invalid_address value %q", s)
	}
}

// zone is the resolved, ready-to-use form of config.ZoneConfig.
type zone struct {
	name             string
	domains          []string // already lower-cased
	forwarder        string   // empty → use default
	prefix           net.IP   // nil → no NAT64 synthesis
	returnPublicIPv4 bool
	returnPublicIPv6 bool
}

// yggNet is the 200::/7 Yggdrasil address range used to detect native
// yggdrasil AAAA responses that should be passed through unchanged.
var yggNet *net.IPNet

func init() {
	_, yggNet, _ = net.ParseCIDR("200::/7")
}

// buildZones converts the config zone map into a slice of resolved zone
// structs.  Validation has already been done in config.validate().
func buildZones(cfgZones map[string]config.ZoneConfig) []zone {
	out := make([]zone, 0, len(cfgZones))
	for name, z := range cfgZones {
		var prefix net.IP
		if z.Prefix != "" {
			prefix = net.ParseIP(z.Prefix)
		}
		domains := make([]string, len(z.Domains))
		for i, d := range z.Domains {
			domains[i] = strings.ToLower(d)
		}
		out = append(out, zone{
			name:             name,
			domains:          domains,
			forwarder:        z.Forwarder,
			prefix:           prefix,
			returnPublicIPv4: z.ReturnPublicIPv4,
			returnPublicIPv6: z.ReturnPublicIPv6,
		})
	}
	return out
}

// matchZone finds the most-specific zone for the given FQDN (already lowercased,
// trailing dot included).  Returns nil if no zone matches.
//
// Priority:
//  1. Exact domain match or subdomain of a listed domain (most specific first).
//  2. A zone with domains = ["."] acts as the catch-all default.
func matchZone(zones []zone, fqdn string) *zone {
	// fqdn comes in as "foo.bar.com." — strip the trailing dot for matching.
	name := strings.TrimSuffix(strings.ToLower(fqdn), ".")

	var defaultZone *zone
	for i := range zones {
		z := &zones[i]
		for _, d := range z.domains {
			if d == "." {
				defaultZone = z
				continue
			}
			dl := strings.ToLower(d)
			if strings.EqualFold(name, dl) || strings.HasSuffix(name, "."+dl) {
				return z
			}
		}
	}
	return defaultZone // may be nil if no catch-all
}

// makeSynthesisedAAAA embeds ipv4 into prefix to create a NAT64 AAAA address.
// prefix must be a 16-byte IPv6 address; the last 4 bytes are replaced by ipv4.
func makeSynthesisedAAAA(prefix, ipv4 net.IP) net.IP {
	result := make(net.IP, net.IPv6len)
	copy(result, prefix.To16())
	copy(result[12:], ipv4.To4())
	return result
}
