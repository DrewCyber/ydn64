package dns64

import (
	"fmt"
	"net"
	"strings"

	"github.com/DrewCyber/ydn64/src/config"
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
	domains             []string // already lower-cased
	forwarder           string   // empty → use default
	prefix              net.IP   // nil → no NAT64 synthesis
	returnIPv4Addresses bool
	returnIPv6Addresses bool
}

// buildZones converts the config zone slice into a slice of resolved zone
// structs.  Validation has already been done in config.validate().
func buildZones(cfgZones []config.ZoneConfig) []zone {
	out := make([]zone, 0, len(cfgZones))
	for _, z := range cfgZones {
		var prefix net.IP
		if z.Prefix != "" {
			prefix = net.ParseIP(z.Prefix)
		}
		domains := make([]string, len(z.Domains))
		for j, d := range z.Domains {
			dl := strings.ToLower(d)
			// Normalise an optional leading dot (e.g. ".ygg" == "ygg") so
			// matchZone's suffix check ("."+dl) doesn't end up comparing
			// against a double dot that can never match.
			if dl != "." {
				dl = strings.TrimPrefix(dl, ".")
			}
			domains[j] = dl
		}
		out = append(out, zone{
			domains:             domains,
			forwarder:           z.Forwarder,
			prefix:              prefix,
			returnIPv4Addresses: z.ReturnIPv4Addresses,
			returnIPv6Addresses: z.ReturnIPv6Addresses,
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
