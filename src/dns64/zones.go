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
		return IAIgnore, fmt.Errorf("unknown Dns64InvalidAddress value %q (want \"ignore\", \"process\", or \"discard\")", s)
	}
}

// zone is the resolved, ready-to-use form of config.ZoneConfig.
type zone struct {
	domains             []string       // already lower-cased
	forwarder           string         // empty → use default
	prefix              *config.Pref64 // nil → no NAT64 synthesis
	returnIPv4Addresses bool
	returnIPv6Addresses bool
}

// buildZones converts the config zone slice into a slice of resolved zone
// structs.  Validation has already been done in config.validate().
func buildZones(cfgZones []config.ZoneConfig) []zone {
	out := make([]zone, 0, len(cfgZones))
	for _, z := range cfgZones {
		var prefix *config.Pref64
		if z.Prefix != "" {
			// Validation guarantees this parses; surface a nil-safe fallback
			// rather than a half-configured zone if it ever doesn't.
			prefix, _ = config.ParsePref64Addr(z.Prefix)
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

// matchZone finds the zone for the given FQDN (already lowercased, trailing
// dot included). Zones are evaluated in CONFIG ORDER: the first zone whose
// domain list contains an exact match or suffix of fqdn wins — so list more
// specific zones before broader ones. A zone with domains = ["."] acts as
// the catch-all default and is only consulted after every other zone has
// been checked. Returns nil if no zone matches.
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

// makeSynthesisedAAAA embeds ipv4 into the zone's RFC 6052 prefix to create
// a NAT64 AAAA address (u octet and suffix left zero).
func makeSynthesisedAAAA(prefix *config.Pref64, ipv4 net.IP) net.IP {
	if prefix == nil {
		return nil
	}
	return prefix.Embed(ipv4)
}
