package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hjson/hjson-go/v4"
	ygconfig "github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// ZoneConfig defines DNS64 behaviour for a matched domain group.
type ZoneConfig struct {
	Domains             []string `json:"domains"`
	Forwarder           string   `json:"forwarder,omitempty"`
	Prefix              string   `json:"prefix,omitempty"`
	ReturnIPv4Addresses bool     `json:"return-ipv4-addresses,omitempty"`
	ReturnIPv6Addresses bool     `json:"return-ipv6-addresses,omitempty"`
}

// DNS64Config holds configuration for the embedded DNS64 service.
type DNS64Config struct {
	Enable          bool
	Listen          string
	Default         string
	CacheExp        int
	CachePurge      int
	MaxCacheEntries int
	MaxQueries      int
	RateLimit       int
	InvalidAddress  string
	Zones           []ZoneConfig
}

// NAT64Config holds configuration for the NAT64 service.
type NAT64Config struct {
	Enable                  bool
	Pool6                   string
	UDPTimeout              int
	MaxTCPClients           int
	MaxUDPSessions          int
	MaxUDPSessionsPerSrc    int
	MaxTCPConnectionsPerSrc int
}

// Default resource-bound values applied when the corresponding keys are
// unset or non-positive. Any allowed peer can generate unbounded load
// otherwise, so every limit is deliberately bounded by default.
const (
	DefaultDns64MaxCacheEntries   = 4096
	DefaultDns64MaxQueries        = 512
	DefaultNat64MaxTCPConnections = 1024
	DefaultNat64MaxUDPSessions    = 4096

	// Anti-abuse ceilings (RFC 5358, RFC 6146 §5.3): generous enough for a
	// busy legitimate client, tight enough that a single peer cannot dominate
	// the resolver or exhaust translator state.
	DefaultDns64RateLimit               = 50 // queries per second per source
	DefaultNat64MaxUDPSessionsPerSrc    = 256
	DefaultNat64MaxTCPConnectionsPerSrc = 128
)

// DefaultIgnoredDstSubnets contains the default IPv4 private, loopback, link-local,
// and multicast/reserved subnets ignored by NAT64 and DNS64.
var DefaultIgnoredDstSubnets = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"100.64.0.0/10",
	"0.0.0.0/8",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	// IANA special-purpose ranges (RFC 6890): benchmarking, 6to4 relay
	// legacy prefix, and the port-control protocol anycast range.
	"192.0.0.0/24",
	"198.18.0.0/15",
	"192.88.99.0/24",
}

// AppConfig holds the ydn64-specific (NAT64/DNS64) settings. It is decoded
// from the same single HJSON file (ydn64.conf) as the Yggdrasil node
// configuration; only the ydn64-specific keys (AllowedSources, IgnoredDstSubnets,
// Nat64*, Dns64*) are read into this struct — the Yggdrasil keys (PrivateKey, Peers,
// Listen, ...) are parsed separately into a ygconfig.NodeConfig and are
// simply ignored here.
type AppConfig struct {
	AllowedSources            []string     `json:"AllowedSources"`
	IgnoredDstSubnets         []string     `json:"IgnoredDstSubnets"`
	Nat64Enable               bool         `json:"Nat64Enable"`
	Nat64Pool                 string       `json:"Nat64Pool"`
	Nat64UdpTimeout           int          `json:"Nat64UdpTimeout"`
	Nat64MaxTCPConnections    int          `json:"Nat64MaxTCPConnections"`
	Nat64MaxUDPSessions       int          `json:"Nat64MaxUDPSessions"`
	Nat64MaxUDPSessionsPerSrc int          `json:"Nat64MaxUDPSessionsPerSource"`
	Nat64MaxTCPConnectionsSrc int          `json:"Nat64MaxTCPConnectionsPerSource"`
	Dns64Enable               bool         `json:"Dns64Enable"`
	Dns64Listen               string       `json:"Dns64Listen"`
	Dns64Default              string       `json:"Dns64Default"`
	Dns64CacheExpiration      int          `json:"Dns64CacheExpiration"`
	Dns64CachePurge           int          `json:"Dns64CachePurge"`
	Dns64MaxCacheEntries      int          `json:"Dns64MaxCacheEntries"`
	Dns64MaxConcurrentQueries int          `json:"Dns64MaxConcurrentQueries"`
	Dns64RateLimit            int          `json:"Dns64RateLimit"`
	Dns64InvalidAddress       string       `json:"Dns64InvalidAddress"`
	Dns64Zones                []ZoneConfig `json:"Dns64Zones"`
}

// ApplyPrivateKeyOverride recomputes Nat64Pool and Dns64Listen, and resets
// Dns64Zones to a single default synthesis zone, using addresses derived
// from an overridden PrivateKey (nodeIP, pool6CIDR, pool6Prefix — see
// DeriveFromPrivateKey). This keeps NAT64/DNS64 addressing consistent when
// PrivateKey is overridden at runtime (e.g. via YDN64_PRIVATE_KEY) instead
// of read as-is from the config file, discarding any custom Dns64Zones in
// favor of the single default zone.
func (c *AppConfig) ApplyPrivateKeyOverride(nodeIP, pool6CIDR, pool6Prefix string) {
	c.Nat64Pool = pool6CIDR
	c.Dns64Listen = fmt.Sprintf("[%s]:53", nodeIP)
	c.Dns64Zones = []ZoneConfig{
		{
			Domains:             []string{"."},
			ReturnIPv4Addresses: false,
			Prefix:              pool6Prefix,
		},
	}
}

// ParseIPNets converts config entries (bare IPs or CIDRs) into a slice of *net.IPNet.
// Invalid entries are silently skipped — AppConfig.Validate() is responsible
// for rejecting them at load time.
func ParseIPNets(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		} else if _, cidr, err := net.ParseCIDR(entry); err == nil {
			out = append(out, cidr)
		}
	}
	return out
}

// ParseAllowedNets converts AllowedSources config entries (bare IPs or
// CIDRs) into a slice of *net.IPNet, as consumed by nat64.Service and
// dns64.Service's isAllowed() checks.
func ParseAllowedNets(sources []string) []*net.IPNet {
	return ParseIPNets(sources)
}

// NAT64 returns the NAT64Config view of the merged configuration.
func (c *AppConfig) NAT64() NAT64Config {
	return NAT64Config{
		Enable:                  c.Nat64Enable,
		Pool6:                   c.Nat64Pool,
		UDPTimeout:              c.Nat64UdpTimeout,
		MaxTCPClients:           c.Nat64MaxTCPConnections,
		MaxUDPSessions:          c.Nat64MaxUDPSessions,
		MaxUDPSessionsPerSrc:    c.Nat64MaxUDPSessionsPerSrc,
		MaxTCPConnectionsPerSrc: c.Nat64MaxTCPConnectionsSrc,
	}
}

// DNS64 returns the DNS64Config view of the merged configuration.
func (c *AppConfig) DNS64() DNS64Config {
	return DNS64Config{
		Enable:          c.Dns64Enable,
		Listen:          c.Dns64Listen,
		Default:         c.Dns64Default,
		CacheExp:        c.Dns64CacheExpiration,
		CachePurge:      c.Dns64CachePurge,
		MaxCacheEntries: c.Dns64MaxCacheEntries,
		MaxQueries:      c.Dns64MaxConcurrentQueries,
		RateLimit:       c.Dns64RateLimit,
		InvalidAddress:  c.Dns64InvalidAddress,
		Zones:           c.Dns64Zones,
	}
}

// Load reads and validates the single ydn64.conf HJSON configuration file at
// path, returning the Yggdrasil node configuration and the ydn64-specific
// (NAT64/DNS64) configuration.
func Load(path string) (*ygconfig.NodeConfig, *AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	ygCfg := ygconfig.GenerateConfig()
	if _, err := ygCfg.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, nil, fmt.Errorf("parsing yggdrasil section of %q: %w", path, err)
	}

	appCfg := &AppConfig{}
	if err := hjson.Unmarshal(data, appCfg); err != nil {
		return nil, nil, fmt.Errorf("parsing ydn64 section of %q: %w", path, err)
	}
	if err := appCfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return ygCfg, appCfg, nil
}

func (c *AppConfig) Validate() error {
	for _, src := range c.AllowedSources {
		if _, _, err := net.ParseCIDR(src); err != nil {
			if net.ParseIP(src) == nil {
				return fmt.Errorf("AllowedSources: invalid entry %q", src)
			}
		}
	}

	if c.IgnoredDstSubnets == nil {
		c.IgnoredDstSubnets = append([]string(nil), DefaultIgnoredDstSubnets...)
	}

	for _, dst := range c.IgnoredDstSubnets {
		if _, _, err := net.ParseCIDR(dst); err != nil {
			if net.ParseIP(dst) == nil {
				return fmt.Errorf("IgnoredDstSubnets: invalid entry %q", dst)
			}
		}
	}

	if c.Nat64Enable {
		if c.Nat64Pool == "" {
			return fmt.Errorf("Nat64Pool is required when Nat64Enable = true")
		}
		_, ipnet, err := net.ParseCIDR(c.Nat64Pool)
		if err != nil {
			return fmt.Errorf("Nat64Pool %q is not a valid CIDR: %w", c.Nat64Pool, err)
		}
		// Everything downstream hard-codes the well-known prefix format:
		// embedded-v4 extraction at byte 12, AAAA synthesis and PTR
		// generation all assume exactly 96 prefix bits. A hand-edited /64
		// would misbehave silently, so reject anything else up front.
		if ones, _ := ipnet.Mask.Size(); ones != 96 {
			return fmt.Errorf("Nat64Pool %q must be a /96 prefix (got /%d); variable-length RFC 6052 prefixes are not supported", c.Nat64Pool, ones)
		}
		if c.Nat64UdpTimeout <= 0 {
			c.Nat64UdpTimeout = 300
		} else if c.Nat64UdpTimeout < 120 {
			return fmt.Errorf("Nat64UdpTimeout must not be less than 120 seconds")
		}
		if c.Nat64MaxTCPConnections <= 0 {
			c.Nat64MaxTCPConnections = DefaultNat64MaxTCPConnections
		}
		if c.Nat64MaxUDPSessions <= 0 {
			c.Nat64MaxUDPSessions = DefaultNat64MaxUDPSessions
		}
		if c.Nat64MaxUDPSessionsPerSrc <= 0 {
			c.Nat64MaxUDPSessionsPerSrc = DefaultNat64MaxUDPSessionsPerSrc
		}
		if c.Nat64MaxTCPConnectionsSrc <= 0 {
			c.Nat64MaxTCPConnectionsSrc = DefaultNat64MaxTCPConnectionsPerSrc
		}
	}

	if c.Dns64Enable {
		if c.Dns64Default == "" {
			return fmt.Errorf("Dns64Default forwarder is required when Dns64Enable = true")
		}
		if c.Dns64InvalidAddress == "" {
			c.Dns64InvalidAddress = "ignore"
		}
		ia := strings.ToLower(c.Dns64InvalidAddress)
		if ia != "ignore" && ia != "process" && ia != "discard" {
			return fmt.Errorf(`Dns64InvalidAddress must be "ignore", "process", or "discard", got %q`, c.Dns64InvalidAddress)
		}
		if err := validateForwarder("Dns64Default", c.Dns64Default); err != nil {
			return err
		}
		for i, zone := range c.Dns64Zones {
			if zone.Prefix != "" && zone.ReturnIPv6Addresses {
				return fmt.Errorf("Dns64Zones[%d]: \"prefix\" and \"return-ipv6-addresses: true\" are mutually exclusive", i)
			}
			if len(zone.Domains) == 0 {
				return fmt.Errorf("Dns64Zones[%d]: \"domains\" list is required", i)
			}
			if zone.Prefix != "" {
				ip := net.ParseIP(zone.Prefix)
				switch {
				case ip == nil:
					return fmt.Errorf("Dns64Zones[%d]: \"prefix\" %q is not a valid IPv6 address", i, zone.Prefix)
				case ip.To4() != nil:
					return fmt.Errorf("Dns64Zones[%d]: \"prefix\" %q must be an IPv6 address", i, zone.Prefix)
				}
				// Synthesis overwrites the last four bytes with the embedded
				// IPv4 address (and PTR matching compares the first twelve),
				// so a prefix with any of those bits set would silently
				// produce garbage — require a true /96 network up front.
				if p := ip.To16(); !bytes.Equal(p[12:], make([]byte, 4)) {
					return fmt.Errorf("Dns64Zones[%d]: \"prefix\" %q must be a /96 network (its last four bytes must be zero)", i, zone.Prefix)
				}
			}
			if zone.Forwarder != "" {
				if err := validateForwarder(fmt.Sprintf("Dns64Zones[%d].forwarder", i), zone.Forwarder); err != nil {
					return err
				}
			}
		}
		if c.Dns64CacheExpiration <= 0 {
			c.Dns64CacheExpiration = 300
		}
		if c.Dns64CachePurge <= 0 {
			c.Dns64CachePurge = 600
		}
		if c.Dns64MaxCacheEntries <= 0 {
			c.Dns64MaxCacheEntries = DefaultDns64MaxCacheEntries
		}
		if c.Dns64MaxConcurrentQueries <= 0 {
			c.Dns64MaxConcurrentQueries = DefaultDns64MaxQueries
		}
		if c.Dns64RateLimit <= 0 {
			c.Dns64RateLimit = DefaultDns64RateLimit
		}
	}

	return nil
}

// validateForwarder checks that a forwarder address has "host:port"
// structure with a numeric port in range. The host may be an IP literal or
// a hostname; note that Yggdrasil-native (200::/7) forwarders only work as
// numeric IPv6 literals, since they dial through the embedded netstack.
func validateForwarder(name, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q is not in host:port form: %v", name, addr, err)
	}
	if host == "" {
		return fmt.Errorf("%s %q has an empty host", name, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s %q has an invalid port %q (want 1-65535)", name, addr, portStr)
	}
	return nil
}
