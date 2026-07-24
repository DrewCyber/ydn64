package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
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
	Enable         bool
	Listen         string
	Default        string
	CacheExp       int
	CachePurge     int
	InvalidAddress string
	Zones          []ZoneConfig
}

// NAT64Config holds configuration for the NAT64 service.
type NAT64Config struct {
	Enable     bool
	Pool6      string
	UDPTimeout int
}

// AppConfig holds the ydn64-specific (NAT64/DNS64) settings. It is decoded
// from the same single HJSON file (ydn64.conf) as the Yggdrasil node
// configuration; only the ydn64-specific keys (AllowedSources, Nat64*,
// Dns64*) are read into this struct — the Yggdrasil keys (PrivateKey, Peers,
// Listen, ...) are parsed separately into a ygconfig.NodeConfig and are
// simply ignored here.
type AppConfig struct {
	AllowedSources       []string     `json:"AllowedSources"`
	Nat64Enable          bool         `json:"Nat64Enable"`
	Nat64Pool            string       `json:"Nat64Pool"`
	Nat64UdpTimeout      int          `json:"Nat64UdpTimeout"`
	Dns64Enable          bool         `json:"Dns64Enable"`
	Dns64Listen          string       `json:"Dns64Listen"`
	Dns64Default         string       `json:"Dns64Default"`
	Dns64CacheExpiration int          `json:"Dns64CacheExpiration"`
	Dns64CachePurge      int          `json:"Dns64CachePurge"`
	Dns64InvalidAddress  string       `json:"Dns64InvalidAddress"`
	Dns64Zones           []ZoneConfig `json:"Dns64Zones"`
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

// ParseAllowedNets converts AllowedSources config entries (bare IPs or
// CIDRs) into a slice of *net.IPNet, as consumed by nat64.Service and
// dns64.Service's isAllowed() checks. Invalid entries are silently skipped —
// AppConfig.Validate() is responsible for rejecting them at load time.
func ParseAllowedNets(sources []string) []*net.IPNet {
	var out []*net.IPNet
	for _, src := range sources {
		if ip := net.ParseIP(src); ip != nil {
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		} else if _, cidr, err := net.ParseCIDR(src); err == nil {
			out = append(out, cidr)
		}
	}
	return out
}

// NAT64 returns the NAT64Config view of the merged configuration.
func (c *AppConfig) NAT64() NAT64Config {
	return NAT64Config{
		Enable:     c.Nat64Enable,
		Pool6:      c.Nat64Pool,
		UDPTimeout: c.Nat64UdpTimeout,
	}
}

// DNS64 returns the DNS64Config view of the merged configuration.
func (c *AppConfig) DNS64() DNS64Config {
	return DNS64Config{
		Enable:         c.Dns64Enable,
		Listen:         c.Dns64Listen,
		Default:        c.Dns64Default,
		CacheExp:       c.Dns64CacheExpiration,
		CachePurge:     c.Dns64CachePurge,
		InvalidAddress: c.Dns64InvalidAddress,
		Zones:          c.Dns64Zones,
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

	if c.Nat64Enable {
		if c.Nat64Pool == "" {
			return fmt.Errorf("Nat64Pool is required when Nat64Enable = true")
		}
		if _, _, err := net.ParseCIDR(c.Nat64Pool); err != nil {
			return fmt.Errorf("Nat64Pool %q is not a valid CIDR: %w", c.Nat64Pool, err)
		}
		if c.Nat64UdpTimeout <= 0 {
			c.Nat64UdpTimeout = 30
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
		for i, zone := range c.Dns64Zones {
			if zone.Prefix != "" && zone.ReturnIPv6Addresses {
				return fmt.Errorf("Dns64Zones[%d]: \"prefix\" and \"return-ipv6-addresses: true\" are mutually exclusive", i)
			}
			if len(zone.Domains) == 0 {
				return fmt.Errorf("Dns64Zones[%d]: \"domains\" list is required", i)
			}
			if zone.Prefix != "" && net.ParseIP(zone.Prefix) == nil {
				return fmt.Errorf("Dns64Zones[%d]: \"prefix\" %q is not a valid IPv6 address", i, zone.Prefix)
			}
		}
		if c.Dns64CacheExpiration <= 0 {
			c.Dns64CacheExpiration = 300
		}
		if c.Dns64CachePurge <= 0 {
			c.Dns64CachePurge = 600
		}
	}

	return nil
}
