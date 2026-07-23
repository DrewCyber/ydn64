package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// ZoneConfig defines DNS64 behaviour for a matched domain group.
type ZoneConfig struct {
	Domains          []string `toml:"domains"`
	Forwarder        string   `toml:"forwarder,omitempty"`
	Prefix           string   `toml:"prefix,omitempty"`
	ReturnPublicIPv4 bool     `toml:"return-public-ipv4"`
	ReturnPublicIPv6 bool     `toml:"return-public-ipv6"`
}

// DNS64Config holds configuration for the embedded DNS64 service.
type DNS64Config struct {
	Enable         bool                  `toml:"enable"`
	Listen         string                `toml:"listen"`
	Default        string                `toml:"default"`
	CacheExp       int                   `toml:"cache_expiration"`
	CachePurge     int                   `toml:"cache_purge"`
	InvalidAddress string                `toml:"invalid_address"`
	Zones          map[string]ZoneConfig `toml:"zones"`
}

// NAT64Config holds configuration for the NAT64 service.
type NAT64Config struct {
	Enable     bool   `toml:"enable"`
	Pool6      string `toml:"pool6"`
	UDPTimeout int    `toml:"udp_timeout"`
}

// AppConfig is the top-level ydn64 TOML configuration.
type AppConfig struct {
	YggdrasilConf  string      `toml:"yggdrasil_conf"`
	AllowedSources []string    `toml:"allowed_sources"`
	NAT64          NAT64Config `toml:"nat64"`
	DNS64          DNS64Config `toml:"dns64"`
}

// Load reads and validates the ydn64 TOML configuration file at path.
func Load(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	cfg := &AppConfig{}
	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *AppConfig) validate() error {
	if c.YggdrasilConf == "" {
		return fmt.Errorf("yggdrasil_conf is required")
	}

	for _, src := range c.AllowedSources {
		if _, _, err := net.ParseCIDR(src); err != nil {
			if net.ParseIP(src) == nil {
				return fmt.Errorf("allowed_sources: invalid entry %q", src)
			}
		}
	}

	if c.NAT64.Enable {
		if c.NAT64.Pool6 == "" {
			return fmt.Errorf("nat64.pool6 is required when nat64.enable = true")
		}
		if _, _, err := net.ParseCIDR(c.NAT64.Pool6); err != nil {
			return fmt.Errorf("nat64.pool6 %q is not a valid CIDR: %w", c.NAT64.Pool6, err)
		}
		if c.NAT64.UDPTimeout <= 0 {
			c.NAT64.UDPTimeout = 30
		}
	}

	if c.DNS64.Enable {
		if c.DNS64.Default == "" {
			return fmt.Errorf("dns64.default forwarder is required when dns64.enable = true")
		}
		if c.DNS64.InvalidAddress == "" {
			c.DNS64.InvalidAddress = "ignore"
		}
		ia := strings.ToLower(c.DNS64.InvalidAddress)
		if ia != "ignore" && ia != "process" && ia != "discard" {
			return fmt.Errorf(`dns64.invalid_address must be "ignore", "process", or "discard", got %q`, c.DNS64.InvalidAddress)
		}
		for name, zone := range c.DNS64.Zones {
			if zone.Prefix != "" && zone.ReturnPublicIPv6 {
				return fmt.Errorf("dns64.zones.%s: \"prefix\" and \"return-public-ipv6 = true\" are mutually exclusive", name)
			}
			if len(zone.Domains) == 0 {
				return fmt.Errorf("dns64.zones.%s: \"domains\" list is required", name)
			}
			if zone.Prefix != "" && net.ParseIP(zone.Prefix) == nil {
				return fmt.Errorf("dns64.zones.%s: \"prefix\" %q is not a valid IPv6 address", name, zone.Prefix)
			}
		}
		if c.DNS64.CacheExp <= 0 {
			c.DNS64.CacheExp = 300
		}
		if c.DNS64.CachePurge <= 0 {
			c.DNS64.CachePurge = 600
		}
	}

	return nil
}
