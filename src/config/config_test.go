package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hjson/hjson-go/v4"
)

func TestAppConfigValidate_UDPTimeout(t *testing.T) {
	tests := []struct {
		name           string
		config         AppConfig
		expectErr      bool
		expectedErrSub string
		expectedVal    int
	}{
		{
			name: "Default timeout when <= 0",
			config: AppConfig{
				Nat64Enable: true,
				Nat64Pool:   "300:1:2:3::/96",
			},
			expectErr:   false,
			expectedVal: 300,
		},
		{
			name: "Error when timeout is less than 120",
			config: AppConfig{
				Nat64Enable:     true,
				Nat64Pool:       "300:1:2:3::/96",
				Nat64UdpTimeout: 119,
			},
			expectErr:      true,
			expectedErrSub: "must not be less than 120 seconds",
		},
		{
			name: "Valid when timeout is exactly 120",
			config: AppConfig{
				Nat64Enable:     true,
				Nat64Pool:       "300:1:2:3::/96",
				Nat64UdpTimeout: 120,
			},
			expectErr:   false,
			expectedVal: 120,
		},
		{
			name: "Valid when timeout is greater than 120",
			config: AppConfig{
				Nat64Enable:     true,
				Nat64Pool:       "300:1:2:3::/96",
				Nat64UdpTimeout: 150,
			},
			expectErr:   false,
			expectedVal: 150,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.config
			err := cfg.Validate()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, but got nil")
				}
				if !strings.Contains(err.Error(), tc.expectedErrSub) {
					t.Errorf("expected error to contain %q, got: %v", tc.expectedErrSub, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg.Nat64UdpTimeout != tc.expectedVal {
					t.Errorf("expected Nat64UdpTimeout to be %d, got %d", tc.expectedVal, cfg.Nat64UdpTimeout)
				}
			}
		})
	}
}

// nat64Base returns an AppConfig with a valid NAT64 baseline for validation
// tests.
func nat64Base() AppConfig {
	return AppConfig{
		Nat64Enable: true,
		Nat64Pool:   "300:1:2:3::/96",
	}
}

func TestValidateNat64PoolPrefixFormats(t *testing.T) {
	tests := []struct {
		pool   string
		wantOK bool
	}{
		{"300:1:2:3::/96", true},          // classic ydn64 derived form
		{"301:ca27:1d6e:6d2f::/96", true}, // another canonical /96
		{"64:ff9b::/96", true},            // RFC 6052 Well-Known Prefix shape
		{"2001:db8::/32", true},           // RFC 6052 §2.2 variable lengths
		{"2001:db8:1::/40", true},
		{"2001:db8:1:2::/48", true},
		{"2001:db8:1:2:3::/56", true},
		{"2001:db8::/64", true},
		{"300:1:2:3::/24", false},           // not an RFC 6052 length
		{"300:1:2:3::/128", false},          // no room for embedded IPv4
		{"10.0.0.0/8", false},               // not even IPv6
		{"300:1:2:3::1/64", false},          // dirty suffix bits
		{"300:1:2:3::c000:201:0/32", false}, // dirty u octet (byte 8)
	}
	for _, tc := range tests {
		cfg := nat64Base()
		cfg.Nat64Pool = tc.pool
		err := cfg.Validate()
		if tc.wantOK && err != nil {
			t.Errorf("Validate(pool=%q) = %v, want nil", tc.pool, err)
		}
		if !tc.wantOK {
			if err == nil {
				t.Errorf("Validate(pool=%q) = nil, want rejection", tc.pool)
			} else if !strings.Contains(err.Error(), "RFC 6052") &&
				!strings.Contains(err.Error(), "non-zero bits") &&
				!strings.Contains(err.Error(), "IPv6") {
				t.Errorf("Validate(pool=%q) error = %v, want it to mention RFC 6052, dirty bits, or IPv6", tc.pool, err)
			}
		}
	}
}

func TestValidateZonePrefixMustBeSlash96Network(t *testing.T) {
	tests := []struct {
		prefix string
		wantOK bool
	}{
		{"301:ca27:1d6e:6d2f::", true},   // canonical derived prefix
		{"301:ca27:1d6e:6d2f::1", false}, // host bits set: synthesis would overwrite them
		{"::c0a8:101", false},            // trailing four bytes non-zero
		{"192.0.2.1", false},             // not IPv6
		{"not-an-address", false},
	}
	dnsBase := func(prefix string) AppConfig {
		return AppConfig{
			Dns64Enable:  true,
			Dns64Default: "8.8.8.8:53",
			Dns64Zones: []ZoneConfig{
				{Domains: []string{"."}, Prefix: prefix},
			},
		}
	}
	for _, tc := range tests {
		cfg := dnsBase(tc.prefix)
		err := cfg.Validate()
		if tc.wantOK && err != nil {
			t.Errorf("Validate(prefix=%q) = %v, want nil", tc.prefix, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("Validate(prefix=%q) = nil, want rejection", tc.prefix)
		}
	}
}

func TestValidateForwarderFormat(t *testing.T) {
	tests := []struct {
		forwarder string
		wantOK    bool
	}{
		{"8.8.8.8:53", true},
		{"[308:84:68:55::]:53", true},
		{"resolver.example.com:5353", true}, // hostnames allowed (OS-dialled path)
		{"8.8.8.8", false},                  // missing port
		{":53", false},                      // empty host
		{"8.8.8.8:", false},                 // empty port
		{"8.8.8.8:notaport", false},         // non-numeric port
		{"8.8.8.8:0", false},                // port out of range
		{"8.8.8.8:70000", false},
	}
	for _, tc := range tests {
		cfg := AppConfig{
			Dns64Enable:  true,
			Dns64Default: tc.forwarder,
		}
		err := cfg.Validate()
		if tc.wantOK && err != nil {
			t.Errorf("Validate(default forwarder=%q) = %v, want nil", tc.forwarder, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("Validate(default forwarder=%q) = nil, want rejection", tc.forwarder)
		}
	}

	// Zone-level forwarders are validated too, with the zone index in the
	// message.
	cfg := AppConfig{
		Dns64Enable:  true,
		Dns64Default: "8.8.8.8:53",
		Dns64Zones: []ZoneConfig{
			{Domains: []string{".ygg"}, Forwarder: "no-port-here"},
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Dns64Zones[0].forwarder") {
		t.Errorf("Validate() = %v, want Dns64Zones[0].forwarder format error", err)
	}
}

func TestAppConfigValidate_TCPTimeout(t *testing.T) {
	tests := []struct {
		name           string
		val            int
		expectErr      bool
		expectedErrSub string
		expectedVal    int
	}{
		{
			name:        "Default timeout when unset",
			val:         0,
			expectErr:   false,
			expectedVal: DefaultNat64TcpTimeout,
		},
		{
			name:        "Default timeout when negative",
			val:         -5,
			expectErr:   false,
			expectedVal: DefaultNat64TcpTimeout,
		},
		{
			name:           "Error below RFC 5382 REQ-5 floor",
			val:            DefaultNat64TcpTimeout - 1,
			expectErr:      true,
			expectedErrSub: "must not be less than 7440 seconds",
		},
		{
			name:        "Valid at exactly the floor",
			val:         DefaultNat64TcpTimeout,
			expectErr:   false,
			expectedVal: DefaultNat64TcpTimeout,
		},
		{
			name:        "Valid above the floor",
			val:         DefaultNat64TcpTimeout + 3600,
			expectErr:   false,
			expectedVal: DefaultNat64TcpTimeout + 3600,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nat64Base()
			cfg.Nat64TcpTimeout = tc.val
			err := cfg.Validate()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, but got nil")
				}
				if !strings.Contains(err.Error(), tc.expectedErrSub) {
					t.Errorf("expected error to contain %q, got: %v", tc.expectedErrSub, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg.Nat64TcpTimeout != tc.expectedVal {
					t.Errorf("expected Nat64TcpTimeout to be %d, got %d", tc.expectedVal, cfg.Nat64TcpTimeout)
				}
			}
		})
	}
}

func TestAppConfigValidate_UDPFiltering(t *testing.T) {
	tests := []struct {
		name        string
		val         string
		expectErr   bool
		expectedVal string
	}{
		{
			name:        "Default when unset",
			val:         "",
			expectErr:   false,
			expectedVal: "address-dependent",
		},
		{
			name:        "Address-dependent accepted",
			val:         "address-dependent",
			expectErr:   false,
			expectedVal: "address-dependent",
		},
		{
			name:        "Case-insensitive, normalised",
			val:         "ADDRESS-and-port-DEPENDENT",
			expectErr:   false,
			expectedVal: "address-and-port-dependent",
		},
		{
			name:        "Endpoint-independent accepted (RFC 4787 REQ-8)",
			val:         "ENDPOINT-INDEPENDENT",
			expectErr:   false,
			expectedVal: "endpoint-independent",
		},
		{
			name:      "Garbage rejected",
			val:       "filter-everything",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nat64Base()
			cfg.Nat64UdpFiltering = tc.val
			err := cfg.Validate()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectedVal != "" && cfg.Nat64UdpFiltering != tc.expectedVal {
				t.Errorf("expected Nat64UdpFiltering to be %q, got %q", tc.expectedVal, cfg.Nat64UdpFiltering)
			}
		})
	}
}

// TestGenconfOutputPassesValidation guards against template drift: whatever
// -genconf prints must always pass AppConfig.Validate as-is.
func TestAppConfigValidate_PortParity(t *testing.T) {
	tests := []struct {
		name        string
		val         string
		expectErr   bool
		expectedVal string
	}{
		{
			name:        "Default when unset",
			val:         "",
			expectErr:   false,
			expectedVal: "preserve",
		},
		{
			name:        "preserve accepted",
			val:         "preserve",
			expectErr:   false,
			expectedVal: "preserve",
		},
		{
			name:        "Case-insensitive, normalised",
			val:         "Do-Not-Preserve",
			expectErr:   false,
			expectedVal: "do-not-preserve",
		},
		{
			name:        "DO-NOT-PRESERVE accepted",
			val:         "DO-NOT-PRESERVE",
			expectErr:   false,
			expectedVal: "do-not-preserve",
		},
		{
			name:      "Garbage rejected",
			val:       "random-ports",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nat64Base()
			cfg.Nat64PortParity = tc.val
			err := cfg.Validate()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectedVal != "" && cfg.Nat64PortParity != tc.expectedVal {
				t.Errorf("expected Nat64PortParity to be %q, got %q", tc.expectedVal, cfg.Nat64PortParity)
			}
		})
	}
}

// TestGenconfOutputPassesValidation guards against template drift: whatever
// -genconf prints must always pass AppConfig.Validate as-is.
func TestAppConfigValidate_AAAAExcludedSubnets(t *testing.T) {
	tests := []struct {
		name      string
		vals      []string
		expectErr bool
	}{
		{name: "nil list is fine", vals: nil},
		{name: "IPv6 CIDR accepted", vals: []string{"200::/7"}},
		{name: "WKP accepted", vals: []string{"64:ff9b::/96"}},
		{name: "bare IPv6 accepted as /128", vals: []string{"2606:4700::1111"}},
		{name: "mixed entries accepted", vals: []string{"200::/7", "64:ff9b::/96"}},
		{name: "IPv4 CIDR rejected (cannot match AAAA)", vals: []string{"10.0.0.0/8"}, expectErr: true},
		{name: "garbage rejected", vals: []string{"not-a-subnet"}, expectErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := nat64Base()
			cfg.Dns64AAAAExcludedSubnets = tc.vals
			err := cfg.Validate()
			if tc.expectErr && err == nil {
				t.Errorf("expected error for %v, got nil", tc.vals)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for %v: %v", tc.vals, err)
			}
		})
	}
}

func TestGenconfOutputPassesValidation(t *testing.T) {
	out, err := Generate(GenerateOverrides{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var appCfg AppConfig
	if err := hjson.Unmarshal([]byte(out), &appCfg); err != nil {
		t.Fatalf("Unmarshal(generated config): %v", err)
	}
	if err := appCfg.Validate(); err != nil {
		t.Fatalf("generated config failed validation: %v\nconfig:\n%s", err, out)
	}
	if !bytes.Contains([]byte(out), []byte("/96")) {
		t.Error("generated Nat64Pool is not a /96")
	}
}
