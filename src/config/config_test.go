package config

import (
	"strings"
	"testing"
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
