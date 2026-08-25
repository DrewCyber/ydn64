package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gologme/log"

	"github.com/DrewCyber/ydn64/src/config"
)

// TestReloadConfigWarnsOnRestartRequiredCapacitySettings pins the
// code-review-2026-08-24 #7 fix: both concurrency ceilings are sem-sized at
// service construction, so a SIGHUP reload cannot apply them — but unlike
// before, an operator editing them must now see a warning instead of
// silence. With both services nil the reload reduces to exactly the
// warning-and-ignore behaviour under test.
func TestReloadConfigWarnsOnRestartRequiredCapacitySettings(t *testing.T) {
	// Repo-local scratch space per AGENTS.md (never the system temp dir).
	dir := filepath.Join("..", "..", "tmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	confPath := filepath.Join(dir, "ydn64-reload-test.conf")
	conf := `{
		Nat64Enable: true
		Nat64Pool: "300:1:2:3::/96"
		Nat64MaxTCPConnections: 1024
		Dns64MaxConcurrentQueries: 512
	}`
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	defer os.Remove(confPath)

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.EnableLevel("warn") // gologme suppresses warn by default

	runningNat64 := config.NAT64Config{Enable: true, Pool6: "300:1:2:3::/96", MaxTCPClients: 2048}
	runningDNS64 := config.DNS64Config{MaxQueries: 256}

	reloadConfig(confPath, logger, nil, runningNat64, nil, runningDNS64)

	out := buf.String()
	for _, want := range []string{
		"Nat64MaxTCPConnections change (2048",
		"Dns64MaxConcurrentQueries change (256",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reload output missing %q warning; got:\n%s", want, out)
		}
	}

	// The unchanged settings must stay silent — only real changes warn.
	if strings.Contains(out, "(1024") && strings.Contains(out, "Nat64MaxTCPConnections") {
		t.Errorf("Nat64MaxTCPConnections warned despite matching value:\n%s", out)
	}
}
