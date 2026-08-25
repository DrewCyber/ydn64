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

// TestSetLogLevelWarnsOnUnknownLevel pins the code-review-2026-08-24 #12 fix:
// an unrecognised -loglevel value is announced instead of silently meaning
// info. Printf passes gologme's level gating, so the warning is always
// visible regardless of the level being configured.
func TestSetLogLevelWarnsOnUnknownLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	setLogLevel("verbose", logger)
	if !strings.Contains(buf.String(), `unknown -loglevel "verbose"`) {
		t.Errorf("missing unknown-level warning; got:\n%s", buf.String())
	}

	buf.Reset()
	setLogLevel("debug", logger) // known values stay silent
	if buf.Len() != 0 {
		t.Errorf("known level produced output:\n%s", buf.String())
	}
}

// TestReloadConfigWarnsWhenAllowedSourcesEmptied pins the code-review-
// 2026-08-24 #16 fix: the loud deny-all warning the startup path emits must
// repeat on SIGHUP when a reload applies an emptied AllowedSources list.
func TestReloadConfigWarnsWhenAllowedSourcesEmptied(t *testing.T) {
	dir := filepath.Join("..", "..", "tmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	confPath := filepath.Join(dir, "ydn64-reload-empty-sources.conf")
	conf := "{ Nat64Enable: false }"
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	defer os.Remove(confPath)

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.EnableLevel("warn")

	reloadConfig(confPath, logger, nil,
		config.NAT64Config{Enable: false}, nil, config.DNS64Config{})

	out := buf.String()
	if !strings.Contains(out, "AllowedSources is EMPTY after reload") {
		t.Errorf("reload applied an emptied AllowedSources silently; got:\n%s", out)
	}
}
