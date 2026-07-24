package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/gologme/log"
	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	ygconfig "github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/DrewCyber/ydn64/src/dns64"
	"github.com/DrewCyber/ydn64/src/nat64"
	"github.com/DrewCyber/ydn64/src/netstack"
)

var buildVersion = "dev"

type node struct {
	core      *core.Core
	multicast *multicast.Multicast
	admin     *admin.AdminSocket
}

// splitEnvList splits a comma and/or whitespace separated environment
// variable value (e.g. "tls://a:1, tls://b:2") into a trimmed, non-empty
// slice of entries.
func splitEnvList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func setLogLevel(loglevel string, logger *log.Logger) {
	levels := [...]string{"error", "warn", "info", "debug", "trace"}
	idx := 2 // default: info
	for k, v := range levels {
		if v == loglevel {
			idx = k
			break
		}
	}
	for k, v := range levels {
		if k <= idx {
			logger.EnableLevel(v)
		}
	}
}

func main() {
	genconf := flag.Bool("genconf", false, "print a new config to stdout")
	useconffile := flag.String("useconffile", "", "path to ydn64.conf config file")
	ver := flag.Bool("version", false, "print version and exit")
	logto := flag.String("logto", "stdout", `log destination: "stdout", "syslog", or a file path`)
	loglevel := flag.String("loglevel", "info", `log level: "error", "warn", "info", "debug", "trace"`)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *ver {
		fmt.Println("ydn64", buildVersion)
		return
	}

	if *genconf {
		// If all three environment variables are set, bake them into the
		// generated config so a container can boot with a fully
		// pre-configured identity/peers/allowlist without any manual
		// editing afterwards. Any subset left unset falls back to the
		// usual random key / empty peers / placeholder AllowedSources.
		overrides := config.GenerateOverrides{
			PrivateKeyHex:  os.Getenv("YDN64_PRIVATE_KEY"),
			Peers:          splitEnvList(os.Getenv("YDN64_PEERS")),
			AllowedSources: splitEnvList(os.Getenv("YDN64_ALLOWED_SOURCES")),
		}
		content, err := config.Generate(overrides)
		if err != nil {
			fmt.Fprintln(os.Stderr, "genconf error:", err)
			os.Exit(1)
		}
		fmt.Print(content)
		return
	}

	if *useconffile == "" {
		fmt.Fprintln(os.Stderr, "error: -useconffile is required (use -genconf to create a config)")
		flag.Usage()
		os.Exit(1)
	}

	// ── Logger setup ─────────────────────────────────────────────────────────

	var logger *log.Logger
	switch *logto {
	case "stdout":
		logger = log.New(os.Stdout, "", log.Flags())
	case "syslog":
		if sl, err := gsyslog.NewLogger(gsyslog.LOG_NOTICE, "DAEMON", "ydn64"); err == nil {
			logger = log.New(sl, "", log.Flags()&^(log.Ldate|log.Ltime))
		}
	default:
		if fd, err := os.OpenFile(*logto, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			logger = log.New(fd, "", log.Flags())
		}
	}
	if logger == nil {
		logger = log.New(os.Stdout, "", log.Flags())
		logger.Warnln("logging destination unavailable, falling back to stdout")
	}
	setLogLevel(*loglevel, logger)

	// ── Load ydn64.conf ────────────────────────────────────────────────────────

	ygCfg, appCfg, err := config.Load(*useconffile)
	if err != nil {
		logger.Fatalf("failed to load ydn64 config: %v", err)
	}

	// Force TUN-less mode and disable admin socket.
	ygCfg.AdminListen = "none"
	ygCfg.IfName = "none"

	// ── Environment variable overrides (container-friendly) ──────────────────
	// Lets a Docker/Podman container built from a single generated config
	// still be pointed at real peers and locked down to the operator's own
	// Yggdrasil address without baking either into the image or hand-editing
	// the mounted config file. YDN64_PRIVATE_KEY additionally lets the whole
	// node identity (and everything derived from it: Nat64Pool, Dns64Listen,
	// Dns64Zones) be supplied entirely via environment variables, so a
	// container can run without any config file/volume at all.
	if pk := os.Getenv("YDN64_PRIVATE_KEY"); pk != "" {
		privKey, err := config.ParsePrivateKeyHex(pk)
		if err != nil {
			logger.Fatalf("YDN64_PRIVATE_KEY override invalid: %v", err)
		}
		ygCfg.PrivateKey = ygconfig.KeyBytes(privKey)
		if err := ygCfg.GenerateSelfSignedCertificate(); err != nil {
			logger.Fatalf("YDN64_PRIVATE_KEY override: failed to regenerate certificate: %v", err)
		}
		nodeIP, pool6CIDR, pool6Prefix := config.DeriveFromPrivateKey(privKey)
		appCfg.ApplyPrivateKeyOverride(nodeIP, pool6CIDR, pool6Prefix)
		if err := appCfg.Validate(); err != nil {
			logger.Fatalf("config invalid after YDN64_PRIVATE_KEY override: %v", err)
		}
		logger.Infof("YDN64_PRIVATE_KEY override: node address %s, Nat64Pool %s", nodeIP, appCfg.Nat64Pool)
	}
	if peers := os.Getenv("YDN64_PEERS"); peers != "" {
		ygCfg.Peers = splitEnvList(peers)
		logger.Infof("YDN64_PEERS override: %d peer(s)", len(ygCfg.Peers))
	}
	if allowed := os.Getenv("YDN64_ALLOWED_SOURCES"); allowed != "" {
		appCfg.AllowedSources = splitEnvList(allowed)
		if err := appCfg.Validate(); err != nil {
			logger.Fatalf("YDN64_ALLOWED_SOURCES override invalid: %v", err)
		}
		logger.Infof("YDN64_ALLOWED_SOURCES override: %d entr(y/ies)", len(appCfg.AllowedSources))
	}

	// ── Start yggdrasil core ─────────────────────────────────────────────────

	n := &node{}

	{
		opts := []core.SetupOption{
			core.NodeInfo(ygCfg.NodeInfo),
			core.NodeInfoPrivacy(ygCfg.NodeInfoPrivacy),
		}
		for _, addr := range ygCfg.Listen {
			opts = append(opts, core.ListenAddress(addr))
		}
		for _, peer := range ygCfg.Peers {
			opts = append(opts, core.Peer{URI: peer})
		}
		for intf, peers := range ygCfg.InterfacePeers {
			for _, peer := range peers {
				opts = append(opts, core.Peer{URI: peer, SourceInterface: intf})
			}
		}
		for _, keyHex := range ygCfg.AllowedPublicKeys {
			k, err := hex.DecodeString(keyHex)
			if err != nil {
				logger.Fatalf("invalid AllowedPublicKey %q: %v", keyHex, err)
			}
			opts = append(opts, core.AllowedPublicKey(k))
		}
		if n.core, err = core.New(ygCfg.Certificate, logger, opts...); err != nil {
			logger.Fatalf("failed to start yggdrasil core: %v", err)
		}
	}

	logger.Printf("public key   : %s", hex.EncodeToString(n.core.PublicKey()))
	logger.Printf("node address : %s", n.core.Address())
	snet := n.core.Subnet()
	logger.Printf("node subnet  : %s", snet.String())

	// ── Admin socket (AdminListen = "none" → no-op listener) ─────────────────

	{
		opts := []admin.SetupOption{
			admin.ListenAddress(ygCfg.AdminListen),
		}
		if ygCfg.LogLookups {
			opts = append(opts, admin.LogLookups{})
		}
		if n.admin, err = admin.New(n.core, logger, opts...); err != nil {
			logger.Fatalf("failed to start admin socket: %v", err)
		}
		if n.admin != nil {
			n.admin.SetupAdminHandlers()
		}
	}

	// ── Multicast peer discovery ──────────────────────────────────────────────

	{
		opts := []multicast.SetupOption{}
		for _, intf := range ygCfg.MulticastInterfaces {
			opts = append(opts, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		if n.multicast, err = multicast.New(n.core, logger, opts...); err != nil {
			logger.Fatalf("failed to start multicast: %v", err)
		}
		if n.admin != nil && n.multicast != nil {
			n.multicast.SetupAdminHandlers(n.admin)
		}
	}

	// ── gVisor netstack ───────────────────────────────────────────────────────

	nat64Cfg := appCfg.NAT64()
	dns64Cfg := appCfg.DNS64()

	pool6CIDR := ""
	if nat64Cfg.Enable {
		pool6CIDR = nat64Cfg.Pool6
	}

	ns, err := netstack.CreateYdn64Netstack(n.core, pool6CIDR)
	if err != nil {
		logger.Fatalf("failed to create netstack: %v", err)
	}

	// ── NAT64 service ─────────────────────────────────────────────────────────

	if nat64Cfg.Enable {
		svc, err := nat64.NewService(nat64Cfg, appCfg.AllowedSources, ns)
		if err != nil {
			logger.Fatalf("failed to create NAT64 service: %v", err)
		}
		svc.Start(ctx, logger)
	}

	// ── DNS64 service ─────────────────────────────────────────────────────────

	if dns64Cfg.Enable {
		svc, err := dns64.NewService(dns64Cfg, appCfg.AllowedSources, ns)
		if err != nil {
			logger.Fatalf("failed to create DNS64 service: %v", err)
		}
		if err := svc.Start(ctx, logger); err != nil {
			logger.Fatalf("failed to start DNS64 service: %v", err)
		}
	}

	logger.Println("ydn64 running — press Ctrl+C or send SIGTERM to stop")
	<-ctx.Done()
	logger.Println("shutting down…")

	// Ordered shutdown: services → multicast → admin → core.
	// DNS64 and NAT64 stop via context cancellation already in flight.
	if n.multicast != nil {
		if err := n.multicast.Stop(); err != nil {
			logger.Warnf("multicast stop: %v", err)
		}
	}
	if n.admin != nil {
		if err := n.admin.Stop(); err != nil {
			logger.Warnf("admin stop: %v", err)
		}
	}
	n.core.Stop()
	logger.Println("stopped")
}
