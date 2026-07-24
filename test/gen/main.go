// Command gen is a black-box test helper. It is NOT part of the ydn64
// binary — it only runs on the host (via `go run ./test/gen`) to produce
// ready-to-use merged ydn64.conf / yggdrasil.conf files for the podman-based
// test harness under test/, reusing the real upstream config structs
// (ygconfig.NodeConfig) instead of sed/text-patching hand-written HJSON.
//
// It prints the derived node address, subnet, DNS64 listen address and
// NAT64 pool prefix as KEY=VALUE lines to -envout so the shell harness can
// pick them up without re-deriving anything itself.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	ygconfig "github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// existingPrivateKey reads the "PrivateKey" field out of a previously
// generated config at path, if any. This lets repeated -out regenerations
// to the same file (e.g. a test case restarting a container with one
// tweaked setting) preserve node identity/address instead of picking a new
// random key every time.
func existingPrivateKey(path string) ygconfig.KeyBytes {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var existing struct {
		PrivateKey ygconfig.KeyBytes
	}
	if err := json.Unmarshal(data, &existing); err != nil {
		return nil
	}
	return existing.PrivateKey
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	role := flag.String("role", "", `"ydn64" or "client"`)
	peers := flag.String("peers", "", "comma-separated outbound Peers URIs")
	listen := flag.String("listen", "", "comma-separated Listen URIs")
	allowedSources := flag.String("allowed-sources", "200::/7", "comma-separated AllowedSources CIDRs/IPs (role=ydn64 only)")
	dns64Default := flag.String("dns64-default", "8.8.8.8:53", "Dns64Default forwarder host:port (role=ydn64 only)")
	dns64Invalid := flag.String("dns64-invalid", "ignore", "Dns64InvalidAddress (role=ydn64 only)")
	nat64Enable := flag.Bool("nat64-enable", true, "Nat64Enable (role=ydn64 only)")
	dns64Enable := flag.Bool("dns64-enable", true, "Dns64Enable (role=ydn64 only)")
	yggZone := flag.Bool("ygg-zone", true, "include the .ygg Dns64Zones entry (role=ydn64 only)")
	out := flag.String("out", "", "output config file path (required)")
	envout := flag.String("envout", "", "output KEY=VALUE env file path (required)")
	flag.Parse()

	if *role != "ydn64" && *role != "client" {
		fmt.Fprintln(os.Stderr, "error: -role must be \"ydn64\" or \"client\"")
		os.Exit(1)
	}
	if *out == "" || *envout == "" {
		fmt.Fprintln(os.Stderr, "error: -out and -envout are required")
		os.Exit(1)
	}

	ygCfg := ygconfig.GenerateConfig()
	if key := existingPrivateKey(*out); key != nil {
		ygCfg.PrivateKey = key
	}
	ygCfg.Peers = splitCSV(*peers)
	ygCfg.Listen = splitCSV(*listen)
	// Disable multicast discovery: the test harness uses static peering only,
	// so behaviour is deterministic regardless of container network multicast
	// support.
	ygCfg.MulticastInterfaces = nil

	if *role == "ydn64" {
		// ydn64 always forces these regardless of what's in the file (see
		// cmd/ydn64/main.go); set explicitly here too for clarity.
		ygCfg.AdminListen = "none"
		ygCfg.IfName = "none"
	}

	privKey := ed25519.PrivateKey(ygCfg.PrivateKey)
	pubKey := privKey.Public().(ed25519.PublicKey)
	nodeAddr := net.IP(address.AddrForKey(pubKey)[:])
	subnetBytes := address.SubnetForKey(pubKey)
	subnetIP := make(net.IP, net.IPv6len)
	copy(subnetIP, subnetBytes[:])

	merged := map[string]interface{}{}
	nodeJSON, err := json.Marshal(ygCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal NodeConfig:", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(nodeJSON, &merged); err != nil {
		fmt.Fprintln(os.Stderr, "unmarshal NodeConfig:", err)
		os.Exit(1)
	}

	envLines := []string{
		fmt.Sprintf("NODE_ADDR=%s", nodeAddr.String()),
		fmt.Sprintf("NODE_SUBNET=%s/64", subnetIP.String()),
	}

	if *role == "ydn64" {
		pool6IP := make(net.IP, net.IPv6len)
		copy(pool6IP, subnetBytes[:])
		pool6Prefix := pool6IP.String()
		pool6CIDR := fmt.Sprintf("%s/96", pool6Prefix)
		dns64Listen := fmt.Sprintf("[%s]:53", nodeAddr.String())

		merged["AllowedSources"] = splitCSV(*allowedSources)
		merged["Nat64Enable"] = *nat64Enable
		merged["Nat64Pool"] = pool6CIDR
		merged["Nat64UdpTimeout"] = 30
		merged["Dns64Enable"] = *dns64Enable
		merged["Dns64Listen"] = dns64Listen
		merged["Dns64Default"] = *dns64Default
		merged["Dns64CacheExpiration"] = 300
		merged["Dns64CachePurge"] = 600
		merged["Dns64InvalidAddress"] = *dns64Invalid
		zones := []map[string]interface{}{
			// Real-world escape hatch used only by
			// test/cases/05_real_world_icmp.sh: dns.google is forwarded to
			// Google's real public resolver instead of the hermetic fake
			// target, so that case can validate NAT64/DNS64 against an
			// actual internet host. Every other test queries only
			// target.test, which still resolves entirely through the
			// catch-all zone below via the offline fake target container.
			{
				"domains":   []string{"dns.google"},
				"forwarder": "8.8.8.8:53",
				"prefix":    pool6Prefix,
			},
			{
				"domains":               []string{"."},
				"return-ipv4-addresses": false,
				"prefix":                pool6Prefix,
			},
		}
		if *yggZone {
			// Real-world escape hatch used only by
			// test/cases/06_ygg_zone_resolution.sh: forwards .ygg queries to
			// a real Alfis DNS server over the actual Yggdrasil network (see
			// -peers), so that case can validate zone forwarding and
			// return-ipv6-addresses against a genuine 200::/7 answer.
			zones = append(zones, map[string]interface{}{
				"domains":               []string{".ygg"},
				"forwarder":             "[308:84:68:55::]:53",
				"return-ipv6-addresses": true,
			})
		}
		merged["Dns64Zones"] = zones

		envLines = append(envLines,
			fmt.Sprintf("DNS64_LISTEN=%s", dns64Listen),
			fmt.Sprintf("DNS64_LISTEN_ADDR=%s", nodeAddr.String()),
			fmt.Sprintf("NAT64_POOL_PREFIX=%s", pool6Prefix),
			fmt.Sprintf("NAT64_POOL_CIDR=%s", pool6CIDR),
		)
	}

	outBytes, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal merged config:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, outBytes, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write config:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*envout, []byte(strings.Join(envLines, "\n")+"\n"), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write envout:", err)
		os.Exit(1)
	}
}
