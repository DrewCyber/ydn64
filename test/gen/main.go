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
	dns64Exclude := flag.String("dns64-exclude", "", `comma-separated IPv6 subnets for Dns64AAAAExcludedSubnets (RFC 6147 5.1.4, role=ydn64 only)`)
	dns64Static := flag.String("dns64-static", "", `comma-separated name=ip pairs for Dns64Static local authoritative answers (role=ydn64 only)`)
	dns64EmptyZone := flag.Bool("dns64-empty-zone", false, `add a blocked zone for domains "empty.test": no prefix/pass-through → NXDOMAIN for every type without upstream contact (role=ydn64 only)`)
	nat64Enable := flag.Bool("nat64-enable", true, "Nat64Enable (role=ydn64 only)")
	udpFiltering := flag.String("udp-filtering", "address-dependent", `Nat64UdpFiltering: "address-dependent", "address-and-port-dependent" or "endpoint-independent" (role=ydn64 only)`)
	dns64Enable := flag.Bool("dns64-enable", true, "Dns64Enable (role=ydn64 only)")
	yggZone := flag.Bool("ygg-zone", true, "include the .ygg Dns64Zones entry (role=ydn64 only)")
	ifmtu := flag.Int("ifmtu", 1500, "IfMTU for the generated node config(s)")
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

	// A realistic (1500-byte) path MTU instead of yggdrasil's 65535 default.
	// For the client this is load-bearing: its TUN interface actually
	// segments/fragments at this size, so datagrams larger than ~1472 bytes
	// exercise real IPv6 fragmentation + reassembly on the Yggdrasil leg
	// (see test/cases/08_udp_fragmented_datagrams.sh). The ydn64 node never
	// builds a TUN, but setting it here keeps both configs symmetric and
	// documents the harness's assumed path MTU in one place.
	if *ifmtu < 1280 {
		fmt.Fprintf(os.Stderr, "error: -ifmtu must be >= 1280 (IPv6 minimum MTU), got %d\n", *ifmtu)
		os.Exit(1)
	}
	ygCfg.IfMTU = uint64(*ifmtu)

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
		// Explicitly empty: production defaults would ignore RFC1918 and
		// loopback embedded-IPv4 destinations, but the deterministic UDP
		// fragmentation case (test/cases/08_udp_fragmented_datagrams.sh)
		// targets a loopback-bound echo server inside container A through
		// NAT64. Test cases that need private-destination filtering assert
		// it themselves (see 05_allowed_sources_config_change.sh for the
		// source-filter analogue).
		merged["IgnoredDstSubnets"] = []interface{}{}
		merged["Nat64Enable"] = *nat64Enable
		merged["Nat64Pool"] = pool6CIDR
		merged["Nat64UdpTimeout"] = 300
		if strings.TrimSpace(*udpFiltering) != "" {
			merged["Nat64UdpFiltering"] = strings.TrimSpace(*udpFiltering)
		}
		merged["Dns64Enable"] = *dns64Enable
		merged["Dns64Listen"] = dns64Listen
		merged["Dns64Default"] = *dns64Default
		merged["Dns64CacheExpiration"] = 300
		merged["Dns64CachePurge"] = 600
		merged["Dns64InvalidAddress"] = *dns64Invalid
		if exclude := strings.Split(strings.TrimSpace(*dns64Exclude), ","); len(exclude) > 0 && exclude[0] != "" {
			merged["Dns64AAAAExcludedSubnets"] = exclude
		}
		// Default (catch-all) zone: synthesise AAAA records from real A
		// records using the NAT64 prefix, forwarding to Dns64Default (a
		// real public resolver, 8.8.8.8:53 by default) — matches the
		// checked-in top-level ydn64.conf's default zone. There is no local
		// fake target anymore: every test case that needs a name to resolve
		// uses a real-world one (e.g. dns.google) and goes through real
		// internet/Yggdrasil egress from A.
		zones := []map[string]interface{}{
			{
				"domains":               []string{"."},
				"return-ipv4-addresses": false,
				"prefix":                pool6Prefix,
			},
		}
		if *yggZone {
			// Real-world escape hatch used by
			// test/cases/03_ygg_zone_resolution.sh: forwards .ygg queries to
			// a real Alfis DNS server over the actual Yggdrasil network (see
			// -peers), so that case can validate zone forwarding and
			// return-ipv6-addresses against a genuine 200::/7 answer.
			zones = append(zones, map[string]interface{}{
				"domains":               []string{".ygg"},
				"forwarder":             "[308:84:68:55::]:53",
				"return-ipv6-addresses": true,
			})
		}
		if *dns64EmptyZone {
			// Blocked zone for test/cases/17_dns64_static_empty_zones.sh:
			// no prefix and no pass-through flags → local NXDOMAIN for every
			// query type without contacting any forwarder.
			zones = append(zones, map[string]interface{}{
				"domains": []string{"empty.test"},
			})
		}
		merged["Dns64Zones"] = zones

		if strings.TrimSpace(*dns64Static) != "" {
			static := map[string]interface{}{}
			for _, pair := range splitCSV(*dns64Static) {
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" || strings.TrimSpace(kv[1]) == "" {
					fmt.Fprintf(os.Stderr, "error: bad -dns64-static pair %q (want name=ip)\n", pair)
					os.Exit(1)
				}
				static[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
			merged["Dns64Static"] = static
		}

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
