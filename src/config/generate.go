package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	ygconfig "github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// ParsePrivateKeyHex decodes and validates a hex-encoded ed25519 private
// key, as used by the PrivateKey config field and the YDN64_PRIVATE_KEY
// environment variable override.
func ParsePrivateKeyHex(s string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// DeriveFromPrivateKey derives the node's Yggdrasil address and its NAT64
// /96 pool prefix from a raw ed25519 private key. It is used both by
// -genconf (with a freshly generated key) and at runtime when PrivateKey is
// overridden via YDN64_PRIVATE_KEY, so Nat64Pool/Dns64Listen/Dns64Zones can
// be kept consistent with whatever key is actually in effect.
func DeriveFromPrivateKey(privKey ed25519.PrivateKey) (nodeIP string, pool6CIDR string, pool6Prefix string) {
	pubKey := privKey.Public().(ed25519.PublicKey)

	nodeAddr := address.AddrForKey(pubKey) // *address.Address = *[16]byte
	nodeIP = net.IP(nodeAddr[:]).String()

	// address.Subnet is [8]byte — the /64 prefix bytes for this node's subnet.
	subnet := address.SubnetForKey(pubKey) // *address.Subnet = *[8]byte

	// Build the /96 pool6 prefix: 8 subnet bytes + 8 zero bytes → /96 subnet.
	pool6IP := make(net.IP, net.IPv6len) // 16 zero bytes
	copy(pool6IP, subnet[:])             // first 8 bytes from subnet prefix
	pool6CIDR = fmt.Sprintf("%s/96", pool6IP.String())
	pool6Prefix = pool6IP.String() // e.g. "301:363a:9499:c858::"

	return nodeIP, pool6CIDR, pool6Prefix
}

// GenerateOverrides holds optional values, normally sourced from the
// YDN64_PRIVATE_KEY / YDN64_PEERS / YDN64_ALLOWED_SOURCES environment
// variables, to bake into a freshly generated config instead of the usual
// random key / empty peers / placeholder AllowedSources entry. This lets a
// container started with all three variables set produce a fully
// pre-configured config file via `-genconf` with no further editing.
type GenerateOverrides struct {
	PrivateKeyHex  string   // hex-encoded ed25519 private key; empty = generate a new random key
	Peers          []string // empty = no peers (Peers: [])
	AllowedSources []string // empty = placeholder example entry
}

// Generate returns a freshly generated, single merged ydn64.conf HJSON
// document (pre-derived pool6 address) as a string, ready to be printed to
// stdout. Any non-empty field in overrides replaces the corresponding
// default/random value.
func Generate(overrides GenerateOverrides) (string, error) {
	var privKey ed25519.PrivateKey
	if overrides.PrivateKeyHex != "" {
		pk, err := ParsePrivateKeyHex(overrides.PrivateKeyHex)
		if err != nil {
			return "", err
		}
		privKey = pk
	} else {
		// Generate a fresh yggdrasil NodeConfig (includes a new random key pair).
		ygCfg := ygconfig.GenerateConfig()
		privKey = ed25519.PrivateKey(ygCfg.PrivateKey)
	}

	nodeIP, pool6CIDR, pool6Prefix := DeriveFromPrivateKey(privKey)
	privKeyHex := hex.EncodeToString(privKey)

	return buildConf(privKeyHex, nodeIP, pool6CIDR, pool6Prefix, overrides.Peers, overrides.AllowedSources, DefaultIgnoredDstSubnets), nil
}

// formatPeersHJSON renders the Peers list the same way as the hand-written
// sample config (one unquoted URI per line), or "[]" if empty.
func formatPeersHJSON(peers []string) string {
	if len(peers) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for _, p := range peers {
		// Quoted deliberately: peer URIs can contain '#' (comment in HJSON)
		// or '{}' (InterfacePeers syntax) which break unquoted parsing.
		b.WriteString(fmt.Sprintf("    %q\n", p))
	}
	b.WriteString("  ]")
	return b.String()
}

// formatAllowedSourcesHJSON renders the AllowedSources list inline, quoting
// each entry. If empty, it falls back to the previous placeholder example
// so -genconf output without an override still shows users what to edit.
func formatAllowedSourcesHJSON(sources []string) string {
	if len(sources) == 0 {
		return `["200:aaaa:bbbb:cccc:dddd:eeee:ffff:1234/128"]`
	}
	quoted := make([]string, len(sources))
	for i, s := range sources {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func formatIgnoredDstSubnetsHJSON(subnets []string) string {
	if len(subnets) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for _, s := range subnets {
		b.WriteString(fmt.Sprintf("    %q\n", s))
	}
	b.WriteString("  ]")
	return b.String()
}

func buildConf(privKeyHex, nodeIP, pool6CIDR, pool6Prefix string, peers, allowedSources, ignoredDstSubnets []string) string {
	var sb strings.Builder

	sb.WriteString("{\n")
	sb.WriteString("  # ydn64 — TUN-less Yggdrasil node with NAT64 + DNS64\n")
	sb.WriteString("  # Generated by: ydn64 -genconf\n\n")

	sb.WriteString("  # Your private key. DO NOT share this with anyone!\n")
	sb.WriteString(fmt.Sprintf("  PrivateKey: %s\n\n", privKeyHex))

	sb.WriteString("  # List of outbound peer connection strings (e.g. tls://a.b.c.d:e or\n")
	sb.WriteString("  # socks://a.b.c.d:e/f.g.h.i:j). Connection strings can contain options,\n")
	sb.WriteString("  # see https://yggdrasil-network.github.io/configurationref.html#peers.\n")
	sb.WriteString("  # Yggdrasil has no concept of bootstrap nodes - all network traffic\n")
	sb.WriteString("  # will transit peer connections. Therefore make sure to only peer with\n")
	sb.WriteString("  # nearby nodes that have good connectivity and low latency. Avoid adding\n")
	sb.WriteString("  # peers to this list from distant countries as this will worsen your\n")
	sb.WriteString("  # node's connectivity and performance considerably.\n")
	sb.WriteString(fmt.Sprintf("  Peers: %s\n\n", formatPeersHJSON(peers)))

	sb.WriteString("  # List of connection strings for outbound peer connections in URI format,\n")
	sb.WriteString("  # arranged by source interface, e.g. { \"eth0\": [ \"tls://a.b.c.d:e\" ] }.\n")
	sb.WriteString("  # You should only use this option if your machine is multi-homed and you\n")
	sb.WriteString("  # want to establish outbound peer connections on different interfaces.\n")
	sb.WriteString("  # Otherwise you should use \"Peers\".\n")
	sb.WriteString("  InterfacePeers: {}\n\n")

	sb.WriteString("  # Listen addresses for incoming connections. You will need to add\n")
	sb.WriteString("  # listeners in order to accept incoming peerings from non-local nodes.\n")
	sb.WriteString("  # This is not required if you wish to establish outbound peerings only.\n")
	sb.WriteString("  # Multicast peer discovery will work regardless of any listeners set\n")
	sb.WriteString("  # here. Each listener should be specified in URI format as above, e.g.\n")
	sb.WriteString("  # tls://0.0.0.0:0 or tls://[::]:0 to listen on all interfaces.\n")
	sb.WriteString("  Listen: []\n\n")

	sb.WriteString("  # Configuration for which interfaces multicast peer discovery should be\n")
	sb.WriteString("  # enabled on. Regex is a regular expression which is matched against an\n")
	sb.WriteString("  # interface name, and interfaces use the first configuration that they\n")
	sb.WriteString("  # match against. Beacon controls whether or not your node advertises its\n")
	sb.WriteString("  # presence to others, whereas Listen controls whether or not your node\n")
	sb.WriteString("  # listens out for and tries to connect to other advertising nodes. See\n")
	sb.WriteString("  # https://yggdrasil-network.github.io/configurationref.html#multicastinterfaces\n")
	sb.WriteString("  # for more supported options.\n")
	sb.WriteString("  MulticastInterfaces: [\n")
	sb.WriteString("    {\n      Regex: .*\n      Beacon: false\n      Listen: true\n      Password: \"\"\n    }\n")
	sb.WriteString("  ]\n\n")

	sb.WriteString("  # List of peer public keys to allow incoming peering connections\n")
	sb.WriteString("  # from. If left empty/undefined then all connections will be allowed\n")
	sb.WriteString("  # by default. This does not affect outgoing peerings, nor does it\n")
	sb.WriteString("  # affect link-local peers discovered via multicast.\n")
	sb.WriteString("  # WARNING: THIS IS NOT A FIREWALL and DOES NOT limit who can reach\n")
	sb.WriteString("  # open ports or services running on your machine, for that see the\n")
	sb.WriteString("  # GroupPassword option below.\n")
	sb.WriteString("  AllowedPublicKeys: []\n\n")

	sb.WriteString("  # Traffic is only allowed to/from nodes with the same group password.\n")
	sb.WriteString("  # If you want to form a private sub-network or ensure that other public\n")
	sb.WriteString("  # users cannot connect to your machines, choose a strong group password\n")
	sb.WriteString("  # and then configure the same password only with other group members.\n")
	sb.WriteString("  # If left empty or not specified, public connectivity will be permitted.\n")
	sb.WriteString("  # If specified, you WILL NOT be able to reach public services or hosts.\n")
	sb.WriteString("  # This option DOES NOT affect peering connections or traffic routing.\n")
	sb.WriteString("  GroupPassword: \"\"\n\n")

	sb.WriteString("  # By default, nodeinfo contains some defaults including the platform,\n")
	sb.WriteString("  # architecture and Yggdrasil version. These can help when surveying\n")
	sb.WriteString("  # the network and diagnosing network routing problems. Enabling\n")
	sb.WriteString("  # nodeinfo privacy prevents this, so that only items specified in\n")
	sb.WriteString("  # \"NodeInfo\" are sent back if specified.\n")
	sb.WriteString("  NodeInfoPrivacy: false\n\n")

	sb.WriteString("  # Optional nodeinfo. This must be a { \"key\": \"value\", ... } map\n")
	sb.WriteString("  # or set as null. This is entirely optional but, if set, is visible\n")
	sb.WriteString("  # to the whole network on request.\n")
	sb.WriteString("  NodeInfo: {}\n\n")

	sb.WriteString("  # Shared allowed source filter for both NAT64 and DNS64 services.\n")
	sb.WriteString("  # CIDR notation or individual IPv6 addresses. WARNING: never use a\n")
	sb.WriteString("  # broad range like 200::/7 here - that turns this node into an open\n")
	sb.WriteString("  # proxy for the entire public Yggdrasil network. List only your own\n")
	sb.WriteString("  # clients, e.g.: AllowedSources: [\"201:aaaa:bbbb:cccc:dddd:eeee:ffff:1234/128\"]\n")
	sb.WriteString(fmt.Sprintf("  AllowedSources: %s\n\n", formatAllowedSourcesHJSON(allowedSources)))

	sb.WriteString("  # List of IPv4 subnets that will be ignored (not NATed or synthesised).\n")
	sb.WriteString("  # To allow NAT for specific subnets, remove them from this list.\n")
	sb.WriteString(fmt.Sprintf("  IgnoredDstSubnets: %s\n\n", formatIgnoredDstSubnetsHJSON(ignoredDstSubnets)))

	sb.WriteString("  # Enable NAT64 service. If false, the NAT64 service will not be started.\n")
	sb.WriteString("  Nat64Enable: true\n\n")

	sb.WriteString("  # NAT64 prefix to use for synthesising IPv6 addresses from IPv4 addresses.\n")
	sb.WriteString("  # Pre-generated from the private key (a /96). RFC 6052 section 2.2 also\n")
	sb.WriteString("  # allows /32, /40, /48, /56 and /64 if you replace it by hand.\n")
	sb.WriteString(fmt.Sprintf("  Nat64Pool: %q\n\n", pool6CIDR))

	sb.WriteString("  # Idle timeout in seconds before a UDP NAT64 session is expired.\n")
	sb.WriteString("  Nat64UdpTimeout: 300\n\n")

	sb.WriteString("  # Filtering applied to datagrams arriving at a NAT-assigned UDP\n")
	sb.WriteString("  # port (RFC 6146 section 5.2 / RFC 4787 REQ-8). One client source\n")
	sb.WriteString("  # socket shares one NAT port across ALL its destinations\n")
	sb.WriteString("  # (endpoint-independent mapping, RFC 4787 REQ-1), so this governs\n")
	sb.WriteString("  # which inbound IPv4 senders are relayed back to the client:\n")
	sb.WriteString("  #   \"address-dependent\" (default) - any port of an IPv4 address the\n")
	sb.WriteString("  #     client has already sent to is accepted.\n")
	sb.WriteString("  #   \"address-and-port-dependent\" - additionally requires the exact\n")
	sb.WriteString("  #     server port (strictest; the pre-EIM behaviour).\n")
	sb.WriteString("  # Reloadable via SIGHUP.\n")
	sb.WriteString("  Nat64UdpFiltering: \"address-dependent\"\n\n")

	sb.WriteString("  # Idle timeout in seconds before an idle-but-alive proxied TCP\n")
	sb.WriteString("  # connection is expired and both legs are closed (freeing its\n")
	sb.WriteString("  # connection slots). Refreshed by payload traffic in either\n")
	sb.WriteString("  # direction, never by keepalives. Must be >= 7440 (2h04m, the\n")
	sb.WriteString("  # RFC 5382 REQ-5 minimum). Reloadable via SIGHUP.\n")
	sb.WriteString(fmt.Sprintf("  Nat64TcpTimeout: %d\n\n", DefaultNat64TcpTimeout))

	sb.WriteString("  # Maximum number of concurrently proxied NAT64 TCP connections.\n")
	sb.WriteString("  # Excess connections are refused until existing ones close.\n")
	sb.WriteString("  # Applied at startup; changing this value requires a restart.\n")
	sb.WriteString("  Nat64MaxTCPConnections: 1024\n\n")

	sb.WriteString("  # Maximum number of tracked NAT64 UDP sessions; when full, the\n")
	sb.WriteString("  # least-recently-active session is evicted to make room.\n")
	sb.WriteString("  Nat64MaxUDPSessions: 4096\n\n")

	sb.WriteString("  # Per-client anti-abuse ceilings (RFC 6146 section 5.3): how many UDP\n")
	sb.WriteString("  # sessions / proxied TCP connections a single source address may hold.\n")
	sb.WriteString("  # Flows beyond these are shed immediately. Reloadable via SIGHUP.\n")
	sb.WriteString("  Nat64MaxUDPSessionsPerSource: 256\n")
	sb.WriteString("  Nat64MaxTCPConnectionsPerSource: 128\n\n")

	sb.WriteString("  # Enable DNS64 service. If false, the DNS64 service will not be started.\n")
	sb.WriteString("  Dns64Enable: true\n\n")

	sb.WriteString("  # Listen address for DNS64 service. Must be a valid IPv6 address and port.\n")
	sb.WriteString("  # Pre-generated from the private key.\n")
	sb.WriteString(fmt.Sprintf("  Dns64Listen: %q\n\n", "["+nodeIP+"]:53"))

	sb.WriteString("  Dns64Default: \"8.8.8.8:53\"\n")
	sb.WriteString("  Dns64CacheExpiration: 300\n")
	sb.WriteString("  Dns64CachePurge: 600\n\n")

	sb.WriteString("  # Maximum number of DNS cache entries; when full, expired entries are\n")
	sb.WriteString("  # evicted first, otherwise an arbitrary entry is evicted.\n")
	sb.WriteString("  Dns64MaxCacheEntries: 4096\n\n")

	sb.WriteString("  # Maximum number of concurrent DNS64 queries in flight (UDP query\n")
	sb.WriteString("  # goroutines + DNS-over-TCP connections). Excess UDP queries are\n")
	sb.WriteString("  # answered with SERVFAIL immediately and excess TCP connections are\n")
	sb.WriteString("  # closed. Applied at startup; changing it requires a restart.\n")
	sb.WriteString("  Dns64MaxConcurrentQueries: 512\n\n")

	sb.WriteString("  # Per-client DNS64 query rate limit in queries per second (RFC 5358:\n")
	sb.WriteString("  # keep this resolver from being abused as a reflection/amplification\n")
	sb.WriteString("  # engine). Short bursts above the rate are tolerated; sustained\n")
	sb.WriteString("  # excess is refused. Reloadable via SIGHUP.\n")
	sb.WriteString("  Dns64RateLimit: 50\n\n")

	sb.WriteString("  # Dns64InvalidAddress: \"ignore\" | \"process\" | \"discard\"\n")
	sb.WriteString("  # What to do with an \"0.0.0.0\" and [::] addresses\n")
	sb.WriteString("  #   \"ignore\"  - treated like a regular address (i.e. 0.0.0.0 return as [prefix::], [::] - drop)\n")
	sb.WriteString("  #               default behavior.\n")
	sb.WriteString("  #   \"process\" - 0.0.0.0 translate to [::]. [::] return \"as-is\"\n")
	sb.WriteString("  #   \"discard\" - discard this address\n")
	sb.WriteString("  Dns64InvalidAddress: \"ignore\"\n\n")

	sb.WriteString("  Dns64Zones: [\n")
	sb.WriteString("    # Default zone: synthesise AAAA records from A records using the NAT64 prefix.\n")
	sb.WriteString("    # A zone \"prefix\" is a /96 network written out in full (its last\n")
	sb.WriteString("    # four bytes zero); an explicit \"/n\" (e.g. \"2001:db8::/48\") selects\n")
	sb.WriteString("    # one of the other RFC 6052 section 2.2 formats. Forwarders must be\n")
	sb.WriteString("    # \"host:port\" with a numeric port.\n")
	sb.WriteString("    {\n")
	sb.WriteString("      domains: [\".\"]\n")
	sb.WriteString("      return-ipv4-addresses: false\n")
	sb.WriteString(fmt.Sprintf("      prefix: %q\n", pool6Prefix))
	sb.WriteString("    }\n")
	sb.WriteString("    # Yggdrasil-native .ygg zone — forward to Alfis DNS, return its\n")
	sb.WriteString("    # AAAA answers as-is (this zone is explicitly configured to pass through\n")
	sb.WriteString("    # AAAA answers; there's no implicit special-casing of 200::/7).\n")
	sb.WriteString("    # ALFIS servers list: https://dns.r3v.dev/\n")
	sb.WriteString("    {\n")
	sb.WriteString("      domains: [\".ygg\"]\n")
	sb.WriteString("      forwarder: \"[308:84:68:55::]:53\"\n")
	sb.WriteString("      return-ipv6-addresses: true\n")
	sb.WriteString("    }\n")
	sb.WriteString("    # Example: Pass-through zone — return real IPv4 and IPv6 records unchanged.\n")
	sb.WriteString("    # {\n")
	sb.WriteString("    #   domains: [\"example.com\", \"com.tr\"]\n")
	sb.WriteString("    #   return-ipv4-addresses: true\n")
	sb.WriteString("    #   return-ipv6-addresses: true\n")
	sb.WriteString("    # }\n")
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")

	return sb.String()
}
