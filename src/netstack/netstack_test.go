package netstack

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gologme/log"

	ygconfig "github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// newTestCore builds an offline Yggdrasil core (random identity, no peers,
// no listeners) so CreateYdn64Netstack can be exercised without a network.
func newTestCore(t *testing.T) *core.Core {
	t.Helper()
	cfg := ygconfig.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate: %v", err)
	}
	c, err := core.New(cfg.Certificate, log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	t.Cleanup(func() { c.Stop() })
	return c
}

func TestCreateYdn64NetstackUsesCubic(t *testing.T) {
	ygg := newTestCore(t)

	ns, err := CreateYdn64Netstack(ygg, 1500, "")
	if err != nil {
		t.Fatalf("CreateYdn64Netstack: %v", err)
	}

	var cc tcpip.CongestionControlOption
	if gerr := ns.Stack().TransportProtocolOption(tcp.ProtocolNumber, &cc); gerr != nil {
		t.Fatalf("GetTransportProtocolOption(CongestionControlOption): %v", gerr)
	}
	if cc != "cubic" {
		t.Errorf("congestion control = %q, want cubic (T6)", string(cc))
	}

	var avail tcpip.TCPAvailableCongestionControlOption
	if gerr := ns.Stack().TransportProtocolOption(tcp.ProtocolNumber, &avail); gerr != nil {
		t.Fatalf("GetTransportProtocolOption(TCPAvailableCongestionControlOption): %v", gerr)
	}
	found := map[string]bool{}
	for _, part := range strings.Split(string(avail), " ") {
		found[part] = true
	}
	if !found["cubic"] || !found["reno"] {
		t.Errorf("available algorithms = %q, want both cubic and reno", string(avail))
	}
}
