package dns64

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNS64ErrorRcodeHandling(t *testing.T) {
	// 1. Start a mock DNS server on a random port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)

			switch name {
			case "nxdomain.example.com.":
				resp.SetRcode(req, dns.RcodeNameError)
			case "servfail.example.com.":
				resp.SetRcode(req, dns.RcodeServerFailure)
			case "empty.example.com.":
				resp.SetRcode(req, dns.RcodeSuccess)
			case "synth.example.com.":
				resp.SetRcode(req, dns.RcodeSuccess)
				if q.Qtype == dns.TypeA {
					rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A 1.2.3.4", q.Name))
					if rr != nil {
						resp.Answer = append(resp.Answer, rr)
					}
				}
			default:
				resp.SetRcode(req, dns.RcodeNameError)
			}
			w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	defer dnsServer.Shutdown()

	// Wait briefly for the server to be active
	time.Sleep(50 * time.Millisecond)

	// 2. Set up our proxy instance.
	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second),
	}

	prefix := net.ParseIP("64:ff9b::")
	if prefix == nil {
		t.Fatal("failed to parse prefix")
	}

	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	})

	// 3. Test Cases.
	tests := []struct {
		name         string
		expectedR    int
		expectedAns  int
		expectSynth  bool
		synthAddress string
	}{
		{
			name:        "nxdomain.example.com.",
			expectedR:   dns.RcodeNameError,
			expectedAns: 0,
		},
		{
			name:        "servfail.example.com.",
			expectedR:   dns.RcodeServerFailure,
			expectedAns: 0,
		},
		{
			name:        "empty.example.com.",
			expectedR:   dns.RcodeSuccess,
			expectedAns: 0,
		},
		{
			name:         "synth.example.com.",
			expectedR:    dns.RcodeSuccess,
			expectedAns:  1,
			expectSynth:  true,
			synthAddress: "64:ff9b::102:304", // 1.2.3.4 embedded in 64:ff9b::
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.name, dns.TypeAAAA)
			resp := p.handle(req)

			if resp.Rcode != tc.expectedR {
				t.Errorf("expected Rcode %d (%s), got %d (%s)",
					tc.expectedR, dns.RcodeToString[tc.expectedR],
					resp.Rcode, dns.RcodeToString[resp.Rcode],
				)
			}

			if len(resp.Answer) != tc.expectedAns {
				t.Errorf("expected %d answers, got %d", tc.expectedAns, len(resp.Answer))
			}

			if tc.expectSynth {
				if len(resp.Answer) > 0 {
					aaaa, ok := resp.Answer[0].(*dns.AAAA)
					if !ok {
						t.Errorf("expected AAAA record, got %T", resp.Answer[0])
					} else {
						gotIP := aaaa.AAAA.String()
						expectedIP := net.ParseIP(tc.synthAddress).String()
						if gotIP != expectedIP {
							t.Errorf("expected synthesised IP %s, got %s", expectedIP, gotIP)
						}
					}
				}
			}
		})
	}
}
