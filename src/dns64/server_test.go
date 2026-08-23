package dns64

import (
	"testing"

	"github.com/miekg/dns"
)

// TestEDNS0UDPSizeNegotiation exercises negotiateUDPSize — the same function
// serveUDP uses — across the RFC 6891 §6.2.5 rules: 512 for classic queries,
// a 512 floor on sub-512 advertisements, and clamping at maxUDPSize.
func TestEDNS0UDPSizeNegotiation(t *testing.T) {
	tests := []struct {
		name             string
		clientBufferSize uint16
		clientSendsEDNS  bool
		expectedUDPSize  int
	}{
		{
			name:            "No EDNS(0) from client",
			clientSendsEDNS: false,
			expectedUDPSize: legacyMaxMsgSize,
		},
		{
			name:             "Client requests 512 bytes",
			clientBufferSize: 512,
			clientSendsEDNS:  true,
			expectedUDPSize:  512,
		},
		{
			name:             "Client requests 100 bytes (below the MUST-treat-as-512 floor)",
			clientBufferSize: 100,
			clientSendsEDNS:  true,
			expectedUDPSize:  legacyMaxMsgSize,
		},
		{
			name:             "Client requests 1232 bytes",
			clientBufferSize: 1232,
			clientSendsEDNS:  true,
			expectedUDPSize:  1232,
		},
		{
			name:             "Client requests 2048 bytes",
			clientBufferSize: 2048,
			clientSendsEDNS:  true,
			expectedUDPSize:  2048,
		},
		{
			name:             "Client requests 4096 bytes (at cap)",
			clientBufferSize: 4096,
			clientSendsEDNS:  true,
			expectedUDPSize:  maxUDPSize,
		},
		{
			name:             "Client requests 8192 bytes (exceeds cap)",
			clientBufferSize: 8192,
			clientSendsEDNS:  true,
			expectedUDPSize:  maxUDPSize,
		},
		{
			name:             "Client requests 65535 bytes (maximum)",
			clientBufferSize: 65535,
			clientSendsEDNS:  true,
			expectedUDPSize:  maxUDPSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)
			if tt.clientSendsEDNS {
				req.SetEdns0(tt.clientBufferSize, false)
			}

			if got := negotiateUDPSize(req.IsEdns0()); got != tt.expectedUDPSize {
				t.Errorf("negotiateUDPSize() = %d, want %d", got, tt.expectedUDPSize)
			}
		})
	}
}

// TestEDNS0Truncation verifies that oversized responses are truncated
// using the negotiated UDP size limit, mirroring serveUDP's sequence:
// negotiate via negotiateUDPSize, attach the server OPT when the client
// sent one, truncate when over the limit.
func TestEDNS0Truncation(t *testing.T) {
	tests := []struct {
		name             string
		clientBufferSize uint16
		clientSendsEDNS  bool
		answerCount      int
		expectTruncated  bool
	}{
		{
			name:            "Small response fits in legacy 512 buffer",
			clientSendsEDNS: false,
			answerCount:     2,
			expectTruncated: false,
		},
		{
			name:             "Response fits in 4096 buffer",
			clientBufferSize: 4096,
			clientSendsEDNS:  true,
			answerCount:      10,
			expectTruncated:  false,
		},
		{
			name:             "Large response exceeds 512 buffer",
			clientBufferSize: 512,
			clientSendsEDNS:  true,
			answerCount:      20,
			expectTruncated:  true,
		},
		{
			name:            "Huge response exceeds legacy 512 default",
			clientSendsEDNS: false,
			answerCount:     50,
			expectTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)
			if tt.clientSendsEDNS {
				req.SetEdns0(tt.clientBufferSize, false)
			}
			clientOPT := req.IsEdns0()
			udpSize := negotiateUDPSize(clientOPT)

			resp := new(dns.Msg)
			resp.SetReply(req)
			for i := 0; i < tt.answerCount; i++ {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)},
				})
			}

			if clientOPT != nil && resp.IsEdns0() == nil {
				resp.SetEdns0(maxUDPSize, false)
			}

			origLen := resp.Len()
			origAnswerCount := len(resp.Answer)

			if resp.Len() > udpSize {
				resp.Truncate(udpSize)
			}

			if tt.expectTruncated {
				if !resp.Truncated {
					t.Errorf("TC bit not set, expected truncation (original size %d > limit %d)", origLen, udpSize)
				}
				if resp.Len() > udpSize {
					t.Errorf("truncated response size %d still exceeds limit %d", resp.Len(), udpSize)
				}
				if len(resp.Answer) >= origAnswerCount {
					t.Errorf("truncation did not remove any answers (still %d)", len(resp.Answer))
				}
			} else {
				if resp.Truncated {
					t.Errorf("TC bit set unexpectedly (size %d fits in limit %d)", origLen, udpSize)
				}
				if len(resp.Answer) != origAnswerCount {
					t.Errorf("answer count changed from %d to %d without truncation", origAnswerCount, len(resp.Answer))
				}
			}
		})
	}
}

// TestEDNS0TruncationPreservesQuestion verifies that truncation always
// keeps the question section intact, per RFC 6891 §7.
func TestEDNS0TruncationPreservesQuestion(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("toolong.example.com.", dns.TypeAAAA)
	req.SetEdns0(512, false)

	resp := new(dns.Msg)
	resp.SetReply(req)

	// Add many AAAA records to force truncation
	for i := 0; i < 100; i++ {
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "toolong.example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)},
		})
	}

	resp.SetEdns0(maxUDPSize, false)
	resp.Truncate(512)

	if !resp.Truncated {
		t.Errorf("TC bit not set after truncation")
	}

	if len(resp.Question) != 1 {
		t.Errorf("question section not preserved: expected 1 question, got %d", len(resp.Question))
	}

	if resp.Question[0].Name != "toolong.example.com." {
		t.Errorf("question name mangled: got %s, want toolong.example.com.", resp.Question[0].Name)
	}

	if resp.Len() > 512 {
		t.Errorf("truncated response size %d exceeds 512 byte limit", resp.Len())
	}
}

// TestEDNS0EdgeCases exercises negotiateUDPSize on malformed or unusual
// EDNS(0) advertisements through the real function.
func TestEDNS0EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		setupRequest    func(*dns.Msg)
		expectedUDPSize int
	}{
		{
			name: "Client advertises size 0",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(0, false)
			},
			expectedUDPSize: legacyMaxMsgSize,
		},
		{
			name: "Client advertises size 1 (pathological minimum)",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(1, false)
			},
			// RFC 6891 §6.2.5: values lower than 512 MUST be treated as 512.
			expectedUDPSize: legacyMaxMsgSize,
		},
		{
			name: "Client advertises size 511 (just below the floor)",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(511, false)
			},
			expectedUDPSize: legacyMaxMsgSize,
		},
		{
			name: "Client sets DO bit (DNSSEC OK)",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(4096, true)
			},
			expectedUDPSize: 4096,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)
			tt.setupRequest(req)

			clientOPT := req.IsEdns0()
			udpSize := negotiateUDPSize(clientOPT)

			if udpSize != tt.expectedUDPSize {
				t.Errorf("negotiateUDPSize() = %d, want %d", udpSize, tt.expectedUDPSize)
			}

			// Verify response construction doesn't break with edge cases
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			})

			if clientOPT != nil && resp.IsEdns0() == nil {
				resp.SetEdns0(maxUDPSize, false)
			}

			if resp.Len() > udpSize {
				resp.Truncate(udpSize)
			}

			// Verify response can be packed without error
			if _, err := resp.Pack(); err != nil {
				t.Errorf("packing response failed: %v", err)
			}
		})
	}
}

// TestEDNS0ConstantsMatchRFC verifies that the configured constants align
// with RFC 1035 / RFC 6891 requirements.
func TestEDNS0ConstantsMatchRFC(t *testing.T) {
	if legacyMaxMsgSize != 512 {
		t.Errorf("legacyMaxMsgSize = %d, want 512 (RFC 6891 §6.2.2/§6.2.5 floor)", legacyMaxMsgSize)
	}

	if maxUDPSize < 512 {
		t.Errorf("maxUDPSize = %d, must be at least 512 per RFC 1035", maxUDPSize)
	}

	if maxUDPSize > 65535 {
		t.Errorf("maxUDPSize = %d, exceeds DNS message maximum of 65535", maxUDPSize)
	}
}
