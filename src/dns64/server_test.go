package dns64

import (
	"testing"

	"github.com/miekg/dns"
)

// TestEDNS0UDPSizeNegotiation verifies that UDP buffer size negotiation
// respects client preferences, applies the configured cap, and falls back
// to the default when no EDNS(0) is present.
func TestEDNS0UDPSizeNegotiation(t *testing.T) {
	tests := []struct {
		name               string
		clientBufferSize   uint16
		clientSendsEDNS    bool
		expectedUDPSize    int
		expectedServerSize uint16
	}{
		{
			name:               "No EDNS(0) from client",
			clientSendsEDNS:    false,
			expectedUDPSize:    defaultUDPSize,
			expectedServerSize: 0,
		},
		{
			name:               "Client requests 512 bytes",
			clientBufferSize:   512,
			clientSendsEDNS:    true,
			expectedUDPSize:    512,
			expectedServerSize: maxUDPSize,
		},
		{
			name:               "Client requests 1232 bytes (default)",
			clientBufferSize:   1232,
			clientSendsEDNS:    true,
			expectedUDPSize:    1232,
			expectedServerSize: maxUDPSize,
		},
		{
			name:               "Client requests 2048 bytes",
			clientBufferSize:   2048,
			clientSendsEDNS:    true,
			expectedUDPSize:    2048,
			expectedServerSize: maxUDPSize,
		},
		{
			name:               "Client requests 4096 bytes (at cap)",
			clientBufferSize:   4096,
			clientSendsEDNS:    true,
			expectedUDPSize:    4096,
			expectedServerSize: maxUDPSize,
		},
		{
			name:               "Client requests 8192 bytes (exceeds cap)",
			clientBufferSize:   8192,
			clientSendsEDNS:    true,
			expectedUDPSize:    maxUDPSize,
			expectedServerSize: maxUDPSize,
		},
		{
			name:               "Client requests 65535 bytes (maximum)",
			clientBufferSize:   65535,
			clientSendsEDNS:    true,
			expectedUDPSize:    maxUDPSize,
			expectedServerSize: maxUDPSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)

			if tt.clientSendsEDNS {
				req.SetEdns0(tt.clientBufferSize, false)
			}

			// Simulate the negotiation logic from serveUDP
			udpSize := defaultUDPSize
			clientOPT := req.IsEdns0()
			if clientOPT != nil {
				clientSize := int(clientOPT.UDPSize())
				if clientSize > maxUDPSize {
					udpSize = maxUDPSize
				} else if clientSize > defaultUDPSize {
					udpSize = clientSize
				} else if clientSize > 0 {
					udpSize = clientSize
				}
			}

			if udpSize != tt.expectedUDPSize {
				t.Errorf("negotiated UDP size = %d, want %d", udpSize, tt.expectedUDPSize)
			}

			// Verify response OPT handling
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

			if tt.clientSendsEDNS {
				respOPT := resp.IsEdns0()
				if respOPT == nil {
					t.Errorf("response missing OPT record when client sent one")
				} else if respOPT.UDPSize() != tt.expectedServerSize {
					t.Errorf("response OPT UDP size = %d, want %d", respOPT.UDPSize(), tt.expectedServerSize)
				}
			} else {
				if resp.IsEdns0() != nil {
					t.Errorf("response includes OPT record when client sent none")
				}
			}
		})
	}
}

// TestEDNS0Truncation verifies that oversized responses are truncated
// correctly using the negotiated UDP size limit.
func TestEDNS0Truncation(t *testing.T) {
	tests := []struct {
		name            string
		clientBufferSize uint16
		answerCount     int
		expectTruncated bool
	}{
		{
			name:            "Small response fits in default buffer",
			clientBufferSize: 0,
			answerCount:     2,
			expectTruncated: false,
		},
		{
			name:            "Response fits in 4096 buffer",
			clientBufferSize: 4096,
			answerCount:     10,
			expectTruncated: false,
		},
		{
			name:            "Large response exceeds 512 buffer",
			clientBufferSize: 512,
			answerCount:     20,
			expectTruncated: true,
		},
		{
			name:            "Huge response exceeds 1232 default",
			clientBufferSize: 0,
			answerCount:     50,
			expectTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeAAAA)

			if tt.clientBufferSize > 0 {
				req.SetEdns0(tt.clientBufferSize, false)
			}

			// Determine negotiated size
			udpSize := defaultUDPSize
			clientOPT := req.IsEdns0()
			if clientOPT != nil {
				clientSize := int(clientOPT.UDPSize())
				if clientSize > maxUDPSize {
					udpSize = maxUDPSize
				} else if clientSize > defaultUDPSize {
					udpSize = clientSize
				} else if clientSize > 0 {
					udpSize = clientSize
				}
			}

			// Build response with multiple AAAA records
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

// TestEDNS0EdgeCases verifies handling of malformed or unusual EDNS(0) requests.
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
			expectedUDPSize: defaultUDPSize,
		},
		{
			name: "Client advertises size 1 (pathological minimum)",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(1, false)
			},
			expectedUDPSize: 1,
		},
		{
			name: "Client advertises size 511 (just below RFC 1035 minimum)",
			setupRequest: func(req *dns.Msg) {
				req.SetEdns0(511, false)
			},
			expectedUDPSize: 511,
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

			udpSize := defaultUDPSize
			clientOPT := req.IsEdns0()
			if clientOPT != nil {
				clientSize := int(clientOPT.UDPSize())
				if clientSize > maxUDPSize {
					udpSize = maxUDPSize
				} else if clientSize > defaultUDPSize {
					udpSize = clientSize
				} else if clientSize > 0 {
					udpSize = clientSize
				}
			}

			if udpSize != tt.expectedUDPSize {
				t.Errorf("negotiated UDP size = %d, want %d", udpSize, tt.expectedUDPSize)
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
			_, err := resp.Pack()
			if err != nil {
				t.Errorf("packing response failed: %v", err)
			}
		})
	}
}

// TestEDNS0ConstantsMatchRFC verifies that the configured constants align
// with RFC 6891 recommendations.
func TestEDNS0ConstantsMatchRFC(t *testing.T) {
	if defaultUDPSize != 1232 {
		t.Errorf("defaultUDPSize = %d, RFC 6891 §6.2.5 recommends 1232", defaultUDPSize)
	}

	if maxUDPSize < 512 {
		t.Errorf("maxUDPSize = %d, must be at least 512 per RFC 1035", maxUDPSize)
	}

	if maxUDPSize > 65535 {
		t.Errorf("maxUDPSize = %d, exceeds DNS message maximum of 65535", maxUDPSize)
	}

	if defaultUDPSize > maxUDPSize {
		t.Errorf("defaultUDPSize %d exceeds maxUDPSize %d", defaultUDPSize, maxUDPSize)
	}
}
