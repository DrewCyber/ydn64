package nat64

import (
	"encoding/binary"
	"sync/atomic"
)

// IPv6 extension-header chain handling for the NIC-intercepted ICMPv6 path
// (RFC 8200 §4). The interceptor used to assume a fixed Next Header offset
// (pkt[6] == 58), which silently dropped every Echo Request arriving behind
// a Fragment, Hop-by-Hop, Routing or Destination Options header.

const (
	chainICMPv6  chainStatus = iota // chain terminates in an ICMPv6 header
	chainOther                      // chain terminates in another protocol (TCP/UDP/...) — pass through
	chainInvalid                    // truncated/malformed chain or nested fragment headers — drop
)

type chainStatus int

// ipv6ChainInfo locates the upper-layer header inside an IPv6 packet and,
// when a Fragment header is present, its datagram-reassembly parameters
// (RFC 8200 §4.5: offset in 8-byte units of the fragmentable part, M flag).
type ipv6ChainInfo struct {
	l4Offset   int    // offset of the final (upper-layer) header
	fragOffset uint16 // fragment offset in 8-byte units; 0 when isFrag=false
	fragIdent  uint32 // fragment identification from the Fragment header
	fragMore   bool   // more-fragments flag
	isFrag     bool
}

// parseIPv6HeaderChain walks an IPv6 packet's Next Header chain and reports
// where it terminates. Only the extension headers that can legally precede
// an upper-layer header are walked (Hop-by-Hop 0, Routing 43, Destination
// Options 60, Fragment 44); anything else ends the walk as chainOther.
func parseIPv6HeaderChain(pkt []byte) (ipv6ChainInfo, chainStatus) {
	var info ipv6ChainInfo
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return info, chainInvalid
	}
	nh := pkt[6]
	off := 40
	sawFrag := false
	for {
		switch nh {
		case 0, 60, 43: // Hop-by-Hop Options / Destination Options / Routing
			if off+2 > len(pkt) {
				return info, chainInvalid
			}
			extLen := (int(pkt[off+1]) + 1) * 8
			if extLen < 8 || off+extLen > len(pkt) {
				return info, chainInvalid
			}
			nh = pkt[off]
			off += extLen
		case 44: // Fragment
			if sawFrag || off+8 > len(pkt) {
				return info, chainInvalid // nested Fragment headers are illegal
			}
			sawFrag = true
			info.isFrag = true
			// Fragment word (RFC 8200 §4.5): offset in 8-octet units in the
			// top 13 bits, two reserved bits, M flag at bit 0.
			word := binary.BigEndian.Uint16(pkt[off+2 : off+4])
			info.fragOffset = word >> 3
			info.fragMore = word&0x0001 != 0
			info.fragIdent = binary.BigEndian.Uint32(pkt[off+4 : off+8])
			nh = pkt[off]
			off += 8
		default:
			info.l4Offset = off
			if nh == 58 {
				return info, chainICMPv6
			}
			return info, chainOther
		}
	}
}

// replyFragIdent generates identification values for outbound fragmented
// replies. A process-lifetime counter suffices: replies to distinct clients
// collide only across identical 16-bit wraps, and reassembly ambiguity is
// additionally scoped per (src,dst) pair.
var replyFragIdent atomic.Uint32

func init() { replyFragIdent.Store(1) }

// fragmentIPv6Packet splits an IPv6 packet into fragments no larger than
// mtu bytes, per RFC 8200 §4.5. Packets already within the MTU are returned
// unchanged as a single-element slice. The fragmentable part (everything
// after the fixed header — here always one ICMPv6 message) is cut on 8-byte
// boundaries; each output carries its own Fragment header and a freshly
// computed payload length. Checksums are unaffected: the pseudo-header
// checksum covers only the upper-layer data, which every fragment carries a
// piece of verbatim.
func fragmentIPv6Packet(pkt []byte, mtu int, ident uint32) [][]byte {
	if len(pkt) <= 40 || len(pkt) <= mtu {
		return [][]byte{pkt}
	}
	const fragHdrLen = 8
	perFrag := ((mtu - 40 - fragHdrLen) / 8) * 8 // 8-byte-aligned fragment capacity
	if perFrag <= 0 {
		return nil // absurd MTU (< 56); caller treats nil as "not sent"
	}

	body := pkt[40:]
	var out [][]byte
	for sent := 0; sent < len(body); {
		end := sent + perFrag
		if end > len(body) {
			end = len(body)
		}
		more := end < len(body)
		offsetUnits := uint16(sent / 8)

		p := make([]byte, 40+fragHdrLen+end-sent)
		copy(p[:40], pkt[:40])
		p[4], p[5] = 0, 0
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		p[6] = 44 // Next Header = Fragment
		p[40] = 58
		// Fragment word (RFC 8200 §4.5): offset in 8-octet units in the top
		// 13 bits, two reserved bits, M flag at bit 0 — packed as one word
		// so the offset can never clobber the flag bits.
		word := uint16(offsetUnits) << 3
		if more {
			word |= 1
		}
		binary.BigEndian.PutUint16(p[42:44], word)
		binary.BigEndian.PutUint32(p[44:48], ident)
		copy(p[48:], body[sent:end])

		out = append(out, p)
		sent = end
	}
	return out
}
