package netstack

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
)

// pcapGlobalHeaderLen is the size of the libpcap file header.
const pcapGlobalHeaderLen = 24

// dltRaw is the LINKTYPE_ value for "raw IP" capture files: packets carry no
// link-layer header, they start directly at the IPv4/IPv6 header.
const dltRaw = 101

// pcapWriter appends packets to a libpcap-format capture file. Everything is
// written little-endian (file magic 0xD4C3B2A1 on disk), which every pcap
// reader understands. No third-party dependencies — the format is a fixed
// 24-byte header plus per-packet 16-byte record headers.
type pcapWriter struct {
	mu sync.Mutex
	f  *os.File
}

// openPcap creates path and writes the libpcap global header.
func openPcap(path string) (*pcapWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, pcapGlobalHeaderLen)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4) // magic (LE on disk)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], dltRaw)   // network = LINKTYPE_RAW
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapWriter{f: f}, nil
}

// writePacket appends one packet record with the given timestamp.
func (w *pcapWriter) writePacket(ts time.Time, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	rec := make([]byte, 16, 16+len(data))
	sec := ts.Unix()
	usec := ts.Nanosecond() / 1000
	binary.LittleEndian.PutUint32(rec[0:4], uint32(sec))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(usec))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(data)))  // incl_len
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(data))) // orig_len
	rec = append(rec, data...)

	_, err := w.f.Write(rec)
	return err
}

func (w *pcapWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
