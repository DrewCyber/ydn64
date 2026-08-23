package netstack

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

func TestPcapWriterFileFormat(t *testing.T) {
	path := t.TempDir() + "/test.pcap"
	w, err := openPcap(path)
	if err != nil {
		t.Fatalf("openPcap: %v", err)
	}

	payload := []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40} // fake IPv6 prefix
	ts := time.Unix(1700000000, 500_000_000)
	if err := w.writePacket(ts, payload); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	if err := w.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	// Global header.
	if len(raw) < pcapGlobalHeaderLen {
		t.Fatalf("file too short for global header: %d bytes", len(raw))
	}
	if magic := binary.LittleEndian.Uint32(raw[0:4]); magic != 0xA1B2C3D4 {
		t.Errorf("magic = %#x, want %#x (little-endian)", magic, 0xA1B2C3D4)
	}
	if vmaj := binary.LittleEndian.Uint16(raw[4:6]); vmaj != 2 {
		t.Errorf("version major = %d, want 2", vmaj)
	}
	if vmin := binary.LittleEndian.Uint16(raw[6:8]); vmin != 4 {
		t.Errorf("version minor = %d, want 4", vmin)
	}
	if link := binary.LittleEndian.Uint32(raw[20:24]); link != dltRaw {
		t.Errorf("linktype = %d, want %d (DLT_RAW)", link, dltRaw)
	}

	// Packet record header + data.
	rec := raw[pcapGlobalHeaderLen:]
	if len(rec) != 16+len(payload) {
		t.Fatalf("record size = %d, want %d", len(rec), 16+len(payload))
	}
	if sec := binary.LittleEndian.Uint32(rec[0:4]); sec != uint32(1700000000) {
		t.Errorf("ts_sec = %d, want 1700000000", sec)
	}
	if usec := binary.LittleEndian.Uint32(rec[4:8]); usec != 500_000 {
		t.Errorf("ts_usec = %d, want 500000", usec)
	}
	if incl := binary.LittleEndian.Uint32(rec[8:12]); incl != uint32(len(payload)) {
		t.Errorf("incl_len = %d, want %d", incl, len(payload))
	}
	if orig := binary.LittleEndian.Uint32(rec[12:16]); orig != uint32(len(payload)) {
		t.Errorf("orig_len = %d, want %d", orig, len(payload))
	}
	for i, b := range payload {
		if rec[16+i] != b {
			t.Errorf("payload byte %d = %#x, want %#x", i, rec[16+i], b)
		}
	}
}

func TestPcapWriterMultiplePackets(t *testing.T) {
	path := t.TempDir() + "/multi.pcap"
	w, err := openPcap(path)
	if err != nil {
		t.Fatalf("openPcap: %v", err)
	}
	n := 3
	for i := 0; i < n; i++ {
		if err := w.writePacket(time.Now(), []byte{byte(i)}); err != nil {
			t.Fatalf("writePacket %d: %v", i, err)
		}
	}
	if err := w.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, _ := os.ReadFile(path)
	want := pcapGlobalHeaderLen + n*(16+1)
	if len(raw) != want {
		t.Errorf("file size = %d, want %d", len(raw), want)
	}
}
