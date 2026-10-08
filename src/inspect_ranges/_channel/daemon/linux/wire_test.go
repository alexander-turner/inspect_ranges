// The cross-codec drift guard: this Go codec must encode every shared wire
// vector to the exact frame bytes the Python codec pins, and decode those
// bytes back to the same message and bulk. Run via `go test ./...` (wrapped
// by tests/test_go_daemon.py so the Python suite drives it when the pinned
// toolchain is present).
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorDoc struct {
	Protocol int `json:"protocol"`
	Vectors  []struct {
		Name      string          `json:"name"`
		Message   json.RawMessage `json:"message"`
		BulkHex   *string         `json:"bulk_hex"`
		FramesHex []string        `json:"frames_hex"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) *vectorDoc {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "..", "tests", "wire_vectors", "v3.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var doc vectorDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("vectors parse: %v", err)
	}
	if doc.Protocol != ProtocolVersion {
		t.Fatalf("vector protocol %d != %d", doc.Protocol, ProtocolVersion)
	}
	return &doc
}

func TestVectorsRoundTrip(t *testing.T) {
	doc := loadVectors(t)
	for _, vector := range doc.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			wire := []byte{}
			for _, frame := range vector.FramesHex {
				raw, err := hex.DecodeString(frame)
				if err != nil {
					t.Fatalf("frame hex: %v", err)
				}
				wire = append(wire, raw...)
			}
			var bulk []byte
			if vector.BulkHex != nil {
				raw, err := hex.DecodeString(*vector.BulkHex)
				if err != nil {
					t.Fatalf("bulk hex: %v", err)
				}
				bulk = raw
			}

			// decode: pinned bytes -> message + bulk
			reader := NewFrameReader(bytes.NewReader(wire))
			message, decodedBulk, err := ReadMessage(reader, DefaultBulkCap*2)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(decodedBulk, bulk) {
				t.Fatalf("bulk mismatch: got %d bytes, want %d", len(decodedBulk), len(bulk))
			}

			// encode: decoded message -> the exact pinned bytes
			encoded, err := EncodeMessage(message, decodedBulk)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(encoded, wire) {
				t.Fatalf("vector %s: encode drifted from pinned bytes\n got: %x\nwant: %x",
					vector.Name, encoded, wire)
			}
		})
	}
}

func TestDecodeHardening(t *testing.T) {
	rid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name    string
		payload string
	}{
		{"missing-v", `{"id":"` + rid + `","kind":"ping"}`},
		{"wrong-v", `{"v":2,"id":"` + rid + `","kind":"ping"}`},
		{"explicit-null", `{"v":3,"id":"` + rid + `","kind":"exec","cmd":["true"],"cwd":null}`},
		{"duplicate-key", `{"v":3,"id":"` + rid + `","kind":"ping","kind":"ping"}`},
		{"unknown-kind", `{"v":3,"id":"` + rid + `","kind":"evil"}`},
		{"unknown-field", `{"v":3,"id":"` + rid + `","kind":"ping","x":1}`},
		{"bad-id", `{"v":3,"id":"ZZ","kind":"ping"}`},
		{"bulk-on-bulkless", `{"v":3,"data_size":4,"id":"` + rid + `","kind":"ok"}`},
		{"etime-without-layer", `{"v":3,"errno":"ETIME","id":"` + rid + `","kind":"error","message":"x"}`},
		{"empty-cmd", `{"v":3,"cmd":[],"id":"` + rid + `","kind":"exec"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseControl([]byte(c.payload)); err == nil {
				t.Fatalf("accepted dishonest payload %s", c.name)
			}
		})
	}
}

func TestFrameReaderCaps(t *testing.T) {
	// length field lying beyond the cap must refuse before buffering
	header := []byte{0x01, 0x00, 0x00, 0x00, FrameControl}
	reader := NewFrameReader(bytes.NewReader(header))
	if _, _, err := reader.Read(); err == nil {
		t.Fatal("accepted an over-cap length field")
	}
}
