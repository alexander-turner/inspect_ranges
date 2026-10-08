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
	Daemon   struct {
		KillGraceMs    int64 `json:"kill_grace_ms"`
		WaitDelayMs    int64 `json:"wait_delay_ms"`
		InboundBulkCap int64 `json:"inbound_bulk_cap"`
	} `json:"daemon"`
	Vectors []struct {
		Name      string          `json:"name"`
		Message   json.RawMessage `json:"message"`
		BulkHex   *string         `json:"bulk_hex"`
		FramesHex []string        `json:"frames_hex"`
	} `json:"vectors"`
	Rejects []struct {
		Name    string `json:"name"`
		Payload string `json:"payload"`
	} `json:"rejects"`
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
		{"negative-max-entries", `{"id":"` + rid + `","kind":"diag","max_entries":-1,"v":3}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseControl([]byte(c.payload)); err == nil {
				t.Fatalf("accepted dishonest payload %s", c.name)
			}
		})
	}
}

// TestSharedRejectTable drives the cross-codec rejection corpus: every
// payload here must be refused by all three codecs, so any parity break
// becomes a missing table entry rather than a silent divergence.
func TestSharedRejectTable(t *testing.T) {
	doc := loadVectors(t)
	if len(doc.Rejects) < 50 {
		t.Fatalf("shared reject table suspiciously small: %d entries", len(doc.Rejects))
	}
	for _, reject := range doc.Rejects {
		t.Run(reject.Name, func(t *testing.T) {
			if _, err := ParseControl([]byte(reject.Payload)); err == nil {
				t.Fatalf("accepted shared-reject payload %s: %s", reject.Name, reject.Payload)
			}
		})
	}
}

func TestVectorCoverage(t *testing.T) {
	doc := loadVectors(t)
	seen := map[string]bool{}
	for _, vector := range doc.Vectors {
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(vector.Message, &probe); err != nil {
			t.Fatalf("vector %s: %v", vector.Name, err)
		}
		seen[probe.Kind] = true
	}
	for kind := range allKinds {
		if !seen[kind] {
			t.Errorf("no vector covers kind %q", kind)
		}
	}
	for kind := range seen {
		if !allKinds[kind] {
			t.Errorf("vector kind %q is not in the protocol", kind)
		}
	}
	if len(doc.Vectors) < len(allKinds) {
		t.Fatalf("only %d vectors for %d kinds", len(doc.Vectors), len(allKinds))
	}
}

func TestDaemonConstantsPinnedByVectors(t *testing.T) {
	// the host observation grace derives from these; drift here silently
	// breaks exec deadline verdicts
	doc := loadVectors(t)
	if doc.Daemon.KillGraceMs != KillGrace.Milliseconds() {
		t.Fatalf("KillGrace %dms != pinned %dms", KillGrace.Milliseconds(), doc.Daemon.KillGraceMs)
	}
	if doc.Daemon.WaitDelayMs != WaitDelay.Milliseconds() {
		t.Fatalf("WaitDelay %dms != pinned %dms", WaitDelay.Milliseconds(), doc.Daemon.WaitDelayMs)
	}
	if doc.Daemon.InboundBulkCap != ReceiveBulkCap {
		t.Fatalf("inbound bulk cap %d != pinned %d", ReceiveBulkCap, doc.Daemon.InboundBulkCap)
	}
}

func TestPerKindFieldTable(t *testing.T) {
	rid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rejects := []struct {
		name    string
		payload string
	}{
		{"ping-with-cmd", `{"cmd":["x"],"id":"` + rid + `","kind":"ping","v":3}`},
		{"ok-with-errno", `{"errno":"ENOENT","id":"` + rid + `","kind":"ok","v":3}`},
		{"pending-missing-elapsed", `{"id":"` + rid + `","kind":"pending","target_id":"` + rid + `","v":3}`},
		{"error-missing-message", `{"errno":"ENOENT","id":"` + rid + `","kind":"error","v":3}`},
		{"stage-missing-stage", `{"id":"` + rid + `","kind":"stage","v":3}`},
		{"heartbeat-with-path", `{"id":"` + rid + `","kind":"heartbeat","path":"/x","uptime_ms":1,"v":3}`},
	}
	for _, c := range rejects {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseControl([]byte(c.payload)); err == nil {
				t.Fatalf("accepted cross-kind payload %s", c.name)
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
