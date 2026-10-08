// Behavioral pins for the daemon core, including the at-most-once tombstone
// (an evicted-unacked result must never allow a double run).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func execMessage(id string, argv ...string) *Message {
	return &Message{V: ProtocolVersion, ID: id, Kind: "exec", Cmd: argv}
}

func rid(n int) string { return fmt.Sprintf("%032x", n) }

func TestTombstoneForbidsDoubleRun(t *testing.T) {
	daemon := NewDaemon()
	marker := filepath.Join(t.TempDir(), "marker")

	first := daemon.dispatch(execMessage(rid(1), "sh", "-c", "echo ran >> "+marker), nil)
	if first.message.Kind != "exec_result" {
		t.Fatalf("first run: got %s", first.message.Kind)
	}

	// evict the unacked result from the bounded FIFO
	for i := 0; i < StoredBound+8; i++ {
		daemon.store.Put(rid(1000+i), okReply(rid(1000+i)))
	}

	// a poll for the evicted id answers ESTALE, not ENOENT
	poll := daemon.poll(&Message{V: ProtocolVersion, ID: rid(2), Kind: "poll", TargetID: rid(1)})
	if poll.message.Kind != "error" || poll.message.Errno != "ESTALE" {
		t.Fatalf("poll after eviction: got %s/%s", poll.message.Kind, poll.message.Errno)
	}

	// a resend of the same id answers ESTALE and must NOT run the command again
	resent := daemon.dispatch(execMessage(rid(1), "sh", "-c", "echo ran >> "+marker), nil)
	if resent.message.Kind != "error" || resent.message.Errno != "ESTALE" {
		t.Fatalf("resend after eviction: got %s/%s", resent.message.Kind, resent.message.Errno)
	}
	content, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	if string(content) != "ran\n" {
		t.Fatalf("command ran %d times", len(content)/4)
	}
}

func TestAckedResultsAreNotTombstoned(t *testing.T) {
	daemon := NewDaemon()
	result := daemon.dispatch(execMessage(rid(3), "true"), nil)
	if result.message.Kind != "exec_result" {
		t.Fatalf("got %s", result.message.Kind)
	}
	daemon.store.Ack(rid(3))
	for i := 0; i < StoredBound+8; i++ {
		daemon.store.Put(rid(2000+i), okReply(rid(2000+i)))
	}
	if daemon.store.Tombstoned(rid(3)) {
		t.Fatal("an acked id must not tombstone")
	}
	poll := daemon.poll(&Message{V: ProtocolVersion, ID: rid(4), Kind: "poll", TargetID: rid(3)})
	if poll.message.Errno != "ENOENT" {
		t.Fatalf("acked id should poll ENOENT, got %s", poll.message.Errno)
	}
}

func TestReadFileBoundedForHugeSources(t *testing.T) {
	daemon := NewDaemon()
	limit := int64(4096)
	reply := daemon.readFile(&Message{
		V: ProtocolVersion, ID: rid(5), Kind: "read_file",
		Path: "/dev/zero", MaxBytes: &limit,
	})
	if reply.message.Kind != "file_data" {
		t.Fatalf("got %s: %s", reply.message.Kind, reply.message.Message)
	}
	if *reply.message.Size != limit || !*reply.message.Truncated {
		t.Fatalf("expected truncated read at %d, got size=%d truncated=%v",
			limit, *reply.message.Size, *reply.message.Truncated)
	}
}
