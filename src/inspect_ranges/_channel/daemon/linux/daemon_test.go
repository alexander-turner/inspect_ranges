// Behavioral pins for the daemon core, including the at-most-once tombstone
// (an evicted-unacked result must never allow a double run).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func execMessage(id string, argv ...string) *Message {
	return &Message{V: ProtocolVersion, ID: id, Kind: "exec", Cmd: argv}
}

func rid(n int) string { return fmt.Sprintf("%032x", n) }

// TestAcquireFinishHammer pins the TOCTOU fix: under racing acquires for
// the same id, exactly one caller wins the fresh run and every other caller
// gets the stored reply (or the tombstone truth), never a second run.
func TestAcquireFinishHammer(t *testing.T) {
	store := NewStore()
	for round := 0; round < 2000; round++ {
		id := rid(round)
		const workers = 8
		var fresh atomic.Int64
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stored, tombstoned, run, isNew := store.Acquire(id)
				if tombstoned {
					t.Errorf("round %d: unexpected tombstone", round)
					return
				}
				if isNew {
					fresh.Add(1)
					store.Finish(id, okReply(id))
					return
				}
				if stored != nil {
					return
				}
				<-run.done
				if _, ok := store.Get(id); !ok && !store.Tombstoned(id) {
					t.Errorf("round %d: finished without stored result or tombstone", round)
				}
			}()
		}
		wg.Wait()
		if fresh.Load() != 1 {
			t.Fatalf("round %d: %d fresh acquisitions, want exactly 1", round, fresh.Load())
		}
		store.Ack(id)
	}
}

// TestHugeBudgetDoesNotWrap pins the deadline clamp: a 13e12 ms budget
// overflows time.Duration nanoseconds if converted naively, firing the
// budget timer immediately and failing a healthy command with ETIME.
func TestHugeBudgetDoesNotWrap(t *testing.T) {
	daemon := NewDaemon()
	message := execMessage(rid(9077), "true")
	huge := int64(13_000_000_000_000)
	message.Budget = &Budget{UntimedBoundMs: &huge}
	reply := daemon.dispatch(message, nil)
	if reply.message.Kind != "exec_result" {
		t.Fatalf("huge budget: got %s (%s)", reply.message.Kind, reply.message.Message)
	}
}

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
