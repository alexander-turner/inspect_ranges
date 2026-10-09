// Behavioral pins for the daemon core, including the at-most-once tombstone
// (an evicted-unacked result must never allow a double run).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestSessionStableWithinDaemonFreshAcrossRestarts pins the layer-2b
// contract: every pong from one daemon process reports the same well-formed
// session, and a restarted daemon (whose dedupe store is empty) reports a
// different one, so the host can detect the restart.
func TestSessionStableWithinDaemonFreshAcrossRestarts(t *testing.T) {
	ping := func(d *Daemon, id string) string {
		reply := d.dispatch(&Message{V: ProtocolVersion, ID: id, Kind: "ping"}, nil)
		if reply.message.Kind != "pong" {
			t.Fatalf("ping: got %s", reply.message.Kind)
		}
		if !sessionRe.MatchString(reply.message.Session) {
			t.Fatalf("malformed session %q", reply.message.Session)
		}
		return reply.message.Session
	}
	first := NewDaemon()
	if ping(first, rid(6001)) != ping(first, rid(6002)) {
		t.Fatal("session changed between pings of one daemon process")
	}
	restarted := NewDaemon()
	if ping(first, rid(6003)) == ping(restarted, rid(6004)) {
		t.Fatal("a restarted daemon must mint a fresh session")
	}
}

// TestWriteFileHonorsMode pins the atomic-permissions contract: the mode
// travels with the write (umask-proof), so a 0600 secret is never
// world-readable between creation and a separate chmod.
func TestWriteFileHonorsMode(t *testing.T) {
	daemon := NewDaemon()
	path := filepath.Join(t.TempDir(), "secret.sh")
	mode := int64(0o600)
	reply := daemon.dispatch(&Message{
		V: ProtocolVersion, ID: rid(6101), Kind: "write_file",
		Path: path, Mode: &mode, DataSize: i64(4),
	}, []byte("blob"))
	if reply.message.Kind != "ok" {
		t.Fatalf("write: got %s (%s)", reply.message.Kind, reply.message.Message)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", info.Mode().Perm())
	}
}

// TestEtimeCarriesPartialOutput pins the optional slice-4 extension: the
// budget-expiry error reply carries the killed command's output tail as a
// capped TEXT field (never bulk), and the reply still encodes.
func TestEtimeCarriesPartialOutput(t *testing.T) {
	daemon := NewDaemon()
	message := execMessage(rid(6201), "sh", "-c", "echo marker; sleep 30")
	budget := int64(200)
	message.Budget = &Budget{CommandMs: &budget}
	reply := daemon.dispatch(message, nil)
	if reply.message.Kind != "error" || reply.message.Errno != "ETIME" {
		t.Fatalf("got %s/%s", reply.message.Kind, reply.message.Errno)
	}
	if reply.message.Partial == nil || !strings.Contains(*reply.message.Partial, "marker") {
		t.Fatalf("partial should carry the stdout tail, got %v", reply.message.Partial)
	}
	if len(*reply.message.Partial) > PartialCap {
		t.Fatalf("partial exceeds cap: %d", len(*reply.message.Partial))
	}
	if reply.bulk != nil {
		t.Fatal("an error reply must never carry bulk")
	}
	if _, err := EncodeMessage(reply.message, nil); err != nil {
		t.Fatalf("ETIME reply with partial failed to encode: %v", err)
	}
}

// TestMissingCwdIsChdirEnoent pins the pre-check shape: with the runuser
// prefix a missing cwd would otherwise surface as an ambiguous fork/exec
// ENOENT on the runuser binary itself.
func TestMissingCwdIsChdirEnoent(t *testing.T) {
	daemon := NewDaemon()
	message := execMessage(rid(6301), "true")
	gone := filepath.Join(t.TempDir(), "gone")
	message.Cwd = &gone
	reply := daemon.dispatch(message, nil)
	if reply.message.Kind != "error" || reply.message.Errno != "ENOENT" {
		t.Fatalf("got %s/%s (%s)", reply.message.Kind, reply.message.Errno, reply.message.Message)
	}
	want := "chdir " + gone + ": no such file or directory"
	if reply.message.Message != want {
		t.Fatalf("message %q, want %q", reply.message.Message, want)
	}
}

// TestRunuserExecFailureTranslation pins the 126/127 mapping of runuser's
// rc-1 exec-failure diagnostics (util-linux breaks the shell convention),
// and that anything else — including multi-line output that merely ends with
// the signature — keeps its honest rc.
func TestRunuserExecFailureTranslation(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   int64
	}{
		{"not-found", "runuser: failed to execute nope: No such file or directory\n", 127},
		{"not-executable", "runuser: failed to execute /etc/passwd: Permission denied\n", 126},
		{"unknown-user", "runuser: user nosuchuser does not exist\n", 1},
		{"plain-failure", "some command output\n", 1},
		{"multiline-suffix-spoof", "x\nrunuser: failed to execute y: Permission denied", 1},
		{"other-exec-errno", "runuser: failed to execute z: Exec format error\n", 1},
	}
	for _, c := range cases {
		if got := runuserExecFailureRc([]byte(c.stderr), 1); got != c.want {
			t.Errorf("%s: rc %d, want %d", c.name, got, c.want)
		}
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
