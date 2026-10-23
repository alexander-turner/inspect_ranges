// Unit tests for the exec witness (execve-witness-v1): fake event sources
// stand in for netlink, so nothing here needs root or CONFIG_PROC_EVENTS.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeSource feeds scripted datagrams; an exhausted script blocks until stop.
type fakeSource struct {
	mu           sync.Mutex
	datagrams    [][]byte
	errs         []error
	stop         chan struct{}
	subscribeErr error
	closed       bool
}

func (s *fakeSource) Subscribe() error { return s.subscribeErr }

func (s *fakeSource) Read() ([]byte, error) {
	s.mu.Lock()
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		s.mu.Unlock()
		return nil, err
	}
	if len(s.datagrams) > 0 {
		data := s.datagrams[0]
		s.datagrams = s.datagrams[1:]
		s.mu.Unlock()
		return data, nil
	}
	s.mu.Unlock()
	<-s.stop
	return nil, errors.New("stopped")
}

func (s *fakeSource) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

// execDatagram builds one connector PROC_EVENT_EXEC datagram for tgid, with
// the nlmsg type and connector id the ingest filter requires.
func execDatagram(tgid uint32) []byte {
	buf := make([]byte, 60)
	binary.LittleEndian.PutUint32(buf[0:], 60)
	binary.LittleEndian.PutUint16(buf[4:], uint16(unix.NLMSG_DONE))
	binary.LittleEndian.PutUint32(buf[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(buf[20:], cnValProc)
	binary.LittleEndian.PutUint32(buf[36:], procEventExec)
	binary.LittleEndian.PutUint32(buf[52:], tgid) // process_pid
	binary.LittleEndian.PutUint32(buf[56:], tgid) // process_tgid
	return buf
}

func testWitness(t *testing.T, source eventSource, facts procFacts) *execWitness {
	t.Helper()
	w := newExecWitness()
	w.newSource = func() eventSource { return source }
	w.readProc = facts
	// end the supervised loop at test exit so run() never outlives the test
	// spinning restarts (review round 1, finding 8)
	t.Cleanup(func() { close(w.stop) })
	return w
}

func staticFacts(argv ...string) procFacts {
	return func(pid uint32) (*int64, *int64, string, []string, bool) {
		ppid := int64(1)
		uid := int64(0)
		if argv == nil {
			argv = []string{}
		}
		return &ppid, &uid, "test", argv, false
	}
}

func waitFor(t *testing.T, label string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", label)
}

func pollWitness(w *execWitness, since int64) *Message {
	reply := w.handle(&Message{V: ProtocolVersion, ID: strings.Repeat("a", 32), Kind: "exec_events", SinceSeq: i64(since)})
	return reply.message
}

func TestLazyArmAndEventFlow(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{}), datagrams: [][]byte{execDatagram(42)}}
	w := testWitness(t, source, staticFacts("nmap", "-sV"))
	defer close(source.stop)
	if w.armed {
		t.Fatal("witness armed before any poll")
	}
	reply := pollWitness(w, 0)
	if reply.Kind != "exec_events_result" {
		t.Fatalf("unexpected reply kind %q", reply.Kind)
	}
	waitFor(t, "the scripted event", func() bool {
		return len(pollWitness(w, 0).Events) == 1
	})
	events := pollWitness(w, 0).Events
	if events[0].Pid != 42 || events[0].Argv[1] != "-sV" || events[0].Seq != 0 {
		t.Fatalf("bad event: %+v", events[0])
	}
	// the cursor resumes past it
	again := pollWitness(w, *reply.NextSeq)
	_ = again
}

func TestArmFailureIsCachedTerminal(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{}), subscribeErr: errors.New("EINVAL: no connector")}
	w := testWitness(t, source, staticFacts())
	for i := 0; i < 3; i++ {
		reply := pollWitness(w, 0)
		if reply.Kind != "error" || reply.Errno != "ENOSYS" {
			t.Fatalf("want cached ENOSYS, got %q/%q", reply.Kind, reply.Errno)
		}
	}
	if w.armed {
		t.Fatal("a failed arm must never mark the witness armed")
	}
}

func TestConcurrentFirstPollsArmOnce(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{})}
	w := testWitness(t, source, staticFacts())
	defer close(source.stop)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pollWitness(w, 0)
		}()
	}
	wg.Wait()
	if !w.armed {
		t.Fatal("not armed after concurrent polls")
	}
}

func TestRingOverflowShowsAsSeqDiscontinuity(t *testing.T) {
	datagrams := make([][]byte, ExecRingSize+10)
	for i := range datagrams {
		datagrams[i] = execDatagram(uint32(i + 2))
	}
	source := &fakeSource{stop: make(chan struct{}), datagrams: datagrams}
	w := testWitness(t, source, staticFacts("x"))
	defer close(source.stop)
	pollWitness(w, 0)
	waitFor(t, "ring to fill past capacity", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.nextSeq == int64(ExecRingSize+10)
	})
	reply := pollWitness(w, 0)
	if len(reply.Events) == 0 || reply.Events[0].Seq != 10 {
		t.Fatalf("overwritten ring must start at seq 10, got %+v", reply.Events[0])
	}
}

func TestPackingStaysUnderTheReplyBudget(t *testing.T) {
	big := strings.Repeat("a", MaxExecArgvBytes-10)
	datagrams := make([][]byte, 64)
	for i := range datagrams {
		datagrams[i] = execDatagram(uint32(i + 2))
	}
	source := &fakeSource{stop: make(chan struct{}), datagrams: datagrams}
	w := testWitness(t, source, staticFacts(big))
	defer close(source.stop)
	pollWitness(w, 0)
	waitFor(t, "all events ingested", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.nextSeq == 64
	})
	reply := pollWitness(w, 0)
	encoded, err := json.Marshal(reply.Events)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > ExecReplyBudget+1024 { // slice brackets/commas ride above per-event sums
		t.Fatalf("reply events encode to %d bytes, budget %d", len(encoded), ExecReplyBudget)
	}
	if len(reply.Events) >= 64 {
		t.Fatal("budget never clipped the reply")
	}
	// drain: the cursor walks the remainder without loss
	seen := len(reply.Events)
	cursor := *reply.NextSeq
	for i := 0; i < 20 && seen < 64; i++ {
		next := pollWitness(w, cursor)
		seen += len(next.Events)
		cursor = *next.NextSeq
	}
	if seen != 64 {
		t.Fatalf("drain lost events: saw %d of 64", seen)
	}
}

func TestReadErrorResubscribesAndCounts(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{}), errs: []error{errors.New("read torn down")}, datagrams: nil}
	w := testWitness(t, source, staticFacts())
	defer close(source.stop)
	pollWitness(w, 0)
	waitFor(t, "the restart counter", func() bool { return w.restarts.Load() == 1 })
	reply := pollWitness(w, 0)
	if *reply.Restarts != 1 {
		t.Fatalf("restarts not surfaced: %d", *reply.Restarts)
	}
}

func TestRaceFactsStillRecord(t *testing.T) {
	raceFacts := func(pid uint32) (*int64, *int64, string, []string, bool) {
		return nil, nil, "", []string{}, true // /proc gone mid-exit
	}
	source := &fakeSource{stop: make(chan struct{}), datagrams: [][]byte{execDatagram(99)}}
	w := testWitness(t, source, raceFacts)
	defer close(source.stop)
	pollWitness(w, 0)
	waitFor(t, "the race event", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.nextSeq == 1
	})
	event := pollWitness(w, 0).Events[0]
	if event.Pid != 99 || event.Ppid != nil || event.Uid != nil || !event.Truncated {
		t.Fatalf("race event must keep connector facts: %+v", event)
	}
}

func TestIngestFiltersNonConnectorShapes(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{})}
	w := testWitness(t, source, staticFacts("x"))
	w.ring = make([]ExecEvent, ExecRingSize) // ingest directly, no loop
	spoofWrongType := execDatagram(50)
	binary.LittleEndian.PutUint16(spoofWrongType[4:], 2) // NLMSG_ERROR
	spoofWrongID := execDatagram(51)
	binary.LittleEndian.PutUint32(spoofWrongID[16:], 7) // not CN_IDX_PROC
	w.ingest(spoofWrongType)
	w.ingest(spoofWrongID)
	w.ingest(execDatagram(52))
	if w.nextSeq != 1 {
		t.Fatalf("filter admitted %d events, want exactly the real one", w.nextSeq)
	}
	if w.ring[0].Pid != 52 {
		t.Fatalf("wrong event admitted: %+v", w.ring[0])
	}
}

func TestArgvItemCapBoundsEmptyArgStorms(t *testing.T) {
	// finding 1/2's trigger shape: thousands of zero-byte args cost no byte
	// budget but unbounded encoded overhead; the item cap bounds them and the
	// capped event must validate AND encode inside the frame
	argv := []string{}
	truncated := false
	parts := append([]string{"x"}, make([]string, 15000)...)
	total := 0
	for _, part := range parts {
		if len(argv) >= MaxExecArgvItems {
			truncated = true
			break
		}
		remaining := MaxExecArgvBytes - total
		if remaining <= 0 {
			truncated = true
			break
		}
		arg := sanitizeWireString(part, remaining)
		argv = append(argv, arg)
		total += len(arg)
	}
	if len(argv) != MaxExecArgvItems || !truncated {
		t.Fatalf("item cap not enforced: %d items, truncated=%v", len(argv), truncated)
	}
	event := ExecEvent{Seq: 0, TsMs: 1, Pid: 1, Comm: "x", Argv: argv, Truncated: truncated}
	msg := &Message{V: ProtocolVersion, ID: strings.Repeat("a", 32), Kind: "exec_events_result",
		Events: []ExecEvent{event}, NextSeq: i64(1), Drops: i64(0), Restarts: i64(0)}
	if err := msg.validate(); err != nil {
		t.Fatalf("capped event must validate: %v", err)
	}
	if _, err := EncodeMessage(msg, nil); err != nil {
		t.Fatalf("capped event must encode inside the frame: %v", err)
	}
}

func TestPackReportsTheTrueHeadOnStaleCursors(t *testing.T) {
	source := &fakeSource{stop: make(chan struct{}), datagrams: [][]byte{execDatagram(42)}}
	w := testWitness(t, source, staticFacts("x"))
	pollWitness(w, 0)
	waitFor(t, "one event", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.nextSeq == 1
	})
	// a cursor from a previous daemon life: the reply must expose the true
	// head (the restart signal), never clamp up to the stale cursor
	reply := pollWitness(w, 500)
	if len(reply.Events) != 0 || *reply.NextSeq != 1 {
		t.Fatalf("stale cursor must see the true head: %+v next=%d", reply.Events, *reply.NextSeq)
	}
}

func TestSanitizeWireString(t *testing.T) {
	cases := []struct {
		in   string
		cap  int
		want string
	}{
		{"plain", 64, "plain"},
		{"caf\xc3\xa9", 64, "café"},
		{"bad\xffbyte", 64, "bad�byte"},
		{"héllo", 2, "h"}, // cut lands mid-rune and backs up to a boundary
	}
	for _, c := range cases {
		if got := sanitizeWireString(c.in, c.cap); got != c.want {
			t.Fatalf("sanitize(%q, %d) = %q, want %q", c.in, c.cap, got, c.want)
		}
	}
}
