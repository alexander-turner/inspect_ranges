// Daemon core: the request store (dedupe + durable replies), exec with
// in-guest budgets and tree kill, file operations with errno mapping, the
// diag ring buffer, and the per-connection serve loop.
//
// Trust posture: the peer (checked to be the hypervisor host, CID 2) is
// trusted, but the decode path stays hardened per the wire vectors; the
// daemon's own replies are what the host treats as untrusted.
package main

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	OutputCap      = 16 * 1024 * 1024 // per stream, the qemu-ga precedent
	StoredBound    = 256              // durable replies held bounded (FIFO) until acked
	TombstoneBound = 4096             // evicted-unacked ids answering ESTALE, their own FIFO
	DiagBound      = 256
	KillGrace      = 5 * time.Second // SIGTERM, then SIGKILL after grace
	WaitDelay      = 5 * time.Second // bound on reaping pipe copiers after exit (cmd.WaitDelay)
	MaxConnActive  = 512             // resource bound against floods; polls must outlive held exec slots
	DaemonVersion  = "vsockd 3.0.0 (go)"
	DefaultPort    = 5000
	TrustedPeerCID = 2
	// inbound bulk (write_file payloads, exec stdin): generous but bounded;
	// outbound stays capped at OutputCap per stream
	ReceiveBulkCap = 256 * 1024 * 1024
)

type storedReply struct {
	message *Message
	bulk    []byte
}

type runningExec struct {
	start time.Time
	done  chan struct{} // closed when the stored reply exists
}

// Store is the dedupe and durability core: every request kind stores its
// reply by id until acked, bounded FIFO (oldest unacked evicted first).
// Evicted-unacked ids leave a TOMBSTONE: the effect ran, the result is gone,
// and polls or resends for the id answer ESTALE so a client can never
// double-run it (range-channel property 1 under eviction).
type Store struct {
	mu         sync.Mutex
	replies    map[string]*storedReply
	order      *list.List // front = oldest
	keys       map[string]*list.Element
	running    map[string]*runningExec
	tombs      map[string]bool
	tombsOrder *list.List
}

func NewStore() *Store {
	return &Store{
		replies:    map[string]*storedReply{},
		order:      list.New(),
		keys:       map[string]*list.Element{},
		running:    map[string]*runningExec{},
		tombs:      map[string]bool{},
		tombsOrder: list.New(),
	}
}

// Tombstoned reports whether id executed but lost its unacked result.
func (s *Store) Tombstoned(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tombs[id]
}

func (s *Store) addTombstoneLocked(id string) {
	if !s.tombs[id] {
		s.tombs[id] = true
		s.tombsOrder.PushBack(id)
	}
	for s.tombsOrder.Len() > TombstoneBound {
		oldest := s.tombsOrder.Front()
		s.tombsOrder.Remove(oldest)
		delete(s.tombs, oldest.Value.(string))
	}
}

func (s *Store) Get(id string) (*storedReply, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply, ok := s.replies[id]
	return reply, ok
}

func (s *Store) Put(id string, reply *storedReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.replies[id]; !exists {
		s.keys[id] = s.order.PushBack(id)
	}
	s.replies[id] = reply
	for s.order.Len() > StoredBound {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		key := oldest.Value.(string)
		delete(s.replies, key)
		delete(s.keys, key)
		s.addTombstoneLocked(key) // evicted UNACKED: effect ran, result lost
	}
}

func (s *Store) Ack(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.keys[id]; ok {
		s.order.Remove(element)
		delete(s.keys, id)
		delete(s.replies, id)
	}
	delete(s.tombs, id) // an ack means the client consumed it after all
}

// Begin registers an in-flight durable request id. Returns (running, isNew):
// when isNew is false the caller must wait on running.done and read the
// stored reply (attach semantics: the effect runs exactly once per id, even
// when a retransmit arrives while the first attempt is still executing).
func (s *Store) Begin(id string) (*runningExec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run, ok := s.running[id]; ok {
		return run, false
	}
	run := &runningExec{start: time.Now(), done: make(chan struct{})}
	s.running[id] = run
	return run, true
}

func (s *Store) Finish(id string, reply *storedReply) {
	s.Put(id, reply)
	s.mu.Lock()
	run := s.running[id]
	delete(s.running, id)
	s.mu.Unlock()
	if run != nil {
		close(run.done)
	}
}

func (s *Store) Running(id string) (*runningExec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.running[id]
	return run, ok
}

// Diag is the bounded in-guest ring buffer, retrievable over the channel and
// never written anywhere the range can see.
type Diag struct {
	mu      sync.Mutex
	entries []DiagEntry
	started time.Time
}

func NewDiag() *Diag { return &Diag{started: time.Now()} }

func (d *Diag) Add(level, event string, requestID *string, detail string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, DiagEntry{
		TsMs:      time.Since(d.started).Milliseconds(),
		Level:     level,
		Event:     event,
		RequestID: requestID,
		Detail:    truncateString(detail, 2048),
	})
	if len(d.entries) > DiagBound {
		d.entries = d.entries[len(d.entries)-DiagBound:]
	}
}

func (d *Diag) Tail(limit int64) []DiagEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if limit < 0 {
		limit = 0 // defense in depth: decode already rejects negatives
	}
	if limit > int64(len(d.entries)) {
		limit = int64(len(d.entries))
	}
	tail := make([]DiagEntry, limit)
	copy(tail, d.entries[int64(len(d.entries))-limit:])
	return tail
}

func truncateString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// Daemon ties the store, diag, and handlers together.
type Daemon struct {
	store *Store
	diag  *Diag
}

func NewDaemon() *Daemon { return &Daemon{store: NewStore(), diag: NewDiag()} }

// Serve handles one connection: one request, one reply, close.
func (d *Daemon) Serve(conn io.ReadWriteCloser) {
	defer conn.Close()
	reader := NewFrameReader(conn)
	request, bulk, err := ReadMessage(reader, ReceiveBulkCap)
	if err != nil {
		if err != io.EOF {
			d.diag.Add("warn", "decode-failed", nil, err.Error())
		}
		return
	}
	d.diag.Add("info", "request", &request.ID, request.Kind)
	reply := d.dispatch(request, bulk)
	frames, err := EncodeMessage(reply.message, reply.bulk)
	if err != nil {
		d.diag.Add("error", "encode-failed", &request.ID, err.Error())
		return
	}
	if _, err := conn.Write(frames); err != nil {
		d.diag.Add("warn", "reply-write-failed", &request.ID, err.Error())
	}
}

func (d *Daemon) dispatch(request *Message, bulk []byte) *storedReply {
	switch request.Kind {
	case "ack":
		d.store.Ack(request.TargetID)
		return okReply(request.ID)
	case "poll":
		return d.poll(request)
	case "ping":
		return &storedReply{message: &Message{
			V: ProtocolVersion, ID: request.ID, Kind: "pong",
			Daemon: DaemonVersion, Protocol: i64(ProtocolVersion),
		}}
	case "diag":
		limit := int64(100)
		if request.MaxEntries != nil {
			limit = *request.MaxEntries
		}
		return &storedReply{message: &Message{
			V: ProtocolVersion, ID: request.ID, Kind: "diag_result",
			Entries: d.diag.Tail(limit),
		}}
	}
	// durable kinds: dedupe on id before executing any effect; attach to an
	// in-flight first attempt rather than racing it (exactly-once per id)
	if stored, ok := d.store.Get(request.ID); ok {
		return stored
	}
	if d.store.Tombstoned(request.ID) {
		return errorReply(request.ID, "ESTALE",
			"executed, result lost before acknowledgement", nil)
	}
	run, isNew := d.store.Begin(request.ID)
	if !isNew {
		<-run.done
		if stored, ok := d.store.Get(request.ID); ok {
			return stored
		}
		return errorReply(request.ID, "EPROTO", "request finished without a stored result", nil)
	}
	var reply *storedReply
	switch request.Kind {
	case "exec":
		reply = d.runCommand(request, bulk)
	case "read_file":
		reply = d.readFile(request)
	case "write_file":
		reply = d.writeFile(request, bulk)
	default:
		reply = errorReply(request.ID, "EPROTO", fmt.Sprintf("unsupported request %s", request.Kind), nil)
	}
	d.store.Finish(request.ID, reply)
	return reply
}

func (d *Daemon) poll(request *Message) *storedReply {
	if stored, ok := d.store.Get(request.TargetID); ok {
		return stored // replayed with the ORIGINAL id, by design
	}
	if d.store.Tombstoned(request.TargetID) {
		return errorReply(request.ID, "ESTALE",
			"executed, result lost before acknowledgement", nil)
	}
	if run, ok := d.store.Running(request.TargetID); ok {
		return &storedReply{message: &Message{
			V: ProtocolVersion, ID: request.ID, Kind: "pending",
			TargetID:  request.TargetID,
			ElapsedMs: i64(time.Since(run.start).Milliseconds()),
		}}
	}
	return errorReply(request.ID, "ENOENT", "no stored result", nil)
}

type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	room := OutputCap - lb.buf.Len()
	if room <= 0 {
		lb.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		lb.buf.Write(p[:room])
		lb.truncated = true
		return len(p), nil
	}
	lb.buf.Write(p)
	return len(p), nil
}

func (d *Daemon) runCommand(request *Message, stdin []byte) *storedReply {
	argv := request.Cmd
	if request.User != nil {
		argv = append([]string{"runuser", "-u", *request.User, "--"}, argv...)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own group: budget kills the tree
	if request.Cwd != nil {
		cmd.Dir = *request.Cwd
	}
	cmd.Env = os.Environ()
	for _, key := range sortedKeys(request.Env) {
		cmd.Env = append(cmd.Env, key+"="+request.Env[key])
	}
	if request.DataSize != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	stdout := &limitedBuffer{}
	stderr := &limitedBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// a killed process group can leave a descendant holding the stdout pipe
	// (setsid daemonizer): WaitDelay bounds Wait's pipe-copier wait after the
	// process exits, so runCommand can never hang a slot forever
	cmd.WaitDelay = WaitDelay

	if err := cmd.Start(); err != nil {
		return execStartFailure(request.ID, argv[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var budget <-chan time.Time
	var commandMs int64 = DefaultUntimedMs
	if request.Budget != nil && request.Budget.CommandMs != nil {
		commandMs = *request.Budget.CommandMs
	} else if request.Budget != nil && request.Budget.UntimedBoundMs != nil {
		commandMs = *request.Budget.UntimedBoundMs
	}
	timer := time.NewTimer(time.Duration(commandMs) * time.Millisecond)
	defer timer.Stop()
	budget = timer.C

	timedOut := false
	select {
	case <-done:
	case <-budget:
		timedOut = true
		// kill-grace: TERM the tree, then KILL after the grace window
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(KillGrace):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	if timedOut {
		d.diag.Add("warn", "exec-budget-killed", &request.ID, argv[0])
		return errorReply(request.ID,
			"ETIME",
			fmt.Sprintf("command budget expired after %d ms (process-group kill; setsid descendants survive)", commandMs),
			strp("command"))
	}
	rc := int64(cmd.ProcessState.ExitCode())
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		rc = -int64(status.Signal()) // killed-by-signal convention: negative
	}
	outBytes := stdout.buf.Bytes()
	errBytes := stderr.buf.Bytes()
	payload := append(append([]byte{}, outBytes...), errBytes...)
	message := &Message{
		V: ProtocolVersion, ID: request.ID, Kind: "exec_result",
		Rc:              i64(rc),
		StdoutSize:      i64(int64(len(outBytes))),
		StderrSize:      i64(int64(len(errBytes))),
		StdoutTruncated: boolp(stdout.truncated),
		StderrTruncated: boolp(stderr.truncated),
	}
	var bulk []byte
	if len(payload) > 0 {
		message.DataSize = i64(int64(len(payload)))
		bulk = payload
	}
	return &storedReply{message: message, bulk: bulk}
}

func execStartFailure(id, command string, err error) *storedReply {
	var pathError *fs.PathError
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return execRc(id, 127, nil, []byte("command not found: "+command+"\n"))
	case errors.Is(err, fs.ErrPermission):
		return execRc(id, 126, nil, []byte("permission denied: "+command+"\n"))
	case errors.As(err, &pathError):
		return errorReply(id, errnoName(pathError.Err), pathError.Error(), nil)
	default:
		return errorReply(id, "EIO", err.Error(), nil)
	}
}

func execRc(id string, rc int64, stdout, stderr []byte) *storedReply {
	payload := append(append([]byte{}, stdout...), stderr...)
	message := &Message{
		V: ProtocolVersion, ID: id, Kind: "exec_result",
		Rc:              i64(rc),
		StdoutSize:      i64(int64(len(stdout))),
		StderrSize:      i64(int64(len(stderr))),
		StdoutTruncated: boolp(false),
		StderrTruncated: boolp(false),
	}
	var bulk []byte
	if len(payload) > 0 {
		message.DataSize = i64(int64(len(payload)))
		bulk = payload
	}
	return &storedReply{message: message, bulk: bulk}
}

func (d *Daemon) readFile(request *Message) *storedReply {
	info, err := os.Stat(request.Path)
	if err == nil && info.IsDir() {
		return errorReply(request.ID, "EISDIR", "Is a directory", nil)
	}
	// incremental, bounded read: at most limit+1 bytes ever in memory, so a
	// multi-GiB file or an endless device cannot OOM or wedge the daemon
	limit := int64(DefaultBulkCap)
	if request.MaxBytes != nil {
		limit = *request.MaxBytes
	}
	handle, err := os.Open(request.Path)
	if err != nil {
		return fileError(request.ID, err)
	}
	defer handle.Close()
	data := make([]byte, 0, min64(limit+1, 1<<20))
	chunk := make([]byte, 1<<20)
	for int64(len(data)) <= limit {
		n, readErr := handle.Read(chunk)
		data = append(data, chunk[:n]...)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fileError(request.ID, readErr)
		}
	}
	truncated := false
	if int64(len(data)) > limit {
		data = data[:limit]
		truncated = true
	}
	message := &Message{
		V: ProtocolVersion, ID: request.ID, Kind: "file_data",
		Size: i64(int64(len(data))), Truncated: boolp(truncated),
	}
	var bulk []byte
	if len(data) > 0 {
		message.DataSize = i64(int64(len(data)))
		bulk = data
	}
	return &storedReply{message: message, bulk: bulk}
}

func (d *Daemon) writeFile(request *Message, data []byte) *storedReply {
	if parent := parentDir(request.Path); parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fileError(request.ID, err)
		}
	}
	if err := os.WriteFile(request.Path, data, 0o644); err != nil {
		return fileError(request.ID, err)
	}
	return okReply(request.ID)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func parentDir(path string) string {
	for i := len(path) - 1; i > 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

func fileError(id string, err error) *storedReply {
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		return errorReply(id, errnoName(pathError.Err), pathError.Error(), nil)
	}
	return errorReply(id, "EIO", err.Error(), nil)
}

func errnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EISDIR:
			return "EISDIR"
		case syscall.EACCES:
			return "EACCES"
		case syscall.ENOTDIR:
			return "ENOTDIR"
		case syscall.ENOSPC:
			return "ENOSPC"
		case syscall.EROFS:
			return "EROFS"
		}
	}
	return "EIO"
}

func okReply(id string) *storedReply {
	return &storedReply{message: &Message{V: ProtocolVersion, ID: id, Kind: "ok"}}
}

func errorReply(id, errno, detail string, layer *string) *storedReply {
	return &storedReply{message: &Message{
		V: ProtocolVersion, ID: id, Kind: "error",
		Errno: errno, Message: truncateString(detail, 4096), Layer: layer,
	}}
}
