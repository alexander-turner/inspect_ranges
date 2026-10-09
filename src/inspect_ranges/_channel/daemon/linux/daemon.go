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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	OutputCap      = 16 * 1024 * 1024 // per stream, the qemu-ga precedent
	StoredBound    = 256              // durable replies held bounded (FIFO) until acked
	TombstoneBound = 4096             // evicted-unacked ids answering ESTALE, their own FIFO
	DiagBound      = 256
	KillGrace      = 5 * time.Second // SIGTERM, then SIGKILL after grace
	WaitDelay      = 5 * time.Second // bound on reaping pipe copiers after exit (cmd.WaitDelay)
	MaxConnActive  = 512             // resource bound against floods; polls must outlive held exec slots
	DaemonVersion  = "vsockd 3.1.0 (go)"
	// exec must not PATH-resolve a privilege boundary: a range-writable PATH
	// entry could shadow runuser, so the daemon invokes it absolutely
	RunuserPath    = "/usr/sbin/runuser"
	AgentUser      = "agent"
	PartialCap     = 4096 // ETIME partial-output tail (a capped text field, never bulk)
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
	// acked ids leave stale order nodes; bound the LIVE tombstone count and
	// drop residue nodes as they surface
	for len(s.tombs) > TombstoneBound && s.tombsOrder.Len() > 0 {
		oldest := s.tombsOrder.Front()
		s.tombsOrder.Remove(oldest)
		delete(s.tombs, oldest.Value.(string))
	}
	for s.tombsOrder.Len() > 0 {
		front := s.tombsOrder.Front()
		if s.tombs[front.Value.(string)] {
			break
		}
		s.tombsOrder.Remove(front) // residue from an acked id
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

// Acquire is the ONE atomic dedupe step for durable ids: under a single lock
// it returns the stored reply, the tombstone verdict, an in-flight run to
// attach to, or registers a fresh run. Separate Get/Tombstoned/Begin calls
// raced a completing first attempt (a retransmit could land between Finish
// removing the run and the resend's Begin, re-running the effect).
func (s *Store) Acquire(id string) (stored *storedReply, tombstoned bool, run *runningExec, isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reply, ok := s.replies[id]; ok {
		return reply, false, nil, false
	}
	if s.tombs[id] {
		return nil, true, nil, false
	}
	if existing, ok := s.running[id]; ok {
		return nil, false, existing, false
	}
	fresh := &runningExec{start: time.Now(), done: make(chan struct{})}
	s.running[id] = fresh
	return nil, false, fresh, true
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

// msDuration converts a millisecond budget to time.Duration, clamping
// values whose nanosecond count overflows int64 (e.g. 13e12 ms): the
// wrapped negative Duration would fire the budget timer immediately.
func msDuration(ms int64) time.Duration {
	const maxMs = math.MaxInt64 / int64(time.Millisecond)
	if ms > maxMs {
		ms = maxMs
	}
	return time.Duration(ms) * time.Millisecond
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Daemon ties the store, diag, and handlers together.
type Daemon struct {
	store *Store
	diag  *Diag
	// session: minted once per daemon process and reported in every pong.
	// The host pins it per guest, so a daemon restart (which empties the
	// dedupe store) surfaces as a session change instead of a silent loss of
	// the exactly-once guarantee.
	session string
	// agent: the unprivileged default identity for exec and file operations,
	// nil when the daemon cannot drop to it (pre-v4 golden without the user,
	// or an unprivileged run)
	agent *agentIdentity
	// supervised listener recoveries since start; surfaced in diag_result
	// so batteries can assert the storm never wedged the accept loop
	listenerRestarts atomic.Int64
}

func NewDaemon() *Daemon {
	daemon := &Daemon{store: NewStore(), diag: NewDiag(), session: newSessionID()}
	daemon.agent = resolveAgent(daemon.diag)
	return daemon
}

// newSessionID mints the daemon's boot session: 32 lowercase hex chars.
func newSessionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("session entropy unavailable: %v", err))
	}
	return hex.EncodeToString(buf)
}

// agentIdentity is the unprivileged default identity for guest operations.
type agentIdentity struct {
	uid int
	gid int
}

// resolveAgent returns the agent user's ids when the daemon can actually
// drop to them: running as root on a guest whose image created the user.
// Otherwise nil, with a diag warning: pre-v4 goldens have no agent user, and
// operations there keep the daemon's own identity rather than hard-failing.
func resolveAgent(diag *Diag) *agentIdentity {
	if os.Geteuid() != 0 {
		diag.Add("warn", "agent-user-unavailable", nil,
			"not running as root; operations keep the daemon's identity")
		return nil
	}
	record, err := user.Lookup(AgentUser)
	if err != nil {
		diag.Add("warn", "agent-user-unavailable", nil,
			fmt.Sprintf("user %q missing (pre-v4 golden?); operations run as root: %v", AgentUser, err))
		return nil
	}
	uid, uidErr := strconv.Atoi(record.Uid)
	gid, gidErr := strconv.Atoi(record.Gid)
	if uidErr != nil || gidErr != nil {
		diag.Add("warn", "agent-user-unavailable", nil,
			fmt.Sprintf("user %q has non-numeric ids; operations run as root", AgentUser))
		return nil
	}
	return &agentIdentity{uid: uid, gid: gid}
}

// asAgentFS runs fn with this OS thread's FILESYSTEM identity dropped to the
// agent user: fsuid, fsgid, and the supplementary groups (without setgroups
// the daemon's root groups would still grant access). The identity is
// restored afterwards; if any restoration step fails the thread stays locked
// so Go destroys it on goroutine exit, and a half-privileged thread never
// rejoins the scheduler pool. A panic in fn skips restoration entirely and
// retires the thread the same way (dispatch's recover produces the reply).
func (d *Daemon) asAgentFS(id string, fn func() *storedReply) *storedReply {
	if d.agent == nil {
		return fn()
	}
	runtime.LockOSThread()
	restored := false
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	previousGroups, err := unix.Getgroups()
	if err != nil {
		restored = true // nothing dropped yet
		return errorReply(id, "EIO", "getgroups: "+err.Error(), nil)
	}
	if err := unix.Setgroups([]int{d.agent.gid}); err != nil {
		restored = true // nothing dropped yet
		return errorReply(id, "EIO", "setgroups: "+err.Error(), nil)
	}
	previousFsgid, gidDropped := swapFsgid(d.agent.gid)
	if !gidDropped {
		restored = unix.Setgroups(previousGroups) == nil
		return errorReply(id, "EIO", "setfsgid did not take", nil)
	}
	previousFsuid, uidDropped := swapFsuid(d.agent.uid)
	if !uidDropped {
		_, gidBack := swapFsgid(previousFsgid)
		groupsBack := unix.Setgroups(previousGroups) == nil
		restored = gidBack && groupsBack
		return errorReply(id, "EIO", "setfsuid did not take", nil)
	}
	reply := fn()
	_, uidBack := swapFsuid(previousFsuid)
	_, gidBack := swapFsgid(previousFsgid)
	groupsBack := unix.Setgroups(previousGroups) == nil
	restored = uidBack && gidBack && groupsBack
	if !restored {
		d.diag.Add("error", "fs-identity-restore-failed", &id,
			"retiring the locked OS thread")
	}
	return reply
}

// swapFsuid sets this thread's filesystem uid and reports whether the change
// VERIFIABLY took. setfsuid(2) gives no error indication (it returns the
// previous id unconditionally, per its BUGS section), so the only honest
// check is a read-back through a second call with the same value.
func swapFsuid(uid int) (previous int, ok bool) {
	previous, err := unix.SetfsuidRetUid(uid)
	if err != nil {
		return previous, false
	}
	current, err := unix.SetfsuidRetUid(uid)
	return previous, err == nil && current == uid
}

// swapFsgid mirrors swapFsuid for the filesystem gid (setfsgid(2) has the
// same no-error-reporting contract).
func swapFsgid(gid int) (previous int, ok bool) {
	previous, err := unix.SetfsgidRetGid(gid)
	if err != nil {
		return previous, false
	}
	current, err := unix.SetfsgidRetGid(gid)
	return previous, err == nil && current == gid
}

// fileModeFromWire maps octal POSIX permission bits (the wire form) to
// fs.FileMode, whose setuid/setgid/sticky bits live elsewhere.
func fileModeFromWire(wire int64) fs.FileMode {
	mode := fs.FileMode(wire & 0o777)
	if wire&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if wire&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if wire&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

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
		// a stored reply the codec refuses (e.g. invalid UTF-8 smuggled
		// past truncation) must not strand the client in silence: degrade
		// to a safe ASCII error reply instead
		d.diag.Add("error", "encode-failed", &request.ID, err.Error())
		fallback := errorReply(request.ID, "EIO", "reply could not be encoded", nil)
		frames, err = EncodeMessage(fallback.message, nil)
		if err != nil {
			return
		}
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
			Session: d.session,
		}}
	case "diag":
		limit := int64(100)
		if request.MaxEntries != nil {
			limit = *request.MaxEntries
		}
		return &storedReply{message: &Message{
			V: ProtocolVersion, ID: request.ID, Kind: "diag_result",
			Entries:          d.diag.Tail(limit),
			ListenerRestarts: i64(d.listenerRestarts.Load()),
		}}
	}
	// durable kinds: dedupe, tombstones, and attach-to-in-flight in ONE
	// atomic acquire (exactly-once per id, immune to the completion race)
	stored, tombstoned, run, isNew := d.store.Acquire(request.ID)
	if stored != nil {
		return stored
	}
	if tombstoned {
		return errorReply(request.ID, "ESTALE",
			"executed, result lost before acknowledgement", nil)
	}
	if !isNew {
		<-run.done
		if attached, ok := d.store.Get(request.ID); ok {
			return attached
		}
		if d.store.Tombstoned(request.ID) {
			return errorReply(request.ID, "ESTALE",
				"executed, result lost before acknowledgement", nil)
		}
		return errorReply(request.ID, "EPROTO", "request finished without a stored result", nil)
	}
	var reply *storedReply
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				reply = errorReply(request.ID, "EIO", fmt.Sprintf("handler panicked: %v", recovered), nil)
			}
			d.store.Finish(request.ID, reply)
		}()
		switch request.Kind {
		case "exec":
			reply = d.runCommand(request, bulk)
		case "read_file":
			reply = d.asAgentFS(request.ID, func() *storedReply { return d.readFile(request) })
		case "write_file":
			reply = d.asAgentFS(request.ID, func() *storedReply { return d.writeFile(request, bulk) })
		default:
			reply = errorReply(request.ID, "EPROTO", fmt.Sprintf("unsupported request %s", request.Kind), nil)
		}
	}()
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

// Snapshot copies the buffered bytes under the lock: after a WaitDelay
// interruption a pipe copier may still be mid-write when the ETIME reply is
// built, so an unlocked read would race.
func (lb *limitedBuffer) Snapshot() []byte {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return append([]byte{}, lb.buf.Bytes()...)
}

// Len reports the buffered byte count under the lock (a cheap pre-filter so
// multi-MiB streams are never copied just to probe for a short signature).
func (lb *limitedBuffer) Len() int {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.buf.Len()
}

func (d *Daemon) runCommand(request *Message, stdin []byte) *storedReply {
	argv := request.Cmd
	usedRunuser := false
	switch {
	case request.User != nil:
		argv = append([]string{RunuserPath, "-u", *request.User, "--"}, argv...)
		usedRunuser = true
	case d.agent != nil:
		// the unprivileged agent user is the default exec identity; an
		// unknown explicit user above stays a failed exec_result naming the
		// user (runuser exits nonzero), never a channel error
		argv = append([]string{RunuserPath, "-u", AgentUser, "--"}, argv...)
		usedRunuser = true
	}
	// neither arm: no agent identity and no explicit user, so the command
	// keeps the daemon's own identity (pre-v4 golden or unprivileged run;
	// resolveAgent already left the diag warning)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own group: budget kills the tree
	if request.Cwd != nil {
		// pre-check: with the runuser prefix a missing or non-directory cwd
		// would otherwise surface as an ambiguous fork/exec error on the
		// runuser binary; name the real cause, in the shape LocalEndpoint
		// emulates
		info, err := os.Stat(*request.Cwd)
		if err != nil {
			errno := "ENOENT"
			reason := "no such file or directory"
			var pathError *fs.PathError
			if errors.As(err, &pathError) {
				errno = errnoName(pathError.Err)
				reason = pathError.Err.Error()
			}
			return errorReply(request.ID, errno, fmt.Sprintf("chdir %s: %s", *request.Cwd, reason), nil)
		}
		if !info.IsDir() {
			return errorReply(request.ID, "ENOTDIR",
				fmt.Sprintf("chdir %s: not a directory", *request.Cwd), nil)
		}
		cmd.Dir = *request.Cwd
	}
	// NOTE: when the runuser prefix is active, util-linux runuser always
	// resets HOME, SHELL, USER, LOGNAME, and PATH to the target user's values
	// (its --whitelist-environment explicitly ignores those five), so caller
	// values for them do not survive this path; the provider routes env that
	// touches those keys through the wrapper script, whose exports run after
	// runuser. All other keys pass through untouched.
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
	timer := time.NewTimer(msDuration(commandMs))
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
		reply := errorReply(request.ID,
			"ETIME",
			fmt.Sprintf("command budget expired after %d ms (process-group kill; setsid descendants survive)", commandMs),
			strp("command"))
		if tail := partialTail(stdout.Snapshot(), stderr.Snapshot()); tail != "" {
			reply.message.Partial = &tail
		}
		return reply
	}
	rc := int64(cmd.ProcessState.ExitCode())
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		rc = -int64(status.Signal()) // killed-by-signal convention: negative
	}
	if usedRunuser && rc == 1 && stderr.Len() <= runuserSignatureBound {
		rc = runuserExecFailureRc(stderr.Snapshot(), rc)
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

// runuserSignatureBound caps how much stderr runuserExecFailureRc inspects:
// the one-line diagnostic is "runuser: failed to execute <path>: <reason>",
// and paths over PATH_MAX cannot reach exec, so anything longer cannot be
// the signature.
const runuserSignatureBound = 4096 + 128

// runuserExecFailureRc translates runuser's exec-failure reporting into the
// shell's 126/127 convention. util-linux runuser (as shipped on noble) exits
// 1 both when the target command is missing and when it is not executable,
// unlike a shell; its single-line diagnostic is unambiguous, so the
// user-switched path is mapped to match the direct-exec path
// (execStartFailure) and the contract's expectations. A command that itself
// exits 1 printing exactly this one-line signature would be misread; its
// stderr is attacker-influenceable output anyway, and the blast radius is an
// rc of 127/126 instead of 1.
func runuserExecFailureRc(stderr []byte, rc int64) int64 {
	if len(stderr) > runuserSignatureBound {
		return rc
	}
	text := strings.TrimSpace(string(stderr))
	if !strings.HasPrefix(text, "runuser: failed to execute ") ||
		strings.ContainsRune(text, '\n') {
		return rc
	}
	switch {
	case strings.HasSuffix(text, ": No such file or directory"):
		return 127
	case strings.HasSuffix(text, ": Permission denied"):
		return 126
	}
	return rc
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

// partialTail returns the capped, UTF-8-sanitized tail of a killed
// command's output for the ETIME reply: stdout when it produced any, else
// stderr. Deliberately a small text field, never bulk, so the bulk-on-error
// side channel stays closed.
func partialTail(stdout, stderr []byte) string {
	source := stdout
	if len(source) == 0 {
		source = stderr
	}
	if len(source) > PartialCap {
		source = source[len(source)-PartialCap:]
	}
	return strings.ToValidUTF8(string(source), "")
}

func (d *Daemon) writeFile(request *Message, data []byte) *storedReply {
	if parent := parentDir(request.Path); parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fileError(request.ID, err)
		}
	}
	if request.Mode == nil {
		if err := os.WriteFile(request.Path, data, 0o644); err != nil {
			return fileError(request.ID, err)
		}
		return okReply(request.ID)
	}
	// mode-carrying writes pin the permission bits BEFORE any content lands:
	// O_CREATE filters the mode through umask and ignores it entirely for a
	// pre-existing file (whose old, possibly wider bits would otherwise cover
	// the fresh secret until a trailing chmod), so open without truncating,
	// fchmod to the exact bits, then truncate and write
	mode := fileModeFromWire(*request.Mode)
	handle, err := os.OpenFile(request.Path, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return fileError(request.ID, err)
	}
	defer handle.Close()
	if err := handle.Chmod(mode); err != nil {
		return fileError(request.ID, err)
	}
	if err := handle.Truncate(0); err != nil {
		return fileError(request.ID, err)
	}
	if _, err := handle.Write(data); err != nil {
		return fileError(request.ID, err)
	}
	if err := handle.Close(); err != nil {
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
