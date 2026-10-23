// The exec witness (design/inspect-ranges/execve-witness-v1.md): a lazy-armed
// kernel process-connector subscriber serving the exec_events verb. Concept
// adopted from glovebox PR #15's execve witness, with attribution.
//
// Discipline mirrors the accept loop's (main.go): the subscriber is its own
// supervised goroutine that resubscribes with backoff and counts restarts, it
// NEVER blocks the serving path (a bounded ring overwrites oldest; kernel-side
// overflow counts drops), and it does not exist at all until the host's first
// exec_events poll (lazy-arm: builds never poll, so the fork-heaviest
// workloads never pay; the host-side kill switch therefore needs no rebake).
// A failed first arm is cached terminally and answered ENOSYS forever.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	// ExecRingSize bounds the witness ring: events, not bytes (worst case
	// ~10 MiB at the argv cap, typical far less); overflow overwrites oldest
	// and shows host-side as a seq discontinuity.
	ExecRingSize = 4096

	// process connector protocol numbers (linux/connector.h, linux/cn_proc.h)
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
)

// eventSource abstracts the netlink subscription so unit tests inject
// crafted datagrams without root or CONFIG_PROC_EVENTS.
type eventSource interface {
	Subscribe() error
	Read() ([]byte, error)
	Close()
}

type netlinkSource struct {
	fd int
}

func (s *netlinkSource) Subscribe() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink bind: %w", err)
	}
	// PROC_CN_MCAST_LISTEN: nlmsghdr(16) + cn_msg(20) + op(4)
	buf := make([]byte, 40)
	binary.LittleEndian.PutUint32(buf[0:], 40)                      // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:], uint16(unix.NLMSG_DONE)) // nlmsg_type
	binary.LittleEndian.PutUint32(buf[16:], cnIdxProc)              // cb_id.idx
	binary.LittleEndian.PutUint32(buf[20:], cnValProc)              // cb_id.val
	binary.LittleEndian.PutUint16(buf[32:], 4)                      // cn_msg.len
	binary.LittleEndian.PutUint32(buf[36:], procCnMcastListen)      // op
	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink subscribe: %w", err)
	}
	s.fd = fd
	return nil
}

func (s *netlinkSource) Read() ([]byte, error) {
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *netlinkSource) Close() {
	if s.fd > 0 {
		unix.Close(s.fd)
		s.fd = 0
	}
}

// procFacts reads what /proc still holds for a just-exec'd pid; every field
// may be gone by the time we look (the always-record race posture: connector
// facts alone still make an event).
type procFacts func(pid uint32) (ppid *int64, uid *int64, comm string, argv []string, truncated bool)

type execWitness struct {
	mu          sync.Mutex
	armed       bool
	unsupported error // terminal: cached on the first failed arm
	ring        []ExecEvent
	nextSeq     int64
	drops       atomic.Int64
	restarts    atomic.Int64
	newSource   func() eventSource
	readProc    procFacts
	stop        chan struct{}
}

func newExecWitness() *execWitness {
	return &execWitness{
		newSource: func() eventSource { return &netlinkSource{} },
		readProc:  readProcFacts,
		stop:      make(chan struct{}),
	}
}

// handle serves one exec_events request; dispatched pre-store like diag
// (polling is a read, never charged to the durable store).
func (w *execWitness) handle(request *Message) *storedReply {
	if err := w.arm(); err != nil {
		return errorReply(request.ID, "ENOSYS", "process connector unavailable: "+err.Error(), nil)
	}
	since := int64(0)
	if request.SinceSeq != nil {
		since = *request.SinceSeq
	}
	limit := int64(128)
	if request.MaxEvents != nil {
		limit = *request.MaxEvents
	}
	events, nextSeq := w.pack(since, int(limit))
	return &storedReply{message: &Message{
		V: ProtocolVersion, ID: request.ID, Kind: "exec_events_result",
		Events:   events,
		NextSeq:  i64(nextSeq),
		Drops:    i64(w.drops.Load()),
		Restarts: i64(w.restarts.Load()),
	}}
}

// arm subscribes on the first poll (mutex+flag, not sync.Once: a failed arm
// must stay re-answerable as the cached terminal error without re-arming).
func (w *execWitness) arm() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.unsupported != nil {
		return w.unsupported
	}
	if w.armed {
		return nil
	}
	source := w.newSource()
	if err := source.Subscribe(); err != nil {
		w.unsupported = err
		return err
	}
	w.ring = make([]ExecEvent, ExecRingSize)
	w.armed = true
	go w.run(source)
	return nil
}

// run is the supervised read loop: ENOBUFS counts a drop and keeps reading
// (the kernel-side queue overflowed, the socket is fine); any other error
// closes, backs off (100ms doubling to 5s), resubscribes, and counts a
// restart, the accept-loop discipline.
func (w *execWitness) run(source eventSource) {
	backoff := 100 * time.Millisecond
	for {
		data, err := source.Read()
		switch {
		case err == nil:
			backoff = 100 * time.Millisecond
			w.ingest(data)
		case err == unix.ENOBUFS:
			w.drops.Add(1)
		default:
			source.Close()
			select {
			case <-w.stop:
				return
			default:
			}
			w.restarts.Add(1)
			for {
				time.Sleep(backoff)
				if backoff < 5*time.Second {
					backoff *= 2
				}
				source = w.newSource()
				if err := source.Subscribe(); err == nil {
					break
				}
				select {
				case <-w.stop:
					return
				default:
				}
			}
		}
	}
}

// ingest walks a datagram's netlink messages (4-byte aligned) and records
// every PROC_EVENT_EXEC.
func (w *execWitness) ingest(datagram []byte) {
	for len(datagram) >= 16 {
		msgLen := int(binary.LittleEndian.Uint32(datagram[0:]))
		if msgLen < 16 || msgLen > len(datagram) {
			return
		}
		w.ingestOne(datagram[:msgLen])
		aligned := (msgLen + 3) &^ 3
		if aligned >= len(datagram) {
			return
		}
		datagram = datagram[aligned:]
	}
}

func (w *execWitness) ingestOne(msg []byte) {
	// nlmsghdr(16) + cn_msg(20) + proc_event{what@36, cpu@40, ts_ns@44,
	// exec{process_pid@52, process_tgid@56}}; the kernel packs proc_event
	// unaligned after cn_msg, so offsets are explicit
	if len(msg) < 60 {
		return
	}
	if binary.LittleEndian.Uint32(msg[36:]) != procEventExec {
		return
	}
	tgid := binary.LittleEndian.Uint32(msg[56:])
	if tgid == 0 {
		return
	}
	ppid, uid, comm, argv, truncated := w.readProc(tgid)
	event := ExecEvent{
		TsMs:      time.Now().UnixMilli(),
		Pid:       int64(tgid),
		Ppid:      ppid,
		Uid:       uid,
		Comm:      comm,
		Argv:      argv,
		Truncated: truncated,
	}
	w.mu.Lock()
	event.Seq = w.nextSeq
	w.ring[w.nextSeq%ExecRingSize] = event
	w.nextSeq++
	w.mu.Unlock()
}

// pack mirrors the host-side reference geometry (protocol.pack_exec_events):
// events in seq order from max(since, oldest-retained), the first qualifying
// event always packs, stop at max_events or the reply byte budget. Go's
// json.Marshal HTML-escapes <>&, so the estimate only over-counts, keeping
// the reply further under the frame cap.
func (w *execWitness) pack(since int64, limit int) ([]ExecEvent, int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if limit > MaxExecEvents {
		limit = MaxExecEvents
	}
	start := since
	if oldest := w.nextSeq - ExecRingSize; start < oldest {
		start = oldest // the overwrite shows as a seq discontinuity host-side
	}
	if start < 0 {
		start = 0
	}
	events := []ExecEvent{}
	budget := 0
	for seq := start; seq < w.nextSeq && len(events) < limit; seq++ {
		event := w.ring[seq%ExecRingSize]
		encoded, err := json.Marshal(&event)
		if err != nil {
			continue
		}
		if len(events) > 0 && budget+len(encoded) > ExecReplyBudget {
			break
		}
		events = append(events, event)
		budget += len(encoded)
	}
	nextSeq := w.nextSeq
	if len(events) > 0 {
		nextSeq = events[len(events)-1].Seq + 1
	} else if since > nextSeq {
		nextSeq = since
	}
	return events, nextSeq
}

// readProcFacts reads what /proc still holds for the pid; unreadable pieces
// go null/empty with truncated set when argv is lost or capped.
func readProcFacts(pid uint32) (ppid *int64, uid *int64, comm string, argv []string, truncated bool) {
	argv = []string{}
	base := "/proc/" + strconv.FormatUint(uint64(pid), 10)
	if raw, err := os.ReadFile(base + "/comm"); err == nil {
		comm = sanitizeWireString(strings.TrimRight(string(raw), "\n"), MaxExecComm)
	}
	if raw, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if value, ok := strings.CutPrefix(line, "PPid:"); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
					ppid = &n
				}
			}
			if value, ok := strings.CutPrefix(line, "Uid:"); ok {
				fields := strings.Fields(value)
				if len(fields) > 0 {
					if n, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
						uid = &n
					}
				}
			}
		}
	}
	raw, err := os.ReadFile(base + "/cmdline")
	if err != nil || len(raw) == 0 {
		truncated = true // gone or empty mid-exit: connector facts only
		return
	}
	total := 0
	for _, part := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
		remaining := MaxExecArgvBytes - total
		if remaining <= 0 {
			truncated = true
			break
		}
		arg := sanitizeWireString(part, remaining)
		if len(arg) < len(strings.ToValidUTF8(part, "�")) {
			truncated = true
		}
		argv = append(argv, arg)
		total += len(arg)
	}
	return
}

// sanitizeWireString makes a /proc byte string safe for the wire: valid
// UTF-8 (lossy replacement) cut at a rune boundary under `cap` bytes.
func sanitizeWireString(s string, cap int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= cap {
		return s
	}
	for cap > 0 && !utf8.ValidString(s[:cap]) {
		cap--
	}
	return s[:cap]
}
