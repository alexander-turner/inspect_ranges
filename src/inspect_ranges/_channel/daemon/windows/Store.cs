// The dedupe and durability core of the Windows daemon, in its own file so
// the host-side vector check (net8) can compile and hammer it alongside the
// in-guest csc.exe build. Mirrors the Go Store: every request kind stores
// its reply by id until acked (bounded FIFO); evicted-unacked ids tombstone
// and answer ESTALE so a resend can never double-run.

using System;
using System.Collections.Generic;
using System.Threading;

namespace VsockD
{
    sealed class StoredReply
    {
        public Dictionary<string, object> Message;
        public byte[] Bulk;
        public StoredReply(Dictionary<string, object> message, byte[] bulk)
        {
            Message = message; Bulk = bulk;
        }
    }

    // quality-review B8: all internal timing is monotonic. DateTime.UtcNow
    // steps backwards on w32time resyncs (routine on Windows guests): a step
    // while a command ran minted NEGATIVE pending elapsed_ms / diag ts_ms,
    // which the host's strict decode rejects as TAMPER (an honest guest in
    // the wrong failure class), and skewed exec budget deadlines by the step
    // size. Stopwatch rides QPC and never steps; the Go daemon's time.Since
    // is already monotonic.
    static class Mono
    {
        public static long NowMs()
        {
            // split arithmetic: ts * 1000 overflows long on TSC-scale QPC
            // frequencies (~3 GHz on VMs without the hypervisor QPC
            // enlightenment) after ~35 days of uptime, which would mint the
            // very negative timestamps this helper exists to prevent
            long ts = System.Diagnostics.Stopwatch.GetTimestamp();
            long f = System.Diagnostics.Stopwatch.Frequency;
            return (ts / f) * 1000L + (ts % f) * 1000L / f;
        }
    }

    sealed class RunningEntry
    {
        public long StartMs = Mono.NowMs();
        public ManualResetEvent Done = new ManualResetEvent(false);
    }

    // Dedupe + durability + tombstones, mirroring the Go Store: every request
    // kind stores its reply by id until acked (bounded FIFO); evicted-unacked
    // ids tombstone and answer ESTALE so a resend can never double-run.
    sealed class Store
    {
        public const int StoredBound = 256;
        public const int TombstoneBound = 4096;

        private readonly object _lock = new object();
        private readonly Dictionary<string, StoredReply> _replies = new Dictionary<string, StoredReply>();
        private readonly LinkedList<string> _order = new LinkedList<string>();
        private readonly Dictionary<string, LinkedListNode<string>> _nodes = new Dictionary<string, LinkedListNode<string>>();
        private readonly Dictionary<string, RunningEntry> _running = new Dictionary<string, RunningEntry>();
        private readonly HashSet<string> _tombs = new HashSet<string>();
        private readonly LinkedList<string> _tombOrder = new LinkedList<string>();

        public StoredReply Get(string id)
        {
            lock (_lock)
            {
                StoredReply reply;
                return _replies.TryGetValue(id, out reply) ? reply : null;
            }
        }

        public bool Tombstoned(string id)
        {
            lock (_lock) { return _tombs.Contains(id); }
        }

        public void Put(string id, StoredReply reply)
        {
            lock (_lock)
            {
                if (!_replies.ContainsKey(id))
                    _nodes[id] = _order.AddLast(id);
                _replies[id] = reply;
                while (_order.Count > StoredBound)
                {
                    string oldest = _order.First.Value;
                    _order.RemoveFirst();
                    _nodes.Remove(oldest);
                    _replies.Remove(oldest);
                    // evicted UNACKED: the effect ran, the result is lost
                    if (_tombs.Add(oldest)) _tombOrder.AddLast(oldest);
                    // purge dead leading nodes (acked ids) on every add so
                    // the order list is bounded by LIVE tombstones even when
                    // the live count stays below the threshold (Go parity)
                    while (_tombOrder.Count > 0 && !_tombs.Contains(_tombOrder.First.Value))
                        _tombOrder.RemoveFirst();
                    while (_tombs.Count > TombstoneBound && _tombOrder.Count > 0)
                    {
                        // acked ids leave stale order nodes: skip them so the
                        // bound governs LIVE tombstones, not residue
                        string candidate = _tombOrder.First.Value;
                        _tombOrder.RemoveFirst();
                        _tombs.Remove(candidate);
                    }
                }
            }
        }

        public void Ack(string id)
        {
            lock (_lock)
            {
                LinkedListNode<string> node;
                if (_nodes.TryGetValue(id, out node))
                {
                    _order.Remove(node);
                    _nodes.Remove(id);
                    _replies.Remove(id);
                }
                _tombs.Remove(id); // an ack means the client consumed it
            }
        }

        // Acquire is the ONE atomic dedupe step for durable ids: under a
        // single lock it returns the stored reply, the tombstone verdict, or
        // the running entry to attach to, or registers a fresh run. Separate
        // Get/Tombstoned/Begin calls would race a completing first attempt
        // (the TOCTOU the review caught, fixed in the Go daemon too).
        public RunningEntry Acquire(string id, out StoredReply stored, out bool tombstoned, out bool isNew)
        {
            lock (_lock)
            {
                tombstoned = false;
                isNew = false;
                if (_replies.TryGetValue(id, out stored)) return null;
                if (_tombs.Contains(id)) { tombstoned = true; return null; }
                RunningEntry entry;
                if (_running.TryGetValue(id, out entry)) return entry;
                entry = new RunningEntry();
                _running[id] = entry;
                isNew = true;
                return entry;
            }
        }

        public void Finish(string id, StoredReply reply)
        {
            Put(id, reply);
            RunningEntry entry = null;
            lock (_lock)
            {
                if (_running.TryGetValue(id, out entry)) _running.Remove(id);
            }
            if (entry != null) entry.Done.Set();
        }

        public RunningEntry Running(string id)
        {
            lock (_lock)
            {
                RunningEntry entry;
                return _running.TryGetValue(id, out entry) ? entry : null;
            }
        }
    }

}
