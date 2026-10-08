// vsockd v3 for Windows: the daemon core behind the Wire codec.
//
// Ports the proven spike engine (design/spikes/vsockd-win: viosock quirks,
// CreateProcess/CreateProcessAsUser with Job Objects, errno mapping) onto
// protocol v3 semantics mirroring the Go daemon: request-id dedupe for every
// kind with attach-to-in-flight, durable results (errors included) held in a
// bounded FIFO until acked, ESTALE tombstones for evicted-unacked ids,
// poll/pending, the diag ring buffer, and in-guest command budgets.
//
// Kill semantics on Windows: there is no TERM analog, so the budget fires
// TerminateJobObject immediately (job = whole tree); the shared grace
// constants (KillGraceMs + WaitDelayMs, pinned by the wire vectors) bound
// the post-kill reaping instead, matching the host's 12 s observation grace.
// A process that breaks out of the Job (explicit breakaway) survives, the
// Windows analog of the documented Linux setsid escape.
//
// Listener supervision: the accept loop is watched; accept failures AND the
// wedge signature (listener readable but never acceptable) both recreate
// the socket with backoff, so recovery never requires Restart-Service.
//
// Target: .NET Framework 4.8, C# 5 (in-guest csc.exe), like the spike.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VsockD
{
    // ------------------------------------------------------------- transport
    // (ported verbatim from the spike: the viosock provider has no blocking
    // waits, rejects >32 KiB single sends, and has no working select)

    sealed class VSockEndPoint : System.Net.EndPoint
    {
        public const int AF_VSOCK = 40;
        public const uint VMADDR_CID_ANY = 0xFFFFFFFF;
        public uint Cid;
        public uint Port;

        public VSockEndPoint(uint cid, uint port) { Cid = cid; Port = port; }

        public override AddressFamily AddressFamily
        {
            get { return (AddressFamily)AF_VSOCK; }
        }

        public override System.Net.SocketAddress Serialize()
        {
            System.Net.SocketAddress sa = new System.Net.SocketAddress((AddressFamily)AF_VSOCK, 16);
            byte[] port = BitConverter.GetBytes(Port);
            byte[] cid = BitConverter.GetBytes(Cid);
            for (int i = 0; i < 4; i++) { sa[4 + i] = port[i]; sa[8 + i] = cid[i]; }
            return sa;
        }

        public override System.Net.EndPoint Create(System.Net.SocketAddress sa)
        {
            byte[] port = new byte[4];
            byte[] cid = new byte[4];
            for (int i = 0; i < 4; i++) { port[i] = sa[4 + i]; cid[i] = sa[8 + i]; }
            return new VSockEndPoint(BitConverter.ToUInt32(cid, 0), BitConverter.ToUInt32(port, 0));
        }
    }

    static class Io
    {
        private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);

        private static bool Retryable(SocketException se)
        {
            return se.SocketErrorCode == SocketError.WouldBlock
                || se.NativeErrorCode == STATUS_BUFFER_TOO_SMALL;
        }

        public static int Recv(Socket s, byte[] buf, int off, int len)
        {
            while (true)
            {
                try { return s.Receive(buf, off, len, SocketFlags.None); }
                catch (SocketException se)
                {
                    if (!Retryable(se)) throw;
                }
                try { s.Poll(1000000, SelectMode.SelectRead); }
                catch (Exception) { Thread.Sleep(1); }
            }
        }

        public const int SEND_CHUNK = 32 * 1024;

        public static void SendAll(Socket s, byte[] buf, int off, int len)
        {
            int sent = 0;
            int stall = 0;
            while (sent < len)
            {
                try
                {
                    sent += s.Send(buf, off + sent, Math.Min(SEND_CHUNK, len - sent), SocketFlags.None);
                    stall = 0;
                }
                catch (SocketException se)
                {
                    if (!Retryable(se)) throw;
                    stall++;
                    if (stall < 2000) Thread.Sleep(0); else Thread.Sleep(1);
                }
            }
        }
    }

    sealed class SockSource : Wire.IByteSource
    {
        private readonly Socket _s;
        private byte[] _buf = new byte[0];
        private int _pos;

        public SockSource(Socket s) { _s = s; }

        public void ReadExact(byte[] dest, int count)
        {
            int got = 0;
            int avail = _buf.Length - _pos;
            if (avail > 0)
            {
                int take = Math.Min(avail, count);
                Array.Copy(_buf, _pos, dest, 0, take);
                _pos += take; got = take;
            }
            while (got < count)
            {
                int n = Io.Recv(_s, dest, got, count - got);
                if (n == 0) throw new DecodeException("stream ended mid-frame");
                got += n;
            }
        }
    }

    // ------------------------------------------------------------- store

    sealed class StoredReply
    {
        public Dictionary<string, object> Message;
        public byte[] Bulk;
        public StoredReply(Dictionary<string, object> message, byte[] bulk)
        {
            Message = message; Bulk = bulk;
        }
    }

    sealed class RunningEntry
    {
        public long StartTicks = DateTime.UtcNow.Ticks;
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
                    while (_tombOrder.Count > TombstoneBound)
                    {
                        _tombs.Remove(_tombOrder.First.Value);
                        _tombOrder.RemoveFirst();
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

        // Begin registers an in-flight durable id. isNew=false: wait on the
        // returned entry's Done, then Get (attach semantics: exactly once).
        public RunningEntry Begin(string id, out bool isNew)
        {
            lock (_lock)
            {
                RunningEntry entry;
                if (_running.TryGetValue(id, out entry)) { isNew = false; return entry; }
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

    // ------------------------------------------------------------- diag ring

    sealed class Diag
    {
        public const int Bound = 256;
        private readonly object _lock = new object();
        private readonly List<Dictionary<string, object>> _entries = new List<Dictionary<string, object>>();
        private readonly long _started = DateTime.UtcNow.Ticks;

        public void Add(string level, string eventName, string requestId, string detail)
        {
            Dictionary<string, object> entry = new Dictionary<string, object>();
            entry["ts_ms"] = (DateTime.UtcNow.Ticks - _started) / TimeSpan.TicksPerMillisecond;
            entry["level"] = level;
            entry["event"] = eventName;
            if (requestId != null) entry["request_id"] = requestId;
            entry["detail"] = detail.Length > 2048 ? detail.Substring(0, 2048) : detail;
            lock (_lock)
            {
                _entries.Add(entry);
                if (_entries.Count > Bound) _entries.RemoveAt(0);
            }
            Daemon.Log(level + " " + eventName + " " + detail);
        }

        public List<object> Tail(long limit)
        {
            lock (_lock)
            {
                if (limit < 0) limit = 0;
                int take = (int)Math.Min(limit, _entries.Count);
                List<object> tail = new List<object>();
                for (int i = _entries.Count - take; i < _entries.Count; i++)
                    tail.Add(_entries[i]);
                return tail;
            }
        }
    }

    // ------------------------------------------------------------- daemon

    static class Daemon
    {
        public const int PORT = 5000;
        public const int KillGraceMs = 5000;  // pinned by the wire vectors
        public const int WaitDelayMs = 5000;  // pinned by the wire vectors
        public static string BaseDir = "C:\\vsockd";
        public static readonly Store Replies = new Store();
        public static readonly Diag Ring = new Diag();
        public static string Version = "vsockd 3.0.0 (windows)";

        public static void Log(string msg)
        {
            try
            {
                File.AppendAllText(Path.Combine(BaseDir, "vsockd.log"),
                    DateTime.UtcNow.ToString("o") + " " + msg + "\r\n");
            }
            catch (Exception) { }
        }

        // ---------------------------------------------------------- listener

        public static void ListenLoop()
        {
            string work = Path.Combine(BaseDir, "work");
            Directory.CreateDirectory(work);
            Directory.SetCurrentDirectory(work);
            Native.timeBeginPeriod(1);

            // supervision: the accept loop is watched; both exception storms
            // and the wedge signature (readable-but-unacceptable) recreate
            // the listener, so recovery never requires Restart-Service
            while (true)
            {
                Socket listener;
                try
                {
                    listener = new Socket((AddressFamily)VSockEndPoint.AF_VSOCK, SocketType.Stream, ProtocolType.Unspecified);
                    listener.Bind(new VSockEndPoint(VSockEndPoint.VMADDR_CID_ANY, PORT));
                    listener.Listen(64);
                }
                catch (Exception e)
                {
                    Ring.Add("error", "listen-failed", null, e.Message);
                    Thread.Sleep(1000);
                    continue;
                }
                Ring.Add("info", "listening", null, "vsock port " + PORT);
                AcceptLoop(listener);
                try { listener.Close(); } catch (Exception) { }
                Ring.Add("error", "listener-restarted", null, "accept loop died");
                Thread.Sleep(100);
            }
        }

        static void AcceptLoop(Socket listener)
        {
            int consecutiveFailures = 0;
            int wedgeSignals = 0;
            try { listener.Blocking = false; } catch (Exception) { }
            while (true)
            {
                bool readable;
                try { readable = listener.Poll(1000000, SelectMode.SelectRead); }
                catch (Exception e)
                {
                    Ring.Add("warn", "listener-poll-failed", null, e.Message);
                    return; // supervisor rebinds
                }
                if (!readable) { wedgeSignals = 0; continue; }

                Socket conn;
                try { conn = listener.Accept(); }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.WouldBlock)
                    {
                        // readable said yes, accept says no: the wedge
                        // signature; sustained means the listener is dead
                        wedgeSignals++;
                        if (wedgeSignals >= 5)
                        {
                            Ring.Add("error", "listener-wedged", null,
                                "readable but unacceptable x" + wedgeSignals);
                            return; // supervisor rebinds
                        }
                        Thread.Sleep(2);
                        continue;
                    }
                    consecutiveFailures++;
                    Ring.Add("warn", "accept-failed", null, se.Message);
                    if (consecutiveFailures >= 8) return; // supervisor rebinds
                    Thread.Sleep(10);
                    continue;
                }
                catch (Exception e)
                {
                    consecutiveFailures++;
                    Ring.Add("warn", "accept-failed", null, e.Message);
                    if (consecutiveFailures >= 8) return;
                    Thread.Sleep(10);
                    continue;
                }
                consecutiveFailures = 0;
                wedgeSignals = 0;

                try { conn.Blocking = true; } catch (Exception) { }
                try { conn.SendBufferSize = 4 << 20; conn.ReceiveBufferSize = 4 << 20; } catch (Exception) { }
                VSockEndPoint peer = null;
                try { peer = conn.RemoteEndPoint as VSockEndPoint; } catch (Exception) { }
                if (peer == null || peer.Cid != 2) // host-only; fail closed
                {
                    try { conn.Close(); } catch (Exception) { }
                    continue;
                }
                Thread t = new Thread(delegate () { HandleConn(conn); });
                t.IsBackground = true;
                t.Start();
            }
        }

        // ---------------------------------------------------------- serve

        static void HandleConn(Socket conn)
        {
            try
            {
                SockSource source = new SockSource(conn);
                byte[] bulk;
                Dictionary<string, object> request;
                try { request = Wire.ReadMessage(source, Wire.ReceiveBulkCap, out bulk); }
                catch (DecodeException e)
                {
                    Ring.Add("warn", "decode-failed", null, e.Message);
                    return;
                }
                string id = (string)request["id"];
                Ring.Add("info", "request", id, (string)request["kind"]);
                StoredReply reply = Dispatch(request, bulk);
                byte[] wire = Wire.EncodeMessage(reply.Message, reply.Bulk);
                Io.SendAll(conn, wire, 0, wire.Length);
            }
            catch (Exception e) { Log("conn: " + e.GetType().Name + ": " + e.Message); }
            finally { try { conn.Close(); } catch (Exception) { } }
        }

        static Dictionary<string, object> Base(string id, string kind)
        {
            Dictionary<string, object> m = new Dictionary<string, object>();
            m["v"] = (long)Wire.ProtocolVersion;
            m["id"] = id;
            m["kind"] = kind;
            return m;
        }

        static StoredReply ErrorReply(string id, string errno, string message, string layer)
        {
            Dictionary<string, object> m = Base(id, "error");
            m["errno"] = errno;
            m["message"] = message.Length > 4096 ? message.Substring(0, 4096) : message;
            if (layer != null) m["layer"] = layer;
            return new StoredReply(m, null);
        }

        static StoredReply OkReply(string id)
        {
            return new StoredReply(Base(id, "ok"), null);
        }

        public static StoredReply Dispatch(Dictionary<string, object> request, byte[] bulk)
        {
            string kind = (string)request["kind"];
            string id = (string)request["id"];

            if (kind == "ack")
            {
                Replies.Ack((string)request["target_id"]);
                return OkReply(id);
            }
            if (kind == "poll") return Poll(request);
            if (kind == "ping")
            {
                Dictionary<string, object> pong = Base(id, "pong");
                pong["daemon"] = Version;
                pong["protocol"] = (long)Wire.ProtocolVersion;
                return new StoredReply(pong, null);
            }
            if (kind == "diag")
            {
                long limit = 100;
                object maxEntries;
                if (request.TryGetValue("max_entries", out maxEntries)) limit = (long)maxEntries;
                Dictionary<string, object> result = Base(id, "diag_result");
                result["entries"] = Ring.Tail(limit);
                return new StoredReply(result, null);
            }

            // durable kinds: dedupe, tombstones, attach-to-in-flight
            StoredReply stored = Replies.Get(id);
            if (stored != null) return stored;
            if (Replies.Tombstoned(id))
                return ErrorReply(id, "ESTALE", "executed, result lost before acknowledgement", null);
            bool isNew;
            RunningEntry entry = Replies.Begin(id, out isNew);
            if (!isNew)
            {
                entry.Done.WaitOne();
                StoredReply attached = Replies.Get(id);
                if (attached != null) return attached;
                return ErrorReply(id, "EPROTO", "request finished without a stored result", null);
            }
            StoredReply reply;
            if (kind == "exec") reply = ExecRequest(request, bulk);
            else if (kind == "read_file") reply = ReadFile(request);
            else if (kind == "write_file") reply = WriteFile(request, bulk);
            else reply = ErrorReply(id, "EPROTO", "unsupported request " + kind, null);
            Replies.Finish(id, reply);
            return reply;
        }

        static StoredReply Poll(Dictionary<string, object> request)
        {
            string target = (string)request["target_id"];
            string id = (string)request["id"];
            StoredReply stored = Replies.Get(target);
            if (stored != null) return stored; // replayed under the ORIGINAL id
            if (Replies.Tombstoned(target))
                return ErrorReply(id, "ESTALE", "executed, result lost before acknowledgement", null);
            RunningEntry running = Replies.Running(target);
            if (running != null)
            {
                Dictionary<string, object> pending = Base(id, "pending");
                pending["target_id"] = target;
                pending["elapsed_ms"] = (DateTime.UtcNow.Ticks - running.StartTicks) / TimeSpan.TicksPerMillisecond;
                return new StoredReply(pending, null);
            }
            return ErrorReply(id, "ENOENT", "no stored result", null);
        }

        // ---------------------------------------------------------- ops

        static StoredReply ExecRequest(Dictionary<string, object> request, byte[] stdin)
        {
            string id = (string)request["id"];
            List<string> argv = new List<string>();
            foreach (object part in (List<object>)request["cmd"]) argv.Add((string)part);
            object cwdObj, userObj, envObj, budgetObj;
            string cwd = request.TryGetValue("cwd", out cwdObj) ? (string)cwdObj : null;
            string user = request.TryGetValue("user", out userObj) ? (string)userObj : null;
            Dictionary<string, string> env = null;
            if (request.TryGetValue("env", out envObj))
            {
                env = new Dictionary<string, string>();
                foreach (KeyValuePair<string, object> kv in (Dictionary<string, object>)envObj)
                    env[kv.Key] = (string)kv.Value;
            }
            long commandMs = Wire.DefaultUntimedMs;
            if (request.TryGetValue("budget", out budgetObj))
            {
                Dictionary<string, object> budget = (Dictionary<string, object>)budgetObj;
                object commandObj, untimedObj;
                if (budget.TryGetValue("command_ms", out commandObj)) commandMs = (long)commandObj;
                else if (budget.TryGetValue("untimed_bound_ms", out untimedObj)) commandMs = (long)untimedObj;
            }

            ExecOutcome outcome = ExecEngine.Run(argv, cwd, env, user, commandMs, stdin);
            if (outcome.Errno != null)
                return ErrorReply(id, outcome.Errno, outcome.ErrorMessage, null);
            if (outcome.TimedOut)
            {
                Ring.Add("warn", "exec-budget-killed", id, argv[0]);
                return ErrorReply(id, "ETIME",
                    "command budget expired after " + commandMs + " ms (job-object kill; breakaway processes survive)",
                    "command");
            }
            Dictionary<string, object> result = Base(id, "exec_result");
            result["rc"] = outcome.Rc;
            result["stdout_size"] = (long)outcome.Stdout.Length;
            result["stderr_size"] = (long)outcome.Stderr.Length;
            result["stdout_truncated"] = outcome.StdoutTruncated;
            result["stderr_truncated"] = outcome.StderrTruncated;
            byte[] payload = null;
            if (outcome.Stdout.Length + outcome.Stderr.Length > 0)
            {
                payload = new byte[outcome.Stdout.Length + outcome.Stderr.Length];
                Array.Copy(outcome.Stdout, 0, payload, 0, outcome.Stdout.Length);
                Array.Copy(outcome.Stderr, 0, payload, outcome.Stdout.Length, outcome.Stderr.Length);
                result["data_size"] = (long)payload.Length;
            }
            return new StoredReply(result, payload);
        }

        static StoredReply ReadFile(Dictionary<string, object> request)
        {
            string id = (string)request["id"];
            string path = (string)request["path"];
            long limit = Wire.DefaultBulkCap;
            object maxBytes;
            if (request.TryGetValue("max_bytes", out maxBytes)) limit = (long)maxBytes;
            if (Directory.Exists(path))
                return ErrorReply(id, "EISDIR", "Is a directory: " + path, null);
            if (!File.Exists(path))
                return ErrorReply(id, "ENOENT", "No such file or directory: " + path, null);
            try
            {
                // incremental, bounded: at most limit+1 bytes ever in memory
                using (FileStream fs = File.OpenRead(path))
                {
                    MemoryStream data = new MemoryStream();
                    byte[] chunk = new byte[1 << 20];
                    while (data.Length <= limit)
                    {
                        int n = fs.Read(chunk, 0, chunk.Length);
                        if (n <= 0) break;
                        data.Write(chunk, 0, n);
                    }
                    bool truncated = data.Length > limit;
                    byte[] body = data.ToArray();
                    if (truncated)
                    {
                        byte[] cut = new byte[limit];
                        Array.Copy(body, cut, (int)limit);
                        body = cut;
                    }
                    Dictionary<string, object> result = Base(id, "file_data");
                    result["size"] = (long)body.Length;
                    result["truncated"] = truncated;
                    if (body.Length > 0) result["data_size"] = (long)body.Length;
                    return new StoredReply(result, body.Length > 0 ? body : null);
                }
            }
            catch (Exception e) { return FileError(id, e, path); }
        }

        static StoredReply WriteFile(Dictionary<string, object> request, byte[] data)
        {
            string id = (string)request["id"];
            string path = (string)request["path"];
            if (data == null) data = new byte[0];
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                if (Directory.Exists(path))
                    return ErrorReply(id, "EISDIR", "Is a directory: " + path, null);
                File.WriteAllBytes(path, data);
                return OkReply(id);
            }
            catch (Exception e) { return FileError(id, e, path); }
        }

        static StoredReply FileError(string id, Exception e, string path)
        {
            string name = "EIO";
            if (e is FileNotFoundException || e is DirectoryNotFoundException) name = "ENOENT";
            else if (e is UnauthorizedAccessException) name = "EACCES";
            else if (e is PathTooLongException) name = "ENAMETOOLONG";
            return ErrorReply(id, name, e.Message + ": " + path, null);
        }
    }
}
