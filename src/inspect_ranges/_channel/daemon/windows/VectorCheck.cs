// The third-codec drift guard: decode every shared wire vector from its
// pinned frame bytes, validate, re-encode, and demand byte equality; refuse
// every payload in the SHARED rejection table (doc-driven, so a new table
// entry pins all three codecs at once); pin the daemon grace constants; and
// hammer the Store dedupe core (the TOCTOU regression pin). Runs on any
// .NET (built with the pinned SDK via vsockd-win.csproj); the daemon itself
// never compiles this file in-guest.
//
// Usage: dotnet run --project . -- <path-to tests/wire_vectors/v3.json>

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace VsockD
{
    sealed class SliceSource : Wire.IByteSource
    {
        readonly byte[] _data;
        int _pos;
        public SliceSource(byte[] data) { _data = data; }
        public void ReadExact(byte[] dest, int count)
        {
            if (_pos + count > _data.Length) throw new DecodeException("stream ended mid-frame");
            Array.Copy(_data, _pos, dest, 0, count);
            _pos += count;
        }
        public bool Exhausted { get { return _pos == _data.Length; } }
    }

    static class VectorCheck
    {
        static byte[] FromHex(string hex)
        {
            byte[] data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++)
                data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return data;
        }

        static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("usage: VectorCheck <v3.json>");
                return 2;
            }
            object docObj = Wire.ParseJson(File.ReadAllBytes(args[0]));
            Dictionary<string, object> doc = (Dictionary<string, object>)docObj;
            if ((long)doc["protocol"] != Wire.ProtocolVersion)
            {
                Console.Error.WriteLine("vector protocol mismatch");
                return 1;
            }
            Dictionary<string, object> daemonPins = (Dictionary<string, object>)doc["daemon"];
            if ((long)daemonPins["inbound_bulk_cap"] != Wire.ReceiveBulkCap)
            {
                Console.Error.WriteLine("inbound bulk cap drifted from the vector pin");
                return 1;
            }
            // grace constants: the host's 12 s observation grace is computed
            // from these pins, so daemon drift would silently break budgets
            if ((long)daemonPins["kill_grace_ms"] != Daemon.KillGraceMs ||
                (long)daemonPins["wait_delay_ms"] != Daemon.WaitDelayMs)
            {
                Console.Error.WriteLine("grace constants drifted from the vector pins");
                return 1;
            }

            int failures = 0;
            List<object> vectors = (List<object>)doc["vectors"];
            HashSet<string> kinds = new HashSet<string>();
            foreach (object vectorObj in vectors)
            {
                Dictionary<string, object> vector = (Dictionary<string, object>)vectorObj;
                string name = (string)vector["name"];
                try
                {
                    List<object> framesHex = (List<object>)vector["frames_hex"];
                    MemoryStream wireStream = new MemoryStream();
                    foreach (object frame in framesHex)
                    {
                        byte[] raw = FromHex((string)frame);
                        wireStream.Write(raw, 0, raw.Length);
                    }
                    byte[] wire = wireStream.ToArray();
                    byte[] expectedBulk = null;
                    object bulkHex;
                    if (vector.TryGetValue("bulk_hex", out bulkHex))
                        expectedBulk = FromHex((string)bulkHex);

                    SliceSource source = new SliceSource(wire);
                    byte[] bulk;
                    Dictionary<string, object> message = Wire.ReadMessage(source, Wire.ReceiveBulkCap, out bulk);
                    if (!source.Exhausted) throw new Exception("trailing bytes after the message");
                    kinds.Add((string)message["kind"]);

                    if (!BytesEqual(bulk, expectedBulk)) throw new Exception("bulk mismatch");
                    byte[] reencoded = Wire.EncodeMessage(message, bulk);
                    if (!BytesEqual(reencoded, wire)) throw new Exception("encode drifted from pinned bytes");
                    Console.WriteLine("  PASS " + name);
                }
                catch (Exception error)
                {
                    failures++;
                    Console.WriteLine("  FAIL " + name + ": " + error.Message);
                }
            }

            // decode hardening: the SHARED rejection table, doc-driven so
            // every parity fix lands in all three codecs at once
            List<object> rejects = (List<object>)doc["rejects"];
            if (rejects.Count < 50)
            {
                Console.Error.WriteLine("shared reject table suspiciously small: " + rejects.Count);
                return 1;
            }
            foreach (object rejectObj in rejects)
            {
                Dictionary<string, object> reject = (Dictionary<string, object>)rejectObj;
                string rejectName = (string)reject["name"];
                string payload = (string)reject["payload"];
                bool refused = false;
                try { Wire.ParseControl(System.Text.Encoding.UTF8.GetBytes(payload)); }
                catch (DecodeException) { refused = true; }
                if (!refused)
                {
                    failures++;
                    Console.WriteLine("  FAIL reject/" + rejectName + ": accepted dishonest payload");
                }
                else
                {
                    Console.WriteLine("  PASS reject/" + rejectName);
                }
            }

            int hammerFailures = StoreHammer();
            if (hammerFailures == 0) Console.WriteLine("  PASS store-hammer (2000 rounds)");
            else Console.WriteLine("  FAIL store-hammer: " + hammerFailures + " violations");
            failures += hammerFailures;

            failures += SessionCheck();

            Console.WriteLine("vectors: " + vectors.Count + ", kinds covered: " + kinds.Count +
                ", failures: " + failures);
            return failures == 0 ? 0 : 1;
        }

        // The layer-2b session pin, mirroring the Go daemon test: every pong
        // from one daemon process carries the same well-formed 32-hex session
        // (a restart is a new process, so a fresh session by construction:
        // Daemon.Session is static readonly, minted at type initialization),
        // and the reply with the session must survive the strict codec.
        static int SessionCheck()
        {
            Dictionary<string, object> ping = new Dictionary<string, object>();
            ping["v"] = (long)Wire.ProtocolVersion;
            ping["id"] = new string('a', 32);
            ping["kind"] = "ping";
            StoredReply first = Daemon.Dispatch(ping, null);
            ping["id"] = new string('b', 32);
            StoredReply second = Daemon.Dispatch(ping, null);
            string session1 = (string)first.Message["session"];
            string session2 = (string)second.Message["session"];
            bool shaped = session1.Length == 32;
            foreach (char c in session1)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) shaped = false;
            bool encodes = true;
            try { Wire.EncodeMessage(first.Message, null); }
            catch (Exception) { encodes = false; }
            if (shaped && session1 == session2 && encodes)
            {
                Console.WriteLine("  PASS session (stable, 32-hex, encodes)");
                return 0;
            }
            Console.WriteLine("  FAIL session: shaped=" + shaped + " stable=" +
                (session1 == session2) + " encodes=" + encodes);
            return 1;
        }

        // The TOCTOU regression pin, ported from the Go daemon_test hammer:
        // racing acquires for one id must yield exactly one fresh run, and
        // every other caller must land on the stored reply (or tombstone).
        static int StoreHammer()
        {
            Store store = new Store();
            int totalFailures = 0;
            for (int round = 0; round < 2000; round++)
            {
                string id = round.ToString("x32");
                object stateLock = new object();
                int fresh = 0;
                int errors = 0;
                Thread[] workers = new Thread[8];
                for (int w = 0; w < workers.Length; w++)
                {
                    workers[w] = new Thread(delegate ()
                    {
                        StoredReply stored;
                        bool tombstoned, isNew;
                        RunningEntry entry = store.Acquire(id, out stored, out tombstoned, out isNew);
                        if (tombstoned)
                        {
                            lock (stateLock) { errors++; }
                            return;
                        }
                        if (isNew)
                        {
                            lock (stateLock) { fresh++; }
                            Dictionary<string, object> ok = new Dictionary<string, object>();
                            ok["v"] = (long)Wire.ProtocolVersion;
                            ok["id"] = id;
                            ok["kind"] = "ok";
                            store.Finish(id, new StoredReply(ok, null));
                            return;
                        }
                        if (stored != null) return;
                        entry.Done.WaitOne();
                        if (store.Get(id) == null && !store.Tombstoned(id))
                            lock (stateLock) { errors++; }
                    });
                    workers[w].IsBackground = true;
                }
                foreach (Thread worker in workers) worker.Start();
                foreach (Thread worker in workers) worker.Join();
                if (fresh != 1 || errors != 0) totalFailures++;
                store.Ack(id);
            }
            return totalFailures;
        }

        static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null) return true;
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
