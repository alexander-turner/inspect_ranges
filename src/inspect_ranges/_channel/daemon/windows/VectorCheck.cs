// The third-codec drift guard: decode every shared wire vector from its
// pinned frame bytes, validate, re-encode, and demand byte equality, plus a
// hardening table mirroring Python's and Go's rejection cases. Runs on any
// .NET (built with the pinned SDK via vsockd-win.csproj); the daemon itself
// never compiles this file in-guest.
//
// Usage: dotnet run --project . -- <path-to tests/wire_vectors/v3.json>

using System;
using System.Collections.Generic;
using System.IO;

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

            // decode hardening: the shared rejection table
            string rid = new string('a', 32);
            string[][] rejects = new string[][]
            {
                new[] { "missing-v", "{\"id\":\"" + rid + "\",\"kind\":\"ping\"}" },
                new[] { "wrong-v", "{\"id\":\"" + rid + "\",\"kind\":\"ping\",\"v\":2}" },
                new[] { "explicit-null", "{\"cmd\":[\"true\"],\"cwd\":null,\"id\":\"" + rid + "\",\"kind\":\"exec\",\"v\":3}" },
                new[] { "duplicate-key", "{\"id\":\"" + rid + "\",\"kind\":\"ping\",\"kind\":\"ping\",\"v\":3}" },
                new[] { "unknown-kind", "{\"id\":\"" + rid + "\",\"kind\":\"evil\",\"v\":3}" },
                new[] { "cross-kind-field", "{\"cmd\":[\"x\"],\"id\":\"" + rid + "\",\"kind\":\"ping\",\"v\":3}" },
                new[] { "pending-missing-elapsed", "{\"id\":\"" + rid + "\",\"kind\":\"pending\",\"target_id\":\"" + rid + "\",\"v\":3}" },
                new[] { "etime-without-layer", "{\"errno\":\"ETIME\",\"id\":\"" + rid + "\",\"kind\":\"error\",\"message\":\"x\",\"v\":3}" },
                new[] { "bulk-on-bulkless", "{\"data_size\":4,\"id\":\"" + rid + "\",\"kind\":\"ok\",\"v\":3}" },
                new[] { "non-integer-number", "{\"id\":\"" + rid + "\",\"kind\":\"heartbeat\",\"uptime_ms\":1.5,\"v\":3}" },
                new[] { "negative-max-entries", "{\"id\":\"" + rid + "\",\"kind\":\"diag\",\"max_entries\":-1,\"v\":3}" },
                new[] { "rc-outside-int32", "{\"id\":\"" + rid + "\",\"kind\":\"exec_result\",\"rc\":2147483648,\"stderr_size\":0,\"stdout_size\":0,\"v\":3}" },
                new[] { "bad-u-escape-0x", "{\"id\":\"" + rid + "\",\"kind\":\"error\",\"errno\":\"EIO\",\"message\":\"\\u0x41\",\"v\":3}" },
                new[] { "bad-u-escape-nonhex", "{\"id\":\"" + rid + "\",\"kind\":\"error\",\"errno\":\"EIO\",\"message\":\"\\uzzzz\",\"v\":3}" },
                new[] { "lone-high-surrogate", "{\"id\":\"" + rid + "\",\"kind\":\"error\",\"errno\":\"EIO\",\"message\":\"\\ud800\",\"v\":3}" },
                new[] { "wrong-typed-port", "{\"host\":\"h\",\"id\":\"" + rid + "\",\"kind\":\"forward\",\"port\":\"80\",\"v\":3}" },
                new[] { "wrong-typed-target", "{\"id\":\"" + rid + "\",\"kind\":\"ack\",\"target_id\":5,\"v\":3}" },
            };
            foreach (string[] reject in rejects)
            {
                bool refused = false;
                try { Wire.ParseControl(System.Text.Encoding.UTF8.GetBytes(reject[1])); }
                catch (DecodeException) { refused = true; }
                if (!refused)
                {
                    failures++;
                    Console.WriteLine("  FAIL hardening/" + reject[0] + ": accepted dishonest payload");
                }
                else
                {
                    Console.WriteLine("  PASS hardening/" + reject[0]);
                }
            }

            Console.WriteLine("vectors: " + vectors.Count + ", kinds covered: " + kinds.Count +
                ", failures: " + failures);
            return failures == 0 ? 0 : 1;
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
