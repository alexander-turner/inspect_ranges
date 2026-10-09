// Protocol v3 wire codec for the Windows daemon (C# 5 / .NET Framework 4.8,
// compiled in-guest by the in-box csc.exe; also compiled on net8 for the
// host-side vector check). Byte-compatible with the Python reference
// (src/inspect_ranges/_channel/{protocol,codec}.py) and the Go daemon,
// pinned by tests/wire_vectors/v3.json.
//
// Canonical JSON (the cross-codec contract): sorted keys (ordinal), compact
// separators, raw UTF-8 (no ASCII escaping beyond JSON's required set:
// quote, backslash, and controls, with \b \t \n \f \r shorthands and
// lowercase \u00xx otherwise), integers only, null optionals OMITTED on
// encode and REJECTED on decode, duplicate keys rejected, v required, and
// the per-kind required/forbidden field table enforced (ported from
// wire.go; the dictionary message model is deliberate for C# 5, the table
// is the schema).

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace VsockD
{
    class DecodeException : Exception
    {
        public DecodeException(string reason) : base("decode: " + reason) { }
    }

    static class Wire
    {
        public const int ProtocolVersion = 3;
        public const int MaxFramePayload = 32 * 1024;
        public const long MaxBulkDeclarable = 1L << 30;
        public const long MaxWireInt = 1L << 53;
        public const long DefaultBulkCap = 16L * 1024 * 1024;
        public const long ReceiveBulkCap = 256L * 1024 * 1024; // pinned by the vectors
        public const long DefaultUntimedMs = 14400000;

        // strict-side-wins caps and literal sets, adopted from the Python
        // schema and pinned by the shared rejection table
        public const int MaxDaemonLen = 128;
        public const int MaxMessageLen = 4096;
        public const int MaxStageDetailLen = 4096;
        public const int MaxEventLen = 128;
        public const int MaxDiagDetailLen = 2048;
        public const int MaxRequestIdLen = 64;
        public const int MaxGrants = 64;
        public const int MaxDiagEntries = 1000;

        static readonly HashSet<string> StageLiterals =
            new HashSet<string> { "fetch", "construct", "boot", "verify", "ready", "failed" };
        static readonly HashSet<string> LayerLiterals =
            new HashSet<string> { "command", "channel", "untimed", "transport" };
        static readonly HashSet<string> LevelLiterals =
            new HashSet<string> { "info", "warn", "error" };
        static readonly HashSet<string> GuestStateLiterals =
            new HashSet<string> { "pending", "booting", "ready", "failed" };

        public const byte FrameControl = 0x43;
        public const byte FrameData = 0x44;
        public const byte FrameEnd = 0x45;

        static readonly Regex RequestIdRe = new Regex("^[0-9a-f]{32}$");
        static readonly Regex ErrnoRe = new Regex("^[A-Z][A-Z0-9]{1,15}$");
        static readonly Regex Sha256Re = new Regex("^[0-9a-f]{64}$");
        static readonly Regex SessionRe = new Regex("^[0-9a-f]{32}$");

        // ------------------------------------------------------------ JSON

        // Strict parser: objects as Dictionary<string, object>, arrays as
        // List<object>, strings, longs, bools. Nulls, duplicate keys,
        // non-integer numbers, and trailing data are all decode errors.
        public static object ParseJson(byte[] payload)
        {
            string text;
            try { text = new UTF8Encoding(false, true).GetString(payload); }
            catch (Exception) { throw new DecodeException("payload is not UTF-8"); }
            int pos = 0;
            object value = ParseValue(text, ref pos, 0);
            SkipWs(text, ref pos);
            if (pos != text.Length) throw new DecodeException("trailing data after JSON document");
            return value;
        }

        static void SkipWs(string s, ref int pos)
        {
            while (pos < s.Length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++;
        }

        static object ParseValue(string s, ref int pos, int depth)
        {
            if (depth > 32) throw new DecodeException("nesting too deep");
            SkipWs(s, ref pos);
            if (pos >= s.Length) throw new DecodeException("unexpected end of JSON");
            char c = s[pos];
            if (c == '{') return ParseObject(s, ref pos, depth);
            if (c == '[') return ParseArray(s, ref pos, depth);
            if (c == '"') return ParseString(s, ref pos);
            if (c == 't') { Expect(s, ref pos, "true"); return true; }
            if (c == 'f') { Expect(s, ref pos, "false"); return false; }
            if (c == 'n') throw new DecodeException("explicit null in payload");
            return ParseNumber(s, ref pos);
        }

        static void Expect(string s, ref int pos, string word)
        {
            if (pos + word.Length > s.Length || s.Substring(pos, word.Length) != word)
                throw new DecodeException("not JSON near position " + pos);
            pos += word.Length;
        }

        static Dictionary<string, object> ParseObject(string s, ref int pos, int depth)
        {
            pos++; // {
            Dictionary<string, object> result = new Dictionary<string, object>();
            SkipWs(s, ref pos);
            if (pos < s.Length && s[pos] == '}') { pos++; return result; }
            while (true)
            {
                SkipWs(s, ref pos);
                if (pos >= s.Length || s[pos] != '"') throw new DecodeException("object key expected");
                string key = ParseString(s, ref pos);
                if (result.ContainsKey(key)) throw new DecodeException("duplicate JSON key \"" + key + "\"");
                SkipWs(s, ref pos);
                if (pos >= s.Length || s[pos] != ':') throw new DecodeException("':' expected");
                pos++;
                result[key] = ParseValue(s, ref pos, depth + 1);
                SkipWs(s, ref pos);
                if (pos >= s.Length) throw new DecodeException("unterminated object");
                if (s[pos] == ',') { pos++; continue; }
                if (s[pos] == '}') { pos++; return result; }
                throw new DecodeException("',' or '}' expected");
            }
        }

        static List<object> ParseArray(string s, ref int pos, int depth)
        {
            pos++; // [
            List<object> result = new List<object>();
            SkipWs(s, ref pos);
            if (pos < s.Length && s[pos] == ']') { pos++; return result; }
            while (true)
            {
                result.Add(ParseValue(s, ref pos, depth + 1));
                SkipWs(s, ref pos);
                if (pos >= s.Length) throw new DecodeException("unterminated array");
                if (s[pos] == ',') { pos++; continue; }
                if (s[pos] == ']') { pos++; return result; }
                throw new DecodeException("',' or ']' expected");
            }
        }

        static string ParseString(string s, ref int pos)
        {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                if (pos >= s.Length) throw new DecodeException("unterminated string");
                char c = s[pos++];
                if (c == '"') return sb.ToString();
                if (c == '\\')
                {
                    if (pos >= s.Length) throw new DecodeException("unterminated escape");
                    char e = s[pos++];
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            _pendingLow = '\0';
                            sb.Append(ParseUnicodeEscape(s, ref pos, false));
                            if (_pendingLow != '\0') sb.Append(_pendingLow);
                            break;
                        default: throw new DecodeException("bad escape '\\" + e + "'");
                    }
                    continue;
                }
                if (c < 0x20) throw new DecodeException("raw control character in string");
                sb.Append(c);
            }
        }

        static char ParseUnicodeEscape(string s, ref int pos, bool wantLow)
        {
            if (pos + 4 > s.Length) throw new DecodeException("bad \\u escape");
            int code = 0;
            for (int i = 0; i < 4; i++)
            {
                char h = s[pos + i];
                int digit;
                if (h >= '0' && h <= '9') digit = h - '0';
                else if (h >= 'a' && h <= 'f') digit = h - 'a' + 10;
                else if (h >= 'A' && h <= 'F') digit = h - 'A' + 10;
                else throw new DecodeException("bad \\u escape (non-hex digit)");
                code = (code << 4) | digit;
            }
            pos += 4;
            char c = (char)code;
            if (wantLow)
            {
                if (!char.IsLowSurrogate(c))
                    throw new DecodeException("lone high surrogate escape");
                return c;
            }
            if (char.IsLowSurrogate(c))
                throw new DecodeException("lone low surrogate escape");
            if (char.IsHighSurrogate(c))
            {
                // a high surrogate must pair with an escaped low surrogate
                if (pos + 2 > s.Length || s[pos] != '\\' || s[pos + 1] != 'u')
                    throw new DecodeException("lone high surrogate escape");
                pos += 2;
                // the pair is appended by the caller via two Append calls:
                // return the high here and stash the low through recursion
                char low = ParseUnicodeEscape(s, ref pos, true);
                _pendingLow = low;
            }
            return c;
        }

        [ThreadStatic] static char _pendingLow;

        static object ParseNumber(string s, ref int pos)
        {
            int start = pos;
            if (pos < s.Length && s[pos] == '-') pos++;
            while (pos < s.Length && s[pos] >= '0' && s[pos] <= '9') pos++;
            if (pos == start || (s[start] == '-' && pos == start + 1))
                throw new DecodeException("not JSON near position " + start);
            if (pos < s.Length && (s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E'))
                throw new DecodeException("non-integer number (the wire is integer-only)");
            string digits = s.Substring(start, pos - start);
            string unsigned = digits[0] == '-' ? digits.Substring(1) : digits;
            if (unsigned.Length > 1 && unsigned[0] == '0')
                throw new DecodeException("leading zero in number");
            long value;
            if (!long.TryParse(digits, out value)) throw new DecodeException("number out of range");
            return value;
        }

        // Canonical writer: byte-identical to Python's
        // json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
        public static byte[] CanonicalJson(object value)
        {
            StringBuilder sb = new StringBuilder();
            WriteValue(sb, value);
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        static void WriteValue(StringBuilder sb, object value)
        {
            if (value is bool) { sb.Append((bool)value ? "true" : "false"); return; }
            if (value is long) { sb.Append(((long)value).ToString()); return; }
            if (value is int) { sb.Append(((int)value).ToString()); return; }
            string s = value as string;
            if (s != null) { WriteString(sb, s); return; }
            Dictionary<string, object> dict = value as Dictionary<string, object>;
            if (dict != null)
            {
                List<string> keys = new List<string>(dict.Keys);
                keys.Sort(StringComparer.Ordinal);
                sb.Append('{');
                for (int i = 0; i < keys.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteString(sb, keys[i]);
                    sb.Append(':');
                    WriteValue(sb, dict[keys[i]]);
                }
                sb.Append('}');
                return;
            }
            List<object> list = value as List<object>;
            if (list != null)
            {
                sb.Append('[');
                for (int i = 0; i < list.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteValue(sb, list[i]);
                }
                sb.Append(']');
                return;
            }
            if (value == null) throw new InvalidOperationException("the wire never carries null");
            throw new InvalidOperationException("unencodable value type " + value.GetType().Name);
        }

        static void WriteString(StringBuilder sb, string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) &&
                    (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])))
                    throw new InvalidOperationException("lone surrogate is unencodable");
                if (char.IsLowSurrogate(s[i]) &&
                    (i == 0 || !char.IsHighSurrogate(s[i - 1])))
                    throw new InvalidOperationException("lone surrogate is unencodable");
            }
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            sb.Append(c); // raw UTF-8 on encode, incl. non-ASCII
                        break;
                }
            }
            sb.Append('"');
        }

        // ------------------------------------------------------------ frames

        public static byte[] FrameBytes(byte frameType, byte[] payload)
        {
            byte[] frame = new byte[5 + payload.Length];
            frame[0] = (byte)((payload.Length >> 24) & 0xFF);
            frame[1] = (byte)((payload.Length >> 16) & 0xFF);
            frame[2] = (byte)((payload.Length >> 8) & 0xFF);
            frame[3] = (byte)(payload.Length & 0xFF);
            frame[4] = frameType;
            Array.Copy(payload, 0, frame, 5, payload.Length);
            return frame;
        }

        public static string Sha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder(64);
                foreach (byte b in digest) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        // EncodeMessage renders a validated control dict (and optional bulk)
        // into wire frames. data_size consistency is the caller's contract,
        // checked here.
        public static byte[] EncodeMessage(Dictionary<string, object> message, byte[] bulk)
        {
            object declaredObj;
            bool hasDeclared = message.TryGetValue("data_size", out declaredObj);
            if (!hasDeclared && bulk != null)
                throw new InvalidOperationException("bulk supplied but data_size absent");
            byte[] payload = CanonicalJson(message);
            if (payload.Length > MaxFramePayload)
                throw new InvalidOperationException("control payload " + payload.Length + " exceeds frame cap");
            List<byte[]> frames = new List<byte[]>();
            frames.Add(FrameBytes(FrameControl, payload));
            if (hasDeclared)
            {
                long declared = (long)declaredObj;
                if (bulk == null || bulk.Length != declared)
                    throw new InvalidOperationException("data_size=" + declared + " but bulk is " +
                        (bulk == null ? "absent" : bulk.Length.ToString()));
                for (int off = 0; off < bulk.Length; off += MaxFramePayload)
                {
                    int len = Math.Min(MaxFramePayload, bulk.Length - off);
                    byte[] chunk = new byte[len];
                    Array.Copy(bulk, off, chunk, 0, len);
                    frames.Add(FrameBytes(FrameData, chunk));
                }
                Dictionary<string, object> end = new Dictionary<string, object>();
                end["sha256"] = Sha256Hex(bulk);
                end["size"] = declared;
                frames.Add(FrameBytes(FrameEnd, CanonicalJson(end)));
            }
            int total = 0;
            foreach (byte[] f in frames) total += f.Length;
            byte[] wire = new byte[total];
            int at = 0;
            foreach (byte[] f in frames) { Array.Copy(f, 0, wire, at, f.Length); at += f.Length; }
            return wire;
        }

        // ----------------------------------------------------------- decode

        public interface IByteSource
        {
            // fills exactly count bytes or throws; EOF mid-read is an error
            void ReadExact(byte[] dest, int count);
        }

        public static void ReadFrame(IByteSource src, out byte frameType, out byte[] payload)
        {
            byte[] header = new byte[5];
            src.ReadExact(header, 5);
            long length = ((long)header[0] << 24) | ((long)header[1] << 16) | ((long)header[2] << 8) | header[3];
            if (length > MaxFramePayload)
                throw new DecodeException("frame declares " + length + " bytes (cap " + MaxFramePayload + ")");
            frameType = header[4];
            if (frameType != FrameControl && frameType != FrameData && frameType != FrameEnd)
                throw new DecodeException("unknown frame type 0x" + frameType.ToString("x2"));
            payload = new byte[length];
            if (length > 0) src.ReadExact(payload, (int)length);
        }

        public static Dictionary<string, object> ReadMessage(IByteSource src, long bulkCap, out byte[] bulk)
        {
            byte frameType;
            byte[] payload;
            ReadFrame(src, out frameType, out payload);
            if (frameType != FrameControl)
                throw new DecodeException("expected CONTROL frame, got 0x" + frameType.ToString("x2"));
            Dictionary<string, object> message = ParseControl(payload);
            bulk = null;
            object declaredObj;
            if (!message.TryGetValue("data_size", out declaredObj)) return message;
            long declared = (long)declaredObj;
            // grow-as-received: a lying huge declaration cannot pre-allocate
            System.IO.MemoryStream body = new System.IO.MemoryStream();
            while (true)
            {
                ReadFrame(src, out frameType, out payload);
                if (frameType == FrameData)
                {
                    if (body.Length + payload.Length > bulkCap)
                        throw new DecodeException("bulk exceeds reader cap " + bulkCap);
                    if (body.Length + payload.Length > declared)
                        throw new DecodeException("bulk exceeds declared data_size " + declared);
                    body.Write(payload, 0, payload.Length);
                    continue;
                }
                if (frameType == FrameEnd)
                {
                    Dictionary<string, object> end = ParseEnd(payload);
                    long endSize = (long)end["size"];
                    if (endSize != body.Length || body.Length != declared)
                        throw new DecodeException("bulk size mismatch declared=" + declared + " received=" + body.Length + " end=" + endSize);
                    bulk = body.ToArray();
                    if (Sha256Hex(bulk) != (string)end["sha256"])
                        throw new DecodeException("bulk sha256 mismatch");
                    return message;
                }
                throw new DecodeException("CONTROL frame inside bulk transfer");
            }
        }

        static Dictionary<string, object> ParseEnd(byte[] payload)
        {
            object parsed = ParseJson(payload);
            Dictionary<string, object> end = parsed as Dictionary<string, object>;
            if (end == null || end.Count != 2 || !end.ContainsKey("sha256") || !end.ContainsKey("size"))
                throw new DecodeException("END payload must be exactly {sha256, size}");
            string sha = end["sha256"] as string;
            if (sha == null || !Sha256Re.IsMatch(sha))
                throw new DecodeException("END sha256 malformed");
            if (!(end["size"] is long) || (long)end["size"] < 0 || (long)end["size"] > MaxBulkDeclarable)
                throw new DecodeException("END size out of bounds");
            return end;
        }

        public static Dictionary<string, object> ParseControl(byte[] payload)
        {
            object parsed = ParseJson(payload);
            Dictionary<string, object> message = parsed as Dictionary<string, object>;
            if (message == null) throw new DecodeException("control payload is not a JSON object");
            object v;
            if (!message.TryGetValue("v", out v) || !(v is long) || (long)v != ProtocolVersion)
                throw new DecodeException("control payload must carry v=" + ProtocolVersion);
            Validate(message);
            return message;
        }

        // ------------------------------------------------------- validation

        static readonly Dictionary<string, string[]> RequiredFields = new Dictionary<string, string[]>
        {
            { "ping", new string[0] },
            { "pong", new[] { "daemon", "session" } },
            { "exec", new[] { "cmd" } },
            { "read_file", new[] { "path" } },
            { "write_file", new[] { "path" } },
            { "forward", new[] { "host", "port" } },
            { "poll", new[] { "target_id" } },
            { "ack", new[] { "target_id" } },
            { "diag", new string[0] },
            { "exec_result", new[] { "rc", "stdout_size", "stderr_size" } },
            { "file_data", new[] { "size" } },
            { "ok", new string[0] },
            { "pending", new[] { "target_id", "elapsed_ms" } },
            { "forward_ok", new[] { "handle" } },
            { "diag_result", new string[0] },
            { "error", new[] { "errno", "message" } },
            { "realize", new[] { "bundle_digest" } },
            { "teardown", new string[0] },
            { "stage", new[] { "stage" } },
            { "heartbeat", new[] { "uptime_ms" } },
        };

        static readonly Dictionary<string, string[]> OptionalFields = new Dictionary<string, string[]>
        {
            { "ping", new string[0] },
            { "pong", new[] { "protocol" } },
            { "exec", new[] { "cwd", "env", "user", "budget" } },
            { "read_file", new[] { "max_bytes", "budget" } },
            { "write_file", new[] { "budget", "mode" } },
            { "forward", new[] { "budget" } },
            { "poll", new string[0] },
            { "ack", new string[0] },
            { "diag", new[] { "max_entries" } },
            { "exec_result", new[] { "stdout_truncated", "stderr_truncated" } },
            { "file_data", new[] { "truncated" } },
            { "ok", new string[0] },
            { "pending", new string[0] },
            { "forward_ok", new string[0] },
            { "diag_result", new[] { "entries", "listener_restarts" } },
            { "error", new[] { "layer", "partial" } },
            { "realize", new[] { "grants" } },
            { "teardown", new string[0] },
            { "stage", new[] { "detail", "guests" } },
            { "heartbeat", new[] { "guests" } },
        };

        static readonly HashSet<string> BulkKinds =
            new HashSet<string> { "exec", "write_file", "exec_result", "file_data" };

        static long? GetLong(Dictionary<string, object> m, string key)
        {
            object v;
            if (!m.TryGetValue(key, out v)) return null;
            if (!(v is long)) throw new DecodeException(key + " must be an integer");
            return (long)v;
        }

        static string GetString(Dictionary<string, object> m, string key)
        {
            object v;
            if (!m.TryGetValue(key, out v)) return null;
            string s = v as string;
            if (s == null) throw new DecodeException(key + " must be a string");
            return s;
        }

        static bool? GetBool(Dictionary<string, object> m, string key)
        {
            object v;
            if (!m.TryGetValue(key, out v)) return null;
            if (!(v is bool)) throw new DecodeException(key + " must be a boolean");
            return (bool)v;
        }

        static long RequireLong(Dictionary<string, object> m, string key)
        {
            object v;
            if (!m.TryGetValue(key, out v) || !(v is long))
                throw new DecodeException(key + " must be an integer");
            return (long)v;
        }

        public static void Validate(Dictionary<string, object> m)
        {
            string kind = GetString(m, "kind");
            if (kind == null || !RequiredFields.ContainsKey(kind))
                throw new DecodeException("unknown kind \"" + (kind ?? "<absent>") + "\"");
            string id = GetString(m, "id");
            if (id == null || !RequestIdRe.IsMatch(id))
                throw new DecodeException(kind + ": bad request id");

            HashSet<string> allowed = new HashSet<string> { "v", "id", "kind" };
            if (BulkKinds.Contains(kind)) allowed.Add("data_size");
            foreach (string f in RequiredFields[kind])
            {
                allowed.Add(f);
                if (!m.ContainsKey(f))
                    throw new DecodeException(kind + ": missing required field \"" + f + "\"");
            }
            foreach (string f in OptionalFields[kind]) allowed.Add(f);
            foreach (string key in m.Keys)
                if (!allowed.Contains(key))
                    throw new DecodeException(kind + ": field \"" + key + "\" does not belong to this kind");

            long? dataSize = GetLong(m, "data_size");
            if (dataSize.HasValue && (dataSize.Value < 0 || dataSize.Value > MaxBulkDeclarable))
                throw new DecodeException(kind + ": data_size out of bounds");

            foreach (string f in new[] { "elapsed_ms", "uptime_ms", "listener_restarts" })
            {
                long? v = GetLong(m, f);
                if (v.HasValue && (v.Value < 0 || v.Value > MaxWireInt))
                    throw new DecodeException(kind + ": integer field out of bounds");
            }
            // byte-count fields adopt Python's tighter cap (strict side wins)
            foreach (string f in new[] { "max_bytes", "size", "stdout_size", "stderr_size" })
            {
                long? v = GetLong(m, f);
                if (v.HasValue && (v.Value < 0 || v.Value > MaxBulkDeclarable))
                    throw new DecodeException(kind + ": byte-count field out of bounds");
            }

            object budgetObj;
            if (m.TryGetValue("budget", out budgetObj))
            {
                Dictionary<string, object> budget = budgetObj as Dictionary<string, object>;
                if (budget == null) throw new DecodeException(kind + ": budget must be an object");
                foreach (string key in budget.Keys)
                    if (key != "command_ms" && key != "channel_ms" && key != "untimed_bound_ms")
                        throw new DecodeException(kind + ": unknown budget field \"" + key + "\"");
                long outer = DefaultUntimedMs;
                foreach (string f in new[] { "command_ms", "channel_ms", "untimed_bound_ms" })
                {
                    long? v = GetLong(budget, f);
                    if (v.HasValue && (v.Value < 1 || v.Value > MaxWireInt))
                        throw new DecodeException(kind + ": budget field out of bounds");
                    if (f == "untimed_bound_ms" && v.HasValue) outer = v.Value;
                }
                long? command = GetLong(budget, "command_ms");
                if (command.HasValue && command.Value > DefaultUntimedMs)
                    throw new DecodeException(kind + ": command_ms above the cap");
                if (command.HasValue && command.Value > outer)
                    throw new DecodeException(kind + ": untimed_bound_ms must cover command_ms");
            }

            switch (kind)
            {
                case "exec":
                    List<object> cmd = m["cmd"] as List<object>;
                    if (cmd == null || cmd.Count == 0) throw new DecodeException("exec: empty cmd");
                    foreach (object part in cmd)
                        if (!(part is string)) throw new DecodeException("exec: cmd items must be strings");
                    GetString(m, "cwd");
                    GetString(m, "user");
                    object envObj;
                    if (m.TryGetValue("env", out envObj))
                    {
                        Dictionary<string, object> env = envObj as Dictionary<string, object>;
                        if (env == null) throw new DecodeException("exec: env must be an object");
                        foreach (object value in env.Values)
                            if (!(value is string))
                                throw new DecodeException("exec: env values must be strings");
                    }
                    break;
                case "read_file":
                case "write_file":
                    if (GetString(m, "path").Length == 0) throw new DecodeException(kind + ": empty path");
                    if (kind == "write_file" && !dataSize.HasValue)
                        throw new DecodeException("write_file requires data_size");
                    if (kind == "write_file")
                    {
                        long? writeMode = GetLong(m, "mode");
                        if (writeMode.HasValue && (writeMode.Value < 0 || writeMode.Value > 0xFFF))
                            throw new DecodeException("write_file: mode out of range");
                    }
                    break;
                case "poll":
                case "ack":
                case "pending":
                    if (!RequestIdRe.IsMatch(GetString(m, "target_id")))
                        throw new DecodeException(kind + ": bad target id");
                    break;
                case "exec_result":
                    long rc = RequireLong(m, "rc");
                    if (rc < -(1L << 31) || rc > (1L << 31) - 1)
                        throw new DecodeException("exec_result: rc outside int32");
                    long declared = dataSize.HasValue ? dataSize.Value : 0;
                    if (RequireLong(m, "stdout_size") + RequireLong(m, "stderr_size") != declared)
                        throw new DecodeException("exec_result: sizes do not match data_size");
                    GetBool(m, "stdout_truncated");
                    GetBool(m, "stderr_truncated");
                    break;
                case "file_data":
                    long fdDeclared = dataSize.HasValue ? dataSize.Value : 0;
                    if (RequireLong(m, "size") != fdDeclared)
                        throw new DecodeException("file_data: size does not match data_size");
                    GetBool(m, "truncated");
                    break;
                case "error":
                    if (!ErrnoRe.IsMatch(GetString(m, "errno")))
                        throw new DecodeException("error: bad errno shape");
                    if (GetString(m, "message").Length > MaxMessageLen)
                        throw new DecodeException("error: message too long");
                    string errno = (string)m["errno"];
                    if ((errno == "ETIME" || errno == "ETIMEDOUT") && !m.ContainsKey("layer"))
                        throw new DecodeException("error: budget errors must name their layer");
                    if (m.ContainsKey("layer") && !LayerLiterals.Contains(GetString(m, "layer")))
                        throw new DecodeException("error: unknown layer");
                    if (m.ContainsKey("partial"))
                    {
                        if (errno != "ETIME" && errno != "ETIMEDOUT")
                            throw new DecodeException("error: partial output is only legal on budget expiries");
                        if (GetString(m, "partial").Length > MaxMessageLen)
                            throw new DecodeException("error: partial too long");
                    }
                    break;
                case "forward":
                    long port = RequireLong(m, "port");
                    if (port < 1 || port > 65535) throw new DecodeException("forward: bad port");
                    GetString(m, "host");
                    break;
                case "pong":
                    if (GetString(m, "daemon").Length > MaxDaemonLen)
                        throw new DecodeException("pong: daemon too long");
                    long? pongProtocol = GetLong(m, "protocol");
                    if (pongProtocol.HasValue && pongProtocol.Value != ProtocolVersion)
                        throw new DecodeException("pong: protocol must be " + ProtocolVersion);
                    if (!SessionRe.IsMatch(GetString(m, "session")))
                        throw new DecodeException("pong: session must be 32 lowercase hex chars");
                    break;
                case "forward_ok":
                    GetString(m, "handle");
                    break;
                case "stage":
                    if (!StageLiterals.Contains(GetString(m, "stage")))
                        throw new DecodeException("stage: unknown stage");
                    string stageDetail = GetString(m, "detail");
                    if (stageDetail != null && stageDetail.Length > MaxStageDetailLen)
                        throw new DecodeException("stage: detail too long");
                    ValidateGuests(m);
                    break;
                case "heartbeat":
                    ValidateGuests(m);
                    break;
                case "diag_result":
                    ValidateDiagEntries(m);
                    break;
                case "diag":
                    long? maxEntries = GetLong(m, "max_entries");
                    if (maxEntries.HasValue && (maxEntries.Value < 1 || maxEntries.Value > 1000))
                        throw new DecodeException("diag: max_entries out of bounds");
                    break;
                case "realize":
                    if (!Sha256Re.IsMatch(GetString(m, "bundle_digest")))
                        throw new DecodeException("realize: bad bundle digest");
                    object grantsObj;
                    if (m.TryGetValue("grants", out grantsObj))
                    {
                        List<object> grants = grantsObj as List<object>;
                        if (grants == null) throw new DecodeException("realize: grants must be a list");
                        if (grants.Count > MaxGrants) throw new DecodeException("realize: too many grants");
                        foreach (object grant in grants)
                            if (!(grant is string))
                                throw new DecodeException("realize: grants must be strings");
                    }
                    break;
            }
        }

        static void ValidateGuests(Dictionary<string, object> m)
        {
            object guestsObj;
            if (!m.TryGetValue("guests", out guestsObj)) return;
            Dictionary<string, object> guests = guestsObj as Dictionary<string, object>;
            if (guests == null) throw new DecodeException("guests must be an object");
            foreach (object state in guests.Values)
            {
                string name = state as string;
                if (name == null || !GuestStateLiterals.Contains(name))
                    throw new DecodeException("unknown guest state");
            }
        }

        static readonly HashSet<string> DiagEntryFields =
            new HashSet<string> { "ts_ms", "level", "event", "request_id", "detail" };

        static void ValidateDiagEntries(Dictionary<string, object> m)
        {
            object entriesObj;
            if (!m.TryGetValue("entries", out entriesObj)) return;
            List<object> entries = entriesObj as List<object>;
            if (entries == null) throw new DecodeException("diag_result: entries must be a list");
            if (entries.Count > MaxDiagEntries) throw new DecodeException("diag_result: too many entries");
            foreach (object entryObj in entries)
            {
                Dictionary<string, object> entry = entryObj as Dictionary<string, object>;
                if (entry == null) throw new DecodeException("diag_result: entries must be objects");
                foreach (string key in entry.Keys)
                    if (!DiagEntryFields.Contains(key))
                        throw new DecodeException("diag_result: field \"" + key + "\" does not belong to an entry");
                long ts = RequireLong(entry, "ts_ms");
                if (ts < 0 || ts > MaxWireInt)
                    throw new DecodeException("diag_result: ts_ms out of bounds");
                string level = GetString(entry, "level");
                if (level == null || !LevelLiterals.Contains(level))
                    throw new DecodeException("diag_result: unknown level");
                string evt = GetString(entry, "event");
                if (evt == null || evt.Length == 0 || evt.Length > MaxEventLen)
                    throw new DecodeException("diag_result: bad event");
                string requestId = GetString(entry, "request_id");
                if (requestId != null && requestId.Length > MaxRequestIdLen)
                    throw new DecodeException("diag_result: request_id too long");
                string detail = GetString(entry, "detail");
                if (detail != null && detail.Length > MaxDiagDetailLen)
                    throw new DecodeException("diag_result: detail too long");
            }
        }
    }
}
