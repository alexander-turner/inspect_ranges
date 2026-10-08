// The exec engine, ported from the proven spike (vsockd-win): CreateProcess /
// CreateProcessAsUser with Job Objects for tree-kill, capped pipe readers,
// standard Windows argv quoting, errno mapping. v3 changes only the result
// shape (raw bytes for the bulk, ETIME via the caller) and aligns the
// post-kill reaping to the shared grace constants.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VsockD
{
    static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        public const uint CREATE_SUSPENDED = 0x4;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x400;
        public const int STARTF_USESTDHANDLES = 0x100;
        public const uint INFINITE = 0xFFFFFFFF;
        public const uint WAIT_TIMEOUT = 0x102;
        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_PROVIDER_DEFAULT = 0;
        public const uint HANDLE_FLAG_INHERIT = 1;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES sa, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(IntPtr token, string app, StringBuilder cmd, IntPtr pa, IntPtr ta,
            bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUserW(string user, string domain, string pass, int type, int provider, out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateJobObject(IntPtr attrs, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr h, uint ms);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr h, out uint code);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("winmm.dll")]
        public static extern uint timeBeginPeriod(uint ms);
    }

    static class Config
    {
        public static string PasswordFor(string user)
        {
            try
            {
                string path = Path.Combine(Daemon.BaseDir, "users.txt");
                if (!File.Exists(path)) return null;
                foreach (string line in File.ReadAllLines(path))
                {
                    int i = line.IndexOf(':');
                    if (i > 0 && line.Substring(0, i).Equals(user, StringComparison.OrdinalIgnoreCase))
                        return line.Substring(i + 1);
                }
            }
            catch (Exception) { }
            return null;
        }
    }

    sealed class CappedPipeReader
    {
        public const int OUTPUT_CAP = 16 * 1024 * 1024;
        private readonly object _lock = new object();
        private readonly MemoryStream _head = new MemoryStream();
        public long Total;
        private readonly FileStream _fs;
        public Thread Thread;

        public CappedPipeReader(IntPtr handle)
        {
            _fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(handle, true), FileAccess.Read);
            Thread = new Thread(Run);
            Thread.IsBackground = true;
            Thread.Start();
        }

        public byte[] Snapshot()
        {
            lock (_lock) { return _head.ToArray(); }
        }

        public void ForceClose()
        {
            try { _fs.Close(); } catch (Exception) { }
        }

        private void Run()
        {
            byte[] buf = new byte[1 << 16];
            try
            {
                while (true)
                {
                    int n = _fs.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    lock (_lock)
                    {
                        Total += n;
                        if (_head.Length < OUTPUT_CAP)
                            _head.Write(buf, 0, (int)Math.Min(n, OUTPUT_CAP - _head.Length));
                    }
                }
            }
            catch (Exception) { }
            finally { try { _fs.Close(); } catch (Exception) { } }
        }
    }

    sealed class ExecOutcome
    {
        public bool TimedOut;
        public long Rc;
        public byte[] Stdout = new byte[0];
        public byte[] Stderr = new byte[0];
        public bool StdoutTruncated;
        public bool StderrTruncated;
        public string Errno;        // set for non-exec failures (ENOENT cwd etc.)
        public string ErrorMessage;

        public static ExecOutcome Error(string errno, string message)
        {
            ExecOutcome o = new ExecOutcome();
            o.Errno = errno;
            o.ErrorMessage = message;
            return o;
        }

        public static ExecOutcome Failure(long rc, string stderr)
        {
            ExecOutcome o = new ExecOutcome();
            o.Rc = rc;
            o.Stderr = Encoding.UTF8.GetBytes(stderr);
            return o;
        }
    }

    static class ExecEngine
    {
        public static ExecOutcome Run(List<string> argv, string cwd, Dictionary<string, string> envOverrides,
            string user, long commandMs, byte[] stdin)
        {
            if (cwd != null)
            {
                if (File.Exists(cwd)) return ExecOutcome.Error("ENOTDIR", "not a directory: " + cwd);
                if (!Directory.Exists(cwd)) return ExecOutcome.Error("ENOENT", "no such directory: " + cwd);
            }

            IntPtr token = IntPtr.Zero;
            if (user != null)
            {
                string password = Config.PasswordFor(user);
                if (password == null)
                    return ExecOutcome.Failure(1, "user " + user + " does not exist or has no configured credentials");
                if (!Native.LogonUserW(user, ".", password, Native.LOGON32_LOGON_INTERACTIVE,
                        Native.LOGON32_PROVIDER_DEFAULT, out token))
                    return ExecOutcome.Failure(1, "logon failed for user " + user + " (error " +
                        Marshal.GetLastWin32Error() + ")");
            }

            try { return RunWithToken(argv, cwd, envOverrides, token, commandMs, stdin); }
            finally { if (token != IntPtr.Zero) Native.CloseHandle(token); }
        }

        private static ExecOutcome RunWithToken(List<string> argv, string cwd,
            Dictionary<string, string> envOverrides, IntPtr token, long commandMs, byte[] stdin)
        {
            StringBuilder cmdline = new StringBuilder(BuildCommandLine(argv));
            if (cmdline.Length > 32766)
                return ExecOutcome.Error("E2BIG",
                    "command line too long: " + cmdline.Length + " chars (Windows limit 32767)");

            Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
            sa.bInheritHandle = true;

            IntPtr stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW;
            if (!Native.CreatePipe(out stdinR, out stdinW, ref sa, 0) ||
                !Native.CreatePipe(out stdoutR, out stdoutW, ref sa, 0) ||
                !Native.CreatePipe(out stderrR, out stderrW, ref sa, 0))
                return ExecOutcome.Error("EIO", "pipe creation failed");
            Native.SetHandleInformation(stdinW, Native.HANDLE_FLAG_INHERIT, 0);
            Native.SetHandleInformation(stdoutR, Native.HANDLE_FLAG_INHERIT, 0);
            Native.SetHandleInformation(stderrR, Native.HANDLE_FLAG_INHERIT, 0);

            Native.STARTUPINFO si = new Native.STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(Native.STARTUPINFO));
            si.dwFlags = Native.STARTF_USESTDHANDLES;
            si.hStdInput = stdinR;
            si.hStdOutput = stdoutW;
            si.hStdError = stderrW;
            si.lpDesktop = "";

            IntPtr envBlock = BuildEnvBlock(envOverrides);
            uint flags = Native.CREATE_SUSPENDED | Native.CREATE_NO_WINDOW | Native.CREATE_UNICODE_ENVIRONMENT;

            Native.PROCESS_INFORMATION pi;
            bool ok;
            if (token == IntPtr.Zero)
                ok = Native.CreateProcessW(null, cmdline, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi);
            else
                ok = Native.CreateProcessAsUserW(token, null, cmdline, IntPtr.Zero, IntPtr.Zero, true, flags, envBlock, cwd, ref si, out pi);

            Marshal.FreeHGlobal(envBlock);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                Native.CloseHandle(stdinR); Native.CloseHandle(stdinW);
                Native.CloseHandle(stdoutR); Native.CloseHandle(stdoutW);
                Native.CloseHandle(stderrR); Native.CloseHandle(stderrW);
                if (err == 2 || err == 3)
                    return ExecOutcome.Failure(127, "command not found: " + argv[0]);
                if (err == 5 || err == 193)
                    return ExecOutcome.Failure(126, "permission denied: " + argv[0]);
                return ExecOutcome.Error("EIO", "CreateProcess failed (error " + err + ")");
            }

            IntPtr job = Native.CreateJobObject(IntPtr.Zero, null);
            bool assigned = job != IntPtr.Zero && Native.AssignProcessToJobObject(job, pi.hProcess);
            if (!assigned)
            {
                // capture the cause FIRST: every cleanup call below overwrites
                // the thread's last-error slot
                int jobErr = Marshal.GetLastWin32Error();
                // without a Job the budget kill would be a silent no-op:
                // kill the still-suspended child (it never joined the job,
                // so TerminateJobObject reaches nothing) and refuse the exec
                Native.TerminateProcess(pi.hProcess, 1);
                Native.CloseHandle(pi.hThread);
                Native.CloseHandle(pi.hProcess);
                if (job != IntPtr.Zero) Native.CloseHandle(job);
                Native.CloseHandle(stdinR); Native.CloseHandle(stdinW);
                Native.CloseHandle(stdoutR); Native.CloseHandle(stdoutW);
                Native.CloseHandle(stderrR); Native.CloseHandle(stderrW);
                return ExecOutcome.Error("EIO",
                    "job object unavailable (error " + jobErr +
                    "); refusing an unbudgetable exec");
            }
            Native.ResumeThread(pi.hThread);
            Native.CloseHandle(pi.hThread);
            Native.CloseHandle(stdinR);
            Native.CloseHandle(stdoutW);
            Native.CloseHandle(stderrW);

            CappedPipeReader outReader = new CappedPipeReader(stdoutR);
            CappedPipeReader errReader = new CappedPipeReader(stderrR);

            Thread stdinWriter = new Thread(delegate ()
            {
                FileStream w = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(stdinW, true), FileAccess.Write);
                try { if (stdin != null && stdin.Length > 0) w.Write(stdin, 0, stdin.Length); }
                catch (Exception) { }
                finally { w.Close(); }
            });
            stdinWriter.IsBackground = true;
            stdinWriter.Start();

            long deadlineTicks;
            long now = DateTime.UtcNow.Ticks;
            if (commandMs > (long.MaxValue - now) / TimeSpan.TicksPerMillisecond)
                deadlineTicks = long.MaxValue; // clamp: huge budgets never wrap negative
            else
                deadlineTicks = now + commandMs * TimeSpan.TicksPerMillisecond;

            bool timedOut = false;
            if (Native.WaitForSingleObject(pi.hProcess, RemainingMs(deadlineTicks)) == Native.WAIT_TIMEOUT)
                timedOut = true;
            if (!timedOut)
            {
                // the process exited: pipe reaping gets ONE shared WaitDelay
                // budget across BOTH joins (the cmd.WaitDelay analog), never
                // the command budget. Closing our FileStream does NOT cancel
                // a blocked anonymous-pipe read; the real guarantee is that
                // the reply returns now, and a lingering reader is a bounded
                // background thread that dies with the pipe's write handles.
                long reapDeadline = DateTime.UtcNow.Ticks +
                    (long)Daemon.WaitDelayMs * TimeSpan.TicksPerMillisecond;
                if (!outReader.Thread.Join(RemainingJoinMs(reapDeadline)))
                    outReader.ForceClose();
                if (!errReader.Thread.Join(RemainingJoinMs(reapDeadline)))
                    errReader.ForceClose();
                outReader.Thread.Join(1000);
                errReader.Thread.Join(1000);
            }

            ExecOutcome outcome = new ExecOutcome();
            if (timedOut)
            {
                // Windows has no TERM analog: the budget kills the Job (the
                // whole tree) immediately; the shared grace constants bound
                // the post-kill reaping. Worst case here is KillGraceMs (5 s)
                // + ONE shared WaitDelayMs across both joins (5 s) + the 1 s
                // stdin join = 11 s, inside the host's 12 s observation grace.
                Native.TerminateJobObject(job, 1);
                Native.WaitForSingleObject(pi.hProcess, (uint)Daemon.KillGraceMs);
                long killReapDeadline = DateTime.UtcNow.Ticks +
                    (long)Daemon.WaitDelayMs * TimeSpan.TicksPerMillisecond;
                outReader.Thread.Join(RemainingJoinMs(killReapDeadline));
                errReader.Thread.Join(RemainingJoinMs(killReapDeadline));
                outcome.TimedOut = true;
            }
            else
            {
                uint rc;
                Native.GetExitCodeProcess(pi.hProcess, out rc);
                // signed int32 convention (the Windows unsigned-32 lesson)
                outcome.Rc = (int)rc;
                outcome.Stdout = outReader.Snapshot();
                outcome.Stderr = errReader.Snapshot();
                outcome.StdoutTruncated = outReader.Total > CappedPipeReader.OUTPUT_CAP;
                outcome.StderrTruncated = errReader.Total > CappedPipeReader.OUTPUT_CAP;
            }
            stdinWriter.Join(1000);
            Native.CloseHandle(pi.hProcess);
            Native.CloseHandle(job); // no KILL_ON_CLOSE: background children survive
            return outcome;
        }

        private static uint RemainingMs(long deadlineTicks)
        {
            long ms = (deadlineTicks - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond;
            return ms <= 0 ? 0 : (uint)Math.Min(ms, uint.MaxValue - 1);
        }

        private static int RemainingJoinMs(long deadlineTicks)
        {
            long ms = (deadlineTicks - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond;
            return ms <= 0 ? 0 : (int)Math.Min(ms, int.MaxValue);
        }

        public static string BuildCommandLine(List<string> argv)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < argv.Count; i++)
            {
                if (i > 0) sb.Append(' ');
                string a = argv[i];
                bool needQuote = a.Length == 0 || a.IndexOfAny(new char[] { ' ', '\t', '"' }) >= 0;
                if (!needQuote) { sb.Append(a); continue; }
                sb.Append('"');
                int backslashes = 0;
                foreach (char c in a)
                {
                    if (c == '\\') { backslashes++; continue; }
                    if (c == '"')
                    {
                        sb.Append('\\', backslashes * 2 + 1);
                        sb.Append('"');
                        backslashes = 0;
                        continue;
                    }
                    sb.Append('\\', backslashes);
                    backslashes = 0;
                    sb.Append(c);
                }
                sb.Append('\\', backslashes * 2);
                sb.Append('"');
            }
            return sb.ToString();
        }

        private static IntPtr BuildEnvBlock(Dictionary<string, string> overrides)
        {
            SortedDictionary<string, string> env =
                new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry e in Environment.GetEnvironmentVariables())
                env[(string)e.Key] = (string)e.Value;
            if (overrides != null)
                foreach (KeyValuePair<string, string> kv in overrides)
                    env[kv.Key] = kv.Value;

            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kv in env)
            {
                sb.Append(kv.Key); sb.Append('='); sb.Append(kv.Value); sb.Append('\0');
            }
            sb.Append('\0');
            return Marshal.StringToHGlobalUni(sb.ToString());
        }
    }
}
