# vsockd v3 (Windows)

The in-guest control daemon for Windows guests: C# over the viosock winsock provider, protocol v3, mirroring the Go daemon's semantics (per-kind strict decode, dedupe for every request kind with attach-to-in-flight, durable results until acked, ESTALE tombstones, poll/pending, the diag ring buffer, in-guest budgets). The decision to stay C# is deliberate: viosock interop from Go is unproven, while this engine is the proven vsockd-win spike port (40/44 self_check).

## Build story

**In guest (production and battery)**: the in-box .NET Framework 4.8 `csc.exe` compiles `Wire.cs Exec.cs Daemon.cs Program.cs` (all C# 5); no toolchain or download is ever added to images. `install-daemon.ps1` performs the full setup (viosock driver, compile, auto-restart service).

**On the host (the drift guard)**: `Wire.cs` is platform-neutral and compiles under the pinned .NET SDK for the vector round-trip check:

```sh
curl -fsSL -o /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh
bash /tmp/dotnet-install.sh --version 8.0.404 --install-dir "$HOME/.local/dotnet"
~/.local/dotnet/dotnet run --project . -- ../../../../../tests/wire_vectors/v3.json
```

SDK pin: **8.0.404**; `vsockd-win.csproj` pins `LangVersion=5` so everything stays within the in-guest compiler's reach, and compiles only `Wire.cs` + `VectorCheck.cs` (the daemon needs .NET Framework and Windows).

## CI story

`tests/test_cs_codec.py` drives the vector check from the Python suite. Linux CI installs the pinned SDK (8.0.404 by sha256 into `$HOME/.local/dotnet`) and sets `INSPECT_RANGES_REQUIRE_DOTNET=1`, so the guard is enforced there exactly like the Go gate: it fails loudly if the toolchain is absent and skips with a visible reason only on dev machines without the pin. A Windows-behavioral runner (in-box csc.exe build path, real Windows path APIs) remains the recorded follow-up in channel-v1.md for when the build phase resumes Windows work; until then those surfaces are covered by the host-side unit pins plus the in-guest battery.

## Kill semantics (differs from Linux, deliberately)

Windows has no TERM analog: the command budget fires `TerminateJobObject` immediately (the Job is the whole tree); the shared grace constants (`kill_grace_ms` + `wait_delay_ms`, pinned by the wire vectors) bound the post-kill pipe reaping instead, so the host's 12 s observation grace holds unchanged. Escape honesty: plain Job Objects deny `CREATE_BREAKAWAY_FROM_JOB`, so a child cannot simply opt out of the tree-kill; the real escape is asking an out-of-job intermediary (WMI, schtasks, the service manager) to spawn on the caller's behalf, the Windows analog of the documented Linux setsid escape. The ETIME message says so.

## Listener supervision (the nested-virt wedge)

The accept loop runs non-blocking under a poll: accept exceptions AND the wedge signature (listener polls readable but `Accept` keeps refusing) both tear down and recreate the socket with backoff, so recovery never requires `Restart-Service`. The reconnect-storm regression battery (`design/spikes/channel-v1/windows/`) pins this.
