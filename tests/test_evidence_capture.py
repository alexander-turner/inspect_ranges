"""The capture streamer and the sidecar supervisor (evidence-v1 slice 2, CI side).

The streamer runs against a directory-backed tap simulating the capture volume; the supervisor runs as a real python3 subprocess with a stub `tcpdump`, so its lifecycle (bridge wait, bounded restarts, disk cap, stop protocol, kernel-drop parsing) is exercised for real without a range. The devbox battery (`design/spikes/evidence-v1/`) covers the live end.
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from inspect_ranges._evidence import (
    CaptureStreamer,
    ClockStamp,
    EvidenceWriter,
    LocalDirSink,
    LocalDirStore,
    LocalTap,
    StageRecorder,
    verify_location,
)
from inspect_ranges._evidence.supervisor import SUPERVISOR_SOURCE

# ---------------------------------------------------------------------------
# streamer over a directory-backed tap
# ---------------------------------------------------------------------------


def write_status(
    root: Path,
    segments: dict[str, dict[str, Any]],
    *,
    stopped: bool = False,
) -> None:
    defaults: dict[str, Any] = {
        "state": "running",
        "restarts": 0,
        "active": None,
        "kernel_drops": 0,
        "dropped_bytes": 0,
        "dropped_files": 0,
    }
    status = {
        "ts": time.time(),
        "stopped": stopped,
        "segments": {name: {**defaults, **entry} for name, entry in segments.items()},
    }
    (root / "status.json").write_text(json.dumps(status))


def harness(
    tmp_path: Path, **writer_kwargs: Any
) -> tuple[Path, Path, EvidenceWriter, LocalTap]:
    location = tmp_path / "evidence"
    capture = tmp_path / "capture"
    consoles = tmp_path / "consoles"
    capture.mkdir()
    consoles.mkdir()
    writer = EvidenceWriter(
        LocalDirSink(location), part_interval_s=0, writer="host", **writer_kwargs
    )
    return location, capture, writer, LocalTap(capture, consoles)


async def one_cycle(streamer: CaptureStreamer) -> None:
    await streamer.poll_once()


def test_streamer_ships_completed_chunks_and_skips_active(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        (capture / "dmz" / "g0.pcap").write_bytes(b"chunk-zero")
        (capture / "dmz" / "g0.pcap1").write_bytes(b"chunk-one-active")
        write_status(capture, {"dmz": {"active": "dmz/g0.pcap1"}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)
        # completed chunk shipped and removed; active left in place
        assert not (capture / "dmz" / "g0.pcap").exists()
        assert (capture / "dmz" / "g0.pcap1").exists()
        # rotation completes: next cycle ships the former active
        (capture / "dmz" / "g0.pcap2").write_bytes(b"next-active")
        write_status(capture, {"dmz": {"active": "dmz/g0.pcap2"}})
        await one_cycle(streamer)
        write_status(
            capture, {"dmz": {"active": None, "state": "stopped"}}, stopped=True
        )
        await streamer.stop(stop_timeout_s=2.0)
        seal, _ = await writer.seal()
        assert seal.status == "complete"
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        pcap = report.writers["host"].streams["pcap/dmz"]
        assert pcap.chunks == 3 and pcap.size == len(
            b"chunk-zero" + b"chunk-one-active" + b"next-active"
        )

    asyncio.run(scenario())


def test_streamer_turns_status_losses_into_gaps(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        write_status(capture, {"dmz": {}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)
        write_status(
            capture,
            {
                "dmz": {
                    "state": "exhausted",
                    "restarts": 2,
                    "kernel_drops": 43308,
                    "dropped_bytes": 4096,
                    "dropped_files": 1,
                }
            },
        )
        await one_cycle(streamer)
        await one_cycle(streamer)  # same status again: deltas fire exactly once
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        causes = sorted(gap.cause for gap in report.writers["host"].gaps)
        assert causes == [
            "capture-cap",
            "capture-dead",
            "capture-restart",
            "kernel-drops",
        ]
        cap_gap = next(
            g for g in report.writers["host"].gaps if g.cause == "capture-cap"
        )
        assert cap_gap.dropped == 4096

    asyncio.run(scenario())


def test_streamer_tails_consoles_and_reports_truncation(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        console = tmp_path / "consoles" / "web.log"
        write_status(capture, {})
        streamer = CaptureStreamer(writer, tap, segments=[], console_guests=["web"])
        await one_cycle(streamer)  # no console file yet: routine, not an error
        console.write_bytes(b"boot line one\n")
        await one_cycle(streamer)
        console.write_bytes(b"boot line one\nboot line two\n")
        await one_cycle(streamer)
        console.write_bytes(b"fresh\n")  # shrank: truncation
        await one_cycle(streamer)  # gap recorded, offset reset
        await one_cycle(streamer)  # post-truncation content ships from zero
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        stream = report.writers["host"].streams["console/web"]
        assert stream.chunks == 3  # two increments plus the post-truncation content
        truncated = [
            g for g in report.writers["host"].gaps if g.cause == "console-truncated"
        ]
        assert len(truncated) == 1
        store = LocalDirStore(location)
        shipped = b"".join(
            [await store.get(f"chunks/host/console/web/{i:06d}.bin") for i in (0, 1)]
        )
        assert shipped == b"boot line one\nboot line two\n"

    asyncio.run(scenario())


def test_streamer_ships_capture_stderr_incrementally(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        write_status(capture, {"dmz": {}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        (capture / "dmz" / "stderr.log").write_bytes(b"listening on br-dmz\n")
        await one_cycle(streamer)
        (capture / "dmz" / "stderr.log").write_bytes(
            b"listening on br-dmz\n43308 packets dropped by kernel\n"
        )
        await one_cycle(streamer)
        await writer.seal()
        store = LocalDirStore(location)
        first = await store.get("chunks/host/capture-stderr/dmz/000000.bin")
        second = await store.get("chunks/host/capture-stderr/dmz/000001.bin")
        assert first == b"listening on br-dmz\n"
        assert second == b"43308 packets dropped by kernel\n"

    asyncio.run(scenario())


def test_stage_recorder_routes_stages_and_verify(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        write_status(capture, {})
        recorder = StageRecorder()
        recorder.on_stage("range-container", "ok", {})
        recorder.on_stage("readiness", "ok", {"guest": "web"})
        recorder.on_stage("ready", "ok", {"seconds": 47.0})
        streamer = CaptureStreamer(
            writer, tap, segments=[], console_guests=[], stage_recorder=recorder
        )
        await one_cycle(streamer)
        await writer.seal()
        store = LocalDirStore(location)
        stages = (
            (await store.get("chunks/host/stages/000000.bin")).decode().splitlines()
        )
        verify = (
            (await store.get("chunks/host/verify/000000.bin")).decode().splitlines()
        )
        assert [json.loads(line)["stage"] for line in stages] == [
            "range-container",
            "readiness",
            "ready",
        ]
        assert [json.loads(line)["stage"] for line in verify] == ["readiness", "ready"]
        assert all("wall" in json.loads(line) for line in stages)

    asyncio.run(scenario())


def test_streamer_records_wall_jump(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        write_status(capture, {})
        stamps = iter(
            [
                ClockStamp(wall=1000.0, monotonic=10.0),
                ClockStamp(wall=1600.0, monotonic=11.0),  # wall leapt 600s in 1s
            ]
        )

        def clock() -> ClockStamp:
            return next(stamps)

        streamer = CaptureStreamer(
            writer, tap, segments=[], console_guests=[], clock=clock
        )
        await one_cycle(streamer)
        await one_cycle(streamer)
        await writer.seal()
        store = LocalDirStore(location)
        records = [
            json.loads(line)
            for i in (0, 1)
            for line in (await store.get(f"chunks/host/clock/{i:06d}.bin"))
            .decode()
            .splitlines()
        ]
        jumps = [r for r in records if r["kind"] == "wall-jump"]
        assert len(jumps) == 1 and jumps[0]["drift_s"] > 500

    asyncio.run(scenario())


def test_stop_bounds_a_wedged_final_harvest(tmp_path: Path) -> None:
    """A tap that wedges at the final harvest: stop() returns within its harvest bound with explicit harvest-timeout gaps instead of holding the caller's finalize budget hostage (quality-review A6)."""
    import time as time_mod

    class WedgedHarvestTap:
        def __init__(self, backing: LocalTap) -> None:
            self._backing = backing

        def read_status(self) -> bytes:
            return self._backing.read_status()

        def list_segment_files(self, segment: str) -> list[str]:
            time_mod.sleep(30.0)  # the wedged docker compose cp shape
            return []

        def read_file(self, relpath: str) -> bytes:
            return self._backing.read_file(relpath)

        def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]:
            return self._backing.read_tail(relpath, offset)

        def remove_file(self, relpath: str) -> None:
            self._backing.remove_file(relpath)

        def request_stop(self) -> None:
            self._backing.request_stop()

        def read_console(self, guest: str, offset: int) -> tuple[int, bytes]:
            return self._backing.read_console(guest, offset)

    async def scenario() -> None:
        location, capture, writer, backing = harness(tmp_path)
        # a stopped sidecar with a trustworthy status: the harvest proceeds to
        # the (wedged) listing instead of being skipped by the ship bound
        write_status(
            capture, {"dmz": {"active": None, "state": "stopped"}}, stopped=True
        )
        streamer = CaptureStreamer(
            writer, WedgedHarvestTap(backing), segments=["dmz"], console_guests=[]
        )
        started = time_mod.monotonic()
        await streamer.stop(stop_timeout_s=0.5, harvest_timeout_s=0.3)
        assert time_mod.monotonic() - started < 10.0, "stop stays bounded"
        await writer.seal("incomplete")
        report = await verify_location(LocalDirStore(location))
        causes = {gap.cause for gap in report.writers["host"].gaps}
        assert "harvest-timeout" in causes, f"gaps: {causes}"

    asyncio.run(scenario())


def test_streamer_survives_a_hostile_tap(tmp_path: Path) -> None:
    class HostileTap:
        def read_status(self) -> bytes:
            raise RuntimeError("no status for you")

        def list_segment_files(self, segment: str) -> list[str]:
            raise OSError("no listing")

        def read_file(self, relpath: str) -> bytes:
            raise OSError("no bytes")

        def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]:
            raise OSError("no tail")

        def claim_file(self, relpath: str) -> None:
            raise OSError("no claim")

        def remove_file(self, relpath: str) -> None:
            raise OSError("no removal")

        def request_stop(self) -> None:
            raise RuntimeError("unreachable")

        def read_console(self, guest: str, offset: int) -> tuple[int, bytes]:
            raise OSError("no console")

    async def scenario() -> None:
        location = tmp_path / "evidence"
        writer = EvidenceWriter(
            LocalDirSink(location), part_interval_s=0, writer="host"
        )
        streamer = CaptureStreamer(
            writer, HostileTap(), segments=["dmz"], console_guests=["web"]
        )
        await one_cycle(streamer)
        await streamer.stop(stop_timeout_s=0.5)
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok and report.writers["host"].sealed
        causes = {gap.cause for gap in report.writers["host"].gaps}
        assert "capture-unreachable" in causes
        # tap trouble is observable in the shipped heartbeat, not internals
        store = LocalDirStore(location)
        first_heartbeat = json.loads(
            (await store.get("chunks/host/heartbeat/000000.bin"))
            .decode()
            .splitlines()[0]
        )
        assert first_heartbeat["source"] == "streamer"
        assert first_heartbeat["tap_errors"] > 0
        assert first_heartbeat["status_available"] is False

    asyncio.run(scenario())


def test_stop_never_raises_against_a_sealed_writer(tmp_path: Path) -> None:
    """stop() is the teardown call: an already-sealed writer plus an unreachable sidecar must not raise (chunk-1 verification probe)."""

    class UnreachableTap:
        def read_status(self) -> bytes:
            raise RuntimeError("unreachable")

        def list_segment_files(self, segment: str) -> list[str]:
            raise OSError("unreachable")

        def read_file(self, relpath: str) -> bytes:
            raise OSError("unreachable")

        def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]:
            raise OSError("unreachable")

        def claim_file(self, relpath: str) -> None:
            raise OSError("unreachable")

        def remove_file(self, relpath: str) -> None:
            raise OSError("unreachable")

        def request_stop(self) -> None:
            raise RuntimeError("unreachable")

        def read_console(self, guest: str, offset: int) -> tuple[int, bytes]:
            raise OSError("unreachable")

    async def scenario() -> None:
        writer = EvidenceWriter(
            LocalDirSink(tmp_path / "evidence"), part_interval_s=0, writer="host"
        )
        streamer = CaptureStreamer(
            writer, UnreachableTap(), segments=["dmz"], console_guests=[]
        )
        await writer.seal()  # out-of-order teardown: sealed before stop
        await streamer.stop(stop_timeout_s=0.2)  # must return, never raise

    asyncio.run(scenario())


def test_streamer_start_stop_lifecycle(tmp_path: Path) -> None:
    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        (capture / "dmz" / "g0.pcap").write_bytes(b"only-chunk")
        write_status(
            capture, {"dmz": {"active": None, "state": "stopped"}}, stopped=True
        )
        streamer = CaptureStreamer(
            writer, tap, segments=["dmz"], console_guests=[], poll_s=0.05
        )
        await streamer.start()
        await streamer.start()  # idempotent
        await asyncio.sleep(0.2)
        await streamer.stop(stop_timeout_s=2.0)
        assert (capture / "stop").exists()
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        assert report.writers["host"].streams["pcap/dmz"].chunks == 1
        heartbeat = report.writers["host"].streams["heartbeat"]
        assert heartbeat.chunks >= 1

    asyncio.run(scenario())


def test_streamer_ships_nothing_without_a_status_claim(tmp_path: Path) -> None:
    """No status (or no segment entry) means active is unknown: shipping would risk a half-written chunk."""

    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        (capture / "dmz" / "g0.pcap").write_bytes(b"maybe-active")
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)  # no status.json at all
        write_status(capture, {})  # status without a dmz entry
        await one_cycle(streamer)
        assert (capture / "dmz" / "g0.pcap").exists()
        store = LocalDirStore(location)
        assert await store.list("chunks/host/pcap") == []

    asyncio.run(scenario())


def test_streamer_never_ships_at_or_past_the_declared_active(tmp_path: Path) -> None:
    """A stale status must fail safe: files at or past the declared active may still be open."""

    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        for name, content in (
            ("g0.pcap", b"old-completed"),
            ("g0.pcap1", b"declared-active"),
            ("g0.pcap2", b"newer-than-declared"),  # rotation outran the status
        ):
            (capture / "dmz" / name).write_bytes(content)
        write_status(capture, {"dmz": {"active": "dmz/g0.pcap1"}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)
        assert not (capture / "dmz" / "g0.pcap").exists()
        assert (capture / "dmz" / "g0.pcap1").exists()
        assert (capture / "dmz" / "g0.pcap2").exists()
        # a writer-less state ships everything on disk
        write_status(capture, {"dmz": {"active": None, "state": "restarting"}})
        await one_cycle(streamer)
        assert list((capture / "dmz").glob("g*.pcap*")) == []
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        assert report.writers["host"].streams["pcap/dmz"].chunks == 3

    asyncio.run(scenario())


def test_evidence_names_refuse_at_planning(tmp_path: Path) -> None:
    from inspect_ranges._compiler import PlanOptions, resolve_plan
    from inspect_ranges.types import IssueError

    from tests.test_compiler import two_segment_spec

    spec = two_segment_spec()
    spec = spec.model_copy(
        update={
            "hosts": [spec.hosts[0].model_copy(update={"name": "Web"})] + spec.hosts[1:]
        }
    )
    resolve_plan(spec, PlanOptions())  # fine without capture
    try:
        resolve_plan(spec, PlanOptions(evidence_capture=True))
        raise AssertionError("expected evidence-capture-name refusal")
    except IssueError as error:
        assert [issue.code for issue in error.issues] == ["evidence-capture-name"]


# ---------------------------------------------------------------------------
# the supervisor as a real subprocess with a stub tcpdump
# ---------------------------------------------------------------------------

STUB_TCPDUMP = """\
#!/usr/bin/env python3
import os, signal, sys, time

base = sys.argv[sys.argv.index("-w") + 1]


def summary(signum=None, frame=None):
    sys.stderr.write("7 packets dropped by kernel\\n")
    sys.stderr.flush()
    sys.exit(0)


mode = os.environ.get("STUB_MODE", "run")
with open(base, "wb") as handle:
    handle.write(b"PCAP" + mode.encode())
if mode == "exit":
    sys.stderr.write("3 packets dropped by kernel\\n")
    sys.exit(1)
with open(base + "1", "wb") as handle:
    handle.write(b"PCAP-rotated")
signal.signal(signal.SIGTERM, summary)
while True:
    time.sleep(0.05)
"""


class Supervisor:
    """One supervisor subprocess over tmp directories and the stub tcpdump."""

    def __init__(
        self, tmp_path: Path, *, mode: str = "run", env: dict[str, str] | None = None
    ) -> None:
        self.capture = tmp_path / "capture"
        self.render = tmp_path / "render"
        self.netdev = tmp_path / "netdev"
        for directory in (self.capture, self.render / "capture", self.netdev):
            directory.mkdir(parents=True, exist_ok=True)
        (self.render / "capture" / "bridges.tsv").write_text("dmz\tbr-dmz\n")
        stub = tmp_path / "tcpdump-stub"
        stub.write_text(STUB_TCPDUMP)
        stub.chmod(0o755)
        self.env = {
            **os.environ,
            "CAPTURE_DIR": str(self.capture),
            "RENDER_DIR": str(self.render),
            "NETDEV_DIR": str(self.netdev),
            "CAPTURE_TCPDUMP": str(stub),
            "CAPTURE_POLL_S": "0.05",
            "CAPTURE_MAX_RESTARTS": "2",
            "STUB_MODE": mode,
            **(env or {}),
        }
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-c", SUPERVISOR_SOURCE], env=self.env
        )

    def status(self) -> dict[str, Any] | None:
        path = self.capture / "status.json"
        try:
            parsed: Any = json.loads(path.read_text())
            return dict(parsed)
        except (OSError, ValueError):
            return None

    def wait_for(
        self, predicate: Callable[[dict[str, Any]], bool], timeout: float = 10.0
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.status()
            if status is not None and predicate(status):
                return status
            time.sleep(0.05)
        raise AssertionError(f"supervisor never reached state; last: {self.status()}")

    def finish(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def test_supervisor_waits_starts_and_stops(tmp_path: Path) -> None:
    supervisor = Supervisor(tmp_path)
    try:
        supervisor.start()
        supervisor.wait_for(lambda s: s["segments"]["dmz"]["state"] == "waiting")
        (supervisor.netdev / "br-dmz").touch()  # the bridge appears
        supervisor.wait_for(lambda s: s["segments"]["dmz"]["state"] == "running")
        # the stub writes its rotated pair on startup; the active file is the newest
        supervisor.wait_for(lambda s: s["segments"]["dmz"]["active"] == "dmz/g0.pcap1")
        (supervisor.capture / "stop").touch()
        final = supervisor.wait_for(lambda s: s["stopped"] is True)
        assert final["segments"]["dmz"]["state"] == "stopped"
        assert (
            final["segments"]["dmz"]["kernel_drops"] == 7
        )  # parsed from the exit summary
        assert final["segments"]["dmz"]["active"] is None
        # idles for the final harvest instead of exiting
        assert supervisor.proc is not None and supervisor.proc.poll() is None
    finally:
        supervisor.finish()
    assert supervisor.proc is not None and supervisor.proc.wait(timeout=10) == 0


def test_supervisor_bounds_restarts(tmp_path: Path) -> None:
    supervisor = Supervisor(tmp_path, mode="exit")
    try:
        supervisor.start()
        (supervisor.netdev / "br-dmz").touch()
        final = supervisor.wait_for(
            lambda s: s["segments"]["dmz"]["state"] == "exhausted"
        )
        assert final["segments"]["dmz"]["restarts"] == 2
        # one appended summary line per generation; the running total sums them
        assert final["segments"]["dmz"]["kernel_drops"] == 9
        # a restarted capture never reuses a generation basename
        names = sorted(p.name for p in (supervisor.capture / "dmz").glob("g*.pcap*"))
        assert names == ["g0.pcap", "g1.pcap", "g2.pcap"]
    finally:
        supervisor.finish()


def test_supervisor_keeps_restart_budget_while_bridge_absent(tmp_path: Path) -> None:
    """A dead capture plus a missing bridge must wait in `restarting`, not burn the budget."""
    supervisor = Supervisor(
        tmp_path,
        mode="exit",
        env={"CAPTURE_MAX_RESTARTS": "50", "CAPTURE_POLL_S": "0.1"},
    )
    try:
        supervisor.start()
        (supervisor.netdev / "br-dmz").touch()
        supervisor.wait_for(lambda s: s["segments"]["dmz"]["restarts"] >= 1)
        (supervisor.netdev / "br-dmz").unlink()  # the bridge disappears
        time.sleep(0.5)  # let any in-flight start settle
        first = supervisor.wait_for(
            lambda s: s["segments"]["dmz"]["state"] == "restarting"
        )
        time.sleep(1.0)  # ten polls with the bridge absent
        second = supervisor.status()
        assert second is not None
        assert second["segments"]["dmz"]["state"] == "restarting"
        assert (
            second["segments"]["dmz"]["restarts"]
            == first["segments"]["dmz"]["restarts"]
        )
    finally:
        supervisor.finish()


def test_supervisor_enforces_disk_cap(tmp_path: Path) -> None:
    supervisor = Supervisor(tmp_path, env={"CAPTURE_CAP_MB": "1"})
    segment = supervisor.capture / "dmz"
    segment.mkdir()
    for index in range(4):
        path = segment / ("g0.pcap" + (str(index) if index else ""))
        path.write_bytes(b"x" * 600_000)
        os.utime(path, (1000.0 + index, 1000.0 + index))
    try:
        supervisor.start()  # bridge never appears: cap enforcement runs regardless
        final = supervisor.wait_for(
            lambda s: s["segments"]["dmz"]["dropped_files"] >= 3
        )
        # 2.4 MB on disk against a 1 MiB cap: three oldest files go
        assert final["segments"]["dmz"]["dropped_bytes"] == 1_800_000
        survivors = sorted(p.name for p in segment.glob("g0.pcap*"))
        assert survivors == ["g0.pcap3"]  # oldest deleted first
    finally:
        supervisor.finish()


# -- B13: shipped bytes can never be reported as capture-cap loss ---------------


def test_shipped_chunk_is_claimed_and_removal_retries_without_reship(
    tmp_path: Path,
) -> None:
    """The streamer claims (renames) a completed chunk before shipping, so the sidecar's cap accounting can no longer see it; a failed removal retries next cycle without a second append."""

    class RemoveOnceFailsTap(LocalTap):
        def __init__(self, root: Path, console_dir: Path) -> None:
            super().__init__(root, console_dir)
            self.failures = 1

        def remove_file(self, relpath: str) -> None:
            if self.failures > 0:
                self.failures -= 1
                raise OSError("removal unavailable")
            super().remove_file(relpath)

    async def scenario() -> None:
        location = tmp_path / "evidence"
        capture = tmp_path / "capture"
        consoles = tmp_path / "consoles"
        capture.mkdir()
        consoles.mkdir()
        writer = EvidenceWriter(
            LocalDirSink(location), part_interval_s=0, writer="host"
        )
        tap = RemoveOnceFailsTap(capture, consoles)
        (capture / "dmz").mkdir()
        (capture / "dmz" / "g0.pcap").write_bytes(b"completed-bytes")
        (capture / "dmz" / "g0.pcap1").write_bytes(b"active")
        write_status(capture, {"dmz": {"active": "dmz/g0.pcap1"}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])

        await one_cycle(streamer)
        # claimed out of the sidecar's PCAP_RE namespace, shipped, removal failed
        assert not (capture / "dmz" / "g0.pcap").exists()
        assert (capture / "dmz" / "g0.pcap.shipped").exists()

        await one_cycle(streamer)  # removal retried; never re-appended
        assert not (capture / "dmz" / "g0.pcap.shipped").exists()
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        stream = report.writers["host"].streams["pcap/dmz"]
        assert stream.chunks == 1 and stream.gaps == 0

    asyncio.run(scenario())


def test_new_claims_pause_while_removals_fail(tmp_path: Path) -> None:
    """Review finding on B13: cap-invisible claimed files stay bounded when removal fails persistently; the remainder stays unclaimed and cap-visible."""
    from inspect_ranges._evidence.capture import CLAIMED_PENDING_LIMIT

    class RemovalsDeadTap(LocalTap):
        def remove_file(self, relpath: str) -> None:
            raise OSError("removal dead")

    async def scenario() -> None:
        location = tmp_path / "evidence"
        capture = tmp_path / "capture"
        consoles = tmp_path / "consoles"
        capture.mkdir()
        consoles.mkdir()
        writer = EvidenceWriter(
            LocalDirSink(location), part_interval_s=0, writer="host"
        )
        tap = RemovalsDeadTap(capture, consoles)
        (capture / "dmz").mkdir()
        for index in range(CLAIMED_PENDING_LIMIT + 4):
            (capture / "dmz" / f"g0.pcap{index if index else ''}").write_bytes(b"chunk")
        (capture / "dmz" / "g0.pcap99").write_bytes(b"active")
        write_status(capture, {"dmz": {"active": "dmz/g0.pcap99"}})
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)
        await one_cycle(streamer)
        claimed = list((capture / "dmz").glob("*.shipped"))
        unclaimed = [
            p
            for p in (capture / "dmz").glob("g0.pcap*")
            if not p.name.endswith(".shipped")
        ]
        assert len(claimed) == CLAIMED_PENDING_LIMIT
        # the active file plus the 4 past-limit chunks stay cap-visible
        assert len(unclaimed) == 5

    asyncio.run(scenario())


def test_claimed_file_from_a_dead_streamer_ships_without_a_status_claim(
    tmp_path: Path,
) -> None:
    """A claim froze the file as completed, so crash recovery ships it even when the active file is unknown; unclaimed files still wait."""

    async def scenario() -> None:
        location, capture, writer, tap = harness(tmp_path)
        (capture / "dmz").mkdir()
        (capture / "dmz" / "g0.pcap.shipped").write_bytes(b"claimed-then-crashed")
        (capture / "dmz" / "g0.pcap1").write_bytes(b"maybe-active")
        streamer = CaptureStreamer(writer, tap, segments=["dmz"], console_guests=[])
        await one_cycle(streamer)  # no status.json at all
        assert not (capture / "dmz" / "g0.pcap.shipped").exists()
        assert (capture / "dmz" / "g0.pcap1").exists()
        await writer.seal()
        report = await verify_location(LocalDirStore(location), location=str(location))
        assert report.ok
        assert report.writers["host"].streams["pcap/dmz"].chunks == 1

    asyncio.run(scenario())


def test_supervisor_cap_excludes_claimed_files(tmp_path: Path) -> None:
    """B13's supervisor half: a claimed (`.shipped`) file is invisible to enforce_cap, so shipped bytes are never unlinked or counted as dropped."""
    supervisor = Supervisor(tmp_path, env={"CAPTURE_CAP_MB": "1"})
    segment = supervisor.capture / "dmz"
    segment.mkdir()
    claimed = segment / "g0.pcap.shipped"
    claimed.write_bytes(b"x" * 600_000)
    os.utime(claimed, (999.0, 999.0))  # oldest of all: first to go if visible
    for index in range(1, 4):
        path = segment / f"g0.pcap{index}"
        path.write_bytes(b"x" * 600_000)
        os.utime(path, (1000.0 + index, 1000.0 + index))
    try:
        supervisor.start()
        final = supervisor.wait_for(
            lambda s: s["segments"]["dmz"]["dropped_files"] >= 2
        )
        # 1.8 MB of UNCLAIMED chunks against a 1 MiB cap: two oldest unclaimed go
        assert final["segments"]["dmz"]["dropped_bytes"] == 1_200_000
        assert claimed.exists()
    finally:
        supervisor.finish()
