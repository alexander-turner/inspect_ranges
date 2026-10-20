#!/usr/bin/env python3
"""evidence-v1 slice-2 battery: live capture, streaming, and verification on a real range.

Run via ./run.sh (which stages the golden image, exports the env knobs, and holds the shared battery flock). The script renders an evidence-enabled bundle at CID base 30100, boots it, runs the CaptureStreamer against the live sidecar, generates known flows, injures the capture (restart, then exhaustion), stops, seals, and verifies the record offline, asserting per-segment correctness from the shipped chunks alone.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(SPIKE.parent.parent.parent / "src"))

from inspect_ranges._channel.channel import MessageChannel, request_id  # noqa: E402
from inspect_ranges._channel.protocol import Budget, ExecRequest  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._evidence import (  # noqa: E402
    CaptureStreamer,
    ComposeTap,
    EvidenceWriter,
    LocalDirSink,
    LocalDirStore,
    StageRecorder,
    verify_location,
)
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

TMP = SPIKE / "tmp"
BUNDLE = TMP / "bundle"
EVIDENCE = TMP / "evidence"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])

PASS = 0
FAIL = 0


def ok(name: str) -> None:
    global PASS
    PASS += 1
    print(f"PASS  {name}", flush=True)


def bad(name: str) -> None:
    global FAIL
    FAIL += 1
    print(f"FAIL  {name}", flush=True)


def check(condition: bool, name: str) -> bool:
    (ok if condition else bad)(name)
    return condition


class Guests:
    """vsock exec against the booted guests, from boot.json."""

    def __init__(self, bundle: Path) -> None:
        boot = json.loads((bundle / "boot.json").read_text())
        self.cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}

    def channel(self) -> MessageChannel:
        return MessageChannel(
            VsockTransport(self.cids), label="ev1-battery", channel_budget_s=10.0
        )

    async def exec(self, guest: str, command: str, timeout_ms: int = 30_000) -> int:
        channel = self.channel()
        outcome = await channel.exec(
            guest,
            ExecRequest(
                id=request_id(),
                cmd=["sh", "-c", command],
                budget=Budget(command_ms=timeout_ms),
            ),
        )
        return outcome.rc

    async def ping_all(self) -> bool:
        channel = self.channel()
        for guest in self.cids:
            await channel.ping(guest)
        return True


def compose_exec_capture(project: str, script: str) -> int:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(BUNDLE),
            "exec",
            "-T",
            "capture",
            "sh",
            "-c",
            script,
        ],
        capture_output=True,
    ).returncode


async def wait_for(predicate, name: str, timeout: float = 60.0) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if await predicate():
                return check(True, name)
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return check(False, name)


def pcap_count(chunks: list[bytes], bpf: str) -> int:
    """Sum tcpdump counts across shipped chunk files (each chunk is a complete pcap)."""
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        for index, data in enumerate(chunks):
            path = Path(tmp) / f"{index}.pcap"
            path.write_bytes(data)
            result = subprocess.run(
                ["tcpdump", "-r", str(path), "--count", bpf],
                capture_output=True,
                text=True,
            )
            digits = "".join(c for c in result.stdout if c.isdigit())
            total += int(digits) if digits else 0
    return total


async def stream_chunks(store: LocalDirStore, stream: str) -> list[bytes]:
    keys = await store.list(f"chunks/host/{stream}")
    return [await store.get(key) for key in sorted(keys)]


async def main() -> int:
    print("=== render: evidence-enabled bundle, floor assert ===", flush=True)
    spec = load_range(SPIKE / "spec.yaml")
    render_bundle(
        spec,
        BUNDLE,
        PlanOptions(image_cache=IMAGE_CACHE, cid_base=30100, evidence_capture=True),
    )
    compose = yaml.safe_load((BUNDLE / "compose.yaml").read_text())
    check(
        "NET_RAW" not in compose["services"]["range"]["cap_add"],
        "range container floor: the eight only (no NET_RAW)",
    )
    check(
        compose["services"]["capture"]["cap_add"] == ["NET_RAW"],
        "capture sidecar: NET_RAW alone",
    )

    print("=== up (with stage recorder) ===", flush=True)
    recorder = StageRecorder()
    # up() is synchronous and runs its own event loop internally
    result = await asyncio.to_thread(
        up,
        BUNDLE,
        UpOptions(image_cache=IMAGE_CACHE),
        on_stage=recorder.on_stage,
    )
    project = result.project
    check(all(g.ready for g in result.guests), f"range up: {project} ({result.seconds}s)")
    guests = Guests(BUNDLE)

    writer = EvidenceWriter(
        LocalDirSink(EVIDENCE), writer="host", sample_id="ev1-battery"
    )
    tap = ComposeTap(project, BUNDLE)
    streamer = CaptureStreamer(
        writer,
        tap,
        segments=["dmz", "internal"],
        console_guests=["attacker", "web", "db", "router"],
        stage_recorder=recorder,
        poll_s=0.5,
        heartbeat_s=2.0,
    )
    store = LocalDirStore(EVIDENCE)

    try:
        await streamer.start()

        print("=== capture live, consoles continuous ===", flush=True)
        await wait_for(
            lambda: _status_running(tap),
            "sidecar status: both segments running",
            timeout=90,
        )
        await wait_for(
            lambda: _has_chunks(store, "console/"),
            "console streamed continuously (range healthy, no failure)",
        )

        print("=== known flows ===", flush=True)
        rc = await guests.exec("attacker", "ping -c 4 -i 0.3 10.94.20.10")
        check(rc == 0, "cross-segment ping attacker->db")
        rc = await guests.exec("web", "ping -c 4 -i 0.3 10.94.10.3")
        check(rc == 0, "same-segment ping web->attacker")

        print("=== flood: rotation + live shipping, range stays healthy ===", flush=True)
        blast = (
            "python3 - <<'EOF'\n"
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "p = b'x' * 1400\n"
            "for i in range(8000):\n"
            "    s.sendto(p, ('10.94.20.10', 9999))\n"
            "print('sent 8000')\n"
            "EOF"
        )
        rc = await guests.exec("attacker", blast, timeout_ms=60_000)
        check(rc == 0, "flood sent (8000 x 1400B)")
        await wait_for(
            lambda: _has_chunks(store, "pcap/dmz/"),
            "pcap chunks shipped live under rotation",
            timeout=90,
        )
        check(await guests.ping_all(), "range healthy after flood (all daemons answer)")

        print("=== injury: restart once, then exhaust ===", flush=True)
        for _ in range(3):  # CAPTURE_MAX_RESTARTS=2: third kill exhausts
            compose_exec_capture(project, "pkill -f 'tcpdump.*br-dmz' || true")
            await asyncio.sleep(2.0)
        await wait_for(
            lambda: _status_state(tap, "dmz", "exhausted"),
            "dmz capture exhausted after bounded restarts",
            timeout=30,
        )

        print("=== stop, seal, verify ===", flush=True)
    finally:
        await streamer.stop(stop_timeout_s=30.0)

    seal, digest = await writer.seal()
    check(seal.status == "complete", f"sealed complete (digest {digest[:16]})")
    report = await verify_location(store, location=str(EVIDENCE))
    check(report.ok, "evidence verify: chain unbroken offline")
    host = report.writers["host"]
    causes = {gap.cause for gap in host.gaps}
    check("capture-restart" in causes, "gap recorded: capture-restart")
    check("capture-dead" in causes, "gap recorded: capture-dead")
    check(host.streams.get("heartbeat") is not None, "heartbeat stream present")
    stderr_dmz = b"".join(await stream_chunks(store, "capture-stderr/dmz"))
    check(b"listening on" in stderr_dmz, "capture stderr shipped (listening lines)")
    check(
        b"dropped by kernel" in stderr_dmz,
        "capture stderr carries kernel-drop summaries",
    )
    stages = b"".join(await stream_chunks(store, "stages"))
    verify_stream = b"".join(await stream_chunks(store, "verify"))
    check(b'"stage": "ready"' in stages or b'"stage":"ready"' in stages, "stages stream carries ready")
    check(b"readiness" in verify_stream, "verify stream carries readiness")

    print("=== per-segment correctness from shipped chunks alone ===", flush=True)
    dmz = await stream_chunks(store, "pcap/dmz")
    internal = await stream_chunks(store, "pcap/internal")
    cross_dmz = pcap_count(dmz, "icmp and host 10.94.20.10")
    cross_int = pcap_count(internal, "icmp and host 10.94.20.10")
    same_dmz = pcap_count(dmz, "icmp and host 10.94.10.10")
    same_int = pcap_count(internal, "icmp and host 10.94.10.10")
    flood_int = pcap_count(internal, "udp and port 9999")
    print(
        f"counts: cross dmz={cross_dmz} int={cross_int}; same dmz={same_dmz} int={same_int}; flood int={flood_int}",
        flush=True,
    )
    # 4 echo requests + 4 replies cross each segment at minimum; both segment
    # captures must agree exactly (the same flow crossed both)
    check(
        cross_dmz == cross_int and cross_dmz >= 8,
        "cross-segment flow identical on BOTH streams, >= all 8 echo frames",
    )
    check(same_dmz >= 8 and same_int == 0, "same-segment flow in its own stream ONLY")
    check(flood_int == 8000, "flood complete on the internal stream (8000/8000)")

    print("=== down ===", flush=True)
    await asyncio.to_thread(down, project)
    # not a counted check: down() raising would already fail the run, and the
    # wrapper's pre-sweep residue count is the real leak check
    print("down complete", flush=True)
    return 0 if FAIL == 0 else 1


async def _status_running(tap: ComposeTap) -> bool:
    status = json.loads(await asyncio.to_thread(tap.read_status))
    states = {name: seg["state"] for name, seg in status["segments"].items()}
    return states.get("dmz") == "running" and states.get("internal") == "running"


async def _status_state(tap: ComposeTap, segment: str, state: str) -> bool:
    status = json.loads(await asyncio.to_thread(tap.read_status))
    return bool(status["segments"][segment]["state"] == state)


async def _has_chunks(store: LocalDirStore, prefix: str) -> bool:
    return len(await store.list(f"chunks/host/{prefix}")) > 0


if __name__ == "__main__":
    code = asyncio.run(main())
    print(f"\nBATTERY RESULT: PASS={PASS} FAIL={FAIL}", flush=True)
    sys.exit(code)
