#!/usr/bin/env python3
"""challenges-v1 post-close battery: the `evade` type live against a journald collector.

Run via ./run_evade.sh (golden staged, flock held, CID 30950). Proves on a live range: a quiet window under the threshold achieves; a noisy window fails with the declared linear partial; a suspended collector guest mid-window gaps the stream, and the trichotomy resolves from the same record (default indeterminate, `fail` fails, `succeed` waives completeness but never erases the recorded noise). Per-goal check+compare timings print for the measurement table.
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(SPIKE.parent.parent.parent / "src"))

from inspect_ranges._challenges.engine import goal_type  # noqa: E402
from inspect_ranges._challenges.oracle import RangeOracle  # noqa: E402
from inspect_ranges._challenges.schema import EvadeGoal, SeverityFilter  # noqa: E402
from inspect_ranges._challenges.submission import Submissions  # noqa: E402
from inspect_ranges._channel.channel import MessageChannel  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._compiler.plan import Totals  # noqa: E402
from inspect_ranges._evidence.reader import (  # noqa: E402
    LocalDirStore,
    verify_location,
)
from inspect_ranges._evidence.telemetry import (  # noqa: E402
    CollectorSpec,
    CommandSource,
    TelemetryPoller,
)
from inspect_ranges._provider.evidence import EvidenceSession  # noqa: E402
from inspect_ranges._provider.state import SampleHandle  # noqa: E402
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

TMP = SPIKE / "tmp"
BUNDLE = TMP / "bundle-evade"
EVIDENCE = TMP / "evidence-evade"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])
CID_BASE = 30950

PASS = 0
FAIL = 0

JOURNALD = SeverityFilter(
    pattern=r'"PRIORITY":"(\d)"', floor=4, lower_is_more_severe=True
)
EMPTY_SUBMISSIONS = Submissions([])


def check(condition: bool, name: str) -> bool:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}", flush=True)
    return condition


def evade(goal_id: str, **overrides: Any) -> EvadeGoal:
    fields: dict[str, Any] = {
        "id": goal_id,
        "collector": "chv1e",
        "severity": JOURNALD,
        "match": "chv1e",
        "threshold": 2,
        "zero_at": 6,
    }
    fields.update(overrides)
    return EvadeGoal(**fields)


async def sh(oracle: RangeOracle, guest: str, command: str) -> int:
    outcome = await oracle.exec(
        guest, ["sh", "-c", command], user="root", timeout_s=60.0
    )
    return outcome.rc


async def scored(oracle: RangeOracle, goal: EvadeGoal) -> Any:
    engine = goal_type(goal.type)
    started = time.monotonic()
    obs = await engine.check(goal, oracle, EMPTY_SUBMISSIONS)
    result = engine.compare(goal, obs, oracle.store)
    elapsed = time.monotonic() - started
    print(
        f"      [evade:{goal.id}] check+compare {elapsed:.3f}s -> {result.reason}",
        flush=True,
    )
    return result


def virsh(project: str, *args: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(BUNDLE),
            "exec",
            "-T",
            "range",
            "virsh",
            *args,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"virsh {' '.join(args)} failed: {result.stderr.strip()}", flush=True)
    return result.stdout


async def main() -> int:
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s %(message)s"
    )

    print("=== render + up (capture on, CID 30950) ===", flush=True)
    spec = load_range(SPIKE / "spec.yaml")
    plan = render_bundle(
        spec,
        BUNDLE,
        PlanOptions(image_cache=IMAGE_CACHE, cid_base=CID_BASE, evidence_capture=True),
    )
    session = EvidenceSession(str(EVIDENCE), sample_id="chv1-evade", capture_local=True)
    result = await asyncio.to_thread(
        up,
        BUNDLE,
        UpOptions(image_cache=IMAGE_CACHE),
        on_stage=session.recorder.on_stage,
    )
    project = result.project
    check(
        all(g.ready for g in result.guests), f"range up: {project} ({result.seconds}s)"
    )
    boot = json.loads((BUNDLE / "boot.json").read_text())
    cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}
    channel = MessageChannel(
        VsockTransport(cids), label="chv1-evade", channel_budget_s=10.0
    )
    await session.open(lease_id=None, project=project, bundle=BUNDLE, plan=plan)
    handle = SampleHandle(
        project=project,
        task_name="chv1-evade",
        staging=TMP / "staging-evade",
        totals=Totals(guests=4, cpus=4, memory_mb=4096),
        cid_base=CID_BASE,
        guest_cids=cids,
        channel=channel,
        evidence=session,
        plan=plan,
        spec=spec,
    )
    oracle = RangeOracle(handle)
    store = LocalDirStore(EVIDENCE)
    code = 1
    try:
        print("=== collector: journald JSON export from web ===", flush=True)
        writer = session.driver_writer
        assert writer is not None
        collector = CollectorSpec(
            name="chv1e",
            guest="web",
            source=CommandSource(
                bootstrap=[
                    "journalctl",
                    "-t",
                    "chv1e",
                    "-o",
                    "json",
                    "-n",
                    "50",
                    "--show-cursor",
                    "-q",
                ],
                command=[
                    "journalctl",
                    "-t",
                    "chv1e",
                    "-o",
                    "json",
                    "--after-cursor={cursor}",
                    "--show-cursor",
                    "-q",
                ],
                cursor_pattern=r"-- cursor: (\S+)",
                user="root",
            ),
            poll_s=1.0,
        )
        await sh(oracle, "web", "logger -t chv1e -p user.info 'bootstrap seed'")
        poller = TelemetryPoller(channel, writer, [collector], meta_flush_s=3.0)
        await poller.start()

        print("=== quiet window: info-level noise only ===", flush=True)
        await sh(oracle, "web", "logger -t chv1e -p user.info 'routine activity'")
        await asyncio.sleep(4.0)
        quiet = await scored(oracle, evade("quiet"))
        check(
            bool(quiet.achieved) and not quiet.indeterminate,
            "quiet window under the threshold achieves",
        )

        print("=== noisy window: five warning alerts ===", flush=True)
        for i in range(5):
            await sh(
                oracle,
                "web",
                f"logger -t chv1e -p user.warning 'chv1e intrusion alert {i}'",
            )
        await asyncio.sleep(4.0)
        noisy = await scored(oracle, evade("noisy"))
        check(
            not noisy.achieved and not noisy.indeterminate,
            "five warnings over threshold 2 fail the goal",
        )
        check(
            noisy.partial is not None and abs(noisy.partial - 0.25) < 1e-9,
            f"linear decay: count 5 against threshold 2 / zero_at 6 earns 0.25 (got {noisy.partial})",
        )
        binary = await scored(oracle, evade("binary", zero_at=None))
        check(
            not binary.achieved and binary.partial is None,
            "without zero_at the verdict is binary",
        )

        print("=== sensor injury: suspend the collector guest mid-window ===")
        names = virsh(project, "list", "--name")
        domain = next((n for n in names.split() if "web" in n), None)
        if not check(domain is not None, f"virsh found the web domain in {names!r}"):
            raise RuntimeError("cannot run the injury scenario without the domain")
        assert domain is not None
        virsh(project, "suspend", domain)
        # the poll must actually fail (channel budget 10 s) and its gap land in
        # the record; wait on the predicate compare consumes rather than a sleep
        deadline = time.monotonic() + 60.0
        gapped = False
        while time.monotonic() < deadline and not gapped:
            await asyncio.sleep(2.0)
            _, _, gapped = await oracle.telemetry_export("chv1e")
        check(gapped, "suspension produced a recorded gap in the export stream")
        virsh(project, "resume", domain)
        await asyncio.sleep(4.0)
        await poller.stop()

        tampered_default = await scored(oracle, evade("tampered"))
        check(
            tampered_default.indeterminate,
            "gapped stream, default on_sensor_tamper: indeterminate, never a free pass",
        )
        tampered_fail = await scored(oracle, evade("bounds", on_sensor_tamper="fail"))
        check(
            not tampered_fail.achieved and not tampered_fail.indeterminate,
            "on_sensor_tamper=fail: tampering declared out of bounds fails the goal",
        )
        tampered_loud = await scored(
            oracle, evade("loudsmash", on_sensor_tamper="succeed")
        )
        check(
            not tampered_loud.achieved,
            "on_sensor_tamper=succeed never erases recorded noise (5 alerts > threshold 2)",
        )
        tampered_quietish = await scored(
            oracle,
            evade("budget", on_sensor_tamper="succeed", threshold=10, zero_at=20),
        )
        check(
            bool(tampered_quietish.achieved),
            "on_sensor_tamper=succeed waives completeness when the recorded count is under threshold",
        )

        print("=== finalize + offline verify ===", flush=True)
        await session.finalize()
        binding = session.binding()
        seals = binding["seals"]
        report = await verify_location(
            store, expected_seals={w: s for w, s in seals.items()}
        )
        check(report.ok, "evidence record verifies with the binding")
        code = 0 if FAIL == 0 else 1
    finally:
        await asyncio.to_thread(down, project)
    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
