#!/usr/bin/env python3
"""evidence-v1 slice-5 battery: the provider/host seam wiring on real ranges.

Run via ./run_seam.sh. Sections: (S1) a normal provider sample streaming to real S3, live shipping proven while the sample runs, the compromise-window demonstration (conditional-put refusal from the instance; a post-completion plain overwrite is DETECTED as a chunk-digest break by the binding-holder), the binding verified from a scrubbed subprocess, and the capture-cost budget; (S2) the kill -9 headline: driver SIGKILLed mid-sample, the reaper reclaims and reap-seals, and everything streamed before the kill verifies intact off-instance; (S3) backpressure under a tiny buffer cap: in-chain gaps, unbroken chain, healthy range; (S4) the separated topology: the applier owns the host capture writer, the binding carries both writers' digests. The inspect-eval smoke (S5) runs from run_seam.sh after this script.
"""

import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SPIKE = Path(__file__).resolve().parent
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "design/spikes/range-host-v1"))

from applier_proc import SOCKET, start_applier  # noqa: E402
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope  # noqa: E402

from inspect_ranges._evidence.reader import VerifyReport, verify_location  # noqa: E402
from inspect_ranges._evidence.s3 import store_for_location  # noqa: E402
from inspect_ranges._host.reaper import sweep  # noqa: E402
from inspect_ranges._provider.provider import (  # noqa: E402
    RangeSandboxEnvironment as Env,
)
from inspect_ranges._runtime.ownership import default_state_dir  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

SPEC = SPIKE / "spec.yaml"
TMP = SPIKE / "tmp"
S3_PREFIX = os.environ["SEAM_S3_PREFIX"]
UP_BUDGET_S = 56.0
"""Stated in advance: the 4-VM enforced-ready baseline is ~51 s (chunk-2 battery, twice); capture plus evidence wiring must stay within ~10%."""

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


FLOOD = (
    "python3 - <<'EOF'\n"
    "import socket\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "p = b'x' * 1400\n"
    "for i in range(8000):\n"
    "    s.sendto(p, ('10.94.20.10', 9999))\n"
    "print('sent 8000')\n"
    "EOF"
)


async def wait_for(probe, name: str, timeout: float = 90.0) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await probe():
            return check(True, name)
        await asyncio.sleep(1.0)
    return check(False, name)


async def chunk_keys(location: str) -> list[str]:
    try:
        return await store_for_location(location).list("chunks")
    except Exception:
        return []


def scrubbed_verify(location: str, seals: dict[str, str]) -> int:
    """`evidence verify` from a scrubbed subprocess (fresh HOME, minimal env, instance-role creds), the chunk-3 second-machine substitution."""
    args = [str(ROOT / ".venv" / "bin" / "inspect-ranges"), "evidence", "verify"]
    for writer, digest in sorted(seals.items()):
        args += ["--expect-seal", f"{writer}={digest}"]
    args.append(location)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(TMP / "scrub-home"),
    }
    (TMP / "scrub-home").mkdir(parents=True, exist_ok=True)
    return subprocess.run(args, env=env, capture_output=True).returncode


async def run_sample(
    sample_id: str, *, traffic: bool = True
) -> tuple[dict[str, object], float, "SessionProbe"]:
    """One full provider sample: boot, traffic, cleanup; returns (binding, up seconds, probe)."""
    spec = load_range(SPEC)
    started = time.monotonic()
    envs = await Env.sample_init("seam", spec, {"__sample_id__": sample_id})
    up_seconds = time.monotonic() - started
    handles = [e._handle for e in envs.values() if isinstance(e, Env)]  # pyright: ignore[reportPrivateUsage]
    session = handles[0].evidence
    assert session is not None, "evidence must be on for the battery samples"
    probe = SessionProbe(session.location, session)
    if traffic:
        ping = await envs["attacker"].exec(
            ["ping", "-c", "4", "-i", "0.3", "10.94.20.10"]
        )
        check(ping.returncode == 0, f"{sample_id}: cross-segment ping")
        flood = await envs["attacker"].exec(["sh", "-c", FLOOD], timeout=60)
        check(flood.returncode == 0, f"{sample_id}: flood sent (8000 x 1400B)")
        await wait_for(
            lambda: _nonempty(probe.location),
            f"{sample_id}: chunks ship off-instance while the sample is LIVE",
        )
        pong = await envs["attacker"].exec(["true"])
        check(pong.returncode == 0, f"{sample_id}: range healthy after flood")
    await Env.sample_cleanup("seam", None, envs, interrupted=False)
    return probe.session.binding(), up_seconds, probe


async def _nonempty(location: str) -> bool:
    return len(await chunk_keys(location)) > 0


async def _has_manifests(location: str) -> bool:
    try:
        return len(await store_for_location(location).list("manifests")) > 0
    except Exception:
        return False


class SessionProbe:
    def __init__(self, location: str, session) -> None:  # type: ignore[no-untyped-def]
        self.location = location
        self.session = session


async def s1_normal_sample_s3() -> None:
    print("=== S1: normal sample streaming to S3 ===", flush=True)
    os.environ["INSPECT_RANGES_EVIDENCE_SINK"] = f"{S3_PREFIX}/s1"
    try:
        with sandbox_lifecycle_scope():
            binding, up_seconds, probe = await run_sample("s1")
    finally:
        del os.environ["INSPECT_RANGES_EVIDENCE_SINK"]
    print(f"up: {up_seconds:.1f}s (budget {UP_BUDGET_S}s)", flush=True)
    check(up_seconds <= UP_BUDGET_S, "capture cost inside the stated budget")
    seals = binding["seals"]
    assert isinstance(seals, dict)
    check(set(seals) == {"driver", "host"}, "binding carries both writers' digests")
    heads = binding["chain_heads"]
    assert isinstance(heads, dict)
    check(bool(heads.get("host")), "binding carries host chain heads")
    check(
        scrubbed_verify(probe.location, seals) == 0,
        "scrubbed-process verify with the binding exits 0",
    )
    # the compromise window. In-window: the writer's own write path cannot be
    # replayed against delivered keys (the store's conditional-put refusal,
    # proven from this very instance). Post-window: a PLAIN overwrite (the
    # bucket carries no deny-overwrite policy; IAM denied applying one, the
    # recorded chunk-3 limitation) is DETECTED by the binding-holder as a
    # chunk-digest break: tamper-evident, exactly the claim and no more.
    store = store_for_location(probe.location)
    keys = await store.list("chunks")
    victim = next(key for key in keys if key.startswith("chunks/host/pcap/"))
    import boto3  # noqa: PLC0415

    bucket, _, prefix = probe.location.removeprefix("s3://").partition("/")
    client = boto3.client("s3")
    try:
        client.put_object(
            Bucket=bucket,
            Key=f"{prefix}/{victim}",
            Body=b"forged",
            IfNoneMatch="*",
        )
        check(False, "conditional re-put of a delivered chunk is refused (412)")
    except Exception as error:
        check(
            "PreconditionFailed" in str(error) or "412" in str(error),
            "conditional re-put of a delivered chunk is refused (412)",
        )
    client.put_object(Bucket=bucket, Key=f"{prefix}/{victim}", Body=b"forged")
    report = await verify_location(store, deep=True, expected_seals=dict(seals))  # type: ignore[arg-type]
    broken = report.writers["host"].first_break
    check(
        broken is not None and broken.kind in ("chunk-digest", "chunk-size"),
        "post-window plain overwrite is DETECTED as a chunk break"
        + (f" ({broken.kind} at {broken.key})" if broken is not None else ""),
    )


async def s2_kill9_reaper() -> None:
    print("=== S2: kill -9, reaper reclaim, reaped seal off-instance ===", flush=True)
    location_hint = f"{S3_PREFIX}/s2"
    child_env = dict(os.environ)
    child_env["INSPECT_RANGES_EVIDENCE_SINK"] = location_hint
    child_env["INSPECT_RANGES_LEASE_TTL_S"] = "20"
    child = subprocess.Popen(
        [str(ROOT / ".venv" / "bin" / "python"), str(SPIKE / "seam_child.py")],
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    location = ""
    assert child.stdout is not None
    deadline = time.monotonic() + 240
    for line in child.stdout:
        print(f"  child: {line.rstrip()}", flush=True)
        if line.startswith("LOCATION "):
            location = line.split(" ", 1)[1].strip()
            break
        if time.monotonic() > deadline:
            break
    if not check(bool(location), "child booted and reported its location"):
        child.kill()
        return
    pre_kill = await wait_for(
        lambda: _nonempty(location), "pre-kill evidence is on S3", timeout=120
    )
    # the manifest commitment batches (part_interval_s): the headline claim is
    # about COMMITTED evidence, so the kill waits for a delivered part; chunks
    # newer than the last part are the bounded crash-window loss, visible
    # below as listed-unreferenced residue
    committed = await wait_for(
        lambda: _has_manifests(location),
        "pre-kill manifest part committed on S3",
        timeout=60,
    )
    keys_before = await chunk_keys(location)
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=10)
    # not a counted check: pre_kill and committed are the two wait_for rows
    # just recorded; this line only narrates the ordering for the log
    if pre_kill and committed:
        print("kill -9 delivered AFTER evidence left the instance", flush=True)
    await asyncio.sleep(25)  # lease TTL 20s: expire
    # sweep is sync by design (the reaper is a fresh process); from the
    # battery's loop it runs in a thread so the reap-seal's own event loop
    # (asyncio.run in the sealer path) has no running loop above it
    outcomes = await asyncio.to_thread(sweep, default_state_dir())
    check(
        any(outcome.action == "reaped" for outcome in outcomes),
        f"reaper reclaimed the dead driver's range ({[o.action for o in outcomes]})",
    )
    store = store_for_location(location)
    report: VerifyReport = await verify_location(store, deep=True)
    sealed = {
        name: writer
        for name, writer in report.writers.items()
        if writer.seal_status == "reaped"
    }
    check(report.ok, "the record verifies after the reap")
    check(bool(sealed), f"reaped seal(s) present ({sorted(sealed)})")
    keys_after = await chunk_keys(location)
    check(
        set(keys_before) <= set(keys_after),
        "every pre-kill chunk survived the driver's death",
    )
    # chunks newer than the last committed part are the recorded batching
    # trade-off: durable, listed as unreferenced residue, never a break
    print(
        f"unreferenced post-kill chunks (bounded crash window): "
        f"{len(report.unreferenced)}",
        flush=True,
    )


async def s3_backpressure() -> None:
    print("=== S3: backpressure under a 1 MB buffer cap ===", flush=True)
    local_root = TMP / "s3-backpressure"
    os.environ["INSPECT_RANGES_EVIDENCE_SINK"] = str(local_root)
    os.environ["INSPECT_RANGES_EVIDENCE_BUFFER_MB"] = "1"
    try:
        with sandbox_lifecycle_scope():
            binding, _, probe = await run_sample("s3bp")
    finally:
        del os.environ["INSPECT_RANGES_EVIDENCE_SINK"]
        del os.environ["INSPECT_RANGES_EVIDENCE_BUFFER_MB"]
    store = store_for_location(probe.location)
    report = await verify_location(store, deep=True)
    check(report.ok, "chain unbroken under backpressure")
    gaps = report.writers["host"].gaps
    causes = {gap.cause for gap in gaps}
    check(
        bool(
            causes
            & {"buffer-cap", "capture-cap", "kernel-drops", "evidence-cap"}
        ),
        f"loss under pressure is explicit in-chain gaps ({sorted(causes)})",
    )
    del binding


async def s4_separated_topology() -> None:
    print("=== S4: separated topology (applier owns capture) ===", flush=True)
    state_dir = default_state_dir()
    applier = start_applier(ROOT, state_dir, TMP / "logs" / "applier.log")
    local_root = TMP / "s4-evidence"
    os.environ["INSPECT_RANGES_EVIDENCE_SINK"] = str(local_root)
    os.environ["INSPECT_RANGES_HOST"] = f"uds:{SOCKET}"
    try:
        with sandbox_lifecycle_scope():
            binding, _, probe = await run_sample("s4", traffic=True)
    finally:
        del os.environ["INSPECT_RANGES_EVIDENCE_SINK"]
        del os.environ["INSPECT_RANGES_HOST"]
        applier.terminate()
        applier.wait(timeout=15)
    seals = binding["seals"]
    assert isinstance(seals, dict)
    check(
        set(seals) == {"driver", "host"},
        f"separated binding carries BOTH digests ({sorted(seals)})",
    )
    store = store_for_location(probe.location)
    report = await verify_location(store, deep=True, expected_seals=dict(seals))  # type: ignore[arg-type]
    check(report.ok, "both writers verify with the binding")
    host = report.writers.get("host")
    check(
        host is not None and any(s.startswith("pcap/") for s in host.streams),
        "capture streams were written by the APPLIER (host writer)",
    )
    driver = report.writers.get("driver")
    check(
        driver is not None and "session" in driver.streams,
        "driver streams stayed driver-side",
    )


async def main() -> int:
    (TMP / "logs").mkdir(parents=True, exist_ok=True)
    await s1_normal_sample_s3()
    await s2_kill9_reaper()
    await s3_backpressure()
    await s4_separated_topology()
    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
