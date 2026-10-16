"""A10 live demonstration: the realize verify gap on a real multi-guest range through a real applier.

Three realizes of the evidence-v1 four-guest spec. Warm-up (default budgets) pays the one-time image/cache costs so the measured runs see warm construct stages. Measured run A drives realize with a deliberately small per-report channel allowance (below one real cloud-init pass) plus the plan-derived `verify_allowance_s` the uds seams now compute: it must reach `ready`, and the measured verify-to-ready gap must exceed the plain allowance, proving the envelope was load-bearing on real hardware. Measured run B (the control) uses the same small allowance WITHOUT the envelope: it must fail with a channel-layer `ChannelBudgetError` mid-readiness, which is exactly the pre-fix behavior U4 traced.

CID leases sit at 31000+ (the quality-review battery band). Run via run_a10.sh (flock, env, golden derivation).
"""

import asyncio
import sys
import time
from pathlib import Path

SPIKE = Path(__file__).resolve().parent
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "design/spikes/range-host-v1"))

from applier_proc import SOCKET, start_applier  # noqa: E402

from inspect_ranges._channel.channel import (  # noqa: E402
    ChannelBudgetError,
    MessageChannel,
)
from inspect_ranges._channel.uds import UdsTransport  # noqa: E402
from inspect_ranges._compiler.plan import PlanOptions  # noqa: E402
from inspect_ranges._compiler.render import render_bundle  # noqa: E402
from inspect_ranges._host import (  # noqa: E402
    LeasePlacement,
    RemoteHostProvider,
    SampleSpec,
)
from inspect_ranges._provider.naming import CidAllocator  # noqa: E402
from inspect_ranges._runtime.ownership import default_state_dir  # noqa: E402
from inspect_ranges._runtime.up import bundle_digest  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

SPEC = ROOT / "design/spikes/evidence-v1/spec.yaml"
SMALL_ALLOWANCE_S = 20.0
PASS = 0
FAIL = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global PASS, FAIL
    PASS += int(ok)
    FAIL += int(not ok)
    suffix = f"  ({detail})" if detail else ""
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}", flush=True)


async def one_realize(
    tag: str,
    state_dir: Path,
    image_cache: Path,
    *,
    channel_budget_s: float,
    use_envelope: bool,
) -> tuple[list[str], float, Exception | None]:
    """One lease + realize; returns (stages seen, verify-to-terminal seconds, error)."""
    spec = load_range(SPEC)
    allocator = CidAllocator(state_dir, base=31_000)
    project = f"ir-a10-{tag}"
    cid_lease = allocator.lease(project, 5)
    staging = SPIKE / "tmp" / tag
    bundle = staging / "bundle"
    plan = render_bundle(
        spec, bundle, PlanOptions(image_cache=image_cache, cid_base=cid_lease.base)
    )
    digest = bundle_digest(bundle)
    provider = RemoteHostProvider(SOCKET, state_dir)
    host = await provider.acquire(
        SampleSpec(
            sample_id=tag,
            task_name="a10",
            spec_sha256=plan.range.spec_sha256,
            bundle_digest=digest,
            totals=plan.totals,
        ),
        LeasePlacement(project=project, bundle_path=str(bundle), staging=str(staging)),
    )
    channel = MessageChannel(
        UdsTransport(SOCKET, host.lease.lease_id),
        label=f"a10-{tag}",
        channel_budget_s=channel_budget_s,
    )
    # the plan-derived envelope exactly as remote.py computes it
    envelope = 300.0 + len(plan.guests) * 10.0 + 30.0
    stages: list[str] = []
    verify_at: float | None = None
    gap_s = 0.0
    error: Exception | None = None
    try:
        async for report in channel.realize(
            digest, [], gap_allowances={"verify": envelope} if use_envelope else None
        ):
            stages.append(report.stage)
            if report.stage == "verify":
                verify_at = time.monotonic()
            if report.stage in ("ready", "failed") and verify_at is not None:
                gap_s = time.monotonic() - verify_at
    except ChannelBudgetError as failure:
        if verify_at is not None:
            gap_s = time.monotonic() - verify_at
        error = failure
    finally:
        try:
            await channel.teardown()
        except Exception as teardown_error:  # noqa: BLE001 - cleanup is best effort
            print(f"  (teardown note for {tag}: {teardown_error})", flush=True)
        await provider.release(host)
        allocator.release(project)
    return stages, gap_s, error


async def main() -> int:
    state_dir = default_state_dir()
    image_cache = Path(sys.argv[1])
    (SPIKE / "tmp" / "logs").mkdir(parents=True, exist_ok=True)
    applier = start_applier(ROOT, state_dir, SPIKE / "tmp" / "logs" / "applier.log")
    try:
        print("=== warm-up realize (default budgets; pays one-time costs) ===")
        stages, gap, error = await one_realize(
            "warm", state_dir, image_cache, channel_budget_s=180.0, use_envelope=True
        )
        check(error is None and stages[-1:] == ["ready"], "warm-up reaches ready")
        print(f"  warm verify->ready gap: {gap:.1f}s", flush=True)

        print(f"=== A: small allowance ({SMALL_ALLOWANCE_S:.0f}s) + plan envelope ===")
        stages, gap_a, error = await one_realize(
            "fixed",
            state_dir,
            image_cache,
            channel_budget_s=SMALL_ALLOWANCE_S,
            use_envelope=True,
        )
        check(
            error is None and stages[-1:] == ["ready"],
            "realize reaches ready with the plan-derived envelope",
            f"stages={stages}",
        )
        check(
            gap_a > SMALL_ALLOWANCE_S,
            "the verify->ready gap exceeded the plain allowance (the envelope "
            "was load-bearing)",
            f"gap={gap_a:.1f}s allowance={SMALL_ALLOWANCE_S:.0f}s",
        )

        print(f"=== B: control, small allowance ({SMALL_ALLOWANCE_S:.0f}s), no envelope ===")
        stages, gap_b, error = await one_realize(
            "control",
            state_dir,
            image_cache,
            channel_budget_s=SMALL_ALLOWANCE_S,
            use_envelope=False,
        )
        check(
            isinstance(error, ChannelBudgetError)
            and getattr(error, "layer", "") == "channel",
            "the control starves at the verify gap exactly as U4 traced",
            f"stages={stages} error={error}",
        )
        check("verify" in stages and "ready" not in stages, "the starvation is the verify gap")
        print(
            f"timings: fixed verify->ready {gap_a:.1f}s; control starved after "
            f"{gap_b:.1f}s of the gap",
            flush=True,
        )
    finally:
        applier.terminate()
        applier.wait(timeout=15)
    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
