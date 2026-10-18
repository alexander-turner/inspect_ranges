"""Challenge behavioral checks at build time (build-v1 slice 6).

The ratified verification structure puts exploitability proof in exactly one place: the challenge's behavioral checks (the reference solution passes, an insufficient attempt fails, a forged submission fails). The build runs them against the range's CAPTURED artifacts: after capture and the build range's teardown, the realized images boot once more through the gate's own `swap_realized_spec` consumption step, the checks run, and only then does the manifest land on disk with the results in its `behavioral_checks` slot. The save is deferred past this phase deliberately (slice 6 review), and a failed proof lands as a REFUSED manifest (parked-decisions item 4): the failure's records are saved, the gate refuses `range-unproven`, and the next build reuses every guest and re-runs only the proof; under exits that record nothing (a teardown error before the phase, Ctrl-C, a crash) no manifest exists at all. Either way no consumer can boot a range whose challenge is unproven. Running against the captured artifacts rather than the build range proves the thing that ships, and exploit debris dirties only ephemeral per-boot overlays. A declared checks tree must be complete (`_validate_checks`): proof that silently does not run is indistinguishable from proof, so a misnamed directory or a missing trio script refuses instead of skipping. Check scripts and `challenges.yaml` participate in the build's cached fast path through `checks_digest`, never in guest build keys.

Check convention: `<range>/checks/<challenge-id>/{reference,insufficient,forged}.sh`, each a bash script run ON THE ATTACKER GUEST via the oracle (outside an eval there is no `sandbox()`; the foothold-only property is held by construction here and enforced by the eval path), with `IR_ATTACKER_IP` exported. Scripts emit `SUBMIT <goal-id> <value>` lines (the refchains contract); `reference` must score 1.0 with validity `valid`, `insufficient` and `forged` must score 0.0. Per-check plants are fresh: `run_setup` runs per check with a fresh `PlantStore`, and each check's planted files are removed afterward (the plant script refuses an existing target, and this runner reuses one boot across checks where a sample plants once per boot). Runtime samples re-plant, so nothing a check planted survives as a valid secret.
"""

import asyncio
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

from .errors import BuildError
from .manifest import BehavioralCheckRecord
from .recipes import StageSink

if TYPE_CHECKING:
    from inspect_ai.util._store import Store

    from .._challenges.oracle import RangeOracle
    from .._challenges.schema import Challenge, Challenges
    from .._compiler.plan import ResolvedPlan
    from ..types import RangeSpec

logger = logging.getLogger(__name__)

CHECKS_DIR_NAME = "checks"
CHECK_NAMES = ("reference", "insufficient", "forged")
CHAIN_TIMEOUT_S = 300.0

_SUBMIT = re.compile(r"SUBMIT\s+(\S+)\s+(.+)$")


def checks_declared(range_dir: Path) -> bool:
    """Whether the range carries build-time behavioral checks."""
    return (range_dir / "challenges.yaml").is_file() and (
        range_dir / CHECKS_DIR_NAME
    ).is_dir()


def checks_digest(range_dir: Path) -> str:
    """Content digest over the range's behavioral-check inputs: `challenges.yaml` plus every file under `checks/` (relative path, exec bit, bytes).

    Check scripts are proof tools, not guest content, so they never enter a guest build key; this digest is what invalidates the build's cached fast path when a check is authored or edited after a green build (slice 6 review: without it, new or changed checks silently never ran).
    """
    hasher = hashlib.sha256()
    hasher.update((range_dir / "challenges.yaml").read_bytes())
    root = range_dir / CHECKS_DIR_NAME
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        exec_bit = b"x" if path.stat().st_mode & 0o111 else b"-"
        hasher.update(path.relative_to(root).as_posix().encode() + b"\0" + exec_bit)
        hasher.update(b"\0" + path.read_bytes() + b"\0")
    return hasher.hexdigest()


def _validate_checks(challenges: "Challenges", range_dir: Path) -> None:
    """A declared checks tree must be complete: proof that silently does not run is indistinguishable from proof (slice 6 review).

    Raises:
        BuildError: stage `behavioral`, naming the misnamed directory or the missing script.
    """
    root = range_dir / CHECKS_DIR_NAME
    declared = {challenge.id for challenge in challenges.challenges}
    for entry in sorted(root.iterdir()):
        if entry.is_dir() and entry.name not in declared:
            raise BuildError(
                "behavioral",
                f"checks directory {entry.name!r} matches no declared challenge "
                f"(declared: {sorted(declared)})",
            )
    for challenge in challenges.challenges:
        check_dir = root / challenge.id
        if not check_dir.is_dir():
            raise BuildError(
                "behavioral",
                f"challenge {challenge.id!r} has no checks directory under "
                f"{CHECKS_DIR_NAME}/ (this range declares behavioral checks; "
                "every challenge needs the full trio)",
            )
        for name in CHECK_NAMES:
            if not (check_dir / f"{name}.sh").is_file():
                raise BuildError(
                    "behavioral",
                    f"challenge {challenge.id!r} is missing check "
                    f"{CHECKS_DIR_NAME}/{challenge.id}/{name}.sh",
                )


def load_challenges(range_dir: Path) -> "Challenges":
    """The range's challenges.yaml, validated."""
    from .._challenges.schema import Challenges

    raw = yaml.safe_load((range_dir / "challenges.yaml").read_text())
    return Challenges.model_validate(raw)


async def run_behavioral_checks(
    spec: "RangeSpec",
    plan: "ResolvedPlan",
    range_dir: Path,
    *,
    project: str,
    bundle: Path,
    cids: dict[str, int],
    evidence_dir: Path,
    stage_log: StageSink | None = None,
) -> tuple[BehavioralCheckRecord, ...]:
    """Run every declared check against the live (realized-image) range; a failing check ENDS the run and is returned as its record (the caller saves a refused manifest), while infra and authoring failures raise.

    Raises:
        BuildError: stage `behavioral`, for malformed check trees (`_validate_checks`) or a missing attacker; infra failures (evidence, channel) propagate as their own exceptions.
    """
    # imported here, not at module top: _provider imports _build (the gate),
    # so the behavioral runner's provider/challenge imports must stay lazy
    from .._challenges.oracle import RangeOracle
    from .._channel.channel import MessageChannel
    from .._channel.vsock import VsockTransport
    from .._provider.evidence import EvidenceSession
    from .._provider.state import SampleHandle

    challenges = load_challenges(range_dir)
    _validate_checks(challenges, range_dir)
    attacker_ip = _attacker_ip(plan)
    session = EvidenceSession(
        str(evidence_dir), sample_id=f"build-{project}", capture_local=True
    )
    await session.open(lease_id=None, project=project, bundle=bundle, plan=plan)
    channel = MessageChannel(
        VsockTransport(cids), label="build-behavioral", channel_budget_s=10.0
    )
    handle = SampleHandle(
        project=project,
        task_name=f"build-{spec.meta.name}",
        staging=bundle,
        totals=plan.totals,
        cid_base=min(cids.values()),
        guest_cids=cids,
        channel=channel,
        evidence=session,
        plan=plan,
        spec=spec,
    )
    records: list[BehavioralCheckRecord] = []
    try:
        for challenge in challenges.challenges:
            check_dir = range_dir / CHECKS_DIR_NAME / challenge.id
            for name in CHECK_NAMES:
                script = check_dir / f"{name}.sh"
                # plant keys are write-once per store and the pcap/evidence
                # memo must not leak across checks: fresh store and oracle
                # per check (fresh plants are the per-check contract)
                handle.plants = None
                oracle = RangeOracle(handle)
                record = await _run_one(
                    oracle, challenge, name, script.read_text(), attacker_ip
                )
                if stage_log is not None:
                    # stages.jsonl grammar is start|ok|fail; a failing check's
                    # detail rides the `error` field the CLI fail branch prints
                    if record.status == "pass":
                        stage_log.log(
                            "behavioral",
                            "ok",
                            challenge=challenge.id,
                            check=name,
                            detail=record.detail,
                        )
                    else:
                        stage_log.log(
                            "behavioral",
                            "fail",
                            challenge=challenge.id,
                            check=name,
                            error=record.detail,
                        )
                records.append(record)
                if record.status != "pass":
                    # a failing check is a VERDICT, not an error: the caller
                    # records it in a refused manifest (parked-decisions item
                    # 4), so the next build reuses guests and re-runs only the
                    # proof; infra failures still raise
                    return tuple(records)
    finally:
        # the provider's teardown verb: stops the capture streamer (final
        # harvest) and seals the record; bounded, idempotent, never raises
        await session.finalize()
    return tuple(records)


async def _run_one(
    oracle: "RangeOracle",
    challenge: "Challenge",
    name: str,
    script: str,
    attacker_ip: str,
) -> BehavioralCheckRecord:
    from inspect_ai.util._store import Store

    from .._challenges.setup import run_setup

    store = Store()
    planted = await run_setup(oracle, challenge, store)
    try:
        return await _execute_and_score(
            oracle, challenge, name, script, attacker_ip, store
        )
    finally:
        # the plant script refuses an existing target (it never truncates real
        # guest content), and samples plant exactly once per boot; this runner
        # reuses ONE boot across checks, so each check's plants are removed
        # here to keep the next `run_setup` fresh; removal failures are logged
        # and never mask the primary diagnosis (round-1 review)
        for key in planted:
            plant = oracle.store.plant(key)
            if not plant.path.startswith("/"):
                continue
            try:
                removal = await oracle.exec(
                    plant.guest, ["rm", "-f", "--", plant.path], user="root"
                )
                if removal.rc != 0:
                    logger.warning(
                        "check plant removal: %s:%s exited %d",
                        plant.guest,
                        plant.path,
                        removal.rc,
                    )
            except Exception:
                logger.warning(
                    "check plant removal failed: %s:%s", plant.guest, plant.path
                )


async def _execute_and_score(
    oracle: "RangeOracle",
    challenge: "Challenge",
    name: str,
    script: str,
    attacker_ip: str,
    store: "Store",
) -> BehavioralCheckRecord:
    wrapped = f"export IR_ATTACKER_IP={attacker_ip}\n{script}"
    outcome = await oracle.exec(
        "attacker", ["bash", "-c", wrapped], user="root", timeout_s=CHAIN_TIMEOUT_S
    )
    if outcome.rc != 0:
        detail = (
            f"chain exited {outcome.rc}: "
            f"{outcome.stderr.decode(errors='replace')[-300:] or outcome.stdout.decode(errors='replace')[-300:]}"
        )
        # a nonzero reference chain is a failure; nonzero insufficient/forged
        # chains are authoring errors too (they must run and score zero)
        return BehavioralCheckRecord(
            challenge=challenge.id, check=name, status="fail", detail=detail
        )
    if getattr(outcome, "stdout_truncated", False):
        # dropped SUBMIT lines would degrade a check into a vacuous pass
        return BehavioralCheckRecord(
            challenge=challenge.id,
            check=name,
            status="fail",
            detail="chain stdout truncated; SUBMIT lines may be lost",
        )
    entries: list[dict[str, object]] = []
    for line in outcome.stdout.decode(errors="replace").splitlines():
        match = _SUBMIT.match(line.strip())
        if match:
            entries.append(
                {
                    "goal_id": match.group(1),
                    "value": match.group(2),
                    "wall": time.time(),
                }
            )
    from .._challenges.scorer import score_challenge
    from .._challenges.submission import SUBMISSIONS_STORE_KEY, Submission, Submissions

    store.set(SUBMISSIONS_STORE_KEY, entries)
    if name == "reference":
        await asyncio.sleep(
            4.0
        )  # let the beacon's capture chunk rotate (refchains lesson)
    submissions = Submissions(
        [
            Submission(
                goal_id=str(e["goal_id"]),
                value=str(e["value"]),
                wall=float(e["wall"]),  # pyright: ignore[reportArgumentType]
            )
            for e in entries
        ]
    )
    value, metadata = await score_challenge(oracle, store, challenge, submissions)
    validity = str(metadata.get("validity", ""))
    goals_meta = cast("dict[str, dict[str, Any]]", metadata.get("goals", {}))
    uncorroborated = [
        goal.id
        for goal in challenge.goals
        if getattr(goal, "beacon_segment", None) is not None
        and goals_meta.get(goal.id, {}).get("corroborated") is not True
    ]
    detail = f"value={value:.2f} validity={validity} submissions={len(entries)}"
    if name == "reference":
        # a declared beacon must corroborate in capture (parked-decisions
        # item 6): a beacon that never has to land is theater
        ok = value == 1.0 and validity == "valid" and not uncorroborated
        if uncorroborated and value == 1.0 and validity == "valid":
            detail += f" uncorroborated={','.join(uncorroborated)}"
    else:
        # the negative half of the trio must FAIL FOR REAL: an indeterminate
        # scorer (validity not valid) or a chain that submitted nothing scores
        # 0.0 without ever testing whether the forgery fools scoring (round-1)
        ok = value == 0.0 and validity == "valid" and len(entries) >= 1
    return BehavioralCheckRecord(
        challenge=challenge.id,
        check=name,
        status="pass" if ok else "fail",
        detail=detail,
    )


def _attacker_ip(plan: "ResolvedPlan") -> str:
    for guest in plan.guests:
        if guest.kind == "attacker":
            return str(guest.interfaces[0].ip)
    raise BuildError("behavioral", "the plan has no attacker guest")
