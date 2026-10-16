"""The provider's evidence session: location resolution, open/finalize/binding, and the lifecycle integration.

Slice-5 contract (`evidence-v1.md`): evidence resolves at acquire and never fails the sample, writers open only after a successful boot, `finalize evidence` is bounded and idempotent, and the binding (pointer, per-writer seal digests, chain heads) reaches the Inspect sample store with an unconditional log mirror.
"""

import asyncio
from pathlib import Path
from typing import cast

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._compiler.plan import resolve_plan
from inspect_ranges._evidence.location import EVIDENCE_SINK_OVERRIDE_VAR
from inspect_ranges._evidence.reader import LocalDirStore, verify_location
from inspect_ranges._provider.evidence import (
    EVIDENCE_BUFFER_MB_VAR,
    EvidenceSession,
    resolve_evidence_session,
)
from inspect_ranges._provider.provider import (
    LibvirtRangeSandboxEnvironment as Env,
)

from tests.test_provider_lifecycle import rigged_runtime, small_spec


def test_resolve_off_without_identity_or_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(EVIDENCE_SINK_OVERRIDE_VAR, raising=False)
    assert (
        resolve_evidence_session(sample_id="s1", run_hint="task", capture_local=True)
        is None
    )


def test_resolve_uses_override_fallback_layout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(EVIDENCE_SINK_OVERRIDE_VAR, str(tmp_path))
    session = resolve_evidence_session(
        sample_id="s1", run_hint="mytask", capture_local=False
    )
    assert session is not None
    assert session.location.startswith(f"{tmp_path}/mytask-")
    assert session.location.endswith(".evidence/s1_1_1")
    assert session.capture_local is False
    # the fallback run id is unique per resolve: a static name would turn a
    # repeated run's whole record into write-once conflicts
    second = resolve_evidence_session(
        sample_id="s1", run_hint="mytask", capture_local=False
    )
    assert second is not None and second.location != session.location


def test_admission_charge_counts_resident_writers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(EVIDENCE_BUFFER_MB_VAR, "16")
    local = EvidenceSession("loc", sample_id="s", capture_local=True)
    separated = EvidenceSession("loc", sample_id="s", capture_local=False)
    assert local.admission_memory_mb() == 32  # driver + host writers
    assert separated.admission_memory_mb() == 16  # driver only


def test_open_record_finalize_and_binding(tmp_path: Path) -> None:
    """The separated-shape session (no local capture): recorder drains into the driver's record, pins and re-pins land in the session stream, finalize seals, and the binding carries digest and chain heads that verify."""

    async def scenario() -> None:
        plan = resolve_plan(small_spec())
        session = EvidenceSession(str(tmp_path), sample_id="s1", capture_local=False)
        session.recorder.on_stage("fetch", "report", {"detail": "images ok"})
        await session.open(
            lease_id="lease-9",
            project="ir-p",
            bundle=tmp_path / "bundle",
            plan=plan,
        )
        await session.record_session_pins({"attacker": "sess-a", "web": "sess-b"})
        await session.record_session_event("web", "sess-c", "re-pinned")
        await session.finalize()
        await session.finalize()  # idempotent
        binding = session.binding()
        assert binding["location"] == str(tmp_path)
        seals = cast(dict[str, str], binding["seals"])
        assert set(seals) == {"driver"}
        session.write_binding()  # outside a sample store context: logs, never raises
        report = await verify_location(
            LocalDirStore(tmp_path), expected_seals={"driver": seals["driver"]}
        )
        driver = report.writers["driver"]
        assert report.ok and driver.binding_checked
        assert driver.lease_id == "lease-9" and driver.sample_id == "s1"
        assert set(driver.streams) == {"stages", "session"}
        heads = binding["chain_heads"]
        assert isinstance(heads, dict)
        assert heads["driver"]["session"] == await _chain_head(
            tmp_path, "driver", "session"
        )

    asyncio.run(scenario())


async def _chain_head(root: Path, writer: str, stream: str) -> str:
    from inspect_ranges._evidence.manifest import Seal

    seal = Seal.model_validate_json(
        (root / "manifests" / writer / "seal.json").read_bytes()
    )
    return seal.streams[stream].chain


def test_open_failure_disables_without_raising(tmp_path: Path) -> None:
    async def scenario() -> None:
        plan = resolve_plan(small_spec())
        session = EvidenceSession(
            "ftp://nowhere/x", sample_id="s1", capture_local=False
        )
        await session.open(
            lease_id=None, project="p", bundle=tmp_path, plan=plan
        )  # unsupported scheme: disables, never raises
        await session.record_session_pins({"web": "s"})  # no-op, no raise
        await session.finalize()
        session.write_binding()
        assert session.binding()["seals"] == {}

    asyncio.run(scenario())


def test_lifecycle_runs_evidence_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real provider lifecycle (fake seams): the session opens post-boot, the destroy path finalizes and seals, and the sample's teardown bookkeeping is untouched by evidence."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            evidence_root = tmp_path / "evidence-root"
            monkeypatch.setenv(EVIDENCE_SINK_OVERRIDE_VAR, str(evidence_root))
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "e1"})
            handles = [
                env._handle  # pyright: ignore[reportPrivateUsage]
                for env in envs.values()
                if isinstance(env, Env)
            ]
            session = handles[0].evidence
            assert session is not None, "the session rides the handle after boot"
            location = Path(session.location)
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert runtime.registry == {} and seams.down_calls, (
                "teardown bookkeeping is evidence-independent"
            )
            report = await verify_location(LocalDirStore(location))
            driver = report.writers["driver"]
            assert report.ok and driver.seal_status == "complete"
            assert "session" in driver.streams, "the boot pins are in the record"
            # local topology: the streamer owns the recorder, so stage events
            # live in the HOST writer's record (sealed by finalize even though
            # the fake project has no live sidecar to harvest)
            host = report.writers["host"]
            assert host.seal_status == "complete"
            assert "stages" in host.streams, "stage events are in the record"

    asyncio.run(scenario())


def test_lifecycle_without_evidence_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            monkeypatch.delenv(EVIDENCE_SINK_OVERRIDE_VAR, raising=False)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "n1"})
            handles = [
                env._handle  # pyright: ignore[reportPrivateUsage]
                for env in envs.values()
                if isinstance(env, Env)
            ]
            assert handles[0].evidence is None
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert runtime.registry == {}
            del seams

    asyncio.run(scenario())


def test_finalize_with_failing_sink_never_raises(tmp_path: Path) -> None:
    """Evidence never destabilizes the sample: a sink that refuses every put leaves the record unsealed and finalize/binding still return."""

    class RefusingSink:
        async def put(self, key: str, data: bytes) -> None:
            raise ConnectionError("sink down")

    async def scenario() -> None:
        plan = resolve_plan(small_spec())
        session = EvidenceSession(str(tmp_path), sample_id="s1", capture_local=False)
        await session.open(lease_id=None, project="p", bundle=tmp_path, plan=plan)
        # swap the sink under the opened writer: the delivery path must buffer
        # and the seal must fail SOFT (logged), never raise out of finalize
        writer = session._driver  # pyright: ignore[reportPrivateUsage]
        assert writer is not None
        writer._sink = RefusingSink()  # pyright: ignore[reportPrivateUsage]
        writer._put_attempts = 1  # pyright: ignore[reportPrivateUsage]
        await session.record_session_pins({"web": "s"})
        await session.finalize()
        session.write_binding()
        assert session.binding()["seals"] == {}

    asyncio.run(scenario())


def test_wedged_producer_stop_cannot_starve_the_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The finalize phases (quality-review A6): a producer stop that outlives its share still yields a SEALED record (status incomplete), a binding carrying the seal digest, and a verifiable driver writer (adopted from the U7 probe, which demonstrated a permanently unsealed record with an empty binding)."""
    import inspect_ranges._provider.evidence as evidence_mod

    async def scenario() -> None:
        plan = resolve_plan(small_spec())
        session = EvidenceSession(str(tmp_path), sample_id="s1", capture_local=False)
        await session.open(
            lease_id="feedfeedfeedfeedfeedfeedfeedfeed",
            project="ir-probe",
            bundle=tmp_path / "bundle",
            plan=plan,
        )
        await session.append_driver("session", b'{"event": "pinned"}\n')

        async def wedged_stop() -> None:
            await asyncio.sleep(5.0)

        session.register_producer(wedged_stop)
        monkeypatch.setattr(evidence_mod, "FINALIZE_BUDGET_S", 0.6)
        monkeypatch.setattr(evidence_mod, "SEAL_RESERVE_S", 0.4)
        await session.finalize()
        await session.finalize()  # idempotent, still no retry
        seals = cast(dict[str, str], session.binding()["seals"])
        assert set(seals) == {"driver"}, "the seal phase always gets its share"
        report = await verify_location(
            LocalDirStore(tmp_path), expected_seals={"driver": seals["driver"]}
        )
        driver = report.writers["driver"]
        assert report.ok and driver.sealed and driver.binding_checked
        assert driver.seal_status == "incomplete", (
            "a stop timeout loses producer tails; the seal says so"
        )

    asyncio.run(scenario())


def test_hanging_sink_bounds_the_seal_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sink whose puts hang forever: finalize returns within its phase budgets with the record unsealed (the one remaining unsealed case, honestly logged), never raising and never holding teardown (quality-review A6 and coverage proposal T6)."""
    import time as time_mod

    import inspect_ranges._provider.evidence as evidence_mod

    class HangingSink:
        async def put(self, key: str, data: bytes) -> None:
            await asyncio.Event().wait()  # never set

    async def scenario() -> None:
        plan = resolve_plan(small_spec())
        session = EvidenceSession(str(tmp_path), sample_id="s1", capture_local=False)
        await session.open(lease_id=None, project="p", bundle=tmp_path, plan=plan)
        await session.record_session_pins({"web": "s"})
        # the sink hangs from HERE: only finalize's phase budgets bound it
        writer = session._driver  # pyright: ignore[reportPrivateUsage]
        assert writer is not None
        writer._sink = HangingSink()  # pyright: ignore[reportPrivateUsage]
        monkeypatch.setattr(evidence_mod, "FINALIZE_BUDGET_S", 0.6)
        monkeypatch.setattr(evidence_mod, "SEAL_RESERVE_S", 0.3)
        started = time_mod.monotonic()
        await session.finalize()
        assert time_mod.monotonic() - started < 5.0, "finalize stays bounded"
        session.write_binding()
        assert session.binding()["seals"] == {}

    asyncio.run(scenario())


def test_bad_knob_disables_evidence_not_the_sample(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(EVIDENCE_SINK_OVERRIDE_VAR, str(tmp_path))
    monkeypatch.setenv(EVIDENCE_BUFFER_MB_VAR, "64MB")
    assert (
        resolve_evidence_session(sample_id="s", run_hint="t", capture_local=True)
        is None
    ), "a malformed knob disables evidence with a named error, never the sample"


def test_knob_validation() -> None:
    import os

    from inspect_ranges._provider.evidence import (
        evidence_buffer_bytes,
        evidence_max_bytes,
    )

    os.environ[EVIDENCE_BUFFER_MB_VAR] = "0"
    try:
        with pytest.raises(ValueError):
            evidence_buffer_bytes()
    finally:
        del os.environ[EVIDENCE_BUFFER_MB_VAR]
    os.environ["INSPECT_RANGES_EVIDENCE_MAX_MB"] = "-1"
    try:
        with pytest.raises(ValueError):
            evidence_max_bytes()
    finally:
        del os.environ["INSPECT_RANGES_EVIDENCE_MAX_MB"]
