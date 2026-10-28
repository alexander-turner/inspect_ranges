"""Slice-2 battery (CI half): the oracle's raw-channel discipline, the plant store's value/digest split, and setup/unwind semantics.

The residue rule is pinned mechanically: a recording endpoint captures every request the oracle sends, and tests assert plant values appear ONLY as `write_file` bulk, never in argv, env, stdin, logs, or the emitted plant records.
"""

import asyncio
import json
import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from inspect_ranges._challenges.oracle import (
    PLANT_SCRIPT,
    WIN_PLANT_SCRIPT,
    WIN_UNPLANT_SCRIPT,
    OracleSetupError,
    RangeOracle,
)
from inspect_ranges._challenges.plants import PlantStore
from inspect_ranges._challenges.schema import Challenge
from inspect_ranges._challenges.setup import (
    _unwind,  # pyright: ignore[reportPrivateUsage]
    plant_and_start,
    plant_secret_file,
    run_setup,
)
from inspect_ranges._channel.channel import (  # pyright: ignore[reportPrivateUsage]
    GuestError,
    LoopbackTransport,
    MessageChannel,
    TransportFailure,
    _StoredReply,
)
from inspect_ranges._channel.protocol import (
    ExecEventsReply,
    ExecRequest,
    Message,
    WriteFileRequest,
)
from inspect_ranges._compiler.plan import ResolvedPlan, Totals
from inspect_ranges._evidence.execwitness import ExecWitnessPoller
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink
from inspect_ranges._evidence.telemetry import CollectorSpec, FileSource
from inspect_ranges._provider.provider import (
    RangeSandboxEnvironment,
    sample_handle_for,
)
from inspect_ranges._provider.state import SampleHandle

from tests.local_endpoint import LocalEndpoint, _result_reply
from tests.test_evidence_execwitness import WitnessFakeChannel, event, reply

VALUE_MARKER = b"never-in-argv"
"""Plant values in these tests carry this marker so residue scans are unambiguous."""


class RecordingEndpoint(LocalEndpoint):
    """A `LocalEndpoint` that records every request and its bulk for residue assertions."""

    def __init__(self, name: str, root: Path) -> None:
        super().__init__(name, root)
        self.requests: list[tuple[Message, bytes | None]] = []

    async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
        self.requests.append((message, bulk))
        return await super().handle(message, bulk)

    async def _run_command(self, request: ExecRequest, stdin: bytes) -> _StoredReply:
        # ownership emulation, extending LocalEndpoint's root-chown shape: the
        # CI host cannot be root, so the oracle's root verbs are emulated at
        # the contract level. The plant script writes stdin at the translated
        # path with the requested mode and records the owner; root `rm` (the
        # unwind verb) runs as the current user.
        if request.user == "root" and request.cmd[:3] == ["sh", "-c", PLANT_SCRIPT]:
            _, _, _, _, path, mode, owner = request.cmd
            target = self.translate(path)
            if target.exists():
                # the script's pre-existence refusal: nothing touched, exit 2
                reply = _result_reply(
                    request, rc=2, stdout=b"", stderr=b"plant target exists\n"
                )
                self._store(request.id, reply)
                return reply
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stdin)
            target.chmod(int(mode, 8))
            self.file_modes[path] = int(mode, 8)
            self.file_owners[path] = owner
            reply = _result_reply(request, rc=0, stdout=b"", stderr=b"")
            self._store(request.id, reply)
            return reply
        if request.cmd and request.cmd[-1] == WIN_PLANT_SCRIPT:
            # contract-level emulation of the Windows plant (no powershell on
            # the CI host): path/principal arrive in env, value on stdin
            win_path = request.env["IR_PLANT_PATH"]
            target = self.translate(_strip_drive(win_path))
            if target.exists():
                reply = _result_reply(
                    request, rc=2, stdout=b"", stderr=b"plant target exists\n"
                )
                self._store(request.id, reply)
                return reply
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stdin)
            self.file_owners[win_path] = request.env["IR_PLANT_PRINCIPAL"]
            reply = _result_reply(request, rc=0, stdout=b"", stderr=b"")
            self._store(request.id, reply)
            return reply
        if request.cmd and request.cmd[-1] == WIN_UNPLANT_SCRIPT:
            target = self.translate(_strip_drive(request.env["IR_PLANT_PATH"]))
            target.unlink(missing_ok=True)
            reply = _result_reply(request, rc=0, stdout=b"", stderr=b"")
            self._store(request.id, reply)
            return reply
        if request.user == "root" and request.cmd and request.cmd[0] in ("rm", "cat"):
            return await super()._run_command(
                request.model_copy(update={"user": None}), stdin
            )
        return await super()._run_command(request, stdin)


def _strip_drive(win_path: str) -> str:
    """A Windows plant path as the endpoint's private-tmp translation input (`translate` maps only the agent home and `/tmp`; other absolute paths touch the real host)."""
    return "/tmp/" + win_path.partition(":\\")[2].replace("\\", "/")


class FailingPlantEndpoint(RecordingEndpoint):
    """The plant script fails here (as it would for an unknown owner), writing nothing."""

    async def _run_command(self, request: ExecRequest, stdin: bytes) -> _StoredReply:
        if request.cmd[:3] == ["sh", "-c", PLANT_SCRIPT]:
            reply = _result_reply(
                request, rc=1, stdout=b"", stderr=b"chown: invalid user\n"
            )
            self._store(request.id, reply)
            return reply
        return await super()._run_command(request, stdin)


class FakePlantSession:
    """Captures `record_plant` payloads; duck-typed for `PlantStore` and `available_observers`."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.records: list[dict[str, object]] = []
        self.enabled = enabled
        self.driver_writer: object | None = None
        """Mimics `EvidenceSession.driver_writer`; `None` makes telemetry producer start refuse."""

    async def record_plant(self, record: dict[str, object]) -> None:
        self.records.append(record)


def make_oracle(
    root: Path,
    *,
    endpoint: RecordingEndpoint | None = None,
    session: FakePlantSession | None = None,
    capture: bool = False,
    windows: bool = False,
) -> tuple[RangeOracle, RecordingEndpoint, SampleHandle]:
    """An oracle over a recording local endpoint named `box`."""
    endpoint = endpoint or RecordingEndpoint("box", root)
    transport = LoopbackTransport(guests=())
    transport.guests["box"] = endpoint
    plan = cast(
        ResolvedPlan,
        SimpleNamespace(
            requirements=SimpleNamespace(evidence_capture=capture, probe_segments=()),
            guests=[SimpleNamespace(name="box", os="windows" if windows else "linux")],
        ),
    )
    handle = SampleHandle(
        project="ir-challenges-test",
        task_name="challenges",
        staging=root / "staging",
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=10_000,
        guest_cids={"box": 10_000},
        channel=MessageChannel(transport, label="challenges-test"),
        evidence=cast(Any, session),
        plan=plan,
    )
    return RangeOracle(handle), endpoint, handle


def recorded_execs(endpoint: RecordingEndpoint) -> list[ExecRequest]:
    return [m for m, _ in endpoint.requests if isinstance(m, ExecRequest)]


def assert_no_residue(endpoint: RecordingEndpoint, value: bytes) -> None:
    """The value rides only the sanctioned content channels (`write_file` bulk, the plant script's stdin bulk): never argv, env, paths, or any other request field."""
    for message, bulk in endpoint.requests:
        serialized = message.model_dump_json().encode()
        assert value not in serialized, f"plant value in request fields: {message.kind}"
        sanctioned = isinstance(message, WriteFileRequest) or (
            isinstance(message, ExecRequest)
            and (
                message.cmd[:3] == ["sh", "-c", PLANT_SCRIPT]
                or message.cmd[-1:] == [WIN_PLANT_SCRIPT]
            )
        )
        if bulk is not None and not sanctioned:
            assert value not in bulk, f"plant value in {message.kind} bulk"


class TestOracleWriteFile:
    def test_owner_flow_root_script_value_on_stdin_only(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path)
            value = VALUE_MARKER + b"-owner"
            await oracle.write_file("box", "/tmp/plant", value, owner="svc")
            assert endpoint.file_modes["/tmp/plant"] == 0o600
            assert endpoint.file_owners["/tmp/plant"] == "svc"
            [plant] = recorded_execs(endpoint)
            assert plant.cmd == [
                "sh",
                "-c",
                PLANT_SCRIPT,
                "plant",
                "/tmp/plant",
                "600",
                "svc",
            ]
            assert plant.user == "root"
            assert plant.env == {}
            assert_no_residue(endpoint, value)
            assert (tmp_path / "tmp" / "plant").read_bytes() == value

        asyncio.run(scenario())

    def test_preexisting_target_refused_untouched(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)
            existing = tmp_path / "tmp" / "occupied"
            existing.parent.mkdir(parents=True, exist_ok=True)
            existing.write_bytes(b"real guest content")
            with pytest.raises(OracleSetupError):
                await oracle.write_file("box", "/tmp/occupied", b"plant", owner="svc")
            assert existing.read_bytes() == b"real guest content"

        asyncio.run(scenario())

    def test_privileged_read_honors_caller_cap(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)
            await oracle.write_file("box", "/tmp/big", b"x" * 8192, owner=None)
            with pytest.raises(OracleSetupError, match="cap"):
                await oracle.read_file("box", "/tmp/big", cap=4096, user="root")
            small = await oracle.read_file("box", "/tmp/big", user="root")
            assert small == b"x" * 8192

        asyncio.run(scenario())

    def test_exec_timeout_conversion_never_zero(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path)
            await oracle.exec("box", ["true"], timeout_s=0.0005)
            [request] = recorded_execs(endpoint)
            assert request.budget.command_ms == 1

        asyncio.run(scenario())

    def test_no_owner_means_no_exec(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path)
            await oracle.write_file("box", "/tmp/raw", b"content", owner=None)
            assert recorded_execs(endpoint) == []
            assert endpoint.file_modes["/tmp/raw"] == 0o600

        asyncio.run(scenario())

    def test_plant_failure_leaves_nothing_and_names_principal(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> None:
            endpoint = FailingPlantEndpoint("box", tmp_path)
            oracle, _, _ = make_oracle(tmp_path, endpoint=endpoint)
            value = VALUE_MARKER + b"-rollback"
            with pytest.raises(OracleSetupError) as excinfo:
                await oracle.write_file("box", "/tmp/doomed", value, owner="ghost")
            message = str(excinfo.value)
            assert "ghost" in message and "/tmp/doomed" in message
            assert VALUE_MARKER.decode() not in message
            assert not (tmp_path / "tmp" / "doomed").exists()
            assert_no_residue(endpoint, value)

        asyncio.run(scenario())


class TestAnswerOracleRead:
    def test_oracle_read_source_snapshots_at_setup(self, tmp_path: Path) -> None:
        """The host+path answer source snapshots at setup (fourteenth scoring-integrity amendment): the expected value is fixed before agent entry, so rewriting the file afterwards moves nothing, and the rewrite-and-submit attack scores zero."""
        import time as _time

        from inspect_ranges._challenges.goaltypes import AnswerType
        from inspect_ranges._challenges.schema import AnswerGoal
        from inspect_ranges._challenges.submission import Submission, Submissions

        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)
            await oracle.write_file("box", "/tmp/fact", b"a1b2c3\n")
            goal = AnswerGoal(id="fact", host="box", path="/tmp/fact")
            engine = AnswerType()
            assert engine.assurance_for(goal) == "host-anchored"
            keys = await engine.setup(goal, oracle)
            assert keys == ["answer:fact"]
            right = Submissions(
                [Submission(goal_id="fact", value="a1b2c3", wall=_time.time())]
            )
            observations = await engine.check(goal, oracle, right)
            assert engine.compare(goal, observations, oracle.store).achieved
            # the agent rewrites the comparison source and submits the rewrite
            await oracle.write_file("box", "/tmp/fact", b"forged\n")
            attack = Submissions(
                [Submission(goal_id="fact", value="forged", wall=_time.time())]
            )
            observations = await engine.check(goal, oracle, attack)
            assert not engine.compare(goal, observations, oracle.store).achieved
            # the setup-time truth still scores after the rewrite
            observations = await engine.check(goal, oracle, right)
            assert engine.compare(goal, observations, oracle.store).achieved

        asyncio.run(scenario())


class TestPlantAndStart:
    def test_producer_start_failure_unwinds_plants(self, tmp_path: Path) -> None:
        """B15: the never-half-planted contract covers producer start, not only plants."""

        async def scenario() -> None:
            session = FakePlantSession()
            oracle, _, _ = make_oracle(tmp_path, session=session)
            challenge = challenge_of(
                [
                    {
                        "id": "user",
                        "type": "flag",
                        "host": "box",
                        "path": "/tmp/user-flag",
                    },
                    {
                        "id": "seen",
                        "type": "detection",
                        "collector": "siem",
                        "signal": "intrusion",
                    },
                ]
            )
            collector = CollectorSpec(
                name="siem", guest="box", source=FileSource(path="/var/log/app.log")
            )
            with pytest.raises(RuntimeError, match="driver evidence writer"):
                await plant_and_start(
                    oracle,
                    challenge,
                    None,
                    [collector],
                    extra_observers=frozenset({"telemetry-collector"}),
                )
            assert oracle.store.keys() == []
            assert not (tmp_path / "tmp" / "user-flag").exists()
            assert [r["event"] for r in session.records] == ["planted", "unwound"]

        asyncio.run(scenario())

    def test_failing_telemetry_half_never_starts_the_prober(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Raise-able producer steps run before anything starts: a refused sample must not leave a prober probing its unwound range."""
        import inspect_ranges._challenges.setup as setup_module
        from inspect_ranges._challenges.prober import ProbeTarget

        started: list[str] = []

        class RecordingProber:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def start(self) -> None:
                started.append("prober")

            async def stop(self) -> None:  # pragma: no cover - never started
                pass

        async def scenario() -> None:
            monkeypatch.setattr(setup_module, "Prober", RecordingProber)

            def fixed_targets(oracle: object, challenge: object) -> list[ProbeTarget]:
                return [ProbeTarget(goal_id="t", ip="10.0.0.9", port=8080)]

            monkeypatch.setattr(setup_module, "_probe_targets", fixed_targets)
            session = FakePlantSession()  # driver_writer None: telemetry refuses
            oracle, _, _ = make_oracle(tmp_path, session=session)
            challenge = challenge_of(
                [
                    {
                        "id": "seen",
                        "type": "detection",
                        "collector": "siem",
                        "signal": "intrusion",
                    }
                ]
            )
            collector = CollectorSpec(
                name="siem", guest="box", source=FileSource(path="/var/log/app.log")
            )
            with pytest.raises(RuntimeError, match="driver evidence writer"):
                await plant_and_start(
                    oracle,
                    challenge,
                    None,
                    [collector],
                    extra_observers=frozenset({"telemetry-collector"}),
                )
            assert started == []

        asyncio.run(scenario())

    def test_cancellation_during_producer_start_still_unwinds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A sample cancellation mid-start must not leave the half-planted state (shielded unwind)."""
        import inspect_ranges._challenges.setup as setup_module

        async def hanging(*args: object, **kwargs: object) -> None:
            await asyncio.Event().wait()

        async def scenario() -> None:
            monkeypatch.setattr(setup_module, "_start_producers", hanging)
            session = FakePlantSession()
            oracle, _, _ = make_oracle(tmp_path, session=session)
            challenge = challenge_of(
                [
                    {
                        "id": "user",
                        "type": "flag",
                        "host": "box",
                        "path": "/tmp/user-flag",
                    }
                ]
            )
            task = asyncio.create_task(plant_and_start(oracle, challenge, None, []))
            await asyncio.sleep(0.2)  # plants land, producers hang
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.2)  # a detached unwind gets its beat
            assert oracle.store.keys() == []
            assert not (tmp_path / "tmp" / "user-flag").exists()
            assert [r["event"] for r in session.records] == ["planted", "unwound"]

        asyncio.run(scenario())


class TestOracleSurface:
    def test_exec_and_read_file_roundtrip(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)
            outcome = await oracle.exec("box", ["echo", "hello"])
            assert outcome.rc == 0 and outcome.stdout.strip() == b"hello"
            await oracle.write_file("box", "/tmp/readback", b"data", owner=None)
            assert await oracle.read_file("box", "/tmp/readback") == b"data"

        asyncio.run(scenario())

    def test_nonce_fresh_per_call(self, tmp_path: Path) -> None:
        oracle, _, _ = make_oracle(tmp_path)
        nonces = {oracle.nonce() for _ in range(100)}
        assert len(nonces) == 100
        assert all(len(nonce) == 32 for nonce in nonces)

    def test_resolved_requires_plan(self, tmp_path: Path) -> None:
        oracle, _, handle = make_oracle(tmp_path)
        handle.plan = None
        with pytest.raises(OracleSetupError):
            oracle.resolved()

    def test_sample_handle_for_rejects_foreign_env(self, tmp_path: Path) -> None:
        with pytest.raises(TypeError):
            sample_handle_for(cast(Any, object()))
        _, _, handle = make_oracle(tmp_path)
        env = RangeSandboxEnvironment("box", handle)
        assert sample_handle_for(env) is handle

    def test_available_observers(self, tmp_path: Path) -> None:
        oracle, _, _ = make_oracle(tmp_path)
        assert oracle.available_observers() == frozenset()
        oracle, _, _ = make_oracle(tmp_path, session=FakePlantSession())
        assert oracle.available_observers() == frozenset({"evidence-sink"})
        oracle, _, _ = make_oracle(tmp_path, session=FakePlantSession(), capture=True)
        assert oracle.available_observers() == frozenset(
            {"evidence-sink", "segment-pcap", "console"}
        )


class FakeEvidenceSession(FakePlantSession):
    """`FakePlantSession` plus the `.location` the oracle's evidence accessors derive their read store from."""

    def __init__(self, location: str) -> None:
        super().__init__()
        self.location = location


async def _witnessed_oracle(
    root: Path, script: list[ExecEventsReply | Exception]
) -> RangeOracle:
    """An oracle over a record the real `ExecWitnessPoller` wrote from scripted replies (the production-written-fixture discipline: the accessor reads exactly what the witness ships, never a hand-built transcript)."""
    channel = WitnessFakeChannel()
    channel.script = list(script)
    location = root / "evidence"
    writer = EvidenceWriter(LocalDirSink(location), part_interval_s=0, writer="driver")
    poller = ExecWitnessPoller(cast(Any, channel), writer, ["box"], [], meta_flush_s=0)
    await poller.poll_once("box")
    await poller.stop()
    await writer.checkpoint()
    oracle, _, _ = make_oracle(root, session=FakeEvidenceSession(str(location)))
    return oracle


class TestExecEventsAccessor:
    def test_round_trip_ordering_spans_and_memo(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle = await _witnessed_oracle(
                tmp_path,
                [
                    reply([event(0, argv=["id"]), event(1, argv=["nmap", "-sV"])], 2),
                    reply([], 2),
                ],
            )
            meta, events, gapped = await oracle.exec_events("box")
            assert not gapped
            assert [e.record["seq"] for e in events] == [0, 1]
            assert events[1].record["argv"] == ["nmap", "-sV"]
            assert [m.record["outcome"] for m in meta] == ["ok", "ok"]
            # exec events stamp no `wall`: the chunk's host span start is the fallback
            assert "wall" not in events[0].record
            assert events[0].wall() == events[0].wall_start > 0.0
            with oracle.evidence_memo():
                first = await oracle.exec_events("box")
                assert await oracle.exec_events("box") is first

        asyncio.run(scenario())

    @pytest.mark.parametrize(
        "script",
        [
            pytest.param([reply([event(5)], 6), reply([], 6)], id="ring-overflow"),
            pytest.param(
                [reply([event(0)], 1, drops=3), reply([], 1, drops=3)],
                id="subscriber-loss",
            ),
        ],
    )
    def test_counted_loss_flips_the_gap_flag(
        self, tmp_path: Path, script: list[ExecEventsReply | Exception]
    ) -> None:
        async def scenario() -> None:
            oracle = await _witnessed_oracle(tmp_path, script)
            _, events, gapped = await oracle.exec_events("box")
            assert gapped
            assert events, "surviving events still read back alongside the gap"

        asyncio.run(scenario())

    def test_daemon_unsupported_declares_one_meta_record(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle = await _witnessed_oracle(
                tmp_path, [GuestError("ENOSYS", "exec witness unavailable", None)]
            )
            meta, events, gapped = await oracle.exec_events("box")
            assert events == [] and not gapped
            [drop] = meta
            assert drop.record["outcome"] == "unsupported"
            assert drop.record["reason"] == "daemon-unsupported"
            assert drop.record["errno"] == "ENOSYS"

        asyncio.run(scenario())

    def test_no_evidence_session_refuses(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)
            with pytest.raises(OracleSetupError):
                await oracle.exec_events("box")

        asyncio.run(scenario())


class TestPlantStore:
    def test_record_emits_digest_never_value(self) -> None:
        async def scenario() -> None:
            session = FakePlantSession()
            store = PlantStore(cast(Any, session))
            value = VALUE_MARKER + b"-digest"
            await store.record(
                "flag:f1", value, goal_id="f1", guest="box", path="/tmp/f"
            )
            assert store.get("flag:f1") == value
            [record] = session.records
            assert record["event"] == "planted"
            assert record["sha256"] == store.digest("flag:f1")
            assert record["size"] == len(value)
            serialized = json.dumps(record).encode()
            assert value not in serialized and b'"value"' not in serialized

        asyncio.run(scenario())

    def test_duplicate_key_refused(self) -> None:
        async def scenario() -> None:
            store = PlantStore(None)
            await store.record("k", b"v", goal_id="g", guest="box", path="/p")
            with pytest.raises(ValueError):
                await store.record("k", b"w", goal_id="g", guest="box", path="/p")

        asyncio.run(scenario())

    def test_discard_emits_unwound(self) -> None:
        async def scenario() -> None:
            session = FakePlantSession()
            store = PlantStore(cast(Any, session))
            await store.record("k", b"v", goal_id="g", guest="box", path="/p")
            await store.discard("k", reason="setup unwound")
            assert [r["event"] for r in session.records] == ["planted", "unwound"]
            assert session.records[1]["reason"] == "setup unwound"
            with pytest.raises(KeyError):
                store.get("k")

        asyncio.run(scenario())

    def test_plant_repr_hides_value(self) -> None:
        async def scenario() -> None:
            store = PlantStore(None)
            await store.record("k", VALUE_MARKER, goal_id="g", guest="box", path="/p")
            assert VALUE_MARKER.decode() not in repr(store.plant("k"))

        asyncio.run(scenario())


def challenge_of(goals: list[dict[str, object]]) -> Challenge:
    return Challenge.model_validate({"id": "c", "prompt": "do things", "goals": goals})


class TestRunSetup:
    def test_plants_in_order_with_t1_records(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        async def scenario() -> None:
            session = FakePlantSession()
            oracle, endpoint, _ = make_oracle(tmp_path, session=session)
            challenge = challenge_of(
                [
                    {
                        "id": "user",
                        "type": "flag",
                        "host": "box",
                        "path": "/tmp/user-flag",
                    },
                    {
                        "id": "root",
                        "type": "control",
                        "host": "box",
                        "principal": "svc",
                        "secret_path": "/tmp/root-secret",
                    },
                ]
            )
            with caplog.at_level(logging.INFO, logger="inspect_ranges.challenges"):
                await run_setup(oracle, challenge)
            assert [r["key"] for r in session.records] == ["flag:user", "control:root"]
            flag_value = oracle.store.get("flag:user")
            assert (tmp_path / "tmp" / "user-flag").read_bytes() == flag_value
            assert endpoint.file_owners["/tmp/user-flag"] == "root"
            assert endpoint.file_owners["/tmp/root-secret"] == "svc"
            for key in ("flag:user", "control:root"):
                value = oracle.store.get(key)
                assert_no_residue(endpoint, value)
                assert not any(
                    value.decode() in record.getMessage() for record in caplog.records
                )

        asyncio.run(scenario())

    def test_failure_unwinds_prior_plants(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            session = FakePlantSession()
            oracle, _, _ = make_oracle(tmp_path, session=session)
            challenge = challenge_of(
                [
                    {"id": "ok", "type": "flag", "host": "box", "path": "/tmp/planted"},
                    {
                        "id": "bad",
                        "type": "flag",
                        "host": "missing-guest",
                        "path": "/tmp/never",
                    },
                ]
            )
            with pytest.raises(RuntimeError, match="setup failed at goal 'bad'"):
                await run_setup(oracle, challenge)
            assert not (tmp_path / "tmp" / "planted").exists()
            # the T1 record precedes guest state: the failing plant records,
            # then self-discards on write failure, then the earlier plant
            # unwinds
            assert [(r["event"], r["key"]) for r in session.records] == [
                ("planted", "flag:ok"),
                ("planted", "flag:bad"),
                ("unwound", "flag:bad"),
                ("unwound", "flag:ok"),
            ]
            assert oracle.store.keys() == []

        asyncio.run(scenario())

    def test_missing_observer_refuses_before_any_plant(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path, session=None)
            challenge = challenge_of(
                [{"id": "f", "type": "flag", "host": "box", "path": "/tmp/f"}]
            )
            with pytest.raises(RuntimeError, match="evidence-sink"):
                await run_setup(oracle, challenge)
            assert endpoint.requests == []

        asyncio.run(scenario())

    def test_write_failure_discards_record(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            session = FakePlantSession()
            oracle, _, _ = make_oracle(tmp_path, session=session)
            with pytest.raises(TransportFailure):
                await plant_secret_file(
                    oracle,
                    key="flag:x",
                    goal_id="x",
                    guest="absent",
                    path="/tmp/x",
                    owner="root",
                )
            assert oracle.store.keys() == []
            assert [r["event"] for r in session.records] == ["planted", "unwound"]

        asyncio.run(scenario())


class TestTracebackLocalsScrub:
    """A failing plant's challenge-layer frames carry no plant bytes, so a locals-rendered traceback (`INSPECT_TRACEBACK_LOCALS=1`) cannot leak them from here (lower channel frames are documented out of scope; the flag stays forbidden on scoring runs)."""

    def test_plant_frames_scrubbed(self, tmp_path: Path) -> None:
        async def scenario() -> list[types.FrameType]:
            endpoint = FailingPlantEndpoint("box", tmp_path)
            oracle, _, _ = make_oracle(tmp_path, endpoint=endpoint)
            oracle.nonce = lambda: VALUE_MARKER.decode()  # type: ignore[method-assign]
            try:
                await plant_secret_file(
                    oracle,
                    key="k",
                    goal_id="g",
                    guest="box",
                    path="/tmp/x",
                    owner="ghost",
                )
            except OracleSetupError:
                frames: list[types.FrameType] = []
                tb = sys.exc_info()[2]
                while tb is not None:
                    frames.append(tb.tb_frame)
                    tb = tb.tb_next
                return frames
            raise AssertionError("plant unexpectedly succeeded")

        frames = asyncio.run(scenario())
        ours = [
            frame
            for frame in frames
            if frame.f_code.co_name in ("plant_secret_file", "write_file")
            and "_challenges" in frame.f_code.co_filename
        ]
        assert len(ours) >= 2, "expected both challenge-layer frames in the chain"
        for frame in ours:
            for name, local in frame.f_locals.items():
                assert VALUE_MARKER.decode() not in repr(local), (
                    f"plant bytes in frame {frame.f_code.co_name} local {name!r}"
                )


class TestWindowsPlantShape:
    """Windows-ad-v1 slice 4: a Windows target dispatches the fixed PowerShell plant literal, with the path and principal in env (no quoting surface), the value on stdin, and the daemon's SYSTEM identity (user None — "root" is not a Windows principal)."""

    def test_windows_plant_dispatches_env_carried_literal(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path, windows=True)
            value = VALUE_MARKER + b"-win"
            path = "C:\\ProgramData\\proof\\token"
            await oracle.write_file("box", path, value, owner="NORTH\\Administrator")
            [plant] = recorded_execs(endpoint)
            assert plant.cmd[0] == "powershell" and plant.cmd[-1] == WIN_PLANT_SCRIPT
            assert plant.env == {
                "IR_PLANT_PATH": path,
                "IR_PLANT_PRINCIPAL": "NORTH\\Administrator",
            }
            assert plant.user is None
            assert_no_residue(endpoint, value)
            assert (
                tmp_path / "tmp" / "ProgramData" / "proof" / "token"
            ).read_bytes() == value
            assert endpoint.file_owners[path] == "NORTH\\Administrator"

        asyncio.run(scenario())

    def test_windows_plant_unwinds_through_the_fixed_literal(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> None:
            oracle, endpoint, _ = make_oracle(tmp_path, windows=True)
            path = "C:\\ProgramData\\proof\\token"
            key = await plant_secret_file(
                oracle,
                key="control:srv02-admin",
                goal_id="srv02-admin",
                guest="box",
                path=path,
                owner="NORTH\\Administrator",
            )
            target = tmp_path / "tmp" / "ProgramData" / "proof" / "token"
            assert target.exists()
            await _unwind(oracle, [key])
            assert not target.exists()
            unplant = recorded_execs(endpoint)[-1]
            assert unplant.cmd[-1] == WIN_UNPLANT_SCRIPT
            assert unplant.env == {"IR_PLANT_PATH": path}
            assert unplant.user is None

        asyncio.run(scenario())
