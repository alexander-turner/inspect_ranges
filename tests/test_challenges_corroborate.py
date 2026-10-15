"""Slice-5 corroboration: the contradiction/gap boundary, temporal check, probe exclusion, session flags.

The integrity-critical line under test: a contradiction (evidence proving a latched claim impossible, over COMPLETE coverage) invalidates the sample; a coverage gap only flags incomplete and never changes the score. Evidence fixtures are written through the real `EvidenceWriter` so manifests, spans, and gaps carry the production shapes.
"""

import asyncio
import struct
import time
from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from inspect_ai.util import Store
from inspect_ranges._challenges.corroborate import (
    CorroborationReport,
    corroborate,
)
from inspect_ranges._challenges.engine import (
    LATCHES_STORE_KEY,
    LatchRecord,
)
from inspect_ranges._challenges.schema import Challenge, ExecuteGoal
from inspect_ranges._challenges.scorer import score_challenge
from inspect_ranges._challenges.submission import Submission, Submissions
from inspect_ranges._compiler.plan import ResolvedPlan
from inspect_ranges._evidence.manifest import ClockSpan, ClockStamp
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink

from tests.test_challenges_engine import pcap_chunk
from tests.test_challenges_oracle import make_oracle

GUEST_IP = "10.9.0.5"
SEGMENT = "dmz"


def probe_sourced_chunk(payload: bytes, src_ip: str) -> bytes:
    """One packet whose Ethernet SOURCE MAC carries the probe convention (02:50:...)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ip = (
        bytes([0x45, 0, 0, 0])
        + b"\x00" * 8
        + IPv4Address(src_ip).packed
        + IPv4Address("10.9.0.99").packed
        + payload
    )
    pkt = b"\xaa" * 6 + b"\x02\x50\x00\x00\x00\x01" + b"\x08\x00" + ip
    return out + struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt


def span(start: float, end: float) -> ClockSpan:
    return ClockSpan(start=ClockStamp(wall=start), end=ClockStamp(wall=end))


class EvidenceSessionFake:
    """Duck-typed session: `enabled`/`location` for the oracle, `record_plant` for the store."""

    def __init__(self, location: str) -> None:
        self.enabled = True
        self.location = location
        self.records: list[dict[str, object]] = []

    async def record_plant(self, record: dict[str, object]) -> None:
        self.records.append(record)


async def write_evidence(
    root: Path,
    *,
    pcap_chunks: list[tuple[bytes, ClockSpan]] | None = None,
    gaps: list[ClockSpan] | None = None,
    session_lines: list[bytes] | None = None,
) -> str:
    location = root / "evidence"
    host = EvidenceWriter(
        LocalDirSink(location), writer="host", part_interval_s=0, part_max_records=1
    )
    for data, chunk_span in pcap_chunks or []:
        await host.append(f"pcap/{SEGMENT}", data, span=chunk_span)
    for gap_span in gaps or []:
        await host.gap(f"pcap/{SEGMENT}", span=gap_span, cause="capture-dead")
    await host.seal()
    if session_lines is not None:
        driver = EvidenceWriter(
            LocalDirSink(location),
            writer="driver",
            part_interval_s=0,
            part_max_records=1,
        )
        await driver.append("session", b"\n".join(session_lines))
        await driver.seal()
    return str(location)


def execute_challenge() -> Challenge:
    return Challenge(
        id="c",
        prompt="p",
        goals=[
            ExecuteGoal(
                id="g",
                host="box",
                service_user="svc",
                token_path="/var/tmp/token",
                beacon_segment=SEGMENT,
            )
        ],
    )


def oracle_with_evidence(root: Path, location: str) -> Any:
    oracle, _, handle = make_oracle(root)
    handle.evidence = cast(Any, EvidenceSessionFake(location))
    handle.plan = cast(
        ResolvedPlan,
        SimpleNamespace(
            requirements=SimpleNamespace(evidence_capture=True),
            guests=[
                SimpleNamespace(
                    name="box",
                    interfaces=[
                        SimpleNamespace(network=SEGMENT, ip=IPv4Address(GUEST_IP))
                    ],
                )
            ],
        ),
    )
    # the oracle construction already bound handle.plants; rebind evidence-aware
    oracle._plants._session = handle.evidence  # pyright: ignore[reportPrivateUsage]
    return oracle


def claim_record(*, wall: float, corroborated: bool | None = True) -> LatchRecord:
    return LatchRecord(
        achieved=True,
        corroborated=corroborated,
        wall=wall,
        assurance="guest-corroborated",
        primitive="execute",
        elapsed_s=0.0,
    )


def run(coro: Any) -> Any:
    return asyncio.run(coro)


async def plant_token(oracle: Any) -> bytes:
    token = b"tok-6a6a6a6a"
    await oracle.store.record(
        "execute:g", token, goal_id="g", guest="box", path="/var/tmp/token"
    )
    return token


class TestClaimReverification:
    def test_present_beacon_confirms(self, tmp_path: Path) -> None:
        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (
                        pcap_chunk([(GUEST_IP, b"xx tok-6a6a6a6a xx")]),
                        span(now - 2, now),
                    )
                ],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            token = await plant_token(oracle)
            assert token in pcap_chunk([(GUEST_IP, b"xx " + token + b" xx")])
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "confirmed"
        assert not report.invalid and not report.incomplete
        assert report.scanned_bytes > 0

    def test_absent_beacon_over_complete_capture_contradicts(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (pcap_chunk([(GUEST_IP, b"innocent traffic")]), span(now - 2, now))
                ],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now - 1)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "contradicted"
        assert report.invalid

    def test_gap_overlapping_window_is_incomplete_never_invalid(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (pcap_chunk([(GUEST_IP, b"innocent")]), span(now - 10, now - 8))
                ],
                gaps=[span(now - 8, now)],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now - 1)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "unverifiable"
        assert report.incomplete and not report.invalid

    def test_coverage_stopping_before_latch_is_incomplete(self, tmp_path: Path) -> None:
        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (pcap_chunk([(GUEST_IP, b"early")]), span(now - 120, now - 100))
                ],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "unverifiable"
        assert report.incomplete and not report.invalid

    def test_probe_sourced_frames_never_confirm(self, tmp_path: Path) -> None:
        """The token appears ONLY in a frame whose source MAC carries the probe convention; exclusion-by-spec means the claim stays contradicted."""

        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (
                        probe_sourced_chunk(b"xx tok-6a6a6a6a xx", GUEST_IP),
                        span(now - 2, now),
                    )
                ],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now - 1)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "contradicted"
        assert report.invalid

    def test_unclaimed_pass_without_evidence_is_untouched(self, tmp_path: Path) -> None:
        """`corroborated=None` claims nothing: no evidence is read, nothing invalidates or flags."""

        async def scenario() -> CorroborationReport:
            oracle, _, _ = make_oracle(tmp_path)  # no evidence session at all
            await plant_token(oracle)
            now = time.time()
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now, corroborated=None)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts == {}
        assert not report.invalid and not report.incomplete

    def test_evidence_unavailable_with_claim_flags_incomplete(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> CorroborationReport:
            oracle, _, _ = make_oracle(tmp_path)  # claim exists, evidence absent
            await plant_token(oracle)
            now = time.time()
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "unverifiable"
        assert report.incomplete and not report.invalid


class TestTemporal:
    def test_submission_before_plant_contradicts(self, tmp_path: Path) -> None:
        async def scenario() -> CorroborationReport:
            oracle, _, _ = make_oracle(tmp_path)
            await plant_token(oracle)
            now = time.time()
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now, corroborated=None)},
                Submissions([Submission(goal_id="g", value="x", wall=now - 3600)]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "contradicted"
        assert report.invalid
        assert any("temporal" in flag for flag in report.flags)


class TestSessionFlags:
    def test_re_pin_inside_window_flags(self, tmp_path: Path) -> None:
        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (
                        pcap_chunk([(GUEST_IP, b"xx tok-6a6a6a6a xx")]),
                        span(now - 2, now),
                    )
                ],
                session_lines=[
                    (
                        b'{"event": "re-pinned", "guest": "box", '
                        b'"session": "s2", "wall": %f}' % (now - 1)
                    ),
                    b"not json at all",
                ],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert any("re-pin" in flag for flag in report.flags)
        assert not report.invalid  # a re-pin flags for review, never invalidates


class TestScorerWiring:
    def test_contradiction_reaches_score_validity(self, tmp_path: Path) -> None:
        """A forged `corroborated=True` latch over a complete, beacon-free capture turns the SCORE invalid; a gap in the same shape leaves it valid."""

        async def scenario(with_gap: bool) -> tuple[float, dict[str, object]]:
            now = time.time()
            location = await write_evidence(
                tmp_path / ("gap" if with_gap else "full"),
                pcap_chunks=[
                    (
                        pcap_chunk([(GUEST_IP, b"innocent")]),
                        span(now - 10, now - 5 if with_gap else now + 10),
                    )
                ],
                gaps=[span(now - 5, now + 60)] if with_gap else None,
            )
            oracle = oracle_with_evidence(tmp_path, location)
            token = await plant_token(oracle)
            store = Store()
            # a tampered/buggy claim: achieved with corroborated=True, latched
            # BEFORE scoring (what the contradiction machinery exists to catch)
            store.set(
                LATCHES_STORE_KEY,
                {"g": claim_record(wall=now + 5).model_dump(mode="json")},
            )
            submissions = Submissions(
                [Submission(goal_id="g", value=token.decode(), wall=time.time())]
            )
            return await score_challenge(
                oracle, store, execute_challenge(), submissions
            )

        value, metadata = run(scenario(with_gap=False))
        assert value == 1.0  # aggregation is untouched; validity carries the verdict
        assert metadata["validity"] == "invalid"

        value, metadata = run(scenario(with_gap=True))
        assert value == 1.0
        assert metadata["validity"] == "valid"
        corroboration = cast(dict[str, Any], metadata["corroboration"])
        assert corroboration["incomplete"] is True


class TestWindowScoping:
    def test_gap_outside_window_does_not_suppress_contradiction(
        self, tmp_path: Path
    ) -> None:
        """An ancient boot-time gap (long before the plant existed) must not shield a forged claim from contradiction."""

        async def scenario() -> CorroborationReport:
            now = time.time()
            location = await write_evidence(
                tmp_path,
                pcap_chunks=[
                    (
                        pcap_chunk([(GUEST_IP, b"innocent")]),
                        span(now - 60, now + 10),
                    )
                ],
                gaps=[span(now - 7200, now - 7100)],
            )
            oracle = oracle_with_evidence(tmp_path, location)
            await plant_token(oracle)  # recorded_wall ~ now, far after the gap
            return await corroborate(
                oracle,
                Store(),
                execute_challenge(),
                {"g": claim_record(wall=now)},
                Submissions([Submission(goal_id="g", value="x", wall=time.time())]),
            )

        report = run(scenario())
        assert report.verdicts["g"] == "contradicted"
        assert report.invalid
