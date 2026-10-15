"""The hostile mutation battery: every tamper the format claims to detect, demonstrated.

Each test builds a sealed two-stream record, applies one mutation directly to the stored objects (the attacker is not bound by the write-once sink), and asserts verify names the FIRST break with the claimed kind. The one honest limitation is pinned too: a chain is not an HMAC, so a validly re-chained forged tail is caught by the seal (parts count and chain heads), which is why the seal digest lives in the Inspect sample store.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner
from inspect_ranges._cli.evidencecmd import evidence
from inspect_ranges._evidence.manifest import (
    ClockSpan,
    ClockStamp,
    GapRecord,
    ManifestPart,
    canonical_bytes,
    chain_genesis,
    chain_next,
)
from inspect_ranges._evidence.reader import LocalDirStore, VerifyReport, verify_location
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink


class FakeClock:
    """Deterministic dual-clock source."""

    def __init__(self) -> None:
        self.now = 2000.0

    def __call__(self) -> ClockStamp:
        self.now += 1.0
        return ClockStamp(wall=self.now, monotonic=self.now / 2)


def _span(clock: FakeClock) -> ClockSpan:
    stamp = clock()
    return ClockSpan(start=stamp, end=stamp)


def _build_sealed(root: Path) -> str:
    """A sealed record: two streams, three parts, one legitimate gap; returns the seal digest."""

    async def build() -> str:
        clock = FakeClock()
        writer = EvidenceWriter(
            LocalDirSink(root),
            writer="host",
            lease_id="lease-9",
            clock=clock,
            retry_wait_s=0,
        )
        # same-size pcap chunks so a content swap hits the digest check, not size
        await writer.append("pcap/dmz", b"frame-aaa", span=_span(clock))
        await writer.append("console/web", b"line one", span=_span(clock))
        await writer.flush()  # part 0
        await writer.append("pcap/dmz", b"frame-bbb", span=_span(clock))
        await writer.gap(
            "console/web", span=_span(clock), cause="write-failed", dropped=4
        )
        await writer.flush()  # part 1
        await writer.append("pcap/dmz", b"frame-ccc", span=_span(clock))
        _, digest = await writer.seal()  # part 2 + seal
        return digest

    return asyncio.run(build())


def _verify(root: Path) -> VerifyReport:
    return asyncio.run(verify_location(LocalDirStore(root), location=str(root)))


def _break_kind(root: Path) -> str:
    report = _verify(root)
    assert not report.ok, "mutation went undetected"
    broke = report.writers["host"].first_break
    assert broke is not None
    return broke.kind


def test_clean_record_verifies(tmp_path: Path) -> None:
    digest = _build_sealed(tmp_path)
    report = _verify(tmp_path)
    assert report.ok
    host = report.writers["host"]
    assert host.sealed and host.seal_digest == digest and host.parts == 3
    assert host.streams["pcap/dmz"].chunks == 3
    assert len(host.gaps) == 1 and host.gaps[0].cause == "write-failed"
    # clock coverage spans are populated for incident orientation
    assert host.streams["pcap/dmz"].wall_start is not None


def test_mutated_chunk_bytes(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    target = tmp_path / "chunks/pcap/dmz/000001.bin"
    target.write_bytes(b"frame-XXX")  # same size: digest is what catches it
    assert _break_kind(tmp_path) == "chunk-digest"


def test_swapped_chunk_contents(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    first = tmp_path / "chunks/pcap/dmz/000000.bin"
    second = tmp_path / "chunks/pcap/dmz/000001.bin"
    a, b = first.read_bytes(), second.read_bytes()
    first.write_bytes(b)
    second.write_bytes(a)
    report = _verify(tmp_path)
    broke = report.writers["host"].first_break
    assert broke is not None and broke.kind == "chunk-digest"
    # the FIRST break is named: the earlier of the two swapped chunks
    assert broke.seq == 0


def test_deleted_chunk(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    (tmp_path / "chunks/console/web/000000.bin").unlink()
    assert _break_kind(tmp_path) == "chunk-missing"


def test_truncated_tail(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    (tmp_path / "manifests/host/part-000002.json").unlink()
    assert _break_kind(tmp_path) == "seal-parts"


def test_reput_manifest_part_without_rechain(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    key = tmp_path / "manifests/host/part-000001.json"
    part = ManifestPart.model_validate_json(key.read_bytes())
    part.records[0].span.start.wall += 7.0  # rewrite a timestamp, keep the stored chain
    key.write_bytes(canonical_bytes(part))
    assert _break_kind(tmp_path) == "chain"


def test_reput_manifest_part_with_consistent_rechain(tmp_path: Path) -> None:
    """An attacker who re-chains the tail consistently is caught by the seal's chain head."""
    _build_sealed(tmp_path)
    parts = [
        ManifestPart.model_validate_json(path.read_bytes())
        for path in sorted((tmp_path / "manifests/host").glob("part-*.json"))
    ]
    # rewrite one pcap record's span, then recompute that stream's chain end to end
    # (records commit gaps-at-call and chunks-at-delivery, so select by stream)
    target = next(r for r in parts[1].records if r.stream == "pcap/dmz")
    target.span.start.wall += 7.0
    chain = chain_genesis("host", "pcap/dmz")
    for part in parts:
        for record in part.records:
            if record.stream == "pcap/dmz":
                record.chain = chain_next(chain, record)
                chain = record.chain
    for part in parts:
        (tmp_path / f"manifests/host/part-{part.part:06d}.json").write_bytes(
            canonical_bytes(part)
        )
    assert _break_kind(tmp_path) == "seal-chain-head"


def test_forged_gap_out_of_sequence(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    key = tmp_path / "manifests/host/part-000001.json"
    part = ManifestPart.model_validate_json(key.read_bytes())
    stamp = ClockStamp(wall=1.0, monotonic=None)
    forged = GapRecord(
        stream="pcap/dmz",
        seq=0,  # duplicates an already-used slot
        span=ClockSpan(start=stamp, end=stamp),
        cause="forged",
        dropped=0,
        chain=chain_genesis("host", "pcap/dmz"),
    )
    part.records.insert(0, forged)
    key.write_bytes(canonical_bytes(part))
    assert _break_kind(tmp_path) == "record-sequence"


def test_forged_tail_part_after_seal(tmp_path: Path) -> None:
    """A validly-chained forged part appended after sealing: the seal's part count catches it."""
    _build_sealed(tmp_path)
    parts = [
        ManifestPart.model_validate_json(path.read_bytes())
        for path in sorted((tmp_path / "manifests/host").glob("part-*.json"))
    ]
    # replay the honest chain to its head, then extend it validly (no secret guards the chain)
    chain = chain_genesis("host", "pcap/dmz")
    seq = 0
    for part in parts:
        for record in part.records:
            if record.stream == "pcap/dmz":
                chain = record.chain
                seq = record.seq + 1
    stamp = ClockStamp(wall=1.0, monotonic=None)
    forged = GapRecord(
        stream="pcap/dmz",
        seq=seq,
        span=ClockSpan(start=stamp, end=stamp),
        cause="forged",
        dropped=0,
        chain=chain_genesis("host", "pcap/dmz"),
    )
    forged.chain = chain_next(chain, forged)
    extra = ManifestPart(writer="host", part=len(parts), records=[forged])
    (tmp_path / f"manifests/host/part-{extra.part:06d}.json").write_bytes(
        canonical_bytes(extra)
    )
    assert _break_kind(tmp_path) == "seal-parts"


def test_unparseable_manifest(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    (tmp_path / "manifests/host/part-000000.json").write_bytes(b"{not json")
    assert _break_kind(tmp_path) == "manifest-unparseable"


def test_unsealed_is_reported_not_broken(tmp_path: Path) -> None:
    """No seal: honest incomplete state, loudly reported, replay still clean."""
    _build_sealed(tmp_path)
    (tmp_path / "manifests/host/seal.json").unlink()
    report = _verify(tmp_path)
    host = report.writers["host"]
    assert host.ok and not host.sealed


def test_empty_location(tmp_path: Path) -> None:
    report = _verify(tmp_path)
    assert not report.ok and not report.writers


def test_two_attempts_disjoint_chains(tmp_path: Path) -> None:
    """Two attempts of one sample: disjoint prefixes, independent chains, both verify."""
    from inspect_ranges._evidence.location import derive_evidence_location

    log = str(tmp_path / "logs" / "2026-10-14T12-00-00_task_ab12.eval")
    first = derive_evidence_location(log, sample_id="s1", epoch=1, attempt=1)
    second = derive_evidence_location(log, sample_id="s1", epoch=1, attempt=2)
    assert first != second
    _build_sealed(Path(first))
    _build_sealed(Path(second))
    assert _verify(Path(first)).ok and _verify(Path(second)).ok


def test_cli_verify(tmp_path: Path) -> None:
    _build_sealed(tmp_path)
    runner = CliRunner()
    ok = runner.invoke(evidence, ["verify", str(tmp_path)])
    assert ok.exit_code == 0 and "verify: OK" in ok.output

    as_json = runner.invoke(evidence, ["verify", str(tmp_path), "--json"])
    assert as_json.exit_code == 0
    parsed: dict[str, Any] = json.loads(as_json.output)
    assert parsed["writers"]["host"]["sealed"] is True

    (tmp_path / "chunks/pcap/dmz/000000.bin").unlink()
    broken = runner.invoke(evidence, ["verify", str(tmp_path)])
    assert broken.exit_code == 1 and "BREAK [chunk-missing]" in broken.output

    remote = runner.invoke(evidence, ["verify", "s3://bucket/prefix"])
    assert remote.exit_code != 0 and "slice 3" in remote.output
