"""Reap-sealing: an abandoned record gets a `reaped` seal the verifier accepts; broken records are left honestly unsealed."""

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspect_ranges._evidence.manifest import seal_key
from inspect_ranges._evidence.reader import LocalDirStore, verify_location
from inspect_ranges._evidence.sealer import seal_abandoned
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink
from inspect_ranges._host.host import HostFacts
from inspect_ranges._host.leases import LeaseStore
from inspect_ranges._host.reaper import sweep


async def _abandoned_record(root: Path, *, writer: str = "host") -> None:
    """A record with delivered chunks and parts but no seal (the dead-driver shape)."""
    evidence = EvidenceWriter(
        LocalDirSink(root), part_interval_s=0, writer=writer, retry_wait_s=0
    )
    await evidence.append("pcap/dmz", b"pre-kill frames")
    await evidence.gap("pcap/dmz", cause="capture-restart")
    await evidence.append("console/web", b"boot output")
    await evidence.flush()
    # no seal: the driver died


def test_seal_abandoned_produces_a_verifiable_reaped_seal(tmp_path: Path) -> None:
    async def scenario() -> None:
        await _abandoned_record(tmp_path)
        sealed = await seal_abandoned(str(tmp_path), lease_id="lease-1", sample_id="s1")
        assert set(sealed) == {"host"}
        report = await verify_location(
            LocalDirStore(tmp_path), expected_seals={"host": sealed["host"]}
        )
        host = report.writers["host"]
        assert report.ok and host.sealed and host.binding_checked
        assert host.seal_status == "reaped"
        assert host.lease_id == "lease-1" and host.sample_id == "s1"
        assert host.streams["pcap/dmz"].chunks == 1
        assert host.streams["pcap/dmz"].gaps == 1

    asyncio.run(scenario())


def test_seal_abandoned_skips_sealed_writers_and_races(tmp_path: Path) -> None:
    async def scenario() -> None:
        writer = EvidenceWriter(
            LocalDirSink(tmp_path), part_interval_s=0, writer="driver", retry_wait_s=0
        )
        await writer.append("session", b"pinned")
        _, digest = await writer.seal()
        sealed = await seal_abandoned(str(tmp_path), lease_id=None, sample_id=None)
        assert sealed == {}, "a finalized writer is never re-sealed"
        report = await verify_location(
            LocalDirStore(tmp_path), expected_seals={"driver": digest}
        )
        assert report.ok and report.writers["driver"].seal_status == "complete"

    asyncio.run(scenario())


def test_seal_abandoned_leaves_broken_records_unsealed(tmp_path: Path) -> None:
    async def scenario() -> None:
        await _abandoned_record(tmp_path)
        part = tmp_path / "manifests" / "host" / "part-000000.json"
        part.write_bytes(b"not json")  # tampered or torn part
        sealed = await seal_abandoned(str(tmp_path), lease_id=None, sample_id=None)
        assert sealed == {}, "a seal must never anchor state the sealer cannot replay"
        assert not (tmp_path / seal_key("host")).exists()

    asyncio.run(scenario())


def test_reaper_sweep_reap_seals_the_lease_evidence(tmp_path: Path) -> None:
    """The reaper integration: an expired lease with an evidence location gets its record sealed `reaped` after teardown, and sealing failure never blocks the reap (the broken-record case still reaps)."""
    state_dir = tmp_path / "state"
    evidence_root = tmp_path / "evidence"
    asyncio.run(_abandoned_record(evidence_root))
    frozen = datetime(2026, 10, 15, tzinfo=UTC)
    store = LeaseStore(state_dir, now_fn=lambda: frozen)
    lease = store.acquire(
        project="ir-dead",
        task_name="t",
        sample_id="s1",
        isolation="shared",
        origin="local",
        bundle_path=str(tmp_path / "bundle"),
        bundle_digest="0" * 64,
        staging=str(tmp_path / "staging"),
        host_facts=HostFacts(arch="x86_64", hostname="h", host_class="test"),
        ttl_s=60,
        evidence_location=str(evidence_root),
    )
    late = frozen + timedelta(seconds=120)
    expired_store = LeaseStore(state_dir, now_fn=lambda: late)
    outcomes = sweep(
        state_dir,
        store=expired_store,
        down_fn=lambda project, sd: None,  # type: ignore[arg-type, return-value]
    )
    assert [outcome.action for outcome in outcomes] == ["reaped"]
    assert expired_store.get(lease.lease_id) is None

    async def check() -> None:
        report = await verify_location(LocalDirStore(evidence_root))
        host = report.writers["host"]
        assert report.ok and host.seal_status == "reaped"
        assert host.lease_id == lease.lease_id

    asyncio.run(check())
