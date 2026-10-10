"""The independent reaper: on-disk-only sweeps, destroy-before-release, crash resume (range-host-v1 slice 2)."""

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner
from inspect_ranges._cli.main import ranges
from inspect_ranges._host import HostFacts, HostLease, LeaseStore
from inspect_ranges._host.reaper import ReapOutcome, sweep
from inspect_ranges._provider.naming import CidAllocator
from inspect_ranges._runtime.down import DownResult
from inspect_ranges._runtime.ownership import owner_record, read_owner, write_owner


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Rig:
    """One expired lease with everything the reaper must reclaim: CID lease, owner record, staging."""

    def __init__(self, tmp_path: Path, origin: str = "local") -> None:
        self.state = tmp_path / "state"
        self.clock = Clock()
        self.store = LeaseStore(self.state, now_fn=self.clock)
        self.allocator = CidAllocator(self.state)
        self.project = "ir-reapme-000000"
        self.allocator.lease(self.project, 2)
        self.staging = tmp_path / "staging" / self.project
        self.staging.mkdir(parents=True)
        (self.staging / "bundle").mkdir()
        write_owner(self.state, owner_record(self.project, "r", "0" * 64, self.staging))
        self.lease = self.store.acquire(
            project=self.project,
            task_name="task",
            sample_id="s1",
            isolation="shared",
            origin=origin,
            bundle_path=str(self.staging / "bundle"),
            bundle_digest="ab" * 32,
            staging=str(self.staging),
            host_facts=HostFacts(arch="x86_64", hostname="h", host_class="test"),
            ttl_s=10,
        )
        self.clock.advance(20)
        self.down_calls: list[str] = []
        self.down_errors: list[Exception] = []

    def down(self, project: str, state_dir: Path) -> DownResult:
        # destroy-before-release, observed DURING teardown: everything is
        # still findable while down runs
        assert self.store.get(self.lease.lease_id) is not None
        assert self.allocator.leased_projects() == [self.project]
        self.down_calls.append(project)
        if self.down_errors:
            raise self.down_errors.pop(0)
        return DownResult(project=project, containers=1, volumes=1, networks=1)

    def sweep(self) -> list[ReapOutcome]:
        return sweep(self.state, store=self.store, down_fn=self.down)


def test_sweep_reaps_an_expired_lease_in_order(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    outcomes = rig.sweep()
    assert [(o.action, o.project) for o in outcomes] == [("reaped", rig.project)]
    assert rig.down_calls == [rig.project]
    assert rig.store.leases() == []
    assert rig.allocator.leased_projects() == []
    assert not rig.staging.exists()
    assert read_owner(rig.state, rig.project) is None


def test_failed_down_frees_nothing(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.down_errors = [RuntimeError("docker wedged")]
    outcomes = rig.sweep()
    assert [(o.action, o.error) for o in outcomes] == [("down-failed", "docker wedged")]
    survivor = rig.store.get(rig.lease.lease_id)
    assert survivor is not None and survivor.state == "reaping"
    assert rig.allocator.leased_projects() == [rig.project]
    assert rig.staging.exists()
    assert read_owner(rig.state, rig.project) is not None


def test_crash_resume_completes_on_the_second_invocation(tmp_path: Path) -> None:
    """First sweep marks `reaping` and its teardown fails (the crash analog); the second invocation resumes from the state alone and finishes the reclaim."""
    rig = Rig(tmp_path)
    rig.down_errors = [RuntimeError("crashed mid-teardown")]
    first = rig.sweep()
    assert [o.action for o in first] == ["down-failed"]
    # wind the clock back before expiry: resume must key on state, not expiry
    rig.clock.advance(-1000)
    second = rig.sweep()
    assert [o.action for o in second] == ["reaped"]
    assert rig.store.leases() == []
    assert rig.allocator.leased_projects() == []


def test_uds_lease_without_applier_falls_back_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    rig = Rig(tmp_path, origin="uds:/tmp/applier.sock")
    with caplog.at_level(logging.WARNING, logger="inspect_ranges.reaper"):
        outcomes = rig.sweep()
    assert [o.action for o in outcomes] == ["reaped"]
    assert rig.down_calls == [rig.project], "direct down is the fallback"
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "admission charge" in messages


def test_uds_lease_prefers_the_applier_teardown(tmp_path: Path) -> None:
    rig = Rig(tmp_path, origin="uds:/tmp/applier.sock")
    torn_down: list[str] = []

    def applier_teardown(lease: HostLease) -> None:
        torn_down.append(lease.lease_id)

    outcomes = sweep(
        rig.state,
        store=rig.store,
        down_fn=rig.down,
        applier_teardown=applier_teardown,
    )
    assert [o.action for o in outcomes] == ["reaped"]
    assert torn_down == [rig.lease.lease_id]
    assert rig.down_calls == [], "the applier owned the teardown"


def test_failing_applier_teardown_falls_back_to_direct_down(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    rig = Rig(tmp_path, origin="uds:/tmp/applier.sock")

    def refusing(lease: HostLease) -> None:
        raise ConnectionError("applier gone")

    with caplog.at_level(logging.WARNING, logger="inspect_ranges.reaper"):
        outcomes = sweep(
            rig.state, store=rig.store, down_fn=rig.down, applier_teardown=refusing
        )
    assert [o.action for o in outcomes] == ["reaped"]
    assert rig.down_calls == [rig.project]
    assert "admission charge" in " ".join(r.getMessage() for r in caplog.records)


def test_sweep_leaves_healthy_leases_alone(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.clock.advance(-15)  # back inside the TTL: active and unexpired
    assert rig.sweep() == []
    assert rig.down_calls == []
    current = rig.store.get(rig.lease.lease_id)
    assert current is not None and current.state == "active"


def test_reaper_cli_one_shot_on_a_clean_state_dir(tmp_path: Path) -> None:
    result = CliRunner().invoke(ranges, ["reaper", "--state-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert result.output == ""
