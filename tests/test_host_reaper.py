"""The independent reaper: on-disk-only sweeps, destroy-before-release, crash resume (range-host-v1 slice 2)."""

import importlib
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner
from inspect_ranges._cli.main import ranges
from inspect_ranges._host import (
    HostBackend,
    HostFacts,
    HostLease,
    LeasePlacement,
    LeaseStore,
    RangeHost,
    SampleSpec,
)
from inspect_ranges._host.reaper import ReapOutcome, sweep
from inspect_ranges._provider.naming import CidAllocator
from inspect_ranges._runtime.down import DownResult
from inspect_ranges._runtime.ownership import (
    owner_record,
    read_owner,
    remove_project,
    write_owner,
)

from tests.test_host_leases import Clock


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
        # destroy-before-release, observed DURING teardown: the host lease
        # (the retry anchor) is findable on every pass, and nothing at all
        # is freed before the first teardown succeeds
        assert self.store.get(self.lease.lease_id) is not None
        if not self.down_calls:
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
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The REAL uds bundle resolved from the lease origin: the applier at the (dead) socket refuses, so the reclaim warns and falls back to direct down (correct only because a uds host is this machine)."""
    rig = Rig(tmp_path, origin="uds:/tmp/ir-test-no-applier.sock")

    # importlib, not an import statement: the `_runtime` package re-exports
    # the `down` FUNCTION under the same name as its submodule
    down_module = importlib.import_module("inspect_ranges._runtime.down")

    def direct_down(project: str, state_dir: Path) -> DownResult:
        return rig.down(project, state_dir)

    monkeypatch.setattr(down_module, "down", direct_down)
    with caplog.at_level(logging.WARNING, logger="inspect_ranges.reaper"):
        outcomes = rig.sweep()
    assert [o.action for o in outcomes] == ["reaped"]
    assert rig.down_calls == [rig.project], "direct down is the fallback"
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "admission charge" in messages


class _StubProvider:
    """Satisfies the `HostProvider` protocol for bundles whose reaper path never acquires."""

    async def acquire(self, sample: SampleSpec, placement: LeasePlacement) -> RangeHost:
        raise NotImplementedError

    async def release(self, host: RangeHost) -> None:
        raise NotImplementedError

    async def abandon(self, host: RangeHost) -> None:
        raise NotImplementedError


def test_backend_reclaim_owns_the_teardown(tmp_path: Path) -> None:
    """A lease origin resolving to a bundle with a reclaim connector tears down through it; the local down path is never touched."""
    rig = Rig(tmp_path, origin="mypkg.hosts.fleet:region-a")
    torn_down: list[str] = []

    def reclaim(lease: HostLease, state_dir: Path) -> None:
        torn_down.append(lease.lease_id)

    def resolver(origin: str, state_dir: Path) -> HostBackend:
        assert origin == rig.lease.origin, "resolution keys on the recorded origin"
        return HostBackend(provider=_StubProvider(), reclaim=reclaim)

    outcomes = sweep(
        rig.state, store=rig.store, down_fn=rig.down, resolve_origin=resolver
    )
    assert [o.action for o in outcomes] == ["reaped"]
    assert torn_down == [rig.lease.lease_id]
    assert rig.down_calls == [], "the backend owned the teardown"


def test_failing_backend_reclaim_frees_nothing(tmp_path: Path) -> None:
    """A custom backend's failing reclaim gets NO direct-down fallback (the host lives elsewhere): the outcome is down-failed and everything stays findable for the next sweep."""
    rig = Rig(tmp_path, origin="mypkg.hosts.fleet:region-a")

    def refusing(lease: HostLease, state_dir: Path) -> None:
        raise ConnectionError("fleet gone")

    def resolver(origin: str, state_dir: Path) -> HostBackend:
        return HostBackend(provider=_StubProvider(), reclaim=refusing)

    outcomes = sweep(
        rig.state, store=rig.store, down_fn=rig.down, resolve_origin=resolver
    )
    assert [(o.action, o.error) for o in outcomes] == [("down-failed", "fleet gone")]
    assert rig.down_calls == [], "no vacuous direct down against a remote host"
    survivor = rig.store.get(rig.lease.lease_id)
    assert survivor is not None and survivor.state == "reaping"
    assert rig.allocator.leased_projects() == [rig.project]


def test_unresolvable_origin_reclaims_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A lease origin naming a backend this environment cannot import touches NOTHING: no vacuous down, no release; the lease stays reaping and the next sweep retries the same way."""
    rig = Rig(tmp_path, origin="no_such_pkg.hosts.fleet:region-a")
    with caplog.at_level(logging.ERROR, logger="inspect_ranges.reaper"):
        outcomes = rig.sweep()
    assert [o.action for o in outcomes] == ["origin-unresolvable"]
    assert rig.down_calls == [], "a vacuous local down would orphan the remote host"
    survivor = rig.store.get(rig.lease.lease_id)
    assert survivor is not None and survivor.state == "reaping"
    assert rig.allocator.leased_projects() == [rig.project]
    assert rig.staging.exists()
    assert read_owner(rig.state, rig.project) is not None
    assert "install the backend's package" in " ".join(
        record.getMessage() for record in caplog.records
    )
    retry = rig.sweep()
    assert [o.action for o in retry] == ["origin-unresolvable"]


def test_sweep_leaves_healthy_leases_alone(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.clock.advance(-15)  # back inside the TTL: active and unexpired
    assert rig.sweep() == []
    assert rig.down_calls == []
    current = rig.store.get(rig.lease.lease_id)
    assert current is not None and current.state == "active"


def test_release_failure_is_contained_and_the_next_sweep_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-teardown bookkeeping error must not escape the sweep (a long-lived reaper survives it); the lease stays reaping and the next pass completes the reclaim."""
    rig = Rig(tmp_path)
    original = CidAllocator.release
    failures = ["flock hiccup"]

    def flaky(self: CidAllocator, project: str) -> None:
        if failures:
            raise OSError(failures.pop())
        original(self, project)

    monkeypatch.setattr(CidAllocator, "release", flaky)
    first = rig.sweep()
    assert [(o.action, o.error) for o in first] == [("release-failed", "flock hiccup")]
    survivor = rig.store.get(rig.lease.lease_id)
    assert survivor is not None and survivor.state == "reaping"
    second = rig.sweep()
    assert [o.action for o in second] == ["reaped"]
    assert rig.store.leases() == []
    assert rig.allocator.leased_projects() == []


def test_host_lease_release_failure_leaves_the_retry_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host lease is released LAST: a bookkeeping failure after teardown (here `remove_project`) leaves the reaping lease on disk, so the next sweep genuinely retries and finishes, owner record included."""
    import inspect_ranges._host.reaper as reaper_module

    rig = Rig(tmp_path)
    failures = ["state dir hiccup"]

    def flaky(state_dir: Path, project: str) -> None:
        if failures:
            raise OSError(failures.pop())
        remove_project(state_dir, project)

    monkeypatch.setattr(reaper_module, "remove_project", flaky)
    first = rig.sweep()
    assert [(o.action, o.error) for o in first] == [
        ("release-failed", "state dir hiccup")
    ]
    survivor = rig.store.get(rig.lease.lease_id)
    assert survivor is not None and survivor.state == "reaping", (
        "the lease is the retry anchor and must survive the failure"
    )
    second = rig.sweep()
    assert [o.action for o in second] == ["reaped"]
    assert rig.store.leases() == []
    assert read_owner(rig.state, rig.project) is None


def test_reaper_cli_one_shot_on_a_clean_state_dir(tmp_path: Path) -> None:
    result = CliRunner().invoke(ranges, ["reaper", "--state-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert result.output == ""


def test_reaper_cli_one_shot_exits_1_on_a_failed_reclaim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect_ranges._cli.reapercmd as reapercmd

    outcome = ReapOutcome("deadbeef", "ir-x", "down-failed", "docker wedged")

    def rigged_sweep(state_dir: Path) -> list[ReapOutcome]:
        return [outcome]

    monkeypatch.setattr(reapercmd, "sweep", rigged_sweep)
    result = CliRunner().invoke(ranges, ["reaper", "--state-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "down-failed: ir-x (lease deadbeef): docker wedged" in result.output
