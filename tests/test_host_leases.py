"""The host lease store: record shape, renewal CAS, the reap race, cross-process safety (range-host-v1 slice 2)."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from inspect_ranges._host import HostFacts, HostLease, LeaseLostError, LeaseStore
from inspect_ranges._host.leases import lease_ttl_s


class Clock:
    """A frozen, manually advanced UTC clock."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def facts() -> HostFacts:
    return HostFacts(arch="x86_64", hostname="devbox", host_class="test")


def acquire(store: LeaseStore, project: str = "ir-x", ttl_s: float = 600) -> HostLease:
    return store.acquire(
        project=project,
        task_name="task",
        sample_id="s1",
        isolation="shared",
        origin="local",
        bundle_path="/staging/bundle",
        bundle_digest="ab" * 32,
        staging="/staging",
        host_facts=facts(),
        ttl_s=ttl_s,
    )


def test_acquire_mints_the_record_shape(tmp_path: Path) -> None:
    clock = Clock()
    store = LeaseStore(tmp_path, now_fn=clock)
    lease = acquire(store, ttl_s=600)
    assert len(lease.lease_id) == 32 and int(lease.lease_id, 16) >= 0
    assert lease.state == "active"
    assert lease.created == clock.now.isoformat()
    assert lease.expires() == clock.now + timedelta(seconds=600)
    assert store.get(lease.lease_id) == lease
    assert store.leases() == [lease]
    assert store.expired() == []


def test_renew_cas_extends_expiry(tmp_path: Path) -> None:
    clock = Clock()
    store = LeaseStore(tmp_path, now_fn=clock)
    lease = acquire(store, ttl_s=600)
    clock.advance(500)
    renewed = store.renew(lease.lease_id, ttl_s=600)
    assert renewed.expires() == clock.now + timedelta(seconds=600)
    assert renewed.state == "active"
    assert store.get(lease.lease_id) == renewed


def test_renew_of_a_released_lease_is_lease_lost(tmp_path: Path) -> None:
    store = LeaseStore(tmp_path, now_fn=Clock())
    lease = acquire(store)
    store.release(lease.lease_id)
    store.release(lease.lease_id)  # idempotent
    with pytest.raises(LeaseLostError, match="gone"):
        store.renew(lease.lease_id)


def test_the_reap_race_pinned_both_ways(tmp_path: Path) -> None:
    """The flock settles the renewal-versus-reap race atomically in one direction or the other: a renewal that lands first is spared by the sweep's expiry re-check; a sweep that marks first makes renewal refuse with `LeaseLostError`."""
    clock = Clock()
    store = LeaseStore(tmp_path, now_fn=clock)

    # way 1: expired, but the renewal lands before the sweep: spared
    spared = acquire(store, project="ir-spared", ttl_s=10)
    clock.advance(20)
    store.renew(spared.lease_id, ttl_s=600)
    assert store.mark_reaping() == [], "a just-renewed lease must be spared"

    # way 2: the sweep marks first: the next renewal is a lost CAS
    reaped = acquire(store, project="ir-reaped", ttl_s=10)
    clock.advance(20)
    marked = store.mark_reaping()
    assert [lease.lease_id for lease in marked] == [reaped.lease_id]
    assert marked[0].state == "reaping"
    with pytest.raises(LeaseLostError, match="reaping"):
        store.renew(reaped.lease_id)


def test_mark_reaping_resumes_after_a_crash(tmp_path: Path) -> None:
    """A lease already `reaping` (teardown crashed before release) is selected again by the next sweep, via its state alone."""
    clock = Clock()
    store = LeaseStore(tmp_path, now_fn=clock)
    lease = acquire(store, ttl_s=10)
    clock.advance(20)
    assert len(store.mark_reaping()) == 1
    # even with the clock wound back before expiry, the reaping state selects
    clock.advance(-1000)
    resumed = store.mark_reaping()
    assert [entry.lease_id for entry in resumed] == [lease.lease_id]
    assert resumed[0].state == "reaping"


def test_active_unexpired_leases_are_untouched(tmp_path: Path) -> None:
    clock = Clock()
    store = LeaseStore(tmp_path, now_fn=clock)
    lease = acquire(store, ttl_s=600)
    clock.advance(100)
    assert store.mark_reaping() == []
    current = store.get(lease.lease_id)
    assert current is not None and current.state == "active"


def test_foreign_entries_survive_verbatim_and_reads_never_rewrite(
    tmp_path: Path,
) -> None:
    """An entry another version wrote is preserved verbatim through every mutation, and read-only operations never rewrite the file."""
    registry = tmp_path / "leases.json"
    foreign = {"future-lease": {"schema": 99, "payload": ["opaque"]}}
    registry.write_text(json.dumps(foreign))
    store = LeaseStore(tmp_path, now_fn=Clock())
    lease = acquire(store)
    store.renew(lease.lease_id)
    before = registry.read_bytes()
    assert store.leases() == [store.get(lease.lease_id)]
    assert store.expired() == []
    assert registry.read_bytes() == before, "reads must never rewrite the file"
    store.release(lease.lease_id)
    on_disk = json.loads(registry.read_text())
    assert on_disk["future-lease"] == foreign["future-lease"]


def test_lease_ttl_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INSPECT_RANGES_LEASE_TTL_S", raising=False)
    assert lease_ttl_s() == 600.0
    monkeypatch.setenv("INSPECT_RANGES_LEASE_TTL_S", "90")
    assert lease_ttl_s() == 90.0
    for bad in ("soon", "0", "-5"):
        monkeypatch.setenv("INSPECT_RANGES_LEASE_TTL_S", bad)
        with pytest.raises(ValueError, match="INSPECT_RANGES_LEASE_TTL_S"):
            lease_ttl_s()


_CONTENDER = """
import json, sys
from pathlib import Path
from inspect_ranges._host import HostFacts
from inspect_ranges._host.leases import LeaseStore

store = LeaseStore(Path(sys.argv[1]))
facts = HostFacts(arch="x86_64", hostname="h", host_class="test")
ids = [
    store.acquire(
        project=f"ir-p{sys.argv[2]}-{i}",
        task_name="task",
        sample_id=f"s{i}",
        isolation="shared",
        origin="local",
        bundle_path="/b",
        bundle_digest="ab" * 32,
        staging="/s",
        host_facts=facts,
        ttl_s=600,
    ).lease_id
    for i in range(20)
]
print(json.dumps(ids))
"""


def test_cross_process_contention_mints_disjoint_leases(tmp_path: Path) -> None:
    """Two real OS processes contending on `leases.json` mint disjoint leases and never corrupt a foreign entry."""
    foreign = {"future-lease": {"schema": 99}}
    (tmp_path / "leases.json").write_text(json.dumps(foreign))
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CONTENDER, str(tmp_path), str(index)],
            stdout=subprocess.PIPE,
            text=True,
        )
        for index in range(2)
    ]
    minted: list[str] = []
    for proc in procs:
        stdout, _ = proc.communicate(timeout=60)
        assert proc.returncode == 0
        minted.extend(json.loads(stdout))
    assert len(minted) == 40
    assert len(set(minted)) == 40, "lease ids must never collide"
    on_disk = json.loads((tmp_path / "leases.json").read_text())
    assert on_disk["future-lease"] == foreign["future-lease"]
    store = LeaseStore(tmp_path)
    assert sorted(lease.lease_id for lease in store.leases()) == sorted(minted)
