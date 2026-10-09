"""Slice-2 battery: project naming and the cross-process CID lease registry."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from inspect_ranges._provider.naming import (
    PROVIDER_CID_BASE,
    CidAllocator,
    sample_project,
)


def test_sample_project_shape_and_uniqueness() -> None:
    names = {sample_project("dmz-pivot", "Sample_01") for _ in range(50)}
    assert len(names) == 50, "every attempt must mint a fresh identity"
    pattern = re.compile(r"^ir-dmz-pivot-sample_01-[0-9a-f]{6}$")
    for name in names:
        assert pattern.match(name), name


def test_sample_project_sanitizes_hostile_ids() -> None:
    name = sample_project("My Range!", "s/1:2 $(rm -rf)")
    assert re.match(r"^ir-[a-z0-9_-]+-[a-z0-9_-]+-[0-9a-f]{6}$", name), name
    long = sample_project("r" * 100, "s" * 100)
    assert len(long) <= len("ir-") + 24 + 1 + 24 + 7


def test_lease_release_and_first_fit(tmp_path: Path) -> None:
    allocator = CidAllocator(tmp_path)
    a = allocator.lease("ir-a", 3)
    b = allocator.lease("ir-b", 2)
    assert a.base == PROVIDER_CID_BASE
    assert b.base == PROVIDER_CID_BASE + 3
    with pytest.raises(ValueError, match="already holds"):
        allocator.lease("ir-a", 1)
    allocator.release("ir-a")
    allocator.release("ir-a")  # idempotent
    c = allocator.lease("ir-c", 3)
    assert c.base == PROVIDER_CID_BASE, "released block is reused first-fit"
    d = allocator.lease("ir-d", 4)
    assert d.base == PROVIDER_CID_BASE + 5, "block too big for the gap goes after"


def test_prune_drops_only_dead_leases(tmp_path: Path) -> None:
    allocator = CidAllocator(tmp_path)
    allocator.lease("ir-live", 2)
    allocator.lease("ir-dead", 2)
    pruned = allocator.prune({"ir-live"})
    assert pruned == ["ir-dead"]
    assert allocator.leased_projects() == ["ir-live"]


def test_corrupt_registry_never_blocks_allocation(tmp_path: Path) -> None:
    (tmp_path / "cids.json").write_text("{not json")
    allocator = CidAllocator(tmp_path)
    lease = allocator.lease("ir-x", 1)
    assert lease.base == PROVIDER_CID_BASE


_CONTENDER = """
import json, sys
from pathlib import Path
from inspect_ranges._provider.naming import CidAllocator

state = Path(sys.argv[1])
allocator = CidAllocator(state)
leases = [allocator.lease(f"ir-p{sys.argv[2]}-{i}", 2) for i in range(20)]
print(json.dumps([[lease.base, lease.count] for lease in leases]))
"""


def test_cross_process_contention_yields_disjoint_blocks(tmp_path: Path) -> None:
    """Two real OS processes contending on the flock lease disjoint blocks."""
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CONTENDER, str(tmp_path), str(index)],
            stdout=subprocess.PIPE,
            text=True,
        )
        for index in range(2)
    ]
    blocks: list[tuple[int, int]] = []
    for proc in procs:
        stdout, _ = proc.communicate(timeout=60)
        assert proc.returncode == 0
        blocks.extend((base, count) for base, count in json.loads(stdout))
    assert len(blocks) == 40
    claimed: set[int] = set()
    for base, count in blocks:
        for cid in range(base, base + count):
            assert cid not in claimed, f"CID {cid} double-leased"
            claimed.add(cid)
    assert min(claimed) >= PROVIDER_CID_BASE
