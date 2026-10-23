"""The out-of-band oracle attach: recorded-state parsing, refusals, the context-manager lifecycle, and the loud log line."""

import asyncio
import logging
import subprocess
from pathlib import Path

import pytest
from inspect_ranges import range_oracle
from inspect_ranges._challenges.attach import attach_endpoints, attach_oracle
from inspect_ranges._challenges.oracle import OracleSetupError, RangeOracle
from inspect_ranges._runtime.ownership import ch_vsock_dir, owner_record, write_owner
from inspect_ranges._runtime.up import BootGuest, BootPlan, ch_uid

PROJECT = "ir-tiny-attach"


@pytest.fixture(autouse=True)
def local_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """The semantics under test are the local backend's: a dev shell's exported `INSPECT_RANGES_HOST` must not leak in."""
    monkeypatch.delenv("INSPECT_RANGES_HOST", raising=False)


def boot_plan() -> BootPlan:
    """A two-guest boot plan covering both VMM kinds (the shapes `up` records)."""
    return BootPlan(
        parallel=True,
        guests=[
            BootGuest(
                name="web",
                cid=3000,
                image_file="web.qcow2",
                overlay_gb=10,
                readiness="cloud-init",
            ),
            BootGuest(
                name="attack",
                cid=3001,
                image_file="attack.qcow2",
                overlay_gb=10,
                readiness="daemon",
                vmm="cloud-hypervisor",
                cpus=2,
                memory_mb=1024,
            ),
        ],
        verify={},
    )


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    """A project state directory with the owner record and boot plan `up` records."""
    state = tmp_path / "state"
    write_owner(state, owner_record(PROJECT, "tiny", "a" * 64, tmp_path / "bundle"))
    (state / PROJECT / "boot.json").write_text(boot_plan().model_dump_json())
    return state


class FakeDocker:
    """Scriptable liveness runner: answers `docker ps` with the given container ids."""

    def __init__(self, ps_output: str = "abc123\n") -> None:
        self.ps_output = ps_output
        self.calls: list[list[str]] = []

    def __call__(
        self,
        argv: list[str],
        env: dict[str, str] | None = None,
        input: str | None = None,
        timeout: float | None = None,
    ) -> "subprocess.CompletedProcess[str]":
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, self.ps_output, "")


def test_attach_refuses_unknown_project(tmp_path: Path) -> None:
    """A project with no owner record refuses, naming the state path and the up remedy, before any docker call."""
    with pytest.raises(OracleSetupError, match=r"unknown project 'ir-nope'.*up"):
        with range_oracle("ir-nope", state_dir=tmp_path / "state"):
            pass  # pragma: no cover - the attach refuses before yielding


def test_attach_refuses_unrecorded_boot_plan(tmp_path: Path) -> None:
    """A registered project without a recorded boot.json (an older inspect-ranges booted it) refuses, naming the missing file."""
    state = tmp_path / "state"
    write_owner(state, owner_record(PROJECT, "tiny", "a" * 64, tmp_path / "bundle"))
    with pytest.raises(
        OracleSetupError, match=r"no recorded boot plan at .*boot\.json"
    ):
        with range_oracle(PROJECT, state_dir=state):
            pass  # pragma: no cover


def test_attach_refuses_malformed_boot_plan(state_dir: Path) -> None:
    """A recorded boot.json that no longer parses refuses in place rather than dialing anything."""
    (state_dir / PROJECT / "boot.json").write_text("{not json")
    with pytest.raises(
        OracleSetupError, match=r"boot\.json is unreadable or malformed"
    ):
        with range_oracle(PROJECT, state_dir=state_dir):
            pass  # pragma: no cover


def test_attach_refuses_stopped_project(state_dir: Path) -> None:
    """A registered project with no running containers is stale: the refusal names the state path and the re-boot remedy, and the liveness query asks docker for RUNNING containers only (a crashed project's exited containers must not pass)."""
    docker = FakeDocker(ps_output="")
    with pytest.raises(OracleSetupError, match="no running containers"):
        with attach_oracle(PROJECT, state_dir=state_dir, runner=docker):
            pass  # pragma: no cover
    assert docker.calls and docker.calls[0][:2] == ["docker", "ps"]
    assert "-a" not in docker.calls[0]


def test_attach_refuses_without_docker(state_dir: Path) -> None:
    """A machine without docker cannot host a running range: the attach refuses with the setup error type, not a raw FileNotFoundError."""

    def no_docker(
        argv: list[str],
        env: dict[str, str] | None = None,
        input: str | None = None,
        timeout: float | None = None,
    ) -> "subprocess.CompletedProcess[str]":
        raise FileNotFoundError("docker")

    with pytest.raises(OracleSetupError, match="docker"):
        with attach_oracle(PROJECT, state_dir=state_dir, runner=no_docker):
            pass  # pragma: no cover


def test_attach_refuses_separated_topology(
    state_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With `INSPECT_RANGES_HOST` set the guests live behind the applier: the attach refuses naming the limitation, before reading any state."""
    monkeypatch.setenv("INSPECT_RANGES_HOST", "uds:/tmp/applier.sock")
    with pytest.raises(OracleSetupError, match="INSPECT_RANGES_HOST"):
        with range_oracle(PROJECT, state_dir=state_dir):
            pass  # pragma: no cover


def test_attach_yields_oracle_logs_loudly_and_detaches(
    state_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The lifecycle: a running project yields a `RangeOracle` with one loud attach line, and verbs after exit refuse as detached before any dial."""
    with caplog.at_level(logging.WARNING, logger="inspect_ranges.oracle"):
        with attach_oracle(PROJECT, state_dir=state_dir, runner=FakeDocker()) as oracle:
            assert isinstance(oracle, RangeOracle)
            assert oracle.project == PROJECT
    loud = [record for record in caplog.records if "out-of-band" in record.message]
    assert loud and loud[0].levelno == logging.WARNING
    assert PROJECT in loud[0].getMessage()
    with pytest.raises(OracleSetupError, match="detached"):
        asyncio.run(oracle.exec("web", ["id"]))


def test_attach_endpoints_rebuild_cid_map_and_hybrid_sockets() -> None:
    """The recorded boot plan rebuilds the provider's transport inputs: every guest's CID, and hybrid endpoints (project socket, CID-derived VMM uid) for Cloud Hypervisor guests only."""
    cids, hybrid = attach_endpoints(boot_plan(), PROJECT)
    assert cids == {"web": 3000, "attack": 3001}
    assert set(hybrid) == {"attack"}
    assert hybrid["attack"].path == ch_vsock_dir(PROJECT) / "attack.sock"
    assert hybrid["attack"].peer_uid == ch_uid(3001)


def test_attach_endpoints_prefer_the_attack_box_record(state_dir: Path) -> None:
    """A guest realized by an external attack-box provider has no CID-derived socket: its endpoint comes from the record `up` wrote."""
    from inspect_ranges._attackbox import AttackBoxRecord, write_attack_box_record

    write_attack_box_record(
        state_dir,
        AttackBoxRecord(
            origin="pkg.mod.factory",
            project=PROJECT,
            guest_name="attack",
            cid=3001,
            exec_socket="/run/box/attack.sock",
            exec_uid=4242,
            created="2026-10-23T00:00:00+00:00",
        ),
    )
    cids, hybrid = attach_endpoints(boot_plan(), PROJECT, state_dir=state_dir)
    assert cids == {"web": 3000, "attack": 3001}
    assert hybrid["attack"].path == Path("/run/box/attack.sock")
    assert hybrid["attack"].peer_uid == 4242
