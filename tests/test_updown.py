"""`up`/`down` behavior through their public surfaces, with docker faked and real rendered bundles."""

import subprocess
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._compiler import PlanOptions, render_bundle, resolve_plan
from inspect_ranges._compiler.plan import image_file_name
from inspect_ranges._runtime import (
    UpError,
    UpOptions,
    down,
    down_all,
    up,
    verify_bundle,
)
from inspect_ranges._runtime.ownership import StageLog, list_projects, read_owner
from inspect_ranges._runtime.up import boot_script
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
)


def tiny_spec() -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="tiny", description="updown test range."),
        networks=[Network(name="lab", cidr="10.10.10.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "tiny-golden.qcow2").write_bytes(b"golden")
    (cache / "noble-range-guest.qcow2").write_bytes(b"attacker-golden")
    return cache


@pytest.fixture()
def bundle(tmp_path: Path, cache: Path) -> Path:
    out = tmp_path / "bundle"
    render_bundle(tiny_spec(), out, PlanOptions(image_cache=cache, cid_base=3000))
    return out


class FakeDocker:
    """Scriptable runner: records every argv; answers per command prefix."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.ps_output = ""
        self.ps_sequence: list[str] | None = None
        self.fail_prefix: tuple[str, ...] | None = None

    def __call__(
        self,
        argv: list[str],
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> "subprocess.CompletedProcess[str]":
        self.calls.append(argv)
        self.last_env = env
        self.last_input = input
        if (
            self.fail_prefix
            and tuple(argv[: len(self.fail_prefix)]) == self.fail_prefix
        ):
            return subprocess.CompletedProcess(argv, 1, "", "scripted failure")
        if argv[:3] == ["docker", "ps", "-a"] and "-q" in argv:
            if self.ps_sequence:
                return subprocess.CompletedProcess(argv, 0, self.ps_sequence.pop(0), "")
            return subprocess.CompletedProcess(argv, 0, self.ps_output, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def commands(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if tuple(c[: len(prefix)]) == prefix]


def options(cache: Path, tmp_path: Path, **overrides: Any) -> UpOptions:
    return UpOptions(
        image_cache=cache,
        state_dir=tmp_path / "state",
        readiness_timeout=1.0,
        **overrides,
    )


def up_module() -> Any:
    import importlib

    return importlib.import_module("inspect_ranges._runtime.up")


def _always_ready(cid: int, deadline: float) -> bool:
    return True


def _never_ready(cid: int, deadline: float) -> bool:
    return False


def _exec_done(cid: int, command: str, timeout: float) -> tuple[int, str, str]:
    return (0, "done\n", "")


def ready_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up_module().probe, "wait_daemon", _always_ready)
    monkeypatch.setattr(up_module().probe, "guest_exec", _exec_done)


def test_cid_base_is_a_plan_input(cache: Path) -> None:
    plan = resolve_plan(tiny_spec(), PlanOptions(image_cache=cache, cid_base=3000))
    assert [guest.cid for guest in plan.guests] == [3000, 3001]


@pytest.mark.parametrize(
    ("reference", "file"),
    [
        ("tiny-golden", "tiny-golden.qcow2"),
        ("vulhub/zabbix:3.0.3-web", "vulhub-zabbix-3.0.3-web.qcow2"),
        ("ubuntu-24.04", "ubuntu-24.04.qcow2"),
        ("noble-server-cloudimg-amd64.img", "noble-server-cloudimg-amd64.img"),
        ("win.iso", "win.iso"),
    ],
)
def test_image_file_name_unified(reference: str, file: str) -> None:
    assert image_file_name(reference) == file


def test_verify_bundle_accepts_rendered_and_refuses_tamper(bundle: Path) -> None:
    manifest = verify_bundle(bundle)
    assert manifest["range"] == "tiny"
    nft = bundle / "netns" / "range.nft"
    nft.write_text(nft.read_text() + " ")
    with pytest.raises(
        UpError, match=r"(?s)\[verify-bundle\].*range.nft: sha256 mismatch"
    ):
        verify_bundle(bundle)


def test_verify_bundle_refuses_unlisted_and_missing(bundle: Path) -> None:
    (bundle / "extra.txt").write_text("smuggled")
    with pytest.raises(UpError, match="extra.txt: not in manifest"):
        verify_bundle(bundle)
    (bundle / "extra.txt").unlink()
    (bundle / "boot.json").unlink()
    with pytest.raises(UpError, match="boot.json: missing"):
        verify_bundle(bundle)


def test_up_happy_path_env_and_stages(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_probes(monkeypatch)
    docker = FakeDocker()
    result = up(bundle, options(cache, tmp_path), runner=docker)
    assert result.project.startswith("ir-tiny-")
    assert all(guest.ready for guest in result.guests)
    assert [guest.cid for guest in result.guests] == [3000, 3001]
    # the hardened image is forced into the compose environment
    compose_up = docker.commands("docker", "compose")[0]
    assert "--project-directory" in compose_up
    assert docker.last_env is not None
    assert docker.last_env["RANGE_IMAGE"].startswith("inspect-ranges-range:v")
    owner = read_owner(tmp_path / "state", result.project)
    assert owner is not None and owner.range_name == "tiny"
    stages = [e["stage"] for e in StageLog(tmp_path / "state", result.project).events()]
    assert stages[:4] == [
        "verify-bundle",
        "verify-images",
        "range-image",
        "range-container",
    ]
    assert stages[-1] == "ready"


def test_up_refuses_duplicate_project_naming_down_command(
    bundle: Path, cache: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    docker.ps_output = "abc123\n"
    with pytest.raises(UpError, match=r"\[prepare\].*inspect-ranges down ir-tiny-"):
        up(bundle, options(cache, tmp_path), runner=docker)


def test_up_missing_and_mismatched_image(
    bundle: Path, cache: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    (cache / "tiny-golden.qcow2").unlink()
    with pytest.raises(
        UpError, match=r"\[verify-images\] guest 'web'.*not in the cache"
    ):
        up(bundle, options(cache, tmp_path), runner=docker)
    (cache / "tiny-golden.qcow2").write_bytes(b"swapped")
    with pytest.raises(UpError, match=r"\[verify-images\] guest 'web'.*does not match"):
        up(bundle, options(cache, tmp_path), runner=docker)


def test_up_readiness_failure_names_guest_and_tears_down(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(up_module().probe, "wait_daemon", _never_ready)
    docker = FakeDocker()
    docker.ps_sequence = [
        "",
        "c1\n",
    ]  # empty at duplicate check, one container at teardown
    with pytest.raises(UpError, match=r"\[readiness\] guest 'web'.*not ready"):
        up(bundle, options(cache, tmp_path), runner=docker)
    assert docker.commands("docker", "rm", "-f"), "failure must tear the project down"
    # console pull attempted for the failed guest
    assert any("cp" in call for call in docker.commands("docker", "compose"))


def test_up_keep_on_failure_skips_teardown(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(up_module().probe, "wait_daemon", _never_ready)
    docker = FakeDocker()
    with pytest.raises(UpError, match=r"\[readiness\]"):
        up(bundle, options(cache, tmp_path, keep_on_failure=True), runner=docker)
    assert not docker.commands("docker", "rm", "-f")


def test_up_compose_failure_is_stage_named(
    bundle: Path, cache: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    docker.fail_prefix = ("docker", "compose")
    with pytest.raises(UpError, match=r"\[range-container\].*compose up failed"):
        up(bundle, options(cache, tmp_path), runner=docker)


def test_boot_script_realizes_boot_json(bundle: Path) -> None:
    import json

    boot = json.loads((bundle / "boot.json").read_text())
    script = boot_script(boot)
    assert "qemu-img create -f qcow2 -F qcow2 -b /images/tiny-golden.qcow2" in script
    assert "virsh -c qemu:///system start web" in script
    assert script.index("define") < script.index("start web")


def test_down_removes_by_label_and_is_idempotent(tmp_path: Path) -> None:
    docker = FakeDocker()
    docker.ps_output = "c1\nc2\n"
    result = down("ir-tiny-abc", state_dir=tmp_path / "state", runner=docker)
    assert result.containers == 2
    rm = docker.commands("docker", "rm", "-f")[0]
    assert rm[-2:] == ["c1", "c2"]
    docker2 = FakeDocker()
    again = down("ir-tiny-abc", state_dir=tmp_path / "state", runner=docker2)
    assert (again.containers, again.volumes, again.networks) == (0, 0, 0)
    assert not docker2.commands("docker", "rm")


def test_down_all_sweeps_ir_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    docker = FakeDocker()

    def scripted(
        argv: list[str],
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> "subprocess.CompletedProcess[str]":
        docker.calls.append(argv)
        if argv[:3] == ["docker", "ps", "-a"] and "--format" in argv:
            return subprocess.CompletedProcess(argv, 0, "ir-left\nchan-batt\n\n", "")
        if argv[:4] == ["docker", "volume", "ls", "-q"] and len(argv) == 4:
            return subprocess.CompletedProcess(
                argv, 0, "ir-gone_scratch\nchan-batt_scratch\n", ""
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    results = down_all(state_dir=state, runner=scripted)
    assert [r.project for r in results] == ["ir-gone", "ir-left"]
    flat = [" ".join(c) for c in docker.calls]
    assert not any("chan-" in call for call in flat if call.startswith("docker rm")), (
        flat
    )


def test_down_registry_entry_without_resources_is_swept(tmp_path: Path) -> None:
    from inspect_ranges._runtime.ownership import owner_record, write_owner

    state = tmp_path / "state"
    write_owner(state, owner_record("ir-ghost", "ghost", "0" * 64, tmp_path))
    assert list_projects(state) == ["ir-ghost"]
    docker = FakeDocker()
    results = down_all(state_dir=state, runner=docker)
    assert [r.project for r in results] == ["ir-ghost"]
    assert list_projects(state) == []
