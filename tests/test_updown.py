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
        self.fail_on_input = False
        self.fail_rm = False

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
        if self.fail_on_input and input is not None:
            return subprocess.CompletedProcess(argv, 1, "", "boot blew up")
        if self.fail_rm and argv[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(argv, 1, "", "daemon hiccup")
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
        readiness_min_window=0.2,
        **overrides,
    )


def up_module() -> Any:
    import importlib

    return importlib.import_module("inspect_ranges._runtime.up")


class FakeOutcome:
    def __init__(self, rc: int) -> None:
        self.rc = rc
        self.stdout = b""
        self.stderr = b""


class FakeChannel:
    """Readiness-channel stand-in: scriptable ping and exec, optionally executing the probed command for real (behavioral pin)."""

    def __init__(
        self,
        ping_ok: bool = True,
        exec_rc: int = 0,
        run_commands: bool = False,
        env: dict[str, str] | None = None,
    ) -> None:
        self.ping_ok = ping_ok
        self.exec_rc = exec_rc
        self.run_commands = run_commands
        self.env = env
        self.exec_requests: list[Any] = []

    async def ping(self, guest: str) -> object:
        if not self.ping_ok:
            raise ConnectionError("no daemon")
        return object()

    async def exec(self, guest: str, request: Any, **kwargs: Any) -> FakeOutcome:
        self.exec_requests.append(request)
        if self.run_commands:
            import subprocess as sp

            proc = sp.run(list(request.cmd), capture_output=True, env=self.env)
            return FakeOutcome(proc.returncode)
        return FakeOutcome(self.exec_rc)


def use_channel(monkeypatch: pytest.MonkeyPatch, channel: FakeChannel) -> None:
    def factory(cids: dict[str, int]) -> FakeChannel:
        return channel

    monkeypatch.setattr(up_module(), "make_channel", factory)


def ready_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    use_channel(monkeypatch, FakeChannel(ping_ok=True, exec_rc=0))


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
    use_channel(monkeypatch, FakeChannel(ping_ok=False))
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
    use_channel(monkeypatch, FakeChannel(ping_ok=False))
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
    from inspect_ranges._runtime.up import load_boot

    boot = load_boot(bundle)
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


def test_verify_bundle_refuses_corrupt_manifest_and_symlinks(bundle: Path) -> None:
    link = bundle / "netns" / "evil"
    link.symlink_to("/etc/hostname")
    with pytest.raises(UpError, match=r"(?s)\[verify-bundle\].*evil: symlink"):
        verify_bundle(bundle)
    link.unlink()
    (bundle / "manifest.json").write_text("{truncated")
    with pytest.raises(UpError, match=r"\[verify-bundle\].*unreadable or malformed"):
        verify_bundle(bundle)


def test_cloud_init_failure_means_not_ready(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cloud-init exiting nonzero (error or degraded) is an unready guest, loudly."""
    use_channel(monkeypatch, FakeChannel(ping_ok=True, exec_rc=1))
    docker = FakeDocker()
    with pytest.raises(UpError, match=r"\[readiness\] guest 'web'"):
        up(bundle, options(cache, tmp_path), runner=docker)


def test_guest_boot_failure_pulls_consoles_before_teardown(
    bundle: Path, cache: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    docker.fail_on_input = True
    docker.ps_sequence = ["", "c1\n"]  # empty at duplicate check, one at teardown
    with pytest.raises(UpError, match=r"\[guest-boot\]"):
        up(bundle, options(cache, tmp_path), runner=docker)
    flat = [" ".join(c) for c in docker.calls]
    cp_index = next(i for i, c in enumerate(flat) if " cp range:/scratch/console/" in c)
    rm_index = next(i for i, c in enumerate(flat) if c.startswith("docker rm -f"))
    assert cp_index < rm_index, "consoles must be pulled before the volume dies"


def test_relative_image_cache_is_resolved_into_compose_env(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_probes(monkeypatch)
    monkeypatch.chdir(cache.parent)
    docker = FakeDocker()
    up(bundle, options(Path(cache.name), tmp_path), runner=docker)
    assert docker.last_env is not None
    assert Path(docker.last_env["IMAGE_CACHE"]).is_absolute()


def test_down_failure_raises_and_keeps_state(tmp_path: Path) -> None:
    from inspect_ranges._runtime.down import DownError
    from inspect_ranges._runtime.ownership import owner_record, write_owner

    state = tmp_path / "state"
    write_owner(state, owner_record("ir-x", "x", "0" * 64, tmp_path))
    docker = FakeDocker()
    docker.ps_output = "c1\n"
    docker.fail_rm = True
    with pytest.raises(DownError, match="docker rm"):
        down("ir-x", state_dir=state, runner=docker)
    assert list_projects(state) == ["ir-x"], (
        "state kept so a retry can find the project"
    )


def test_cid_base_below_reserved_range_is_rejected() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        PlanOptions(cid_base=2)


def test_down_all_continues_past_a_failing_project(tmp_path: Path) -> None:
    """One stuck project cannot shield the rest of the sweep; failures aggregate."""
    import subprocess as sp

    from inspect_ranges._runtime.down import DownError
    from inspect_ranges._runtime.ownership import owner_record, write_owner

    state = tmp_path / "state"
    for name in ("ir-bad", "ir-good"):
        write_owner(state, owner_record(name, name, "0" * 64, tmp_path))
    calls: list[list[str]] = []

    def scripted(
        argv: list[str],
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> "sp.CompletedProcess[str]":
        calls.append(argv)
        joined = " ".join(argv)
        if "project=ir-bad" in joined and argv[:3] == ["docker", "ps", "-a"]:
            return sp.CompletedProcess(argv, 0, "stuck\n", "")
        if argv[:3] == ["docker", "rm", "-f"] and "stuck" in argv:
            return sp.CompletedProcess(argv, 1, "", "removal in progress")
        return sp.CompletedProcess(argv, 0, "", "")

    with pytest.raises(DownError, match=r"(?s)the rest were swept.*ir-bad"):
        down_all(state_dir=state, runner=scripted)
    assert list_projects(state) == ["ir-bad"], (
        "the good project was swept, the stuck one kept"
    )


def test_verify_bundle_refuses_traversal_and_absolute_members(bundle: Path) -> None:
    """Member names must stay inside the bundle: no .. segments, no absolute paths, no resolving outside the root (hashing host files would make the mismatch error a digest oracle)."""
    import json

    manifest = json.loads((bundle / "manifest.json").read_text())
    for member in ("../outside.txt", "/etc/hostname", "netns/../../escape.txt"):
        crafted = dict(manifest)
        crafted["files"] = dict(manifest["files"])
        crafted["files"][member] = {"sha256": "0" * 64, "size": 1}
        (bundle / "manifest.json").write_text(json.dumps(crafted))
        with pytest.raises(
            UpError, match=r"(?s)\[verify-bundle\].*escapes the bundle root"
        ):
            verify_bundle(bundle)


def test_verify_bundle_refuses_nonobject_shapes(bundle: Path) -> None:
    import json

    manifest = json.loads((bundle / "manifest.json").read_text())
    crafted = dict(manifest)
    crafted["files"] = dict(manifest["files"])
    crafted["files"]["boot.json"] = "not-an-object"
    (bundle / "manifest.json").write_text(json.dumps(crafted))
    with pytest.raises(
        UpError, match=r"(?s)boot.json: manifest entry is not an object"
    ):
        verify_bundle(bundle)
    (bundle / "manifest.json").write_text("[1, 2, 3]")
    with pytest.raises(UpError, match=r"unreadable or malformed"):
        verify_bundle(bundle)


def test_boot_json_shape_is_enforced(bundle: Path) -> None:
    """A crafted boot.json (shell metacharacters in names, unknown readiness, unknown keys) refuses before anything interpolates it."""
    import json

    from inspect_ranges._runtime.up import load_boot

    boot = json.loads((bundle / "boot.json").read_text())
    plan = load_boot(bundle)
    assert [g.name for g in plan.guests] == ["web", "attacker"]
    for mutation in (
        {"name": "web; rm -rf /"},
        {"image_file": "$(reboot).qcow2"},
        {"readiness": "none"},
        {"overlay_gb": 0},
        {"cid": 2},
    ):
        crafted = json.loads(json.dumps(boot))
        crafted["guests"][0].update(mutation)
        (bundle / "boot.json").write_text(json.dumps(crafted))
        with pytest.raises(UpError, match=r"boot.json is unreadable or malformed"):
            load_boot(bundle)


def test_boot_script_shell_quotes_values(bundle: Path) -> None:
    from inspect_ranges._runtime.up import BootGuest, BootPlan
    from inspect_ranges._runtime.up import boot_script as script

    plan = BootPlan(
        parallel=True,
        verify={},
        guests=[
            BootGuest(
                name="we.b-1",
                cid=3000,
                image_file="img.qcow2",
                image_digest=None,
                overlay_gb=10,
                readiness="cloud-init",
            )
        ],
    )
    text = script(plan)
    assert "we.b-1" in text and ";" not in text.replace(";\n", "")


def test_cloud_init_probe_command_behaves(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The probe command is executed for real against a stubbed cloud-init: a nonzero status MUST mean not ready (pins the historically-regressed '; echo done' bug behaviorally, now through the channel exec)."""
    import os

    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    stub = stub_bin / "cloud-init"
    stub.write_text("#!/bin/sh\nexit 1\n")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub_bin}:{os.environ['PATH']}")
    channel = FakeChannel(run_commands=True, env=env)
    use_channel(monkeypatch, channel)
    docker = FakeDocker()
    docker.ps_sequence = ["", "c1\n"]
    with pytest.raises(UpError, match=r"\[readiness\]"):
        up(bundle, options(cache, tmp_path), runner=docker)
    assert channel.exec_requests, "the readiness exec must actually run"
    stub.write_text("#!/bin/sh\nexit 0\n")
    docker2 = FakeDocker()
    result = up(bundle, options(cache, tmp_path), runner=docker2)
    assert all(guest.ready for guest in result.guests)


def test_teardown_failure_never_masks_the_diagnosed_error(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_channel(monkeypatch, FakeChannel(ping_ok=False))
    docker = FakeDocker()
    docker.ps_sequence = ["", "c1\n", "c1\n"]
    docker.fail_rm = True
    with pytest.raises(UpError) as excinfo:
        up(bundle, options(cache, tmp_path), runner=docker)
    message = str(excinfo.value)
    assert "[readiness]" in message and "not ready" in message
    assert "teardown also failed" in message


def test_readiness_fails_closed_on_any_channel_weirdness(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any exception from the readiness channel is not-ready plus normal teardown, never an escape."""

    class WeirdChannel(FakeChannel):
        async def exec(self, guest: str, request: Any, **kwargs: Any) -> FakeOutcome:
            raise RuntimeError("protocol went sideways")

    use_channel(monkeypatch, WeirdChannel())
    docker = FakeDocker()
    docker.ps_sequence = ["", "c1\n"]
    with pytest.raises(UpError, match=r"\[readiness\]"):
        up(bundle, options(cache, tmp_path), runner=docker)
    assert docker.commands("docker", "rm", "-f"), "teardown still runs"


def test_range_image_rebuilds_on_content_mismatch() -> None:
    import subprocess as sp

    from inspect_ranges._runtime.rangeimage import ensure_range_image

    calls: list[list[str]] = []

    def scripted(argv: list[str]) -> "sp.CompletedProcess[str]":
        calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return sp.CompletedProcess(argv, 0, "stale-content-hash\n", "")
        return sp.CompletedProcess(argv, 0, "", "")

    ensure_range_image(scripted)
    assert any(argv[:2] == ["docker", "build"] for argv in calls), (
        "a tag whose content label mismatches must rebuild"
    )


def test_make_channel_uses_the_readiness_allowance() -> None:
    """One wedged accept-but-never-reply guest must cost seconds per attempt, not the channel default."""
    channel = up_module().make_channel({"web": 3000})
    assert channel._channel_budget_s == 10.0  # noqa: SLF001 - the tuned allowance is the contract


def test_readiness_failure_logs_the_swallowed_cause(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_channel(monkeypatch, FakeChannel(ping_ok=True, exec_rc=2))
    docker = FakeDocker()
    docker.ps_sequence = ["", "c1\n"]
    with pytest.raises(UpError, match=r"\[readiness\]"):
        up(bundle, options(cache, tmp_path), runner=docker)
    state_root = tmp_path / "state"
    project = next(entry.name for entry in state_root.iterdir())
    events = StageLog(state_root, project).events()
    fails = [e for e in events if e["stage"] == "readiness" and e["status"] == "fail"]
    assert fails and any("exited 2" in str(e.get("cause", "")) for e in fails)
