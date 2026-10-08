from pathlib import Path

p = Path("tests/test_updown.py")
t = p.read_text()

old = """        self.ps_sequence: list[str] | None = None
        self.fail_prefix: tuple[str, ...] | None = None"""
new = """        self.ps_sequence: list[str] | None = None
        self.fail_prefix: tuple[str, ...] | None = None
        self.fail_on_input = False
        self.fail_rm = False"""
assert old in t
t = t.replace(old, new)

old = """        if self.fail_prefix and tuple(argv[: len(self.fail_prefix)]) == self.fail_prefix:
            return subprocess.CompletedProcess(argv, 1, "", "scripted failure")"""
new = """        if self.fail_prefix and tuple(argv[: len(self.fail_prefix)]) == self.fail_prefix:
            return subprocess.CompletedProcess(argv, 1, "", "scripted failure")
        if self.fail_on_input and input is not None:
            return subprocess.CompletedProcess(argv, 1, "", "boot blew up")
        if self.fail_rm and argv[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(argv, 1, "", "daemon hiccup")"""
assert old in t
t = t.replace(old, new)

tail = '''

def test_verify_bundle_refuses_corrupt_manifest_and_symlinks(bundle: Path) -> None:
    link = bundle / "netns" / "evil"
    link.symlink_to("/etc/hostname")
    with pytest.raises(UpError, match=r"(?s)\\[verify-bundle\\].*evil: symlink"):
        verify_bundle(bundle)
    link.unlink()
    (bundle / "manifest.json").write_text("{truncated")
    with pytest.raises(UpError, match=r"\\[verify-bundle\\].*unreadable or malformed"):
        verify_bundle(bundle)


def test_cloud_init_failure_means_not_ready(
    bundle: Path, cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cloud-init exiting nonzero (error or degraded) is an unready guest, loudly."""
    monkeypatch.setattr(up_module().probe, "wait_daemon", _always_ready)

    def cloud_init_failed(cid: int, command: str, timeout: float) -> tuple[int, str, str]:
        return (1, "", "")

    monkeypatch.setattr(up_module().probe, "guest_exec", cloud_init_failed)
    docker = FakeDocker()
    with pytest.raises(UpError, match=r"\\[readiness\\] guest 'web'"):
        up(bundle, options(cache, tmp_path), runner=docker)


def test_guest_boot_failure_pulls_consoles_before_teardown(
    bundle: Path, cache: Path, tmp_path: Path
) -> None:
    docker = FakeDocker()
    docker.fail_on_input = True
    with pytest.raises(UpError, match=r"\\[guest-boot\\]"):
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
    docker.ps_output = "c1\\n"
    docker.fail_rm = True
    with pytest.raises(DownError, match="docker rm"):
        down("ir-x", state_dir=state, runner=docker)
    assert list_projects(state) == ["ir-x"], "state kept so a retry can find the project"


def test_cid_base_below_reserved_range_is_rejected() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        PlanOptions(cid_base=2)
'''
t = t.rstrip() + "\n" + tail
p.write_text(t)
print("tests added")
