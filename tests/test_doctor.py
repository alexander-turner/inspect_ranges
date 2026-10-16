import json
import os
import subprocess
from pathlib import Path

import pytest
from inspect_ranges._doctor import (
    CheckResult,
    CheckStatus,
    passed,
    render_fix_script,
    render_text,
)
from inspect_ranges._doctor.checks import (
    check_br_netfilter,
    check_docker,
    check_image_tools,
    check_ipv6,
    check_kernel_readable,
    check_provider,
    check_virtualization,
    parse_version,
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["docker"], returncode, stdout, stderr)


def _info(
    server_version: str = "29.8.1", cgroup_version: str = "2"
) -> subprocess.CompletedProcess[str]:
    return _completed(
        stdout=json.dumps(
            {"ServerVersion": server_version, "CgroupVersion": cgroup_version}
        )
    )


def _compose(version: str = "v5.5.1") -> subprocess.CompletedProcess[str]:
    return _completed(stdout=json.dumps({"version": version}))


# real output shape when the daemon can't be reached: exit 1, empty ServerVersion, reason on stderr
_UNREACHABLE = '{"ID":"","ServerVersion":"","CgroupVersion":""}'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("29.8.1", (29, 8, 1)),
        ("v5.5.1", (5, 5, 1)),
        ("2.29.1-desktop.1", (2, 29, 1)),
        ("24.0", (24, 0)),
        ("dev", None),
    ],
)
def test_parse_version(text: str, expected: tuple[int, ...] | None) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("info", "compose", "expected", "fix_mentions"),
    [
        pytest.param(_info(), _compose(), ["ok", "ok", "ok", "ok"], None, id="healthy"),
        pytest.param(
            None,
            None,
            ["fail", "skip", "skip", "skip"],
            "install",
            id="docker-not-installed",
        ),
        pytest.param(
            _completed(
                1,
                _UNREACHABLE,
                "permission denied while trying to connect to the docker API",
            ),
            _compose(),
            ["fail", "skip", "skip", "skip"],
            "usermod -aG docker",
            id="permission-denied",
        ),
        pytest.param(
            _completed(
                1, _UNREACHABLE, "failed to connect to the docker API at unix:///x.sock"
            ),
            _compose(),
            ["fail", "skip", "skip", "skip"],
            "DOCKER_HOST",
            id="daemon-unreachable",
        ),
        pytest.param(
            _info(server_version="20.10.24"),
            _compose(),
            ["ok", "fail", "ok", "ok"],
            "Upgrade",
            id="old-engine",
        ),
        pytest.param(
            _info(),
            _completed(1, "", "docker: unknown command: docker compose"),
            ["ok", "ok", "fail", "ok"],
            "docker-compose-plugin",
            id="compose-missing",
        ),
        pytest.param(
            _info(),
            _compose("v2.21.0"),
            ["ok", "ok", "fail", "ok"],
            "--only-upgrade",
            id="old-compose",
        ),
        pytest.param(
            _info(cgroup_version="1"),
            _compose(),
            ["ok", "ok", "ok", "warn"],
            "cgroup",
            id="cgroup-v1",
        ),
    ],
)
def test_check_docker(
    info: subprocess.CompletedProcess[str] | None,
    compose: subprocess.CompletedProcess[str] | None,
    expected: list[CheckStatus],
    fix_mentions: str | None,
) -> None:
    results = check_docker(info, compose)
    assert [result.status for result in results] == expected
    if fix_mentions is not None:
        fixes = " ".join(result.fix or "" for result in results)
        assert fix_mentions in fixes


@pytest.mark.parametrize(
    ("device", "expected"),
    [
        ("net/tun", "fail"),
        ("vhost-net", "warn"),
        ("vhost-vsock", "fail"),
    ],
)
def test_check_virtualization_missing_device(
    tmp_path: Path, device: str, expected: CheckStatus
) -> None:
    for name in ("kvm", "net/tun", "vhost-net", "vhost-vsock"):
        if name != device:
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
    statuses = {result.name: result.status for result in check_virtualization(tmp_path)}
    assert statuses[(tmp_path / device).as_posix()] == expected
    present = tmp_path / "vhost-net" if device != "vhost-net" else tmp_path / "kvm"
    assert statuses[present.as_posix()] == "ok"


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "ok"), ("0", "ok"), ("1", "warn")],
)
def test_check_br_netfilter(
    tmp_path: Path, value: str | None, expected: CheckStatus
) -> None:
    if value is not None:
        setting = tmp_path / "net" / "bridge" / "bridge-nf-call-iptables"
        setting.parent.mkdir(parents=True)
        setting.write_text(f"{value}\n")
    assert check_br_netfilter(tmp_path).status == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "warn"), ("0", "ok"), ("1", "warn")],
)
def test_check_ipv6(tmp_path: Path, value: str | None, expected: CheckStatus) -> None:
    if value is not None:
        setting = tmp_path / "net" / "ipv6" / "conf" / "all" / "disable_ipv6"
        setting.parent.mkdir(parents=True)
        setting.write_text(f"{value}\n")
    assert check_ipv6(tmp_path).status == expected


@pytest.mark.parametrize(
    ("modes", "expected"),
    [([], "warn"), ([0o644], "ok"), ([0o644, 0o600], "ok"), ([0o644, 0o000], "fail")],
)
def test_check_kernel_readable(
    tmp_path: Path, modes: list[int], expected: CheckStatus
) -> None:
    if expected == "fail" and os.geteuid() == 0:
        pytest.skip("root can read files regardless of mode")
    for index, mode in enumerate(modes):
        kernel = tmp_path / f"vmlinuz-6.{index}.0-generic"
        kernel.write_bytes(b"kernel")
        kernel.chmod(mode)
    assert check_kernel_readable(tmp_path).status == expected


def test_check_image_tools_reports_missing_tool_with_package() -> None:
    def which(tool: str) -> str | None:
        return "/usr/bin/qemu-img" if tool == "qemu-img" else None

    results = {result.name: result for result in check_image_tools(which)}
    assert results["qemu-img"].status == "ok"
    assert results["virt-customize"].status == "fail"
    assert results["virt-customize"].fix == "sudo apt-get install libguestfs-tools"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [(["ok", "warn", "skip"], True), (["ok", "fail"], False), ([], True)],
)
def test_passed_ignores_warnings_and_skips(
    statuses: list[CheckStatus], expected: bool
) -> None:
    results = [
        CheckResult("Group", f"check {index}", status, "detail")
        for index, status in enumerate(statuses)
    ]
    assert passed(results) is expected


def test_render_text_shows_fixes_only_for_problems() -> None:
    results = [
        CheckResult("Group", "fine", "ok", "all good", fix="unused fix"),
        CheckResult("Group", "broken", "fail", "is broken", fix="run the fix"),
    ]
    text = render_text(results)
    assert "fix: run the fix" in text
    assert "unused fix" not in text
    assert text.endswith("1 ok, 0 warning(s), 1 failed, 0 skipped")


def test_render_text_hints_fix_script_when_fixes_are_runnable() -> None:
    results = [
        CheckResult(
            "G", "broken", "fail", "x", fix="f", fix_command="apt-get install -y x"
        )
    ]
    assert "doctor --fix-script" in render_text(results)
    assert "doctor --fix-script" not in render_text(
        [CheckResult("G", "broken", "fail", "x", fix="advice only")]
    )


def test_render_fix_script_includes_only_runnable_fixes_for_problems() -> None:
    results = [
        CheckResult(
            "G", "fine", "ok", "x", fix="f", fix_command="echo should-not-appear"
        ),
        CheckResult(
            "G",
            "pkg",
            "fail",
            "x",
            fix="f",
            fix_command="apt-get install -y qemu-utils",
        ),
        CheckResult(
            "G",
            "group",
            "warn",
            "x",
            fix="f",
            fix_command='usermod -aG kvm "$SUDO_USER"',
        ),
        CheckResult("G", "platform", "fail", "x", fix="use another machine"),
    ]
    script = render_fix_script(results)
    assert script.startswith("#!/bin/sh")
    assert "set -eu" in script
    assert '[ "$(id -u)" -eq 0 ]' in script  # refuses to run unprivileged
    assert "${SUDO_USER:?" in script  # usermod fix needs the invoking user
    assert script.index("apt-get update") < script.index(
        "apt-get install -y qemu-utils"
    )
    assert 'usermod -aG kvm "$SUDO_USER"' in script
    assert "should-not-appear" not in script
    assert "#   G / platform: use another machine" in script  # advice stays a comment


def test_render_fix_script_with_nothing_to_fix() -> None:
    script = render_fix_script([CheckResult("G", "fine", "ok", "x")])
    assert "no runnable fixes needed" in script
    assert "id -u" not in script


def test_check_realizer_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Docker-gated image check (skip vs ok vs warn) and the artifact check verifying the tarball the sidecar names."""
    import inspect_ranges._runtime.images as images_module
    from inspect_ranges._channel.bundle import write_bundle
    from inspect_ranges._doctor.checks import check_realizer

    artifact = tmp_path / "artifacts"
    monkeypatch.setattr(images_module, "DEFAULT_ARTIFACT_DIR", artifact)

    def status_of(results: "list[CheckResult]", name: str) -> str:
        return next(r.status for r in results if r.name == name)

    # docker unreachable: skip, never 'not built yet'
    results = check_realizer(image_inspect=None)
    assert status_of(results, "range image") == "skip"
    # image present
    ok_proc = subprocess.CompletedProcess(["docker"], 0, "ok\n", "")
    assert status_of(check_realizer(image_inspect=ok_proc), "range image") == "ok"
    # image absent (docker reachable)
    warn_proc = subprocess.CompletedProcess(["docker"], 1, "", "no such image")
    assert status_of(check_realizer(image_inspect=warn_proc), "range image") == "warn"
    # artifact absent entirely
    assert status_of(check_realizer(image_inspect=ok_proc), "daemon artifact") == "warn"
    # sidecar present but the tarball it names is missing
    write_bundle(artifact, b"fake", version="9.9.9-test")
    (artifact / "vsockd-bundle-9.9.9-test.tar").unlink()
    results = check_realizer(image_inspect=ok_proc)
    assert status_of(results, "daemon artifact") == "warn"
    assert "republish" in next(r.detail for r in results if r.name == "daemon artifact")
    # full artifact present
    write_bundle(artifact, b"fake", version="9.9.9-test")
    assert status_of(check_realizer(image_inspect=ok_proc), "daemon artifact") == "ok"


def _provider_results(tmp_path: Path) -> dict[str, CheckResult]:
    results = check_provider(state_dir=tmp_path / "state", image_cache=tmp_path / "img")
    return {result.name: result for result in results}


def test_check_provider_on_this_environment(tmp_path: Path) -> None:
    """The installed package registers the entry point and satisfies its own inspect-ai floor; empty cache and state report honestly."""
    results = _provider_results(tmp_path)
    assert results["entry point"].status == "ok"
    assert results["inspect-ai"].status == "ok"
    assert results["golden image"].status == "warn", "no goldens in an empty cache"
    assert results["cid leases"].status == "ok"


def test_check_provider_flags_stale_goldens_with_the_skew_guidance(
    tmp_path: Path,
) -> None:
    from inspect_ranges._runtime.images import DaemonPin, ImageMetadata

    cache = tmp_path / "img"
    cache.mkdir(parents=True)
    stale = ImageMetadata(
        name="old-golden",
        file="old-golden.qcow2",
        recipe_version="3",
        derivation_key="k",
        vendor_file="vendor.img",
        vendor_sha256="0" * 64,
        daemon=DaemonPin(name="vsockd", version="3.0.0", sha256="0" * 64),
        golden_sha256="0" * 64,
        created="2026-10-01T00:00:00+00:00",
    )
    (cache / "old-golden.json").write_text(stale.model_dump_json())
    results = check_provider(state_dir=tmp_path / "state", image_cache=cache)
    golden = next(result for result in results if result.name == "golden image")
    assert golden.status == "warn"
    assert "tamper-shaped" in golden.detail and "re-derive" in (golden.fix or "")


@pytest.mark.parametrize("content", ["{not json", "[]", "null"])
def test_check_provider_flags_a_corrupt_lease_registry(
    tmp_path: Path, content: str
) -> None:
    """Any registry the allocator cannot read is a fail row, never a doctor crash (valid-but-wrong JSON shapes included)."""
    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "cids.json").write_text(content)
    results = check_provider(state_dir=state, image_cache=tmp_path / "img")
    leases = next(result for result in results if result.name == "cid leases")
    assert leases.status == "fail"
    assert "inspect sandbox cleanup" in (leases.fix or "")


def test_check_provider_counts_real_leases(tmp_path: Path) -> None:
    """The lease count reads the allocator's actual flat format, not a wrapper key."""
    from inspect_ranges._provider.naming import CidAllocator

    state = tmp_path / "state"
    state.mkdir(parents=True)
    CidAllocator(state).lease("ir-doctor-probe", 2)
    results = check_provider(state_dir=state, image_cache=tmp_path / "img")
    leases = next(result for result in results if result.name == "cid leases")
    assert leases.status == "ok" and leases.detail.startswith("1 entry")


def test_check_provider_warns_when_the_golden_file_is_gone(tmp_path: Path) -> None:
    """A current-recipe sidecar whose image file was deleted is not a present golden."""
    from inspect_ranges._runtime.images import RECIPE_VERSION, DaemonPin, ImageMetadata

    cache = tmp_path / "img"
    cache.mkdir(parents=True)
    meta = ImageMetadata(
        name="ghost",
        file="ghost.qcow2",
        recipe_version=RECIPE_VERSION,
        derivation_key="k",
        vendor_file="vendor.img",
        vendor_sha256="0" * 64,
        daemon=DaemonPin(name="vsockd", version="3.1.0", sha256="0" * 64),
        golden_sha256="0" * 64,
        created="2026-10-09T00:00:00+00:00",
    )
    (cache / "ghost.json").write_text(meta.model_dump_json())
    results = check_provider(state_dir=tmp_path / "state", image_cache=cache)
    golden = next(result for result in results if result.name == "golden image")
    assert golden.status == "warn" and "image file is gone" in golden.detail


# -- the Host group (range-host-v1 slice 5) -----------------------------------------


def _host_lease(state: Path, project: str = "ir-h", ttl_s: float = 600) -> str:
    from inspect_ranges._host import LeaseStore

    from tests.test_host_leases import facts

    lease = LeaseStore(state).acquire(
        project=project,
        task_name="task",
        sample_id="s1",
        isolation="shared",
        origin="local",
        bundle_path="/b",
        bundle_digest="ab" * 32,
        staging="/s",
        host_facts=facts(),
        ttl_s=ttl_s,
    )
    return lease.lease_id


def test_check_host_clean_state(tmp_path: Path) -> None:
    from inspect_ranges._doctor.checks import check_host

    results = check_host(state_dir=tmp_path / "state", backend="local")
    assert [(r.name, r.status) for r in results] == [("host leases", "ok")]


def test_check_host_counts_current_leases(tmp_path: Path) -> None:
    from inspect_ranges._doctor.checks import check_host

    state = tmp_path / "state"
    _host_lease(state)
    results = {r.name: r for r in check_host(state_dir=state, backend="local")}
    assert results["host leases"].status == "ok"
    assert results["expired leases"].status == "ok"


def test_check_host_hints_the_reaper_for_expired_leases(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    from inspect_ranges._doctor.checks import check_host
    from inspect_ranges._host import LeaseStore

    from tests.test_host_leases import acquire

    state = tmp_path / "state"
    past = datetime.now(UTC) - timedelta(seconds=600)
    store = LeaseStore(state, now_fn=lambda: past)
    acquire(store, project="ir-stale", ttl_s=10)
    results = {r.name: r for r in check_host(state_dir=state, backend="local")}
    expired = results["expired leases"]
    assert expired.status == "warn"
    assert "ir-stale" in expired.detail
    assert expired.fix is not None and "inspect-ranges reaper" in expired.fix


def test_check_host_is_stricter_than_the_store(tmp_path: Path) -> None:
    """An entry the store would preserve-but-skip is a lease the reaper cannot see: doctor fails it loudly."""
    from inspect_ranges._doctor.checks import check_host

    state = tmp_path / "state"
    _host_lease(state)
    registry = state / "leases.json"
    entries = json.loads(registry.read_text())
    entries["future-lease"] = {"schema": 99}
    registry.write_text(json.dumps(entries))
    results = {r.name: r for r in check_host(state_dir=state, backend="local")}
    leases = results["host leases"]
    assert leases.status == "fail"
    assert "future-lease" in leases.detail


def test_check_host_fails_a_corrupt_registry(tmp_path: Path) -> None:
    from inspect_ranges._doctor.checks import check_host

    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "leases.json").write_text("{not json")
    results = {r.name: r for r in check_host(state_dir=state, backend="local")}
    assert results["host leases"].status == "fail"


def test_check_host_fails_an_unknown_backend(tmp_path: Path) -> None:
    """A typo'd INSPECT_RANGES_HOST must fail doctor, because the provider refuses it at eval time."""
    from inspect_ranges._doctor.checks import check_host

    results = {
        r.name: r
        for r in check_host(state_dir=tmp_path / "state", backend="unix:/tmp/x.sock")
    }
    backend = results["backend"]
    assert backend.status == "fail"
    assert "uds:<socket>" in backend.detail


def test_applier_socket_probe_shapes(tmp_path: Path) -> None:
    """Missing socket fails; a routing-answering listener (clean close, no ack) is ok; a bogus ack warns."""
    import asyncio

    from inspect_ranges._doctor.checks import check_host

    missing = tmp_path / "none.sock"
    results = {
        r.name: r
        for r in check_host(state_dir=tmp_path / "state", backend=f"uds:{missing}")
    }
    assert results["applier socket"].status == "fail"

    async def scenario(answer: bytes | None, path: Path) -> CheckResult:
        async def server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            received = b""
            while len(received) < 42:  # the whole preamble, however chunked
                chunk = await reader.read(64)
                if not chunk:
                    break
                received += chunk
            if answer is not None:
                writer.write(answer)
                await writer.drain()
            writer.close()

        listener = await asyncio.start_unix_server(server, path=str(path))
        try:
            probe = await asyncio.to_thread(
                check_host, state_dir=tmp_path / "state", backend=f"uds:{path}"
            )
            return next(r for r in probe if r.name == "applier socket")
        finally:
            listener.close()
            await listener.wait_closed()

    closing = asyncio.run(scenario(None, tmp_path / "closing.sock"))
    assert closing.status == "ok", closing.detail
    acking = asyncio.run(scenario(b"\x06", tmp_path / "acking.sock"))
    assert acking.status == "warn", acking.detail


# -- evidence group ------------------------------------------------------------


def _evidence_results(
    sink_override: str | None,
    log_dir: str | None,
    s3_client: object | None = None,
) -> dict[str, CheckResult]:
    from inspect_ranges._doctor.checks import check_evidence

    return {
        r.name: r for r in check_evidence(sink_override, log_dir, s3_client=s3_client)
    }


def test_check_evidence_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No override, no log dir: knobs ok, sink derived, local-only warned."""
    monkeypatch.delenv("INSPECT_RANGES_EVIDENCE_BUFFER_MB", raising=False)
    monkeypatch.delenv("INSPECT_RANGES_EVIDENCE_MAX_MB", raising=False)
    results = _evidence_results(None, None)
    assert results["knobs"].status == "ok"
    assert results["sink"].status == "ok"
    assert "derived from the eval log location" in results["sink"].detail
    assert results["off-instance"].status == "warn"
    assert results["off-instance"].fix is not None


def test_check_evidence_bad_knob_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_RANGES_EVIDENCE_MAX_MB", "zero")
    results = _evidence_results(None, None)
    assert results["knobs"].status == "fail"
    assert "INSPECT_RANGES_EVIDENCE_MAX_MB" in (results["knobs"].fix or "")


def test_check_evidence_local_sink_probe(tmp_path: Path) -> None:
    """A filesystem override is probed by writing and removing one file; the base is created like first use would."""
    base = tmp_path / "evidence"
    results = _evidence_results(str(base), None)
    assert results["sink"].status == "ok"
    assert base.is_dir()
    assert list(base.iterdir()) == []  # probe file removed
    assert results["off-instance"].status == "warn"


def test_check_evidence_unwritable_local_sink_fails(tmp_path: Path) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("a file where the sink dir should be")
    results = _evidence_results(str(blocker), None)
    assert results["sink"].status == "fail"
    assert "evidence disabled" in results["sink"].detail


def test_check_evidence_off_instance_resolution() -> None:
    """The override wins over the log dir; only a scheme the runtime supports counts as off-instance."""
    s3_log = _evidence_results(None, "s3://bucket/logs")
    assert s3_log["sink"].status == "ok"
    assert s3_log["off-instance"].status == "ok"
    local_override = _evidence_results("/tmp/evidence-x", "s3://bucket/logs")
    assert local_override["off-instance"].status == "warn"


def test_check_evidence_derived_unsupported_scheme_fails() -> None:
    """A fsspec log store the runtime cannot write (gs://, az://) must fail the derived sink row: the runtime would disable evidence for every sample, and a green row here blesses the exact misconfiguration (the override arm was already hardened; this is its derived sibling)."""
    for log_dir in ("gs://acme-evals/logs", "az://evals/logs", "file:///var/logs"):
        results = _evidence_results(None, log_dir)
        assert results["sink"].status == "fail", log_dir
        assert "disable evidence for every sample" in results["sink"].detail
        assert results["off-instance"].status != "ok", log_dir


def test_check_evidence_off_instance_never_blesses_a_rejected_sink() -> None:
    """When the sink row rejects a value, the off-instance row must not report ok for the same value: the row consumes the sink verdict, so this holds for every rejection shape, not just unsupported schemes."""
    for override in ("gs://bucket/evidence", "s3://", "s3:///prefix"):
        results = _evidence_results(override, None)
        assert results["sink"].status == "fail", override
        assert results["off-instance"].status == "warn", override
        assert "sink row carries the failure" in results["off-instance"].detail


def test_check_evidence_derived_malformed_s3_fails() -> None:
    """A bucket-less s3:// log dir is the same silent-disable class one input left of gs://: the derived arm shares the runtime's own predicate, so it must refuse."""
    results = _evidence_results(None, "s3://")
    assert results["sink"].status == "fail"
    assert results["off-instance"].status != "ok"


def test_check_evidence_empty_override_is_unset(tmp_path: Path) -> None:
    """The runtime treats an empty override as unset; doctor must evaluate the same sink (and never probe the cwd)."""
    results = _evidence_results("", "s3://bucket/logs")
    assert "derived from the eval log location" in results["sink"].detail
    assert results["off-instance"].status == "ok"


def test_check_evidence_unsupported_scheme_fails() -> None:
    """A scheme the runtime would refuse is a config fail, never a green local-path probe (which would mkdir a literal 'gs:/...' tree)."""
    for base in ("gs://bucket/evidence", "S3://bucket/evidence"):
        results = _evidence_results(base, None)
        assert results["sink"].status == "fail", base
        assert "unsupported" in results["sink"].detail


def test_check_evidence_each_bad_knob_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One broken knob never masks the other, and the fail row names the variables."""
    monkeypatch.setenv("INSPECT_RANGES_EVIDENCE_BUFFER_MB", "64MB")
    monkeypatch.setenv("INSPECT_RANGES_EVIDENCE_MAX_MB", "-1")
    results = _evidence_results(None, None)
    assert results["knobs"].status == "fail"
    assert "INSPECT_RANGES_EVIDENCE_BUFFER_MB" in results["knobs"].detail
    assert "INSPECT_RANGES_EVIDENCE_MAX_MB" in results["knobs"].detail


def test_check_evidence_local_probe_value_error_is_a_row() -> None:
    """Doctor's contract is a row per check: a NUL-bearing path must fail, not traceback."""
    results = _evidence_results("/tmp/evi\x00dence", None)
    assert results["sink"].status == "fail"


# the stubbed probe of an s3:// sink lives in tests/test_evidence_s3.py
# (that file carries the per-file boto pragmas)
