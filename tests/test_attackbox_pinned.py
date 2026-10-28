"""The pinned external program provider: a release run as a separate program over `<program> attackbox` (protocol 1), selected explicitly through `INSPECT_RANGES_ATTACK_BOX`.

The provider program is a stub script in `tmp_path` that speaks the protocol from a scenario file and logs what it received, tap fd contents included. Releases are served from `file://` URLs, so the download path runs for real with no network.
"""

import asyncio
import hashlib
import json
import os
import re
import sys
import tarfile
from collections.abc import Generator
from contextlib import contextmanager
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._attackbox import (
    AttachedInterface,
    AttackBoxBackend,
    FootholdAttachment,
    attack_box_origin,
    resolve_attack_box,
)
from inspect_ranges._attackbox.backend import ENV_VAR
from inspect_ranges._attackbox.external import ExternalBoxError
from inspect_ranges._attackbox.pinned import (
    BUILTIN_HINT,
    PROGRAM_ENV,
    PinnedProgramProvider,
    ProgramPin,
    ProgramTooOld,
    ensure_program,
    load_pin,
    prepare_attack_box,
)
from inspect_ranges._channel.vsock import HybridEndpoint
from inspect_ranges._provider.provider import RangeSandboxEnvironment as Env

from tests.test_provider_lifecycle import rigged_runtime, small_spec

_STUB = """\
import json, os, sys
if sys.argv[1:] == ["--version"]:
    print(os.environ.get("STUB_VERSION", "glovebox 0.92.4"))
    sys.exit(0)
verb = sys.argv[2]
request = json.loads(sys.stdin.read()) if verb != "probe" else None
taps = {}
if verb == "boot":
    for interface in request["interfaces"]:
        taps[str(interface["fd"])] = os.read(interface["fd"], 64).decode()
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps({"argv": sys.argv[1:], "request": request, "taps": taps}) + "\\n")
reply = json.loads(open(os.environ["STUB_SCENARIO"]).read())[verb]
sys.stdout.write(reply["stdout"])
sys.exit(reply.get("status", 0))
"""

OK_BOOT = {
    "protocol": 1,
    "exec_socket": "/run/glovebox/attacker.sock",
    "exec_uid": 1234,
    "reclaim_token": "vm-7",
}
SETUP = "sudo glovebox setup --kata"


class Stub:
    """A stub `glovebox` that answers `--version` and the `attackbox` verbs, with its scenario and call log."""

    def __init__(self, root: Path) -> None:
        bin_dir = root / "glovebox" / "bin"
        bin_dir.mkdir(parents=True)
        self.program = bin_dir / "glovebox"
        self.program.write_text(f"#!{sys.executable}\n{_STUB}")
        self.program.chmod(0o755)
        self.scenario = root / "scenario.json"
        self.log = root / "calls.jsonl"
        self.set()

    def set(self, **verbs: dict[str, Any] | str | tuple[str, int]) -> None:
        """Set each verb's reply: an object (exit 0), raw stdout (exit 0), or `(stdout, status)`."""
        replies = {
            "boot": OK_BOOT,
            "teardown": {"protocol": 1},
            "probe": {"protocol": 1, "ok": True},
            **verbs,
        }
        scenario: dict[str, dict[str, Any]] = {}
        for verb, reply in replies.items():
            if isinstance(reply, tuple):
                scenario[verb] = {"stdout": reply[0], "status": reply[1]}
            elif isinstance(reply, str):
                scenario[verb] = {"stdout": reply}
            else:
                scenario[verb] = {"stdout": json.dumps(reply)}
        self.scenario.write_text(json.dumps(scenario))

    def calls(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]


@pytest.fixture
def stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Stub:
    """The stub installed as the provider program, selected explicitly through the pinned glovebox origin."""
    made = Stub(tmp_path)
    monkeypatch.setenv(PROGRAM_ENV, str(made.program))
    monkeypatch.setenv("STUB_SCENARIO", str(made.scenario))
    monkeypatch.setenv("STUB_LOG", str(made.log))
    monkeypatch.setenv(ENV_VAR, load_pin("glovebox").origin)
    return made


def attachment(tap_fd: int) -> FootholdAttachment:
    return FootholdAttachment(
        project="p1",
        guest_name="attacker",
        cid=7,
        cpus=1,
        memory_mb=1024,
        interfaces=(
            AttachedInterface(
                segment="dmz",
                bridge="br-dmz",
                tap_fd=tap_fd,
                mac="52:54:00:00:00:05",
                ip=IPv4Address("10.0.0.5"),
                prefixlen=24,
                gateway=IPv4Address("10.0.0.1"),
            ),
        ),
    )


@contextmanager
def tap_pipe(payload: bytes) -> Generator[int]:
    """A real fd standing in for a tap: its read end, with `payload` waiting in it."""
    read_end, write_end = os.pipe()
    os.write(write_end, payload)
    os.close(write_end)
    try:
        yield read_end
    finally:
        os.close(read_end)


def selected_backend(tmp_path: Path) -> AttackBoxBackend:
    origin = attack_box_origin()
    assert origin is not None
    return resolve_attack_box(origin, tmp_path / "state")


# -- boot and teardown -----------------------------------------------------------------


def test_boot_passes_tap_fds_and_builds_the_handle(stub: Stub, tmp_path: Path) -> None:
    backend = selected_backend(tmp_path)
    with tap_pipe(b"frames-for-the-box") as fd:
        handle = asyncio.run(backend.provider.boot(attachment(fd)))
    assert handle.exec_endpoint == HybridEndpoint(
        Path("/run/glovebox/attacker.sock"), 1234
    )
    assert handle.reclaim_token == "vm-7"
    [call] = stub.calls()
    assert call["argv"] == ["attackbox", "boot"]
    assert call["request"]["interfaces"][0]["fd"] == fd
    assert call["taps"] == {str(fd): "frames-for-the-box"}, (
        "the stub must read the tap through the very fd number the request names"
    )
    assert call["request"]["project"] == "p1"
    assert call["request"]["guest_name"] == "attacker"


def test_teardown_sends_the_project_and_is_idempotent(
    stub: Stub, tmp_path: Path
) -> None:
    provider = selected_backend(tmp_path).provider
    asyncio.run(provider.teardown("p1", "vm-7"))
    asyncio.run(provider.teardown("p1", ""))
    requests = [call["request"] for call in stub.calls()]
    assert requests == [
        {"protocol": 1, "project": "p1", "reclaim_token": "vm-7"},
        {"protocol": 1, "project": "p1", "reclaim_token": ""},
    ]


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (
            (
                json.dumps(
                    {
                        "protocol": 1,
                        "error": {
                            "cause": "no KVM",
                            "remedy": SETUP,
                            "report_url": None,
                        },
                    }
                ),
                1,
            ),
            ["no KVM", f"remedy: {SETUP}"],
        ),
        (
            (
                json.dumps(
                    {
                        "protocol": 1,
                        "error": {
                            "cause": "relay wedged",
                            "remedy": None,
                            "report_url": "https://example.test/bug",
                        },
                    }
                ),
                1,
            ),
            ["relay wedged", "report this bug at: https://example.test/bug"],
        ),
        (("Traceback (most recent call last)", 1), ["exited 1 with no protocol reply"]),
        (json.dumps(OK_BOOT) + json.dumps(OK_BOOT), ["exactly one JSON object"]),
        ("", ["exactly one JSON object"]),
        (json.dumps([OK_BOOT]), ["not an object"]),
        ({**OK_BOOT, "protocol": 2}, ["protocol 2"]),
        ({**OK_BOOT, "protocol": True}, ["protocol True"]),
        ({k: v for k, v in OK_BOOT.items() if k != "protocol"}, ["protocol None"]),
        ({**OK_BOOT, "exec_uid": "1234"}, ["not a uid"]),
        ({**OK_BOOT, "exec_socket": "relative.sock"}, ["not an absolute path"]),
        ((json.dumps(OK_BOOT), 3), ["exited 3 without an error object"]),
    ],
    ids=[
        "host-gap-remedy",
        "bug-report-url",
        "no-reply",
        "two-objects",
        "empty",
        "array",
        "protocol-2",
        "protocol-true",
        "protocol-missing",
        "bad-uid",
        "relative-socket",
        "failed-exit-with-success-body",
    ],
)
def test_boot_refusals_name_the_cause_and_the_builtin_box(
    stub: Stub, tmp_path: Path, reply: Any, expected: list[str]
) -> None:
    stub.set(boot=reply)
    with tap_pipe(b"") as fd, pytest.raises(ExternalBoxError) as raised:
        asyncio.run(selected_backend(tmp_path).provider.boot(attachment(fd)))
    message = str(raised.value)
    for fragment in expected:
        assert fragment in message
    assert message.endswith(BUILTIN_HINT)


def test_teardown_refusal_carries_the_error_object(stub: Stub, tmp_path: Path) -> None:
    stub.set(
        teardown=(
            json.dumps(
                {
                    "protocol": 1,
                    "error": {"cause": "vm busy", "remedy": None, "report_url": None},
                }
            ),
            1,
        )
    )
    with pytest.raises(ExternalBoxError, match="vm busy"):
        asyncio.run(selected_backend(tmp_path).provider.teardown("p1", ""))


# -- the pin, the download, the cache, and the version floor ---------------------------


def release(tmp_path: Path, *, version: str) -> tuple[str, str]:
    """A release tarball shaped like glovebox's source archive, whose program reports `version`: its `file://` URL and SHA-256."""
    tree = tmp_path / "src" / "agent-glovebox-9.9.9"
    (tree / "bin").mkdir(parents=True)
    program = tree / "bin" / "glovebox"
    program.write_text(f"#!/bin/sh\necho 'glovebox {version}'\n")
    program.chmod(0o755)
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(tree, arcname=tree.name)
    return archive.as_uri(), hashlib.sha256(archive.read_bytes()).hexdigest()


def make_pin(url: str, digest: str) -> ProgramPin:
    return ProgramPin(
        name="glovebox",
        tag="v9.9.9",
        url=url,
        sha256=digest,
        entry="bin/glovebox",
        min_version="0.92.4",
        url_template="file:///nowhere/{tag}.tar.gz",
    )


def test_first_use_downloads_and_a_second_hits_the_cache(tmp_path: Path) -> None:
    url, digest = release(tmp_path, version="0.92.4")
    pin = make_pin(url, digest)
    cache = tmp_path / "cache"
    program = ensure_program(pin, cache_root=cache)
    assert program == cache / "glovebox" / "v9.9.9" / "bin" / "glovebox"
    Path(url.removeprefix("file://")).unlink()
    assert ensure_program(pin, cache_root=cache) == program, (
        "a cached release needs no download"
    )


def test_a_hash_mismatch_refuses_and_caches_nothing(tmp_path: Path) -> None:
    url, _ = release(tmp_path, version="0.92.4")
    pin = make_pin(url, "0" * 64)
    cache = tmp_path / "cache"
    with pytest.raises(ExternalBoxError, match="nothing was cached"):
        ensure_program(pin, cache_root=cache)
    assert not (cache / "glovebox" / "v9.9.9").exists()


@pytest.mark.parametrize(
    ("reported", "refusal"),
    [
        ("glovebox 0.92.4", None),
        ("glovebox 1.0.0 (v1.0.0-3-gabc123)", None),
        ("glovebox v0.93.0", None),
        ("glovebox 0.92.3", "needs glovebox 0.92.4 or newer"),
        ("glovebox 0.92.4\nlaunching claude", "not 'glovebox MAJOR.MINOR.PATCH'"),
        ("other 9.9.9", "not 'glovebox MAJOR.MINOR.PATCH'"),
        ("glovebox 0.92", "not 'glovebox MAJOR.MINOR.PATCH'"),
        ("", "not 'glovebox MAJOR.MINOR.PATCH'"),
    ],
    ids=[
        "at-floor",
        "newer-with-note",
        "v-prefix",
        "too-old",
        "extra-line",
        "other-program",
        "two-part",
        "silent",
    ],
)
def test_the_override_must_report_the_minimum_version(
    stub: Stub,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reported: str,
    refusal: str | None,
) -> None:
    """`--version` alone decides, parsed strictly, before any verb could reach an older release's launcher."""
    monkeypatch.setenv("STUB_VERSION", reported)
    pin = make_pin("file:///unused", "0" * 64)
    if refusal is None:
        assert ensure_program(pin, cache_root=tmp_path / "cache") == stub.program
    else:
        with pytest.raises(ExternalBoxError, match=re.escape(refusal)):
            ensure_program(pin, cache_root=tmp_path / "cache")
    assert stub.calls() == [], "no attackbox verb runs while the version is checked"


def test_a_release_below_the_floor_is_never_run(tmp_path: Path) -> None:
    """The pinned v0.92.3 is such a release: it would treat `attackbox` as arguments for an agent launch."""
    url, digest = release(tmp_path, version="0.92.3")
    with pytest.raises(ProgramTooOld, match="needs glovebox 0.92.4 or newer"):
        ensure_program(make_pin(url, digest), cache_root=tmp_path / "cache")


def test_teardown_under_a_release_below_the_floor_is_a_no_op(tmp_path: Path) -> None:
    """Such a release cannot have booted a box, so a failed `up`'s project still tears down; boot still refuses by name."""
    url, digest = release(tmp_path, version="0.92.3")
    pin = make_pin(url, digest)
    provider = PinnedProgramProvider(
        lambda: ensure_program(pin, cache_root=tmp_path / "cache"),
        builtin_hint=BUILTIN_HINT,
    )
    asyncio.run(provider.teardown("p1", ""))
    with (
        tap_pipe(b"") as fd,
        pytest.raises(ExternalBoxError, match="needs glovebox 0.92.4 or newer"),
    ):
        asyncio.run(provider.boot(attachment(fd)))


def test_never_pull_refuses_the_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INSPECT_RANGES_NEVER_PULL", "1")
    url, digest = release(tmp_path, version="0.92.4")
    with pytest.raises(ExternalBoxError) as raised:
        ensure_program(make_pin(url, digest), cache_root=tmp_path / "cache")
    assert PROGRAM_ENV in str(raised.value)


# -- eval init: the probe, and through the provider ------------------------------------

PROBE_FAILS = {
    "protocol": 1,
    "ok": False,
    "error": {
        "cause": "kata runtime not installed",
        "remedy": SETUP,
        "report_url": None,
    },
}


def test_a_failed_probe_names_cause_remedy_and_the_builtin_box(stub: Stub) -> None:
    stub.set(probe=PROBE_FAILS)
    with pytest.raises(ExternalBoxError) as raised:
        prepare_attack_box(load_pin("glovebox").origin)
    assert str(raised.value).splitlines() == [
        "kata runtime not installed",
        f"remedy: {SETUP}",
        BUILTIN_HINT,
    ]


@pytest.mark.parametrize(
    ("selected", "probes"),
    [(True, 1), (False, 0)],
    ids=["explicit-pinned-program", "unset-is-builtin"],
)
def test_eval_init_probes_only_a_selected_program(
    stub: Stub,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected: bool,
    probes: int,
) -> None:
    """The origin `up` receives (and stamps into the attack-box record) carries the pinned tag; unset keeps the built-in box and runs nothing."""
    if not selected:
        monkeypatch.delenv(ENV_VAR)

    async def scenario() -> list[str | None]:
        with sandbox_lifecycle_scope():
            _, seams = rigged_runtime(tmp_path)
            await Env.task_init("task", small_spec())
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "s1"})
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            return [options.attack_box for options in seams.up_calls]

    booted = asyncio.run(scenario())
    origin = load_pin("glovebox").origin
    assert booted == [origin if selected else None]
    assert "glovebox/v0.92.3@sha256:" in origin
    probed = [call for call in stub.calls() if call["argv"] == ["attackbox", "probe"]]
    assert len(probed) == probes


def test_eval_init_refuses_when_the_probe_fails(stub: Stub, tmp_path: Path) -> None:
    stub.set(probe=PROBE_FAILS)

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            rigged_runtime(tmp_path)
            await Env.task_init("task", small_spec())

    with pytest.raises(Exception, match="kata runtime not installed") as raised:
        asyncio.run(scenario())
    assert BUILTIN_HINT in str(raised.value)
