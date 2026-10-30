"""The default attack box: the pinned glovebox release when `INSPECT_RANGES_ATTACK_BOX` is unset, with a terminal-only fallback to the built-in box.

The provider program is the protocol stub from `test_attackbox_pinned.py`.
"""

import asyncio
import io
import os
import select
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._attackbox.backend import ENV_VAR
from inspect_ranges._attackbox.external import ExternalBoxError
from inspect_ranges._attackbox.pinned import (
    BUILTIN_HINT,
    FALLBACK_QUESTION,
    PROGRAM_ENV,
    default_attack_box_origin,
    pin_from_config,
    prepare_with_fallback,
)
from inspect_ranges._provider.provider import RangeSandboxEnvironment as Env

from tests.test_attackbox_pinned import PROBE_FAILS, SETUP, Stub
from tests.test_provider_lifecycle import rigged_runtime, small_spec


@pytest.fixture
def stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Stub:
    """The stub installed as the provider program, with `INSPECT_RANGES_ATTACK_BOX` unset: the default."""
    made = Stub(tmp_path)
    monkeypatch.setenv(PROGRAM_ENV, str(made.program))
    monkeypatch.setenv("STUB_SCENARIO", str(made.scenario))
    monkeypatch.setenv("STUB_LOG", str(made.log))
    monkeypatch.delenv(ENV_VAR)
    return made


@contextmanager
def terminal(answer: bytes) -> Generator[tuple[TextIO, TextIO, int]]:
    """A real pseudo-terminal as stdin and stdout, with `answer` already typed; yields the master fd to read the screen."""
    master, slave = os.openpty()
    os.write(master, answer)
    stdin = open(os.dup(slave))  # noqa: SIM115 - closed below
    stdout = open(os.dup(slave), "w")  # noqa: SIM115 - closed below
    try:
        yield stdin, stdout, master
    finally:
        stdin.close()
        stdout.close()
        os.close(slave)
        os.close(master)


def screen(master: int) -> str:
    text = b""
    while select.select([master], [], [], 0.5)[0]:
        text += os.read(master, 4096)
    return text.decode()


@pytest.mark.parametrize(("answer", "falls_back"), [(b"y\n", True), (b"\n", False)])
def test_a_terminal_is_asked_once_and_the_answer_decides(
    stub: Stub, answer: bytes, falls_back: bool
) -> None:
    stub.set(probe=PROBE_FAILS)
    origin = default_attack_box_origin()
    with terminal(answer) as (stdin, stdout, master):
        if falls_back:
            assert prepare_with_fallback(origin, stdin=stdin, stdout=stdout) is None
        else:
            with pytest.raises(
                ExternalBoxError, match="INSPECT_RANGES_ATTACK_BOX=builtin"
            ):
                prepare_with_fallback(origin, stdin=stdin, stdout=stdout)
        shown = screen(master)
    assert "kata runtime not installed" in shown
    assert f"remedy: {SETUP}" in shown
    assert FALLBACK_QUESTION.strip() in shown


def test_without_a_terminal_nothing_is_asked(stub: Stub) -> None:
    stub.set(probe=PROBE_FAILS)
    asked = io.StringIO()
    with pytest.raises(ExternalBoxError) as raised:
        prepare_with_fallback(
            default_attack_box_origin(), stdin=io.StringIO("y\n"), stdout=asked
        )
    assert asked.getvalue() == ""
    assert str(raised.value).splitlines() == [
        "kata runtime not installed",
        f"remedy: {SETUP}",
        BUILTIN_HINT,
    ]


# -- through the provider --------------------------------------------------------------


@pytest.mark.parametrize(
    ("selection", "probe", "answer", "booted_with"),
    [
        (None, {"protocol": 1, "ok": True}, b"", "pinned"),
        (None, PROBE_FAILS, b"y\n", None),
        ("builtin", PROBE_FAILS, b"", None),
    ],
    ids=["default-is-the-pinned-glovebox", "terminal-fallback", "builtin"],
)
def test_eval_init_decides_the_box_each_sample_boots(
    stub: Stub,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selection: str | None,
    probe: dict[str, Any],
    answer: bytes,
    booted_with: str | None,
) -> None:
    """The origin `up` receives (and stamps into the attack-box record) carries the pinned tag; a terminal's yes, or `builtin`, boots the built-in box."""
    if selection is not None:
        monkeypatch.setenv(ENV_VAR, selection)
    stub.set(probe=probe)

    async def scenario() -> list[str | None]:
        with sandbox_lifecycle_scope():
            _, seams = rigged_runtime(tmp_path)
            await Env.task_init("task", small_spec())
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "s1"})
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            return [options.attack_box for options in seams.up_calls]

    with terminal(answer) as (stdin, stdout, _):
        monkeypatch.setattr(sys, "stdin", stdin)
        monkeypatch.setattr(sys, "stdout", stdout)
        booted = asyncio.run(scenario())
    expected = default_attack_box_origin() if booted_with == "pinned" else None
    assert booted == [expected]
    if expected is not None:
        assert pin_from_config(expected.partition(":")[2]).name == "glovebox"
    probed = [call for call in stub.calls() if call["argv"] == ["attackbox", "probe"]]
    assert len(probed) == (0 if selection == "builtin" else 1)


def test_eval_init_refuses_without_a_terminal(stub: Stub, tmp_path: Path) -> None:
    stub.set(probe=PROBE_FAILS)

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            rigged_runtime(tmp_path)
            await Env.task_init("task", small_spec())

    with pytest.raises(Exception, match="kata runtime not installed") as raised:
        asyncio.run(scenario())
    assert BUILTIN_HINT in str(raised.value)
