"""The attack-box conformance battery: refusals, report semantics, and the CLI verb.

The battery's live obligations run real render/up/docker and are the devbox acceptance gate (`INSPECT_RANGES_ATTACK_BOX=tests.fake_attackbox.factory inspect-ranges attackbox verify --spec <canonical range>`); CI holds the refusal surface, the report contract, and the CLI rendering.
"""

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from inspect_ranges._attackbox.conformance import (
    BatteryError,
    BatteryReport,
    BatteryRow,
    _witness_row,
    run_attack_box_battery,
)
from inspect_ranges._channel.channel import (
    ExecContext,
    FakeGuest,
    LoopbackTransport,
    MessageChannel,
)
from inspect_ranges._channel.protocol import ExecEvent
from inspect_ranges._cli.attackboxcmd import attackbox

FOOTHOLD_SPEC = """\
meta:
  name: battery-foothold
  description: battery refusal fixture.
networks:
  - { name: lab, cidr: 10.10.10.0/24, mode: isolated }
hosts:
  - name: web
    os: { type: linux }
    image: img
    interfaces: [{ network: lab }]
attacker: { host: web, entry: external }
"""


def write_spec(tmp_path: Path, text: str = FOOTHOLD_SPEC) -> Path:
    spec = tmp_path / "range.yaml"
    spec.write_text(text)
    return spec


def test_battery_refuses_without_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INSPECT_RANGES_ATTACK_BOX", raising=False)
    with pytest.raises(BatteryError, match="INSPECT_RANGES_ATTACK_BOX is not set"):
        run_attack_box_battery(write_spec(tmp_path))


def test_battery_refuses_an_unresolvable_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INSPECT_RANGES_ATTACK_BOX", "no_such_pkg_xyz.boxes.cell")
    with pytest.raises(BatteryError, match="does not import"):
        run_attack_box_battery(write_spec(tmp_path))


def test_battery_refuses_a_foothold_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A foothold range has no dedicated attack box; the battery names the scope rather than running vacuously."""
    monkeypatch.setenv("INSPECT_RANGES_ATTACK_BOX", "tests.fake_attackbox.factory")
    with pytest.raises(BatteryError, match="dedicated attack box"):
        run_attack_box_battery(write_spec(tmp_path), state_dir=tmp_path / "state")


# -- the exec-witness obligation --------------------------------------------------


def _witness_channel(guest: FakeGuest) -> MessageChannel:
    transport = LoopbackTransport(guests=())
    transport.guests["attacker"] = guest
    return MessageChannel(transport, label="witness-row-test")


def test_witness_row_passes_when_the_marker_is_witnessed() -> None:
    """The behavioral bar: the marker exec appears in the stream after arming, and a re-read from its sequence returns it again (honest cursors)."""
    guest = FakeGuest("attacker")

    async def witnessing_true(context: ExecContext) -> tuple[int, bytes, bytes]:
        guest.exec_events_ring.append(
            ExecEvent(
                seq=len(guest.exec_events_ring) + 1,
                ts_ms=1,
                pid=4242,
                comm="true",
                argv=list(context.argv),
                truncated=False,
            )
        )
        return 0, b"", b""

    guest.register("true", witnessing_true)
    row = asyncio.run(
        _witness_row(_witness_channel(guest), "attacker", marker="m-feed")
    )
    assert row.ok, row.detail
    assert guest.exec_events_armed, "the first poll must arm the subscriber"


def test_witness_row_fails_a_typed_refusal() -> None:
    """ENOSYS/EPROTO stays the declared-drop path for ordinary guests, but the attack box must serve the witness."""
    guest = FakeGuest("attacker")
    guest.exec_events_error = "ENOSYS"
    row = asyncio.run(
        asyncio.wait_for(
            _witness_row(_witness_channel(guest), "attacker", marker="m-feed"),
            timeout=30,
        )
    )
    assert not row.ok
    assert "typed refusal (ENOSYS)" in row.detail


def test_witness_row_tolerates_marker_eviction_on_a_busy_ring() -> None:
    """A busy ring may evict the marker between the find and the re-read; the documented overwrite signal is honest, not a cursor failure."""
    from typing import Any, cast

    from inspect_ranges._channel.protocol import ExecEventsReply

    class EvictingWitnessChannel:
        def __init__(self) -> None:
            self.polls = 0

        async def exec_events(
            self, guest: str, *, since_seq: int = 0, max_events: int = 128
        ) -> ExecEventsReply:
            self.polls += 1
            if self.polls == 1:
                return ExecEventsReply(id="ab" * 16, next_seq=1)
            if self.polls == 2:
                return ExecEventsReply(
                    id="ab" * 16,
                    events=[
                        ExecEvent(
                            seq=1,
                            ts_ms=1,
                            pid=1,
                            comm="true",
                            argv=["true", "m-feed"],
                            truncated=False,
                        )
                    ],
                    next_seq=2,
                )
            # the re-read from the marker's seq: evicted, true head above it
            return ExecEventsReply(
                id="ab" * 16,
                events=[
                    ExecEvent(
                        seq=5, ts_ms=2, pid=2, comm="x", argv=["x"], truncated=False
                    )
                ],
                next_seq=6,
            )

        async def exec(self, guest: str, request: Any, **kwargs: Any) -> object:
            return object()

    row = asyncio.run(
        _witness_row(
            cast(MessageChannel, EvictingWitnessChannel()), "attacker", marker="m-feed"
        )
    )
    assert row.ok, row.detail
    assert "evicted" in row.detail


def test_witness_row_fails_a_surface_that_serves_but_never_witnesses() -> None:
    """A shim can answer the verb with an empty ring forever; the marker requirement catches it."""
    guest = FakeGuest("attacker")  # default `true` handler, ring stays empty
    row = asyncio.run(
        _witness_row(
            _witness_channel(guest), "attacker", marker="m-feed", deadline_s=1.0
        )
    )
    assert not row.ok
    assert "never appeared" in row.detail


def test_report_passes_only_when_every_row_does() -> None:
    ok = BatteryRow("realize", True)
    bad = BatteryRow("teardown", False, "record survived")
    assert BatteryReport(rows=[ok]).passed
    assert not BatteryReport(rows=[ok, bad]).passed
    payload = BatteryReport(rows=[ok, bad], project="ir-x").to_json()
    assert payload["passed"] is False and payload["project"] == "ir-x"
    assert [row["name"] for row in payload["rows"]] == ["realize", "teardown"]


def test_cli_verify_renders_rows_and_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect_ranges._cli.attackboxcmd as command_module

    report = BatteryReport(
        rows=[
            BatteryRow("realize", True, "project ir-x"),
            BatteryRow("exec-parity", False, "test_exec_timeout: hung"),
        ],
        project="ir-x",
    )

    def fake_battery(*args: object, **kwargs: object) -> BatteryReport:
        return report

    monkeypatch.setattr(command_module, "run_attack_box_battery", fake_battery)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec)])
    assert result.exit_code == 1
    assert "[FAIL] exec-parity" in result.output
    assert "a provider boots when it passes: FAIL" in result.output


def test_cli_verify_json_and_pass_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect_ranges._cli.attackboxcmd as command_module

    report = BatteryReport(rows=[BatteryRow("realize", True)], project="ir-x")

    def fake_battery(*args: object, **kwargs: object) -> BatteryReport:
        return report

    monkeypatch.setattr(command_module, "run_attack_box_battery", fake_battery)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["passed"] is True


def test_cli_verify_turns_refusals_into_clean_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INSPECT_RANGES_ATTACK_BOX", raising=False)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec)])
    assert result.exit_code != 0
    assert "INSPECT_RANGES_ATTACK_BOX is not set" in result.output
