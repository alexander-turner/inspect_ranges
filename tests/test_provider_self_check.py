"""Slice-3 milestone: inspect-ai's full `self_check` suite against the provider on CI, zero VMs.

Every check from `inspect_ai.util._sandbox.self_check` runs as a pytest case against a `LibvirtRangeSandboxEnvironment` whose channel reaches a `LocalEndpoint` (real argv on this host under a temp root). The xfail pin is TWO-SIDED: a pinned check that passes fails the run, so the list can never rot. A second parametrization runs the identical suite through `LatencyTransport`, the chatty-regression milestone range-channel.md requires, with a per-check exchange budget asserted from `ChannelStats` (deterministic, unlike wall clock).

The checks run through the house convention (`asyncio.run` per case) rather than pytest-asyncio, which the repo deliberately does not use.
"""

import asyncio
import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import inspect_ai.util._sandbox.self_check as self_check_module
import pytest
from inspect_ai.util import SandboxEnvironment
from inspect_ranges._channel.channel import LoopbackTransport, MessageChannel, Transport
from inspect_ranges._channel.mocks import LatencyTransport
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._provider.provider import LibvirtRangeSandboxEnvironment
from inspect_ranges._provider.state import SampleHandle

from tests.local_endpoint import LocalEndpoint

Check = Callable[[SandboxEnvironment], Awaitable[None]]

CHECKS: list[tuple[str, Check]] = [
    (name, getattr(self_check_module, name)) for name in self_check_module.__all__
]

# -- the two-sided CI xfail pin ------------------------------------------------
# Keyed by check name; the value is the reason. A pinned check that PASSES
# fails the run (xpass), so this list cannot rot. These are limits of the CI
# endpoint host, not of the provider: the real gates are the booted-range runs
# (slices 4 and 5), where the pin must shrink to empty.

CI_XFAILS: dict[str, str] = {
    "test_exec_as_user": "needs root on the endpoint host (adduser/userdel provisioning)",
}
if os.geteuid() == 0:
    for name in (
        "test_read_file_not_allowed",
        "test_write_text_file_without_permissions",
        "test_write_binary_file_without_permissions",
    ):
        CI_XFAILS[name] = (
            "running as root: file modes do not bind (the daemon agent-user fix is slice 4)"
        )

LATENCY_RTT_S = 0.05
EXCHANGES_BUDGET_PER_CHECK = 120
"""Generous but real: the chattiest honest check (~20 ops at <=3 exchanges each,
plus wrapper-script uploads) stays far under this; a per-chunk-round-trip
regression blows through it immediately."""


def make_env(
    root: Path, transport_kind: str
) -> tuple[SandboxEnvironment, MessageChannel]:
    loopback = LoopbackTransport(guests=())
    loopback.guests["box"] = LocalEndpoint("box", root)
    transport: Transport = loopback
    if transport_kind == "latency":
        transport = LatencyTransport(loopback, rtt_s=LATENCY_RTT_S)
    channel = MessageChannel(transport, label=f"self-check-{transport_kind}")
    handle = SampleHandle(
        project="ir-self-check",
        task_name="self_check",
        staging=root / "staging",
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=10_000,
        guest_cids={"box": 10_000},
        channel=channel,
    )
    return LibvirtRangeSandboxEnvironment("box", handle), channel


@pytest.mark.parametrize("transport_kind", ["loopback", "latency"])
@pytest.mark.parametrize(("name", "check"), CHECKS, ids=[name for name, _ in CHECKS])
def test_self_check(
    name: str, check: Check, transport_kind: str, tmp_path: Path
) -> None:
    if transport_kind == "latency" and name in (
        "test_read_and_write_large_file_binary",
        "test_exec_input_large",
    ):
        pytest.skip(
            "50 MiB payload cases add nothing under latency; loopback covers them"
        )
    env, channel = make_env(tmp_path, transport_kind)

    async def scenario() -> None:
        await check(env)

    if name in CI_XFAILS:
        try:
            asyncio.run(scenario())
        except BaseException:
            return  # expected failure on this endpoint
        pytest.fail(
            f"{name} unexpectedly PASSED despite the CI xfail pin "
            f"({CI_XFAILS[name]}); update the pin, two-sidedly"
        )
    asyncio.run(scenario())
    if transport_kind == "latency":
        assert channel.stats.exchanges <= EXCHANGES_BUDGET_PER_CHECK, (
            f"{name} used {channel.stats.exchanges} exchanges: a chatty "
            f"regression (budget {EXCHANGES_BUDGET_PER_CHECK})"
        )


def test_ci_xfail_pin_is_short() -> None:
    """The record requires the CI pin to stay short and enumerated; growth is a review event."""
    assert set(CI_XFAILS) <= {
        "test_exec_as_user",
        "test_read_file_not_allowed",
        "test_write_text_file_without_permissions",
        "test_write_binary_file_without_permissions",
    }


def test_check_inventory_matches_the_installed_suite() -> None:
    """The harness runs every exported check (a new inspect-ai check shows up here as a count change)."""
    assert len(CHECKS) == 44, (
        f"inspect-ai self_check now exports {len(CHECKS)} checks; "
        "review the delta and update the harness expectations"
    )
