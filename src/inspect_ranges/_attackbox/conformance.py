"""The attack-box conformance battery: a provider boots when it passes (attack-box-v1).

The governance story of the seam as one runnable command (`inspect-ranges attackbox verify --spec <range.yaml>`): against a live range realized through the registered provider, the battery holds the proof obligations the design attaches to a foreign attack box. The obligations, as report rows: `capabilities` (the bundle declares honestly; `console_stream=True` has no ingest path and refuses), `realize` (attach, boot, strict readiness through the real `up`), `attacker-surface` (the agent-containment negative checks against the foreign box: a shared-segment defender sweeping the attacker finds zero answers, hypervisor endpoints answer exactly their declared service, reserved segment addresses stay silent), `session-stability` (the exec surface pins one daemon session across dials), `exec-parity` (inspect-ai's full sandbox `self_check` suite over the surface, with an EMPTY xfail pin: the live box is where CI pins must evaporate), and `teardown` (`down` reclaims the box before the netns, clears the record, re-dial refuses, and a second `down` is a no-op).

The battery runs the REAL paths end to end (render, up, the provider, docker); it is the acceptance gate a provider author runs on a KVM host, not a CI unit. Refusals that prevent the battery from running at all (no registered backend, a foothold spec with no dedicated attack box) raise `BatteryError`; obligation outcomes land as rows, most-severe first-failure semantics left to the caller's exit code.
"""

import asyncio
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .._build.manifest import (
    apply_build_manifest,
    default_build_cache,
    realized_backings,
)
from .._channel.channel import MessageChannel
from .._channel.vsock import HybridEndpoint, VsockTransport
from .._compiler import PlanOptions, render_bundle
from .._compiler.plan import ResolvedPlan, Totals
from .._provider.naming import CidAllocator
from .._runtime.down import DownError, down
from .._runtime.images import default_image_cache
from .._runtime.ownership import default_state_dir
from .._runtime.up import UpError, UpOptions, up
from ..types import RangeSpec
from .backend import AttackBoxBackend, attack_box_origin, resolve_attack_box
from .record import read_attack_box_record


class BatteryError(Exception):
    """The battery cannot run at all; the message names the remedy."""


@dataclass(frozen=True)
class BatteryRow:
    """One obligation's outcome."""

    name: str
    ok: bool
    detail: str = ""


@dataclass
class BatteryReport:
    """Every obligation's outcome, in run order; `passed` is the boot verdict."""

    rows: list[BatteryRow] = field(default_factory=list[BatteryRow])
    project: str | None = None

    @property
    def passed(self) -> bool:
        return all(row.ok for row in self.rows)

    def to_json(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "project": self.project,
            "rows": [
                {"name": row.name, "ok": row.ok, "detail": row.detail}
                for row in self.rows
            ],
        }


def _capabilities_row(backend: AttackBoxBackend) -> BatteryRow:
    if backend.capabilities.console_stream:
        return BatteryRow(
            "capabilities",
            False,
            "console_stream=True is not supported (no ingest path); declare "
            "False and let the drop land as a declared evidence gap",
        )
    return BatteryRow(
        "capabilities", True, "console drop declared (recorded as an evidence gap)"
    )


async def _live_rows(
    spec: RangeSpec,
    plan: ResolvedPlan,
    cids: dict[str, int],
    hybrid: dict[str, HybridEndpoint],
    attacker: str,
    staging: Path,
) -> list[BatteryRow]:
    """The obligations that hold against the running range: surface sweep, session stability, exec parity."""
    from .._build.behavioral import conformance_plan, run_conformance_checks
    from .._build.errors import BuildError
    from .._channel.channel import request_id
    from .._channel.protocol import Budget, ExecRequest
    from .._provider.provider import RangeSandboxEnvironment
    from .._provider.state import SampleHandle

    rows: list[BatteryRow] = []
    channel = MessageChannel(
        VsockTransport(cids, hybrid_sockets=hybrid), label="attackbox-battery"
    )

    # the box must HOLD its reserved addresses before the sweep means anything:
    # an L2-absent box answers the sweep with silence too, but by ARP timeout,
    # which both lies about the obligation and burns the whole exec budget
    defender, attacker_ips, _, _ = conformance_plan(spec, plan)
    reachable = False
    if defender is None:
        rows.append(
            BatteryRow(
                "foothold-reach",
                False,
                "no shared-segment linux defender in the spec; use a battery "
                "spec with one (dmz_pivot is the canonical shape)",
            )
        )
    else:
        try:
            probe = " && ".join(f"ping -c1 -W2 {ip} >/dev/null" for ip in attacker_ips)
            outcome = await channel.exec(
                defender,
                ExecRequest(
                    id=request_id(),
                    cmd=["sh", "-c", probe],
                    budget=Budget(command_ms=30_000),
                ),
            )
            reachable = outcome.rc == 0
            rows.append(
                BatteryRow(
                    "foothold-reach",
                    reachable,
                    f"the box answers on {', '.join(attacker_ips)} from {defender}"
                    if reachable
                    else f"the box does not hold its reserved address "
                    f"({', '.join(attacker_ips)}): nothing answered the "
                    f"defender's ping",
                )
            )
        except Exception as error:  # noqa: BLE001 - every obligation is a row
            rows.append(
                BatteryRow("foothold-reach", False, f"reach probe failed: {error}")
            )
    if reachable:
        try:
            await run_conformance_checks(spec, plan, cids, hybrid_sockets=hybrid)
            rows.append(
                BatteryRow(
                    "attacker-surface",
                    True,
                    "defender sweep clean; hypervisor endpoints and reserved "
                    "addresses as declared",
                )
            )
        except BuildError as error:
            rows.append(BatteryRow("attacker-surface", False, str(error)))
        except Exception as error:  # noqa: BLE001 - every obligation is a row
            rows.append(BatteryRow("attacker-surface", False, f"sweep failed: {error}"))
    else:
        rows.append(
            BatteryRow(
                "attacker-surface",
                False,
                "skipped: the box is not reachable on its segment",
            )
        )
    try:
        first = await channel.ping(attacker)
        second = await channel.ping(attacker)
        stable = bool(first.session) and first.session == second.session
        rows.append(
            BatteryRow(
                "session-stability",
                stable,
                f"daemon {first.daemon!r} session "
                + ("stable across dials" if stable else "UNSTABLE across dials"),
            )
        )
    except Exception as error:
        rows.append(BatteryRow("session-stability", False, f"ping failed: {error}"))

    import inspect_ai.util._sandbox.self_check as self_check_module

    handle = SampleHandle(
        project="ir-attackbox-battery",
        task_name="attackbox-verify",
        staging=staging,
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=cids[attacker],
        guest_cids={attacker: cids[attacker]},
        channel=channel,
    )
    environment = RangeSandboxEnvironment(attacker, handle)
    failures: list[str] = []
    names = list(self_check_module.__all__)
    for name in names:
        check = getattr(self_check_module, name)
        try:
            await check(environment)
        except Exception as error:  # noqa: BLE001 - each failure is a finding
            failures.append(f"{name}: {str(error)[:200]}")
    rows.append(
        BatteryRow(
            "exec-parity",
            not failures,
            f"{len(names)} self_check checks, empty xfail pin"
            if not failures
            else "; ".join(failures),
        )
    )
    return rows


def _teardown_rows(
    project: str,
    state_dir: Path,
    cids: dict[str, int],
    hybrid: dict[str, HybridEndpoint],
    attacker: str,
) -> list[BatteryRow]:
    try:
        down(project, state_dir=state_dir)
    except DownError as error:
        return [BatteryRow("teardown", False, str(error))]
    problems: list[str] = []
    try:
        if read_attack_box_record(state_dir, project) is not None:
            problems.append("the attack-box record survived teardown")
    except Exception as error:  # noqa: BLE001 - every obligation is a row
        problems.append(f"the attack-box record is unreadable after teardown: {error}")
    try:
        second = down(project, state_dir=state_dir)
        if (second.containers, second.volumes, second.networks) != (0, 0, 0):
            problems.append("a second down removed resources (teardown left some)")
    except DownError as error:
        problems.append(f"a second down failed instead of no-opping: {error}")

    async def probe() -> None:
        channel = MessageChannel(
            VsockTransport(cids, hybrid_sockets=hybrid),
            label="attackbox-battery-postdown",
            channel_budget_s=5.0,
        )
        await channel.ping(attacker)

    try:
        asyncio.run(probe())
        problems.append("the exec surface still answers after teardown")
    except Exception:
        pass  # refusal is the obligation
    if problems:
        return [BatteryRow("teardown", False, "; ".join(problems))]
    return [
        BatteryRow(
            "teardown",
            True,
            "box reclaimed before the netns; record cleared; re-dial refused; "
            "second down a no-op",
        )
    ]


def run_attack_box_battery(
    spec_path: Path,
    *,
    image_cache: Path | None = None,
    state_dir: Path | None = None,
    keep: bool = False,
    readiness_timeout: float = 300.0,
) -> BatteryReport:
    """Run the whole battery against `spec_path` through the registered provider; see the module docstring for the obligations.

    Raises:
        BatteryError: `INSPECT_RANGES_ATTACK_BOX` is unset or does not resolve, the spec does not load, or it declares a foothold (no dedicated attack box, so the seam excludes it by construction).
    """
    from ..schema import load_range

    try:
        origin = attack_box_origin()
    except ValueError as error:
        raise BatteryError(str(error)) from error
    if origin is None:
        raise BatteryError(
            "INSPECT_RANGES_ATTACK_BOX is not set; register the provider under "
            "test as '<module>.<factory>[:<config>]' and re-run"
        )
    state = state_dir if state_dir is not None else default_state_dir()
    try:
        backend = resolve_attack_box(origin, state)
    except ValueError as error:
        raise BatteryError(str(error)) from error
    try:
        spec = load_range(spec_path)
    except Exception as error:
        raise BatteryError(f"spec {spec_path} does not load: {error}") from error
    if spec.attacker.host is not None:
        raise BatteryError(
            f"spec {spec_path} declares a foothold attacker (host: "
            f"{spec.attacker.host!r}); the battery needs a dedicated attack "
            "box, which is the seam's whole scope"
        )
    cache = image_cache if image_cache is not None else default_image_cache()

    report = BatteryReport(rows=[_capabilities_row(backend)])
    staging_root = state.parent / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    # a well-behaved tenant: the battery leases its CID block from the shared
    # registry like the provider does, so it coexists with live ranges on the
    # host (a fixed base collided with a running eval, measured)
    allocator = CidAllocator(state)
    project = f"ir-abox-battery-{uuid.uuid4().hex[:8]}"
    guest_count = len(spec.hosts) + len(spec.routers) + 1  # + the attack box
    cid_lease = allocator.lease(project, guest_count)
    try:
        with tempfile.TemporaryDirectory(
            prefix="ir-abox-battery-", dir=staging_root
        ) as temp:
            spec, realized_sections, consumed = apply_build_manifest(
                spec, image_cache=cache, build_cache=default_build_cache()
            )
            bundle = Path(temp) / "bundle"
            render_bundle(
                spec,
                bundle,
                PlanOptions(
                    image_cache=cache,
                    cid_base=cid_lease.base,
                    realized_sections=realized_sections,
                    realized_backings=realized_backings(consumed) if consumed else {},
                ),
            )
            plan = ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())
            attacker = next(g.name for g in plan.guests if g.kind == "attacker")
            try:
                result = up(
                    bundle,
                    UpOptions(
                        project=project,
                        image_cache=cache,
                        state_dir=state,
                        readiness_timeout=readiness_timeout,
                        attack_box=origin,
                    ),
                )
            except UpError as error:
                report.rows.append(BatteryRow("realize", False, str(error)))
                return report
            report.project = result.project
            report.rows.append(
                BatteryRow(
                    "realize",
                    True,
                    f"project {result.project}: every guest ready, the attack "
                    "box through the provider",
                )
            )
            cids = {guest.name: guest.cid for guest in result.guests}
            hybrid = {
                guest.name: guest.hybrid_vsock
                for guest in result.guests
                if guest.hybrid_vsock is not None
            }
            try:
                report.rows.extend(
                    asyncio.run(
                        _live_rows(spec, plan, cids, hybrid, attacker, Path(temp))
                    )
                )
            except Exception as error:  # noqa: BLE001 - teardown still owed
                report.rows.append(
                    BatteryRow("live-obligations", False, f"aborted: {error}")
                )
            finally:
                if keep:
                    report.rows.append(
                        BatteryRow(
                            "teardown",
                            True,
                            f"skipped (--keep); tear down with: inspect-ranges "
                            f"down {result.project} (the CID lease is held "
                            "while the range lives; the reaper's prune "
                            "releases it after the down)",
                        )
                    )
                else:
                    report.rows.extend(
                        _teardown_rows(result.project, state, cids, hybrid, attacker)
                    )
    finally:
        if not keep:
            allocator.release(project)
    return report
