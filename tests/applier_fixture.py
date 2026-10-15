"""Applier test fixture: in-process helpers plus the two-OS-process entry point.

`fake_guest_connector` serves `FakeGuest`s (or `LocalEndpoint`s) over memory streams exactly the way `LoopbackTransport` does, so the applier's byte pump relays real codec frames to real endpoint logic. `fake_up` emits the honest up stage sequence through `on_stage` and returns an `UpResult` derived from the bundle's `plan.json`, so the applier's translation, relay registration, and replay log run against the genuine flow with no docker behind it.

Run as a script (`python tests/applier_fixture.py --socket S --state-dir D --mode conformance|self-check`) it serves a REAL `Applier` in a separate OS process: `conformance` wires one `FakeGuest` fleet per lease, `self-check` wires one `LocalEndpoint` per lease rooted under the lease's staging dir. A background task polls the lease store and (re-)registers each lease's relay map, so guest routing works before any realize and survives a teardown between tests.
"""

import asyncio
import time
from pathlib import Path

from inspect_ranges._channel.channel import (
    ByteStream,
    FakeGuest,
    stream_pair,
)
from inspect_ranges._channel.codec import (
    ChannelClosed,
    DecodeError,
    MessageStreamReader,
    encode_message,
)
from inspect_ranges._channel.protocol import DAEMON_INBOUND_BULK_CAP
from inspect_ranges._host.applier import Applier
from inspect_ranges._host.leases import LeaseStore
from inspect_ranges._provider.admission import HostCapacity
from inspect_ranges._runtime.down import DownResult
from inspect_ranges._runtime.up import GuestState, OnStage, UpOptions, UpResult

from tests.local_endpoint import LocalEndpoint

FIXTURE_GUEST_CID = 20_000
"""First CID the fixture assigns (the range-host battery band, 20000+)."""


def make_bundle(out: Path, name: str = "uds-fixture", *, evidence: bool = False) -> str:
    """A minimal CI bundle (manifest.json + plan.json) at `out`; returns its canonical digest. With `evidence`, the plan carries `requirements.evidence_capture` so the applier's host-writer path engages."""
    import hashlib
    import json

    from inspect_ranges._compiler.plan import PlanOptions, plan_json, resolve_plan
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        RangeMeta,
        RangeSpec,
    )

    spec = RangeSpec(
        meta=RangeMeta(name=name, description="applier fixture range"),
        networks=[Network(name="lab", cidr="10.9.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    plan = resolve_plan(
        spec,
        PlanOptions(
            image_cache=out / "cache",
            cid_base=FIXTURE_GUEST_CID + 500,
            evidence_capture=evidence,
        ),
    )
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.json").write_text(plan_json(plan))
    manifest = (
        json.dumps(
            {
                "range": plan.range.name,
                "spec_sha256": plan.range.spec_sha256,
                "files": {},
            },
            indent=2,
        )
        + "\n"
    )
    (out / "manifest.json").write_text(manifest)
    return hashlib.sha256(manifest.encode()).hexdigest()


HONEST_UP_EVENTS: tuple[tuple[str, str], ...] = (
    ("verify-bundle", "ok"),
    ("verify-images", "ok"),
    ("range-image", "ok"),
    ("range-container", "start"),
    ("range-container", "ok"),
    ("guest-boot", "start"),
    ("guest-boot", "ok"),
    ("readiness", "start"),
    ("readiness", "ok"),
    ("ready", "ok"),
)


async def serve_guest(guest: FakeGuest, stream: ByteStream) -> None:
    """One per-operation guest connection, exactly `LoopbackTransport`'s daemon side."""
    reader = MessageStreamReader(stream.receive, bulk_cap=DAEMON_INBOUND_BULK_CAP)
    try:
        message, bulk = await reader.next()
    except (DecodeError, ChannelClosed):
        await stream.aclose()
        return
    reply = await guest.handle(message, bulk)
    if guest.drop_next_reply:
        guest.drop_next_reply = False
        await stream.aclose()
        return
    for frame in encode_message(reply.message, reply.bulk):
        await stream.send(frame)
    await stream.aclose()


class FakeGuestConnector:
    """A `GuestConnector` dialing an in-memory fleet keyed by CID; `auto_create` mints a guest per unseen CID (for flows where the plan allocates CIDs the test cannot predict)."""

    def __init__(
        self,
        guests: dict[int, FakeGuest] | None = None,
        *,
        auto_create: bool = False,
    ) -> None:
        self.guests: dict[int, FakeGuest] = guests or {}
        self._auto_create = auto_create
        self._tasks: set["asyncio.Task[None]"] = set()

    async def __call__(self, cid: int) -> ByteStream:
        guest = self.guests.get(cid)
        if guest is None and self._auto_create:
            guest = FakeGuest(f"cid-{cid}")
            self.guests[cid] = guest
        if guest is None:
            raise ConnectionError(f"no guest at cid {cid}")
        client_side, server_side = stream_pair()
        task = asyncio.create_task(serve_guest(guest, server_side))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return client_side


def fake_up(bundle: Path, options: UpOptions, on_stage: OnStage) -> UpResult:
    """The honest up flow with zero docker: stage events through `on_stage`, guests from `plan.json`."""
    from inspect_ranges._compiler.plan import ResolvedPlan

    plan = ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())
    marker = bundle / "fail-at-stage"
    fail_at = marker.read_text().strip() if marker.exists() else None
    for stage, status in HONEST_UP_EVENTS:
        if fail_at is not None and stage == fail_at:
            on_stage(stage, "fail", {"error": f"injected failure at {stage}"})
            from inspect_ranges._runtime.up import UpError

            raise UpError(stage, f"injected failure at {stage}")
        on_stage(stage, status, {})
    return UpResult(
        project=options.project or "fixture",
        range_name=plan.range.name,
        guests=[
            GuestState(name=guest.name, cid=guest.cid, ready=True)
            for guest in plan.guests
        ],
        seconds=0.01,
    )


def fake_down(project: str, state_dir: Path) -> DownResult:
    return DownResult(project=project, containers=0, volumes=0, networks=0)


async def register_relays_forever(
    applier: Applier,
    store: LeaseStore,
    connector: FakeGuestConnector,
    mode: str,
) -> None:
    """(Re-)register each lease's relay map every 25 ms: guest routing works before any realize and survives teardown between tests."""
    assigned: dict[str, int] = {}
    next_cid = FIXTURE_GUEST_CID
    while True:
        for lease in store.leases():
            cid = assigned.get(lease.lease_id)
            if cid is None:
                cid = next_cid
                next_cid += 1
                assigned[lease.lease_id] = cid
                if mode == "self-check":
                    root = Path(lease.staging) / "endpoint-root"
                    connector.guests[cid] = LocalEndpoint("box", root)
                else:
                    connector.guests[cid] = FakeGuest("web")
            name = "box" if mode == "self-check" else "web"
            relays = applier._relays  # pyright: ignore[reportPrivateUsage] - test fixture wiring
            if lease.lease_id not in relays:
                relays[lease.lease_id] = {name: cid}
        await asyncio.sleep(0.025)


async def serve_fixture(socket_path: Path, state_dir: Path, mode: str) -> None:
    store = LeaseStore(state_dir)
    connector = FakeGuestConnector()
    applier = Applier(
        socket_path,
        state_dir,
        image_cache=state_dir / "image-cache",
        up_fn=fake_up,
        down_fn=fake_down,
        guest_connector=connector,
        capacity=HostCapacity(cpus=1024, memory_mb=1 << 22),
        gate=lambda: [],
    )
    await applier.start()
    registrar = asyncio.create_task(
        register_relays_forever(applier, store, connector, mode)
    )
    try:
        await asyncio.Event().wait()
    finally:
        registrar.cancel()
        await applier.aclose()


def wait_for_socket(socket_path: Path, timeout_s: float = 15.0) -> None:
    """Block until the fixture's socket exists (the subprocess has started serving)."""
    deadline = time.monotonic() + timeout_s
    while not socket_path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"applier fixture socket {socket_path} never appeared")
        time.sleep(0.02)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("conformance", "self-check"), required=True)
    arguments = parser.parse_args()
    asyncio.run(serve_fixture(arguments.socket, arguments.state_dir, arguments.mode))
