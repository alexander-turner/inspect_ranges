#!/usr/bin/env python3
"""challenges-v1 slice-2 battery: oracle planting and the residue sweep on a real range.

Run via ./run_oracle.sh (golden staged, env knobs exported, shared battery flock held). Renders an evidence-enabled bundle at CID base 30600, boots it, opens a real EvidenceSession (which owns capture), plants a flag-shaped and an owner-bound value through `run_setup`, then sweeps: /proc cmdline+environ, files modified since a pre-plant marker, plant mode/owner, the plants evidence stream (digests only), and the live pcap (values never on the wire; vsock is not a network). The failure leg proves refusal-with-unwind on a dead plant target. Per-plant setup timings print for the measurement table.
"""

import asyncio
import base64
import json
import logging
import os
import sys
import time
from pathlib import Path

SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(SPIKE.parent.parent.parent / "src"))

from inspect_ranges._challenges.oracle import (  # noqa: E402
    OracleSetupError,
    RangeOracle,
)
from inspect_ranges._challenges.schema import Challenge  # noqa: E402
from inspect_ranges._challenges.setup import run_setup  # noqa: E402
from inspect_ranges._channel.channel import MessageChannel  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._compiler.plan import Totals  # noqa: E402
from inspect_ranges._evidence.reader import (  # noqa: E402
    LocalDirStore,
    stream_chunks,
    verify_location,
)
from inspect_ranges._provider.evidence import EvidenceSession  # noqa: E402
from inspect_ranges._provider.state import SampleHandle  # noqa: E402
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

TMP = SPIKE / "tmp"
BUNDLE = TMP / "bundle"
EVIDENCE = TMP / "evidence"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])

PASS = 0
FAIL = 0


def check(condition: bool, name: str) -> bool:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}", flush=True)
    return condition


async def sh(
    oracle: RangeOracle, guest: str, command: str, *, user: str | None = "root"
) -> tuple[int, bytes]:
    outcome = await oracle.exec(guest, ["sh", "-c", command], user=user, timeout_s=60.0)
    return outcome.rc, outcome.stdout


async def proc_dump(oracle: RangeOracle, guest: str) -> bytes:
    rc, out = await sh(
        oracle,
        guest,
        "cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | base64",
    )
    return base64.b64decode(out) if rc == 0 else b""


async def new_files(oracle: RangeOracle, guest: str, marker: str) -> list[str]:
    rc, out = await sh(
        oracle,
        guest,
        f"find / -xdev -type f -newer {marker} 2>/dev/null",
    )
    return [line for line in out.decode().splitlines() if line] if rc == 0 else []


async def main() -> int:
    # per-plant timings (the measure-first rows) come from the setup logger
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s %(message)s"
    )
    logging.getLogger("inspect_ranges.challenges").setLevel(logging.INFO)
    print("=== render + up (capture on, CID 30600) ===", flush=True)
    spec = load_range(SPIKE / "spec.yaml")
    plan = render_bundle(
        spec,
        BUNDLE,
        PlanOptions(image_cache=IMAGE_CACHE, cid_base=30600, evidence_capture=True),
    )
    session = EvidenceSession(
        str(EVIDENCE), sample_id="chv1-oracle", capture_local=True
    )
    result = await asyncio.to_thread(
        up,
        BUNDLE,
        UpOptions(image_cache=IMAGE_CACHE),
        on_stage=session.recorder.on_stage,
    )
    project = result.project
    check(
        all(g.ready for g in result.guests), f"range up: {project} ({result.seconds}s)"
    )

    boot = json.loads((BUNDLE / "boot.json").read_text())
    cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}
    channel = MessageChannel(
        VsockTransport(cids), label="chv1-oracle", channel_budget_s=10.0
    )
    await session.open(lease_id=None, project=project, bundle=BUNDLE, plan=plan)
    check(session.enabled, "evidence session open (owns capture)")

    handle = SampleHandle(
        project=project,
        task_name="chv1-oracle",
        staging=TMP / "staging",
        totals=Totals(guests=4, cpus=4, memory_mb=4096),
        cid_base=30600,
        guest_cids=cids,
        channel=channel,
        evidence=session,
        plan=plan,
    )
    oracle = RangeOracle(handle)
    store = LocalDirStore(EVIDENCE)
    code = 1
    try:
        check(
            oracle.available_observers()
            == frozenset({"evidence-sink", "segment-pcap", "console"}),
            "observers available: sink, pcap, console",
        )

        print("=== marker, cross-segment noise, plants ===", flush=True)
        await oracle.write_file("web", "/tmp/residue-marker", b"m", owner=None)
        await oracle.write_file("db", "/tmp/residue-marker", b"m", owner=None)
        await asyncio.sleep(1.1)  # mtime granularity for find -newer
        rc, _ = await sh(oracle, "attacker", "ping -c 3 -W 2 10.95.20.10")
        check(rc == 0, "cross-segment noise generated (capture has traffic)")

        challenge = Challenge.model_validate(
            {
                "id": "battery",
                "prompt": "p",
                "goals": [
                    {
                        "id": "crown",
                        "type": "flag",
                        "host": "web",
                        "path": "/root/crown-flag",
                    },
                    {
                        "id": "owned",
                        "type": "control",
                        "host": "db",
                        "principal": "daemon",
                        "secret_path": "/opt/owned-secret",
                    },
                ],
            }
        )
        started = time.monotonic()
        await run_setup(oracle, challenge)
        total = time.monotonic() - started
        check(True, f"plants landed via run_setup ({total:.2f}s for 2 plants)")
        flag_value = oracle.store.get("flag:crown")
        secret_value = oracle.store.get("control:owned")

        print("=== placement: mode and owner ===", flush=True)
        rc, out = await sh(oracle, "web", "stat -c '%a %U' /root/crown-flag")
        check(
            rc == 0 and out.split() == [b"600", b"root"],
            f"flag placement 600 root (got {out.decode().strip()!r})",
        )
        rc, out = await sh(oracle, "db", "stat -c '%a %U' /opt/owned-secret")
        check(
            rc == 0 and out.split() == [b"600", b"daemon"],
            f"secret placement 600 daemon (got {out.decode().strip()!r})",
        )
        readback = await oracle.read_file("web", "/root/crown-flag", user="root")
        check(readback == flag_value, "flag content matches the in-memory store")

        print("=== residue sweep: proc, disk, evidence, wire ===", flush=True)
        for guest in ("web", "db", "attacker", "router"):
            dump = await proc_dump(oracle, guest)
            check(
                len(dump) > 0 and flag_value not in dump and secret_value not in dump,
                f"proc sweep clean on {guest} ({len(dump)} bytes scanned)",
            )

        plant_paths = {"/root/crown-flag", "/opt/owned-secret"}
        for guest in ("web", "db"):
            listed = await new_files(oracle, guest, "/tmp/residue-marker")
            dirty: list[str] = []
            for path in listed:
                if path in plant_paths or path == "/tmp/residue-marker":
                    continue
                try:
                    content = await oracle.read_file(guest, path, user="root")
                except OracleSetupError:
                    continue  # vanished or special; a plant value cannot hide in ENOENT
                if flag_value in content or secret_value in content:
                    dirty.append(path)
            check(
                not dirty,
                f"disk sweep clean on {guest} ({len(listed)} new files; dirty={dirty})",
            )

        plants_raw = b"".join(await stream_chunks(store, "driver", "plants"))
        records = [
            json.loads(line) for line in plants_raw.decode().splitlines() if line
        ]
        planted = [r for r in records if r["event"] == "planted"]
        check(
            [r["key"] for r in planted] == ["flag:crown", "control:owned"]
            and all(r["sha256"] == oracle.store.digest(r["key"]) for r in planted),
            "plants stream carries both digests in order",
        )
        check(
            flag_value not in plants_raw and secret_value not in plants_raw,
            "plants stream carries no plant values",
        )

        print("=== failure leg: refusal with unwind ===", flush=True)
        doomed = Challenge.model_validate(
            {
                "id": "doomed",
                "prompt": "p",
                "goals": [
                    {"id": "pre", "type": "flag", "host": "web", "path": "/root/pre"},
                    {
                        "id": "dead",
                        "type": "flag",
                        "host": "nonexistent",
                        "path": "/root/x",
                    },
                ],
            }
        )
        refused = False
        started = time.monotonic()
        try:
            await run_setup(oracle, doomed)
        except RuntimeError as error:
            refused = "setup failed at goal 'dead'" in str(error)
        check(refused, f"dead target refused ({time.monotonic() - started:.1f}s)")
        gone = False
        try:
            # root read: EACCES-as-agent would be vacuous; only ENOENT counts
            await oracle.read_file("web", "/root/pre", user="root")
        except OracleSetupError:
            gone = True
        check(gone, "prior plant unwound from the guest")
        check("flag:pre" not in oracle.store.keys(), "prior plant discarded from store")

        print("=== finalize, wire cleanliness, verify ===", flush=True)
        await session.finalize()
        pcap = b""
        for segment in ("dmz", "internal"):
            pcap += b"".join(await stream_chunks(store, "host", f"pcap/{segment}"))
        check(len(pcap) > 0, f"pcap captured ({len(pcap)} bytes across segments)")
        check(
            flag_value not in pcap and secret_value not in pcap,
            "wire clean: no plant bytes in any segment pcap",
        )
        report = await verify_location(store)
        check(report.ok, "evidence record verifies offline")
        code = 0 if FAIL == 0 else 1
    finally:
        await asyncio.to_thread(down, project)
        print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
