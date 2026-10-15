#!/usr/bin/env python3
"""evidence-v1 slice-4 battery: in-guest telemetry export against a real range.

Run via ./run_telemetry.sh. Boots the minimal telemetry range at CID base 30300, polls a journald collector and a file collector on the target over vsock while a real producer emits, then exercises the slice's claims live: a producer kill shows as a watermark stall with polling provably continuing, a paused VM shows as poll-failed gaps with recovery after resume, a truncated log shows as a watermark regression, and the sealed record verifies offline with completeness decidable from the record alone.
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(SPIKE.parent.parent.parent / "src"))

from inspect_ranges._channel.channel import MessageChannel, request_id  # noqa: E402
from inspect_ranges._channel.protocol import Budget, ExecRequest  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._evidence import (  # noqa: E402
    CollectorSpec,
    CommandSource,
    EvidenceWriter,
    FileSource,
    LocalDirSink,
    LocalDirStore,
    TelemetryPoller,
    verify_location,
)
from inspect_ranges._evidence.manifest import ManifestPart  # noqa: E402
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

TMP = SPIKE / "tmp-telemetry"
BUNDLE = TMP / "bundle"
EVIDENCE = TMP / "evidence"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])

LOG_PATH = "/var/log/tele.log"

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


class Guests:
    def __init__(self, bundle: Path) -> None:
        boot = json.loads((bundle / "boot.json").read_text())
        self.cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}

    def channel(self) -> MessageChannel:
        return MessageChannel(
            VsockTransport(self.cids), label="ev1-telemetry", channel_budget_s=10.0
        )

    async def exec(self, guest: str, command: str, timeout_ms: int = 30_000) -> int:
        outcome = await self.channel().exec(
            guest,
            ExecRequest(
                id=request_id(),
                cmd=["sh", "-c", command],
                user="root",
                budget=Budget(command_ms=timeout_ms),
            ),
        )
        return outcome.rc


def virsh(project: str, *args: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(BUNDLE),
            "exec",
            "-T",
            "range",
            "virsh",
            *args,
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout


async def wait_for(predicate: Any, name: str, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if await predicate():
                return check(True, name)
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return check(False, name)


async def meta_records(store: LocalDirStore, collector: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in sorted(await store.list(f"chunks/driver/telemetry-meta/{collector}")):
        for line in (await store.get(key)).decode().splitlines():
            records.append(json.loads(line))
    return records


async def data_bytes(store: LocalDirStore, collector: str) -> bytes:
    keys = sorted(await store.list(f"chunks/driver/telemetry/{collector}"))
    return b"".join([await store.get(key) for key in keys])


async def gap_causes(store: LocalDirStore, stream: str) -> list[str]:
    causes: list[str] = []
    for key in sorted(await store.list("manifests/driver")):
        if "part-" not in key:
            continue
        part = ManifestPart.model_validate_json(await store.get(key))
        causes.extend(
            r.cause for r in part.records if r.kind == "gap" and r.stream == stream
        )
    return causes


async def main() -> int:
    print("=== render + up (CID base 30300) ===", flush=True)
    spec = load_range(SPIKE / "spec-telemetry.yaml")
    render_bundle(spec, BUNDLE, PlanOptions(image_cache=IMAGE_CACHE, cid_base=30300))
    result = await asyncio.to_thread(up, BUNDLE, UpOptions(image_cache=IMAGE_CACHE))
    project = result.project
    check(
        all(g.ready for g in result.guests), f"range up: {project} ({result.seconds}s)"
    )
    guests = Guests(BUNDLE)

    writer = EvidenceWriter(
        LocalDirSink(EVIDENCE), writer="driver", sample_id="ev1-telemetry-battery"
    )
    store = LocalDirStore(EVIDENCE)
    collectors = [
        CollectorSpec(
            name="journal",
            guest="db",
            source=CommandSource(
                command=[
                    "journalctl",
                    "-t",
                    "evtest",
                    "--after-cursor={cursor}",
                    "--show-cursor",
                    "-q",
                    "-o",
                    "cat",
                ],
                bootstrap=[
                    "journalctl",
                    "-t",
                    "evtest",
                    "-n",
                    "50",
                    "--show-cursor",
                    "-q",
                    "-o",
                    "cat",
                ],
                cursor_pattern=r"-- cursor: (\S+)",
                user="root",
            ),
            poll_s=0.5,
        ),
        CollectorSpec(
            name="applog",
            guest="db",
            source=FileSource(path=LOG_PATH),
            poll_s=0.5,
        ),
    ]
    poller = TelemetryPoller(guests.channel(), writer, collectors)

    try:
        print("=== producers: file appender + journald events ===", flush=True)
        # setsid: the daemon reaps the exec's process group on return, so a
        # plain backgrounded loop dies with its exec; a new session survives
        rc = await guests.exec(
            "db",
            "setsid sh -c 'i=0; while :; do i=$((i+1)); "
            f'echo "file-line-$i" >> {LOG_PATH}; sleep 0.3; done\' '
            "</dev/null >/dev/null 2>&1 & echo ok",
        )
        check(rc == 0, "file producer started")
        for n in range(1, 4):
            await guests.exec("db", f"logger -t evtest journal-event-{n}")

        await poller.start()

        print("=== events flow, watermarks advance ===", flush=True)
        await wait_for(
            lambda: _advanced(store, "applog", 3),
            "file collector: watermark advanced across >=3 separate polls",
            timeout=45,
        )
        await wait_for(
            lambda: _journal_ok(store),
            "journal collector: events shipped, cursor watermark present",
            timeout=30,
        )

        print("=== producer kill: watermark stall, polls continue ===", flush=True)
        await guests.exec("db", f"pkill -f {LOG_PATH} || true")
        # content-based (delivery-lag immune): the record's own poll counters
        # prove >=4 polls ran after the last ok with every one of them quiet
        await wait_for(
            lambda: _stalled(store, "applog", 4),
            "stall: >=4 polls after the last ok, all quiet (coverage continued)",
            timeout=45,
        )

        print("=== outage: pause the VM, gap, resume, recover ===", flush=True)
        names = virsh(project, "list", "--name")
        domain = next(n for n in names.split() if "db" in n)
        virsh(project, "suspend", domain)
        await wait_for(
            lambda: _error_seen(store, "applog"),
            "outage: poll errors recorded in meta while the guest is paused",
            timeout=45,
        )
        virsh(project, "resume", domain)
        resume_mark = len(await meta_records(store, "applog"))
        await wait_for(
            lambda: _recovered(store, "applog", resume_mark),
            "recovery: polls succeed again after resume",
            timeout=60,
        )

        print("=== regression: truncate the log ===", flush=True)
        await guests.exec(
            "db", f": > {LOG_PATH} && echo fresh-after-truncate >> {LOG_PATH}"
        )
        await wait_for(
            lambda: _regressed(store),
            "regression: watermark-regression gap recorded, shipping resumed",
            timeout=30,
        )
    finally:
        await poller.stop()
        seal, digest = await writer.seal()
        print(f"sealed: status={seal.status} digest={digest}", flush=True)
        await asyncio.to_thread(down, project)

    print("=== offline verification, from the record alone ===", flush=True)
    report = await verify_location(store, expected_seals={"driver": digest})
    check(report.ok, "offline verify: chain unbroken, binding checked")
    check(seal.status == "complete", "seal status complete")
    journal_data = await data_bytes(store, "journal")
    check(b"journal-event-1" in journal_data, "journald events present in the record")
    check(b"file-line-1" in await data_bytes(store, "applog"), "file events present")
    applog_gaps = await gap_causes(store, "telemetry/applog")
    check(
        applog_gaps.count("poll-failed") == 1,
        f"outage recorded as exactly one poll-failed gap (saw {applog_gaps})",
    )
    check(
        "watermark-regression" in applog_gaps,
        "truncation recorded as a watermark-regression gap",
    )
    meta = await meta_records(store, "applog")
    outcomes = [m["outcome"] for m in meta]
    check("error" in outcomes, "meta: outage polls visible as errors")
    applog_chunks = len(await store.list("chunks/driver/telemetry/applog"))
    check(
        applog_chunks == outcomes.count("ok"),
        "every applog data chunk pairs with an ok poll (nothing shipped during the stall)",
    )
    check(
        all(isinstance(m["watermark"], int) for m in meta if m["outcome"] != "error"),
        "meta: every non-error poll carries its watermark",
    )

    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return 1 if FAIL else 0


async def _advanced(store: LocalDirStore, collector: str, count: int) -> bool:
    meta = await meta_records(store, collector)
    advanced = [m for m in meta if m.get("advanced")]
    return len(advanced) >= count and bool(await data_bytes(store, collector))


async def _journal_ok(store: LocalDirStore) -> bool:
    meta = await meta_records(store, "journal")
    return any(
        m.get("outcome") == "ok" and isinstance(m.get("watermark"), str) for m in meta
    )


async def _stalled(store: LocalDirStore, collector: str, count: int) -> bool:
    meta = await meta_records(store, collector)
    last_ok = max((i for i, m in enumerate(meta) if m["outcome"] == "ok"), default=None)
    if last_ok is None:
        return False
    tail = meta[last_ok + 1 :]
    return (
        len(tail) >= count
        and all(m["outcome"] == "quiet" for m in tail)
        and tail[-1]["poll"] - meta[last_ok]["poll"] >= count
    )


async def _error_seen(store: LocalDirStore, collector: str) -> bool:
    return any(m["outcome"] == "error" for m in await meta_records(store, collector))


async def _recovered(store: LocalDirStore, collector: str, mark: int) -> bool:
    meta = (await meta_records(store, collector))[mark:]
    return any(m["outcome"] in ("ok", "quiet") for m in meta)


async def _regressed(store: LocalDirStore) -> bool:
    gaps = await gap_causes(store, "telemetry/applog")
    if "watermark-regression" not in gaps:
        return False
    return b"fresh-after-truncate" in await data_bytes(store, "applog")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
