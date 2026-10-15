#!/usr/bin/env python3
"""evidence-v1 slice-3 battery: the off-instance leg against real S3.

Run via ./run.sh (flock, golden staging, env knobs). Boots the slice-2 range with capture on, streams the evidence to the designated scratch bucket through `S3Sink` (reached via the real `derive_evidence_location` -> `sink_for_location` path), measures watermark lag per delivered chunk, exercises an uplink outage and a bad-credential writer, seals, and verifies the record from a scrubbed-environment subprocess with and without the `--expect-seal` binding. Put-only is proven at the client layer (botocore event audit: every S3 operation issued is PutObject); the IAM limitations that forced that fallback are recorded in the README.
"""

# boto3/botocore are untyped-by-nature (the _devbox rationale, applied per-file)
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

import asyncio
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SPIKE = Path(__file__).resolve().parent
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from inspect_ranges._channel.channel import MessageChannel, request_id  # noqa: E402
from inspect_ranges._channel.protocol import Budget, ExecRequest  # noqa: E402
from inspect_ranges._channel.vsock import VsockTransport  # noqa: E402
from inspect_ranges._compiler import PlanOptions, render_bundle  # noqa: E402
from inspect_ranges._evidence import (  # noqa: E402
    CaptureStreamer,
    ComposeTap,
    EvidenceWriter,
    S3Store,
    SealDeliveryError,
    StageRecorder,
    derive_evidence_location,
    seal_digest,
    sink_for_location,
    verify_location,
)
from inspect_ranges._evidence.s3 import S3Sink  # noqa: E402
from inspect_ranges._runtime.down import down  # noqa: E402
from inspect_ranges._runtime.up import UpOptions, up  # noqa: E402
from inspect_ranges.schema import load_range  # noqa: E402

import json  # noqa: E402

SPEC = SPIKE.parent / "evidence-v1" / "spec.yaml"
TMP = SPIKE / "tmp"
BUNDLE = TMP / "bundle"
IMAGE_CACHE = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])
BUCKET = "caisi-cyber-590183887456-us-east-1-an"
RUN_PREFIX = f"inspect-ranges/spikes/evidence-v1-s3/runs/{int(time.time())}"

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


def skip(name: str, why: str) -> None:
    print(f"SKIP  {name} ({why})", flush=True)


class AuditedLagMeteredSink:
    """Real `S3Sink` plus three battery instruments: a botocore event audit (which S3 operations were issued), a per-chunk landed-time record for watermark lag, and an outage toggle that fails puts while 'down'."""

    def __init__(self, inner: S3Sink) -> None:
        self.inner = inner
        self.operations: set[str] = set()
        self.landed: dict[str, float] = {}
        self.down = False
        self.outage_failures = 0
        client = inner._s3()  # instrument the REAL client, before first use
        client.meta.events.register(
            "provide-client-params.s3.*", self._record_operation
        )

    def _record_operation(self, event_name: str = "", **_: Any) -> None:
        self.operations.add(event_name.split(".")[-1])

    async def put(self, key: str, data: bytes) -> None:
        if self.down:
            self.outage_failures += 1
            raise ConnectionError("battery outage window")
        await self.inner.put(key, data)
        self.landed[key] = time.time()


class Guests:
    def __init__(self, bundle: Path) -> None:
        boot = json.loads((bundle / "boot.json").read_text())
        self.cids = {g["name"]: int(g["cid"]) for g in boot["guests"]}

    async def exec(self, guest: str, command: str, timeout_ms: int = 30_000) -> int:
        channel = MessageChannel(
            VsockTransport(self.cids), label="ev1s3-battery", channel_budget_s=10.0
        )
        outcome = await channel.exec(
            guest,
            ExecRequest(
                id=request_id(),
                cmd=["sh", "-c", command],
                budget=Budget(command_ms=timeout_ms),
            ),
        )
        return outcome.rc


async def wait_for(predicate: Any, name: str, timeout: float = 90.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if await predicate():
                return check(True, name)
        except Exception:
            pass
        await asyncio.sleep(1.0)
    return check(False, name)


def scrubbed_verify(location: str, *expect_seal: str) -> int:
    """Run `inspect-ranges evidence verify` in a subprocess with a scrubbed environment (fresh HOME, no repo state, credentials only via the instance role). The honest substitution for a second machine; see the README."""
    scrub_home = TMP / "scrub-home"
    scrub_home.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(scrub_home),
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    argv = [str(ROOT / ".venv" / "bin" / "inspect-ranges"), "evidence", "verify"]
    for item in expect_seal:
        argv += ["--expect-seal", item]
    argv.append(location)
    result = subprocess.run(argv, env=env, capture_output=True, text=True)
    print(result.stdout.strip(), flush=True)
    if result.stderr.strip():
        print(result.stderr.strip(), flush=True)
    return result.returncode


async def main() -> int:
    print("=== render + up (capture on, CID 30200) ===", flush=True)
    spec = load_range(SPEC)
    render_bundle(
        spec,
        BUNDLE,
        PlanOptions(image_cache=IMAGE_CACHE, cid_base=30200, evidence_capture=True),
    )
    recorder = StageRecorder()
    result = await asyncio.to_thread(
        up, BUNDLE, UpOptions(image_cache=IMAGE_CACHE), on_stage=recorder.on_stage
    )
    project = result.project
    check(all(g.ready for g in result.guests), f"range up: {project}")
    guests = Guests(BUNDLE)

    # the real derivation path: an S3 "eval log" location yields the evidence
    # prefix, and the factory dispatches to the S3 sink
    log_location = f"s3://{BUCKET}/{RUN_PREFIX}/logs/battery.eval"
    location = derive_evidence_location(
        log_location, sample_id="s3-battery", epoch=1, attempt=1
    )
    check(
        location.startswith(f"s3://{BUCKET}/{RUN_PREFIX}/")
        and location.endswith("battery.evidence/s3-battery_1_1"),
        f"location derived beside the log: {location}",
    )
    base_sink = sink_for_location(location)
    check(isinstance(base_sink, S3Sink), "factory dispatched s3:// to S3Sink")
    assert isinstance(base_sink, S3Sink)
    sink = AuditedLagMeteredSink(base_sink)
    writer = EvidenceWriter(sink, writer="host", sample_id="s3-battery")
    store = S3Store(location)
    streamer = CaptureStreamer(
        writer,
        tap=ComposeTap(project, BUNDLE),
        segments=["dmz", "internal"],
        console_guests=["attacker", "web", "db", "router"],
        stage_recorder=recorder,
        poll_s=0.5,
        heartbeat_s=2.0,
    )

    code = 1
    project_name = project
    try:
        await streamer.start()

        print("=== evidence lands off-instance as generated ===", flush=True)
        await wait_for(
            lambda: _any_chunks(store),
            "first chunks on S3 while the range is live (streamed, not end-dumped)",
        )

        print("=== flows ===", flush=True)
        rc = await guests.exec("attacker", "ping -c 4 -i 0.3 10.94.20.10")
        check(rc == 0, "cross-segment ping attacker->db")
        burst = (
            "python3 - <<'EOF'\n"
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "p = b'x' * 1400\n"
            "for i in range(1500):\n"
            "    s.sendto(p, ('10.94.20.10', 9999))\n"
            "EOF"
        )
        check(
            await guests.exec("attacker", burst, timeout_ms=60_000) == 0,
            "udp burst (rotates 1 MB chunks)",
        )

        print("=== uplink outage mid-sample ===", flush=True)
        sink.down = True
        await guests.exec("attacker", "echo outage-window-marker > /dev/console")
        await asyncio.sleep(8.0)
        sink.down = False
        check(
            sink.outage_failures > 0,
            f"outage exercised ({sink.outage_failures} failed put attempts; "
            "the writer buffers the affected chunks for the next flush)",
        )
        await asyncio.sleep(6.0)  # recovery flushes the buffer

        print("=== stop + seal ===", flush=True)
        await streamer.stop()
        seal, digest = await writer.seal()
        check(seal.status == "complete", f"sealed complete (digest {digest[:16]}...)")
        report = await verify_location(store, location=location)
        host_report = report.writers.get("host")
        check(report.ok, "offline verify over S3: no break (chain unbroken across the outage)")
        check(
            bool(host_report and host_report.sealed),
            "host writer sealed on S3",
        )

        print("=== put-only client audit (the SINK's client only) ===", flush=True)
        # scope stated precisely: the hook instruments the sink's client, so
        # this proves the writer-side client issued only PutObject; the
        # battery's own reads (S3Store polling, verify) use a separate
        # client this hook never sees
        check(
            sink.operations == {"PutObject"},
            f"sink's client issued only PutObject (observed: {sorted(sink.operations)})",
        )

        print("=== store-level write-once (real 412) ===", flush=True)
        try:
            await base_sink.put("manifests/host/seal.json", b"forged")
            check(False, "re-put of the sealed manifest refused by the store")
        except FileExistsError:
            check(True, "re-put of the sealed manifest refused by the store (412)")

        print("=== scrubbed-process verify (second-machine substitution) ===", flush=True)
        check(
            scrubbed_verify(location) == 0,
            "verify from scrubbed process: internal consistency OK",
        )
        check(
            scrubbed_verify(location, f"host={digest}") == 0,
            "verify with the correct --expect-seal binding: OK",
        )
        check(
            scrubbed_verify(location, "host=" + "0" * 64) == 1,
            "verify with a wrong binding: FAILS (seal-digest-mismatch)",
        )

        print("=== credential expiry: loud, honest, never raises mid-stream ===", flush=True)
        import boto3

        bogus = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="AKIAEXPIRED0000000",
            aws_secret_access_key="expired",
        )
        bad_sink = S3Sink(location + "-badcreds", client=bogus)
        bad_writer = EvidenceWriter(bad_sink, writer="host", retry_wait_s=0.0)
        await bad_writer.append("stages", b"x")
        flush = await bad_writer.flush()
        check(
            bool(flush.errors) and flush.pending_chunks == 1,
            "bad credentials: errors reported and buffered, nothing raised",
        )
        try:
            await bad_writer.seal()
            check(False, "seal with undeliverable parts refuses")
        except SealDeliveryError:
            check(True, "seal with undeliverable parts refuses (record stays honestly unsealed)")

        print("=== deny-overwrite bucket policy ===", flush=True)
        skip(
            "bucket policy requiring s3:if-none-match on every put",
            "PutBucketPolicy denied by IAM on the shared scratch bucket; "
            "the policy JSON is in the README and the mechanism it enforces "
            "(conditional-put 412) is store-proven above",
        )

        # per-chunk watermark lag, computed offline: landed wall minus span end
        lag_report = await _lag_report(store, sink.landed)
        if lag_report:
            median = statistics.median(lag_report)
            worst = max(lag_report)
            print(
                f"watermark lag over {len(lag_report)} chunks: "
                f"median {median:.1f}s, worst {worst:.1f}s",
                flush=True,
            )
            check(median < 30.0, f"median watermark lag under 30s ({median:.1f}s)")
        else:
            check(False, "no chunk lag measurements collected")

        code = 0 if FAIL == 0 else 1
    finally:
        print("=== down ===", flush=True)
        await asyncio.to_thread(down, project_name)
    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return code


async def _any_chunks(store: S3Store) -> bool:
    return bool(await store.list("chunks"))


async def _lag_report(store: S3Store, landed: dict[str, float]) -> list[float]:
    """Per-chunk lag: landed wall time minus the chunk's capture span end, replayed from the delivered manifest."""
    from inspect_ranges._evidence.manifest import ChunkRecord, ManifestPart, chunk_key

    lags: list[float] = []
    for key in await store.list("manifests/host"):
        if not key.split("/")[-1].startswith("part-"):
            continue
        part = ManifestPart.model_validate_json(await store.get(key))
        for record in part.records:
            if isinstance(record, ChunkRecord):
                object_key = chunk_key("host", record.stream, record.seq)
                when = landed.get(object_key)
                if when is not None:
                    lags.append(when - record.span.end.wall)
    return lags


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
