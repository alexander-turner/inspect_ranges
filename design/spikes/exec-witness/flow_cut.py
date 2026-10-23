"""execve-witness-v1 live flow cut (review round 2): a real command on a real guest lands in a SEALED `exec/<guest>` stream that `verify_location` replays.

Runs after the storm battery in `run.sh` against the same booted guest: a fresh daemon-side cursor would carry the storm's events, so the cut polls from the current head, runs a marker command through the ordinary exec verb, drains, seals, and verifies. Exercises the real `ExecWitnessPoller` against the real daemon (the provider glue above it is pinned by unit and lifecycle tests).
"""

import asyncio
import os
import tempfile
from pathlib import Path

from inspect_ranges._channel.channel import MessageChannel, request_id
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport
from inspect_ranges._evidence.execwitness import ExecWitnessPoller, exec_event_lines
from inspect_ranges._evidence.reader import (
    LocalDirStore,
    stream_chunks,
    verify_location,
)
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink

CID = int(os.environ["IR_EXEC_WITNESS_CID"])
GUEST = "guest"
MARKER = "witness-flow-cut-$((40+2))"


async def main() -> None:
    channel = MessageChannel(VsockTransport({GUEST: CID}))
    with tempfile.TemporaryDirectory() as tmp:
        location = Path(tmp)
        writer = EvidenceWriter(
            LocalDirSink(location),
            part_interval_s=0,
            writer="driver",
            sample_id="flow-cut",
        )
        # start from the daemon's TRUE head so the storm's backlog stays out:
        # a since_seq past everything packs nothing, and the packers report
        # the head (never clamped up) exactly for this kind of resync
        from inspect_ranges._channel.protocol import MAX_WIRE_INT

        head = (
            await channel.exec_events(GUEST, since_seq=MAX_WIRE_INT, max_events=1)
        ).next_seq
        poller = ExecWitnessPoller(channel, writer, [GUEST], [])
        poller._states[GUEST].cursor = head  # pyright: ignore[reportPrivateUsage]
        await poller.start()
        outcome = await channel.exec(
            GUEST,
            ExecRequest(
                id=request_id(),
                cmd=["sh", "-c", f"echo {MARKER}"],
                budget=Budget(command_ms=30_000),
            ),
        )
        assert outcome.rc == 0 and b"witness-flow-cut-42" in outcome.stdout
        await asyncio.sleep(4.0)  # two poll cycles
        await poller.stop()
        await writer.seal()

        store = LocalDirStore(location)
        report = await verify_location(store)
        assert report.ok, f"evidence verify failed: {report}"
        chunks = await stream_chunks(store, "driver", f"exec/{GUEST}")
        events = [line for chunk in chunks for line in exec_event_lines(chunk)]
        hits = [
            e
            for e in events
            if any("witness-flow-cut" in str(arg) for arg in e.get("argv", []))
        ]
        assert hits, f"marker exec not witnessed ({len(events)} events seen)"
        meta_chunks = await stream_chunks(store, "driver", f"exec-meta/{GUEST}")
        assert meta_chunks, "coverage records missing"
        print(
            f"PASS  flow cut: marker exec witnessed (pid {hits[0]['pid']}, "
            f"uid {hits[0]['uid']}) among {len(events)} sealed events; "
            "record verifies"
        )


if __name__ == "__main__":
    asyncio.run(main())
