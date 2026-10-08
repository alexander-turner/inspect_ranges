"""Slice 4 battery: the real vsock transport against the Go v3 daemon.

Environment-gated: these tests run only when `IR_VSOCK_BATTERY_CID` points at a booted battery guest (see `design/spikes/channel-v1/run.sh`, which builds the daemon-baked golden, boots it in the range container at a chan-band CID, and drives this file). CI without a guest skips.

Coverage per channel-v1 slice 4: the PORTABLE conformance suite over the real transport, dropped-reply retry without double-run (raw socket fault injection), results re-readable until acked, and the 500+ operation soak with zero flake tolerance. The hostile-daemon shim and self_check run from the harness scripts beside this file.
"""

import asyncio
import os
import uuid

import pytest
from inspect_ranges._channel.channel import (
    GuestError,
    MessageChannel,
    request_id,
)
from inspect_ranges._channel.codec import MessageStreamReader, encode_message
from inspect_ranges._channel.protocol import (
    AckRequest,
    ExecRequest,
    ExecResult,
    Message,
    PendingReply,
    PollRequest,
)
from inspect_ranges._channel.vsock import VsockTransport

from tests.channel_conformance import PortableChannelSuite

CID = int(os.environ.get("IR_VSOCK_BATTERY_CID", "0"))
PORT = int(os.environ.get("IR_VSOCK_BATTERY_PORT", "5000"))

pytestmark = pytest.mark.skipif(
    CID == 0,
    reason="no battery guest (set IR_VSOCK_BATTERY_CID; see design/spikes/channel-v1)",
)


def transport() -> VsockTransport:
    return VsockTransport({"guest": CID}, port=PORT)


class TestVsockPortable(PortableChannelSuite):
    """The portable conformance suite over AF_VSOCK against the Go daemon."""

    guest = "guest"
    has_host_plane = False  # the applier belongs to the realizer, not the daemon
    probe_user = "root"  # the battery golden has no postgres user

    @pytest.fixture
    def channel(self) -> MessageChannel:
        return MessageChannel(transport(), label="vsock")

    # the fixture-contract vocabulary, mapped to a real Linux guest
    def argv_stderr(self, text: str) -> tuple[list[str], int]:
        return ["sh", "-c", f"printf '%s\\n' '{text}' >&2; exit 2"], 2

    def argv_sleep_ms(self, ms: int) -> list[str]:
        return ["sh", "-c", f"sleep {ms / 1000}"]

    def argv_env_probe(self) -> list[str]:
        return [
            "sh",
            "-c",
            'printf "cwd=%s\\nuser=%s\\nANSWER=%s\\n" "$(pwd)" "$(id -un)" "$ANSWER"',
        ]


async def _raw_exchange(
    frames: list[bytes], *, read_reply: bool
) -> tuple[Message, bytes | None] | None:
    """One raw round trip outside MessageChannel, for fault injection."""
    stream = await transport().connect("guest")
    try:
        for frame in frames:
            await stream.send(frame)
        if not read_reply:
            return None  # drop the connection before the reply (the lost-reply fault)
        reader = MessageStreamReader(stream.receive, bulk_cap=64 * 1024 * 1024)
        return await reader.next()
    finally:
        await stream.aclose()


def test_dropped_reply_retry_never_double_runs() -> None:
    """The daemon dedupes on id: a resent exec after a dropped reply runs the command once."""
    marker = f"/tmp/dedupe-{uuid.uuid4().hex}"
    rid = request_id()
    request = ExecRequest(id=rid, cmd=["sh", "-c", f"echo ran >> {marker}"])

    async def scenario() -> bytes:
        frames = encode_message(request)
        await _raw_exchange(frames, read_reply=False)  # reply dropped in flight
        await asyncio.sleep(0.3)  # let the first run complete guest-side
        channel = MessageChannel(transport(), label="dedupe")
        outcome = await channel.exec("guest", request)
        assert outcome.rc == 0
        return await channel.read_file("guest", marker)

    content = asyncio.run(scenario())
    assert content == b"ran\n", f"command ran {content.count(b'ran')} times"


def test_results_rereadable_until_acked() -> None:
    """A completed result replays on poll until acknowledged, then is gone."""
    rid = request_id()
    request = ExecRequest(id=rid, cmd=["echo", "durable"])

    async def scenario() -> None:
        first = await _raw_exchange(encode_message(request), read_reply=True)
        assert first is not None
        reply, bulk = first
        assert isinstance(reply, ExecResult) and bulk == b"durable\n"

        # not acked: poll must replay the identical result
        poll = PollRequest(id=request_id(), target_id=rid)
        replayed = await _raw_exchange(encode_message(poll), read_reply=True)
        assert replayed is not None
        replay_reply, replay_bulk = replayed
        assert isinstance(replay_reply, ExecResult) and replay_reply.id == rid
        assert replay_bulk == b"durable\n"

        # ack, then the stored result is gone
        ack = AckRequest(id=request_id(), target_id=rid)
        acked = await _raw_exchange(encode_message(ack), read_reply=True)
        assert acked is not None and acked[0].kind == "ok"
        gone = await _raw_exchange(
            encode_message(PollRequest(id=request_id(), target_id=rid)),
            read_reply=True,
        )
        assert gone is not None and gone[0].kind == "error"

    asyncio.run(scenario())


def test_pending_liveness_for_running_command() -> None:
    """A poll during a long command answers pending with elapsed time."""

    async def scenario() -> None:
        rid = request_id()
        slow = ExecRequest(id=rid, cmd=["sh", "-c", "sleep 1.5"])
        send_task = asyncio.create_task(
            _raw_exchange(encode_message(slow), read_reply=True)
        )
        await asyncio.sleep(0.4)
        polled = await _raw_exchange(
            encode_message(PollRequest(id=request_id(), target_id=rid)),
            read_reply=True,
        )
        assert polled is not None
        pending = polled[0]
        assert isinstance(pending, PendingReply) and pending.target_id == rid
        assert pending.elapsed_ms >= 200
        result = await send_task
        assert result is not None and isinstance(result[0], ExecResult)
        await _raw_exchange(
            encode_message(AckRequest(id=request_id(), target_id=rid)),
            read_reply=True,
        )

    asyncio.run(scenario())


def test_errno_for_unreadable_root_file() -> None:
    """Reading a missing path under a protected dir maps to a real errno, not a crash."""
    channel = MessageChannel(transport(), label="errno")

    async def scenario() -> None:
        with pytest.raises(GuestError) as failure:
            await channel.read_file("guest", "/proc/1/fdinfo/999999")
        assert failure.value.errno in ("ENOENT", "EACCES")

    asyncio.run(scenario())


def test_soak_500_operations_zero_flake() -> None:
    """Soak at the vsockd-win scale: 520 mixed operations, zero tolerance for flake."""
    channel = MessageChannel(transport(), label="soak")
    failures: list[str] = []

    async def one(i: int) -> None:
        try:
            if i % 4 == 0:
                outcome = await channel.exec(
                    "guest", ExecRequest(id=request_id(), cmd=["echo", f"soak-{i}"])
                )
                assert outcome.rc == 0 and outcome.stdout == f"soak-{i}\n".encode()
            elif i % 4 == 1:
                payload = bytes(
                    (i + j) % 251 for j in range(8192 if i % 50 else 200_000)
                )
                await channel.write_file("guest", f"/tmp/soak-{i % 7}", payload)
                assert await channel.read_file("guest", f"/tmp/soak-{i % 7}") == payload
            elif i % 4 == 2:
                pong = await channel.ping("guest")
                assert pong.protocol == 3
            else:
                outcome = await channel.exec(
                    "guest", ExecRequest(id=request_id(), cmd=["true"])
                )
                assert outcome.rc == 0
        except Exception as error:  # noqa: BLE001 - the soak reports, the assert fails
            failures.append(f"op {i}: {type(error).__name__}: {error}")

    async def scenario() -> None:
        # sequential half (pacing-friendly), then concurrent batches
        for i in range(260):
            await one(i)
        for batch in range(26):
            await asyncio.gather(*(one(260 + batch * 10 + k) for k in range(10)))

    asyncio.run(scenario())
    assert not failures, f"{len(failures)} flakes in 520 ops: {failures[:5]}"
