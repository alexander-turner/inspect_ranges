"""Slice 6 battery: the portable conformance suite and durability pins against the Windows v3 daemon.

Environment-gated by `IR_VSOCK_WIN_CID` (set by `design/spikes/channel-v1/windows/run-win.sh` after it boots the battery guest). The guest is the test image: busybox-w32 applets on PATH, `rangeuser` planted for `user=`, the temp and `/etc` fixtures staged, so the portable vocabulary maps onto busybox `sh`.
"""

import asyncio
import os
import uuid

import pytest
from inspect_ranges._channel.channel import (
    MessageChannel,
    TransportFailure,
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
    WriteFileRequest,
)
from inspect_ranges._channel.vsock import VsockTransport

from tests.channel_conformance import PortableChannelSuite

CID = int(os.environ.get("IR_VSOCK_WIN_CID", "0"))
PORT = int(os.environ.get("IR_VSOCK_WIN_PORT", "5000"))

pytestmark = pytest.mark.skipif(
    CID == 0,
    reason="no Windows battery guest (set IR_VSOCK_WIN_CID; see design/spikes/channel-v1/windows)",
)


def transport() -> VsockTransport:
    return VsockTransport({"guest": CID}, port=PORT)


class TestVsockWindowsPortable(PortableChannelSuite):
    """The portable suite over AF_VSOCK against the Windows C# daemon (busybox vocabulary)."""

    guest = "guest"
    has_host_plane = False
    probe_cwd = "C:/tmp"
    probe_user = "rangeuser"
    missing_path = "C:/no/such/file"
    directory_path = "C:/Windows"
    scratch_path = "C:/tmp/conformance-blob"

    @pytest.fixture
    def channel(self) -> MessageChannel:
        return MessageChannel(transport(), label="vsock-win")

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
    stream = await transport().connect("guest")
    try:
        for frame in frames:
            await stream.send(frame)
        if not read_reply:
            return None
        reader = MessageStreamReader(stream.receive, bulk_cap=64 * 1024 * 1024)
        return await reader.next()
    finally:
        await stream.aclose()


def test_dropped_reply_retry_never_double_runs() -> None:
    marker = f"C:/tmp/dedupe-{uuid.uuid4().hex}"
    rid = request_id()
    request = ExecRequest(id=rid, cmd=["sh", "-c", f"echo ran >> {marker}"])

    async def scenario() -> bytes:
        await _raw_exchange(encode_message(request), read_reply=False)
        await asyncio.sleep(1.0)  # Windows process creation is slower
        channel = MessageChannel(transport(), label="dedupe-win")
        outcome = await channel.exec("guest", request)
        assert outcome.rc == 0
        return await channel.read_file("guest", marker)

    content = asyncio.run(scenario())
    assert content.replace(b"\r", b"") == b"ran\n", f"command ran twice: {content!r}"


def test_results_rereadable_until_acked() -> None:
    rid = request_id()
    request = ExecRequest(id=rid, cmd=["echo", "durable"])

    async def scenario() -> None:
        first = await _raw_exchange(encode_message(request), read_reply=True)
        assert first is not None and isinstance(first[0], ExecResult)
        poll = PollRequest(id=request_id(), target_id=rid)
        replayed = await _raw_exchange(encode_message(poll), read_reply=True)
        assert replayed is not None
        assert isinstance(replayed[0], ExecResult) and replayed[0].id == rid
        acked = await _raw_exchange(
            encode_message(AckRequest(id=request_id(), target_id=rid)), read_reply=True
        )
        assert acked is not None and acked[0].kind == "ok"
        gone = await _raw_exchange(
            encode_message(PollRequest(id=request_id(), target_id=rid)), read_reply=True
        )
        assert gone is not None and gone[0].kind == "error"

    asyncio.run(scenario())


def test_pending_liveness_for_running_command() -> None:
    async def scenario() -> None:
        rid = request_id()
        slow = ExecRequest(id=rid, cmd=["sh", "-c", "sleep 2"])
        send_task = asyncio.create_task(
            _raw_exchange(encode_message(slow), read_reply=True)
        )
        await asyncio.sleep(0.8)
        polled = await _raw_exchange(
            encode_message(PollRequest(id=request_id(), target_id=rid)),
            read_reply=True,
        )
        assert polled is not None
        pending = polled[0]
        assert isinstance(pending, PendingReply) and pending.target_id == rid
        result = await send_task
        assert result is not None and isinstance(result[0], ExecResult)
        await _raw_exchange(
            encode_message(AckRequest(id=request_id(), target_id=rid)), read_reply=True
        )

    asyncio.run(scenario())


def test_estale_after_eviction_never_reruns() -> None:
    """The at-most-once tombstone, proven against the real C# daemon."""
    marker = f"C:/tmp/estale-{uuid.uuid4().hex}"
    rid = request_id()
    request = ExecRequest(id=rid, cmd=["sh", "-c", f"echo ran >> {marker}"])

    async def scenario() -> None:
        await _raw_exchange(
            encode_message(request), read_reply=True
        )  # executed, unacked
        # evict: 300 unacked durable writes
        for index in range(300):
            write = encode_message(
                WriteFileRequest(
                    id=request_id(), path=f"C:/tmp/flood-{index % 3}", data_size=1
                ),
                b"x",
            )
            await _raw_exchange(write, read_reply=True)
        channel = MessageChannel(transport(), label="estale-win")
        with pytest.raises(TransportFailure, match="result lost"):
            await channel.exec("guest", request)
        content = await channel.read_file("guest", marker)
        assert content.replace(b"\r", b"").count(b"ran") == 1, (
            "tombstone failed: re-ran"
        )

    asyncio.run(scenario())


def test_soak_500_operations_zero_flake() -> None:
    """The vsockd-win-scale soak over v3: 520 mixed ops, zero tolerance."""
    channel = MessageChannel(transport(), label="soak-win")
    failures: list[str] = []

    async def one(i: int) -> None:
        try:
            if i % 4 == 0:
                outcome = await channel.exec(
                    "guest", ExecRequest(id=request_id(), cmd=["echo", f"soak-{i}"])
                )
                assert outcome.rc == 0
                assert outcome.stdout.replace(b"\r", b"") == f"soak-{i}\n".encode()
            elif i % 4 == 1:
                payload = bytes(
                    (i + j) % 251 for j in range(8192 if i % 50 else 200_000)
                )
                await channel.write_file("guest", f"C:/tmp/soak-{i % 7}", payload)
                assert (
                    await channel.read_file("guest", f"C:/tmp/soak-{i % 7}") == payload
                )
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
        for i in range(260):
            await one(i)
        for batch in range(26):
            await asyncio.gather(*(one(260 + batch * 10 + k) for k in range(10)))

    asyncio.run(scenario())
    assert not failures, f"{len(failures)} flakes in 520 ops: {failures[:5]}"
