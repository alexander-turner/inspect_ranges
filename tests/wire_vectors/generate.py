"""Regenerate `v3.json`, the shared wire test vectors for protocol v3.

Run from the repo root: `uv run python tests/wire_vectors/generate.py`. The vectors pin the encoding byte-exactly; every codec implementation (Python, Go, C#) must encode each vector's message and bulk to exactly `frames_hex` and decode `frames_hex` back to the message and bulk. Regenerating this file is a protocol change and needs the matching review.

Encoding rules the vectors pin: canonical JSON is sorted-key, compact-separator, raw UTF-8 (this JSON file ASCII-escapes its own copies of the messages, but `frames_hex` carries the true UTF-8 wire bytes); null-valued optional fields are omitted on the wire AND an explicit null anywhere in a decoded payload is rejected (an honest encoder cannot produce one); `v` is always emitted and required on decode.
"""

import json
from pathlib import Path

from inspect_ranges._channel import codec
from inspect_ranges._channel import protocol as p


def _rid(n: int) -> str:
    return f"{n:032x}"


def _cases() -> list[tuple[str, p.Message, bytes | None]]:
    two_chunk = (bytes(range(256)) * 157)[:40000]
    return [
        ("ping", p.PingRequest(id=_rid(1)), None),
        ("pong", p.PongReply(id=_rid(1), daemon="vsockd 3.0.0"), None),
        (
            "exec-with-stdin",
            p.ExecRequest(
                id=_rid(2),
                cmd=["cat", "-"],
                env={"LANG": "C"},
                cwd="/tmp",
                user="root",
                data_size=3,
                budget=p.Budget(command_ms=5000),
            ),
            b"hi\n",
        ),
        (
            "exec-result-with-output",
            p.ExecResult(id=_rid(2), rc=0, stdout_size=3, stderr_size=4, data_size=7),
            b"hi\nerr\n",
        ),
        ("exec-unicode", p.ExecRequest(id=_rid(3), cmd=["echo", "snowman ☃"]), None),
        (
            "exec-with-liveness-allowance",
            p.ExecRequest(
                id=_rid(14),
                cmd=["long-task"],
                budget=p.Budget(command_ms=600000, channel_ms=2000),
            ),
            None,
        ),
        (
            "read-file",
            p.ReadFileRequest(id=_rid(4), path="/etc/hostname", max_bytes=65536),
            None,
        ),
        (
            "file-data-two-chunks",
            p.FileData(id=_rid(4), size=40000, data_size=40000),
            two_chunk,
        ),
        (
            "write-file-empty",
            p.WriteFileRequest(id=_rid(5), path="/tmp/empty", data_size=0),
            b"",
        ),
        ("ok", p.OkReply(id=_rid(5)), None),
        ("forward", p.ForwardRequest(id=_rid(6), host="10.0.0.5", port=443), None),
        ("forward-ok", p.ForwardReply(id=_rid(6), handle=_rid(16)), None),
        ("poll", p.PollRequest(id=_rid(7), target_id=_rid(2)), None),
        (
            "pending",
            p.PendingReply(id=_rid(7), target_id=_rid(2), elapsed_ms=1500),
            None,
        ),
        ("ack", p.AckRequest(id=_rid(8), target_id=_rid(2)), None),
        ("diag", p.DiagRequest(id=_rid(9), max_entries=50), None),
        (
            "diag-result",
            p.DiagReply(
                id=_rid(9),
                entries=[
                    p.DiagEntry(
                        ts_ms=12,
                        level="error",
                        event="listener-restarted",
                        request_id=None,
                        detail="accept loop died: WSAECONNRESET",
                    )
                ],
            ),
            None,
        ),
        (
            "error-budget-command",
            p.ErrorReply(
                id=_rid(2),
                errno="ETIME",
                message="command budget expired after 5000 ms",
                layer="command",
            ),
            None,
        ),
        (
            "exec-result-killed",
            p.ExecResult(id=_rid(13), rc=-9, stdout_size=0, stderr_size=0),
            None,
        ),
        (
            "error-enoent",
            p.ErrorReply(
                id=_rid(4), errno="ENOENT", message="No such file or directory"
            ),
            None,
        ),
        (
            "error-estale-result-lost",
            p.ErrorReply(
                id=_rid(15),
                errno="ESTALE",
                message="executed, result lost before acknowledgement",
            ),
            None,
        ),
        (
            "realize",
            p.RealizeRequest(
                id=_rid(10),
                bundle_digest="ab" * 32,
                grants=["s3://bucket/image.qcow2"],
            ),
            None,
        ),
        (
            "stage-report",
            p.StageReport(
                id=_rid(10),
                stage="boot",
                detail="",
                guests={"web": "booting", "router": "ready"},
            ),
            None,
        ),
        (
            "heartbeat",
            p.Heartbeat(id=_rid(11), uptime_ms=60000, guests={"web": "ready"}),
            None,
        ),
        ("teardown", p.TeardownRequest(id=_rid(12)), None),
    ]


def main() -> None:
    vectors: list[dict[str, object]] = []
    for name, message, bulk in _cases():
        frames = codec.encode_message(message, bulk)
        vectors.append(
            {
                "name": name,
                "message": message.model_dump(mode="json", exclude_none=True),
                "bulk_hex": bulk.hex() if bulk is not None else None,
                "frames_hex": [frame.hex() for frame in frames],
            }
        )
    doc = {
        "format": "inspect-ranges wire vectors",
        "protocol": 3,
        "daemon": {
            "kill_grace_ms": p.DAEMON_KILL_GRACE_MS,
            "wait_delay_ms": p.DAEMON_WAIT_DELAY_MS,
            "inbound_bulk_cap": p.DAEMON_INBOUND_BULK_CAP,
        },
        "note": "Every codec implementation (Python, Go, C#) must encode message+bulk to exactly frames_hex and decode frames_hex back to message+bulk. Control payloads are canonical JSON: sorted keys, separators ',' ':', raw UTF-8 (frames_hex carries the wire bytes; this file's message copies are ASCII-escaped), null optional fields omitted (explicit nulls rejected on decode), v required. rc convention: signed int32, killed-by-signal negative.",
        "vectors": vectors,
    }
    out = Path(__file__).parent / "v3.json"
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=True) + "\n")
    print(f"wrote {len(vectors)} vectors to {out}")


if __name__ == "__main__":
    main()
