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
        (
            "write-file-mode-600",
            p.WriteFileRequest(
                id=_rid(31), path="/tmp/secret.sh", mode=0o600, data_size=4
            ),
            b"blob",
        ),
        (
            "error-etime-partial",
            p.ErrorReply(
                id=_rid(32),
                errno="ETIME",
                message="command budget expired after 1000 ms",
                layer="command",
                partial="tail of the killed command's stdout",
            ),
            None,
        ),
        (
            "pong",
            p.PongReply(
                id=_rid(1),
                daemon="vsockd 3.1.0",
                session="ffffffffffffffffffffffffffffffff",
            ),
            None,
        ),
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


RID = "a" * 32


def _rejects() -> list[dict[str, str]]:
    """The SHARED rejection table: control payloads every codec must refuse.

    Every three-codec parity break found by review or probe gets a case here, never only a fix in one codec. Frame-level malformations (truncation, length lies) stay codec-local; this table is control-payload validation.
    """
    import json as j

    def d(**kw: object) -> str:
        return j.dumps(kw, ensure_ascii=False)

    base = {"v": 3, "id": RID}
    cases: list[tuple[str, str]] = [
        ("missing-v", d(id=RID, kind="ping")),
        ("v-wrong-int", d(v=2, id=RID, kind="ping")),
        ("v-float", d(v=3.0, id=RID, kind="ping")),
        ("v-string", d(v="3", id=RID, kind="ping")),
        ("explicit-null", d(**base, kind="exec", cmd=["true"], cwd=None)),
        ("duplicate-key", '{"v":3,"id":"' + RID + '","kind":"ping","kind":"ping"}'),
        ("unknown-kind", d(**base, kind="backdoor")),
        ("bad-request-id", d(v=3, id="Z" * 32, kind="ping")),
        ("unknown-field", d(**base, kind="ping", x=1)),
        ("cross-kind-field", d(**base, kind="ping", cmd=["x"])),
        ("bulk-on-bulkless", d(**base, kind="ok", data_size=4)),
        ("non-integer-number", d(**base, kind="heartbeat", uptime_ms=1.5)),
        (
            "lone-surrogate-escape",
            d(**base, kind="error", errno="EIO", message=chr(92) + "LONESURR").replace(
                chr(92) * 2 + "LONESURR", chr(92) + "ud800"
            ),
        ),
        (
            "bad-u-escape-0x",
            d(**base, kind="error", errno="EIO", message=chr(92) + "BADESC").replace(
                chr(92) * 2 + "BADESC", chr(92) + "u0x41"
            ),
        ),
        (
            "bad-u-escape-nonhex",
            d(**base, kind="error", errno="EIO", message=chr(92) + "BADESC").replace(
                chr(92) * 2 + "BADESC", chr(92) + "uzzzz"
            ),
        ),
        ("pending-missing-elapsed", d(**base, kind="pending", target_id=RID)),
        (
            "pending-elapsed-float",
            d(**base, kind="pending", target_id=RID, elapsed_ms=1.5),
        ),
        ("error-missing-message", d(**base, kind="error", errno="EIO")),
        ("stage-missing-stage", d(**base, kind="stage")),
        ("exec-empty-cmd", d(**base, kind="exec", cmd=[])),
        ("exec-cmd-nonstring", d(**base, kind="exec", cmd=["echo", 1])),
        ("exec-cwd-nonstring", d(**base, kind="exec", cmd=["true"], cwd=5)),
        ("exec-user-nonstring", d(**base, kind="exec", cmd=["true"], user=5)),
        (
            "exec-env-value-nonstring",
            d(**base, kind="exec", cmd=["true"], env={"X": 1}),
        ),
        ("write-missing-datasize", d(**base, kind="write_file", path="/f")),
        ("negative-data-size", d(**base, kind="write_file", path="/f", data_size=-1)),
        (
            "exec-result-size-mismatch",
            d(
                **base,
                kind="exec_result",
                rc=0,
                stdout_size=3,
                stderr_size=1,
                data_size=3,
            ),
        ),
        (
            "rc-outside-int32",
            d(**base, kind="exec_result", rc=2**31, stdout_size=0, stderr_size=0),
        ),
        (
            "exec-result-truncated-nonbool",
            d(
                **base,
                kind="exec_result",
                rc=0,
                stdout_size=0,
                stderr_size=0,
                stdout_truncated=1,
            ),
        ),
        ("file-data-size-mismatch", d(**base, kind="file_data", size=2, data_size=3)),
        (
            "file-data-truncated-nonbool",
            d(**base, kind="file_data", size=0, truncated="yes"),
        ),
        ("etime-without-layer", d(**base, kind="error", errno="ETIME", message="x")),
        ("bad-errno-shape", d(**base, kind="error", errno="enoent", message="x")),
        (
            "layer-bad-literal",
            d(**base, kind="error", errno="EIO", message="x", layer="cosmic"),
        ),
        ("message-overlong", d(**base, kind="error", errno="EIO", message="x" * 5000)),
        ("negative-max-entries", d(**base, kind="diag", max_entries=-1)),
        ("diag-entries-nonlist", d(**base, kind="diag_result", entries={})),
        ("diag-entry-nonobject", d(**base, kind="diag_result", entries=[1])),
        (
            "diag-entry-bad-level",
            d(
                **base,
                kind="diag_result",
                entries=[{"ts_ms": 1, "level": "fatal", "event": "x", "detail": ""}],
            ),
        ),
        (
            "diag-entry-extra-member",
            d(
                **base,
                kind="diag_result",
                entries=[
                    {"ts_ms": 1, "level": "info", "event": "x", "detail": "", "zz": 1}
                ],
            ),
        ),
        (
            "diag-entry-missing-event",
            d(
                **base,
                kind="diag_result",
                entries=[{"ts_ms": 1, "level": "info", "detail": ""}],
            ),
        ),
        (
            "diag-entry-empty-event",
            d(
                **base,
                kind="diag_result",
                entries=[{"ts_ms": 1, "level": "info", "event": "", "detail": ""}],
            ),
        ),
        (
            "diag-restarts-negative",
            d(**base, kind="diag_result", entries=[], listener_restarts=-1),
        ),
        ("bad-bundle-digest", d(**base, kind="realize", bundle_digest="nope")),
        (
            "realize-grants-nonlist",
            d(**base, kind="realize", bundle_digest="ab" * 32, grants={}),
        ),
        (
            "realize-grant-nonstring",
            d(**base, kind="realize", bundle_digest="ab" * 32, grants=[1]),
        ),
        ("forward-bad-port", d(**base, kind="forward", host="h", port=0)),
        ("forward-port-string", d(**base, kind="forward", host="h", port="80")),
        ("ack-target-nonstring", d(**base, kind="ack", target_id=5)),
        ("stage-bad-stage", d(**base, kind="stage", stage="warp")),
        ("stage-detail-nonstring", d(**base, kind="stage", stage="boot", detail=1)),
        (
            "stage-detail-overlong",
            d(**base, kind="stage", stage="boot", detail="x" * 5000),
        ),
        (
            "heartbeat-guests-nonobject",
            d(**base, kind="heartbeat", uptime_ms=1, guests=[]),
        ),
        (
            "guests-bad-state",
            d(**base, kind="heartbeat", uptime_ms=1, guests={"web": "exploding"}),
        ),
        (
            "pong-session-missing",
            d(**base, kind="pong", daemon="d", protocol=3),
        ),
        (
            "pong-session-short",
            d(**base, kind="pong", daemon="d", protocol=3, session="abc123"),
        ),
        (
            "pong-session-badchars",
            d(**base, kind="pong", daemon="d", protocol=3, session="Z" * 32),
        ),
        (
            "pong-session-nonstring",
            d(**base, kind="pong", daemon="d", protocol=3, session=12345),
        ),
        (
            "write-mode-negative",
            d(**base, kind="write_file", path="/f", data_size=0, mode=-1),
        ),
        (
            "write-mode-overrange",
            d(**base, kind="write_file", path="/f", data_size=0, mode=4096),
        ),
        (
            "write-mode-nonint",
            d(**base, kind="write_file", path="/f", data_size=0, mode="0600"),
        ),
        (
            "error-partial-overlong",
            d(
                **base,
                kind="error",
                errno="ETIME",
                message="m",
                layer="command",
                partial="x" * 5000,
            ),
        ),
        (
            "error-partial-on-nonbudget",
            d(**base, kind="error", errno="EIO", message="m", partial="sneaky"),
        ),
        (
            "pong-protocol-nonint",
            d(
                **base,
                kind="pong",
                daemon="d",
                protocol="3",
                session="ffffffffffffffffffffffffffffffff",
            ),
        ),
        (
            "pong-protocol-wrong",
            d(
                **base,
                kind="pong",
                daemon="d",
                protocol=2,
                session="ffffffffffffffffffffffffffffffff",
            ),
        ),
        (
            "pong-daemon-overlong",
            d(
                **base,
                kind="pong",
                daemon="x" * 200,
                session="ffffffffffffffffffffffffffffffff",
            ),
        ),
        (
            "command-ms-over-cap",
            d(**base, kind="exec", cmd=["true"], budget={"command_ms": 20_000_000}),
        ),
        (
            "budget-outer-below-command",
            d(
                **base,
                kind="exec",
                cmd=["true"],
                budget={"command_ms": 5000, "untimed_bound_ms": 1000},
            ),
        ),
        (
            "budget-unknown-field",
            d(**base, kind="exec", cmd=["true"], budget={"zz": 1}),
        ),
        ("max-bytes-over-cap", d(**base, kind="read_file", path="/f", max_bytes=2**31)),
    ]
    return [{"name": name, "payload": payload} for name, payload in cases]


def main() -> None:
    vectors: list[dict[str, object]] = []
    for name, message, bulk in _cases():
        frames = codec.encode_message(message, bulk)
        vector: dict[str, object] = {
            "name": name,
            "message": message.model_dump(mode="json", exclude_none=True),
            "frames_hex": [frame.hex() for frame in frames],
        }
        if bulk is not None:
            vector["bulk_hex"] = bulk.hex()  # omitted entirely when bulkless
        vectors.append(vector)
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
        "rejects": _rejects(),
    }
    out = Path(__file__).parent / "v3.json"
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=True) + "\n")
    print(f"wrote {len(vectors)} vectors to {out}")


if __name__ == "__main__":
    main()
