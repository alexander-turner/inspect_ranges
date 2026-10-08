"""Protocol v3 message schemas for the range channel.

Two planes ride one message contract (`range-channel.md`): guest control (`exec`, `read_file`, `write_file`, `forward`, plus the durability verbs `poll`/`ack` and the `diag` ring-buffer read) and host lifecycle (`realize`, `teardown`, stage reports, heartbeat). Every message carries the protocol version, a request id, and an optional out-of-band bulk declaration (`data_size`); bulk bytes never ride the control payload.

Wire conventions, chosen so the Go and C# codecs cannot drift: every numeric field is an integer (milliseconds, bytes, counts; never floats), control payloads are canonical JSON (sorted keys, compact separators, UTF-8), and schemas are strict (unknown keys are errors, no cross-type coercion) because every reply originates on an attackable guest.
"""

from typing import Annotated, Literal, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    model_validator,
)

PROTOCOL_VERSION = 3

MAX_FRAME_PAYLOAD = 32 * 1024
"""Per-frame payload cap: the virtio viosock send cap makes implicit chunking a trap."""

MAX_BULK_DECLARABLE = 1 << 30
"""Upper bound on `data_size` a message may declare; readers enforce their own, smaller caps."""

DEFAULT_BULK_CAP = 16 * 1024 * 1024
"""Reader-side default cap on accepted bulk bytes (per stream, the qemu-ga precedent)."""

DEFAULT_CHANNEL_BUDGET_MS = 180_000
"""Channel-communication allowance per round trip (the layered-budget middle layer)."""

DEFAULT_UNTIMED_BOUND_MS = 14_400_000
"""Bound on commands that declared no timeout (4 h, the layered-budget outer layer)."""

DAEMON_KILL_GRACE_MS = 5_000
"""The daemon's TERM-to-KILL grace on a command budget expiry (mirrored by the Go daemon; the vectors pin it)."""

DAEMON_WAIT_DELAY_MS = 5_000
"""The daemon's bound on reaping pipe copiers after the process exits (`cmd.WaitDelay`; the vectors pin it)."""

EXEC_OBSERVATION_GRACE_S = (DAEMON_KILL_GRACE_MS + DAEMON_WAIT_DELAY_MS) / 1000 + 2.0
"""Host-side grace added to `command_ms` before an exec deadline verdict: the daemon's worst-case honest kill latency (kill grace plus wait delay) plus margin, derived from the shared constants so host and daemon cannot drift apart."""

DAEMON_INBOUND_BULK_CAP = 256 * 1024 * 1024
"""The daemon's reader-side cap on inbound bulk (write payloads, exec stdin); the host refuses larger payloads before sending."""

MAX_WIRE_INT = 2**53
"""Upper bound for unbounded-looking integer wire fields: safe in int64 and double codecs alike."""

RequestId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
"""Request ids are 32 lowercase hex chars (`uuid4().hex`); retries reuse the id, never regenerate it."""

ErrnoName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]{1,15}$")]

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

GuestState = Literal["pending", "booting", "ready", "failed"]

BudgetLayer = Literal["command", "channel", "untimed", "transport"]
"""Which budget layer fired: in-guest command timeout, channel allowance, the untimed bound, or the transport itself."""


class _WireModel(BaseModel):
    """Base for every wire schema: strict types, unknown keys are errors."""

    model_config = ConfigDict(extra="forbid", strict=True)


class Budget(_WireModel):
    """Layered time budgets carried by guest-control requests.

    The layers are independent by design (`guest-exec-lessons.md`): `command_ms` is enforced in-guest with a process-tree kill; `channel_ms` bounds each channel round trip host-side (per attempt, so retries extend wall time by at most the attempt count; `None` takes the channel default); `untimed_bound_ms` is an outer total per operation, covering every attempt and backoff.

    Exec liveness: the channel allowance bounds each exec round trip too. When the initial reply does not arrive within the allowance, the client switches to polling the request id; the daemon answers `pending` while the command runs, so a long exec stays allowance-bounded between polls while the command itself is bounded in-guest by `command_ms` (plus the host's observation grace) or the untimed total. A host-side exec deadline firing WITHOUT observed liveness is a channel-layer verdict; WITH observed liveness (polls answered, command overdue past kill grace) it is a command-layer verdict, since the guest demonstrably failed to kill.

    Retry interaction: a lost reply is recovered by resending the identical request id, which the endpoint deduplicates. A host-side deadline firing without an observed in-guest kill is attributed to the channel layer, never the command layer; command-layer errors come only from the guest's own budget reply. Any future layer that retried a transport failure with a FRESH request id would reintroduce double-runs, letting an attacker launder a replay through induced truncation; retries must reuse the id, always.
    """

    command_ms: int | None = Field(default=None, ge=1, le=DEFAULT_UNTIMED_BOUND_MS)
    channel_ms: int | None = Field(default=None, ge=1, le=MAX_WIRE_INT)
    untimed_bound_ms: int = Field(
        default=DEFAULT_UNTIMED_BOUND_MS, ge=1, le=MAX_WIRE_INT
    )

    @model_validator(mode="after")
    def _outer_covers_command(self) -> "Budget":
        if self.command_ms is not None and self.command_ms > self.untimed_bound_ms:
            raise ValueError(
                "untimed_bound_ms is the outer total and must cover command_ms"
            )
        return self


class _MessageBase(_WireModel):
    """Envelope fields every message carries. The codec additionally requires `v` on the wire: a payload omitting it (or carrying any other version) is a typed decode error, since an honest endpoint always emits it; the schema default exists only for Python construction ergonomics."""

    v: Literal[3] = PROTOCOL_VERSION
    id: RequestId


class _BulkMessage(_MessageBase):
    """Base for the only kinds that may carry out-of-band bulk (exec stdin, write_file, exec_result, file_data). Everywhere else, bulk is an unknown key and therefore a schema violation: a hostile endpoint gets no byte side-channel on ok/error/pending replies."""

    data_size: int | None = Field(default=None, ge=0, le=MAX_BULK_DECLARABLE)
    """Byte count of the out-of-band bulk that follows the control frame; `None` means no bulk frames at all."""


def declared_bulk(message: "Message") -> int | None:
    """The bulk byte count `message` declares, or `None` for bulk-less kinds."""
    return message.data_size if isinstance(message, _BulkMessage) else None


# ---------------------------------------------------------------------------
# Guest control plane: requests
# ---------------------------------------------------------------------------


class PingRequest(_MessageBase):
    """Liveness and protocol-version probe."""

    kind: Literal["ping"] = "ping"


class ExecRequest(_BulkMessage):
    """Run an argv command in the guest (never an implicit shell); stdin rides the bulk."""

    kind: Literal["exec"] = "exec"
    cmd: list[str] = Field(min_length=1)
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    user: str | None = None
    budget: Budget = Field(default_factory=Budget)


class ReadFileRequest(_MessageBase):
    """Read a guest file; the reply's bulk carries the bytes."""

    kind: Literal["read_file"] = "read_file"
    path: str = Field(min_length=1)
    max_bytes: int | None = Field(default=None, ge=0, le=MAX_BULK_DECLARABLE)
    """Advisory cap so an honest daemon can refuse early; the reader enforces its own cap regardless."""
    budget: Budget = Field(default_factory=Budget)


class WriteFileRequest(_BulkMessage):
    """Write a guest file; the request's bulk carries the bytes (zero-size bulk writes an empty file)."""

    kind: Literal["write_file"] = "write_file"
    path: str = Field(min_length=1)
    budget: Budget = Field(default_factory=Budget)

    @model_validator(mode="after")
    def _requires_bulk(self) -> "WriteFileRequest":
        if self.data_size is None:
            raise ValueError("write_file requires data_size (0 for an empty file)")
        return self


class ForwardRequest(_MessageBase):
    """Open a capability-gated forward to a target reachable from the guest."""

    kind: Literal["forward"] = "forward"
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    budget: Budget = Field(default_factory=Budget)


class PollRequest(_MessageBase):
    """Re-deliver the stored reply of `target_id` (durable-replies recovery after a dropped reply)."""

    kind: Literal["poll"] = "poll"
    target_id: RequestId


class AckRequest(_MessageBase):
    """Acknowledge `target_id`: the daemon may drop its stored reply."""

    kind: Literal["ack"] = "ack"
    target_id: RequestId


class DiagRequest(_MessageBase):
    """Read the daemon's in-guest diagnostic ring buffer (never written anywhere the range can see)."""

    kind: Literal["diag"] = "diag"
    max_entries: int = Field(default=100, ge=1, le=1000)


# ---------------------------------------------------------------------------
# Guest control plane: replies
# ---------------------------------------------------------------------------


class PongReply(_MessageBase):
    kind: Literal["pong"] = "pong"
    daemon: str = Field(max_length=128)
    protocol: Literal[3] = PROTOCOL_VERSION


class ExecResult(_BulkMessage):
    """Exec outcome; the bulk is stdout then stderr, concatenated at the declared sizes.

    `rc` uses the signed convention: killed-by-signal is negative (`-signal`), and daemons convert platform-unsigned exit codes to signed int32 before replying (the Windows unsigned-32 lesson).
    """

    kind: Literal["exec_result"] = "exec_result"
    rc: int = Field(ge=-(2**31), le=2**31 - 1)
    stdout_size: int = Field(ge=0, le=MAX_BULK_DECLARABLE)
    stderr_size: int = Field(ge=0, le=MAX_BULK_DECLARABLE)
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @model_validator(mode="after")
    def _sizes_match_bulk(self) -> "ExecResult":
        declared = self.data_size if self.data_size is not None else 0
        if self.stdout_size + self.stderr_size != declared:
            raise ValueError("stdout_size + stderr_size must equal data_size")
        return self


class FileData(_BulkMessage):
    """Reply to `read_file`; the bulk carries the bytes."""

    kind: Literal["file_data"] = "file_data"
    size: int = Field(ge=0, le=MAX_BULK_DECLARABLE)
    truncated: bool = False

    @model_validator(mode="after")
    def _size_matches_bulk(self) -> "FileData":
        declared = self.data_size if self.data_size is not None else 0
        if self.size != declared:
            raise ValueError("size must equal data_size")
        return self


class OkReply(_MessageBase):
    """Positive acknowledgement for operations with no payload (write, ack, teardown)."""

    kind: Literal["ok"] = "ok"


class PendingReply(_MessageBase):
    """Reply to `poll` when the target request is still running in the guest."""

    kind: Literal["pending"] = "pending"
    target_id: RequestId
    elapsed_ms: int = Field(ge=0, le=MAX_WIRE_INT)


class ForwardReply(_MessageBase):
    kind: Literal["forward_ok"] = "forward_ok"
    handle: RequestId


class DiagEntry(_WireModel):
    ts_ms: int = Field(ge=0, le=MAX_WIRE_INT)
    level: Literal["info", "warn", "error"]
    event: str = Field(min_length=1, max_length=128)
    request_id: str | None = Field(default=None, max_length=64)
    detail: str = Field(default="", max_length=2048)


class DiagReply(_MessageBase):
    kind: Literal["diag_result"] = "diag_result"
    entries: list[DiagEntry] = Field(max_length=1000)
    listener_restarts: int = Field(default=0, ge=0, le=MAX_WIRE_INT)
    """Supervised listener recreations since daemon start: the storm battery asserts it stays 0."""


class ErrorReply(_MessageBase):
    """Errno-tagged failure. Budget expiries set `errno` `ETIME` and must name the layer that fired.

    `ESTALE` is the at-most-once sentinel: the effect EXECUTED but its unacknowledged result was evicted; a client must surface it as an infrastructure failure and never resend the id.

    Post-compromise, everything in an error reply (errno, message, layer) is attacker-influenceable: layer attribution from the guest is triage advice, and the host-enforced budgets remain the real bound.
    """

    kind: Literal["error"] = "error"
    errno: ErrnoName
    message: str = Field(max_length=4096)
    layer: BudgetLayer | None = None

    @model_validator(mode="after")
    def _budget_errors_name_their_layer(self) -> "ErrorReply":
        if self.errno in ("ETIME", "ETIMEDOUT") and self.layer is None:
            raise ValueError("budget errors must name the layer that fired")
        return self


# ---------------------------------------------------------------------------
# Host lifecycle plane (schemas here; exercised against mocks until the
# provider phase wires the real applier)
# ---------------------------------------------------------------------------


class RealizeRequest(_MessageBase):
    kind: Literal["realize"] = "realize"
    bundle_digest: Sha256Hex
    grants: list[str] = Field(default_factory=list, max_length=64)


class TeardownRequest(_MessageBase):
    kind: Literal["teardown"] = "teardown"


class StageReport(_MessageBase):
    """Staged realization progress; `failed` carries diagnostics in `detail`."""

    kind: Literal["stage"] = "stage"
    stage: Literal["fetch", "construct", "boot", "verify", "ready", "failed"]
    detail: str = Field(default="", max_length=4096)
    guests: dict[str, GuestState] = Field(default_factory=dict)


class Heartbeat(_MessageBase):
    kind: Literal["heartbeat"] = "heartbeat"
    uptime_ms: int = Field(ge=0, le=MAX_WIRE_INT)
    guests: dict[str, GuestState] = Field(default_factory=dict)


GuestRequest = (
    PingRequest
    | ExecRequest
    | ReadFileRequest
    | WriteFileRequest
    | ForwardRequest
    | PollRequest
    | AckRequest
    | DiagRequest
)

GuestReply = (
    PongReply
    | ExecResult
    | FileData
    | OkReply
    | PendingReply
    | ForwardReply
    | DiagReply
    | ErrorReply
)

HostMessage = RealizeRequest | TeardownRequest | StageReport | Heartbeat

Message = Annotated[
    GuestRequest | GuestReply | HostMessage,
    Field(discriminator="kind"),
]
"""Every v3 message, discriminated on `kind`; the codec validates against this adapter."""

MESSAGE_ADAPTER: TypeAdapter[Message] = TypeAdapter(Message)


def _all_kinds() -> frozenset[str]:
    kinds: set[str] = set()
    for union in (GuestRequest, GuestReply, HostMessage):
        for member in get_args(union):
            kinds.add(member.model_fields["kind"].default)
    return frozenset(kinds)


ALL_MESSAGE_KINDS = _all_kinds()
"""Every `kind` discriminator value; the wire vectors must cover each one."""
