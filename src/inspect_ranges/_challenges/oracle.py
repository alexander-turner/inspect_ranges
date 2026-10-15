"""The range oracle: privileged, scoring-only access to one sample's range.

The oracle is the surface goal types run against (`challenges-v1.md`): it binds the RAW `MessageChannel`, never the provider's convenience wrappers, because the provider's oversized-exec wrapper persists argv and env as an on-guest script and would deposit plant material where a compromised guest can read it (the residue leak recorded in `challenges-scoring-integrity.md`). It is constructed from provider internals by `range_oracle()` and is never registered as a sandbox or handed to a solver's tools.

Residue rule, enforced here by construction: plant VALUES never ride argv, env, stdin of oracle execs, any log line, or evidence in the clear. File content travels only as `write_file` bulk; the owner flow is write-0600-then-chown so only the path appears in argv.
"""

import secrets
from contextlib import contextmanager
from typing import TYPE_CHECKING, cast

from inspect_ai.util import sandbox

from .._channel.channel import ExecOutcome, MessageChannel, request_id
from .._channel.protocol import DEFAULT_BULK_CAP, Budget, ExecRequest
from .._compiler.plan import ResolvedPlan
from .._evidence.reader import EvidenceStore, manifest_records, stream_chunks
from .._evidence.s3 import store_for_location
from .._provider.provider import sample_handle_for
from .._provider.state import SampleHandle
from ..types import RangeSpec
from .evidenceread import (
    SpannedRecord,
    stream_chunks_with_spans,
    stream_json_records,
)
from .plants import PlantStore

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

    from .._provider.evidence import EvidenceSession

__all__ = ["OracleSetupError", "RangeOracle", "range_oracle"]


class OracleSetupError(RuntimeError):
    """A privileged setup operation failed; the message names the operation, never a value."""


PLANT_SCRIPT = (
    'if [ -e "$1" ] || [ -L "$1" ]; then echo "plant target exists" >&2; exit 2; fi; '
    'umask 077; ( set -C; : > "$1" ) || exit 3; '
    'cat > "$1" && chown -- "$3" "$1"'
    ' && chmod -- "$2" "$1" || { rm -f -- "$1"; exit 1; }'
)
"""The owner-flow write, run as root with the value on stdin.

A fixed literal by design (the residue rule bans values and value-derived text from argv): path, octal mode, and owner arrive as positional arguments, and the content arrives on stdin. The ordering and guards each carry an invariant: a pre-existing target, including a symlink dangling or not, refuses untouched (exit 2); the empty file is created exclusively first (`set -C`, exit 3 touching nothing on a lost race), so the failure branch's `rm` can only ever remove a file this script itself created and a plant never truncates real guest content; `umask 077` means the file is never wider than 0600 before the explicit `chmod`; and `chown` runs BEFORE `chmod` because chown(2) clears setuid/setgid bits, which would silently strip them from any mode that carries them.
"""


class RangeOracle:
    """Privileged access to one sample's range for setup and scoring. Not a `SandboxEnvironment`.

    Obtain one with `range_oracle()` from setup or scoring code running in the sample context.
    """

    def __init__(self, handle: SampleHandle) -> None:
        if handle.channel is None:
            raise OracleSetupError("the sample's channel is not connected")
        self._handle = handle
        self._channel: MessageChannel = handle.channel
        if handle.plants is None:
            handle.plants = PlantStore(handle.evidence)
        self._plants = handle.plants
        self._evidence_memo: dict[tuple[str, str], object] | None = None

    @property
    def store(self) -> PlantStore:
        """The sample's plant record: values in memory, digests at T1."""
        return self._plants

    @property
    def project(self) -> str:
        """The sample's compose project name (how the prober addresses the probe sidecar)."""
        return self._handle.project

    @property
    def channel(self) -> MessageChannel:
        """The sample's raw channel (the telemetry poller polls through it; same residue rules as every oracle verb)."""
        return self._channel

    def evidence_session(self) -> "EvidenceSession | None":
        """The sample's evidence session (producer registration, driver stream appends); `None` when evidence is unavailable."""
        return self._handle.evidence

    def nonce(self) -> str:
        """A fresh per-call secret from independent entropy, never derived from any recorded seed."""
        return secrets.token_hex(16)

    def available_observers(self) -> frozenset[str]:
        """The trusted observers this sample's deployment can supply right now.

        `evidence-sink` exists when the evidence session is live; `segment-pcap` and `console` when capture was rendered into the range. The prober and telemetry-collector observers arrive with their engine slices; until then challenges requiring them refuse at planting.
        """
        available: set[str] = set()
        session = self._handle.evidence
        if session is not None and session.enabled:
            available.add("evidence-sink")
            plan = self._handle.plan
            if plan is not None and plan.requirements.evidence_capture:
                available.update(("segment-pcap", "console"))
            if plan is not None and plan.requirements.probe_segments:
                available.add("active-prober")
        return frozenset(available)

    def resolved(self) -> ResolvedPlan:
        """The sample's resolved plan (variable draws, allocations); how `answer` goals learn instance facts."""
        if self._handle.plan is None:
            raise OracleSetupError("the sample's resolved plan is unavailable")
        return self._handle.plan

    def range_spec(self) -> RangeSpec:
        """The sample's validated range spec: declared variables (defaults until draws land) and scenario content."""
        if self._handle.spec is None:
            raise OracleSetupError("the sample's range spec is unavailable")
        return self._handle.spec

    # -- guest verbs (raw channel) ---------------------------------------------

    async def exec(
        self,
        guest: str,
        cmd: list[str],
        *,
        user: str | None = None,
        timeout_s: float | None = None,
    ) -> ExecOutcome:
        """Run `cmd` (argv, never an implicit shell) in `guest` over the raw channel.

        `cmd` must never carry plant material: values travel as `write_file` bulk or `read_file` replies only.
        """
        budget = (
            Budget(command_ms=max(1, round(timeout_s * 1000)))
            if timeout_s is not None
            else Budget()
        )
        request = ExecRequest(id=request_id(), cmd=cmd, user=user, budget=budget)
        return await self._channel.exec(guest, request)

    async def read_file(
        self,
        guest: str,
        path: str,
        *,
        cap: int = DEFAULT_BULK_CAP,
        user: str | None = None,
    ) -> bytes:
        """Read a guest file raw (a T3 read like any other; the cost rule applies to oracle reads too).

        The daemon's file plane reads as the daemon identity (the agent user), so privileged locations (a 0600 root plant, another principal's file) need `user`: the read then rides the exec plane (`cat` with only the path in argv; the content returns as reply bulk, the same privacy class as a file read).

        Raises:
            OracleSetupError: The privileged read failed or was truncated at the reply cap.
        """
        if user is None:
            return await self._channel.read_file(guest, path, cap=cap)
        outcome = await self.exec(guest, ["cat", "--", path], user=user)
        if outcome.rc != 0:
            raise OracleSetupError(
                f"privileged read as {user!r} failed on {guest}:{path} "
                f"(rc {outcome.rc})"
            )
        if outcome.stdout_truncated or len(outcome.stdout) > cap:
            raise OracleSetupError(
                f"privileged read of {guest}:{path} exceeded the caller's cap "
                f"({cap} bytes); both read paths refuse oversize rather than "
                "silently returning more"
            )
        return outcome.stdout

    async def write_file(
        self,
        guest: str,
        path: str,
        data: bytes,
        *,
        mode: int = 0o600,
        owner: str | None = None,
    ) -> None:
        """Write a guest file with `mode` applied from the first byte; `owner` sets the principal.

        Without `owner`, this is the daemon's file plane (mode pinned atomically with the write, daemon identity, so the path must be daemon-writable). With `owner`, the write rides the exec plane as root: the daemon's file identity cannot create files in privileged locations (`/root`, another principal's 0700 home), so the value travels as exec stdin (request bulk, the same transport privacy as a file write and never argv or env) into `umask 077 && cat`, then `chmod`/`chown` by positional argument. Any failure removes the file in the same script: a plant is never left behind under the wrong mode or principal.

        On every failure path this frame scrubs `data` before raising, so a locals-rendered traceback (`INSPECT_TRACEBACK_LOCALS=1`) cannot carry plant bytes from here; lower channel frames are outside this guarantee, which is why that flag is forbidden on scoring runs.

        Raises:
            OracleSetupError: The owner-flow script failed (nothing is left at `path`).
        """
        if owner is None:
            try:
                await self._channel.write_file(guest, path, data, mode=mode)
            except BaseException:
                del data
                raise
            return
        request = ExecRequest(
            id=request_id(),
            cmd=[
                "sh",
                "-c",
                PLANT_SCRIPT,
                "plant",
                path,
                format(mode, "o"),
                owner,
            ],
            user="root",
            data_size=len(data),
            budget=Budget(),
        )
        try:
            outcome = await self._channel.exec(guest, request, stdin=data)
        except BaseException:
            del data
            raise
        if outcome.rc != 0:
            del data
            raise OracleSetupError(
                f"owned write for {owner!r} failed on {guest}:{path} "
                f"(rc {outcome.rc}; the script removed any partial file)"
            )

    # -- evidence accessors (read-only) -----------------------------------------

    @contextmanager
    def evidence_memo(self) -> "Generator[None]":
        """Memoize the evidence accessors for the duration of one scoring pass.

        The evidence record is immutable once written, so within a pass every accessor returns the same bytes; without the memo, scoring cost scales with the number of agent-submitted candidates (each candidate's `check` refetches the capture), which hands the agent linear control over scoring cost through `submit_goal` calls. The memo is per-key (`pcap/<segment>`, `telemetry/<collector>`, ...), cleared on exit, and only `score_challenge` opens it: the poller never fetches evidence, and setup runs before any evidence exists.
        """
        self._evidence_memo = {}
        try:
            yield
        finally:
            self._evidence_memo = None

    async def _memoized(
        self, key: tuple[str, str], fetch: "Callable[[], Awaitable[object]]"
    ) -> object:
        memo = self._evidence_memo
        if memo is not None and key in memo:
            return memo[key]
        value = await fetch()
        if memo is not None:
            memo[key] = value
        return value

    async def pcap(self, segment: str) -> list[bytes]:
        """The segment's captured pcap chunks from the sample's evidence record (host writer)."""
        return cast(
            "list[bytes]",
            await self._memoized(
                ("pcap", segment),
                lambda: stream_chunks(
                    self._evidence_store(), "host", f"pcap/{segment}"
                ),
            ),
        )

    async def telemetry(self, collector: str) -> list[bytes]:
        """The collector's exported telemetry chunks (driver writer); query semantics arrive with the detection engine."""
        return cast(
            "list[bytes]",
            await self._memoized(
                ("telemetry", collector),
                lambda: stream_chunks(
                    self._evidence_store(), "driver", f"telemetry/{collector}"
                ),
            ),
        )

    async def console(self, guest: str) -> list[bytes]:
        """The guest's continuous serial-console chunks from the sample's evidence record (host writer)."""
        return cast(
            "list[bytes]",
            await self._memoized(
                ("console", guest),
                lambda: stream_chunks(
                    self._evidence_store(), "host", f"console/{guest}"
                ),
            ),
        )

    async def probe_records(self, goal_id: str) -> "tuple[list[SpannedRecord], bool]":
        """The goal's recorded probe verdicts (driver writer) plus whether the stream carries gaps.

        A gap is an observation hole: the prober flushes `down` verdicts immediately, so a lost chunk is disproportionately likely to be the one carrying failures, and the prober types treat a gapped stream as indeterminate rather than trusting the survivors.
        """
        return cast(
            "tuple[list[SpannedRecord], bool]",
            await self._memoized(
                ("probe", goal_id),
                lambda: stream_json_records(
                    self._evidence_store(), "driver", f"probe/{goal_id}"
                ),
            ),
        )

    async def telemetry_export(
        self, collector: str
    ) -> "tuple[list[SpannedRecord], list[tuple[bytes, float, float]], bool]":
        """The collector's export for scoring: meta records, data chunks with spans, and the gap flag.

        One manifest fetch serves both streams (the detection check runs per goal, possibly on a poller cadence, against a possibly remote store).
        """
        return cast(
            "tuple[list[SpannedRecord], list[tuple[bytes, float, float]], bool]",
            await self._memoized(
                ("telemetry-export", collector),
                lambda: self._telemetry_export_fetch(collector),
            ),
        )

    async def _telemetry_export_fetch(
        self, collector: str
    ) -> "tuple[list[SpannedRecord], list[tuple[bytes, float, float]], bool]":
        store = self._evidence_store()
        manifest = await manifest_records(store, "driver")
        meta, meta_gapped = await stream_json_records(
            store, "driver", f"telemetry-meta/{collector}", manifest=manifest
        )
        data, data_gapped = await stream_chunks_with_spans(
            store, "driver", f"telemetry/{collector}", manifest=manifest
        )
        return meta, data, meta_gapped or data_gapped

    def _evidence_store(self) -> EvidenceStore:
        session = self._handle.evidence
        if session is None:
            raise OracleSetupError(
                "evidence is not enabled for this sample; the goal's observer "
                "requirement should have refused at planting"
            )
        return store_for_location(session.location)


def range_oracle() -> RangeOracle:
    """The current sample's oracle, resolved through the default sandbox.

    Call only from setup (`plant_goals`) or scoring code running inside the sample context. The returned capability must never be exposed to the agent's tool loop.

    Raises:
        TypeError: The sample's sandbox is not a `libvirt_range` environment.
    """
    return RangeOracle(sample_handle_for(sandbox()))
