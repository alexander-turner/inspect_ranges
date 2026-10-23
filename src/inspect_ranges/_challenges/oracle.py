"""The range oracle: privileged, scoring-only access to one sample's range.

The oracle is the surface goal types run against (`challenges-v1.md`): it binds the RAW `MessageChannel`, never the provider's convenience wrappers, because the provider's oversized-exec wrapper persists argv and env as an on-guest script and would deposit plant material where a compromised guest can read it (the residue leak recorded in `challenges-scoring-integrity.md`). It is constructed from provider internals by `range_oracle()`, or out of band by `range_oracle("<project>")` against a running `up` project (`attach.py`), and is never registered as a sandbox or handed to a solver's tools.

Residue rule, enforced here by construction: plant VALUES never ride argv, env, stdin of oracle execs, any log line, or evidence in the clear. File content travels only as `write_file` bulk; the owner flow is write-0600-then-chown so only the path appears in argv.
"""

import logging
import secrets
from contextlib import contextmanager
from typing import TYPE_CHECKING, cast, overload

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

logger = logging.getLogger("inspect_ranges.challenges")

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator
    from contextlib import AbstractContextManager
    from pathlib import Path

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

WIN_PLANT_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$plantPath = $env:IR_PLANT_PATH; $plantPrincipal = $env:IR_PLANT_PRINCIPAL; "
    "if (-not $plantPath -or -not $plantPrincipal) { exit 5 }; "
    "if (Test-Path -LiteralPath $plantPath) "
    "{ [Console]::Error.WriteLine('plant target exists'); exit 2 }; "
    "$plantDir = Split-Path -Parent $plantPath; "
    "if ($plantDir) { [System.IO.Directory]::CreateDirectory($plantDir) | Out-Null }; "
    "try { [System.IO.File]::Open($plantPath, [System.IO.FileMode]::CreateNew).Dispose() } "
    "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 3 }; "
    "icacls $plantPath /inheritance:r /grant 'SYSTEM:F' (\"{0}:R\" -f $plantPrincipal) | Out-Null; "
    "if ($LASTEXITCODE -ne 0) { Remove-Item -Force -LiteralPath $plantPath; exit 1 }; "
    "try { "
    "$plantFs = [System.IO.File]::Open($plantPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write); "
    "try { [Console]::OpenStandardInput().CopyTo($plantFs) } finally { $plantFs.Dispose() } "
    "} catch { Remove-Item -Force -LiteralPath $plantPath; "
    "[Console]::Error.WriteLine($_.Exception.Message); exit 6 }; "
    "if ((Get-Item -LiteralPath $plantPath).Length -eq 0) "
    "{ Remove-Item -Force -LiteralPath $plantPath; exit 4 }"
)
"""The Windows owner-flow write, run as the daemon's SYSTEM identity with the value on stdin (windows-ad-v1 slice 4).

A fixed literal like `PLANT_SCRIPT`; the path and principal travel in the exec request's `env` (never interpolated into command text — PowerShell has no positional-argv `-Command` form, and `env` carries arbitrary bytes without a quoting surface). The invariants mirror the POSIX script where NTFS allows: a pre-existing target refuses untouched (exit 2); `FileMode.CreateNew` creates exclusively (exit 3 touching nothing on a lost race); the ACL — inheritance stripped, exactly SYSTEM (full) and the principal (read) — lands on the still-EMPTY file BEFORE the value is written, the POSIX never-wider-than-0600 analogue (slice-4 review: writing first left a window under ProgramData's inherited read ACEs); an EMPTY landing removes itself and fails (exit 4) so a transport that silently dropped stdin can never pass as a plant (plant values are never empty). The honest weakening versus 0600: NTFS lets local Administrators and SYSTEM take ownership regardless, so "readable only by the principal" is a domain-boundary claim, not an absolute one — exactly the claim AD control/privilege goals make. Exit 5 is the env-contract guard (an executor that dropped the env would otherwise probe `Test-Path $null`). Exit 6 is the stdin-copy failure branch (phase review round 1: a mid-copy exception previously disposed the handle but left the PARTIAL file under the applied ACL, contradicting the removal invariant the driver's error reports).
"""

WIN_UNPLANT_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "if ($env:IR_PLANT_PATH -and (Test-Path -LiteralPath $env:IR_PLANT_PATH)) "
    "{ Remove-Item -Force -LiteralPath $env:IR_PLANT_PATH }"
)
"""The Windows unwind: removal by `env`-carried path, the same no-quoting-surface rule as the plant. `$ErrorActionPreference = 'Stop'` makes a locked-file removal exit NONZERO so the unwind's warning breadcrumb fires (phase review round 1: the default non-terminating error exited 0 and the next check's plant refused with no trail)."""


class RangeOracle:
    """Privileged access to one sample's range for setup and scoring. Not a `SandboxEnvironment`.

    Obtain one with `range_oracle()` from setup or scoring code running in the sample context, or attach out of band to a running `up` project with `with range_oracle("<project>") as oracle:`.
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

    async def flush_capture(self) -> int:
        """Snapshot-ship the active capture chunks so scoring reads current traffic; never raises.

        Size-based rotation means a quiet segment's beacon usually sits in the still-active tcpdump file at scoring time; the scorer calls this once before any pcap read (the 2026-10-23 fleet-pass finding). Returns the snapshot chunks shipped: `0` with no evidence session, under separated capture (the applier owns the streamer; a flush verb there is a recorded follow-up), or on any failure.
        """
        session = self.evidence_session()
        # fixtures substitute lean session stubs; a missing flush is a no-op
        flush = getattr(session, "flush_capture", None)
        if session is None or flush is None:
            return 0
        try:
            flushed = await flush()
            return int(flushed)
        except Exception as error:  # noqa: BLE001  (observability, never load-bearing)
            logger.info("capture flush skipped: %s", error)
            return 0

    def nonce(self) -> str:
        """A fresh per-call secret from independent entropy, never derived from any recorded seed."""
        return secrets.token_hex(16)

    def available_observers(self) -> frozenset[str]:
        """The trusted observers this sample's deployment can supply right now.

        `evidence-sink` exists when the evidence session is live; `segment-pcap` and `console` when capture was rendered into the range; `active-prober` when the plan carries rendered probe endpoints. `telemetry-collector` is deployment knowledge the oracle cannot see (which collector specs exist), so `challenge_setup` supplies it as an extra observer to `run_setup` when a matching spec was passed; a challenge requiring an observer absent from the union refuses at planting.
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
        """The sample's resolved plan (per-guest address and CID allocations; see `guest_segment_ip`). Variables never ride the plan: `answer` goals read `variable_value()`, which folds the sample's draws over the declared defaults."""
        if self._handle.plan is None:
            raise OracleSetupError("the sample's resolved plan is unavailable")
        return self._handle.plan

    def range_spec(self) -> RangeSpec:
        """The sample's validated range spec: declared variables (defaults; see `draws()` for the sample's drawn values) and scenario content."""
        if self._handle.spec is None:
            raise OracleSetupError("the sample's range spec is unavailable")
        return self._handle.spec

    def draws(self) -> dict[str, int | str]:
        """The sample's drawn variable values (variable-draws-v0), keyed by variable name; empty when the range declares no `draw: boot` variables or the handle carries no sample context."""
        return dict(self._handle.draws)

    def variable_value(self, name: str) -> str | int | bool:
        """The sample's value for a declared variable: the drawn value when one exists, the declared default otherwise. The one place the draw-else-default rule lives; `answer` scoring reads it.

        Raises:
            KeyError: The range declares no variable `name`.
        """
        drawn = self._handle.draws.get(name)
        if drawn is not None:
            return drawn
        return self.range_spec().variables[name].default

    # -- guest verbs (raw channel) ---------------------------------------------

    def is_windows(self, guest: str) -> bool:
        """Whether `guest` runs Windows, from the sample's resolved plan; a plan-less handle (unit fixtures) treats every guest as linux."""
        plan = self._handle.plan
        if plan is None:
            return False
        return any(g.name == guest and g.os == "windows" for g in plan.guests)

    async def exec(
        self,
        guest: str,
        cmd: list[str],
        *,
        user: str | None = None,
        timeout_s: float | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecOutcome:
        """Run `cmd` (argv, never an implicit shell) in `guest` over the raw channel.

        `cmd` must never carry plant material: values travel as `write_file` bulk or `read_file` replies only. `env` is the Windows path-carrying contract (fixed script literals read `IR_PLANT_*` from it); it must never carry plant material either.
        """
        budget = (
            Budget(command_ms=max(1, round(timeout_s * 1000)))
            if timeout_s is not None
            else Budget()
        )
        request = ExecRequest(
            id=request_id(), cmd=cmd, user=user, env=env or {}, budget=budget
        )
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

        Without `owner`, this is the daemon's file plane (mode pinned atomically with the write, daemon identity, so the path must be daemon-writable; the Windows daemon ignores `mode` by design — NTFS has ACLs, not permission bits). With `owner`, the write rides the exec plane: on Linux as root into `umask 077 && cat` then `chmod`/`chown` by positional argument; on a Windows guest (dispatched from the sample's plan) as the daemon's SYSTEM identity into `WIN_PLANT_SCRIPT`, whose ACL grant (inheritance stripped, SYSTEM full + the principal read) is the mode analogue. Either way the value travels as exec stdin (request bulk, the same transport privacy as a file write and never argv or env). Any failure removes the file in the same script: a plant is never left behind under the wrong mode or principal.

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
        if self.is_windows(guest):
            # the Windows daemon's identity is SYSTEM (user stays None: "root"
            # is not a Windows principal and the daemon refuses it); the path
            # and principal ride env into the fixed literal, and `mode` has no
            # NTFS referent — the script's ACL grant is the mode analogue
            request = ExecRequest(
                id=request_id(),
                cmd=[
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    WIN_PLANT_SCRIPT,
                ],
                env={"IR_PLANT_PATH": path, "IR_PLANT_PRINCIPAL": owner},
                data_size=len(data),
                budget=Budget(),
            )
        else:
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

        The evidence record is immutable once written, so within a pass every accessor returns the same bytes; without the memo, scoring cost scales with the number of agent-submitted candidates (each candidate's `check` refetches the capture), which hands the agent linear control over scoring cost through `verify_goal` calls. The memo is per-key (`pcap/<segment>`, `telemetry/<collector>`, ...) and cleared when the outermost open exits. Reentrant: `challenge_scorer` opens one memo around the whole pass (so two goals on the same segment share one fetch), and `score_challenge`'s per-goal open nests inside it as a no-op; the poller never fetches evidence, setup runs before any evidence exists, and `corroborate()` deliberately bypasses the memo (its claim-scoped reads ride `stream_chunks` directly).
        """
        if self._evidence_memo is not None:
            yield
            return
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
    ) -> "tuple[list[SpannedRecord], list[tuple[bytes, float | None, float | None]], bool]":
        """The collector's export for scoring: meta records, data chunks with spans (`None` spans mark the delivered-but-uncommitted tail), and the gap flag.

        One manifest fetch serves both streams (the detection check runs per goal, possibly on a poller cadence, against a possibly remote store).
        """
        return cast(
            "tuple[list[SpannedRecord], list[tuple[bytes, float | None, float | None]], bool]",
            await self._memoized(
                ("telemetry-export", collector),
                lambda: self._telemetry_export_fetch(collector),
            ),
        )

    async def _telemetry_export_fetch(
        self, collector: str
    ) -> "tuple[list[SpannedRecord], list[tuple[bytes, float | None, float | None]], bool]":
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


@overload
def range_oracle() -> RangeOracle: ...


@overload
def range_oracle(
    project: str, *, state_dir: "Path | None" = None
) -> "AbstractContextManager[RangeOracle]": ...


def range_oracle(
    project: str | None = None, *, state_dir: "Path | None" = None
) -> "RangeOracle | AbstractContextManager[RangeOracle]":
    """The range oracle: the current sample's, or an out-of-band attach to a running project.

    Without arguments, the current sample's oracle, resolved through the default sandbox: call only from setup (`challenge_setup`) or scoring code running inside the sample context. The returned capability must never be exposed to the agent's tool loop.

    With a `project` name, a context manager attaching to a RUNNING range booted with `inspect-ranges up` (or `up --from-spec`), for poking at a range from a REPL or script: `with range_oracle("ir-dmz-pivot-...") as oracle:` yields the same oracle verbs (`exec`, `read_file`, `write_file`, ...) over a transport rebuilt from the project's recorded state (`state_dir` overrides the default project state directory). The attach is local-backend only and logs loudly, so an attach during a scoring run is visible in the run's logs; leaving the context detaches the oracle, and later verbs refuse. An attached oracle carries no sample context: `resolved()`, `range_spec()`, and the evidence accessors refuse, and `is_windows` reads an empty plan, so the owner-flow `write_file` dispatches the POSIX script on every guest.

    Raises:
        TypeError: The sample's sandbox is not a `range` environment (sample form).
        OracleSetupError: The attach refused: separated topology (`INSPECT_RANGES_HOST` set), unknown or stale project, or a project that is registered but no longer running (attach form; the message names the state path and the remedy).
    """
    if project is not None:
        from .attach import attach_oracle

        return attach_oracle(project, state_dir=state_dir)
    if state_dir is not None:
        raise OracleSetupError(
            "state_dir applies only to the attach-by-project form "
            "(range_oracle('<project>', state_dir=...))"
        )
    return RangeOracle(sample_handle_for(sandbox()))
