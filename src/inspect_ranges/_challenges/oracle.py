"""The range oracle: privileged, scoring-only access to one sample's range.

The oracle is the surface goal types run against (`challenges-v1.md`): it binds the RAW `MessageChannel`, never the provider's convenience wrappers, because the provider's oversized-exec wrapper persists argv and env as an on-guest script and would deposit plant material where a compromised guest can read it (the residue leak recorded in `challenges-scoring-integrity.md`). It is constructed from provider internals by `range_oracle()` and is never registered as a sandbox or handed to a solver's tools.

Residue rule, enforced here by construction: plant VALUES never ride argv, env, stdin of oracle execs, any log line, or evidence in the clear. File content travels only as `write_file` bulk; the owner flow is write-0600-then-chown so only the path appears in argv.
"""

import secrets

from inspect_ai.util import sandbox

from .._channel.channel import ExecOutcome, MessageChannel, request_id
from .._channel.protocol import DEFAULT_BULK_CAP, Budget, ExecRequest
from .._compiler.plan import ResolvedPlan
from .._evidence.reader import EvidenceStore, stream_chunks
from .._evidence.s3 import store_for_location
from .._provider.provider import sample_handle_for
from .._provider.state import SampleHandle
from .plants import PlantStore

__all__ = ["OracleSetupError", "RangeOracle", "range_oracle"]


class OracleSetupError(RuntimeError):
    """A privileged setup operation failed; the message names the operation, never a value."""


PLANT_SCRIPT = (
    'if [ -e "$1" ]; then echo "plant target exists" >&2; exit 2; fi; '
    'umask 077 && { set -C; cat > "$1"; } && chown -- "$3" "$1"'
    ' && chmod -- "$2" "$1" || { rm -f -- "$1"; exit 1; }'
)
"""The owner-flow write, run as root with the value on stdin.

A fixed literal by design (the residue rule bans values and value-derived text from argv): path, octal mode, and owner arrive as positional arguments, and the content arrives on stdin. The ordering and guards each carry an invariant: a pre-existing target refuses untouched (exit 2) and `set -C` makes creation exclusive, so a plant never truncates real guest content and the failure branch never removes a file this script did not create; `umask 077` means the file is never wider than 0600 before the explicit `chmod`; and `chown` runs BEFORE `chmod` because chown(2) clears setuid/setgid bits, which would silently strip them from any mode that carries them.
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

    @property
    def store(self) -> PlantStore:
        """The sample's plant record: values in memory, digests at T1."""
        return self._plants

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
        return frozenset(available)

    def resolved(self) -> ResolvedPlan:
        """The sample's resolved plan (variable draws, allocations); how `answer` goals learn instance facts."""
        if self._handle.plan is None:
            raise OracleSetupError("the sample's resolved plan is unavailable")
        return self._handle.plan

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

        Raises:
            OracleSetupError: The owner-flow script failed (nothing is left at `path`).
        """
        if owner is None:
            await self._channel.write_file(guest, path, data, mode=mode)
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
        outcome = await self._channel.exec(guest, request, stdin=data)
        if outcome.rc != 0:
            raise OracleSetupError(
                f"owned write for {owner!r} failed on {guest}:{path} "
                f"(rc {outcome.rc}; the script removed any partial file)"
            )

    # -- evidence accessors (read-only) -----------------------------------------

    async def pcap(self, segment: str) -> list[bytes]:
        """The segment's captured pcap chunks from the sample's evidence record (host writer)."""
        return await stream_chunks(self._evidence_store(), "host", f"pcap/{segment}")

    async def telemetry(self, collector: str) -> list[bytes]:
        """The collector's exported telemetry chunks (driver writer); query semantics arrive with the detection engine."""
        return await stream_chunks(
            self._evidence_store(), "driver", f"telemetry/{collector}"
        )

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
