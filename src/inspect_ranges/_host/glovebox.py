"""The glovebox control-channel connector: drive a glovebox-managed Kata cell as a Ranges guest.

Part 3 of the route-2 integration contract (`route2-full/ROUTE2-FULL.md`). A `provider: glovebox` attacker box is not booted by Ranges; it is an externally-supplied glovebox Kata cell whose exec rides the CRI/kata-agent channel, not the Ranges `vsockd` protocol. `glovebox_connector` bridges that gap behind the applier's `GuestConnector` byte-pump seam without changing it: for a cell's reserved cid it returns an in-process `ByteStream` whose far end is a tiny v3 wire server (`serve_guest_connection`) that reads one guest-control request, runs it against a `CellExecutor` (default: `crictl exec` into the pod), writes one wire-accurate reply, and closes — the per-operation-connect shape every honest daemon uses.

The server speaks the same codec (`_channel/codec.py`) and schema (`_channel/protocol.py`) as the Go daemon, so the real client validates it as untrusted input. Recorded gaps to a production connector: no durable-replies store (`poll`/`ack` are no-ops/ok because each op is synchronous, so a lost reply is retried by a fresh connect), no in-guest process-tree kill on `command_ms`, and no `forward`/`diag`.
"""

import asyncio
import base64
import hashlib
import logging
import shlex
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .._channel.channel import ByteStream, stream_pair
from .._channel.codec import encode_message, read_message
from .._channel.protocol import (
    DAEMON_INBOUND_BULK_CAP,
    AckRequest,
    ErrorReply,
    ExecRequest,
    ExecResult,
    FileData,
    Message,
    OkReply,
    PendingReply,
    PingRequest,
    PollRequest,
    PongReply,
    ReadFileRequest,
    WriteFileRequest,
)

if TYPE_CHECKING:
    from .._compiler.plan import ResolvedPlan

logger = logging.getLogger("inspect_ranges.glovebox")

_DAEMON_NAME = "glovebox-crictl-connector/0.1"
_RC_MARKER = "__IR_GB_RC__"


# ---------------------------------------------------------------------------
# The cell executor seam (default: crictl exec into the pod)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CellExecResult:
    """One command's outcome in the cell: signed rc, and raw stdout/stderr bytes."""

    rc: int
    stdout: bytes
    stderr: bytes


class CellExecutor:
    """Runs guest-control operations inside one glovebox Kata cell.

    The default implementation (`CrictlCellExecutor`) shells into the cell's CRI container with `crictl exec`; tests inject a fake. Every method maps a provider operation to an in-cell action, returning bytes/rc the wire server re-frames as a v3 reply.
    """

    async def run(
        self,
        cmd: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        user: str | None,
        stdin: bytes,
    ) -> CellExecResult:
        raise NotImplementedError

    async def read_file(self, path: str, *, max_bytes: int | None) -> bytes:
        raise NotImplementedError

    async def write_file(self, path: str, data: bytes, *, mode: int | None) -> None:
        raise NotImplementedError


RunCommand = Callable[[Sequence[str], bytes], Awaitable[CellExecResult]]
"""Low-level `(argv, stdin) -> result` hook: run argv directly in the cell. Injectable so the exec/file mapping is tested without a live `crictl`."""


@dataclass
class CrictlCellExecutor(CellExecutor):
    """A `CellExecutor` that runs commands in a CRI container with `crictl exec`.

    `container_id` is the cell's CRI container (the `gbcell` pod's app container). `run_command` defaults to spawning `crictl exec -i <container_id> <argv>` and is injectable for tests.

    Exit codes: `crictl exec` does not reliably propagate the in-cell command's exit status, so `run` wraps the command in a `/bin/sh -c` that prints a sentinel `rc` line on stdout and parses it back. This is the one shell indirection; argv is passed as positional parameters (`sh -c '...' sh arg0 arg1`) so argv semantics (no implicit word-splitting of the caller's argv) are preserved. Binary file transfer rides base64 for fidelity.
    """

    container_id: str
    crictl: str = "crictl"
    run_command: RunCommand | None = None

    async def _run_argv(self, argv: Sequence[str], stdin: bytes) -> CellExecResult:
        if self.run_command is not None:
            return await self.run_command(argv, stdin)
        full = [self.crictl, "exec", "-i", self.container_id, *argv]
        proc = await asyncio.create_subprocess_exec(
            *full,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate(stdin)
        return CellExecResult(rc=proc.returncode or 0, stdout=out, stderr=err)

    async def run(
        self,
        cmd: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        user: str | None,
        stdin: bytes,
    ) -> CellExecResult:
        prefix = ""
        if cwd is not None:
            prefix += f"cd {shlex.quote(cwd)} || exit 127; "
        for key, value in env.items():
            prefix += f"export {shlex.quote(key)}={shlex.quote(value)}; "
        # run the caller's argv (as "$@") then emit the real rc as a sentinel on
        # stdout, since crictl exec swallows the command's exit status
        script = f'{prefix}"$@"; printf "\\n{_RC_MARKER}%d\\n" "$?"'
        argv: list[str] = []
        if user is not None:
            argv += ["runuser", "-u", user, "--"]
        argv += ["/bin/sh", "-c", script, "sh", *cmd]
        result = await self._run_argv(argv, stdin)
        rc, stdout = _split_rc_marker(result.stdout, fallback=result.rc)
        return CellExecResult(rc=rc, stdout=stdout, stderr=result.stderr)

    async def read_file(self, path: str, *, max_bytes: int | None) -> bytes:
        argv = ["/bin/sh", "-c", f"base64 {shlex.quote(path)}"]
        result = await self._run_argv(argv, b"")
        if result.rc != 0:
            raise FileNotFoundError(path)
        data = base64.b64decode(result.stdout)
        if max_bytes is not None and len(data) > max_bytes:
            data = data[:max_bytes]
        return data

    async def write_file(self, path: str, data: bytes, *, mode: int | None) -> None:
        encoded = base64.b64encode(data)
        script = f"base64 -d > {shlex.quote(path)}"
        if mode is not None:
            script += f" && chmod {mode:o} {shlex.quote(path)}"
        argv = ["/bin/sh", "-c", script]
        result = await self._run_argv(argv, encoded)
        if result.rc != 0:
            raise PermissionError(
                f"write_file {path} failed rc={result.rc}: "
                f"{result.stderr.decode('utf-8', 'replace')[:256]}"
            )


def _split_rc_marker(stdout: bytes, *, fallback: int) -> tuple[int, bytes]:
    """Split the trailing `__IR_GB_RC__<n>` sentinel off stdout; fall back to `fallback` if absent."""
    marker = f"\n{_RC_MARKER}".encode()
    idx = stdout.rfind(marker)
    if idx < 0:
        return fallback, stdout
    tail = stdout[idx + len(marker) :].strip()
    try:
        rc = int(tail)
    except ValueError:
        return fallback, stdout
    return rc, stdout[:idx]


# ---------------------------------------------------------------------------
# The wire server: one request -> one reply (per-operation connect)
# ---------------------------------------------------------------------------


def _session_for(key: str) -> str:
    """A stable 32-hex session id derived from `key` (one cell == one session while it lives)."""
    return hashlib.sha256(key.encode()).hexdigest()[:32]


@dataclass
class CellConnection:
    """Binds a `CellExecutor` to a stable session id for one cell."""

    executor: CellExecutor
    session: str = field(default="")
    daemon: str = _DAEMON_NAME

    def __post_init__(self) -> None:
        if not self.session:
            self.session = _session_for(repr(self.executor))


async def serve_guest_connection(stream: ByteStream, cell: CellConnection) -> None:
    """Serve exactly one guest-control request off `stream`, then close (per-operation connect).

    Reads one v3 message, dispatches it against the cell, writes one wire-accurate reply, and closes the stream so the client's post-reply `receive()` sees the clean EOF it requires. Any dispatch failure becomes an `ErrorReply` (never a dropped connection), so the client gets a typed verdict rather than a loss.
    """
    try:
        try:
            message, bulk = await read_message(
                stream.receive, bulk_cap=DAEMON_INBOUND_BULK_CAP
            )
        except Exception:
            # EOF or malformed input before a full request: nothing to answer
            return
        reply, reply_bulk = await _dispatch(message, bulk or b"", cell)
        for frame in encode_message(reply, reply_bulk):
            await stream.send(frame)
    finally:
        await stream.aclose()


def _error(message: Message, errno: str, detail: str) -> tuple[Message, bytes | None]:
    return ErrorReply(id=message.id, errno=errno, message=detail[:4096]), None


async def _dispatch(
    message: Message, bulk: bytes, cell: CellConnection
) -> tuple[Message, bytes | None]:
    if isinstance(message, PingRequest):
        return (
            PongReply(id=message.id, daemon=cell.daemon, session=cell.session),
            None,
        )
    if isinstance(message, ExecRequest):
        return await _exec(message, bulk, cell)
    if isinstance(message, ReadFileRequest):
        return await _read_file(message, cell)
    if isinstance(message, WriteFileRequest):
        return await _write_file(message, bulk, cell)
    if isinstance(message, PollRequest):
        # ops are synchronous here, so a poll's target already replied (and the
        # client resends the request itself on loss); answer "still running"
        # with zero elapsed is never reached in practice, but keeps the kind live
        return PendingReply(
            id=message.id, target_id=message.target_id, elapsed_ms=0
        ), None
    if isinstance(message, AckRequest):
        return OkReply(id=message.id), None
    return _error(
        message, "ENOSYS", f"glovebox connector does not serve {message.kind}"
    )


async def _exec(
    message: ExecRequest, stdin: bytes, cell: CellConnection
) -> tuple[Message, bytes | None]:
    try:
        result = await cell.executor.run(
            message.cmd,
            cwd=message.cwd,
            env=message.env,
            user=message.user,
            stdin=stdin,
        )
    except FileNotFoundError as missing:
        return _error(message, "ENOENT", f"exec: {missing}")
    except Exception as failure:  # noqa: BLE001 - surfaced as a typed wire error
        return _error(message, "EIO", f"exec failed: {failure}")
    stdout, stderr = result.stdout, result.stderr
    reply = ExecResult(
        id=message.id,
        rc=_clamp_rc(result.rc),
        stdout_size=len(stdout),
        stderr_size=len(stderr),
        data_size=len(stdout) + len(stderr),
    )
    return reply, stdout + stderr


async def _read_file(
    message: ReadFileRequest, cell: CellConnection
) -> tuple[Message, bytes | None]:
    try:
        data = await cell.executor.read_file(message.path, max_bytes=message.max_bytes)
    except FileNotFoundError:
        return _error(message, "ENOENT", f"read_file: no such file: {message.path}")
    except PermissionError:
        return _error(
            message, "EACCES", f"read_file: permission denied: {message.path}"
        )
    except Exception as failure:  # noqa: BLE001
        return _error(message, "EIO", f"read_file failed: {failure}")
    return (
        FileData(id=message.id, size=len(data), data_size=len(data)),
        data,
    )


async def _write_file(
    message: WriteFileRequest, data: bytes, cell: CellConnection
) -> tuple[Message, bytes | None]:
    try:
        await cell.executor.write_file(message.path, data, mode=message.mode)
    except PermissionError as denied:
        return _error(message, "EACCES", f"write_file: {denied}")
    except Exception as failure:  # noqa: BLE001
        return _error(message, "EIO", f"write_file failed: {failure}")
    return OkReply(id=message.id), None


def _clamp_rc(rc: int) -> int:
    lo, hi = -(2**31), 2**31 - 1
    return max(lo, min(hi, rc))


# ---------------------------------------------------------------------------
# The connector seam (drop-in GuestConnector)
# ---------------------------------------------------------------------------

GuestConnector = Callable[[int], Awaitable[ByteStream]]


def glovebox_connector(
    cells: Mapping[int, CellConnection],
    fallback: GuestConnector,
) -> GuestConnector:
    """A `GuestConnector` that serves glovebox cells in-process and defers everything else to `fallback`.

    Args:
        cells: Reserved cid to the glovebox cell bound behind it. Read at dial time, so a live mapping sees cells registered after the applier starts.
        fallback: The connector for every non-glovebox cid (the real `cloud_hypervisor_connector` / vsock dial).

    For a glovebox cid, each dial creates a fresh in-process duplex pipe, spawns `serve_guest_connection` on the server end as a tracked background task, and returns the client end to the applier's byte pump. The task self-completes when the one request/reply exchange finishes and the applier closes the client end.
    """
    tasks: set[asyncio.Task[None]] = set()

    async def connect(cid: int) -> ByteStream:
        cell = cells.get(cid)
        if cell is None:
            return await fallback(cid)
        client, server = stream_pair()
        task = asyncio.create_task(serve_guest_connection(server, cell))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return client

    return connect


# ---------------------------------------------------------------------------
# The applier-side lifecycle (contract parts 2+3 wired behind the applier seam)
# ---------------------------------------------------------------------------

RootRunner = Callable[[Sequence[Sequence[str]]], Awaitable[None]]
"""Runs a sequence of root `ip`/`nsenter` argv in order. Injectable so stitch/unstitch are tested without touching the host network; the default shells out with `asyncio.create_subprocess_exec`."""

NetnsPidFn = Callable[[str], Awaitable[int]]
"""`project -> range-container netns pid`: where the applier's in-netns segment bridges live (the `range` compose service). Injectable; the default reads it via `docker`."""

ExecutorFactory = Callable[[str], CellExecutor]
"""`container_id -> CellExecutor` for one cell. Injectable so the applier's relay-into-cell path is tested end to end without a live `crictl`; the default builds a `CrictlCellExecutor`."""


async def _default_root_runner(commands: Sequence[Sequence[str]]) -> None:
    """Run each argv in order; a non-zero `ip link add ... type bridge` whose device already exists is tolerated (the node bridge is shared across leases/the pre-booted cell), every other failure raises."""
    for argv in commands:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        if proc.returncode:
            detail = err.decode("utf-8", "replace").strip()
            tolerable = (
                "type" in argv
                and "bridge" in argv
                and ("exists" in detail.lower() or "file exists" in detail.lower())
            )
            if not tolerable:
                raise OSError(f"root command {' '.join(argv)} failed: {detail}")


async def _default_netns_pid(project: str) -> int:
    """The `range` service container's init pid for `project`, via `docker inspect` on the compose-labeled container."""
    find = await asyncio.create_subprocess_exec(
        "docker",
        "ps",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--filter",
        "label=com.docker.compose.service=range",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await find.communicate()
    container = out.decode().strip().splitlines()
    if find.returncode or not container:
        raise OSError(
            f"no range container for project {project}: "
            f"{err.decode('utf-8', 'replace').strip()}"
        )
    inspect = await asyncio.create_subprocess_exec(
        "docker",
        "inspect",
        "-f",
        "{{.State.Pid}}",
        container[0],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    pid_out, pid_err = await inspect.communicate()
    if inspect.returncode:
        raise OSError(
            f"docker inspect of {container[0]} failed: "
            f"{pid_err.decode('utf-8', 'replace').strip()}"
        )
    return int(pid_out.decode().strip())


def _veth_names(project: str, index: int) -> tuple[str, str]:
    """A stable, <=15-char (host, peer) veth pair name per (project, segment index), unique across concurrent leases."""
    tag = hashlib.sha256(f"{project}:{index}".encode()).hexdigest()[:8]
    return f"gbv{tag}h", f"gbv{tag}p"


@dataclass
class GloveboxHost:
    """The applier's glovebox plane: maps each reserved glovebox guest to a live cell and stitches its segment bridge into the node netns at realize, tearing the stitch down at teardown.

    `containers` maps a `provider: glovebox` guest name to the CRI container id of the cell that IS that box (the operator boots the cell out of band — see `route2-full/ROUTE2-FULL.md`; automating the cell boot is the remaining lifecycle gap). `cells` is the live cid->`CellConnection` map the `connector` reads at dial time; `realize` populates it from the plan's reserved cids. The `root_runner`/`netns_pid_fn` seams are injectable for tests; defaults drive the real host network via `docker`/`ip`/`nsenter`.
    """

    containers: Mapping[str, str]
    crictl: str = "crictl"
    root_runner: RootRunner = _default_root_runner
    netns_pid_fn: NetnsPidFn = _default_netns_pid
    executor_factory: ExecutorFactory | None = None
    cells: dict[int, CellConnection] = field(default_factory=dict[int, CellConnection])
    # per project: the (node_bridge, veth_host) pairs stitched for it, so
    # teardown can undo exactly what realize created (stored as plain strings so
    # the field type stays independent of `GloveboxSegment`, defined below)
    _stitched: dict[str, list[tuple[str, str]]] = field(
        default_factory=dict[str, list[tuple[str, str]]]
    )
    _cell_cids: dict[str, list[int]] = field(default_factory=dict[str, list[int]])

    def connector(self, fallback: GuestConnector) -> GuestConnector:
        """A `GuestConnector` serving this host's cells, deferring every other cid to `fallback` (the real vsock dial)."""
        return glovebox_connector(self.cells, fallback)

    async def realize(self, plan: "ResolvedPlan", project: str) -> None:
        """Bind each configured glovebox guest to its cell at the plan-reserved cid, then stitch its segment bridge out to the node netns so the cell reaches the range's guests.

        A glovebox guest with no configured container is bound neither to a cell nor a stitch (routing it would fail loudly at dial, which is the honest outcome for a missing cell). Stitch failures propagate: a half-stitched segment is worse than a refused realize.
        """
        cids: list[int] = []
        for guest in plan.guests:
            if guest.provider == "glovebox" and guest.name in self.containers:
                container_id = self.containers[guest.name]
                executor = (
                    self.executor_factory(container_id)
                    if self.executor_factory is not None
                    else CrictlCellExecutor(
                        container_id=container_id, crictl=self.crictl
                    )
                )
                self.cells[guest.cid] = CellConnection(executor=executor)
                cids.append(guest.cid)
        self._cell_cids[project] = cids
        segments = [
            segment
            for segment in glovebox_segments(plan)
            if any(
                guest.provider == "glovebox"
                and guest.name in self.containers
                and segment.attacker_ip in {str(nic.ip) for nic in guest.interfaces}
                for guest in plan.guests
            )
        ]
        if not segments:
            return
        netns_pid = await self.netns_pid_fn(project)
        stitched: list[tuple[str, str]] = []
        for index, segment in enumerate(segments):
            veth_host, veth_peer = _veth_names(project, index)
            await self.root_runner(
                stitch_commands(
                    segment,
                    netns_pid=netns_pid,
                    veth_host=veth_host,
                    veth_peer=veth_peer,
                )
            )
            stitched.append((segment.node_bridge, veth_host))
        self._stitched[project] = stitched

    async def teardown(self, project: str) -> None:
        """Unstitch every segment this host stitched for `project` and drop its cells; tolerant and idempotent (teardown must not raise over an already-gone device).

        The undo mirrors `unstitch_commands` (deleting the host veth takes its in-netns peer with it, then the node bridge goes), built here from the recorded `(node_bridge, veth_host)` so teardown needs no live plan.
        """
        for node_bridge, veth_host in self._stitched.pop(project, []):
            try:
                await self.root_runner(
                    [
                        ["ip", "link", "del", veth_host],
                        ["ip", "link", "del", node_bridge],
                    ]
                )
            except OSError as error:
                logger.warning("glovebox unstitch of %s failed: %s", project, error)
        for guest_cid in self._cell_cids.pop(project, []):
            self.cells.pop(guest_cid, None)


# ---------------------------------------------------------------------------
# Bridge-netns handshake (contract part 2): make a glovebox segment's bridge
# node-reachable (route2-full blocker #2)
# ---------------------------------------------------------------------------

# METHOD CHOSEN: (b) a veth pair stitching the range container's in-netns
# segment bridge to a node-side bridge.
#
# WHY (b) over (a): Ranges' applier runs every segment bridge INSIDE the
# hardened range container's network namespace (`_compiler/render.py`: the
# `range` service is `network_mode: none` and creates the bridges from
# `netns/bridges.txt` in its own netns). A node-level Kata CNI
# (`00-gb-dmz.conflist`) operates in the NODE netns and cannot see a bridge that
# lives in the container netns. Method (a) -- emitting the glovebox segment's
# bridge in the node netns instead -- would fork the applier's single
# bridge-creation path and move the range's own guest taps (web, db) out of the
# hardened netns, widening the range's blast radius for the sake of one segment.
# Method (b) leaves the applier's netns model untouched: the range keeps ALL its
# bridges and taps inside its hardened netns exactly as today; we add only a
# single L2 veth from the glovebox segment's bridge out to a node-side bridge the
# cell's CNI attaches to. The provider marker already reserves the attacker's
# {ip, mac} on that segment and emits the bridge (part 1); this stitch is the
# minimal node-reachability glue, created after the range is up and removed at
# teardown. The node-side end is where glovebox's peer/open-tier CNI attaches the
# cell on the Ranges-reserved address, so glovebox's node egress filter still
# governs the card.


@dataclass(frozen=True)
class GloveboxSegment:
    """A range segment that carries a `provider: glovebox` guest, with the facts the stitch and the cell's CNI need.

    `range_bridge` is the bridge inside the range container's netns (the applier's own device); `node_bridge` is the node-netns bridge this stitch creates and the cell's CNI attaches to. `attacker_ip`/`attacker_mac` are the addresses Ranges reserved for the externally-supplied guest on this segment (part 1), which the cell must take so the range's addressing and ACLs treat it as that guest.
    """

    network: str
    range_bridge: str
    node_bridge: str
    cidr: str
    gateway: str | None
    attacker_ip: str
    attacker_mac: str


def glovebox_segments(plan: "ResolvedPlan") -> list[GloveboxSegment]:
    """The segments that host a `provider: glovebox` guest, each with its reserved attacker address.

    A glovebox guest is not booted by Ranges, but its `InterfaceAllocation`s still carry the reserved per-segment {ip, mac} (the provider marker keeps the allocation). One `GloveboxSegment` is emitted per (glovebox guest, interface) pair; a node bridge name is derived from the network so repeated calls are stable.
    """
    by_network = {network.name: network for network in plan.networks}
    segments: list[GloveboxSegment] = []
    for guest in plan.guests:
        if guest.provider != "glovebox":
            continue
        for interface in guest.interfaces:
            network = by_network[interface.network]
            gateway = (
                str(network.hypervisor_address)
                if network.hypervisor_address is not None
                else None
            )
            segments.append(
                GloveboxSegment(
                    network=network.name,
                    range_bridge=network.bridge,
                    node_bridge=_node_bridge_name(network.name),
                    cidr=str(network.cidr),
                    gateway=gateway,
                    attacker_ip=str(interface.ip),
                    attacker_mac=interface.mac,
                )
            )
    return segments


def _node_bridge_name(network: str) -> str:
    """A node-netns bridge name for `network`, capped to the 15-char Linux ifname limit."""
    name = f"gbx-{network}"
    return name[:15]


def stitch_commands(
    segment: GloveboxSegment,
    *,
    netns_pid: int,
    veth_host: str,
    veth_peer: str,
) -> list[list[str]]:
    """The root `ip`/`nsenter` argv sequence stitching `segment.range_bridge` (in the range netns at `netns_pid`) to `segment.node_bridge` (node netns) over a veth pair.

    After this runs, the node bridge and the in-range segment bridge share one L2 domain, so a cell attached to the node bridge reaches the range's guests (web, db) on that segment directly, and the range's router/ACLs see the cell's frames as the reserved attacker address. Idempotent `add`s are the caller's concern (the helper emits the create-once sequence); teardown is `unstitch_commands`.
    """
    return [
        ["ip", "link", "add", "name", segment.node_bridge, "type", "bridge"],
        ["ip", "link", "set", segment.node_bridge, "up"],
        ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_peer],
        ["ip", "link", "set", veth_peer, "netns", str(netns_pid)],
        ["ip", "link", "set", veth_host, "master", segment.node_bridge],
        ["ip", "link", "set", veth_host, "up"],
        [
            "nsenter",
            "-t",
            str(netns_pid),
            "-n",
            "ip",
            "link",
            "set",
            veth_peer,
            "master",
            segment.range_bridge,
        ],
        ["nsenter", "-t", str(netns_pid), "-n", "ip", "link", "set", veth_peer, "up"],
    ]


def unstitch_commands(segment: GloveboxSegment, *, veth_host: str) -> list[list[str]]:
    """Tear down the stitch: deleting the host veth end removes its peer, then the node bridge goes."""
    return [
        ["ip", "link", "del", veth_host],
        ["ip", "link", "del", segment.node_bridge],
    ]


def cell_cni_conflist(
    segment: GloveboxSegment, *, name: str = "gb-dmz", ipam_range_start: int = 20
) -> dict[str, object]:
    """A bridge-CNI conflist (glovebox's peer/open-tier primitive) pointing the cell at `segment.node_bridge` on the segment CIDR.

    Mirrors glovebox's `config/kata/probe-cni.conflist` re-pointed from the probe bridge to the node-side glovebox bridge. The host-local IPAM range starts above the reserved low addresses; for a single cell on a known reserved address, the operator pins `attacker_ip`. Named `00-<name>.conflist` on disk so containerd's lexically-first pick lands here (the sort-order gotcha from route2-build).
    """
    network = segment.cidr.rsplit("/", 1)[0]
    octets = network.split(".")
    range_start = ".".join(octets[:3] + [str(ipam_range_start)])
    range_end = ".".join(octets[:3] + ["99"])
    plugin: dict[str, object] = {
        "type": "bridge",
        "bridge": segment.node_bridge,
        "isGateway": False,
        "ipMasq": False,
        "ipam": {
            "type": "host-local",
            "ranges": [
                [
                    {
                        "subnet": segment.cidr,
                        "rangeStart": range_start,
                        "rangeEnd": range_end,
                    }
                ]
            ],
        },
    }
    if segment.gateway is not None:
        plugin["ipam"] = {
            **plugin["ipam"],  # type: ignore[dict-item]
            "gateway": segment.gateway,
        }
    return {
        "cniVersion": "1.0.0",
        "name": name,
        "plugins": [plugin],
    }
