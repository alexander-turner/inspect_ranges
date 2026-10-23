"""`FakeAttackBoxProvider`: the in-tree reference consumer of the attack-box seam, boot-nothing edition.

Test infrastructure (deliberately not shipped, like `LocalEndpoint`, which it serves: real argv run on this host). `boot` validates the handoff (every tap fd is a real open descriptor), then stands up a unix socket speaking the daemon wire protocol one request per connection, exactly the exec-surface shape the seam contracts on; `sandbox("attacker").exec` and the conformance battery drive it unmodified. Server registries are module-global so the fresh provider instance a later `resolve_attack_box` creates (teardown through `down`) still reaches the running server; a genuinely fresh process finds nothing and no-ops, which teardown idempotency absorbs.
"""

import asyncio
import os
import socket
import threading
from pathlib import Path

from inspect_ranges._attackbox import (
    AttackBoxBackend,
    AttackBoxContext,
    AttackBoxHandle,
    FootholdAttachment,
)
from inspect_ranges._channel.vsock import HybridEndpoint, VsockStream
from inspect_ranges._runtime.ownership import ch_vsock_dir

from tests.applier_fixture import serve_guest
from tests.local_endpoint import LocalEndpoint

_SERVERS: dict[str, "_BoxServer"] = {}
_LOCK = threading.Lock()


class _BoxServer:
    """One fake box: a threaded unix-socket server answering guest-control requests via `LocalEndpoint`."""

    def __init__(self, guest: str, root: Path, socket_path: Path, fds: list[int]):
        self._endpoint = LocalEndpoint(guest, root)
        self._socket_path = socket_path
        self._fds = fds
        self._listener: socket.socket | None = None

    def start(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket_path.unlink(missing_ok=True)
        listener.bind(str(self._socket_path))
        listener.listen(16)
        self._listener = listener
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while True:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return  # stopped
            threading.Thread(
                target=self._serve_one, args=(connection,), daemon=True
            ).start()

    def _serve_one(self, connection: socket.socket) -> None:
        async def run() -> None:
            connection.setblocking(False)
            loop = asyncio.get_running_loop()
            # the hybrid-vsock preamble the dialer speaks (CONNECT <port> ->
            # OK <port>), byte-exact: everything after the newline is the
            # guest stream
            line = b""
            while not line.endswith(b"\n") and len(line) < 64:
                byte = await loop.sock_recv(connection, 1)
                if not byte:
                    connection.close()
                    return
                line += byte
            if not line.startswith(b"CONNECT "):
                connection.close()
                return
            port = line.decode().strip().split(" ", 1)[1]
            await loop.sock_sendall(connection, f"OK {port}\n".encode())
            await serve_guest(self._endpoint, VsockStream(connection))

        asyncio.run(run())

    def stop(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        self._socket_path.unlink(missing_ok=True)
        for fd in self._fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds = []


class FakeAttackBoxProvider:
    """Satisfies `AttackBoxProvider`: validates the attachment, serves the exec surface, owns nothing else."""

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir

    async def boot(self, attachment: FootholdAttachment) -> AttackBoxHandle:
        if not attachment.interfaces:
            raise ValueError("attachment carries no interfaces")
        for nic in attachment.interfaces:
            os.fstat(nic.tap_fd)  # the handoff delivered real open fds
        root = self._state_dir / "fake-box" / attachment.project
        root.mkdir(parents=True, exist_ok=True)
        socket_path = ch_vsock_dir(attachment.project) / "fake-box.sock"
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        server = _BoxServer(
            attachment.guest_name,
            root,
            socket_path,
            fds=[nic.tap_fd for nic in attachment.interfaces],
        )
        server.start()
        with _LOCK:
            _SERVERS[attachment.project] = server
        return AttackBoxHandle(
            exec_endpoint=HybridEndpoint(socket_path, os.getuid()),
            reclaim_token=attachment.project,
        )

    async def teardown(self, project: str, reclaim_token: str) -> None:
        with _LOCK:
            server = _SERVERS.pop(project, None)
        if server is not None:
            server.stop()


def factory(ctx: AttackBoxContext) -> AttackBoxBackend:
    """`INSPECT_RANGES_ATTACK_BOX=tests.fake_attackbox.factory` resolves here (CI, the battery's own tests)."""
    return AttackBoxBackend(provider=FakeAttackBoxProvider(ctx.state_dir))
