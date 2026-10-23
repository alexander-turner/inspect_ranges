"""The tap-fd attachment: build the external attack box's NICs inside the range netns and hand the fds out.

The invariant this module exists to preserve (`architecture.md`: the host netns carries zero range state while a range runs): the external VMM gets its NIC as an OPEN TAP FD created inside the range container's network namespace, never as a device name it cannot resolve and never as a veth or bridge leg reaching into the host netns. A short verbatim helper (`ATTACH_HELPER_SOURCE`, the capture-supervisor pattern) runs inside the range container as root over the same `docker compose exec` transport as the boot script: it opens `/dev/net/tun`, `TUNSETIFF`s one non-persistent tap per attacker interface (so the fd IS the tap's lifetime), applies the libvirt tap-MAC rule, enslaves each tap to its segment bridge, then connects to a host-side unix listener in the shared vsock directory and ships the fds over `SCM_RIGHTS`. The host receives them in the realizing process and hands them to the provider in-process; the fd plumbing never crosses the public seam.

The taps are created with `IFF_VNET_HDR`, matching what QEMU and Cloud Hypervisor request when they create taps themselves, so virtio offload negotiation works for an external VMM consuming the fd; a provider that cannot use the header may still read/write raw frames after `TUNSETVNETHDRSZ`. Teardown needs nothing from this module: a non-persistent tap dies when its last fd closes, and unconditionally when the range container's netns is destroyed; `down` tears the provider first, so the external VMM never outlives its NIC.
"""

import array
import os
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._channel.vsock import peer_uid
from .backend import AttachedInterface, FootholdAttachment

if TYPE_CHECKING:
    from .._runtime.up import BootGuest

ATTACH_TIMEOUT_S = 60.0
"""How long the host waits for the in-container helper to build the taps and connect back."""

ATTACH_HELPER_SOURCE = '''\
"""Attack-box attach helper: runs as root inside the range container (its netns IS the range netns).

Config arrives as JSON in argv[1] (every value shape-validated host-side by `BootPlan` before interpolation). For each interface: open /dev/net/tun, TUNSETIFF a non-persistent IFF_TAP|IFF_NO_PI|IFF_VNET_HDR device, set the fe:-prefixed tap MAC BEFORE enslaving (the bridge adopts its lowest port MAC; a random tap MAC would leak onto the segment), enslave to the segment bridge, bring it up. Then connect to the handoff socket and send one JSON line plus every tap fd via SCM_RIGHTS; wait for the one-byte ack so the fds are known-received before this process (and its fd copies) exits. Any failure tracebacks to stderr and exits nonzero: the host fails the attach stage with it.
"""

import array
import fcntl
import json
import socket
import struct
import subprocess
import sys

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFF_VNET_HDR = 0x4000


def main() -> None:
    config = json.loads(sys.argv[1])
    fds = []
    taps = []
    for spec in config["interfaces"]:
        fd = open("/dev/net/tun", "rb+", buffering=0)
        name = spec["tap"]
        ifr = struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI | IFF_VNET_HDR)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        subprocess.run(["ip", "link", "set", name, "address", spec["tap_mac"]], check=True)
        subprocess.run(["ip", "link", "set", name, "master", spec["bridge"]], check=True)
        subprocess.run(["ip", "link", "set", name, "up"], check=True)
        fds.append(fd)
        taps.append(name)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(config["socket"])
        payload = json.dumps({"taps": taps}).encode()
        rights = array.array("i", [fd.fileno() for fd in fds])
        client.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
        ack = client.recv(1)
    if ack != b"1":
        raise SystemExit("handoff not acknowledged; taps die with this process")


main()
'''


class AttachError(Exception):
    """The attachment did not complete; the message carries the helper's stderr or the handoff failure."""


def tap_name(cid: int, index: int) -> str:
    """The external attack box's per-NIC tap device name: CID-derived like the Cloud Hypervisor scheme (`ch{cid}n{index}`), distinct prefix so a review of a live netns tells the two apart, within IFNAMSIZ."""
    return f"ab{cid}n{index}"


def tap_mac(mac: str) -> str:
    """The tap-device MAC for a guest MAC: first octet `fe`, the libvirt rule the boot script also applies (`up.py`), so the bridge never adopts a MAC that would leak onto the segment."""
    return f"fe{mac[2:]}"


def helper_config(guest: "BootGuest", container_socket: str) -> dict[str, Any]:
    """The attach helper's argv[1] config for one attacker entry: tap name, tap MAC, and bridge per interface, plus the in-container handoff socket path. Pure; every value is already shape-validated by `BootPlan`."""
    return {
        "socket": container_socket,
        "interfaces": [
            {
                "tap": tap_name(guest.cid, index),
                "tap_mac": tap_mac(nic.mac),
                "bridge": nic.bridge,
            }
            for index, nic in enumerate(guest.interfaces)
        ],
    }


@dataclass(frozen=True)
class AttachInvocation:
    """Everything the attacher needs to run the helper and receive the fds; built by `up`, injectable for tests."""

    argv: list[str]
    """The `docker compose exec ... python3 - <config-json>` command."""
    env: dict[str, str]
    source: str
    """The helper program, fed on stdin (`ATTACH_HELPER_SOURCE`)."""
    host_socket: Path
    """Where the host listens for the handoff (the shared vsock dir, so the container sees the same socket)."""
    expected_fds: int
    timeout: float = ATTACH_TIMEOUT_S


Attacher = Callable[[AttachInvocation], list[int]]
"""Runs the helper and returns one open tap fd per attacker interface, in interface order. Injectable so `up`'s attach stage is tested without a container; the default is `run_attacher`."""


def receive_fds(listener: socket.socket, expected: int, timeout: float) -> list[int]:
    """Accept the helper's connection and receive `expected` fds via `SCM_RIGHTS`, acking so the sender may exit.

    The handoff socket sits in the shared vsock directory, which the range container mounts, so every in-container uid (the unprivileged VMMs foremost) can connect to it during the window: the accept loop therefore requires the peer to be the compose-exec root helper (`SO_PEERCRED`, the same check discipline as every exec dial: host uid 0 under rootful docker, the invoking user's uid under rootless, and never a VMM's per-guest uid) and keeps accepting until a credentialed peer or the deadline, so a hostile connector can neither hand over fds nor starve the real helper of its slot. Every blocking step is deadline-bounded (B21: the failure path is as bounded as the boot path), truncated ancillary data (`MSG_CTRUNC`) refuses, and received fds are marked non-inheritable (a provider passing them to its VMM does so explicitly, e.g. `pass_fds`).

    Raises:
        AttachError: No credentialed helper connected within `timeout`, the handoff was truncated, or it carried the wrong fd count (any received fds are closed before raising; half an attachment is worse than none).
    """
    deadline = time.monotonic() + timeout
    anomaly: str | None = None

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise AttachError(
                f"helper never completed the handoff within {timeout:.0f}s"
                + (f" (last anomaly: {anomaly})" if anomaly else "")
            )
        return left

    while True:
        listener.settimeout(remaining())
        try:
            connection, _ = listener.accept()
        except TimeoutError as error:
            raise AttachError(
                f"helper never connected to the handoff socket within {timeout:.0f}s"
                + (f" (last anomaly: {anomaly})" if anomaly else "")
            ) from error
        with connection:
            if peer_uid(connection) not in (0, os.getuid()):
                continue  # not the root helper; keep the slot open for it
            # a credentialed stray (another same-uid process probing sockets)
            # must not abort the attach either: bound its recv so it cannot
            # eat the window, note the anomaly, and keep awaiting the helper
            connection.settimeout(min(remaining(), 10.0))
            try:
                space = socket.CMSG_SPACE(expected * array.array("i").itemsize)
                payload, ancillary, flags, _ = connection.recvmsg(4096, space)
            except TimeoutError:
                anomaly = "a credentialed peer connected but sent nothing"
                continue
            fds: list[int] = []
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received = array.array("i")
                    received.frombytes(
                        data[: len(data) - (len(data) % received.itemsize)]
                    )
                    fds.extend(received.tolist())
            if flags & socket.MSG_CTRUNC or len(fds) != expected:
                for fd in fds:
                    os.close(fd)
                anomaly = (
                    f"a credentialed peer sent {len(fds)} fds for {expected} "
                    f"interfaces"
                    f"{' (ancillary truncated)' if flags & socket.MSG_CTRUNC else ''}:"
                    f" {payload!r}"
                )
                continue
            for fd in fds:
                os.set_inheritable(fd, False)
            connection.sendall(b"1")
        return fds


def run_attacher(invocation: AttachInvocation) -> list[int]:
    """The default `Attacher`: bind the handoff listener, run the helper in the range container, receive the fds, and require the helper's clean exit.

    The listener binds BEFORE the helper starts (the helper connects, so there is no race), world-connectable because the container's root is not this uid; the private 0700 per-user root of the vsock dir bounds who can reach the path at all, and the socket is removed as soon as the handoff completes.

    Raises:
        AttachError: The helper failed, timed out, or the handoff was short; the message carries the helper's stderr tail.
    """
    invocation.host_socket.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(invocation.host_socket))
        os.chmod(invocation.host_socket, 0o666)
        listener.listen(4)
        process = subprocess.Popen(
            invocation.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=invocation.env,
        )
        delivered = False
        try:
            assert process.stdin is not None  # Popen with stdin=PIPE guarantees it
            # the helper reads its program to EOF before executing, so stdin
            # closes NOW; detach it from the Popen so communicate() below does
            # not flush the already-closed pipe
            process.stdin.write(invocation.source.encode())
            process.stdin.close()
            process.stdin = None
            try:
                fds = receive_fds(listener, invocation.expected_fds, invocation.timeout)
            except AttachError as error:
                process.kill()
                _, stderr = process.communicate(timeout=10.0)
                raise AttachError(
                    f"{error} (helper stderr: {stderr.decode('utf-8', 'replace').strip()[-800:]})"
                ) from error
            try:
                _, stderr = process.communicate(timeout=invocation.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate(timeout=10.0)
            if process.returncode != 0:
                for fd in fds:
                    os.close(fd)
                raise AttachError(
                    "helper exited "
                    f"{process.returncode}: {stderr.decode('utf-8', 'replace').strip()[-800:]}"
                )
            delivered = True
        finally:
            invocation.host_socket.unlink(missing_ok=True)
            if not delivered and process.poll() is None:
                # an unexpected escape (connection reset, interrupt) must not
                # orphan the root helper un-reaped
                process.kill()
                try:
                    process.communicate(timeout=10.0)
                except subprocess.TimeoutExpired:
                    pass
    return fds


def attachment_from_boot(
    guest: "BootGuest",
    *,
    project: str,
    fds: list[int],
    seed_dir: Path | None,
) -> FootholdAttachment:
    """Fold one attacker `boot.json` entry plus its received tap fds into the provider's `FootholdAttachment`. Pure.

    Raises:
        ValueError: The entry lacks the attacker address facts (a bundle rendered before they existed) or sizing; the caller folds this into its re-render refusal.
    """
    if guest.cpus is None or guest.memory_mb is None:
        raise ValueError(f"attacker entry {guest.name!r} carries no sizing")
    interfaces: list[AttachedInterface] = []
    for nic, fd in zip(guest.interfaces, fds, strict=True):
        if nic.network is None or nic.ip is None or nic.prefixlen is None:
            raise ValueError(
                f"attacker entry {guest.name!r} carries no address facts "
                "(bundle rendered before attack-box support); re-render the bundle"
            )
        interfaces.append(
            AttachedInterface(
                segment=nic.network,
                bridge=nic.bridge,
                tap_fd=fd,
                mac=nic.mac,
                ip=IPv4Address(nic.ip),
                prefixlen=nic.prefixlen,
                gateway=IPv4Address(nic.gateway) if nic.gateway is not None else None,
            )
        )
    return FootholdAttachment(
        project=project,
        guest_name=guest.name,
        cid=guest.cid,
        cpus=guest.cpus,
        memory_mb=guest.memory_mb,
        interfaces=tuple(interfaces),
        seed_dir=seed_dir,
    )
