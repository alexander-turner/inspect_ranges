"""The tap-fd attachment: helper config, the SCM_RIGHTS handoff, and the attachment fold, without a container.

`run_attacher` is exercised end to end with a real subprocess fed a stand-in source over the same stdin+argv transport as the container helper; only the tap creation itself (root, `/dev/net/tun`) is out of scope here, held by the conformance battery on a live host.
"""

import json
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._attackbox.attach import (
    ATTACH_HELPER_SOURCE,
    AttachError,
    AttachInvocation,
    attachment_from_boot,
    helper_config,
    receive_fds,
    run_attacher,
    tap_mac,
    tap_name,
)
from inspect_ranges._runtime.up import BootGuest

FAKE_HELPER = """
import array, json, os, socket, sys
config = json.loads(sys.argv[1])
fds = [os.open(os.devnull, os.O_RDWR) for _ in config["interfaces"]]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(config["socket"])
    rights = array.array("i", fds).tobytes()
    client.sendmsg([b"{}"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
    ack = client.recv(1)
sys.exit(0 if ack == b"1" else 3)
"""


def attacker_entry(**overrides: Any) -> BootGuest:
    entry: dict[str, Any] = {
        "name": "attacker",
        "kind": "attacker",
        "cid": 3001,
        "image_file": "attack.qcow2",
        "overlay_gb": 10,
        "readiness": "cloud-init",
        "vmm": "cloud-hypervisor",
        "cpus": 2,
        "memory_mb": 2048,
        "interfaces": [
            {
                "bridge": "br-dmz",
                "mac": "52:54:00:aa:bb:cc",
                "network": "dmz",
                "ip": "10.80.10.2",
                "prefixlen": 24,
                "gateway": "10.80.10.1",
            }
        ],
    }
    entry.update(overrides)
    return BootGuest.model_validate(entry)


# -- naming and config (pure) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("cid", "index", "name"),
    [(3001, 0, "ab3001n0"), (99_999_999, 9, "ab99999999n9")],
)
def test_tap_name_is_cid_derived_and_fits_ifnamsiz(
    cid: int, index: int, name: str
) -> None:
    assert tap_name(cid, index) == name
    assert len(name) <= 15


def test_tap_mac_applies_the_libvirt_fe_rule() -> None:
    assert tap_mac("52:54:00:aa:bb:cc") == "fe:54:00:aa:bb:cc"


def test_helper_config_carries_tap_mac_bridge_per_interface() -> None:
    config = helper_config(attacker_entry(), container_socket="/run/ch-vsock/a.sock")
    assert config == {
        "socket": "/run/ch-vsock/a.sock",
        "interfaces": [
            {"tap": "ab3001n0", "tap_mac": "fe:54:00:aa:bb:cc", "bridge": "br-dmz"}
        ],
    }


def test_helper_source_compiles() -> None:
    compile(ATTACH_HELPER_SOURCE, "<attach-helper>", "exec")


# -- the handoff -----------------------------------------------------------------------


def test_receive_fds_round_trips_and_acks(tmp_path: Path) -> None:
    socket_path = tmp_path / "handoff.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        read_end, write_end = os.pipe()
        acked: list[bytes] = []

        def send() -> None:
            import array

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                rights = array.array("i", [read_end]).tobytes()
                client.sendmsg(
                    [b'{"taps": ["ab1n0"]}'],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
                acked.append(client.recv(1))

        sender = threading.Thread(target=send)
        sender.start()
        fds = receive_fds(listener, expected=1, timeout=5.0)
        sender.join()
    os.close(write_end)
    os.close(read_end)
    assert len(fds) == 1 and fds[0] != read_end, "the fd arrived as a new descriptor"
    os.fstat(fds[0])
    os.close(fds[0])
    assert acked == [b"1"]


def test_receive_fds_times_out_as_attach_error(tmp_path: Path) -> None:
    socket_path = tmp_path / "handoff.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        with pytest.raises(AttachError, match="never connected"):
            receive_fds(listener, expected=1, timeout=0.1)


def test_receive_fds_refuses_a_short_handoff(tmp_path: Path) -> None:
    socket_path = tmp_path / "handoff.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)

        def send_nothing() -> None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b"{}")
                client.recv(1)  # the refused side closes without acking

        sender = threading.Thread(target=send_nothing)
        sender.start()
        with pytest.raises(AttachError, match="0 fds for 1"):
            receive_fds(listener, expected=1, timeout=5.0)
        sender.join()


def _invocation(
    tmp_path: Path, expected: int = 1, source: str = FAKE_HELPER
) -> AttachInvocation:
    socket_path = tmp_path / "handoff.sock"
    config: dict[str, Any] = {
        "socket": str(socket_path),
        "interfaces": [{} for _ in range(expected)],
    }
    return AttachInvocation(
        argv=[sys.executable, "-", json.dumps(config)],
        env=dict(os.environ),
        source=source,
        host_socket=socket_path,
        expected_fds=expected,
        timeout=10.0,
    )


def test_run_attacher_round_trips_fds_through_a_real_process(tmp_path: Path) -> None:
    """The whole orchestration (bind, spawn, receive, ack, clean exit) with a stand-in helper over the production stdin+argv transport."""
    invocation = _invocation(tmp_path, expected=2)
    fds = run_attacher(invocation)
    assert len(fds) == 2
    for fd in fds:
        os.fstat(fd)
        os.close(fd)
    assert not invocation.host_socket.exists(), "the handoff socket is removed"


def test_run_attacher_surfaces_the_helper_stderr_on_failure(tmp_path: Path) -> None:
    broken = "import sys; sys.stderr.write('no such bridge br-x'); sys.exit(2)"
    with pytest.raises(AttachError, match="no such bridge br-x"):
        run_attacher(_invocation(tmp_path, source=broken))


# -- the attachment fold ---------------------------------------------------------------


def test_attachment_from_boot_folds_facts_and_fds(tmp_path: Path) -> None:
    fd = os.open(os.devnull, os.O_RDWR)
    attachment = attachment_from_boot(
        attacker_entry(), project="ir-x", fds=[fd], seed_dir=tmp_path
    )
    nic = attachment.interfaces[0]
    assert (attachment.guest_name, attachment.cid) == ("attacker", 3001)
    assert (attachment.cpus, attachment.memory_mb) == (2, 2048)
    assert (nic.segment, nic.bridge, nic.tap_fd) == ("dmz", "br-dmz", fd)
    assert (str(nic.ip), nic.prefixlen, str(nic.gateway)) == (
        "10.80.10.2",
        24,
        "10.80.10.1",
    )
    assert attachment.seed_dir == tmp_path
    os.close(fd)


def test_attachment_from_boot_refuses_missing_facts() -> None:
    entry = attacker_entry(
        interfaces=[{"bridge": "br-dmz", "mac": "52:54:00:aa:bb:cc"}]
    )
    fd = os.open(os.devnull, os.O_RDWR)
    try:
        with pytest.raises(ValueError, match="re-render"):
            attachment_from_boot(entry, project="ir-x", fds=[fd], seed_dir=None)
    finally:
        os.close(fd)
