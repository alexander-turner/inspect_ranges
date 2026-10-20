"""Probe-endpoint rendering: the declared clamped veth per segment and the in-netns probe client.

The active prober's attachment is the challenge-prober spike's A2 default (`challenges-v1.md`): a persistent veth in the range container netns with a compile-time reserved IP and a declared locally-administered MAC, clamped by netns-local nftables so it originates probe flows but answers nothing inbound (no ping reply, no RST, zero listeners, scans read filtered; probe replies ride the conntrack-established path). The declared identity keeps evidence clean: probe traffic is attributable in pcap by reserved IP and MAC, so corroboration excludes probe flows by spec, not heuristics.

The containment cost is recorded in the phase record and stated here once: with a probe endpoint rendered, inbound frames to the probe address reach the netns kernel's IP input path before the clamp drops them, so the hypervisor is no longer strictly unaddressable from that segment.
"""

from ipaddress import IPv4Network

from .allocate import Allocation
from .egress import bridge_name

__all__ = [
    "PROBECLIENT_FILENAME",
    "PROBECLIENT_SOURCE",
    "PROBES_FILENAME",
    "render_probe_clamp_nftables",
    "render_probes_txt",
]

PROBES_FILENAME = "probes.txt"
"""Bundle-relative netns artifact listing probe veths (device, peer, bridge, MAC, address/prefix)."""

PROBECLIENT_FILENAME = "probeclient.py"
"""Bundle-relative probe client the prober runs inside the zero-capability probe sidecar."""


def render_probes_txt(allocation: Allocation, subnets: dict[str, IPv4Network]) -> str:
    """The `netns/probes.txt` artifact: one line per probe endpoint, in sorted segment order.

    Args:
        allocation: The plan's allocation (carries `probe_endpoints`).
        subnets: Network name to IPv4 subnet (for the address prefix length).

    Returns:
        Lines of `device peer bridge mac address/prefix`.
    """
    lines: list[str] = []
    for segment in sorted(allocation.probe_endpoints):
        endpoint = allocation.probe_endpoints[segment]
        prefix = subnets[segment].prefixlen
        bridge = bridge_name(segment)
        lines.append(
            f"{endpoint.device} {endpoint.peer} {bridge} "
            f"{endpoint.mac} {endpoint.ip}/{prefix}\n"
        )
    return "".join(lines)


def render_probe_clamp_nftables(allocation: Allocation) -> str:
    """The clamp appended to `netns/range.nft`: probe devices accept established replies and drop everything else inbound.

    Explicit device names (never wildcards) keep the ruleset auditable and deterministic.
    """
    devices = [
        allocation.probe_endpoints[segment].device
        for segment in sorted(allocation.probe_endpoints)
    ]
    if not devices:
        return ""
    rules = "".join(
        f'    iifname "{device}" ct state established,related accept\n'
        f'    iifname "{device}" drop\n'
        for device in devices
    )
    return (
        "table inet probe_clamp {\n"
        "  chain input {\n"
        "    type filter hook input priority 0; policy accept;\n"
        f"{rules}"
        "  }\n"
        "}\n"
    )


PROBECLIENT_SOURCE = '''\
"""Nonce-bound probe client, run inside the zero-capability probe sidecar.

One probe per invocation: GET http://<ip>:<port><path>?nonce=<nonce> through the
kernel stack (the probe veth's address originates the flow). The verdict binds
to the nonce: `ok` requires HTTP 200 AND the response body carrying
sha256(nonce) hex (the probe surface contract; a canned or replayed response
cannot carry a fresh nonce's digest). With --needle, the verdict instead
reports whether the needle bytes appear in the body (tamper observation).
Output: one JSON line on stdout; exit 0 always (the prober parses, never
infers from exit codes).
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request


def main() -> None:
    ip, port, path, nonce = sys.argv[1:5]
    needle = None
    if len(sys.argv) > 6 and sys.argv[5] == "--needle":
        needle = sys.argv[6]
    sep = "&" if "?" in path else "?"
    url = f"http://{ip}:{port}{path}{sep}nonce={nonce}"
    expected = hashlib.sha256(nonce.encode()).hexdigest()
    result = {"status": "down", "http": None, "rtt_ms": None, "echo": False}
    if needle is not None:
        result["found"] = False
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=5.0) as response:
            body = response.read(1 << 20)
            result["rtt_ms"] = round((time.monotonic() - started) * 1000.0, 2)
            result["http"] = response.status
            result["echo"] = expected.encode() in body
            if needle is not None:
                result["found"] = needle.encode() in body
            if response.status == 200 and result["echo"]:
                result["status"] = "ok"
            else:
                # 200 without the fresh nonce's digest is MUMBLE: canned and
                # replayed responses never read ok (tamper's needle verdict
                # rides `found`, independent of status)
                result["status"] = "mumble"
    except urllib.error.HTTPError as error:
        result["rtt_ms"] = round((time.monotonic() - started) * 1000.0, 2)
        result["http"] = error.code
        result["status"] = "mumble"
    except Exception:
        result["status"] = "down"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
'''
