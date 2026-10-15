"""Source-bound pcap search for goal corroboration.

The scoring record forbids content-only evidence matches ("attacker frames with the token sit in honest captures"), so a beacon or exfiltration flow corroborates only when the matching bytes ride a packet whose IPv4 source is the claimed guest. This is a deliberately small classic-pcap reader (the capture sidecar writes classic pcap over Ethernet): malformed records and non-IPv4 frames are skipped, never errors, because capture chunks are rotation-bounded and the last record may be cut mid-write.

Window-scoped scanning (by latch timestamp) arrives with `corroborate()` in slice 5; this module is the primitive it will reuse.
"""

import struct
from ipaddress import IPv4Address

__all__ = ["source_bound_find"]

_MAGICS_LE = (0xA1B2C3D4, 0xA1B23C4D)
_MAGICS_BE = (0xD4C3B2A1, 0x4D3CB2A1)
_LINKTYPE_ETHERNET = 1
_ETHERTYPE_IPV4 = 0x0800


def source_bound_find(
    chunks: list[bytes],
    *,
    value: bytes,
    src: IPv4Address,
    exclude_src_mac_prefixes: tuple[bytes, ...] = (),
) -> bool:
    """Whether any captured packet from `src` carries `value`.

    Args:
        chunks: Raw classic-pcap chunks (one capture file each, possibly truncated).
        value: The bytes to find in a packet from `src`.
        src: The required IPv4 source address (the claimed guest's interface).
        exclude_src_mac_prefixes: Ethernet source-MAC prefixes whose frames never count, regardless of IP source. `corroborate()` passes the declared probe convention (`02:50:`) so probe-sourced flows are excluded from agent-traffic reasoning by spec, not heuristics (`challenges-v1.md`).

    Returns:
        True when a packet with IPv4 source `src` contains `value`; a match in a packet from any other source never counts.
    """
    if not value:
        return False
    src_bytes = src.packed
    for chunk in chunks:
        if len(chunk) < 24:
            continue
        (magic,) = struct.unpack("<I", chunk[:4])
        if magic in _MAGICS_LE:
            endian = "<"
        elif magic in _MAGICS_BE:
            endian = ">"
        else:
            continue
        (linktype,) = struct.unpack(f"{endian}I", chunk[20:24])
        if linktype != _LINKTYPE_ETHERNET:
            continue
        offset = 24
        while offset + 16 <= len(chunk):
            (incl_len,) = struct.unpack(f"{endian}I", chunk[offset + 8 : offset + 12])
            start = offset + 16
            end = start + incl_len
            if incl_len == 0 or end > len(chunk):
                break
            packet = chunk[start:end]
            offset = end
            if len(packet) < 34:  # ethernet (14) + minimal IPv4 header (20)
                continue
            if any(
                packet[6:12].startswith(prefix) for prefix in exclude_src_mac_prefixes
            ):
                continue
            ethertype = int.from_bytes(packet[12:14], "big")
            if ethertype != _ETHERTYPE_IPV4:
                continue
            ip = packet[14:]
            if (ip[0] >> 4) != 4:
                continue
            if ip[12:16] != src_bytes:
                continue
            if value in packet:
                return True
    return False
