"""Mechanism (c): a userspace AF_PACKET prober with no IP presence at all.

Runs inside a NET_RAW-only sidecar sharing the range container's netns, bound to the segment bridge. It fabricates a locally-administered MAC and an unassigned IP, resolves the target with its own ARP, hand-rolls a minimal TCP client (SYN, ACK, one GET, cumulative ACKs, RST close) with real checksums, and answers ARP for its fabricated IP for the session's duration. The kernel never owns the identity, so nothing pings, nothing RSTs, and nothing enters any neighbor cache from our side; the cost is exactly this file: a userspace TCP implementation sufficient for one HTTP exchange.

Usage: rawprobe.py <iface> <src_mac> <src_ip> <dst_ip> <dport> <nonce> [timeout_s]
Prints: RTT_MS <float> / BODY <hex> on success; exits 1 on timeout.
"""

import random
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
BCAST = b"\xff\xff\xff\xff\xff\xff"


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


class Probe:
    def __init__(
        self, iface: str, src_mac: str, src_ip: str, dst_ip: str, dport: int
    ) -> None:
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.2)
        self.smac = mac_bytes(src_mac)
        self.sip = socket.inet_aton(src_ip)
        self.dip = socket.inet_aton(dst_ip)
        self.dmac = b""
        self.dport = dport
        self.sport = random.randint(40000, 60000)
        self.seq = random.randint(0, 0xFFFF0000)
        self.ack = 0
        self.ip_id = random.randint(0, 0xFFFF)

    def eth(self, dst: bytes, ethertype: int) -> bytes:
        return dst + self.smac + struct.pack("!H", ethertype)

    def arp_request(self) -> bytes:
        return self.eth(BCAST, 0x0806) + struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            1,
            self.smac,
            self.sip,
            b"\x00" * 6,
            self.dip,
        )

    def arp_reply(self, to_mac: bytes, to_ip: bytes) -> bytes:
        return self.eth(to_mac, 0x0806) + struct.pack(
            "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, self.smac, self.sip, to_mac, to_ip
        )

    def answer_arp(self, frame: bytes) -> None:
        """Reply to who-has for our fabricated IP; the target needs this to speak to us."""
        if len(frame) >= 42 and frame[12:14] == b"\x08\x06":
            op = struct.unpack("!H", frame[20:22])[0]
            if op == 1 and frame[38:42] == self.sip:
                self.sock.send(self.arp_reply(frame[22:28], frame[28:32]))

    def tcp(self, flags: int, payload: bytes = b"") -> bytes:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        total = 20 + 20 + len(payload)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total,
            self.ip_id,
            0x4000,
            64,
            6,
            0,
            self.sip,
            self.dip,
        )
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        tcp = struct.pack(
            "!HHIIBBHHH",
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            5 << 4,
            flags,
            65535,
            0,
            0,
        )
        pseudo = self.sip + self.dip + struct.pack("!BBH", 0, 6, 20 + len(payload))
        checksum = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack("!H", checksum) + tcp[18:]
        return self.eth(self.dmac, 0x0800) + ip + tcp + payload

    def match_tcp(self, frame: bytes) -> tuple[int, int, int, bytes] | None:
        """Return (flags, seq, ack, payload) when the frame is our flow's reply."""
        if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
            return None
        ihl = (frame[14] & 0x0F) * 4
        if frame[26:30] != self.dip or frame[30:34] != self.sip:
            return None
        o = 14 + ihl
        sport, dport = struct.unpack("!HH", frame[o : o + 4])
        if sport != self.dport or dport != self.sport:
            return None
        seq, ack = struct.unpack("!II", frame[o + 4 : o + 12])
        doff = (frame[o + 12] >> 4) * 4
        flags = frame[o + 13]
        total = struct.unpack("!H", frame[16:18])[0]
        payload = frame[14 + ihl + doff : 14 + total]
        return flags, seq, ack, payload

    def pump(self, deadline: float) -> tuple[int, int, int, bytes] | None:
        """Receive until a frame for our flow arrives, answering ARP along the way."""
        while time.monotonic() < deadline:
            try:
                frame = self.sock.recv(65535)
            except socket.timeout:
                continue
            self.answer_arp(frame)
            hit = self.match_tcp(frame)
            if hit:
                return hit
        return None

    def resolve(self, deadline: float) -> bool:
        while time.monotonic() < deadline:
            self.sock.send(self.arp_request())
            step = min(deadline, time.monotonic() + 1.0)
            while time.monotonic() < step:
                try:
                    frame = self.sock.recv(65535)
                except socket.timeout:
                    continue
                self.answer_arp(frame)
                if (
                    len(frame) >= 42
                    and frame[12:14] == b"\x08\x06"
                    and struct.unpack("!H", frame[20:22])[0] == 2
                    and frame[28:32] == self.dip
                ):
                    self.dmac = frame[22:28]
                    return True
        return False

    def fetch(self, request: bytes, deadline: float) -> bytes | None:
        for _ in range(3):
            self.sock.send(self.tcp(0x02))  # SYN
            hit = self.pump(min(deadline, time.monotonic() + 2.0))
            if hit and hit[0] & 0x12 == 0x12:  # SYN-ACK
                break
        else:
            return None
        _, srv_seq, _, _ = hit
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        self.ack = (srv_seq + 1) & 0xFFFFFFFF
        self.sock.send(self.tcp(0x10))  # ACK
        self.sock.send(self.tcp(0x18, request))  # PSH|ACK
        self.seq = (self.seq + len(request)) & 0xFFFFFFFF
        body = b""
        while time.monotonic() < deadline:
            hit = self.pump(deadline)
            if hit is None:
                return None
            flags, seq, _, payload = hit
            if payload and seq == self.ack:
                body += payload
                self.ack = (self.ack + len(payload)) & 0xFFFFFFFF
                self.sock.send(self.tcp(0x10))
            if flags & 0x01:  # FIN: ack it, reset, done
                self.ack = (self.ack + 1) & 0xFFFFFFFF
                self.sock.send(self.tcp(0x10))
                self.sock.send(self.tcp(0x04))
                return body
            if flags & 0x04:  # RST from the server
                return body or None
        return None


def main() -> int:
    iface, src_mac, src_ip, dst_ip, dport, nonce = sys.argv[1:7]
    timeout = float(sys.argv[7]) if len(sys.argv) > 7 else 10.0
    probe = Probe(iface, src_mac, src_ip, dst_ip, int(dport))
    deadline = time.monotonic() + timeout
    if not probe.resolve(deadline):
        print("ARP_TIMEOUT", file=sys.stderr)
        return 1
    request = f"GET /probe?n={nonce} HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n".encode()
    start = time.monotonic()
    body = probe.fetch(request, deadline)
    if body is None:
        print("TCP_TIMEOUT", file=sys.stderr)
        return 1
    elapsed = (time.monotonic() - start) * 1000.0
    text = body.split(b"\r\n\r\n", 1)[-1].strip().decode(errors="replace")
    print(f"RTT_MS {elapsed:.1f}")
    print(f"BODY {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
