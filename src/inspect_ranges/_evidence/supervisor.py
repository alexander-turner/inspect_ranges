"""The capture-sidecar supervisor: a static python3 program rendered into every evidence-enabled bundle.

The sidecar is the evidence-capture answer from the evidence-capture spike: a separate compose service sharing the range container's network namespace with `CAP_NET_RAW` alone, so the range container's measured eight-capability floor does not grow and the pre-stream pcap chunks live outside the container a QEMU escapee would land in. The supervisor runs one `tcpdump` per bridge listed in the bundle's `capture/bridges.tsv`, rotates by size, enforces a disk cap by deleting the oldest completed chunk files (counted, never silent: the host-side streamer turns the counts into in-chain gap records), bounds restarts, and publishes `status.json` for the streamer.

The program is a verbatim constant (`SUPERVISOR_SOURCE`), not a template: per-range facts arrive as data (`bridges.tsv`) and host tuning as environment, so the rendered artifact is identical across ranges and the bundle stays byte-deterministic. Rotated files are named per tcpdump generation (`g<restart>.pcap`, `g<restart>.pcap1`, ...) so a restarted capture never rewrites a path it already wrote: write-once discipline holds at the capture tier too.

Chunk accounting deliberately excludes streamer-claimed files (B13): the host-side streamer renames a completed chunk to `<name>.shipped` before shipping it, which drops it out of `PCAP_RE` and therefore out of `enforce_cap`, so shipped bytes can never be unlinked here and reported as `capture-cap` loss. A claimed file is the streamer's to remove; its claim window is one streamer cycle, with removal retried on failure.

On stop (the `stop` file, or SIGTERM at teardown) the supervisor terminates its captures, parses each tcpdump's exit summary for kernel-drop counts, writes a final `status.json` with `stopped: true`, and then idles so the container stays up for the streamer's final harvest; `docker compose down` ends it.
"""

BRIDGES_FILENAME = "bridges.tsv"
"""Bundle-relative data file under `capture/`: one `<segment>\\t<bridge>` line per captured network."""

SUPERVISOR_FILENAME = "capture.py"
"""Bundle-relative name of the rendered supervisor under `capture/`."""

STOP_FILENAME = "stop"
"""Touching this file under the capture volume requests an orderly stop."""

STATUS_FILENAME = "status.json"
"""The supervisor's atomically-replaced status report under the capture volume."""


def render_bridges_tsv(segments: dict[str, str]) -> str:
    """The `capture/bridges.tsv` content for a plan's segment-to-bridge map."""
    return "".join(
        f"{segment}\t{bridge}\n" for segment, bridge in sorted(segments.items())
    )


SUPERVISOR_SOURCE = '''\
"""Capture-sidecar supervisor (rendered verbatim by inspect-ranges; see _evidence/supervisor.py)."""

import json
import os
import re
import signal
import subprocess
import sys
import time

CAPTURE_DIR = os.environ.get("CAPTURE_DIR", "/capture")
RENDER_DIR = os.environ.get("RENDER_DIR", "/render")
NETDEV_DIR = os.environ.get("NETDEV_DIR", "/sys/class/net")
TCPDUMP = os.environ.get("CAPTURE_TCPDUMP", "tcpdump")
CHUNK_MB = int(os.environ.get("CAPTURE_CHUNK_MB", "10"))
CAP_MB = int(os.environ.get("CAPTURE_CAP_MB", "2048"))
MAX_RESTARTS = int(os.environ.get("CAPTURE_MAX_RESTARTS", "5"))
POLL_S = float(os.environ.get("CAPTURE_POLL_S", "0.5"))

PCAP_RE = re.compile(r"^g(\\d+)\\.pcap(\\d*)$")
DROPS_RE = re.compile(r"(\\d+) packets? dropped by kernel")

stop_requested = False


def on_term(signum, frame):
    global stop_requested
    stop_requested = True


class Segment:
    def __init__(self, name, bridge):
        self.name = name
        self.bridge = bridge
        self.dir = os.path.join(CAPTURE_DIR, name)
        self.state = "waiting"
        self.proc = None
        self.generation = -1
        self.restarts = 0
        self.kernel_drops = 0
        self.dropped_bytes = 0
        self.dropped_files = 0
        os.makedirs(self.dir, exist_ok=True)

    def bridge_present(self):
        return os.path.exists(os.path.join(NETDEV_DIR, self.bridge))

    def active_file(self):
        if self.proc is None or self.proc.poll() is not None:
            return None
        newest = None
        for name, generation, index in self.chunks():
            if generation == self.generation:
                if newest is None or index > newest[1]:
                    newest = (name, index)
        return os.path.join(self.name, newest[0]) if newest else None

    def chunks(self):
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        out = []
        for name in names:
            match = PCAP_RE.match(name)
            if match:
                out.append((name, int(match.group(1)), int(match.group(2) or 0)))
        return out

    def start(self):
        self.generation += 1
        base = os.path.join(self.dir, "g%d.pcap" % self.generation)
        stderr = open(os.path.join(self.dir, "stderr.log"), "ab")
        self.proc = subprocess.Popen(
            [TCPDUMP, "-Z", "root", "-B", "8192", "-s", "0",
             "-i", self.bridge, "-C", str(CHUNK_MB), "-w", base],
            stdout=subprocess.DEVNULL, stderr=stderr,
        )
        stderr.close()
        self.state = "running"

    def harvest_drops(self):
        # tcpdump prints one drop summary per process exit; the file is
        # append-only and carries only per-generation banner/summary lines,
        # so summing the whole file is bounded and monotone
        try:
            with open(os.path.join(self.dir, "stderr.log"), "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            return
        self.kernel_drops = sum(int(count) for count in DROPS_RE.findall(text))

    def tick(self):
        if self.state in ("exhausted", "stopped"):
            return
        if self.proc is not None and self.proc.poll() is not None:
            # the restart budget is spent on actual starts, never on waiting
            # for an absent bridge
            self.harvest_drops()
            self.proc = None
            self.state = "restarting"
        if self.proc is None and self.bridge_present():
            if self.state == "restarting":
                if self.restarts >= MAX_RESTARTS:
                    self.state = "exhausted"
                    return
                self.restarts += 1
            self.start()

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            deadline = time.monotonic() + 5.0
            while self.proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
        self.harvest_drops()
        self.state = "stopped"

    def status(self):
        return {
            "state": self.state,
            "restarts": self.restarts,
            "active": self.active_file(),
            "kernel_drops": self.kernel_drops,
            "dropped_bytes": self.dropped_bytes,
            "dropped_files": self.dropped_files,
        }


def enforce_cap(segments):
    """Delete the oldest completed chunk files once the pool exceeds the cap; counted per segment."""
    active = {s.name: s.active_file() for s in segments}
    pool = []
    total = 0
    for segment in segments:
        for name, generation, index in segment.chunks():
            rel = os.path.join(segment.name, name)
            if rel == active[segment.name]:
                continue
            path = os.path.join(CAPTURE_DIR, rel)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            total += stat.st_size
            pool.append((generation, index, stat.st_mtime, path, stat.st_size, segment))
    pool.sort(key=lambda item: (item[2], item[0], item[1]))
    index = 0
    while total > CAP_MB * 1024 * 1024 and index < len(pool):
        _, _, _, path, size, segment = pool[index]
        index += 1
        try:
            os.unlink(path)
        except OSError:
            continue
        total -= size
        segment.dropped_bytes += size
        segment.dropped_files += 1


def write_status(segments, stopped):
    status = {
        "ts": time.time(),
        "stopped": stopped,
        "segments": {s.name: s.status() for s in segments},
    }
    tmp = os.path.join(CAPTURE_DIR, ".status.tmp")
    with open(tmp, "w") as handle:
        json.dump(status, handle, sort_keys=True)
    os.replace(tmp, os.path.join(CAPTURE_DIR, "status.json"))


def main():
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    segments = []
    with open(os.path.join(RENDER_DIR, "capture", "bridges.tsv")) as handle:
        for line in handle:
            line = line.strip()
            if line:
                name, bridge = line.split("\\t")
                segments.append(Segment(name, bridge))
    stop_file = os.path.join(CAPTURE_DIR, "stop")
    while not stop_requested and not os.path.exists(stop_file):
        for segment in segments:
            segment.tick()
        enforce_cap(segments)
        write_status(segments, stopped=False)
        time.sleep(POLL_S)
    for segment in segments:
        segment.stop()
    write_status(segments, stopped=True)
    # stay up so the streamer's final harvest can read the volume through
    # this container; compose down delivers the SIGTERM that ends the idle
    while not stop_requested:
        time.sleep(POLL_S)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
"""The sidecar program, written verbatim to `capture/capture.py` in evidence-enabled bundles."""
