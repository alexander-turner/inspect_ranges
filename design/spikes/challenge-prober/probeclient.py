"""Kernel-stack probe client for mechanisms (a)/(b): one nonce GET via the probe veth.

Runs in a zero-capability sidecar sharing the range container's netns; the veth's IP is the kernel's, so this is an ordinary TCP client. Prints RTT_MS and BODY like rawprobe.py so the harness validates both the same way.

Usage: probeclient.py <dst_ip> <port> <nonce> [timeout_s]
"""

import sys
import time
import urllib.request

dst, port, nonce = sys.argv[1:4]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 5.0
start = time.monotonic()
with urllib.request.urlopen(
    f"http://{dst}:{port}/probe?n={nonce}", timeout=timeout
) as r:
    body = r.read().decode()
elapsed = (time.monotonic() - start) * 1000.0
print(f"RTT_MS {elapsed:.1f}")
print(f"BODY {body}")
