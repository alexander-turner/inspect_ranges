# Spike battery: cloud-hypervisor VMM (PR #10 opt-in)

*The first live boot of a `vmm: cloud-hypervisor` guest. A two-guest range (CH attacker, qemu host) proves the whole opt-in surface end to end: the range image's pinned CH binary and firmware boot the derived golden; readiness rides the hybrid-vsock Unix socket (the `CONNECT`/`OK` handshake plus the `SO_PEERCRED` check, since CH guests have no `AF_VSOCK` listener); exec works over the same channel; the VMM runs as its own unprivileged CID-derived uid with no capabilities; the CH guest's bridged tap carries the lab segment to its qemu sibling; the serial console records; and `down` removes the containers and the private hybrid socket directory. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 3900.*

*Reproduce: `./run.sh` (noble vendor image, `vhost_vsock`, docker). `./run.sh down` tears down.*

## Checks

1. **C1/C2** both guests reach ready (the CH guest's readiness probe itself proves the hybrid channel) and the attacker reports its hybrid endpoint.
2. **C3/C4** exec over hybrid vsock on the CH guest; the qemu sibling is unaffected.
3. **C5** the CH guest's tap is bridged: it reaches the qemu host across the lab segment.
4. **C6** the VMM process runs as `ch_uid(cid)`, not root and not `libvirt-qemu`.
5. **C7** the CH serial console log is non-empty.
6. **C8** teardown removes the containers and the hybrid socket dir.

## Files

- `run.sh` — derive a noble golden, run the probe under the battery lock.
- `probe.py` — the spec, boot, channel probes, and teardown assertions.
