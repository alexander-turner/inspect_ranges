# Spike battery: win-build (windows-ad v1, slice 1)

*The Windows guest, first-class on the production pipeline: `images derive-windows` installs the sysprep'd golden from digest-pinned eval media in a one-shot hardened range container (unattended install, virtio guest tools + the vsock control daemon baked at first logon from the daemon bundle's Windows sources, `sysprep /generalize /shutdown`, no cached answer file), re-deriving is a cache hit; then a range with one Windows host and a Linux attacker renders and boots: the clone specializes from the render-emitted unattend seed on a virtio-scsi cdrom (hostname and the MAC-keyed static address prove it), readiness is daemon-only, exec answers as SYSTEM over vsock, L3 is proven across the segment (the Windows host pings the attacker: the Windows Firewall drops inbound ICMP), and teardown is clean. Windows artifacts are LOCAL ONLY (recipes-not-images, the ratified posture). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4150.*

*Reproduce: `./run.sh` (ws2022-eval.iso + virtio-win.iso + the noble vendor in the shared cache, `vhost_vsock`; ~30 min, dominated by the unattended install). `./run.sh down` tears down.*

## Checks

1. **W1** the golden installs from pinned media; re-deriving with the same pins is a cache hit.
2. **W2** render emits the unattend seed + scsi-cdrom domain; `up` reaches readiness on the daemon alone.
3. **W3** the specialize seed applied: `hostname` is the guest name, `ipconfig` shows the static address, `whoami` is SYSTEM, and the Windows host pings the Linux attacker across the segment (inbound ICMP is dropped by the Windows Firewall, so the honest probe runs outbound).
4. **W4** teardown leaves nothing.

## Files

- `run.sh`: derive, boot, prove, teardown under the battery lock.
