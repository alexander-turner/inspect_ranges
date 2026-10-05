# Spike: hardened range container (the production privilege floor)

*Settles the acceptance gate from [external review](../../inspect-ranges/external-review.md) finding 3: the prototype spikes ran with Docker's default capabilities retained (`cap_add` is additive), QEMU as container root, and `apparmor=unconfined` — so "runs without `--privileged`" was the only demonstrated claim. This spike establishes the actual minimal runtime profile empirically, by dropping everything and adding back only what observable failures demanded. Reuses the net-compile spike's compiled 4-VM range and test battery unchanged. Run on the m6i.metal devbox, 2026-10-04. `./run.sh` reproduces (needs `../net-compile/run.sh` to have produced the guest image and render once); `./run.sh down` tears down.*

## Verdict

**The full stack runs under a hardened profile at zero measured cost**: all capabilities dropped except an explicit list of eight, Docker's default seccomp and AppArmor (`docker-default (enforce)`) in place, `no-new-privileges` set, every QEMU process running as `libvirt-qemu` (not root), and QEMU's own seccomp sandbox on (`obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`). Range fully enforced-ready in **49.8 s** vs ~50 s for the unhardened prototype; all nine ACL/isolation tests pass; external egress is blocked from every guest **before and after a simulated router compromise** (router firewall flushed in-guest; the hypervisor-side invariants, not the router, are the external containment authority).

## Docker non-involvement (added 2026-10-05, after reviewer skepticism of Docker networking)

The container now runs `network_mode: none`: Docker provides no networking whatsoever to the range container, so the machinery behind Docker's networking reputation (per-container iptables rules, published ports, docker0 veths, embedded DNS, the userland proxy) is absent rather than configured around. Non-propagation to the host is interface-absence, not filtering. Asserted from the running system by `run.sh`: the container netns holds only loopback plus the compiled bridges/taps (no `eth0`/veth), the container has no Docker-assigned IP, `iptables-save` on the host contains no rules referencing the container, and the range's nft table does not exist in the host netns — all while the full T1-T9 + egress battery stays green at unchanged cost (50.1 s enforced-ready).

## The measured capability floor

Every capability in the final set is justified by an observed failure when removed:

| Capability | Observed failure without it |
|---|---|
| `NET_ADMIN` | bridge/nftables creation in the container netns (established in earlier spikes) |
| `SETPCAP` | libvirtd's QEMU capability probe fails → "Cannot find suitable emulator for x86_64" (libvirtd clears the bounding set of processes it spawns as a non-root user) |
| `DAC_OVERRIDE` | "Failed to create save dir /var/lib/libvirt/qemu/save: Permission denied" (the package owns state dirs as `libvirt-qemu`; root-in-container has no override without it) |
| `FOWNER` | "cannot set mode of '/run/libvirt/qemu/dbus' to 0770" (libvirtd chowns state dirs away, then chmods them) |
| `KILL` | `virsh destroy` fails and teardown strands all VMs (root libvirtd signalling `libvirt-qemu`-owned QEMU) |
| `SETUID`, `SETGID` | required structurally to drop QEMU to `libvirt-qemu` (not individually bisected) |
| `CHOWN` | required by `dynamic_ownership` handing overlays/seeds/device nodes to `libvirt-qemu` (not individually bisected) |

Profile verification is read from the running system by `run.sh`: `CapEff` decodes to exactly the declared eight; AppArmor `docker-default (enforce)`; `Seccomp: 2`; `NoNewPrivs: 1`; `ps` shows 4 × `libvirt-qemu` QEMU processes; the QEMU command line carries `-sandbox on,...`.

## What changed vs the prototype containers

- **qemu.conf**: `user = "libvirt-qemu"`, `group = "kvm"`, `dynamic_ownership = 1`, `namespaces = []` (libvirt's private `/dev` mount namespace needs `CAP_SYS_ADMIN` + mount, both denied by the default profiles — disabling it is what makes default AppArmor workable), `seccomp_sandbox = 1`.
- **entrypoint**: chowns the container-local device nodes (`/dev/kvm`, `/dev/vhost-*`) to `root:kvm` 660 — these are container-created nodes, so nothing on the host changes.
- **compose**: `cap_drop: [ALL]` + the eight, `no-new-privileges:true`, no `security_opt: apparmor=unconfined`.

## Consequences for the design

1. **Backlog items 6 (AppArmor) and the capability floor are now demonstrated, not planned** — and cheaper than expected: Docker's *default* AppArmor profile suffices once libvirt's mount namespace is off; no tailored profile was needed to boot, run, enforce, and tear down. A tailored profile remains an available tightening (narrower file rules than docker-default), no longer a precondition.
2. **The escape-chain claim strengthens concretely**: a QEMU escape now lands in an unprivileged *user* (`libvirt-qemu`) inside an unprivileged container under default seccomp + AppArmor with eight capabilities, `NoNewPrivs`, and a QEMU that was itself running `-sandbox on` with `elevateprivileges=deny,spawn=deny`.
3. **`seccomp_sandbox = 1` costs nothing** at this scale (boot/exec/teardown all normal) — backlog item 3's qemu.conf half is confirmed viable; the explicit minimal device model remains open.
4. **External containment authority verified**: flushing the router guest's entire nftables ruleset (legitimate in-range agent behavior) changes nothing about external reachability — the range-netns invariants carry it. The NAT-granted case (a range that legitimately requests egress) still needs its conformance test once the compiler supports `nat` realization.
5. The production compose template should start from this spike's `compose.yaml` + `range/`, not from the earlier prototypes.

## Files

- `compose.yaml` — the hardened profile (the deliverable)
- `range/Dockerfile`, `range/entrypoint.sh` — non-root-QEMU qemu.conf, device-node ownership
- `run.sh` — profile verification read from the running system + the net-compile T1–T9 battery + egress conformance before/after router flush
- `tmp/run-final.log` — the clean run (23 PASS, 0 FAIL)
