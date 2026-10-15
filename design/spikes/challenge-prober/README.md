# challenge-prober spike: the active prober's attachment mechanism

How does the active prober reach a guest service from outside every VM, when bridges are deliberately IP-less and the hypervisor is unaddressable from any segment? Measured 2026-10-15 on the devbox against a nonce-bound HTTP service (`httpnonce.py`) on a booted one-segment range (hardened profile, eight-capability floor asserted, CID band 30500). 30/30 checks green, zero residue; `./run.sh` reproduces.

## Mechanisms measured

| | Mechanism | Nonce probe | Agent active recon | Agent passive sniff during probes |
|---|---|---|---|---|
| A | Persistent probe veth with an IP in the range container netns (MAC `02:50:00:00:02:50`, IP `.250`) | 5/5 verified, RTT ~20 ms (python urllib client; see note) | ping answers; closed ports RST; zero listeners | 1 frame total: the initial ARP broadcast; 0 unicast (switched segment) |
| A2 | A plus a netns-local nftables clamp (`input iifname pr0: ct established accept; drop`) | still verified (established path) | ping silent; scans read filtered, no RST | as A |
| B | Transient veth, existing only during the probe window | verified; create+probe+delete 756 ms | endpoint dark after the window | ARP residue persists on the agent (`NEIGH 10.95.10.250 REACHABLE` after deletion): the blink is recorded by the segment |
| C | AF_PACKET userspace probe, no kernel identity (`rawprobe.py`: own ARP, hand-rolled TCP, real checksums; MAC `02:50:00:00:02:51`, IP `.251`) | 3/3 verified, RTT 0.7 ms | nothing to scan, ever | **9 frames, 8 unicast: the server's replies to the fabricated MAC are unknown-unicast and flood every port** |
| C2 | C plus an FDB pin for the fabricated MAC on the bridge device | verified | as C | 2 broadcasts (ARP), 0 unicast: flooding stops |

Attribution: all probe traffic lands in our own per-segment pcap and is selectable by the declared source identity (A: 126 frames by probe IP; C: 56 by IP, 70 by fabricated MAC; agent traffic separately: 9), so corroboration can exclude probe-sourced flows by identity.

Conformance held throughout: no probe interfaces in the host netns, attacker egress still none, the agent's listener surface unchanged (0 open before and after, scanned from the target).

RTT note: mechanism A's ~20 ms is dominated by the python HTTP client (likely a delayed-ACK interaction with its write pattern); C's hand-rolled single-segment exchange shows the wire path is 0.7 ms. Slice 4's prober should measure its own client rather than inherit this number.

## Recommendation (security paragraph drafted for the record)

**Default: a declared persistent probe endpoint with the clamp (A2).** The prober gets a per-segment veth in the range container netns with a compile-time reserved IP and a declared locally-administered MAC (`02:50:...`), clamped by netns-local nftables so it originates probe flows but answers nothing inbound: no ping reply, no RST, nothing listening, scans read filtered. Scoring rule 2 already makes visible checks acceptable, and a silent, stable monitoring address is realistic segment furniture; the kernel stack does the protocol work, so HTTPS and arbitrary services probe without custom code. The containment cost, stated honestly: inbound frames to the probe address now reach the range container's IP input path before the clamp drops them, so the hypervisor is no longer unaddressable in the strict sense; the added surface is the netns kernel's IP input processing, ARP handling, and conntrack entries for probe flows, reachable from L2 by an agent, inside the same jailed, credential-free container the bridge processing path already exposes. The declared identity keeps evidence clean: probe flows are attributable in pcap by reserved IP and MAC, and corroboration excludes them from agent-traffic reasoning by spec rather than heuristics.

**Recorded upgrade path, not default: the userspace prober (C2).** Zero kernel identity and sub-millisecond, but it must carry the bridge FDB pin for its fabricated MAC: without it the server's replies are unknown-unicast and flood to every port, where a passively sniffing agent sees the probe's existence precisely because the prober tried to be invisible (measured: 8 unicast frames leaked without the pin, 0 with it). ARP broadcasts for the fabricated IP still appear during sessions, so this is lower-signature, not invisible. The cost is a userspace TCP client per protocol: viable for plaintext nonce HTTP (~190 lines, proven), prohibitive for TLS. Use it when a scenario's realism budget cannot afford a visible monitoring address.

**Rejected: transient attach (B).** The window costs ~760 ms per probe, the agent's ARP cache retains the endpoint after deletion anyway, and an appearing-and-vanishing neighbor is a stranger artifact than a stable silent one.

## Operational parameters for slice 4

- Reserve one probe address per declared network at compile time (IPAM, recorded in `allocation.json`), MAC convention `02:50:00:` plus allocation; both land in the plan so attribution is spec-driven.
- Create the veth and install the clamp with the generated netns invariants when a challenge declares the `active-prober` observer; the endpoint lives for the range's lifetime.
- The prober process needs zero capabilities once the veth exists (proven: zero-cap sidecar); it writes nonce, window, verdict, and measure into its evidence stream per probe, keyed by the declared identity.
- Probes are ordinary segment traffic and appear in pcap by design; `corroborate()` excludes probe-sourced flows by the declared identity.

## Files

- `run.sh`: the full battery (setup, floor assert, boot, mechanisms A/A2/B/C/C2, attribution, conformance, teardown).
- `spec.yaml`: one-segment range, static IPs, eight-cap floor.
- `httpnonce.py`: the target's nonce-bound HTTP service.
- `probeclient.py`: kernel-stack probe client (A/B), zero-capability sidecar.
- `rawprobe.py`: the userspace AF_PACKET prober (C), NET_RAW-only sidecar.
- `agentview.py`, `sniff.py`: the agent box's active and passive visibility measurements, run over the channel as root.
