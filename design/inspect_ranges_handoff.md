# inspect_ranges — Design Handoff

Summary of a design discussion about building a cyber-range sandbox for Inspect AI evals.
This captures the decisions reached, the architecture, open questions, and next steps.
It is a condensed summary, not a verbatim transcript.

---

## 1. Goal

Build an Inspect extension that lets eval authors (humans and LLM agents) define multi-host
cyber ranges (including Active Directory networks) in a single YAML spec and run them as
Inspect sandboxes, with strong containment, fast iteration, and good performance.

Broader framing: a great **range development and testing environment** for humans and agents.
Practitioners who have built many ranges (on Proxmox) report that the biggest pain point is that
ranges are cumbersome to set up and maintain. So developer experience is the product, not a
nicety. That means one spec, tooling to visualize it and to shell into and inspect a running range
(§10), and the ability to plug the same spec into different deployment topologies (§9). A built-in
libvirt engine is the default for a lightweight, fast inner loop, with backends that can scale out
to Proxmox (or others) later without changing the spec.

## 2. Names (decided)

| Thing | Name |
|---|---|
| Python package | `inspect_ranges` (`pip install inspect-ranges`) |
| CLI | `inspect-ranges` (primary), `inspect-rgs` (short alias) |
| Spec file | `range.yaml` |
| Sandbox (libvirt backend) | `sandbox="inspect_ranges/libvirt"` (package-qualified to avoid collisions; plain `libvirt` as shortcut if unambiguous) |
| Future backends | `inspect_ranges/proxmox`, `inspect_ranges/kubevirt` |

Rejected: `inspect_cyber` (taken by UK AISI), `inspect_ranger` (bare `ranger` CLI collides with the
ranger file manager), `range`/`inspect_range` as sandbox names.

Note: spelled **libvirt** (not "libvert").

## 3. Key technology decisions

- **libvirt/KVM over Proxmox** for the eval runtime. Rationale: eval episodes are short-lived,
  independent, code-driven, and disposable. We don't need a GUI, multi-user access control,
  clustering, HA, or integrated storage. Proxmox's costs (dedicated OS, storage/SDN/token setup,
  larger concept surface, slower API-driven iteration, cluster-wide SDN apply) remain.
  - **The tradeoff we're accepting** (from practitioner feedback): libvirt is a *library*, not a
    *platform*. Proxmox provides opinionated, integrated features behind one API, and with libvirt
    we implement those patterns ourselves. The ones called out are network policy/firewalling and
    IPAM (automatic static IP allocation, which is heavily used in Proxmox ranges). Nothing Proxmox
    does is impossible on libvirt; it's just not provided. The bet is that this is now affordable
    because (a) our scope is narrow (short-lived, single-host, code-driven episodes), and (b) LLM-assisted
    development makes filling these gaps much cheaper than it was in 2024. Practitioners who
    chose Proxmox have said in hindsight they might pick libvirt, so the tradeoff is genuinely
    close. §8a lists the platform features we must provide ourselves.
- **Vagrant is not used.** Its jobs are replaced: boxes → OCI image registry; lifecycle → our sandbox;
  SSH/WinRM → QEMU guest agent; provisioning → baked images; in-guest networking → cloud-init.
  **Keep Packer** for building images.
- **Native `range.yaml` format, not Docker Compose compatibility.** Compose + `x-libvirt` extensions
  can't run on Docker anyway, and anything fully Compose-expressible can run on Docker/k8s
  (use Kata/gVisor on k8s if VM-level isolation is the only reason). Portability lives at the
  Inspect sandbox interface (`exec`/`read_file`/`write_file`), not the environment file.
  Optional: one-way Compose→range.yaml importer at authoring time.
- **Docker is an implementation detail of the libvirt sandbox.** The `inspect_ranges/libvirt`
  sandbox reads `range.yaml`, generates a Compose project, and runs it via Docker. Authors never
  write Compose.
- **Developers are exclusively on Linux.** Mac users (if any) use a remote EC2 dev box via
  VS Code Remote-SSH / `DOCKER_HOST=ssh://`. No native macOS backend (libvirt+HVF on macOS is
  ARM64-only, no Windows Server, no Linux bridges/netns, and the Docker agent path breaks).
  Parallels + ARM Ubuntu only supports nested Linux guests on M3+/macOS 15+; not a supported path.

## 4. Runtime architecture (libvirt backend)

Per sample:

1. Sandbox generates a Compose project from `range.yaml`.
2. **`range` container**: ordinary image running libvirtd + QEMU. Gets `/dev/kvm`, `/dev/net/tun`,
   `/dev/vhost-net`; host image cache bind-mounted **read-only**; per-sample scratch volume for
   qcow2 overlays. Creates bridges **inside its own network namespace**, creates overlays on
   read-only golden images, boots VMs. Healthcheck passes when VMs/targets are ready.
3. **`default` agent container** (typical case: Linux/Kali image, `network_mode: none`,
   `cap_add: [NET_ADMIN, NET_RAW]`, IPv6 enabled).
4. **veth attach**: sandbox runs a short-lived privileged helper container
   (`--pid=host --network=host`) that creates a veth pair, moves one end into the agent
   container's netns as `range0` with its address, and attaches the other end to the named bridge
   inside the range container's netns. No host daemon required. (Alternative considered: a host
   daemon watching Docker events for `range.attach` labels — only needed if using the *stock*
   Docker sandbox.)
   - Validate before attaching: bridge must belong to the same project's range spec; never host
     interfaces or other projects; address must be within the segment subnet.
5. Agent healthcheck checks **local state only** (e.g. `range0` has an address) — don't ping
   targets (creates range traffic for the whole sample), and tolerate agents modifying interfaces
   (Responder/mitm6).
6. Inspect runs the sample; `sandbox("default")` = `docker exec` into agent container;
   `sandbox("dc01")` etc. = exec via range container → QEMU guest agent on that VM.
7. Teardown: `compose down` with volumes removed; QEMU dies with the container; overlays discarded.

### Why not share the network namespace (`network_mode: service:range`)

Rejected. It puts the agent on the hypervisor side of every bridge: with default `CAP_NET_RAW` it
can sniff/inject on all segments, breaking segmentation fidelity (agent should pivot) and
containment.

### Why the agent is bridged (L2), not routed

AD attacks (LLMNR/NBT-NS poisoning via Responder, ARP spoofing, mitm6) require being in the
broadcast domain. Routed access is fine only for "external attacker" scenarios. Bridged veth gives
L2 fidelity with fast `docker exec`.

### Agent box: container vs VM

- Default: **container** (most attack boxes will be Linux; Linux is the standard AD-attack platform:
  impacket, NetExec, Responder, mitm6, bloodhound-python, Certipy). Fast exec, runs at L1 (no
  nesting tax).
- Supported alternative: **agent VM** (`kind: vm`) for Windows attack boxes or escape-sensitive
  evals. Exec via QEMU guest agent (polling-based, ~60 KiB write limit — see UK AISI Proxmox
  provider's ISO hot-plug workaround). If latency is a problem, add a virtio-vsock exec daemon.
- Spec lets a task declare the attack box as either kind on a given segment.

### Agent scaffolds

- Bash-only agents work (tell them their network access or make discovery part of the task).
  Ensure `tmux` (and `screen`) are in the image; verify backgrounded processes survive the exec
  implementation/timeouts. Consider Inspect's `bash_session` for persistent shells.
- **Terminus** (Terminal-Bench's tmux-keystroke agent) is a strong fit: interactive tools, listeners,
  reverse shells; logic runs outside the environment; needs only exec + tmux.
- **inspect_swe** agents should "just work" in a container `default` — but the agent container has
  no egress, so verify scaffold install/model relay works via sandbox exec/file ops only, or bake
  what's needed into the image.

## 5. Containment and security

- **One sample per EC2 instance** → Nitro is the boundary between samples. Makes `--privileged`
  on the range container acceptable-ish; still prefer specific devices + capabilities.
- Protect the instance: IMDSv2 with hop limit 1; minimal IAM instance role; control channel
  (SSM/SSH) can't reach beyond the instance; VPC-level egress controls (security groups) as a
  second layer.
- Range networks: no `<ip>` on libvirt networks for agent-facing segments (host not reachable);
  host-level default-deny egress; management network fully separate.
- **Evidence integrity**: stream pcaps/console logs/scoring artifacts off-instance as generated
  (or capture externally, e.g. VPC traffic mirroring) since an escaped agent owns the instance.
- LLM-as-range-developer: agent gets the **CLI only** (validate/up/exec/logs/down), never raw
  `virsh`/libvirt group (≈ root). Containment lives in a layer the spec can't change. Run builder
  agents on separate infra from eval hosts. Human review at boundaries (new ranges/images,
  anything touching egress).

## 6. Performance notes

- Docker adds nothing measurable to QEMU.
- **Nested virtualization** on EC2 C8i/M8i/R8i (supported since Feb 2026; KVM as L1). Costs are
  from VM exits: Windows boot, interrupts, I/O, small-packet networking. AWS still recommends metal
  for performance-sensitive workloads.
- Levers: virtio disk/net, vhost-net, `-cpu host`, **Hyper-V enlightenments for Windows guests**
  (probably the biggest win), hugepages.
- **Never put qcow2 in the container writable layer** (overlayfs copy-up of multi-GB files). Host
  image cache mounted read-only; overlays on a volume.
- **EBS gp3 baseline** (3000 IOPS / 125 MB/s) is shared by all VMs; raise it or use `d`-variant
  instances (local NVMe) for overlays and memory snapshots. Memory-snapshot restore reads the whole
  RAM image (4 GiB ≈ 30+ s at baseline gp3).
- Snapshot restore caveats: identical RNG state, clock jumps (force time sync — Kerberos/AD care).
  Since decided: memory restore is an opt-in optimization, not the default; cold boot from
  converged disk checkpoints is the default for all range classes
  (see `inspect-ranges/memory-restore-ad.md`).
- Memory is not overcommitted; include QEMU per-VM overhead (a few hundred MB) in cgroup limits.
  KSM is reasonable within one sample (cross-sample side channel concern is moot with 1/instance).
- **Cold start** likely dominates with one sample per instance: EBS volumes from snapshots load
  lazily (use Fast Snapshot Restore or pre-read); consider a **warm pool** of instances.

## 7. Images

- Sources: pinned upstream cloud images (URL + SHA-256) → derived base images with guest agent,
  logging, hardening, tooling built in CI with Packer → published to an **OCI registry via ORAS**
  (GHCR/ECR/Harbor). Windows: shared Packer template, images built privately per org (can't
  redistribute); Sysprep before cloning (duplicate SIDs break AD).
- Reference images **by digest** in `range.yaml` (or resolve tags → digests and record in eval log).
- Task-specific images: `virt-customize` (offline edits, Linux) or Packer-from-base (booted config,
  Windows/AD). Cache builds by hash(base digest + recipe).
- Publish **flattened** images; use backing chains only locally (golden read-only + per-episode overlay).
- Host: digest-keyed local cache, verify on pull, read-only; pre-pull command; eviction.
- Check registry blob-size limits for 10–20 GB Windows images.
- Per-episode artifacts (pcaps, consoles, screenshots, retained overlays) go to object storage next
  to eval logs, not the registry.

## 8. `range.yaml` spec (principles)

- Backend-neutral core: VMs, containers, segments, links, images (by digest), sandbox designation,
  containment policy, tests. Backend-specific settings clearly marked as extensions.
- Borrow conventions: containerlab's explicit links, KYPO's hosts/routers/networks separation,
  Compose-like names where semantics match. Reuse cloud-init (Linux) / cloudbase-init (Windows)
  and **JSON Schema** for validation.
- Reject unsupported keys loudly; backends declare supported features and reject specs they can't
  faithfully realize.
- In-guest addressing: cloud-init NoCloud seed ISO (Linux), cloudbase-init or guest-agent
  PowerShell (Windows), or DHCP on a router VM with MAC reservations. These deliver the
  addresses; choosing them is IPAM's job (§8a).
- Egress: default deny; opt-in allowlist only, policy-checked and human-reviewed.
- Existing specs worth studying/importing from: Ludus range configs (GOAD content), KYPO topology
  definitions, containerlab topologies, kcli plans.

## 8a. Platform features the libvirt backend must provide

Proxmox gives these features out of the box. On libvirt they are ours to build, and they belong in
the shared library so every backend and tool uses the same logic.

- **One source of truth for networking.** The known libvirt pain point is that firewall rules
  (nftables) live outside the libvirt domain/network XML, so you maintain two configs that drift.
  Here, `range.yaml` is the only source. Segments, links, routing, and firewall/containment policy
  are all declared there. Libvirt network XML and nftables rulesets are **generated** artifacts
  (inspectable via `render`) and are never hand-edited. The rules are applied inside the range
  container's network namespace, so they are created and destroyed with the range and never
  touch the host's own firewall.
- **IPAM.** Addresses are optional in the spec. When omitted, they are allocated
  deterministically from each segment's subnet (a stable order, so the same spec always gets
  the same addresses), with reserved ranges for gateways and the agent attachment. Explicit
  addresses are validated against the subnet and checked for conflicts. The resolved allocation
  (IPs, MACs, hostnames) is emitted as structured output. It feeds cloud-init/cloudbase-init
  configs, DHCP reservations, DNS records for the range, the VS Code topology view, and the eval
  log.
- Other patterns to own rather than expect: templates/linked clones (golden image + overlay,
  §7), snapshots (§6), console/screenshot access (§10), and a per-range event log of what the
  backend did (for debugging and for agents building ranges).

## 9. Backend abstraction / scale

- Backend interface: create segments, create VMs from images, attach agent container, exec/file
  transfer, snapshot/restore, collect evidence, teardown.
- libvirt caps **range size** at one host (large nested-capable instances fit dozens–~100 VMs);
  fleet scale handled by the provisioning layer. Cross-host ranges possible later via VXLAN.
- Future backends: **KubeVirt** (Multus for multi-NIC),
  **Proxmox** (translate range.yaml to UK AISI provider config/reuse its pieces; agent likely a VM
  since Proxmox has no Docker and the API lacks LXC exec), OpenStack. On Proxmox, IPAM and
  firewalling can map onto PVE's native SDN/IPAM/firewall rather than our generated rules.
- **Native EC2/VPC** is viable for **routed-only** ranges (e.g. "external attacker" scenarios)
  and scales horizontally. It loses L2 (no broadcast/ARP/multicast), so it can't run AD
  poisoning attacks. That makes it the clearest case for **backend capability declarations**:
  a spec marks what it needs (e.g. `l2_broadcast`, Windows guests, nested virt), and a backend
  that can't provide it refuses the spec rather than silently degrading (see §8). The same
  mechanism extends to deployment capabilities — `forward_upstream`, `egress_grant`,
  `image_delivery` (registry | granted-urls | pre-seeded) — with the same refuse-at-planning
  semantics (see §11).
- Libvirt remains the default, built-in engine. Other backends are opt-in plugins behind the same
  interface, so designing for multiple backends from the start costs little as long as the first
  implementation is libvirt only.
- Same conformance + range tests run against every backend.

## 10. Developer experience

- Dev boxes: Linux; or remote EC2 dev box (same instance families as prod; EBS for cache, NVMe
  only as scratch; auto-stop when idle; SSM access; isolated account/VPC; dev AMI or Ansible role
  sharing setup code with prod).
- CLI commands: `host install`, `doctor` (KVM, Docker/cgroups, IPv6, disk, helper versions,
  **end-to-end smoke test** — Docker iptables/br_netfilter can interfere with bridged traffic),
  `init` (templates: single Linux target; DMZ+internal; minimal AD), `validate`, `render` (write
  generated Compose/XML for debugging), `up`, `shell <vm>`, `console <vm>`, `test`, `pull`, `down`,
  list/attach to kept-alive failed ranges.
- Fail fast at sample start with exact fix instructions.
- One library shared by CLI, sandbox, and AWS path; version the label/spec schema.
- VS Code: publish JSON Schema first (Red Hat YAML extension gives completion/validation for free).
  Custom extension (thin client over CLI JSON output): live topology visualization (highlight
  egress/containment), running-range explorer (shell/console/screenshot/teardown), validate/up/test
  commands as diagnostics, image digest hovers, link from Inspect log sample to preserved range.
- Agent-facing feedback: serial console captured to files, structured JSON health/diagnostics,
  guest log retrieval, `virsh screenshot`.
- Verification: connectivity assertions, reference solution must succeed, negative checks
  (no trivial solves, no unintended routes/egress).
- Run Inspect's sandbox conformance suite (`self_check`) in CI from day one.

## 11. Deployment seam

Separate **where** from **what** (resolved; the full contract lives in the deployment-seam
records). An orchestration layer provisions an instance (one sample per instance) and provides a
`RangeHost`: a lease plus a transport-agnostic `RangeChannel`. The driver sends one
self-sufficient, digest-pinned realization bundle; the host realizes it with no further driver
round trips and streams evidence out as a declared output. A Docker endpoint is one transport of
the channel, not the contract. Don't depend on Inspect Docker sandbox private internals — call the
Docker CLI/API directly.

Also raise Inspect's sandbox setup timeout for range tasks (Windows DC boot under nesting).

## 12. Dual-use / info hazard position

- The orchestration framework itself is low-hazard (comparable public tools: Ludus, KYPO, GOAD,
  UK AISI Proxmox provider). Benefit is asymmetric toward evaluators/defenders.
- Higher hazard: automated range generation + automated verification (an RL environment factory),
  realistic range content, reference solutions, agent trajectories, novel vulnerabilities.
- Policies: publish provider/tooling; keep generation pipelines, throughput-at-scale features,
  held-out ranges, solutions, and transcripts internal/controlled; ship only thin templates;
  consider staged release to known partners; canary strings on any released content; route
  training use through governance review.

## 13. Suggested first experiments

On an m8i instance (and a metal instance for comparison):

1. Single Linux VM under libvirtd in a range container + Ubuntu agent container attached via veth.
2. Windows DC boot time and memory-snapshot restore time on gp3 vs local NVMe.
3. Several VMs booting concurrently (find gp3 saturation).
4. iperf between VMs; fio in guest; with/without vhost-net and Hyper-V enlightenments.
5. Cold start: instance launch → range ready (AMI-baked images with/without Fast Snapshot Restore
   vs registry pull).
6. Guest-agent exec round trip / large output / file transfer vs `docker exec`.
7. Background processes surviving exec calls/timeouts; tmux-based agent (Terminus) and an
   inspect_swe agent against a no-egress range.
8. L2 checks: broadcast/ARP/multicast between agent container and VMs (Responder-style).
9. Single source of truth: generate libvirt network XML + nftables from a small two-segment
   `range.yaml` with IPAM-allocated addresses. Verify the intended routes and blocks hold,
   and that teardown leaves no host-side rules behind.

## 14. References

- Inspect extensions: https://inspect.aisi.org.uk/extensions/
- Inspect sandbox extension docs: https://inspect.aisi.org.uk/extensions-sandboxes.html
- UK AISI k8s sandbox: https://github.com/UKGovernmentBEIS/inspect_k8s_sandbox
- Prior art: UK AISI `inspect_proxmox_sandbox`, `inspect_ec2_sandbox`, Jason Gwartz
  `inspect_vagrant_sandbox` (libvirt via vagrant-libvirt), `inspect-glovebox` (microVM + egress
  allowlist record), UK AISI `inspect_cyber`.
- Terminus / Terminal-Bench: https://www.tbench.ai/news/terminus
- Tools: Packer (QEMU builder), ORAS, virt-customize (libguestfs), cloud-init, cloudbase-init,
  kcli, containerlab, Ludus, KYPO/CyberRangeCZ, KubeVirt.
