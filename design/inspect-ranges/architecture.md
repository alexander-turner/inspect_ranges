---
type: document
title: "inspect_ranges — design and architecture review (draft 1)"
audience: broader review (eng, security, Inspect maintainers)
status: draft-for-review
tags: [inspect-ranges, architecture, review]
timestamp: 2026-10-01
---

# inspect_ranges — design and architecture review (draft 1)

*First full draft for broader review. Everything claimed as **measured** was run on an m6i.metal EC2 devbox (Ubuntu 24.04, Docker 29.8.1) on 2026-09-30/10-01 and is reproducible from a spike directory in this repo (`design/spikes/*/run.sh`). The document distinguishes throughout between what is **implemented and demonstrated** and what is **designed but unbuilt** — see the ledger in §11. Detailed decision records are linked per section; this document is the synthesis, not the only source.*

## 1. What this is and why

`inspect_ranges` is an [Inspect AI](https://inspect.aisi.org.uk) extension that lets eval authors define multi-host cyber ranges — including Active Directory networks — in a single `range.yaml`, and run them as Inspect sandboxes with strong containment and a fast iteration loop. The product thesis (from practitioner feedback): ranges fail as evals because they are cumbersome to build and maintain, so **developer experience is the product** — one spec, compiled (never hand-configured) realization, tooling to validate/render/inspect, and the same spec portable across deployment backends.

The design baseline is six real public ranges translated from fetched upstream configs (vulhub CVE stack, KYPO routed demo, CyRIS firewalled segments, MHBench breach-derived enterprise, GOAD-Light AD forest, Splunk attack_range telemetry lab) — chosen so every schema field and networking requirement is *forced by a real artifact*, not invented ([survey](survey.md), [requirements table](range-yaml-swag.md)).

## 2. System overview

```
Inspect eval (controller)
  └─ sharding layer: dispatches samples, one resident sample per Nitro instance
       └─ EC2 Nitro instance  ──────────────  the inter-sample security boundary
            └─ Inspect worker + inspect_ranges provider (local Docker daemon)
                 └─ "range" container (unprivileged; libvirtd + QEMU; init: true)
                      ├─ bridges + generated nftables  (in the container's netns only)
                      ├─ router VM(s)   ─ generated nftables = the declared ACL
                      ├─ target VMs     ─ Linux: vsockd │ Windows: qemu-ga
                      └─ agent VM       ─ always a VM; controlled ONLY via vsock
```

Key properties, each elaborated below: the **agent is always a VM** (§6); the **control plane is virtio-vsock, not a network** (§5); **all networking is compiled from the spec** into inspectable artifacts (§4); **nothing runs privileged** anywhere in the runtime (§6); the **host netns carries zero range state** even while a range runs (§4); **Nitro one-sample-per-instance is the only inter-tenant boundary**, and the layers inside exist for eval validity, not tenant isolation (§6).

## 3. The spec layer: `range.yaml` schema v0.1 — implemented

([schema-v0.1-scope](schema-v0.1-scope.md); code: `src/inspect_ranges/schema.py`; CLI: `inspect-ranges validate`, `inspect-ranges schema`.)

v0.1 covers **only what the runtime consumes** — `range` (identity/provenance), `networks`, `routers` (with the ACL), `hosts`, `attacker` — validated strictly (unknown keys are errors; pydantic `extra="forbid"` plus cross-reference checks). Everything half-designed is **excluded entirely**, parked verbatim in each example's `deferred.yaml`, with a deferral table recording what unblocks each (attack_path → AD edge vocabulary; variables/generation → the L2 layer; goals/oracles → real scorers; defense → D-tier experience; guest config → the provisioning pipeline). All six example ranges validate green; sentinels like `to-verify` live in comments, never in typed values.

A complete valid range (the smoke-test example, abridged):

```yaml
range:
  name: vulhub-zabbix
  schema_version: "0.1"
  description: >
    A realistic 4-host Zabbix monitoring stack on one flat network ...
  # upstream provenance lives in source.md beside the spec (convention, not schema)

networks:
  - name: lab
    cidr: 10.10.10.0/24
    mode: isolated                  # isolated | nat | routed
    dns: { records: [{ name: server }, { name: web }, ...] }

hosts:
  - name: web
    os: { type: linux }
    image: vulhub/zabbix:3.0.3-web
    interfaces: [{ network: lab }]  # ip omitted → deterministic IPAM

attacker:
  interfaces: [{ network: lab }]    # a dedicated attack VM on the segment
  entry: external
  egress: none                      # default
```

Inter-segment policy is **one vocabulary, on routers**, default-deny and stateful — the shape the networking spike proved end to end:

```yaml
routers:
  - name: router_external
    interfaces: [{ network: dmz }, { network: internal }]
    acl:
      - { from: dmz, to: internal, allow: [tcp/5432] }   # proto/port or proto/lo-hi
```

Cross-validators enforce: unique names, every interface/ACL endpoint references a declared network, explicit IPs within their subnet, attacker foothold rules. The JSON Schema is exported for editor completion (`inspect-ranges schema`).

## 4. Networking: compiled, never configured — demonstrated

([net-compile spike](../spikes/net-compile/README.md); design principle: handoff §8a "one source of truth".)

The known failure mode of libvirt-based ranges is firewall/network config drifting apart from the spec. Our answer: **every networking artifact is generated** — deterministic IPAM (IPs, MACs, vsock CIDs, emitted as `allocation.json`), bridge plan, per-VM cloud-init seeds, the router's nftables ruleset, hypervisor-netns invariants, and the boot plan. Nothing downstream of the spec is hand-written; NIC naming via MAC-match + `set-name` makes the generated firewall and the generated interfaces consistent by construction. The generated router ruleset for the ACL above:

```
table inet fw {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "dmz0" oifname "internal0" tcp dport 5432 accept
  }
}
```

**Demonstrated** (two-segment range: router, two targets, agent — all booted from a 40-line spec): same-segment L2 intact; allowed cross-segment port reachable (fast RST proves routing + accept + stateful return in one observation); **denied-but-listening** port drops (enforcement, not absence of listener); asymmetric deny holds against a live listener; cross-segment ICMP blocked; segments are separate broadcast domains (forced ARP gets no reply); **zero range bridges visible in the host netns while the range runs**; teardown leaves the host link table exactly as found. Bridges live in the range container's network namespace and die with it — rules never touch the host firewall.

Realization choices: router-as-guest (ordinary nftables a defender could inspect in-range — realism), bridges carry no IP (hypervisor not addressable from any segment), the range netns carries only generated invariants (FORWARD drop), `br_netfilter` off (doctor-enforced).

## 5. Guests and the control plane

### The agent is always a VM, controlled over vsock — demonstrated

([agent-containment](agent-containment.md); [vsock-exec spike](../spikes/vsock-exec/README.md).)

The agent boots as an ordinary libvirt guest from a standard image (Kali for attack, Debian for generic) with a small exec/file daemon baked in. The harness drives it over **virtio-vsock — a hypervisor channel, not a network**: no management NIC exists, nothing in-range can discover or firewall the control plane, and a NIC-less guest is fully controllable (demonstrated). Loopback exists in the guest, so injected proxies (inspect_swe-style runtime binary injection) work; their upstream leg rides a vsock `forward` op.

Measured (metal): exec round-trip **1.1 ms median** (vs 44.5 ms for `docker exec` — the VM path is ~40× faster than the container path it replaced); file inject/extract **~400/~700 MB/s**; exec_remote-style polling overhead is noise; background processes survive exec returns; boot-to-daemon-ready **9.6 s** with the daemon baked into the image (cloud-init delivery costs +2 min on NIC-less guests — hence baked images are a requirement, not a preference).

### Windows targets: qemu-ga, by necessity — demonstrated

([win-guest spike](../spikes/win-guest/README.md); [guest-exec-lessons](guest-exec-lessons.md).)

**The control plane is unified: Windows targets speak the same vsock protocol as Linux guests.** The win-guest spike observed the vsock device unbound after a guest-tools install; the [viosock spike](../spikes/viosock/README.md) established why: the stable virtio-win ISO ships a **WHQL-signed** `viosock` driver (2k16–2k25, w10/w11) that the guest-tools MSI simply doesn't install — one `pnputil` call binds it and registers a Winsock provider (AF 40). The [vsockd-win spike](../spikes/vsockd-win/README.md) (2026-10-04) then **ported the daemon** (C# 5 / .NET Framework 4.8, compiled in-guest by the in-box `csc.exe`, SYSTEM service with restart-on-failure, Job-Object process-tree kill, `LogonUser`+`CreateProcessAsUser` for `user=`): identical wire protocol, driven by the identical host-side provider code — **`self_check` 40/44 with zero unexpected failures** (the four xfails are platform facts: no POSIX read-permission bit, adduser-provisioned user test, the 32,767-char Windows command-line cap → clean `E2BIG`, no signal-death exit codes), 15/15 native supplement, **570/570 soak with zero flake** (vs qemu-ga's ~5–7%), clean recovery across save/restore and reboot, file plane **400/281 MB/s** (~500× qemu-ga's 0.6 MB/s). **ISO hot-plug retires as the Windows bulk path; qemu-ga returns to being a build-time image tool.** The port encodes the viosock provider's quirks (no blocking mode — recv `WSAEWOULDBLOCK` / send `STATUS_BUFFER_TOO_SMALL` on empty/full buffers; single sends capped ~32 KiB; no select or overlapped I/O), none of which hurt throughput with a prompt reader.

Windows economics measured on metal: unattended Server 2022 install → finalized golden image **189 s**; boot from golden overlay to exec-responsive **6.5 s**; memory snapshot save **10.1 s** (4 GB → 1.16 GB state), **restore 1.3 s** with the agent responsive 0.1 s later. Checkpoint-after-AD-converges is the Windows boot-storm answer — now demonstrated, not hypothesized: the [ad-domain spike](../spikes/ad-domain/README.md) built a working forest (promotion 177 s, join 20 s) and restored the converged pair in 3 s with the Kerberos secure channel intact. Per reviewer recommendation the per-sample default is a cold boot of the converged disks; the measured memory-restore path is an experimental per-range opt-in ([memory-restore-ad](memory-restore-ad.md)). Its one hard finding: clones joining a domain whose DC shares their golden image are refused outright (domain SID = machine SID), so **AD-bound golden images must be sysprep-generalized** (~3.5 min specialize per clone, paid at range build, not per sample).

### The exec/file contract (the hard-won part)

The Proxmox provider (MIT) encodes the qemu-ga edge cases we would otherwise rediscover, and its lessons bind our vsock daemon as *contract* even where the transport dodges the mechanics ([guest-exec-lessons](guest-exec-lessons.md)):

- Never run the user's command directly: a generated wrapper applies cwd/env/user/stdin, enforces the timeout **in-guest** (`timeout -k`), and writes results to durable storage — because qemu-ga's `exec-status` is **single-shot** (output is discarded after one read) and retried launches can double-run (their flock guard; our request IDs).
- The virtio-serial channel fails **~5–7% of calls on Windows** — retry with transient/permanent classification and layered budgets is a protocol layer, not an afterthought.
- **Every reply from a guest is attacker-controlled** (an agent that roots a VM owns its daemon): strict schema validation, tamper errors, reader-side byte caps, and a hostile-daemon shim in the conformance tests.
- Inspect's sandbox `self_check` suite is the acceptance test for both planes.

### Images

Pinned upstream cloud images → derived goldens via offline `virt-customize` (daemon baked in; package installation belongs in Packer CI — `--install` is broken on noble hosts); qcow2 overlays per guest on read-only goldens, never in a container layer; backing references must be relative (cache mounts at a different path in-container); publication as **content-addressed qcow2 delta layers over OCI/ORAS** — Docker's distribution model with backing chains in place of overlayfs — with digest-verified eager S3 pulls as the fleet cold-start baseline (revised 2026-10-05: S3-only; EBS/FSR demoted to a deployment-side cache-in-AMI note) and lazy HTTP backing (`curl` driver + copy-on-read; measured: 0.4 s boot penalty, chains resolve over HTTP, self-warming cache) hiding Windows-sized pulls ([image-distribution](image-distribution.md), [lazy-pull spike](../spikes/lazy-pull/README.md)). Standard agent/guest images ship **zero network listeners** (`ss -tlnp` empty at boot — access is vsock-only); the current spike images violate this (cloud-image sshd), recorded as hardening backlog item 9.

## 6. Security posture

([agent-containment](agent-containment.md) is the full record; this is the synthesis.)

**Threat model.** The untrusted principal is the agent (potentially a frontier model) with root and raw-network tooling inside its VM — `NET_ADMIN`/`NET_RAW`-class capabilities are the product, not a privilege to withhold. Targets become attacker-controlled *by design* once compromised, so their daemons' outputs are untrusted too. Assets: (inter-sample) other tenants' samples; (intra-sample) eval validity — scoring artifacts, flags, evidence.

**Boundary stack and escape chain.** The agent faces, in order: (1) **KVM** — a hypervisor escape through a minimal virtio device model is the only opening move; commodity container escapes don't apply. (2) Landing in the QEMU process means landing as an **unprivileged user inside an unprivileged, credential-free container**: the [hardened-container spike](../spikes/hardened-container/README.md) (2026-10-04) demonstrated the full stack with `cap_drop: ALL` plus an explicit eight-capability list (each justified by an observed failure when removed), QEMU running as `libvirt-qemu` (not container root) with `-sandbox on,elevateprivileges=deny,spawn=deny`, Docker's default seccomp and AppArmor (`docker-default (enforce)`) applied, `no-new-privileges`, no Docker socket, read-only goldens, IMDS blocked by hop-limit-1, `NET_ADMIN` scoped to its own netns — at zero measured cost (49.8 s to enforced-ready vs ~50 s unhardened). (3) Host root requires a *second, independent* kernel/runc exploit. (4) The host is deliberately **asset-free**: no secrets, evidence streamed off-instance, Nitro caps the blast radius at one invalidated sample.

**Honest tier grading.** Nitro (no public escape; carries EC2 multi-tenancy) > Firecracker (~50 K lines Rust, tiny device model, production multi-tenant boundary) > QEMU/KVM (large C codebase, recurring contest escapes — but nearly all land in the QEMU *process*, i.e. our jailed container, and the practical surface is the *configured* device model). The architecture pairs boundary strength to stakes: Nitro guards tenants; QEMU guards one sample's validity, where a breach is detectable and discardable.

**Why the VM boundary earns its cost: eval validity.** An agent that escapes a *container* on the eval host gets the Docker socket — and with it the range spec, planted flags, and the answer key: the ability to cheat quietly rather than solve. Behind KVM, that costs a hypervisor escape first. Detection (evidence streaming) covers tampering; the VM boundary covers *reading the answers*, which is quieter than tampering.

**vsock-plane security.** CIDs are host-kernel-global (not namespaced): allocation is deterministic per host, guests' daemons accept only CID 2 (the hypervisor host), and isolation of the control plane between samples leans on one-sample-per-instance — restated as a dispatch constraint in §7. Guest daemons are untrusted endpoints (above).

**Defender→agent isolation.** In-range defenders cannot *connect* to the agent (the control plane has no IP endpoint; standard images ship zero network listeners — the only connectable surface is a port the agent opened as tradecraft), can *detect* only its transmitted traffic (interior, control channel, and oracle are invisible to in-guest defenders; fingerprinting is homogeneous with targets), and cannot *own* it remotely except by hack-back through the agent's own tooling — a per-range D5 policy decision; even then an owned agent box cannot pivot (vsock is host↔guest only) and costs one detectable sample. Defender→agent port scans returning zero open ports are mandatory range conformance checks. Full analysis in [agent-containment](agent-containment.md).

**Precondition, stated loudly: one sample per instance.** The entire posture is derived from this asset layout. If multi-sample packing is ever proposed, the container boundary becomes load-bearing between tenants and everything in this section must be re-derived.

**Dev vs prod.** The devbox (shared, holds a repo-scoped GitHub token, 443 egress) runs the identical containment stack, so routine dev-grade runs are fine; genuinely adversarial runs belong on production instances. Isolation level is a **logged per-sample claim** (`instance` vs `shared`), with warnings for untrusted-model evals on shared hosts.

**Hardening backlog** (ranked; items 3 and 6 are "make QEMU-in-a-jail approximate Firecracker-in-a-jailer"):
1. Branch protection + required review on `main` (blunts the one asset that reaches beyond any box — the devbox GitHub token).
2. Evidence streaming off-instance implemented early (it *is* the integrity story).
3. QEMU surface reduction — **done** ([min-devices spike](../spikes/min-devices/README.md)): explicit per-role domain XML (agent strict-minimal: virtio disk/net/vsock/rng + serial only; targets add video where scenarios need it); guest-visible PCI 25 → 15; seed moved to a virtio disk; the qemu-ga channel dropped from Linux guests; full battery green under the hardened profile at 44.1 s range-ready. `seccomp_sandbox` on since hardened-container.
4. Deny `AF_VSOCK` to non-range containers on dev boxes.
5. Tripwires: alert on abnormal QEMU exits; canary credentials in the range container.
6. ~~Tailored AppArmor profile for the range container~~ **resolved cheaper than planned** (hardened-container spike): Docker's *default* AppArmor profile suffices once libvirt's mount namespace is disabled (`namespaces = []`); `apparmor=unconfined` is gone from the production profile. A tailored profile remains an optional tightening.
7. Devbox egress allowlisting; burn-after-risky-run practice.
8. Evaluate Docker userns-remap (container root → unprivileged host uid); rootless Podman via its Docker-compatible socket is the recorded fallback.

**Residual risks, accepted with eyes open:** a QEMU 0-day unwinds the intra-sample boundary (mitigated by 3/5; blast radius capped by Nitro); the devbox always holds richer assets than prod (mitigated by 1 and run placement). If the agent boundary ever needs Firecracker-class strength, the recorded upgrade path is a rust-vmm hypervisor (cloud-hypervisor) for the agent VM only — possible because the vsock plane doesn't care which VMM is underneath.

## 7. Deployment: sharded Inspect, strictly local realization

([host-provider](host-provider.md).)

Inspect's sharding layer dispatches samples to instances; a worker runs on each instance and drives `inspect_ranges` against the **local** Docker daemon — the vsock fast path everywhere, no remote plumbing. Both target environments converge: the orchestration environment's integration is "provision a Nitro instance (our bootstrap/AMI: Docker + host prerequisites, gated by `inspect-ranges doctor --json`, fixable by `doctor --fix-script`) → run the worker on it"; the run-inside-Nitro environment already works this way. Docker's role is precisely scoped: packaging/lifecycle/netns-scoping/cgroups for the hypervisor stack — never agent isolation (alternatives analysis in [agent-containment](agent-containment.md): host-libvirtd, Podman, containerd, gVisor/Kata all weighed and rejected or deferred).

What we require from the sharding layer: **one sample per instance lifetime** — release destroys the instance or hands it to independent reprovisioning; a used instance never returns to a warm pool (sequential reuse would let a compromised host persist into the next sample); the worker told its isolation level (for the logged claim); **mid-run log/evidence sync** off-instance — *open external dependency: confirm Inspect sharding supports mid-run sync; if end-of-shard only, evidence streaming needs its own channel.*

A second, fully supported topology (revised 2026-10-03; seam re-cut 2026-10-04) separates the scaffold from the range: a pluggable `HostProvider` lets an orchestration layer allocate a machine per sandbox. The seam contracts on a self-sufficient, digest-pinned **realization bundle** going in (realization splits into driver-side `render` and host-side `apply`), a transport-agnostic `RangeChannel` for control, and evidence as a declared output ([host-provider](host-provider.md), [range-channel](range-channel.md)). Transports range from the `docker exec`↔vsock bridge (the reference connected transport) to queued messages via an intermediary for backends with no inbound surface at all; nothing above the channel may know which. This is the **stronger posture** — the worker's model credentials and eval state live outside the attackable instance — and is preferred for untrusted-model runs; co-resident sharding remains the simpler default and runs the same render and apply stages in one process.

## 8. Host story: `doctor`

Implemented: `inspect-ranges doctor` verifies a host end to end (KVM/tun/vhost-net/**vhost-vsock** devices, Docker/Compose versions, cgroup v2, br_netfilter off, IPv6, image tooling, kernel readability), with exact fixes; `doctor --fix-script | sudo sh` applies the runnable subset (root-guarded, `SUDO_USER`-aware, review-first by construction — doctor itself never runs privileged, or its user-scoped checks would lie). Supported hosts: metal instances and c8i/m8i/r8i nested-virt (both devbox-provisionable); any Linux x86_64 with KVM for workstations; Mac develops via Remote-SSH to a devbox. Only `up` needs KVM — `validate`/`render`/authoring run anywhere.

## 9. Evidence and scoring integrity (designed, mostly unbuilt)

The oracle sees everything; defenders see only what the agent transmits. pcap capture happens on bridges in the range container — outside every VM including the agent's — giving the eval-correct asymmetry: the agent's sanctuary is invisible to in-range defenders (no management NIC to discover) but fully observed by scoring. Evidence (pcaps, consoles, artifacts) streams off-instance as generated, which is what makes the security posture's detection-over-prevention stance a property rather than a plan — hence backlog item 2 and the §7 dependency. Scoring material stays off-instance where range content allows; readiness gates on cloud-init completion per VM, not daemon-up (a daemon-up range can be an *unenforced* range — observed directly in the networking spike).

## 10. Performance envelope (all measured, metal)

| Operation | Measured |
|---|---|
| 1 Linux VM range: compose up → SSH-able | 15.3 s cold |
| 4-VM two-segment range: up → all daemons | 16 s |
| 4-VM range fully enforced (cloud-init done) | 50 s |
| vsock exec round-trip (median / p95) | 1.1 ms / 3.5 ms |
| `docker exec` (comparison) | 44.5 ms / 47.2 ms |
| vsock file inject / extract (100 MB) | 398 / 696 MB/s |
| qemu-ga file transfer (Windows) | ~0.6 MB/s (bulk → ISO hot-plug) |
| Windows Server 2022 unattended install → golden | 189 s |
| Windows boot → exec-responsive | 6.5 s |
| Windows 4 GB snapshot save / restore | 10.1 s / 1.4 s |
| Agent VM boot → daemon ready (baked image) | 9.6 s |
| Full `inspect eval` vs 2-VM range (boot→solve→score→teardown) | 15–16 s |
| Lazy-pull boot (HTTP backing, no pre-download) vs local | 10.2 s vs 9.8 s; warm reboot 7.2 s (+11 MB) |
| AD forest promotion (Server 2022, via qemu-ga) → AD DS answering | 177 s |
| `sysprep /generalize` → specialized clone (new SID) | 208 s |
| Domain join post-sysprep → rebooted into domain | 20 s |
| Converged DC+member pair: save / restore (secure channel intact) | 19 s / 3 s |
| Checkpoint bundle: capture / per-sample instantiation (overlays + restore pair + clocks) | 19 s / **3 s** |
| Hardened container profile vs prototype profile (4-VM enforced-ready) | 49.8 s vs ~50 s (no cost) |
| Minimal device model + hardened profile (4-VM enforced-ready; guest PCI 25 → 15) | 44.1 s |
| GOAD-light forest build (root + child + delegation + member + Linux box, verified) | 1007 s (child promotion 467 s is the long pole) |
| Whole-forest save / restore (4 VMs, trust + secure channel intact) | 48 s |
| Boot storm, warm host: 48 concurrent ranges (96 VMs), zero failures | median 77 s vs 47 s solo; no knee found |
| S3 eager pull (32 parallel streams, unsigned HTTPS) | 617 MB/s (Linux set ~2 s, Windows set ~20 s, worst AD set ~41 s) |
| S3 ranged GET, 64 KiB cold reads (lazy-boot pattern) | 146 ms median / 225 ms p95 TTFB |
| Windows vsock daemon: channel RTT / exec RTT | 0.36 ms / 17.3 ms (vs ~2 s qemu-ga exec) |
| Windows vsock file plane (100 MB, verified) | 400 / 281 MB/s (vs 0.6 MB/s qemu-ga) |

Not yet measured: nested-virt (c8i/m8i) vs metal deltas, cold-start economics under the S3 baseline (eager-pull throughput measured by [s3-pull](../spikes/s3-pull/README.md); the EBS/FSR comparison is [superseded](../spikes/ebs-fsr/README.md)), Windows restore storms — handoff §13 experiments 3–5, partially closed by boot-storm.

## 11. Implemented vs designed — the ledger

| Component | Status | Evidence |
|---|---|---|
| Schema v0.1 + `validate` + JSON Schema | **Implemented** | `schema.py`, 58 tests, six examples green |
| `doctor` + `--fix-script` | **Implemented** | CLI + tests; in daily use on the devbox |
| Devbox tooling (metal + nested) | **Implemented** | `devbox/` |
| Unprivileged libvirt-in-Docker runtime | **Demonstrated** (spike) | l2-attach, net-compile |
| Hardened container profile (cap floor, non-root QEMU, default seccomp/AppArmor, QEMU sandbox) | **Demonstrated** | hardened-container, 23/23 checks, zero cost |
| AD domain build through the pipeline (promotion, sysprep, join) | **Demonstrated** | ad-domain |
| Checkpoint cloning (fresh independent samples from a converged bundle) | **Demonstrated** | checkpoint-clone, 3 s/sample, named CPU model |
| Two-domain AD forest from an example range.yaml (trust, DNS chain, Linux in-zone) | **Demonstrated** | goad-forest |
| Windows vsock transport (signed driver, data path) | **Validated** | viosock |
| Windows vsock daemon (unified control plane) | **Demonstrated** | vsockd-win: self_check 40/44 (0 unexpected), 570/570 soak, 400/281 MB/s |
| Compiled networking (IPAM→nftables) | **Demonstrated** (spike-grade compiler) | net-compile, 9/9 checks |
| vsock exec/file plane | **Demonstrated** (prototype daemon) | vsock-exec |
| Windows guests + qemu-ga + snapshots | **Demonstrated** | win-guest |
| Sandbox provider (`SandboxEnvironment`) + `self_check` | **Demonstrated** (spike): `inspect eval` end-to-end, accuracy 1.0 in ~15 s; `self_check` 41/44 (all 3 failures = daemon-as-root permission semantics) | [e2e-provider spike](../spikes/e2e-provider/README.md) |
| Production vsockd (idempotent, validated, hostile-tested) | Designed | guest-exec-lessons punch list |
| Evidence streaming off-instance | Designed | backlog item 2; §7 dependency |
| Image pipeline (Packer CI, ORAS registry) | Designed | handoff §7 |
| QEMU device minimization (explicit per-role XML) | **Demonstrated** | min-devices: PCI 25 → 15, battery green, 44.1 s |
| Semantic schema validators (duplicate IPs, DNS refs, ACL attachment) | **Implemented** | `schema.py`, 68 tests |
| Deferred schema sections (attack_path, goals, variables, defense, guest config) | Deliberately deferred | schema-v0.1-scope deferral table |
| Separated HostProvider topology | Designed, supported; implementation not started | host-provider (seam re-cut 2026-10-04), range-channel |
| KubeVirt / Proxmox / EC2-routed backends | Future | handoff §9 (capability declarations) |

## 12. Open questions for reviewers

1. **Inspect sharding mid-run sync** (§7) — the one external dependency load-bearing for the security posture.
2. **ACL expressiveness**: v0.1's single router-level vocabulary deliberately drops subnet NACL semantics (translated at carve time) — is that the right v1 cut for ranges you want to run?
3. **libvirtd itself**: we use a thin slice of a heavyweight daemon; driving QEMU directly would shrink the range container's surface at reimplementation cost. Parked until the provider's real libvirt usage is known.
4. **Agent-boundary strength**: is jailed-minimal-QEMU acceptable for the threat models you care about, or should the rust-vmm agent-VM option be scheduled rather than recorded?
5. **The deferral table** (schema-v0.1-scope): does any deferred section need to move up for your use cases — particularly `goals`/oracles for scoring?
6. **Dual-use posture** (handoff §12): tooling public, generation pipelines/held-out content controlled — unchanged by this architecture, but review-worthy alongside it.

## 13. Confirmation spikes: done and queued

**Done** (2026-10-03/04):

1. **Active Directory range** — [ad-domain](../spikes/ad-domain/README.md). DC promotion + member join from clones of one golden image works end to end over qemu-ga; the one hard finding is that unsysprepped clones are refused ("domain SID identical to machine SID"), so AD-bound images must be sysprep-generalized (208 s specialize per clone, once per range build). Promotion 177 s, join 20 s. Both remaining items closed by [goad-forest](../spikes/goad-forest/README.md) (below).
2. **Hardened container profile** ([external review](external-review.md) finding 3) — [hardened-container](../spikes/hardened-container/README.md). The measured capability floor (eight, each justified by an observed failure), non-root QEMU, default seccomp/AppArmor, QEMU sandbox; zero cost; egress conformance holds before and after simulated router compromise.
3. **Checkpoint cloning** (finding 4) — [checkpoint-clone](../spikes/checkpoint-clone/README.md). Bundled disk+memory+XML checkpoint of a converged AD pair on a named CPU model; destructive sample then a pristine second sample at 3 s per instantiation; survives container recreation. Memory restore has since been scoped to an experimental opt-in, with cold boot from the converged disks as the universal default ([memory-restore-ad](memory-restore-ad.md)). Remaining: cross-instance-family restore, bundle checksums/manifest.
4. **Windows vsock** (finding 8) — [viosock](../spikes/viosock/README.md). WHQL-signed driver on the stock ISO; binds via pnputil; native Winsock listener exchanged data with a Linux host client.
5. **Windows vsock daemon port** — [vsockd-win](../spikes/vsockd-win/README.md). Parity port of the v2 protocol (C#, in-box compiler, SYSTEM service): self_check 40/44 with zero unexpected failures, 15/15 native checks, 570/570 soak (zero flake), save/restore + reboot recovery, 400/281 MB/s files. Unifies the control plane; ISO hot-plug retired for Windows targets; qemu-ga back to build-time only. Remaining: production image recipe integration, checkpoint-flow behavior.
6. **Minimal QEMU device model** (backlog item 3) — [min-devices](../spikes/min-devices/README.md). Explicit per-role domain XML under the hardened profile: guest-visible PCI 25 → 15 (USB, memballoon, qemu-ga channel, 8 root ports removed; seed on virtio), full battery green incl. save/restore, 44.1 s range-ready (faster than defaults). No ease-on-failure entries were needed.
7. **Boot-storm density** — [boot-storm](../spikes/boot-storm/README.md). 1→48 concurrent ranges (96 VMs) on one metal host: graceful +61% latency, zero failures, no knee; warm goldens never touch disk; CPU and EBS writes are the (unsaturated) contended resources. Incidental finding promoted to the production template: range containers run `network_mode: none` (no Docker network at all — compose's default per-project networks exhaust Docker's address pools at ~31 projects, and the control plane needs only docker-exec + vsock).
8. **GOAD-light forest** — [goad-forest](../spikes/goad-forest/README.md). The flagship example's two-domain forest, with the build plan derived from its actual `range.yaml` (the first fixture to drive real VMs): root promotion 186 s, child domain + delegation 467 s, member join 74 s, ~17 min boot-to-verified-forest; cross-domain auth both directions through the parent-child trust; the Linux attack box resolves the AD zone per the spec's `dns.authoritative` and reaches Kerberos/LDAP; whole-forest save/restore in 48 s with trust and secure channel intact.

**Queued:**

1. **Inspect sharding mid-run log sync** — the open question in §12 item 1, confirmable with a small sharded run; load-bearing for continuous off-instance evidence in the co-resident topology.
2. **Evidence streaming path** — §9 is designed, unbuilt; now also a contract term of the deployment seam (a declared host output: durable, append-only, writable-not-rewritable — [host-provider](host-provider.md)); spike the minimal version (per-segment pcap + console to durable append-only storage, bypassing the scaffold).
3. ~~EBS/FSR cold start~~ **superseded (2026-10-05)**: S3-only adopted as the distribution baseline; eager-pull throughput measured by [s3-pull](../spikes/s3-pull/README.md), lazy boot already measured by lazy-pull; cache-in-AMI noted as the deployment-side zero-pull option.
4. **NAT-granted egress conformance** — the hardened-container spike verified the no-egress case structurally; the case where a range legitimately requests egress needs the compiler's `nat` realization plus the layer-3 conformance battery ([agent-containment](agent-containment.md) network-authority section).
5. **Channel conformance mocks** — the hostile and latency-injecting mock channels ([range-channel](range-channel.md)), due with the first provider implementation.

## 14. Next-phase design directions (recorded, not built)

From the [external review](external-review.md) triage; these shape the provider/compiler implementation phase and are deliberately design-only here.

- **The compiler emits an immutable resolved plan before any mutation** (finding 6): allocations (IPs, MACs, CIDs), routes and DNS roles per host, image digests, required host capabilities, resource totals, generated infrastructure names. Unsupported feature combinations fail at planning, not mid-boot. Scenario identifiers (IPs/MACs, deliberately repeatable across isolated samples) are distinguished from runtime identifiers (host-global CIDs, compose project names — collision-free by allocation). `validate`, `render`, admission, execution, and the eval log all consume the same plan. `render` emits the digest-pinned **realization bundle** (plan plus rendered compose project, domain XML, nftables, boot/verify spec) that the `apply` stage consumes; the bundle is what crosses the deployment seam ([host-provider](host-provider.md)).
- **The provider is a sample state machine, not a try/finally** (findings 2, 10): acquire (leased, with identity and expiry) → prepare → verify (containment conformance, collectors ready) → execute (agent starts only after verification) → finalize evidence → destroy. An independent reaper reclaims from recorded ownership; infrastructure failure is distinguishable from agent failure; admission limits include overlay growth, evidence volume, and process counts, and evidence-storage exhaustion yields an *indeterminate* sample, never a silent ordinary score ([scoring-integrity](scoring-integrity.md)).
- **Image distribution ships integrity-first** (finding 9): published blobs use a canonical relative-path layout so they materialize unchanged (digest-verifiable); verified eager pulls and immutable caches first; lazy registry reads only with chunk/block verification or an explicitly trusted immutable backing service (a whole-blob SHA-256 cannot authenticate arbitrary blocks mid-fetch). The measured local layering and EBS/FSR paths are unaffected.

## 15. Reading map

Decision records: [agent-containment](agent-containment.md) (security), [host-provider](host-provider.md) (deployment), [range-channel](range-channel.md) (channel wire contract), [scoring-integrity](scoring-integrity.md) (proof contracts), [range-build](range-build.md) (build manifest + checkpoints), [docker-provider-reuse](docker-provider-reuse.md) (what we port), [schema-v0.1-scope](schema-v0.1-scope.md) (spec), [guest-exec-lessons](guest-exec-lessons.md) (exec contract), [external-review](external-review.md) (findings triage). Evidence: [l2-attach](../spikes/l2-attach/README.md), [vsock-exec](../spikes/vsock-exec/README.md), [net-compile](../spikes/net-compile/README.md), [win-guest](../spikes/win-guest/README.md), [ad-domain](../spikes/ad-domain/README.md), [hardened-container](../spikes/hardened-container/README.md), [checkpoint-clone](../spikes/checkpoint-clone/README.md), [viosock](../spikes/viosock/README.md), [vsockd-win](../spikes/vsockd-win/README.md), [min-devices](../spikes/min-devices/README.md), [goad-forest](../spikes/goad-forest/README.md), [boot-storm](../spikes/boot-storm/README.md), [s3-pull](../spikes/s3-pull/README.md) — each reproducible via its `run.sh`. Background: [the design handoff](../inspect_ranges_handoff.md), [survey](survey.md), [range-yaml-swag](range-yaml-swag.md), the six examples under [ranges/](ranges/).
