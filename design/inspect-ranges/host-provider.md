---
type: decision
title: "Deployment seam: two supported topologies — co-resident sharding, or a host interface separating the scaffold from the range"
status: accepted
tags: [inspect-ranges, sandbox, deployment, sharding, host-provider, decision]
timestamp: 2026-10-01
---

# Deployment seam: two supported topologies — co-resident sharding, or a host interface separating the scaffold from the range

*Decision record. `inspect_ranges` never creates the Nitro instance it runs on — it stipulates one ([agent-containment](agent-containment.md) precondition). This records how the stack reaches its instance in production, concretizing handoff §11's "separate where from what". An earlier same-day draft made a pluggable per-sample Docker-endpoint (`HostProvider`) the primary seam; superseded once Inspect's sharding emerged as the natural fit (and as how the run-inside-Nitro environment already operates). Revised 2026-10-04, before any provider implementation: the separated seam is re-cut to contract on a realization bundle in, a transport-agnostic `RangeChannel` for control, and evidence as a declared output, with the Docker endpoint demoted to one transport. The wire contract lives in [range-channel](range-channel.md).*

## Decision

**Sharding is the default deployment model; `inspect_ranges` realizes ranges through the channel the deployment supplies** — an in-process channel over the local daemon under sharding, or a `HostProvider`-supplied per-sample channel in the separated topology. Everything below the channel (range container, VM boot, vsock exec/file, evidence, teardown) is identical in both.

- Inspect's sharding layer dispatches samples to instances; an Inspect worker runs on each instance and drives `inspect_ranges` in place. The "where" (instance provisioning, sample dispatch) belongs to the sharding layer and the caller's orchestration; the "what" (render, range container, VM boot, vsock exec/file, evidence, teardown) is ours and is strictly host-local.
- Both deployment environments converge on the identical on-instance story. The orchestration environment's integration is: provision a Nitro instance its way (our bootstrap/AMI provides Docker + host prerequisites, gated by `inspect-ranges doctor --json`, fixable by `doctor --fix-script`) → run the worker on it. No inspect_ranges-specific provisioning interface to implement.
- **The host-interface path is fully supported** (revised 2026-10-03; it was previously deferred-until-sharding-proves-unviable): a `HostProvider` lets an orchestration layer allocate a machine per sandbox, with the Inspect scaffold running in a completely separate context from the range. **This topology has the stronger security posture**: in the co-resident topology the worker — and its model API credentials and live eval state — shares the instance an escaped agent would land on; the separated topology moves all of that outside the blast radius. Co-resident sharding remains the simpler default (direct vsock, no transport in the way); the host interface is preferred where isolation of the scaffold matters (e.g. frontier/untrusted-model runs).
- The channel interface is the contract, not an insurance policy (revised 2026-10-04; it began as "a thin channel interface so a bridged transport can be added later"). Nothing above the channel may know its transport.

## What we require from the sharding layer

The containment preconditions, restated as dispatch constraints:

- **One sample per instance lifetime** — the entire [containment posture](agent-containment.md) is derived from this, and "at a time" is not enough: under the threat model a compromised host can persist into the next sample even after every VM and container is removed. Release means the instance is destroyed or handed to an independently controlled reprovisioning process; a warm pool may hold only never-used instances, and a used instance never returns to one.
- The worker is told its isolation level (`instance` in production, `shared` on dev boxes) so the per-sample eval-log claim stays truthful; `shared` warns for untrusted-model evals.
- **Mid-run log/evidence sync off-instance**, not end-of-shard collection — prompt streaming is load-bearing for detection-over-prevention (agent-containment backlog item 2). This must be confirmed against Inspect's sharding semantics early; if sync is end-of-run only, evidence streaming needs its own channel. The seam now names evidence as a declared output (below), so the separated topology meets this by contract.

## Development

- Linux workstations with KVM and the EC2 devbox run the same local path (dev *is* production topology, minus the isolation claim).
- Mac/laptop development uses VS Code Remote-SSH onto the devbox — already the documented path — so no remote Docker support is needed for dev either. (`DOCKER_HOST=ssh://` remoting stays out for dev: the bridged transport is a production seam component, not a dev convenience.)

## Choosing a topology

- **Co-resident (sharding)**: simplest; direct vsock fast path (1.1 ms exec); the worker's model credentials and eval state are on the instance — acceptable for dev and lower-stakes runs.
- **Separated (host interface)**: scaffold, credentials, and logs live outside the attackable instance; exec rides the channel's transport (bridged: setup once per sample, then network RTT + ~1 ms per call; connectionless: second-scale calls). Preferred where the agent is genuinely untrusted.

## The host interface, as re-cut (2026-10-04)

The earlier sketch contracted on a `DockerEndpoint` (a `DOCKER_HOST`-style URL plus credentials) with exec tunneled through one held-open `docker exec`↔vsock stream. Both are transport decisions, and putting them in the contract had two costs. It excluded the strongest separation postures: a sandbox host with no inbound surface at all (nothing to dial; driver and host exchange queued, schema-validated messages through an intermediary under per-principal access scoping; image bytes arrive as digest-pinned blobs over granted URLs). A seam designed for separation should not require a standing connection to the thing it is separating from. And it granted broad standing authority: a Docker credential lets a compromised scaffold run arbitrary containers on the host, where the [scaffold-compromise analysis](agent-containment.md) asks for narrow authority between the parser of attacker-influenced bytes and anything holding credentials. The channel's verbs are exactly that narrow interface, auditable per verb.

### Render → apply: the realization bundle

Realization splits into two stages of one pipeline. **`render`** runs driver-side, where the compiler toolchain lives, and turns the resolved plan into concrete artifacts. **`apply`** turns artifacts into a running range: co-resident runs it in-process; separated ships it host-side (packaged into the AMI/bootstrap, gated by `doctor`). The seam, where present, sits between the stages.

What crosses the seam is the **realization bundle**: the resolved plan plus the rendered compose project, per-guest domain XML, network definitions, nftables rulesets, boot order with readiness probes and the verify-battery spec, and a reference to the [range build manifest](range-build.md) by digest — all under a digest-pinned top-level manifest. The applier verifies the bundle digest, format version, and host versions before acting, and refuses on mismatch; the eval log records the bundle digest, so the exact bytes applied to the host are auditable.

- **Self-sufficiency rule**: the bundle plus a backend-supplied *fetch grant* per image digest must be sufficient to realize the range with zero further driver round trips. If realization has to ask the driver anything mid-flight, the plan was incomplete; treat that as a compiler bug, in the same spirit as "unsupported feature combinations fail at planning, not mid-boot". (Strictly host-side realization is only *required* for connectionless backends; the rule that matters everywhere is bundle self-sufficiency.)
- **Render inputs are host-class declarations, never per-instance probes**: the canonical cache layout ([image-distribution](image-distribution.md)), CIDs allocated in the plan, the named CPU model per fleet ([range-build](range-build.md)). A backend that cannot meet the conventions refuses at planning, like any other capability mismatch.
- **Secrets stay out of the bundle**: proof material is generated driver-side (the scorer needs it), planted after verify through channel verbs, and recorded only at the evidence sink (per range-build and [scoring-integrity](challenges-scoring-integrity.md)). The bundle is a function of range version, host class, and per-sample allocations, with no confidentiality requirement beyond the intermediary's access scoping.

### Lifecycle is messages, not calls

`realize(bundle, grants)` and `teardown()` are requests; the host answers with staged progress reports (fetch, construct, boot, verify, ready | failed) carrying structured diagnostics, plus a periodic heartbeat with per-guest state. The driver gates the agent's start on the host-side **verify** stage (the containment conformance battery: egress checks, defender port-scan negatives, no host-side vsock listeners) reporting green; per-sample secrets are planted after that gate. The sample is a state machine — acquire (leased) → realize → verify → execute → finalize evidence → destroy — with every transition observable as a message.

The production contract from the external review (finding 10) carries over unchanged:

- **Lease semantics**: `acquire` returns a lease with an identity and an expiry; a sample that outlives its lease is reclaimed. Controller crashes, interrupted acquisition, partial boots, and network partitions are normal cases, not exceptions.
- **An independent reaper**: cleanup must be idempotent and recoverable from recorded resource ownership (instance tags, compose project names), never dependent on the original Python process reaching `finally`. The e2e spike demonstrated the failure concretely: `pkill` on the harness leaves the range running.
- **Release is destruction**: per the dispatch constraint above, `release` destroys the instance or hands it to independent reprovisioning; it never returns a used instance to a pool.

### Interface sketch

```python
class RangeChannel(Protocol):
    """Transport-agnostic control plane to one sample's range.

    Implementations: direct vsock (co-resident); a docker-exec↔vsock bridge
    over ssh/tls (the reference connected transport; measured numbers in the
    vsock-exec spike); queued messages via an intermediary (connectionless).
    Nothing above this interface may know which.
    """

    async def realize(self, bundle: RealizationBundle, grants: FetchGrants) -> AsyncIterator[StageReport]: ...
    async def exec(self, guest: str, req: ExecRequest) -> ExecResult: ...
    async def read_file(self, guest: str, path: str) -> bytes: ...
    async def write_file(self, guest: str, path: str, data: bytes) -> None: ...
    async def forward(self, guest: str, target: ForwardTarget) -> ForwardHandle: ...  # capability-gated
    async def teardown(self) -> None: ...

class RangeHost(Protocol):
    channel: RangeChannel
    isolation: Literal["instance", "shared"]   # claimed by the provider, logged per sample
    capabilities: HostCapabilities             # backend + deployment declarations (below)
    facts: HostFacts                           # arch, host-class identity

class HostProvider(Protocol):
    async def acquire(self, sample: SampleSpec) -> RangeHost: ...   # returns a lease: identity + expiry
    async def release(self, host: RangeHost) -> None: ...           # release is destruction
```

*As built ([range-host-v1](range-host-v1.md), 2026-10-10): the sketch held with four recorded deviations. `channel` is `RangeChannel | None` (the co-resident backend attaches it after boot), `RangeHost` gained `check_lease()` (ops surface lease loss loudly), `acquire` takes a `LeasePlacement` second argument (driver-side placement facts the lease record needs that `SampleSpec` deliberately omits), and `HostProvider` gained `abandon()` for the `cleanup=False` path. Code: `src/inspect_ranges/_host/host.py`.*

Providers register through the same entry-point mechanism as other inspect_ranges components; `acquire` gates on `doctor` readiness and fails the sample fast with the report. The message-level contract the channel's transports must satisfy (request IDs, idempotent retry, durable replies, bulk data, error taxonomy, reply validation) is specified in [range-channel](range-channel.md); every transport is subject to the same conformance testing (`self_check`) as the local fast path.

### Deployment capability declarations

Backend capability declarations (handoff §9: `l2_broadcast`, Windows guests, nested virt; a backend that cannot provide them refuses rather than silently degrading) extend to deployment capabilities, at minimum:

- `forward_upstream`: whether `forward` can reach anything outside the sample. A maximally isolated deployment has no such path (model credentials live only driver-side), so injected-proxy scaffolds fail at planning with a clear message, and exec-driven scaffolds remain the portable shape.
- `egress_grant`: whether the deployment grants a range's requested external access. The three-layer network-authority model ([agent-containment](agent-containment.md)) already says the spec *requests* and the deployment *grants*; this makes the refusal machine-checkable at planning.
- `image_delivery`: `registry | granted-urls | pre-seeded`, so the plan carries the right fetch shape (see [image-distribution](image-distribution.md)).

### Evidence is a declared output

Evidence (pcaps, consoles, verification results, scoring artifacts) is a first-class output of the host with its own delivery contract: durable, append-only, writable-not-rewritable by the host. This makes the integrity rule from agent-containment ("the evidence path must not depend on the scaffold's continued honesty") a property of the seam instead of a plan, and moves the mid-run sync requirement from backlog to contract terms every backend must meet. Backends whose transport is already durable, append-only object storage get it nearly free.

*Implemented by [evidence-v1](evidence-v1.md) (2026-10-15): capture outside every VM, a hash-chained write-once record beside the eval log with the seal digest bound into the sample store, the applier as the host-side capture writer in the separated topology, and the reaper sealing abandoned records. The mid-run sync dependency on Inspect sharding is closed for evidence (the sink is the host's own writer) and remains open only for eval logs.*

### Latency is a declared budget

The contract must hold at round trips on the order of a second, not only at vsock's 1.1 ms: timeouts enforced in-guest (already the design); no multi-round-trip chatter in the hot path (bulk data never rides the control message); readiness narrated by staged reports rather than driver-side spin-polling. Enforced mechanically: `self_check` conformance runs against a latency-injecting mock channel in CI, so a chatty regression fails fast rather than surfacing only on a slow backend. Direct vsock keeps its 1.1 ms through the same interface. At measured call volumes (low hundreds of execs per sample) a second-scale transport costs minutes per sample, traded for isolation.
