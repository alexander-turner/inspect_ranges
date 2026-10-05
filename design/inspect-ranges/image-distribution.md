---
type: document
title: "Image distribution: content-addressed qcow2 layers, lazy block pull, and platform-native caches"
audience: inspect-ranges development
status: draft
tags: [inspect-ranges, images, distribution, registry, oras, decision]
timestamp: 2026-10-02
---

# Image distribution: content-addressed qcow2 layers, lazy block pull, and platform-native caches

*Prompted by the Proxmox provider author: "I'm super curious whether you can find a solution to the problem of the large binary images we end up needing to ship around. Docker 'solved' this by using overlayfs; in the proxmox provider there are template VMs and linked clones, but it's still not ideal." The reframe this doc builds on: Docker solved distribution with **content-addressed layers**; overlayfs is only the runtime view. Templates + linked clones replicate the runtime half; the missing half is the distribution model — and qcow2 has the native primitive to steal it.*

## The problem is three problems

1. **Local instantiation** (many guests/samples from one image): solved — read-only golden + per-guest qcow2 overlay, proven across all spikes. Linked clones are the same idea. Not the pain.
2. **Distribution of derived images** ("I changed one package; why am I shipping 12 GB?"): the real pain, addressed below with layering.
3. **Cold start at fleet scale** (a fresh instance needs 20 GB of goldens *now*): a different problem, addressed with lazy block access, not shipping formats.

## 1. Publication format: qcow2 backing chains as OCI layers (the 80% win)

A qcow2 with a backing file **is a delta layer**. Every derived image this project builds is already one (the vsockd golden is a few-MB overlay on the 600 MB noble base). So: publish images to the OCI registry (ORAS, already planned) as **manifests of qcow2 delta layers, each content-addressed, with the backing relationship pinned by digest in annotations**. Pull = fetch only missing layers; the puller materializes the chain in the local cache with *relative* backing paths (per the net-compile spike's backing-path lesson). This is Docker's model verbatim — manifest → content-addressed blobs → local CoW assembly — with qcow2 chains in place of overlayfs.

Disciplines that make it work:

- **Shallow chains** (2–3 deep: upstream base → org golden → task delta); every read miss walks the chain. Optional background flattening of hot images locally. This deliberately **inverts the handoff §7 guidance** ("publish flattened, chain locally"): publish *chained* for distribution economics; flatten *locally* if profiling demands.
- **Deltas derive only from pinned base digests**, enforced at push: a chain whose base drifted is corrupt by construction.
- Offline `virt-customize` derivation (already our practice) keeps task deltas naturally small; full Packer rebuilds are reserved for true bases.

## 2. Where lineage fails: content-defined chunking (targeted, not day one)

qcow2 deltas capture **write lineage, not content similarity**: a rebuilt Windows base (patch Tuesday) shares no chain with its predecessor, so the "delta" is everything. The fix for that case is CDC — `casync`/`desync`-style rolling-hash chunks, content-addressed chunk store (S3), ship only changed chunks; CDC finds the unchanged bulk of a rebuilt image with no lineage at all. It slots under the same registry index (chunk index as an OCI artifact). Hard constraint: CDC needs a **stable representation** — compressed qcow2 scrambles chunk boundaries; chunk the raw view or uncompressed qcow2, or the dedup evaporates. Prior art to study before building: **overlaybd** (block-level layered OCI with lazy pull — the closest existing system), KubeVirt containerDisk/CDI (cautionary: one layer = whole blob, no delta win), zchunk/zsync.

Position: hold CDC until base-rebuild churn actually hurts; monthly full-base ships may be acceptable long before task-delta ships are.

## 3. Cold start: pull from object storage (revised 2026-10-05: S3-only is the baseline)

*Revision provenance: the deployment design under review supports object storage but not an EBS snapshot/volume interface. Analysis concluded S3-only costs little and fits more architectures, so the EBS path is demoted from "designated production path" to a deployment-side note.*

- **Baseline: digest-verified eager pull from object storage (S3 or any registry).** A fresh instance pulls the range's chains before first boot, verified blob-by-blob against the manifest digests (the integrity contract below). The cost is bounded and Windows-shaped: Linux range sets (≤1 GB) pull in seconds; Windows/AD sets (10–25 GB incl. checkpoint memory images) cost tens of seconds per instance at measured S3 throughput ([s3-pull spike](../spikes/s3-pull/README.md)) — paid per sample under one-instance-per-sample, amortized to zero on long-lived dev hosts. The deployment interface collapses to "read access to a bucket" (or the granted-URLs mode below), which composes with any provisioner and any object store (S3, GCS, MinIO).
- **Optional lazy boot: QEMU's curl block driver + copy-on-read — bounded by measured S3 latency, never the default.** An HTTPS URL can *be* a backing file; a local overlay opened `copy-on-read=on` self-populates with every block the guest reads. **Measured** ([lazy-pull spike](../spikes/lazy-pull/README.md)): lazy boot 10.2 s vs 9.8 s local against a same-host HTTP cache — but that number does *not* transfer to S3, where cold 64 KiB ranged reads run **~146 ms median TTFB** ([s3-pull](../spikes/s3-pull/README.md)), making demand-paged boot TTFB-bound and jittery — the same instability class as booting on an un-warmed EBS volume (confirmed by Proxmox-provider operational experience, 2026-10-05). The supported shapes are therefore: eager pull before boot (the baseline — at 20–40 s for Windows sets it is cheap enough to be the default), lazy boot racing a **background full hydrate** (`block-stream`/parallel fetch, with range-readiness still gating on provisioning completion so a sample never starts on a cold disk path), or pure lazy only against a low-latency backing tier (same-host or same-VPC cache, where the +0.4 s figure was measured). The mechanism resolves **multi-layer backing chains over HTTP**, so §1's chained distribution and lazy access compose for free; the integrity condition is satisfied because the bucket is ours (an *explicitly trusted immutable backing service*, per the contract below). Honest caveat: a small Linux golden's first boot over-fetched (123% of chain size — working set ≈ whole image, plus readahead/COR races), so for small images lazy pull wins on *time*, not bytes. Requires `qemu-block-extra` on Ubuntu. The shared-cache tier (one streamed copy serving many VMs on a host) uses the same chain plus `block-stream`/background flatten into a host cache layer — design sketch, not yet built.
- **Deployment-side note: cache-in-AMI recovers the EBS behavior without an EBS interface.** An AMI *is* an EBS snapshot: a deployment that bakes the image cache into its instance image (optionally with Fast Snapshot Restore enabled on it) gets lazy block hydration and zero-pull cold starts implicitly, versioned with the AMI. This is the deployment's choice and machinery, not ours — the orchestration layer never needs volume/snapshot operations in its interface. (This demotes the earlier "EBS snapshots + FSR as designated production path" framing; FSR is a paid, per-AZ operational knob, and plain EBS hydration is lazy S3 underneath — often slower than an eager parallel pull.) **Warming is mandatory on this path**: booting ranges against an un-hydrated snapshot-backed volume is a known instability source (Proxmox-provider operational experience, and consistent with our measured S3 cold-read latency) — a deployment choosing cache-in-AMI must enable FSR or fully pre-warm the volume before range boot.

## Integrity and materialization (added 2026-10-04, external review finding 9)

The layering story needs its trust semantics stated, not implied:

- **Published blobs are canonical and materialize unchanged.** A qcow2's backing reference is part of its bytes, so rewriting it after download would break digest verification. The publication format therefore fixes a canonical *relative* layout (backing refs are relative names within the cache layout, set at build/push time); the puller writes blobs verbatim, verifies each against its OCI descriptor digest, and never edits them. Anything locally derived (flattened hot images, overlays) lives apart from verified source blobs and is never pushed as if original.
- **The local cache has ownership rules**: downloads land under temporary names and move in atomically (concurrent pullers converge by digest); a manifest is usable only when every referenced blob is present and verified (no partial publication observed as complete); eviction is by whole chain, never a backing layer out from under a dependent; backing-chain validation (every `backing file` resolves inside the cache and matches the manifest's digest annotations) runs at materialization.
- **Lazy reads have an integrity gap that eager pulls do not**: a whole-blob SHA-256 cannot authenticate arbitrary blocks before the full blob has been fetched. The curl+copy-on-read path is therefore only sound against an *explicitly trusted immutable backing service* (same-trust-domain nginx/S3, as in the spike), or with chunk/block-level verification (CDC chunk digests, §2) in front of an untrusted registry. Production ships **verified eager pulls + immutable caches first**; lazy registry reads arrive only with one of those two integrity contracts stated.
- **Delivery modes are deployment capabilities, not integrity variants** (added 2026-10-04, deployment seam): a backend declares `image_delivery` as `registry | granted-urls | pre-seeded` and supplies a *fetch grant* per digest with the realization bundle ([host-provider](host-provider.md)). All three modes sit under the same contract above — digest-pinned blobs, verified before use, canonical layout. Granted URLs are the connectionless shape of a pull (pre-signed, digest-pinned blob fetches with no registry credential on the instance); pre-seeded means the cache already holds the verified chain.

## Recommendation

Local golden+overlay (done) → **chained-qcow2-over-ORAS** as the publication format (small to build; the compiler/image tooling already emits the deltas) → **digest-verified eager pull from object storage** as the fleet cold-start baseline, with **curl+copy-on-read against the same bucket** hiding the Windows-sized pulls (cache-in-AMI available deployment-side where zero-pull matters) → CDC held as the targeted fix for base-rebuild churn.

The one-line answer to the Proxmox author: *linked clones are the overlayfs half; the missing half is content-addressed layer distribution, and qcow2 backing chains let you take it from Docker almost verbatim — and in the fleet case, lazy block access over the bucket means a guest can boot before its image has been "shipped" at all.*
