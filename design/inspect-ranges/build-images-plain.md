---
type: document
title: "The build/images system in plain language: from range.yaml to a running range"
status: draft
tags: [inspect-ranges, build, images, distribution, overview]
timestamp: 2026-10-17
---

# The build/images system in plain language: from range.yaml to a running range

*A one-page companion to [build-images-requirements](build-images-requirements.md). That document is the exhaustive inventory; this one is the story. It describes the end-to-end system the architecture work is designing, in ordinary language, and makes no new decisions. Where it states something as settled, a decision record says so; everything else is the target we are designing toward.*

## The story

**An author writes a range.** A `range.yaml` file declares everything the range is: the machines and networks, and the guest content that makes it a scenario rather than empty infrastructure (user accounts, running services, planted vulnerabilities and misconfigurations, files on disk, defensive telemetry, an Active Directory forest). The author gets fast feedback from `validate` and `plan` without building anything. Today this part works, but the guest content is declaration-only: the planner refuses to realize it. The build system is what deletes those refusals.

**A build turns the definition into artifacts.** Building happens once per range version. It is allowed to be expensive (a Windows AD forest takes about 17 minutes) because the result is cached and reused. The build: resolves every image name in the spec to one exact, pinned artifact; derives golden images (a vendor's stock OS image plus our control daemon, nothing scenario-specific); boots the range and runs recipes (wrapped automation, often the upstream project's own scripts or Ansible) to install the big application stacks; applies the small typed configuration declared in the spec (users, services, toggles, planted files); independently verifies every declaration on the actual guest, trusting no recipe's word for it; and, for ranges whose setup is expensive, captures a checkpoint of the fully converged machines. The output is the **build manifest**: a single document that pins every input and output by cryptographic digest and records what was verified. It never contains secrets; flags and proof material are planted per sample, later.

**Artifacts are published once, pulled anywhere.** Goldens, scenario content, checkpoints, and manifests are published to a registry as content-addressed layers, the same model Docker uses for container images: push only the layers that changed, pull only the layers you are missing, verify everything against its digest before use. Disk images make this natural because a derived qcow2 image already is a small delta on its base. The registries come in two tiers. The public `meridianlabsai` org on Docker Hub carries the reusable bases (canonical goldens and shared tooling) and makes the zero-setup case work. A real deployment runs its own registry for its own built ranges, with the public org as an automatic fallback for the bases, so a connected deployment never has to copy anything. Disconnected fleets do copy: a mirror command syncs the public org into the private registry (or into a plain directory that can cross an air gap as files), since many evals run with no internet at all. And no registry is required for an author iterating on a laptop: locally built artifacts run locally.

**An eval runner consumes without becoming a builder.** The target experience is: fetch the range by name at a pinned digest, verify, `inspect eval`. No Go toolchain, no vendor image hunting, no hand-carried digest ceremony. Each sample then gets its own fresh range: thin copy-on-write overlays on the cached images, a cold boot of the already-converged disks (checkpoint memory restore exists but is an experimental opt-in), freshly generated flags from new entropy, and total destruction afterward. Nothing a previous sample did survives.

## Three rules that hold the system together

**Names are for people, digests are for machines.** A spec says something readable like `image: windows-2019-dc`; the build resolves it to an exact artifact and the manifest records only the digest. A host refuses to run anything whose digests it cannot verify.

**Rebuild cost is proportional to the change.** Edit a recipe and only that recipe's outputs and dependent checkpoints rebuild; bump the control daemon and goldens re-derive; edit the spec and only the cheap render step reruns. Getting this dependency algebra right is most of what makes AD-range iteration usable.

**Claims are verified, never trusted.** Every pulled artifact is checked against its digest before use, and a build declaration counts as true only after our verifiers confirmed it on the guest, independent of what the recipe reported.

## Who the system serves

Three journeys are the acceptance test. The **author** iterates on a range with a tight loop: build, read a clear per-section verification report, fix, rebuild only what changed. The **eval runner** goes from nothing to a running eval with one fetch plus one eval command. The **operator** publishes blessed artifacts from CI, maintains the fleet's pins, and prunes caches safely. If any journey needs more than a handful of commands or concepts, the design is wrong on paper and gets fixed there first.

## Deliberately out of scope

The recipe language itself (recipes are opaque bundles judged by exit status plus our verification), per-sample randomization draws (the generation layer owns them; the build only decides what may be baked), and challenges/scoring (its own completed phase, and the first consumer of all of this).
