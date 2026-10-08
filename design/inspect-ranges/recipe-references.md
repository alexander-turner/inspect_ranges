---
type: decision
title: "Recipe references: addressing and invocation are uniform, the language stays out"
status: proposed
tags: [inspect-ranges, build, provisioning, recipes, decision]
timestamp: 2026-10-08
---

# Recipe references: addressing and invocation are uniform, the language stays out

*Decision record for how `provisioning` references resolve and execute. [range-build](range-build.md) fixed the boundary (recipes run at build time, versions land in the manifest, the runtime never runs them) and deliberately deferred the recipe language. [guest-config-v0.3](guest-config-v0.3.md) gave the language a spec surface (`ProvisioningStep {recipe, version?, vars}`) whose reference grammar was unspecified. This record specifies the reference: what a recipe name resolves to, what the build hands a recipe at execution, and what it demands back. The language inside the recipe remains permanently out of scope.*

## The model: copy the image discipline

The project already has one by-reference resolution discipline, for `image:`: the spec names the artifact logically, the build resolves the name against a local cache to a content digest, and the manifest records the digest, never the name. Recipes get the identical treatment. One rule for both reference kinds; nothing new to learn or implement twice.

A recipe is a **content-addressed bundle**: a directory containing the recipe's code (whatever it is) plus a small self-description, `recipe.yaml`:

- `name`: the logical name `provisioning` steps reference (dotted, e.g. `acme.telemetry_stack`).
- `version`: the version string steps may pin.
- `entrypoint`: the executable the build invokes (e.g. `run.sh`).
- `inputs`: the declared variables, validated against the step's `vars` before execution.
- `mode`: `offline` (operates on a disk image, `virt-customize` style) or `online` (converges a booted build-time guest).

Resolution order: the range's own directory (`./recipes/<name>/`), then the shared local recipe cache (a sibling of the image cache). A reference that resolves nowhere is an error at build with the same shape as `image-not-in-cache`. The build hashes the resolved bundle and records `name`, `version`, and digest in the build manifest; rebuilds re-run a recipe only when its digest or inputs changed. There is no remote registry; vendoring upstream automation into the bundle (GOAD's Ansible, per the survey) is the distribution mechanism until something forces more.

## The invocation contract

Uniformity lives at the boundary, not inside. The build executes `entrypoint` with:

- the step's `vars` (validated against `inputs`) as environment,
- a connection to the target: the disk path for `offline` recipes, or the guest's control channel / build-network address for `online` recipes,
- the bundle directory as working directory.

The build demands back exactly one thing: exit status 0. Recipe success is necessary and never sufficient: the build's own verifiers then check every declaration on the guest (services listening at version, accounts present, toggles set, files planted), independent of anything the recipe claims. A recipe that exits 0 but leaves a declaration unverified fails the build.

Dependency ordering between recipes across guests uses the build sequencer's dependency edges ([range-build](range-build.md), boot-ordering section); within one host, `provisioning` steps run in declaration order.

## What this deliberately does not decide

- **The recipe language.** The build never parses recipe content. Ansible, shell, PowerShell over the control channel: all equivalent behind the entrypoint. The moment addressing uniformity creeps into content uniformity (a task vocabulary, a module system, inline verbs in `range.yaml`), the project is rebuilding Ansible; cyris's inline task verbs stay deferred exactly here.
- **Runner pinning.** Executing recipes inside a pinned container (so the recipe's tooling version is reproducible) is the reproducibility-correct extension and the first step toward a packaging system. Deferred until a recipe actually breaks from tool drift; the manifest's bundle digest already detects that the recipe itself did not change.
- **A remote registry.** Local directory and cache resolution only, until forced.

## Consequences

- `ProvisioningStep.recipe`/`version` acquire a defined resolution semantics with no schema change.
- The build manifest's "provisioning recipe versions" entry ([range-build](range-build.md)) becomes `(name, version, digest)` triples.
- The goad-forest spike's plain scripts are already this shape (directory, entrypoint, convergence polling inside); formalizing them as bundles is mechanical.
- The review package can present `provisioning` as specified-by-reference rather than unspecified: the grammar question reduces to the bundle contract above.
