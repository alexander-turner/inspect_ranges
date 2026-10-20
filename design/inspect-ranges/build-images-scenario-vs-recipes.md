---
type: decision
title: "Scenario images versus recipes: one primitive, two cache granularities"
status: accepted
tags: [inspect-ranges, build, images, recipes, scenario-images, decision]
timestamp: 2026-10-17 (ratified in discussion, 2026-10-17)
---

# Scenario images versus recipes: one primitive, two cache granularities

*Q4 of [build-images-requirements](build-images-requirements.md): the author-facing rule for when application content is a prebuilt scenario image versus a build-time recipe, with vulhub-zabbix (the requirements doc's named test case) written out both ways. Builds on the [spine memo](build-images-spine.md), whose artifact ledger already made scenario images a publishable tier with a build key of `base image digest + recipe digest + vars hash`. That key is this memo's whole argument in miniature.*

## The reframe: these are not two authoring models

The requirements doc frames vulhub (references prebuilt upstream app images) and attack-range (references an Ansible role) as live counterexamples pulling in opposite directions. The spine's build-key discipline dissolves the opposition: **a scenario image is not an alternative to a recipe, it is the cached, publishable output of one.** Every scenario image in the ledger carries the recipe digest that produced it; there is no scenario image that did not come from a recipe run (ours or a publisher's), because an image with no recorded derivation would have no build key, no invalidation story, and no place in the verification chain.

So the author question is never "do I write a recipe or use a scenario image": application content is always expressed as a recipe. The real question is **who runs it and when**: your build runs it every time its key changes (the recipe form), or a publisher ran it once and you pull the output by digest (the scenario-image form). This is precisely the source-package-versus-binary-package distinction, and the invalidation algebra already treats it that way.

Two things this choice is explicitly *not* about. It is not about caching: recipe outputs are always cached under their build key, so a range with a `provisioning` block pays the recipe run once per input change, never per build, and reaching for a scenario image buys no caching that recipes lack. And it is not about consumers: whoever pulls a published range gets the built outputs either way and never runs provisioning; recipes are re-run only by someone rebuilding the range. The scenario-image form exists for one thing: letting a *different* range's `image:` line consume a realized guest without having the recipe that made it. The Docker analogy is exact: a recipe is a Dockerfile, a scenario image is the pushed image someone built from it, and you choose `FROM someone/image` over owning the Dockerfile when the content is theirs to maintain, not because of layer caching.

## Vulhub both ways

**As recipes (build runs the stack):** each host boots the golden and `provisioning` applies a range-local recipe; the upstream docker-compose content vendored under `./recipes/` is the recipe body.

```yaml
- name: web
  os: { type: linux }
  image: ubuntu-noble
  provisioning:
    - { recipe: vulhub.zabbix-web, vars: { version: "3.0.3", db_host: mysql } }
  services:
    - { name: zabbix-web, port: 80, version: 3.0.3 }
  vulnerabilities:
    - { id: CVE-2016-10134, ... }
```

Build cost: minutes per range version (the stack installs on four guests), paid once and cached. Iteration: edit the recipe, rebuild reruns exactly that recipe (the Q2 algebra). Everything realizes on our golden, so the daemon, agent user, and injectors are uniformly present.

**As scenario images (a publisher ran the stack):** the same recipes run once in a publisher's CI; `push` publishes each output as a scenario image; ranges reference it directly.

```yaml
- name: web
  os: { type: linux }
  image: meridian/vulhub-zabbix-web          # scenario image: golden + recipe output, published
  services:
    - { name: zabbix-web, port: 80, version: 3.0.3 }
  vulnerabilities:
    - { id: CVE-2016-10134, ... }
```

Build cost: a range build is seconds (nothing to run; verification still runs in full against the booted guests). The spec's `services`/`vulnerabilities` declarations are unchanged in both forms, and the verifiers check them identically: spec visibility of scenario content never depended on which form delivered the bits.

**What the two forms share:** identical final artifacts (same build key inputs, so byte-equivalent goldens-plus-content), identical spec declarations, identical verification. **What differs:** where the build minutes are spent, and who owns iteration on the stack.

## The author-facing rule

**Write a recipe when the content is yours to iterate; reference a scenario image when you are consuming a blessed stack unchanged.** Concretely:

- Range-specific content (vulhub's zabbix stack, a planted misconfiguration's supporting app) is a range-local recipe under `./recipes/`. This is the default, and it is the only form that supports the Journey A iteration loop.
- Shared infrastructure stacks (attack-range's Splunk collector, a standard IIS baseline) are published recipe bundles first; if a stack is heavy and stable enough that rebuilding it per range hurts, its publisher also pushes the output as a scenario image, and ranges may reference that instead. The decision to bless a scenario image belongs to the publisher of the stack (Q11), not to each consuming author.
- Upstream prebuilt images (vulhub's docker images, a vendor appliance) are not directly bootable guests in this system; their content enters through a recipe that installs or converts it. The one exception is the unmodifiable appliance class, which is a vendor base (layer 1), not a scenario image, and is handled by the config-injection menu's DHCP path.

**Verdict for the vulhub slice: the recipe form.** The stack is range-specific, the slice exists to prove the recipe pipeline end to end, and four small Linux installs are well inside the build-time budget. Nothing is lost: publishing its outputs as scenario images later is a `push` away, with no spec or recipe change.

## Promotion is an explicit `publish`, never a side effect of `push` (user decision, 2026-10-17)

A plain `push` publishes the range for consumption *as a range*: pull it, eval it, mirror it, rebuild it. It mints no image names, even though every realized guest disk is in the registry by digest as part of the manifest's closure. Making a guest consumable by other ranges' `image:` lines is a separate, deliberate `publish` act that binds a chosen logical name (`acme/zabbix-web`) to the output, because a name is a public contract and `push` must not create contracts as a side effect: auto-named guests would acquire downstream consumers, and therefore maintenance obligations, the author never chose. `publish` is only valid for boot-fresh guests; a guest captured inside a checkpoint embeds converged cross-guest state and cannot stand alone as an image.

## Boundary with checkpoints

A scenario image is per-guest, boot-fresh content; a checkpoint is whole-range, converged state. The line is cross-guest convergence: content whose realization requires guests to talk to each other (AD promotion, join, replication) cannot be a per-guest scenario image and is captured as a checkpoint. Vulhub sits entirely on the scenario-image side of this line (each guest's stack installs independently; the services find each other at boot via DNS); goad-light sits entirely on the checkpoint side. A range may use both (scenario-image member disks inside a checkpointed range), which the spine's checkpoint build key already accommodates.

## Consequences

- The vulhub translation's `image:` strings (`mysql:5`, `vulhub/zabbix:3.0.3-server (command: server)`) are confirmed as provenance notes to migrate into `notes.md`; the range gets golden references plus recipes in the slice, per [Journey A](build-images-journey-a.md).
- The five-layer criterion (range-build) is unchanged; this memo only sharpens layer 3: recipes are the authoring primitive, scenario images are layer-3 outputs promoted to artifacts, and the promotion is a publisher act.
- `image:` may name either a golden or a scenario image, with no grammar change (both are image artifacts under the Q1 grammar; the ledger distinguishes them by build key, not by name shape).
- Requirements conflict 3.4.6 closes: vulhub and attack-range were never pulling in different directions, they are the two halves of the rule (range-local recipe; shared published stack).

## What stays open

Whether any of the six examples beyond attack-range warrants a blessed scenario image (a Q11/publisher question, decidable after the vulhub and goad slices); the `publish` verb's exact surface and its place in a CI publisher pipeline (Q8/Q11; the push/publish split itself is decided above); and offline-mode recipes applied at derive time versus online recipes against a booted build guest for the same content, which the slice decides empirically per recipe.
