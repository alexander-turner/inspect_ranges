---
type: document
title: "Decision: standard images v1 (the catalog)"
audience: inspect-ranges development
status: accepted
tags: [inspect-ranges, images, catalog, attack-image, phase-plan, decision]
timestamp: 2026-10-18
---

# Decision: standard images v1 (the catalog)

*Phase plan for the catalog phase of the build/images arc (phase 2 of the ratified sequencing, consuming [distribution v1](distribution-v1.md)). The phase gives the spine's bare-name promises real referents: the standard attack image the schema has pointed at since v0.1 ("the backend's standard attack image"), the blessed goldens, the daemon bundle, and the hardened range container image, all published under `docker.io/meridianlabsai` on a single publish day at phase end (user decision, 2026-10-18). The exit criterion: a consumer on a clean machine runs a real `inspect eval` against a range whose every image resolved from the public catalog, with zero local builds and zero hand-pinned artifacts.*

## Ratified inputs (user, 2026-10-18)

- **The attack image is broad kali-class, metasploit included** (user choice over the lean-core recommendation: ecosystem familiarity and agent expectations outweigh footprint and attribution concerns). It is recipe-built and pinned like everything else, so it rebuilds reproducibly and its contents are a recorded manifest, not a drifting base.
- **The hardened range container image publishes** as a canonical pinned image under the org (a conventional Docker image, unlike the OCI-wrapped qcow2 artifacts).
- **Publish day is this phase's close**: one deliberate day, the exact repo list staged, you run the pushes with your credentials (the house posture: canonical publishes are manual user acts, like git pushes).
- **Windows artifacts stay local/private only** and are out of this phase entirely.

## The slices

**Slice 1: the attack image recipe.** A recipe-built attack golden derived from noble: the kali-class toolset (nmap, netcat/socat, curl/wget, tcpdump, python3 with impacket and requests, sqlmap, hydra, john, metasploit-framework via its apt repo, plus the quality-of-life layer: gobuster/ffuf-class discovery, smbclient, ldap-utils) installed by a pinned recipe with build-time egress (the metasploit repo key fingerprint-pinned), every tool presence-asserted IN the recipe with a metasploit major-version floor and the zero-non-loopback-listener containment invariant (the verification engine attributes versions through listeners, which CLI tools deliberately lack), the delivered package set recorded into the image (`/etc/attack-image.manifest`), captured as the realized attack image. The spec default (`Attacker.image` omitted) resolves to it. Battery: an attack-image build from scratch, tool-presence verification live, a range booting with the default attacker and the toolset answering over the channel.

**Slice 2: catalog publication mechanics.** The `publish` promotion verb (the deliberate act distribution v1 deferred): a built golden or scenario image publishes standalone under its bare catalog name, and the catalog's name list publishes as a well-known index artifact (closing the hub-enumeration gap mirror recorded). The Q11 fleet pin file (names to digests, consumed as `@sha256` pins) and the publisher runbook. Battery: publish/pull/refresh of catalog names against local registries, the name-list artifact driving a whole-org mirror.

**Slice 3: the range image on the hub.** The hardened range container image builds reproducibly, publishes to a conventional repo, and `up`/doctor gain the pull-and-pin consumption path (local build remains the fallback and the dev loop). Battery: a clean machine consumes the pinned range image and boots a range with it.

**Slice 4: publish day and the exit.** The staged publish commands run (user, with their credentials): goldens (noble, focal), the daemon bundle, the attack image, the range image, the catalog index. The exit transcript: clean machine, `git clone`, `inspect eval` with every image resolving from the public catalog. Close-out docs (the catalog page, guests.qmd's attacker default updated), CHANGELOG, and the house two-round review.

## Non-goals

No Windows anything public; no new goal types or challenges content (phase 3's examples own that); no CDC or lazy pull; no signing (the trusted-operator posture holds); no CI publisher beyond the runbook (recorded follow-up).

## Parked for the user

Accumulated in [standard-images-v1-parked-decisions.md](standard-images-v1-parked-decisions.md) per the AFK protocol.

## Ledger

| Slice | Status |
|---|---|
| 1 attack image recipe | done 2026-10-19: battery 9/9 ([cat-attack](../spikes/cat-attack/README.md)): the kali-class toolset recipe builds over the noble golden (metasploit from its official repo, key fingerprint-pinned), presence-asserts in-build, records the delivered package set into the image (`/etc/attack-image.manifest`, 801 packages live), asserts the metasploit 6.x floor and the ZERO-non-loopback-listener containment invariant (which fired on its first run against build-time UDP resolver noise, teaching the ephemeral-floor filter now recorded in the recipe), and the realized image boots as a consumer range's cloud-hypervisor attacker with every tool answering, nmap getting real L3 answers, and msfvenom functional; fresh-context review: 2 blocking (the unpinned-feed reproducibility posture, discharged with the in-image manifest + version floor + the parked republish discipline, decision 1 in the parked file; the zero-listener guarantee had no assertion anywhere, now a build-failing invariant AND a live battery leg) + 3 non-blocking (the repo-key fingerprint pin, the nmap leg asserting closed-or-open instead of passing on filtered, the qcow2 sparsify sizing note parked), all fixed and re-batteried 9/9; the recipe edit re-keyed the build and renamed the realized image, demonstrating the republish discipline live |
| 2 catalog publication mechanics | |
| 3 range image on the hub | |
| 4 publish day + exit | |
