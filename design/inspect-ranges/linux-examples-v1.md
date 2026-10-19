---
type: document
title: "Decision: Linux examples v1"
audience: inspect-ranges development
status: accepted
tags: [inspect-ranges, examples, kypo, cyris, mhbench, phase-plan, decision]
timestamp: 2026-10-19
---

# Decision: Linux examples v1

*Phase plan for the examples phase of the ratified arc (phase 3 of the 2026-10-18 sequencing, consuming [distribution v1](distribution-v1.md) and [standard images v1](standard-images-v1.md)). The three translated Linux fixtures in [ranges/](ranges/) promote from validated requirements documents to BUILT, VERIFIED, SOLVED ranges: recipes realize their guest content, behavioral checks prove it, and each range's `challenges.yaml` is exercised by a real `inspect eval` whose reference intrusion chain solves through the foothold. The exit criterion: all three ranges build from clean caches and their reference chains score, with the whole flow on the catalog's standard images (the attacker default included).*

## Inputs

- The fixtures are faithful translations with vendored upstream and per-field provenance (kypo-demo from KYPO CRP, MIT; cyris-basic from CyRIS, BSD-3; mhbench-equifax-small from MHBench, MIT). Semantics preserved there are not renegotiated here; what changes is realization (logical images re-point at catalog names, deferred provisioning becomes recipes).
- The challenges-v1 machinery (plants, goal types, scoring, the foothold wall) and the build pipeline (recipes, behavioral checks, conformance) are consumed as-is; no new goal types (a phase non-goal, per the catalog phase's record).
- **Variables posture (the one schema decision this phase makes):** `variables:` currently refuses at planning. V1 lifts the gate to DEFAULTS-RESOLUTION: declared variables resolve to their defaults at build time and are consumable as recipe vars; secrets that must differ per sample (the KYPO flags) already do, via the challenge plant layer, which re-plants them with proof entropy. Full per-instance randomization (the KYPO APG / generation layer, e.g. a random `telnet_port` per sandbox) is explicitly deferred and recorded in the parked file for ratification.

## The slices

**Slice 1: kypo-demo built and solved.** The two-subnet routed topology with the explicit Debian-class router (realized on the catalog goldens), server recipes (telnetd on the `telnet_port` variable, the alice weak-password account, the sudoers `less` escalation, both flag files), client recipes (nmap/hydra/medusa, the password list, the trainee account), the variables gate lifted to defaults-resolution, behavioral checks covering the chain's load-bearing facts (telnet answers on the drawn port, alice authenticates with the weak password, the sudoers rule exists). Battery: clean build plus a real eval in which the reference chain (scan, hydra, flag, sudo-less escape, root flag) scores through the client foothold and an insufficient chain does not.

**Slice 2: cyris-basic built and solved.** The CyRIS reference range: firewall-as-router with its rules, desktop foothold, webserver with its planted content, the per-guest `tasks:` layer as recipes, images on catalog goldens. Battery: clean build plus the reference-chain eval.

**Slice 3: mhbench-equifax-small built and solved.** The six-host two-segment MHBench topology with its security-group ACLs, the vulnerable service chain per upstream, and the attacker as the catalog default (`image:` line removed: the schema default IS the standard attack box now). Battery: clean build plus the reference-chain eval; this is the phase's scale proof (most guests, real CVE content).

**Slice 4: promotion, docs, and the exit.** The three ranges promote to `examples/` beside vulhub-zabbix (provenance docs travel), an examples docs page, CHANGELOG, and the exit transcript: from clean caches, build all three and run all three evals green. The house two-round phase review.

## Non-goals

No new goal types or scoring semantics; no generation layer beyond defaults-resolution (parked); no Windows anything (phase 4, local/private only); no MHBench corpus beyond `equifax_small` (the other 39 topologies are a recorded follow-up); no goad-light or attack-range-windows work.

## Parked for the user

Accumulated in [linux-examples-v1-parked-decisions.md](linux-examples-v1-parked-decisions.md) per the AFK protocol.

## Ledger

| Slice | Status |
|---|---|
| 1 kypo-demo | |
| 2 cyris-basic | |
| 3 mhbench-equifax-small | |
| 4 promotion + exit | |
