---
type: decision
title: "Guest configuration (schema v0.3): converged-state declarations, parsed now, realized at build"
status: proposed
tags: [inspect-ranges, range-yaml, schema, guest-config, decision]
timestamp: 2026-10-07
---

# Guest configuration (schema v0.3): converged-state declarations, parsed now, realized at build

*Decision record for the layer-4 guest-content vocabulary, lifting the schema-v0.1 deferral of `users`, `services`, `vulnerabilities`, `misconfigurations`, `data`, `defense`, `active_directory`, and `provisioning`. Produced for the external syntax review: the parser accepts everything uniformly so reviewers see one language, and the honesty gate for unrealized content sits at planning. The evidence base is the six examples' `deferred.yaml` files, whose carved content already converged on this vocabulary; migrating that content back into the `range.yaml` files is the acceptance criterion.*

## The core stance: declarations describe converged state

A guest-content declaration is a statement about the **converged state** of a guest, not a boot-time action. The build applies it by whatever means the image situation demands: a provisioning recipe, content baked directly into a derived image, or a captured checkpoint. The build then **verifies** it before the range ships (per [range-build](range-build.md)'s manifest verification results), and the runtime never applies it per sample. "Bake it into the image" and "declare it in the spec" are therefore not alternatives: the declaration is the source of truth and the surface randomization, auditing, and scoring consume; baking is one of its realizations.

Two corollaries:

- **Scenario credentials belong in the spec in plaintext.** They are scenario content, visible by design. Per-sample proof material (flags, canaries, principal-bound secrets) never appears in the spec; it is generated from independent entropy at instantiation ([scoring-integrity](scoring-integrity.md)).
- **Realization is gated, not pretended.** Until the build phase lands, `resolve_plan` refuses specs carrying guest content with `guest-config-not-realized` (one positioned issue per occurrence), the same pattern as `windows-render-not-supported`. Nothing boots with silently missing content.

## The vocabulary

All sections follow the layer-4 criterion from [range-build](range-build.md): small, typed, and worth being spec-visible. Forced-by evidence cites the carved `deferred.yaml` content.

| Section | Shape | Forced by |
|---|---|---|
| `hosts[].users`, `routers[].users` | `{name, password?, groups, note?}`; local accounts only (domain accounts live in `active_directory`) | cyris (incl. router account), kypo, attack_range |
| `hosts[].services` | `{name, port?, version?, credentials?, note?}` — **assertions about the converged listening surface**, never an install language; the build satisfies them (recipe, bake, or checkpoint) and verifies them (listening, version) | vulhub (describes upstream images), attack_range (installed by roles), kypo, cyris |
| `hosts[].vulnerabilities` | `{id, cve?, service?, description}`; `id` is ours, `cve:` an attribute when one applies — resolving the old vocabulary question (CVE ids vs classes vs roles) | vulhub (CVE-2016-10134), kypo (weak-telnet-password), goad (adcs-esc1) |
| `hosts[].misconfigurations` | `{id, description}`; a distinct list because real intrusions lean on misconfigurations — the list is the classification, so there is no `class` field | kypo (sudo-less-privesc), goad (firewall-disabled, acl-chain) |
| `hosts[].data` | `{path, description?, sensitive, contents?}`; planted scenario files, never flags | cyris (flag.txt as scenario data, pcaps) |
| `hosts[].defense` | typed toggles `{defender?, firewall?, windows_update?}`; extended when evidence forces | goad per-host toggles |
| `defense` (top level) | `{tier: D0..D5, description?, telemetry: [{source, collector, sink}]}` | attack_range (D2, Sysmon→Splunk triples), vulhub (D0) |
| `active_directory` (top level) | `{forest, domains: [{name, netbios, dc, parent?, users: [{name, password?, groups, spns, note?}], acls}]}`; identity is range-scoped, so it is not host content | goad (forest, child domain, kerberoastable SPNs) |
| `AdAcl` edges | `{principal, right, target}` with `right` a Literal of the observed set (GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, SelfMembership, AddMember) | goad's seeded ACL-abuse chain |
| `hosts[].provisioning` | ordered `{recipe, version?, vars}` references; **the recipe language stays deliberately undecided** — steps name build-time work, the runtime never runs them, versions land in the build manifest | attack_range (Ansible role refs); cyris's inline task verbs stay deferred as recipe-language material |

Cross-validation (collecting, in `semantic_issues`): `vulnerability.service` must name a service on the same host; `telemetry.source` must be a declared guest; `active_directory.domains[].dc` must be a declared host; `parent` must be a declared domain. AD ACL principals and targets stay unvalidated strings this round: they may be users, groups, OUs, or computer objects, and typing that namespace belongs to the attack_path design.

## Still deferred, and why

| Deferred | Why |
|---|---|
| `count:`/`ip_start:` expansion | touches naming and allocation; revisit with the generation layer (mhbench stays hand-unrolled) |
| `variables` / generation | the L2 layer; its own design effort |
| `attack_path` | consumes the AD ACL vocabulary and couples to scoring; its own round |
| `goals` | decided task-side (`challenges.yaml`) |
| `management`, `lifecycle`, `replication`, network `ingress`/`user_accessible` | operator/deployment policy, not range semantics |

## Realization path

Guest content realizes in the build phase ([range-build](range-build.md)): recipes and declarative appliers run once per range version under the dependency graph, the converged result is captured, and the build manifest records recipe versions and the per-section verification evidence (services listening, accounts present, toggles applied, AD chain seeded). The planning gate is deleted per section as its applier and verification land, under the same lockstep rule as networking v0.2.

## Consequences

- `schema_version: "0.3"`; fully additive over v0.2.
- The six examples carry their guest content in `range.yaml` again; their `deferred.yaml` files shrink to the genuinely deferred remainder.
- The review package shows one uniform language; the only remaining "tell us what you need" surfaces are the deferred table above and the vocabulary edges (AD rights set, defense toggle set), both marked as extension points.
