---
type: document
title: kypo-demo — source note
status: draft
tags: [inspect-ranges, range-example, provenance]
timestamp: 2026-09-30
---

# kypo-demo — source note

*Status: translated requirements fixture. `range.yaml` validates against schema v0.3 and preserves upstream semantics; it has not been built or booted as a VM range (images are logical references, provisioning is deferred). Promotion to a runnable range requires the build pipeline and behavioral verification.*

Translation of the KYPO Cyber Range Platform demo sandbox definition (`gitlab.ics.muni.cz/muni-kypo-crp/prototypes-and-examples/sandbox-definitions/kypo-crp-demo-training`, MIT, cloned 2026-09-30). KYPO's `topology.yml` is the cleanest published range-topology schema we found and is the primary structural influence on our draft format.

## Where each fact comes from (vendored in `upstream/`)

| range.yaml section | Source file | Detail |
|---|---|---|
| hosts/router images, flavors | `topology.yml` | server+client ubuntu-focal, router debian-9, all standard.small |
| networks, CIDRs, `user_accessible` | `topology.yml` | server-switch 192.168.20.0/24 (`accessible_by_user: False`), client-switch 192.168.30.0/24 |
| static IPs (hosts + router) | `topology.yml` | `net_mappings` (server .20.5, client .30.5) + `router_mappings` (.20.1/.30.1) |
| randomized variables | `variables.yml` | `telnet_port` (type port, min 1500), `alice_flag`, `root_flag` (type text) |
| server content (telnetd, alice/bacon, sudoers less privesc, both flags, /etc/hosts alias) | `provisioning/roles/server/tasks/main.yml` + `defaults/main.yml` | defaults: alice/bacon, port 2323, flags "Top_Secret_Flag"/"Cant_Guess_This" |
| client content (user/Password123 sudo, nmap/hydra/medusa, passlist.txt) | `provisioning/playbook.yml` + `roles/client/tasks/main.yml` | `kypo-user-access` role sets user/Password123 |
| command logging (defense tier D2) | `provisioning/playbook.yml` | `sandbox-logging` role on all hosts, syslog port 514/515 to management |
| task prompts + reference solutions (`challenges.yaml`) | `upstream/training.json` | KYPO training definition: 3 training levels with verbatim task text, `answer_variable_name` per level, and step-by-step solutions |

## Tagged defaults / judgment calls

- `defense.tier: D2` is our classification (telemetry logged, not acted on) — the upstream files just install the logging role.
- `attacker.host: client` derives from `accessible_by_user` semantics (trainee reaches only client-switch); upstream doesn't use the word "foothold".

## To-verify

- Egress posture of a deployed KYPO sandbox (platform-level, not in these files).
- Whether the KYPO local build (Vagrant `cyber-sandbox-creator`) preserves the router as a real VM (OpenStack build does).

## What this example exercises in the schema

Explicit **router as first-class object** with per-network gateway IPs, **CIDR + static-IP mappings** (KYPO's `net_mappings`/`router_mappings` — adopted nearly verbatim), a **user-accessibility flag** on networks (which networks the agent may attach to), and a **per-instance randomization layer** (`variables:`) — the smallest working precedent for the generation-policy layer (L2 in [range-yaml-swag.md](../../../../design/inspect-ranges/range-yaml-swag.md) §0).

> Schema v0.1 carve-out (2026-10-01): sections awaiting schema design (goals, attack_path, guest config, ...) moved verbatim from `range.yaml` to [`deferred.yaml`](deferred.yaml); see [schema-v0.1-scope](../../../../design/inspect-ranges/schema-v0.1-scope.md).


## Realized (2026-10-19, linux-examples-v1 slice 1)

The fixture is now BUILT, VERIFIED, and SOLVED (battery: design/spikes/kypo-build). Realization choices, each tagged in range.yaml: images moved to the catalog goldens (`ubuntu-focal` hosts, `ubuntu-noble` router; upstream debian-9 router preserved in routing semantics only), network `mode` corrected from `routed` to `isolated` (mode is the EGRESS posture; the declared router provides inter-subnet routing), recipes `kypo.server`/`kypo.client` realize the upstream roles (flag files stay the challenge plant layer's), `defense` moved to deferred.yaml (tier declarations gate the build; the substrate's evidence layer records outside the guests). The earlier "has not been built or booted" status is superseded. Convention: this section records realization; the translation tables above stay frozen at translation time.

## Extended (2026-10-28, example-coverage): int and choice draws

Ours, not upstream (the variables table above stays frozen at the upstream three). Two variables join the randomization layer to exercise the remaining drawable types: `maintenance_code` (`int`, explicit `min`/`max` per the drawability rules) and `banner_wing` (`choice`, two non-default candidates). Both declare `draw: boot` and both land in the server's pre-login telnet banner: `kypo.server` (recipe v3) bakes `/etc/issue.net` with the defaults (in.telnetd prints it before the login prompt) and the existing `kypo-apply-draws` boot unit (name unchanged, so no activity-name churn) rewrites it from the draws file alongside the telnetd port move. The ladder gains a second rung, `report-maintenance-code` (`answer` on the int variable; the prompt paragraph is ours, flagged in challenges.yaml), between the port discovery and the user flag: the banner is served on the drawn port, so every later rung implies it and the `later_implies_earlier` ordering holds. Draws exclude the defaults, so the baked banner never scores; the trio covers the rung (reference parses the greeting, insufficient submits the checked-in default, forged submits a value below the draw floor). range.yaml moved, so the published kypo build needs a rebuild and republish.
