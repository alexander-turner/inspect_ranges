---
type: document
title: Small realistic cyber ranges — source survey for inspect_ranges
audience: inspect-ranges development
status: draft
tags: [inspect-ranges, cyber-range, survey, range-yaml]
timestamp: 2026-09-30
---

# Small realistic cyber ranges — source survey for inspect_ranges

*What public artifacts exist that define small, realistic, quickly-runnable cyber ranges with concrete machine-readable configuration, surveyed 2026-09-30 to select a development/testing baseline for `inspect_ranges` and its `range.yaml` format. Selection criteria: diversity of target systems, contexts, and network topology; fast enough to run for testing; and — top priority — translatable with content correctness from real config files, not from papers' prose. The six selected examples live in [ranges/](index.md); the schema they exercise is in [range-yaml-swag](range-yaml-swag.md).*

## 1. The six selected examples

| Example | Source artifact (license) | Shape | Why it's in the set |
|---|---|---|---|
| [vulhub-zabbix](../../examples/vulhub-zabbix/notes.md) | vulhub `zabbix/CVE-2016-10134` (MIT) | 4 Linux hosts, 1 flat network | the minimal case: real public CVE, name-based discovery, boots in seconds upstream |
| [kypo-demo](../../examples/kypo-demo/notes.md) | KYPO CRP demo sandbox (MIT) | 2 hosts + explicit router, 2 routed subnets | cleanest published topology schema; static IPs, user-accessibility flags, per-instance randomized variables |
| [cyris-basic](../../examples/cyris-basic/notes.md) | CyRIS `examples/full.yml` (BSD-3) | 3 guests (firewall as gateway), 2 segments | KVM/libvirt-native; entry_point marker, guest tasks layer, forwarding rules, range replication |
| [mhbench-equifax-small](../../examples/mhbench-equifax-small/notes.md) | MHBench `equifax_small` (MIT) | 7 hosts (2 web + 4 db + attacker), 3 subnets + mgmt plane | breach-derived; asymmetric per-subnet ACLs, planted credential-reuse path, exfil oracle |
| [goad-light](../../examples/goad-light/notes.md) | GOAD-Light (GPL-3.0) | 3 Windows Server 2019 VMs, 1 forest / 2 domains, flat subnet | the AD forcing function: static DC addressing, AD-integrated DNS chain, identity data as config, Defender on/off per host |
| [attack-range-windows](../../examples/attack-range-windows/notes.md) | Splunk attack_range v5 AWS template (Apache-2.0) | Ubuntu Splunk host + Windows Server 2022 endpoint | the instrumented/blue example: telemetry (Sysmon→Splunk) as first-class config, detection-flavored oracle |

Coverage: Linux (vulhub, kypo, cyris, mhbench) vs Windows (goad, attack-range); flat (vulhub, goad, attack-range) vs routed/segmented (kypo, cyris, mhbench); containers-upstream (vulhub) vs KVM (cyris) vs OpenStack (kypo, mhbench) vs Vagrant/cloud VMs (goad, attack-range); defense D0 (vulhub, cyris, mhbench) / D2 telemetry (kypo, attack-range) / D4 real EDR (goad). Every example translated from fetched config files vendored in its `upstream/` directory; invented values are tagged `default:` in each range.yaml and itemized in each notes.md.

## 1a. MHBench is fully public — corpus assessment

The repo (`github.com/bsinger98/MHBench`, MIT, cloned 2026-09-30) contains all topology definitions — 10 hand-designed Terraform topologies under `src/environments/terraform/topologies/` (equifax_small/medium/large/network, enterprise_a/b/c, chain_2hosts, dumbbell, ring, star) plus 30 generated networks as JSON under `src/environments/generated/`. (The Incalmo paper, arXiv:2501.16466, left it ambiguous whether the full 40-network corpus was released; it is.) Measured directly from the 30 JSON files (confirmed):

- **Scale/complexity:** 11–45 hosts per network (median ~32), 2–4 subnets (8 nets with 2, 8 with 3, 14 with 4), explicit `subnet_connections`; planted attack paths of length 2–15 steps.
- **The planted path is a first-class machine-readable artifact.** Each definition carries `attack_paths` (per-step from/to host and user IDs) and an `attack_graph`, plus machine-checkable `goals` (`data_exfiltration` with explicit target host/user/file and the playbook that plants it). This is exactly the L5 requirement ([range-yaml-swag §0](range-yaml-swag.md)) — constructive solvability with the path as an edge list — satisfied by construction. Ready-made ground truth for an `inspect_ranges` reachability-lint and for graded (per-edge) scoring.
- **Uniform schema** (`networks/subnets/hosts/users` with CIDRs, per-host fixed IPs, gateway IPs, security-group names): trivially translatable to range.yaml in bulk — good compiler test fixtures.
- **But the generated corpus is a monoculture on the axes that matter for realism.** Vulnerabilities: exactly two types across all 30 nets — `lateral_movement` (625 instances, planted SSH keys via `setup_ssh_keys.yml`) and `privilege_escalation` (113); **zero exploitable service CVEs in the generated networks** (the richer library — Struts, vsftpd 2.3.4 backdoor, Nostromo RCE, netcat shell, weak passwords, five sudo-privesc variants — exists under `ansible/vulnerabilities/` but is wired only into hand-designed instances). OS: every host `Ubuntu20`/`p2.tiny`. Users: patterned `user_N` (1846 users, exactly 50% admins, no decoys populated). Defense: D0 throughout. This is the "too tidy" hazard of generated topologies — real estates are characterized by accretion (overlapping tech generations, forgotten trusts, inconsistent policy), and a corpus this clean measures credential-reuse graph traversal, not exploitation.

**Assessment:** a very good corpus to build the *system* on — bulk format-translation fixtures, generated-vs-hand-designed both represented, planted-path ground truth for oracles and lint, MIT, and emulation-real (Ubuntu VMs; OpenStack→libvirt translation is mechanical, as the equifax_small example shows). It is **not** sufficient as a capability corpus: for eval-grade diversity it needs the hand-designed instances (where the real vuln library is used), plus AD (GOAD-class), real-CVE services (vulhub-class), and defense tiers from elsewhere. Treat it as the Linux lateral-movement tier and the harness-scaling substrate, not the whole diet.

## 2. Catalog of surveyed artifacts

Formats verified by fetching real config files unless marked to-verify.

| Artifact | Definition format | Size | Substrate | Defense | License | Spin-up |
|---|---|---|---|---|---|---|
| **KYPO CRP** (Masaryk U.) | `topology.yml`: hosts / routers / networks (cidr, accessible_by_user) / net_mappings / router_mappings; `variables.yml` randomization | demo: 2 hosts + router | OpenStack; local via Vagrant | D0–D2 | MIT | minutes |
| **CyRIS** (JAIST) | 3-section YAML: host_settings / guest_settings (tasks) / clone_settings (topology, entry_point, forwarding) | small; clones scale | KVM/libvirt | D0 | BSD-3 | minutes on prepped images |
| **MHBench** (CMU) | Terraform per topology + Python specs + Ansible guest config; 30 generated topologies as JSON | 22–50 hosts (equifax_small: 6+attacker) | OpenStack | D0 | MIT | heavy full-size; small topologies modest |
| **Perry** (CMU, RAID 2025) | Python DSL: attacker/defender state machines + 5 environments (20–50 hosts) | 20–50 hosts | OpenStack (shares MHBench substrate) | D3 | open (github.com/bsinger98/Perry) | heavy |
| **GOAD / -Light / -Mini, NHA, SCCM** (Orange Cyberdefense) | Ansible inventory + per-host `config.json` (vulns, users, ACLs) + provider inventory (IPs/DNS) | Light: 3 Win VMs; full: 5 | Vagrant/Ansible VMs (VirtualBox/VMware/Proxmox/Ludus/cloud) | D1/D4 toggle | GPL-3.0 | hours |
| **Splunk attack_range v5** | per-provider template YAML: servers list (AMI, instance type, ip_last_octet, ansible roles) | 2–5 nodes | Terraform+Ansible, cloud-only | telemetry (D2) | Apache-2.0 | tens of minutes |
| **Ludus** (Bad Sector Labs) | one-file range config: per-VM template/vlan/ip_last_octet/roles; 255 VLANs | any | Proxmox | varies | to-verify | heavy templates, clean config |
| **Vulhub** | plain docker-compose per CVE (hundreds of CVEs) | 1–4 containers | Docker | D0 | MIT | seconds |
| **SecGen** | XML scenarios; vulns picked by abstract constraints, randomized | 1–several VMs | Vagrant+Puppet | D0 | GPL-3.0 | slow |
| **CybORG / CAGE-2/-4** | scenario YAML: Subnets with per-subnet NACLs (in/out), explicit Defender host | 13 hosts / 3 subnets (CC2) | simulation (emu possible) | D2/D3 | CC0 | instant (sim) |
| **NASimEmu** | scenario YAML: subnet sizes, adjacency-matrix topology, per-subnet firewalls; v2 randomization; emu → Vagrant + RouterOS | tiny–moderate | sim or Vagrant | D0 | MIT (NASim) | instant / minutes |
| **CyberBattleSim** (Microsoft) | Python graph: nodes with value + planted vulns (leaked creds), protocol-labeled edges | toy | simulation | implicit | MIT | instant |
| **AgentCyberRange** (Fudan) | Docker-based, 8 ranges / 156 hosts, defenders + canary oracle | 156 hosts total | Docker | ~D3 | open | — (not selected) |
| **PACEbench** | 32 container challenges incl. chained + defense families | small | containers | mixed | public | fast |

Scenario-description languages worth mining for ideas, no runnable artifacts adopted: **VSDL** (SMT-checked connectivity/firewall constraints, arXiv:2001.06681), **CRACK/TOSCA** (Datalog check that declared attack paths are reachable pre-deploy), CST-SDL, ARCeR (arXiv:2504.12143), RangeFactory (arXiv:2608.09526, format to-verify).

### Private artifacts (design detail only, no configs to translate)

- **UK AISI ranges** (The Last Ones / Doing Life / Cooling Tower, as described in frontier-lab system cards and UK AISI's methodology paper, arXiv:2603.11214) — Proxmox VM networks run in Inspect, per-sample SDN isolation, step/milestone scoring, D1–D2. The ranges themselves are unreleased; the methodology constrains what a serious range needs (egress posture declared, per-sample isolation) without providing definitions.
- **CyScenarioBench** (Irregular) — containerized, responsive defense, simulated employees; vendor-internal, described only in frontier-lab system cards.
- **Dynamic Cyber Ranges** — LLM-defender concept (preprint); no artifacts released.

## 3. What the survey adds to the schema question

The requirements extraction lives in [range-yaml-swag §2](range-yaml-swag.md); the short version: the six examples jointly force CIDRs, static per-guest IPs (incl. sequential-under-count), DHCP-vs-static per network, egress modes, explicit routers with per-network gateway IPs, inter-segment forwarding rules, asymmetric per-subnet ACLs, interface-level multi-homing, guest-provided authoritative DNS chains (AD), management planes that exist but are out of play, operator-ingress allowlists, and per-sample isolation of the whole network set. None of this is expressible in the current docker/k8s Inspect sandboxes (the motivation for the libvirt sandbox); all of it has a direct libvirt realization.

## 4. External references

- KYPO: gitlab.ics.muni.cz/muni-kypo-crp/prototypes-and-examples/sandbox-definitions/kypo-crp-demo-training; docs.crp.kypo.muni.cz
- CyRIS: github.com/crond-jaist/cyris
- MHBench: github.com/bsinger98/MHBench · Incalmo: github.com/cylabcyberautonomy/Incalmo (arXiv:2501.16466) · Perry: github.com/bsinger98/Perry (arXiv:2506.20770)
- GOAD: github.com/Orange-Cyberdefense/GOAD; orange-cyberdefense.github.io/GOAD
- attack_range: github.com/splunk/attack_range
- Ludus: docs.ludus.cloud; github.com/badsectorlabs/ludus-range-configs
- Vulhub: github.com/vulhub/vulhub
- CybORG/CAGE: github.com/cage-challenge/CybORG · NASimEmu: github.com/jaromiru/NASimEmu · CyberBattleSim: github.com/microsoft/CyberBattleSim
- SecGen: github.com/cliffe/SecGen · XBOW validation benchmarks: github.com/xbow-engineering/validation-benchmarks (single-target web CTF, not multi-host — noted and passed over)

## 5. Open to-verify items

- Ludus license; SecGen exact license file; NASimEmu license.
- RangeFactory (arXiv:2608.09526) definition format.
- Per-example to-verify items live in each `notes.md` (exact Struts CVE, CyRIS clone CIDR allocation, GOAD runtime egress + lockout policy, attack_range telemetry role contents, KYPO platform egress).
