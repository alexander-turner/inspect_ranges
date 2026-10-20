---
type: document
title: Upstream licenses and attribution
status: draft
tags: [inspect-ranges, licenses]
timestamp: 2026-09-30
---

# Upstream licenses and attribution

Each example range vendors verbatim copies of its source's configuration (and, where available, task/prompt) files under its own `upstream/` directory (`../../examples/<name>/upstream/`), for provenance and so tooling can read the originals alongside our `range.yaml` translation. All were fetched 2026-09-30. Copyright remains with the upstream authors; each project's full license text is at the linked repository root.

| Vendored under | Upstream project | Copyright | License |
|---|---|---|---|
| `examples/vulhub-zabbix/upstream/` | [vulhub](https://github.com/vulhub/vulhub) (`zabbix/CVE-2016-10134/`) | Vulhub contributors | MIT |
| `../../examples/kypo-demo/upstream/` | [kypo-crp-demo-training](https://gitlab.ics.muni.cz/muni-kypo-crp/prototypes-and-examples/sandbox-definitions/kypo-crp-demo-training) | 2020 Masaryk University | MIT |
| `../../examples/cyris-basic/upstream/` | [CyRIS](https://github.com/crond-jaist/cyris) (`examples/`) | 2016–2021 Japan Advanced Institute of Science and Technology | BSD-3-Clause |
| `../../examples/mhbench-equifax-small/upstream/` (topology, specs, playbook) | [MHBench](https://github.com/bsinger98/MHBench) | 2025 Brian Singer | MIT |
| `../../examples/mhbench-equifax-small/upstream/incalmo-prompts/` | [Incalmo](https://github.com/cylabcyberautonomy/Incalmo) | 2025 Brian Singer | MIT |
| `../../examples/goad-light/upstream/` (inventory, config.json, provider files) | [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (`ad/GOAD-Light/`) | Orange Cyberdefense | GPL-3.0 |
| `../../examples/goad-light/upstream/cochise/` | [cochise](https://github.com/andreashappe/cochise) | 2025 Andreas Happe | MIT |
| `../../examples/splunk-detection/upstream/` | [attack_range](https://github.com/splunk/attack_range) (`templates/aws/`) | Splunk Inc. | Apache-2.0 |

Notes:

- The GOAD files are unmodified copies of configuration data distributed under GPL-3.0; this folder redistributes them with attribution and this notice. Our `range.yaml`/`challenges.yaml`/`notes.md` are independent factual descriptions, not derivative code.
- `examples/vulhub-zabbix/upstream/README.txt` and `../../examples/goad-light/upstream/cochise/scenario.txt` are upstream Markdown files renamed to `.txt` (kept byte-identical).
- Our own files in this folder (every `range.yaml`, `challenges.yaml`, `notes.md`, and the documents at the folder root) carry this repository's license.

## Pinned upstream sources

Every vendored file was matched to its upstream repository by git blob hash (checked 2026-09-30): each is byte-identical to the file at the path below in the pinned commit, which was that repository's HEAD at the time. These pins let the `upstream/` copies be replaced by references once a range's translation has been verified and the copies are no longer needed; files a range needs at runtime (e.g. cochise's username list) move into that range's assets instead.

| Upstream repository @ commit | Vendored file (under `../../examples/`) | Upstream path |
|---|---|---|
| `github.com/vulhub/vulhub` @ `8fd63916f7a8711e2e01dda0d27237e4d6175d38` | `vulhub-zabbix/upstream/docker-compose.yml` | `zabbix/CVE-2016-10134/docker-compose.yml` |
| | `vulhub-zabbix/upstream/README.txt` | `zabbix/CVE-2016-10134/README.md` |
| `gitlab.ics.muni.cz/muni-kypo-crp/prototypes-and-examples/sandbox-definitions/kypo-crp-demo-training` @ `9d268bc5fbb718341aae902391f82428a5c976bc` | `kypo-demo/upstream/topology.yml` | `topology.yml` |
| | `kypo-demo/upstream/variables.yml` | `variables.yml` |
| | `kypo-demo/upstream/training.json` | `training.json` |
| | `kypo-demo/upstream/provisioning/playbook.yml` | `provisioning/playbook.yml` |
| | `kypo-demo/upstream/provisioning/roles/client/tasks/main.yml` | `provisioning/roles/client/tasks/main.yml` |
| | `kypo-demo/upstream/provisioning/roles/server/defaults/main.yml` | `provisioning/roles/server/defaults/main.yml` |
| | `kypo-demo/upstream/provisioning/roles/server/tasks/main.yml` | `provisioning/roles/server/tasks/main.yml` |
| `github.com/crond-jaist/cyris` @ `8b65a30581cdd8e126c7b1fa26db2a4b770b7f17` | `cyris-basic/upstream/full.yml` | `examples/full.yml` |
| | `cyris-basic/upstream/basic-multi_host.yml` | `examples/basic-multi_host.yml` |
| `github.com/bsinger98/MHBench` @ `3b3db857cb2277da01e121c418966966c2104ee6` | `mhbench-equifax-small/upstream/main.tf` | `src/environments/terraform/topologies/equifax_small/main.tf` |
| | `mhbench-equifax-small/upstream/security_rules.tf` | `src/environments/terraform/topologies/equifax_small/security_rules.tf` |
| | `mhbench-equifax-small/upstream/modules/attacker/attacker.tf` | `src/environments/terraform/topologies/modules/attacker/attacker.tf` |
| | `mhbench-equifax-small/upstream/modules/attacker/security_rules.tf` | `src/environments/terraform/topologies/modules/attacker/security_rules.tf` |
| | `mhbench-equifax-small/upstream/modules/perry_manager/perry_manager.tf` | `src/environments/terraform/topologies/modules/perry_manager/perry_manager.tf` |
| | `mhbench-equifax-small/upstream/modules/perry_manager/security_groups.tf` | `src/environments/terraform/topologies/modules/perry_manager/security_groups.tf` |
| | `mhbench-equifax-small/upstream/equifax_small.py` | `src/environments/terraform/specifications/equifax_small.py` |
| | `mhbench-equifax-small/upstream/equifax_instance.py` | `src/environments/terraform/specifications/equifax_instance.py` |
| | `mhbench-equifax-small/upstream/setupStruts.yml` | `ansible/vulnerabilities/apacheStruts/setupStruts.yml` |
| `github.com/cylabcyberautonomy/Incalmo` @ `932c5fcd1f97c2e75ae3ac7f008d947956995bd9` | `mhbench-equifax-small/upstream/incalmo-prompts/bash-pre_prompt.txt` | `incalmo/core/strategies/llm/interfaces/preprompts/bash/pre_prompt.txt` |
| | `mhbench-equifax-small/upstream/incalmo-prompts/incalmo-pre_prompt.txt` | `incalmo/core/strategies/llm/interfaces/preprompts/incalmo/pre_prompt.txt` |
| `github.com/Orange-Cyberdefense/GOAD` @ `992307adf944b934a3b76a2f56a637104c54b805` | `goad-light/upstream/inventory.ini` | `ad/GOAD-Light/data/inventory` |
| | `goad-light/upstream/config.json` | `ad/GOAD-Light/data/config.json` |
| | `goad-light/upstream/provider-vmware-inventory.ini` | `ad/GOAD-Light/providers/vmware/inventory` (identical in `virtualbox/` and `vmware_esxi/`) |
| | `goad-light/upstream/Vagrantfile` | `ad/GOAD-Light/providers/vmware/Vagrantfile` (identical in `vmware_esxi/`) |
| `github.com/andreashappe/cochise` @ `3abdb11f577dbdc8c4cf219c1b289d8c858f2877` | `goad-light/upstream/cochise/scenario.txt` | `src/cochise/templates/scenario.md` |
| | `goad-light/upstream/cochise/osint_users.txt` | `scenario-data/users.txt` |
| `github.com/splunk/attack_range` @ `fc9b9e719d8835da0bbb5c20d46c52a9778d64e2` | `splunk-detection/upstream/splunk_windows_aws.yml` | `templates/aws/splunk_windows_aws.yml` |

## Tooling fetched at spike run time (not vendored)

| Fetched to | Project | License | Use |
|---|---|---|---|
| `$IMAGE_CACHE/busybox.exe` (downloaded by `spikes/vsockd-win/run.sh`) | [busybox-w32](https://frippery.org/busybox/) | GPL-2.0 | POSIX userland staged into the vsockd-win spike's **test image only** (never production goldens), so inspect_ai's `self_check` suite can run against the Windows daemon |
