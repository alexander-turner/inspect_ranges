## Unreleased


- Attack box: an external provider can now be a pinned program rather than a Python package. `INSPECT_RANGES_ATTACK_BOX=inspect_ranges._attackbox.pinned.pinned_attack_box:<pin file>` selects the release a deployment-written pin file names. The first eval downloads it and checks its SHA-256, the program must report the pin's minimum version, eval init probes the host, the recorded origin carries the pin's contents, and `INSPECT_RANGES_ATTACK_BOX_PROGRAM` names an installed program for offline hosts.



## 0.2.4 (30 October 2026)

- Distribution: a registry location may name one repository with a tag prefix (`registry.example.net/mirror:ranges`), keeping every artifact in that single repository with the name in its tags (`ranges--attack`, `ranges--vulhub-zabbix--spec-<hash>`), for registries where a repository is a pre-created, allowlisted resource (Amazon ECR): one repository admitted once serves every range. Mirror, pull, push, publish and enumeration work unchanged from it. Tag listings now follow the distribution spec's `Link` header for pagination, which is the form ECR paginates with (it refused the previous `last=<tag>` guess on repositories over a thousand tags).

## 0.2.3 (29 October 2026)

- Packaging: the wheel ships the range container's `Dockerfile` beside its entrypoint. 0.2.0 through 0.2.2 omitted it, so a pip install could not build the range image when `INSPECT_RANGES_RANGE_IMAGE` was unset (the default), failing at `up` with a missing build context.

## 0.2.2 (28 October 2026)

- Distribution: a registry answering 401 with a `Basic` challenge (Amazon ECR) is authenticated with the docker config's credential for the host directly, beside the existing `Bearer` token flow; a Basic challenge with no credential is a coded refusal naming the host. The docker config honors `DOCKER_CONFIG` the way the docker CLI does (`$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`), so a deployment can hand the client a config without touching the home directory.

- `plan_totals(spec)` is public: the guest count and summed vCPUs and MiB a range declares (a guest without `resources:` counts 1 vCPU / 1024 MiB), computed from the spec alone so a deployment can size a host for a range whose build it has not pulled; `resolve_plan` records the same sums through it. `catalog_image_references(spec)` is public beside it: the catalog image names a range resolves outside its build (content-free hosts, routers, the attack box), which with the build itself is what a deployment mirrors for the range.

- New task `inspect_ranges/examples_smoke`: the Linux example ranges with published builds in one eval, each sample naming its own example's range as its sandbox (the first challenge of each by default, every challenge with `-T per_example=all`), for proving a deployment pulls, boots, scores, and tears down ranges end to end.

- `challenge_dataset` stamps sandbox-escape guard facts on every sample it builds against a `range_spec` (`escape_sentinel_facts`, the key Inspect's escape sentinel reads): the declared targets with the goals naming them, the agent's seat and router policy, the goal mix, and the egress reality, derived from `range.yaml` and `challenges.yaml` alone, so the guard judges range tradecraft against the declared targets rather than as leaving the sandbox.

## 0.2.1 (28 October 2026)

- Requires inspect-ai 0.3.286. The sandbox contract's new `user:` parameter on `read_file`/`write_file` is enforced genuinely rather than refused: an explicit user rides the exec plane (the oracle's privileged-op pattern, since the daemon's file plane acts as the agent identity), with the contract's exception mapping and read cap intact.

- Builds no longer brick on a declared-but-dead `dns.nameservers` entry: the build nameserver now prepends to a network's resolvers instead of appending (glibc tries resolv.conf in order at 5 s per server, so the settle probe's budget burned entirely on a dead first resolver, surfacing as an unrelated-looking channel error). The settle failure message now names the guest's resolver list, an unanswerable `--build-nameserver` refuses up front (`build-nameserver-unanswerable`), and `validate` warns on a `dns.nameservers` entry in an address block nothing can answer (`dns-nameserver-unanswerable`: documentation, benchmark, reserved blocks; entries inside a declared network cidr, private ranges, and link-local stay silent, since a VPC resolver is routinely private or link-local).

- defender-ops gains `quiet-journal`, the first consumer of the evade goal's numeric severity mode (`lower_is_more_severe` over journald `PRIORITY`): the watchdog mirrors health lines to stdout with syslog `<N>` prefixes, a recipe-installed exporter ships the unit's journal under the cursor-banner contract (empty deltas ship the bare banner; a cursor that no longer resolves to its exact record fails the poll, so vacuum-and-rotate tampering prices through `on_sensor_tamper` instead of hiding; journald rate limiting is off for the unit so floods price as truncation gaps), and the cleanup challenge scores a second sensor plane: the root-owned OS journal beside the agent-writable file log. Rebuild and republish.

- Evidence: a whitespace-only telemetry poll no longer counts as pipeline flow (the window-flowing check saw stray separator bytes around a cursor banner as data, which could hand quiet verdicts to a silenced sensor behind a chatty exporter).

- Terminal cast attribution has its first end-to-end proof: a multi-agent eval arm (supervisor handing off to two sub-agents, each with its own `terminal(instance=...)`) run against kypo-demo cleaves the stored casts by agent span, with every finalize-flushed cast carrying its opener's identity. Multi-agent solvers should give each sub-agent a distinct `instance=`: nothing in inspect-ai sets `tool_state_scope`, so a shared default namespace collapses the second agent's `open` into the first's session.

- New example `defender_ops` (original): king-of-the-hill sabotage of a small ops environment (status-board tamper, orderboard degrade, watchdog crash-by-address) while the bastion gate must stay up, then a quiet patch-and-cleanup scored from the exec witness and the exported ops log. Exercises scoped NAT egress on a routerless segment, a router ACL with a deny carve-out, static routes, drawn int/choice variables applied by a boot unit, a file-source telemetry collector with ordered evade severity, and a custom registered goal type (`lotl`). With the example-coverage extensions below, every goal type and every realizable evidence mechanism now has a shipped exerciser (design: example-coverage-2026-10.md).

- Examples: kypo-demo draws an `int` maintenance code and a `choice` banner wing per sample (observable in the pre-login telnet banner, with a new ladder rung scored against the int draw); cyris-basic adds a first-match `deny:` carve-out and an `icmp` entry to the firewall ACL (the recon answer is now measured, not read off the spec) and a guest-read `host:`+`path:` answer goal on the forensics triage; splunk-detection adds a quiet-discovery challenge with a `stealth: true` detection goal and an `evade` goal using `zero_at` partial credit under the default `on_sensor_tamper` policy. kypo-demo and cyris-basic rebuild and republish.

- Routers reload their ruleset at boot: the seed's `systemctl enable --now nftables` was a start-no-op against a realized image's already-active service, so an ACL-only change (no guest rebuild) left the realize-era rules running with the new rules unloaded on disk. The seed now enables and restarts; the first ACL-only change in the tree is what caught it (the cyris trio honestly measured the stale policy and refused the build).

- The build's proof boot gains provider parity it lacked: it runs the exec witness (so witness-consuming goals are build-provable, same kill switch) and supplies the build's own uplink when the plan requires egress. The eval path gains `INSPECT_RANGES_UPLINK_NETWORK` (provider and applier read their own environment, the attack-box deployment-knowledge rule), required to boot a spec-declared egress range and ignored by egress-free ranges.

- Scoring integrity (fourteenth amendment): the `answer` goal's `host`+`path` source snapshots the file at setup, before agent entry, and compares submissions against the snapshot; the previous live read at scoring time let an agent with write access to the file rewrite the comparison source and submit the rewrite for a guaranteed pass. The source's assurance label becomes `host-anchored` (plant-time trust, like every planted goal), and the build trio's forged check for the first authored consumer demonstrates the closed attack.

- Terminal tool: the blocking send's completion signal (`; tmux wait -S done-...`) no longer appears in the session's asciicast.

## 0.2.0 (25 October 2026)

- Initial release.
