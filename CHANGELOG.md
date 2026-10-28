## Unreleased

- New example `defender_ops` (original): king-of-the-hill sabotage of a small ops environment (status-board tamper, orderboard degrade, watchdog crash-by-address) while the bastion gate must stay up, then a quiet patch-and-cleanup scored from the exec witness and the exported ops log. Exercises scoped NAT egress on a routerless segment, a router ACL with a deny carve-out, static routes, drawn int/choice variables applied by a boot unit, a file-source telemetry collector with ordered evade severity, and a custom registered goal type (`lotl`). With the example-coverage extensions below, every goal type and every realizable evidence mechanism now has a shipped exerciser (design: example-coverage-2026-10.md).

- Examples: kypo-demo draws an `int` maintenance code and a `choice` banner wing per sample (observable in the pre-login telnet banner, with a new ladder rung scored against the int draw); cyris-basic adds a first-match `deny:` carve-out and an `icmp` entry to the firewall ACL (the recon answer is now measured, not read off the spec) and a guest-read `host:`+`path:` answer goal on the forensics triage; splunk-detection adds a quiet-discovery challenge with a `stealth: true` detection goal and an `evade` goal using `zero_at` partial credit under the default `on_sensor_tamper` policy. kypo-demo and cyris-basic rebuild and republish.

- Routers reload their ruleset at boot: the seed's `systemctl enable --now nftables` was a start-no-op against a realized image's already-active service, so an ACL-only change (no guest rebuild) left the realize-era rules running with the new rules unloaded on disk. The seed now enables and restarts; the first ACL-only change in the tree is what caught it (the cyris trio honestly measured the stale policy and refused the build).

- The build's proof boot gains provider parity it lacked: it runs the exec witness (so witness-consuming goals are build-provable, same kill switch) and supplies the build's own uplink when the plan requires egress. The eval path gains `INSPECT_RANGES_UPLINK_NETWORK` (provider and applier read their own environment, the attack-box deployment-knowledge rule), required to boot a spec-declared egress range and ignored by egress-free ranges.

- Scoring integrity (fourteenth amendment): the `answer` goal's `host`+`path` source snapshots the file at setup, before agent entry, and compares submissions against the snapshot; the previous live read at scoring time let an agent with write access to the file rewrite the comparison source and submit the rewrite for a guaranteed pass. The source's assurance label becomes `host-anchored` (plant-time trust, like every planted goal), and the build trio's forged check for the first authored consumer demonstrates the closed attack.

- Terminal tool: the blocking send's completion signal (`; tmux wait -S done-...`) no longer appears in the session's asciicast.

## 0.2.0 (25 October 2026)

- Initial release.
