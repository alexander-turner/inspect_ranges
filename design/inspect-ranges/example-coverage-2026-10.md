# Record: the example-coverage arc (2026-10-28)

Status: executed overnight (user-ratified plan, single PR, branch `example-coverage`). The post-release coverage matrix found that every shipped example exercised the agent-submission direction while the outside-observer direction was untested; this arc closed it with one new example plus targeted extensions, so every goal type and every realizable evidence mechanism now has at least one shipped exerciser.

## The gap, before

5 of 14 goal types had zero example usage (`availability`, `degrade`, `tamper`, `hijack`, `patch`), taking whole subsystems with them unexercised: the active prober and its `probe/<goal-id>` stream, console-observer verification, `register_exploit()`, degrade partial credit, and the disclosed-needle channel. The exec witness was produced but consumed by nothing. File-source telemetry had zero collectors. One-value knobs everywhere: no `stealth: true`, no `zero_at`, no ordered severity `levels`, `on_sensor_tamper` only ever `fail`, ACLs allow-only, every network `isolated` with `egress: none`, one drawn variable in the whole set, no custom goal type, no Linux scheduled activity.

## What closed it

**defender_ops** (new, original, Linux-only): king-of-the-hill sabotage of a small ops environment. Carries `tamper` (status-page defacement, disclosed needle), `degrade` (error-fraction window), `hijack` (crash-by-address watchdog with console corroboration), `availability` (the bastion gate stays up, fraction partial credit), `patch` (registered exploit re-run), and `lotl`, the first shipped custom goal type and the exec witness's first scoring consumer (name-discipline absence claim with honest completeness rules and a stated matching floor, the hijack precedent). Topology: routerless `mode: nat` with scoped CIDR egress (network and attacker), a router ACL with a `deny:` carve-out plus `icmp`/guest-name/CIDR endpoints, a static route, drawn `int` and `choice` variables applied by a boot unit, Linux `scheduled_activity` (`@boot` and `every` with `user:`), and a `kind: file` telemetry collector feeding an `evade` goal with ordered severity `levels`. Build trios for both challenges, including the first prober-driven, hijack, and patch checks the build has ever run.

**Extensions**: kypo-demo draws an `int` maintenance code and a `choice` banner wing (observable pre-login; a new ladder rung scores the int draw). cyris-basic gains a first-match `deny:` carve-out plus an `icmp` entry (the recon answer is now measured, not read off the spec) and the first `host`+`path` answer goal. splunk-detection gains a `stealth: true` detection goal and an `evade` goal with `zero_at` partial credit under the default `on_sensor_tamper` policy.

## What the first consumers flushed out (the arc's real yield)

1. **Routers never reloaded a fresh ruleset on realized images**: the seed's `systemctl enable --now nftables` is a start-no-op against the realize-era-active service, so any ACL-only change silently kept the baked rules. The cyris trio honestly measured the stale policy and refused the build. Fixed: enable + restart.
2. **The proof boot ran no exec witness**, so a witness-consuming goal could never be build-proven. Fixed: provider-parity `ExecWitnessPoller` in the behavioral boot, same kill switch.
3. **The proof boot was uplink-free by design**, failing the first egress-declaring runtime spec at compose up. Fixed: the proof boot passes the build's own uplink exactly when the plan requires one.
4. **The eval path had no uplink either**: neither provider nor applier passed `uplink_network`, so an egress-declaring spec could not boot as a sample. Fixed: `INSPECT_RANGES_UPLINK_NETWORK`, read by each boot path's own environment per the deployment-knowledge rule.
5. **The `host`+`path` answer source was agent-writable at scoring** (fourteenth scoring-integrity amendment): live-read comparison let rewrite-and-submit pass; now snapshotted at setup, host-anchored, with the cyris forged check running the closed attack.

Plus review-grade authoring fixes: the forged gate code moved out of the draw domain (a ~1/9000 healthy-build refusal), the lotl floor stated, the splunk signal reach widened against the long-path dodge, and a dead declared `dns.nameservers` removed after it bricked the first defender_ops build (a validation-warn candidate: a resolver no guest can reach fails network-settle with an unrelated-looking error).

## Deliberate exclusions (recorded, not gaps)

Designed-not-built (gated, unauthorable): FQDN egress entries, egress on router-attached networks, IPv6, `observer: guest-snapshot`. Deliberate non-takes: `on_sensor_tamper: succeed` (no current sensor is destroy-only; declaring it on an Administrators-writable log would be a cheap completeness waiver), `dns.nameservers` (needs a live in-range resolver story; the field realizes but a dead value bricks builds), `defense.tier` variation (pure metadata; nothing branches on it), terminal `instance=` namespacing and multi-agent examples (post-v1), `primitive:` coverage is metadata-only by definition. `lower_is_more_severe` was on this list (schema-exclusive with ordered `levels`; needs a numeric-severity collector) until this arc closed it (2026-10-28): defender-ops grew the numeric-severity collector it needed, the `opsjournal` journald export, and a second cleanup evade goal (`quiet-journal`) over its `PRIORITY` field with floor 4 and `lower_is_more_severe`. Known flake recorded: splunk's execute-and-confirm reference failed once on a clean pipeline (settle-margin timing) and passed identically on re-run; widen the settle margin if it recurs.

## Verification

All four touched builds proven: defender-ops 6/6 (twice), cyris-basic 12/12 including the rewrite-attack forgery, kypo-demo green with the drawn-banner assertion, splunk-detection 9/9 including quiet-discovery. Two fresh-context adversarial reviews, all findings fixed. Full suite green throughout (2312 at close). Real-model evals of the four changed examples follow the PR merge, with publish of the three catalog builds after.
