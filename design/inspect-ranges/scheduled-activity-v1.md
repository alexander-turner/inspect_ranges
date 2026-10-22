---
type: decision
title: "Scheduled activity v1: recurring in-guest behavior realized at build"
status: accepted
tags: [inspect-ranges, build, guest-config, scheduled-activity, decision]
timestamp: 2026-10-22
---

# Scheduled activity v1: recurring in-guest behavior realized at build

*Decision record for the first realizer of `hosts[].scheduled_activity` ([guest-config-v0.3](guest-config-v0.3.md)). The section parsed since v0.3 and refused at planning with `guest-config-not-realized`. The motivating consumer is detection realism: background benign activity on an instrumented endpoint (splunk-detection), so a stealth task is not passed by the range simply being silent. The GOAD bot scripts remain out of scope until they are vendored.*

## The question

A `scheduled_activity` declaration names a script, a schedule, and optionally a user. Something has to turn that declaration into behavior a sample actually exhibits, decide where the script comes from, and prove the installation happened. This record settles the mechanics.

## Decisions

**Scripts resolve from the range directory.** A declaration's `script` is a relative path under `activities/` beside `range.yaml` (`activities/<script>`). The build resolves it at the fail-fast resolution step, content-digests the file, and records the digest in the manifest; the digest also enters the guest's build key, so an edited script rebuilds exactly the guests that declare it. This follows the recipe-bundle pattern: the file is a build input with a content identity. An absolute or traversing `script` refuses at validation (`invalid-scheduled-activity`); a missing file refuses at build resolution (`activity-not-resolved`), before anything boots.

**Realization installs a persistent unit in the captured image.** During the build, after recipes and before verification, each activity is pushed into its guest and registered so the captured disk carries it: on Linux a systemd service (plus a timer for interval schedules) under `/etc/systemd/system/`, enabled but not started; on Windows a scheduled task registered through `Register-ScheduledTask`. Every consumer boot of the captured image then runs the activity on its schedule with no per-sample work, matching the build-time stance of every other guest section. Unit and task names are `ir-activity-<guest>-<index>` (declaration order), so the spec alone determines them. Scripts land at `/opt/inspect-ranges/activities/<script>` (0755) on Linux and `C:\ProgramData\inspect-ranges\activities\<script>` on Windows; a Linux script needs a shebang (the service executes the file), and a Windows script runs through `powershell -NoProfile -ExecutionPolicy Bypass -File`.

**The activity runs as `user` when declared, root/SYSTEM otherwise.** Linux sets `User=` on the service. Windows registers the task principal as SYSTEM (`ServiceAccount` logon) by default, or as the declared user with S4U logon (no stored credential, no interactive token). The `user` field exists for scenario-relevant principals, for example the token surface a user-owned scheduled task creates.

**The v0 schedule grammar is two forms.** A present `schedule` must be `@boot` (run once at each boot) or `every <N><unit>` with `<N>` a positive integer and `<unit>` one of `s`, `m`, `h` (for example `every 30s`, `every 5m`, `every 1h`). Anything else refuses at validation with a positioned `invalid-scheduled-activity`. The schema keeps `schedule` optional (the v0.3 shape records it as `schedule?`), and a schedule-less declaration refuses at build resolution (`activity-schedule-required`). The Windows task scheduler's repetition floor is one minute, so `every <N>s` on a Windows host refuses at build resolution (`activity-schedule-unsupported`). Interval schedules map to a systemd timer (`OnBootSec`/`OnUnitActiveSec`) on Linux and a repeating trigger (past start boundary, no repetition duration, which repeats indefinitely on the supported Server releases) on Windows; `@boot` maps to an enabled service (`WantedBy=multi-user.target`) and an `-AtStartup` trigger.

**Verification checks the installed unit, spec-derived.** The declaration-verification engine gains an `activity` kind beside `service` and `vulnerability`: on Linux `systemctl is-enabled` on the unit (the timer for interval schedules, the service for `@boot`), on Windows `Get-ScheduledTask` with a not-`Disabled` state check. Failures carry `activity-not-verified` with the observed output. Because the probe derives everything from the spec, the same check runs in the build's verify pass and in the proof boot's convergence loop, so the captured artifact is verified to carry the unit too. There is no first-run execution check: an activity may legitimately run long (a listener-style bot), and a build-time run would dirty the captured disk at an arbitrary point; the enabled unit is the verified claim, and behavioral checks prove any activity a chain depends on.

**The gate lifts the way `provisioning` lifted.** `scheduled_activity` joins `BUILD_REALIZED_SECTIONS` and `has_guest_content`: the build's planning passes set it in `realized_sections`, a host declaring only activities counts as a content guest (built, captured, gated by `range-not-built` until a manifest matches), and the runtime path without a manifest keeps refusing `guest-config-not-realized`. Unbuilt content stays inert.

**The manifest records activities per guest.** Each `GuestRecord` gains an `activities` tuple (`script`, content digest, `schedule`, `user`, unit name), and the verification record carries the `activity` declaration results. Older manifests parse unchanged (the tuple defaults empty); a manifest written before this slice fails the key match anyway once a guest declares an activity, because the projection and key both moved.

## Out of scope

- The GOAD dc02 bot scripts: upstream is unvendored, so nothing realizes them honestly; they stay in `goad_light`'s `deferred.yaml`.
- Live-range noise tuning (jitter, activity profiles, per-sample variation): the v0 schedule is fixed by the spec.
- Eval-runtime start/stop of activities beyond what the baked units provide.
- Cron-expression schedules: the two v0 forms cover the consumers in evidence; the grammar extends when a range demands more.

## Consequences

- `splunk-detection` declares a benign-admin activity on its `win` host (`activities/benign-admin.ps1`, `every 10m`): periodic service queries, directory listings, and event-log reads that generate ordinary telemetry on the instrumented endpoint. The fixture is local-only, so no published artifact is invalidated; its next build re-keys the `win` guest.
- A Windows build and battery run for splunk-detection has not been executed in this slice (no KVM in the authoring environment); the user runs it as a follow-up before relying on the realized activity.
