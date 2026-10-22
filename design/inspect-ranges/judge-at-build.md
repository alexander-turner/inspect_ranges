---
type: decision
title: "Judge goals at build: the trio exempts the model-graded share"
status: accepted
tags: [inspect-ranges, build, challenges, behavioral-checks, judge, decision]
timestamp: 2026-10-22
---

# Judge goals at build: the trio exempts the model-graded share

## The question

`judge` goals grade through `get_model()` at eval time. The build's behavioral trio (`reference`/`insufficient`/`forged`, build-v1 slice 6) scores each check through the same `score_challenge` the eval uses, and the build runner has no model plumbing: a judge goal can never be achieved during the trio, so a reference chain on a challenge carrying one can never reach the required 1.0, and the build refuses the range. This blocked splunk-detection's designed `telemetry_report_goal` (the sketch sat in its `deferred.yaml`) since the challenges phase closed.

## The decision

The trio exempts model-graded goals from its scoring. Each check scores a copy of the challenge with the model-graded goals removed, so the aggregate's weighted mean renormalizes over the remaining goals' weights. Goals are classified by assurance (`assurance_for(goal) == "model-graded"`, the predicate the engine's weight cap already uses), so a custom model-graded type is exempt on the same terms.

The exemption semantics, precisely:

- `reference` must score exactly 1.0 with validity `valid` over the non-model-graded share.
- `insufficient` and `forged` must score exactly 0.0 with validity `valid` over the same share. The negative checks' one-submission floor also reads that share: a judge goal consumes submissions at eval, and with the exemption it no longer forces submissions onto an otherwise observation-only trio (the splunk-detection shape).
- The exemption is recorded: a check on a challenge with exempt goals carries `judge-exempt=<goal ids>` in its detail, which lands in the `behavioral` stage line and in the manifest's `behavioral_checks` records. A proven range with a judge goal reads as proven except the model-graded share.
- A challenge whose goals are all model-graded has no provable share, so `_validate_checks` refuses it with the coded error `challenge-not-provable` before any chain runs.
- Under `milestones` scoring the exempt goal also leaves the implication chain for the trio's pass. Model-graded proofs hold the lowest assurance rank, so an exempt goal could never have granted implied credit to a higher-assurance goal anyway.

Eval-time scoring is unchanged: judge goals grade at eval, and the engine caps their weight share at `JUDGE_WEIGHT_CAP` (25%) whenever a non-model-graded goal exists. The cap bounds what the exemption leaves unproven: on any mixed challenge, at most 25% of the effective weight.

The rationale: the trio's contract is exact scores (1.0 and 0.0) over reproducible mechanics, and a model grade is neither exact nor reproducible, so binding the trio to one would make the proof flaky. The exemption keeps the proof's claim visible and lets a challenge carry the judge goal it was designed with.

## Parked: a host-side model call at build

The alternative is real model plumbing in the build runner, for example a `--judge-model` flag: the build host has egress (only the proof boot's attacker is contained), so the call is feasible. Parked, with this recommendation: if a consumer later needs the model-graded share exercised at build (a rubric regressing against the reference chain's report with nothing to catch it), the right shape is an opt-in flag naming the model, the grade recorded in the check detail, and the exemption remaining the default, because a hard gate over a nondeterministic grade refuses flakily. The recorded `judge-exempt` detail is the hook such a gate would tighten on. Build it when a real range demonstrates the need.

## The consumer

splunk-detection realizes the deferred `telemetry_report_goal` as the `telemetry-report` judge goal on `execute-and-confirm-t1003-001`, weight 0.25 (a 0.2 share beside the weight-1.0 detection goal, inside the cap). The challenge prompt already instructs the report, so only the goal was missing. The example is local-only (Windows), so no published build invalidates; re-running its local build and battery is a user follow-up.
