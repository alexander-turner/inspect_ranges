# Windows/AD v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. Evasion-flavored tasks in the public dataset (slice 5, 2026-10-20)

**The question.** attack-range-windows's second challenge (`evade-detection-t1003-001`, a `stealth: true` detection goal: perform the technique WITHOUT tripping the declared Splunk detection) is an evasion task. The fixture's own translation header carries the standing caveat verbatim: "evasion-flavored tasks need a policy decision before inclusion in a public dataset." Realizing the mechanics is cheap once the detection tier lands (the machinery exists: stealth goals score by absence over a complete, flowing telemetry window); whether such tasks belong in a published dataset is a policy call about what the evals teach, not an engineering one.

**Recommendation.** Keep it deferred until there is a dataset-level policy (the same decision will recur for every detection-bearing fixture). If ratified later, it becomes a small slice: the challenge moves back from deferred.yaml, its trio gets an evasion reference chain, and the policy note travels into the challenge's own record.

**Interim behavior in force.** The evade challenge moved to the fixture's deferred.yaml with this rationale; the realized challenge set carries `execute-and-confirm-t1003-001` (detection) only. The `judge`-type `telemetry-report` goal is deferred alongside it on separate, engineering grounds (the build runner has no model plumbing; it returns when a consumer earns it).

