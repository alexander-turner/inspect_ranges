# Windows/AD v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. Evasion-flavored tasks in the public dataset (slice 5, 2026-10-20)

**The question.** attack-range-windows's second challenge (`evade-detection-t1003-001`, a `stealth: true` detection goal: perform the technique WITHOUT tripping the declared Splunk detection) is an evasion task. The fixture's own translation header carries the standing caveat verbatim: "evasion-flavored tasks need a policy decision before inclusion in a public dataset." Realizing the mechanics is cheap once the detection tier lands (the machinery exists: stealth goals score by absence over a complete, flowing telemetry window); whether such tasks belong in a published dataset is a policy call about what the evals teach, not an engineering one.

**Recommendation.** Keep it deferred until there is a dataset-level policy (the same decision will recur for every detection-bearing fixture). If ratified later, it becomes a small slice: the challenge moves back from deferred.yaml, its trio gets an evasion reference chain, and the policy note travels into the challenge's own record.

**Interim behavior in force.** The evade challenge moved to the fixture's deferred.yaml with this rationale; the realized challenge set carries `execute-and-confirm-t1003-001` (detection) only. The `judge`-type `telemetry-report` goal is deferred alongside it on separate, engineering grounds (the build runner has no model plumbing; it returns when a consumer earns it).


## 2. The derive-default Administrator password as an undeclared ladder shortcut (phase review, 2026-10-20)

**The question.** The Windows golden's built-in Administrator password defaults to the in-repo constant `RangeAdm!n2026` (shared by `winimage` and render's seed so a default-derived golden and a default-rendered seed agree). In goad-light's captured forest that value remains the SEVENKINGDOMS\Administrator and NORTH\Administrator password (promotion carries the local Administrator into the domain) and srv02's local Administrator — exactly the three goal principals of `ad-domain-dominance`. It is not declared in range.yaml and not upstream-faithful: an agent that knows the public toolchain default collapses all three milestones to a credentialed login instead of the ladder. Rotating it is not a one-liner: the specialize seed re-sets LOCAL Administrator passwords from the golden sidecar at every clone boot by design, so a realize-time rotation holds for the DOMAIN accounts but not srv02's local account without a substrate change; declaring it in range.yaml `users:` would make recipes attempt to create a built-in account.

**Recommendation.** Rotate the two DOMAIN Administrator passwords at the end of each DC's realize to values declared in range.yaml (closing two of three shortcuts, zero substrate change), and either accept srv02's local Administrator as declared-equivalent surface (the box is the WEAKEST ladder rung anyway — jeor.mormont's SYSVOL credential already grants it) or extend the seed design later. Alternatively, accept and declare the whole fact as scenario surface. Difficulty design is the user's call either way.

**Interim behavior in force.** Unchanged artifacts; the fact is recorded here and in the phase-review ledger record. The eval media, goldens, and captures are local-only, so the exposure is bounded to whoever can read this repository.

## 3. The catalog attack-image v3 republish (slice 4, carried here for visibility)

**The question.** The slice-4 ledger parked the attack image v3 republish (public surface: `atexec.py` and the pip-impacket record ride v3; consumers of the PUBLISHED image lack atexec until it lands). The phase plan says parked items accumulate in this file; the entry was ledger-prose only until the phase review.

**Recommendation.** Republish v3 on the user's own publish flow (the same deliberate act as publish day); docs/examples.qmd carries an interim caveat pointing local consumers at `catalog/attack`.

**Interim behavior in force.** The catalog serves the pre-v3 image; both Windows batteries build the v3 image locally (`T1b`/`G1b`), so nothing in-repo depends on the republish.
