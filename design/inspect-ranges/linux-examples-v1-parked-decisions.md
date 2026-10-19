# Linux examples v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. The generation layer stays deferred; variables resolve to defaults (phase plan, 2026-10-19)

**The fact:** KYPO's whole randomization story (`variables:` with per-instance draws, e.g. `telnet_port` min 1500) is the smallest public precedent for a per-sample generation layer. V1 lifts the planning gate only as far as DEFAULTS-RESOLUTION: a declared variable resolves to its default at build time and is consumable in recipes; it never redraws per sample.

**Why this is safe:** the secrets that must differ per sample (both KYPO flags) already do, through the challenge plant layer (re-planted with proof entropy at setup, so the checked-in defaults never score). What stays fixed is non-secret topology-ish state (the telnet port), which upstream randomizes for training variety, not for scoring integrity; the `answer` goal for `telnet_port` scores the recorded default, as the challenges file has noted since 2026-10-15.

**The decision parked:** whether and when to build the real generation layer (per-sample draws injected at realization, with build keys and challenge answers tracking the draw). Recommendation: not before a concrete consumer needs per-sample NON-SECRET variation; the plant layer covers secrets, and per-sample rebuilds of guest content would fight the build cache's whole design (sticky realized images). If training-variety randomization becomes a requirement, draw at BOOT (cloud-init consuming a draw file) rather than at build, so images stay shared.
