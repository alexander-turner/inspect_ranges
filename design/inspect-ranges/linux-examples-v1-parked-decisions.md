# Linux examples v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. The generation layer stays deferred; variables resolve to defaults (phase plan, 2026-10-19)

**The fact:** KYPO's whole randomization story (`variables:` with per-instance draws, e.g. `telnet_port` min 1500) is the smallest public precedent for a per-sample generation layer. V1 lifts the planning gate only as far as DEFAULTS-RESOLUTION: a declared variable resolves to its default at build time and is consumable in recipes; it never redraws per sample.

**Why this is safe:** the secrets that must differ per sample (both KYPO flags) already do, through the challenge plant layer (re-planted with proof entropy at setup, so the checked-in defaults never score). What stays fixed is non-secret topology-ish state (the telnet port), which upstream randomizes for training variety, not for scoring integrity; the `answer` goal for `telnet_port` scores the recorded default, as the challenges file has noted since 2026-10-15.

**The decision parked:** whether and when to build the real generation layer (per-sample draws injected at realization, with build keys and challenge answers tracking the draw). Recommendation: not before a concrete consumer needs per-sample NON-SECRET variation; the plant layer covers secrets, and per-sample rebuilds of guest content would fight the build cache's whole design (sticky realized images). If training-variety randomization becomes a requirement, draw at BOOT (cloud-init consuming a draw file) rather than at build, so images stay shared.

**DECIDED (user, 2026-10-19): stay deferred.** Defaults-resolution is the v1 semantic; the generation layer waits for a concrete consumer of non-secret per-sample variation, and draws at boot when it comes.

**BUILT (user-requested, 2026-10-22): the consumer arrived and the boot-draw slice landed.** `draw: boot` on a variable draws a per-sample value at boot (never at build; images and build keys unchanged), delivered through a cloud-init draws file and applied by range-authored boot units; kypo-demo's `telnet_port` is the first consumer, and its published build needs a rebuild and republish. See [variable-draws-v0.md](variable-draws-v0.md).


## 2. Router provisioning (and the firewall-pivot path it unlocks) (slice 2, 2026-10-19)

**The fact:** CyRIS marks its firewall `is_host: true` with its own weak account (robot.abc): the router is ALSO a target, and the natural cross-segment attack path is pivoting THROUGH it. Our build runs recipes on `hosts` only; router guest content has no realization mechanism, and the planning gate on `routers[].users` still stands.

**Interim behavior in force:** the firewall's account moved to cyris-basic's `deferred.yaml`; the cross-segment challenge revised to the recon the declared environment supports (measuring the 25/53 forwarding policy), with the revision rationale recorded in `challenges.yaml`.

**The decision parked:** whether to build router provisioning (schema `routers[].provisioning`, the build loop including routers, capture/swap for router guests) so firewall-as-target ranges realize fully. Recommendation: yes, but as its own slice when a second consumer appears (GOAD-class ranges will want it); the machinery is a straight extension of the host path, and the gate already refuses honestly until then.

**DECIDED (user, 2026-10-19): build it on the second consumer.** It becomes a planned slice of whichever phase first needs it (likely Windows/AD); cyris-basic's firewall-pivot challenge is restored in the same slice.

**BUILT (user-ratified 2026-10-21): the trigger fired and the slice landed.** Schema `routers[].provisioning` (users realize through router recipes; content requires a declared `image`, `router-image-required`, since the appliance default is a backend resolution the build key cannot pin), the build loop extended to routers (no build egress: router-attached egress is itself unrealized, so router recipes run offline and the settle gate skips them), capture/manifest/build keys/`range-not-built` gate all on the host path, and cyris-basic's firewall account plus the firewall-pivot challenge restored with their trio.
