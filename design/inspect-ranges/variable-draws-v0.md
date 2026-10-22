# Decision: variable draws v0 (per-sample draws applied at boot)

*2026-10-22. Executes the recommendation parked in [linux-examples-v1-parked-decisions.md](linux-examples-v1-parked-decisions.md) entry 1 (DECIDED 2026-10-19): the generation layer waits for a concrete consumer of non-secret per-sample variation, and draws at boot when it comes. The consumer arrived: the user requested per-sample draws of non-secret variables, kypo-demo's telnet port being the forcing case. This is the simple version: no build-time redraws, no fully dynamic ranges.*

## The shape

A variable opts in with a new `draw: boot` field. Everything without it behaves exactly as before: loading substitutes defaults, builds realize defaults, nothing per-sample exists.

For a `draw: boot` variable, each sample draws its own value when its range boots:

- **Realization never sees draws.** Defaults substitute at load exactly as today. Realized images, build keys, and the plan are unchanged by a draw; one built image serves every sample. Every substituted reference in `range.yaml` (a declared service port, a recipe `vars` entry, an ACL) still carries the default, so the spec documents the baked state and the drawn value exists only beside it.
- **The provider draws per sample.** In `sample_init`, before anything renders: a fresh seed (`secrets.token_hex(8)`), then `draw_variables(spec.variables, seed)` (`_compiler/draws.py`), a pure function of (variables, seed). Respins reuse the sample's draws (drawn before `_acquire_range`). The algorithm is a reproducibility contract: the recorded seed must keep re-deriving the recorded values, so treat changes to it like wire-format changes.
- **The draw file.** Rendering writes the drawn values into every Linux guest's cloud-init seed as a `write_files` entry: `/etc/inspect-ranges/draws.json`, a JSON mapping of variable name to drawn value, mode 0644 (draws are non-secret by construction). The agent's foothold guest is excluded: a drawn value is often a challenge's expected answer (kypo's port), and a readable file on the agent's own box would hand it over. The `/etc` path survives an in-sample reboot, unlike `/run`. Windows guests get no draws file in v0 (the unattend seed has no `write_files` lane).
- **Guests apply draws themselves.** A recipe installs a boot unit (`After=cloud-init.service`, since `write_files` runs in that stage) that reads the file and reconfigures its service. The file is absent at build boots, so the unit is a no-op there and the recipe's own assertions check the default.
- **Scoring follows the draw.** `oracle.variable_value(name)` is the one place the rule lives: the drawn value when one exists, the declared default otherwise. `AnswerType.check` and the poller's cheap tier both read it, and `oracle.draws()` exposes the full mapping. For a drawn variable the checked-in default can never score: the draw domain excludes the default outright (see below). Undrawn variables keep the existing exposure guidance (the default is as public as the repository).
- **Recording.** The seed and the drawn values land verbatim on a new `draws` evidence stream (driver-side, beside `plants` and `session`), so a recorded sample's scoring is reproducible post-hoc. The build manifest's `seeds` slot is a build-side record and stays empty: builds never draw.

## Drawable types

`draw: boot` requires an explicit drawable type; validation (`invalid-variable`) refuses the rest:

| Type | Draw | Rule |
|------|------|------|
| `port` | uniform over `min`..`max`, excluding the default | bounds default to 1024..65535 (unprivileged ports) |
| `int` | uniform over `min`..`max`, excluding the default | explicit `min` and `max` required |
| `choice` | uniform over `choices`, excluding the default | at least one choice besides the default required |
| `text` | refused | no constraint vocabulary to draw from in v0 |
| `password` | refused | per-sample secrets are the challenge plant layer's job |
| omitted | refused | a draw needs declared constraints |

Excluding the default from the domain is deliberate: it is the one value every reader of the repository knows, and removing it gives drawn variables the "checked-in defaults can never score" property [challenges-scoring-integrity.md](challenges-scoring-integrity.md) names as the end state. Validation refuses a domain with nothing left after the exclusion.

## The proof boot draws too

The build's behavioral proof boot renders draws like a sample and records them on its evidence record, so the boot-apply units and the chains' value discovery are proven before the build is consumable. One consequence surfaced in code: the settle gate (`verify_range`) checks declared services on their declared ports, which are substituted defaults, while the apply unit has moved the service. The proof boot therefore verifies against a drawn view of the spec (`_drawn_spec`: raw `range.yaml` re-substituted with the draws via `substitute_variables(overrides=...)`), which is the state the range actually boots into. Scoring and conformance keep the unchanged spec plus the draws mapping.

The expected `randomization-not-realized` gate does not exist in code: nothing has gated declared variables since linux-examples-v1 made defaults-resolution the semantic, so there was nothing to lift. The scoring-integrity record's sketch of draws riding `oracle.resolved()` is superseded: variables never ride the plan, and draws ride the handle (`oracle.draws()`).

## The consumer: kypo-demo

`telnet_port` declares `draw: boot`, and the `kypo.server` recipe (version 2) installs `kypo-apply-draws`: a oneshot unit that reads the draws file, rewrites the xinetd port, and restarts xinetd. The `answer` goal `find-telnet-port` then scores the drawn port.

**Rollout note (action required): kypo-demo is published, and this is a semantic `range.yaml` change.** The normalized spec hash moves, so consumers refuse `no-build-for-spec` against the published build until the range is rebuilt and republished (and the recipe change alone would rebuild the server guest anyway). Until the republish lands, `inspect eval inspect_ranges/kypo_demo` on a clean machine fails honestly. A rebuild, a full battery run, and a republish are user follow-ups, not part of this slice.

## Out of scope (recorded, not designed)

- Build-time redraws and per-sample rebuilt content (equifax-style randomized key placement). The build cache's sticky realized images are the design; anything per-sample must ride boot or the plant layer.
- `text` draws: they need a generation vocabulary (patterns, wordlists) that does not exist yet.
- Draws for Windows guests: the unattend seed carries no general file lane in v0.
- Draws on the dev paths: `inspect-ranges up --from-spec` and the CLI `render` boot with defaults (no sample identity, no draw). A draw-at-up flag can come with a consumer.
- Re-substituting draws into spec-derived state (ACLs, dnsmasq, declared users): the realized range carries defaults there by design, and a range author must not reference a drawn variable where only realization can apply it.
