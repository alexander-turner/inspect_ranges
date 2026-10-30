# Round 2, Unit 6: the user surface (docs claims, CLI ergonomics, knob inventory)

Worktree: `.claude/worktrees/r2-u6-surface` at c68cc93. All probes ran read-only (scratch configs under /tmp, a scratch image cache, no ranges or VMs created). Implicated tests pass: `tests/test_docs.py` + `tests/test_cli.py` 76 passed / 6 skipped.

## Findings (ranked; none blocking)

### F1 (mechanical, misleading-error class; moderate): `validate_range`/`validate_challenges` raise raw tracebacks despite a "never raises" contract, and the CLI relays them

- `src/inspect_ranges/schema.py:146`: `parse_marked(path.read_text())` catches only `yaml.YAMLError`; `read_text()` raises `OSError` (directory, permission) and `UnicodeDecodeError` (non-UTF8 file) uncaught. The docstring at `schema.py:135` promises "this never raises on invalid content: YAML syntax errors, structural schema violations, and semantic cross-reference problems all become `Issue` entries".
- `src/inspect_ranges/_challenges/schema.py:930` has the identical pattern under the identical promise ("Like `validate_range`, this never raises on invalid content").
- Reaches the user through `inspect-ranges validate` (`src/inspect_ranges/_cli/validate.py:25`; `click.Path(exists=True)` admits directories), `plan` and `render` (`src/inspect_ranges/_cli/plancmd.py:14`, `_load_or_exit`), and at eval time through `challenge_dataset`/`validate_challenges`.
- Probes:
  - `inspect-ranges validate <dir>` and `inspect-ranges plan <dir>`: full Python traceback ending `IsADirectoryError: [Errno 21] Is a directory`, exit 1.
  - `inspect-ranges validate <binary file>`: traceback ending `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd8 ...`.
  - Python API: `validate_challenges(Path(<dir>))` raises `IsADirectoryError` instead of returning a report.
- This is simultaneously a docstring contradicting behavior and a traceback where a diagnosis belongs; `validate` also takes `nargs=-1`, so one bad path in a multi-file invocation kills the whole run with a traceback instead of a per-file issue. Natural fix shape: catch `OSError`/`UnicodeDecodeError` in both validate functions into a positioned file-level `Issue` (both already do exactly this for `yaml.YAMLError`). I could not rule out that round 1 considered-and-declined this (unit decline lists are not in the repo), but it appears in no recorded residual.

### F2 (mechanical, docs claim vs behavior; moderate-low): networks.qmd annotates the attacker's allocated address wrongly

- `docs/networks.qmd`, "Addressing" section, YAML tab line 100: `attacker: interfaces: [{ network: lab }]  # allocated: 10.10.10.2`.
- Actual behavior: with no router on the segment the attacker takes the first usable address. Probe (`inspect-ranges plan` on that exact example): `attacker ... 10.10.10.1`. The code's own policy (`src/inspect_ranges/_compiler/allocate.py:5`) and the page's prose ("routers take the first usable addresses, the attacker follows") agree with .1; only the annotation claims .2 (true only when a router occupies .1, as in the later router examples where I probed attacker=.2). A user authoring ACLs, DNS records, or challenge fields against the annotated address targets the wrong guest. The YAML/Python parity test cannot catch comments.

### F3 (mechanical, docs/CI pin fidelity; low): two docs examples that refuse at planning are unmarked, and the harness's class check is one-way

- `tests/test_docs.py` runs `resolve_plan` only on blocks classed `.plan-invalid` ("classed blocks fail exactly as documented"); unmarked complete blocks are never planned. Probe over all unmarked blocks found two that refuse:
  - `docs/guests.qmd` block 0 ("hosts", line 26): `guest-config-not-realized` twice (hostname, fqdn). The surrounding prose does state the gate, so this one is only a missing CI pin.
  - `docs/networks.qmd` block 4 ("dns-ad", line 270): same two refusals. This section presents the Active Directory DNS pattern (`hostname: dc01`, `fqdn: dc01.corp.example`) with no gating note on the page; a first author copying it hits two planning refusals the page did not predict.
- Fix shape: mark both blocks `.plan-invalid` (and add the dns-ad gating note), and/or make the harness assert the inverse (unmarked complete blocks plan cleanly; planning with default options is image-cache independent, so this is stable in CI).

## Knob inventory (code vs docs)

Code and docs enumerate exactly the same knob set; no knob is documented but absent, none is absent but load-bearing. All defaults match.

| Knob | Defined | Documented | Default match |
|---|---|---|---|
| INSPECT_RANGES_EVIDENCE_SINK (unset) | `_evidence/location.py:17`, `_provider/evidence.py:34` | evidence.qmd | yes |
| INSPECT_RANGES_EVIDENCE_BUFFER_MB (64) | `_evidence/sink.py:47`, `_provider/evidence.py:80` | evidence.qmd | yes (64 MiB; admission charge join verified at `provider.py:195`) |
| INSPECT_RANGES_EVIDENCE_MAX_MB (4096) | `_provider/evidence.py:37` | evidence.qmd | yes |
| CAPTURE_CHUNK_MB / CAP_MB / MAX_RESTARTS / POLL_S (10/2048/5/0.5) | `_evidence/supervisor.py:47-50` (+ compose defaults `_compiler/render.py:137-139`) | evidence.qmd | yes |
| INSPECT_RANGES_POLL_S (10; 0 disables) | `_challenges/poller.py:31,35` | challenges.qmd | yes |
| INSPECT_RANGES_REGISTER_ALL_GUESTS (unset; 1/true/yes) | `_provider/provider.py:84` | provider.qmd, challenges.qmd | yes |
| INSPECT_RANGES_MAX_SANDBOXES (host-derived max(1, min(cpus/2, mem_gb/8))) | `_provider/admission.py:46,54` | provider.qmd | yes |
| INSPECT_RANGES_RETRY_EXEC/FILE/WAIT_INITIAL/WAIT_MAX/UP (3/5/1/10/2), RETRY_DISABLE | `_provider/retry.py:182-198` | provider.qmd | yes |
| INSPECT_RANGES_IMAGE_CACHE (~/.cache/inspect-ranges/images) | `_runtime/images.py:43` (single source, B17) | provider.qmd + CLI show_default | yes |
| INSPECT_RANGES_HOST (local) | `_provider/state.py:106`, `_doctor/checks.py:50` | topology.qmd | yes |
| INSPECT_RANGES_LEASE_TTL_S (600, renew TTL/3) | `_host/leases.py:38` | topology.qmd | yes |
| INSPECT_RANGES_HOST_CLASS (unspecified) | `_host/local.py:41` | topology.qmd | yes |
| XDG_STATE_HOME (~/.local/state) | `_runtime/ownership.py:39` | provider.qmd | yes |

Other documented constants verified against code: finalize budget 30 s (`_provider/evidence.py:40`, with the recorded A6 phase-split), manifest cadence 15 s / 256 (`_evidence/sink.py:50,53`), candidate cap 8 (`_challenges/scorer.py:39`), judge weight cap 25% (`_challenges/engine.py:64`), resource defaults 1 vCPU / 1024 MiB / 10 GiB (`_compiler/plan.py:370-372`), lease/applier errnos (EINVAL/EAGAIN/ENOSPC/EBUSY/ENOTSUP, `_host/applier.py`), gap-cause vocabulary (all seven doc examples exist in code), store keys `inspect_ranges:timings` and `inspect_ranges:evidence`, evidence location template, artifact cache path `~/.cache/inspect-ranges/artifacts` (confirmed live via doctor). The challenges.qmd goal-type table's field names match the schema exactly (all 13 Spec classes dumped and compared), and the custom-goal-type example matches the real `GoalType`/`register_goal_type`/oracle API signature for signature.

## CLI ergonomics probes (misleading-error sweep, all run)

Clean, correctly-attributed errors everywhere except F1: `up` on a missing/empty bundle refuses stage-named (`[verify-bundle] ... has no manifest.json`); `images derive` wrong digest refuses `[verify-vendor]` with both digests, missing artifact refuses `[resolve-daemon]` naming the exact republish command; `down` on a nonexistent project is a visible no-op (idempotency as documented); `evidence verify` on empty/missing locations prints `no manifests found` and exits 1 as documented, bogus scheme refuses cleanly; `applier` on an unbindable socket refuses with one line (B25 holds); `reaper` one-shot clean on clean state; `doctor` 22 ok / 4 warnings / exit 0 with warnings-not-failures exactly as cli.qmd claims; the docs' sample `validate` output reproduces byte-for-byte in format (positions, did-you-mean hint, cross-reference deferral note).

## Considered and declined

- README `pip install inspect-ranges` pre-publication: index.qmd states not-ready status; publishing is release work.
- `schema` and `devbox` commands absent from docs pages: discoverable via `--help`, developer-facing, not a load-bearing first-user workflow.
- `evidence verify --shallow` undocumented in evidence.qmd: help text covers it; the page documents the guarantee, not every flag.
- provider.qmd "leaks the applier's admission charge until the lease expires" (strictly: until the reaper sweeps the expired lease through the applier): pedantry; the reaper path is named two bullets away.
- MAX_SANDBOXES raising on malformed values while POLL_S falls back: a loud eval-start refusal is a defensible posture split from B20's mid-run-continuity rationale.
- cli.qmd "interrupted derives (self-healing on the next run)" vs `images list`'s "remove by hand" note: consistent on inspection (`images.py:308-311` sweeps same-name temps under the lock; the list note covers temps of names never re-derived).
- daemon-bundle building with no `go` on PATH: the pinned toolchain at `~/.local/go-toolchains` is the documented resolution; the refusal path names the pin when it is truly absent (`_channel/bundle.py:96-108`).
- Docs validate-output line numbers differing by one from my reproduction: illustrative block; format, codes, hints identical.
- Applier ENOENT bind message not naming the mkdir step: errno text is accurate, not misleading as to cause.
- POLL_S=0 disable semantics absent from challenges.qmd: minor omission, recorded in the poller docstring.
- evidence.qmd "finalize flush budget (30 seconds)" vs the A6 phase-split's bounded overshoot: the recorded A6 disposition; the doc's actual claim (teardown never hostage) holds.
- TamperGoal's `observer` field absent from the challenges table: the table documents proof contracts, not full field reference.
- up second-run refusal / console pulls / state-dir claims: concretely traced at `_runtime/up.py:417,519,558` rather than live-probed; booting ranges was out of scope.
- `sandbox(name)` single-environment semantic, retry contract, execution identity, cleanup semantics, isolation claim: verified as recorded design (round-1 territory); no drift found.

## Quality

The user surface is in genuinely good shape and visibly benefits from round 1: the four definition pages' examples are CI-pinned with YAML/Python parity, every environment table matches the defining constant, CLI errors are stage-named with copy-pasteable fix commands, and the round-1 ergonomics fixes (B17 image-cache centralization, B25 applier refusals, B18 recovery wording) all hold under probing. Nothing I found rises above mechanical: the one code defect is an unguarded file read behind an explicit never-raises promise (worth fixing because `validate` is the first command every external author runs, and it is the only place the CLI still shows a raw traceback), and the two docs defects are a wrong address annotation and a one-way CI pin that let two planning-gated examples drift unmarked. Finding little here is the expected round-2 result, and I am reporting it as such rather than inflating.
