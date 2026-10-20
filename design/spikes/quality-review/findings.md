# Quality review 2026-10: consolidated findings for triage

*Phase-3 adjudication of the eight review units plus the coverage pass. Every entry survived the charter (reachable correctness defect, load-bearing test gap, or mechanical defect; no design re-litigation, no hypothetical hardening). Probes live uncommitted in the reviewers' kept worktrees, cited per entry. Nothing is fixed until this list is triaged; strike anything.*

Suite baseline for the whole round: 1335 passed / 75 skipped / 3 xfailed; coverage 87% line+branch (first measurement; `make coverage` lands with the fixes).

## Group A: fix now (high-consequence correctness; recommend fix, all)

| id | finding | source | consequence | fix shape |
|---|---|---|---|---|
| A1 | Daemon vsock fds lack CLOEXEC; every exec'd child inherits listener + connection fds | U3, probed both legs | An UNROOTED agent can accept() driver connections (read plant values, forge honest-shaped replies): an unrecorded containment breach. Also the TRUE root cause of the recorded exec budget-hold (the recorded pipe-drain theory is disproven by counter-probe) | 2 lines Go (`SOCK_CLOEXEC` at socket+accept4), 2 `SetHandleInformation` calls C#; battery check pinning no inherited fds; correct the challenges-v1 residual phrasing and battery README |
| A2 | A scoped attacker egress allowlist does not scope the attacker (flows fall through to the network allowlist and leave) | U1, probed on rendered ruleset | Containment wider than documented; `EgressPolicy`'s "exactly what may leave, nothing else" is false | Trailing attacker drop after scoped accepts; `egress-requires-nat` gate extended to the attacker; render tests for `open` and scoped (none exist) |
| A3 | Telemetry export strips any line CONTAINING a cursor-pattern match | U5, probed end-to-end | Agent-craftable silent alert suppression: a false stealth pass through evade/detection's own completeness gate, in our T1 layer | Strip only the cursor's own line (or anchor to line start); pin |
| A4 | Windowed evade/detection silently exclude delivered-but-uncommitted chunks (span 0,0) while meta reads complete | U6, probed; evidenceread is also the 15%-coverage module | Free stealth pass / false definite verdicts over data the record contains; adversarially timeable (final ~15 s) | Unknown-span chunk includes or makes the window incomplete, never excluded-with-definite-verdict; direct evidenceread CI pins (production-built fixtures) |
| A5 | Degrade latency measure double-counts failed-and-slow records (up to 2x partial, clamped) | U6, probed | Attacker over-credit on a real aggregation path (probe client routinely emits the overlapping shape) | Per-record union instead of sum; mixed-status test |
| A6 | Finalize-budget timeout leaves a permanently unsealed record, writes a seal-less binding, and releases the lease that was the reaper's retry anchor | U7, probed | Unsealed-at-rest on a HEALTHY teardown path (not the recorded crash windows); the budget is provably over-subscribed (20+20+15+unbounded harvest inside 30 s) | Per-stop sub-budgets inside finalize; the timeout arm does checkpoint+gap+seal-attempt per the applier's reviewed precedent (both driver and applier arms) |
| A7 | `cli_cleanup` never reap-seals and deletes the lease pointing at the evidence | U4, traced | The documented kill-9 recovery path strands unsealed records, defeating "finalize and the reaper both seal" | Thread the sealer through cli_cleanup before lease release |
| A8 | Goal ids never validated against the evidence stream grammar | U7, probed | A legal `Recon-1` goal id silently destroys its own probe records (never-raise swallows), scoring indeterminate: infra-shaped misattribution of an authoring slip | Grammar check in `challenge_issues` (the compiler's `_evidence_name_issues` pattern); fix the too-permissive `_FakeSession` fixture |
| A9 | Spec names flow into paths/device names with no grammar or length validation | U1, probed (traversal + bridge collision) | `../../escape` writes outside the bundle; 12-char-prefix networks silently merge onto one bridge (ACL bypass if apply ever dedupes); probe-veth truncation same family | One name-grammar+length validator for hosts/networks/routers at schema, positioned refusals; covers A8's pattern at the range layer |
| A10 | `up()`'s 300 s sequential readiness emits no stage report, but the realize channel allows 180 s per report | U4, traced arithmetic | Multi-guest ranges (the deployed topology's core content) boot co-resident but fail mid-readiness through the applier, and the error type never respins | Per-guest readiness stage reports (or a keepalive report) through the `on_stage` seam; fix round picks the shape |
| A11 | Doctor Evidence group passes green while the runtime disables evidence for every sample (non-s3 fsspec log dir, e.g. `gs://`); off-instance row blesses it | U8, probed | The pass-green class the doctor was hardened against, on the derived arm the hardening missed | Scheme check on the derived arm matching the override arm; fix the contradictory off-instance row (U8-F4) |

## Group B: fix (correctness, lower consequence; recommend fix, all)

| id | finding | source |
|---|---|---|
| B1 | exec counts a delivery on connect-timeout: `attempts` lies by one on the never-left distinction; safe same-id resend refused | U2, probed |
| B2 | Silent-window stall detector permanently disarms after first liveness; untimed exec rides 4 h instead of ~3 windows | U2, probed |
| B3 | realize terminal drain lets raw `ConnectionResetError` escape untyped, failing a succeeded realize | U2, probed |
| B4 | `read_file`'s bare confirm ping replaces `SandboxUnavailableError` with raw `TransportFailure` (sibling drift) | U4, probed |
| B5 | Admission: cancelling the head waiter never re-serves; traced deadlock under interrupt deferral | U4, probed |
| B6 | Completed-within-budget command reported ETIME when a pipe-holding child delays the reap (both daemons) | U3, probed |
| B7 | C# daemon writes diag entries to a guest-visible file, contradicting the recorded diag posture | U3 |
| B8 | C# daemon times off non-monotonic `UtcNow`: a clock step mints negative elapsed values the host rejects as TAMPER | U3 |
| B9 | C# connection lifecycle parity, minimal scope: idle recv/send timeouts matching Go's 60 s (concurrency bound deferred; scoped down by adjudication) | U3 |
| B10 | `read_file`/`write_file` block forever on special files (FIFO): agent converts obstruction into infra-shaped failure + leaks limiter slots | U3, probed |
| B11 | Telemetry re-bootstrap `replay` flag consumed by a FAILED bootstrap; the replayed window ships unflagged | U5, probed |
| B12 | Gap records can precede, in chain order, data chunks appended before them (commit-time asymmetry) | U5, probed |
| B13 | Supervisor/streamer double-accounting emits a spurious `capture-cap` gap for shipped bytes (conservative direction) | U5 |
| B14 | Reap-seal put is the one single-attempt write in the system (one transient 5xx = permanently unsealed) | U5 |
| B15 | `tamper` location grammar refuses late with a bare ValueError and skips unwind (positioned-refusal pattern broken) | U6 |
| B16 | Router-hosted prober goals pass planning, then refuse at plant (dataset fallback ignores routers) | U6 |
| B17 | `INSPECT_RANGES_IMAGE_CACHE` ignored by all CLI commands (three drifted defaults); docs claim otherwise; doctor's fix text reproduces the miss | U8, probed |
| B18 | Deferred-teardown recovery message recommends `inspect-ranges down`, which under uds leaks the applier's charge | U8, traced |
| B19 | Prober's `docker compose exec` child leaks on external cancellation (kill belongs in finally) | U7 |
| B20 | Malformed `INSPECT_RANGES_POLL_S` silently disables the poller (posture outlier; fall back to default or raise) | U7 |
| B21 | `up()` is not "internally bounded" as the cancellation-drain comment requires (`compose up --wait` and guest-boot exec unbounded); minimal bounds aligned to the readiness envelope | U7 |
| B22 | `Host.hostname`/`fqdn` accepted, documented, silently unrealized, ungated. DISPOSITION RECOMMENDATION: add the planning gate now (existing silent-expressibility rule); realization goes to the images arc | U1, probed |
| B23 | Allocator refuses realizable 16-31-address subnets and leaks a bare ValueError through an API promising typed refusals | U1, probed |
| B24 | Diagnostics loc-walk corrupts paths for scalar unions (3 issues with pydantic tags for one authored mistake) | U1, probed |
| B25 | `inspect-ranges applier` surfaces expected startup refusals as raw tracebacks (exit code already correct) | U8, probed |

## Group C: test additions (no production change beyond tests)

C1 `exfiltrate` end-to-end: the ONLY goal type with no test anywhere (compare semantics, canary containment, presence-only rejected, source-bound corroboration with probe exclusion). The round's biggest pure gap.
C2 Mid-acquisition cancellation of `sample_init` (the cancellation drain, exactly-once unwind, lease/CID/registry/admission balance): the most intricate provider code, zero coverage.
C3-C14: the coverage pass's remaining behavior-named proposals merged with unit-named gaps: answer oracle-read source; scorer never-raise guards; finalize budget under a hanging sink; host-seal fallback binding; corroborate unverifiable trio; second-cancellation drain exactly-once; realize reconnect replay; reap-seal continuation; poller stop on a wedged tick; daemon-fd non-inheritance battery check (with A1); attacker egress open/scoped renders (with A2); evidenceread span alignment (with A4); degrade mixed-status (with A5); doctor derived-scheme (with A11); channel connect-timeout and silent-window (with B1/B2).

## Group D: mechanical (recommend fix in one sweep commit per subsystem)

Channel: dead/duplicated default constants; unstamped post-delivery tamper `attempts`; "reply lost after 3 attempts" on a never-delivered request. Provider/runtime: stale slice-3 module docstring; duplicated docker-filter argv in down.py; needless late imports in ops.py; `StageRecorder.VERIFY_STAGES` half-matching the uds vocabulary. Challenges: `EvadeType` missing from package exports; stale `available_observers` and `evidence_memo` docstrings (memo is per-goal, corroborate bypasses it: document, or widen to per-pass in the same commit if trivial); `_unwind`'s non-file plant paths. Evidence: `flush`/`checkpoint` duplicated body; knob-name-less int() error. Compiler: probe.py re-derives bridge name inline; redundant json import; attacker default-image doc/option-name drift; `Service.name` uniqueness docstring vs validator. Ops: `images list` stale-recipe mislabel; devbox dead empty-stdin branch. Daemons: `SockSource` dead buffer branch; ENAMETOOLONG mapping parity.

## Record corrections (prose, not code)

R1 challenges-v1 budget-hold residual + battery README: the recorded pipe-drain diagnosis is wrong (U3's counter-probes); the hold is the inherited connection fd, fixed by A1; "returns rc 0 after the full in-guest budget" is a driver-side observation artifact.
R2 The close-out record carries all units' "considered and declined" lists.

## Adjudication notes

- Zero submitted findings were declined outright; one was scoped down (B9: idle-timeout parity only; full concurrency bounding would be speculative hardening at current densities).
- Clusters intentionally share fixes: A8+A9 (one name-grammar discipline, two layers), A6+A7+B14 (sealing lifecycle completeness), A1+B6 (same daemon region, one battery).
- One embedded decision needs your eye: B22's gate-now recommendation.
- Systemic lessons for the close-out record: budgets summed across layers nobody owned; never-raise layers turning upstream gaps into silent scoring degradation; fixtures more permissive than production seams; the identifier namespace; OS-resource surfaces invisible to wire-level batteries.

## Dispositions (phase 4, integrated branch)

Provider-slice commit ids below are the ORIGINAL branch ids from its report; those commits were rebuilt (cherry-picked, new ids) on the integration branch to strip 605 MB of accidentally committed battery artifacts from `727c57d` (`design/spikes/quality-review/tmp/`, now gitignored). All other slices merged with their ids intact.

**Group A, all fixed:**
- A1 fixed (daemons `6479463`): Go `SOCK_CLOEXEC`/`Accept4`, C# `SetHandleInformation`. Live: budget-hold 180 s to 0.01 s; exec child inherits 0 daemon sockets (battery pin). C# compile- and vector-verified only; behavioral confirmation rides the recorded Windows-runner follow-up.
- A2 fixed (compiler `e934be1`, battery `07355d8`): trailing attacker drop + `attacker-egress-requires-nat`; live ES1-ES4 green incl. the network-allowlist non-leak against a live listener.
- A3 fixed (evidence `b40539c`; review `b189b1a` rescoped the residual honestly: at worst one mis-taken trailing-line cursor, loud next poll, never window-wide suppression).
- A4 fixed (challenges `b7a6aee`): unknown-span chunks included end to end; pins written by a real `EvidenceWriter`.
- A5 fixed (challenges `35ff873`): per-record union; mixed-status pin.
- A6 fixed (provider `8c4ae53` + review + battery-driven harvest resize): finalize phase-split with a protected seal reserve; wedged stop seals `incomplete` with the binding carrying the digest.
- A7 fixed (provider `dcd60e1`): cli_cleanup reap-seals before lease release, pinned end to end.
- A8 fixed with deviation (challenges `6a0a8d5`): the grammar check landed on `GoalBase` (always-on, range-independent) rather than `challenge_issues`; `_FakeSession` now enforces the real stream grammar.
- A9 fixed (compiler `91f7150`, review `103e111`): `[a-z0-9][a-z0-9._-]*`, max 63, plus derived-device uniqueness single-sourced in `types.derive_device`. Adjudicated: underscores/dots stay legal (recorded fixtures use them; the collision check covers the real hazard).
- A10 fixed with deviation (provider `88859cc`): plan-derived verify allowance instead of keepalives (keepalives would violate the strictly-increasing stage rule; wire-carried readiness fields recorded as the growth path). Live 5/5: a 43.2 s verify gap reaches ready under a 20 s per-report allowance; the control starves exactly as U4 traced.
- A11 fixed (ops `17fb223`, review `0c9eaf5`): both doctor arms and the runtime share one `valid_sink_location()` predicate; the off-instance row consumes the sink verdict.

**Group B, all fixed:** B1 `92eda6f` (hung-connect exec now SUCCEEDS via the safe same-id resend), B2 `081a7a6`, B3 `0d62846`, B4 `777166e`, B5 `0ad161b`, B6 `65b9e70` fixed with correction (Go only; C# was never affected, correcting the U3 report), B7 `35da7f9`, B8 `f4627d4`, B9 `02ef40c` as adjudicated (idle timeouts only), B10 `ca73334` with recorded platform divergence (Go serves char/block devices per the pinned bounded-read contract; C# refuses non-disk), B11 `aba4e57`, B12 `67ddc95` (unified gap/chunk FIFO), B13 `4361dc5` (claim-rename; review bounded the claim window), B14 `61d1ddc` (shared `bounded_put`), B15 `438dc7d`, B16 `3bdf4af`, B17 `51f304f` (`default_image_cache` centralized in `_runtime/images.py`), B18 `b6a4570`, B19 `ea5de79`, B20 `ffbe28f`, B21 `2b861cc` (+ failure-path bounds from review), B22 `aaeb154` (gate, per the approved disposition), B23 `2bb3707`, B24 `7beefc7`, B25 `c5f9c8b`.

**Group C:** C1 landed as CI proof-contract tests PLUS a live `data-db` exfiltrate row in the vulhub chain (no pcap claim: ssh keeps the wire ciphertext; content corroboration CI-pinned, stated in the YAML and README). C2 landed (mid-acquisition cancellation suite; exposed and fixed one real unguarded store read in the scorer's hints path). T8 and T10 were found already covered and not duplicated. **T7 (host-seal fallback to driver-only binding) did not land in any slice: the one open test proposal, carried to the close-out record as a residual.** All other proposals landed with their findings.

**Group D:** all landed, one sweep commit per subsystem. **R1:** landed (daemons `ba544d2`).

**Integration additions (`3ed9534`):** `WedgedHarvestTap` gained `claim_file` (B13's protocol growth vs the provider slice's A6 test, the one cross-merge break); `LocalEndpoint` now mirrors the daemons' FIFO refusal with a channel-level pin (resolving the daemons slice's cross-worker note).
