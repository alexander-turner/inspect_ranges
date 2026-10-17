# Spike battery: recipe bundles and the executor (build-v1 slice 1)

*Proves the recipe-references bundle contract as implemented in `inspect_ranges._build`: resolution (range dir, then cache), deterministic bundle digesting, vars validation against declared inputs, and host-side execution of online recipes against a live guest through the `IR_*` contract (`IR_GUEST`, `IR_GUEST_CIDS`, `IR_EXEC`, `IR_PUSH`, `IR_EXEC_BUDGET_MS`). Serializes on `/tmp/inspect-ranges-battery.lock`.*

*Reproduce: `./run.sh` (needs the noble vendor image at the default cache path or `VENDOR=`, the pinned Go toolchain for `daemon-bundle`, and `vhost_vsock`); `SKIP_VM=1 ./run.sh` runs the four host-only checks. `./run.sh down` tears down. Logs land under `tmp/`. 11/11 on first full run.*

## Checks

1. **B1 digest**: a bundle digests identically twice and across an identical rebuild in another directory; a content change changes the digest.
2. **B2 unresolved**: a reference that resolves neither in the range nor the cache refuses with `recipe-not-resolved` (the `image-not-in-cache` shape).
3. **B3 vars**: an unknown var and a missing required input are collected into one `IssueError` (`recipe-var-unknown`, `recipe-var-missing`).
4. **B4 offline**: `mode: offline` is typed-refused (`recipe-mode-unsupported`) before any execution.
5. **B5 success**: `bv1.ok` runs end to end; the stage log records `start` then `ok`; the run log exists.
6. **B6/B7 push**: the recipe's `IR_PUSH` landed `/etc/recipe.conf` with vars rendered (`marker=zig`, default `verbose=false`) at mode 600.
7. **B8 exec**: the recipe's root `IR_EXEC` created `/opt/recipe-made`.
8. **B9 nonzero exit**: `bv1.fail` produces a `RecipeError` at stage `run` naming `exited 3`, with stderr captured in the run log.
9. **B10 budget**: `bv1.slow` (a sleeping child in the group) is killed as a process group within seconds of the 2 s budget.
10. **B11 background children**: an in-guest exec launching a `setsid` child with redirected fds returns promptly instead of holding its 8 s budget (the challenges-v1 CLOEXEC lesson, pinned).

## Files

- `run.sh` — the battery; cold-starts its own daemon bundle, golden (`build-guest`), render, and `up` under battery-isolated state.
- `battery.py` — driver exercising the public `_build` surface, one check per invocation.
- `spec.yaml` — minimal single-guest range the live checks run against (CID band 3100).
- `fixtures/recipes/` — the five fixture bundles (`bv1.ok`, `bv1.fail`, `bv1.slow`, `bv1.bg`, `bv1.offline`).
