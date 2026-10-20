# Spike battery: the `build` verb (build-v1 slice 2)

*Proves `inspect-ranges build` end to end: a bare invocation from inside a range directory boots the egress build plan (isolated networks flipped to NAT-with-allowlist plus an external resolver, uplinked onto a docker network the verb ensures exists), runs `provisioning` recipes in declaration order against the live guests, and tears down on success and failure, with builds as ordinary `ir-` projects whose crash cleanup is the realizer's. Serializes on `/tmp/inspect-ranges-battery.lock`.*

*Reproduce: `./run.sh` (needs the noble vendor image at the default cache path or `VENDOR=`, the pinned Go toolchain, `vhost_vsock`, and outbound internet for the egress check). `./run.sh down` tears down. Logs land under `tmp/`. 9/9 on first full run.*

## Checks

1. **C1 bare build**: `inspect-ranges build --keep` run from the range directory (the `.` default) exits 0 with `build OK` and stage-prefixed output.
2. **C2 declaration order**: two steps of the same recipe with different vars appended `first` then `second` to `/opt/build-order`, read back from the live guest.
3. **C3 build-time egress**: a recipe resolved and connected to `archive.ubuntu.com:80` from inside the guest (DNS via the injected build nameserver, outbound TCP via the NAT build plan).
4. **C4 duplicate refusal**: a second concurrent build of the same range refuses, naming the running project.
5. **C5 failing recipe**: `bc.fail` (exit 3) fails the build with `build FAILED` naming guest `web`, the recipe, and the log path.
6. **C6/C6b teardown and stage log**: the failed build leaves zero `ir-` containers, and its `stages.jsonl` records the recipe failure.
7. **C7 kill -9 during boot**: SIGKILLing the build mid-boot then `down --all` leaves zero `ir-` containers.
8. **C8 kill -9 during a recipe**: SIGKILLing mid-provision (a 300 s sleeping recipe) then `down --all` leaves zero `ir-` containers.

## Files

- `run.sh` — the battery; cold-starts its own daemon bundle and golden (`build-guest`), CID band 3300.
- `fixtures/buildrange/` — the happy-path range (ordered steps + egress proof) with its `./recipes/`.
- `fixtures/failrange/` — the nonzero-exit recipe range.
- `fixtures/slowrange/` — the 300 s recipe for the mid-provision kill.
