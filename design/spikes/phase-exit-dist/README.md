# Phase exit: distribution v1 (the Journey B transcripts, verbatim)

*The exit criterion from [distribution-v1.md](../../inspect-ranges/distribution-v1.md): the [Journey B transcripts](../../inspect-ranges/build-images-journey-b.md) execute command for command on the real vulhub-zabbix range, with the ratified substitution that the public org's role is played by local registries (canonical publishes land on catalog-phase publish day). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4050; registries 5062 (ours) / 5063 (the other group's).*

*Reproduce: `./run.sh` (focal vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## The sessions, as checks

1. **X0** the builder's Journey A tail: vulhub builds green.
2. **X1** *Publishing*: `push` prints the transcript's shape (the `manifest` line with the spec hash, `push OK <name>@<digest>`).
3. **X2** *Consuming, connected*: a consumer with fresh empty caches runs explicit `pull` (resolve + verified fetch), then a REAL `inspect eval` solves the pulled range (the build-v1 journey eval: reference chain through the foothold, 1.0/valid with corroborated beacons): nothing was built, derived, or hand-pinned on that side. **X2c** the semantically edited spec refuses `no-build-for-spec` naming the nearest published build, in the transcript's house style.
4. **X3** *Mirroring*: the whole-location mirror seeds `./ranges-archive`, which tars for the sneakernet.
5. **X4** *Consuming a range built by another group*: the spec-driven `mirror . --from theirs --to ours` resolves the exact source build with the dedup accounting visible. One deliberate adaptation from the transcript, recorded: the transcript's bare `mirror --from --to` means spec-driven when run inside a range directory and whole-location otherwise, which is cwd-dependent dispatch; under the round-3/round-5 cwd-independence rule, bare `mirror` is ALWAYS the whole-location seed and the in-range-directory move is the explicit `mirror .` (the `.` default convention every other verb uses).
6. **X5** *Consuming, disconnected*: the shipped archive untars elsewhere and, configured as the registry, serves a byte-identical spec-driven pull.
