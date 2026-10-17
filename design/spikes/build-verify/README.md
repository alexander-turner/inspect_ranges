# Spike battery: the verification engine (build-v1 slice 4)

*Proves `services`/`vulnerabilities` assertions verified against the live, provisioned range: whole-range, after all recipes, independent of recipe claims. The mechanical contract: a service verifies on its listening port and (when declared) its version, with version attribution through the explicit `Service.package` field, then the listener-process chain (port, pid, exe, owning dpkg), then a dpkg named exactly like the service; a vulnerability verifies iff its linked service verifies (exploitability proof is challenge behavioral-check territory). Failures are the Journey A shape: `[service-not-verified]` / `[vulnerability-not-verified]` with the declared-vs-observed delta and the per-guest probe log path. Serializes on `/tmp/inspect-ranges-battery.lock`.*

*The fixtures install real packages (nginx from the focal archives) through build-time egress, so the battery also exercises the slice-2 egress plan and settle gate end to end. Reproduce: `./run.sh` (needs the focal vendor image, the pinned Go toolchain, `vhost_vsock`, outbound internet). `./run.sh down` tears down. 8/8 on first full run.*

## Checks

1. **V1 all-green**: a recipe-installed nginx declared `{port: 80, version: "1.18", package: nginx-core}` plus a linked vulnerability passes verification and the build.
2. **V2 per-declaration output**: the build prints an ok line per declaration (service and vulnerability).
3. **V3 stage log**: `stages.jsonl` carries one `verify` record per declaration plus the `verified` summary.
4. **V4 wrong version fails the build**: declaring `1.19` against installed 1.18.x fails at stage `verify` (the Journey A scenario).
5. **V5 refusal shape**: the failure names the code, guest, declared-vs-observed versions, and the probe log path.
6. **V6 dead service**: a declared-but-never-installed service fails on listening (`no tcp/udp socket on port 6379`).
7. **V7 linkage**: the vulnerability linked to the dead service fails with `vulnerability-not-verified`.
8. **V8 teardown**: a verification failure tears the range down (zero `ir-` containers).

## Files

- `run.sh` — the battery; CID band 3500, battery-isolated state and cache, focal golden derived in-run.
- `fixtures/okrange/`, `fixtures/wrongversion/` — nginx recipe ranges (green and Journey A wrong-version).
- `fixtures/deadservice/` — no recipes; a service and linked vulnerability that cannot verify.
