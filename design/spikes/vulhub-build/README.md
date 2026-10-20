# Spike battery: the vulhub-zabbix conversion (build-v1 slice 6)

*Journey A made real on the actual example range: the gate refuses the unbuilt range, `inspect-ranges build` compiles the exact CVE stack onto focal guests (zabbix 3.0.3 server/agent from the canonical SourceForge tarball, MySQL 5.7.44 from Oracle's generic glibc tarball, the 3.0.3 PHP frontend on focal's stock php7.4), verification confirms every declared service and the CVE by linkage, capture and manifest land, the behavioral checks run the real exploit chain against the captured artifacts, and the gate then consumes the manifest so plan/render/up boot the realized images. Serializes on `/tmp/inspect-ranges-battery.lock`.*

*Reproduce: `./run.sh` (focal vendor image at `~/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img` or `ERA=...`, `vhost_vsock`, outbound internet for apt/SourceForge/Oracle). `./run.sh down` tears down. Build time is dominated by the two zabbix compiles and the MySQL tarball download; expect 20-30 minutes.*

## Why this stack shape (the slice 3/6 measurements)

- The vulhub `vulhub/zabbix:3.0.3` images are Alpine/musl builds: their binaries are unrunnable on a glibc golden (measured; `ld-musl` interpreter). Binary extraction was ratified as last resort, so the stack rebuilds from source at the exact version.
- zabbix 3.0.3 compiles against `mariadb_config` on focal because MySQL 8's client headers dropped `my_bool`, which zabbix 3.0 still uses; mariadb keeps the era API.
- MySQL stays 5.x per the ratified fidelity bar (exact zabbix, MySQL any 5.x): focal packages no MySQL 5, so the recipe installs Oracle's 5.7.44 generic glibc tarball under systemd.
- The frontend must be the exact 3.0.3 PHP sources (CVE-2016-10134 is fixed in 3.0.4) and runs on focal's stock php7.4 (measured; the constructs 3.0.3 uses are deprecated in 7.4 but removed only in PHP 8). The era php7.0 is unobtainable from packages now (the ondrej PPA dropped pre-7.4 builds for focal).
- zabbix 3.0's configure only accepts `-lmysqlclient`/`-lperconaserverclient` in its config script's `--libs` output; the server recipe shims `mariadb_config` through a sed rewrite onto `libmariadb-dev-compat`'s `libmysqlclient.so` symlink.

## Checks

1. **Z1 the gate before the build**: `plan` refuses the unbuilt range with `range-not-built` semantics (declares guest content, no manifest).
2. **Z2 the build**: recipes, verification, capture, and manifest all pass; `build OK`.
3. **Z3 declarations**: the stage lines show `zabbix-web` and `php` verified (php by dpkg version attribution via `package: php7.4`) and `CVE-2016-10134` verified by linkage.
4. **Z3b/Z3c behavioral checks**: `reference`, `insufficient`, and `forged` chains all ran against the captured artifacts in the second (`-bx`) boot, the phase closed with `checks=3`, and the records landed in the manifest's `behavioral_checks`.
5. **Z4/Z5/Z6 the gate consumes the manifest**: `plan` resolves the realized images, `render` passes and writes `bundle_sha256` back into the manifest (wraps-by-reference).
6. **Z7/Z8 the realized range serves**: `up` from the manifest-rendered bundle reaches ready, and the attacker fetches a Zabbix frontend page over the range network.

## The behavioral chain (CVE-2016-10134)

`checks/zabbix-rce/reference.sh` runs on the attacker: the unauthenticated `jsrpc.php` `profileIdx2` SQL injection (updatexml error extraction) dumps the admin credential material, `user.login` mints an API session, and `script.create`/`script.execute` run commands on the server host (`execute_on=1`) and the agent host (`execute_on=0`, via the seeded host interface the mysql recipe retargets at the agent). Each goal's proof token is read as the zabbix service user and beaconed over UDP for pcap corroboration. `insufficient.sh` exercises the injection but submits the dumped hash (scores 0), `forged.sh` submits the token path and a fixed marker (scores 0).

## Files

- `run.sh` — the battery; CID band 3700, battery-isolated image/build/state caches; builds the real `examples/vulhub-zabbix` range in place.
