# Spike battery: the era-class golden (build-v1 slice 3)

*Proves the second vendor class for `images derive`: **focal (20.04)**, which is what the example ranges actually demand (mhbench's `Ubuntu20` hosts, kypo's `ubuntu-focal-x86_64`). The derive pipeline needed zero code changes, and the derivation key's vendor digest keeps classes distinct in one cache by construction. This battery is the proof realizer-v1 decision 3 asked of every new distro ("further distros arrive when a range forces them, each behind the same battery"). Serializes on `/tmp/inspect-ranges-battery.lock`.*

*Why not older, measured (2026-10-17): **xenial (16.04) GA is physically impossible**: its kernel 4.4 has no virtio-vsock transport (`/lib/modules/4.4.0-210-generic/kernel/net/vmw_vsock/` carries only the VMware transport; virtio landed in 4.8), so the control daemon has no channel. **Bionic (18.04) is blocked twice**: its netplan rejects the `to: default` route syntax render emits (the keyword arrived in netplan 0.103; the fix is emitting `0.0.0.0/0`, a one-liner deferred until a range demands bionic because it changes rendered bundle bytes), and beyond that an unresolved boot divergence (forensic record below). Decision per the user (2026-10-17): old-image archaeology is not worth the disruption when no real range goes back that far.*

*What the focal decision does and does not cover for vulhub (recorded honestly): PHP 7.0 is the easy half (the ondrej PPA publishes php7.0 for focal). The hard half is **unmeasured until slice 6**: MySQL 5 has no focal-native packages (focal archives carry mysql 8 / mariadb 10.3, and Zabbix 3.0 predates MySQL 8 support), and repo.zabbix.com's 3.0 line ships trusty/xenial builds only. Slice 6's install path for those leans on the decision-3 fallback ladder in order: era archives where they exist, per-recipe vendored packages (MySQL 5.7 generic Linux tarballs are glibc-portable; zabbix 3.0 frontend is PHP source), and upstream-image extraction as the last resort. If none land, the class decision gets revisited with that measurement in hand.*

*Reproduce: `./run.sh` (needs the noble and focal vendor images at the default cache path or `NOBLE=`/`ERA=`, the pinned Go toolchain, `vhost_vsock`). `./run.sh down` tears down. 12/12 on first full run after the review round (the pre-review E7 miscounted timesyncd's ephemeral NTP client socket as a listener, then over-corrected to a privileged-ports-only filter the review caught as too loose).*

## Checks

1. **E1 focal derive**: `images derive` on the focal cloud image succeeds unchanged.
2. **E2a-c coexistence**: noble derives into the same cache; the two goldens carry distinct derivation keys; `images list` shows both.
3. **E3 refusal**: a wrong focal vendor digest refuses at `verify-vendor` before any cache write.
4. **E4 full path**: a focal range builds end to end via the build verb (render with network-config v2, cloud-init readiness, recipes).
5. **E5/E6 daemon and identities**: root exec answers on vsock; the agent user is baked.
6. **E7 posture, tight**: zero TCP listeners of any kind, and every UDP socket owned by systemd-timesyncd (its ephemeral NTP client socket is not a service); any LLMNR/mDNS/unprivileged-UDP service regression fails this check.
7. **E8 executor**: a slice-1 recipe ran against the era guest (`/opt/era-ok`).
8. **E9 identity**: the guest's os-release is 20.04.
9. **E10 ssh mask asserted**: `systemctl is-enabled ssh` reports masked (direct assertion, not inferred from the listener count).

## Bionic divergence: forensic record (2026-10-17, unresolved, preserved for whoever picks bionic up)

Symptoms on a bionic guest booted from a correctly-derived golden: the masked `ssh.service` started and listened; the enabled `vsockd.service` produced zero journal or syslog entries (never loaded, not failed); a later-planted `/etc/cron.d` probe never fired. Evidence trail, each step reproducible:

- `virt-ls -l` on the **golden**: `/etc/systemd/system/ssh.service -> /dev/null`, `ssh.socket -> /dev/null`, `vsockd.service` regular file 927 B, `multi-user.target.wants/vsockd.service -> /etc/systemd/system/vsockd.service`. All correct.
- `virt-ls -l` on the **live overlay** (copied out via `docker cp <range container>:/scratch/web.qcow2`, `qemu-img rebase -u -F qcow2 -b era-guest.qcow2`): identical, still correct at runtime.
- Persistent journal (golden given `/var/log/journal` via `virt-customize --mkdir`, journal copied out with `virt-copy-out`, read with `journalctl --file`): PID 1 dispatched the full multi-user batch (`Started OpenBSD Secure Shell server`, sshd listening on 22) with **zero mentions of vsockd** — not failed, not condition-skipped, never loaded.
- Guest syslog: `cloud-init-local` fails first (`/etc/netplan/50-cloud-init.yaml: unicast route must include both a 'to' and 'via' IP` — the known old-netplan `to: default` issue, independent of the unit divergence).
- Ruled out: systemd first-boot preset rewriting (no preset/firstboot console or journal lines); dynamic-linking of the daemon (`file`: statically linked); missing virtio-vsock modalias (`alias virtio:d00000013v* vmw_vsock_virtio_transport` present in bionic's modules.alias); wrong partition modified (virt tools and the booted guest agree on the single rootfs, and the files are visible in the live overlay).
- Not ruled out: something in bionic's boot path reading unit enablement from a state the offline edits don't reach. Three independent /etc changes (mask, wants link, cron.d) were all ignored at runtime while visible on disk, which points at the filesystem systemd/cron actually read, not at unit semantics.

## Files

- `run.sh` — the battery; CID band 3400, battery-isolated state and cache.
- `fixtures/erarange/` — one-guest focal range with a trivial recipe.
