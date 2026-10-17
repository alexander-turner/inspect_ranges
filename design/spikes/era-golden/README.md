# Spike battery: the era-class golden (build-v1 slice 3)

*Proves the second vendor class for `images derive`: **focal (20.04)**, which is what the example ranges actually demand (mhbench's `Ubuntu20` hosts, kypo's `ubuntu-focal-x86_64`). The derive pipeline needed zero code changes, and the derivation key's vendor digest keeps classes distinct in one cache by construction. This battery is the proof realizer-v1 decision 3 asked of every new distro ("further distros arrive when a range forces them, each behind the same battery"). Serializes on `/tmp/inspect-ranges-battery.lock`.*

*Why not older, measured (2026-10-17): **xenial (16.04) GA is physically impossible**: its kernel 4.4 has no virtio-vsock transport (`/lib/modules/4.4.0-210-generic/kernel/net/vmw_vsock/` carries only the VMware transport; virtio landed in 4.8), so the control daemon has no channel. **Bionic (18.04) is blocked twice**: its netplan rejects the `to: default` route syntax render emits (the keyword arrived in netplan 0.103; the fix is emitting `0.0.0.0/0`, a one-liner deferred until a range demands bionic because it changes rendered bundle bytes), and beyond that its boot exhibited an unresolved divergence where systemd ignored the golden's `/etc` modifications (masked ssh started; the enabled vsockd unit was never loaded; a planted cron.d probe never fired) despite three independent offline inspections showing the files correct on disk. Decision per the user (2026-10-17): old-image archaeology is not worth the disruption when no real range goes back that far; vulhub's PHP 7.0-era userland is reachable on focal via the ondrej PPA at build time under the ratified era-archives pattern.*

*Reproduce: `./run.sh` (needs the noble and focal vendor images at the default cache path or `NOBLE=`/`ERA=`, the pinned Go toolchain, `vhost_vsock`). `./run.sh down` tears down. 11/11 on first full run after the E7 check fix (10/11 before it: the original check miscounted timesyncd's ephemeral NTP client socket as a listener).*

## Checks

1. **E1 focal derive**: `images derive` on the focal cloud image succeeds unchanged.
2. **E2a-c coexistence**: noble derives into the same cache; the two goldens carry distinct derivation keys; `images list` shows both.
3. **E3 refusal**: a wrong focal vendor digest refuses at `verify-vendor` before any cache write.
4. **E4 full path**: a focal range builds end to end via the build verb (render with network-config v2, cloud-init readiness, recipes).
5. **E5/E6 daemon and identities**: root exec answers on vsock; the agent user is baked.
6. **E7 posture**: zero TCP listeners (the ssh mask holds on focal) and zero privileged-port sockets (the resolved stub drop-in holds); ephemeral client sockets are not services.
7. **E8 executor**: a slice-1 recipe ran against the era guest (`/opt/era-ok`).
8. **E9 identity**: the guest's os-release is 20.04.

## Files

- `run.sh` — the battery; CID band 3400, battery-isolated state and cache.
- `fixtures/erarange/` — one-guest focal range with a trivial recipe.
