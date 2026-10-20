# Spike battery: cat-publish (standard images v1, slice 2)

*The promotion act, live: the attack factory builds, `publish --guest box --as attack` promotes the realized image to the bare catalog name at a live `registry:2` (and `publish --golden` promotes the noble golden under its own name), a consumer machine runs `images pull attack` and lands `attack.qcow2` with its whole chain and provenance, a range declaring `image: attack` as its ATTACKER renders by bare name and boots with the toolset verifiably aboard, whole-location `mirror` enumerates via the published catalog artifact (the hub-shaped path, no `_catalog` needed), and the Q11 fleet pin file refuses a catalog that moved past the pinned state. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4070; registry port 5064.*

*Reproduce: `./run.sh` (noble vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## Checks

1. **P1** the factory builds; `publish` promotes the realized image to `attack` and the golden under its own name, both updating the catalog list.
2. **P2** `images pull attack` lands the renamed cache file with chain and provenance; a consumer range resolves the BARE NAME as its attacker, boots it (chain verified at `up`), and the booted box is verifiably the attack image (msf present, the recorded package manifest aboard).
3. **P3** whole-location mirror enumerates both names via the catalog artifact; `images pin` writes the fleet pin file; a pinned host refuses `pin-mismatch` when the publisher moves the catalog.

## Files

- `run.sh`: factory build, publish, consumer pull-and-boot, catalog mirror, pin legs under the battery lock.
