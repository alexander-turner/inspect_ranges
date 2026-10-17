# Spike battery: the build manifest, capture, and invalidation (build-v1 slice 5)

*Proves the slice-5 contract end to end on live focal guests: a build captures each provisioned guest's overlay as a realized image (clean `systemctl poweroff`, `virsh domstate` wait, overlay copied out and rebased onto its golden, digested, cached with a `.realized.json` sidecar) and writes the range build manifest (identity, per-guest build keys and realized digests, recipe triples with vars hashes, verification results, never secrets) atomically into the builds cache. Invalidation follows the spine's two-key algebra per guest: a recipe/vars edit rebuilds exactly that guest while unchanged guests boot from their realized images with recipes skipped, a full-key no-op is the cached fast path (nothing boots; the recorded verification is reported with its timestamp), and `--reverify` forces the full pass. The headline live proof is M5: nginx verifies on the REUSED guest, demonstrating that captured content survives capture and reboot. Serializes on `/tmp/inspect-ranges-battery.lock`.*

*`--keep` builds are diagnostic: they capture nothing and mint no manifest (the kept range runs from its build overlays). Reproduce: `./run.sh` (focal vendor image, pinned Go toolchain, `vhost_vsock`, outbound internet for apt). `./run.sh down` tears down. 9/9 on first full run.*

## Checks

1. **M1 first build**: passes and prints its manifest path.
2. **M2 manifest integrity**: both guests recorded; every realized image exists in the image cache, its sha256 matches the manifest, and its provenance sidecar is present.
3. **M3/M4 incremental**: editing db's recipe vars rebuilds only db; web's nginx recipe logs `skipped=unchanged` and web boots from its realized image.
4. **M5/M5b the live reuse proof**: full verification passes on the reused web (nginx serving from the captured disk after reboot), and db's edited recipe actually re-ran.
5. **M6 cached fast path**: an unchanged rebuild reports `build OK (cached, verified <ts>)` in seconds, booting nothing.
6. **M7 --reverify**: boots and fully re-verifies despite matching keys (recipes still skipped; nothing recaptured).
7. **M8 stale bundle**: a bundle rendered before the cache's image changed refuses at `up` naming the cause and the fix (re-render).

## Files

- `run.sh` — the battery; CID band 3600, battery-isolated image/build/state caches; builds from a scratch copy of the fixture (the edit check mutates it).
- `fixtures/incr/` — two provisioned hosts (nginx, marker) for incremental substance.
- `fixtures/plain/` — content-free range for the stale-bundle check.
