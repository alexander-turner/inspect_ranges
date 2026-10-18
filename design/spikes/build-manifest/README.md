# Spike battery: the build manifest, capture, and invalidation (build-v1 slice 5)

*Proves the slice-5 contract end to end on live focal guests: a build captures each provisioned guest's overlay as a realized image (clean `systemctl poweroff`, `virsh domstate` wait, overlay copied out and rebased onto its golden, digested, cached with a `.realized.json` sidecar) and writes the range build manifest (identity, per-guest build keys and realized digests, recipe triples with vars hashes, verification results, never secrets) atomically into the builds cache. Invalidation follows the spine's two-key algebra per guest: a recipe/vars edit rebuilds exactly that guest while unchanged guests boot from their realized images with recipes skipped, a full-key no-op is the cached fast path (nothing boots; the recorded verification is reported with its timestamp), and `--reverify` forces the full pass. The headline live proof is M5: nginx verifies on the REUSED guest, demonstrating that captured content survives capture and reboot. Serializes on `/tmp/inspect-ranges-battery.lock`.*

*`--keep` builds are diagnostic: they capture nothing and mint no manifest (the kept range runs from its build overlays). Reproduce: `./run.sh` (focal vendor image, pinned Go toolchain, `vhost_vsock`, outbound internet for apt). `./run.sh down` tears down. 11/11 after the review round (9/9 pre-review; the spec-only-edit and golden-cascade matrix legs were review findings).*

## Checks

1. **M1 first build**: passes and prints its manifest path.
2. **M2 manifest integrity**: both guests recorded; every realized image exists in the image cache, its sha256 matches the manifest, and its provenance sidecar is present.
3. **M3/M4 incremental**: editing db's recipe vars rebuilds only db; web's nginx recipe logs `skipped=unchanged` and web boots from its realized image.
4. **M5/M5b the live reuse proof**: full verification passes on the reused web (nginx serving from the captured disk after reboot), and db's edited recipe actually re-ran.
5. **M6 cached fast path**: an unchanged rebuild reports `build OK (cached, verified <ts>)` in seconds, booting nothing.
6. **M7 --reverify**: boots and fully re-verifies despite matching keys (recipes still skipped; nothing recaptured).
7. **M9 spec-only edit**: a description change moves the spec hash (not the cached path) but reuses every guest, skips all recipes, and still re-verifies in full.
8. **M10 golden cascade**: changing the golden's bytes moves every build key; both guests rebuild from the new golden with recipes re-run.
9. **M8 stale bundle** (runs last; it corrupts the golden): a bundle rendered before the cache's image changed refuses at `up` naming the cause and the fix (re-render).

## Recorded hazard (review finding, parked for slice 6/publishing)

A captured realized image bakes the BUILD's egress artifacts into its disk: the host-derived nameserver (a deployment's VPC resolver IP) in netplan, and cloud-init's instance state under the render's deterministic instance-id. Reuse within the build path is proven safe live (M5 boots under the same build plan), but a future runtime seed carrying different per-instance config would be skipped by cloud-init as already-run, and a published realized image would carry the building deployment's resolver. The fix direction (bump the instance-id with the build key so runtime seeds re-apply, and strip or re-point the build nameserver at capture) belongs to slice 6/publishing and is tracked in build-v1.md's parked list.

## Files

- `run.sh` — the battery; CID band 3600, battery-isolated image/build/state caches; builds from a scratch copy of the fixture (the edit check mutates it).
- `fixtures/incr/` — two provisioned hosts (nginx, marker) for incremental substance.
- `fixtures/plain/` — content-free range for the stale-bundle check.
