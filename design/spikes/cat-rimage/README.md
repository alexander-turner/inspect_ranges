# Spike battery: cat-rimage (standard images v1, slice 3)

*The hardened range container image as a published, digest-pinned artifact: `up` with no knob still builds the content-labeled local tag (the dev-loop default, R1); a consumer that sets `INSPECT_RANGES_RANGE_IMAGE` to `repo@sha256:<hex>` gets the pin pulled from a live `registry:2` and the running range container is that digest byte-for-byte (R2); doctor reports the source; a mutable tag or an unpullable pin refuses coded `[range-image]` and leaves nothing running (R3). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4080; registry port 5065.*

*Reproduce: `./run.sh` (noble vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## Checks

1. **R1** no knob: `up` builds and boots the local `inspect-ranges-range:v*` tag; the running range container carries it.
2. **R2** the pin path: push the built image to a local registry, forget it locally, set the pin; `up` pulls and boots; `docker inspect` of the running range container shows the exact `@sha256` pin; `doctor` reports `pinned <pin>`.
3. **R3** refusals: an unpinned tag refuses `digest-pinned` (a mutable tag could swap the hardened jail); a pin the registry does not hold refuses with the pull cause; refused `up`s leave no containers.

## Files

- `run.sh`: local-default, pull-and-pin, and refusal legs under the battery lock.
