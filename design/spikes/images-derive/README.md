# Spike battery: golden image derivation (realizer-v1 slice 1)

*The conformance battery for `inspect-ranges images derive`: host-side failure modes against a temporary cache, then the derived golden booted in the range container with the daemon answering on vsock from the realizer CID band and zero TCP listeners in the guest. Serializes on the shared battery lock (`/tmp/inspect-ranges-battery.lock`).*

*Reproduce: `./run.sh` (needs the noble vendor image in the shared cache, `vhost_vsock` loaded, and docker; `./run.sh down` tears down). Run logs under `tmp/` (gitignored).*

## Checks

1. Vendor digest mismatch refuses at the `verify-vendor` stage with nothing written to the cache.
2. `derive` produces the golden overlay plus its provenance sidecar (vendor digest, pinned daemon, recipe version, golden digest).
3. Re-running with the same inputs is a cache hit reporting the identical golden digest, with no commands run.
4. A same-named file without provenance metadata is never clobbered.
5. `images list` shows managed provenance and flags unmanaged files.
6. The golden boots in the range container (CID 3000, the realizer battery band); the baked daemon answers on vsock.
7. `ss -tln` inside the booted guest shows zero TCP listeners (ssh masked, resolved stub listener off).

## Files

- `run.sh` — the battery
- `client2.py` — minimal v2 vsock client (`wait`, `exec`)
- `compose.yaml` — the net-compile range container with the battery's temp cache mounted at `/images`
