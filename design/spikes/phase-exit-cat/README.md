# Spike battery: phase-exit-cat (standard images v1, the exit)

*Publish day rehearsed end-to-end, then the exit transcript. The publisher half runs the [runbook](../../inspect-ranges/standard-images-v1-publish-runbook.md)'s commands verbatim against a local `registry:2` standing in for the public org: both goldens (`noble-range-guest`, `ubuntu-focal`), the daemon bundle, the attack image promoted to its bare name, the range container image pushed and digest-recorded, and the fleet pin file (3 names). The consumer half is the exit criterion live: fresh empty caches, a range whose attacker declares NO image (the flipped default resolves the catalog's `attack`), one real `inspect eval` whose init pulls the attack chain, the noble golden, and the pinned range container image implicitly, with the booted foothold provably the attack image (metasploit, the recorded manifest, nmap getting an L3 answer from the target), then a WARM second eval with the registry stopped (zero network, by proof). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4090; registry port 5066.*

*Reproduce: `./run.sh` (noble + focal vendor images in the shared cache, `vhost_vsock`, docker, the `registry:2` image; ~25 min, dominated by the attack build). `./run.sh down` tears down.*

*The real exit: after the user runs publish day, `./run.sh public <range-image-pin>` reruns the consumer half against `docker.io/meridianlabsai` on a clean machine.*

## Checks

1. **X1** the publisher half: the attack factory builds green; both goldens, the daemon bundle, and the attack image publish; the range container image pushes with its digest captured; `images pin` records all three catalog names.
2. **X2** the exit transcript: with `INSPECT_RANGES_REGISTRY` at the catalog and `INSPECT_RANGES_RANGE_IMAGE` pinned, a cold consumer's `inspect eval` succeeds; the implicit pull landed `attack.qcow2` with chain and provenance; the pinned range container image was pulled; the solver proves the foothold is the attack image.
3. **X3** the second eval runs green with the registry GONE: the warm path touches no network.

## Files

- `run.sh`: publisher rehearsal + consumer transcript under the battery lock; `public` mode for the real exit.
- `exit_eval.py`: the mockllm eval whose solver probes msfconsole, the package manifest, and a live nmap of the target through the foothold.
