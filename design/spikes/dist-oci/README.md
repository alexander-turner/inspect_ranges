# Spike battery: dist-oci (distribution v1, slice 1)

*The OCI encoding and the registry-less directory form, proven on the real vulhub build: `push_build` encodes the built range's transitive closure (vendor base, golden with its provenance sidecar, four realized images with theirs, the recipe bundles, and the build manifest as the pull root) into a plain OCI image-layout directory, the layout survives the tar sneakernet shape, `materialize_closure` lands everything into fresh empty caches with real backing-chain validation (qemu-img against the actual qcow2 headers, which the unit tier fakes), tampering refuses by digest with no consumable manifest left dangling, and the pulled caches plan, render, boot, and serve zabbix to the attacker. Zero network, zero credentials. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4000.*

*Reproduce: `./run.sh` (needs the focal vendor image in the shared cache, `vhost_vsock`, docker, and host `qemu-img`). `./run.sh down` tears down.*

## Checks

1. **D1** the vulhub build is green (the artifact set under test is real, not synthetic).
2. **D2/D3** push writes a valid layout and prints the root digest; a second push adds zero blobs and reproduces the root digest (content addressing is doing the dedup).
3. **D4/D5** the layout tars, ships, untars, and materializes into fresh empty caches; all four realized images land with sidecars; the pulled golden's REAL qcow2 backing chain resolves and validates.
4. **D6** every pulled image is byte-identical to the built original, and the pulled build manifest is the exact published bytes.
5. **D7** a second pull converges by digest and fetches nothing.
6. **D8** a tampered blob refuses with `blob-digest-mismatch` and no build manifest lands (manifest-lands-last, so a refused pull is never consumable).
7. **D9** the headline: plan consumes the pulled manifest, render and `up` run against the pulled caches (verify-images green on the pulled chain), and the frontend serves to the attacker over the range network.

## Files

- `run.sh`: build vulhub, then the push/ship/pull/tamper/boot legs under the battery lock.
- `dist.py`: drives `push_build`/`materialize_closure` (the CLI verbs arrive with Q8 in slice 3).
