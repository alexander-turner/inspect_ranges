# Spike battery: dist-mirror (distribution v1, slice 5)

*Mirror, the air gap, and the GC chain tier, live: a build publishes to registry A; the whole-location `mirror` seeds an OCI-layout archive off the registry's catalog listing; the archive tars across the gap and a disconnected consumer pulls spec-driven FROM it byte-identically (the exact-spec ref travels with every mirrored root); the cross-group spec-driven form (`mirror <range-dir> --from A --to B`) resolves the exact source build and registry B then serves pulls; re-mirrors copy zero blobs; and `images prune --chains` offers an orphan golden while protecting the referenced chain, evicts it with its sidecar, leaves the shared vendor under its surviving dependent, and the surviving manifest's closure stays consumable (`plan` green post-prune). No boots (dist-oci and dist-provider own the boot proofs). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4040; registries 5060/5061.*

*Reproduce: `./run.sh` (focal vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## Checks

1. **M1** build green, published to registry A.
2. **M2** whole-location mirror seeds the archive (the `/v2/_catalog` listing drives it; hub sources refuse enumeration with the catalog-phase follow-up named, pinned at the unit tier).
3. **M3** the sneakernet: tar, ship, untar, and a disconnected consumer's spec-driven pull from the archive lands the exact manifest bytes.
4. **M4** the cross-group move: spec-driven mirror A to B, and a pull from B is byte-identical.
5. **M5** re-mirror copies zero blobs (dedup by digest at the destination).
6. **M6** the chain tier: the orphan golden is offered and evicted with its sidecar; the shared vendor survives under its surviving dependent; the surviving manifest still plans green.

## Files

- `run.sh` — the whole arc under the battery lock; the fixture is dist-registry's `minirange`.
