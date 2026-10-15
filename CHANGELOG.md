## Unreleased

- Evidence: every sample records tamper-evident evidence outside the VMs (per-segment pcap via a `NET_RAW`-only sidecar, continuous consoles, stage/verification streams, daemon session continuity, poll-based in-guest telemetry export), streamed as generated to `<evallogstem>.evidence/<sample>_<epoch>_<attempt>` (local or S3, write-once conditional puts) with a hash-chained manifest, explicit in-chain gap records, per-writer seals, and the seal digests bound into the eval log's sample store; `inspect-ranges evidence verify [--expect-seal]` replays a record offline (docs: Evidence).
- `inspect-ranges doctor` gains the Evidence group: evidence knob validity, a sink writability probe when `INSPECT_RANGES_EVIDENCE_SINK` is set, and an off-instance warning for local-only evidence.
- CI enforces the C# codec drift guard: the py-test job installs the pinned .NET SDK (8.0.404 by sha256) and sets `INSPECT_RANGES_REQUIRE_DOTNET=1`, so three-codec parity fails loudly in CI instead of silently skipping.

- Host topology: every sample now holds a renewable host lease (`leases.json`), reclaimed by the new independent `inspect-ranges reaper` on expiry alone; `INSPECT_RANGES_HOST=uds:<socket>` selects the separated topology, where a standing `inspect-ranges applier` process owns realization and teardown and relays guest operations over one unix socket (docs: Host Topology).
- `inspect-ranges doctor` gains the Host group: strict `leases.json` health, an expired-leases hint naming the reaper, and an applier socket probe when one is configured.
- `libvirt_range` Inspect sandbox provider: per-sample realizer-booted ranges with named sandboxes, layered retries with session invalidation, interrupted-sample containment, and `inspect sandbox cleanup libvirt_range` crash recovery (docs: Sandbox Provider).
- `inspect-ranges doctor` gains the Provider group: entry-point registration, the inspect-ai floor, current-recipe goldens (with stale-golden guidance), and CID lease registry health.
- Initial release.
