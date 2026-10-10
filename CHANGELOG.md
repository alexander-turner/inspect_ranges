## Unreleased

- Host topology: every sample now holds a renewable host lease (`leases.json`), reclaimed by the new independent `inspect-ranges reaper` on expiry alone; `INSPECT_RANGES_HOST=uds:<socket>` selects the separated topology, where a standing `inspect-ranges applier` process owns realization and teardown and relays guest operations over one unix socket (docs: Host Topology).
- `inspect-ranges doctor` gains the Host group: strict `leases.json` health, an expired-leases hint naming the reaper, and an applier socket probe when one is configured.
- `libvirt_range` Inspect sandbox provider: per-sample realizer-booted ranges with named sandboxes, layered retries with session invalidation, interrupted-sample containment, and `inspect sandbox cleanup libvirt_range` crash recovery (docs: Sandbox Provider).
- `inspect-ranges doctor` gains the Provider group: entry-point registration, the inspect-ai floor, current-recipe goldens (with stale-golden guidance), and CID lease registry health.
- Initial release.
