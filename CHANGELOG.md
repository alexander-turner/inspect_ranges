## Unreleased

- CI tests on Python 3.12 and 3.14. The matrix jobs now set `UV_PYTHON`, so each entry runs its own version; before, every entry ran on the 3.12 from `.python-version`.

- CI enforces the C# codec drift guard: the py-test job installs the pinned .NET SDK (8.0.404 by sha256) and sets `INSPECT_RANGES_REQUIRE_DOTNET=1`, so three-codec parity fails loudly in CI instead of silently skipping.

- Host topology: every sample now holds a renewable host lease (`leases.json`), reclaimed by the new independent `inspect-ranges reaper` on expiry alone; `INSPECT_RANGES_HOST=uds:<socket>` selects the separated topology, where a standing `inspect-ranges applier` process owns realization and teardown and relays guest operations over one unix socket (docs: Host Topology).
- `inspect-ranges doctor` gains the Host group: strict `leases.json` health, an expired-leases hint naming the reaper, and an applier socket probe when one is configured.
- `libvirt_range` Inspect sandbox provider: per-sample realizer-booted ranges with named sandboxes, layered retries with session invalidation, interrupted-sample containment, and `inspect sandbox cleanup libvirt_range` crash recovery (docs: Sandbox Provider).
- `inspect-ranges doctor` gains the Provider group: entry-point registration, the inspect-ai floor, current-recipe goldens (with stale-golden guidance), and CID lease registry health.
- Initial release.
