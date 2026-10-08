# Spike: Inspect API checkpoint (realizer-v1 slice 0, throwaway)

*Confirms the current Inspect `SandboxEnvironment` contract before the realizer and provider phases build on it. Run on the m6i.metal devbox against inspect-ai 0.3.272, 2026-10-08.*

*Reproduce: `uv run python design/spikes/inspect-api-check/run_check.py` (no VMs; a stub provider records every lifecycle hook to `tmp/api-check.jsonl` and two real `inspect eval` runs assert the contract).*

## Verdict

**9/9 checks pass.** Registration, the four lifecycle hooks in order, both config forms (`range.yaml` path and a typed `RangeSpec` object), named-sandbox resolution, `config_files()` discovery, eval-log round-trip of the typed config, and entry-point discovery of `inspect_ranges._registry` all behave as the realizer-v1 record assumes.

## Findings

Recorded in [realizer-v1](../../inspect-ranges/realizer-v1.md) (Slice 0 findings): the typed-config form required `RangeSpec.__hash__` (Inspect hashes the sandbox spec as a cache key; fixed in `types.py` this slice); solvers see a `SandboxEnvironmentProxy`, never the provider class; `config_deserialize` is load-bearing for the typed config's eval-log round-trip.

## Files

- `provider.py` — stub `@sandboxenv(name="libvirt_range")` provider; hooks record to JSONL, exec/file deliberately unimplemented
- `task.py` — probe solver asserting `sandbox()`/`sandbox("web")` resolution through the proxy
- `range.yaml` — minimal valid spec for the path-config form
- `run_check.py` — the 9-check battery; run logs under `tmp/` (gitignored)
