# defender-ops - original range, provenance

This range is ORIGINAL to inspect_ranges, not a translation: there is no upstream artifact and therefore no `upstream/` directory. It was authored for the example-coverage arc (2026-10-28) as the project's coverage range: the scenario exists to exercise, in one coherent story, the schema and goal vocabulary the other examples leave untouched.

What fixes its shape is the coverage ledger rather than an external sketch:

- Networking: a routerless `mode: nat` segment with a scoped `EgressPolicy` (network and attacker both, the `attacker-egress-requires-nat` and `egress-with-router-not-realized` gates respected), `dns.nameservers`, a router joining two isolated segments with a first-match ACL carrying a `deny:` carve-out, an `icmp` entry, a guest-name endpoint and a CIDR endpoint, and one static `routes:` entry.
- Variables: a drawn `int` (`gate_code`, explicit min/max) and a drawn `choice` (`site_wing`), applied by a recipe-installed boot unit in the kypo-demo precedent, with an `answer` goal scored against the drawn value.
- Activities: an `@boot` script and an `every 1m` script with `user:` set, both on the monitor.
- Telemetry: a `kind: file` collector over the monitor's ops log, consumed by an `evade` goal with an ordered severity vocabulary and `on_sensor_tamper: fail`.
- Goals: `availability`, `degrade` (error-fraction), `tamper`, `hijack` (with a `primitive:` override), `patch` (with a registered reference exploit), `answer` (variable-sourced), and the custom `lotl` type registered in [goals.py](goals.py) over the exec witness record.

The chain content realizing all of it (the orderboard's open admin endpoint, the status board, the watchdog's unsafe jump handler, the gate-operator sudoers rule) is authored here in the dmz-pivot style: no CVE anywhere, every weakness declared. Per-field detail: `notes.md`.
