# dmz-pivot — original range, provenance

This range is ORIGINAL to inspect_ranges, not a translation: there is no upstream artifact and therefore no `upstream/` directory. Its provenance is the project's own dmz-pivot sketch, which the docs home page and the design overview present as the introductory example:

- `design/ranges-overview.qmd` — the sketch of record: the two-segment topology (dmz 10.80.10.0/24, internal 10.80.20.0/24), the router whose ACL allows only tcp/5432 from dmz to internal, hosts web (10.80.10.10) and db (10.80.20.10), the dedicated attack box with `entry: external`, and the three-challenge ladder (`web-foothold` execute, `customer-data` exfiltrate of `/srv/data/customers.db`, `crown-jewels` flag at `/root/flag.txt`).
- `docs/index.qmd` — the published home page carrying the same topology diagram (`docs/diagrams/dmz-pivot.excalidraw.png`) and challenge ladder.

The sketch fixes the topology, addresses, ACL, and the challenge goals' hosts/paths/types. Everything else — the no-CVE weak-credential chain that makes the ladder solvable (deploy's wordlist password, the planted `.pgpass`, the postgres superuser's server-side read primitives, the sudoers `less` rule) — is realization content authored here, following the kypo-demo precedent (weak password + wordlist, GTFOBins-style `less` escalation). Per-field detail: `notes.md`.
