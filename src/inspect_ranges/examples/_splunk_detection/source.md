# Splunk Attack Range (Windows) — telemetry-instrumented two-host lab

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: attack_range (github.com/splunk/attack_range), templates/aws/splunk_windows_aws.yml
    license: Apache-2.0
    files:
      - upstream/splunk_windows_aws.yml   # full template (verbatim)
    upstream_substrate: Terraform + Ansible on AWS (v5 is cloud-only; Ludus-derived roles)
    fetched: 2026-09-30
    commit: fc9b9e719d8835da0bbb5c20d46c52a9778d64e2   # upstream commit; every file in upstream/ matches it byte-for-byte
```
