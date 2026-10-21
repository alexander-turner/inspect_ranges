# CyRIS full example — firewall-segmented office/servers with guest tasks

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: CyRIS (github.com/crond-jaist/cyris), examples/full.yml
    license: BSD-3-Clause
    files:
      - upstream/full.yml               # entire definition (verbatim, annotated upstream)
      - upstream/basic-multi_host.yml   # minimal two-physical-host variant (verbatim)
    upstream_substrate: KVM (libvirt); base images defined by libvirt XML (basevm_*.xml)
    fetched: 2026-09-30
    commit: 8b65a30581cdd8e126c7b1fa26db2a4b770b7f17   # upstream commit; every file in upstream/ matches it byte-for-byte
```
