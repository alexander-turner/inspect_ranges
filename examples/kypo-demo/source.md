# KYPO demo training — routed two-subnet Linux with telnet brute-force + sudo privesc

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: kypo-crp-demo-training (gitlab.ics.muni.cz/muni-kypo-crp/prototypes-and-examples/sandbox-definitions/kypo-crp-demo-training)
    license: MIT
    files:
      - upstream/topology.yml               # hosts/routers/networks/mappings (verbatim)
      - upstream/variables.yml              # per-instance randomized variables (verbatim)
      - upstream/provisioning/playbook.yml  # guest configuration (verbatim)
      - upstream/provisioning/roles/        # server + client roles (verbatim)
    upstream_substrate: OpenStack (KYPO CRP; local variant via Vagrant/VirtualBox)
    fetched: 2026-09-30
    commit: 9d268bc5fbb718341aae902391f82428a5c976bc   # upstream commit; every file in upstream/ matches it byte-for-byte
```
