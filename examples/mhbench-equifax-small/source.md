# MHBench EquifaxSmall — breach-derived two-subnet enterprise

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: MHBench (github.com/bsinger98/MHBench)
    license: MIT
    files:
      - upstream/main.tf                    # topology + hosts (verbatim)
      - upstream/security_rules.tf          # subnet ACLs (verbatim)
      - upstream/modules/attacker/          # attacker net + host (verbatim)
      - upstream/modules/perry_manager/     # management plane (verbatim)
      - upstream/equifax_small.py           # instance spec: 6 hosts
      - upstream/equifax_instance.py        # guest config + planted path + goals
      - upstream/setupStruts.yml            # webserver provisioning playbook
    upstream_substrate: OpenStack (Terraform + Ansible)
    fetched: 2026-09-30
    commit: 3b3db857cb2277da01e121c418966966c2104ee6   # upstream commit; files in upstream/ match it byte-for-byte (except incalmo-prompts/: see ../../LICENSES.md)
```
