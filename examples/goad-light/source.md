# GOAD-Light — 3-VM Windows AD forest (parent+child domain) with seeded misconfigurations

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: GOAD (github.com/Orange-Cyberdefense/GOAD), ad/GOAD-Light/
    license: GPL-3.0
    files:
      - upstream/inventory.ini                  # lab inventory: groups, role tags, defender toggles (verbatim)
      - upstream/config.json                    # hosts, vulns, domains, users, ACLs (verbatim)
      - upstream/provider-vmware-inventory.ini  # per-host IPs and DNS chain (verbatim)
      - upstream/Vagrantfile                    # VM images and sizing (verbatim)
    upstream_substrate: VMs via Vagrant/Ansible-over-WinRM (VirtualBox/VMware/Proxmox/Ludus/AWS/Azure)
    fetched: 2026-09-30
    commit: 992307adf944b934a3b76a2f56a637104c54b805   # upstream commit; files in upstream/ match it byte-for-byte (except cochise/: see ../../design/inspect-ranges/LICENSES.md)
```
