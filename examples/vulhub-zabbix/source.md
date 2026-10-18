# Vulhub Zabbix CVE-2016-10134 — flat single-subnet service stack, real CVE

Upstream provenance for this range. Moved verbatim from `range.yaml` (2026-10-03) when `source:`/`title:` became documentation conventions rather than schema; see also `notes.md` for per-field provenance.

```yaml
  source:
    artifact: vulhub (github.com/vulhub/vulhub), zabbix/CVE-2016-10134/
    license: MIT
    files:
      - upstream/docker-compose.yml   # services, images, wiring (verbatim)
      - upstream/README.txt           # CVE description + reproduction (verbatim)
    upstream_substrate: Docker Compose
    fetched: 2026-09-30
    commit: 8fd63916f7a8711e2e01dda0d27237e4d6175d38   # upstream commit; every file in upstream/ matches it byte-for-byte
```
