---
type: document
title: vulhub-zabbix — source note
status: draft
tags: [inspect-ranges, range-example, provenance]
timestamp: 2026-09-30
---

# vulhub-zabbix — source note

*Status: built and proven (2026-10-18, build-v1 slice 6). `range.yaml` (schema 0.3) builds end to end on the focal era golden: provisioning recipes run live, every declared service and the CVE verify, the realized images are captured with a manifest, and the three behavioral chains (reference exploit 1.00/valid, insufficient 0.00, forged 0.00) prove exploitability against the captured artifacts. See the "Build realization provenance" section below and `design/spikes/vulhub-build/`.*

Translation of `vulhub/zabbix/CVE-2016-10134` (`github.com/vulhub/vulhub`, MIT, cloned 2026-09-30). Chosen as the minimal/smoke-test example over a single-container CVE because it is a genuine 4-host service stack (web, server, agent, database) while still booting in seconds upstream. Upstream is docker-compose; per the project decision (2026-09-30), we express it substrate-agnostically — the images/services are what we replicate, not the container runtime.

## Where each fact comes from (vendored in `upstream/`)

| range.yaml section | Source | Detail |
|---|---|---|
| four hosts, images, commands | `docker-compose.yml` | server + agent from `vulhub/zabbix:3.0.3-server` (commands `server`/`agent`), `mysql:5`, `vulhub/zabbix:3.0.3-web` |
| service wiring + credentials | `docker-compose.yml` env vars | DATABASE_HOST=mysql, root/root, db `zabbix`; web's ZBX_SRV_HOST=server:10051; agent's ZBX_SRV_HOST=server |
| mysql seeding | `docker-compose.yml` | `./database/` mounted to `/docker-entrypoint-initdb.d/` |
| exposed web port | `docker-compose.yml` | `8080:80` (web UI on container port 80) |
| CVE, guest login, exploit chain | `README.txt` | SQLi in latest.php `toggle_ids`, unauth via jsrpc.php; guest/empty login; session hijack → RCE per exploit-db 40237/40353 |

## Tagged defaults (invented, not upstream)

- Network `lab` with CIDR 10.10.10.0/24, DHCP, `mode: isolated` — upstream uses the default docker bridge with name-based DNS.
- Zabbix server port 10051 and agent port 10050 (standard Zabbix ports; compose relies on defaults — only web's `ZBX_SRV_PORT=10051` env var states one of them).
- Guest OS "linux" per host — upstream pins container images, not distros.
- Attacker host, `egress: none`, and the RCE goal/canary oracle — upstream has no attacker or scoring.

## To-verify

- Nothing load-bearing; the range is fully specified by the two upstream files. (If rebuilt as VMs rather than containers, the vulhub images' internal build steps — Zabbix 3.0.3 from source with guest login enabled — would need porting; see the vulhub `zabbix` base image.)

## What this example exercises in the schema

The **minimal case**: one flat network, name-based service discovery (DNS records instead of static IPs), inter-service credentials as config, a **real public CVE** as the entry vuln, no defense, and a canary-style oracle. The floor every schema draft must express trivially.

> Schema v0.1 carve-out (2026-10-01): sections awaiting schema design (goals, attack_path, guest config, ...) moved verbatim from `range.yaml` to [`deferred.yaml`](deferred.yaml); see [schema-v0.1-scope](../../../../design/inspect-ranges/schema-v0.1-scope.md).

## Build realization provenance (build-v1 slice 6, 2026-10-18)

The pre-build translation carried upstream's docker image tags as `image:` strings (`mysql:5`, `"vulhub/zabbix:3.0.3-server (command: server)"`, `vulhub/zabbix:3.0.3-web`); under the Q1 reference grammar those were provenance notes, not references, and they live here now. The `(command: server|agent)` annotation selected the role inside upstream's shared server image; roles are now separate recipes (`vulhub.zabbix-server`, `vulhub.zabbix-agent`).

Stack realization facts, measured during the slice:

- The vulhub images are Alpine/musl builds (`lib/ld-musl-x86_64.so.1`; `zabbix_server` links musl), so their binaries cannot run on a glibc golden; the canonical `zabbix-3.0.3.tar.gz` (SourceForge still serves it) carries everything instead: server and agent compile at build time, the frontend's PHP sources deploy verbatim (CVE-2016-10134 is fixed in 3.0.4, so the exact 3.0.3 sources are the scenario).
- The server compiles against MariaDB's client: focal's MySQL 8 client headers dropped `my_bool`, which zabbix 3.0 uses; mariadb keeps the era API. Zabbix 3.0's configure only accepts `-lmysqlclient`/`-lperconaserverclient` in the config script's `--libs` output (measured: `-lmariadb` leaves the link line's `-l` empty), so the recipe installs a `zbx-mysql-config` shim that rewrites `-lmariadb` to `-lmysqlclient` and relies on `libmariadb-dev-compat`'s `libmysqlclient.so` symlink.
- MySQL is Oracle's 5.7.44 generic glibc tarball (upstream `mysql:5`; focal archives carry only 8.x), schema/images/data seeded from the same zabbix tarball, root/root grants per upstream compose.
- The frontend runs on focal's stock php7.4. The earlier "7.4 breaks 3.0.x" belief was wrong: `each()` and `get_magic_quotes_gpc()` are deprecated in 7.4 but removed only in PHP 8, and the measured chain (frontend render, unauth jsrpc.php SQLi leaking the admin hash, api_jsonrpc user.login) works on 7.4 against the exact 3.0.3 sources. The era php7.0 is no longer obtainable from packages (the ondrej PPA dropped pre-7.4 builds for focal), so 7.4 also keeps the build hermetic to distro archives. Interpreter flexibility mirrors the ratified MySQL-any-5.x call: the CVE lives in the zabbix PHP sources, which stay exact.
- `EnableRemoteCommands=1` on the agent is deliberate scenario content: the declared attack path ends in "zabbix agent remote command", which 3.0 agents refuse by default; upstream's compose wiring presumes it.
- The seeded "Zabbix server" host's interface is retargeted from 127.0.0.1 to the agent guest (10.10.10.13) so server-driven commands reach it; hosts gained static addresses for that determinism (upstream used docker DHCP).
- MySQL and the zabbix daemons install from tarballs, so they have no dpkg identity: their `services` declarations verify by listening port, with versions recorded in notes (version attribution for non-dpkg installs is a parked schema question in build-v1.md); `php` is dpkg-attributable and declares `version: "7.4", package: php7.4`.
