---
type: document
title: "Catalog releases"
audience: inspect-ranges development
status: accepted
tags: [inspect-ranges, catalog, publish, record]
timestamp: 2026-10-19
---

# Catalog releases

*The publish-day record the runbook requires: every canonical push, by digest, with the publishing commit. Append per publish day; never rewrite an entry.*

## 2026-10-19 — the first publish (standard-images-v1 exit)

Published from commit `3591e0b` (plus the uncommitted release record itself) by the project publisher, per the user's in-session authorization, to `docker.io/meridianlabsai/inspect-ranges` (hub repos spelled `inspect-ranges-<name>`).

| Name | Root digest |
|---|---|
| `attack` | `sha256:dab4b6e15907bd3e65a9c39dcd23dca79ff4000ba6444fc6496b40b14205eb7a` |
| `ubuntu-noble` | `sha256:f66e784b13f5e1e2fb29a6b846359cc918fbb3810c077a0457fd0184c95707bb` |
| `ubuntu-focal` | `sha256:de3f863e109aeef24b0d261add0c0bf2bfadd9ef4e49e7cd47c4946b3898587f` |
| `daemon-bundle` | `sha256:b7959585344569fc5ddc30320479ff47a104f83f863745aac8441812186eb074` |

Range container image: `docker.io/meridianlabsai/inspect-ranges-range:v0.1.dev533`, pin `docker.io/meridianlabsai/inspect-ranges-range@sha256:5247c6165af4fecf7ba9f2762255a091c163e88da0f31b6ded7c5f0ef1771dab`.

Inputs: noble vendor `sha256:6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`, focal vendor `sha256:18f2977d77dfea1b74aee14533bd21c34f789139e949c57023b7364894b7e5e9`, daemon bundle `sha256:02c1c930ff14f567e12990e732d73b8b44a553d08503b619af4b13b16e83612a` (vsockd v3.1.0), attack build `attack-box-6cb8063b6e5e` over the published `ubuntu-noble`.

Fleet pin file (`images pin --from docker.io/meridianlabsai/inspect-ranges`):

```json
{
  "pins": {
    "attack": "sha256:dab4b6e15907bd3e65a9c39dcd23dca79ff4000ba6444fc6496b40b14205eb7a",
    "ubuntu-focal": "sha256:de3f863e109aeef24b0d261add0c0bf2bfadd9ef4e49e7cd47c4946b3898587f",
    "ubuntu-noble": "sha256:f66e784b13f5e1e2fb29a6b846359cc918fbb3810c077a0457fd0184c95707bb"
  }
}
```

Operational note, recorded for the runbook: `docker push` fails from a host logged in with an org access token because docker requests a cross-repo mount scope on the base image's repo (`library/ubuntu`), which org tokens can never grant; `skopeo copy docker-archive:<saved tar> docker://…` pushes cleanly with the same credential.

## 2026-10-20 — attack v3 (windows-ad-v1)

Published from commit `2085b54` by the project publisher, per the user's in-session authorization, to `docker.io/meridianlabsai/inspect-ranges`.

| Name | Root digest |
|---|---|
| `attack` | `sha256:43a10d17e39383949916b6b3b71a4f3388f7cfc93563c8fbd455f050eb3e142c` |

The v3 recipe adds pip impacket 0.12.0 with presence assertions for the Windows ladder's tools (`atexec.py`, `psexec.py`, `wmiexec.py`, `secretsdump.py`, `GetUserSPNs.py`, `raiseChild.py`, `lookupsid.py`, `smbexec.py`, `mssqlclient.py`) and records the pip install in `/etc/attack-image.manifest` (windows-ad-v1 slice 4; both Windows example batteries assert against this build). Goldens unchanged (`ubuntu-noble`/`ubuntu-focal` keep their 2026-10-19 digests). Build `attack-box-22995e7cb56d` over the published `ubuntu-noble`; hub pin list verified post-push (`images pin --from`).

## 2026-10-20 — dmz-pivot build (the hello-world example)

Pushed from commit `c6838e6` by the user from the main session (the public-surface push is the user's own act; preparation and verification ran in-session), to `docker.io/meridianlabsai/inspect-ranges`.

| Name | Root digest |
|---|---|
| `dmz-pivot` | `sha256:c36fb23b96ea8dca4cfcb818623b7011d08a56818b857c231847a0e5c84ef117` |

The first published range build: spec `sha256:8e2c07eed07c7ab671872c8a42f7c7755a3b03890178dcca5ccfa4f18a46a7fd` (`examples/dmz-pivot/range.yaml` as merged in `724e846`), realized images for `web` and `db` over the published `ubuntu-noble`, recipes `dmz.web`/`dmz.db`. Spec-driven pull now serves the docs home page's clone-and-eval journey. Catalog image names and the fleet pin list are unchanged (a range build is not a catalog image; `images pin --from` re-verified post-push: `attack`/`ubuntu-noble`/`ubuntu-focal` digests exactly as recorded above).

## 2026-10-20 — equifax build

Pushed from commit `e4b1d2f` to `docker.io/meridianlabsai/inspect-ranges`; the push ran in-session at the user's explicit request (preparation, build, and verification in-session as before).

| Name | Root digest |
|---|---|
| `equifax` | `sha256:52d43f1f57b41bc5c03228eee430ae59e047f03581a4864a0491b72cd4ee5ed0` |

The second published range build, under the example's new name (renamed from `mhbench-equifax-small`, merged in `64db161`): spec `sha256:9c60f909a1421397b31cde2175ea68923ae7189702859151842db4927d427377` (`examples/equifax/range.yaml` as merged), realized images for `webserver_0`/`webserver_1` and `database_0`–`database_3` over the published `ubuntu-focal` (router on `ubuntu-noble`), recipes `mh.webserver`/`mh.database`. Built fresh on main after the rename merge (`build OK (418.2 s, 6 recipes)`, all three behavioral check trios proven), distinct from the rename slice's battery build, whose spike cache died with its worktree. Catalog image names and the fleet pin list are unchanged (a range build is not a catalog image; `images pin --from` re-verified post-push: `attack`/`ubuntu-noble`/`ubuntu-focal` digests exactly as recorded above).

## 2026-10-21 — vulhub-zabbix build

Pushed from commit `fb94837` (main; code exactly the router-provisioning merge `4e2dd37`, the interleaved commit being docs-only) to `docker.io/meridianlabsai/inspect-ranges`, in-session per the user's explicit publish-day authorization (2026-10-21, "Publish fully"). The same authorization and commit cover every 2026-10-21 entry below.

| Name | Root digest |
|---|---|
| `vulhub-zabbix` | `sha256:6eb3549184ae9de71d045de9b7bd1a1ddc5e2023df4cd09e7774dcac3d711c26` |

First publish of this range: spec `sha256:aafa303dc8eac66bca244417170410c7acc0b4bf68c9433060e5239b533428e8`, realized images for `mysql`/`server`/`agent`/`web` over the published `ubuntu-focal`, recipes `vulhub.mysql57`/`vulhub.zabbix-server`/`vulhub.zabbix-agent`/`vulhub.zabbix-web`. Built fresh on main (`build OK (470.8 s, 4 recipes)`): every declared service and `CVE-2016-10134` verified, the behavioral trio proven against the captured artifacts (reference 1.00/valid, insufficient and forged 0.00, `behavioral checks=3`), conformance green. No spike eval runner exists for this example (the build-v1 battery rebuilds in its own caches), so this publish rests on the build proof alone, honestly noted. Pin list re-verified post-push: `attack`/`ubuntu-noble`/`ubuntu-focal` digests exactly as recorded above.

## 2026-10-21 — kypo-demo build

| Name | Root digest |
|---|---|
| `kypo-demo` | `sha256:0b3baf19a90eaacce252ff9830bb5f0627f23a35647072096394c9bb118bde63` |

First publish of this range: spec `sha256:cfa6331df3339dedbf9c27abc5c21c1b1d52119d687e8e95e4d39671cc32310d`, realized images for `server`/`client` over the published `ubuntu-focal`, recipes `kypo.server`/`kypo.client`. Built fresh on main (`build OK (272.2 s, 2 recipes)`, the telnet-ladder trio proven, `behavioral checks=3`); the kypo-build eval leg ran green against this build (8/8: the reference ladder scored 1.0 valid through the client foothold, the sandbox wall pinned). Pin list re-verified post-push: digests unchanged.

## 2026-10-21 — cyris-basic build

| Name | Root digest |
|---|---|
| `cyris-basic` | `sha256:d3d46028552bde6142072b58318a283900eefc9cd073368f2f6738a1da7ae91e` |

First publish of this range: spec `sha256:6d0887255f4d0db278343089ff1ff2ef825141174e2b022c9668dedfef62d94d`, realized images for `desktop`/`webserver` over the published `ubuntu-focal` and the provisioned `firewall` router over `ubuntu-noble`, recipes `cyris.desktop`/`cyris.webserver`/`cyris.firewall`. Built fresh on main (`build OK (217.8 s, 3 recipes)`, all four trios proven, `behavioral checks=12`); the cyris-build eval leg ran green against this build (14/14: all four reference chains scored 1.0 valid through the desktop foothold, the wall pinned). Pin list re-verified post-push: digests unchanged.

## 2026-10-21 — dmz-pivot build (supersedes 2026-10-20)

| Name | Root digest |
|---|---|
| `dmz-pivot` | `sha256:9e4c5ff6ec07030d7ba18b065818bada94e4da08cec7ad29fa15f1b5928da807` |

SUPERSEDES `sha256:c36fb23b96ea8dca4cfcb818623b7011d08a56818b857c231847a0e5c84ef117` (2026-10-20): router provisioning moved every routed spec's normalized hash, so the earlier published build reads stale to spec-driven consumers on current code; the old digest stays served by ref. New spec `sha256:0ce9688e56ffd49cc20310bd7b9270242a4f202743764699b56bb06a526e148f` (was `sha256:8e2c07ee…`), guests `web`/`db` over the published `ubuntu-noble` (recipes `dmz.web`/`dmz.db`) reused under unchanged build keys (same realized disks `dmz-pivot-web-aacb15138f1a`/`dmz-pivot-db-36c511fe87b6`) with a fresh proof boot: `build OK (153.3 s, 0 recipes)`, all three trios proven, `behavioral checks=9`; the publish-day eval leg (the crown-jewels full chain through the attack-box foothold, kypo-eval shape) scored 1.0 valid with the wall pinned. Pin list re-verified post-push: digests unchanged.

## 2026-10-21 — equifax build (supersedes 2026-10-20)

| Name | Root digest |
|---|---|
| `equifax` | `sha256:f784f0a6037d0293c6bb552113c9def839ebb72876a303a9b509ce250ecb8a9c` |

SUPERSEDES `sha256:52d43f1f57b41bc5c03228eee430ae59e047f03581a4864a0491b72cd4ee5ed0` (2026-10-20), for the same spec-hash move; the old digest stays served by ref. New spec `sha256:85ab65d5293cd2a42a3bcb0da4b3a1b95c6b66331922a9255f9217b66ba57aeb` (was `sha256:9c60f909…`), realized images for `webserver_0`/`webserver_1` and `database_0`–`database_3` over the published `ubuntu-focal` (router on `ubuntu-noble`, attacker the catalog default) reused under unchanged build keys, recipes `mh.webserver`/`mh.database`, with a fresh proof boot: `build OK (149.0 s, 0 recipes)`, the Equifax-chain trio proven, `behavioral checks=3`; the mh-build eval leg ran green against this build (8/8: coverage scored 1.0 valid on the attack-box foothold, msfconsole aboard). Pin list re-verified post-push: digests unchanged.

## 2026-10-21 — the catalog list

`publish OK  catalog@sha256:7c2e7eafc9ac23062ac671fc88258263e10fceac8eb846c58e5e36f9451f28a9 -> docker.io/meridianlabsai/inspect-ranges (3 name(s))`: the list rewritten to exactly `attack`, `ubuntu-noble`, `ubuntu-focal` (each verified to resolve there first). Range names are deliberately NOT in enumeration (an open user decision). Verified post-publish: a `source_names` read of the org enumerates exactly those three.

## 2026-10-21 — the typed catalog list (eight names)

`publish OK  catalog@sha256:ade2e4b70e6d226fd29b0dc5918f52cba19ba256db4d369b46c7d33ea2359122 -> docker.io/meridianlabsai/inspect-ranges (8 name(s))`, run in-session under the user's standing authorization, sequenced after the user's main push landed the typed reader (the compatibility is one-way: pre-change readers see a typed list as empty, recorded in the slice's CHANGELOG bullet). The list now enumerates every published name with its kind: `attack`, `ubuntu-noble`, `ubuntu-focal` as images; `vulhub-zabbix`, `kypo-demo`, `cyris-basic`, `dmz-pivot`, `equifax` as ranges. Verified post-publish: `source_names` enumerates all eight, `catalog_entries` reports the kinds above, and `images pin --from` writes exactly the three image pins with digests unchanged (`attack` 43a10d17..., `ubuntu-noble` f66e784b..., `ubuntu-focal` de3f863e...), the per-class drift split working as designed. A whole-org `mirror` now carries the images and every published example build in one command.
