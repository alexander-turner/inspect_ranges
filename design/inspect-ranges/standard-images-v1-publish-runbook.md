---
type: document
title: "Publish day runbook: the standard images catalog"
audience: inspect-ranges development
status: accepted
tags: [inspect-ranges, catalog, publish, runbook]
timestamp: 2026-10-19
---

# Publish day runbook: the standard images catalog

*The staged commands for the catalog's one deliberate publish day (ratified 2026-10-18: canonical publishes are manual user acts, run with the user's credentials). Every command below is rehearsed verbatim by [phase-exit-cat](../spikes/phase-exit-cat/README.md) against a local registry; publish day only swaps the destination. The exit criterion follows the pushes: `./run.sh public <range-image-pin>` on a clean machine.*

## One-time hub setup (user, in the Docker Hub UI)

1. Create these repositories under `meridianlabsai`, each **public** (pushing to a nonexistent repo auto-creates it with the org's default visibility, so creating them deliberately avoids an accidental private publish): `inspect-ranges-attack`, `inspect-ranges-ubuntu-noble`, `inspect-ranges-ubuntu-focal`, `inspect-ranges-catalog`, `inspect-ranges-daemon-bundle`, `inspect-ranges-range`. The `inspect-ranges-` spelling is the hub location's repo-name prefix (`docker.io/meridianlabsai/inspect-ranges`, user decision 2026-10-19): catalog names stay bare (`attack`), the shared org's namespace stays clean.
2. Generate an org access token with read+write scope covering those repositories (the devbox's current token is scoped to `ir-dist-test` and cannot push them). Note the standing quirk from [distribution-v1-parked-decisions.md](distribution-v1-parked-decisions.md) entry 1: while a narrowly-scoped token is logged in, public `docker pull`s on that host fail; the distribution client is unaffected.
3. `docker login -u meridianlabsai` with the token.

## Pre-flight (the publishing machine)

- `design/spikes/cat-attack/run.sh`, `cat-publish/run.sh`, `cat-rimage/run.sh`, and `phase-exit-cat/run.sh` all green at the publishing commit.
- Republish discipline ([standard-images-v1-parked-decisions.md](standard-images-v1-parked-decisions.md) entry 1): if this is a REpublish of `attack`, `catalog/attack/recipes/catalog.attack-tools/recipe.yaml` MUST have a bumped version, so the realized name re-keys and nothing silently replaces published bytes.

## Vendor inputs

The derives below consume the Ubuntu cloud images. On a machine that lacks them: fetch `noble-server-cloudimg-amd64.img` and `focal-server-cloudimg-amd64.img` from `https://cloud-images.ubuntu.com/<release>/current/`, verify each against Canonical's co-published `SHA256SUMS`, and use that verified value as the `--sha256` pin (the pin is the provenance record; `derive` refuses a mismatch before writing anything).

## The publish commands (in order)

```bash
# fresh inputs: the daemon bundle and both goldens, derived with it
inspect-ranges daemon-bundle -o dist/daemon
inspect-ranges images derive ~/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img \
  --sha256 <noble-sha> --name ubuntu-noble --daemon-bundle dist/daemon --daemon-sha256 <bundle-sha>
inspect-ranges images derive ~/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img \
  --sha256 <focal-sha> --name ubuntu-focal --daemon-bundle dist/daemon --daemon-sha256 <bundle-sha>

# the attack image: a fresh green build, then promotion
(cd catalog/attack && inspect-ranges build --recipe-budget 1800)

# publication (the catalog list updates with each image publish)
inspect-ranges publish --golden ubuntu-noble --to docker.io/meridianlabsai/inspect-ranges
inspect-ranges publish --golden ubuntu-focal     --to docker.io/meridianlabsai/inspect-ranges
inspect-ranges publish --daemon dist/daemon      --to docker.io/meridianlabsai/inspect-ranges
(cd catalog/attack && inspect-ranges publish --guest box --as attack --to docker.io/meridianlabsai/inspect-ranges)

# the hardened range container image (a conventional Docker image; record the digest).
# The local tag is version-suffixed; read it off the built image:
#   docker images --format '{{.Repository}}:{{.Tag}}' | grep '^inspect-ranges-range:'
# (or build/print it: uv run python -c "from inspect_ranges._runtime.rangeimage import ensure_range_image; print(ensure_range_image())")
docker tag inspect-ranges-range:v<version> meridianlabsai/inspect-ranges-range:v<version>
# NOTE (recorded live, 2026-10-19): `docker push` FAILS from a host logged in
# with an org access token — docker requests a cross-repo mount scope on the
# base image's repo (library/ubuntu), which org tokens cannot grant. Push via
# skopeo with the same credential instead:
docker save meridianlabsai/inspect-ranges-range:v<version> -o /tmp/rimage.tar
skopeo copy --dest-authfile ~/.docker/config.json docker-archive:/tmp/rimage.tar docker://meridianlabsai/inspect-ranges-range:v<version>
skopeo inspect --format '{{.Digest}}' docker://meridianlabsai/inspect-ranges-range:v<version>   # the pin digest

# the fleet pin file (3 names: attack, ubuntu-noble, ubuntu-focal)
inspect-ranges images pin --from docker.io/meridianlabsai/inspect-ranges --out pins.json
```

## Record and verify

1. Record in `design/inspect-ranges/catalog-releases.md`: the date, the publishing commit, every `publish OK <name>@sha256:...` root digest, the range image pin (`docker.io/meridianlabsai/inspect-ranges-range@sha256:...`), and the pin file content.
2. The exit transcript, on a clean machine (or after `docker rmi` of the pin and with fresh caches): `design/spikes/phase-exit-cat/run.sh public docker.io/meridianlabsai/inspect-ranges-range@sha256:<digest>`.
3. Spot checks: `inspect-ranges images pull attack` on an unconfigured machine (the default search path tail is the public org); anonymous `docker pull` of the range image from a logged-out host (the hub rate limit was measured at 100 pulls per rolling hour for anonymous pulls, so fleets should mirror or authenticate).

## Follow-ups recorded, not owned by publish day

- A CI publisher is a recorded follow-up (phase non-goal); this runbook is the publisher until then.
- Windows artifacts never appear in any of these repositories (ratified).

## Addendum (2026-10-21): the catalog list's regeneration verb

`publish --list` rewrites a location's catalog list to exactly the names given, each verified to resolve at the destination before anything writes (so the list never claims a name the org does not serve). Image publishes keep appending to the list on their own; this verb exists for renames (only a rewrite drops a name from enumeration and pin generation), torn or missing lists, and names pushed without a list update (a pushed range can join hub enumeration this way). The regeneration command for the public org as published today:

```bash
inspect-ranges publish --list attack --list ubuntu-noble --list ubuntu-focal \
  --to docker.io/meridianlabsai/inspect-ranges
```

## Addendum (2026-10-21, later): typed list entries and the current regenerate command

The catalog list is now typed: each entry records its name and kind (`image` or `range`), detected by `publish --list` at the destination from what each name's root actually serves (a pushed range records its build identity; a published image records its published name; anything else refuses `catalog-kind-unknown`). The bare-strings list published earlier today keeps reading as all images, so nothing republishes for compatibility alone. Enumeration (`mirror`) carries every entry; `images pin` writes the image entries only, because a published range pins via the consuming clone's spec hash and must never enter the pin file (its republish churn would break fleets with `pin-mismatch` noise). The regeneration command for the public org with all eight names published today:

```bash
inspect-ranges publish --list attack --list ubuntu-noble --list ubuntu-focal \
  --list vulhub-zabbix --list kypo-demo --list cyris-basic \
  --list dmz-pivot --list equifax \
  --to docker.io/meridianlabsai/inspect-ranges
```
