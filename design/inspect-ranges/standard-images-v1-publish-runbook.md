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

1. Create these repositories under `meridianlabsai`, each **public** (pushing to a nonexistent repo auto-creates it with the org's default visibility, so creating them deliberately avoids an accidental private publish): `attack`, `noble-range-guest`, `ubuntu-focal`, `catalog`, `daemon-bundle`, `inspect-ranges-range`.
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
  --sha256 <noble-sha> --name noble-range-guest --daemon-bundle dist/daemon --daemon-sha256 <bundle-sha>
inspect-ranges images derive ~/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img \
  --sha256 <focal-sha> --name ubuntu-focal --daemon-bundle dist/daemon --daemon-sha256 <bundle-sha>

# the attack image: a fresh green build, then promotion
(cd catalog/attack && inspect-ranges build --recipe-budget 1800)

# publication (the catalog list updates with each image publish)
inspect-ranges publish --golden noble-range-guest --to docker.io/meridianlabsai
inspect-ranges publish --golden ubuntu-focal     --to docker.io/meridianlabsai
inspect-ranges publish --daemon dist/daemon      --to docker.io/meridianlabsai
(cd catalog/attack && inspect-ranges publish --guest box --as attack --to docker.io/meridianlabsai)

# the hardened range container image (a conventional Docker image; record the digest)
docker tag inspect-ranges-range:v<version> meridianlabsai/inspect-ranges-range:v<version>
docker push meridianlabsai/inspect-ranges-range:v<version>   # output ends with the sha256 digest

# the fleet pin file (3 names: attack, noble-range-guest, ubuntu-focal)
inspect-ranges images pin --from docker.io/meridianlabsai --out pins.json
```

## Record and verify

1. Record in `design/inspect-ranges/catalog-releases.md`: the date, the publishing commit, every `publish OK <name>@sha256:...` root digest, the range image pin (`docker.io/meridianlabsai/inspect-ranges-range@sha256:...`), and the pin file content.
2. The exit transcript, on a clean machine (or after `docker rmi` of the pin and with fresh caches): `design/spikes/phase-exit-cat/run.sh public docker.io/meridianlabsai/inspect-ranges-range@sha256:<digest>`.
3. Spot checks: `inspect-ranges images pull attack` on an unconfigured machine (the default search path tail is the public org); anonymous `docker pull` of the range image from a logged-out host (the hub rate limit was measured at 100 pulls per rolling hour for anonymous pulls, so fleets should mirror or authenticate).

## Follow-ups recorded, not owned by publish day

- A CI publisher is a recorded follow-up (phase non-goal); this runbook is the publisher until then.
- Windows artifacts never appear in any of these repositories (ratified).
