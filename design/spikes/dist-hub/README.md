# Spike: dist-hub (distribution v1, slice 6): run and recorded 2026-10-18

*The production path against the real Docker Hub, the s3-pull discipline (one credentialed run, results recorded here). A tiny REAL qcow2 chain (qemu-img created, so backing validation runs for real) published as the range `ir-dist-test` to the private test repo `docker.io/meridianlabsai/ir-dist-test` using the org access token logged into this devbox, pulled back into fresh caches, and probed for the hub behaviors no local `registry:2` exhibits.*

## Results (2026-10-18, 5/5)

1. **H1** push over the production bearer-token flow: `auth.docker.io` challenge answered with the docker-config Basic credential, scoped `pull,push`, root `sha256:103d19ba6449...`. One live finding fixed during the run: the hub's load balancer emits LOWERCASE response headers (`location:`), which the client's plain-dict header lookup missed; response headers now normalize case (`registry.py`), and the local batteries never showed it because `registry:2` capitalizes.
2. **H2** spec-driven pull resolved the hub's `spec-<sha256>` tag to the pushed root exactly.
3. **H3** pulled bytes byte-identical THROUGH the hub's blob-storage redirects: the origin-bound redirect handler (round-2 B3) proven live: the bearer token stays on `registry-1.docker.io`, the presigned storage GET succeeds, and real qemu-img chain validation ran on the materialized chain.
4. **H4** the `name@sha256:` pin form works against the hub.
5. **H5** anonymous access to the private repo denies cleanly (`registry-denied`, no traceback, the credential-helper hint machinery intact).

**Measured, for the fleet guidance:** anonymous pulls carry `ratelimit-limit: 100;w=3600` (100 pulls per rolling hour per address). A fleet cold-pulling the public org anonymously exhausts that fast; prepend a deployment registry or mirror the org (docs/distribution.qmd carries the guidance).

**Artifacts left behind:** the private test repo holds the tiny fixture chain under `latest`/`spec-...` tags plus the earlier `credential-check` tag; all private, non-canonical, deletable at will (the scoped token deliberately cannot delete).

*Reproduce: `uv run python hub.py` (needs the org token logged in via `docker login -u meridianlabsai` and the private repo; see distribution-v1-parked-decisions.md entry 1 for the public-pull caveat while that token is logged in).*

## Recorded: the repo-name-prefix probe (2026-10-19)

`prefix_probe.py`, run once against the real hub after the prefixed-location decision: the location `docker.io/meridianlabsai/ir-dist` spelled the bare name `test` as the standing private repo `meridianlabsai/ir-dist-test` (zero new repos), the real qcow2 chain pushed through `push_image_artifact` (deliberately no catalog write), and a fresh-cache `pull_image` by bare name landed it byte-identically with the vendor base travelling. 5/5. This is the live proof behind `DEFAULT_REGISTRY = docker.io/meridianlabsai/inspect-ranges`.
