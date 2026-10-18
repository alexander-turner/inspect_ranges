# Spike battery: dist-resolve (distribution v1, slice 3)

*Resolution and the spec-driven verbs, live: the CLI `push` publishes a real build to a layout location and to a live `registry:2`, bare `pull` resolves by the normalized-spec hash across a configured search path (a prepended registry shadows the layout fallback deterministically, proven by which location the resolve line names), a semantically edited spec refuses `no-build-for-spec` naming the nearest published build, the `name@digest` pin form bypasses the match, catalog images pull sticky (`images pull`; a published name that moved refuses rather than silently replacing the cache) and move forward only on explicit `images refresh` (chain and sidecar together), and a fresh builder cache with `INSPECT_RANGES_REGISTRY` pointing at the catalog fetches the published golden through the build path's Q1 registry tier and builds green. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4020; registry port 5058. The fixture range is dist-registry's `minirange` (copied into tmp so spec edits never dirty the shared fixture).*

*Reproduce: `./run.sh` (needs the focal vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## Checks

1. **S1** the fixture range builds green (two real builds run in this battery: this one, and S8's tier-fetching build).
2. **S2/S3** `push` prints the publishable `name@digest`; bare `pull` resolves by spec hash, lands the exact manifest bytes, and `plan` consumes the pulled caches.
3. **S4/S5** an edited spec refuses `no-build-for-spec` with the nearest build named and nothing landed; `--pin` pulls that exact root anyway.
4. **S6** with `INSPECT_RANGES_REGISTRY="<registry>,<layout>"`, the resolve line names the prepended registry: first match wins, shadowing is deterministic.
5. **S7** `images pull` lands a published golden chain with its sidecar; after the publisher moves the name forward, a plain pull refuses `cache-name-conflict` (sticky) and `images refresh` replaces chain and sidecar (explicit move-forward).
6. **S8** the headline for the Q1 tier: a fresh empty builder cache resolves `ubuntu-focal` through the search path, fetches the chain, and the build runs green end to end.

## Files

- `run.sh`: the whole arc under the battery lock; publishes catalog images via a small inline driver (the `publish` promotion verb is catalog-phase work).
