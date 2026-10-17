---
type: document
title: "Journey B, written first: prebuilt ranges are published, mirrored, and consumed without building"
status: draft
tags: [inspect-ranges, build, images, distribution, journeys, usability]
timestamp: 2026-10-17
---

# Journey B, written first: prebuilt ranges are published, mirrored, and consumed without building

*The target experience for consuming prebuilt ranges, written as terminal sessions before any of it exists, in the manner of [Journey A](build-images-journey-a.md). This covers the eval runner (Journey B proper) plus the two moves that enable it, publishing and mirroring; the rest of the operator's Journey C (CI as the pin authority, prune/GC) comes later. Command names and output are proposals for taste review; the sequence, the concept count, and the two user decisions recorded below are the contract.*

## The registry posture (user, 2026-10-17)

**The public org carries reusable bases; deployments run their own registry; none of it is strictly required.** `docker.io/meridianlabsai` holds only the reusable upstream tier: goldens, the daemon bundle, common recipes. It is the out-of-box default so the zero-setup case works, and it is where this project's own publisher (Q11) pushes. The registry configuration is an ordered search path with the public org as the default fallback: a connected deployment sets up its own registry, prepends it, and pushes its own built ranges to it, letting base images fall through to the public org with no mirroring required (first match wins, so the deployment's artifacts shadow public names deterministically, and user ranges never land anywhere public). Mirroring the public org into the private registry remains the move for disconnected fleets and for deployments that want no runtime dependency on Docker Hub. A registry is never strictly required: Journey A is fully local (build, then eval, nothing pulled or pushed), and the OCI-layout directory form is a zero-infrastructure registry where even that setup is too much.

## Two decisions this journey builds on (user, 2026-10-17)

**A registry location has three interchangeable forms.** Everywhere a registry appears (`push --to`, `mirror --to/--from`, `pull`, the configured default) the location may be: the public hub (`docker.io/meridianlabsai`, the simple default), a private OCI registry (ECR or similar, for redirected and disconnected fleets), or a plain directory in standard OCI image-layout format. The directory form is the registry-less shape: tar it, scp it, carry it across an air gap, and it still verifies blob-by-blob because the integrity contract ([image-distribution](image-distribution.md)) never depended on the transport.

**`pull` is spec-driven by default, over the normalized spec.** Run bare in a range directory (the `.` default, as everywhere), `pull` reads `range.yaml`, computes the content hash of its normalized form (the compiler's existing normalization, so comment and formatting edits do not de-match; semantic edits do), and looks up a published build manifest for that range name whose recorded normalized-spec hash matches exactly. The spec travels by git like the code it is; the registry carries only built artifacts; the spec hash is the join between them. An exact semantic match is required: a build of a different spec is a different range, and the refusal says so rather than guessing. The explicit `name@sha256:...` form remains for pulling without a spec in hand.

**Pulling is seamless at eval time; the explicit verb is preflight.** Following the Docker provider's precedent, the resolve-verify-fetch runs in the provider's `task_init` (which already exists and already resolves the plan so a broken range fails at startup): once per distinct sandbox config, never in `sample_init`, with samples sharing the materialized cache (concurrent pullers already converge by digest under the cache ownership rules). Placement in `task_init` is load-bearing for UX, verified against inspect-ai: the eval runner cycles through sandbox configs serially with the task display suspended, so pull progress and failures are plainly visible up front before the eval UI comes up, and a missing or mismatched build aborts the run before any sample starts. The cheap part runs every eval (normalized-spec hash is milliseconds, the registry resolve is one small request, cache-hit verification uses the existing sidecar discipline rather than re-hashing multi-GB blobs); the expensive part (blob fetch and full digest verification) runs only on a cache miss, exactly when the user would otherwise have had to type `pull`. The explicit `pull` verb remains for prefetching ahead of a run, warming CI and fleet images, and staging air-gap archives, and a config knob can pin a host to never-pull for strict offline posture.

## The sessions

### Publishing (the builder, after Journey A ends)

```console
$ inspect-ranges push
manifest  vulhub-zabbix (spec sha256:77ab41...) -> registry.acme-evals.net/ranges
layers    3 already on registry, 5 uploaded (1.1 GB)
push OK   vulhub-zabbix@sha256:ab12e0...
```

`push` reads the current directory's build manifest and uploads its transitive closure to the configured registry (the deployment's own; pushing to the public org is the project publisher's job, not a user move). Layers the registry already holds because the public org was mirrored into it (the noble vendor base, the golden) are not re-sent. The printed `name@digest` is the range's publishable identity. `push` mints no image names: making one of the range's realized guests consumable by other ranges' `image:` lines is the separate, deliberate `publish` act ([scenario-vs-recipes](build-images-scenario-vs-recipes.md)).

### Consuming, connected (Journey B proper)

```console
$ git clone https://github.com/meridianlabs-ai/ranges && cd ranges/vulhub-zabbix
$ inspect-ranges pull
resolve   spec sha256:77ab41... -> vulhub-zabbix@sha256:ab12e0... (docker.io/meridianlabsai)
fetch     7 blobs, 1.6 GB, verified
pull OK
$ inspect eval . -T challenge=rce --model anthropic/claude-opus-5-5
```

Nothing was built, derived, or hand-pinned on this machine; render runs inside the provider. The explicit `pull` is optional preflight: skipping it and running `inspect eval` directly triggers the same resolve-verify-fetch at provider init, so the minimal connected journey is `git clone`, `inspect eval`. If the local spec has been semantically edited past every published build, the refusal is explicit (at `pull`, or at eval init before any sample starts), in the house style:

```console
$ inspect-ranges pull
[no-build-for-spec] registry has builds of 'vulhub-zabbix' but none matching this
range.yaml (nearest: sha256:ab12e0..., built 2026-10-17 from spec 77ab41...)
hint: run 'inspect-ranges build' for the edited spec, or check out the spec revision
matching a published build
```

### Mirroring (the operator, both forms)

Seeding a deployment's own registry from the public org (the encouraged setup move, and the recurring sync as the org publishes new bases):

```console
$ inspect-ranges mirror --from docker.io/meridianlabsai \
    --to registry.acme-evals.net/ranges
mirror    12 artifacts: 9 already present, 3 copied (verified)
```

To a directory, for the air gap; the archive is a standard OCI layout, so it tars and ships like any file tree:

```console
$ inspect-ranges mirror vulhub-zabbix@sha256:ab12e0... --to ./ranges-archive
$ tar czf ranges-archive.tgz ranges-archive    # sneakernet from here
```

`mirror` takes either a whole location (seed or sync everything, as in the first example) or a single build manifest (as in the second); a manifest always carries its transitive closure, which is what makes the copy complete by construction.

### Consuming a range built by another group

The near-universal cross-group move (user, 2026-10-17): another group built and published a range in their registry, and you want it in yours. `mirror` is spec-driven exactly like `pull`, so from the range directory it is one command:

```console
$ cd ranges/their-range            # from the other group's git repo
$ inspect-ranges mirror --from registry.other-group.net/ranges \
    --to registry.acme-evals.net/ranges
resolve   spec sha256:3c91e4... -> other-group/their-range@sha256:f00d12...
mirror    9 blobs: 6 already present (shared bases), 3 copied (2.1 GB, verified)
```

Efficiency here is structural, not best-effort: digest dedup means blobs the destination already holds (the vendor base and golden layers every range shares) are never re-sent, so what actually moves is the range's scenario deltas, recipes, and checkpoint members; the chained-layer publication format is what keeps that remainder small. Blobs stream from source to destination without materializing a local copy of the whole set, and everything is digest-verified in flight. After the mirror, the range resolves from your own registry like anything you built: `pull` or plain `inspect eval` from the range directory.

### Consuming, disconnected

The client is configured once to look at the mirror instead of the public hub (`registry` in config or `INSPECT_RANGES_REGISTRY`; the private ECR and the unpacked archive directory are equally valid values), and the session is then identical to the connected one:

```console
$ inspect-ranges pull           # resolves and fetches from the configured mirror
$ inspect eval . ...
```

Pre-seeded delivery is this same move performed by the fleet image instead of the user: bake the pulled cache into the AMI and `pull` becomes a no-op verification pass.

## What this transcript commits the design to

- **One location type, three forms.** Public hub, private registry, OCI-layout directory, interchangeable everywhere a registry location appears. No separate "archive" subsystem exists.
- **The normalized spec hash is the join.** Specs travel by git, artifacts by registry, and `pull` connects them by exact normalized-spec-hash match against the build manifest. The build manifest also embeds the spec it was built from, so a pulled artifact set is always recoverable to source even without the git checkout.
- **Pull is implicit in `task_init`, explicit for preflight.** The provider auto-pulls in `task_init`, before the eval UI comes up, visibly and serially per sandbox config (Docker-provider precedent, verified against inspect-ai's startup sequencing); warm-path overhead is a spec hash plus one registry resolve plus sidecar-verified cache hits, never a re-hash of multi-GB blobs. A never-pull knob exists for strict offline hosts.
- **Redirection is one knob.** A single configured registry location (with the public org as default) redirects every reference; nothing in any spec or manifest names a registry host.
- **Verification is unconditional.** Every blob verifies against its manifest digest on every path (push, mirror, pull, pre-seeded), including out of a directory archive.
- **Transfers render rich progress, modeled on `docker pull`** (user decision, 2026-10-17). Every long-running transfer (`pull`, `push`, `mirror`, and the auto-pull in `task_init`) renders the docker-pull shape: one live line per blob keyed by short digest, with explicit states (`Waiting`, `Downloading` with a bar plus bytes/rate, `Verifying`, `Complete`, and `Already exists` for dedup hits, which makes the layer-sharing economics visible to the user), concurrent lines for parallel streams, and a final `name@digest` line naming what was materialized. The `task_init` placement is what makes this possible at eval time: the display is suspended, so the progress UI owns the terminal before the eval UI comes up. Non-TTY contexts (CI logs) degrade to periodic plain-text progress lines, and failures always end with the house-style coded refusal, never a bare traceback under a half-drawn bar.
- **Concept count for the eval runner:** range directory and `eval`, with `pull` and one config knob (where to pull from) as the only optional extras. The builder-era ceremony (vendor pins, daemon digests, derive) appears nowhere.
