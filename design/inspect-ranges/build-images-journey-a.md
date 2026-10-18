---
type: document
title: "Journey A, written first: an author iterates on vulhub-zabbix"
status: draft
tags: [inspect-ranges, build, images, journeys, usability]
timestamp: 2026-10-17
---

# Journey A, written first: an author iterates on vulhub-zabbix

*The target experience for the range author, written as a terminal session before any of it exists. [build-images-requirements](build-images-requirements.md) section 5.4 makes the three journeys the architecture's usability acceptance test; this document is Journey A's half of that test, and the first vertical slice ([vulhub-zabbix](../../examples/vulhub-zabbix/range.yaml)) builds until this transcript is true. Command names and output formats here are proposals for taste review, not commitments; the sequence and concept count are the contract. Spec syntax follows the provisional grammar in [build-images-spine](build-images-spine.md); whether vulhub's app stack is recipes (shown here) or a prebuilt scenario image is Q4, deferred to its own memo with this range written out both ways.*

## The spec, revised under the proposed grammar

Today's translation smuggles provenance and boot variation into image names (`image: "vulhub/zabbix:3.0.3-server (command: server)"`). Under the spine memo's grammar, `image:` is a logical name resolved against the local cache and then the configured registry, and the app stack becomes explicit provisioning:

```yaml
hosts:
  - name: mysql
    os: { type: linux }
    image: ubuntu-noble          # golden; resolves local cache -> registry
    provisioning:
      - { recipe: vulhub.zabbix-mysql, vars: { root_password: root } }
    services:
      - { name: mysql, port: 3306, version: "5", ... }
```

The recipes live in `./recipes/` beside the range (resolution order per [recipe-references](recipe-references.md)), vendored from upstream vulhub compose/config content.

## The session

The author has the repo, a working `doctor`, and network access to the default registry (`meridianlabsai` on Docker Hub). No Go toolchain, no hand-carried digests, no `daemon-bundle` invocation: builder-only ceremony is gone from this journey.

```console
$ inspect-ranges validate
range.yaml: OK (schema v0.3)

$ inspect-ranges build
resolve   images: ubuntu-noble -> sha256:9f3c1a... (registry: docker.io/meridianlabsai)
resolve   recipes: vulhub.zabbix-mysql, vulhub.zabbix-server, vulhub.zabbix-agent, vulhub.zabbix-web (./recipes)
fetch     ubuntu-noble golden chain: 2 layers, 641 MB, verified
boot      4 guests to ready (34 s)
recipe    mysql: vulhub.zabbix-mysql        ok  41 s
recipe    server: vulhub.zabbix-server      ok  58 s
recipe    agent: vulhub.zabbix-agent        ok  22 s
recipe    web: vulhub.zabbix-web            ok  63 s
verify    services: mysql:3306 ok  zabbix-server:10051 ok  zabbix-agent:10050 ok  zabbix-web:80 ok
verify    vulnerabilities: CVE-2016-10134 ... FAIL
          [vulnerability-not-verified] guest 'web': SQLi probe against latest.php got patched
          behavior (zabbix-web reports 3.0.31, spec declares 3.0.3)
          log: ~/.local/state/inspect-ranges/builds/vulhub-zabbix/web/verify.log
build FAILED: 8 of 9 declarations verified (6 m 10 s)
```

The failure names the guest, the declaration, the observed-versus-declared gap, and the log to open. The author finds the recipe installed the distro's current zabbix-web package, pins it, and rebuilds. Only the changed recipe and its dependents rerun; verification always reruns in full:

```console
$ inspect-ranges build
resolve   unchanged
recipe    web: vulhub.zabbix-web (digest changed)   ok  66 s
recipe    mysql, server, agent: unchanged, skipped
verify    9 of 9 declarations verified
manifest  ~/.cache/inspect-ranges/builds/vulhub-zabbix/manifest.json (sha256:ab12e0...)
build OK (2 m 05 s)
```

The build manifest now exists, so the range stops being a fixture: `up` and the provider instantiate from built, verified artifacts, and every image digest in play is recorded.

```console
$ inspect eval ranges/vulhub-zabbix -T challenge=rce --model anthropic/claude-opus-5-5
```

To poke at a guest by hand between edits (did the plant land, is the service really listening), the existing surface already suffices and stays: `inspect-ranges up`, the console logs, `down`.

## What this transcript commits the design to

- **One new verb carries the journey.** Author iteration is `edit, build, eval`. Whether `build` subsumes `render` and `images derive` internally is Q8's call; the journey requires only that the author never types them.
- **The range directory argument defaults to `.`** (user decision, 2026-10-17): every spec-taking verb (`validate`, `plan`, `render`, `build`) works bare from inside a range directory, uniformly, matching the optional arguments `up` and `down` already have. An explicit path remains available for working across ranges.
- **Verification is the product of the build.** The per-declaration verify report (every service, vulnerability, user, file checked on the real guest, independent of recipe exit status) is the author's primary feedback, and failures carry a stable issue code, the observed-versus-declared delta, and a log path, in the house refusal style.
- **Incremental rebuild is honest.** Rerun cost is proportional to the edit (the spine memo's invalidation algebra is what makes `unchanged, skipped` true rather than hopeful). Verification is all-or-nothing: any change triggers a full re-verify of the whole range, and only a build with every input unchanged may report its recorded verification instead of re-running it (`build --reverify` forces the full pass).
- **No builder ceremony in the author path.** Goldens arrive by verified pull from the configured registry (public default, redirectable to a private mirror per the disconnected-operation requirement); the daemon bundle is an internal detail of the golden, not an author concept.
- **Concept count:** range directory, logical image name, recipe, build, manifest. Five, down from Journey B's current nine-ish, and nothing in the loop requires understanding digests beyond "the manifest pins things".
