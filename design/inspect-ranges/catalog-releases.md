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
