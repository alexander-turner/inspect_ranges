# Standard images v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. What "reproducible" means for the attack image (slice-1 review B1, 2026-10-19)

**The fact:** the toolset recipe pins its INPUTS' identities (the recipe digest keys the build; the metasploit repo key fingerprint is pinned; the golden and vendor are digest-pinned), but the apt feeds themselves move daily, so two builds weeks apart produce different bytes from the same recipe digest, under the SAME realized file name (the build key cannot see apt contents). Same-name-different-bytes is the digest-refusal ping-pong class the build records forbid.

**Interim behavior in force (implemented):** every build records what the feeds delivered into the image itself (`/etc/attack-image.manifest`: full dpkg list plus the msf version), asserts a metasploit major-version floor (6.x), and asserts the zero-non-loopback-listener containment invariant, so drift is visible and bounded even though bytes differ.

**The decision parked:** the republish discipline. Recommendation: drift is ACCEPTED between publish days (the catalog ships digests, consumers pin by digest, so published artifacts never drift under anyone); every republish MUST bump `recipe.yaml`'s `version`, which re-keys the build and renames the realized file, so no two publishes ever share a name with different bytes; publish day records the image's dpkg-manifest alongside the catalog entry. Alternative: full apt snapshotting (snapshot.ubuntu.com + a frozen msf mirror), which buys byte-reproducibility at the cost of running a package mirror.

**Also noted (slice-1 review N3):** the realized attack image (~2.9 GB) carries dead qcow2 clusters from deleted package archives; a capture-time sparsify pass would shrink every consumer's pull. Parked as a nice-to-have for the publish-day sizing, not a correctness issue.
