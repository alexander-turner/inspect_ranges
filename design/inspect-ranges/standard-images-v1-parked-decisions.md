# Standard images v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force. None blocks the slice that parked it.*

## 1. What "reproducible" means for the attack image (slice-1 review B1, 2026-10-19)

**The fact:** the toolset recipe pins its INPUTS' identities (the recipe digest keys the build; the metasploit repo key fingerprint is pinned; the golden and vendor are digest-pinned), but the apt feeds themselves move daily, so two builds weeks apart produce different bytes from the same recipe digest, under the SAME realized file name (the build key cannot see apt contents). Same-name-different-bytes is the digest-refusal ping-pong class the build records forbid.

**Interim behavior in force (implemented):** every build records what the feeds delivered into the image itself (`/etc/attack-image.manifest`: full dpkg list plus the msf version), asserts a metasploit major-version floor (6.x), and asserts the zero-non-loopback-listener containment invariant, so drift is visible and bounded even though bytes differ.

**The decision parked:** the republish discipline. Recommendation: drift is ACCEPTED between publish days (the catalog ships digests, consumers pin by digest, so published artifacts never drift under anyone); every republish MUST bump `recipe.yaml`'s `version`, which re-keys the build and renames the realized file, so no two publishes ever share a name with different bytes; publish day records the image's dpkg-manifest alongside the catalog entry. Alternative: full apt snapshotting (snapshot.ubuntu.com + a frozen msf mirror), which buys byte-reproducibility at the cost of running a package mirror.

**Also noted (slice-1 review N3):** the realized attack image (~2.9 GB) carries dead qcow2 clusters from deleted package archives; a capture-time sparsify pass would shrink every consumer's pull. Parked as a nice-to-have for the publish-day sizing, not a correctness issue.

**DECIDED (user, 2026-10-19): the digest discipline.** Drift accepted between publish days; every republish bumps the recipe version (re-keying the name); publish day records the dpkg manifest alongside the catalog entry. No apt snapshotting.


## 2. When the attacker's image default flips to `attack` (slice 2, 2026-10-19)

**The question:** the schema promises "the backend's standard attack image" for an omitted `Attacker.image`; today that resolves to the router default (`noble-range-guest`). Flipping the default to `attack` before the catalog publishes bricks every offline dev box and every existing battery (the name resolves nowhere); flipping with a silent fallback to the router default violates the deterministic-resolution posture.

**Recommendation:** flip HARD on publish day (slice 4), when `docker.io/meridianlabsai/attack` exists and the Q1 registry tier resolves it everywhere connected; offline hosts pull it once or keep declaring `image: noble-range-guest` explicitly. Until then the default stays as-is, and the battery-proven consumption path (`image: attack` after an `images pull attack`, or the realized file by name) is the opt-in.

**Interim behavior in force:** the default is unchanged; `publish`/`images pull` make `attack` consumable by name on any host that fetched it.

**DECIDED (user, 2026-10-19): ratified**, with publish day imminent and the ordering publish-before-push making the pre-publish window moot.

**Executed (slice 4, 2026-10-19):** the flip landed per the recommendation, as part of the publish-day slice: a dedicated attack box with no `image:` resolves `attack` (routers unchanged), eval init pulls catalog images implicitly so a connected machine needs no explicit fetch, and `INSPECT_RANGES_NEVER_PULL` hosts refuse coded. Window to note: between this commit landing and the user running publish day, a no-image attacker resolves `attack` from a cache or a configured registry only (every in-repo range and battery declares its image, so nothing in the tree is affected); publish day closes the window for the public default path.
