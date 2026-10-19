# win-forest — the whole-range converged capture battery (windows-ad-v1 slice 3)

A two-domain forest builds on the PRODUCTION pipeline in converged mode and a consumer boots the captured forest with cross-domain auth intact. CID band 4180 (consumer render at 4190).

The forest: `dc01` promotes the root (`corp.local`), `dc02` polls the root from its own view and promotes the child (`north.corp.local`, `Install-ADDSDomain -NewDomainNetbiosName NORTH`, DNS delegation created in the parent zone — goad-forest lessons 1 and 2: the child is the long pole at ~467 s and serializes behind the root), `srv02` joins the child. No in-build sysprep anywhere (the slice-2 proof: clones specialize from the generalized golden with fresh SIDs). All reboots are detached with `LastBootUpTime` barriers.

What it proves, in order:

- **F1** the Windows golden installs from digest-pinned eval media into the battery's isolated cache.
- **F2** the forest builds; **F2b/F2c** CONVERGED capture: all three content hosts quiesce (scrub, shutdown, shutoff) at one point, and no disk is copied before the last quiesce — cross-guest domain state (replication, machine accounts, the delegation) captures from a single moment, never a sliding window; **F2d** all three realized images land.
- **F3** the unchanged forest is a cached no-op (converged reuse is all-or-nothing; the no-op is the "all" side, and the unit suite pins the "nothing" side — one guest's edit rebuilds every guest).
- **F4** a consumer boots the captured forest: the member still joined to the child domain, its machine secure channel re-validated (convergence-gated: netlogon re-establishes lazily on a cold boot), the child DC's TRUST channel to the parent verified (`nltest /sc_verify:corp.local`), and cross-domain DC discovery from the member through the delegated DNS chain (`nltest /dsgetdc:corp.local` finds `\\dc01`).
- **F5** teardown leaves nothing.

Media pins ride the environment (`WIN_ISO`, `VIRTIO_ISO`, `NOBLE`). The battery wipes `tmp/` each run: a full run re-installs the golden (~25 min), builds the forest (~20-25 min: root ~4 min, child ~8 min serialized behind it, join, three captures), and boots the consumer.
