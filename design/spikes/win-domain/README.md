# win-domain — the Windows build pipeline battery (windows-ad-v1 slice 2)

A two-guest Windows domain builds on the PRODUCTION build pipeline and a consumer boots the captured pair with the domain intact. CID band 4160 (consumer render at 4170).

What it proves, in order:

- **D1** the Windows golden installs from digest-pinned eval media into the battery's isolated cache (`images derive-windows`), plus the noble golden for the attacker.
- **D2** `inspect-ranges build` realizes the domain: the `win.dc-promote` recipe installs AD DS and promotes a forest (`range.local`) with the promotion reboot launched DETACHED and detected by `LastBootUpTime` change (ad-domain lesson 5); the `win.domain-join` recipe polls the domain's SRV record and LDAP port from the member's own view, joins, rides its own detached reboot, and asserts `Test-ComputerSecureChannel`. No in-build sysprep anywhere: clones specialize from the generalized golden with fresh SIDs, so the ad-domain spike's sysprep-before-join requirement is satisfied by construction on this path — the join succeeding IS the proof. The verify engine attributes all five declared Windows listeners (dns/ldap/kerberos/smb on the DC, smb on the member) through the PowerShell probe, and both guests capture as realized images.
- **D3** an unchanged rebuild is a cached no-op (the Windows build key carries name + addressing, so this also pins that the key is stable).
- **D4** a consumer (`render` + `up` against the build cache) boots the captured pair: daemon readiness, the member still domain-joined, the machine secure channel intact across capture, the build-only resolver scrubbed from the baked DNS (exactly `10.30.0.10` remains), and the DC booting as a primary domain controller (`DomainRole` 5).
- **D5** teardown leaves nothing.

Media pins ride the environment (`WIN_ISO`, `VIRTIO_ISO`, `NOBLE`), defaulting to the shared `~/.cache/inspect-ranges/images` copies. The battery wipes `tmp/` each run, so a full run re-installs the Windows golden (~25 min) before the build (~15 min) and consumer legs.
