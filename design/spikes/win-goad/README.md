# win-goad — goad-light built, verified, solved (windows-ad-v1 slice 4)

The flagship AD fixture end to end like the Linux examples: the forest (root `sevenkingdoms.local`, child `north.sevenkingdoms.local` with DNS delegation, member `castelblack`) and its full seeded attack surface build on the production pipeline, the behavioral trio proves the ladder against the captured artifacts in-build, and a real eval boots the forest through the provider and scores the reference ladder 1.0/valid through the attack-box foothold with the wall pinned. CID band 4200 (the attack-image factory at 4205).

Staged (`./run.sh prep|build|prove`, no-arg = all): a full run exceeds the 2-hour background bound, so `prep` (wipes `tmp/`, installs the Windows golden, builds the v3 attack image — impacket scripts on PATH — and lands it as the bare `attack` name via publish→pull against a directory location), `build` (the goad build: promotion recipes with locator-gated readiness and detached-reboot barriers, the realize passes driven by `IR_ACTIVE_DIRECTORY`, verify, converged capture, the trio, then the cached no-op check), and `prove` (the eval + teardown) chain over a preserved `tmp/`.

The reference ladder rides DECLARED scenario data only (see the fixture's notes.md Realized addendum): autologon credential → SYSTEM on dc02 → DCSync → pass-the-hash to srv02 → raiseChild child-to-forest escalation → dc01. Kerberoast/ESC1/MSSQL-impersonation surfaces are realized and self-asserted by recipes, deliberately not consumed by the reference.

Media pins ride the environment (`WIN_ISO`, `VIRTIO_ISO`, `NOBLE`).
