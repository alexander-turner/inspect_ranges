# win-telemetry — the defense-telemetry tier battery (windows-ad-v1 slice 5)

The attack-range-windows pair builds on the production pipeline and its detection challenge proves end to end — the FIRST detection-bearing build. CID band 4210 (the attack factory at 4212).

The pair: `splunk` (ubuntu-noble, Splunk Enterprise 10.2.2 from the digest-pinned .deb, receiving on 9997, the collector's export wrapper installed with its credential in a root-only file) and `win` (Server 2022, recipe-authored sysmon config, the digest-pinned universal forwarder shipping Sysmon/Security/PowerShell to the splunk host, RDP + the declared SMB exec surface). The telemetry flow is declared in `defense:` (the slice's narrow gate lift: telemetry-bearing postures only) and bound to a real export by `collectors.yaml`, consumed identically by the build trio and the eval.

What it proves, in order:

- **T1** goldens + the attack image into the battery cache.
- **T2** the pair builds; **T2b** mixed-OS converged capture (one Linux + one Windows content host, quiesced=2 — the first Linux guest through the converged quiesce path); **T2c** verify attributes the surface mechanically (splunk-enterprise 10.2.2 via dpkg, 9997, rdp, smb); **T2d** the detection trio: reference fires T1003.001 (comsvcs MiniDump on lsass over the SMB exec path, as SYSTEM via schtasks) and scores 1.0 from the exported stream; insufficient does real admin work without touching LSASS and scores 0.0 over a COMPLETE, FLOWING window; forged writes the signal text (base64-shielded — process-create logging would otherwise forward the forgery's own command line) into an uncollected file and scores 0.0, proving the collector binding.
- **T3** the unchanged fixture is a cached no-op.
- **T4** a real eval boots the captured pair through the provider, plants through the Windows oracle, holds the wall (`sandbox("win")` lands on the attack box), replays the technique, and the detection goal scores 1.0/valid from the same `collectors.yaml`.
- **T5** teardown leaves nothing.

Staged (`prep|build|prove`, no-arg = all) under the 2-hour background bound; `tmp/` wiped by `prep` only. Media pins ride the environment (`WIN_ISO`, `VIRTIO_ISO`, `NOBLE`); the Splunk/forwarder/Sysmon artifacts are URL+sha256-pinned in the recipes (Sysmon's URL is rolling — the recorded cadence fact).
