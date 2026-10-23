# Decision: the in-guest brand is `guestd`

**Status: decided (user, 2026-10-23), implemented.** From the first real-model fleet pass, finding 8 ([fleet-pass-2026-10.md](fleet-pass-2026-10.md)): a transcript showed the agent reading `/opt/inspect-ranges` off its own foothold. Every guest carried harness-naming strings an agent could trip over: the daemon's install home and unit, `ir-` prefixed activity units, the terminal tool's sink directory and wait channels (the channel echoes in the pane), the draws file under `/etc/inspect-ranges/`, the exec wrapper scripts' `/tmp/.ir-exec-*` names, and the Windows unattend's registered owner. String-level eval-awareness tells, baked into the captured images.

## The decision

Everything the harness lands inside a guest carries one deliberately boring brand token, `guestd`, held in a single constant module (`_brand.py`). Three principles govern it:

- **One knob.** Every in-guest name derives from the constant; a future rebrand is one edit plus a rebake.
- **Boring-generic, never mimicry.** The token reads like ordinary guest tooling (a guest daemon named like a guest daemon); it never impersonates a real product.
- **Renaming is not hiding.** The posture is honest: an AF_VSOCK listener remains findable by any agent that looks, the daemon binary still carries its `vsockd` identity string on the wire, and this record is public. What the rename removes is the harness NAMING ITSELF to the evaluated agent.

Host-side names (cache directories, CLI verbs, `ir-` project prefixes, bundle/artifact file names, evidence paths) deliberately keep the `inspect-ranges` identity: they never land in a guest, and renaming them would only obscure operator surfaces.

## What changed in-guest

| Surface | Was | Is |
|---|---|---|
| Linux daemon | `/opt/inspect-ranges/vsockd`, `vsockd.service` | `/opt/guestd/guestd`, `guestd.service` (unit description is just `guestd`) |
| Windows daemon | `C:\vsockd`, service `vsockd`, `vsockd.exe` | `C:\guestd`, service `guestd`, `guestd.exe` |
| Activity scripts | `/opt/inspect-ranges/activities`, `C:\ProgramData\inspect-ranges\activities` | the `guestd` equivalents |
| Activity units/tasks | `ir-activity-<guest>-<index>` | the script's sanitized file stem (`benign-admin.timer` reads like admin cruft); same-host stem collisions refuse `activity-name-conflict` at resolution |
| Draws file | `/etc/inspect-ranges/draws.json` | `/etc/guestd/draws.json` (authoring contract: recipes that read it change too) |
| Terminal tool | `/tmp/.ir-terminal`, `ir-done-<session>-<nonce>` channels | `/tmp/.guestd`, `done-<session>-<nonce>` |
| Exec wrapper scripts | `/tmp/.ir-exec-<id>.sh` | `/tmp/.guestd-<id>.sh` |
| Windows unattend | owner/org `inspect-ranges`, daemon-naming command descriptions | `user`/`lab`, neutral descriptions |

Build-time transients that never survive into a captured image (recipe staging names, the goad `.ir-goad-*` scrub-enforced temp files) are unchanged: no agent ever sees them.

## Cost

The daemon bundle's digest moves (member names, installer, unit, Windows service), so every golden re-derives and every build re-keys: a republish day covers the catalog. Versions bumped to mark it: daemon bundle 3.2.0, Linux derive recipe 5, Windows derive recipe 3. Local images and builds refresh on next derive/build; nothing silently mixes old and new names because the derivation key and build keys carry the bundle digest.
