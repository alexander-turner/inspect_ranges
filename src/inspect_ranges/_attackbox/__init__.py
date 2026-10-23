"""The attack-box provider seam (`attack-box-v1.md`): an external supplier for one range's dedicated attack box.

The range supplies an L2 attachment point on the foothold's segment (taps built inside the range netns, fds handed over) and routes the attacker's exec to the surface the provider returns; the provider supplies the box behind both and owns its lifecycle. Registration mirrors `INSPECT_RANGES_HOST`: the `INSPECT_RANGES_ATTACK_BOX` value is the registration, persisted as the project's attack-box origin so teardown re-resolves from disk. Selection is deployment knowledge, never `range.yaml`. Scope is dedicated attack boxes only: an assumed-breach foothold is a content guest this project builds and captures, excluded by construction.
"""

from .backend import (
    ENV_VAR,
    AttachedInterface,
    AttackBoxBackend,
    AttackBoxCapabilities,
    AttackBoxContext,
    AttackBoxFactory,
    AttackBoxHandle,
    AttackBoxProvider,
    AttackBoxReclaimFn,
    FootholdAttachment,
    ParsedAttackBox,
    attack_box_origin,
    parse_attack_box,
    resolve_attack_box,
)
from .record import (
    AttackBoxRecord,
    attack_box_record_path,
    read_attack_box_record,
    write_attack_box_record,
)

__all__ = [
    "ENV_VAR",
    "AttachedInterface",
    "AttackBoxBackend",
    "AttackBoxCapabilities",
    "AttackBoxContext",
    "AttackBoxFactory",
    "AttackBoxHandle",
    "AttackBoxProvider",
    "AttackBoxReclaimFn",
    "AttackBoxRecord",
    "FootholdAttachment",
    "ParsedAttackBox",
    "attack_box_origin",
    "attack_box_record_path",
    "parse_attack_box",
    "read_attack_box_record",
    "resolve_attack_box",
    "write_attack_box_record",
]
