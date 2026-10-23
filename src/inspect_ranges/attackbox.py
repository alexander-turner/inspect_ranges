"""The attack-box extension point: implement and register an external provider for a range's dedicated attack box.

A provider is registered by the environment variable itself: `INSPECT_RANGES_ATTACK_BOX=<module>.<factory>[:<config>]` names an `AttackBoxFactory` that is imported and called at resolution, and the same value is persisted verbatim as the project's attack-box `origin`, so a fresh process re-resolves teardown from disk alone wherever the provider's package is installed. The factory returns an `AttackBoxBackend` bundle: an `AttackBoxProvider` (boot, teardown), an optional teardown-by-origin `reclaim` connector, an optional doctor probe, and the declared `AttackBoxCapabilities`.

The contract is proof obligations, not plumbing: the range hands `boot` a `FootholdAttachment` (taps created inside the range container's netns with the fds passed over, plus the allocated MAC/IP facts the box must present), and the provider returns an `AttackBoxHandle` whose `exec_endpoint` is a unix socket serving the daemon wire protocol, one request per connection, peer-uid enforced at every dial. A provider boots when it passes the published attack-box conformance battery (`inspect-ranges attackbox verify`): the foothold wall holds, the attacker-surface sweep is clean, the exec surface passes the sandbox `self_check` suite, readiness and teardown behave, and evidence drops are declared. A range with an external attack box carries the weaker of the two containment stories; the battery is the floor, stated in the eval's record, never implied away.
"""

from ._attackbox import (
    ENV_VAR,
    AttachedInterface,
    AttackBoxBackend,
    AttackBoxCapabilities,
    AttackBoxContext,
    AttackBoxFactory,
    AttackBoxHandle,
    AttackBoxProvider,
    AttackBoxReclaimFn,
    AttackBoxRecord,
    FootholdAttachment,
    attack_box_origin,
    parse_attack_box,
    resolve_attack_box,
)
from ._channel.vsock import HybridEndpoint
from ._host.backend import DoctorProbe

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
    "DoctorProbe",
    "FootholdAttachment",
    "HybridEndpoint",
    "attack_box_origin",
    "parse_attack_box",
    "resolve_attack_box",
]
