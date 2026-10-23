"""Backend selection for `INSPECT_RANGES_ATTACK_BOX`: the grammar, the bundle, and the resolver.

The variable's value IS the registration, exactly as `INSPECT_RANGES_HOST` works (`_host/backend.py`): a dotted import path naming an `AttackBoxFactory`, as `<module>.<factory>[:<config>]`, imported and called at resolution. There are no built-in forms; the variable's absence is the built-in behavior (the realizer renders and boots the attack box itself). The value splits on the FIRST colon, so a config may itself contain colons.

The value is persisted verbatim as the project's attack-box `origin` (`record.py`), and teardown-by-origin re-resolves it through `resolve_attack_box` in whatever process reclaims: `down` foremost, which may run fresh and never saw the driver's environment. Factories and provider constructors must therefore be cheap and must not dial anything: resolution happens in doctor, in `down`, and before `up` touches any docker resource; remote work belongs in the provider's `boot`.

The seam itself is deliberately minimal (every method added is API someone freezes against): an attachment goes in, an exec surface and a teardown obligation come out. The provider's exec surface is held to the daemon wire protocol over a unix socket (the Cloud Hypervisor hybrid-vsock shape, `HybridEndpoint`), which is what makes the published conformance battery, not code review, the gate a provider must pass.
"""

import asyncio
import importlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Protocol

from .._channel.vsock import HybridEndpoint
from .._host.backend import DoctorProbe
from .record import AttackBoxRecord

ENV_VAR = "INSPECT_RANGES_ATTACK_BOX"

_GRAMMAR = "(expected a backend factory as '<module>.<factory>[:<config>]')"


@dataclass(frozen=True)
class AttachedInterface:
    """One L2 attachment point on a foothold segment, built inside the range container's netns.

    The tap is created and enslaved to the segment bridge inside the range netns before the provider sees it; the provider receives only the open fd. The host netns never carries a device for it, and the attachment dies with the fd (the tap is non-persistent) or with the range container's netns, whichever comes first.
    """

    segment: str
    """The attached network's name in the plan."""
    bridge: str
    """The segment bridge device name inside the range netns (a fact; the tap is already enslaved)."""
    tap_fd: int
    """The open tap fd. The provider owns it from handoff: pass it to the VMM and close it on teardown."""
    mac: str
    """The allocated guest MAC the external box MUST present on this segment (addressing and ACLs treat it as this guest)."""
    ip: IPv4Address
    """The allocated interface address the external box MUST take."""
    prefixlen: int
    """The segment prefix length."""
    gateway: IPv4Address | None
    """The segment gateway address, when the segment has one."""


@dataclass(frozen=True)
class FootholdAttachment:
    """What the compiled plan hands an external attack-box provider: attachment in, nothing else.

    Everything here is a plan fact; the provider supplies its own box (image, VMM, hardening) and attaches it behind the taps. `seed_dir` points at the rendered cloud-init seed for the attack box when the bundle carries one; a provider MAY consume it for in-guest network configuration and is never required to.
    """

    project: str
    guest_name: str
    cid: int
    """The guest's plan-reserved control-channel CID: a pure addressing token for exec routing, never a uid or tap-name promise."""
    cpus: int
    memory_mb: int
    interfaces: tuple[AttachedInterface, ...]
    seed_dir: Path | None = None


@dataclass(frozen=True)
class AttackBoxHandle:
    """What a provider's `boot` returns: the exec surface plus a reclaim token, nothing else."""

    exec_endpoint: HybridEndpoint
    """A unix socket serving the daemon wire protocol, one request per connection (the Cloud Hypervisor hybrid-vsock shape); the peer uid is enforced at every dial."""
    reclaim_token: str = ""
    """Opaque provider state persisted in the attack-box record, handed back verbatim at `teardown`."""


class AttackBoxProvider(Protocol):
    """An external supplier of one range's dedicated attack box.

    `boot` receives the attachment and returns the running box's handle; it owns the box's lifecycle from that moment. `teardown` must be idempotent (a crash between the record write and `boot` reclaims a box that never existed) and must tolerate a token from a `boot` that half-completed.
    """

    async def boot(self, attachment: FootholdAttachment) -> AttackBoxHandle: ...

    async def teardown(self, project: str, reclaim_token: str) -> None: ...


@dataclass(frozen=True)
class AttackBoxCapabilities:
    """What the backend declares it can do; a declared gap is recorded as evidence, never silently absent."""

    console_stream: bool = False
    """Whether the provider delivers the attack box's console stream. `False` records a declared gap on `console/<guest>`; `True` is not yet supported (no ingest path) and is refused."""


AttackBoxReclaimFn = Callable[[AttackBoxRecord, Path], None]
"""The teardown-by-origin connector: `(record, state_dir)`; raises on failure, after which `down` refuses to touch the range's own resources (a dead netns strands a live foreign VMM)."""


@dataclass(frozen=True)
class AttackBoxBackend:
    """One resolved backend bundle: the provider plus the hooks the provider protocol alone cannot carry.

    `reclaim` overrides the teardown-by-origin connector; left `None`, teardown runs `provider.teardown` with the recorded token. `doctor_probe` lets `inspect-ranges doctor` check reachability. `capabilities` is the declared-drop surface the evidence record and the conformance battery hold the provider to.
    """

    provider: AttackBoxProvider
    reclaim: AttackBoxReclaimFn | None = None
    doctor_probe: DoctorProbe | None = None
    capabilities: AttackBoxCapabilities = AttackBoxCapabilities()

    def reclaimer(self) -> AttackBoxReclaimFn:
        """The teardown-by-origin connector `down` runs: the explicit `reclaim`, or the provider's own `teardown` with the recorded token."""
        if self.reclaim is not None:
            return self.reclaim
        provider = self.provider

        def provider_reclaim(record: AttackBoxRecord, state_dir: Path) -> None:
            asyncio.run(provider.teardown(record.project, record.reclaim_token))

        return provider_reclaim


@dataclass(frozen=True)
class AttackBoxContext:
    """What an `AttackBoxFactory` is called with."""

    origin: str
    """The full `INSPECT_RANGES_ATTACK_BOX` value, verbatim: what `up` stamps into the attack-box record, so a fresh process re-resolves teardown from disk alone."""
    config: str | None
    """The text after the value's first colon, `None` when absent: the backend's own opaque config."""
    state_dir: Path
    """The shared project state dir (the attack-box record lives under it)."""


AttackBoxFactory = Callable[[AttackBoxContext], AttackBoxBackend]
"""What the dotted path in `INSPECT_RANGES_ATTACK_BOX` names. Must be cheap: no dialing, no probing; remote work belongs in the provider's `boot`."""


@dataclass(frozen=True)
class ParsedAttackBox:
    """One `INSPECT_RANGES_ATTACK_BOX` value, split but not yet resolved."""

    value: str
    """The full value, verbatim: what `up` stamps as the record's origin."""
    head: str
    """The part before the first colon: the factory's dotted import path."""
    config: str | None
    """The part after the first colon (`None` when absent): opaque backend config."""


def parse_attack_box(value: str) -> ParsedAttackBox:
    """Split an `INSPECT_RANGES_ATTACK_BOX` value against the grammar, without importing anything.

    Raises:
        ValueError: The value is not a dotted factory path; the message carries the full grammar.
    """
    head, sep, tail = value.partition(":")
    config = tail if sep else None
    if "." in head and all(part.isidentifier() for part in head.split(".")):
        return ParsedAttackBox(value, head, config)
    raise ValueError(f"unknown {ENV_VAR} backend {value!r} {_GRAMMAR}")


def resolve_attack_box(value: str, state_dir: Path) -> AttackBoxBackend:
    """THE resolver: an `INSPECT_RANGES_ATTACK_BOX` value (or a persisted record origin) to its backend bundle.

    Raises:
        ValueError: The value fits no grammar form, the dotted path does not import or does not name a callable, or the factory returned something other than an `AttackBoxBackend`. A factory's own exception propagates as-is.
    """
    parsed = parse_attack_box(value)
    module_name, _, attr = parsed.head.rpartition(".")
    try:
        module = importlib.import_module(module_name)
    except ImportError as error:
        raise ValueError(
            f"{ENV_VAR}={parsed.value!r}: backend module {module_name!r} does "
            f"not import ({error}); install the package providing it, or fix "
            f"the variable {_GRAMMAR}"
        ) from error
    factory: Any = getattr(module, attr, None)
    if factory is None:
        raise ValueError(
            f"{ENV_VAR}={parsed.value!r}: module {module_name!r} has no "
            f"attribute {attr!r} {_GRAMMAR}"
        )
    if not callable(factory):
        raise ValueError(
            f"{ENV_VAR}={parsed.value!r}: {parsed.head!r} is not callable "
            "(expected an AttackBoxFactory)"
        )
    backend = factory(
        AttackBoxContext(origin=parsed.value, config=parsed.config, state_dir=state_dir)
    )
    if not isinstance(backend, AttackBoxBackend):
        raise ValueError(
            f"{ENV_VAR}={parsed.value!r}: {parsed.head!r} returned "
            f"{type(backend).__name__}, not an AttackBoxBackend"
        )
    return backend


def attack_box_origin() -> str | None:
    """The configured attack-box origin, validated against the grammar; `None` when unset or empty.

    Validation here is parse-only (no import), so a malformed value refuses loudly wherever the origin is first consulted, before any resource exists.

    Raises:
        ValueError: The variable is set but fits no grammar form.
    """
    value = os.environ.get(ENV_VAR)
    if not value:
        return None
    parse_attack_box(value)
    return value
