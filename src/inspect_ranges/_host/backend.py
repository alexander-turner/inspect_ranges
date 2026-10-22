"""Backend selection for `INSPECT_RANGES_HOST`: the grammar, the bundle, and the resolver.

The variable's value IS the registration. `local` and `uds:<socket>` are the built-in backends; any other value is a dotted import path naming a `HostBackendFactory`, as `<module>.<factory>[:<config>]`, imported and called at resolution (there is no registry dict and no register call to forget in a fresh process). The value splits on the FIRST colon, so a config may itself contain colons.

The value is also persisted verbatim as each lease's `origin` (`leases.py`), and teardown-by-origin re-resolves it through `resolve_host_backend` in whatever process does the reclaiming: the reaper foremost, which runs fresh and never saw the driver's environment. A self-describing origin makes that work by import alone; the only cross-process requirement is that the backend's package is installed where the reclaiming process runs. Factories and provider constructors must therefore be cheap and must not dial anything: resolution happens in doctor, in the reaper, and at provider-runtime construction, and remote work belongs in `acquire`.
"""

import importlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .host import HostProvider
from .leases import HostLease
from .seams import ChannelForLease, channel_teardown

ReclaimFn = Callable[[HostLease, Path], None]
"""The reaper's teardown-by-origin connector: `(lease, state_dir)`; raises on failure, after which the lease stays `reaping` and the next sweep retries."""

DoctorProbe = Callable[[], str | None]
"""An optional reachability probe for `inspect-ranges doctor`: `None` when healthy, else the failure detail."""

_GRAMMAR = (
    "(expected 'local', 'uds:<socket>', or a backend factory as "
    "'<module>.<factory>[:<config>]')"
)


@dataclass(frozen=True)
class ParsedHostBackend:
    """One `INSPECT_RANGES_HOST` value, split but not yet resolved."""

    kind: Literal["local", "uds", "custom"]
    value: str
    """The full value, verbatim: what a provider stamps as the lease origin."""
    head: str
    """The part before the first colon: the backend name, or the factory's dotted import path."""
    config: str | None
    """The part after the first colon (`None` when absent): the socket path for `uds`, opaque backend config otherwise."""


@dataclass(frozen=True)
class HostBackendContext:
    """What a `HostBackendFactory` is called with."""

    origin: str
    """The full `INSPECT_RANGES_HOST` value, verbatim. The backend's provider MUST stamp it as each lease's `origin` (`LeaseStore.acquire(origin=...)`), so a fresh process can re-resolve teardown from disk alone; extra placement data rides inside the config portion of the value."""
    config: str | None
    """The text after the value's first colon, `None` when absent: the backend's own opaque config."""
    state_dir: Path
    """The shared state dir (`leases.json` and the CID registry live here); hand it to `LeaseStore` to reuse the lease machinery."""


@dataclass(frozen=True)
class HostBackend:
    """One resolved backend bundle: the provider plus the hooks a `HostProvider` alone cannot carry.

    `channel_for_lease` is `None` for a co-resident backend (the runtime keeps its local `up`/`down`/channel seams); a separated backend supplies it and the runtime derives the swapped seams from it (`seams.py`). `reclaim` overrides the reaper's teardown-by-origin connector; left `None`, a separated backend gets the channel-teardown default and a co-resident one the reaper's direct `down`. `doctor_probe` lets `inspect-ranges doctor` check reachability.
    """

    provider: HostProvider
    channel_for_lease: ChannelForLease | None = None
    reclaim: ReclaimFn | None = None
    doctor_probe: DoctorProbe | None = None

    @property
    def separated(self) -> bool:
        """Whether the backend reaches its host through a channel rather than running co-resident."""
        return self.channel_for_lease is not None

    def reclaimer(self) -> ReclaimFn | None:
        """The teardown-by-origin connector the reaper runs: the explicit `reclaim`, the channel-teardown default for a separated backend, or `None` for a co-resident one (the reaper's direct `down` applies)."""
        if self.reclaim is not None:
            return self.reclaim
        if self.channel_for_lease is None:
            return None
        channel_for_lease = self.channel_for_lease

        def channel_reclaim(lease: HostLease, state_dir: Path) -> None:
            channel_teardown(channel_for_lease, lease)

        return channel_reclaim


HostBackendFactory = Callable[[HostBackendContext], HostBackend]
"""What a custom backend exports under the dotted path `INSPECT_RANGES_HOST` names. Must be cheap: no dialing, no probing; remote work belongs in the provider's `acquire`."""


def parse_host_backend(value: str) -> ParsedHostBackend:
    """Split an `INSPECT_RANGES_HOST` value against the grammar, without importing anything.

    Raises:
        ValueError: The value fits no grammar form; the message carries the full grammar.
    """
    head, sep, tail = value.partition(":")
    config = tail if sep else None
    if head == "local":
        if config is not None:
            raise ValueError(
                f"INSPECT_RANGES_HOST={value!r}: the local backend takes no "
                f"config {_GRAMMAR}"
            )
        return ParsedHostBackend("local", value, head, None)
    if head == "uds":
        if not config:
            raise ValueError(
                f"INSPECT_RANGES_HOST={value!r}: the uds backend needs a "
                f"socket path {_GRAMMAR}"
            )
        return ParsedHostBackend("uds", value, head, config)
    if "." in head and all(part.isidentifier() for part in head.split(".")):
        return ParsedHostBackend("custom", value, head, config)
    raise ValueError(f"unknown INSPECT_RANGES_HOST backend {value!r} {_GRAMMAR}")


def resolve_host_backend(value: str, state_dir: Path) -> HostBackend:
    """THE resolver: an `INSPECT_RANGES_HOST` value (or a persisted lease origin) to its backend bundle.

    The built-ins resolve through the same bundle shape as third parties, so every dispatch site (the provider runtime, the reaper, doctor) sees one interface.

    Raises:
        ValueError: The value fits no grammar form, the dotted path does not import or does not name a callable, or the factory returned something other than a `HostBackend`. A factory's own exception propagates as-is.
    """
    parsed = parse_host_backend(value)
    if parsed.kind == "local":
        from .local import LocalHostProvider

        return HostBackend(provider=LocalHostProvider(state_dir))
    if parsed.kind == "uds":
        assert parsed.config is not None  # parse guarantees a socket
        return _uds_backend(Path(parsed.config), state_dir)
    return _custom_backend(parsed, state_dir)


def _uds_backend(socket_path: Path, state_dir: Path) -> HostBackend:
    """The built-in separated backend: a running applier behind a unix socket."""
    from .remote import RemoteHostProvider, uds_channel_for_lease

    channel_for_lease = uds_channel_for_lease(socket_path)

    def reclaim(lease: HostLease, state_dir_arg: Path) -> None:
        # prefer teardown through the applier (it also releases the applier's
        # admission charge and relay map); on connect failure fall back to
        # direct down, which is correct ONLY because a uds host is this
        # machine - a custom remote backend never inherits this fallback.
        # The connector runs only under the reaper, so its warning stays on
        # the reaper's logger
        try:
            channel_teardown(channel_for_lease, lease)
        except Exception as error:
            logging.getLogger("inspect_ranges.reaper").warning(
                "reaper: applier teardown of lease=%s project=%s failed (%s); "
                "falling back to direct down (a live applier's admission "
                "charge leaks until restart)",
                lease.lease_id,
                lease.project,
                error,
            )
            from .._runtime.down import down as run_down

            run_down(lease.project, state_dir=state_dir_arg)

    return HostBackend(
        provider=RemoteHostProvider(socket_path, state_dir),
        channel_for_lease=channel_for_lease,
        reclaim=reclaim,
    )


def _custom_backend(parsed: ParsedHostBackend, state_dir: Path) -> HostBackend:
    """Import the dotted path and call the factory it names."""
    module_name, _, attr = parsed.head.rpartition(".")
    try:
        module = importlib.import_module(module_name)
    except ImportError as error:
        raise ValueError(
            f"INSPECT_RANGES_HOST={parsed.value!r}: backend module "
            f"{module_name!r} does not import ({error}); install the package "
            f"providing it, or fix the variable {_GRAMMAR}"
        ) from error
    factory: Any = getattr(module, attr, None)
    if factory is None:
        raise ValueError(
            f"INSPECT_RANGES_HOST={parsed.value!r}: module {module_name!r} "
            f"has no attribute {attr!r} {_GRAMMAR}"
        )
    if not callable(factory):
        raise ValueError(
            f"INSPECT_RANGES_HOST={parsed.value!r}: {parsed.head!r} is not "
            "callable (expected a HostBackendFactory)"
        )
    backend = factory(
        HostBackendContext(
            origin=parsed.value, config=parsed.config, state_dir=state_dir
        )
    )
    if not isinstance(backend, HostBackend):
        raise ValueError(
            f"INSPECT_RANGES_HOST={parsed.value!r}: {parsed.head!r} returned "
            f"{type(backend).__name__}, not a HostBackend"
        )
    return backend
