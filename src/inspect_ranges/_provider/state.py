"""Run-scoped provider state: the sample registry and the injectable runtime.

`ProviderRuntime` lives on Inspect's `SandboxLifecycleState` (keyed by class, default-constructed on first use), the one registry visible across `task_init`, every sample, and `task_cleanup` of a batch; a `ContextVar` bound in `sample_init` would never reach `task_cleanup`. The up/down/render/channel seams are mutable attributes defaulting to the real functions (the `runner=` pattern), so lifecycle tests inject fakes by mutating the scope's instance.
"""

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from inspect_ai.util._sandbox.lifecycle import (
    SandboxLifecycleState,
    sandbox_lifecycle_state,
)

from .._build.manifest import (
    apply_build_manifest,
    default_build_cache,
    realized_backings,
)
from .._channel.channel import MessageChannel
from .._channel.vsock import HybridEndpoint
from .._compiler.plan import PlanOptions, ResolvedPlan, Totals, resolve_plan
from .._compiler.render import render_bundle
from .._host.host import HostProvider, RangeHost
from .._host.reaper import OriginResolver
from .._runtime.down import DownResult, down

# the canonical default lives in the (light) runtime layer so CLI commands
# share it without importing the provider stack; re-exported here for the
# provider-side consumers
from .._runtime.images import default_image_cache as default_image_cache
from .._runtime.ownership import default_state_dir
from .._runtime.up import OnStage, UpOptions, UpResult, up
from ..types import RangeSpec
from .admission import HostCapacity, WeightedAdmission
from .naming import CidAllocator
from .retry import RetryConfig, RetryStats

if TYPE_CHECKING:
    from .._challenges.plants import PlantStore
    from .._channel.channel import Transport
    from .._host.backend import HostBackend
    from .evidence import EvidenceSession

logger = logging.getLogger("inspect_ranges.provider")

UpFn = Callable[[Path, UpOptions, OnStage | None], UpResult]
"""The boot seam. The third argument observes stage events (`evidence-v1.md`'s `stages`/`verify` streams and clock-offset pairs): the local backend passes it to `up(on_stage=...)` (host emit clocks), the uds backend invokes it per folded stage report (driver receive clocks). `None` when evidence is off."""
DownFn = Callable[[str, Path], DownResult]
RenderFn = Callable[["RangeSpec", Path, PlanOptions | None], ResolvedPlan]
ChannelFactory = Callable[
    [dict[str, int], str, dict[str, HybridEndpoint]], MessageChannel
]
"""(guest CIDs, label, hybrid-vsock sockets of Cloud Hypervisor guests) -> channel."""


def _default_channel_factory(
    cids: dict[str, int], label: str, hybrid_sockets: dict[str, HybridEndpoint]
) -> MessageChannel:
    from .._channel.vsock import VsockTransport

    transport: "Transport" = VsockTransport(cids, hybrid_sockets=hybrid_sockets)
    return MessageChannel(transport, label=label)


def _default_up(bundle: Path, options: UpOptions, on_stage: OnStage | None) -> UpResult:
    return up(bundle, options, on_stage=on_stage)


def _default_down(project: str, state_dir: Path) -> DownResult:
    return down(project, state_dir=state_dir)


def _default_resolve_origin(origin: str, state_dir: Path) -> "HostBackend":
    """The reaper's resolver (`resolve_host_backend`), imported lazily like `_install_backend`'s."""
    from .._host.backend import resolve_host_backend

    return resolve_host_backend(origin, state_dir)


@dataclass
class SampleHandle:
    """Everything one sample's cleanup needs, registered BEFORE anything boots."""

    project: str
    task_name: str
    staging: Path
    totals: Totals
    cid_base: int
    guest_cids: dict[str, int] = field(default_factory=dict[str, int])
    guest_sockets: dict[str, HybridEndpoint] = field(
        default_factory=dict[str, HybridEndpoint]
    )
    """Hybrid-vsock sockets of the Cloud Hypervisor guests (QEMU guests are reached by CID)."""
    channel: MessageChannel | None = None
    sessions: dict[str, str] = field(default_factory=dict[str, str])
    stats: RetryStats = field(default_factory=RetryStats)
    retry: RetryConfig = field(default_factory=RetryConfig.from_env)
    booted: bool = False
    deferred: bool = False
    admission_charged: bool = False
    host: RangeHost | None = None
    """The sample's leased host, set between render and boot; `None` again once the lease is released."""
    evidence: "EvidenceSession | None" = None
    """The sample's evidence session (`evidence-v1.md`), `None` when evidence is off; finalized by `_destroy` before `down`."""
    plan: ResolvedPlan | None = None
    """The sample's resolved plan, set at `sample_init`; the oracle's `resolved()` reads it (`challenges-v1.md`)."""
    spec: "RangeSpec | None" = None
    """The sample's validated range spec, set beside `plan`; the oracle's `range_spec()` reads it for declared variables and scenario content (`challenges-v1.md`). Carries the resolved per-instance values once the generation layer lands."""
    plants: "PlantStore | None" = None
    """The sample's plant store, created lazily by the oracle factory; plant VALUES live only here, in memory (`challenges-v1.md`)."""
    draws: dict[str, int | str] = field(default_factory=dict[str, int | str])
    """The sample's drawn variable values (variable-draws-v0), set before render so the bundle's draws file and scoring read the same values; empty when the range declares no `draw: boot` variables."""
    draw_seed: str | None = None
    """The seed the sample's draws derive from, recorded with the values on the `draws` evidence stream; `None` when nothing draws."""


def ensure_pulled(spec: "RangeSpec", *, image_cache: Path) -> None:
    """The implicit resolve-verify-fetch at init (Journey B): once per distinct sandbox config, before the eval UI comes up, with docker-pull-shaped progress; the warm path costs one spec hash plus artifact-presence checks and zero network. Failures surface as inspect's clean prerequisite refusals (the coded message, never a traceback) and abort the run before any sample starts."""
    from .._build.recipes import default_recipe_cache
    from .._dist.errors import DistError
    from .._dist.progress import TransferDisplay
    from .._dist.resolve import ensure_build_available, ensure_images_available

    display = TransferDisplay()
    try:
        report = ensure_build_available(
            spec,
            image_cache=image_cache,
            build_cache=default_build_cache(),
            recipe_cache=default_recipe_cache(),
            progress=display,
        )
        # the catalog tier: images outside the build closure (the attacker's
        # default `attack`, bare-name goldens) pull the same implicit way, so
        # a clean machine's first eval needs no explicit pull verbs
        pulled_images = ensure_images_available(
            spec, image_cache=image_cache, progress=display
        )
    except DistError as error:
        display.close()
        raise _prerequisite(str(error)) from error
    if report is not None:
        display.final(f"pull OK   {spec.meta.name}@{report.root} ({report.location})")
    if pulled_images:
        display.final(f"pull OK   catalog image(s): {', '.join(pulled_images)}")


def _prerequisite(message: str) -> Exception:
    """Inspect renders `PrerequisiteError` as the bare message (the docker provider's init precedent); the private-API pin is isolated with a fallback like the repo's other inspect pins."""
    try:
        from inspect_ai._util.error import PrerequisiteError

        return PrerequisiteError(message)
    except ImportError:  # the pin's fallback: the coded error still carries it all
        from .._dist.errors import DistError

        return DistError("init", message)


class ProviderRuntime:
    """One eval batch's provider state (seams, config, registry); default-constructible for `SandboxLifecycleState.get`."""

    def __init__(self) -> None:
        self.retry_config = RetryConfig.from_env()
        self.image_cache = default_image_cache()
        self.state_dir = default_state_dir()
        self.capacity = HostCapacity.measure()
        self.up_fn: UpFn = _default_up
        self.down_fn: DownFn = _default_down
        self.render_fn: RenderFn = render_bundle
        self.channel_factory: ChannelFactory = _default_channel_factory
        self.resolve_origin: OriginResolver = _default_resolve_origin
        """`cli_cleanup`'s teardown-by-origin seam: a host lease's recorded origin to its backend bundle, the same resolution the reaper runs (`_reap_one`); tests inject fakes."""
        self.registry: dict[str, SampleHandle] = {}
        self.host_backend = os.environ.get("INSPECT_RANGES_HOST", "local")
        self._admission: WeightedAdmission | None = None
        self._allocator: CidAllocator | None = None
        self._host_provider: HostProvider | None = None
        self._resolved: dict[
            str | RangeSpec,
            tuple[RangeSpec, ResolvedPlan, frozenset[str], dict[str, tuple[str, str]]],
        ] = {}
        self._backend: "HostBackend | None" = None
        self._backend_value: str | None = None
        # the backend resolves at construction, not lazily: an unresolvable
        # value must refuse here, before admission, CID lease, and render,
        # and a separated backend's derived seams must install for paths
        # that never touch host_provider (cli_cleanup foremost), or the
        # backend's host-side state (the applier's admission charge and
        # relay map foremost) leaks silently behind a direct down
        self._install_backend()

    def _install_backend(self) -> None:
        """Resolve `host_backend` to its bundle and, for a separated backend, swap in the channel-derived seams.

        Raises:
            ValueError: The value names a backend that does not resolve.
        """
        from .._host.backend import resolve_host_backend
        from .._host.seams import derive_channel_seams

        self._backend = resolve_host_backend(self.host_backend, self.state_dir)
        self._backend_value = self.host_backend
        if self._backend.channel_for_lease is not None:
            self.up_fn, self.down_fn, self.channel_factory = derive_channel_seams(
                self._backend.channel_for_lease, self.state_dir
            )

    def _resolved_backend(self) -> "HostBackend":
        """The current bundle, re-resolved when a test flipped `host_backend` after construction (so the matching seams install too)."""
        if self._backend is None or self._backend_value != self.host_backend:
            self._install_backend()
        assert self._backend is not None
        return self._backend

    @property
    def backend_separated(self) -> bool:
        """Whether the selected backend reaches its host through a channel (teardown must route through the backend; local capture is unavailable)."""
        return self._resolved_backend().separated

    @property
    def admission(self) -> WeightedAdmission:
        """The weighted gate, constructed lazily inside the event loop that uses it."""
        if self._admission is None:
            self._admission = WeightedAdmission(self.capacity)
        return self._admission

    @property
    def allocator(self) -> CidAllocator:
        if self._allocator is None:
            self._allocator = CidAllocator(self.state_dir)
        return self._allocator

    @property
    def host_provider(self) -> HostProvider:
        """The lease-granting backend `INSPECT_RANGES_HOST` selects (default `local`); mutable like the other seams. For a separated backend the derived channel seams (re-)install here too, so a test that flips `host_backend` after construction gets the matching seams.

        Raises:
            ValueError: The variable names a backend that does not resolve.
        """
        if self._host_provider is None:
            self._host_provider = self._resolved_backend().provider
        return self._host_provider

    @host_provider.setter
    def host_provider(self, provider: HostProvider) -> None:
        self._host_provider = provider

    def staging_root(self) -> Path:
        """The sweep-visible staging root (`down --all` clears leftovers after a SIGKILL)."""
        root = self.state_dir.parent / "staging"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def resolve_config(
        self, config: "str | RangeSpec", resolver: Callable[[], RangeSpec]
    ) -> tuple[RangeSpec, ResolvedPlan, frozenset[str], dict[str, tuple[str, str]]]:
        """The validated spec, base plan, and realized sections for one config, resolved once per batch.

        Keyed by the config path or the (hashable) `RangeSpec` itself; `resolver` runs only on a miss, so per-sample YAML loads and plan resolution happen once per task rather than once per sample. The build-aware gate applies here (build-v1 slice 6): a spec with guest content consumes its build manifest (hosts swap to the captured realized images; the manifest's sections count as realized at planning) or refuses `range-not-built` before anything boots.
        """
        cached = self._resolved.get(config)
        if cached is not None:
            return cached
        spec = resolver()
        ensure_pulled(spec, image_cache=self.image_cache)
        spec, realized_sections, consumed = apply_build_manifest(
            spec, image_cache=self.image_cache, build_cache=default_build_cache()
        )
        backings = realized_backings(consumed) if consumed else {}
        plan = resolve_plan(
            spec,
            self.plan_options(
                realized_sections=realized_sections, realized_backings=backings
            ),
        )
        self._resolved[config] = (spec, plan, realized_sections, backings)
        return spec, plan, realized_sections, backings

    def plan_options(
        self,
        cid_base: int | None = None,
        evidence_capture: bool = False,
        probe_segments: tuple[str, ...] = (),
        realized_sections: frozenset[str] = frozenset(),
        realized_backings: dict[str, tuple[str, str]] | None = None,
        draws: dict[str, int | str] | None = None,
    ) -> PlanOptions:
        if cid_base is None:
            return PlanOptions(
                image_cache=self.image_cache,
                evidence_capture=evidence_capture,
                probe_segments=probe_segments,
                realized_sections=realized_sections,
                realized_backings=realized_backings or {},
                draws=draws or {},
            )
        return PlanOptions(
            image_cache=self.image_cache,
            cid_base=cid_base,
            evidence_capture=evidence_capture,
            probe_segments=probe_segments,
            realized_sections=realized_sections,
            realized_backings=realized_backings or {},
            draws=draws or {},
        )


_fallback_state: SandboxLifecycleState | None = None


def provider_runtime() -> ProviderRuntime:
    """The enclosing lifecycle scope's runtime (or a process-global fallback outside any scope)."""
    state = sandbox_lifecycle_state()
    if state is None:
        global _fallback_state
        if _fallback_state is None:
            logger.debug("no sandbox lifecycle scope; using a process-global runtime")
            _fallback_state = SandboxLifecycleState()
        state = _fallback_state
    return state.get(ProviderRuntime)
