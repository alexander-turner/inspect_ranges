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

from .._channel.channel import MessageChannel
from .._compiler.plan import PlanOptions, ResolvedPlan, Totals
from .._compiler.render import render_bundle
from .._runtime.down import DownResult, down
from .._runtime.ownership import default_state_dir
from .._runtime.up import UpOptions, UpResult, up
from .admission import HostCapacity, WeightedAdmission
from .naming import CidAllocator
from .retry import RetryConfig, RetryStats

if TYPE_CHECKING:
    from .._channel.channel import Transport

logger = logging.getLogger("inspect_ranges.provider")

UpFn = Callable[[Path, UpOptions], UpResult]
DownFn = Callable[[str, Path], DownResult]
RenderFn = Callable[..., ResolvedPlan]
ChannelFactory = Callable[[dict[str, int], str], MessageChannel]


def default_image_cache() -> Path:
    """`INSPECT_RANGES_IMAGE_CACHE`, or the CLI's `~/.cache/inspect-ranges/images` default."""
    override = os.environ.get("INSPECT_RANGES_IMAGE_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "inspect-ranges" / "images"


def _default_channel_factory(cids: dict[str, int], label: str) -> MessageChannel:
    from .._channel.vsock import VsockTransport

    transport: "Transport" = VsockTransport(cids)
    return MessageChannel(transport, label=label)


def _default_up(bundle: Path, options: UpOptions) -> UpResult:
    return up(bundle, options)


def _default_down(project: str, state_dir: Path) -> DownResult:
    return down(project, state_dir=state_dir)


@dataclass
class SampleHandle:
    """Everything one sample's cleanup needs, registered BEFORE anything boots."""

    project: str
    task_name: str
    staging: Path
    totals: Totals
    cid_base: int
    guest_cids: dict[str, int] = field(default_factory=dict[str, int])
    channel: MessageChannel | None = None
    sessions: dict[str, str] = field(default_factory=dict[str, str])
    stats: RetryStats = field(default_factory=RetryStats)
    booted: bool = False
    deferred: bool = False
    admission_charged: bool = False


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
        self.registry: dict[str, SampleHandle] = {}
        self._admission: WeightedAdmission | None = None
        self._allocator: CidAllocator | None = None

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

    def staging_root(self) -> Path:
        """The sweep-visible staging root (`down --all` clears leftovers after a SIGKILL)."""
        root = self.state_dir.parent / "staging"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def plan_options(self, cid_base: int | None = None) -> PlanOptions:
        if cid_base is None:
            return PlanOptions(image_cache=self.image_cache)
        return PlanOptions(image_cache=self.image_cache, cid_base=cid_base)


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
