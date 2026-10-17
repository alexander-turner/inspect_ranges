"""The `build` orchestration (build-v1 slice 2): boot the egress build plan, run recipes, tear down.

A build is an ordinary realizer project: the spec's egress-enabled build variant renders to a staging bundle, `up` boots it (ownership records, stage logs, and crash cleanup all inherited), each host's `provisioning` steps run in declaration order through the slice-1 executor, and the range is torn down on success and on failure (`keep` preserves it for diagnosis, as `up` does). Capture of the provisioned disks and the build manifest arrive with slice 5; until then a build proves orchestration and realization, not persistence.

The egress build plan is a plan transformation, never a spec change (build-v1, decided 2026-10-17): routerless networks flip to `mode: nat` with an allow-all egress policy and an external nameserver appended, router-attached and `routed` networks are left untouched (the goad-era question), and the runtime spec is never mutated. The transformed spec re-validates before planning, and planning runs with `provisioning` in `PlanOptions.realized_sections`: the build realizes that section now, while the runtime path keeps its gate.
"""

import asyncio
import logging
import shutil
import subprocess
import time
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import VsockTransport
from .._compiler.plan import PlanOptions, spec_sha256
from .._compiler.render import render_bundle
from .._runtime.down import down
from .._runtime.images import default_image_cache
from .._runtime.ownership import (
    PROJECT_PREFIX,
    StageLog,
    default_state_dir,
    project_dir,
)
from .._runtime.up import OnStage, UpOptions, UpResult, up
from ..schema import revalidate_range
from ..types import DnsConfig, EgressPolicy, Issue, IssueError, RangeSpec
from .recipes import (
    DEFAULT_RECIPE_BUDGET_S,
    RecipeError,
    RecipeRun,
    RecipeTarget,
    ResolvedRecipe,
    VarValue,
    default_recipe_cache,
    resolve_recipe,
    run_recipe,
    validate_vars,
)

logger = logging.getLogger(__name__)

FALLBACK_BUILD_NAMESERVER = "1.1.1.1"
"""Build nameserver of last resort, when the host's own upstream resolver cannot be determined."""


_RESOLV_CONF_SEARCH = (
    Path("/run/systemd/resolve/resolv.conf"),
    Path("/etc/resolv.conf"),
)


def default_build_nameserver(search: tuple[Path, ...] = _RESOLV_CONF_SEARCH) -> str:
    """The deployment's resolver, derived from the host: the first non-loopback v4 nameserver in `/run/systemd/resolve/resolv.conf` (the real upstreams behind a systemd-resolved stub) or `/etc/resolv.conf`.

    Hardcoding a public resolver fails on fleets that force DNS through a VPC resolver (measured on the devbox: outbound UDP/53 to the internet is blocked while the VPC resolver answers through the build's double NAT), so the build points guests at whatever actually resolves for this host.
    """
    for candidate in search:
        try:
            text = candidate.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    address = ip_address(parts[1])
                except ValueError:
                    continue
                if not address.is_loopback and address.version == 4:
                    return str(address)
    return FALLBACK_BUILD_NAMESERVER

DEFAULT_UPLINK_NETWORK = "ir-uplink"
"""Docker network the build range's egress masquerades onto; ensured to exist by default so a bare `inspect-ranges build` works."""

UpFn = Callable[..., UpResult]
DownFn = Callable[..., Any]
RecipeFn = Callable[..., RecipeRun]


class BuildOptions(BaseModel):
    """Inputs to a build run (never per-instance probes; mirrors `UpOptions` where they overlap)."""

    image_cache: Path | None = None
    """Image cache for golden resolution; defaults to the shared cache."""

    recipe_cache: Path | None = None
    """Recipe cache for the resolution fallback; defaults to the shared cache (the image cache's sibling)."""

    state_dir: Path | None = None
    """Ownership/stage-log root; defaults to the user state dir."""

    cid_base: int = 3
    """First vsock CID for the build range (plan-time input, as everywhere)."""

    keep: bool = False
    """Keep the built range running (success or failure) for diagnosis; the caller owns the eventual `down`."""

    uplink_network: str = DEFAULT_UPLINK_NETWORK
    """The deployment-supplied docker network build egress masquerades onto."""

    readiness_timeout: float = 300.0
    """Per-`up` readiness budget."""

    recipe_budget_s: float = DEFAULT_RECIPE_BUDGET_S
    """Whole-entrypoint budget per provisioning step."""

    build_nameserver: str | None = None
    """Resolver handed to build guests; `None` derives it from the host (`default_build_nameserver`)."""

    settle_probe: str | None = "archive.ubuntu.com"
    """Name whose in-guest resolution gates a guest's first recipe: guest readiness (cloud-init plus daemon) does not cover systemd-resolved having link DNS live, and the gap is seconds wide, exactly when recipes start. `None` disables the gate."""

    settle_timeout_s: float = 90.0
    """Per-guest bound on the network-settle gate."""


class BuildError(Exception):
    """Stage-named build failure; recipe failures carry guest, recipe, and log path."""

    def __init__(
        self,
        stage: str,
        message: str,
        *,
        guest: str | None = None,
        recipe: str | None = None,
        log_path: Path | None = None,
    ) -> None:
        self.stage = stage
        self.guest = guest
        self.recipe = recipe
        self.log_path = log_path
        detail = f" guest {guest!r}" if guest else ""
        detail += f" recipe {recipe!r}" if recipe else ""
        super().__init__(f"[{stage}]{detail}: {message}" if detail else f"[{stage}] {message}")


class BuildResult(BaseModel):
    """A completed build run (slice 2: orchestration proof; artifacts and manifest arrive with slice 5)."""

    model_config = ConfigDict(frozen=True)

    project: str
    range_name: str
    recipes: tuple[RecipeRun, ...]
    seconds: float
    kept: bool
    """True when the range was left running (`keep`); tear down with `inspect-ranges down PROJECT`."""


def egress_build_spec(spec: RangeSpec, nameserver_ip: str | None = None) -> RangeSpec:
    """The egress-enabled build variant of a spec: a deep copy, never a mutation of the runtime spec.

    Routerless networks flip to `mode: nat` with an allow-all v4 egress policy and the build nameserver (host-derived by default) appended to their resolvers; router-attached and `routed` networks are untouched. The copy re-validates, so the egress semantic gates still apply to what the build actually boots.
    """
    build = spec.model_copy(deep=True)
    router_networks = {
        interface.network for router in build.routers for interface in router.interfaces
    }
    nameserver = ip_address(
        nameserver_ip if nameserver_ip is not None else default_build_nameserver()
    )
    for network in build.networks:
        if network.name in router_networks or network.mode == "routed":
            continue
        network.mode = "nat"
        network.egress = EgressPolicy(allow=["0.0.0.0/0"])
        if network.dns is None:
            network.dns = DnsConfig(nameservers=[nameserver])
        elif network.dns.nameservers is None:
            network.dns.nameservers = [nameserver]
        elif nameserver not in network.dns.nameservers:
            network.dns.nameservers.append(nameserver)
    return revalidate_range(build)


class _ResolvedStep(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    guest: str
    recipe: ResolvedRecipe
    vars: dict[str, VarValue]


def resolve_provisioning(
    spec: RangeSpec, range_dir: Path, recipe_cache: Path
) -> list[_ResolvedStep]:
    """Resolve and pre-validate every host's provisioning steps, failing fast before anything boots.

    All issues across all steps are collected into one refusal: unresolvable recipes, version-pin mismatches, var violations, and (for now) `offline` recipes.
    """
    steps: list[_ResolvedStep] = []
    issues: list[Issue] = []
    for host_index, host in enumerate(spec.hosts):
        for step_index, step in enumerate(host.provisioning):
            path = ("hosts", host_index, "provisioning", step_index)
            try:
                recipe = resolve_recipe(
                    step.recipe,
                    range_dir=range_dir,
                    cache=recipe_cache,
                    version=step.version,
                    path=path,
                )
                if recipe.spec.mode != "online":
                    raise IssueError(
                        [
                            Issue(
                                code="recipe-mode-unsupported",
                                path=path,
                                message=f"recipe {recipe.name!r} declares mode {recipe.spec.mode!r}, which the build cannot execute yet",
                                hint="offline recipes arrive when a range demands them; declare mode: online",
                            )
                        ]
                    )
                validate_vars(recipe, step.vars, path=path)
            except IssueError as error:
                issues.extend(error.issues)
                continue
            steps.append(
                _ResolvedStep(guest=host.name, recipe=recipe, vars=dict(step.vars))
            )
    if issues:
        raise IssueError(issues)
    return steps


def build_range(
    spec: RangeSpec,
    range_dir: Path,
    options: BuildOptions | None = None,
    *,
    on_stage: OnStage | None = None,
    up_fn: UpFn = up,
    down_fn: DownFn = down,
    recipe_fn: RecipeFn = run_recipe,
    ensure_uplink: Callable[[str], None] | None = None,
    settle_fn: Callable[..., float] | None = None,
) -> BuildResult:
    """Build a range: resolve, render the egress build plan, boot, provision, tear down.

    The build is an ordinary project named `ir-<range>-<build spec digest>`; a second build of the same spec while one runs refuses through `up`'s existing project check, naming the running project. On any failure after boot the range tears down (unless `keep`), and the failure names its stage, guest, and recipe with a log path.

    Raises:
        IssueError: spec, recipe-resolution, or planning refusals (all collected, house codes).
        UpError: boot-phase failures (stage-named; `up` handled its own teardown per `keep`).
        BuildError: recipe-phase failures, after teardown.
    """
    options = options or BuildOptions()
    state_dir = options.state_dir if options.state_dir is not None else default_state_dir()
    recipe_cache = (
        options.recipe_cache if options.recipe_cache is not None else default_recipe_cache()
    )
    started = time.monotonic()

    steps = resolve_provisioning(spec, range_dir, recipe_cache)
    build_spec = egress_build_spec(spec, options.build_nameserver)
    project = f"{PROJECT_PREFIX}{build_spec.meta.name}-{spec_sha256(build_spec)[:12]}"
    tee = _BuildTee(StageLog(state_dir, project), on_stage)
    tee.log("resolve", "ok", recipes=len(steps), guests=len(build_spec.hosts) + 1)

    staging = state_dir.parent / "staging" / project
    if staging.exists():
        shutil.rmtree(staging)
    plan_options = PlanOptions(
        image_cache=options.image_cache,
        cid_base=options.cid_base,
        realized_sections=frozenset({"provisioning"}),
    )
    try:
        render_bundle(build_spec, staging, plan_options)
    except IssueError:
        tee.log("render", "fail", error="planning refused (see issues)")
        raise
    tee.log("render", "ok", bundle=str(staging))

    uplink = ensure_uplink if ensure_uplink is not None else _ensure_uplink_network
    uplink(options.uplink_network)

    result = up_fn(
        staging,
        UpOptions(
            project=project,
            image_cache=_image_cache(options),
            state_dir=state_dir,
            readiness_timeout=options.readiness_timeout,
            keep_on_failure=options.keep,
            uplink_network=options.uplink_network,
        ),
        on_stage=on_stage,
    )

    cids = {guest.name: guest.cid for guest in result.guests}
    log_dir = project_dir(state_dir, project) / "recipes"
    runs: list[RecipeRun] = []
    settle = settle_fn if settle_fn is not None else _settle_network
    settled: set[str] = set()
    try:
        for step in steps:
            if options.settle_probe is not None and step.guest not in settled:
                seconds = settle(
                    cids, step.guest, options.settle_probe, options.settle_timeout_s
                )
                tee.log(
                    "network-settle", "ok", guest=step.guest, seconds=round(seconds, 1)
                )
                settled.add(step.guest)
            run = recipe_fn(
                step.recipe,
                step_vars=step.vars,
                target=RecipeTarget(guest=step.guest, cids=cids),
                log_dir=log_dir,
                stage_log=tee,
                budget_s=options.recipe_budget_s,
            )
            runs.append(run)
    except RecipeError as error:
        disposition = _dispose(options, project, down_fn, tee, state_dir)
        raise BuildError(
            "recipe",
            f"{error.detail} ({disposition})",
            guest=error.guest,
            recipe=error.recipe,
            log_path=error.log_path,
        ) from error
    except BuildError:
        _dispose(options, project, down_fn, tee, state_dir)
        raise

    kept = options.keep
    if not kept:
        down_fn(project, state_dir=state_dir, keep_state=True)
        tee.log("teardown", "ok", after="success")
    seconds = time.monotonic() - started
    tee.log("build", "ok", seconds=round(seconds, 1), recipes=len(runs), kept=kept)
    return BuildResult(
        project=project,
        range_name=build_spec.meta.name,
        recipes=tuple(runs),
        seconds=seconds,
        kept=kept,
    )


class _BuildTee:
    """The `up` stage-tee pattern: JSONL first, callback mirrored, callback failures never alter the build."""

    def __init__(self, log: StageLog, on_stage: OnStage | None) -> None:
        self._log = log
        self._on_stage = on_stage

    def log(self, stage: str, status: str, **fields: Any) -> None:
        self._log.log(stage, status, **fields)
        if self._on_stage is not None:
            try:
                self._on_stage(stage, status, dict(fields))
            except Exception:  # pragma: no cover - callback bugs never alter the build
                logger.exception("on_stage callback failed (ignored)")


def _image_cache(options: BuildOptions) -> Path:
    return options.image_cache if options.image_cache is not None else default_image_cache()


def _dispose(
    options: BuildOptions,
    project: str,
    down_fn: DownFn,
    tee: "_BuildTee",
    state_dir: Path,
) -> str:
    """Tear down a failed build's range (unless `keep`); returns the disposition clause for the error message."""
    if options.keep:
        return f"range kept running: inspect-ranges down {project}"
    down_fn(project, state_dir=state_dir, keep_state=True)
    tee.log("teardown", "ok", after="build-failure")
    return "range torn down"


def _settle_network(
    cids: dict[str, int], guest: str, probe: str, timeout_s: float
) -> float:
    """Block until the guest resolves `probe` (the build-egress DNS warm-up gate); returns the wait.

    Raises:
        BuildError: stage `network-settle` when the guest cannot resolve within the bound; the build's egress promise would be a lie for its recipes.
    """

    async def wait() -> float:
        channel = MessageChannel(VsockTransport(cids), label="build-settle")
        started = time.monotonic()
        deadline = started + timeout_s
        while time.monotonic() < deadline:
            try:
                outcome = await channel.exec(
                    guest,
                    ExecRequest(
                        id=request_id(),
                        cmd=["getent", "hosts", probe],
                        budget=Budget(command_ms=5_000),
                    ),
                )
                if outcome.rc == 0:
                    return time.monotonic() - started
            except Exception:  # transient channel noise during early boot
                pass
            await asyncio.sleep(2.0)
        raise BuildError(
            "network-settle",
            f"guest cannot resolve {probe!r} within {timeout_s:.0f} s; build-time egress is not usable",
            guest=guest,
        )

    return asyncio.run(wait())


def _ensure_uplink_network(name: str) -> None:
    """Create the uplink docker network when absent (idempotent; shared across builds, never removed)."""
    probe = subprocess.run(
        ["docker", "network", "inspect", name],
        capture_output=True,
        timeout=60,
    )
    if probe.returncode == 0:
        return
    subprocess.run(
        ["docker", "network", "create", name],
        capture_output=True,
        timeout=60,
        check=True,
    )
