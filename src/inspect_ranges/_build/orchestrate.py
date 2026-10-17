"""The `build` orchestration (build-v1 slice 2): boot the egress build plan, run recipes, tear down.

A build is an ordinary realizer project: the spec's egress-enabled build variant renders to a staging bundle, `up` boots it (ownership records, stage logs, and crash cleanup all inherited), each host's `provisioning` steps run in declaration order through the slice-1 executor, every `services`/`vulnerabilities` declaration is then verified against the live range through the slice-4 engine (whole-range, independent of recipe claims), and the range is torn down on success and on failure (`keep` preserves it for diagnosis, as `up` does). Capture of the provisioned disks and the build manifest arrive with slice 5; until then a build proves orchestration, realization, and verification, not persistence.

The egress build plan is a plan transformation, never a spec change (build-v1, decided 2026-10-17): routerless networks flip to `mode: nat` with an allow-all egress policy and the build nameserver appended (host-derived by default, because fleets that force DNS through a VPC resolver are the norm), router-attached and `routed` networks are left untouched (the goad-era question), and the runtime spec is never mutated. The transformed spec re-validates before planning, and planning runs with `provisioning` in `PlanOptions.realized_sections`: the build realizes that section now, while the runtime path keeps its gate. The staging bundle is per-run (a fresh temp dir) and removed after the build unless `keep` left the range running from it, so the egress-enabled bundle never lingers where a runtime verb could boot it.
"""

import asyncio
import logging
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, ValidationError

from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import VsockTransport
from .._compiler.plan import PlanOptions, resolve_image_reference, spec_sha256
from .._compiler.render import render_bundle
from .._diagnostics import issues_from_validation_error
from .._runtime.down import down
from .._runtime.images import default_image_cache
from .._runtime.ownership import (
    PROJECT_PREFIX,
    StageLog,
    default_state_dir,
    project_dir,
)
from .._runtime.up import OnStage, UpOptions, UpResult, up
from .._runtime.images import sha256_file
from ..schema import revalidate_range
from .capture import RealizedImageMeta, capture_guest, default_capture_runner, shutdown_guest, wait_shutoff
from .errors import BuildError
from .manifest import (
    BuildManifest,
    GuestRecord,
    RecipeRecord,
    VerificationRecord,
    default_build_cache,
    guest_build_key,
    load_manifest,
    manifest_matches_spec,
    manifest_path,
    now_iso,
    realized_file_name,
    save_manifest,
    vars_hash,
)
from ..types import DnsConfig, EgressPolicy, Issue, IssueError, RangeSpec
from .recipes import (
    DEFAULT_RECIPE_BUDGET_S,
    RecipeError,
    RecipeRun,
    RecipeTarget,
    ResolvedRecipe,
    StageSink,
    VarValue,
    default_recipe_cache,
    resolve_recipe,
    run_recipe,
    validate_vars,
)
from .verify import DeclarationResult, verify_range

logger = logging.getLogger(__name__)

FALLBACK_BUILD_NAMESERVER = "1.1.1.1"
"""Build nameserver of last resort, when the host's own upstream resolver cannot be determined."""

DEFAULT_UPLINK_NETWORK = "ir-uplink"
"""Docker network the build range's egress masquerades onto; ensured to exist by default so a bare `inspect-ranges build` works."""

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


class UpFn(Protocol):
    """The boot seam: `up`'s callable shape."""

    def __call__(
        self, bundle: Path, options: UpOptions, *, on_stage: OnStage | None = None
    ) -> UpResult: ...


class DownFn(Protocol):
    """The teardown seam: `down`'s callable shape."""

    def __call__(
        self, project: str, *, state_dir: Path, keep_state: bool
    ) -> object: ...


class RecipeFn(Protocol):
    """The executor seam: `run_recipe`'s callable shape."""

    def __call__(
        self,
        recipe: ResolvedRecipe,
        *,
        step_vars: Mapping[str, VarValue],
        target: RecipeTarget,
        log_dir: Path,
        stage_log: StageSink | None,
        budget_s: float,
    ) -> RecipeRun: ...


SettleFn = Callable[[dict[str, int], str, str, float], float]
"""The network-settle seam: `(cids, guest, probe, timeout_s) -> seconds waited`."""


class CaptureFn(Protocol):
    """The capture seam: clean shutdown plus overlay capture, returning the realized image's sha256."""

    def __call__(
        self,
        project: str,
        guest: str,
        cids: dict[str, int],
        *,
        image_cache: Path,
        golden_file: str,
        realized_name: str,
        meta: RealizedImageMeta,
    ) -> str: ...


def _capture_realized(
    project: str,
    guest: str,
    cids: dict[str, int],
    *,
    image_cache: Path,
    golden_file: str,
    realized_name: str,
    meta: RealizedImageMeta,
) -> str:
    shutdown_guest(cids, guest)
    wait_shutoff(default_capture_runner, project, guest)
    return capture_guest(
        default_capture_runner,
        project,
        guest,
        image_cache=image_cache,
        golden_file=golden_file,
        realized_name=realized_name,
        meta=meta,
    )


class VerifyFn(Protocol):
    """The verification seam: `verify_range`'s callable shape."""

    def __call__(
        self,
        spec: RangeSpec,
        cids: dict[str, int],
        *,
        log_dir: Path,
        stage_log: StageSink | None,
    ) -> list[DeclarationResult]: ...


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

    build_cache: Path | None = None
    """Builds cache for manifests; defaults to the shared cache."""

    reverify: bool = False
    """Force the full boot-and-verify pass even when every build key matches the recorded manifest."""

    settle_probe: str | None = "archive.ubuntu.com"
    """Name whose in-guest resolution gates a guest's first recipe: guest readiness (cloud-init plus daemon) does not cover systemd-resolved having link DNS live, and the gap is seconds wide, exactly when recipes start. `None` disables the gate."""

    settle_timeout_s: float = 90.0
    """Per-guest bound on the network-settle gate."""




class BuildResult(BaseModel):
    """A completed build run (slice 2: orchestration proof; artifacts and manifest arrive with slice 5)."""

    model_config = ConfigDict(frozen=True)

    project: str
    range_name: str
    recipes: tuple[RecipeRun, ...]
    verifications: tuple[DeclarationResult, ...]
    seconds: float
    kept: bool
    """True when the range was left running (`keep`); tear down with `inspect-ranges down PROJECT`."""

    cached: bool = False
    """True when every build key matched the recorded manifest and nothing booted (verification reported from the record)."""

    manifest_path: Path | None = None
    """The build manifest, when one was produced (`keep` builds are diagnostic and produce none)."""

    verified_at: str | None = None
    """When the reported verification ran (now, or the recorded time on the cached path)."""


def egress_build_spec(spec: RangeSpec, nameserver_ip: str | None = None) -> RangeSpec:
    """The egress-enabled build variant of a spec: a deep copy, never a mutation of the runtime spec.

    Routerless networks flip to `mode: nat` with an allow-all v4 egress policy and the build nameserver (host-derived by default) appended to their resolvers; router-attached and `routed` networks are untouched. The copy re-validates, so the egress semantic gates still apply to what the build actually boots.

    Raises:
        IssueError: when the transformed spec fails re-validation (the semantic gates), as positioned issues where the validator carried them.
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
    try:
        return revalidate_range(build)
    except ValidationError as error:
        issues, _ = issues_from_validation_error(error, RangeSpec, None)
        if not issues:
            first = str(error).strip().splitlines()[0]
            issues = [
                Issue(
                    code="build-plan-invalid",
                    message=f"the egress build variant failed validation: {first}",
                    hint="the build transformation only touches routerless networks; check the spec's egress-adjacent declarations",
                )
            ]
        raise IssueError(issues) from error


class ResolvedStep(BaseModel):
    """One provisioning step resolved to its recipe, pre-validated and ready to execute."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    guest: str
    recipe: ResolvedRecipe
    vars: dict[str, VarValue]


def resolve_provisioning(
    spec: RangeSpec, range_dir: Path, recipe_cache: Path
) -> list[ResolvedStep]:
    """Resolve and pre-validate every host's provisioning steps, failing fast before anything boots.

    All issues across all steps are collected into one refusal: unresolvable recipes, version-pin mismatches, var violations, and (for now) `offline` recipes.
    """
    steps: list[ResolvedStep] = []
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
                ResolvedStep(guest=host.name, recipe=recipe, vars=dict(step.vars))
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
    settle_fn: SettleFn | None = None,
    verify_fn: VerifyFn = verify_range,
    capture_fn: CaptureFn | None = None,
) -> BuildResult:
    """Build a range: resolve, render the egress build plan, boot, provision, tear down.

    The build is an ordinary project named `ir-<range>-<build spec digest>`; a second build of the same spec while one runs refuses through `up`'s existing project check, naming the running project, and each run renders into its own staging directory so concurrent attempts can never destroy each other's bundles. On any failure after boot the range tears down (unless `keep`), the failure names its stage, guest, and recipe with a log path, and a teardown error is appended to the diagnosed failure, never substituted for it.

    Raises:
        IssueError: spec, recipe-resolution, build-variant, or planning refusals (all collected, house codes).
        UpError: boot-phase failures (stage-named; `up` handled its own teardown per `keep`).
        BuildError: recipe-phase, settle, uplink, and teardown failures, stage-named.
    """
    options = options or BuildOptions()
    state_dir = (
        options.state_dir if options.state_dir is not None else default_state_dir()
    )
    recipe_cache = (
        options.recipe_cache
        if options.recipe_cache is not None
        else default_recipe_cache()
    )
    image_cache = (
        options.image_cache if options.image_cache is not None else default_image_cache()
    )
    build_cache = (
        options.build_cache if options.build_cache is not None else default_build_cache()
    )
    started = time.monotonic()

    steps = resolve_provisioning(spec, range_dir, recipe_cache)
    steps_by_host: dict[str, list[ResolvedStep]] = {}
    for step in steps:
        steps_by_host.setdefault(step.guest, []).append(step)
    content_hosts = [
        host
        for host in spec.hosts
        if host.provisioning or host.services or host.vulnerabilities
    ]
    goldens: dict[str, Any] = {}
    keys: dict[str, str] = {}
    missing: list[Issue] = []
    for index, host in enumerate(spec.hosts):
        if host not in content_hosts:
            continue
        reference = resolve_image_reference(host.image, image_cache)
        if reference.digest is None:
            missing.append(
                Issue(
                    code="image-not-in-cache",
                    path=("hosts", index, "image"),
                    message=f"image {host.image!r} for guest {host.name!r} is not in the image cache, so its build key cannot resolve",
                    hint="pull or derive the golden into the cache first",
                )
            )
            continue
        goldens[host.name] = reference
        keys[host.name] = guest_build_key(
            reference.digest,
            host,
            [(s.recipe, s.vars) for s in steps_by_host.get(host.name, [])],
        )
    if missing:
        raise IssueError(missing)

    spec_hash = spec_sha256(spec)
    prior = load_manifest(build_cache, spec.meta.name)
    reusable: dict[str, GuestRecord] = {}
    if prior is not None:
        for host in content_hosts:
            record = prior.guest(host.name)
            if record is None or record.build_key != keys[host.name]:
                continue
            realized = image_cache / record.realized_file
            if realized.is_file() and sha256_file(realized) == record.realized_sha256:
                reusable[host.name] = record

    build_spec = egress_build_spec(spec, options.build_nameserver)

    if (
        prior is not None
        and not options.reverify
        and manifest_matches_spec(prior, spec_hash)
        and all(host.name in reusable for host in content_hosts)
    ):
        # the no-op fast path: every key matches and the verification is
        # recorded, so nothing boots (all-or-nothing caching, ratified)
        project = f"{PROJECT_PREFIX}{spec.meta.name}-{spec_sha256(build_spec)[:12]}"
        tee = _BuildTee(StageLog(state_dir, project), on_stage)
        tee.log(
            "build",
            "ok",
            cached=True,
            verified_at=prior.verification.verified_at,
            declarations=len(prior.verification.declarations),
        )
        return BuildResult(
            project=project,
            range_name=spec.meta.name,
            recipes=(),
            verifications=prior.verification.declarations,
            seconds=time.monotonic() - started,
            kept=False,
            cached=True,
            manifest_path=manifest_path(build_cache, spec.meta.name),
            verified_at=prior.verification.verified_at,
        )

    for host in build_spec.hosts:
        if host.name in reusable:
            # unchanged guests boot from their captured realized image and
            # skip their recipes; verification still covers them in full
            host.image = reusable[host.name].realized_file
    project = f"{PROJECT_PREFIX}{spec.meta.name}-{spec_sha256(build_spec)[:12]}"
    tee = _BuildTee(StageLog(state_dir, project), on_stage)
    run_steps = [step for step in steps if step.guest not in reusable]
    tee.log(
        "resolve",
        "ok",
        recipes=len(steps),
        reused_guests=len(reusable),
        rebuilt_guests=len(content_hosts) - len(reusable),
    )
    for step in steps:
        if step.guest in reusable:
            tee.log(
                "recipe",
                "ok",
                recipe=step.recipe.name,
                guest=step.guest,
                skipped="unchanged",
            )

    staging_root = state_dir.parent / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=staging_root, prefix=f"{project}-"))
    kept = False
    try:
        plan_options = PlanOptions(
            image_cache=image_cache,
            cid_base=options.cid_base,
            # the build realizes provisioning (slice 2) and verifies services
            # and vulnerabilities (slice 4); the runtime path keeps its gates
            realized_sections=frozenset({"provisioning", "services", "vulnerabilities"}),
        )
        try:
            plan = render_bundle(build_spec, staging, plan_options)
        except IssueError:
            tee.log("render", "fail", error="planning refused (see issues)")
            raise
        tee.log("render", "ok", bundle=str(staging), guests=plan.totals.guests)

        uplink = ensure_uplink if ensure_uplink is not None else _ensure_uplink_network
        uplink(options.uplink_network)

        result = up_fn(
            staging,
            UpOptions(
                project=project,
                image_cache=image_cache,
                state_dir=state_dir,
                readiness_timeout=options.readiness_timeout,
                keep_on_failure=options.keep,
                uplink_network=options.uplink_network,
            ),
            on_stage=on_stage,
        )
        kept = options.keep  # from here the range is running; keep governs staging too

        cids = {guest.name: guest.cid for guest in result.guests}
        log_dir = project_dir(state_dir, project) / "recipes"
        runs: list[RecipeRun] = []
        settle = settle_fn if settle_fn is not None else _settle_network
        settled: set[str] = set()
        try:
            for step in run_steps:
                if options.settle_probe is not None and step.guest not in settled:
                    seconds = settle(
                        cids, step.guest, options.settle_probe, options.settle_timeout_s
                    )
                    tee.log(
                        "network-settle",
                        "ok",
                        guest=step.guest,
                        seconds=round(seconds, 1),
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
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                "recipe",
                f"{error.detail} ({disposition})",
                guest=error.guest,
                recipe=error.recipe,
                log_path=error.log_path,
            ) from error
        except BuildError as error:
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                error.stage,
                f"{_strip_stage(error)} ({disposition})",
                guest=error.guest,
                recipe=error.recipe,
                log_path=error.log_path,
            ) from error

        verify_dir = project_dir(state_dir, project) / "verify"
        try:
            verifications = verify_fn(spec, cids, log_dir=verify_dir, stage_log=tee)
        except Exception as error:
            tee.log("verify", "fail", error=str(error))
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                "verify",
                f"verification probe failed: {error} ({disposition})",
            ) from error
        failed = [result for result in verifications if result.status == "fail"]
        if failed:
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                "verify",
                f"{len(failed)} of {len(verifications)} declarations failed verification; logs: {verify_dir} ({disposition})",
                guest=failed[0].guest,
            )
        if verifications:
            tee.log("verified", "ok", declarations=len(verifications))

        saved_manifest: Path | None = None
        verified_at: str | None = None
        if options.keep:
            tee.log("capture", "ok", skipped="--keep (diagnostic build; no manifest)")
        else:
            capture = capture_fn if capture_fn is not None else _capture_realized
            guest_records: list[GuestRecord] = []
            try:
                for host in content_hosts:
                    if host.name in reusable:
                        guest_records.append(reusable[host.name])
                        continue
                    key = keys[host.name]
                    realized_name = realized_file_name(spec.meta.name, host.name, key)
                    golden = goldens[host.name]
                    digest = capture(
                        project,
                        host.name,
                        cids,
                        image_cache=image_cache,
                        golden_file=golden.file,
                        realized_name=realized_name,
                        meta=RealizedImageMeta(
                            range_name=spec.meta.name,
                            guest=host.name,
                            build_key=key,
                            golden_file=golden.file,
                            sha256="",
                            created=now_iso(),
                        ),
                    )
                    tee.log("capture", "ok", guest=host.name, file=realized_name)
                    guest_records.append(
                        GuestRecord(
                            name=host.name,
                            golden_reference=host.image,
                            golden_digest=golden.digest,
                            realized_file=realized_name,
                            realized_sha256=digest,
                            build_key=key,
                            recipes=tuple(
                                RecipeRecord(
                                    name=s.recipe.name,
                                    version=s.recipe.version,
                                    digest=s.recipe.digest,
                                    vars_hash=vars_hash(s.vars),
                                )
                                for s in steps_by_host.get(host.name, [])
                            ),
                        )
                    )
            except BuildError as error:
                disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
                raise BuildError(
                    error.stage,
                    f"{_strip_stage(error)} ({disposition})",
                    guest=error.guest,
                ) from error
            verified_at = now_iso()
            manifest = BuildManifest(
                range_name=spec.meta.name,
                schema_version=spec.meta.schema_version,
                spec_sha256=spec_hash,
                built_at=verified_at,
                guests=tuple(guest_records),
                verification=VerificationRecord(
                    verified_at=verified_at, declarations=tuple(verifications)
                ),
            )
            saved_manifest = save_manifest(manifest, build_cache)
            tee.log("manifest", "ok", path=str(saved_manifest), guests=len(guest_records))

        if not options.keep:
            try:
                down_fn(project, state_dir=state_dir, keep_state=True)
            except Exception as error:
                tee.log("teardown", "fail", error=str(error))
                raise BuildError(
                    "teardown",
                    f"range built and provisioned, but teardown failed: {error}; retry with: inspect-ranges down {project}",
                ) from error
            tee.log("teardown", "ok", after="success")
            kept = False
    finally:
        if not kept:
            shutil.rmtree(staging, ignore_errors=True)

    seconds = time.monotonic() - started
    tee.log("build", "ok", seconds=round(seconds, 1), recipes=len(runs), kept=kept)
    return BuildResult(
        project=project,
        range_name=build_spec.meta.name,
        recipes=tuple(runs),
        verifications=tuple(verifications),
        seconds=seconds,
        kept=kept,
        cached=False,
        manifest_path=saved_manifest,
        verified_at=verified_at,
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


def _dispose(
    options: BuildOptions,
    project: str,
    down_fn: DownFn,
    tee: _BuildTee,
    state_dir: Path,
) -> tuple[str, bool]:
    """Tear down a failed build's range (unless `keep`); returns the disposition clause and whether the range (and so its staging bundle) survives.

    A teardown error is appended to the clause, never substituted for the diagnosed failure (the `up` contract).
    """
    if options.keep:
        return f"range kept running: inspect-ranges down {project}", True
    try:
        down_fn(project, state_dir=state_dir, keep_state=True)
    except Exception as error:
        tee.log("teardown", "fail", error=str(error))
        return (
            f"teardown also failed, range left behind: {error}; retry with: inspect-ranges down {project}",
            True,
        )
    tee.log("teardown", "ok", after="build-failure")
    return "range torn down", False


def _strip_stage(error: BuildError) -> str:
    """The message portion of a `BuildError` without its `[stage]`/context prefix (for re-wrapping)."""
    text = str(error)
    return text.split(": ", 1)[1] if ": " in text else text


def _settle_network(
    cids: dict[str, int], guest: str, probe: str, timeout_s: float
) -> float:
    """Block until the guest resolves `probe` (the build-egress DNS warm-up gate); returns the wait.

    Raises:
        BuildError: stage `network-settle` when the guest cannot resolve within the bound, carrying the last underlying cause; the build's egress promise would be a lie for its recipes.
    """

    async def wait() -> float:
        channel = MessageChannel(VsockTransport(cids), label="build-settle")
        started = time.monotonic()
        deadline = started + timeout_s
        last_cause = "resolution never succeeded"
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
                last_cause = f"getent exited {outcome.rc}"
            except Exception as error:  # transient channel noise during early boot
                last_cause = f"{type(error).__name__}: {error}"
            await asyncio.sleep(2.0)
        raise BuildError(
            "network-settle",
            f"guest cannot resolve {probe!r} within {timeout_s:.0f} s (last cause: {last_cause}); build-time egress is not usable",
            guest=guest,
        )

    return asyncio.run(wait())


def _ensure_uplink_network(name: str) -> None:
    """Create the uplink docker network when absent (idempotent; shared across builds, never removed).

    Raises:
        BuildError: stage `uplink` when docker is unavailable or the network cannot be created, carrying the stderr tail.
    """
    try:
        probe = subprocess.run(
            ["docker", "network", "inspect", name],
            capture_output=True,
            timeout=60,
        )
        if probe.returncode == 0:
            return
        create = subprocess.run(
            ["docker", "network", "create", name],
            capture_output=True,
            timeout=60,
        )
    except FileNotFoundError as error:
        raise BuildError(
            "uplink", "docker is not installed or not on PATH"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise BuildError(
            "uplink", f"docker did not answer within 60 s while ensuring {name!r}"
        ) from error
    if create.returncode != 0:
        stderr = create.stderr.decode(errors="replace").strip()[-300:]
        raise BuildError(
            "uplink",
            f"docker network create {name!r} failed (rc {create.returncode}): {stderr or '(no stderr)'}",
        )
