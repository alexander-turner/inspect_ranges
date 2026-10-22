"""The `build` orchestration (build-v1 slice 2): boot the egress build plan, run recipes, tear down.

A build is an ordinary realizer project: the spec's egress-enabled build variant renders to a staging bundle, `up` boots it (ownership records, stage logs, and crash cleanup all inherited), each guest's `provisioning` steps (hosts, then routers) run in declaration order through the slice-1 executor, every `services`/`vulnerabilities` declaration is then verified against the live range through the slice-4 engine (whole-range, independent of recipe claims), and the range is torn down on success and on failure (`keep` preserves it for diagnosis, as `up` does). Provisioned guests are then captured as realized images and the build manifest records the whole build (slice 5); declared behavioral checks run against the captured artifacts before the manifest lands (slice 6), so a recorded build is realized, verified, AND proven.

Provisioned ROUTERS build on the host path with one deliberate difference: they get no build egress (their attached networks stay untouched by the egress variant, and scoped egress on a router-attached network is itself unrealized, `egress-with-router-not-realized`), so a router's recipes run offline — account seeding and reconfiguring what the golden already carries, with the per-guest settle gate skipped and a network-reaching recipe failing as an ordinary recipe error. Routers also declare no `services`/`vulnerabilities`, so the verification engine has no router scope; a router recipe self-asserts, and behavioral checks prove whatever the chains depend on.

The egress build plan is a plan transformation, never a spec change (build-v1, decided 2026-10-17): routerless networks flip to `mode: nat` with an allow-all egress policy and the build nameserver appended (host-derived by default, because fleets that force DNS through a VPC resolver are the norm), router-attached and `routed` networks are left untouched with stranded content hosts gaining a build-only NAT uplink segment (the goad-era question, answered in linux-examples-v1), and the runtime spec is never mutated. The transformed spec re-validates before planning, and planning runs with `provisioning` in `PlanOptions.realized_sections`: the build realizes that section now, while the runtime path keeps its gate. The staging bundle is per-run (a fresh temp dir) and removed after the build unless `keep` left the range running from it, so the egress-enabled bundle never lingers where a runtime verb could boot it.
"""

import asyncio
import logging
import os
import secrets
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
from .._channel.vsock import HybridEndpoint, VsockTransport
from .._compiler.draws import draw_variables
from .._compiler.plan import (
    ImageRef,
    PlanOptions,
    ResolvedPlan,
    resolve_image_reference,
    spec_sha256,
)
from .._compiler.render import render_bundle
from .._diagnostics import issues_from_validation_error
from .._runtime.down import down
from .._runtime.images import default_image_cache, sha256_file
from .._runtime.ownership import (
    PROJECT_PREFIX,
    StageLog,
    default_state_dir,
    project_dir,
)
from .._runtime.up import OnStage, UpError, UpOptions, UpResult, up
from ..schema import revalidate_range
from ..types import (
    DnsConfig,
    EgressPolicy,
    Host,
    Interface,
    Issue,
    IssueError,
    Network,
    RangeSpec,
    Router,
    has_guest_content,
    has_router_content,
)
from .behavioral import (
    CHECKS_DIR_NAME,
    checks_declared,
    checks_digest,
    load_challenges,
    probe_segments_for_checks,
)
from .capture import (
    SHUTOFF_TIMEOUT_S,
    SHUTOFF_TIMEOUT_WINDOWS_S,
    RealizedImageMeta,
    capture_guest,
    collect_realized_garbage,
    default_capture_runner,
    live_project_files,
    scrub_guest,
    shutdown_guest,
    wait_shutoff,
)
from .errors import BuildError
from .guesttool import ps_quote
from .manifest import (
    BUILD_REALIZED_SECTIONS,
    BaseImageRecord,
    BehavioralCheckRecord,
    BuildManifest,
    GuestRecord,
    RecipeRecord,
    VerificationRecord,
    active_directory_hash,
    default_build_cache,
    guest_build_key,
    load_manifest,
    manifest_matches_spec,
    manifest_path,
    now_iso,
    realized_file_name,
    save_manifest,
    save_refused_manifest,
    validate_range_name,
    vars_hash,
    windows_key_facts,
)
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


SettleFn = Callable[
    [dict[str, int], str, str, float, "HybridSockets", str | None], float
]
"""The network-settle seam: `(cids, guest, probe, timeout_s, hybrid_sockets, windows_resolver) -> seconds waited` (the map dials Cloud Hypervisor guests through their hybrid-vsock sockets; a non-None `windows_resolver` picks the Windows probe shape, querying that build resolver directly)."""


HybridSockets = dict[str, HybridEndpoint]
"""Guest name to the hybrid-vsock endpoint of its Cloud Hypervisor VMM; empty for all-QEMU ranges. Collected from `UpResult.guests` and threaded through every build-side channel (recipes, settle, verify, capture, behavioral), since CH guests have no `AF_VSOCK` listener."""


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
        hybrid_sockets: "HybridSockets | None" = None,
        windows: bool = False,
        build_nameserver: str | None = None,
        quiesced: bool = False,
    ) -> str: ...


class QuiesceFn(Protocol):
    """The quiesce seam: scrub, clean shutdown, and shutoff wait for one guest, separable from the disk copy so a converged capture can quiesce EVERY content host at one point before copying any disk (windows-ad-v1 slice 3)."""

    def __call__(
        self,
        project: str,
        guest: str,
        cids: dict[str, int],
        *,
        hybrid_sockets: "HybridSockets | None" = None,
        windows: bool = False,
        build_nameserver: str | None = None,
    ) -> None: ...


def _quiesce_guest(
    project: str,
    guest: str,
    cids: dict[str, int],
    *,
    hybrid_sockets: "HybridSockets | None" = None,
    windows: bool = False,
    build_nameserver: str | None = None,
) -> None:
    scrub_guest(
        cids, guest, hybrid_sockets, windows=windows, build_nameserver=build_nameserver
    )
    diagnosis = shutdown_guest(cids, guest, hybrid_sockets, windows=windows)
    wait_shutoff(
        default_capture_runner,
        project,
        guest,
        timeout_s=SHUTOFF_TIMEOUT_WINDOWS_S if windows else SHUTOFF_TIMEOUT_S,
        shutdown_diagnosis=diagnosis,
    )


def _capture_realized(
    project: str,
    guest: str,
    cids: dict[str, int],
    *,
    image_cache: Path,
    golden_file: str,
    realized_name: str,
    meta: RealizedImageMeta,
    hybrid_sockets: "HybridSockets | None" = None,
    windows: bool = False,
    build_nameserver: str | None = None,
    quiesced: bool = False,
) -> str:
    if not quiesced:
        _quiesce_guest(
            project,
            guest,
            cids,
            hybrid_sockets=hybrid_sockets,
            windows=windows,
            build_nameserver=build_nameserver,
        )
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
        hybrid_sockets: "HybridSockets | None" = None,
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

    Routerless networks flip to `mode: nat` with an allow-all v4 egress policy and the build nameserver (host-derived by default) appended to their resolvers; router-attached and `routed` networks are untouched. A content-carrying host left with no egress-bearing attachment gets a dedicated `build-uplink` NAT segment appended instead (the routed-topology answer: the runtime spec never carries it, and realized images keep no reference because network config is per-boot cloud-init). Provisioned ROUTERS deliberately get no uplink: attaching one would put a router on an egress-bearing network, the exact combination the semantic gate refuses (`egress-with-router-not-realized`), so router recipes run offline instead (module docstring). The copy re-validates, so the egress semantic gates still apply to what the build actually boots.

    Raises:
        IssueError: when the transformed spec fails re-validation (the semantic gates), as positioned issues where the validator carried them.
    """
    build = spec.model_copy(deep=True)
    router_networks = {
        interface.network for router in build.routers for interface in router.interfaces
    }
    try:
        nameserver = ip_address(
            nameserver_ip if nameserver_ip is not None else default_build_nameserver()
        )
    except ValueError as error:
        raise IssueError(
            [
                Issue(
                    code="build-nameserver-invalid",
                    path=("range", "name"),
                    message=f"build nameserver {nameserver_ip!r} is not an IP address",
                    hint="pass --build-nameserver with a literal resolver IP",
                )
            ]
        ) from error
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
    # the build uplink (linux-examples-v1, answering the recorded goad-era
    # question): a content-carrying host whose every attachment is a
    # router-attached or routed segment has no egress-bearing network after
    # the flips above, so the build variant attaches it to a dedicated NAT
    # uplink segment instead; the runtime spec never carries it, the realized
    # image keeps no reference (network config is per-boot cloud-init), and
    # the proof boot consumes the runtime spec, uplink-free
    egress_bearing = {
        network.name for network in build.networks if network.mode == "nat"
    }
    stranded = [
        host
        for host in build.hosts
        if host.provisioning
        and not any(
            interface.network in egress_bearing for interface in host.interfaces
        )
    ]
    if stranded:
        from ipaddress import ip_network

        taken = {network.name for network in build.networks}
        uplink_name = "build-uplink"
        while uplink_name in taken:
            uplink_name = "ir-" + uplink_name
        declared = [ip_network(str(network.cidr)) for network in build.networks]
        # the last resort lives in CGNAT space (100.64/10): never a guest
        # subnet in practice, and 172.31/16 overlaps AWS default VPCs
        candidates = (
            "10.254.169.0/24",
            "192.168.254.0/24",
            "100.127.199.0/24",
            "172.31.199.0/24",
        )
        uplink_cidr = next(
            (
                candidate
                for candidate in candidates
                if not any(
                    ip_network(candidate).overlaps(existing) for existing in declared
                )
            ),
            None,
        )
        if uplink_cidr is None:
            raise IssueError(
                [
                    Issue(
                        code="build-uplink-cidr-exhausted",
                        path=("networks",),
                        message="every build-uplink candidate subnet overlaps a declared network; the build cannot attach egress",
                        hint="free one of 10.254.169.0/24, 192.168.254.0/24, 100.127.199.0/24, 172.31.199.0/24",
                    )
                ]
            )
        build.networks.append(
            Network(
                name=uplink_name,
                cidr=uplink_cidr,
                mode="nat",
                egress=EgressPolicy(allow=["0.0.0.0/0"]),
                dns=DnsConfig(nameservers=[nameserver]),
            )
        )
        for host in stranded:
            host.interfaces.append(Interface(network=uplink_name))
    # a provisioned FOOTHOLD host is also the attacker, whose runtime
    # containment (egress: none) drops its flows at the hypervisor before any
    # network policy applies; the build boots no agent, so the build variant
    # lifts the drop exactly when recipes must run on that host (every such
    # host has an egress-bearing attachment by now: flipped or uplinked). The
    # runtime spec keeps the containment untouched.
    if build.attacker.host is not None:
        foothold = next(
            (host for host in build.hosts if host.name == build.attacker.host), None
        )
        if foothold is not None and foothold.provisioning:
            build.attacker.egress = "open"
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
    """Resolve and pre-validate every guest's provisioning steps (hosts, then routers), failing fast before anything boots.

    All issues across all steps are collected into one refusal: unresolvable recipes, version-pin mismatches, var violations, and (for now) `offline` recipes.
    """
    steps: list[ResolvedStep] = []
    issues: list[Issue] = []
    provisioned: list[tuple[str, int, Host | Router]] = [
        ("hosts", index, host) for index, host in enumerate(spec.hosts)
    ]
    provisioned += [
        ("routers", index, router) for index, router in enumerate(spec.routers)
    ]
    for section, host_index, host in provisioned:
        for step_index, step in enumerate(host.provisioning):
            path = (section, host_index, "provisioning", step_index)
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
    quiesce_fn: QuiesceFn | None = None,
    behavioral_fn: "BehavioralFn | None" = None,
) -> BuildResult:
    """Build a range: resolve, render the egress build plan, boot, provision, tear down.

    The build is an ordinary project named `ir-<range>-<build spec digest>`; a second build of the same spec while one runs refuses through `up`'s existing project check, naming the running project (known limit, round-2 review: the check sees compose containers, so the behavioral phase's `-bx` window is not covered and two same-spec builds can interleave there; the identity-guarded refused save replaces only the revision this build loaded, keeping a sibling's green manifest safe), and each run renders into its own staging directory so concurrent attempts can never destroy each other's bundles. On any failure after boot the range tears down (unless `keep`), the failure names its stage, guest, and recipe with a log path, and a teardown error is appended to the diagnosed failure, never substituted for it.

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
        options.image_cache
        if options.image_cache is not None
        else default_image_cache()
    )
    build_cache = (
        options.build_cache
        if options.build_cache is not None
        else default_build_cache()
    )
    started = time.monotonic()

    name_issue = validate_range_name(spec.meta.name)
    if name_issue is not None:
        raise IssueError([name_issue])

    steps = resolve_provisioning(spec, range_dir, recipe_cache)
    steps_by_host: dict[str, list[ResolvedStep]] = {}
    for step in steps:
        steps_by_host.setdefault(step.guest, []).append(step)
    content_guests: list[Host | Router] = [
        *(host for host in spec.hosts if has_guest_content(host)),
        *(router for router in spec.routers if has_router_content(router)),
    ]
    content_names = {guest.name for guest in content_guests}
    goldens: dict[str, ImageRef] = {}
    keys: dict[str, str] = {}
    missing: list[Issue] = []
    indexed_guests: list[tuple[str, int, Host | Router]] = [
        ("hosts", index, host) for index, host in enumerate(spec.hosts)
    ]
    indexed_guests += [
        ("routers", index, router) for index, router in enumerate(spec.routers)
    ]
    for section, index, host in indexed_guests:
        if host.name not in content_names:
            continue
        image_name = host.image
        if image_name is None:
            # the planning gate's rule, applied before any image resolution:
            # a content-bearing router must pin its golden itself
            missing.append(
                Issue(
                    code="router-image-required",
                    path=(section, index, "image"),
                    message=f"router {host.name!r} declares provisioning but no image; the default router appliance is a backend resolution its build key cannot pin",
                    hint="declare image: on a content-bearing router (the build key pins the golden its recipes realize on)",
                )
            )
            continue
        reference = resolve_image_reference(image_name, image_cache)
        if reference.digest is None:
            # the Q1 registry tier: a bare name absent from the cache resolves
            # against the configured search path, fetched once and sticky
            # thereafter (freezing is automatic; moving forward is `images
            # refresh`); only a clean not-published miss falls through to the
            # image-not-in-cache refusal, every other failure names itself
            from .._dist import DistError

            try:
                reference = _fetch_image_tier(image_name, image_cache) or reference
            except DistError as error:
                missing.append(
                    Issue(
                        code="image-fetch-failed",
                        path=(section, index, "image"),
                        message=f"image {image_name!r} for guest {host.name!r} is not in the cache and fetching it failed: {error}",
                        hint="fix the configured location (INSPECT_RANGES_REGISTRY), or derive/pull the image manually",
                    )
                )
                continue
        if reference.digest is None:
            missing.append(
                Issue(
                    code="image-not-in-cache",
                    path=(section, index, "image"),
                    message=f"image {image_name!r} for guest {host.name!r} is not in the image cache and no configured location publishes it, so its build key cannot resolve",
                    hint="derive the golden, or publish it and 'inspect-ranges images pull' it (INSPECT_RANGES_REGISTRY sets the search path)",
                )
            )
            continue
        goldens[host.name] = reference
        keys[host.name] = guest_build_key(
            reference.digest,
            host,
            [(s.recipe, s.vars) for s in steps_by_host.get(host.name, [])],
            range_name=spec.meta.name,
            active_directory_hash=active_directory_hash(spec),
            network_state=(
                windows_key_facts(spec, host.name, image_cache=image_cache)
                if isinstance(host, Host) and host.os.type == "windows"
                else None
            ),
        )
    if missing:
        raise IssueError(missing)

    spec_hash = spec_sha256(spec)
    if (range_dir / CHECKS_DIR_NAME).is_dir() and not (
        range_dir / "challenges.yaml"
    ).is_file():
        # the root-level silent-skip guard (round-1 review): a checks tree
        # whose metadata file is missing or misnamed must refuse, not mint a
        # manifest whose proof never ran
        raise BuildError(
            "behavioral",
            f"{CHECKS_DIR_NAME}/ exists but challenges.yaml is missing; "
            "behavioral checks declare through both files, so a misnamed "
            "metadata file would otherwise silently skip the proof",
        )
    checks = checks_declared(range_dir)
    try:
        current_checks_sha = checks_digest(range_dir) if checks else ""
    except OSError as error:
        # unreadable check inputs refuse in the house shape, never traceback
        raise BuildError(
            "behavioral", f"behavioral-check inputs are unreadable: {error}"
        ) from error
    prior = load_manifest(build_cache, spec.meta.name)
    if prior is not None and prior.checks_sha256 and not checks:
        # the inverse of the misnamed-metadata guard (round-2 review): the
        # recorded build was PROVEN by checks that no longer exist, so a
        # silent green rebuild would downgrade proven to unproven-but-
        # consumable with zero signal
        raise BuildError(
            "behavioral",
            "the recorded build carries behavioral proof but this range "
            f"directory declares no checks ({CHECKS_DIR_NAME}/ with "
            "challenges.yaml); restore the checks tree, or delete "
            f"{manifest_path(build_cache, spec.meta.name)} to accept the downgrade",
        )
    reusable: dict[str, GuestRecord] = {}
    if prior is not None:
        for host in content_guests:
            record = prior.guest(host.name)
            if record is None or record.build_key != keys[host.name]:
                continue
            realized = image_cache / record.realized_file
            if realized.is_file() and sha256_file(realized) == record.realized_sha256:
                reusable[host.name] = record

    # CONVERGED mode (windows-ad-v1 slice 3): Windows domain state is
    # cross-guest by nature (machine accounts, NTDS, SYSVOL, DNS
    # registrations), so a multi-guest build carrying Windows content treats
    # its content set as ONE artifact: reuse is all-or-nothing (a partial
    # rebuild would compose disks from different convergence points), and
    # every content host quiesces at one point before any disk is copied. A
    # guest whose state the domain mutates but that declares no content of its
    # own joins the set by declaring any content (at minimum a convergence
    # recipe; declared services or vulnerabilities equally count).
    converged = len(content_guests) > 1 and any(
        isinstance(host, Host) and host.os.type == "windows" for host in content_guests
    )
    if converged and len(reusable) != len(content_guests):
        if reusable:
            tee_note = f"{len(reusable)} of {len(content_guests)} guests unchanged, but converged ranges rebuild whole"
        else:
            tee_note = None
        reusable = {}
    else:
        tee_note = None

    # derived once: egress_build_spec appends it to resolvers and the Windows
    # scrub strips it back out; two independent resolv.conf reads could
    # disagree mid-build (slice-2 review)
    build_ns = (
        options.build_nameserver
        if options.build_nameserver is not None
        else default_build_nameserver()
    )
    build_spec = egress_build_spec(spec, build_ns)

    if (
        prior is not None
        and not options.reverify
        and not options.keep
        # a keep build exists to leave a running range for diagnosis, which
        # the no-op path cannot provide (round-1 review)
        and manifest_matches_spec(prior, spec_hash)
        and all(host.name in reusable for host in content_guests)
        and prior.checks_sha256 == current_checks_sha
        and all(
            record.status == "pass" for record in prior.verification.behavioral_checks
        )
        # a refused manifest (failed proof) is a reuse source, never a cache
    ):
        # the no-op fast path: every key matches, the verification is
        # recorded, and the behavioral-check inputs are the ones that were
        # proven, so nothing boots (all-or-nothing caching, ratified); a new
        # or edited check script re-runs the pass (slice 6 review: proof
        # tools are build inputs even though they are not guest content);
        # the stage record lands in the project that produced the verification
        project = prior.project
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

    for guest in [*build_spec.hosts, *build_spec.routers]:
        if guest.name in reusable:
            # unchanged guests boot from their captured realized image and
            # skip their recipes; verification still covers them in full
            guest.image = reusable[guest.name].realized_file
    project = f"{PROJECT_PREFIX}{spec.meta.name}-{spec_sha256(build_spec)[:12]}"
    tee = _BuildTee(StageLog(state_dir, project), on_stage)
    run_steps = [step for step in steps if step.guest not in reusable]
    if tee_note is not None:
        tee.log("resolve", "ok", converged=tee_note)
    tee.log(
        "resolve",
        "ok",
        recipes=len(steps),
        reused_guests=len(reusable),
        rebuilt_guests=len(content_guests) - len(reusable),
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
            # the build realizes the recipe-realizable guest sections: recipes
            # implement them, behavioral checks prove them, and the challenge
            # plant layer owns declared secret data at sample time
            # (linux-examples-v1); the runtime path keeps its gates
            realized_sections=frozenset(BUILD_REALIZED_SECTIONS),
        )
        try:
            plan = render_bundle(build_spec, staging, plan_options)
        except IssueError:
            tee.log("render", "fail", error="planning refused (see issues)")
            raise
        tee.log("render", "ok", bundle=str(staging), guests=plan.totals.guests)

        uplink = ensure_uplink if ensure_uplink is not None else _ensure_uplink_network
        try:
            uplink(options.uplink_network)
        except BuildError as error:
            tee.log("uplink", "fail", error=str(error))
            raise

        try:
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
        except UpError:
            # up disposed (or kept) the range itself per keep_on_failure; the
            # staging bundle must survive exactly when the range does (round-1
            # review: a kept boot failure is precisely when plan.json matters)
            kept = options.keep
            raise
        except BaseException:
            # a non-UpError exit (Ctrl-C mid-boot) gives no disposal guarantee:
            # assume the range survives and keep the bundle it mounts (round-2)
            kept = True
            raise
        # the range is running from here: staging survives (the running range
        # mounts it) until a teardown actually succeeds or _dispose rules
        kept = True

        cids = {guest.name: guest.cid for guest in result.guests}
        hybrid: HybridSockets = {
            guest.name: guest.hybrid_vsock
            for guest in result.guests
            if guest.hybrid_vsock is not None
        }
        guest_os = {host.name: host.os.type for host in spec.hosts}
        for router in spec.routers:
            # windows routers refuse at planning, so a router's recipes always
            # run the linux executor path
            guest_os[router.name] = router.os.type if router.os is not None else "linux"
        windows_hosts = frozenset(
            name for name, os_type in guest_os.items() if os_type == "windows"
        )
        defense_by_host = {
            host.name: host.defense for host in spec.hosts if host.defense is not None
        }
        # the scrub must never strip a resolver the RUNTIME spec declares:
        # egress_build_spec only appends build_ns where it is not already
        # declared, so a declared match means the address is legitimate
        # baked state (slice-2 review)
        declared_resolvers = {
            str(address)
            for network in spec.networks
            if network.dns is not None and network.dns.nameservers
            for address in network.dns.nameservers
        }
        scrub_ns = None if build_ns in declared_resolvers else build_ns
        log_dir = project_dir(state_dir, project) / "recipes"
        runs: list[RecipeRun] = []
        settle = settle_fn if settle_fn is not None else _settle_network
        router_names = frozenset(router.name for router in spec.routers)
        settled: set[str] = set()
        try:
            for step in run_steps:
                if step.guest in router_names and step.guest not in settled:
                    # routers get no build egress (their attached networks stay
                    # untouched by the egress variant, and the router-attached
                    # egress combination is itself unrealized), so the settle
                    # gate's claim cannot hold for them: a router's recipes run
                    # offline, and one that reaches for the network fails as an
                    # ordinary recipe error
                    tee.log(
                        "network-settle",
                        "ok",
                        guest=step.guest,
                        skipped="router (recipes run without build egress)",
                    )
                    settled.add(step.guest)
                if options.settle_probe is not None and step.guest not in settled:
                    seconds = settle(
                        cids,
                        step.guest,
                        options.settle_probe,
                        options.settle_timeout_s,
                        hybrid,
                        build_ns if step.guest in windows_hosts else None,
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
                    target=RecipeTarget(
                        guest=step.guest,
                        cids=cids,
                        hybrid_sockets={
                            name: (str(endpoint.path), endpoint.peer_uid)
                            for name, endpoint in hybrid.items()
                        },
                        guest_os=guest_os,
                        active_directory=(
                            spec.active_directory.model_dump_json()
                            if spec.active_directory is not None
                            else None
                        ),
                        host_defense=(
                            defense_by_host[step.guest].model_dump_json()
                            if defense_by_host.get(step.guest) is not None
                            else None
                        ),
                    ),
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
            tee.log(error.stage, "fail", error=_strip_stage(error))
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                error.stage,
                f"{_strip_stage(error)} ({disposition})",
                guest=error.guest,
                recipe=error.recipe,
                log_path=error.log_path,
            ) from error
        except Exception as error:
            # the one post-boot arm that lacked a broad disposal catch
            # (round-2 review): an ENOSPC out of the log plumbing must
            # dispose and name its stage like every sibling phase, never
            # leak the egress-enabled range behind a raw traceback
            tee.log("recipe", "fail", error=str(error))
            disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
            raise BuildError(
                "recipe", f"recipe phase failed: {error} ({disposition})"
            ) from error

        verify_dir = project_dir(state_dir, project) / "verify"
        try:
            verifications = verify_fn(
                spec, cids, log_dir=verify_dir, stage_log=tee, hybrid_sockets=hybrid
            )
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
        manifest: BuildManifest | None = None
        verified_at: str | None = None
        if options.keep:
            tee.log("capture", "ok", skipped="--keep (diagnostic build; no manifest)")
        else:
            capture = capture_fn if capture_fn is not None else _capture_realized
            quiesce = quiesce_fn if quiesce_fn is not None else _quiesce_guest
            guest_records: list[GuestRecord] = []
            try:
                if converged:
                    # one quiesce point: every content host is scrubbed and
                    # shut off before ANY disk is copied, so cross-guest
                    # domain state (replication, machine accounts) is
                    # captured from a single moment, never a sliding window.
                    # Quiesce order is spec declaration order: today's scrub
                    # steps are purely guest-local, but a future domain-aware
                    # scrub would make this ordering load-bearing (the root
                    # DC, declared first, shuts off first)
                    for host in content_guests:
                        if host.name in reusable:
                            continue
                        try:
                            quiesce(
                                project,
                                host.name,
                                cids,
                                hybrid_sockets=hybrid,
                                windows=host.name in windows_hosts,
                                build_nameserver=scrub_ns,
                            )
                        except BuildError as error:
                            # re-staged: no disk copy has started, and the
                            # stage log should say which phase actually died
                            raise BuildError(
                                "quiesce", _strip_stage(error), guest=host.name
                            ) from error
                        tee.log("quiesce", "ok", guest=host.name)
                for host in content_guests:
                    if host.name in reusable:
                        guest_records.append(reusable[host.name])
                        continue
                    key = keys[host.name]
                    realized_name = realized_file_name(spec.meta.name, host.name, key)
                    golden = goldens[host.name]
                    assert (
                        golden.digest is not None
                    )  # gated by the image-not-in-cache refusal above
                    digest = capture(
                        project,
                        host.name,
                        cids,
                        image_cache=image_cache,
                        golden_file=golden.file,
                        realized_name=realized_name,
                        hybrid_sockets=hybrid,
                        windows=host.name in windows_hosts,
                        build_nameserver=scrub_ns,
                        quiesced=converged,
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
                            golden_reference=golden.reference,
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
                # the stage log is the --keep-free diagnosis artifact: a
                # quiesce or capture failure must leave a fail row like every
                # sibling phase (slice-3 review)
                tee.log(error.stage, "fail", error=_strip_stage(error))
                disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
                raise BuildError(
                    error.stage,
                    f"{_strip_stage(error)} ({disposition})",
                    guest=error.guest,
                ) from error
            except Exception as error:
                # a raising capture (docker cp timeout, full disk) must dispose
                # like every other stage, never escape raw past teardown
                tee.log("capture", "fail", error=str(error))
                disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
                raise BuildError(
                    "capture", f"capture failed: {error} ({disposition})"
                ) from error
            try:
                verified_at = now_iso()
                manifest = BuildManifest(
                    range_name=spec.meta.name,
                    schema_version=spec.meta.schema_version,
                    spec_sha256=spec_hash,
                    spec=spec.model_dump(mode="json", by_alias=True),
                    project=project,
                    built_at=verified_at,
                    checks_sha256=current_checks_sha,
                    base_images=_base_images(spec, image_cache),
                    guests=tuple(guest_records),
                    verification=VerificationRecord(
                        verified_at=verified_at, declarations=tuple(verifications)
                    ),
                )
                if not checks:
                    # with checks declared the save is DEFERRED past the
                    # behavioral phase: a manifest on disk is consumable by the
                    # gate, and nothing unproven may ever be consumable, under
                    # any exit (teardown failure, Ctrl-C, a crash mid-phase)
                    saved_manifest = save_manifest(manifest, build_cache)
            except Exception as error:
                tee.log("manifest", "fail", error=str(error))
                disposition, kept = _dispose(options, project, down_fn, tee, state_dir)
                raise BuildError(
                    "manifest", f"manifest write failed: {error} ({disposition})"
                ) from error
            if saved_manifest is not None:
                tee.log(
                    "manifest",
                    "ok",
                    path=str(saved_manifest),
                    guests=len(guest_records),
                )

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

        if not options.keep and manifest is not None and checks:
            # behavioral checks run against the CAPTURED artifacts: the exact
            # images samples boot, after the build range is down (slice 6);
            # the manifest is handed over in memory and lands on disk either
            # proven (all checks pass) or REFUSED (the gate rejects it,
            # parked-decisions item 4)
            behavioral = (
                behavioral_fn if behavioral_fn is not None else _run_behavioral_phase
            )
            try:
                behavioral_records = behavioral(
                    spec,
                    range_dir,
                    manifest=manifest,
                    image_cache=image_cache,
                    build_cache=build_cache,
                    state_dir=state_dir,
                    options=options,
                    project=project,
                    stage_log=tee,
                    up_fn=up_fn,
                    down_fn=down_fn,
                )
            except BuildError as error:
                # an infra or authoring failure left the proof unrun: the
                # refused manifest carries a synthetic phase record, so the
                # gate refuses range-unproven while guest reuse survives
                # (parked-decisions item 4; this replaced deletion)
                tee.log("behavioral", "fail", error=str(error))
                _save_refused(
                    manifest,
                    (
                        BehavioralCheckRecord(
                            challenge="",
                            check="phase",
                            status="fail",
                            detail=_strip_stage(error),
                        ),
                    ),
                    build_cache,
                    tee,
                    prior.built_at if prior is not None else None,
                )
                raise BuildError(
                    error.stage,
                    f"{_strip_stage(error)} ({REFUSED_CLAUSE})",
                ) from error
            except Exception as error:
                tee.log("behavioral", "fail", error=str(error))
                _save_refused(
                    manifest,
                    (
                        BehavioralCheckRecord(
                            challenge="",
                            check="phase",
                            status="fail",
                            detail=str(error),
                        ),
                    ),
                    build_cache,
                    tee,
                    prior.built_at if prior is not None else None,
                )
                raise BuildError(
                    "behavioral",
                    f"behavioral phase failed: {error} ({REFUSED_CLAUSE})",
                ) from error
            failed = [
                record for record in behavioral_records if record.status != "pass"
            ]
            if failed:
                verdict = failed[0]
                tee.log(
                    "behavioral",
                    "fail",
                    challenge=verdict.challenge,
                    check=verdict.check,
                    error=verdict.detail,
                )
                _save_refused(
                    manifest,
                    behavioral_records,
                    build_cache,
                    tee,
                    prior.built_at if prior is not None else None,
                )
                raise BuildError(
                    "behavioral",
                    f"challenge {verdict.challenge!r} check {verdict.check!r} "
                    f"failed: {verdict.detail} ({REFUSED_CLAUSE})",
                )
            tee.log("behavioral", "ok", checks=len(behavioral_records))
            manifest = manifest.model_copy(
                update={
                    "verification": manifest.verification.model_copy(
                        update={"behavioral_checks": behavioral_records}
                    )
                }
            )
            try:
                saved_manifest = save_manifest(manifest, build_cache)
            except Exception as error:
                # the build range is already down; nothing to dispose
                tee.log("manifest", "fail", error=str(error))
                raise BuildError(
                    "manifest", f"manifest write failed: {error}"
                ) from error
            tee.log(
                "manifest",
                "ok",
                path=str(saved_manifest),
                guests=len(manifest.guests),
            )
    finally:
        if not kept:
            shutil.rmtree(staging, ignore_errors=True)

    if saved_manifest is not None and manifest is not None:
        # automatic realized-image GC at build success (parked-decisions item
        # 1): range-scoped, keep-1 (the replaced manifest's generation stays
        # for free rollback), running projects excluded precisely via their
        # boot.json; failures here never fail a green build
        try:
            keep = {record.realized_file for record in manifest.guests}
            if prior is not None:
                keep |= {record.realized_file for record in prior.guests}
            keep |= live_project_files(state_dir)
            removed, reclaimed = collect_realized_garbage(
                spec.meta.name, image_cache, keep
            )
            if removed:
                tee.log(
                    "gc",
                    "ok",
                    files=removed,
                    reclaimed_mb=round(reclaimed / (1024 * 1024)),
                )
        except Exception as error:  # pragma: no cover - best-effort stewardship
            tee.log("gc", "fail", error=str(error))

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


class BehavioralFn(Protocol):
    """The behavioral-check seam: boot the captured artifacts and run the declared checks."""

    def __call__(
        self,
        spec: RangeSpec,
        range_dir: Path,
        *,
        manifest: BuildManifest,
        image_cache: Path,
        build_cache: Path,
        state_dir: Path,
        options: "BuildOptions",
        project: str,
        stage_log: StageSink,
        up_fn: UpFn,
        down_fn: DownFn,
    ) -> tuple[BehavioralCheckRecord, ...]: ...


def _run_behavioral_phase(
    spec: RangeSpec,
    range_dir: Path,
    *,
    manifest: BuildManifest,
    image_cache: Path,
    build_cache: Path,
    state_dir: Path,
    options: "BuildOptions",
    project: str,
    stage_log: StageSink,
    up_fn: UpFn,
    down_fn: DownFn,
) -> tuple[BehavioralCheckRecord, ...]:
    """Boot the just-captured realized artifacts (the exact things samples boot) and run the checks against them; exploit debris dirties only this boot's overlays.

    The manifest arrives in memory, not from disk: it is saved only after this phase passes, so an unproven build is never consumable (slice 6 review).
    """
    from .manifest import realized_backings, swap_realized_spec

    swapped, sections = swap_realized_spec(spec, manifest, image_cache=image_cache)
    # the proof boot draws (variable-draws-v0): a sample boot renders drawn
    # values into the seeds, so the proof must too, or the boot-apply units
    # and the chains' value discovery would ship unproven
    draw_seed = secrets.token_hex(8)
    draws = draw_variables(spec.variables, draw_seed)
    staging_root = state_dir.parent / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=staging_root, prefix=f"{project}-bx-"))
    # mkdtemp creates 0700; the capture sidecar runs with cap_drop ALL (no
    # CAP_DAC_OVERRIDE), so container root cannot traverse a 0700 bundle mount
    staging.chmod(0o755)
    bx_project = f"{project}-bx"
    rotate_stale_bx_state(state_dir, bx_project)
    # beacons must land in a ROTATED capture chunk to corroborate, and the
    # default 10 MB chunk never rotates for check-sized traffic: the bx boot
    # defaults to 1 MB chunks (parked-decisions item 6); explicit env wins
    chunk_override = os.environ.get("CAPTURE_CHUNK_MB")
    if chunk_override is None:
        os.environ["CAPTURE_CHUNK_MB"] = "1"
    bx_down = True  # until a boot succeeds there is nothing to keep the bundle for
    try:
        plan = render_bundle(
            swapped,
            staging,
            PlanOptions(
                image_cache=image_cache,
                cid_base=options.cid_base,
                realized_sections=sections,
                realized_backings=realized_backings(manifest),
                evidence_capture=True,
                # prober-backed goals probe from rendered endpoints: the proof
                # boot's bundle carries the same probe segments the provider
                # derives per sample, or the per-check prober has no vantage
                # and run_setup refuses active-prober
                probe_segments=(
                    probe_segments_for_checks(load_challenges(range_dir), spec)
                    if checks_declared(range_dir)
                    else ()
                ),
                draws=draws,
            ),
        )
        result = up_fn(
            staging,
            UpOptions(
                project=bx_project,
                image_cache=image_cache,
                state_dir=state_dir,
                readiness_timeout=options.readiness_timeout,
                keep_on_failure=False,
            ),
            on_stage=None,
        )
        cids = {guest.name: guest.cid for guest in result.guests}
        bx_hybrid: HybridSockets = {
            guest.name: guest.hybrid_vsock
            for guest in result.guests
            if guest.hybrid_vsock is not None
        }
        # from here the bx range is RUNNING: every exit, including the
        # conformance stage's designed refusal and a convergence timeout,
        # must pass through the teardown finally (round-3 review B1)
        try:
            return _prove_realized_boot(
                spec,
                plan,
                range_dir,
                cids=cids,
                bx_hybrid=bx_hybrid,
                bx_project=bx_project,
                staging=staging,
                state_dir=state_dir,
                options=options,
                stage_log=stage_log,
                settle_spec=_drawn_spec(range_dir, draws) if draws else spec,
                draws=draws,
                draw_seed=draw_seed,
            )
        finally:
            try:
                down_fn(bx_project, state_dir=state_dir, keep_state=True)
                bx_down = True
            except Exception as error:  # the primary diagnosis stays primary
                bx_down = False
                stage_log.log(
                    "teardown",
                    "fail",
                    error=f"{error}; retry with: inspect-ranges down {bx_project}",
                    project=bx_project,
                )
    finally:
        if chunk_override is None:
            os.environ.pop("CAPTURE_CHUNK_MB", None)
        # the surviving-range-keeps-its-bundle invariant applies to the bx
        # range too (round-2): a failed bx teardown leaves the bundle for the
        # retry hint to make sense
        if bx_down:
            shutil.rmtree(staging, ignore_errors=True)


def _drawn_spec(range_dir: Path, draws: dict[str, int | str]) -> RangeSpec:
    """The spec as the proof boot runs it: raw `range.yaml` re-substituted with the drawn values over the defaults (variable-draws-v0).

    The validated `spec` carries the defaults everywhere a reference stood, but the boot-apply units move drawn services to their drawn values, so the settle gate must verify against this view or it would wait on default ports that no longer answer. Only the settle gate consumes it; the build itself realizes defaults.
    """
    import yaml as _yaml

    from ..schema import substitute_variables

    data: Any = _yaml.safe_load((range_dir / "range.yaml").read_text())
    substituted, issues = substitute_variables(data, overrides=draws)
    if issues:  # the build already loaded this file; a new issue is a race
        raise BuildError(
            "behavioral",
            f"range.yaml no longer substitutes cleanly: {issues[0].message}",
        )
    return RangeSpec.model_validate(substituted)


def _prove_realized_boot(
    spec: RangeSpec,
    plan: ResolvedPlan,
    range_dir: Path,
    *,
    cids: dict[str, int],
    bx_hybrid: "HybridSockets",
    bx_project: str,
    staging: Path,
    state_dir: Path,
    options: "BuildOptions",
    stage_log: StageSink,
    settle_spec: RangeSpec,
    draws: dict[str, int | str],
    draw_seed: str | None,
) -> tuple[BehavioralCheckRecord, ...]:
    """Convergence, conformance, and the behavioral checks against the booted bx range (the caller owns the teardown finally).

    `settle_spec` is the drawn view of the spec (`_drawn_spec`): the settle gate verifies declared services where the boot-apply units put them, while scoring and conformance read the unchanged `spec` plus `draws`.
    """
    from .behavioral import run_behavioral_checks, run_conformance_checks

    # the realized boot must CONVERGE before the proof runs: readiness
    # covers the control plane, not the app stack (a fresh-instance boot
    # re-seeds, and era daemons reconnect to their databases on their own
    # schedule), and the declared services are exactly the convergence
    # contract, so the slice-4 engine gates the checks (vulhub live
    # finding: zabbix-server listens only once mysqld accepts)
    settle_dir = project_dir(state_dir, bx_project) / "settle"
    settle_started = time.monotonic()
    deadline = settle_started + options.readiness_timeout
    while True:
        failing = [
            result_
            for result_ in verify_range(
                settle_spec, cids, log_dir=settle_dir, hybrid_sockets=bx_hybrid
            )
            if result_.status != "ok"
        ]
        if not failing:
            break
        if time.monotonic() > deadline:
            first = failing[0]
            raise BuildError(
                "behavioral",
                f"the realized boot did not converge within "
                f"{options.readiness_timeout:.0f} s: {first.kind} "
                f"{first.guest}/{first.name} ({first.observed})",
            )
        time.sleep(5.0)
    stage_log.log(
        "behavioral-settle",
        "ok",
        seconds=round(time.monotonic() - settle_started, 1),
    )
    # agent-containment section 6, automated (issue #6): the converged
    # realized boot proves its defender-to-agent containment before the
    # challenge proof runs; a finding refuses the manifest like any
    # failed proof
    asyncio.run(
        run_conformance_checks(
            spec, plan, cids, hybrid_sockets=bx_hybrid, stage_log=stage_log
        )
    )
    return asyncio.run(
        run_behavioral_checks(
            spec,
            plan,
            range_dir,
            project=bx_project,
            bundle=staging,
            cids=cids,
            evidence_dir=project_dir(state_dir, bx_project) / "evidence",
            stage_log=stage_log,
            hybrid_sockets=bx_hybrid,
            draws=draws,
            draw_seed=draw_seed,
        )
    )


def rotate_stale_bx_state(state_dir: Path, bx_project: str) -> None:
    """Move a leftover bx project directory aside so the proof boot's evidence record starts empty.

    Every bx teardown keeps its project state (`keep_state=True`: the evidence record is the proof's audit trail), and the next build of the same spec reuses the deterministic `-bx` project name — the store's chunks and manifest parts are write-once, so without rotation every chunk collides as a recorded gap and the telemetry windows can never complete (measured, windows-ad-v1 slice 5). The previous run's directory is renamed, not deleted, so the latest prior record stays available for autopsy; OLDER rotated copies are pruned so repeated rebuilds hold exactly one stale sibling instead of accumulating evidence stores without bound (slice-5 review finding 3). The known `-bx` interleave limit applies here too: a concurrent same-spec build's live store would rotate with it.
    """
    stale = project_dir(state_dir, bx_project)
    if stale.exists():
        for old in stale.parent.glob(f"{stale.name}-stale-*"):
            shutil.rmtree(old, ignore_errors=True)
        stale.rename(stale.with_name(f"{stale.name}-stale-{int(time.time() * 1000)}"))


def _fetch_image_tier(name: str, image_cache: Path) -> "ImageRef | None":
    """Try the registry search path for a bare image name; `None` only for a clean not-published miss. Integrity, auth, and reachability failures PROPAGATE (round-3 B3): a corruptly published or auth-denied chain must refuse loudly, never degrade into "not published"."""
    import os as _os

    from .._dist.location import registry_locations
    from .._dist.progress import TransferDisplay
    from .._dist.resolve import NEVER_PULL_ENV, pull_image

    if _os.environ.get(NEVER_PULL_ENV):
        return None  # pinned hosts skip the implicit tier; the refusal's hint names the pull
    display = TransferDisplay()
    try:
        pulled = pull_image(
            name,
            registry_locations(),
            image_cache=image_cache,
            progress=display,
        )
    finally:
        display.close()
    if pulled is None:
        return None
    return resolve_image_reference(name, image_cache)


def _base_images(spec: RangeSpec, image_cache: Path) -> tuple[BaseImageRecord, ...]:
    """Every guest's base image resolved to a digest (range-build's resolved-inputs commitment)."""
    records: list[BaseImageRecord] = []
    guests: list[tuple[str, str, str | None]] = [
        (host.name, "host", host.image) for host in spec.hosts
    ]
    guests += [(router.name, "router", router.image) for router in spec.routers]
    guests.append((spec.attacker.name, "attacker", spec.attacker.image))
    for name, kind, reference in guests:
        if reference is None:
            continue  # defaulted images resolve at plan time; recorded when a default lands here
        resolved = resolve_image_reference(reference, image_cache)
        records.append(
            BaseImageRecord(
                guest=name,
                kind=kind,
                reference=reference,
                file=resolved.file,
                digest=resolved.digest or "",
            )
        )
    return tuple(records)


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


REFUSED_CLAUSE = (
    "a refused manifest was recorded; consumers refuse range-unproven "
    "until a rebuild proves the range"
)
"""The failure clause for the behavioral phase: proof-or-refuse now lands as a saved-but-gate-refused manifest (parked-decisions item 4), which keeps guest reuse while nothing unproven is consumable."""


def _save_refused(
    manifest: BuildManifest,
    records: tuple[BehavioralCheckRecord, ...],
    build_cache: Path,
    tee: "_BuildTee",
    supersedes_built_at: str | None,
) -> None:
    """Record the failed proof, identity-guarded: the refused manifest replaces only the revision this build loaded at resolve, never a concurrent sibling's fresh save (round-2 review); a save failure is logged, never masks the verdict."""
    refused = manifest.model_copy(
        update={
            "verification": manifest.verification.model_copy(
                update={"behavioral_checks": records}
            )
        }
    )
    try:
        path = save_refused_manifest(refused, build_cache, supersedes_built_at)
        if path is not None:
            tee.log("manifest", "ok", path=str(path), refused=True)
        else:
            tee.log(
                "manifest",
                "fail",
                error="a newer manifest exists (concurrent build); the refused verdict was not recorded",
            )
    except Exception as error:  # the verdict is the primary diagnosis
        tee.log("manifest", "fail", error=f"refused-manifest write failed: {error}")


def _strip_stage(error: BuildError) -> str:
    """The message portion of a `BuildError` without its exact `[stage] guest .. recipe ..:` prefix (for re-wrapping); colons INSIDE the message (challenge names, command detail) are preserved verbatim, which the old split-on-first-colon mangled (round-1 review)."""
    text = str(error)
    detail = f" guest {error.guest!r}" if error.guest else ""
    detail += f" recipe {error.recipe!r}" if error.recipe else ""
    prefix = f"[{error.stage}]{detail}: " if detail else f"[{error.stage}] "
    return text[len(prefix) :] if text.startswith(prefix) else text


def _settle_network(
    cids: dict[str, int],
    guest: str,
    probe: str,
    timeout_s: float,
    hybrid_sockets: "HybridSockets | None" = None,
    windows_resolver: str | None = None,
) -> float:
    """Block until the guest resolves `probe` (the build-egress DNS warm-up gate); returns the wait.

    A Windows guest queries `windows_resolver` (the build's egress resolver) DIRECTLY: on an `dns.authoritative` network the system resolver order deliberately leads with a DC whose DNS does not exist yet (measured: `-QuickTimeout` aborts on the dead preferred server and plain resolution burns any honest budget on it), and the gate's claim is exactly that the EGRESS resolver answers from inside the guest — the in-domain resolution path is the promotion recipe's own exit criterion.

    Raises:
        BuildError: stage `network-settle` when the guest cannot resolve within the bound, carrying the last underlying cause; the build's egress promise would be a lie for its recipes.
    """
    if windows_resolver is not None:
        # PowerShell cold-start alone costs seconds: the exec budget is
        # windows-sized (measured: 5 s loses every attempt)
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; "
            f"Resolve-DnsName -Name {ps_quote(probe)} "
            f"-Server {ps_quote(windows_resolver)} "
            "-Type A -QuickTimeout | Out-Null",
        ]
        command_ms = 15_000
    else:
        cmd = ["getent", "hosts", probe]
        command_ms = 5_000

    async def wait() -> float:
        channel = MessageChannel(
            VsockTransport(cids, hybrid_sockets=hybrid_sockets), label="build-settle"
        )
        started = time.monotonic()
        deadline = started + timeout_s
        last_cause = "resolution never succeeded"
        while time.monotonic() < deadline:
            try:
                outcome = await channel.exec(
                    guest,
                    ExecRequest(
                        id=request_id(),
                        cmd=cmd,
                        budget=Budget(command_ms=command_ms),
                    ),
                )
                if outcome.rc == 0:
                    return time.monotonic() - started
                last_cause = f"{cmd[0]} exited {outcome.rc}"
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
        raise BuildError("uplink", "docker is not installed or not on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise BuildError(
            "uplink", f"docker did not answer within 60 s while ensuring {name!r}"
        ) from error
    if create.returncode != 0:
        # two concurrent first builds can race create; the loser's failure is
        # benign iff the network now exists (round-1 review)
        try:
            recheck = subprocess.run(
                ["docker", "network", "inspect", name], capture_output=True, timeout=60
            )
            if recheck.returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass  # fall through to the create failure, the primary diagnosis
        stderr = create.stderr.decode(errors="replace").strip()[-300:]
        raise BuildError(
            "uplink",
            f"docker network create {name!r} failed (rc {create.returncode}): {stderr or '(no stderr)'}",
        )
