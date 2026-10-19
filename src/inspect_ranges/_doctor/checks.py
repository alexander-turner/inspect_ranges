import json
import os
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .result import CheckResult, CheckStatus

PLATFORM = "Platform"
REALIZER = "Realizer"
PROVIDER = "Provider"
HOST = "Host"
EVIDENCE = "Evidence"
VIRTUALIZATION = "Virtualization"
DOCKER = "Docker"
NETWORKING = "Networking"
DISTRIBUTION = "Distribution"
IMAGE_TOOLING = "Image tooling"
BUILD = "Build"

# same minimums as inspect_ai's Docker sandbox provider (Compose 2.22.0 is its `pull --policy` floor)
DOCKER_ENGINE_MIN_VERSION = (24, 0, 6)
DOCKER_COMPOSE_MIN_VERSION = (2, 22, 0)

COMMAND_TIMEOUT = 30


def run_checks() -> list[CheckResult]:
    """Check this machine, returning results in report order."""
    results = _readiness_results()
    host = results[0]
    if host.status == "ok":
        results += [
            check_br_netfilter(Path("/proc/sys")),
            check_ipv6(Path("/proc/sys")),
            *check_image_tools(shutil.which),
            check_kernel_readable(Path("/boot")),
        ]
    else:
        results.append(_skip(NETWORKING, "all checks", "requires Linux x86_64"))
        results.append(_skip(IMAGE_TOOLING, "all checks", "requires Linux x86_64"))
    results += check_provider(
        state_dir=_provider_state_dir(),
        image_cache=_provider_image_cache(),
    )
    results += check_host(
        state_dir=_provider_state_dir(),
        backend=os.environ.get("INSPECT_RANGES_HOST", "local"),
    )
    results += check_evidence(
        sink_override=os.environ.get("INSPECT_RANGES_EVIDENCE_SINK"),
        log_dir=os.environ.get("INSPECT_LOG_DIR"),
    )
    from .._build.manifest import default_build_cache
    from .._build.recipes import default_recipe_cache

    results += check_build(default_build_cache(), default_recipe_cache())
    results += check_distribution(_provider_image_cache())
    if host.status != "ok":
        results.append(_skip(REALIZER, "all checks", "requires Linux x86_64"))
    else:
        docker_probe = _run(["docker", "version", "--format", "ok"])
        results += check_realizer(
            image_inspect=(
                _run(
                    [
                        "docker",
                        "image",
                        "inspect",
                        _range_image_tag(),
                        "--format",
                        "ok",
                    ]
                )
                if docker_probe is not None and docker_probe.returncode == 0
                else None
            ),
        )
    return results


def check_distribution(image_cache: Path) -> list[CheckResult]:
    """The distribution rows: configured locations parse (directory forms exist and are valid layouts), and the cache's provenance chains are whole (every realized image's golden present, every golden's vendor present)."""
    from .._dist.errors import DistError
    from .._dist.location import REGISTRY_ENV, registry_locations

    results: list[CheckResult] = []
    configured = os.environ.get(REGISTRY_ENV)
    try:
        locations = registry_locations(configured)
        broken: list[str] = []
        for location in locations:
            if location.directory is not None:
                try:
                    from .._dist.oci import OciLayout

                    OciLayout(location.directory).open()
                except DistError as error:
                    broken.append(f"{location.describe()}: {error}")
        if broken:
            results.append(
                CheckResult(
                    DISTRIBUTION,
                    "locations",
                    "fail",
                    "; ".join(broken),
                    fix="fix or remove the broken location from INSPECT_RANGES_REGISTRY (a broken first location aborts pulls rather than de-shadowing)",
                )
            )
        else:
            source = "INSPECT_RANGES_REGISTRY" if configured else "default"
            results.append(
                CheckResult(
                    DISTRIBUTION,
                    "locations",
                    "ok",
                    f"{', '.join(location.describe() for location in locations)} "
                    f"({source}; parse-only, registry reachability surfaces on first use)",
                )
            )
    except DistError as error:
        results.append(
            CheckResult(
                DISTRIBUTION,
                "locations",
                "fail",
                str(error),
                fix="fix INSPECT_RANGES_REGISTRY (comma-separated locations)",
            )
        )
    import json as json_module

    missing: list[str] = []
    for sidecar in sorted(image_cache.glob("*.realized.json")):
        try:
            golden = json_module.loads(sidecar.read_text()).get("golden_file")
        except (OSError, ValueError):
            continue
        if isinstance(golden, str) and not (image_cache / golden).is_file():
            missing.append(f"{sidecar.name} -> {golden}")
    for sidecar in sorted(image_cache.glob("*.json")):
        if sidecar.name.endswith(".realized.json"):
            continue
        try:
            meta = json_module.loads(sidecar.read_text())
        except (OSError, ValueError):
            continue
        vendor = meta.get("vendor_file")
        file = meta.get("file")
        if (
            isinstance(vendor, str)
            and isinstance(file, str)
            and (image_cache / file).is_file()
            and not (image_cache / vendor).is_file()
        ):
            missing.append(f"{file} -> {vendor}")
    try:
        from .._build.manifest import default_build_cache as _builds
        from .._dist.gc import unreferenced_chain_files

        # a dirty (lock-free) read is fine for a warn row; the GC itself
        # always re-scans under its exclusive lock
        _, frozen = unreferenced_chain_files(image_cache, _builds(), set())
    except Exception:
        frozen = []
    for reason in frozen[:3]:
        missing.append(f"frozen: {reason}")
    if missing:
        results.append(
            CheckResult(
                DISTRIBUTION,
                "cache chains",
                "warn",
                f"{len(missing)} issue(s): {'; '.join(missing[:4])}",
                fix="re-pull or re-derive the named chains (up refuses mixed chains; a frozen chain also skips the vendor-edge boot check until fixed)",
            )
        )
    else:
        results.append(CheckResult(DISTRIBUTION, "cache chains", "ok", "whole"))
    return results


def _readiness_results() -> list[CheckResult]:
    """The readiness subset (platform first, then virtualization devices and docker): the opening segment of `run_checks` and the whole of `readiness_failures`, defined once so the doctor report and the acquire gate can never disagree."""
    host = check_platform(platform.system(), platform.machine())
    results = [host]
    if host.status == "ok":
        results += check_virtualization(Path("/dev"))
    else:
        results.append(_skip(VIRTUALIZATION, "all checks", "requires Linux x86_64"))
    results += check_docker(
        info=_run(["docker", "info", "--format", "{{json .}}"]),
        compose=_run(["docker", "compose", "version", "--format", "json"]),
    )
    return results


def readiness_failures() -> list[str]:
    """The fast readiness subset host backends gate `acquire` on (`host-provider.md:94`): platform, virtualization devices, docker.

    Failure lines only; `warn` and `skip` results pass (an optional module must never fail acquisition). The full battery stays `run_checks`; this subset is cheap enough to run once per task.
    """
    return [
        f"{result.group}: {result.name}: {result.detail}"
        for result in _readiness_results()
        if result.status == "fail"
    ]


def _provider_state_dir() -> Path:
    from .._runtime.ownership import default_state_dir

    return default_state_dir()


def _provider_image_cache() -> Path:
    from .._runtime.images import default_image_cache

    return default_image_cache()


def check_provider(state_dir: Path, image_cache: Path) -> list[CheckResult]:
    """The Inspect sandbox provider surface: entry-point registration, the inspect-ai floor, a current-recipe golden, and the CID lease registry's health."""
    import importlib.metadata as metadata

    from .._runtime.images import RECIPE_VERSION, ImageMetadata

    results: list[CheckResult] = []

    # entry point: the only registration path `inspect eval` has
    entries = {e.name: e.value for e in metadata.entry_points(group="inspect_ai")}
    if entries.get("inspect_ranges") == "inspect_ranges._registry":
        results.append(CheckResult(PROVIDER, "entry point", "ok", "range registered"))
    else:
        results.append(
            CheckResult(
                PROVIDER,
                "entry point",
                "fail",
                "inspect_ranges is not registered in the inspect_ai entry-point group",
                fix="reinstall the package: pip install -e . (or uv sync)",
            )
        )

    # inspect-ai floor, read from this package's own dependency pin
    floor = _inspect_ai_floor()
    try:
        installed = metadata.version("inspect-ai")
    except metadata.PackageNotFoundError:
        installed = None
    if installed is None:
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "fail",
                "inspect-ai is not installed",
                fix="pip install inspect-ai",
            )
        )
    elif floor is None:
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "warn",
                f"{installed} installed, but the package's own floor could not be "
                "read from its metadata, so the version check did not run",
            )
        )
    elif (parse_version(installed) or ()) < (parse_version(floor) or ()):
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "fail",
                f"{installed} is below the verified floor {floor}",
                fix=f"pip install 'inspect-ai>={floor}'",
            )
        )
    else:
        results.append(CheckResult(PROVIDER, "inspect-ai", "ok", installed))

    # a current-recipe golden must exist as both sidecar AND image file;
    # older-recipe goldens carry a pre-3.1.0 daemon whose session-less pong
    # the host rejects tamper-shaped at boot
    current: list[str] = []
    other_recipe: list[tuple[str, str]] = []
    missing_file: list[str] = []
    for sidecar in sorted(image_cache.glob("*.json")) if image_cache.is_dir() else []:
        try:
            meta = ImageMetadata.model_validate_json(sidecar.read_text())
        except (OSError, ValueError):
            continue
        if meta.recipe_version != RECIPE_VERSION:
            other_recipe.append((meta.file, meta.recipe_version))
        elif not (image_cache / meta.file).is_file():
            missing_file.append(meta.file)
        else:
            current.append(meta.file)
    if current:
        results.append(CheckResult(PROVIDER, "golden image", "ok", ", ".join(current)))
    elif missing_file:
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                "sidecar(s) present but the image file is gone: "
                + ", ".join(missing_file),
                fix="re-derive: inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )
    elif other_recipe:
        details: list[str] = []
        for name, version in other_recipe:
            try:
                older = int(version) < int(RECIPE_VERSION)
            except ValueError:
                older = None
            if older:
                details.append(
                    f"{name} (recipe v{version}: its daemon predates the required "
                    "pong session field, so this host fails the boot ping tamper-shaped)"
                )
            elif older is None:
                details.append(f"{name} (recipe v{version}, not v{RECIPE_VERSION})")
            else:
                details.append(
                    f"{name} (recipe v{version} is NEWER than this package's "
                    f"v{RECIPE_VERSION}: upgrade inspect_ranges or re-derive)"
                )
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                "no current-recipe golden: " + "; ".join(details),
                fix="re-derive: inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )
    else:
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                f"no goldens in {image_cache}; derive one before running evals",
                fix="inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )

    # the CID lease registry: a STRICT read, deliberately stricter than the
    # allocator's own forgiving reader. The file is a flat {project: lease}
    # mapping; a corrupt file or an entry whose block cannot be determined
    # makes `lease()` raise `CidRegistryError` at admission time, which is
    # exactly the pre-eval failure doctor exists to catch.
    from .._provider.naming import CidLease, entry_block

    def reservable(entry: object) -> bool:
        try:
            CidLease.model_validate(entry)
            return True
        except ValueError:
            return entry_block(entry) is not None

    results.append(
        _strict_registry_check(
            PROVIDER,
            "cid leases",
            state_dir / "cids.json",
            reservable,
            bad_label="entries whose CID block cannot be determined",
            hazard=(
                "undeterminable entries block all leasing, and a corrupt file "
                "reads as EMPTY to the allocator, so fresh leases could "
                "silently overlap CIDs of still-running VMs"
            ),
        )
    )
    return results


def _strict_registry_check(
    group: str,
    name: str,
    path: Path,
    entry_ok: Callable[[object], bool],
    *,
    bad_label: str,
    hazard: str,
) -> CheckResult:
    """One flat `{key: entry}` registry read STRICTLY (deliberately stricter than the runtime readers, which preserve-but-skip what they cannot parse): a corrupt file or an unacceptable entry is one loud fail row carrying `hazard`, never a doctor crash."""
    if not path.exists():
        return CheckResult(group, name, "ok", "no lease file yet (clean state)")
    try:
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict):
            raise ValueError("registry root is not an object")
        entries = cast("dict[str, object]", raw)
        bad = sorted(key for key, entry in entries.items() if not entry_ok(entry))
        if bad:
            raise ValueError(f"{bad_label}: " + ", ".join(bad))
        return CheckResult(
            group,
            name,
            "ok",
            f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} at {path}",
        )
    except (OSError, ValueError) as error:
        return CheckResult(
            group,
            name,
            "fail",
            f"{path} unreadable or corrupt ({error}): {hazard}",
            fix=(
                "tear everything down, then remove the registry: "
                f"inspect sandbox cleanup range && rm {path}"
            ),
        )


def check_host(state_dir: Path, backend: str) -> list[CheckResult]:
    """The range-host surface: strict `leases.json` health, an expired-leases hint naming the reaper, the applier socket probe when `INSPECT_RANGES_HOST` points at one, and a loud fail for a backend name the provider would refuse at eval time.

    Like the CID registry check, the lease read is deliberately STRICTER than the store's own forgiving reader: an entry the store would preserve-but-skip is a lease the reaper cannot see, so doctor reports it loudly instead.
    """
    from .._host.leases import HostLease, LeaseStore

    def parseable(entry: object) -> bool:
        try:
            HostLease.model_validate(entry)
            return True
        except ValueError:
            return False

    results = [
        _strict_registry_check(
            HOST,
            "host leases",
            state_dir / "leases.json",
            parseable,
            bad_label="unparseable lease entries",
            hazard=(
                "a lease the store cannot parse is a range the reaper cannot "
                "see or reclaim"
            ),
        )
    ]
    if results[0].status == "ok" and (state_dir / "leases.json").exists():
        # the sweep-selection predicate itself, not a reimplementation: the
        # hint must stay in lockstep with what the reaper will actually select
        stale = sorted(lease.project for lease in LeaseStore(state_dir).expired())
        if stale:
            results.append(
                CheckResult(
                    HOST,
                    "expired leases",
                    "warn",
                    f"{len(stale)} lease(s) expired or mid-reap "
                    f"({', '.join(stale)}): their ranges hold CIDs and "
                    "resources until reclaimed",
                    fix="inspect-ranges reaper  (one-shot; or --interval <s> as a daemon)",
                )
            )
        elif LeaseStore(state_dir).leases():
            results.append(
                CheckResult(HOST, "expired leases", "ok", "every lease is current")
            )
    if backend.startswith("uds:"):
        results.append(_probe_applier_socket(Path(backend.removeprefix("uds:"))))
    elif backend != "local":
        # the provider raises ValueError for this at eval time; a typo'd
        # backend passing doctor clean is exactly the miss doctor exists for
        results.append(
            CheckResult(
                HOST,
                "backend",
                "fail",
                f"INSPECT_RANGES_HOST={backend!r} is not a backend "
                "(expected 'local' or 'uds:<socket>')",
                fix="unset INSPECT_RANGES_HOST, or point it at a running applier: uds:<socket>",
            )
        )
    return results


def _probe_applier_socket(socket_path: Path) -> CheckResult:
    """Connect and send a routing preamble for an unknown lease: a serving applier answers routing (a clean no-ack close); a dead socket refuses."""
    import socket as socket_module

    from .._channel.channel import HOST_APPLIER
    from .._channel.uds import encode_preamble

    try:
        # inside the try: on Python 3.12 Path.is_socket() propagates
        # PermissionError for an unstatable ancestor, and doctor must report,
        # never crash
        if not socket_path.is_socket():
            return CheckResult(
                HOST,
                "applier socket",
                "fail",
                f"INSPECT_RANGES_HOST points at {socket_path}, which is not a socket",
                fix=f"start it: inspect-ranges applier --socket {socket_path}",
            )
        probe = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        probe.settimeout(2.0)
        try:
            probe.connect(str(socket_path))
            # "0"*32 is valid wire shape but can never collide with a
            # uuid4-minted lease id, so a real applier always refuses it
            probe.sendall(encode_preamble("0" * 32, HOST_APPLIER))
            answer = probe.recv(1)
        finally:
            probe.close()
    except OSError as error:  # TimeoutError is an OSError since 3.10
        return CheckResult(
            HOST,
            "applier socket",
            "fail",
            f"{socket_path} did not answer routing ({error})",
            fix=f"start it: inspect-ranges applier --socket {socket_path}",
        )
    if answer == b"":
        return CheckResult(
            HOST, "applier socket", "ok", f"{socket_path} answers routing"
        )
    return CheckResult(
        HOST,
        "applier socket",
        "warn",
        f"{socket_path} acked a probe for an unknown lease: not an inspect-ranges applier?",
    )


def _inspect_ai_floor() -> str | None:
    """The inspect-ai minimum from this package's own dependency metadata.

    Tolerates extras, parenthesized specifiers, and multi-clause pins; `None` means the floor could not be read (the caller reports that visibly rather than skipping silently).
    """
    import importlib.metadata as metadata

    try:
        requires = metadata.requires("inspect_ranges") or []
    except metadata.PackageNotFoundError:
        return None
    for requirement in requires:
        if not requirement.replace("_", "-").startswith("inspect-ai"):
            continue
        match = re.search(r">=\s*([0-9.]+)", requirement)
        if match:
            return match.group(1)
    return None


def _range_image_tag() -> str:
    from .._runtime.rangeimage import RANGE_IMAGE_TAG

    return RANGE_IMAGE_TAG


def check_evidence(
    sink_override: str | None,
    log_dir: str | None,
    *,
    s3_client: Any | None = None,
) -> list[CheckResult]:
    """The evidence surface (`evidence-v1.md`): knob validity, a writability probe of the standing sink override when one is set, and whether evidence resolves off-instance.

    Doctor never requires AWS: a probe that cannot reach the sink (no credentials, no network) is a stated condition (`warn`), not a host failure. The off-instance row is guidance for untrusted-model runs, where instance-local evidence does not survive instance compromise; it warns rather than fails because local evidence is the normal development state.
    """
    from .._provider.evidence import (
        EVIDENCE_BUFFER_MB_VAR,
        EVIDENCE_MAX_MB_VAR,
        evidence_buffer_bytes,
        evidence_max_bytes,
    )

    # the runtime treats an empty override as unset (`if override:` in
    # location.py); doctor must evaluate the same sink the runtime will
    sink_override = sink_override or None
    log_dir = log_dir or None

    results: list[CheckResult] = []
    # each knob in its own try, naming its variable: int() errors carry no
    # variable name, and one broken knob must not mask the other
    knob_failures: list[str] = []
    values: dict[str, int] = {}
    for var, read in (
        (EVIDENCE_BUFFER_MB_VAR, evidence_buffer_bytes),
        (EVIDENCE_MAX_MB_VAR, evidence_max_bytes),
    ):
        try:
            values[var] = read() // (1024 * 1024)
        except ValueError as error:
            knob_failures.append(f"{var} ({error})")
    if knob_failures:
        results.append(
            CheckResult(
                EVIDENCE,
                "knobs",
                "fail",
                f"invalid evidence knob: {'; '.join(knob_failures)}; the provider disables evidence for every sample rather than failing them",
                fix=(
                    f"unset or set {EVIDENCE_BUFFER_MB_VAR} and "
                    f"{EVIDENCE_MAX_MB_VAR} to positive integers (MB)"
                ),
            )
        )
    else:
        results.append(
            CheckResult(
                EVIDENCE,
                "knobs",
                "ok",
                f"buffer {values[EVIDENCE_BUFFER_MB_VAR]} MB, per-writer cap {values[EVIDENCE_MAX_MB_VAR]} MB",
            )
        )

    from .._evidence.s3 import valid_sink_location

    if sink_override is None:
        # the derived arm needs the same guard as the override arm: evidence
        # derives from the log location, and a location sink_for_location
        # refuses (gs://-class schemes, a malformed s3://) disables evidence
        # for every sample at run time; valid_sink_location is the runtime's
        # own predicate, so the two cannot drift
        if log_dir is not None and not valid_sink_location(log_dir):
            results.append(
                CheckResult(
                    EVIDENCE,
                    "sink",
                    "fail",
                    f"evidence derives from the eval log location, and the sink does not support {log_dir!r}; the runtime would disable evidence for every sample",
                    fix=(
                        "use an s3:// or filesystem INSPECT_LOG_DIR, or set "
                        "INSPECT_RANGES_EVIDENCE_SINK to s3://bucket/prefix "
                        "or a filesystem path"
                    ),
                )
            )
        else:
            results.append(
                CheckResult(
                    EVIDENCE,
                    "sink",
                    "ok",
                    "derived from the eval log location at run time (no standing sink to probe)",
                )
            )
    elif sink_override.startswith("s3://"):
        from .s3probe import probe_s3_sink

        results.append(probe_s3_sink(EVIDENCE, sink_override, client=s3_client))
    elif "://" in sink_override:
        # mirror sink_for_location's scheme validation: at run time an
        # unsupported scheme disables evidence for every sample, so a green
        # local-path probe here would bless the exact misconfiguration
        results.append(
            CheckResult(
                EVIDENCE,
                "sink",
                "fail",
                f"unsupported evidence location scheme in {sink_override!r}; the runtime would disable evidence for every sample",
                fix="use s3://bucket/prefix or a filesystem path for INSPECT_RANGES_EVIDENCE_SINK",
            )
        )
    else:
        results.append(_probe_local_sink(sink_override))

    # the off-instance row consumes the sink row's verdict rather than
    # re-deriving validity: "never bless a value the sink row rejected" is
    # then structural, not re-asserted per branch
    sink_result = results[-1]
    resolved = sink_override or log_dir
    remote_shaped = (
        resolved is not None
        and re.match(r"^[a-z0-9+.-]+://", resolved)
        and not resolved.startswith("file://")
    )
    if (
        remote_shaped
        and resolved is not None
        and sink_result.status != "fail"
        and valid_sink_location(resolved)
    ):
        results.append(
            CheckResult(
                EVIDENCE,
                "off-instance",
                "ok",
                f"evidence resolves off-instance ({resolved})",
            )
        )
    elif remote_shaped:
        results.append(
            CheckResult(
                EVIDENCE,
                "off-instance",
                "warn",
                f"evidence names an off-instance location ({resolved}) the runtime cannot write; the sink row carries the failure",
                fix=(
                    "use an s3:// or filesystem INSPECT_LOG_DIR, or set "
                    "INSPECT_RANGES_EVIDENCE_SINK to s3://bucket/prefix "
                    "or a filesystem path"
                ),
            )
        )
    else:
        results.append(
            CheckResult(
                EVIDENCE,
                "off-instance",
                "warn",
                "evidence resolves to instance-local storage; fine for development, but the pre-compromise record only survives instance compromise when it streams off-instance, so untrusted-model runs need a remote log dir or sink",
                fix=(
                    "point INSPECT_LOG_DIR (preferred: evidence then lives beside "
                    "the logs) or INSPECT_RANGES_EVIDENCE_SINK at s3://..."
                ),
            )
        )
    return results


def check_build(build_cache: Path, recipe_cache: Path) -> list[CheckResult]:
    """The build surface (`build-v1.md`): caches writable, cached manifests and recipe bundles parseable, and the build nameserver derivable from this host.

    Caches that do not exist yet are fine (first `build` creates them); what fails is a cache that exists but cannot be used, or recorded state that no longer parses (a manifest or cached recipe that loads with an error would otherwise surface mid-build, minutes in).
    """
    results: list[CheckResult] = [
        _probe_cache_dir("builds cache", build_cache),
        _probe_cache_dir("recipe cache", recipe_cache),
    ]
    if build_cache.is_dir():
        broken: list[str] = []
        # slashed range names nest one level deeper (builds/org/name/manifest.json)
        manifest_files = sorted(build_cache.glob("*/manifest.json")) + sorted(
            build_cache.glob("*/*/manifest.json")
        )
        for manifest_file in manifest_files:
            try:
                from .._build.manifest import BuildManifest

                BuildManifest.model_validate_json(manifest_file.read_text())
            except Exception as error:
                broken.append(f"{manifest_file.parent.name} ({error})")
        if broken:
            results.append(
                CheckResult(
                    BUILD,
                    "manifests",
                    "fail",
                    f"unparseable build manifest(s): {'; '.join(broken[:3])}",
                    fix="delete the broken manifest directory and run `inspect-ranges build` again",
                )
            )
        else:
            results.append(
                CheckResult(
                    BUILD,
                    "manifests",
                    "ok",
                    f"{len(manifest_files)} recorded build(s) parse",
                )
            )
    if recipe_cache.is_dir():
        bad: list[str] = []
        bundles = sorted(path.parent for path in recipe_cache.glob("*/recipe.yaml"))
        for bundle in bundles:
            try:
                from .._build.recipes import load_recipe

                load_recipe(bundle, source="cache")
            except Exception as error:
                bad.append(f"{bundle.name} ({error})")
        if bad:
            results.append(
                CheckResult(
                    BUILD,
                    "cached recipes",
                    "fail",
                    f"unloadable cached recipe(s): {'; '.join(bad[:3])}",
                    fix="remove the broken bundle from the recipe cache; range-local ./recipes/ bundles are unaffected",
                )
            )
        elif bundles:
            results.append(
                CheckResult(
                    BUILD, "cached recipes", "ok", f"{len(bundles)} bundle(s) load"
                )
            )
    from .._build.manifest import recorded_realized_files
    from .._runtime.images import default_image_cache

    image_cache = default_image_cache()
    if image_cache.is_dir():
        from .._build.capture import live_project_files
        from .._runtime.ownership import default_state_dir

        recorded = recorded_realized_files(build_cache) | live_project_files(
            default_state_dir()
        )
        reclaimable = 0
        for sidecar in image_cache.glob("*.realized.json"):
            image = image_cache / (
                sidecar.name.removesuffix(".realized.json") + ".qcow2"
            )
            if image.name not in recorded and image.is_file():
                try:
                    meta = json.loads(sidecar.read_text())
                    from .._cli.imagescmd import is_catalog_realized

                    if is_catalog_realized(
                        str(meta.get("range_name", "")),
                        str(meta.get("guest", "")),
                        str(meta.get("build_key", "")),
                        image.name,
                    ):
                        continue  # pulled catalog images are sticky, not reclaim bait
                except (OSError, ValueError):
                    continue
                reclaimable += image.stat().st_size
        mb = reclaimable / (1024 * 1024)
        if reclaimable:
            results.append(
                CheckResult(
                    BUILD,
                    "reclaimable",
                    "warn" if mb > 20_480 else "ok",
                    f"{mb:.0f} MB of realized images no manifest references",
                    fix="inspect-ranges images prune",
                )
            )
        else:
            results.append(
                CheckResult(BUILD, "reclaimable", "ok", "no superseded realized images")
            )

    from .._build.orchestrate import FALLBACK_BUILD_NAMESERVER, default_build_nameserver

    nameserver = default_build_nameserver()
    if nameserver == FALLBACK_BUILD_NAMESERVER:
        results.append(
            CheckResult(
                BUILD,
                "build nameserver",
                "warn",
                f"no host resolver derivable from resolv.conf; builds fall back to {nameserver}, which VPC-restricted deployments often block",
                fix="pass --build-nameserver <ip> to `inspect-ranges build` (your VPC's resolver)",
            )
        )
    else:
        results.append(
            CheckResult(BUILD, "build nameserver", "ok", f"host-derived {nameserver}")
        )
    return results


def _probe_cache_dir(name: str, root: Path) -> CheckResult:
    """A cache dir is healthy when absent (first use creates it) or writable."""
    import uuid

    if not root.exists():
        return CheckResult(BUILD, name, "ok", f"{root} (absent; created on first use)")
    try:
        probe = root / f".doctor-probe-{uuid.uuid4().hex}"
        probe.write_bytes(b"doctor")
        probe.unlink()
        return CheckResult(BUILD, name, "ok", f"writable at {root}")
    except OSError as error:
        return CheckResult(
            BUILD,
            name,
            "fail",
            f"{root} is not writable ({error})",
            fix=f"make {root} writable by this user, or point the cache env var elsewhere",
        )


def _probe_local_sink(base: str) -> CheckResult:
    """Writability probe of a filesystem sink override: create the base (first use would anyway), write and remove one probe file."""
    import uuid

    try:
        root = Path(base)
        root.mkdir(parents=True, exist_ok=True)
        probe = root / f".doctor-probe-{uuid.uuid4().hex}"
        probe.write_bytes(b"doctor")
        probe.unlink()
        return CheckResult(EVIDENCE, "sink", "ok", f"writable at {base}")
    except (OSError, ValueError) as error:  # ValueError: e.g. an embedded NUL
        return CheckResult(
            EVIDENCE,
            "sink",
            "fail",
            f"{base} is not writable ({error}); every sample would run with evidence disabled",
            fix="make the sink directory writable by the eval user, or change INSPECT_RANGES_EVIDENCE_SINK",
        )


def _artifact_state(sidecar: Path) -> str:
    """`ok`, `tar-missing`, or `absent`: the sidecar names the tarball that must exist beside it."""
    from .._channel.bundle import DaemonBundleInfo, bundle_file_name

    if not sidecar.is_file():
        return "absent"
    try:
        info = DaemonBundleInfo.model_validate_json(sidecar.read_text())
    except (OSError, ValueError):
        return "absent"
    return (
        "ok"
        if (sidecar.parent / bundle_file_name(info.version)).is_file()
        else "tar-missing"
    )


def check_realizer(
    image_inspect: subprocess.CompletedProcess[str] | None,
) -> list[CheckResult]:
    """Realizer host surface: the hardened range image, the daemon artifact, and the Go toolchain that builds it (warnings, not failures: `up` builds the image on demand and `daemon-bundle` publishes the artifact)."""
    from .._channel.bundle import GO_PIN, locate_go
    from .._runtime.images import DEFAULT_ARTIFACT_DIR

    results: list[CheckResult] = []
    if image_inspect is None:
        results.append(
            CheckResult(
                REALIZER,
                "range image",
                "skip",
                "docker unreachable, cannot tell whether the image exists",
            )
        )
    elif image_inspect.returncode == 0:
        from .._runtime.rangeimage import RANGE_IMAGE_ENV

        pinned_image = os.environ.get(RANGE_IMAGE_ENV)
        results.append(
            CheckResult(
                REALIZER,
                "range image",
                "ok",
                f"pinned {pinned_image}"
                if pinned_image
                else f"local {_range_image_tag()}",
            )
        )
    else:
        results.append(
            CheckResult(
                REALIZER,
                "range image",
                "warn",
                f"{_range_image_tag()} not built yet; `inspect-ranges up` builds it on first use",
            )
        )
    sidecar = DEFAULT_ARTIFACT_DIR / "daemon.json"
    artifact_state = _artifact_state(sidecar)
    if artifact_state == "ok":
        results.append(
            CheckResult(REALIZER, "daemon artifact", "ok", str(DEFAULT_ARTIFACT_DIR))
        )
    elif artifact_state == "tar-missing":
        results.append(
            CheckResult(
                REALIZER,
                "daemon artifact",
                "warn",
                f"sidecar present but its bundle tar is missing at {DEFAULT_ARTIFACT_DIR}; republish",
                fix=f"inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
            )
        )
    else:
        results.append(
            CheckResult(
                REALIZER,
                "daemon artifact",
                "warn",
                f"none at {DEFAULT_ARTIFACT_DIR}; publish one: inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
                fix=f"inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
            )
        )
    go = locate_go()
    if go is not None:
        results.append(CheckResult(REALIZER, "go toolchain", "ok", str(go)))
    else:
        results.append(
            CheckResult(
                REALIZER,
                "go toolchain",
                "warn",
                f"no Go toolchain (needed only to build the daemon artifact; pin {GO_PIN})",
            )
        )
    return results


def check_platform(system: str, machine: str) -> CheckResult:
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return CheckResult(PLATFORM, "Linux x86_64", "ok", f"{system} {machine}")
    return CheckResult(
        PLATFORM,
        "Linux x86_64",
        "fail",
        f"{system} {machine}",
        fix="Develop on a Linux x86_64 machine with KVM, e.g. the EC2 devbox (see devbox/README.md).",
    )


def check_virtualization(dev: Path) -> list[CheckResult]:
    kvm = dev / "kvm"
    results = [
        _device(
            kvm,
            "fail",
            "Use a KVM-capable host: on EC2 a metal instance (e.g. m6i.metal) or a c8i/m8i/r8i instance launched with nested virtualization; elsewhere enable VT-x in firmware and load kvm_intel.",
        )
    ]
    if not kvm.exists():
        results.append(_skip(VIRTUALIZATION, "/dev/kvm access", "no /dev/kvm"))
    elif os.access(kvm, os.R_OK | os.W_OK):
        results.append(
            CheckResult(
                VIRTUALIZATION,
                "/dev/kvm access",
                "ok",
                "readable and writable by this user",
            )
        )
    else:
        results.append(
            CheckResult(
                VIRTUALIZATION,
                "/dev/kvm access",
                "warn",
                "not accessible by this user (needed only by tools run directly on the host, e.g. qemu-img, virt-install)",
                fix="sudo usermod -aG kvm $USER, then log in again",
                fix_command='usermod -aG kvm "$SUDO_USER"',
            )
        )
    results.append(
        _device(
            dev / "net" / "tun",
            "fail",
            "sudo modprobe tun && echo tun | sudo tee /etc/modules-load.d/tun.conf",
            fix_command="modprobe tun && echo tun > /etc/modules-load.d/tun.conf",
        )
    )
    results.append(
        _device(
            dev / "vhost-net",
            "warn",
            "sudo modprobe vhost_net && echo vhost_net | sudo tee /etc/modules-load.d/vhost_net.conf",
            fix_command="modprobe vhost_net && echo vhost_net > /etc/modules-load.d/vhost_net.conf",
            missing="missing (VM networking works but is slower)",
        )
    )
    results.append(
        _device(
            dev / "vhost-vsock",
            "fail",
            "sudo modprobe vhost_vsock && echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf",
            fix_command="modprobe vhost_vsock && echo vhost_vsock > /etc/modules-load.d/vhost_vsock.conf",
            missing="missing (vsock is the exec/file control channel for VMs)",
        )
    )
    return results


def check_docker(
    info: subprocess.CompletedProcess[str] | None,
    compose: subprocess.CompletedProcess[str] | None,
) -> list[CheckResult]:
    """Judge `docker info --format '{{json .}}'` and `docker compose version --format json` output (`None` when `docker` isn't installed)."""
    dependents = ["Docker Engine version", "Docker Compose version", "cgroup version"]
    if info is None:
        return [
            CheckResult(
                DOCKER,
                "Docker daemon",
                "fail",
                "docker CLI not found",
                fix="Install Docker Engine: https://docs.docker.com/engine/install/ubuntu/",
            ),
            *_skipped(DOCKER, dependents, "Docker daemon unavailable"),
        ]

    data = _json_object(info.stdout)
    server_version = str(data.get("ServerVersion") or "")
    if info.returncode != 0 or not server_version:
        error = _first_line(info.stderr) or "no server version reported"
        permission = "permission denied" in error.lower()
        fix = (
            "sudo usermod -aG docker $USER, then log in again"
            if permission
            else "Start the daemon (sudo systemctl start docker), or check DOCKER_HOST / the current docker context."
        )
        return [
            CheckResult(
                DOCKER,
                "Docker daemon",
                "fail",
                f"unreachable: {error}",
                fix=fix,
                fix_command='usermod -aG docker "$SUDO_USER"' if permission else None,
            ),
            *_skipped(DOCKER, dependents, "Docker daemon unavailable"),
        ]

    results = [
        CheckResult(DOCKER, "Docker daemon", "ok", "reachable by this user"),
        _minimum_version(
            "Docker Engine version",
            server_version,
            DOCKER_ENGINE_MIN_VERSION,
            "Upgrade Docker Engine: https://docs.docker.com/engine/install/ubuntu/",
        ),
    ]

    compose_version = (
        str(_json_object(compose.stdout).get("version") or "") if compose else ""
    )
    if compose is None or compose.returncode != 0 or not compose_version:
        results.append(
            CheckResult(
                DOCKER,
                "Docker Compose version",
                "fail",
                "Docker Compose plugin not found",
                fix="sudo apt-get install docker-compose-plugin",
                fix_command="apt-get install -y docker-compose-plugin",
            )
        )
    else:
        results.append(
            _minimum_version(
                "Docker Compose version",
                compose_version,
                DOCKER_COMPOSE_MIN_VERSION,
                "sudo apt-get install --only-upgrade docker-compose-plugin",
                fix_command="apt-get install -y --only-upgrade docker-compose-plugin",
            )
        )

    cgroup_version = str(data.get("CgroupVersion") or "unknown")
    if cgroup_version == "2":
        results.append(CheckResult(DOCKER, "cgroup version", "ok", "cgroup v2"))
    else:
        results.append(
            CheckResult(
                DOCKER,
                "cgroup version",
                "warn",
                f"cgroup {cgroup_version} (range memory limits assume cgroup v2)",
                fix="Use a distribution that defaults to cgroup v2 (e.g. Ubuntu 22.04+), or boot with systemd.unified_cgroup_hierarchy=1.",
            )
        )
    return results


def check_br_netfilter(proc_sys: Path) -> CheckResult:
    setting = proc_sys / "net" / "bridge" / "bridge-nf-call-iptables"
    if not setting.exists():
        return CheckResult(NETWORKING, "br_netfilter", "ok", "not loaded")
    if setting.read_text().strip() == "0":
        return CheckResult(
            NETWORKING, "br_netfilter", "ok", "loaded, but bridge-nf-call-iptables=0"
        )
    return CheckResult(
        NETWORKING,
        "br_netfilter",
        "warn",
        "loaded with bridge-nf-call-iptables=1 (host iptables rules can filter bridged range traffic)",
        fix="sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0",
        fix_command="sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0",
    )


def check_ipv6(proc_sys: Path) -> CheckResult:
    setting = proc_sys / "net" / "ipv6" / "conf" / "all" / "disable_ipv6"
    if not setting.exists():
        return CheckResult(
            NETWORKING,
            "IPv6",
            "warn",
            "not available in this kernel (ranges that rely on IPv6, e.g. mitm6 scenarios, won't work)",
            fix="Enable IPv6 in the kernel (remove ipv6.disable=1 from the boot parameters).",
        )
    if setting.read_text().strip() == "0":
        return CheckResult(NETWORKING, "IPv6", "ok", "enabled")
    return CheckResult(
        NETWORKING,
        "IPv6",
        "warn",
        "disabled (ranges that rely on IPv6, e.g. mitm6 scenarios, won't work)",
        fix="sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0",
        fix_command="sysctl -w net.ipv6.conf.all.disable_ipv6=0",
    )


def check_image_tools(which: Callable[[str], str | None]) -> list[CheckResult]:
    """Check the tools used to build VM images (`which` resolves a command name to a path or `None`)."""
    tools = {"qemu-img": "qemu-utils", "virt-customize": "libguestfs-tools"}
    results: list[CheckResult] = []
    for tool, package in tools.items():
        path = which(tool)
        if path:
            results.append(CheckResult(IMAGE_TOOLING, tool, "ok", str(path)))
        else:
            results.append(
                CheckResult(
                    IMAGE_TOOLING,
                    tool,
                    "fail",
                    "not found",
                    fix=f"sudo apt-get install {package}",
                    fix_command=f"apt-get install -y {package}",
                )
            )
    return results


def check_kernel_readable(boot: Path) -> CheckResult:
    """Libguestfs (virt-customize) copies the host kernel to build its appliance, so it must be readable by this user."""
    kernels = sorted(boot.glob("vmlinuz-*"))
    if not kernels:
        return CheckResult(
            IMAGE_TOOLING,
            "host kernel readable",
            "warn",
            f"no vmlinuz-* in {boot} (libguestfs needs a host kernel to build its appliance)",
        )
    unreadable = [kernel.name for kernel in kernels if not os.access(kernel, os.R_OK)]
    if not unreadable:
        return CheckResult(
            IMAGE_TOOLING,
            "host kernel readable",
            "ok",
            f"{len(kernels)} kernel(s) in {boot}",
        )
    return CheckResult(
        IMAGE_TOOLING,
        "host kernel readable",
        "fail",
        f"not readable by this user: {', '.join(unreadable)} (virt-customize will fail)",
        fix="sudo chmod 0644 /boot/vmlinuz-*, and install the kernel hook from the devbox bootstrap "
        + "(/etc/kernel/postinst.d/zz-devbox-kernel-readable) so future kernels stay readable",
        fix_command=(
            "chmod 0644 /boot/vmlinuz-*\n"
            "printf '#!/bin/sh\\nchmod 0644 /boot/vmlinuz-*\\n' > /etc/kernel/postinst.d/zz-devbox-kernel-readable\n"
            "chmod 755 /etc/kernel/postinst.d/zz-devbox-kernel-readable"
        ),
    )


def parse_version(text: str) -> tuple[int, ...] | None:
    """Parse the leading dotted number of a version string, e.g. "v2.22.0-desktop.1" -> (2, 22, 0)."""
    match = re.match(r"v?(\d+(?:\.\d+)*)", text.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _minimum_version(
    name: str,
    version: str,
    minimum: tuple[int, ...],
    fix: str,
    fix_command: str | None = None,
) -> CheckResult:
    required = ".".join(str(part) for part in minimum)
    parsed = parse_version(version)
    if parsed is None:
        return CheckResult(
            DOCKER,
            name,
            "warn",
            f"couldn't parse version {version!r} (need >= {required})",
        )
    if parsed < minimum:
        return CheckResult(
            DOCKER,
            name,
            "fail",
            f"{version} (need >= {required})",
            fix=fix,
            fix_command=fix_command,
        )
    return CheckResult(DOCKER, name, "ok", version)


def _device(
    path: Path,
    severity: CheckStatus,
    fix: str,
    fix_command: str | None = None,
    missing: str = "missing",
) -> CheckResult:
    if path.exists():
        return CheckResult(VIRTUALIZATION, path.as_posix(), "ok", "present")
    return CheckResult(
        VIRTUALIZATION,
        path.as_posix(),
        severity,
        missing,
        fix=fix,
        fix_command=fix_command,
    )


def _skip(group: str, name: str, reason: str) -> CheckResult:
    return CheckResult(group, name, "skip", reason)


def _skipped(group: str, names: list[str], reason: str) -> list[CheckResult]:
    return [_skip(group, name, reason) for name in names]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run a command, returning `None` when its executable isn't installed."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"timed out after {COMMAND_TIMEOUT}s"
        )


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")
