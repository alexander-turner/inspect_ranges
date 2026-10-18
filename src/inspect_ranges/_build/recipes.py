"""Recipe bundles and the build-time executor (build-v1 slice 1).

A recipe is a content-addressed bundle: a directory holding the recipe's code plus a `recipe.yaml` self-description (`name`, `version`, `entrypoint`, `inputs`, `mode`), resolved from the range directory (`./recipes/<name>/`) and then the shared local recipe cache, per the recipe-references record. The build validates a step's `vars` against the declared `inputs`, hashes the bundle deterministically, and invokes the entrypoint on the host with the validated vars as environment, the bundle directory as working directory, and a connection to the target guest expressed through the `IR_*` contract (`IR_GUEST`, `IR_GUEST_CIDS`, `IR_EXEC`, `IR_PUSH`; see `guesttool`). Exit status 0 is demanded back and is never sufficient: verification of declared state happens independently (build-v1 slice 4).

v1 executes `online` recipes only; `mode: offline` parses and is refused with a typed issue at execution until a recipe demands it. The whole-entrypoint budget is enforced host-side with a process-group kill; per-exec budgets inside the guest are the recipe's responsibility through `IR_EXEC --budget-ms` (default `IR_EXEC_BUDGET_MS`), per the challenges-v1 lesson that unbudgeted execs leaving background children hold the exec plane.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from .._diagnostics import PathElement
from .._runtime.images import sha256_file
from ..types import Issue, IssueError


class StageSink(Protocol):
    """Anything accepting stage-log writes: `StageLog`, the build tee."""

    def log(self, stage: str, status: str, **fields: Any) -> None: ...


RECIPES_DIR_NAME = "recipes"
"""Directory inside a range that holds its local recipe bundles."""

DEFAULT_RECIPE_BUDGET_S = 1800.0
"""Default whole-entrypoint budget; recipes that converge big stacks override it per step."""

DEFAULT_EXEC_BUDGET_MS = 600_000
"""Default per-exec in-guest budget handed to `guesttool` via `IR_EXEC_BUDGET_MS`."""

_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")

VarValue = str | int | bool
"""The value types a `ProvisioningStep.vars` entry may carry."""


def default_recipe_cache() -> Path:
    """`INSPECT_RANGES_RECIPE_CACHE`, or `~/.cache/inspect-ranges/recipes`.

    The one source of the recipe-cache default (the sibling of the image cache per recipe-references); every surface resolves through here so the knob cannot drift.
    """
    override = os.environ.get("INSPECT_RANGES_RECIPE_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "inspect-ranges" / "recipes"


class RecipeInput(BaseModel):
    """A declared recipe variable: an input with a default is optional, one without is required."""

    model_config = ConfigDict(extra="forbid")

    default: VarValue | None = None
    """Value used when the step omits the variable; `None` means the variable is required."""

    description: str | None = None
    """One-line description for the authoring surface."""


class RecipeSpec(BaseModel):
    """The `recipe.yaml` self-description of a bundle (recipe-references contract)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    """Logical name `provisioning` steps reference, e.g. `vulhub.zabbix-web`."""

    version: str
    """Version string steps may pin; recorded in the build manifest."""

    entrypoint: str
    """Executable the build invokes, relative to the bundle directory."""

    inputs: dict[str, RecipeInput] = {}
    """Declared variables, validated against a step's `vars` before execution."""

    mode: Literal["online", "offline"] = "online"
    """`online` converges a booted build-time guest; `offline` operates on a disk image (not yet executable)."""

    @field_validator("name")
    @classmethod
    def _name_grammar(cls, value: str) -> str:
        if not _NAME_RE.match(value):
            raise ValueError(
                f"recipe name {value!r} is not a lowercase slug (letters, digits, `.`, `_`, `-`)"
            )
        return value

    @field_validator("version")
    @classmethod
    def _version_nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("recipe version must be a non-empty string")
        return value

    @field_validator("entrypoint")
    @classmethod
    def _entrypoint_inside_bundle(cls, value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts or not value.strip():
            raise ValueError(
                f"entrypoint {value!r} must be a relative path inside the bundle"
            )
        return value


class ResolvedRecipe(BaseModel):
    """A recipe bundle located, validated, and digested; the unit the executor and manifest consume."""

    model_config = ConfigDict(frozen=True)

    spec: RecipeSpec
    """The parsed `recipe.yaml`."""

    bundle_dir: Path
    """The bundle directory the recipe runs from."""

    entrypoint: Path
    """Absolute path of the executable entrypoint."""

    digest: str
    """Deterministic content digest of the whole bundle (see `recipe_digest`)."""

    source: Literal["range", "cache"]
    """Where resolution found the bundle."""

    @property
    def name(self) -> str:
        """The recipe's logical name."""
        return self.spec.name

    @property
    def version(self) -> str:
        """The recipe's version string."""
        return self.spec.version


def recipe_digest(bundle_dir: Path) -> str:
    """Deterministic content digest of a recipe bundle directory.

    The digest covers every regular file's relative path, content hash, and executable bit, rendered as canonical JSON and hashed; two bundles with identical content digest identically regardless of where or when they were materialized. Symlinks and non-regular files are refused: a bundle must be plain files so its digest means what it claims.
    """
    files: dict[str, dict[str, str | bool]] = {}
    issues: list[Issue] = []
    for path in sorted(bundle_dir.rglob("*")):
        relative = path.relative_to(bundle_dir).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            issues.append(
                Issue(
                    code="recipe-bundle-invalid",
                    message=f"bundle member {relative!r} is not a regular file, so the bundle cannot be content-addressed",
                    hint="recipe bundles hold plain files and directories only; replace symlinks with copies",
                )
            )
            continue
        if path.is_dir():
            continue
        files[relative] = {
            "sha256": sha256_file(path),
            # a property of the file, not of who hashes it (os.access would
            # make the digest a function of the calling user)
            "exec": bool(path.stat().st_mode & 0o111),
        }
    if issues:
        raise IssueError(issues)
    material = json.dumps({"format": "recipe-digest-1", "files": files}, sort_keys=True)
    return sha256(material.encode()).hexdigest()


def load_recipe(
    bundle_dir: Path,
    *,
    source: Literal["range", "cache"],
    path: tuple[PathElement, ...] = (),
) -> ResolvedRecipe:
    """Parse and validate a recipe bundle directory into a `ResolvedRecipe`.

    Raises:
        IssueError: `recipe-bundle-invalid` when `recipe.yaml` is missing or malformed, or the entrypoint does not resolve to an executable regular file inside the bundle.
    """
    bundle_dir = (
        bundle_dir.resolve()
    )  # the executor changes cwd, so paths must survive it
    manifest = bundle_dir / "recipe.yaml"
    if not manifest.is_file():
        raise IssueError(
            [
                Issue(
                    code="recipe-bundle-invalid",
                    path=path,
                    message=f"recipe bundle at {bundle_dir} has no recipe.yaml, so it cannot be resolved",
                    hint="every bundle carries a recipe.yaml with name, version, entrypoint, inputs, mode",
                )
            ]
        )
    try:
        raw = yaml.safe_load(manifest.read_text())
        spec = RecipeSpec.model_validate(raw)
    except (yaml.YAMLError, ValueError) as error:
        raise IssueError(
            [
                Issue(
                    code="recipe-bundle-invalid",
                    path=path,
                    message=f"recipe.yaml at {manifest} is invalid: {_first_line(error)}",
                    hint="fix the recipe.yaml fields (name, version, entrypoint, inputs, mode)",
                )
            ]
        ) from error
    entrypoint = bundle_dir / spec.entrypoint
    if not entrypoint.is_file() or not os.access(entrypoint, os.X_OK):
        raise IssueError(
            [
                Issue(
                    code="recipe-bundle-invalid",
                    path=path,
                    message=f"entrypoint {spec.entrypoint!r} of recipe {spec.name!r} is not an executable file in the bundle",
                    hint="create the entrypoint and chmod +x it",
                )
            ]
        )
    return ResolvedRecipe(
        spec=spec,
        bundle_dir=bundle_dir,
        entrypoint=entrypoint,
        digest=recipe_digest(bundle_dir),
        source=source,
    )


def resolve_recipe(
    name: str,
    *,
    range_dir: Path,
    cache: Path | None = None,
    version: str | None = None,
    path: tuple[PathElement, ...] = (),
) -> ResolvedRecipe:
    """Resolve a `provisioning` recipe reference: the range's `./recipes/<name>/`, then the local recipe cache.

    Args:
        name: The logical recipe name a `ProvisioningStep` references.
        range_dir: The range directory (the parent of `range.yaml`).
        cache: Recipe cache override; defaults to `default_recipe_cache()`.
        version: Optional version pin from the step; a resolved bundle with a different version refuses.
        path: Spec path prefix for issues (e.g. `("hosts", 0, "provisioning", 1)`).

    Raises:
        IssueError: `recipe-not-resolved` when no bundle exists in either location; `recipe-bundle-invalid` when the resolved bundle lies about its name; `recipe-version-mismatch` on a failed version pin.
    """
    if not _NAME_RE.match(name):
        raise IssueError(
            [
                Issue(
                    code="recipe-reference-invalid",
                    path=path,
                    message=f"recipe reference {name!r} is not a lowercase slug, so it cannot resolve (and must never leave the recipe roots)",
                    hint="recipe names are lowercase slugs: letters, digits, `.`, `_`, `-`",
                )
            ]
        )
    cache_dir = cache if cache is not None else default_recipe_cache()
    candidates: list[tuple[Literal["range", "cache"], Path]] = [
        ("range", range_dir / RECIPES_DIR_NAME / name),
        ("cache", cache_dir / name),
    ]
    for source, bundle_dir in candidates:
        if not bundle_dir.is_dir():
            continue
        recipe = load_recipe(bundle_dir, source=source, path=path)
        issues: list[Issue] = []
        if recipe.name != name:
            issues.append(
                Issue(
                    code="recipe-bundle-invalid",
                    path=path,
                    message=f"bundle at {bundle_dir} names itself {recipe.name!r} but was resolved as {name!r}",
                    hint="the bundle directory name and its recipe.yaml name must agree",
                )
            )
        if version is not None and recipe.version != version:
            issues.append(
                Issue(
                    code="recipe-version-mismatch",
                    path=path,
                    message=f"recipe {name!r} resolved at version {recipe.version!r} but the step pins {version!r}",
                    hint="update the step's version pin or install the pinned bundle version",
                )
            )
        if issues:
            raise IssueError(issues)
        return recipe
    raise IssueError(
        [
            Issue(
                code="recipe-not-resolved",
                path=path,
                message=f"recipe {name!r} resolves neither in the range ({range_dir / RECIPES_DIR_NAME / name}) nor the recipe cache ({cache_dir / name}), so the build cannot run it",
                hint=f"add ./recipes/{name}/ to the range or install the bundle into the recipe cache (INSPECT_RANGES_RECIPE_CACHE)",
            )
        ]
    )


def validate_vars(
    recipe: ResolvedRecipe,
    step_vars: Mapping[str, VarValue],
    *,
    path: tuple[PathElement, ...] = (),
) -> dict[str, str]:
    """Validate a step's `vars` against the recipe's declared `inputs` and render the entrypoint environment.

    Booleans render lowercase (`true`/`false`), integers decimal; defaults fill omitted optional inputs. All violations are collected and raised at once.

    Raises:
        IssueError: `recipe-var-unknown` for vars the recipe does not declare; `recipe-var-missing` for required inputs the step omits.
    """
    issues: list[Issue] = []
    env: dict[str, str] = {}
    for key, value in step_vars.items():
        rendered = _env_value(value)
        if "\x00" in key or "=" in key or not key:
            issues.append(
                Issue(
                    code="recipe-var-invalid",
                    path=(*path, "vars", key),
                    message=f"recipe input name {key!r} cannot be an environment variable name",
                    hint="input names must be non-empty and free of '=' and NUL",
                )
            )
            continue
        if "\x00" in rendered:
            # YAML can author a NUL directly; Popen would raise a raw
            # ValueError minutes later, mid-build (round-1 review)
            issues.append(
                Issue(
                    code="recipe-var-invalid",
                    path=(*path, "vars", key),
                    message=f"recipe input {key!r} carries a NUL byte, which cannot cross the environment",
                    hint="remove the NUL from the value",
                )
            )
            continue
        if key not in recipe.spec.inputs:
            issues.append(
                Issue(
                    code="recipe-var-unknown",
                    path=(*path, "vars", key),
                    message=f"recipe {recipe.name!r} declares no input {key!r}",
                    hint=f"declared inputs: {', '.join(sorted(recipe.spec.inputs)) or '(none)'}",
                )
            )
            continue
        env[key] = rendered
    for key, declared in recipe.spec.inputs.items():
        if key in env:
            continue
        if declared.default is None:
            issues.append(
                Issue(
                    code="recipe-var-missing",
                    path=(*path, "vars"),
                    message=f"recipe {recipe.name!r} requires input {key!r} and the step does not set it",
                    hint=f"add {key} to the step's vars",
                )
            )
        else:
            default_rendered = _env_value(declared.default)
            if "\x00" in key or "=" in key or "\x00" in default_rendered:
                issues.append(
                    Issue(
                        code="recipe-var-invalid",
                        path=(*path, "vars", key),
                        message=f"recipe {recipe.name!r} declares input {key!r} whose name or default cannot cross the environment",
                        hint="input names must be free of '=' and NUL; defaults free of NUL",
                    )
                )
            else:
                env[key] = default_rendered
    if issues:
        raise IssueError(issues)
    return env


@dataclass(frozen=True)
class RecipeTarget:
    """The guest an online recipe converges, addressed for the vsock channel."""

    guest: str
    cids: Mapping[str, int]


class RecipeError(RuntimeError):
    """Stage-named recipe execution failure: `[stage] recipe NAME on guest GUEST: message`."""

    def __init__(
        self,
        stage: Literal["launch", "run", "budget"],
        message: str,
        *,
        recipe: str,
        guest: str,
        log_path: Path,
    ) -> None:
        self.stage = stage
        self.recipe = recipe
        self.guest = guest
        self.log_path = log_path
        self.detail = message
        super().__init__(f"[{stage}] recipe {recipe!r} on guest {guest!r}: {message}")


class RecipeRun(BaseModel):
    """A successful recipe execution, as the build manifest will record it."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str
    guest: str
    seconds: float
    log_path: Path


def run_recipe(
    recipe: ResolvedRecipe,
    *,
    step_vars: Mapping[str, VarValue],
    target: RecipeTarget,
    log_dir: Path,
    stage_log: StageSink | None = None,
    budget_s: float = DEFAULT_RECIPE_BUDGET_S,
    exec_budget_ms: int = DEFAULT_EXEC_BUDGET_MS,
) -> RecipeRun:
    """Execute an online recipe's entrypoint against a booted guest.

    The entrypoint runs on the host with the bundle directory as working directory, the validated vars as environment, and the `IR_*` contract: `IR_GUEST` and `IR_GUEST_CIDS` address the target, `IR_EXEC` and `IR_PUSH` are generated wrappers over `guesttool` for in-guest exec and file push, and `IR_EXEC_BUDGET_MS` is the default per-exec budget. Output is captured to one log file per run; the whole entrypoint is bounded by `budget_s` and killed as a process group on expiry.

    Raises:
        IssueError: `recipe-mode-unsupported` for `offline` recipes (not yet executable), plus anything `validate_vars` refuses.
        RecipeError: stage `run` on a nonzero exit, stage `budget` on expiry; both carry the log path.
    """
    if recipe.spec.mode != "online":
        raise IssueError(
            [
                Issue(
                    code="recipe-mode-unsupported",
                    message=f"recipe {recipe.name!r} declares mode {recipe.spec.mode!r}, which the build cannot execute yet",
                    hint="offline recipes arrive when a range demands them; declare mode: online",
                )
            ]
        )
    env_vars = validate_vars(recipe, step_vars)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = _next_log_path(log_dir, recipe.name, target.guest)
    if stage_log is not None:
        stage_log.log(
            "recipe",
            "start",
            recipe=recipe.name,
            version=recipe.version,
            guest=target.guest,
        )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ir-recipe-") as scratch:
        contract = _contract_env(target, Path(scratch), recipe.name, exec_budget_ms)
        env = {**os.environ, **env_vars, **contract}
        with open(log_path, "wb") as log_file:
            try:
                process = subprocess.Popen(
                    [str(recipe.entrypoint)],
                    cwd=recipe.bundle_dir,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=True,
                )
            except (OSError, ValueError) as error:
                # ValueError: an env key/value that slipped past validation
                # (defense in depth; the raw escape skipped disposal, round-1)
                message = f"could not launch entrypoint {recipe.spec.entrypoint!r}: {error}; log: {log_path}"
                if stage_log is not None:
                    stage_log.log(
                        "recipe",
                        "fail",
                        recipe=recipe.name,
                        guest=target.guest,
                        error=message,
                    )
                raise RecipeError(
                    "launch",
                    message,
                    recipe=recipe.name,
                    guest=target.guest,
                    log_path=log_path,
                ) from error
            try:
                rc = process.wait(timeout=budget_s)
            except subprocess.TimeoutExpired:
                _kill_group(process)
                message = f"budget of {budget_s:.0f} s exceeded (process group killed); log: {log_path}"
                if stage_log is not None:
                    stage_log.log(
                        "recipe",
                        "fail",
                        recipe=recipe.name,
                        guest=target.guest,
                        error=message,
                    )
                raise RecipeError(
                    "budget",
                    message,
                    recipe=recipe.name,
                    guest=target.guest,
                    log_path=log_path,
                ) from None
    survivors_killed = _sweep_group(process)
    seconds = time.monotonic() - started
    if rc != 0:
        message = f"exited {rc}; log tail: {_log_tail(log_path)}; log: {log_path}"
        if stage_log is not None:
            stage_log.log(
                "recipe", "fail", recipe=recipe.name, guest=target.guest, error=message
            )
        raise RecipeError(
            "run", message, recipe=recipe.name, guest=target.guest, log_path=log_path
        )
    if stage_log is not None:
        stage_log.log(
            "recipe",
            "ok",
            recipe=recipe.name,
            version=recipe.version,
            guest=target.guest,
            seconds=round(seconds, 3),
            survivors_killed=survivors_killed,
        )
    return RecipeRun(
        name=recipe.name,
        version=recipe.version,
        digest=recipe.digest,
        guest=target.guest,
        seconds=seconds,
        log_path=log_path,
    )


def _contract_env(
    target: RecipeTarget, scratch: Path, recipe_name: str, exec_budget_ms: int
) -> dict[str, str]:
    """The `IR_*` environment handed to an entrypoint, with generated helper wrappers in `scratch`."""
    helpers = {
        "IR_EXEC": _write_helper(scratch, "ir-exec", "exec"),
        "IR_PUSH": _write_helper(scratch, "ir-push", "push"),
    }
    return {
        **helpers,
        "IR_GUEST": target.guest,
        "IR_GUEST_CIDS": json.dumps(dict(target.cids), sort_keys=True),
        "IR_RECIPE": recipe_name,
        "IR_EXEC_BUDGET_MS": str(exec_budget_ms),
    }


def _write_helper(scratch: Path, name: str, verb: str) -> str:
    script = scratch / name
    script.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" -m inspect_ranges._build.guesttool {verb} "$@"\n'
    )
    script.chmod(0o755)
    return str(script)


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (
        ProcessLookupError
    ):  # pragma: no cover - the group died between wait and kill
        pass
    process.wait()


def _sweep_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill host-side process-group members a 0-exiting entrypoint left behind; True when any existed.

    A recipe must not leak host processes past its run; survivors are killed rather than tolerated, and the stage log records that it happened.
    """
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:  # pragma: no cover - survivors exited in the gap
        return False
    return True


def _next_log_path(log_dir: Path, name: str, guest: str) -> Path:
    """A per-run log path: the same recipe may run again on the same guest, and no run's log is clobbered."""
    for n in range(1, 10_000):
        candidate = log_dir / f"recipe-{name}-{guest}-{n:03d}.log"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"no free log slot under {log_dir} for {name} on {guest}")


def _log_tail(log_path: Path, limit: int = 400) -> str:
    try:
        text = log_path.read_text(errors="replace")
    except OSError:  # pragma: no cover - log file vanished
        return "(no output captured)"
    tail = text.strip()[-limit:]
    return " ".join(tail.split()) or "(no output)"


def _env_value(value: VarValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _first_line(error: Exception) -> str:
    return str(error).strip().splitlines()[0] if str(error).strip() else "parse error"
