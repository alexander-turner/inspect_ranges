"""`inspect-ranges down`: teardown keyed off recorded ownership, never live process state (realizer-v1 slice 3).

Everything a project owns is found by its compose label (containers, volumes, networks) or its deterministic name, so `down` works from any process, after any crash, and twice in a row. `down --all` sweeps every `ir-` project discovered from the ownership registry, container labels, and compose volume names, and never touches other prefixes (the channel track's `chan-` batteries run concurrently on shared hosts).
"""

from pathlib import Path

from pydantic import BaseModel

from .ownership import (
    PROJECT_PREFIX,
    default_state_dir,
    list_projects,
    remove_project,
)
from .up import Runner, run_command


class DownError(Exception):
    """Teardown failure: a docker query or removal did not succeed, so the project may still own resources (ownership state is kept so a retry can find them)."""


def _ids(run: Runner, argv: list[str]) -> list[str]:
    result = run(argv)
    if result.returncode != 0:
        raise DownError(f"{' '.join(argv[:3])} failed: {result.stderr.strip()[-400:]}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def _remove(run: Runner, argv: list[str], relist: list[str]) -> None:
    result = run(argv)
    if result.returncode != 0:
        # a resource that vanished between the listing and the removal (an
        # auto-removed container, a parallel down) is success, not failure
        if not _ids(run, relist):
            return
        raise DownError(f"{' '.join(argv[:3])} failed: {result.stderr.strip()[-400:]}")


class DownResult(BaseModel):
    """What a teardown removed (all zero means the down was a no-op)."""

    project: str
    containers: int
    volumes: int
    networks: int


def down(
    project: str,
    state_dir: Path | None = None,
    runner: Runner | None = None,
    keep_state: bool = False,
) -> DownResult:
    """Tear down one project by its compose label; idempotent, process-independent.

    Args:
        project: The compose project name (as `up` reported it).
        state_dir: Ownership state root; defaults to the user state dir.
        runner: Command executor, injectable for tests.
        keep_state: Keep the project's state directory (stage log, console logs) for diagnosis; `up` uses this on failure teardown.

    Returns:
        Counts of removed resources; a second `down` returns all zeros.

    Raises:
        DownError: A docker query or removal failed; ownership state is kept so a retry can still find the project.
    """
    run: Runner = runner or run_command
    state = state_dir if state_dir is not None else default_state_dir()

    containers = _ids(
        run,
        [
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
    )
    container_query = [
        "docker",
        "ps",
        "-a",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
    ]
    if containers:
        _remove(run, ["docker", "rm", "-f", *containers], container_query)
    volumes = _ids(
        run,
        [
            "docker",
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
    )
    volume_query = [
        "docker",
        "volume",
        "ls",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
    ]
    if volumes:
        _remove(run, ["docker", "volume", "rm", "-f", *volumes], volume_query)
    networks = _ids(
        run,
        [
            "docker",
            "network",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
    )
    network_query = [
        "docker",
        "network",
        "ls",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project}",
    ]
    if networks:
        _remove(run, ["docker", "network", "rm", *networks], network_query)
    if not keep_state:
        remove_project(state, project)
    return DownResult(
        project=project,
        containers=len(containers),
        volumes=len(volumes),
        networks=len(networks),
    )


def discover_projects(state_dir: Path, runner: Runner) -> list[str]:
    """Every `ir-` project this host knows about: the ownership registry, container labels, and compose volume names (a crashed `up` may have left any subset)."""
    projects = set(list_projects(state_dir))
    labels = runner(
        ["docker", "ps", "-a", "--format", '{{.Label "com.docker.compose.project"}}']
    )
    if labels.returncode != 0:
        raise DownError(f"docker ps failed: {labels.stderr.strip()[-400:]}")
    projects.update(line.strip() for line in labels.stdout.splitlines() if line.strip())
    volumes = runner(["docker", "volume", "ls", "-q"])
    if volumes.returncode != 0:
        raise DownError(f"docker volume ls failed: {volumes.stderr.strip()[-400:]}")
    for name in volumes.stdout.splitlines():
        if name.startswith(PROJECT_PREFIX) and "_" in name:
            projects.add(name.rsplit("_", 1)[0])
    return sorted(p for p in projects if p.startswith(PROJECT_PREFIX))


def down_all(
    state_dir: Path | None = None, runner: Runner | None = None
) -> list[DownResult]:
    """Tear down every discovered `ir-` project; other prefixes are never touched.

    Every project is attempted even when one fails; failures aggregate into one `DownError` raised after the sweep, so a single stuck project cannot shield the rest.

    Raises:
        DownError: One or more projects failed to tear down (each named, with its error).
    """
    run: Runner = runner or run_command
    state = state_dir if state_dir is not None else default_state_dir()
    # sweep --from-spec staging leftovers (a SIGKILLed up cannot clean its own)
    staging = state.parent / "staging"
    if staging.is_dir():
        import shutil

        for leftover in staging.iterdir():
            shutil.rmtree(leftover, ignore_errors=True)
    results: list[DownResult] = []
    failures: list[str] = []
    for project in discover_projects(state, run):
        try:
            results.append(down(project, state_dir=state, runner=run))
        except DownError as error:
            failures.append(f"{project}: {error}")
    if failures:
        raise DownError(
            "some projects failed to tear down (the rest were swept):\n  "
            + "\n  ".join(failures)
        )
    return results
