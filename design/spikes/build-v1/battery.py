#!/usr/bin/env python3
"""build-v1 slice 1 battery driver: the recipe executor exercised through its public surface.

Host-only checks (digest, unresolved, vars, offline) need no range; live checks (ok, fail, budget, bg) take --boot pointing at a booted bundle's boot.json. Each check exits 0 on pass and 1 with a diagnostic on stderr; run.sh wraps them in PASS/FAIL counting.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from inspect_ranges._build import (
    RecipeError,
    RecipeTarget,
    recipe_digest,
    resolve_recipe,
    run_recipe,
    validate_vars,
)
from inspect_ranges._runtime.ownership import StageLog
from inspect_ranges.types import IssueError

GUEST = "web"


def target_from_boot(boot_path: Path) -> RecipeTarget:
    boot = json.loads(boot_path.read_text())
    cids = {g["name"]: g["cid"] for g in boot["guests"]}
    return RecipeTarget(guest=GUEST, cids=cids)


def check_digest(fixtures: Path, tmp: Path) -> None:
    bundle = fixtures / "recipes" / "bv1.ok"
    first = recipe_digest(bundle)
    assert first == recipe_digest(bundle), "same bundle hashed twice differs"
    copy = tmp / "bv1.ok-copy"
    if copy.exists():
        shutil.rmtree(copy)
    shutil.copytree(bundle, copy)
    assert recipe_digest(copy) == first, "identical rebuilt bundle digests differently"
    (copy / "drift.txt").write_text("x\n")
    assert recipe_digest(copy) != first, "content change did not change the digest"


def check_unresolved(fixtures: Path, tmp: Path) -> None:
    try:
        resolve_recipe("bv1.nowhere", range_dir=fixtures, cache=tmp / "empty-cache")
    except IssueError as error:
        assert error.issues[0].code == "recipe-not-resolved", error.issues
        return
    raise AssertionError("unresolvable recipe did not refuse")


def check_vars(fixtures: Path, tmp: Path) -> None:
    recipe = resolve_recipe("bv1.ok", range_dir=fixtures, cache=tmp / "empty-cache")
    try:
        validate_vars(recipe, {"bogus": "x"})
    except IssueError as error:
        codes = sorted(issue.code for issue in error.issues)
        assert codes == ["recipe-var-missing", "recipe-var-unknown"], codes
        return
    raise AssertionError("bad vars did not refuse")


def check_offline(fixtures: Path, tmp: Path) -> None:
    recipe = resolve_recipe("bv1.offline", range_dir=fixtures, cache=tmp / "empty-cache")
    try:
        run_recipe(
            recipe,
            step_vars={},
            target=RecipeTarget(guest=GUEST, cids={GUEST: 0}),
            log_dir=tmp / "logs",
        )
    except IssueError as error:
        assert error.issues[0].code == "recipe-mode-unsupported", error.issues
        return
    raise AssertionError("offline recipe did not refuse")


def check_ok(fixtures: Path, tmp: Path, boot: Path) -> None:
    recipe = resolve_recipe("bv1.ok", range_dir=fixtures, cache=tmp / "empty-cache")
    log = StageLog(tmp / "state", "ir-bv1-driver")
    run = run_recipe(
        recipe,
        step_vars={"marker": "zig"},
        target=target_from_boot(boot),
        log_dir=tmp / "logs",
        stage_log=log,
        budget_s=120.0,
    )
    assert run.digest == recipe.digest and run.guest == GUEST
    assert run.log_path.is_file(), "no run log written"
    statuses = [e["status"] for e in log.events() if e["stage"] == "recipe"]
    assert statuses == ["start", "ok"], statuses


def check_fail(fixtures: Path, tmp: Path, boot: Path) -> None:
    recipe = resolve_recipe("bv1.fail", range_dir=fixtures, cache=tmp / "empty-cache")
    try:
        run_recipe(
            recipe,
            step_vars={},
            target=target_from_boot(boot),
            log_dir=tmp / "logs",
            budget_s=60.0,
        )
    except RecipeError as error:
        assert error.stage == "run", error.stage
        assert "exited 3" in str(error), str(error)
        assert "provisioning exploded" in error.log_path.read_text()
        return
    raise AssertionError("nonzero recipe did not fail")


def check_budget(fixtures: Path, tmp: Path, boot: Path) -> None:
    recipe = resolve_recipe("bv1.slow", range_dir=fixtures, cache=tmp / "empty-cache")
    started = time.monotonic()
    try:
        run_recipe(
            recipe,
            step_vars={},
            target=target_from_boot(boot),
            log_dir=tmp / "logs",
            budget_s=2.0,
        )
    except RecipeError as error:
        elapsed = time.monotonic() - started
        assert error.stage == "budget", error.stage
        assert elapsed < 15.0, f"budget kill took {elapsed:.1f} s"
        return
    raise AssertionError("over-budget recipe did not fail")


def check_bg(fixtures: Path, tmp: Path, boot: Path) -> None:
    recipe = resolve_recipe("bv1.bg", range_dir=fixtures, cache=tmp / "empty-cache")
    started = time.monotonic()
    run_recipe(
        recipe,
        step_vars={},
        target=target_from_boot(boot),
        log_dir=tmp / "logs",
        budget_s=60.0,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 20.0, f"background-child exec held the recipe for {elapsed:.1f} s"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check")
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--tmp", type=Path, required=True)
    parser.add_argument("--boot", type=Path, default=None)
    args = parser.parse_args()
    args.tmp.mkdir(parents=True, exist_ok=True)
    host_only = {
        "digest": check_digest,
        "unresolved": check_unresolved,
        "vars": check_vars,
        "offline": check_offline,
    }
    live = {"ok": check_ok, "fail": check_fail, "budget": check_budget, "bg": check_bg}
    try:
        if args.check in host_only:
            host_only[args.check](args.fixtures, args.tmp)
        elif args.check in live:
            assert args.boot is not None, "--boot required for live checks"
            live[args.check](args.fixtures, args.tmp, args.boot)
        else:
            print(f"unknown check {args.check!r}", file=sys.stderr)
            return 2
    except (AssertionError, IssueError, RecipeError) as error:
        print(f"{args.check}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
