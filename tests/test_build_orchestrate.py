"""Build orchestration through the public `build_range` surface: real spec validation, real egress transformation, real render into staging, with the boot/teardown/recipe seams faked (no VMs)."""

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from inspect_ranges._build import (
    FALLBACK_BUILD_NAMESERVER,
    BuildError,
    BuildOptions,
    RecipeError,
    RecipeRun,
    build_range,
    default_build_nameserver,
    egress_build_spec,
)
from inspect_ranges._build.recipes import RecipeTarget, ResolvedRecipe, StageSink
from inspect_ranges._runtime.up import GuestState, UpOptions, UpResult
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    IssueError,
    Network,
    Os,
    ProvisioningStep,
    RangeMeta,
    RangeSpec,
    Service,
)

from tests.test_build_recipes import write_recipe
from tests.test_compiler import chained_spec


def build_spec_fixture(tmp_path: Path) -> tuple[RangeSpec, Path]:
    """A one-segment spec with three provisioning steps across two hosts, plus its range dir with recipes."""
    range_dir = tmp_path / "range"
    if not (
        range_dir / "recipes" / "acme.web"
    ).exists():  # idempotent for rebuild tests
        write_recipe(range_dir, name="acme.web", inputs={"marker": {}})
        write_recipe(range_dir, name="acme.db")
    spec = RangeSpec(
        meta=RangeMeta(name="buildme", description="orchestration fixture"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab")],
                provisioning=[
                    ProvisioningStep(recipe="acme.web", vars={"marker": "one"}),
                    ProvisioningStep(recipe="acme.web", vars={"marker": "two"}),
                ],
            ),
            Host(
                name="db",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab")],
                provisioning=[ProvisioningStep(recipe="acme.db")],
            ),
        ],
        attacker=Attacker(
            image="tiny-golden",
            interfaces=[Interface(network="lab")],
            entry="external",
        ),
    )
    return spec, range_dir


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "tiny-golden.qcow2").write_bytes(b"golden")
    return cache


class Fakes:
    """Recording seams for up/down/recipes/uplink."""

    def __init__(self, project_guests: list[str]) -> None:
        self.up_calls: list[tuple[Path, UpOptions]] = []
        self.down_calls: list[str] = []
        self.recipe_calls: list[tuple[str, str, dict[str, Any]]] = []
        self.uplinks: list[str] = []
        self.captures: list[tuple[str, str, str]] = []
        self.compose: str = ""
        self._guests = project_guests

    def up_fn(self, bundle: Path, options: UpOptions, **_: Any) -> UpResult:
        self.up_calls.append((bundle, options))
        self.compose = (bundle / "compose.yaml").read_text()
        assert options.project is not None
        guests = [
            GuestState(name=name, cid=3000 + i, ready=True)
            for i, name in enumerate(self._guests)
        ]
        return UpResult(
            project=options.project, range_name="buildme", guests=guests, seconds=1.0
        )

    def down_fn(self, project: str, **_: Any) -> None:
        self.down_calls.append(project)

    def recipe_fn(
        self,
        recipe: ResolvedRecipe,
        *,
        step_vars: Mapping[str, Any],
        target: RecipeTarget,
        log_dir: Path,
        stage_log: StageSink | None = None,
        budget_s: float = 0.0,
    ) -> RecipeRun:
        self.recipe_calls.append((recipe.name, target.guest, dict(step_vars)))
        return RecipeRun(
            name=recipe.name,
            version=recipe.version,
            digest=recipe.digest,
            guest=target.guest,
            seconds=0.1,
            log_path=log_dir / "fake.log",
        )

    def ensure_uplink(self, name: str) -> None:
        self.uplinks.append(name)

    def capture_fn(
        self,
        project: str,
        guest: str,
        cids: dict[str, int],
        *,
        image_cache: Path,
        golden_file: str,
        realized_name: str,
        meta: Any,
    ) -> str:
        self.captures.append((guest, realized_name, golden_file))
        data = b"realized:" + guest.encode()
        (image_cache / realized_name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()


def options_for(tmp_path: Path, cache: Path, **overrides: Any) -> BuildOptions:
    overrides.setdefault("settle_probe", None)
    overrides.setdefault("build_cache", tmp_path / "builds")
    return BuildOptions(
        image_cache=cache, state_dir=tmp_path / "state" / "projects", **overrides
    )


def test_egress_build_spec_transforms_routerless_networks(tmp_path: Path) -> None:
    spec, _ = build_spec_fixture(tmp_path)
    build = egress_build_spec(spec, nameserver_ip="1.1.1.1")
    lab = build.networks[0]
    assert lab.mode == "nat"
    assert lab.egress is not None and lab.egress.allow == ["0.0.0.0/0"]
    assert lab.dns is not None and lab.dns.nameservers is not None
    assert str(lab.dns.nameservers[0]) == "1.1.1.1"
    # the runtime spec is untouched
    assert spec.networks[0].mode == "isolated" and spec.networks[0].egress is None


def test_default_build_nameserver_derivation(tmp_path: Path) -> None:
    stub = tmp_path / "stub.conf"
    stub.write_text("nameserver 127.0.0.53\n")
    real = tmp_path / "real.conf"
    real.write_text("# comment\nnameserver 127.0.0.1\nnameserver 169.254.169.253\n")
    assert default_build_nameserver((stub, real)) == "169.254.169.253"
    assert (
        default_build_nameserver((stub, tmp_path / "absent.conf"))
        == FALLBACK_BUILD_NAMESERVER
    )


def test_egress_build_spec_leaves_router_networks_alone() -> None:
    spec = chained_spec()
    before = {network.name: network.mode for network in spec.networks}
    router_networks = {
        interface.network for router in spec.routers for interface in router.interfaces
    }
    build = egress_build_spec(spec)
    for network in build.networks:
        if network.name in router_networks:
            assert network.mode == before[network.name]


def test_build_runs_recipes_in_declaration_order_and_tears_down(
    tmp_path: Path, cache: Path
) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
    )
    assert [(name, guest) for name, guest, _ in fakes.recipe_calls] == [
        ("acme.web", "web"),
        ("acme.web", "web"),
        ("acme.db", "db"),
    ]
    assert fakes.recipe_calls[0][2] == {"marker": "one"}
    assert fakes.down_calls == [result.project]
    assert not result.kept and len(result.recipes) == 3
    assert fakes.uplinks == ["ir-uplink"]
    # the staging bundle rendered the egress variant (uplink compose) and was
    # removed after the non-keep build
    assert "UPLINK_NETWORK" in fakes.compose
    assert not fakes.up_calls[0][0].exists()


def test_keep_skips_teardown(tmp_path: Path, cache: Path) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache, keep=True),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
    )
    assert result.kept and fakes.down_calls == []
    # keep leaves the staging bundle: the running range mounts it
    assert fakes.up_calls[0][0].exists()


def test_recipe_failure_tears_down_and_names_everything(
    tmp_path: Path, cache: Path
) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])

    def failing_recipe(
        recipe: ResolvedRecipe,
        *,
        step_vars: Mapping[str, Any],
        target: RecipeTarget,
        log_dir: Path,
        stage_log: StageSink | None = None,
        budget_s: float = 0.0,
    ) -> RecipeRun:
        if len(fakes.recipe_calls) >= 1:
            raise RecipeError(
                "run",
                "exited 3",
                recipe=recipe.name,
                guest="web",
                log_path=tmp_path / "r.log",
            )
        return fakes.recipe_fn(
            recipe,
            step_vars=step_vars,
            target=target,
            log_dir=log_dir,
            stage_log=stage_log,
            budget_s=budget_s,
        )

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=failing_recipe,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    error = excinfo.value
    assert error.stage == "recipe"
    assert error.guest == "web" and error.recipe == "acme.web"
    assert error.log_path == tmp_path / "r.log"
    assert len(fakes.down_calls) == 1


def test_bare_build_uses_the_default_image_cache(
    tmp_path: Path, cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The review-caught regression: no --image-cache must mean the shared default, not digest-less refusal."""
    monkeypatch.setenv("INSPECT_RANGES_IMAGE_CACHE", str(cache))
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    result = build_range(
        spec,
        range_dir,
        BuildOptions(
            state_dir=tmp_path / "state" / "projects",
            settle_probe=None,
            build_cache=tmp_path / "builds",
        ),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
    )
    assert len(result.recipes) == 3
    assert fakes.up_calls[0][1].image_cache == cache


def test_network_settle_gates_each_guest_once(tmp_path: Path, cache: Path) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    settled: list[str] = []

    def settle(cids: dict[str, int], guest: str, probe: str, timeout_s: float) -> float:
        assert probe == "archive.ubuntu.com" and "web" in cids
        settled.append(guest)
        return 0.5

    build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache, settle_probe="archive.ubuntu.com"),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        settle_fn=settle,
    )
    # once per guest with steps, not per step; db settles after web's steps
    assert settled == ["web", "db"]


def test_settle_failure_tears_down(tmp_path: Path, cache: Path) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])

    def settle(cids: dict[str, int], guest: str, probe: str, timeout_s: float) -> float:
        raise BuildError("network-settle", "cannot resolve", guest=guest)

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache, settle_probe="archive.ubuntu.com"),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            settle_fn=settle,
        )
    assert excinfo.value.stage == "network-settle"
    assert len(fakes.down_calls) == 1 and fakes.recipe_calls == []


def test_verify_runs_after_recipes_and_failures_tear_down(
    tmp_path: Path, cache: Path
) -> None:
    from inspect_ranges._build.verify import DeclarationResult

    spec, range_dir = build_spec_fixture(tmp_path)
    spec.hosts[0].services = [Service(name="nginx", port=80, version="1.18")]
    fakes = Fakes(["web", "db", "attacker"])
    order: list[str] = []

    def tracking_recipe(recipe: ResolvedRecipe, **kwargs: Any) -> RecipeRun:
        order.append("recipe")
        return fakes.recipe_fn(recipe, **kwargs)

    def failing_verify(
        spec: RangeSpec,
        cids: dict[str, int],
        *,
        log_dir: Path,
        stage_log: Any,
    ) -> list[DeclarationResult]:
        order.append("verify")
        assert "web" in cids
        return [
            DeclarationResult(
                kind="service",
                guest="web",
                name="nginx",
                status="fail",
                code="service-not-verified",
                declared="nginx port 80 version 1.18",
                observed="no tcp/udp socket on port 80",
            )
        ]

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=tracking_recipe,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            verify_fn=failing_verify,
        )
    assert excinfo.value.stage == "verify"
    assert "1 of 1 declarations failed" in str(excinfo.value)
    assert order and order[-1] == "verify" and order.count("recipe") == 3
    assert len(fakes.down_calls) == 1


def test_raising_verify_probe_tears_down_and_stages(
    tmp_path: Path, cache: Path
) -> None:
    """A wedged probe is a stage-named BuildError with teardown, never a raw traceback."""
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])

    def exploding_verify(*args: Any, **kwargs: Any) -> list[Any]:
        raise RuntimeError("fact probe on guest 'web' exited 124")

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            verify_fn=exploding_verify,
        )
    assert excinfo.value.stage == "verify"
    assert "verification probe failed" in str(excinfo.value)
    assert "range torn down" in str(excinfo.value)
    assert len(fakes.down_calls) == 1
    # the staging bundle is cleaned up with the range
    assert not fakes.up_calls[0][0].exists()


def test_verifications_land_on_the_result(tmp_path: Path, cache: Path) -> None:
    from inspect_ranges._build.verify import DeclarationResult

    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    ok = DeclarationResult(
        kind="service",
        guest="web",
        name="nginx",
        status="ok",
        code="",
        declared="nginx port 80",
        observed="tcp/80 by nginx",
    )

    def passing_verify(*args: Any, **kwargs: Any) -> list[DeclarationResult]:
        return [ok]

    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        verify_fn=passing_verify,
    )
    assert result.verifications == (ok,)
    assert fakes.down_calls == [result.project]


def test_resolution_fails_fast_before_boot(tmp_path: Path, cache: Path) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    spec.hosts[1].provisioning = [ProvisioningStep(recipe="acme.missing")]
    spec.hosts[0].provisioning[0].vars = {"bogus": "x"}
    fakes = Fakes(["web", "db", "attacker"])
    with pytest.raises(IssueError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    codes = sorted(issue.code for issue in excinfo.value.issues)
    assert codes == [
        "recipe-not-resolved",
        "recipe-var-missing",
        "recipe-var-unknown",
    ]
    assert fakes.up_calls == [] and fakes.recipe_calls == []


def full_build(tmp_path: Path, cache: Path, fakes: Fakes, **opt: Any) -> Any:
    spec, range_dir = build_spec_fixture(tmp_path)
    return build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache, **opt),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
    )


def test_first_build_captures_and_writes_the_manifest(
    tmp_path: Path, cache: Path
) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, fakes)
    assert not result.cached and result.manifest_path is not None
    assert [guest for guest, _, _ in fakes.captures] == ["web", "db"]
    from inspect_ranges._build import load_manifest

    manifest = load_manifest(tmp_path / "builds", "buildme")
    assert manifest is not None and len(manifest.guests) == 2
    web = manifest.guest("web")
    assert web is not None and web.recipes[0].name == "acme.web"
    assert (cache / web.realized_file).is_file()


def test_noop_rebuild_is_the_cached_fast_path(tmp_path: Path, cache: Path) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    first = full_build(tmp_path, cache, fakes)
    again = Fakes(["web", "db", "attacker"])
    second = full_build(tmp_path, cache, again)
    assert second.cached and second.verified_at == first.verified_at
    # nothing booted, ran, or captured
    assert again.up_calls == [] and again.recipe_calls == [] and again.captures == []
    assert second.manifest_path == first.manifest_path


def test_reverify_boots_despite_matching_keys(tmp_path: Path, cache: Path) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    full_build(tmp_path, cache, fakes)
    again = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, again, reverify=True)
    assert not result.cached
    assert len(again.up_calls) == 1
    # all guests reused: recipes skipped, nothing recaptured
    assert again.recipe_calls == [] and again.captures == []


def test_recipe_edit_rebuilds_exactly_that_guest(tmp_path: Path, cache: Path) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    full_build(tmp_path, cache, fakes)
    # change web's recipe content: its digest, so its key, moves
    (tmp_path / "range" / "recipes" / "acme.web" / "run.sh").write_text(
        "#!/bin/sh\nexit 0\n# edited\n"
    )
    again = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, again)
    assert not result.cached
    assert {guest for _, guest, _ in again.recipe_calls} == {"web"}
    assert [guest for guest, _, _ in again.captures] == ["web"]
    # db booted from its realized image (the build spec swapped its reference)
    assert "db" not in {g for g, _, _ in again.captures}


def test_keep_builds_are_diagnostic_and_mint_no_manifest(
    tmp_path: Path, cache: Path
) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, fakes, keep=True)
    assert result.kept and result.manifest_path is None and fakes.captures == []


def test_invalid_range_name_refuses_before_anything(
    tmp_path: Path, cache: Path
) -> None:
    spec, range_dir = build_spec_fixture(tmp_path)
    spec.meta.name = "../etc"
    fakes = Fakes(["web", "db", "attacker"])
    with pytest.raises(IssueError) as excinfo:
        full_build_spec(spec, range_dir, tmp_path, cache, fakes)
    assert excinfo.value.issues[0].code == "range-name-invalid"
    assert fakes.up_calls == []


def full_build_spec(
    spec: RangeSpec,
    range_dir: Path,
    tmp_path: Path,
    cache: Path,
    fakes: Fakes,
    **extra: Any,
) -> Any:
    return build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        **extra,
    )


def test_spec_only_edit_reuses_guests_and_rewrites_the_manifest(
    tmp_path: Path, cache: Path
) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    first = full_build(tmp_path, cache, fakes)
    from inspect_ranges._build import load_manifest

    before = load_manifest(tmp_path / "builds", "buildme")
    assert before is not None
    spec, range_dir = build_spec_fixture(tmp_path)
    spec.meta.description = "edited description, guest content untouched"
    again = Fakes(["web", "db", "attacker"])
    result = full_build_spec(spec, range_dir, tmp_path, cache, again)
    # not the cached fast path (the spec hash moved), but every guest reused
    assert not result.cached
    assert again.recipe_calls == [] and again.captures == []
    assert len(again.up_calls) == 1
    assert result.manifest_path == first.manifest_path
    from inspect_ranges._build import load_manifest

    manifest = load_manifest(tmp_path / "builds", "buildme")
    assert manifest is not None
    assert manifest.spec_sha256 != before.spec_sha256  # the new spec hash recorded
    assert manifest.guest("web") is not None


def test_golden_change_rebuilds_everything(tmp_path: Path, cache: Path) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    full_build(tmp_path, cache, fakes)
    (cache / "tiny-golden.qcow2").write_bytes(b"golden-v2")
    again = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, again)
    assert not result.cached
    assert [guest for guest, _, _ in again.captures] == ["web", "db"]
    assert {guest for _, guest, _ in again.recipe_calls} == {"web", "db"}


def test_manifest_records_the_committed_inputs(tmp_path: Path, cache: Path) -> None:
    fakes = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, fakes)
    from inspect_ranges._build import load_manifest

    manifest = load_manifest(tmp_path / "builds", "buildme")
    assert manifest is not None
    assert manifest.project == result.project
    spec_range = manifest.spec.get("range")
    assert isinstance(spec_range, dict)
    assert cast(dict[str, object], spec_range).get("name") == "buildme"
    base = {record.guest for record in manifest.base_images}
    assert {"web", "db", "attacker"} <= base
    assert all(record.digest for record in manifest.base_images)
    assert manifest.verification.behavioral_checks == ()


def declare_checks(range_dir: Path) -> None:
    """Make `checks_declared` true for the fixture range (contents never parsed; the seam is faked)."""
    (range_dir / "challenges.yaml").write_text("challenges: []\n")
    demo = range_dir / "checks" / "demo"
    demo.mkdir(parents=True, exist_ok=True)
    for name in ("reference", "insufficient", "forged"):
        (demo / f"{name}.sh").write_text("#!/bin/bash\necho SUBMIT g v\n")


def test_behavioral_records_land_in_the_manifest(tmp_path: Path, cache: Path) -> None:
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])
    records = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="pass", detail="value=1.00"
        ),
    )
    calls: list[str] = []

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, *, project: str, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        # the phase runs against the captured artifacts: the build range must
        # already be down when the checks boot
        assert fakes.down_calls == [project]
        calls.append(project)
        return records

    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert calls == [result.project]
    manifest = load_manifest(tmp_path / "builds", "buildme")
    assert manifest is not None
    assert manifest.verification.behavioral_checks == records


def test_failing_behavioral_check_leaves_no_manifest(
    tmp_path: Path, cache: Path
) -> None:
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        raise BuildError(
            "behavioral", "challenge 'demo' check 'reference' failed: value=0.00"
        )

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            behavioral_fn=behavioral_fn,
        )
    assert "no manifest was written; the build is unproven" in str(excinfo.value)
    assert load_manifest(tmp_path / "builds", "buildme") is None


def test_keep_skips_the_behavioral_phase(tmp_path: Path, cache: Path) -> None:
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        raise AssertionError("behavioral checks must not run while the range is kept")

    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache, keep=True),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert result.kept


def test_behavioral_infra_failure_also_leaves_no_manifest(
    tmp_path: Path, cache: Path
) -> None:
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        raise RuntimeError("compose up failed: capture sidecar exited")

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            behavioral_fn=behavioral_fn,
        )
    assert excinfo.value.stage == "behavioral"
    assert "no manifest was written; the build is unproven" in str(excinfo.value)
    assert load_manifest(tmp_path / "builds", "buildme") is None


def test_teardown_failure_with_checks_declared_leaves_no_manifest(
    tmp_path: Path, cache: Path
) -> None:
    """Slice 6 review finding 1a: the checks never ran, so nothing consumable may exist."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])

    def failing_down(project: str, **_: Any) -> None:
        raise RuntimeError("libvirt wedged")

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        raise AssertionError(
            "the behavioral phase must not run after a failed teardown"
        )

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=failing_down,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            behavioral_fn=behavioral_fn,
        )
    assert excinfo.value.stage == "teardown"
    assert load_manifest(tmp_path / "builds", "buildme") is None


def test_check_edit_invalidates_the_cached_fast_path(
    tmp_path: Path, cache: Path
) -> None:
    """Slice 6 review finding 2: proof tools are build inputs; a new or edited check re-runs the pass."""
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    records = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="pass", detail="value=1.00"
        ),
    )
    calls: list[str] = []

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, *, project: str, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        calls.append(project)
        return records

    fakes = Fakes(["web", "db", "attacker"])
    first = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert not first.cached and calls == [first.project]
    # unchanged inputs: the no-op fast path, no behavioral re-run
    again = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert again.cached and len(calls) == 1
    # an edited check script moves the checks digest: not cached, guests
    # reused, the behavioral phase re-proves
    (range_dir / "checks" / "demo" / "reference.sh").write_text(
        "#!/bin/bash\necho SUBMIT g other\n"
    )
    edited = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert not edited.cached and len(calls) == 2


def test_incomplete_check_trio_refuses(tmp_path: Path) -> None:
    """Slice 6 review finding 3: proof that silently does not run must refuse instead."""
    import yaml as yaml_module
    from inspect_ranges._build.behavioral import _validate_checks

    range_dir = tmp_path / "range"
    (range_dir / "checks" / "demo").mkdir(parents=True)
    (range_dir / "challenges.yaml").write_text(
        yaml_module.safe_dump(
            {
                "challenges": [
                    {
                        "id": "demo",
                        "prompt": "p",
                        "goals": [
                            {
                                "id": "g",
                                "type": "execute",
                                "host": "web",
                                "service_user": "svc",
                                "token_path": "/tmp/t",
                            }
                        ],
                    }
                ]
            }
        )
    )
    from inspect_ranges._build.behavioral import load_challenges

    challenges = load_challenges(range_dir)
    for name in ("reference", "insufficient"):
        (range_dir / "checks" / "demo" / f"{name}.sh").write_text("#!/bin/bash\n")
    with pytest.raises(BuildError) as excinfo:
        _validate_checks(challenges, range_dir)
    assert "forged.sh" in str(excinfo.value)
    (range_dir / "checks" / "demo" / "forged.sh").write_text("#!/bin/bash\n")
    _validate_checks(challenges, range_dir)  # complete trio passes
    (range_dir / "checks" / "typo-dir").mkdir()
    with pytest.raises(BuildError) as excinfo:
        _validate_checks(challenges, range_dir)
    assert "typo-dir" in str(excinfo.value)


def test_failing_reproof_deletes_the_prior_same_spec_manifest(
    tmp_path: Path, cache: Path
) -> None:
    """Round-1 blocking: the deferred save covered first builds only; a rebuild whose checks fail must retract the prior manifest or the gate keeps serving artifacts that just failed their proof."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    good = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="pass", detail="value=1.00"
        ),
    )
    outcomes: list[str] = ["pass", "fail"]

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        if outcomes.pop(0) == "pass":
            return good
        raise BuildError("behavioral", "check 'reference' failed: value=0.00")

    fakes = Fakes(["web", "db", "attacker"])
    first = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        behavioral_fn=behavioral_fn,
    )
    assert first.manifest_path is not None
    assert load_manifest(tmp_path / "builds", "buildme") is not None
    # the check is edited (digest moves, spec hash does not): the rebuild
    # reuses every guest and the re-proof fails
    (range_dir / "checks" / "demo" / "reference.sh").write_text(
        "#!/bin/bash\necho SUBMIT g strengthened\n"
    )
    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            behavioral_fn=behavioral_fn,
        )
    assert "the prior manifest was deleted" in str(excinfo.value)
    assert load_manifest(tmp_path / "builds", "buildme") is None


def test_verify_failure_leaves_no_manifest(tmp_path: Path, cache: Path) -> None:
    """Round-1: the only check of this property was an inert battery grep."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.verify import DeclarationResult

    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])

    def failing_verify(*args: Any, **kwargs: Any) -> list[DeclarationResult]:
        raise BuildError("verify", "1 of 1 declarations failed")

    with pytest.raises(BuildError):
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
            verify_fn=failing_verify,
        )
    assert load_manifest(tmp_path / "builds", "buildme") is None


def test_keep_boot_failure_preserves_the_staging_bundle(
    tmp_path: Path, cache: Path
) -> None:
    """Round-1 blocking: up keeps the range on a kept boot failure, so staging must survive (the running range mounts it and the bundle is the diagnostic)."""
    from inspect_ranges._runtime.up import UpError

    spec, range_dir = build_spec_fixture(tmp_path)
    staged: list[Path] = []

    def failing_up(bundle: Path, options: UpOptions, **_: Any) -> UpResult:
        staged.append(bundle)
        raise UpError("guest-boot", "qemu refused")

    fakes = Fakes(["web", "db", "attacker"])
    with pytest.raises(UpError):
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache, keep=True),
            up_fn=failing_up,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert staged and staged[0].exists()
    # without keep, up tears the range down itself and staging goes too
    staged.clear()
    with pytest.raises(UpError):
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=failing_up,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert staged and not staged[0].exists()


def test_teardown_failure_preserves_the_staging_bundle(
    tmp_path: Path, cache: Path
) -> None:
    """Round-1 blocking: 'retry with: inspect-ranges down' is meaningless if the bundle the running range mounts was already destroyed."""
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    staged: list[Path] = []

    def recording_up(bundle: Path, options: UpOptions, **_: Any) -> UpResult:
        staged.append(bundle)
        return fakes.up_fn(bundle, options)

    def failing_down(project: str, **_: Any) -> None:
        raise RuntimeError("libvirt wedged")

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=recording_up,
            down_fn=failing_down,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert excinfo.value.stage == "teardown"
    assert staged and staged[0].exists()


def test_checks_dir_without_challenges_yaml_refuses(
    tmp_path: Path, cache: Path
) -> None:
    """Round-1 blocking: the root-level silent-skip (a misnamed metadata file) must refuse, not mint a manifest whose proof never ran."""
    spec, range_dir = build_spec_fixture(tmp_path)
    (range_dir / "checks" / "demo").mkdir(parents=True)
    fakes = Fakes(["web", "db", "attacker"])
    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert excinfo.value.stage == "behavioral"
    assert "challenges.yaml is missing" in str(excinfo.value)


def test_keep_bypasses_the_cached_fast_path(tmp_path: Path, cache: Path) -> None:
    """Round-1: --keep exists to leave a running range, which the no-op cannot provide."""
    fakes = Fakes(["web", "db", "attacker"])
    full_build(tmp_path, cache, fakes)
    again = Fakes(["web", "db", "attacker"])
    result = full_build(tmp_path, cache, again, keep=True)
    assert not result.cached and result.kept
    assert len(again.up_calls) == 1  # it really booted (all guests reused)


def test_strip_stage_preserves_message_colons() -> None:
    """Round-1: the old split-on-first-colon mangled challenge names and doubled guest prefixes."""
    from inspect_ranges._build.orchestrate import _strip_stage

    plain = BuildError(
        "behavioral", "challenge 'demo' check 'forged' failed: value=0.00"
    )
    assert _strip_stage(plain) == "challenge 'demo' check 'forged' failed: value=0.00"
    with_guest = BuildError("recipe", "exited 1: tail", guest="web", recipe="acme.web")
    assert _strip_stage(with_guest) == "exited 1: tail"


def test_unexpected_recipe_phase_exception_disposes_and_names_its_stage(
    tmp_path: Path, cache: Path
) -> None:
    """Round-2 blocking: the one post-boot arm without a broad catch leaked the egress-enabled range behind a raw traceback."""
    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])

    def exploding_recipe(*args: Any, **kwargs: Any) -> RecipeRun:
        raise OSError(28, "No space left on device")

    with pytest.raises(BuildError) as excinfo:
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
            recipe_fn=exploding_recipe,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert excinfo.value.stage == "recipe"
    assert "No space left" in str(excinfo.value)
    assert fakes.down_calls  # disposed, not leaked


def test_removing_checks_after_a_proven_build_refuses(
    tmp_path: Path, cache: Path
) -> None:
    """Round-2: the inverse of the misnamed-metadata guard; a silent green rebuild would downgrade proven to unproven-but-consumable."""
    import shutil as shutil_module

    from inspect_ranges._build.manifest import BehavioralCheckRecord

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    records = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="pass", detail="value=1.00"
        ),
    )

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        return records

    fakes = Fakes(["web", "db", "attacker"])
    full_build_spec(
        spec, range_dir, tmp_path, cache, fakes, behavioral_fn=behavioral_fn
    )
    shutil_module.rmtree(range_dir / "checks")
    (range_dir / "challenges.yaml").unlink()
    with pytest.raises(BuildError) as excinfo:
        full_build_spec(
            spec, range_dir, tmp_path, cache, fakes, behavioral_fn=behavioral_fn
        )
    assert excinfo.value.stage == "behavioral"
    assert "declares no checks" in str(excinfo.value)


def test_base_exception_from_up_preserves_staging(tmp_path: Path, cache: Path) -> None:
    """Round-2: a Ctrl-C mid-boot gives no disposal guarantee; the bundle the (likely surviving) range mounts must not be destroyed."""
    spec, range_dir = build_spec_fixture(tmp_path)
    staged: list[Path] = []

    def interrupted_up(bundle: Path, options: UpOptions, **_: Any) -> UpResult:
        staged.append(bundle)
        raise KeyboardInterrupt()

    fakes = Fakes(["web", "db", "attacker"])
    with pytest.raises(KeyboardInterrupt):
        build_range(
            spec,
            range_dir,
            options_for(tmp_path, cache),
            up_fn=interrupted_up,
            down_fn=fakes.down_fn,
            recipe_fn=fakes.recipe_fn,
            ensure_uplink=fakes.ensure_uplink,
            capture_fn=fakes.capture_fn,
        )
    assert staged and staged[0].exists()
