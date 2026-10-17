"""Build orchestration through the public `build_range` surface: real spec validation, real egress transformation, real render into staging, with the boot/teardown/recipe seams faked (no VMs)."""

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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
