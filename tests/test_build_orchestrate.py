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
        self.capture_nameservers: list[str | None] = []
        self.capture_quiesced: list[bool] = []
        self.quiesces: list[str] = []
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

    def quiesce_fn(
        self,
        project: str,
        guest: str,
        cids: dict[str, int],
        *,
        hybrid_sockets: Any = None,
        windows: bool = False,
        build_nameserver: str | None = None,
    ) -> None:
        # ordering proof: every quiesce must precede every capture
        assert self.captures == [], "a capture ran before the quiesce point"
        self.quiesces.append(guest)

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
        hybrid_sockets: Any = None,
        windows: bool = False,
        build_nameserver: str | None = None,
        quiesced: bool = False,
    ) -> str:
        self.captures.append((guest, realized_name, golden_file))
        self.capture_nameservers.append(build_nameserver)
        self.capture_quiesced.append(quiesced)
        data = b"realized:" + guest.encode()
        (image_cache / realized_name).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        # the real capture writes the provenance sidecar beside the image; the
        # GC sweep and images list key on it, so the fake does too
        sidecar = image_cache / (
            realized_name.removesuffix(".qcow2") + ".realized.json"
        )
        sidecar.write_text(meta.model_copy(update={"sha256": digest}).model_dump_json())
        return digest


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

    def settle(
        cids: dict[str, int],
        guest: str,
        probe: str,
        timeout_s: float,
        hybrid_sockets: Any = None,
        windows_resolver: str | None = None,
    ) -> float:
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

    def settle(
        cids: dict[str, int],
        guest: str,
        probe: str,
        timeout_s: float,
        hybrid_sockets: Any = None,
        windows_resolver: str | None = None,
    ) -> float:
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
        hybrid_sockets: Any = None,
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


def test_failing_behavioral_check_records_a_refused_manifest(
    tmp_path: Path, cache: Path
) -> None:
    """Parked-decisions item 4: a failing check saves the manifest WITH its verdict; the gate refuses range-unproven; guest reuse survives for the next build."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import (
        BehavioralCheckRecord,
        apply_build_manifest,
    )

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        return (
            BehavioralCheckRecord(
                challenge="demo",
                check="reference",
                status="fail",
                detail="value=0.00 validity=valid submissions=2",
            ),
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
    assert "a refused manifest was recorded" in str(excinfo.value)
    refused = load_manifest(tmp_path / "builds", "buildme")
    assert refused is not None
    assert refused.verification.behavioral_checks[0].status == "fail"
    with pytest.raises(IssueError) as gate:
        apply_build_manifest(spec, image_cache=cache, build_cache=tmp_path / "builds")
    assert gate.value.issues[0].code == "range-unproven"
    assert "demo/reference" in gate.value.issues[0].message
    # the next build is NOT the cached fast path, but it reuses every guest
    again = Fakes(["web", "db", "attacker"])

    def passing_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        return (
            BehavioralCheckRecord(
                challenge="demo", check="reference", status="pass", detail="value=1.00"
            ),
        )

    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=again.up_fn,
        down_fn=again.down_fn,
        recipe_fn=again.recipe_fn,
        ensure_uplink=again.ensure_uplink,
        capture_fn=again.capture_fn,
        behavioral_fn=passing_fn,
    )
    assert not result.cached
    assert again.recipe_calls == [] and again.captures == []  # all guests reused
    proven = load_manifest(tmp_path / "builds", "buildme")
    assert proven is not None
    assert proven.verification.behavioral_checks[0].status == "pass"
    swapped, _, _ = apply_build_manifest(
        spec, image_cache=cache, build_cache=tmp_path / "builds"
    )
    assert swapped.hosts[0].image.endswith(".qcow2")


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


def test_behavioral_infra_failure_records_a_refused_manifest(
    tmp_path: Path, cache: Path
) -> None:
    """An unrun proof is as unproven as a failed one: the refused manifest carries a synthetic phase record and the gate refuses."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import (
        BehavioralCheckRecord,
        apply_build_manifest,
    )

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
    assert "a refused manifest was recorded" in str(excinfo.value)
    refused = load_manifest(tmp_path / "builds", "buildme")
    assert refused is not None
    record = refused.verification.behavioral_checks[0]
    assert record.check == "phase" and record.status == "fail"
    with pytest.raises(IssueError) as gate:
        apply_build_manifest(spec, image_cache=cache, build_cache=tmp_path / "builds")
    assert gate.value.issues[0].code == "range-unproven"


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


def test_failing_reproof_replaces_the_prior_manifest_with_a_refused_one(
    tmp_path: Path, cache: Path
) -> None:
    """A rebuild whose checks fail must retract the prior green manifest's consumability: the failing build's own refused manifest replaces it (parked-decisions item 4)."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import (
        BehavioralCheckRecord,
        apply_build_manifest,
    )

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    good = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="pass", detail="value=1.00"
        ),
    )
    bad = (
        BehavioralCheckRecord(
            challenge="demo", check="reference", status="fail", detail="value=0.00"
        ),
    )
    outcomes: list[tuple[BehavioralCheckRecord, ...]] = [good, bad]

    def behavioral_fn(
        spec: RangeSpec, range_dir: Path, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        return outcomes.pop(0)

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
    assert "a refused manifest was recorded" in str(excinfo.value)
    current = load_manifest(tmp_path / "builds", "buildme")
    assert current is not None
    assert current.verification.behavioral_checks[0].status == "fail"
    with pytest.raises(IssueError) as gate:
        apply_build_manifest(spec, image_cache=cache, build_cache=tmp_path / "builds")
    assert gate.value.issues[0].code == "range-unproven"


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


def test_build_success_collects_superseded_generations_keeping_one(
    tmp_path: Path, cache: Path
) -> None:
    """Parked-decisions item 1: generation 1 goes when generation 3 lands; generation 2 (the replaced manifest's) stays for free rollback."""
    spec, range_dir = build_spec_fixture(tmp_path)
    generations: list[set[str]] = []
    for marker in ("one", "two", "three"):
        (range_dir / "recipes" / "acme.db" / "run.sh").write_text(
            f"#!/bin/sh\necho {marker}\n"
        )
        fakes = Fakes(["web", "db", "attacker"])
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
        generations.append({path.name for path in cache.glob("buildme-db-*.qcow2")})
    assert len(generations[0]) == 1
    assert len(generations[1]) == 2  # current + previous kept
    assert len(generations[2]) == 2  # generation 1 collected
    gen1 = generations[0]
    assert not (gen1 & generations[2])
    # web never changed: exactly one generation throughout
    assert len({p.name for p in cache.glob("buildme-web-*.qcow2")}) == 1


def test_refused_save_never_clobbers_a_sibling_green_manifest(
    tmp_path: Path, cache: Path
) -> None:
    """Round-2: the refused save is identity-guarded, replacing only the revision this build loaded at resolve; a concurrent sibling's fresh green manifest stays untouched."""
    from inspect_ranges._build import load_manifest
    from inspect_ranges._build.manifest import BehavioralCheckRecord, save_manifest

    spec, range_dir = build_spec_fixture(tmp_path)
    declare_checks(range_dir)
    fakes = Fakes(["web", "db", "attacker"])
    sibling_saved: list[bool] = []

    def failing_behavioral(
        spec: RangeSpec, range_dir: Path, *, manifest: Any, **_: Any
    ) -> tuple[BehavioralCheckRecord, ...]:
        # a sibling build lands its GREEN manifest while this build's
        # behavioral phase runs (the -bx window the project check misses)
        sibling = manifest.model_copy(
            update={
                "built_at": "2099-01-01T00:00:00Z",
                "verification": manifest.verification.model_copy(
                    update={
                        "behavioral_checks": (
                            BehavioralCheckRecord(
                                challenge="demo",
                                check="reference",
                                status="pass",
                                detail="value=1.00",
                            ),
                        )
                    }
                ),
            }
        )
        save_manifest(sibling, tmp_path / "builds")
        sibling_saved.append(True)
        return (
            BehavioralCheckRecord(
                challenge="demo", check="reference", status="fail", detail="value=0.00"
            ),
        )

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
            behavioral_fn=failing_behavioral,
        )
    assert sibling_saved
    survivor = load_manifest(tmp_path / "builds", "buildme")
    assert survivor is not None
    assert survivor.built_at == "2099-01-01T00:00:00Z"
    assert survivor.verification.behavioral_checks[0].status == "pass"


class RecorderSink:
    """A minimal `StageSink` for driving the behavioral phase directly."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, str, dict[str, Any]]] = []

    def log(self, stage: str, status: str, **fields: Any) -> None:
        self.entries.append((stage, status, fields))


def test_conformance_refusal_tears_down_the_bx_range(
    tmp_path: Path, cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-3 B1: the conformance stage's designed refusal (like every post-boot raise) must pass through the bx teardown finally; before the fix it leaked the running bx range while the outer finally rmtree'd the staging bundle the range mounts."""
    import inspect_ranges._build.behavioral as behavioral_module
    import inspect_ranges._build.manifest as manifest_module
    from inspect_ranges._build import orchestrate

    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    # the real swap strips provisioning (a realized image never re-provisions)
    swapped = spec.model_copy(
        update={
            "hosts": [
                host.model_copy(update={"provisioning": None}) for host in spec.hosts
            ]
        }
    )

    def fake_swap(
        spec_: RangeSpec, manifest: Any, image_cache: Path
    ) -> tuple[RangeSpec, frozenset[str]]:
        return swapped, frozenset()

    def fake_backings(manifest: Any) -> dict[str, tuple[str, str]]:
        return {}

    def converged(*args: Any, **kwargs: Any) -> list[Any]:
        return []

    monkeypatch.setattr(manifest_module, "swap_realized_spec", fake_swap)
    monkeypatch.setattr(manifest_module, "realized_backings", fake_backings)
    monkeypatch.setattr(orchestrate, "verify_range", converged)

    async def refuse(*args: Any, **kwargs: Any) -> None:
        raise BuildError("conformance", "attacker answers from web: 10.0.0.9 22")

    monkeypatch.setattr(behavioral_module, "run_conformance_checks", refuse)
    options = options_for(tmp_path, cache)
    state_dir = options.state_dir
    assert state_dir is not None
    with pytest.raises(BuildError, match="conformance"):
        orchestrate._run_behavioral_phase(
            spec,
            range_dir,
            manifest=cast(Any, None),
            image_cache=cache,
            build_cache=tmp_path / "builds",
            state_dir=state_dir,
            options=options,
            project="buildme",
            stage_log=RecorderSink(),
            up_fn=fakes.up_fn,
            down_fn=fakes.down_fn,
        )
    assert fakes.down_calls == ["buildme-bx"]
    staging_root = state_dir.parent / "staging"
    assert not any(staging_root.iterdir())


def test_egress_build_spec_uplinks_stranded_content_hosts() -> None:
    """Linux-examples-v1 (the goad-era answer): a provisioned host whose every attachment is router-attached gets the build-only NAT uplink; content-free guests and the router do not; the runtime spec never carries it."""
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        ProvisioningStep,
        RangeMeta,
        RangeSpec,
        Router,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="routedbuild", description="routed build egress"),
        networks=[
            Network(name="a", cidr="192.168.20.0/24", mode="routed"),
            Network(name="b", cidr="192.168.30.0/24", mode="routed"),
        ],
        routers=[
            Router(
                name="r",
                interfaces=[
                    Interface(network="a", ip="192.168.20.1"),
                    Interface(network="b", ip="192.168.30.1"),
                ],
            )
        ],
        hosts=[
            Host(
                name="server",
                os=Os(type="linux"),
                image="ubuntu-focal",
                interfaces=[Interface(network="a", ip="192.168.20.5")],
                provisioning=[ProvisioningStep(recipe="kypo.server")],
            ),
            Host(
                name="bare",
                os=Os(type="linux"),
                image="ubuntu-focal",
                interfaces=[Interface(network="b", ip="192.168.30.7")],
            ),
        ],
        attacker=Attacker(host="bare", entry="assumed-breach"),
    )
    build = egress_build_spec(spec, nameserver_ip="1.1.1.1")
    uplink = next(n for n in build.networks if n.name == "build-uplink")
    # a content-free foothold keeps its containment in the build variant
    assert build.attacker.egress == "none"
    assert uplink.mode == "nat"
    assert uplink.egress is not None and uplink.egress.allow == ["0.0.0.0/0"]
    assert not any(
        str(uplink.cidr) == str(n.cidr)
        for n in build.networks
        if n.name != "build-uplink"
    )
    by_name = {host.name: host for host in build.hosts}
    assert [i.network for i in by_name["server"].interfaces] == ["a", "build-uplink"]
    assert [i.network for i in by_name["bare"].interfaces] == ["b"]
    assert [i.network for i in build.routers[0].interfaces] == ["a", "b"]
    # the routed segments themselves are untouched, and the runtime spec too
    assert all(n.mode == "routed" for n in build.networks if n.name in ("a", "b"))
    assert not any(n.name == "build-uplink" for n in spec.networks)


def test_egress_build_spec_lifts_containment_for_provisioned_footholds() -> None:
    """A foothold host carrying recipes needs build egress, which the attacker's runtime containment (egress: none) would drop at the hypervisor; the build variant lifts it, the runtime spec keeps it."""
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        ProvisioningStep,
        RangeMeta,
        RangeSpec,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="foothold-build", description="provisioned foothold"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="client",
                os=Os(type="linux"),
                image="ubuntu-focal",
                interfaces=[Interface(network="lab")],
                provisioning=[ProvisioningStep(recipe="kypo.client")],
            )
        ],
        attacker=Attacker(host="client", entry="assumed-breach"),
    )
    build = egress_build_spec(spec, nameserver_ip="1.1.1.1")
    assert build.attacker.egress == "open"
    assert spec.attacker.egress == "none"


def test_egress_build_spec_uplink_dodges_name_and_cidr_collisions() -> None:
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        ProvisioningStep,
        RangeMeta,
        RangeSpec,
        Router,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="collide", description="uplink collisions"),
        networks=[
            Network(name="build-uplink", cidr="10.254.169.0/24", mode="routed"),
            Network(name="b", cidr="192.168.30.0/24", mode="routed"),
        ],
        routers=[
            Router(
                name="r",
                interfaces=[Interface(network="build-uplink"), Interface(network="b")],
            )
        ],
        hosts=[
            Host(
                name="server",
                os=Os(type="linux"),
                image="ubuntu-focal",
                interfaces=[Interface(network="build-uplink")],
                provisioning=[ProvisioningStep(recipe="kypo.server")],
            )
        ],
        attacker=Attacker(host="server", entry="assumed-breach"),
    )
    build = egress_build_spec(spec, nameserver_ip="1.1.1.1")
    uplink = next(n for n in build.networks if n.name == "ir-build-uplink")
    assert str(uplink.cidr) != "10.254.169.0/24"


def test_scrub_never_strips_a_declared_resolver(tmp_path: Path, cache: Path) -> None:
    """The capture scrub strips the build nameserver from Windows adapters; when the build nameserver equals a resolver the RUNTIME spec declares, the strip must not run — the address is legitimate baked state (slice-2 review)."""
    from inspect_ranges.types import DnsConfig

    spec, range_dir = build_spec_fixture(tmp_path)
    fakes = Fakes(["web", "db", "attacker"])
    build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache, build_nameserver="192.0.2.53"),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
    )
    assert fakes.capture_nameservers == ["192.0.2.53", "192.0.2.53"]

    declared = spec.model_copy(deep=True)
    declared.meta.name = "buildme-declared"
    declared.networks[0].dns = DnsConfig(nameservers=["192.0.2.53"])
    declared_fakes = Fakes(["web", "db", "attacker"])
    build_range(
        declared,
        range_dir,
        options_for(tmp_path, cache, build_nameserver="192.0.2.53"),
        up_fn=declared_fakes.up_fn,
        down_fn=declared_fakes.down_fn,
        recipe_fn=declared_fakes.recipe_fn,
        ensure_uplink=declared_fakes.ensure_uplink,
        capture_fn=declared_fakes.capture_fn,
    )
    assert declared_fakes.capture_nameservers == [None, None]


def windows_build_fixture(tmp_path: Path, cache: Path) -> tuple[RangeSpec, Path]:
    """A converged-shape fixture: one Windows content host and one Linux content host (any Windows content in a multi-guest set makes the build converged)."""
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    range_dir = tmp_path / "winrange"
    write_recipe(range_dir, name="acme.web", inputs={"marker": {}})
    write_recipe(range_dir, name="acme.db")
    spec = RangeSpec(
        meta=RangeMeta(name="winbuild", description="converged fixture"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc",
                os=Os(type="windows"),
                image="windows-2022",
                interfaces=[Interface(network="lab", ip="10.0.0.10")],
                provisioning=[
                    ProvisioningStep(recipe="acme.web", vars={"marker": "x"})
                ],
            ),
            Host(
                name="db",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab", ip="10.0.0.11")],
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


def test_converged_build_quiesces_all_before_any_capture(
    tmp_path: Path, cache: Path
) -> None:
    """Windows-ad-v1 slice 3: a multi-guest build with Windows content quiesces EVERY content host at one point before any disk is copied (cross-guest domain state captures from a single moment), and each capture is told its guest is already quiesced."""
    spec, range_dir = windows_build_fixture(tmp_path, cache)
    fakes = Fakes(["dc", "db", "attacker"])
    build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=fakes.up_fn,
        down_fn=fakes.down_fn,
        recipe_fn=fakes.recipe_fn,
        ensure_uplink=fakes.ensure_uplink,
        capture_fn=fakes.capture_fn,
        quiesce_fn=fakes.quiesce_fn,
    )
    assert fakes.quiesces == ["dc", "db"]  # the quiesce_fn fake asserts ordering
    assert fakes.capture_quiesced == [True, True]


def test_converged_build_reuses_all_or_nothing(tmp_path: Path, cache: Path) -> None:
    """A converged range rebuilds whole: one guest's recipe edit invalidates every guest's reuse (a partial rebuild would compose disks from different convergence points), while an unchanged range stays a cached no-op."""
    spec, range_dir = windows_build_fixture(tmp_path, cache)
    first = Fakes(["dc", "db", "attacker"])
    build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=first.up_fn,
        down_fn=first.down_fn,
        recipe_fn=first.recipe_fn,
        ensure_uplink=first.ensure_uplink,
        capture_fn=first.capture_fn,
        quiesce_fn=first.quiesce_fn,
    )
    assert len(first.captures) == 2
    # the unchanged range is a cached no-op (no boot, no captures)
    cached = Fakes(["dc", "db", "attacker"])
    result = build_range(
        spec,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=cached.up_fn,
        down_fn=cached.down_fn,
        recipe_fn=cached.recipe_fn,
        ensure_uplink=cached.ensure_uplink,
        capture_fn=cached.capture_fn,
        quiesce_fn=cached.quiesce_fn,
    )
    assert result.cached and cached.captures == []
    # one guest's edit rebuilds BOTH guests (linux per-guest reuse would keep dc)
    edited = spec.model_copy(deep=True)
    edited.hosts[1].provisioning = [
        ProvisioningStep(recipe="acme.db", vars={}),
        ProvisioningStep(recipe="acme.web", vars={"marker": "changed"}),
    ]
    second = Fakes(["dc", "db", "attacker"])
    build_range(
        edited,
        range_dir,
        options_for(tmp_path, cache),
        up_fn=second.up_fn,
        down_fn=second.down_fn,
        recipe_fn=second.recipe_fn,
        ensure_uplink=second.ensure_uplink,
        capture_fn=second.capture_fn,
        quiesce_fn=second.quiesce_fn,
    )
    assert {guest for guest, _, _ in second.captures} == {"dc", "db"}
    assert {name for name, _, _ in second.recipe_calls} >= {"acme.web", "acme.db"}


def test_stale_bx_state_rotates_aside_before_the_proof_boot(tmp_path: Path) -> None:
    """A failed build's leftover bx evidence must never collide with the next proof boot's write-once store: the stale project dir rotates aside (kept for autopsy), and a fresh boot starts empty."""
    from inspect_ranges._build.orchestrate import rotate_stale_bx_state
    from inspect_ranges._runtime.ownership import project_dir

    state_dir = tmp_path / "state"
    stale = project_dir(state_dir, "ir-acme-bx")
    (stale / "evidence" / "chunks").mkdir(parents=True)
    (stale / "evidence" / "chunks" / "000000.bin").write_bytes(b"old")

    rotate_stale_bx_state(state_dir, "ir-acme-bx")

    assert not stale.exists()
    rotated = [
        p for p in stale.parent.iterdir() if p.name.startswith("ir-acme-bx-stale-")
    ]
    assert len(rotated) == 1
    assert (rotated[0] / "evidence" / "chunks" / "000000.bin").read_bytes() == b"old"
    # a clean state dir is a no-op
    rotate_stale_bx_state(state_dir, "ir-acme-bx")
    assert len(list(stale.parent.iterdir())) == 1
