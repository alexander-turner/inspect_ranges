import re
from pathlib import Path
from typing import Any, cast

import inspect_ranges.types as _types
import pytest
import yaml
from inspect_ranges import validate_range
from inspect_ranges._compiler import resolve_plan
from inspect_ranges.schema import revalidate_range
from inspect_ranges.types import IssueError, RangeSpec

DOCS = Path(__file__).parent.parent / "docs"
PAGES = ("ranges.qmd", "guests.qmd", "networks.qmd", "provider.qmd")
MIN_BLOCKS = {"ranges.qmd": 3, "guests.qmd": 10, "networks.qmd": 9, "provider.qmd": 1}
# YAML/Python tab parity is a definition-language property; the provider page
# documents the eval surface and its Python blocks are usage fragments
DEFINITION_PAGES = ("ranges.qmd", "guests.qmd", "networks.qmd")

# fences: "```yaml" or "``` yaml" (plain), or "``` {.yaml .plan-invalid}"
# (attributed). Test semantics ride as fence classes so the published blocks
# carry no marker comments: .fragment, .invalid-example, .plan-invalid.
_FENCE_BLOCK = re.compile(
    r"^``` ?(?:(?P<lang>yaml|python)|\{(?P<attrs>[^}\n]*)\})[ \t]*\n(?P<body>.*?)^```",
    re.MULTILINE | re.DOTALL,
)


def _fence_blocks(page: str, lang: str) -> list[tuple[set[str], str]]:
    """Every fenced block of a language on a page, as (fence classes, body)."""
    blocks: list[tuple[set[str], str]] = []
    for match in _FENCE_BLOCK.finditer((DOCS / page).read_text()):
        attrs = match.group("attrs")
        classes = (
            {match.group("lang")}
            if attrs is None
            else {token.lstrip(".") for token in attrs.split()}
        )
        if lang in classes:
            blocks.append((classes, match.group("body")))
    return blocks


# docs Python tabs show the import once per page; the rest assume the models
_NAMESPACE: dict[str, Any] = {name: getattr(_types, name) for name in _types.__all__}


def _construct(text: str) -> RangeSpec:
    """Execute a docs Python example and return the spec it constructs."""
    namespace = dict(_NAMESPACE)
    exec(compile(text, "<docs-example>", "exec"), namespace)
    specs = [value for value in namespace.values() if isinstance(value, RangeSpec)]
    assert len(specs) == 1, "expected exactly one RangeSpec per Python example"
    return specs[0]


def _normalize(value: Any) -> Any:
    """Collapse whitespace in every string leaf (YAML folded scalars rewrap)."""
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, list):
        return [_normalize(item) for item in cast("list[Any]", value)]
    if isinstance(value, dict):
        return {
            key: _normalize(item) for key, item in cast("dict[Any, Any]", value).items()
        }
    return value


def _comparable(spec: RangeSpec) -> dict[str, Any]:
    """A dump for YAML/Python parity comparison."""
    dump: dict[str, Any] = _normalize(spec.model_dump(mode="json", by_alias=True))
    return dump


@pytest.mark.parametrize("page", PAGES)
def test_pages_have_examples(page: str) -> None:
    assert len(_fence_blocks(page, "yaml")) >= MIN_BLOCKS[page], (
        f"{page} lost its examples"
    )


@pytest.mark.parametrize(
    ("classes", "text"),
    [block for page in PAGES for block in _fence_blocks(page, "yaml")],
    ids=[
        f"{page.removesuffix('.qmd')}-yaml{index}"
        for page in PAGES
        for index, _ in enumerate(_fence_blocks(page, "yaml"))
    ],
)
def test_docs_examples_validate(classes: set[str], text: str, tmp_path: Path) -> None:
    """Every complete example in the docs validates; classed blocks fail exactly as documented, unmarked blocks plan cleanly."""
    if "fragment" in classes:
        pytest.skip("fragment, not a complete definition")
    path = tmp_path / "range.yaml"
    path.write_text(text)
    report = validate_range(path)
    if "invalid-example" in classes:
        assert not report.valid, "invalid-example block unexpectedly validates"
        return
    assert report.valid, [issue.message for issue in report.issues]
    assert report.spec is not None
    if "plan-invalid" in classes:
        with pytest.raises(IssueError):
            resolve_plan(report.spec)
    else:
        # the inverse direction: an unmarked complete block must plan cleanly
        # (planning with default options is image-cache independent)
        resolve_plan(report.spec)


@pytest.mark.parametrize(
    ("classes", "text"),
    [block for page in PAGES for block in _fence_blocks(page, "python")],
    ids=[
        f"{page.removesuffix('.qmd')}-py{index}"
        for page in PAGES
        for index, _ in enumerate(_fence_blocks(page, "python"))
    ],
)
def test_docs_python_examples_construct(classes: set[str], text: str) -> None:
    """Every Python tab constructs a valid spec; classed blocks gate exactly as documented, unmarked blocks plan cleanly."""
    if "fragment" in classes:
        pytest.skip("fragment, not a complete definition")
    spec = _construct(text)
    revalidate_range(spec)
    if "plan-invalid" in classes:
        with pytest.raises(IssueError):
            resolve_plan(spec)
    else:
        resolve_plan(spec)


@pytest.mark.parametrize("page", DEFINITION_PAGES)
def test_yaml_and_python_tabs_agree(page: str, tmp_path: Path) -> None:
    """The two tabs of every example define the same range, so they cannot drift apart."""
    yaml_specs: dict[str, RangeSpec] = {}
    for classes, text in _fence_blocks(page, "yaml"):
        if classes & {"fragment", "invalid-example"}:
            continue
        path = tmp_path / "range.yaml"
        path.write_text(text)
        report = validate_range(path)
        assert report.spec is not None
        yaml_specs[report.spec.meta.name] = report.spec
    python_specs: dict[str, RangeSpec] = {}
    for classes, text in _fence_blocks(page, "python"):
        if "fragment" in classes:
            continue
        spec = _construct(text)
        python_specs[spec.meta.name] = spec
    assert set(yaml_specs) == set(python_specs), "an example is missing its peer tab"
    for name, yaml_spec in yaml_specs.items():
        assert _comparable(python_specs[name]) == _comparable(yaml_spec), (
            f"the YAML and Python tabs of example {name!r} differ"
        )


def test_attack_image_tool_contract_matches_docs() -> None:
    """Every tool the attack recipe asserts at build is named on the Attack Box page (the contract's documented home), so the documented contract cannot drift from the recipe."""
    run_sh = (
        Path(__file__).parent.parent
        / "catalog/attack/recipes/catalog.attack-tools/run.sh"
    )
    tools: list[str] = []
    for match in re.finditer(r"for t in ([^;]+); do", run_sh.read_text()):
        tools.extend(t for t in match.group(1).split() if t != "\\")
    assert len(tools) >= 20, "the recipe's assertion loops did not parse"
    page = (DOCS / "attackbox.qmd").read_text()
    missing = [tool for tool in tools if f"`{tool}`" not in page]
    assert not missing, f"asserted attack tools absent from attackbox.qmd: {missing}"


EXAMPLES_SRC = Path(__file__).parent.parent / "src" / "inspect_ranges" / "examples"


def _yaml_subset(part: Any, whole: Any) -> bool:
    """Whether `part` is a recursive subset of `whole`: dict keys match recursively, every list item matches some item, scalars compare equal."""
    if isinstance(part, dict):
        whole_map = cast(dict[str, Any], whole) if isinstance(whole, dict) else {}
        part_map = cast(dict[str, Any], part)
        return isinstance(whole, dict) and all(
            key in whole_map and _yaml_subset(value, whole_map[key])
            for key, value in part_map.items()
        )
    if isinstance(part, list):
        part_list = cast(list[Any], part)
        whole_list = cast(list[Any], whole) if isinstance(whole, list) else []
        return isinstance(whole, list) and all(
            any(_yaml_subset(item, candidate) for candidate in whole_list)
            for item in part_list
        )
    return bool(part == whole)


@pytest.mark.parametrize(
    "page", sorted(path.name for path in (DOCS / "examples").glob("*.md"))
)
def test_example_readme_yaml_matches_source(page: str) -> None:
    """Every YAML excerpt on an example page is a subset of the example's real file, so excerpts cannot drift from the source they quote."""
    example_dir = EXAMPLES_SRC / f"_{page.removesuffix('.md')}"
    for _, text in _fence_blocks(f"examples/{page}", "yaml"):
        excerpt = yaml.safe_load(text)
        source = "challenges.yaml" if "challenges" in excerpt else "range.yaml"
        whole = yaml.safe_load((example_dir / source).read_text())
        assert _yaml_subset(excerpt, whole), (
            f"{page}: a YAML excerpt drifted from {source}"
        )
