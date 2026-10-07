import re
from pathlib import Path
from typing import Any, cast

import inspect_ranges.types as _types
import pytest
from inspect_ranges import validate_range
from inspect_ranges._compiler import resolve_plan
from inspect_ranges.schema import revalidate_range
from inspect_ranges.types import IssueError, RangeSpec

DOCS = Path(__file__).parent.parent / "docs"
PAGES = ("ranges.qmd", "guests.qmd", "networks.qmd")
MIN_BLOCKS = {"ranges.qmd": 3, "guests.qmd": 5, "networks.qmd": 10}

# the Quarto visual editor writes "``` yaml", hand-written pages "```yaml"
_YAML_BLOCK = re.compile(r"^``` ?yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)
_PYTHON_BLOCK = re.compile(r"^``` ?python\n(.*?)^```", re.MULTILINE | re.DOTALL)

# docs Python tabs show the import once per page; the rest assume the models
_NAMESPACE: dict[str, Any] = {name: getattr(_types, name) for name in _types.__all__}


def _blocks(page: str, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """Every fenced block of a kind on a docs page, labeled by its first line."""
    return [
        (match.splitlines()[0].strip(), match)
        for match in pattern.findall((DOCS / page).read_text())
    ]


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
    assert len(_blocks(page, _YAML_BLOCK)) >= MIN_BLOCKS[page], (
        f"{page} lost its examples"
    )


@pytest.mark.parametrize(
    ("first_line", "text"),
    [block for page in PAGES for block in _blocks(page, _YAML_BLOCK)],
    ids=[
        f"{page.removesuffix('.qmd')}-{first.lstrip('# ').split(':')[0] or index}"
        for page in PAGES
        for index, (first, _) in enumerate(_blocks(page, _YAML_BLOCK))
    ],
)
def test_docs_examples_validate(first_line: str, text: str, tmp_path: Path) -> None:
    """Every complete example in the docs validates; marked blocks fail exactly as documented."""
    if first_line.startswith("# fragment"):
        pytest.skip("fragment, not a complete definition")
    path = tmp_path / "range.yaml"
    path.write_text(text)
    report = validate_range(path)
    if first_line.startswith("# invalid-example"):
        assert not report.valid, "invalid-example block unexpectedly validates"
        return
    assert report.valid, [issue.message for issue in report.issues]
    if first_line.startswith("# plan-invalid"):
        assert report.spec is not None
        with pytest.raises(IssueError):
            resolve_plan(report.spec)


@pytest.mark.parametrize(
    ("first_line", "text"),
    [block for page in PAGES for block in _blocks(page, _PYTHON_BLOCK)],
    ids=[
        f"{page.removesuffix('.qmd')}-py{index}"
        for page in PAGES
        for index, _ in enumerate(_blocks(page, _PYTHON_BLOCK))
    ],
)
def test_docs_python_examples_construct(first_line: str, text: str) -> None:
    """Every Python tab constructs a valid spec; marked blocks gate exactly as documented."""
    if first_line.startswith("# fragment"):
        pytest.skip("fragment, not a complete definition")
    spec = _construct(text)
    revalidate_range(spec)
    if first_line.startswith("# plan-invalid"):
        with pytest.raises(IssueError):
            resolve_plan(spec)


def test_embedded_real_example_matches_design_file() -> None:
    """The vulhub-zabbix block on ranges.qmd is the design example verbatim (marker line aside), so the two cannot drift."""
    design = (
        Path(__file__).parent.parent
        / "design/inspect-ranges/ranges/vulhub-zabbix/range.yaml"
    ).read_text()
    block = next(
        text
        for first, text in _blocks("ranges.qmd", _YAML_BLOCK)
        if first.startswith("# plan-invalid") and "vulhub-zabbix" in text
    )
    embedded = block.split("\n", 1)[1]
    assert embedded == design, "ranges.qmd vulhub-zabbix drifted from the design file"


@pytest.mark.parametrize("page", PAGES)
def test_yaml_and_python_tabs_agree(page: str, tmp_path: Path) -> None:
    """The two tabs of every example define the same range, so they cannot drift apart."""
    yaml_specs: dict[str, RangeSpec] = {}
    for first_line, text in _blocks(page, _YAML_BLOCK):
        if first_line.startswith(("# fragment", "# invalid-example")):
            continue
        path = tmp_path / "range.yaml"
        path.write_text(text)
        report = validate_range(path)
        assert report.spec is not None
        yaml_specs[report.spec.meta.name] = report.spec
    python_specs: dict[str, RangeSpec] = {}
    for first_line, text in _blocks(page, _PYTHON_BLOCK):
        if first_line.startswith("# fragment"):
            continue
        spec = _construct(text)
        python_specs[spec.meta.name] = spec
    assert set(yaml_specs) == set(python_specs), "an example is missing its peer tab"
    for name, yaml_spec in yaml_specs.items():
        assert _comparable(python_specs[name]) == _comparable(yaml_spec), (
            f"the YAML and Python tabs of example {name!r} differ"
        )
