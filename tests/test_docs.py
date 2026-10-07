import re
from pathlib import Path

import pytest
from inspect_ranges import validate_range
from inspect_ranges._compiler import resolve_plan
from inspect_ranges.types import IssueError

DOCS = Path(__file__).parent.parent / "docs"
PAGES = ("networks.qmd", "guests.qmd")
MIN_BLOCKS = {"networks.qmd": 10, "guests.qmd": 5}

_YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _blocks(page: str) -> list[tuple[str, str]]:
    """Every fenced yaml block on a docs page, labeled by its first line."""
    return [
        (match.splitlines()[0].strip(), match)
        for match in _YAML_BLOCK.findall((DOCS / page).read_text())
    ]


@pytest.mark.parametrize("page", PAGES)
def test_pages_have_examples(page: str) -> None:
    assert len(_blocks(page)) >= MIN_BLOCKS[page], f"{page} lost its examples"


@pytest.mark.parametrize(
    ("first_line", "text"),
    [block for page in PAGES for block in _blocks(page)],
    ids=[
        f"{page.removesuffix('.qmd')}-{first.lstrip('# ').split(':')[0] or index}"
        for page in PAGES
        for index, (first, _) in enumerate(_blocks(page))
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
