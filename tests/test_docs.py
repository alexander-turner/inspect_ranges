import re
from pathlib import Path

import pytest
from inspect_ranges import validate_range

NETWORKS_QMD = Path(__file__).parent.parent / "docs" / "networks.qmd"

_YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _blocks() -> list[tuple[str, str]]:
    """Every fenced yaml block on the networks page, labeled by its first line."""
    return [
        (match.splitlines()[0].strip(), match)
        for match in _YAML_BLOCK.findall(NETWORKS_QMD.read_text())
    ]


def test_page_has_examples() -> None:
    blocks = _blocks()
    assert len(blocks) >= 10, "the networks page lost its examples"
    assert sum("# invalid-example" in first for first, _ in blocks) >= 2


@pytest.mark.parametrize(
    ("first_line", "text"),
    _blocks(),
    ids=[first.lstrip("# ") or f"block-{i}" for i, (first, _) in enumerate(_blocks())],
)
def test_networks_page_examples_validate(
    first_line: str, text: str, tmp_path: Path
) -> None:
    """Every complete example on the docs page validates (or is marked invalid and fails)."""
    if first_line.startswith("# fragment"):
        pytest.skip("fragment, not a complete definition")
    path = tmp_path / "range.yaml"
    path.write_text(text)
    report = validate_range(path)
    if first_line.startswith("# invalid-example"):
        assert not report.valid, "invalid-example block unexpectedly validates"
    else:
        assert report.valid, [issue.message for issue in report.issues]
