"""Loading and validation for `range.yaml` definitions.

The spec models live in `inspect_ranges.types` (re-exported here for compatibility). Load a file with `load_range`, or validate pre-parsed data with `RangeSpec.model_validate`. For complete diagnostics (every error at once, with source positions and hints) use `validate_range`, which returns a `ValidationReport` instead of raising. Typed specs handed across a consumer boundary (the sandbox, the compiler) are re-checked with `revalidate_range`, since models stay mutable after construction. The published JSON Schema is `range_json_schema` (also `inspect-ranges schema` on the CLI).
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ._diagnostics import (
    Issue,
    ValidationReport,
    issues_from_validation_error,
    issues_from_yaml_error,
    locate,
    parse_marked,
)
from .types import (
    AclRule,
    Attacker,
    DnsConfig,
    DnsRecord,
    EgressPolicy,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Resources,
    Route,
    Router,
    semantic_issues,
)

__all__ = [
    "AclRule",
    "Attacker",
    "DnsConfig",
    "DnsRecord",
    "EgressPolicy",
    "Host",
    "Interface",
    "Issue",
    "Network",
    "Os",
    "RangeMeta",
    "RangeSpec",
    "Resources",
    "Route",
    "Router",
    "ValidationReport",
    "load_range",
    "range_json_schema",
    "revalidate_range",
    "semantic_issues",
    "validate_range",
]


def validate_range(path: Path) -> ValidationReport:
    """Validate a `range.yaml` file, reporting every detectable issue at once.

    Unlike `load_range`, this never raises on invalid content: YAML syntax errors, structural schema violations, and semantic cross-reference problems all become `Issue` entries with stable codes, source positions, and hints where available. Field-level structural errors suppress the cross-reference pass (reflected in `ValidationReport.semantic_checked`).

    Args:
        path: Path to the YAML file.

    Returns:
        The report; `ValidationReport.spec` carries the validated spec when the file is valid.
    """
    try:
        data, node = parse_marked(path.read_text())
    except yaml.YAMLError as error:
        return ValidationReport(file=str(path), issues=issues_from_yaml_error(error))
    if not isinstance(data, dict):
        return ValidationReport(
            file=str(path),
            issues=[
                Issue(
                    code="not-a-mapping",
                    message="expected a YAML mapping at the top level",
                )
            ],
        )
    try:
        spec = RangeSpec.model_validate(data)
    except ValidationError as error:
        issues, semantic_checked = issues_from_validation_error(error, RangeSpec, node)
        return ValidationReport(
            file=str(path), issues=issues, semantic_checked=semantic_checked
        )
    warnings: list[Issue] = []
    for issue in semantic_issues(spec):
        if issue.severity != "warning":
            continue
        position = locate(node, issue.path)
        warnings.append(
            issue.model_copy(
                update={
                    "line": position[0] if position else None,
                    "col": position[1] if position else None,
                }
            )
        )
    return ValidationReport(file=str(path), issues=warnings, spec=spec)


def load_range(path: Path) -> RangeSpec:
    """Load and validate a `range.yaml` file.

    Args:
        path: Path to the YAML file.

    Returns:
        The validated spec.

    Raises:
        ValueError: The file is not a YAML mapping.
        yaml.YAMLError: The file is not parseable YAML.
        pydantic.ValidationError: The content does not satisfy schema v0.1.
    """
    data: Any = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return RangeSpec.model_validate(data)


def revalidate_range(spec: RangeSpec) -> RangeSpec:
    """Re-run full validation on a possibly mutated spec, returning a validated copy.

    Spec models are mutable for flexible programmatic construction, so validity at construction is a point-in-time property. Consumer boundaries (the sandbox provider, the compiler) call this at handoff: the spec round-trips through `model_validate`, which catches semantic drift and type-unsafe mutations alike.

    Args:
        spec: The spec to re-check (typically one received as sandbox configuration).

    Returns:
        A freshly validated copy; the input is not modified.

    Raises:
        pydantic.ValidationError: The spec no longer satisfies the schema.
    """
    return RangeSpec.model_validate(spec.model_dump(by_alias=True))


def range_json_schema() -> dict[str, Any]:
    """Return the JSON Schema for `range.yaml` v0.1 (aliased field names, e.g. `from`)."""
    return RangeSpec.model_json_schema(by_alias=True)
