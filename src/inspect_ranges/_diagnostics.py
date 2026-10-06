"""Diagnostics for `range.yaml` validation: issues, positions, and rendering.

This module is the error vocabulary for the whole compiler pipeline: schema validation, the semantic cross-reference pass, and (later) planning and rendering all report problems as `Issue` values collected into a `ValidationReport`. Issues carry a stable kebab-case `code`, a path into the spec, a source position when the YAML parse can supply one, and an actionable hint where we can compute one (did-you-mean suggestions, deferred-section pointers).

The primary consumers are models authoring specs, so the design optimizes for complete single-pass reporting (every detectable error at once) and machine-readable output (`ValidationReport.to_json`), with human-readable rendering (`ValidationReport.render`) built on the same data.
"""

import difflib
from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import ErrorDetails

Severity = Literal["error", "warning"]

PathElement = str | int
"""One step in a spec path: a mapping key or a sequence index."""

SCOPE_DOC = "design/inspect-ranges/schema-v0.1-scope.md"

_DEFERRED_HINT = f"park it in deferred.yaml (see {SCOPE_DOC})"

_DEFERRED_SECTIONS: dict[str, dict[str, str]] = {
    "": {
        "attack_path": _DEFERRED_HINT,
        "variables": _DEFERRED_HINT,
        "goals": "goals belong with the evaluation (challenges.yaml), not the range",
        "defense": _DEFERRED_HINT,
        "vulnerabilities": _DEFERRED_HINT,
        "misconfigurations": _DEFERRED_HINT,
        "management": _DEFERRED_HINT,
        "lifecycle": _DEFERRED_HINT,
        "replication": _DEFERRED_HINT,
        "expansion": _DEFERRED_HINT,
    },
    "hosts": {
        "services": _DEFERRED_HINT,
        "vulnerabilities": _DEFERRED_HINT,
        "count": _DEFERRED_HINT,
        "ip_start": _DEFERRED_HINT,
    },
    "networks": {
        "acl": "inter-segment policy lives on routers in v0.1",
        "ingress": _DEFERRED_HINT,
        "user_accessible": _DEFERRED_HINT,
    },
}


class Issue(BaseModel):
    """One problem found in a range definition."""

    code: str
    """Stable kebab-case identifier, e.g. `undeclared-network`."""

    severity: Severity = "error"
    """Whether the issue blocks use of the spec."""

    path: tuple[PathElement, ...] = ()
    """Location within the spec, e.g. `("networks", 0, "cidr")`."""

    line: int | None = None
    """1-based source line, when the YAML parse can supply it."""

    col: int | None = None
    """1-based source column, when the YAML parse can supply it."""

    message: str
    """What is wrong."""

    hint: str | None = None
    """Actionable suggestion, e.g. a did-you-mean or where deferred content goes."""

    @property
    def path_str(self) -> str:
        """The path rendered as `networks[0].cidr`, or `(root)` for the document root."""
        return format_path(self.path)


class IssueError(ValueError):
    """Carrier for collected issues raised inside pydantic validators.

    Subclasses `ValueError` so pydantic wraps it as an ordinary validation error; `issues_from_validation_error` recovers the original list from the error context, so both the raise path (`RangeSpec.model_validate`) and the report path (`validate_range`) share one implementation of every check.
    """

    def __init__(self, issues: list[Issue]) -> None:
        self.issues = issues
        super().__init__("; ".join(issue.message for issue in issues))


class ValidationReport(BaseModel):
    """Every issue found in one `range.yaml`, with rendering helpers."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file: str
    """The validated file path, as given."""

    issues: list[Issue] = []
    """All issues found, in source order where positions are known."""

    semantic_checked: bool = True
    """False when structural errors prevented the cross-reference checks from running."""

    spec: Any | None = Field(default=None, exclude=True)
    """The validated `RangeSpec` when the file is valid, for callers that need it."""

    @property
    def valid(self) -> bool:
        """True when no error-severity issues were found."""
        return not any(issue.severity == "error" for issue in self.issues)

    def render(self) -> str:
        """Render the report as aligned, human-readable text."""
        if self.valid:
            return f"✓ {self.file}"
        issues = sorted(
            self.issues,
            key=lambda i: (i.line is None, i.line or 0, i.col or 0, i.path_str),
        )
        errors = sum(1 for issue in issues if issue.severity == "error")
        header = f"✗ {self.file}  {errors} error{'s' if errors != 1 else ''}"
        loc_width = max(len(_loc_str(i)) for i in issues)
        path_width = min(max(len(i.path_str) for i in issues), 40)
        lines = [header]
        for issue in issues:
            message = issue.message
            if issue.hint:
                message = f"{message} ({issue.hint})"
            lines.append(
                f"  {_loc_str(issue):>{loc_width}}  {issue.path_str:<{path_width}}  {message}"
            )
        if not self.semantic_checked:
            lines.append(
                "  (cross-reference checks run once the errors above are fixed)"
            )
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        """Return the report as JSON-serializable data with stable field names."""
        return {
            "path": self.file,
            "valid": self.valid,
            "semantic_checked": self.semantic_checked,
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity,
                    "path": issue.path_str,
                    "loc": list(issue.path),
                    "line": issue.line,
                    "col": issue.col,
                    "message": issue.message,
                    "hint": issue.hint,
                }
                for issue in self.issues
            ],
        }


def format_path(path: tuple[PathElement, ...]) -> str:
    """Render a spec path as `networks[0].cidr` (`(root)` when empty)."""
    if not path:
        return "(root)"
    out = ""
    for element in path:
        if isinstance(element, int):
            out += f"[{element}]"
        else:
            out += f".{element}" if out else str(element)
    return out


def _loc_str(issue: Issue) -> str:
    if issue.line is None:
        return "-"
    return f"{issue.line}:{issue.col}" if issue.col is not None else str(issue.line)


def did_you_mean(name: str, candidates: list[str]) -> str | None:
    """Return a `did you mean 'x'?` hint for the closest candidate, if any is close."""
    matches = difflib.get_close_matches(name, candidates, n=1, cutoff=0.6)
    return f"did you mean '{matches[0]}'?" if matches else None


# --- marked YAML parsing ------------------------------------------------------


def parse_marked(text: str) -> tuple[Any, yaml.Node | None]:
    """Parse YAML once, returning both the constructed data and the node tree with source marks.

    Raises:
        yaml.YAMLError: The text is not parseable YAML.
    """
    loader = yaml.SafeLoader(text)
    try:
        node = loader.get_single_node()
        data: Any = loader.construct_document(node) if node is not None else None  # pyright: ignore[reportUnknownMemberType]
    finally:
        loader.dispose()
    return data, node


def locate(
    node: yaml.Node | None, path: tuple[PathElement, ...], key: bool = False
) -> tuple[int, int] | None:
    """Resolve a spec path to a 1-based (line, col) in the parsed node tree.

    Falls back to the position of the deepest node on the path that exists (so a missing field reports its parent), and to the final key's own position when `key` is true (for unknown-key issues, where the key is the problem).
    """
    if node is None:
        return None
    current = node
    for depth, element in enumerate(path):
        last = depth == len(path) - 1
        if isinstance(current, yaml.MappingNode) and isinstance(element, str):
            for key_node, value_node in current.value:
                if key_node.value == element:
                    if last and key:
                        return (
                            key_node.start_mark.line + 1,
                            key_node.start_mark.column + 1,
                        )
                    current = value_node
                    break
            else:
                break
        elif isinstance(current, yaml.SequenceNode) and isinstance(element, int):
            if element >= len(current.value):
                break
            current = current.value[element]
        else:
            break
    return (current.start_mark.line + 1, current.start_mark.column + 1)


# --- pydantic error translation -----------------------------------------------

_CODES_BY_TYPE = {
    "extra_forbidden": "unknown-key",
    "missing": "missing-field",
    "ip_v4_network": "invalid-cidr",
    "ip_v4_address": "invalid-ip",
    "literal_error": "invalid-value",
    "enum": "invalid-value",
}

_IP_ERROR_CODES = {
    "ip_v4_network": "invalid-cidr",
    "ip_v6_network": "invalid-cidr",
    "ip_v4_address": "invalid-ip",
    "ip_v6_address": "invalid-ip",
}


def issues_from_yaml_error(error: yaml.YAMLError) -> list[Issue]:
    """Translate a YAML parse failure into a single `yaml-syntax` issue."""
    line: int | None = None
    col: int | None = None
    message = str(error)
    mark = getattr(error, "problem_mark", None)
    if mark is not None:
        line, col = mark.line + 1, mark.column + 1
        problem = getattr(error, "problem", None)
        if problem:
            message = f"invalid YAML: {problem}"
    return [Issue(code="yaml-syntax", path=(), line=line, col=col, message=message)]


def issues_from_validation_error(
    error: ValidationError, root_model: type[BaseModel], node: yaml.Node | None
) -> tuple[list[Issue], bool]:
    """Translate a pydantic `ValidationError` into issues with positions.

    Returns:
        The issues, and whether the semantic cross-reference pass ran (field-level errors suppress pydantic after-validators, so semantic issues are only complete when this is true).
    """
    issues: list[Issue] = []
    semantic_checked = True
    details, ip_errors = _collapse_ip_union_errors(error.errors(include_url=False))
    for loc, code, value in ip_errors:
        semantic_checked = False
        kind = "network" if code == "invalid-cidr" else "address"
        position = locate(node, loc)
        issues.append(
            Issue(
                code=code,
                path=loc,
                line=position[0] if position else None,
                col=position[1] if position else None,
                message=f"{value!r} is not a valid IPv4 or IPv6 {kind}",
            )
        )
    cleaned = [(detail, _clean_loc(detail["loc"])) for detail in details]
    carried_locs = {
        loc for detail, loc in cleaned if _carried_issues(detail) is not None
    }
    for detail, loc in cleaned:
        carried = _carried_issues(detail)
        if (
            carried is None
            and detail["type"] == "literal_error"
            and loc in carried_locs
        ):
            # union sibling noise: the input matched the model member of a
            # Literal | Model union, whose carried issues already cover it
            continue
        if carried is not None:
            if loc:
                # carried from a nested model's validator, so the root
                # cross-reference pass never ran
                semantic_checked = False
            for issue in carried:
                full_path = loc + issue.path
                position = locate(node, full_path)
                issues.append(
                    issue.model_copy(
                        update={
                            "path": full_path,
                            "line": position[0] if position else None,
                            "col": position[1] if position else None,
                        }
                    )
                )
            continue
        semantic_checked = False
        issues.append(_structural_issue(detail, loc, root_model, node))
    return issues, semantic_checked


def _collapse_ip_union_errors(
    details: list[ErrorDetails],
) -> tuple[list[ErrorDetails], list[tuple[tuple[PathElement, ...], str, Any]]]:
    """Fold the per-family errors a dual-stack address union emits into one entry per field.

    A bad value against `IPv4Network | IPv6Network` produces two pydantic errors whose locs end in machine-generated union-member tags; this strips the tags and keeps one `(loc, code, input)` entry per field, leaving every other error untouched.
    """
    rest: list[ErrorDetails] = []
    collapsed: dict[tuple[PathElement, ...], tuple[str, Any]] = {}
    for detail in details:
        code = _IP_ERROR_CODES.get(detail["type"])
        if code is None:
            rest.append(detail)
            continue
        collapsed.setdefault(_clean_loc(detail["loc"]), (code, detail.get("input")))
    return rest, [(loc, code, value) for loc, (code, value) in collapsed.items()]


def _clean_loc(raw: tuple[int | str, ...]) -> tuple[PathElement, ...]:
    """Strip pydantic's machine-generated union-member tags out of an error loc."""
    return tuple(part for part in raw if not (isinstance(part, str) and "[" in part))


def _carried_issues(detail: ErrorDetails) -> list[Issue] | None:
    """Recover the issue list from an `IssueError` raised inside a validator."""
    if detail["type"] != "value_error":
        return None
    carried = (detail.get("ctx") or {}).get("error")
    return carried.issues if isinstance(carried, IssueError) else None


def _structural_issue(
    detail: ErrorDetails,
    loc: tuple[PathElement, ...],
    root_model: type[BaseModel],
    node: yaml.Node | None,
) -> Issue:
    error_type = detail["type"]
    value = detail.get("input")
    code = _CODES_BY_TYPE.get(error_type, "invalid-type")
    message = detail["msg"]
    hint: str | None = None
    key = False

    if error_type == "extra_forbidden":
        key = True
        key_name = str(loc[-1])
        scope = _deferred_scope(loc)
        deferred_hint = _DEFERRED_SECTIONS.get(scope, {}).get(key_name)
        if deferred_hint is not None:
            code = "deferred-section"
            message = f"'{key_name}' is not part of schema v0.1 (deferred)"
            hint = deferred_hint
        else:
            message = f"unknown key '{key_name}'"
            hint = did_you_mean(key_name, _candidate_keys(root_model, loc[:-1]))
    elif error_type == "missing":
        message = "missing required field"
    elif error_type == "ip_v4_network":
        code, message = "invalid-cidr", f"{value!r} is not a valid IPv4 network"
    elif error_type == "ip_v4_address":
        message = f"{value!r} is not a valid IPv4 address"
    elif error_type == "literal_error":
        if loc[-2:] == ("range", "schema_version") or loc == ("schema_version",):
            code = "invalid-schema-version"
        expected = (detail.get("ctx") or {}).get("expected", "")
        message = f"{value!r} is not one of {expected}" if expected else detail["msg"]

    position = locate(node, loc, key=key)
    return Issue(
        code=code,
        path=loc,
        line=position[0] if position else None,
        col=position[1] if position else None,
        message=message,
        hint=hint,
    )


def _deferred_scope(loc: tuple[PathElement, ...]) -> str:
    if len(loc) == 1:
        return ""
    if len(loc) == 3 and loc[0] in ("hosts", "networks") and isinstance(loc[1], int):
        return str(loc[0])
    return "(none)"


def _candidate_keys(
    root_model: type[BaseModel], path: tuple[PathElement, ...]
) -> list[str]:
    """Field names (by alias) of the model a path points at, for did-you-mean on unknown keys."""
    model = _model_at(root_model, path)
    if model is None:
        return []
    return [field.alias or name for name, field in model.model_fields.items()]


def _model_at(
    root_model: type[BaseModel], path: tuple[PathElement, ...]
) -> type[BaseModel] | None:
    current: Any = root_model
    for element in path:
        if isinstance(element, int):
            continue  # indices do not change the model type; lists are unwrapped below
        if not (isinstance(current, type) and issubclass(current, BaseModel)):
            return None
        field = None
        for name, candidate in current.model_fields.items():
            if element in (name, candidate.alias):
                field = candidate
                break
        if field is None:
            return None
        current = _unwrap_annotation(field.annotation)
    if isinstance(current, type) and issubclass(current, BaseModel):
        return current
    return None


def _unwrap_annotation(annotation: Any) -> Any:
    """Strip `list[...]` and `X | None` wrappers down to the inner type."""
    origin = get_origin(annotation)
    if origin is list:
        return _unwrap_annotation(get_args(annotation)[0])
    if origin in (Union, UnionType):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return _unwrap_annotation(args[0])
    return annotation
