"""Verify that a multi-agent eval's terminal casts cleave by the agent that opened them.

Takes a `.eval` path and asserts, per sample: (1) at least two distinct `ir_agent_span_id` across the sample's `asciinema:*` store casts; (2) at least two distinct `ir_agent`, none of them "supervisor"; (3) each cast's `ir_agent_span_id` resolves to a transcript `SpanBeginEvent` of type "agent" whose name equals `ir_agent` (the denormalization is faithful against real handoff spans); (4) each cast's `ir_tool_span_id` resolves to a `SpanBeginEvent` of type "tool", name "terminal", whose `parent_id` is the cast's `ir_agent_span_id`; (5) reports which casts were flushed at session close versus sample finalize, and that finalize-flushed casts still carry their opener's identity ("identity at open or never").

Usage: python evals/multi_agent/check_log.py logs/multi-agent/<log>.eval
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

from inspect_ai.event import SpanBeginEvent
from inspect_ai.log import read_eval_log

_NAMESPACE_PREFIX = re.compile(r"^t[0-9a-f]{8}-")


def _cast_headers(store: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The parsed asciicast header (first line, JSON) of every `asciinema:*` store entry."""
    headers: dict[str, dict[str, Any]] = {}
    for key, value in store.items():
        if key.startswith("asciinema:") and isinstance(value, str):
            headers[key] = json.loads(value.split("\n", 1)[0])
    return headers


def _closed_sessions(store: dict[str, Any]) -> dict[str, bool]:
    """Whether each cast carries a `close <session>` marker (flushed at close) or not (flushed at sample finalize)."""
    closed: dict[str, bool] = {}
    for key, value in store.items():
        if not (key.startswith("asciinema:") and isinstance(value, str)):
            continue
        lines = value.splitlines()
        header: dict[str, Any] = json.loads(lines[0])
        session = str(header.get("ir_session", ""))
        model_facing = _NAMESPACE_PREFIX.sub("", session)
        closed[key] = any(
            (event := json.loads(line))[1] == "m"
            and event[2] == f"close {model_facing}"
            for line in lines[1:]
            if line
        )
    return closed


class _Report:
    """Accumulates per-assertion PASS/FAIL lines and the overall verdict."""

    def __init__(self) -> None:
        self.failed = False

    def check(self, assertion: str, ok: bool, detail: str) -> None:
        status = "PASS" if ok else "FAIL"
        if not ok:
            self.failed = True
        print(f"  [{status}] {assertion}: {detail}")


def check_sample(sample_id: str, store: dict[str, Any], events: list[Any]) -> bool:
    """Run the five assertions for one sample; returns True when all pass."""
    print(f"sample {sample_id}:")
    report = _Report()
    headers = _cast_headers(store)
    spans: dict[str, SpanBeginEvent] = {
        event.id: event for event in events if isinstance(event, SpanBeginEvent)
    }

    for key, header in sorted(headers.items()):
        ir_fields = {k: v for k, v in header.items() if k.startswith("ir_")}
        print(f"  cast {key}: {json.dumps(ir_fields)}")

    # 1. the cleave: >=2 distinct agent spans across the sample's casts
    agent_span_ids = {
        str(h["ir_agent_span_id"]) for h in headers.values() if "ir_agent_span_id" in h
    }
    report.check(
        "1 cleave (>=2 distinct ir_agent_span_id)",
        len(agent_span_ids) >= 2,
        f"{len(agent_span_ids)} distinct across {len(headers)} casts: {sorted(agent_span_ids)}",
    )

    # 2. >=2 distinct agent names, none "supervisor"
    agent_names = {str(h["ir_agent"]) for h in headers.values() if "ir_agent" in h}
    report.check(
        "2 agents (>=2 distinct ir_agent, no supervisor)",
        len(agent_names) >= 2 and "supervisor" not in agent_names,
        f"names: {sorted(agent_names)}",
    )

    # 3. agent span faithful: SpanBeginEvent(id=ir_agent_span_id) is type "agent", name == ir_agent
    faithful = True
    details: list[str] = []
    for key, header in sorted(headers.items()):
        span = spans.get(str(header.get("ir_agent_span_id")))
        ok = (
            span is not None
            and span.type == "agent"
            and span.name == header.get("ir_agent")
        )
        faithful = faithful and ok
        found = f"type={span.type!r} name={span.name!r}" if span else "span not found"
        details.append(f"{key} -> {found}")
    report.check("3 agent spans faithful", faithful, "; ".join(details) or "no casts")

    # 4. tool span: type "tool", name "terminal", parent is the agent span
    tooled = True
    details = []
    for key, header in sorted(headers.items()):
        span = spans.get(str(header.get("ir_tool_span_id")))
        ok = (
            span is not None
            and span.type == "tool"
            and span.name == "terminal"
            and span.parent_id == header.get("ir_agent_span_id")
        )
        tooled = tooled and ok
        found = (
            f"type={span.type!r} name={span.name!r} parent={span.parent_id!r}"
            if span
            else "span not found"
        )
        details.append(f"{key} -> {found}")
    report.check("4 tool spans faithful", tooled, "; ".join(details) or "no casts")

    # 5. finalize vs close: a cast flushed at finalize must still carry its opener
    closed = _closed_sessions(store)
    finalize_keys = sorted(key for key, was_closed in closed.items() if not was_closed)
    close_keys = sorted(key for key, was_closed in closed.items() if was_closed)
    attributed = all(
        "ir_agent" in headers[key] and "ir_agent_span_id" in headers[key]
        for key in finalize_keys
    )
    detail = f"flushed at close: {close_keys or 'none'}; flushed at finalize: {finalize_keys or 'none'}"
    if finalize_keys:
        detail += (
            "; finalize-flushed casts carry their opener's identity"
            if attributed
            else "; finalize-flushed casts MISSING opener identity"
        )
    else:
        detail += "; (all sessions closed, so the identity-at-finalize claim was not exercised)"
    report.check("5 identity at open or never", attributed, detail)

    return not report.failed


def main() -> int:
    """Read the eval log, run the assertions per sample, and return the exit code."""
    if len(sys.argv) != 2:
        print("usage: python evals/multi_agent/check_log.py <path.eval>")
        return 2
    log = read_eval_log(str(Path(sys.argv[1])))
    if not log.samples:
        print("FAIL: log has no samples")
        return 1
    failed = False
    for sample in log.samples:
        ok = check_sample(str(sample.id), dict(sample.store), list(sample.events))
        failed = failed or not ok
    print("RESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
