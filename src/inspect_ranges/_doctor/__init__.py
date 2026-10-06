"""Host checks for `inspect-ranges doctor`: can this machine run and develop ranges?"""

from .checks import run_checks
from .report import passed, render_fix_script, render_json, render_text
from .result import CheckResult, CheckStatus

__all__ = [
    "CheckResult",
    "CheckStatus",
    "passed",
    "render_fix_script",
    "render_json",
    "render_text",
    "run_checks",
]
