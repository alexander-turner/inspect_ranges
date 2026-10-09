"""The Inspect `SandboxEnvironment` provider for libvirt ranges (provider-v1).

Layered retry is the spine (see `design/inspect-ranges/provider-v1.md`): the channel's wire-level exactly-once is layer 1; `retry.py` is layer 2, bounded fresh-id retries around whole sandbox operations; `errors.py` is the single mapping table from channel failures to the Inspect contract.
"""

from .errors import SessionChangedError, map_file_failure, shell_returncode
from .retry import (
    FailureClass,
    RetryConfig,
    RetryPolicy,
    RetryStats,
    classify,
    with_retry,
)

__all__ = [
    "FailureClass",
    "RetryConfig",
    "RetryPolicy",
    "RetryStats",
    "SessionChangedError",
    "classify",
    "map_file_failure",
    "shell_returncode",
    "with_retry",
]
