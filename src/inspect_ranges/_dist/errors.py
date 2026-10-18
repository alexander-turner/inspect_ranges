"""The distribution layer's coded failure type, shared across its modules.

Every refusal carries a stable kebab-case code (the CLI renders it in the house `[code] message` style) so transfer failures end in a named cause, never a bare traceback.
"""


class DistError(Exception):
    """Coded distribution failure; the message names the artifact and the cause, never credentials."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")
