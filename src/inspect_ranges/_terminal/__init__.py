"""The terminal tool: persistent tmux sessions for agents (terminal-tool-v1)."""

from .tool import TERMINAL_SCREEN_STORE_KEY, discard_terminal_state, terminal

__all__ = ["TERMINAL_SCREEN_STORE_KEY", "discard_terminal_state", "terminal"]
