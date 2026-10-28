## Unreleased

- Scoring integrity (fourteenth amendment): the `answer` goal's `host`+`path` source snapshots the file at setup, before agent entry, and compares submissions against the snapshot; the previous live read at scoring time let an agent with write access to the file rewrite the comparison source and submit the rewrite for a guaranteed pass. The source's assurance label becomes `host-anchored` (plant-time trust, like every planted goal), and the build trio's forged check for the first authored consumer demonstrates the closed attack.

- Terminal tool: the blocking send's completion signal (`; tmux wait -S done-...`) no longer appears in the session's asciicast.

## 0.2.0 (25 October 2026)

- Initial release.
