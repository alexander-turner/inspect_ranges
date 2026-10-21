# Contributing to Inspect Ranges

Thanks for your interest in contributing. Bug reports, doc fixes, and core changes are all welcome.

## Development setup

Inspect Ranges uses [uv](https://docs.astral.sh/uv/) for environment and dependency management, and requires Python 3.12+.

```bash
git clone https://github.com/meridianlabs-ai/inspect_ranges
cd inspect_ranges
uv sync --group dev
```

This installs Inspect Ranges in editable mode along with the dev tools (ruff, pyright, pytest), and puts the `inspect-ranges` CLI on your path.

### Remote development

Running ranges requires Linux with KVM and nested virtualization, so day-to-day development happens on an EC2 devbox:

```bash
uv run devbox/devbox.py --profile <profile> --region <region> up
```

This provisions the box, clones the repo onto it, and sets up SSH so you can connect with `ssh inspect-ranges-devbox` or VS Code Remote-SSH. The box stops itself when idle. See [`devbox/README.md`](devbox/README.md) for prerequisites, the security model, and the required IAM permissions.

## Checks and tests

Before opening a PR, make sure these pass:

```bash
make check   # pyright + ruff check --fix + ruff format
make test    # pytest
```

To run a single test:

```bash
uv run pytest tests/path/to/test.py::test_name -v
```

## Code style

- Type-annotate all functions (including tests). Use modern syntax (`X | None`, `list[str]`).
- Google-style docstrings for public APIs.
- `ruff` handles formatting and import order; don't fight it.
- Don't catch exceptions defensively — let unexpected errors propagate.

See [`CLAUDE.md`](CLAUDE.md) for the full conventions used in this repo.

## Building the docs

Docs live in `docs/` and are built with [Quarto](https://quarto.org). The Quarto CLI and the doc-build dependencies are in the `doc` group, which a plain `uv sync` leaves out (and removes):

```bash
uv sync --group doc
cd docs
source ../.venv/bin/activate
quarto render        # outputs to docs/_site/
quarto preview       # live-reload server
```

The venv must be activated (not just `uv run quarto`) so the reference-page filter can import `griffe` and the `inspect_ranges` package itself.

## Updating the docs extension

`docs/_extensions/` holds a checked-in copy of the [inspect-docs](https://github.com/meridianlabs-ai/inspect-docs) Quarto extension, which contributes the project type `_quarto.yml` declares. It is committed (per Quarto convention) so that a fresh clone can render without any install step.

To pull a newer version:

```bash
cd docs
mv _quarto.yml _quarto.yml.bak
uv run --group doc quarto update meridianlabs-ai/inspect-docs --no-prompt
mv _quarto.yml.bak _quarto.yml
```

The `mv` is a bootstrap workaround, not superstition: `quarto add`/`update` parses `_quarto.yml` to choose an install directory, so it chokes on the very project type the extension provides. Commit the resulting diff.

## Pull requests

- Branch from `main`; we squash-merge.
- Keep PRs focused on one change.
- Add or update tests for behavior changes.
- Update `CHANGELOG.md` under a new top entry if the change is user-visible.

## Reporting issues

Use the [issue tracker](https://github.com/meridianlabs-ai/inspect_ranges/issues). For bugs, include the `inspect_ranges` and `inspect_ai` versions (`pip show inspect-ranges inspect-ai`) and a minimal repro.
