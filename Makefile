.PHONY: typecheck
typecheck:
	uv run pyright

.PHONY: check
check: typecheck
	uv run ruff check --fix
	uv run ruff format

.PHONY: test
test:
	uv run pytest

# CI-suite coverage (branch coverage, both daemon toolchains required so no
# codec test silently skips); VM-battery-only paths show as uncovered here by
# design and are triaged in design/spikes/quality-review/coverage-triage.md.
.PHONY: coverage
coverage:
	INSPECT_RANGES_REQUIRE_GO=1 INSPECT_RANGES_REQUIRE_DOTNET=1 uv run pytest \
		--cov=inspect_ranges --cov-branch \
		--cov-report=term-missing --cov-report=html
