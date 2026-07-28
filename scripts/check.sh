#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=repoguard --cov-report=term-missing --cov-fail-under=90
git diff --check
