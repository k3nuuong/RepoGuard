# RepoGuard Agent Instructions

## Repository Map

- `src/repoguard/`: installable typed Python package and module entry point.
- `tests/`: package and CLI tests.
- `scripts/check.sh`: required local and CI quality gate.
- `docs/project-charter.md`: stable product direction and stage sequence.
- `docs/execplans/`: one active tracked ExecPlan per complex stage.
- `.planning/`: ignored temporary planning notes.
- `.repoguard/`, `artifacts/`, `.worktrees/`: ignored runtime state, run output, and worktrees.

## Commands

Run from the repository root:

```bash
uv sync --frozen
uv run python -m repoguard --version
uv run pytest
uv run ruff check .
uv run ruff format .
uv run mypy src tests
./scripts/check.sh
```

## Rules

- Run `scripts/check.sh` before declaring work complete.
- Create and maintain a self-contained ExecPlan for every complex stage.
- By default, do not modify existing projects, write to external systems, or commit secrets.
- Never fix a failure by lowering test, type-checking, lint, or coverage thresholds.
- Do not claim completion without fresh verification evidence.
