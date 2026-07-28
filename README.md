# RepoGuard

RepoGuard currently provides its M0 development foundation: an installable typed Python package, a
no-key version command, tests, local quality gates, and matching GitHub Actions configuration.

It does not yet review repositories, call language models, retrieve context, create patches, or write
to GitHub.

## Requirements

- Python 3.12
- uv 0.9.2

## Install

From the repository root:

```bash
uv sync --frozen
```

## Run

```bash
uv run python -m repoguard --version
```

Expected output:

```text
repoguard 0.1.0
```

This command does not require an API key.

## Verify

```bash
./scripts/check.sh
```

The script runs Ruff lint and format checks, MyPy strict, pytest with at least 90% coverage, and Git
whitespace validation.
