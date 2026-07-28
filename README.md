# RepoGuard

RepoGuard provides an installable typed Python package and an M1 read-only evidence API. The API
models a local Git repository plus pull-request base and head refs, resolves their unique merge base,
and returns immutable changed-file metadata and UTF-8 diff hunks. Binary files, symlinks, and
submodules remain traceable through modes and object IDs without lossy text conversion.

Evidence collection reads committed Git objects only. It does not inspect dirty worktree content,
fetch missing history, call language models, produce review findings, create patches, or write to the
repository or GitHub.

## Requirements

- Python 3.12
- uv 0.9.2
- Git 2.43 or compatible
- A POSIX environment exposing `/dev/fd` or `/proc/self/fd` for evidence collection

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

## Collect Evidence

```python
from pathlib import Path

from repoguard.evidence import (
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
    evidence_to_json,
)

evidence = collect_evidence(
    RepositoryInput(path=Path(".")),
    PullRequestInput(base_ref="main", head_ref="feature"),
)
canonical_json = evidence_to_json(evidence)
```

The API returns evidence in memory and performs no artifact or external-system writes. RepoGuard does
not yet expose evidence collection as a CLI command.

## Verify

```bash
./scripts/check.sh
```

The script runs Ruff lint and format checks, MyPy strict, pytest with at least 90% coverage, and Git
whitespace validation.
