# RepoGuard

RepoGuard provides an installable typed Python package, an M1 read-only evidence API, and an M2
deterministic review API. Evidence collection models a local Git repository plus pull-request base
and head refs, resolves their unique merge base, and returns immutable changed-file metadata and
UTF-8 diff hunks. Binary files, symlinks, and submodules remain traceable through modes and object
IDs without lossy text conversion.

Evidence collection reads committed Git objects only. It does not inspect dirty worktree content,
fetch missing history, call language models, create patches, or write to the repository or GitHub.
Deterministic review consumes collected evidence in memory and performs no additional I/O.

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

## Review Evidence

```python
from repoguard.review import review_evidence, review_to_json

review = review_evidence(evidence)
canonical_review_json = review_to_json(review)
```

The fixed M2 catalog reports paired private-key blocks and complete unresolved conflict blocks in
added text, newly introduced executable permission, introduced symlinks or changed symlink targets,
and introduced or changed submodule pointers and opaque binary content. Findings are immutable,
severity ordered, evidence referenced, and canonically serializable.

M2 scans only addition lines and head-side metadata already present in the evidence bundle. It does
not read complete files, inspect unchanged repository content, suppress findings by path, or provide
rule configuration or a review CLI. The catalog is a focused deterministic review layer, not a
comprehensive security scanner.

## Verify

```bash
./scripts/check.sh
```

The script runs Ruff lint and format checks, MyPy strict, pytest with at least 90% coverage, and Git
whitespace validation.
