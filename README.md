# RepoGuard

RepoGuard provides an installable typed Python package, an M1 read-only evidence API, an M2
deterministic review API, and an M3 controlled Agent review API. Evidence collection models a local
Git repository plus pull-request base and head refs, resolves their unique merge base, and returns
immutable changed-file metadata and UTF-8 diff hunks. Binary files, symlinks, and submodules remain
traceable through modes and object IDs without lossy text conversion.

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

## Review With An Agent

```python
from repoguard.agent import (
    AgentReviewConfig,
    agent_review_to_json,
    review_with_agent,
)
from repoguard.providers import OpenAIProvider

provider = OpenAIProvider(api_key=openai_api_key)
agent_review = review_with_agent(
    evidence,
    provider=provider,
    config=AgentReviewConfig(model="provider-native-model-id"),
)
canonical_agent_json = agent_review_to_json(agent_review)
```

M3 also provides `AnthropicProvider`. Both adapters require an API key passed directly to the
constructor and an explicit provider-native model ID in `AgentReviewConfig`; RepoGuard does not read
credentials or models from environment variables, dotenv, or configuration files. The synchronous
workflow runs M2 first, makes at most three bounded provider attempts, validates strict structured
output and evidence references locally, preserves all M2 Findings, and returns no partial result
after a failure. Apart from the explicitly requested provider API call, it uses no tools,
persistence, retrieval, patch generation, or writes to the repository, GitHub, or artifacts.

The complete prompt must fit the configured byte limit. RepoGuard fails without calling the
provider when it is too large; it does not truncate, rank, summarize, or retrieve context. Before a
request, it redacts only addition lines covered by M2 `private_key_material` Findings. Other diff
content, old-side content, and secrets that M2 did not identify may be sent to the configured
provider. Callers must decide whether that provider boundary is appropriate for their repository.

The automated suite uses fake providers and mocked SDK responses. It makes no real model or provider
endpoint calls and therefore makes no claim about model review quality. The six M2 rules and the M3
model workflow are not a comprehensive security scanner. RepoGuard still exposes no review CLI;
the CLI remains limited to `--version`.

## Verify

```bash
./scripts/check.sh
```

The script runs Ruff lint and format checks, MyPy strict, pytest with at least 90% coverage, and Git
whitespace validation.
