# RepoGuard

RepoGuard provides an installable typed Python package, an M1 read-only evidence API, an M2
deterministic review API, an M3 controlled Agent review API, and M4 bounded hybrid context retrieval
with an opt-in retrieval-enhanced Agent workflow. M5 adds approval-gated safe repair that validates a
deterministic candidate in rootless Docker and can publish only a dedicated local Git ref. Evidence
collection models a local Git repository plus pull-request base and head refs, resolves their unique
merge base, and returns immutable changed-file metadata and UTF-8 diff hunks. Binary files,
symlinks, and submodules remain traceable through modes and object IDs without lossy text
conversion.

Evidence collection reads committed Git objects only. It does not inspect dirty worktree content,
fetch missing history, call language models, create patches, or write to the repository or GitHub.
Deterministic review consumes collected evidence in memory and performs no additional I/O.
Safe repair is a separate opt-in Python API. It freezes one exact HEAD, requires an exact local
approval over the candidate and validation digests, and never updates HEAD, the worktree, the index,
configuration, remotes, or a caller-selected ref.

## Requirements

- Python 3.12
- uv 0.9.2
- Git 2.43 or compatible
- A POSIX environment exposing `/dev/fd` or `/proc/self/fd` for evidence collection
- SQLite with FTS5 for M4 text retrieval
- An explicit model cache outside the reviewed repository for fixed-BGE retrieval
- Linux x86_64 with rootless Docker, cgroup v2, seccomp, and memory/CPU/PID controls for M5 repair
- The repository-owned validation image built and verified by the maintenance workflow below

M4 CPU and CUDA retrieval are verified on Python 3.12/Linux x86_64. CUDA additionally requires a
compatible caller-supplied CUDA and cuDNN native runtime.

M5 rootless validation is measured on Docker client/server 29.6.1, API 1.55, and runc 1.3.6. These
versions are a tested configuration, not an exact-version gate; runtime capability probes remain
authoritative and fail closed.

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
after a failure. Apart from the explicitly requested provider API call, the original M3 API uses no
tools, persistence, retrieval, patch generation, or writes to the repository, GitHub, or artifacts.

The complete prompt must fit the configured byte limit. RepoGuard fails without calling the
provider when it is too large; it does not truncate, rank, summarize, or retrieve context. Before a
request, it redacts only addition lines covered by M2 `private_key_material` Findings. Other diff
content, old-side content, and secrets that M2 did not identify may be sent to the configured
provider. Callers must decide whether that provider boundary is appropriate for their repository.

The automated suite uses fake providers and mocked SDK responses. It makes no real model or provider
endpoint calls and therefore makes no claim about model review quality. The six M2 rules and the M3
model workflow are not a comprehensive security scanner. RepoGuard still exposes no review CLI;
the CLI remains limited to `--version`.

## Retrieve Committed Context

```python
from pathlib import Path

from repoguard.retrieval import (
    ContextQuery,
    EmbeddingDevice,
    FastEmbedProvider,
    build_context_index,
    retrieve_context,
)

embedding_provider = FastEmbedProvider(
    cache_dir=Path("/var/tmp/repoguard-models"),
    allow_download=False,
    device=EmbeddingDevice.CPU,
)
with build_context_index(evidence, embedding_provider=embedding_provider) as index:
    context = retrieve_context(index, ContextQuery("authentication request validation"))
```

The index reads only ordinary UTF-8 blobs from the exact committed head tree, including unchanged
files. It never reads dirty or untracked content, guesses vendor/generated paths, follows a moving
ref, or fetches missing objects. Binary and non-UTF-8 blobs, symlinks, submodules, and other Git
object types are excluded. The index is process-local and in memory; closing it releases its
embedding, SQLite FTS5, and exact FAISS state without deleting the caller-owned model cache.

`FastEmbedProvider` uses one manifest-pinned BGE Small revision and defaults to offline
`allow_download=False`. A deliberate `allow_download=True` call may anonymously populate only the
fixed revision in the explicit cache. The cache cannot be inside the reviewed repository. Text,
vector, and Python AST symbol results are fused with deterministic integer RRF and retain exact
commit, blob, byte, and line provenance.

M4 applies the M2 paired-private-key rule across eligible head text before embedding or returning
chunks. This is not general secret detection: unmatched secrets may still enter the local embedding
runtime or, through the opt-in workflow below, the explicitly configured LLM provider.

## Review With Retrieved Context

```python
from repoguard.agent import AgentReviewConfig
from repoguard.retrieval_agent import (
    RetrievalAgentReviewConfig,
    review_with_retrieval,
)

agent_embedding_provider = FastEmbedProvider(
    cache_dir=Path("/var/tmp/repoguard-models"),
    allow_download=False,
    device=EmbeddingDevice.CPU,
)
with build_context_index(evidence, embedding_provider=agent_embedding_provider) as index:
    retrieval_review = review_with_retrieval(
        evidence,
        index=index,
        provider=provider,
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="provider-native-model-id"),
        ),
    )
```

This opt-in v2 workflow preserves the complete M1 evidence and all M2 Findings, adds only bounded
whole retrieved chunks, and retains M3 retry, deadline, strict JSON, tracing, and reference
validation behavior. Retrieved chunks are auxiliary context and cannot become Finding citations;
every final Finding must still reference an M1 changed hunk. Because the index is HEAD-only,
unprovable old-side identifiers from later deletion hunks are conservatively omitted from automatic
queries.

The fixed 60-case intrinsic evaluation retained all three channels. Hybrid Recall@12, MRR@12, and
nDCG@12 were `1.000000`, `0.913492`, and `0.934577` with deterministic fake embeddings, and
`0.983333`, `0.861270`, and `0.891024` with the offline fixed BGE model on both CPU and actual CUDA.
CPU/CUDA top-12 IDs also matched on the fixed no-near-tie subset. These measurements establish value
on the checked-in retrieval dataset; they do not establish live-model review quality or make
RepoGuard a comprehensive security scanner.

## Repair With Local Approval

`repoguard.repair.RepairManager` binds one repository and creates durable local sessions from an
exact schema-1 EvidenceBundle, one ReviewResult, explicit targets and allowed paths, generation
policy, and validation policy. A session follows `propose`, `preview`, `approve`, and `apply`.
Approval requires the exact candidate ID, validation digest, and this fixed confirmation:

```text
I approve this exact RepoGuard candidate and validation result for ref-only application.
```

Successful application publishes only
`refs/repoguard/repairs/<candidate-id>`. M5 does not authenticate the declared subject, expose a
repair CLI, contact GitHub, push a remote, or provide remote approval.

### Maintain The Validation Image

The complete image definition is in
`src/repoguard/repair_assets/validation_image_v1/`. `Dockerfile` pins one official Python
linux/amd64 manifest, and canonical `image-lock.json` binds the upstream index, platform manifest,
base config, upstream revision, Dockerfile, local image ID, final config digest, Python, and Git.
The historical externally supplied image is retired.

Build is a deliberate maintenance action. It may contact Docker Hub only to obtain the exact pinned
base and never publishes an image:

```bash
./scripts/manage-repair-image.sh build /run/user/$(id -u)/docker.sock
```

Verification is local-only. It authenticates the rootless daemon capabilities and locked image,
then checks Python and Git with `pull=never`, `network=none`, a read-only root filesystem, no
capabilities, and no-new-privileges:

```bash
./scripts/manage-repair-image.sh verify /run/user/$(id -u)/docker.sock
```

To refresh the image, review and pin the new upstream index, linux/amd64 manifest, config digest,
and source revision; update the Dockerfile and its SHA-256 in `image-lock.json`; run `build` once to
obtain the candidate local image ID; inspect and record its final config digest; then run `build`
twice from no-cache and require the same locked image and config identities. Finish with `verify`,
the focused image/package tests, the real packaged sandbox probe, and `./scripts/check.sh`.
Production `ValidationPolicy.image_id` must use the locked local image ID, never the maintenance tag
or a floating registry reference.

## Verify

```bash
./scripts/check.sh
```

The script runs Ruff lint and format checks, MyPy strict, pytest with at least 90% coverage, and Git
whitespace validation.
