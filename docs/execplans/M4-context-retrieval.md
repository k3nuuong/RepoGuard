# M4: Hybrid Code Context Retrieval

Status: complete

This is the only active tracked ExecPlan for M4 and follows `.agent/PLANS.md`. The M0, M1, M2, and
M3 plans are complete historical records and must not be edited.

## Purpose And Observable Outcome

Add bounded, deterministic hybrid retrieval over the committed head tree represented by an M1
`EvidenceBundle`, and make that context available through a new opt-in M4 Agent review workflow.
M4 retains text, vector, and symbol channels only when a fixed offline evaluation demonstrates their
value. It does not change the M3 `review_with_agent` API, the `agent_review/v1` resources, or any
M0-M3 public result.

The observable M4 result is:

- a synchronous `repoguard.retrieval` API that builds one reusable in-memory index from the resolved
  `head_oid`, accepts an explicit query, and returns canonical schema-1 context hits with exact
  committed provenance;
- an opt-in `repoguard.retrieval_agent` API that deterministically derives bounded queries from M1
  changes and M2 Findings, retrieves auxiliary head context from a caller-supplied index, and runs a
  new `agent_review/v2` workflow;
- fixed, secret-safe, atomic errors and resource ceilings for corpus reading, model use, indexing,
  querying, and Agent orchestration;
- a committed 60-query intrinsic retrieval evaluation with deterministic fake coverage in the
  shared gate and a separately invoked, offline, fixed-BGE ablation; and
- one final additive commit only if the retained channel combination passes every fixed value gate.

Retrieved unchanged code is auxiliary context only. Every final Agent Finding must still resolve to
an M1 changed hunk and use the existing `AgentFinding` and `EvidenceReference` semantics.

## Restored Baseline

M3 is committed on `main` at `187262abf369a8678f04dc68ea511d4ec292f4e6`, with parent M2 at
`6528d2347ec9c355ad8a93c09ffc956d9386b25a`, M1 at
`550a7bbf05a4a58bb3499ff3e8aba91041900c3a`, and M0 at
`853002cc223be1255d4945f0a8b3a24e99096917`. There is no Git remote.

Recovery on 2026-07-29 observed:

    git status --short --branch
    ## main

    uv --version
    uv 0.9.2

    uv run python --version
    Python 3.12.3

    uv run python -m repoguard --version
    repoguard 0.1.0

`uv lock --check` resolved 57 packages, `uv sync --frozen` audited 56 packages, and the direct
runtime versions remained LangGraph 1.2.10, OpenAI 2.49.0, and Anthropic 0.120.2.
`./scripts/check.sh` passed Ruff lint and formatting, MyPy strict, Git whitespace, and all 270 tests
with 91.17% coverage against the unchanged 90% floor. The worktree remained exactly `## main`
afterward.

## Context, Scope, And Constraints

M1 supplies the normalized repository root, object format, immutable `head_oid`, changed-file
metadata, and diff hunks. M4 may add committed-tree/blob reading for the resolved head but must not
read dirty or untracked worktree content, follow a moving ref after validation, fetch a missing
object, or modify the reviewed repository.

M2 supplies six authoritative deterministic rules. M4 applies the exact M2 paired-private-key marker
semantics to every eligible head text before chunk content crosses an embedding, result, prompt, or
logging boundary. This remains intentionally incomplete secret detection; content not matched by
that rule can still cross the explicit local embedding or LLM provider boundary.

M3 supplies the synchronous provider contract, strict response parser, local changed-hunk reference
resolution, retry policy, deadlines, and stable result semantics. M4 may refactor private M3
execution code into a shared internal policy point, but all existing M3 tests, errors, nodes, output
bytes, and the fixed v1 prompt resource digest are compatibility oracles.

M4 does not implement patch generation, repair, worktrees, sandboxes, approvals, GitHub writes, a
review CLI, GitHub Action product behavior, FastMCP, RepoGuardBench, model training, a frontend,
deployment, or production monitoring. The package root continues to export only `__version__`, the
CLI remains version-only, and the package version remains 0.1.0.

The only permitted real network access for M4 is:

- uv/PyPI access needed to resolve, install, build, or smoke-test the locked dependencies; and
- one explicit anonymous download of the fixed BGE model revision when
  `FastEmbedProvider(..., allow_download=True)` is deliberately used.

Automated tests, the shared gate, final intrinsic ablation after the model is cached, and all Agent
acceptance use no socket. No OpenAI, Anthropic, or other LLM/provider endpoint is required or called
for M4. A separate live-provider check of the inherited M3 workflow is recommended when credentials
and network access are deliberately available, but it is not an M4 gate and cannot replace the
offline deterministic acceptance.

## Public Retrieval Interfaces

Add `repoguard.retrieval`. Its public surface includes:

    RetrievalChannel
    RetrievalStage
    RetrievalErrorCode
    RetrievalError
    EmbeddingDevice
    EmbeddingProvider
    FastEmbedProvider
    ContextIndexConfig
    ContextQuery
    ContextIndex
    IndexIdentity
    IndexStatistics
    ChunkProvenance
    ContextChunk
    RetrievalHit
    RetrievalResult
    build_context_index
    retrieve_context
    retrieval_to_dict
    retrieval_to_json

Public enums inherit from `StrEnum`; the provider protocol is runtime-checkable; the fixed provider
and opaque `ContextIndex` own process-local state; and public data records are frozen, slotted
dataclasses using exact built-in tuples. Canonical JSON uses UTF-8, `ensure_ascii=False`, sorted
keys, compact separators, tuple-to-array conversion, and no trailing newline.

`RetrievalChannel` contains `text`, `vector`, and `symbol`. A config has a non-empty, duplicate-free
tuple of enabled channels, defaulting to all three. Channel selection exists so the same production
implementation can run the required ablations. A channel rejected by evaluation is removed from the
final public enum, implementation, dependencies, and README rather than left as an unproven option.

`EmbeddingDevice` contains `auto`, `cpu`, and `cuda`.

`EmbeddingProvider` is a runtime-checkable synchronous protocol bound to this complete contract:

- stable non-empty `name`, fixed `model`, exact `dimension`, and actual `device`;
- deterministic tokenizer spans needed to enforce the 384-token chunk/query limits;
- normalized document embeddings and query embeddings; and
- idempotent `close()`.

The provider methods return exact built-in tuples and float32-compatible vectors. M4 accepts only
the fixed BGE identity and 384 dimensions. The provider instance is unbound before a build. A
successful build transfers exclusive ownership to its `ContextIndex`; it cannot be bound to a
second index. A failed build closes temporary provider state. Closing the index closes the provider
but never deletes model cache files.

`FastEmbedProvider` fixes model identity to `BAAI/bge-small-en-v1.5`. Its constructor requires an
explicit `cache_dir`, defaults to `allow_download=False`, and accepts an `EmbeddingDevice` with
default `auto`. Initialization is lazy so `build_context_index` can reject an unsafe cache location
before model or network activity. Auto chooses CUDA only when the locked ONNX Runtime reports an
available CUDA provider; otherwise it chooses CPU. Once selected, initialization or inference
failure is atomic and does not silently retry on another device.

`ContextIndexConfig` contains these caller-lowerable ceilings and fixed algorithm values:

- enabled channels, normalized include globs, and normalized exclude globs;
- at most 10,000 eligible files;
- at most 2 MiB per eligible file;
- at most 64 MiB total eligible corpus bytes;
- at most 20,000 chunks;
- at most 128 MiB of deterministic logical index bytes;
- at most 180 seconds for model verification/loading, corpus reading, chunking, embedding, and
  index construction;
- at most 10 seconds for one complete standalone or internal multi-query retrieval call;
- 384 tokenizer tokens per chunk including special tokens and 64-token overlap;
- at most 32 candidates per query per enabled channel and at most 12 final chunks; and
- RRF `k=60`, integer scale `1_000_000_000`, and weight 1 for every retained channel.

Every number is an exact non-bool value, positive where applicable, and cannot exceed the displayed
M4 ceiling. Include/exclude collections are exact tuples of valid UTF-8 strings. Normalize their
order by UTF-8 bytes and reject duplicates. Match Git-relative POSIX paths with Python 3.12
`PurePosixPath.match(pattern, case_sensitive=True)`. Empty include means all paths; exclude is
applied afterward and wins.

`ContextQuery(text: str)` is frozen and slotted. Its text must be non-empty valid UTF-8, contain no
Unicode control character, fit in 4,096 UTF-8 bytes, and fit in 384 fixed-BGE tokens. Canonical
results contain only the SHA-256 of the exact query bytes, never the raw query.

`ContextIndex` is an opaque process-local object. It binds:

- normalized repository root and object format;
- resolved head commit OID;
- retrieval schema, normalized config, enabled channels, fixed model/revision/manifest identity,
  dimension, and actual device; and
- immutable corpus/chunk/backend state.

It exposes only identity, aggregate counts, idempotent `close()`, and context-manager methods.
Build is single-threaded and atomically publishes only a complete index. Published state is
immutable. An internal reentrant lock serializes SQLite, FAISS, symbol, and encoder access so
multiple caller threads are safe. A closed index rejects every query with a stable error. Garbage
collection is a resource-release backstop, not the primary lifecycle.

`ChunkProvenance` records the stable chunk ID, Git-relative path, head blob OID, half-open original
blob byte offsets `[start_byte, end_byte)`, and inclusive line range. The chunk ID is a lowercase
SHA-256 over schema and immutable Git/path/offset identity, not over mutable scores.

`ContextChunk` adds the redacted UTF-8 content projection, exact redacted inclusive line ranges, and
ordered Python definition/reference symbol metadata. Content preserves original newline bytes
outside redacted logical lines. Byte offsets always address the original blob, while the public
content is explicitly the redacted projection and can differ in length.

`RetrievalHit` contains one chunk, the ordered contributing channels, optional exact 1-based
text/vector/symbol ranks, `matched_query_count`, and exact integer `rrf_score`. Standalone retrieval
uses one query. Final sorting is descending score, then path UTF-8 bytes, start/end byte, inclusive
line range, and chunk ID.

`RetrievalResult` has schema version 1, index identity, query SHA-256, aggregate candidate/selected/
omitted counts, and at most 12 ordered hits. It contains redacted chunk content and provenance but no
raw query, backend raw score, local model cache path, or hidden partial-failure status.

`build_context_index(bundle, *, embedding_provider, config)` accepts only a valid M1 schema-1 bundle.
`retrieve_context(index, query)` accepts only a live matching M4 index and valid `ContextQuery`.
Zero eligible corpus, zero candidates, and zero hits are successful results with complete identity
and zero counts.

## Corpus, Secret Handling, And Chunking

Read only the full recursive committed tree at the exact `bundle.revisions.head_oid`. Requested base,
merge base, dirty worktree state, and refs moving after validation cannot affect the corpus. Include
unchanged head files. Deleted files are absent. Renames use the new path.

Accept only ordinary Git blob entries whose bytes are valid UTF-8 and contain no NUL. Exclude binary,
non-UTF-8, symlink, submodule, tree, and other entries. Empty ordinary text is eligible but produces
no chunk. Do not guess vendor, generated, minified, dependency, or build paths.

Use hardened argument-array Git subprocesses with `shell=False`, disabled interactive prompts and
lazy fetch, no optional locks, replacement objects, grafts, hooks, config-based helpers, or network.
The supplied head identity must itself have Git object type `commit`; an annotated tag that merely
peels to a commit is invalid. Validate object format and every OID. Stream recursive tree output
under the shared deadline and a fixed 128 MiB stdout ceiling. Before reading any candidate ordinary
blob body, fail closed if tree metadata already exceeds the file-count, per-file-size, or aggregate
inspected-byte ceilings; inspected bytes include candidate blobs later excluded as binary or
non-UTF-8. Verify the complete committed corpus before initializing the embedding provider. A
missing head, internal tree, or blob maps to the stable `missing_object` error and never triggers a
fetch.

Before chunking or embedding, scan logical lines with the exact M2 paired-private-key labels and
greedy FIFO pairing semantics. Every line in a matched inclusive range is represented as
`[REDACTED_PRIVATE_KEY_MATERIAL]` while preserving its line terminator. Record redacted line ranges,
never matched secret text.

For `.py` and `.pyi`, parse with Python 3.12 `ast`:

- each top-level class, function, or async function, including decorators, is a preferred chunk
  region;
- nested definitions and `Name`/`Attribute` references become ordered metadata on the chunks that
  cover them;
- a preferred region at or below 384 tokens remains whole;
- an oversized region is cut by verified tokenizer offsets into 384-token windows with 64-token
  overlap; and
- module regions not covered by top-level definitions use the same windows.

A `SyntaxError` increments `unparsed_python_file_count`; the file still participates in text and
vector retrieval with no symbols. Any other parser exception is an atomic build failure.

All other text uses 384/64 tokenizer windows. Token offsets must map through Python code points to
exact UTF-8 byte boundaries. Preserve complete lines where the token ceiling permits. An oversized
single line is split on tokenizer/code-point-safe offsets, can produce several chunks with the same
inclusive line range, and is distinguished by byte offsets. Every non-empty original byte belongs
to at least one chunk; overlap never creates duplicate chunk identity.

## Text, Vector, Symbol, And Fusion Behavior

Text retrieval uses one private in-memory SQLite database with FTS5. Build verifies FTS5 support and
fails closed when unavailable. Index parameterized columns for path, symbols, and redacted content;
rank with `bm25()` weights path=5, symbols=3, content=1. Query normalization is deterministic and
never interpolated as SQL syntax.

Vector retrieval uses normalized 384-dimensional float32 embeddings and
`faiss-cpu.IndexFlatIP`. Document input is the fixed structured concatenation of path, ordered
definition/reference symbol names, and redacted content. Query embeddings use the provider's query
path. Validate vector count, dimensionality, finite values, normalization, and float32 storage before
publishing the index.

Symbol retrieval supports only Python identifiers. Extract top-level/nested definitions and
`Name`/`Attribute` references. Deterministically split query text on path separators and
camel/snake/identifier boundaries. Match complete identifiers case-sensitively, with definitions
ranked before references; do not use prefix, substring, fuzzy, or language-server behavior.

Each query/channel contributes at most 32 candidates. Rank starts at one. A contribution is:

    floor(1_000_000_000 / (60 + rank))

All retained channels have integer weight one. Sum exact integer contributions across channels and,
for internal Agent retrieval, across deduplicated queries. Deduplicate by chunk ID. For Agent
summaries retain contributing channels, each channel's best rank, matched-query count, and final
integer score, not every query hash or contribution.

Any enabled channel or encoder failure makes the whole build/query fail atomically. There is no
runtime channel degradation. The evaluation-controlled removal branch changes the final
implementation and reruns all gates; it is not a per-call fallback.

## Budgets, Accounting, And Errors

Logical index bytes are the deterministic sum of:

- original eligible blob bytes;
- redacted chunk UTF-8 bytes;
- canonical metadata UTF-8 bytes; and
- dense float32 matrix `nbytes`.

Record each component. Do not claim that this bounds SQLite, FAISS, ONNX Runtime, model, allocator,
or interpreter overhead.

Use a monotonic absolute deadline. Check it before and after every bounded Git/file, tokenize,
embedding, SQLite, FAISS, and fusion batch. Download, manifest verification, model loading, corpus
processing, and backend construction share the 180-second build budget. A complete standalone
single-query call or Agent batch of at most 256 queries shares one 10-second query budget; the
budget is not reset by query or channel. There is no thread/process preemption, so one bounded
native or network call may return after its deadline; detect that immediately afterward and record
this residual risk.

`RetrievalErrorCode` is a closed enum covering unsupported schema, invalid evidence,
invalid configuration, invalid index, closed index, Git unavailable, read failure, missing object,
text backend unavailable, model unavailable, embedding failure, corpus limit, index limit, query
limit, deadline, and backend failure.

`RetrievalStage` is a closed enum that locates validation, corpus read, chunking, embedding, text
index, vector index, symbol index, text query, vector query, symbol query, fusion, and close.
`RetrievalError` exposes only code, stage, and an optional retained `RetrievalChannel`.

Messages are fixed and contain no repository/cache path, content, query, private key, model
exception, SQL, prompt, or response. Public errors have no unsafe `__cause__` or `__context__`.
Failures never publish a partial index/result or leave a usable partly built backend.

## Fixed Model And Dependency Boundary

If vector passes evaluation, add these direct runtime ranges while retaining the three M3 direct
dependencies:

    faiss-cpu>=1.14.3,<2
    fastembed-gpu>=0.8.0,<0.9.0
    numpy>=2.5.1,<3
    huggingface-hub>=1.25.1,<2
    tokenizers>=0.23.1,<1
    onnxruntime-gpu<1.28

Use `fastembed-gpu`, not the CPU `fastembed` distribution. FAISS remains CPU exact search. The GPU
package must support both explicit CPUExecutionProvider and CUDAExecutionProvider in one core
installation. RepoGuard imports ONNX Runtime directly, so its tested upper bound must be present in
wheel `Requires-Dist`, not only in uv's local resolver state. Record the exact locked versions and
full runtime tree.

The fixed model source is repository `Qdrant/bge-small-en-v1.5-onnx-Q` at commit
`52398278842ec682c6f32300af41344b1c0b0bb2`. Package a versioned JSON manifest containing the exact
required relative file names, sizes, and SHA-256 values. Download only that revision from the fixed
official `https://huggingface.co` endpoint, with `token=False` and an explicit cache directory.
Ignore Hugging Face token, endpoint, cache, and offline environment configuration rather than
silently changing source or identity.

Before any model load, verify every required file against the packaged manifest and reject extra
identity ambiguity. Pass the verified model directory to FastEmbed as a specific local model.
Reject a cache directory equal to or inside the reviewed repository root before download or model
initialization.

For explicit CUDA, load the locked ONNX Runtime CUDA provider library with a local
`ctypes.CDLL` preflight before constructing an inference session. Missing CUDA/cuDNN libraries map
to the stable `model_unavailable/embed/vector` boundary without native diagnostics containing local
installation paths. A successful session must still report the actual CUDA provider; CPU fallback
is never accepted as CUDA.

A failed download or hash verification fails the API and does not publish an index. Do not
recursively delete or mutate an externally owned partial Hugging Face cache; a later explicit call
may revalidate or resume it.

RepoGuard emits no logs by default. Tests exercise Python logging, loguru, stdout, and stderr at
DEBUG and require that diff/chunk/query/private-key/cache-path markers do not appear while host
logger levels, handlers, filters, propagation, disabled state, and standard streams remain
unchanged. Fixed model ID/revision and aggregate counts are safe metadata.

## M4 Agent Interfaces And Workflow

Add `repoguard.retrieval_agent` with:

    RetrievalAgentNode
    RetrievalAgentReviewErrorCode
    RetrievalAgentReviewError
    RetrievalAgentReviewConfig
    RetrievalPromptIdentity
    RetrievalChunkSummary
    RetrievalSummary
    RetrievalAgentReviewResult
    review_with_retrieval
    retrieval_agent_review_to_dict
    retrieval_agent_review_to_json

`RetrievalAgentReviewConfig` owns one existing `AgentReviewConfig` plus caller-lowerable M4 ceilings:
at most 256 automatic queries, at most 2,048 UTF-8 bytes per automatic query, and at most 65,536
UTF-8 bytes of retrieved chunk content in the v2 prompt. The M3 131,072-byte complete prompt,
4,096-token output, response/count/text ceilings, three attempts, 0.5/1.0-second backoffs,
30-second per-attempt limit, and 95-second total ceiling remain unchanged. The M4 total deadline
starts before retrieval, so the 10-second retrieval is included in 95 seconds.

`review_with_retrieval(bundle, *, index, provider, config)` requires a prebuilt, open index. It
strictly matches normalized repository root, object format, head OID, schema, retained channels,
model, manifest, and device/config identity before retrieval. It never downloads a model, reads Git,
or builds an index implicitly.

Build automatic queries in stable order:

- one per changed text file from path tokens, safe identifiers on addition/deletion lines, and any
  enclosing Python symbol;
- one per M2 Finding from rule/category/reference metadata, path tokens, safe identifiers in the
  referenced changed range, and enclosing Python symbol.

Never copy a complete code line, string literal, comment, private key, or arbitrary source prose into
an automatic query. Deterministically truncate only at complete-token boundaries to 2,048 bytes,
exact-deduplicate, sort by stable source/path/reference/token identity, and cap at 256.
Because the retrieval corpus is HEAD-only, a deletion in a later hunk may have no trustworthy
old-side enclosing scope or identifier in the head AST. Query derivation conservatively omits that
unproven old-side metadata instead of guessing from shifted head lines or arbitrary hunk prose.

Add immutable resources:

    src/repoguard/prompts/agent_review/v2/system.md
    src/repoguard/prompts/agent_review/v2/response-schema.json

The v2 user payload has schema version 2 and contains:

- the same complete M1 changed evidence and all M2 Findings as v1, with M2 private-key redaction;
- selected redacted chunks in fused order, including identity, provenance, best ranks, matched-query
  count, and integer RRF score.

It omits raw/generated queries, backend raw scores, local repository root, cache path, credentials,
and model internals. Always preserve the complete diff and all M2 Findings. Add whole retrieved
chunks until the 65,536-byte retrieval ceiling or complete 131,072-byte prompt ceiling would be
crossed, then omit lower-ranked chunks. If the complete diff and Findings alone exceed the prompt
limit, fail with the existing context-limit semantics rather than truncate them.

The v2 response schema remains the strict schema-1 model response. Reuse M3 local parsing,
changed-hunk reference validation, M2 preservation, exact model deduplication, ordering, provider
retries, tracing/debug isolation, SDK logging safety, and atomic completion behavior. Retrieved
chunks cannot be cited directly.

`RetrievalAgentReviewResult` has schema version 1 and the same flat repository, revisions, provider,
model, prompt identity, attempt count, usage, prompt/response byte counts, and Findings fields as
M3. It adds one `RetrievalSummary` containing index identity, actual device, query/candidate/
selected/omitted counts, unparsed/excluded counts, logical byte components, and the exact chunks
sent to the provider as content-free `RetrievalChunkSummary` values with provenance, channels,
best ranks, matched-query count, and integer RRF score. It contains no raw query, chunk content,
prompt, response, credential, cache path, or partial status.

`RetrievalAgentReviewErrorCode` copies the M3 error directory and adds `invalid_index` and
`retrieval_failed`. `RetrievalAgentNode` adds retrieval to the stable M3-style node set.
`RetrievalAgentReviewError` exposes code, node, attempt count, and only for `retrieval_failed` an
optional secret-safe `RetrievalErrorCode`. Errors are fixed, detached, and atomic.

## Evaluation And Channel Retention

Commit one M4-local 60-query golden dataset and a deterministic runner. It has 20 lexical, 20 Python
symbol/cross-file, and 20 semantic cases, stratified across simple, medium, and complex difficulty.
Each case identifies expected path, head blob OID, and relevant byte/line span. Relevance is exact
path/OID plus non-empty span overlap; the runner never uses an LLM judge.

Report Recall@12, MRR@12, and nDCG@12 overall and per channel/difficulty stratum. Validate dataset
schema, unique IDs, non-empty relevance, metric arithmetic, and deterministic ordering before
scoring. `validate_evaluation_gates(report)` programmatically enforces every fixed absolute,
contribution, and regression threshold before a report is published.

The shared gate uses a deterministic normalized 384-dimensional fake provider to test algorithms,
serialization, errors, boundaries, and evaluation math without network or model files. The
stage-level value run uses the fixed cached BGE model offline and compares:

- text only;
- text plus symbol;
- text plus vector; and
- complete text plus vector plus symbol.

The complete hybrid must satisfy all of:

- Recall@12 at least 0.90;
- MRR@12 at least 0.75;
- nDCG@12 at least 0.80;
- overall nDCG at least 0.05 above text-only;
- vector improves its semantic stratum nDCG by at least 0.05 in its ablation;
- symbol improves its symbol/cross-file stratum nDCG by at least 0.05 in its ablation; and
- no stratum Recall regresses by more than 0.02.

CPU is the normative value baseline. On the available RTX 4090, rerun the complete ablation offline
with CUDA and require the same thresholds. On a fixed subset with no approximate-score tie, CPU and
GPU top-12 chunk IDs must match exactly through `validate_device_parity(cpu, cuda)`. The fixed
subset contains one simple, medium, and complex case from each stratum:

    lexical-01 lexical-09 lexical-15
    symbol-01 symbol-08 symbol-18
    semantic-01 semantic-08 semantic-15

The CPU score gaps within each selected top-12 and across each rank-12/rank-13 boundary must exceed
`1e-4`. Approximate ties outside this fixed subset are reported but do not support a claim of
all-case device parity. Record actual build/query times and metric values without turning incidental
timings into thresholds.

If vector misses its contribution gate, remove FAISS, FastEmbed GPU, NumPy, Hugging Face,
tokenizers, the model manifest, vector API branches, and GPU paths. Replace token chunking with
code-point-safe UTF-8 windows of at most 8 KiB and 1 KiB overlap, still preferring top-level Python
and complete-line boundaries.

If symbol misses its contribution gate, remove AST parsing, all symbol metadata/index/query behavior,
and changed-symbol automatic queries. Use uniform token windows if vector remains, or uniform byte
windows if vector is also removed.

After removing a rejected channel, rerun the complete absolute and regression gates for the
remaining combination. If the retained combination fails any absolute threshold, M4 is blocked:
do not lower a threshold, update README, claim the capability, or create the final commit.

## Implementation Steps

1. Create and maintain this complete ExecPlan as the first M4 tracked edit.
2. Add and lock the provisional vector/model dependencies, record exact resolved versions, and
   inspect Python 3.12/Linux CPU/CUDA wheel compatibility without changing the package version.
3. Add the packaged fixed model manifest and provider protocol/adapters, including offline/default,
   explicit anonymous download, hash verification, device selection, ownership, and logging tests.
4. Add the committed-head reader, complete evidence/config validation, corpus exclusions/globs,
   M2-equivalent whole-corpus private-key redaction, tokenizer/AST chunking, provenance, identity,
   and deterministic accounting.
5. Add FTS5, FAISS, and Python symbol indexes plus exact integer RRF fusion, query validation,
   immutable index lifetime, concurrency guard, canonical models/serializers, budgets, and stable
   atomic errors.
6. Add v2 prompt/schema resources and private shared Agent execution policy. Keep every M3 public
   behavior and v1 resource byte-identical while adding deterministic automatic queries, retrieval,
   whole-chunk prompt selection, M4 result/summary serialization, and M4 error mapping.
7. Add focused public, Git integration, provider/model, backend, Agent integration, and Hypothesis
   tests. Properties cover chunk byte/token coverage and overlap, redaction secrecy, canonical JSON,
   RRF permutation invariance and monotonicity, deterministic tie-breaks, index identity/close,
   budget boundaries, and M3 oracle equivalence.
8. Add the 60-query dataset and deterministic runner. Run fake evaluation in ordinary tests, then
   explicitly download and verify the fixed model once outside the reviewed repository.
9. Run the full offline CPU and RTX 4090 ablations. Apply the specified removal branch for any
   channel that does not prove value, then rerun all affected tests, dependency checks, and metrics.
10. Update README only after final retained capabilities and metric gates are verified. Keep all
    limitations explicit.
11. Run exact acceptance, build both distributions, inspect all M4 modules/resources with Python
    `zipfile`, and exercise the current wheel with fake provider/encoder plus offline CPU/GPU BGE
    retrieval. Never use the broken Homebrew `unzip`.
12. Obtain two independent read-only reviews: API/algorithm/performance, then
    secret/network/supply-chain/evaluation. Reproduce and reconcile every credible finding.
13. Complete all four living sections, inspect and stage only M4 deliverables, run cached whitespace
    validation, create one `feat: add hybrid context retrieval` commit, and perform all documented
    post-commit checks without amend, remote, or push.

## Validation

Run focused checks as modules land, then run from the repository root:

    uv lock --check
    uv sync --frozen
    uv run python --version
    uv run python -m repoguard --version
    uv tree --no-dev --frozen
    uv run pytest tests/test_embedding.py tests/test_retrieval.py \
        tests/test_retrieval_core.py tests/test_retrieval_properties.py \
        tests/test_retrieval_integration.py tests/test_retrieval_agent.py \
        tests/test_retrieval_agent_workflow.py tests/test_retrieval_evaluation.py
    ./scripts/check.sh
    git diff --check
    uv build --python 3.12

The version must remain `repoguard 0.1.0`. `scripts/check.sh` remains unchanged and is the only
shared gate; Ruff lint/format, MyPy strict, every test, at least 90% coverage, and Git whitespace
must pass. Record actual test count and coverage, including M1 pipe-writer scheduling variance.

Run the deterministic fake evaluation through its tested Python entry point. Then run the fixed
model evaluation with network disabled and explicit CPU/CUDA devices. Exact commands and actual
tables must be written to Progress and Outcomes before completion.

Inspect the wheel with Python 3.12 `zipfile` and require:

- public/private retrieval and retrieval-Agent modules;
- v2 prompt and response-schema resources;
- the fixed BGE manifest; and
- the 60-query evaluation data if the runner loads it as a package resource.

Use `uv run --no-project --isolated --no-cache --with <current-wheel>` for wheel smokes. Package
registry access may install the wheel-metadata dependency graph. The fake smoke builds, queries, and
performs an empty M4 Agent review without a provider endpoint. The fixed-BGE CPU/GPU smokes use a
validated pre-cached model with socket denial.

Before commit, confirm M0-M3 plans and v1 prompt resources have no diff, inspect the complete M4
diff, stage only M4 deliverables, and run:

    git diff --cached --check

Create exactly:

    feat: add hybrid context retrieval

At the committed SHA, rerun lock check, frozen sync, Python/package versions, frozen runtime tree,
the shared gate, offline CPU/GPU evaluation, distribution inspection, both wheel smokes, and:

    git status --short --branch

The final status must be only `## main`.

## Idempotency And Recovery

Git/corpus reading, fake embedding, index building/querying, canonical serialization, tests,
evaluation, lock checking, frozen sync, build, wheel inspection, and offline smoke commands are safe
to rerun. Temporary Git repositories and isolated environments are disposable.

Dependency edits, the fixed model download, README claims, staging, and the final commit are
deliberate one-time actions. Before repeating any of them, inspect `pyproject.toml`, `uv.lock`, the
explicit external cache, Git status, and Progress. Never delete an external model cache recursively.

After interruption:

1. Read `AGENTS.md`, `.agent/PLANS.md`, the charter, all complete M0-M3 plans, this plan, and the
   recovery runbook.
2. Inspect branch, HEAD, status, recent commits, dependencies, resources, and the complete diff.
3. Rerun the latest successful command recorded in Progress.
4. Compare source, tests, evaluation artifacts, and actual Git state with this plan.
5. Resume from the first incomplete implementation step and update all affected living sections.

For every failure, record the exact command and complete error, current hypothesis, and a materially
changed next method in Progress. A repeated attempt must test a different hypothesis. After three
materially different failures without new evidence, mark the blocker and continue independent work.
Never weaken quality or value thresholds.

## Progress

- 2026-07-29: Fully read `AGENTS.md`, `.agent/PLANS.md`, the charter, complete M0-M3 plans, and the
  recovery runbook. Confirmed no prior M4 plan or implementation existed.
- 2026-07-29: Restored exact M3 at `187262abf369a8678f04dc68ea511d4ec292f4e6`, with its expected
  M2 parent, clean `main`, no remote, uv 0.9.2, Python 3.12.3, package 0.1.0, and the expected three
  direct runtime versions. Lock, frozen sync, version, runtime tree, and the sole shared gate all
  passed; 270 tests passed with 91.17% coverage and the worktree remained `## main`.
- 2026-07-29: Confirmed all M4 API, corpus, backend, model, chunking, fusion, cache, budget, safety,
  evaluation, wheel, review, and delivery decisions. M4 permits package installation and one fixed
  BGE download but keeps automated acceptance offline. Separately authorized M3 live-provider
  development/acceptance is recommended when available, not required for M4.
- 2026-07-29: Created this self-contained M4 ExecPlan as the first tracked M4 edit. Next: resolve the
  provisional dependencies and add the fixed model/provider boundary before retrieval code.
- 2026-07-29: Added the five confirmed direct dependency ranges. `uv lock` resolved 74 packages,
  including FAISS 1.14.3, FastEmbed GPU 0.8.0, Hugging Face Hub 1.25.1, NumPy 2.5.1, tokenizers
  0.23.1, and transitive ONNX Runtime GPU 1.28.0. Frozen sync attempt 1,
  `uv lock --check && uv sync --frozen`, passed the lock check but failed because
  `onnxruntime-gpu==1.28.0` has no source distribution or Linux wheel for the current
  `manylinux_2_39_x86_64` platform; uv reported only `win_amd64`. Hypothesis: FastEmbed's open
  transitive range selected a new platform-incomplete release. The changed next method is to inspect
  PyPI file metadata for the newest compatible Linux wheel and add a uv transitive constraint rather
  than change the confirmed direct API/dependency surface or repeat sync.
- 2026-07-29: PyPI metadata showed ONNX Runtime GPU 1.27.0 as the newest release with a CPython 3.12
  manylinux x86_64 wheel. Added uv-only `constraint-dependencies = ["onnxruntime-gpu<1.28"]`;
  `uv lock` changed 1.28.0 to 1.27.0, the exact lock check passed, and frozen sync installed all 74
  resolved packages. The selected direct versions are FAISS 1.14.3, FastEmbed GPU 0.8.0, Hugging
  Face Hub 1.25.1, NumPy 2.5.1, and tokenizers 0.23.1. Next: package and verify the fixed model
  manifest/provider boundary.
- 2026-07-29: Fixed-model download attempt 1 used `snapshot_download` with the exact repository,
  revision, seven-file allowlist, anonymous token, official endpoint, and external cache. It failed
  before transferring model files because HTTPX inherited a host SOCKS proxy but optional
  `socksio` is not installed. Hypothesis: Hugging Face's default client still consumes general proxy
  environment state even though model/HF identity environment was removed. The changed next method
  is the official Hub client factory with `httpx.Client(trust_env=False)`, not a new proxy dependency
  or a relaxed source identity.
- 2026-07-29: Fixed-model download attempt 2 used the official Hub client factory with
  `trust_env=False`; it did not complete even the repository-info request within 180 seconds and was
  interrupted at that budget. Hypothesis: direct egress is unavailable on this host, while the
  inherited proxy requires an uninstalled optional transport. The changed next method is an
  explicit fixed-file transport over the working host HTTPS path, followed by the same packaged
  manifest verification and entirely offline FastEmbed load; do not install proxy extras or relax
  repository/revision/file identity.
- 2026-07-29: The first patch recording download attempt 2 failed atomically because its context
  joined a wrapped line differently from the current plan; no file content changed. The changed
  method used the exact current line boundary and applied this smaller plan-only hunk.
- 2026-07-29: Independently downloaded and hashed the five fixed model files under a temporary
  external directory. A CPU FastEmbed smoke using only those files produced normalized
  384-dimensional float32 vectors and an actual `CPUExecutionProvider`. The product implementation
  must move or re-download these bytes into an explicit durable external cache and revalidate the
  packaged manifest before load; `/tmp` is not a deliverable cache.
- 2026-07-29: CUDA smoke used the locked ONNX Runtime GPU 1.27.0 on the available RTX 4090. Runtime
  discovery advertised CUDA, but session creation could not load `libonnxruntime_providers_cuda.so`
  because `libcudnn.so.9` is absent, then FastEmbed warned and silently created a CPU-only session.
  The changed implementation method is to inspect the initialized nested ONNX session providers and
  fail closed when CUDA was selected but is not actual. Adding ONNX Runtime CUDA/cuDNN Python extras
  would add a new unapproved dependency boundary and roughly 553 MiB for cuDNN alone, while system
  package installation is forbidden. Therefore the required local CUDA value run is currently an
  external-runtime acceptance blocker; CPU implementation, tests, and evaluation continue
  independently without weakening the CUDA gate.
- 2026-07-29: Added the initial public `repoguard.retrieval` contracts and fixed model manifest.
  Public result/provenance/statistics models now enforce their canonical invariants, the fixed model
  identity, exact tuples, and deterministic accounting. Focused Ruff passed. Focused MyPy currently
  reports only missing `_embedding` and `_retrieval` implementations and their resulting `Any`
  returns; those two private modules are the active implementation step, so this is not yet a
  successful static gate.
- 2026-07-29: Added the independent `repoguard.retrieval_agent` value models, stable errors,
  canonical content-free serialization, immutable v2 system/schema resources, and bounded pure v2
  prompt projection. The projection reuses the v1 changed-evidence, deterministic-Finding,
  private-key redaction, and changed-hunk target helpers; it omits only complete lower-ranked
  retrieval chunks. Focused public/prompt tests passed 18 cases. The existing v1 prompt digest
  remains `a8597f69c987b5ef45e59133d750f7fce94b9d455ef70d7cfb4e15054c2c10a6`,
  and the v1/v2 response-schema resources are byte-identical. The private retrieval Agent workflow
  and M3 graph compatibility refactor remain in progress.
- 2026-07-29: A third, materially different CUDA investigation did not install any package: it
  unpacked the PyPI cuDNN wheel under `/tmp` and explicitly preloaded that temporary library.
  The fixed model then created an actual CUDA session and repeated CUDA outputs were bit-identical;
  CPU versus CUDA cosine similarity was 0.9999992847 with maximum absolute element difference
  0.0002103597. Normal dependency resolution would add roughly 1.015 GB of compressed cuDNN,
  cuBLAS, and NVRTC wheels, while ONNX Runtime's declared CUDA extras are currently unresolvable
  from default PyPI because placeholder CUDA 13 projects do not satisfy their constraints. This
  confirms the implementation path but also confirms that enabling it would materially expand the
  approved dependency boundary. The M4 worktree therefore retains strict CUDA detection/failure and
  leaves the required local CUDA ablation blocked.
- 2026-07-29: Completed the fixed-model provider, committed-head corpus reader, whole-corpus M2
  private-key projection, tokenizer/AST chunking, FTS5/FAISS/symbol indexes, integer RRF fusion,
  immutable index lifecycle, canonical public retrieval models, and focused Git/property/provider
  tests. A real cached CPU smoke selected `CPUExecutionProvider` and returned normalized
  384-dimensional document/query vectors at the fixed revision.
- 2026-07-29: Completed the opt-in retrieval Agent workflow and private M3 graph variant. The M3
  wrapper, v1 prompt digest
  `a8597f69c987b5ef45e59133d750f7fce94b9d455ef70d7cfb4e15054c2c10a6`, and byte-identical v1/v2
  response schema remain compatibility oracles. New tests cover conservative query derivation
  across Python string/hunk boundaries, retrieval deadline and lock behavior, prompt whole-chunk
  selection, tracing/debug secrecy, and rejection of references that exist only in retrieved
  context.
- 2026-07-29: Added and strictly validated the packaged 20-file, 60-query evaluation resource and
  deterministic evaluator. The fake-provider ablations were byte-repeatable and measured
  text `0.733333/0.566667/0.610310`, text+symbol `0.733333/0.725000/0.727182`, text+vector
  `1.000000/0.755159/0.817705`, and hybrid `1.000000/0.913492/0.934577` for
  Recall@12/MRR@12/nDCG@12.
- 2026-07-29: Ran the fixed cached BGE ablations with explicit CPU, `allow_download=False`, and
  socket creation denied. Hybrid measured Recall@12 `0.983333`, MRR@12 `0.861270`, and nDCG@12
  `0.891024`; overall nDCG improved `0.280714`, semantic vector nDCG improved `0.491527`, symbol
  nDCG improved `0.369070`, and no stratum Recall regressed. The measured run took 2.36 seconds and
  peaked at 339,308 KiB RSS; these timings are observations, not gates.
- 2026-07-29: Strict-warning CPU acceptance exposed leaked `git cat-file --batch` stdout/stderr
  descriptors after successful corpus reads. Added one shared pipe closer for successful and
  aborted child processes plus a direct lifecycle regression. The strict-warning offline CPU rerun
  then exited cleanly with the same metrics.
- 2026-07-29: The latest complete pytest coverage gate before the final focused boundary additions
  passed 440 tests at 90.16% against the unchanged 90% floor. Focused tests added afterward cover
  multi-byte query byte limits and invalid Evidence rejection before provider ownership transfer.
  The sole shared gate and final exact test count remain to be rerun after review reconciliation.
- 2026-07-29: Reconciled independent review findings. The supplied head must itself be a commit;
  missing internal trees map to `missing_object`; Git tree output and candidate blob accounting are
  deadline/byte bounded before body reads; corpus validation precedes embedding initialization; and
  explicit CUDA now preflights the locked provider library before session creation. Added stable
  regressions for each boundary.
- 2026-07-29: Added executable value and device-parity validators. The fixed nine-case subset has
  CPU top-12 and rank-12/rank-13 score gaps above `1e-4`. CPU/CUDA subset IDs match exactly; four
  approximate cases outside the subset (`lexical-08`, `symbol-07`, `symbol-09`, `semantic-11`)
  differ at low ranks in vector-bearing modes, so no all-case parity claim is made.
- 2026-07-29: Fresh focused verification before documentation: embedding warnings-as-errors passed
  45 tests; core/property/integration passed 54; retrieval Agent passed 48; M3 plus retrieval
  Agent/providers passed 196; complete M4 focused tests passed 214. Ruff, format, MyPy strict,
  whitespace, and the 74-package lock check passed.
- 2026-07-29: Fake evaluation resource SHA-256 is
  `c777ca964972c32aff65d8973aa97b9c31f82541f0f684dd320402bfe04f5d7c`.
  Fake hybrid measured `1.000000/0.913492/0.934577`; offline fixed-BGE CPU and actual CUDA both
  measured `0.983333/0.861270/0.891024` for Recall@12/MRR@12/nDCG@12. The observed CPU/CUDA runs
  took 2.265/0.967 seconds. CUDA used an existing external temporary cuDNN library directory; no
  system package or project dependency was added.
- 2026-07-29: A distribution review found that uv-only transitive constraints are absent from wheel
  metadata while RepoGuard imports ONNX Runtime directly. Promoted `onnxruntime-gpu<1.28` to a
  direct project dependency, regenerated the 74-package lock, added an exact metadata regression,
  and mapped expected private evaluation-entry-point failures to one fixed path-free exit.
  Lock/frozen sync and 55 focused package/evaluation tests passed. Next: run the final shared gate,
  rebuild distributions, execute isolated wheel smokes, and complete pre-commit audit.
- 2026-07-29: Final shared gate passed 484 tests at 90.21% coverage; Ruff, format, MyPy strict, and
  Git whitespace passed. The first fake-entry-point evidence wrapper piped module JSON into a Python
  heredoc. The heredoc consumed stdin as source, so the parser received zero bytes and raised
  `JSONDecodeError`; the producer then raised `BrokenPipeError`. Hypothesis: one stdin cannot carry
  both script and pipeline data. The changed method is an outer Python process that invokes the same
  module entry point with `subprocess.run(..., capture_output=True)` and parses stdout in memory.
- 2026-07-29: The changed fake-entry-point wrapper passed. Its 151,279-byte canonical report SHA-256
  was `c777ca964972c32aff65d8973aa97b9c31f82541f0f684dd320402bfe04f5d7c`; all four metric rows
  matched the fixed values and the entry point wrote no stderr.
- 2026-07-29: Fresh socket-denied fixed-BGE evaluation passed all value gates on explicit CPU and
  actual CUDA. CPU/CUDA hybrid metrics were both `0.983333/0.861270/0.891024`; observed elapsed
  times were 2.141652/0.996508 seconds, and fixed-subset device parity passed. ONNX Runtime emitted
  only content/path-free node-assignment warnings. No provider endpoint was called.
- 2026-07-29: Rebuilt sdist and wheel. `zipfile`/`tarfile` inspection found every M4 module,
  v2 prompt/schema, model manifest, and evaluation resource; both metadata files contain exact
  `onnxruntime-gpu<1.28`. The sdist was 90,951 bytes with SHA-256
  `99c1915ab1eb88f9227734af568abe7b8af7bfa87084fb7cdfdbba862619def5`; the wheel was 107,088
  bytes with SHA-256 `f4a8ea3aae48b06d0a939f6746e3942baff8a0d76f73fb6051fbd2bf485cbc58`.
- 2026-07-29: Fresh `--no-project --isolated --no-cache` wheel smokes resolved
  `onnxruntime-gpu==1.27.0`. The fake provider built and queried an index and completed an empty
  fake-LLM v2 Agent response without a socket. Separate fixed-BGE smokes, with socket creation denied
  after dependency import, selected actual CPU and CUDA and returned 12 hits on each device.
- 2026-07-29: The first combined scope audit exited 1 before its first output because one silent
  assertion failed. All assertions were grouped under `set -e`, so the command did not identify
  which invariant differed. Hypothesis: the known M3 prompt identity digest was incorrectly compared
  with the raw `system.md` file hash rather than the versioned prompt projection. The changed method
  runs each read-only invariant with an explicit label, then reconstructs the final audit using the
  correct resource oracle.
- 2026-07-29: The labelled diagnosis confirmed the only mismatch was that mistaken raw-file hash
  oracle. The corrected final audit passed: exactly 25 M4 delivery files, exact M3/M2 ancestry, no
  remote or staged data, unchanged M0-M3 plans/v1 resources/charter/runbook/package root/main CLI/
  shared gate, ignored transient planning, no M5/frontend files, no dangerous execution primitives
  or credential literals, and only the fixed model endpoint. Lock/frozen sync, `uv pip check`,
  74-package frozen runtime tree, Git object integrity, and whitespace passed. `gh` remains absent.
- 2026-07-29: After staging exactly those 25 files, cached scope, whitespace, credential, and
  conflict-marker checks passed with no unstaged or untracked delivery files. The final staged
  shared-gate rerun passed all 484 tests at 90.18% coverage; the immediately preceding identical-code
  run measured 90.21%, the expected M1 pipe-writer scheduling variance. No threshold changed.

## Surprises & Discoveries

- 2026-07-29: The installed Python 3.12 SQLite 3.45.1 exposes FTS5, but M4 must still test capability
  at build time because this local compile option is not a portable Python contract.
- 2026-07-29: FastEmbed 0.8.0's fixed BGE registry supplies 384-dimensional output and local-file
  loading, but reproducible identity requires bypassing its moving model-source default with a
  fixed repository revision and packaged file hashes.
- 2026-07-29: A redaction sentinel changes byte length. Exact original blob offsets and a redacted
  public projection are therefore separate, explicit fields rather than contradictory claims that
  public content is byte-identical to the original slice.
- 2026-07-29: Token-based chunking depends on the retained vector model tokenizer. The specified
  vector-rejection branch must remove that dependency and switch to deterministic byte windows.
- 2026-07-29: GPU FastEmbed and CPU FAISS are separate concerns. The selected core distribution uses
  ONNX Runtime CPU or CUDA for embeddings while preserving one exact CPU FAISS index algorithm.
- 2026-07-29: ONNX Runtime GPU 1.28.0 is platform-incomplete on PyPI as observed by uv: it cannot
  satisfy the selected Linux core distribution without a compatible transitive version constraint.
- 2026-07-29: `onnxruntime.get_available_providers()` is not proof that a CUDA session exists.
  FastEmbed/ORT can report CUDA availability, fail to load cuDNN, and silently publish a CPU session
  that still returns valid vectors. Actual nested session providers must be checked after model
  initialization.
- 2026-07-29: ONNX Runtime 1.27 offers CUDA/cuDNN extras that can preload vendor libraries from
  Python packages, but FastEmbed GPU does not request them and `preload_dlls()` may print absolute
  library paths. Treating those extras as an implicit repair would violate the confirmed dependency
  and logging boundary.
- 2026-07-29: With cuDNN explicitly preloaded from a temporary unpacked wheel, CPU and CUDA BGE
  vectors are extremely close but not byte-identical. Cross-device acceptance must compare
  retrieval IDs on cases without score ties, as planned, rather than compare raw vector bytes.
- 2026-07-29: ONNX Runtime CUDA may emit node-assignment diagnostics to stderr. Its public
  suppression API changes a process-global severity with no getter for lossless restoration, so
  RepoGuard cannot silently change it merely to make a smoke quiet.
- 2026-07-29: Importing FastEmbed's HTTP dependency graph probes local IPv6 support by attempting
  an `AF_INET6` loopback socket. The offline acceptance guard rejects that probe before a socket is
  created; urllib3 catches the denial and model loading proceeds locally. This is dependency import
  behavior, not a successful network operation.
- 2026-07-29: Waiting for a successful `git cat-file --batch` process is not sufficient to close
  Python's three pipe wrappers. Explicit closure is required even when the child has already exited.
- 2026-07-29: Fixed-BGE tokenizer offsets are context-sensitive: a tail represented by 382 tokens
  in whole-text offsets can require 385 tokens when encoded independently. Each emitted window must
  therefore be re-tokenized and refitted, and overlap must start from final verified spans.
- 2026-07-29: A peelable annotated tag is not a valid immutable head identity for this API. Exact
  object type and missing internal-tree classification require separate Git checks.
- 2026-07-29: A uv-only transitive constraint does not enter wheel `Requires-Dist`. Because
  RepoGuard imports ONNX Runtime directly, the tested `<1.28` compatibility range must be a direct
  distribution dependency.
- 2026-07-29: CPU and CUDA can produce equal aggregate retrieval metrics while low-ranked IDs differ
  near approximate-score ties. Device parity is intentionally limited to the fixed stratified
  subset whose measured CPU score gaps exceed `1e-4`.

## Decision Log

- 2026-07-29: Use a new standalone retrieval API and opt-in M4 Agent API with v2 resources. Reason:
  M3 public behavior and v1 prompt semantics remain immutable compatibility boundaries.
- 2026-07-29: Index only the exact committed head tree and permit unchanged text. Reason: cross-file
  context is the M4 value while dirty worktree/base ambiguity would break identity.
- 2026-07-29: Use in-memory SQLite FTS5, exact FAISS inner product, and Python AST symbol search with
  equal integer RRF. Reason: each channel is inspectable, bounded, and independently ablatable.
- 2026-07-29: Use fixed BGE Small with a pinned source revision and packaged SHA-256 manifest.
  Reason: a model name alone is not reproducible and implicit download/cache/environment behavior
  violates the explicit read-only boundary.
- 2026-07-29: Make the index own one encoder and serialize all backend access. Reason: ONNX, SQLite,
  and FAISS lifecycle/concurrency safety must not depend on caller coordination.
- 2026-07-29: Preserve complete changed evidence and M2 Findings in v2 and trim only whole retrieved
  chunks. Reason: M4 context must supplement rather than silently narrow M3 review coverage.
- 2026-07-29: Use intrinsic fixed-golden offline evaluation only; do not call a live LLM. Reason:
  M4 acceptance must stay deterministic. A separately authorized M3 live-provider check is
  recommended when credentials/network exist but is not an M4 requirement, so M3 live-model
  quality remains a residual risk.
- 2026-07-29: Remove any channel that fails its contribution gate, and block M4 if the remainder
  fails absolute thresholds. Reason: the charter requires demonstrated value, not implementation
  presence.
- 2026-07-29: Keep version 0.1.0 and create one additive M4 commit after two independent reviews.
  Reason: M0-M4 are internal stage commits and historical plans/commits must remain unchanged.
- 2026-07-29: Publish `onnxruntime-gpu<1.28` as a direct dependency. Reason: 1.28.0 has no verified
  Linux wheel for this target, 1.27.0 is the tested Python 3.12 manylinux x86_64 build, RepoGuard
  imports ONNX Runtime directly, and wheel consumers do not inherit uv-only resolver constraints.
- 2026-07-29: Retain all three retrieval channels after fake and normative CPU evaluation. Reason:
  hybrid clears every absolute threshold, vector and symbol each clear their fixed contribution
  gates, and no stratum Recall regression exceeds the fixed allowance.
- 2026-07-29: Accept explicit CUDA using the existing external cuDNN runtime only for validation,
  without adding it to the project graph or installing a system package. Reason: the actual CUDA
  ablation clears the same value gates and fixed-subset parity; callers still must provide a
  compatible native runtime, and missing libraries fail closed.

## Outcomes & Retrospective

M4 delivers a bounded, synchronous hybrid retrieval API over the exact committed HEAD tree and a
separate opt-in retrieval-enhanced Agent v2 workflow. The reusable index is in memory and owns
SQLite FTS5 text search, exact FAISS vector search, Python AST symbol search, fixed-BGE embedding,
deterministic integer RRF, exact committed provenance, whole-corpus M2 private-key-range redaction,
strict lifecycle/concurrency, logical byte accounting, fixed deadlines, and stable atomic errors.
The Agent path derives content-safe bounded queries, preserves complete M1 evidence and every M2
Finding, includes only whole ranked chunks, and still permits Findings to cite changed hunks only.

The checked-in 20-file/60-query intrinsic evaluation programmatically enforces all absolute,
contribution, and stratum-regression gates. Fake hybrid Recall@12/MRR@12/nDCG@12 is
`1.000000/0.913492/0.934577`; fixed-BGE CPU and actual CUDA both measure
`0.983333/0.861270/0.891024`. All three channels are retained. Fixed-subset CPU/CUDA top-12 parity
passes; four approximate-tie cases outside that subset have low-rank differences and are not claimed
as all-case parity. CUDA validation used an external temporary cuDNN runtime without a system
installation or new project dependency.

Final pre-commit acceptance passed Ruff lint and formatting, MyPy strict for 37 source files, all
484 tests, latest coverage of 90.18% against the unchanged 90% floor, Git whitespace, lock/frozen
sync, package compatibility, and the 74-package runtime tree. The preceding identical-code run
measured 90.21%, consistent with the inherited M1 pipe-writer scheduling variance. Rebuilt
sdist/wheel metadata carries the direct `onnxruntime-gpu<1.28` compatibility bound and includes
every M4 module/resource. Fresh isolated no-cache wheel installations exercised fake
build/query/v2 Agent behavior and offline fixed-BGE CPU/CUDA retrieval, resolving ONNX Runtime GPU
1.27.0. The package stays at 0.1.0; M3 v1 resources/behavior, package-root exports, version-only CLI,
shared gate, and M0-M3 history remain unchanged. Independent reviews materially improved deadlines,
query derivation, tokenizer windows, Git object/resource bounds, CUDA diagnostics, executable
evaluation gates, and distribution metadata; every reproduced in-scope finding was reconciled.

Residual risk remains explicit. The corpus is HEAD-only, so unprovable old-side identifiers in later
deletion hunks are omitted; symbol retrieval is Python-only; indexes are not persisted; and native
Git/tokenizer/embedding/backend calls are checked after return rather than preempted. The fixed model
cache is caller-owned, and CUDA callers must supply a compatible native CUDA/cuDNN runtime. The M2
private-key rule does not detect every secret, so unmatched content can cross the local embedding or
explicit LLM boundary. A custom LLM provider must honor timeout and may behave outside RepoGuard's
no-tool graph; LangGraph tracing and SDK credential/log isolation remain coupled to locked
transitive/private APIs.

Inherited M1 gaps remain for real partial-clone missing objects, linked worktrees, alternates, and
M1 blob/patch/bundle size ceilings. M2 still scans only additions/head metadata and has no input or
Finding-count limit. No live-model quality acceptance, GitHub-hosted CI, or external CVE/maintainer
health audit ran; `gh` is absent and system-package installation is prohibited. Distribution smokes
cover Python 3.12/Linux x86_64, not every platform. M4 adds no repair, worktree, sandbox, approval,
GitHub/FastMCP product flow, benchmark, training, frontend, deployment, or production-monitoring
behavior from M5 or later stages.
