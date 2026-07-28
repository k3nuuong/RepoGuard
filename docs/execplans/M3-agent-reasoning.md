# M3: Controlled Agent Review

Status: complete

This is the only active ExecPlan for M3 and follows `.agent/PLANS.md`. The M0, M1, and M2 plans
remain complete and must not be edited.

## Purpose And Observable Outcome

Add two real LLM provider adapters, versioned review prompts, and a controlled LangGraph workflow
over the existing M1 evidence and M2 deterministic review APIs. A caller supplies an
`EvidenceBundle`, an explicitly configured provider, and an explicit provider-native model ID. The
workflow returns a versioned, immutable `AgentReviewResult` whose canonical JSON contains
authoritative M2 Findings plus locally validated model Findings, or raises one stable atomic error.

The observable M3 result is a synchronous Python API that:

- runs the existing deterministic M2 review before any model call;
- prepares a complete, bounded, canonical prompt from M1 evidence and M2 Findings;
- removes M2-identified private-key ranges before the prompt crosses the provider boundary;
- invokes either the official OpenAI or Anthropic SDK through a common typed protocol;
- uses a bounded, in-memory LangGraph with no tools or persistence;
- validates a strict JSON response and resolves every evidence reference locally;
- never returns a partial Agent result after any node failure; and
- leaves the repository, worktree, GitHub, and all external systems unchanged except for the
  explicitly requested provider API call.

The existing CLI remains version-only. The package root continues to export only `__version__`.

## Context, Scope, And Constraints

M2 is committed at `6528d2347ec9c355ad8a93c09ffc956d9386b25a` on `main`, with M1 at
`550a7bbf05a4a58bb3499ff3e8aba91041900c3a` and M0 at
`853002cc223be1255d4945f0a8b3a24e99096917`. Recovery on 2026-07-29 confirmed a clean `main`
worktree, no remote, Python 3.12.3, uv 0.9.2, package version 0.1.0, and a runtime dependency tree
containing only RepoGuard. The restored shared gate passed Ruff lint and formatting, MyPy strict,
all 122 tests, 92.96% coverage against the unchanged 90% floor, and Git whitespace checks.

M1 provides immutable repository and revision identity, changed-file metadata, and UTF-8 diff
hunks. It does not provide complete files or unchanged repository content. M2 provides six fixed,
closed `RuleId` values and immutable Findings. M3 must not extend that enum, mutate M2 Findings, or
claim that the six rules are a complete security scan.

The package version remains 0.1.0. M3 adds `langgraph`, `openai`, and `anthropic` as direct core
runtime dependencies. Resolve the current stable Python 3.12-compatible release of each. In
`pyproject.toml`, set the resolved version as the inclusive lower bound and the next breaking
release as the exclusive upper bound: next major for a package at version 1 or later, and next minor
for a package still below version 1. Commit the exact full graph in `uv.lock` and record the three
resolved direct versions in Progress and Outcomes. Do not add LiteLLM, Pydantic AI,
`langchain-openai`, `langchain-anthropic`, a tokenizer, or a pricing database.

Add `pytest-socket` as a development-only dependency and configure pytest to disable sockets for the
entire automated suite. Package-registry access is allowed only to resolve, install, or smoke-test
locked packages. Automated tests and final acceptance must never call an OpenAI or Anthropic
endpoint or any real model.

M3 is intentionally limited to a single review Agent with bounded provider retries. It does not add:

- RAG, embeddings, FTS5, vector stores, symbol search, truncation, summarization, or context ranking
  from M4;
- patch generation, repair planning, isolated worktrees, sandboxes, approvals, or writes from M5;
- a review CLI, GitHub Action product behavior, GitHub writes, FastMCP, or product configuration
  from M6;
- RepoGuardBench, quality claims, training, a frontend, deployment, or production monitoring; or
- source code copied from another project.

## Public Provider Interfaces

Add `repoguard.providers` with these public exports:

    MessageRole
    LLMMessage
    LLMRequest
    TokenUsage
    LLMResponse
    LLMProvider
    ProviderErrorCode
    ProviderError
    OpenAIProvider
    AnthropicProvider

Public enums inherit from `StrEnum`. Public models are frozen, slotted dataclasses. Ordered
collections use exact built-in tuples.

`MessageRole` contains exactly `system` and `user`.

`LLMMessage` contains `role` and `content`.

`LLMRequest` contains:

- `model`: the explicit provider-native model string;
- `messages`: exactly one system message followed by exactly one user message;
- `max_output_tokens`: the per-call output ceiling; and
- `timeout_seconds`: the per-call timeout.

`TokenUsage` contains optional non-negative exact integers `input_tokens`, `output_tokens`, and
`total_tokens`. Missing provider usage remains null; RepoGuard does not estimate it.

`LLMResponse` contains `output_text` and optional `usage`. It does not contain request IDs, raw SDK
objects, headers, timestamps, or model reasoning.

`LLMProvider` is a runtime-checkable synchronous Protocol with a stable non-empty `name` property and:

    complete(request: LLMRequest) -> LLMResponse

The built-in provider names are `openai` and `anthropic`. A provider either returns one response or
raises `ProviderError`; it never returns a partial stream.

`ProviderErrorCode` contains exactly:

- `authentication_failed`
- `rate_limited`
- `timeout`
- `unavailable`
- `request_failed`
- `refused`
- `invalid_response`

`ProviderError` exposes its code and a fixed secret-safe message. It does not expose the SDK
exception, response body, request content, endpoint headers, or API key through attributes,
`str()`, `repr()`, or exception chaining.

`OpenAIProvider(api_key: str)` uses the official OpenAI Responses API at its fixed official endpoint.
`AnthropicProvider(api_key: str)` uses the official Anthropic Messages API at its fixed official
endpoint. Both require a non-empty key supplied directly to the constructor, disable SDK retries,
perform non-streaming requests, expose no tools, and ignore environment-based API-key or endpoint
configuration. RepoGuard does not read dotenv or a provider config file.

The adapters map known SDK authentication, rate-limit, timeout, connectivity, request, server, and
refusal outcomes to the stable provider codes. Unknown adapter failures become a fixed
`invalid_response` only when the returned SDK shape is invalid; unexpected implementation
exceptions remain available only to the outer workflow as a secret-safe workflow failure.

## Public Agent Interfaces And Schema

Add `repoguard.agent` with these public exports:

    FindingSource
    AgentRuleId
    AgentNode
    AgentReviewErrorCode
    AgentReviewError
    AgentReviewConfig
    PromptIdentity
    AgentFinding
    AgentReviewResult
    review_with_agent
    agent_review_to_dict
    agent_review_to_json

`FindingSource` contains `deterministic` and `agent`.

`AgentRuleId` contains exactly `agent_reasoning`. Existing M2 `RuleId` remains unchanged.

`AgentNode` names the stable workflow locations:

- `validate`
- `deterministic_review`
- `build_prompt`
- `invoke_provider`
- `parse_response`
- `merge_findings`
- `finalize`

`AgentReviewConfig` contains:

    model: str
    max_prompt_bytes: int = 131072
    max_output_tokens: int = 4096
    max_response_bytes: int = 524288
    max_model_findings: int = 100
    max_references_per_finding: int = 8
    max_title_chars: int = 120
    max_message_chars: int = 1000
    max_remediation_chars: int = 1000
    per_attempt_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 95.0
    max_attempts: int = 3

Every numeric value is positive, rejects bool, and cannot exceed its displayed M3 v1 ceiling.
Callers may lower a value. The model is a non-empty, UTF-8 provider-native identifier with no
default or allowlist; reject control characters and an unreasonable identifier length before
building the graph.

`PromptIdentity` contains:

- `name`, fixed to `agent_review`;
- `version`, fixed to `v1`; and
- `sha256`, the lowercase digest of the exact packaged system prompt bytes, one NUL separator byte,
  and the exact packaged response-schema bytes.

`AgentFinding` contains:

- `source`;
- `rule_id`, typed as `RuleId | AgentRuleId`;
- the existing `FindingCategory` and `FindingSeverity`;
- `title`, `message`, and `remediation`; and
- a non-empty tuple of existing `EvidenceReference` values.

A deterministic source requires an M2 `RuleId`; an agent source requires
`AgentRuleId.AGENT_REASONING`. All five existing severities, including `critical`, are valid for
model Findings.

`AgentReviewResult` contains:

- the exact input `RepositoryEvidence` and `RevisionEvidence`;
- provider name and explicit model;
- `PromptIdentity`;
- positive `attempt_count`;
- optional provider-reported `TokenUsage`;
- exact `prompt_bytes` and `response_bytes`;
- the final ordered tuple of `AgentFinding` values; and
- integer `schema_version` 1.

It contains no prompt text, raw model output, API key, request ID, timestamp, cost estimate, patch,
artifact path, or incomplete status.

The public entry point is:

    review_with_agent(
        bundle: EvidenceBundle,
        *,
        provider: LLMProvider,
        config: AgentReviewConfig,
    ) -> AgentReviewResult

It always runs M2 internally rather than accepting a caller-supplied `ReviewResult`, preventing an
evidence/result identity mismatch.

`agent_review_to_dict` maps every field explicitly. `agent_review_to_json` uses UTF-8,
`ensure_ascii=False`, sorted keys, compact separators, arrays for tuples, null for absent values, and
no trailing newline. Canonical serialization is stable for an already constructed result; repeated
real model calls are not claimed to be deterministic.

## Prompt, Context, And Secret Boundary

Package these immutable resources:

    src/repoguard/prompts/agent_review/v1/system.md
    src/repoguard/prompts/agent_review/v1/response-schema.json

Load them with `importlib.resources`. Once M3 completes, semantic prompt changes require a new
version directory rather than editing v1 in place.

The system prompt:

- defines the code-review task and the complete five-level severity rubric;
- identifies all repository fields and code as untrusted data, never instructions;
- states that no tool, command, network search, patch, or external action is available;
- requires findings to be supported only by supplied evidence;
- asks the model not to restate supplied deterministic Findings;
- forbids code fences, prose outside JSON, source dumps, patches, and credentials; and
- embeds or points to the exact strict response schema.

The user message is one compact canonical JSON object produced by structured serialization, not
string substitution into a trusted template. Its schema version is 1 and it contains:

- repository object format, but not the local absolute root;
- base, head, and merge-base OIDs, but not requested ref strings;
- all changed-file old/new metadata and all M1 hunk lines in canonical change order; and
- all exact M2 Findings.

Normalize only change ordering and JSON key ordering. Preserve hunk/line semantic order, Unicode,
CRLF representation, paths, modes, OIDs, content kinds, and inclusive coordinates.

Before serialization, find every M2 `private_key_material` new-side reference and replace the
content of every covered addition line with the exact ASCII sentinel
`[REDACTED_PRIVATE_KEY_MATERIAL]`. Preserve its kind, line numbers, and trailing-newline flag.
Perform this transformation before any provider request object is constructed. Do not mutate the
input bundle.

This is not a general secret scanner. Old-side content and secrets not covered by the M2 rule may
still cross the provider boundary. Document that limitation in README and the final outcomes. The
library emits no logs by default and never records the prompt or response.

The combined UTF-8 bytes of the system and user message content must not exceed
`config.max_prompt_bytes`. Compute the complete prompt before the first provider call. If it is one
byte over the limit, fail atomically with `context_limit_exceeded`; do not truncate, summarize,
rank, omit, or retrieve context. M4 owns any future context-selection policy.

## LangGraph State And Control Flow

Use `langgraph.graph.StateGraph` for one synchronous in-memory invocation. Build or compile it
without a checkpointer, store, interrupt, durable state, or tracing integration. Provider,
configuration, monotonic clock, and sleeper are invocation dependencies held outside serializable
graph state so credentials cannot appear in state snapshots.

The private state contains only the current evidence, deterministic result, rendered messages and
byte count, raw in-memory response, parsed candidates, attempt count, reported usage, pending
secret-safe error, final result, and absolute deadline. Clear prompt and raw-response references in
the finalize path before returning the public result.

Use this fixed flow:

1. `validate`: validate provider shape, configuration, input schema, identity, tuple collections,
   and every context/reference invariant needed by later nodes.
2. `deterministic_review`: call `review_evidence`; map unsupported/invalid input to the matching
   Agent error and an unexpected M2 rule failure to `workflow_execution_failed`.
3. `build_prompt`: load trusted resources, redact private-key ranges, serialize canonical user data,
   compute prompt identity and byte count, and enforce the complete pre-call limit.
4. `invoke_provider`: increment the attempt count and call the provider with the remaining
   per-attempt timeout capped at 30 seconds.
5. A conditional edge retries only `rate_limited`, `timeout`, or `unavailable` when the attempt
   count is below three and the total deadline permits another call. Sleep exactly 0.5 seconds
   before attempt two and 1.0 second before attempt three, with no jitter and no SDK retry.
6. `parse_response`: enforce the raw byte limit, parse strict JSON, validate every field and
   evidence reference, and construct all model Findings before exposing any.
7. `merge_findings`: convert every M2 Finding without changing its content, canonicalize model
   references, deduplicate exact model duplicates, and merge the two sources.
8. `finalize`: construct the only public result and discard internal prompt/response values.

Authentication, request, refusal, and invalid-output errors do not retry. If a retry budget ends,
preserve the final provider-specific Agent error. Use `budget_exceeded` only when the total deadline
prevents an otherwise permitted attempt or completion. A provider is responsible for honoring the
timeout supplied in `LLMRequest`; RepoGuard does not spawn an unbounded background thread to preempt
a provider that violates its protocol.

## Strict Model Output And Local Reference Validation

The response must be exactly one JSON object with no prefix, suffix, Markdown fence, duplicate key,
or non-JSON numeric value:

    {
      "schema_version": 1,
      "findings": [
        {
          "category": "security",
          "severity": "high",
          "title": "Short title",
          "message": "Evidence-based explanation.",
          "remediation": "Concrete remediation.",
          "references": [
            {
              "path": "src/example.py",
              "side": "new",
              "start_line": 10,
              "end_line": 12
            }
          ]
        }
      ]
    }

The top level and every nested object reject unknown or missing fields. Schema version is the exact
integer 1; bool is not an integer. Findings and references are JSON arrays within the configured
counts. Text fields are non-empty UTF-8 strings within their configured character limits. Enum
values must be exact existing lowercase values.

The model never supplies an OID, source, or rule ID. For each reference:

- `path` and `side` must select exactly one version sent in the prompt;
- line coordinates are either both null for a file-level reference or both positive exact integers;
- a line range must be ordered and every inclusive coordinate must exist on that side inside one
  transmitted hunk; and
- RepoGuard fills the OID from the selected M1 `FileVersion`.

Any invalid candidate invalidates the entire response. Never keep valid siblings from a partly
invalid response.

Canonicalize each model reference tuple before identity comparison. Deduplicate model Findings only
when category, severity, all text fields, and the complete reference tuple are exactly equal. Never
semantically deduplicate across sources. M2 Findings are never removed, downgraded, rewritten, or
made conditional on model output.

Sort the final tuple by:

1. severity rank `critical`, `high`, `medium`, `low`, `info`;
2. first reference path as UTF-8 bytes;
3. start line, treating null as zero;
4. end line, treating null as zero;
5. source, with `deterministic` before `agent`;
6. rule ID value;
7. the complete reference tuple; and
8. category, title, message, and remediation as final deterministic tie-breakers.

Changing only input change order, model Finding order, or model reference order must not change the
final Python result or canonical JSON.

## Stable Agent Error Behavior

`AgentReviewErrorCode` contains exactly:

- `unsupported_evidence_schema`
- `invalid_evidence`
- `invalid_configuration`
- `context_limit_exceeded`
- `provider_authentication_failed`
- `provider_rate_limited`
- `provider_timeout`
- `provider_unavailable`
- `provider_request_failed`
- `provider_refused`
- `invalid_model_output`
- `budget_exceeded`
- `workflow_execution_failed`

`AgentReviewError` exposes its code, stable `AgentNode`, and non-negative attempt count. Public
messages are fixed and contain no source text, path, prompt, raw response, provider exception text,
model output, or credential. Provider errors map to the corresponding prefixed Agent error. All
unexpected node exceptions become `workflow_execution_failed` naming only the stable node. Suppress
unsafe exception chaining at the public boundary.

All failures are atomic. No `AgentReviewResult`, M2-only fallback, validated sibling Finding,
artifact, log record, or external write is returned. A caller that explicitly wants deterministic
fallback can call the existing M2 API separately.

## Implementation Steps

1. Create this ExecPlan as the first tracked M3 edit and record the restored M2 baseline plus every
   confirmed user decision before changing dependencies or code.
2. Add compatible direct ranges for LangGraph, OpenAI, and Anthropic, add pytest-socket as a
   development dependency, lock the exact graph, and confirm package version 0.1.0.
3. Add the provider public contract and official SDK adapters with secret-safe errors and no
   environment configuration.
4. Add the prompt v1 package resources, strict response schema, prompt builder, complete context
   validation, and deterministic private-key redaction.
5. Add the public Agent models and canonical serialization without changing M1, M2, package-root, or
   CLI interfaces.
6. Implement the private LangGraph state, fixed nodes, conditional retry edge, deadline handling,
   strict parser, local reference resolution, atomic error boundary, and deterministic merge.
7. Add public-contract, provider-adapter, prompt/output, graph/retry, property, and Git integration
   tests. Every automated test uses a scripted provider or SDK mock transport.
8. Run focused static and behavioral checks, recording every failed command, complete error,
   hypothesis, and changed next approach in Progress before retrying.
9. Update README only with behavior established by tests and explicitly state the no-live-model and
   incomplete-secret-detection limitations.
10. Build and inspect distributions, run an isolated no-cache wheel smoke with a fake provider, and
    record the exact runtime dependency tree.
11. Obtain two independent read-only reviews: first for public API, graph, provider, and dependency
    correctness; second for adversarial prompt injection, secret handling, strict output, no-network
    enforcement, and failure atomicity. Reproduce and reconcile every credible issue.
12. Complete all four living sections, rerun exact acceptance, stage only M3 deliverables, create
    one additive commit, and perform post-commit verification without a remote or push.

## Validation

Run from the repository root:

    uv lock --check
    uv sync --frozen
    uv run pytest tests/test_providers.py tests/test_agent.py \
        tests/test_agent_properties.py tests/test_agent_integration.py
    uv run python -m repoguard --version
    uv tree --no-dev --frozen
    ./scripts/check.sh
    git diff --check
    uv build --python 3.12

The version output must remain `repoguard 0.1.0`. The runtime tree must contain RepoGuard plus only
the locked runtime graph required by LangGraph and the two official SDKs. Record the actual tree;
the M0-M2 expectation that it contains only RepoGuard no longer applies.

The focused suite must cover:

- frozen/slotted provider and Agent public models, exact enum values, schema versions, package-root
  exports, and canonical UTF-8 JSON;
- explicit model and API-key configuration, key-safe repr/errors, fixed official endpoints, disabled
  SDK retries, non-streaming request shape, token/timeout mapping, usage mapping, and every provider
  error code;
- exact packaged prompt resources and digest, canonical user-data fields, omitted root/ref names,
  Unicode, CRLF, special paths, malicious instruction-like source, and private-key redaction before
  the scripted provider sees a request;
- exact byte/count/text boundaries including one-under, exact-limit, and one-over cases;
- every graph node, conditional edge, three-attempt ceiling, 0.5/1.0-second backoff, per-call
  timeout, total deadline, non-retryable failures, and no checkpointer or partial result;
- duplicate JSON keys, fences, prefixes/suffixes, unknown/missing fields, bool-as-int, invalid schema
  or enums, oversized output, too many Findings/references, empty text, hallucinated paths/sides/
  lines, cross-hunk ranges, and mixed-validity atomic rejection;
- M2 preservation, model-only exact deduplication, no cross-source semantic deduplication, complete
  severity/source ordering, and local OID completion;
- a temporary local Git repository through `collect_evidence` and `review_with_agent`, with identical
  Git status and no artifact or log after success and failure; and
- socket denial proving that accidental real network use fails the test process.

Hypothesis remains deterministic with `database=None`, `derandomize=True`, and 100 bounded examples.
Properties verify:

    json.loads(agent_review_to_json(result)) == agent_review_to_dict(result)

They also verify no trailing newline, byte-stable serialization of the same result, invariance under
change/Finding/reference permutations, strict parser rejection without untyped exceptions, and that
generated secret sentinels never appear in prompt, result, error, or captured logs.

After `uv build --python 3.12`, inspect the wheel with Python 3.12 `zipfile`. Require the public and
private M3 modules plus both prompt resources. Do not invoke the broken Homebrew `unzip`.

Run the current wheel in an isolated no-cache environment with a local fake `LLMProvider`. Construct
an empty valid `EvidenceBundle`, return `{"schema_version":1,"findings":[]}` from the fake, call
`review_with_agent`, and require schema 1 plus an empty Finding tuple. Use:

    uv run --no-project --isolated --no-cache \
        --with ./dist/repoguard-0.1.0-py3-none-any.whl \
        python <documented smoke script>

This command may access the package registry for the wheel's locked dependencies but must not call a
provider endpoint.

`scripts/check.sh` remains the sole shared local/CI gate and must pass Ruff lint and format, MyPy
strict, every test, at least 90% total coverage, and Git whitespace checks. Do not alter the script
or lower any threshold. Record the final actual test count and observed coverage, including the
known M1 pipe-writer scheduling variance rather than chasing a specific percentage.

Before commit, inspect the complete diff, confirm M0/M1/M2 plans have no diff, reconcile both
reviews, stage only M3 files, and run:

    git diff --cached --check

Create the local commit:

    feat: add controlled agent review workflow

At the committed SHA, rerun the lock check, frozen sync, version command, runtime dependency tree,
shared gate, distribution smoke, and `git status --short --branch`. Require the status to report
only `## main`. Do not amend history, create a remote, or push.

## Idempotency And Recovery

Prompt rendering, deterministic review, graph construction, strict parsing, canonical
serialization, tests, builds, wheel inspection, and all validation commands are safe to rerun.
Provider calls are not inherently idempotent, but no acceptance command uses a real provider. The
official adapters expose no automatic retry beyond the explicitly bounded workflow.

Dependency resolution and lock editing are deliberate one-time M3 changes. Before repeating them,
inspect `pyproject.toml`, `uv.lock`, and Progress. `uv build` writes only ignored `dist/` output.
Temporary Git repositories, mock transports, and isolated wheel environments are disposable.

After interruption:

1. Read `AGENTS.md`, `.agent/PLANS.md`, the charter, complete M0-M2 plans, this plan, and the recovery
   runbook.
2. Inspect branch, HEAD, status, modified files, dependency metadata, and the complete diff.
3. Rerun the latest successful command recorded in Progress.
4. Compare source, tests, prompt resources, and Git state with this plan.
5. Resume at the first incomplete step and record any discrepancy before editing.

For every failure, record the exact command and complete error, current hypothesis, and a materially
changed next method in Progress. A second attempt must test a different hypothesis. After three
materially different failures without new evidence, stop repeating the operation, mark a blocker,
and continue independent work.

## Progress

- 2026-07-29: Fully read the repository instructions, ExecPlan protocol, charter, complete M0, M1,
  and M2 plans, and recovery runbook. Restored M2 at
  `6528d2347ec9c355ad8a93c09ffc956d9386b25a`; the exact lock, frozen sync, version, runtime tree,
  and shared gate passed with 122 tests and 92.96% coverage, and the worktree remained `## main`.
- 2026-07-29: Confirmed with the user the two official providers, all-core dependency strategy,
  explicit-only credentials and model selection, LangGraph requirement, atomic failure behavior,
  prompt/output/count/time budgets, retry policy, no truncation, private-key redaction, local OID
  completion, unified Finding provenance, complete severity scale, unchanged package version,
  no-live-provider acceptance, and package-registry-only network exception.
- 2026-07-29: Created this complete M3 ExecPlan as the first tracked M3 edit. Next: resolve and lock
  the approved runtime and development dependencies before adding provider or Agent code.
- 2026-07-29: `uv add langgraph openai anthropic` resolved 56 packages and installed
  LangGraph 1.2.10, OpenAI 2.49.0, and Anthropic 0.120.2. `uv add --dev pytest-socket` then resolved
  57 packages and installed pytest-socket 0.8.0. Added the confirmed compatible ranges
  `langgraph>=1.2.10,<2`, `openai>=2.49.0,<3`, and `anthropic>=0.120.2,<0.121.0`, plus the
  suite-wide socket-denial pytest option. Next: refresh the lock under those ranges and verify the
  dependency boundary before implementing public contracts.
- 2026-07-29: Refreshed and checked the lock, completed frozen sync, and added the initial provider
  contracts/adapters, prompt v1 resources, public Agent models, private prompt builder, bounded
  LangGraph workflow, and focused provider/Agent tests. The provider-only sequence passed Ruff
  lint, Ruff formatting, strict MyPy, and 32 tests after the focused corrections recorded below.
- 2026-07-29: The first integrated command
  `uv run ruff check src/repoguard/providers.py src/repoguard/agent.py src/repoguard/_prompt.py
  src/repoguard/_agent.py tests/test_providers.py tests/test_agent.py` failed with five findings:
  `_agent.py` had an unsorted import block, an unused `TokenUsage` import, a 101-character compile
  call, and duplicate pass branches; `test_agent.py` had an unused `ClassVar` import. Hypothesis:
  these are mechanical integration issues in the newly combined files. Next: collect format,
  strict-typing, and behavioral failures before applying one scoped cleanup.
- 2026-07-29: The first integrated Ruff format check failed because `_agent.py`, `_prompt.py`, and
  `test_agent.py` did not match the configured formatter in four compact layout locations.
  Hypothesis: the files were authored independently without a final combined formatting pass.
  Next: continue with strict MyPy and focused pytest, then run the formatter once across all M3
  files as part of the same mechanical cleanup.
- 2026-07-29: The first integrated strict MyPy check failed with seven `_agent.py` errors:
  `_build_graph` returned `object` so `.invoke` was unavailable; retry delay inference mixed `int`
  and `float`; three enum constructors received un-narrowed `object` values; and two casts were
  redundant after validation. Hypothesis: the strict parser needs explicit typed narrowing and the
  LangGraph compiler needs its concrete return type exposed. Next: run focused pytest to identify
  runtime failures, inspect the installed LangGraph typing surface, then patch typing and behavior
  together rather than weakening strictness.
- 2026-07-29: The first combined provider/Agent behavioral command
  `uv run pytest tests/test_providers.py tests/test_agent.py -q` passed all 76 tests in 0.73
  seconds. This isolates the first cleanup to static typing, formatting, and uncovered acceptance
  cases rather than an observed workflow runtime failure.
- 2026-07-29: After the scoped typing cleanup and formatter run, the second integrated Ruff check
  had one remaining import-group finding in `test_agent.py`: removing `ClassVar` also removed the
  blank line before third-party imports. Hypothesis: this is an isolated manual-edit artifact.
  Next: restore the import-group separator and rerun Ruff before proceeding.
- 2026-07-29: Restored the import separator. The next focused Ruff check passed, strict MyPy passed
  all six combined provider/Agent files, and the post-cleanup provider/Agent suite again passed all
  76 tests in 0.73 seconds. Next: add the planned property and Git integration coverage, then
  address review findings before the shared gate.
- 2026-07-29: Added deterministic Hypothesis properties and temporary-Git integration coverage.
  The property suite verifies canonical serialization, prompt/result invariance under change,
  Finding, and reference permutations, generated private-key redaction without input mutation, and
  atomic rejection of mixed valid/hallucinated output. The integration suite verifies both success
  and failure from `collect_evidence` through a fake provider while preserving Git status and files
  and creating no RepoGuard artifacts or logs. Focused Ruff, formatting, strict MyPy, and all six
  new tests passed.
- 2026-07-29: The first format check for the two new test files requested three layout-only
  changes. After formatting, the first property pytest run failed Hypothesis's health check because
  function-scoped `caplog` is not reset for each generated example. Hypothesis: the fixture lifetime
  could contaminate per-example secrecy assertions. Changed approach: use and remove a dedicated
  logging handler inside each generated example; the resulting six-test run passed in 2.03 seconds.
- 2026-07-29: A diagnostic focused coverage run over the four M3 modules passed 76 tests and
  measured 88% combined coverage (`providers.py` 94%, `agent.py` 90%, `_prompt.py` 98%, and
  `_agent.py` 81%). This is not the shared project coverage result and no threshold was changed;
  the uncovered lines are primarily stable failure branches that remain acceptance targets.
- 2026-07-29: The first independent read-only architecture review reproduced one high-severity and
  five medium contract defects. LangGraph inherited an enclosing LangChain/LangSmith callback
  context and exposed the raw graph input, including private-key text, to `collect_runs()`.
  `debug=False` and no checkpointer do not disable callbacks. The same review reproduced acceptance
  of surrounding JSON whitespace, two reads of a mutable/subclassed response text around the byte
  check, a second unvalidated dynamic provider-name read at finalize, successful completion after
  the total deadline, and incomplete context-shape validation that misclassified malformed
  evidence as a workflow failure. Next: add red tests for each reproduction, isolate graph tracing,
  snapshot validated provider/result data once, enforce the completion deadline and exact response
  document, and complete validation before rerunning focused acceptance.
- 2026-07-29: During that read-only snapshot, the reviewer ran the shared gate: 204 tests passed
  with 90.32% coverage. This is pre-remediation evidence, not final acceptance.
- 2026-07-29: Added minimal regressions for the first review. The targeted red command failed seven
  cases exactly as predicted: inherited run collection observed one graph run; a dynamic provider
  name changed after validation; a response subclass changed its text after the byte check; a
  successful provider call completed after its deadline; leading and trailing JSON whitespace were
  accepted; and a string `change_type` became `workflow_execution_failed` instead of
  `invalid_evidence`. The environment-tracing case unexpectedly passed, so its current monkeypatch
  does not reliably force the environment path and must be strengthened rather than counted as
  evidence. Next: correct that test mechanism, add provider completion-status red tests, then make
  the production changes.
- 2026-07-29: The provider portion of the same independent review reproduced a fail-open completion
  defect. OpenAI `status=incomplete` with `max_output_tokens` and Anthropic
  `stop_reason=max_tokens` were accepted when their partial text happened to be valid empty-review
  JSON. Next: require OpenAI `completed` and only Anthropic `end_turn` or `stop_sequence`, mapping
  every other non-refusal completion to `invalid_response` and then `invalid_model_output`.
- 2026-07-29: The first provider completion-status regression failed because OpenAI
  `status=incomplete` returned `LLMResponse` instead of raising. The first environment test only
  asserted workflow success, but LangChain catches tracer-constructor exceptions and merely logs a
  warning. Changed approach: count constructor attempts after clearing LangSmith's environment
  cache; the strengthened test failed with one attempted tracer and a warning. These are now
  reliable red reproductions for adapter completion and environment-driven tracing.
- 2026-07-29: The first combined production patch was rejected atomically by `apply_patch` because
  its evidence-validation context no longer matched the formatted file; no hunk was applied.
  Hypothesis: a single patch spanning several independently formatted regions was too brittle.
  Changed approach: apply and inspect four bounded patches for imports/state, invocation snapshots,
  evidence validation, and provider completion status.
- 2026-07-29: The bounded production patches applied. The first post-patch Ruff check found only
  two import-order issues: `unicodedata` belonged with standard-library imports and the two
  LangChain test imports were reversed. Hypothesis: these are mechanical additions not handled by
  Ruff format. Next: reorder those imports manually, then run the red regression set.
- 2026-07-29: After remediation, all 22 targeted review/provider regressions passed and the full M3
  focused suite passed 91 tests in 2.14 seconds; Ruff and format also passed. Strict MyPy then found
  two `attr-defined` errors because LangSmith's overloaded `get_env_var` type omits the
  `functools.lru_cache`-provided `cache_clear` attribute used by the environment-tracing test.
  Hypothesis: this is a third-party typing omission, not a runtime contract issue. Next: add two
  narrow `attr-defined` ignores at the cache reset calls and rerun strict MyPy.
- 2026-07-29: Two additional public-boundary red tests failed as predicted. A graph-build
  `RuntimeError` escaped with its secret text because graph construction was outside the public
  boundary, and an unknown mutated `ProviderError.code` became
  `workflow_execution_failed` at `finalize` attempt zero rather than at `invoke_provider` attempt
  one. Next: move graph construction inside the sanitized boundary and wrap conditional routing
  with the same invoke-node error mapping.
- 2026-07-29: The first deep-JSON test used 2,000 levels, which Python 3.12.3 accepted, while the
  invalid `AgentFinding.source` test failed as expected. A read-only probe established that 10,000
  levels produces `RecursionError` in only about 20 KB. After adjusting the fixture, both red tests
  failed reliably: recursion became `workflow_execution_failed`, and the bogus source constructed
  successfully. Next: classify parser recursion as invalid model output and validate public
  Finding enums before source/rule pairing.
- 2026-07-29: A further provider-shape regression failed as reproduced: an object with a valid name
  and non-callable `complete=42` passed the runtime Protocol and failed only at invoke as
  `workflow_execution_failed`. Next: snapshot and validate both provider name and completion
  callable in the validate node, and invoke only the validated bound callable.
- 2026-07-29: The final architecture review found that `raise error from None` suppresses display
  but leaves parser or provider exceptions reachable through the public error's `__context__`; a
  forged `EvidenceReference.side` can also pass `AgentFinding` construction and fail later during
  serialization. It additionally identified LangChain global debug as a possible graph-state
  disclosure path after inherited tracing isolation. Next: add regressions for detached exception
  chains and complete nested reference validation, then reproduce and either isolate global debug
  or record a precise residual risk before final acceptance.
- 2026-07-29: The resumed complete M3 focused suite passed all 122 tests in 2.31 seconds and strict
  MyPy passed all 22 source files. The matching format check found one layout-only difference in
  `agent.py`, while Ruff found only `SIM117` in the socket-denial test's nested context managers.
  Hypothesis: both are mechanical changes introduced by the latest boundary tests. Next: add the
  security regressions, combine the context managers, run the configured formatter once, and then
  rerun the full focused sequence.
- 2026-07-29: The three final security-boundary regressions failed exactly as intended. Enabling
  LangChain global debug emitted 34 lines of chain output; a forged nested reference side did not
  raise; and invalid JSON left `JSONDecodeError` reachable through the public error's
  `__context__`. Next: rebuild public errors outside the caught exception context, validate the
  nested enum, and occupy the global-debug callback slot with a local ignore-chain handler before
  rerunning these tests.
- 2026-07-29: Rebuilt public failures from stable fields after leaving the caught exception scope,
  validated nested reference sides, and supplied an ignore-chain console sentinel while preserving
  the host debug flag. Five targeted boundary tests then passed. The full post-remediation M3
  sequence passed Ruff lint and format, strict MyPy for 22 source files, and all 123 focused tests
  in 2.29 seconds. Next: document only verified M3 behavior, run distribution/shared acceptance,
  and reconcile both final independent reviews.
- 2026-07-29: Updated README with the verified M3 API and explicit credential, context, redaction,
  provider-boundary, no-live-model, no-review-CLI, and non-comprehensive-scanner limitations.
  `uv lock --check`, `uv sync --frozen`, and the version command passed; the version remains
  `repoguard 0.1.0`.
- 2026-07-29: The first final shared gate passed Ruff lint and format, strict MyPy, all 245 tests in
  6.47 seconds, 91.27% coverage against the unchanged 90% threshold, and Git whitespace checks.
  This is the observed value; no test or threshold was changed to chase the known M1 scheduling
  variance.
- 2026-07-29: Built `repoguard-0.1.0.tar.gz` and
  `repoguard-0.1.0-py3-none-any.whl`. Python 3.12 `zipfile` confirmed the wheel contains
  `providers.py`, `agent.py`, `_agent.py`, `_prompt.py`, `system.md`, and
  `response-schema.json`. An isolated `--no-cache` install from that wheel used a local fake
  provider and returned version 0.1.0, schema 1, and zero Findings from the installed
  `site-packages` copy without calling a provider endpoint.
- 2026-07-29: The exact final pre-commit runtime dependency tree from
  `uv tree --no-dev --frozen` was:

      repoguard v0.1.0
      ├── anthropic v0.120.2
      │   ├── anyio v4.14.2
      │   │   ├── idna v3.18
      │   │   └── typing-extensions v4.16.0
      │   ├── distro v1.9.0
      │   ├── docstring-parser v0.18.0
      │   ├── httpx v0.28.1
      │   │   ├── anyio v4.14.2 (*)
      │   │   ├── certifi v2026.7.22
      │   │   ├── httpcore v1.0.9
      │   │   │   ├── certifi v2026.7.22
      │   │   │   └── h11 v0.16.0
      │   │   └── idna v3.18
      │   ├── jiter v0.16.0
      │   ├── pydantic v2.13.4
      │   │   ├── annotated-types v0.8.0
      │   │   ├── pydantic-core v2.46.4
      │   │   │   └── typing-extensions v4.16.0
      │   │   ├── typing-extensions v4.16.0
      │   │   └── typing-inspection v0.4.2
      │   │       └── typing-extensions v4.16.0
      │   ├── sniffio v1.3.1
      │   └── typing-extensions v4.16.0
      ├── langgraph v1.2.10
      │   ├── langchain-core v1.5.2
      │   │   ├── jsonpatch v1.33
      │   │   │   └── jsonpointer v3.1.1
      │   │   ├── langchain-protocol v0.0.18
      │   │   │   └── typing-extensions v4.16.0
      │   │   ├── langsmith v0.10.11
      │   │   │   ├── anyio v4.14.2 (*)
      │   │   │   ├── distro v1.9.0
      │   │   │   ├── httpx v0.28.1 (*)
      │   │   │   ├── orjson v3.11.9
      │   │   │   ├── packaging v26.2
      │   │   │   ├── pydantic v2.13.4 (*)
      │   │   │   ├── requests v2.34.2
      │   │   │   │   ├── certifi v2026.7.22
      │   │   │   │   ├── charset-normalizer v3.4.9
      │   │   │   │   ├── idna v3.18
      │   │   │   │   └── urllib3 v2.7.0
      │   │   │   ├── requests-toolbelt v1.0.0
      │   │   │   │   └── requests v2.34.2 (*)
      │   │   │   ├── sniffio v1.3.1
      │   │   │   ├── typing-extensions v4.16.0
      │   │   │   ├── uuid-utils v0.17.0
      │   │   │   ├── websockets v15.0.1
      │   │   │   ├── xxhash v3.8.1
      │   │   │   └── zstandard v0.25.0
      │   │   ├── packaging v26.2
      │   │   ├── pydantic v2.13.4 (*)
      │   │   ├── pyyaml v6.0.3
      │   │   ├── tenacity v9.1.4
      │   │   ├── typing-extensions v4.16.0
      │   │   └── uuid-utils v0.17.0
      │   ├── langgraph-checkpoint v4.1.1
      │   │   ├── langchain-core v1.5.2 (*)
      │   │   └── ormsgpack v1.12.2
      │   ├── langgraph-prebuilt v1.1.0
      │   │   ├── langchain-core v1.5.2 (*)
      │   │   └── langgraph-checkpoint v4.1.1 (*)
      │   ├── langgraph-sdk v0.4.2
      │   │   ├── httpx v0.28.1 (*)
      │   │   ├── langchain-core v1.5.2 (*)
      │   │   ├── langchain-protocol v0.0.18 (*)
      │   │   ├── orjson v3.11.9
      │   │   └── websockets v15.0.1
      │   ├── pydantic v2.13.4 (*)
      │   └── xxhash v3.8.1
      └── openai v2.49.0
          ├── anyio v4.14.2 (*)
          ├── distro v1.9.0
          ├── httpx v0.28.1 (*)
          ├── jiter v0.16.0
          ├── pydantic v2.13.4 (*)
          ├── sniffio v1.3.1
          ├── tqdm v4.70.0
          └── typing-extensions v4.16.0

      (*) Package tree already displayed
- 2026-07-29: The final architecture review invalidated that first gate as delivery evidence by
  reproducing three remaining defects. A nested LangChain fake LLM inside a provider emitted 1,179
  bytes of prompt-bearing stdout under host global debug because the sentinel ignored only chain
  events; forged reference path/OID/line fields caused raw serializer `TypeError`; and a custom
  provider could throw `AgentReviewError` to forge `invalid_evidence / validate / attempt 999`.
  Next: add red regressions, ignore all sentinel callback categories, fully validate nested
  references, and catch protocol-external provider exceptions at the invoke boundary before
  repeating focused and shared acceptance.
- 2026-07-29: The independent final safety review then reproduced an explicit-credential boundary
  defect in the locked SDKs. `OPENAI_CUSTOM_HEADERS` could replace the constructor-derived
  Authorization header, while `ANTHROPIC_CUSTOM_HEADERS` could replace `X-Api-Key` or add an
  Authorization credential. Next: confirm the locked merge path, force safe explicit default
  headers in both adapters, and add environment regressions before repeating provider acceptance.
- 2026-07-29: The combined five-case red run failed exactly as required: nested `FakeListLLM`
  output contained the diff sentinel; path/OID/line forgeries were accepted; the provider's forged
  `invalid_evidence / validate / 999` escaped; and both wire requests used environment credentials
  instead of the constructor key. Next: apply the four owning-boundary fixes, then rerun this exact
  set before broader acceptance.
- 2026-07-29: Expanded the debug sentinel across all callback categories, validated every nested
  reference field, caught all protocol-external provider exceptions inside invoke, and cleared SDK
  custom headers before either client became observable. The exact five-case regression set then
  passed. Added explicit CRLF/special-path, unknown nested field, empty text, invalid side/bool,
  non-JSON constant, and five-level severity tests; that expanded set passed 27 cases. Next: check
  remaining SDK constructor side effects, then run the complete focused static/behavioral sequence.
- 2026-07-29: A new Anthropic constructor probe failed before any request because the locked base
  client called `_has_auto_discoverable_credentials`, which may inspect the default active-profile
  file even with an explicit API key. Next: instantiate a trivial official `Anthropic` subtype so
  the SDK's own non-base-client discovery gate stays closed, and retain the wire-header regression.
- 2026-07-29: The official Anthropic subtype closed the config-discovery probe and retained safe
  wire headers. The complete post-review focused behavior then passed all 137 tests in 2.53
  seconds; Ruff and strict MyPy for 22 source files passed. The format check found only two
  layout-only differences in `agent.py` and `test_agent.py`. Next: run the configured formatter and
  repeat the full focused static sequence.
- 2026-07-29: Applied the configured formatter to the two reported files. The repeated complete
  M3 sequence passed Ruff lint, formatting, strict MyPy for 22 source files, and all 137 focused
  tests in 2.64 seconds. This is the new stable review point. Next: have both independent reviewers
  re-run their reproductions, then execute the second shared and distribution acceptance.
- 2026-07-29: The second shared gate passed all 259 tests in 7.11 seconds with 91.22% coverage,
  Ruff, formatting, strict MyPy, and Git whitespace checks. Rebuilt both distributions and
  confirmed all six required wheel entries. The isolated no-cache smoke then failed before import:
  uv retried the `tenacity==9.1.4` wheel download three times and timed out. Hypothesis: this is
  package-registry latency, not wheel behavior. Changed next method: after the final rebuild,
  preserve `--isolated --no-cache` but raise uv's HTTP timeout.
- 2026-07-29: The final safety re-review cleared the prior tracing, credential, redaction,
  atomicity, parsing, and socket issues, but reproduced two provider classification gaps. HTTP 408
  and 409 from both SDKs became non-retryable `request_failed`; OpenAI response-native
  `failed/server_error`, `failed/rate_limit_exceeded`, and `incomplete/content_filter` all became
  `invalid_response`. Next: add red adapter and workflow retry tests, map only documented native
  states, and narrow README's external-side-effect statement before the final gate.
- 2026-07-29: The first patch adding the final provider regression matrix was rejected atomically
  because its insertion context expected a multiline Anthropic assertion that Ruff had formatted
  onto one line; no file changed. Hypothesis: one patch spanning both parameter tables and the
  formatted function boundary was too broad. Changed next method: apply three narrow patches at the
  exact OpenAI table, Anthropic table, and test-function boundaries, then run only the new cases to
  obtain the required red evidence.
- 2026-07-29: The targeted red command
  `uv run pytest tests/test_providers.py::test_openai_maps_known_sdk_errors_without_leaking_or_chaining
  tests/test_providers.py::test_anthropic_maps_known_sdk_errors_without_leaking_or_chaining
  tests/test_providers.py::test_openai_maps_native_response_failures -q` failed 8 cases and passed
  16. Both adapters classified HTTP 408/409 as `request_failed`; OpenAI classified
  `failed/server_error`, `failed/rate_limit_exceeded`, `failed/invalid_prompt`, and
  `incomplete/content_filter` as `invalid_response`. The `incomplete/max_output_tokens` control
  passed. Hypothesis: the adapters inspect only exception classes and top-level completion status,
  before the locked SDK's documented native detail fields. Next: share an exact HTTP status mapper,
  map only documented OpenAI error/reason literals, preserve unknown shapes as `invalid_response`,
  and rerun this same command.
- 2026-07-29: Added the shared HTTP classification and documented OpenAI native response mapping,
  then reran the exact red command: all 24 cases passed in 0.47 seconds. HTTP 408 now maps to
  `timeout`, 409 and native `server_error` to `unavailable`, native rate limits to `rate_limited`,
  policy filtering to `refused`, and known non-transient request errors to `request_failed`;
  unknown shapes and output-token incompletion remain `invalid_response`. Narrowed README's
  no-write statement to exclude only the explicit provider API call. Next: run the complete focused
  static and behavioral sequence, then obtain final read-only confirmation.
- 2026-07-29: The post-fix `uv run ruff check .` passed. `uv run ruff format --check .` then
  reported one layout-only change for the new `incomplete_details` conditional expression in
  `tests/test_providers.py`; 31 other files were already formatted. Hypothesis: the manually wrapped
  three-line expression differs from Ruff's compact layout. Next: run the configured formatter on
  that test file and repeat the complete focused static sequence.
- 2026-07-29: Formatted the one test expression. The repeated sequence passed Ruff lint and format,
  strict MyPy for 22 source files, and all 146 focused M3 tests in 2.55 seconds. The next shared gate
  passed all 268 tests in 7.12 seconds with 91.15% coverage against the unchanged 90% floor, plus
  Ruff, formatting, strict MyPy, and Git whitespace checks.
- 2026-07-29: `uv lock --check`, `uv sync --frozen`, version 0.1.0, and the frozen runtime tree
  passed. Rebuilt the sdist and wheel; Python 3.12 `zipfile` verified all six required M3 modules and
  prompt resources. The final `UV_HTTP_TIMEOUT=120` isolated, no-cache smoke installed 41 packages
  and ran the fake-provider review from `site-packages`, returning version 0.1.0, schema 1, and zero
  Findings without a provider endpoint call. Next: reconcile both final read-only reviews, complete
  Outcomes, inspect and stage the exact M3 diff, and create the one planned commit.
- 2026-07-29: The final architecture re-review found no new blocker and independently passed all
  268 tests plus callback, forged-reference, forged-provider-error, provider-status, deadline, and
  atomicity probes. The final safety re-review then invalidated the preceding gate as delivery
  evidence by reproducing a new prompt leak: with the locked OpenAI or Anthropic SDK logger at
  DEBUG, each SDK logs complete request options containing the system and user messages before its
  mocked transport runs. Hypothesis: LangGraph callback isolation does not cover provider SDK
  logging. Next: add red tests for both built-in adapters and suppress SDK request-body logging at a
  call-local, concurrency-safe boundary without changing host logger state.
- 2026-07-29: The targeted SDK-logging red command
  `uv run pytest
  tests/test_providers.py::test_openai_sdk_debug_logging_redacts_prompt_without_changing_logger
  tests/test_providers.py::test_anthropic_sdk_debug_logging_redacts_prompt_without_changing_logger
  -q` failed both cases. OpenAI logged both prompt markers inside `json_data.input` and
  `json_data.instructions`; Anthropic logged them inside `messages[].content` and `system`.
  Hypothesis: the SDK logger formats request-option mappings with the sensitive strings' `repr`
  before JSON encoding. A read-only local probe confirmed that an exact `str` subclass with a fixed
  redacted `repr` hides both markers from both SDK logs while preserving the exact bytes on each
  mocked HTTP request. Next: wrap only the two prompt strings at the SDK boundary, without touching
  logger configuration, and rerun the exact red command.
- 2026-07-29: Added the private wire-preserving prompt string wrapper. The exact red command passed
  both cases in 0.62 seconds; the complete provider suite passed 48 tests, and the tests proved both
  prompt markers absent from DEBUG logs, present on the mocked wire, and host logger level,
  handlers, filters, propagation, and disabled state unchanged. Ruff, format, strict MyPy, and all
  148 focused M3 tests then passed.
- 2026-07-29: The post-logging-fix shared gate passed all 270 tests in 7.07 seconds with 91.17%
  coverage against the unchanged 90% floor, plus Ruff, formatting, strict MyPy, and Git whitespace.
  Rebuilt the sdist and wheel, verified the six required entries with Python 3.12 `zipfile`, and
  reran the high-timeout isolated no-cache smoke: 41 packages installed and the `site-packages`
  wheel returned version 0.1.0, schema 1, and zero Findings. The safety review's prompt-log finding
  is reproduced, fixed, and guarded without a real endpoint call.

## Surprises & Discoveries

- 2026-07-29: M2 `Finding.rule_id` is deliberately closed over the six deterministic rules.
  Open-ended model Findings therefore require a new M3 type rather than extending or weakening the
  M2 contract.
- 2026-07-29: An isolated no-cache wheel smoke for M3 must install a non-empty runtime dependency
  graph. Package-registry access is therefore permitted for dependency installation even though all
  provider endpoints and real model calls remain prohibited in acceptance.
- 2026-07-29: LangGraph 1.2.10 brings LangChain Core, LangSmith, checkpoint, prebuilt, and SDK
  packages transitively even though M3 will use only `StateGraph` with no checkpoint or tracing.
  The complete runtime tree and absence of runtime network side effects require explicit review.
- 2026-07-29: Provider SDK call signatures are exposed on resource classes rather than the client
  cached properties. Adapter tests therefore inspect and monkeypatch typed SDK resource classes.
- 2026-07-29: Frozen slotted dataclasses can raise `TypeError`, rather than
  `FrozenInstanceError`, when assigning an unknown slot. Immutability tests target an existing
  field so they assert the public contract rather than an implementation-specific missing slot.
- 2026-07-29: Hypothesis function-scoped fixtures persist across generated examples. Secret/log
  properties therefore need per-example handlers or equivalent explicit cleanup rather than
  `caplog`.
- 2026-07-29: LangGraph runnable tracing is inherited from environment and parent callback context
  even when the graph has `debug=False`, no checkpointer, and no explicit tracing integration. Its
  root input contains the full graph state, so the raw EvidenceBundle crosses the tracing boundary
  before M2-based redaction unless M3 explicitly suppresses inherited tracing.
- 2026-07-29: Runtime-checkable provider and response types do not imply stable properties. Values
  used for validation, byte limits, and public results must be read once and carried through the
  invocation rather than re-read from user-supplied implementations.
- 2026-07-29: A syntactically complete JSON prefix can exist in a provider response whose generation
  status is truncated or otherwise incomplete. Strict JSON parsing alone cannot establish provider
  completion; each adapter must validate its native completion status before exposing text.
- 2026-07-29: Python's `raise ... from None` sets `__suppress_context__` but does not clear
  `__context__`. Secret-safe public errors therefore require an explicit exception-detachment
  boundary, not display suppression alone.
- 2026-07-29: Reusing an immutable M2 value object inside an M3 public model does not make its
  runtime enum members trustworthy when Python callers can forge dataclass field values.
- 2026-07-29: LangChain Core global debug is independent of LangGraph's compile-time `debug=False`.
  Its callback manager injects a `ConsoleCallbackHandler` that serializes complete graph inputs and
  outputs unless a console handler is already explicit. M3 must occupy that callback slot with a
  local discarding handler rather than mutate the process-wide host setting.
- 2026-07-29: Disabling SDK retries transfers the locked SDKs' HTTP 408/409 retry classification
  responsibility to the adapter. Without explicit mapping, otherwise retryable transient outcomes
  bypass the workflow's bounded retry policy.
- 2026-07-29: OpenAI Responses can report documented provider failures through a successful HTTP
  response with `status`, `error`, and `incomplete_details`. Top-level completion validation alone
  cannot distinguish a transient service failure, rate limit, policy refusal, and truncated output.
- 2026-07-29: Both locked SDKs emit complete request-option mappings when their private base-client
  logger is at DEBUG, independent of LangGraph and LangSmith tracing controls. Their mapping
  formatter uses each prompt string's `repr`, while JSON encoding preserves the underlying exact
  `str` value, enabling call-local redaction without logger mutation.

## Decision Log

- 2026-07-29: Use OpenAI Responses and Anthropic Messages through their official SDKs as built-in
  core providers. Reason: the user selected two real adapters rather than a protocol-only M3.
- 2026-07-29: Use LangGraph but constrain it to a synchronous, in-memory, no-tool, no-checkpoint
  graph. Reason: the user selected LangGraph while later-stage persistence, repair, and approval
  semantics remain out of scope.
- 2026-07-29: Require constructor-only API keys and explicit provider-native model IDs. Reason: M6
  owns environment and product configuration, and M3 must not introduce hidden credential sources.
- 2026-07-29: Send the complete M1 diff context up to a 131,072-byte hard limit, redact only
  M2-identified private-key ranges, and fail rather than truncate. Reason: silent partial review is
  unsafe and evaluated retrieval belongs to M4.
- 2026-07-29: Retry only transient provider failures, up to three total attempts with fixed
  0.5/1.0-second delays, a 30-second call timeout, and a 95-second total deadline. Reason: this is
  bounded, testable, and separates provider availability from invalid model output.
- 2026-07-29: Preserve all M2 Findings in a new unified provenance-aware M3 result, deduplicate only
  exact model duplicates, and resolve model OIDs locally. Reason: deterministic evidence must remain
  authoritative and model-supplied identities are untrusted.
- 2026-07-29: Keep package version 0.1.0 and make one additive M3 commit. Reason: M0-M3 are internal
  stage commits rather than release events, and history must remain intact.
- 2026-07-29: Use the locked LangGraph transitives `langsmith.tracing_context` and
  `langchain_core.tracers.stdout.ConsoleCallbackHandler` to suppress inherited tracing and global
  debug output, without declaring a fourth direct runtime dependency. Reason: LangGraph invokes
  these callback layers internally, the approved direct runtime dependencies remain exactly three,
  and tests must prove raw evidence cannot cross either inherited callback path.
- 2026-07-29: Rebuild stable public workflow errors after leaving the caught exception scope.
  Reason: `raise ... from None` affects display only, while reconstruction removes unsafe parser or
  provider exceptions from both `__cause__` and `__context__`.
- 2026-07-29: Map SDK-retryable HTTP 408 to `timeout` and 409 to `unavailable`, and classify only
  locked OpenAI response-error literals into the existing closed Provider error enum. Reason: M3's
  workflow, not either SDK, owns retries; unknown response shapes must still fail closed as
  `invalid_response`.
- 2026-07-29: Pass prompt content to each official SDK as a private exact `str` subtype whose
  `repr` is a fixed redaction sentinel. Reason: this preserves exact wire content while preventing
  locked SDK request-option DEBUG logs from recording the prompt, and unlike logger levels or
  temporary filters it is call-local, concurrency-safe, and leaves host logging state untouched.

## Outcomes & Retrospective

M3 delivers a synchronous controlled review API over immutable M1 evidence and authoritative M2
Findings. It includes frozen typed provider contracts, official OpenAI Responses and Anthropic
Messages adapters, versioned prompt/schema resources, complete bounded context with M2 private-key
range redaction, and a synchronous in-memory LangGraph with no tools, persistence, or partial
result. Strict JSON parsing resolves every model reference locally, adds the trusted OID, preserves
all M2 Findings, deduplicates only exact model duplicates, and returns stable provenance-aware
canonical JSON.

Provider execution is explicit and bounded: constructor-only credentials, caller-selected native
models, official fixed endpoints, SDK retries disabled, at most three workflow attempts, fixed
0.5/1.0-second backoff, 30-second per-attempt and 95-second total ceilings, and stable atomic error
codes. HTTP 408/409 and documented OpenAI native failures now retain their retry/refusal/request
semantics. Prompt values preserve exact wire bytes but expose only a fixed sentinel to the locked
SDK request-option DEBUG loggers; regression tests also prove host logger configuration is
unchanged. The package version remains 0.1.0. Direct runtime versions are LangGraph 1.2.10, OpenAI
2.49.0, and Anthropic 0.120.2; pytest-socket 0.8.0 remains development-only.

Final post-remediation acceptance passed Ruff lint and formatting, strict MyPy for 22 source files,
all 148 focused M3 tests, and the sole shared gate with all 270 tests. Shared coverage was 91.17%
against the unchanged 90% floor; no test or threshold was changed to chase M1 pipe-writer scheduling
variance. The lock check, frozen sync, package compatibility check, version command, runtime tree,
Git whitespace, and unchanged M0-M2 boundaries passed. Both distributions built; Python 3.12
`zipfile` found the four M3 modules and two prompt resources, and an isolated no-cache installation
ran the current wheel's fake-provider workflow from `site-packages`, returning schema 1 with no
Findings. No acceptance test called a provider endpoint or real model.

Two independent read-only reviews materially improved provider status classification, credential
isolation, prompt/tracing secrecy, dynamic protocol validation, error detachment, strict reference
shape checks, deadline enforcement, and completion-status handling. Every credible finding was
reproduced and reconciled. The final SDK DEBUG prompt leak was closed with an exact red-green
regression that also proves unchanged wire content.

Residual risk remains explicit. Only M2-identified new-side private-key ranges are redacted; old-side
or otherwise unidentified secrets may cross the configured provider boundary. A custom provider
must honor the supplied timeout and can perform behavior outside RepoGuard's no-tool graph; the
library does not preempt it in a background thread or sandbox it. Tests use mocks, so they establish
adapter request/response contracts but not live provider behavior, model quality, billing, or
provider-side retention. LangGraph tracing isolation and SDK credential/log hardening depend on
locked transitive or private APIs and must be re-audited on dependency upgrades.

M1's partial-clone, missing-object, size-limit, linked-worktree, alternates, descriptor-path, and
ordinary-filesystem risks remain. M2 still scans only additions and head metadata, is not a complete
security scanner, has no input or Finding-count limit, and retains its documented worst-case
complexity. GitHub-hosted CI and external CVE or maintainer-health audits have not run. M3 adds no
retrieval, embeddings, repair, worktree isolation, GitHub product flow, new CLI workflow, benchmark,
training, frontend, deployment, or monitoring behavior from M4 or later stages. M0-M2 history,
plans, public interfaces, package-root exports, and the version-only CLI remain unchanged.
