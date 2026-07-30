# M6: Product Interfaces

Status: in progress

This is the tracked, self-contained ExecPlan for M6 and follows `.agent/PLANS.md`. It is the first
tracked change after the completed M5 baseline. The M0 through M5 plans and the M5 commit are
immutable historical records unless a newly reproduced M5 correctness defect requires a separately
recorded decision.

## Purpose And Observable Outcome

M6 turns the M1-M5 library capabilities into bounded product interfaces without duplicating their
core logic. It delivers one shared product orchestration layer, a canonical command-line interface,
three GitHub composite actions, and a stdio MCP server built with the official `mcp==2.0.0`
`MCPServer`. Review remains read-only by default. The only active GitHub writes are an exactly
approved review Check Run and an exactly approved repair publication to a fixed absent-only branch
followed by a draft replacement pull request.

The observable result is:

- `repoguard` exposes strict schema-1 product/profile/result/envelope contracts while the package
  root continues to export only `__version__`;
- CLI, Actions, and MCP call shared product orchestration and public M1-M5 APIs, never private
  `_repair_*` modules;
- every product review is bounded atomically and produces a path-free `ProductReviewResult` with
  evidence, deterministic-review, and combined-review digests plus stable repair target IDs that
  map to exact M2 finding/reference coordinates;
- owner-only host profiles bind repository aliases and GitHub identities to fixed executables,
  state roots, policies, validation argv, path prefixes, cache capabilities, and writer switches;
- local M5 approval/application remains a distinct record and authorization domain from GitHub
  publication;
- GitHub proposal, approval, and result records use domain-separated digests and persistent
  compare-and-swap state; publication is resumable without treating artifacts as authoritative;
- composite Actions enforce trusted-event, runner, permission, checkout, artifact, approval, and
  expression boundaries; and
- wheel/sdist, isolated CLI/MCP, full quality gate, locked-image, extracted-wheel rootless-Docker,
  and real GitHub acceptance prove the supported interface behavior.

M6 does not add a web frontend, GitHub Enterprise support, comments, review verdicts, labels,
threads, mutation of the source PR branch, force push, branch deletion, merge, automatic merge,
benchmarking, training, or dependency decomposition.

## Restored M5 Baseline

The immutable M5 baseline is the single commit
`ae8d0992a593ee9940ba9446bd6ff8680dd78593`, with exact parent
`a5f8dce4a71f80cdf6532ff0a91d2989aa51abf1` and subject
`feat: add safe repair workflow`. M6 began with no remote, only `refs/heads/main`, and exact:

    git status --short --branch
    ## main

The completed M5 tracked plan records ALL PHASES COMPLETE (6/6), 30/30 fixed workflow cases,
699/699 focused M5 tests, 1,185/1,185 shared tests at 90.21% coverage, and all seventeen
deterministic Hypothesis properties at exactly 100 passing examples each. It also records passing
Ruff, formatting, strict MyPy, Git whitespace, Python 3.12 wheel/sdist build, package/resource byte
inspection, Git object/ref invariants, local locked-image verification, and an extracted-wheel real
rootless-Docker propose/preview/approve/apply workflow. The accepted repository-owned image is
`sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846`
with config digest
`sha256:102ecfd6432e305a8dbbaecd6ede090a93259dde2c6356e04f55c1ba3bf38be3`.

Before this file was created, M6 reran the previous-stage gate on the exact final SHA. `uv lock
--check` resolved 74 packages, `uv sync --frozen` audited 72 installed packages,
`python -m repoguard --version` returned `repoguard 0.1.0`, and `./scripts/check.sh` passed Ruff,
formatting for 84 files, strict MyPy for 70 source/test files, Git whitespace, and all 1,185 tests in
188.89 seconds. The fresh coverage display was 90.20%, still above the unchanged 90% gate; the
historical exact M5 acceptance display remains 90.21%. Git remained exact `## main` afterward.

## Trust Boundaries And Global Constraints

Repository contents, PR metadata, Git objects, diffs, provider responses, MCP clients, GitHub API
responses, workflow inputs, downloaded artifacts, persistent state, and process output are
untrusted data. Host profiles, fixed local executable paths, protected-environment approval, and
the authenticated human principal are trusted only after their exact boundary checks. Tool
annotations are client hints and never authorization.

All product operations use one schema-1 envelope with exact fields:

    schema_version, operation, ok, result, error

Successful envelopes have a concrete result and no error. Failed envelopes have no result and an
error with exact fields:

    domain, code, message, retryable, stage, state, session_id,
    proposal_sha256, attempt_count

The product layer retains stable lower-layer enum values and disambiguates them with `domain`.
Messages are fixed and content-free: no absolute path, repository content, diff, prompt, model
response, validation output, credential, token, native exception, transport body, or GitHub payload
may cross the envelope boundary.

Canonical product JSON is UTF-8 with sorted keys and compact separators, has no BOM or trailing LF,
and rejects duplicate keys, NaN/infinity, unknown fields, non-exact scalar types, invalid UTF-8,
surrogates, and trailing or leading bytes. CLI stdout writes exactly the canonical envelope plus one
LF. Successful commands write nothing else to stdout; diagnostics never contain secrets or private
payloads.

Exit codes are fixed:

    0   success
    2   CLI syntax
    3   profile or request invalid
    4   non-retryable business failure
    5   authentication or approval failure
    6   operation completed but policy or validation did not pass
    7   stale identity or CAS conflict
    8   capability unavailable
    70  internal error
    75  retryable failure

Secrets are read only from `REPOGUARD_OPENAI_API_KEY`, `REPOGUARD_ANTHROPIC_API_KEY`, and
`REPOGUARD_GITHUB_TOKEN`. M6 supports no dotenv, profile secret, argv token, SDK ambient
credential discovery, custom GitHub endpoint, or secret-bearing persistent value.

## Shared Product Contracts

Add optional `EvidenceCollectionLimits` to M1 collection while preserving byte-for-byte behavior of
existing `collect_evidence()` callers that omit it. Product entry points always use exact ceilings:

    changed files             1,000
    bytes per blob            2 MiB
    aggregate blob bytes      64 MiB
    diff bytes                16 MiB
    materialized diff lines   131,072
    findings                  1,000
    canonical result bytes    4 MiB
    Git operation deadline    60 seconds

Crossing a ceiling fails the complete operation. No blob, diff, finding, or result is truncated.
Deadlines include subprocess completion and bounded stream draining. Existing M1 behavior and
serializers remain unchanged when limits are absent.

`ProductReviewResult` is immutable, schema 1, and contains no absolute path. It binds the canonical
path-free repository/revision identity, `evidence_sha256`, `deterministic_review_sha256`,
`review_sha256`, unified deterministic and optional model findings, policy/provider identity, and
counts/conclusion needed by product consumers. It has an independently strict canonical serializer.
The deterministic and combined review digests are distinct domains even when their canonical data
is otherwise equal.

A stable `repair_target_id` is emitted only for a deterministic M2 finding reference. It is a
domain-separated digest that binds the exact deterministic review digest and exact M2
`(finding_index, reference_index)` coordinates. Resolution revalidates the digest and maps it back
to that exact Finding/reference. Model findings are review-only and can never be repair targets.

Add a public read-only publication-manifest/blob capability for an APPLIED M5 session. The manifest
is obtained through the public M5 facade and, under the existing session lock and path guards,
revalidates the application digest, exact candidate, approval, parent, tree, commit, and every
changed path/mode/blob OID/size. A caller can request each blob by authenticated manifest identity;
the bytes are returned individually in memory and never enter JSON, proposal artifacts, state logs,
workflow outputs, or diagnostic text. No product module imports a private M5 module.

## Host Profile

The schema-1 host profile is an external, owner-only capability. Its path is absolute, outside every
reviewed repository, at most 1 MiB, and opened with no symlink traversal. The file is owned by the
current effective UID and is a single-link regular file at exact mode 0600. Path components are
descriptor-traversed, root/current-euid owned, and non-writable by group/world; the only writable
ancestor exception is a root-owned sticky namespace such as `/tmp`. State directories are exact
mode 0700, owner-only, outside reviewed repositories and Git common directories, and guarded with
descriptor-relative traversal.

The strict profile maps repository aliases to absolute local repository paths and fixed GitHub
repository ID/full-name identities. It also defines absolute executable paths, state roots, named
review policies, named repair generation/validation policies, optional M4 cache capabilities,
trusted validation argv, allowed repair path prefixes, fixed runner labels, and separate MCP GitHub
writer switches. Unknown or missing fields, duplicate names, relative paths, overlapping aliases,
untrusted executables, unsafe state roots, and policy values over library ceilings reject the whole
profile.

Profiles contain no credentials. Repository parameters at CLI and MCP boundaries are aliases only;
an arbitrary client-supplied path is never accepted.

## Shared Orchestration

Implement a typed orchestration layer owned by M6. Every interface calls it rather than composing
M1-M5 independently. It performs profile resolution, bounded evidence collection, deterministic M2
review, optional M3 review and M4 context construction, path-free result projection, target-ID
resolution, M5 manager/session operations, proposal construction, authorization checks, and stable
error mapping.

`repair prepare` is one synchronous orchestration call. In one process it collects evidence, runs
M2, optionally constructs/uses a live M4 `ContextIndex`, creates the M5 session, proposes,
validates, and returns the redacted preview. This preserves the live M4 capability that cannot be
recovered across independent CLI processes. Open/status/preview/decision/application operations
use persistent M5 state through its public facade.

M5 local approval/application and M6 GitHub publication are separate immutable records with
separate confirmation strings and principals. A local M5 approval never authorizes a GitHub write;
a GitHub approval never silently changes an existing M5 record.

## CLI

Keep no-argument behavior and `python -m repoguard --version`. Add the `repoguard` console script.
Except for help and version, every command requires `--profile ABS_PATH --repository ALIAS` and
prints only the canonical schema-1 envelope:

    profile validate
    review run --base-ref REF --head-ref REF --review-profile NAME [--github-pr N]
    repair prepare --base-ref REF --head-ref REF --repair-profile NAME \
      --target ID... --allow-path PATH... [--github-pr N]
    repair status --session-id ID
    repair preview --session-id ID
    repair approve-local --session-id ID --candidate-id ID \
      --validation-sha256 ID --confirmation TEXT
    repair apply-local --session-id ID --approval-sha256 ID
    repair reject --session-id ID ...
    repair cancel --session-id ID ...
    repair expire --session-id ID
    repair recover
    repair cleanup
    github publication status --proposal-sha256 ID
    github publication recover --proposal-sha256 ID
    github publish-check --proposal-sha256 ID --confirmation TEXT
    github publish-repair --proposal-sha256 ID --confirmation TEXT
    mcp serve

Argparse syntax errors use exit 2 and stderr only. A parsed invocation, including a rejected profile
or request, emits exactly one envelope on stdout and exits through the stable mapping above.

## MCP Server

Use the official direct dependency `mcp==2.0.0` and its `MCPServer`. Transport is stdio only. The
fixed tool set is:

    review_run
    repair_prepare
    repair_status
    repair_preview
    repair_apply_local
    repair_reject
    repair_cancel
    github_publish_check
    github_publish_repair

Repository arguments are profile aliases. MCP responses contain the same envelope data as CLI,
without CLI's trailing-LF concern. Tests cover initialize, list, call, cancellation, EOF, concurrent
requests, and shutdown recovery.

`repair_apply_local` and both GitHub writer tools require MCP elicitation/input-required multi-turn
confirmation. The displayed confirmation binds the exact candidate/validation/approval or proposal
identity. A client without elicitation support, a refusal, cancellation, mismatched reply, timeout,
or disconnect causes zero write. GitHub writer tools are registered only when the startup profile
explicitly enables the respective writer and `REPOGUARD_GITHUB_TOKEN` is present. Tool annotations
describe side effects but never replace authorization.

## Composite GitHub Actions

Add three composite actions with string-only inputs and outputs.

The root `action.yml` review action accepts repository path (default `.`), PR number, exact base/head
SHA, mode (default `deterministic`), provider (default `none`), model, cache directory, device
(default `cpu`), and `fail-on` (default `high`). It emits result/evidence/review/proposal path and
digest, artifact ID/digest, finding count, highest severity, and conclusion.

`actions/repair/action.yml` accepts PR number, exact base/head SHA, repair profile name, a canonical
target-ID array, and a canonical allowed-path array. It emits proposal/artifact identities,
candidate, validation, commit, and state.

`actions/publish/action.yml` accepts kind (`check` or `repair`), proposal digest, source run and
attempt, artifact ID/digest, and the exact confirmation. It emits stable publication/result
identities and state.

Every external Action `uses:` value is pinned to a complete 40-hex commit SHA. Checkout always sets
`persist-credentials: false`. No workflow uses `pull_request_target`, interpolates PR-controlled
expressions into a shell, executes PR scripts, restores privileged cache/private state from an
artifact, or permits rootful/privileged Docker fallback.

Automatic `pull_request` supports deterministic M1/M2 only and requires all provider secret
environment variables to be empty. M3/M4 run only from a default-branch `workflow_dispatch` with
explicit provider/model and offline cache; they never consume pull-request workflow secrets.

Repair and publication run only on a unique exact label set for a persistent self-hosted Linux
x86_64 runner. It uses a frozen offline Python environment, fixed owner-only source/runtime roots,
rootless Docker, and the locked local image. M5 sessions, Git packs, private payloads, and validation
logs are never exported to or restored from artifacts.

## GitHub Proposal And Approval

The proposal artifact is named exactly
`repoguard-proposal-v1-<proposal-sha256>`, retained one day, and contains only one canonical
`proposal.json`. A review artifact contains only escaped findings intended for publication. A
repair artifact contains the redacted M5 preview but no session ID, EvidenceBundle, provider
prompt/response, validation logs, Git objects, or runtime files. Persistent runner state remains the
authority for `proposal_sha256 -> session_id` and every repair transition.

Proposal, approval, and result use domain-separated digests:

    repoguard.m6.github_proposal.v1\0
    repoguard.m6.github_approval.v1\0
    repoguard.m6.github_result.v1\0

The proposal binds GitHub repository ID/full name, PR number, exact base/head, origin, 24-hour
expiry, selected profile, review or candidate/validation/preview identities, and the final bounded
payload. Approval binds proposal, authenticated actor, permission, interface, exact confirmation,
and approval time. Result binds proposal, approval, M5 application identity where applicable, and
complete GitHub read-back identity.

Exact confirmation strings are:

    I approve publishing this exact RepoGuard review as a GitHub Check Run.

    I approve publishing this exact RepoGuard repair commit to its dedicated branch and draft pull request.

M5's existing local confirmation remains unchanged. A stronger authenticated M6 repair approval is
persisted independently; the adapter then uses the authenticated actor and original M5 confirmation
to perform the exact local approve/apply steps before any GitHub publication.

Action publication requires a new `workflow_dispatch` carrying exact proposal/artifact identities
and exact confirmation. The job uses the fixed `repoguard-publish` protected environment with a
required reviewer and prevent-self-review. Runtime checks require run attempt 1, actor equal to
triggering actor, and repository permission `write`, `maintain`, or `admin`. CLI/MCP use the same
two-phase proposal plus exact confirmation and recheck the token principal and permission.

## GitHub Publication

The transport is fixed to `https://api.github.com` and the selected fixed API version. It refuses
redirects and bounds connect/read/total time, request bytes, response bytes, JSON depth, and list
counts. It uses only `REPOGUARD_GITHUB_TOKEN`; SDK ambient discovery and custom endpoints are
disabled.

Map 401, 403, 404, 409, 422, 429, 5xx, malformed responses, and ambiguous timeout to stable public
errors. A timed-out write is never blindly retried: read back the exact deterministic identity first
and either converge, report a foreign conflict, or return retryable ambiguity.

The Check Run name is exactly `RepoGuard review` and binds the exact head SHA. Its `external_id` is
derived from repository, head, review, and policy digests. Model text is rendered as escaped plain
text with mentions disabled. The summary fits 60 KiB. Annotations are stably sorted by severity,
sent in pages of at most 50, total at most 1,000, and explicitly report omitted count. The complete
canonical result remains in the proposal artifact.

Repair publication supports same-repository pull requests and GitHub SHA-1 only. It uploads each
authenticated changed blob from the public M5 publication capability, creates an incremental tree
against the exact PR head tree, and creates the fixed M5 commit. Every returned GitHub OID must equal
the local manifest identity. Blobs exist only in one bounded in-memory request and are never logged
or serialized into product state.

After exact commit read-back, create only
`refs/heads/repoguard/repairs/<candidate-id>` with absent-only semantics, then create one draft
replacement PR containing a fixed marker. Branch state is `absent`, `same`, or `foreign`; foreign is
never overwritten. A successful branch followed by failed PR creation is a persistent partial state
that only the same approval can resume. Base/head/PR drift, a closed or foreign replacement PR, or a
post-create race stops publication without deleting an already authorized branch.

Check first-creation idempotency is scoped honestly to workflow concurrency, one persistent
publisher, and a local lock. M6 does not claim exactly-once behavior across uncoordinated publishers.

Forks support read-only review and step summary only. They do not create custom Checks or repair
branches/PRs.

## Implementation Sequence

1. Maintain this ExecPlan before every meaningful implementation boundary.
2. Add strict canonical JSON, envelope, profile, limits, path-free result, and target-ID contracts.
3. Extend M1 with optional atomic limits and M5 with the public read-only publication capability;
   preserve all existing defaults and public behavior.
4. Implement shared orchestration and focused unit/property tests.
5. Implement CLI commands and subprocess contract tests.
6. Lock `mcp==2.0.0`, implement stdio MCP with conditional writer registration and elicitation, and
   test protocol lifecycle, cancellation, concurrency, and zero-write rejection.
7. Implement proposal/store/approval records, bounded GitHub transport, Check publication, repair
   publication, read-back convergence, and partial recovery with fake-transport tests.
8. Add the three composite actions and representative workflows; statically audit permission,
   injection, full-SHA pin, checkout credential, cache/artifact, event, environment, and runner
   boundaries.
9. Build and inspect wheel/sdist; run isolated installed CLI/MCP smoke, full shared gate, locked-image
   verification, and extracted-wheel real-rootless-Docker repair.
10. Perform independent API/state, MCP/CLI, GitHub transport/publication, and Actions/security
    reviews. Reproduce and close every credible finding without weakening a gate.
11. Stage exactly M6, run staged gates, create one `feat: add product interfaces` commit whose parent
    is the exact M5 SHA, and rerun all local acceptance against the resulting exact SHA.
12. Run the real same-repository and fork GitHub acceptance with every `uses:` pinned to the final
    M6 SHA. Restore no remote, only `main`, and exact `## main` afterward. M7's first tracked
    ExecPlan, not this self-referential commit, records final M6 SHA/run URLs/evidence.

## Verification And Acceptance

Unit and property coverage includes strict JSON/profile parsing, digest-domain isolation, every CAS
field mutation, exact limit boundaries, target-ID forward/reverse mapping, proposal expiry,
permission/confirmation checks, and proof that secrets cannot enter error, argv, log, envelope,
artifact, or persistent state. New Hypothesis properties use deterministic settings and exactly 100
passing examples each.

CLI/MCP coverage includes subprocess exit/stdout/stderr, malformed and over-limit arguments, stdio
initialize/list/call/cancel/EOF, concurrency, shutdown recovery, conditional writer registration,
and elicitation refusal/unsupported/cancel/disconnect with zero writes.

GitHub/Action coverage uses a fake transport for every HTTP classification, timeout plus read-back,
Check create/update, annotation batching, same/foreign/absent branch, draft PR, post-branch partial
recovery, and stale CAS. Static tests inspect workflow permission scopes, event restrictions,
expression-to-shell flow, complete SHA pins, credential persistence, protected environment, runner
labels, and cache/artifact boundaries.

The local commands include, at minimum:

    uv lock --check
    uv sync --frozen
    uv run python -m repoguard --version
    uv run repoguard --version
    uv run pytest <focused M6 modules>
    ./scripts/check.sh
    git diff --check
    uv build --python 3.12
    ./scripts/manage-repair-image.sh verify /run/user/$(id -u)/docker.sock
    git status --short --branch

Inspect wheel and sdist with Python 3.12 structured archive APIs. Require the console entry point,
MCP/product/GitHub modules, all M1-M5 schema and resource bytes, exact dependency metadata including
direct `mcp==2.0.0`, no bytecode/private runtime data, and source/archive byte identity. Install the
wheel into an isolated environment and smoke both CLI and stdio MCP. Run an extracted-wheel repair
through the locked local image and rootless Docker, proving exact commit/branch identity, terminal
cleanup, and unchanged source repository state.

Real GitHub acceptance uses a disposable dedicated GitHub.com repository and its fork. Every
`uses:` is pinned to the complete final M6 SHA. It proves hosted fork and same-repository review,
approved Check, permission failure, stale head, repeat idempotency, foreign branch refusal,
self-hosted deterministic repair, partial recovery, and exact branch/commit/draft PR. It must record
run URLs and read-back identities, then remove the source repository remote and restore only `main`
with exact `## main`.

If the environment lacks a GitHub token, protected environment, independent approver, or qualifying
self-hosted runner, record `local implementation accepted, GitHub acceptance pending`. That state is
not M6 completion and does not authorize M7.

## Idempotency And Recovery

Canonical serialization/digests, profile validation, read-only review, proposal construction,
status/preview, archive inspection, static workflow audit, fake transport tests, and local image
verification are safe to rerun. Evidence and result ceilings fail atomically.

Every active operation writes an intent before a potentially ambiguous external action and performs
exact read-back before retry. Local locks serialize publication for the supported topology.
Proposal/artifact identity, approval identity, branch state, Check identity, commit OIDs, and PR
marker are immutable CAS fields. A retry with the same identities converges; any changed identity
stops as stale/foreign. Authorized branch creation is never rolled back merely because PR creation
failed.

After interruption, read this plan and current Git state, rerun the latest recorded command, inspect
only persistent owner-only state through public status/recovery operations, and resume the first
incomplete phase. Never reconstruct M5 private payload from an artifact and never repeat an
ambiguous GitHub write without read-back.

## Progress

- 2026-07-30: Restored exact clean `main@ae8d0992...`, confirmed its exact parent/subject, only
  `refs/heads/main`, and no remote.
- 2026-07-30: Read the complete project charter, repository/ExecPlan protocols, and completed M5
  tracked plan. The terminal M5 evidence agrees with current history.
- 2026-07-30: Reran frozen resolution/sync, version smoke, and the unchanged shared gate before the
  first tracked M6 edit. All 1,185 tests and the 90% coverage gate passed; Git remained clean.
- 2026-07-30: Created this file as the first tracked M6 modification. Next: finish public-boundary
  archaeology, add shared contracts and red tests, and update this section before implementation
  moves to CLI/MCP.
- 2026-07-30: Added strict canonical JSON primitives plus public schema-1 product operation/error/
  envelope, path-free review/finding/reference, domain-separated evidence/review/target digests, and
  exact target resolution. Focused Ruff, formatting, strict MyPy, and 12/12 product tests pass.
- 2026-07-30: Added the strict owner-only host profile contract. It parses existing M5 generation
  and validation policies rather than duplicating them, rejects unknown/noncanonical/duplicate/
  secret fields, validates aliases and GitHub identity, and authenticates profile, executable,
  socket, state, cache, and repository path capabilities. Focused static checks and 12/12 profile
  tests pass. Next: integrate atomic M1 limits and the public M5 publication capability, then run
  shared-contract property and regression coverage.
- 2026-07-30: Added four shared-contract Hypothesis properties, each observed at exactly 100 passing
  examples; the combined product/profile/property set passes 38 tests. The shared product facade and
  orchestration also pass a fresh focused Ruff, format, and strict-MyPy check.
- 2026-07-30: Received the public M5 APPLIED publication manifest/blob implementation for independent
  review. M1 limits review reproduced deadline/cleanup and immutable-input snapshot defects plus an
  undocumented raw-path ceiling; those defects remain open and the limits work is not yet accepted.
  Next: close and verify those findings, add orchestration behavior coverage, then integrate CLI/MCP.
- 2026-07-30: Added five real temporary-Git shared-orchestration tests covering path-free review,
  policy exit 6, unknown alias/profile, invalid ref, and missing provider credentials. Focused pytest,
  Ruff, format, and strict MyPy pass. Product review must still be wired to the profile's exact Git
  executable before this boundary is accepted.
- 2026-07-30: Closed and independently replayed the M1 limits findings. The bounded path snapshots
  its limits, binds an explicit fixed Git executable, strips `REPOGUARD_*`, bounds nonblocking pipe
  cleanup, and preserves legacy omission behavior. The 57-test limit module reports one Hypothesis
  property at exactly 100 examples; the combined evidence regression passes 69 tests.
- 2026-07-30: Locked and installed official `mcp==2.0.0` in a 94-package resolution and added the
  `repoguard` console entry point. Added the shared approve-and-apply operation required to make the
  fixed MCP tool catalog complete from a validated repair session.
- 2026-07-30: Added immutable canonical GitHub proposal, approval, and result contracts. They bind
  the exact 24-hour expiry, repository/PR/base/head/origin/profile/payload, authenticated actor and
  permission, exact interface confirmation, local application identity, and GitHub read-back with
  three distinct digest domains. Fifteen focused tests and targeted static checks pass.
- 2026-07-30: Independent security review reproduced profile executable trust, overlapping mutable
  capability, symlink-blob accounting, MCP reachability, CLI stdio, oversized MCP result, and GitHub
  read-back semantic-CAS defects. Closed the profile and evidence defects with regression tests;
  the affected product/GitHub/profile/limit set passes 115 tests and the limit property again reports
  exactly 100 examples.
- 2026-07-30: Added strict complete `ProductReviewResult` parsing for Check proposals and bound the
  embedded result to the exact proposal base/head. GitHub publication Results now revalidate
  repository, head/external/conclusion or branch/commit/base/head/marker/draft/open identities
  against the complete proposal during construction and deserialization. Wired CLI `mcp serve` to
  the official stdio server without contaminating its JSON-RPC stdout. The affected CLI/GitHub set
  passes 83 tests and targeted Ruff, format, and strict MyPy.
- 2026-07-30: Closed the newly exposed M4 Git capability defect. Public context-index construction
  accepts an optional fixed executable, every retrieval Git environment removes `REPOGUARD_*`, and
  both product retrieval call sites pass the authenticated profile executable. Fifty-five focused
  retrieval/product tests and targeted static checks pass.
- 2026-07-30: Independently reviewed the fixed GitHub.com transport and rejected decoded path
  separators in addition to redirects, proxy/ambient auth, unsafe TLS logging, unbounded JSON, and
  automatic retries. Ninety-seven transport/contract tests and targeted static checks pass. Added
  early repair path validation and public fixed M5 publication commit identity; 31 product and 50
  M5 publication/model regressions pass.
- 2026-07-30: Independently accepted the official MCP v2 stdio implementation. Local apply performs
  an exact VALIDATED-state CAS before official input-required confirmation, rechecks through the
  shared approve/apply operation, and every refusal/unsupported client/drift path is zero-write.
  Oversized or unstructured tool failures become bounded schema-1 errors. MCP middleware also
  rejects malformed, traversal, `.git`, oversized, duplicate, and unsorted repair authority before
  product work. Thirty-five MCP tests plus focused static checks pass.
- 2026-07-30: Added fixed runner labels to the strict host schema and require the standard
  `Linux`, `X64`, and `self-hosted` capabilities plus a canonical custom label. The combined host
  profile, product orchestration, and MCP regression passes 61 tests. GitHub payload builders,
  owner-only publication state, and three composite Actions are undergoing final review before the
  approval-bound publisher is connected.
- 2026-07-30: Added and independently reviewed bounded GitHub proposal payloads, fixed-host
  transport, persistent proposal/approval/result state, and approval-bound Check/repair publication.
  The combined contract/store/transport/publication set passes 186 tests; an independent publication
  review found no confirmed defect. A separate state-store review found lock-replacement,
  root-opening TOCTOU, and missing-repair-binding fail-closed gaps, which are being corrected before
  the store is accepted.
- 2026-07-30: Connected exact source-PR read-back, same-repository proposal creation, fork read-only
  review, publication status/recovery, and approved writers through `ProductOrchestrator`, CLI, and
  MCP provenance. Product/CLI/MCP focused regression passes 105 tests. Check proposals can cross
  from a hosted producer to the persistent publisher only through an Action-only, canonical,
  current-euid, single-link, mode-0600 bounded file import; repair artifacts remain non-authoritative.
- 2026-07-30: Added all three composite Actions and their fixed Python driver. Fork review emits
  only path-free review records and an escaped, mention-disabled summary; same-repository review and
  repair emit exact proposals; publisher metadata preflights source run/attempt and artifact
  identity before accepting one canonical file. Static review caught and fixed an integration bug:
  review/repair now require a GitHub token for source-PR read-back while accepting exactly the
  selected provider secret. The updated Actions/Product CLI subset passes 95 tests.
- 2026-07-30: Accepted the corrected publication store after independent replay. A state-root inode
  lock now survives named-lock replacement, root traversal is descriptor-relative with
  `O_NOFOLLOW`, and an existing repair proposal with no private binding fails closed. The combined
  store/publication set passes 72 tests; a wider 353-test GitHub/product/Action regression plus
  targeted Ruff, formatting, and strict MyPy also passes.
- 2026-07-30: Closed two Action audit findings. Product subprocesses now receive only a fixed
  locale/isolation environment plus the three exact RepoGuard credential names, and artifact
  preflight reads the source run's latest state so any run whose current attempt is not exactly one
  is rejected. The repository CI no longer executes the pull-request worktree's `check.sh`; static
  workflow coverage checks SHA pins, checkout credential persistence, and PR-expression flow.
- 2026-07-30: Fresh package verification built an 88-member wheel and 90-member sdist, matched all
  64 package files and 23 resources byte-for-byte, verified RECORD and ten runtime requirements
  including exact `mcp==2.0.0`, and passed seven package tests. A wheel-first frozen-dependency
  environment passed console and repeated real stdio MCP smoke; the locked image verified without
  pull and a fresh-wheel rootless-Docker repair reached APPLIED with no source-state mutation or
  residual container. This evidence is preliminary because the pending runner-trust correction
  changes package bytes and requires a final rebuild/replay.
- 2026-07-30: Independent resource review found that a newline-dense diff within the 16 MiB raw-byte
  ceiling can expand into hundreds of megabytes of per-line Python objects before the product result
  ceiling is checked. The bounded collector is adding an explicit aggregate diff-line ceiling,
  single-pass bounded parsing, and enforcement properties; the legacy no-limits path remains
  unchanged.
- 2026-07-31: Closed the diff amplification finding with an exact 131,072 materialized-line ceiling,
  single-pass bounded parsing, and real N/N+1 plus dense/aggregate memory regressions. The legacy
  no-limits parser remains unchanged; the two limit properties each run exactly 100 examples.
- 2026-07-31: Closed three publication-interface findings. Action writers now bind the protected
  workflow actor to the token `/user` principal on initial, recovery, and idempotent read-back
  paths; a canonical result may be exactly 4 MiB while its separately bounded envelope carries the
  schema wrapper; and product `repair status`/`preview` use a public shared-lock reader that neither
  initializes runtime storage nor repairs a stale cache. The affected GitHub/product/Action,
  product/MCP, and M5/product regressions pass 95, 100, and 174 tests respectively.
- 2026-07-31: Replaced pathname-only host validation with descriptor-relative protected-ancestor
  traversal, full profile metadata/torn-read checks, and a bounded recursive publisher-package
  scan. The self-hosted bootstrap now executes the final-SHA-pinned bundle driver first, requires
  its bytes to match the fixed local driver, authenticates exact owner-only runtime/source/package
  capabilities before product import, and only then switches to the frozen local Python/driver.
  Host/Action focused regression passes 109 tests.
- 2026-07-31: Reran repository-wide Ruff, format-check, and strict MyPy for 95 source/test files,
  then a 570-test M6 cross-module suite covering limits, M5 publication, profile, MCP, product,
  GitHub, Actions, and retrieval; every check passed. Next: run the full shared gate and final
  package/image/rootless-Docker replay on the resulting source state.
- 2026-07-31: The first terminal full-gate replay passed Ruff, formatting for 110 files, strict
  MyPy for 94 source files, and all 1,728 tests in 224.14 seconds, but correctly failed its unchanged
  coverage gate: 19,250 measured statements with 2,202 misses yielded 88.56%. This is not accepted
  full-gate evidence. Coverage-focused behavior tests are being added for the unexercised product
  orchestration and GitHub publication/recovery branches before the whole gate is repeated.
- 2026-07-31: Independently replayed the six M6 Hypothesis properties after reviewing them for
  tautology, vacuity, assertion strength, input breadth, shrinking, and determinism. The 73-test
  focused run passed, and every property reported exactly 100 passing and zero failing examples.
- 2026-07-31: Final independent code review reproduced three additional boundary defects and they
  were closed with red/green regressions. Host capabilities now exclude an external linked-worktree
  or separate Git common directory discovered by the fixed Git executable in a minimal
  credential-free environment; MCP exceptions after handing stdout to the stdio server return 70
  without emitting a CLI envelope; and wrapped GitHub publication errors preserve exact
  publication, transport, store, or repair product domains.
- 2026-07-31: Added 110 behavior/security coverage cases for product orchestration, CLI/MCP,
  GitHub contracts/publication/store/transport, and host filesystem failures. Expanded package
  regression to require exact `mcp==2.0.0`, package-root `__all__`, all M6 modules, the console
  entry point, and byte identity for every non-bytecode source package/resource file in wheel and
  sdist. The fresh full gate now passes Ruff, formatting for 112 files, strict MyPy for 96 source
  files, all 1,844 tests in 221.31 seconds, `git diff --check`, and the unchanged coverage gate at
  90.28%.
- 2026-07-31: Final pre-commit package acceptance built an 88-member wheel and 90-member sdist with
  SHA-256 identities `ad4ba0c6f1869149c5c98a80774846351c9a3e4efaba33c296c305c76bd0001b`
  and `4609741a0c9ca1326c9f9c32dfded92e109ed8f872b5ffcb5af7725367ab85dc`.
  All 64 non-bytecode package files matched both archives byte-for-byte; all 68 wheel `RECORD`
  entries rehashed exactly; ten direct requirements, exact `mcp==2.0.0`, the console entry point,
  archive paths/types, and the executable sdist image-maintenance script passed structured
  inspection. A wheel-only isolated environment passed dependency, import-origin, module and
  console version checks. Its real stdio server completed initialize, tools/list, `review_run`,
  and EOF with three JSON-RPC-only stdout records, an empty stderr, seven read/local tools, no
  unconfigured writer tools, and a successful schema-1 result.
- 2026-07-31: Final pre-commit image and repair acceptance verified the locked local image
  `sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846`
  without a pull, then imported the fresh wheel ahead of the source tree and ran public
  create/propose/preview/approve/apply APIs through the real rootless Docker socket. The session
  reached APPLIED in 6.56 seconds. Candidate
  `f4dfeaf4b29c6a44a58b0e0be22f52bfe78c5adab320a5ecede84a0f96bbcae1`
  produced exact commit `29cdabaa7f2c5f55c13c3a37011fda2160c7c68c`, tree
  `b7f6c70e24544e273cf9492731b26478a6c5326b`, and its absent-only repair ref. Parent, fixed commit
  bytes, publication manifest/blob, strict Git fsck, source HEAD/tree/index/config/ordinary
  refs/reflogs/worktree non-mutation, terminal private-data removal, and zero residual RepoGuard
  containers all passed.
- 2026-07-31: A post-fix independent review replayed 151 affected regressions and found no confirmed
  critical or important blocker. It revalidated the credential-free external Git-common-directory
  boundary, stdio failure silence, lower-layer GitHub error domains, secret handling, public repair
  API dependency, approval/CAS enforcement, filesystem-link defenses, bounded fixed-host transport,
  and composite Action expression/credential boundaries. The repository contains one workflow,
  zero AI-agent Action instances, no `pull_request_target`, only full-commit external Action pins,
  and checkout with credential persistence disabled.

## Surprises & Discoveries

- 2026-07-30: The requested starting directory is the parent workspace, not the Git repository.
  The actual repository is `RepoGuard/`; running Git once from the parent failed without changing
  state, after which all commands were anchored to the verified repository root.
- 2026-07-30: The fresh coverage display is 90.20% while the completed M5 exact acceptance record
  displays 90.21%. Both runs execute the same 1,185 tests and pass the unchanged 90% threshold;
  M6 records both observations rather than rewriting M5 history.
- 2026-07-30: Existing M1-M4 canonical results include the absolute repository root. M6 therefore
  needs a separate path-free canonical product projection; changing old serializers would invalidate
  M5 request identities.
- 2026-07-30: Existing M1 evidence collection materializes blobs and diff data without a caller
  limit or Git deadline. The optional limit contract must be enforced at collection/read/process
  boundaries, not merely after allocating the complete legacy result.
- 2026-07-30: M1's current Git environment inherits nearly all host variables. In an MCP process
  this can pass all three RepoGuard credentials to Git hooks/helpers/configured subprocesses. The
  bounded M1 path must use a minimal environment or explicitly remove all RepoGuard secret names;
  post-collection envelope scrubbing is too late.
- 2026-07-30: `pathlib.Path(...)` returns a platform subclass such as `PosixPath`. Exact dataclass
  boundaries may require exact record types, but filesystem path capability checks correctly use
  `isinstance(path, Path)` plus absolute/normalized and descriptor identity checks.
- 2026-07-30: The official `mcp==2.0.0` tag is published and its v2 README exports `MCPServer` from
  `mcp.server`; v1 FastMCP examples are not an acceptable API guide for this milestone.
- 2026-07-31: The first installed-wheel MCP acceptance fixture placed its owner-only profile below
  `/tmp`; protected-ancestor validation correctly rejected that world-writable namespace. Moving
  only the profile and state capabilities to a mode-0700 directory below the current owner's home
  allowed the unchanged installed wheel to complete the stdio acceptance.
- 2026-07-30: M1 deadline enforcement must check the clock after process/drain completion and cleanup
  itself must be bounded. A process that exits while a detached descendant holds a pipe can otherwise
  delay or hang the product beyond its declared 60-second ceiling.
- 2026-07-30: The deterministic merge-conflict-marker rule has stable medium severity. The first
  orchestration test assumed high; the test policy threshold was corrected to medium rather than
  changing M2 behavior or weakening the product exit-code assertion.
- 2026-07-30: Mode `120000` names a Git blob even when review intentionally omits the symlink body.
  Blob ceilings therefore require size preflight and aggregate reservation before returning the
  symlink content kind.
- 2026-07-30: Authenticating a GitHub read-back mapping with a Result digest is insufficient when
  the mapping can name a different repository, ref, commit, Check, or pull request than the approved
  Proposal. Construction and loading must compare semantic identities as well as hashes.
- 2026-07-30: M4 starts its own Git processes and originally bypassed the M1 fixed-executable and
  secret-environment corrections. Every subprocess-owning layer needs explicit capability injection
  and credential stripping; an upstream evidence fix does not transitively secure M4.
- 2026-07-30: A composite Action cannot declare its caller's `runs-on`, protected environment,
  workflow permissions, or concurrency. M6 must supply audited trusted caller workflows for those
  topology controls and retain independent runtime event/runner/attempt/actor checks inside the
  fixed Action driver.
- 2026-07-30: A Check proposal produced on a GitHub-hosted review runner is not present in the
  persistent self-hosted publication store. The proposal artifact is therefore a transport record
  for Checks only: after API metadata verification it may seed the exact proposal record through a
  narrow Action-only file capability. Repair publication still resolves its private session binding
  exclusively from the persistent runner and never imports authority from an artifact.
- 2026-07-30: `--github-pr` performs an authenticated source-PR read before evidence so exact
  base/head and fork status can be bound. Consequently automatic deterministic review must have a
  GitHub token even though OpenAI/Anthropic provider secrets remain empty; treating every token as a
  forbidden “provider secret” made the real Action path internally inconsistent.
- 2026-07-30: The exact Git commit used as review `base_oid` is not the replacement pull request's
  base branch name. GitHub proposals therefore bind both values separately: base/head object IDs
  come from evidence and source-PR read-back, while `base_ref` is the authenticated GitHub branch.
- 2026-07-30: Copying nearly the complete runner environment and deleting variables whose names look
  secret is not an enforceable credential boundary. The Action adapter instead constructs a fresh
  child environment from a four-variable locale/isolation allowlist and the three exact supported
  RepoGuard credentials.
- 2026-07-30: Artifact metadata names a workflow run but does not independently identify the
  attempt that produced it. Reading `/attempts/1` only proves that attempt once existed; reading the
  run's latest state and requiring `run_attempt == 1` rejects every rerun artifact fail closed.
- 2026-07-30: The downloaded Action driver cannot authenticate its own downloaded bytes. Persistent
  repair/publication must execute a separately provisioned owner-reviewed local source capability,
  while the real trust anchor for the composite bundle remains a trusted caller's final 40-hex
  `uses:` pin and GitHub's Action delivery boundary.
- 2026-07-30: The publication store's state-root inode lock deliberately serializes different
  repository aliases that share one product state root. This is a conservative availability
  tradeoff for the supported single persistent publisher topology, not a cross-repository
  exactly-once claim.
- 2026-07-31: A 4 MiB product-result limit cannot also be the complete envelope wire limit: the
  fixed schema keys necessarily add bytes. M6 now enforces 4 MiB on canonical `result` bytes and a
  distinct 4 MiB plus 4 KiB envelope ceiling; CLI writes one additional LF outside that bound.
- 2026-07-31: A nominally read-only M5 `RepairManager` construction creates missing runtime
  directories and normal session loads repair a stale cache. Product status/preview therefore need
  a separate public reader that opens only existing state, takes a shared session lock, validates
  immutable events, and deliberately leaves a missing or corrupt cache untouched.
- 2026-07-31: Comparing an Action actor with `github.triggering_actor` does not authenticate the
  token principal. The GitHub writer must additionally compare the exact protected actor with
  `/user` before permission lookup or any write, including final-result and partial recovery paths.
- 2026-07-31: A fixed local Action source path is not a bootstrap trust anchor by itself. The
  caller's final 40-hex `uses:` pin authenticates the delivered bundle; that bundle driver can then
  byte-compare the reviewed local driver and validate the frozen package tree before importing
  product code.
- 2026-07-31: Passing every test does not imply the milestone coverage gate passes. M6 added enough
  production surface that 1,728/1,728 passing tests still measured only 88.56%; at the observed
  19,250-statement denominator, at least 277 previously missed statements must be exercised to
  reach 90% without adding production statements.
- 2026-07-31: A repository worktree path and its Git common directory are not necessarily nested.
  Linked worktrees and `git init --separate-git-dir` can place mutable Git authority elsewhere, so
  profile overlap checks must include a bounded fixed-Git `--git-common-dir` read, not only lexical
  comparison with the reviewed worktree.
- 2026-07-31: Once the official MCP server is invoked, its caller cannot reliably distinguish a
  pre-protocol failure from a failure after JSON-RPC output. Emitting a schema-1 CLI envelope in
  either case can corrupt the stdio stream; runtime failure therefore exits silently with 70 while
  pre-server profile/request errors retain normal envelopes.
- 2026-07-31: The publication adapter already retains whether an error belongs to publication,
  transport, store, or repair. Collapsing all four to product domain `github` discarded the
  disambiguation promised by schema 1; the product enum now carries the corresponding exact domains
  while stable lower-layer codes remain unchanged.

## Decision Log

- 2026-07-30: Keep historical M1-M5 serializers unchanged and add a path-free M6 projection.
  Reason: old canonical bytes are digest inputs and may legitimately serve local library callers,
  while product artifacts must not disclose an absolute host path.
- 2026-07-30: Derive repair target IDs from deterministic-review identity plus exact M2 numeric
  coordinates, and give model findings no target ID. Reason: M5 accepts only exact M2
  finding/reference targets; a model finding has no authoritative repair coordinate.
- 2026-07-30: Place `repair_target_id` on each unified product reference, not merely its enclosing
  finding. Reason: one M2 finding can contain multiple references and M5 authorization selects the
  exact `(finding_index, reference_index)` pair.
- 2026-07-30: Require the host profile bytes themselves to equal canonical JSON and validate
  filesystem capabilities without creating missing directories. Reason: `profile validate` should
  be read-only, and a spelling-normalizing parser would weaken reviewed profile identity.
- 2026-07-30: Keep ignored `.planning/` notes for working memory but treat this tracked ExecPlan as
  the only recovery and completion authority. Reason: M5 demonstrated that an ignored handoff
  cannot close a tracked stage lifecycle.
- 2026-07-30: Separate local M5 and GitHub M6 approvals even when an authenticated M6 principal
  drives the M5 adapter. Reason: they authorize different writes, confirmations, and recovery
  records and cannot safely imply one another.
- 2026-07-30: Snapshot `EvidenceCollectionLimits` at the public call boundary by reconstructing and
  validating an exact value. Reason: frozen dataclasses can still be mutated through low-level Python
  mechanisms, and concurrent mutation must not change an in-flight resource policy.
- 2026-07-30: Extend M1 collection with a backward-compatible optional exact Git executable in
  addition to optional limits, and have only bounded product callers supply it. Reason: a fixed
  executable in the host profile is not meaningful if review still resolves `git` through PATH;
  omitted parameters must retain the legacy M1 invocation behavior.
- 2026-07-30: Keep GitHub records, persistent state, transport, and publication in separate focused
  modules. Reason: contract parsing/digests, owner-only local CAS, HTTP ambiguity, and multi-step
  publication have distinct review and recovery invariants; a GitHub SDK was rejected because its
  ambient authentication, endpoint, redirect, and retry behavior would weaken the fixed boundary.
- 2026-07-30: MCP `repair_apply_local` consumes candidate and validation identities, not an existing
  approval digest. Reason: `repair_prepare` ends in validated state and the fixed MCP catalog has no
  approve tool; confirmation must authorize a shared approve-then-apply workflow or MCP can never
  independently complete the local operation.
- 2026-07-30: Treat fixed Git/Docker/socket paths as host capabilities that must remain outside all
  reviewed repositories; executable files must be root/current-euid owned and not group/world
  writable, and mutable state/cache roots must be pairwise disjoint. Reason: an absolute path alone
  does not prevent PR-controlled program replacement or authority overlap.
- 2026-07-30: Successful `mcp serve` yields stdout exclusively to MCP and emits no trailing CLI
  envelope. Reason: the common envelope remains the tool payload, while any extra process-level
  stdout is invalid stdio JSON-RPC.
- 2026-07-30: Publish the fixed M5 repair commit name, email, message, and timestamp as immutable
  public constants and have M5 itself consume them. Reason: M6 Git Data publication must reproduce
  the exact object without importing or duplicating `_repair_git` implementation literals.
- 2026-07-30: Make self-hosted runner labels an exact, sorted host-profile capability containing
  `Linux`, `X64`, `self-hosted`, and at least one custom label. Reason: repair/publication authority
  must be bound to a unique reviewed runner capability rather than an untracked workflow convention.
- 2026-07-30: Permit an empty runner-label tuple only for hosted/read-only profiles, and require the
  exact sorted `Linux`, `X64`, `repoguard-publisher`, `self-hosted` set for persistent publishers.
  Reason: hosted review has no self-hosted capability to authenticate, while every repair/write
  runner must match one unique reviewed topology.
- 2026-07-30: Require GitHub repository IDs and case-folded full names to be unique across profile
  aliases, and bind the repair proposal payload to its repository alias. Reason: a private
  `proposal_sha256 -> session_id` binding must not be reusable through a second alias naming the
  same GitHub repository.
- 2026-07-30: Require producer, source, and publisher workflow attempts to be exactly one. Reason:
  GitHub artifact metadata does not provide a sufficiently strong independent attempt identity for
  a rerun; a new reviewed workflow run is safer than reusing ambiguous rerun artifacts.
- 2026-07-30: Import an artifact proposal only for `github publish-check` when both the trusted
  interface provenance is `action` and `GITHUB_ACTIONS=true`; require an absolute no-symlink path,
  current-euid regular file, one link, exact 0600 mode, canonical bytes, bounded size, Check kind,
  Action origin, exact digest, and exact repository identity. Reason: hosted Check producers need a
  transport bridge, but general CLI/MCP and all repair publication must not gain artifact authority.
- 2026-07-30: Hold the publication state-root inode lock across each local/remote state transition,
  even though this serializes repositories sharing that root. Reason: the supported topology has
  one persistent publisher, and keeping the namespace inode stable closes lock replacement and
  root-swap attacks without claiming uncontrolled multi-publisher concurrency.
- 2026-07-30: Reject any source workflow whose latest `run_attempt` is not exactly one. Reason:
  GitHub artifact metadata cannot prove which rerun produced a downloaded artifact, so a fresh
  workflow run is required instead of attempting an ambiguous per-attempt association.
- 2026-07-30: Remove the generic CI workflow's `pull_request` trigger while it executes
  repository-owned setup and test scripts. Reason: automatic PR review may parse untrusted Git
  objects through the bounded deterministic product path, but generic CI must not execute
  PR-controlled scripts under the M6 Action trust contract.
- 2026-07-30: Keep the final-SHA caller workflow and protected-environment configuration in the
  disposable acceptance repository, not as a self-referential workflow in the feature commit.
  Reason: a source commit cannot contain a stable pin to its own not-yet-existing object ID; the
  caller, environment reviewers, prevent-self-review, permissions, concurrency, and exact runner
  registration are external acceptance records and remain pending until those capabilities exist.
- 2026-07-31: Treat the 4 MiB ceiling as the canonical result bound and reserve a fixed 4 KiB only
  for the strict envelope wrapper. Reason: accepting an exact-bound result must not fail during the
  final serializer, while arbitrary oversized result data must still fail atomically.
- 2026-07-31: Add public `read_repair_snapshot` and `read_repair_preview` entry points rather than
  constructing a writable manager for product queries. Reason: shared-lock reads must not create a
  runtime root, rewrite cache state, or expose private M5 implementation imports to product code.
- 2026-07-31: Bind an optional expected principal in `GitHubPublicationService`, supplied only by
  Action writer orchestration. Reason: CLI/MCP continue to authorize their explicit token principal,
  while protected Action approval additionally requires that principal to be the exact workflow
  actor on every authorization/revalidation path.
- 2026-07-31: Authenticate self-hosted publication in two stages: execute the pinned bundle driver
  with system Python only for capability bootstrap, require exact bytes against the fixed local
  driver, then execute all product operations with the fixed isolated Python and local driver.
  Reason: neither a downloaded driver nor a local path can prove itself; their independently
  reviewed identities must agree before either gains publication authority.
- 2026-07-31: Resolve each configured repository's absolute Git common directory through the
  already authenticated fixed Git executable with an exact credential-free environment, then
  reject every protected capability that overlaps either worktree or common directory. Reason:
  Git's linked/separate layouts make the worktree alone an incomplete authority boundary.
- 2026-07-31: Preserve `github_publication`, `github_transport`, `github_store`, and `repair` as
  schema-1 product error domains for wrapped publication failures. Reason: identical stable codes
  from different lower layers are meaningful only when their owner remains explicit.

## Outcomes & Retrospective

M6 is in progress. Shared contracts, bounded evidence, the public M5 publication and read-only
session capabilities, product orchestration, CLI, stdio MCP, GitHub contracts/transport/
publication, and the three composite adapters are implemented. The pre-commit full local,
package, installed-wheel MCP, locked-image, real rootless-Docker, and independent security gates
pass. No external GitHub write has been accepted. Completion still requires the one feature commit,
exact-SHA replay, and the real GitHub acceptance described above; the absent token, remote,
protected environment, independent reviewer, and registered persistent runner remain an external
pending outcome rather than a completed stage.
