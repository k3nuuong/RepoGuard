# M1: Read-Only Repository Evidence

Status: complete

This is the only active ExecPlan for M1 and follows `.agent/PLANS.md`. The M0 plan remains complete
and must not be edited.

## Purpose And Observable Outcome

Model a local Git repository and pull-request comparison, then collect deterministic, traceable
evidence from committed Git objects. A caller supplies a repository path plus base and head refs and
receives immutable Python evidence objects or canonical JSON. Collection must not inspect
uncommitted content, call a model, access a network service, modify the repository, or write an
artifact.

The observable M1 result is a typed Python API that resolves refs, computes the unique merge base,
records changed-file metadata and UTF-8 diff hunks, and handles unsupported or invalid inputs with a
stable typed error. The existing CLI remains a version-only M0 interface.

## Context, Scope, And Constraints

M0 is committed at `853002cc223be1255d4945f0a8b3a24e99096917` on `main`. Its restored gate passed
Ruff, MyPy strict, five tests, and 92.31% coverage before this plan was created. The repository uses
Python 3.12, uv 0.9.2, package version 0.1.0, and no third-party runtime dependencies. Git 2.43.0 is
the locally verified implementation baseline. Text patch isolation requires a POSIX anonymous
file-descriptor path at `/dev/fd` or `/proc/self/fd`; the verified local and CI platform is Linux.

M1 reads only a local, non-bare Git worktree. It accepts committed base and head refs, resolves both
to immutable commit object IDs, and compares the unique merge base to the resolved head. Dirty and
untracked worktree content is deliberately ignored. M1 does not fetch missing history or call the
GitHub API.

M1 does not implement deterministic review rules, security Findings, LLM providers, prompts,
LangGraph, retrieval, embeddings, vector stores, patch generation, worktrees, approvals, GitHub
writes, GitHub Action product behavior, FastMCP, benchmarks, training, a frontend, deployment, or
source migration from sibling projects.

The package version stays 0.1.0. Hypothesis may be added only as a development dependency. The
runtime dependency tree must continue to contain only RepoGuard.

## Public Interfaces And Evidence Schema

Add `repoguard.evidence` with these public entry points:

    RepositoryInput(path: pathlib.Path)
    PullRequestInput(base_ref: str, head_ref: str)
    collect_evidence(repository, pull_request) -> EvidenceBundle
    evidence_to_dict(bundle) -> dict[str, object]
    evidence_to_json(bundle) -> str

All evidence types are frozen, slotted dataclasses. Public enums inherit from `StrEnum` and serialize
to lowercase string values.

`EvidenceBundle` has integer `schema_version` 1 and contains:

- `RepositoryEvidence`: the normalized absolute worktree root and Git object format.
- `RevisionEvidence`: requested base/head refs, resolved base/head object IDs, and merge-base ID.
- An ordered tuple of `FileChangeEvidence` values.

Each file change records its change type, optional rename similarity, optional old and new
`FileVersion`, and an ordered tuple of hunks. A file version records its Git-relative UTF-8 path,
mode, full object ID, and content kind. Content kinds are `text`, `binary`, `symlink`, `submodule`,
and `other`.

Each hunk records old/new start and count values. Each line records `context`, `addition`, or
`deletion`, optional old/new line numbers, UTF-8 content without the diff marker, and whether the
source line ended with a newline.

`evidence_to_dict` uses the field names above, JSON arrays for tuples, lowercase enum values, and
JSON null for absent values. `evidence_to_json` uses sorted keys, compact separators, UTF-8 text, and
no trailing newline. It does not add timestamps, commit messages, random identifiers, or environment
metadata. Repeating collection against the same resolved objects and worktree path must return
byte-identical JSON.

`EvidenceCollectionError` exposes an `EvidenceErrorCode`. Stable codes cover Git unavailable,
repository path missing, non-worktree repository, invalid base, invalid head, no merge base,
ambiguous merge base, unsupported path encoding, Git command failure, and malformed Git output.
Failures are atomic and never return partial evidence.

## Data Flow And Read-Only Boundary

1. Validate the supplied path and ask Git for the canonical worktree root and object format.
2. Resolve base and head independently with `rev-parse --verify --end-of-options <ref>^{commit}`.
3. Run `merge-base --all` on the resolved IDs and require exactly one merge base.
4. Read a NUL-delimited raw diff from merge base to head with full object IDs, explicit Myers
   algorithm, disabled indent heuristic, and 50% rename detection. Copy detection is disabled.
5. Classify old and new versions from their mode and blob bytes. Regular files containing NUL or
   invalid UTF-8 are evidence-bearing non-text files and receive no hunks.
6. For text changes, feed the cached old and new blob bytes through anonymous pipes to a
   repository-independent Git no-index diff with three lines of context, then parse hunk coordinates
   and line termination. Special files retain complete metadata without text hunks.
7. Sort changes by their UTF-8 path bytes and return the immutable bundle.

Git is invoked with argument arrays and `shell=False`. Literal pathspec handling is mandatory.
Collection disables external diff, textconv, interactive prompts, lazy fetch, replacement objects,
legacy grafts, external order files, and optional locks. Raw rename detection sources tree
attributes from the resolved head, forces text treatment, and ignores global and system attribute
files. It runs with `GIT_DIR` set to a packaged read-only metadata facade for the detected object
format and `GIT_OBJECT_DIRECTORY` set to the target object store. The facade has no target config,
refs, worktree, or info attributes, so native 50% rename scoring cannot inspect uncommitted target
metadata. Text patches run outside repository discovery with global and system configuration
disabled and `GIT_DIR` fixed to the SHA-1 facade, so even a Git repository at the process working
directory cannot supply path attributes or userdiff drivers. No command may run a hook, fetch,
checkout, update the index, write an object, or create a temporary file.

All serialized paths must be valid UTF-8. A non-UTF-8 repository root or changed path fails with the
unsupported-path-encoding code instead of emitting non-portable JSON. There is no truncation or
partial-result policy in M1.

## Implementation Steps

1. Create this plan before any package, dependency, test, or documentation edit.
2. Add Hypothesis to the development group and lock it without adding a runtime dependency. Ignore
   its local cache.
3. Add the public immutable evidence model, stable error contract, dictionary conversion, and
   canonical JSON serialization.
4. Add the private Git runner and parsers, then connect them to `collect_evidence`.
5. Add focused unit, property, and temporary-repository integration tests.
6. Update README only after the capability is verified. Do not add an evidence CLI command or change
   the package version.
7. Run all acceptance commands, obtain an independent read-only review, update this plan, rerun the
   gates, and create one local M1 commit without amending M0.

## Validation

Run from the repository root:

    uv lock --check
    uv sync --frozen
    uv run pytest tests/test_evidence.py tests/test_git_evidence.py \
        tests/test_evidence_properties.py
    uv run python -m repoguard --version
    uv tree --no-dev --frozen
    ./scripts/check.sh
    git diff --check

The version command must still print `repoguard 0.1.0`. The runtime tree must print only
`repoguard v0.1.0`. The targeted tests and shared gate must pass, and total coverage must remain at
least 90%.

Integration tests create disposable local Git repositories with command-local author identity. They
cover merge-base semantics after the base branch advances, add/modify/delete/mode/rename changes,
line coordinates, missing final newlines, UTF-8 special paths, binary and non-UTF-8 blobs, symlinks,
gitlinks, an ignored dirty worktree, empty comparisons, and stable repeat serialization. Failure
tests cover invalid repositories and refs, unrelated histories, multiple merge bases where practical,
hostile ref-like input, and malformed subprocess output.

Hypothesis is limited to pure parsers and serialization. Strategies generate valid bounded inputs
without broad filtering, include explicit empty and boundary examples, and verify line-number
invariants plus:

    json.loads(evidence_to_json(bundle)) == evidence_to_dict(bundle)

Before commit, inspect the complete diff, obtain a read-only review, stage only M1 files, and run:

    git diff --cached --check

Create the local commit with message:

    feat: add read-only evidence collection

At the committed SHA, rerun the lock check, frozen sync, version command, runtime dependency tree,
and shared gate. Require `git status --short --branch` to report only `## main`. Do not create a
remote or push.

## Idempotency And Recovery

Evidence collection is read-only and safe to rerun. Once refs are resolved, later operations use only
their object IDs, so moving branches or a dirty worktree cannot change an in-flight comparison.
Canonical serialization is deterministic for the same bundle.

`uv add --dev hypothesis` is a one-time dependency edit. After interruption, inspect
`pyproject.toml`, `uv.lock`, Git status, and Progress before deciding whether it already completed.
Lock checks, frozen sync, tests, version inspection, dependency-tree inspection, and quality gates
are safe to repeat.

If the uv cache is read-only in the Codex sandbox, record the exact failing command and error here,
then request only the permission needed to use the existing cache. Do not modify project cache
configuration. For any other failure, record the command, complete error, hypothesis, and changed
next method. A second attempt must test a different hypothesis. After three different approaches
fail without new evidence, stop repeating and perform root-cause diagnosis.

After interruption:

1. Read `AGENTS.md`, `.agent/PLANS.md`, the charter, M0 plan, this plan, and the recovery runbook.
2. Inspect branch, HEAD, status, recent commits, and modified files.
3. Rerun the latest successful command recorded in Progress.
4. Compare its result with this plan and resume at the first incomplete implementation step.

## Progress

- 2026-07-28: Restored M0 at `853002cc223be1255d4945f0a8b3a24e99096917`; the exact frozen
  environment, version command, and shared quality gate passed, and the worktree remained clean.
- 2026-07-28: Confirmed the M1 input source, merge-base semantics, evidence granularity, Python and
  JSON interface, special-file policy, dirty-worktree behavior, Git backend, UTF-8 policy, property
  testing, repository identity, atomic error contract, diff policy, unchanged package version, and
  final local commit policy. Created this ExecPlan as the first M1 edit. Next: add the dev dependency
  and implement the public evidence model.
- 2026-07-28: `uv add --dev hypothesis` resolved 18 packages and installed Hypothesis 6.163.0 plus
  its development-only dependency. Package version 0.1.0 and `dependencies = []` remained unchanged.
  Added the Hypothesis cache boundary. Next: implement the public model and private Git collector.
- 2026-07-28: Source check attempt 1 ran
  `.venv/bin/ruff check src/repoguard/evidence.py src/repoguard/_git.py` successfully, but
  `.venv/bin/ruff format --check src/repoguard/evidence.py src/repoguard/_git.py` requested two
  expression-layout changes. `.venv/bin/mypy src/repoguard/evidence.py src/repoguard/_git.py`
  reported missing returns at `_parse_status` and `_select_patch_block`, plus a variable-length tuple
  returned where a two-item rename tuple is required. Hypothesis: the helpers always raise but were
  annotated as returning `None`, and MyPy cannot infer tuple length after a runtime check. Changed
  approach: annotate raising helpers with `Never`, construct the rename pair by index, apply Ruff's
  requested layout, and rerun all three checks.
- 2026-07-28: Property-test check attempt 1 ran
  `.venv/bin/pytest -q tests/test_evidence.py tests/test_evidence_properties.py` and passed all nine
  tests. `.venv/bin/ruff check src tests/test_evidence.py tests/test_evidence_properties.py` reported
  one import-order issue; the matching Ruff format check requested layout changes in the property
  test. `.venv/bin/mypy src tests/test_evidence.py tests/test_evidence_properties.py` reported two
  imprecise `exclude_categories` tuple types and one missing `LINE_PAIRS` annotation. Hypothesis:
  runtime-valid Hypothesis strategies need narrower static types under MyPy strict. Changed approach:
  use a `Literal["Cs"]` category tuple, annotate the composite strategy with `SearchStrategy`, apply
  the requested import/layout changes, and rerun the four checks.
- 2026-07-28: Git integration attempt 1 ran
  `.venv/bin/pytest -q tests/test_git_evidence.py`; three tests passed and the unrelated-history
  fixture failed because `git switch --orphan unrelated` had already cleared the tracked worktree,
  so the subsequent `git rm -rf .` returned exit 128. Ruff lint and MyPy passed, while Ruff format
  requested one environment-comprehension layout change. Hypothesis: Git 2.43 orphan-switch behavior
  makes the removal redundant. Changed approach: create the unrelated commit directly after the
  orphan switch, apply the format layout, and rerun the same four checks.
- 2026-07-28: Coverage attempt 1 ran
  `.venv/bin/pytest --cov=repoguard --cov-report=term-missing --cov-fail-under=90`. All 18 tests
  passed, but total coverage was 88.61%, so the unchanged 90% gate failed. `_git.py` had 53 uncovered
  statements, concentrated in malformed-output and command-failure branches; all public model code
  was at 100%. Hypothesis: happy-path integration is broad, but the stable atomic error contract
  needs direct parser and subprocess-failure tests. Changed approach: add focused malformed raw diff,
  ambiguous merge-base, invalid UTF-8 path, and Git nonzero-exit tests, then rerun the same coverage
  command without changing the threshold.
- 2026-07-28: Coverage attempt 2 collected 28 tests; all passed and coverage reached 93.01%.
  `.venv/bin/ruff check src tests` and `.venv/bin/mypy src tests` passed. The only failed command was
  `.venv/bin/ruff format --check src tests`, which requested one string-layout change in the
  multi-block patch-selection test. Hypothesis: behavior and typing are correct, but the handwritten
  fixture does not match Ruff's canonical layout. Changed approach: apply that exact layout change,
  then run the repository's shared gate rather than extrapolate from partial checks.
- 2026-07-28: After the format correction, `./scripts/check.sh` passed Ruff lint and format, MyPy
  strict, all 28 tests, 93.01% coverage, and `git diff --check`. This is the first complete M1 gate.
  Updated README only with the verified local Git evidence API and its read-only limitations. Next:
  inspect the full diff, run exact acceptance commands, and obtain an independent read-only review.
- 2026-07-28: Extended Git integration coverage for SHA-256 repositories, repository-subdirectory
  input, a path that is Git pathspec syntax when not treated literally, configured external diff
  commands, and hostile inherited Git environment variables. The focused rerun passed Ruff lint and
  format, MyPy strict, and all six Git integration tests. Next: inspect the complete implementation,
  run the exact acceptance commands, and reconcile the independent review.
- 2026-07-28: Attribute-isolation and raw-record consistency attempt 1 ran
  `.venv/bin/pytest -q
  tests/test_git_evidence.py::test_collects_merge_base_evidence_and_ignores_dirty_worktree
  tests/test_evidence_properties.py::test_raw_diff_parser_rejects_malformed_records` and reported
  `3 failed, 6 passed`. An uncommitted `.git/info/attributes` plus configured
  `core.attributesFile` removed text hunks and changed canonical JSON; added records with an old
  side and modified records with neither side returned normally instead of raising the stable
  malformed-output error. Hypothesis: `GIT_ATTR_SOURCE` isolates worktree `.gitattributes` but not
  higher-precedence attribute sources, while the parser validates each mode/OID pair without
  validating status-level side presence. Changed approach: request patches with Git's explicit text
  override after RepoGuard's own blob classification, validate side presence against each status,
  and rerun the focused tests.
- 2026-07-28: Attribute-isolation and raw-record consistency attempt 2 reran the same focused
  command after the changed implementation and passed all nine cases. RepoGuard's UTF-8/NUL blob
  classification now decides whether a patch is requested, and Git is explicitly told to render
  those blobs as text so uncommitted attribute sources cannot suppress evidence.
- 2026-07-28: The exact pre-review acceptance sequence passed: `uv lock --check` resolved 18
  packages, `uv sync --frozen` audited 17 packages, all 27 targeted M1 tests passed, the version
  remained `repoguard 0.1.0`, and the frozen runtime tree contained only `repoguard v0.1.0`.
  `./scripts/check.sh` then passed Ruff, MyPy strict, all 32 tests, 93.17% coverage, and
  `git diff --check`. These results precede the independent review and are not final acceptance.
- 2026-07-28: Independent review reported four determinism/read-only candidates requiring local
  verification: partial-clone lazy fetch was not explicitly disabled; Git configuration could hide
  gitlink changes or alter patch hunk shape; and a valid UTF-8 repository root containing a newline
  could be rejected by a one-line parser. Next: reproduce each candidate against Git 2.43.0, fix
  confirmed issues, and rerun the full sequence.
- 2026-07-28: Independent-review regression attempt 1 ran
  `.venv/bin/pytest -q
  tests/test_git_evidence.py::test_collects_merge_base_evidence_and_ignores_dirty_worktree
  tests/test_git_evidence.py::test_supports_utf8_repository_root_with_newline
  tests/test_evidence_properties.py::test_git_invocation_disables_lazy_fetch` and all three cases
  failed. Configured diff behavior caused `diff hunk line counts do not match its header`; the
  newline-bearing root raised `worktree root output is not exactly one line`; and the captured Git
  environment lacked `GIT_NO_LAZY_FETCH`. Hypothesis: explicit patch context and blank-line
  formatting plus submodule visibility must override configuration, a single returned path needs a
  terminator parser rather than a one-logical-line parser, and Git's lazy object retrieval must be
  disabled explicitly. Changed approach: add those fixed options and environment invariant, retain
  strict object/ref line parsing, and rerun the same three regressions.
- 2026-07-28: Independent-review regression attempt 2 reran the same three cases and all passed.
  Local inspection also found `GIT_NO_LAZY_FETCH` in the installed `/usr/bin/git` 2.43.0 binary.
  Fixed diff options now preserve gitlink visibility, zero inter-hunk context, and ordinary blank
  context markers despite repository configuration; root paths remove only Git's final line
  terminator and may contain internal newlines.
- 2026-07-28: Post-review static attempt 1 ran `.venv/bin/ruff check src tests`,
  `.venv/bin/ruff format --check src tests`, `.venv/bin/mypy src tests`, and the 29-test targeted
  suite. The targeted tests, format check, and MyPy passed; Ruff reported only `I001` because the new
  private `_invoke_git` test import followed `_resolve_merge_base`. Hypothesis: this is an isolated
  import-order defect. Changed approach: move that import to Ruff's indicated alphabetical position
  and rerun the static checks.
- 2026-07-28: Order-file isolation attempt 1 ran
  `.venv/bin/pytest -q
  tests/test_git_evidence.py::test_collects_merge_base_evidence_and_ignores_dirty_worktree`, but the
  test's own `git status --porcelain=v1 -z` inherited the intentionally missing `diff.orderFile` and
  exited 128 before collection. Hypothesis: the candidate remains valid, but the worktree snapshot
  helper is also a diff consumer. Changed approach: override only the two test-owned status calls
  with `diff.orderFile` set to `os.devnull`, leave RepoGuard exposed to the hostile configuration,
  and rerun the focused test.
- 2026-07-28: Order-file isolation attempt 2 reached RepoGuard collection and failed as expected:
  `_read_raw_changes` raised `GIT_COMMAND_FAILED` because Git tried to read the configured missing
  order file. Hypothesis confirmed: both raw and patch diff inherit `diff.orderFile`. Changed
  approach: set the command-level value to Python's platform-specific `os.devnull` for every Git
  invocation, then rerun the same dirty-configuration equality test.
- 2026-07-28: Order-file isolation attempt 3 reran the focused dirty-configuration test and passed.
  The comparison now remains byte-identical despite hostile committed-external attributes, hidden
  submodules, inter-hunk context, blank-context suppression, and a missing external order file.
- 2026-07-28: Legacy-graft isolation attempt 1 added `.git/info/grafts` declaring the resolved head
  parentless, then reran the dirty-state equality test. Collection raised `NO_MERGE_BASE`, proving
  that `GIT_NO_REPLACE_OBJECTS=1` disables replacement refs but not the legacy graft file.
  Hypothesis: Git exposes a process-local graft-file override. Changed approach: verify the installed
  Git 2.43.0 capability, point that override at `os.devnull` if supported, and retain the regression.
- 2026-07-28: Legacy-graft isolation attempt 2 confirmed `GIT_GRAFT_FILE` in the installed Git
  binary, set it to `os.devnull`, and passed the dirty-state equality test. Committed ancestry is now
  insulated from both replacement refs and legacy grafts without modifying repository metadata.
- 2026-07-28: Final uv lock-check attempt 1 requested minimal access to the existing user uv cache,
  but the environment approval reviewer rejected escalation. The safer sandboxed execution of
  `uv lock --check` then exited 2 with
  `error: failed to open file '/home/k3nwong/.cache/uv/sdists-v9/.git': Read-only file system
  (os error 30)`. Hypothesis: this is the documented Codex cache-mount anomaly; neither lock input
  changed nor a package-resolution defect occurred. Project cache configuration will not be changed.
  Exact final uv acceptance and commit remain pending explicit cache-read permission; workspace-only
  diagnostics may continue independently.
- 2026-07-28: While exact uv acceptance remained permission-blocked, the frozen `.venv` equivalents
  passed Ruff lint and format across the repository, MyPy strict, all 34 tests, 92.86% coverage, and
  `git diff --check`. These are current implementation diagnostics, not a substitute claim for the
  pending exact uv commands or shared entry point.
- 2026-07-28: Attribute-read diagnostic attempt 1 used `strace -e trace=openat` around the exact
  hardened patch command to observe uncommitted attribute sources, but the sandbox rejected
  `PTRACE_TRACEME` and `PTRACE_SETOPTIONS` with `Operation not permitted`. Hypothesis: ptrace is
  unavailable independently of Git behavior. Changed approach: use an unprivileged FIFO as the
  configured attributes file and a bounded `timeout`; blocking proves a read without tracing.
- 2026-07-28: Attribute-read diagnostic attempt 2 pointed `core.attributesFile` at an unread FIFO.
  The exact hardened patch command timed out with exit 124, proving `--text` still reads attributes.
  Adding `GIT_ATTR_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`, and
  `-c core.attributesFile=/dev/null` isolated global and system sources, but replacing
  `.git/info/attributes` with a FIFO still timed out. Raw diff also timed out when rename detection
  was enabled and completed with `--no-renames`. Hypothesis: Git requires path attributes for native
  rename detection, while patch generation can be moved to a pathless comparison. Changed approach:
  retain native raw rename detection but generate hunks from the already classified blob bytes in a
  repository-independent `git diff --no-index` process fed by anonymous pipes.
- 2026-07-28: Independent review's final pass confirmed the lazy-fetch, replace/graft, submodule,
  hunk-context, blank-line, order-file, newline-root, injection, error-atomicity, and stage-boundary
  fixes. It reproduced one remaining medium issue: committed `diff=<driver>` plus an uncommitted
  invalid `diff.<driver>.xfuncname` made the patch command exit 128. No files were edited by the
  reviewer. A real partial-clone integration and bounded blob/patch memory remain residual risks.
- 2026-07-28: Userdiff-isolation attempt 1 ran
  `.venv/bin/pytest -q
  tests/test_git_evidence.py::test_disables_repository_configured_external_diff` after adding the
  reviewer's invalid `diff.repoguard-test.xfuncname=[invalid` configuration. Collection failed with
  `GIT_COMMAND_FAILED: fatal: Invalid regexp to look for hunk header: [invalid`. Hypothesis
  confirmed: path-based patch generation loads uncommitted userdiff configuration even with
  external diff and text conversion disabled. Changed approach: cache bytes for text-classified
  blobs and run Git's Myers no-index diff outside repository discovery, feeding both sides through
  anonymous file-descriptor pipes without shell or filesystem writes.
- 2026-07-28: Userdiff-isolation attempt 2 passed the focused regression, then passed Ruff lint and
  format, MyPy strict, and all 28 targeted M1 tests. Removed the obsolete multi-file patch selector
  and its test because each no-index blob comparison has exactly one file pair. Public evidence
  shape, raw rename detection, line coordinates, and missing-newline behavior remain unchanged.
- 2026-07-28: Pipe-error check attempt 1 passed both the simulated pipe-creation failure and invalid
  userdiff regression; MyPy and Ruff format also passed. Ruff lint reported only `I001` because the
  new `_read_patch` private import preceded `_parse_hunks`. Hypothesis: this is isolated import
  ordering. Changed approach: apply Ruff's alphabetical position and run the complete diagnostics.
- 2026-07-28: The final workspace-only diagnostic after no-index patch isolation passed Ruff lint
  and format, MyPy strict, all 34 tests, 90.86% coverage, and `git diff --check`. README now states
  the verified POSIX file-descriptor requirement. HEAD remains the M0 commit, no files are staged,
  and the M0 ExecPlan has no diff. Exact uv acceptance, plan completion, staging, commit, and
  post-commit verification remain blocked only by the rejected cache-read permission.
- 2026-07-28: The resumed session's exact acceptance sequence used the existing uv cache without a
  project workaround and passed: `uv lock --check` resolved 18 packages, `uv sync --frozen` audited
  17 packages, all 29 targeted M1 tests passed, the version output remained `repoguard 0.1.0`, and
  the frozen runtime tree contained only `repoguard v0.1.0`. `./scripts/check.sh` then passed Ruff,
  MyPy strict, all 34 tests, 90.86% coverage, and `git diff --check`. The implementation and M0
  history remain uncommitted and unchanged respectively. Next: reconcile a fresh independent
  read-only review of the final no-index implementation before completing this plan.
- 2026-07-28: Fresh independent review reported three candidates requiring local reproduction before
  completion: a no-index return code of one with empty output may be mistaken for a successful
  content diff; native similarity-based rename detection may still read `.git/info/attributes`; and
  a thread-start exception may escape the typed error boundary while leaking pipe descriptors. These
  findings supersede the preceding acceptance result as completion evidence. Next: reproduce each
  candidate with focused tests, then change the implementation rather than repeat the existing
  method.
- 2026-07-28: Final-review regression attempt 1 ran
  `uv run pytest -q
  tests/test_evidence_properties.py::test_no_index_access_failure_is_not_treated_as_a_content_diff
  tests/test_evidence_properties.py::test_patch_thread_start_failure_closes_all_descriptors` and
  reported `3 failed`. The access-error simulation returned normally instead of raising, while both
  thread-start cases leaked past the typed boundary as `RuntimeError`. The separate command
  `uv run pytest -q
  tests/test_git_evidence.py::test_similarity_rename_ignores_uncommitted_info_attributes` timed out
  after three seconds and failed after killing its isolated process group. Hypotheses confirmed:
  return code one is ambiguous, writer startup precedes cleanup, and non-exact native rename scoring
  reads the target repository's info attributes. Changed approach: require a clean, parseable
  no-index result for differing text; put all writer startup under descriptor cleanup; and run Git's
  native rename engine through a packaged read-only metadata facade connected only to the target
  object directory.
- 2026-07-28: Final-review regression attempt 2 passed all four new focused cases, then Ruff lint and
  format, MyPy strict, and all 33 targeted M1 tests. `uv build --python 3.12` built both distributions.
  The first standard-library `zipfile` asset check printed all eight facade files but exited one
  because its `len(selected) == 8` assertion also counted eight ZIP directory entries. Hypothesis:
  the package data is present and the inspection counted members at the wrong granularity. Changed
  approach: exclude names ending in `/`, compare the exact eight-file set, and then exercise
  collection from the built wheel rather than rely only on member names.
- 2026-07-28: The corrected standard-library `zipfile` check matched the exact eight facade files.
  An isolated `uv run --no-project --with` installation from the built wheel then collected empty
  same-ref SHA-1 evidence successfully. The shared gate after adding a package-resource regression
  passed Ruff, MyPy strict, all 39 tests, 90.71% coverage, and `git diff --check`; the existing
  SHA-256 integration also passes through its matching facade. M0 remains unchanged. Next: obtain a
  fresh read-only review of the facade and final error/cleanup paths.
- 2026-07-28: A direct diagnostic confirmed that no-index diff works with `GIT_DIR` bound to the
  packaged SHA-1 facade. The implementation now sets that invariant explicitly, removing the prior
  assumption that `/` is not itself a Git worktree. Next: rerun focused and shared checks, then
  reconcile the pending independent review.
- 2026-07-28: The final independent read-only review found no blocking or correctness issues after
  exercising built-wheel SHA-1 linked worktrees, alternates, SHA-256, non-exact rename scoring,
  read-only facade permissions, repository and facade content snapshots, no-index result faults, and
  subprocess startup faults. Its shared gate passed 39 tests at 90.71% before the final explicit
  no-index facade binding. That final increment passed four focused regressions and the shared gate
  with all 40 tests at 90.71%.
- 2026-07-28: Final exact acceptance passed: `uv lock --check` resolved 18 packages,
  `uv sync --frozen` audited 17 packages, all 34 targeted M1 tests passed, the version remained
  `repoguard 0.1.0`, the frozen runtime tree contained only `repoguard v0.1.0`, and
  `git diff --check` passed. This plan is complete. Next: rerun the shared gate after this plan edit,
  stage only M1 files, verify the cached diff, create the required local commit, and perform the
  documented post-commit checks.

## Surprises & Discoveries

- 2026-07-28: Existing M0 content intentionally defines only the M1 boundary, not a schema. The
  concrete schema and behavior above were confirmed before implementation rather than inferred from
  sibling projects.
- 2026-07-28: Git 2.43.0 supports the required literal pathspec, object-format, end-of-options,
  merge-base, and raw diff flags in the current environment.
- 2026-07-28: `GIT_ATTR_SOURCE` does not isolate higher-precedence attributes, and several diff
  configuration values still affect plumbing-like diff output. M1 therefore has to override those
  inputs explicitly even though it never reads worktree content.
- 2026-07-28: `GIT_NO_REPLACE_OBJECTS` does not disable `.git/info/grafts` on Git 2.43.0;
  `GIT_GRAFT_FILE` requires its own null-file override to preserve committed ancestry.
- 2026-07-28: Git can determine an exact `R100` rename without opening target info attributes, but
  similarity scoring for a modified rename reads `.git/info/attributes` even when global, system,
  and worktree attribute sources are isolated. A different repository metadata context is required
  to retain native 50% scoring without reading that uncommitted file.
- 2026-07-28: `git diff --no-index` uses return code one for both ordinary content differences and
  some input-access failures. Successful text evidence therefore requires empty stderr and at least
  one parseable hunk, not only an accepted return code.
- 2026-07-28: Starting pipe writer threads before entering cleanup allowed a rare startup exception
  to escape the typed boundary and leak descriptors. Startup and subprocess execution must share the
  same descriptor-lifetime guard.

## Decision Log

- 2026-07-28: Use local Git refs and unique merge-base-to-head semantics. Reason: this is offline,
  deterministic, and keeps GitHub product integration in M6.
- 2026-07-28: Expose a typed Python API plus canonical in-memory JSON, but no evidence CLI or artifact
  writer. Reason: M1 needs an observable contract without starting the M6 product interface.
- 2026-07-28: Keep special-file metadata and omit hunks for non-text content. Reason: evidence must
  never be silently incomplete or corrupted by lossy decoding.
- 2026-07-28: Use the installed Git executable with hardened argument-array calls and no replaceable
  backend abstraction. Reason: it preserves native Git semantics without a runtime dependency.
- 2026-07-28: Add Hypothesis only to development dependencies. Reason: generated parser and
  serialization edge cases provide stronger evidence while the shipped package stays dependency-free.
- 2026-07-28: Keep package version 0.1.0 and create one new M1 commit after acceptance. Reason: these
  are explicit user choices, and a new commit preserves rather than rewrites M0 history.
- 2026-07-28: Generate text hunks with repository-independent `git diff --no-index` over anonymous
  pipes after classifying committed blobs. Reason: this keeps Git's explicit Myers semantics while
  preventing path attributes, userdiff configuration, worktree content, shell execution, or
  temporary files from influencing patch evidence. Bind the process to the packaged SHA-1 facade so
  repository discovery remains disabled regardless of the host filesystem layout.
- 2026-07-28: Run raw rename detection through packaged SHA-1 and SHA-256 Git metadata facades while
  pointing `GIT_OBJECT_DIRECTORY` at the target object store. Reason: this preserves Git's native
  50% similarity algorithm and committed tree attributes while excluding target info attributes and
  configuration. A custom similarity engine would duplicate subtle Git behavior, and a temporary
  repository would violate M1's no-artifact boundary.
- 2026-07-28: Treat no-index output as valid only when differing inputs produce return code one,
  empty stderr, and at least one valid hunk; place writer startup inside the common descriptor
  cleanup block. Reason: Git's return code alone is ambiguous, and every internal failure must remain
  atomic under the public typed error contract.

## Outcomes & Retrospective

M1 delivers a typed, immutable Python evidence API and canonical JSON schema for a local worktree plus
base/head refs. Collection resolves immutable commits and their unique merge base, reads only
committed objects, records ordered file metadata and UTF-8 hunks, preserves binary, symlink, submodule,
mode, type, and rename evidence, and returns stable atomic errors. Dirty and untracked worktree
content, target info attributes, inherited Git environment, replacement refs, grafts, lazy fetch,
external diff helpers, userdiff configuration, and external order files do not influence the
accepted evidence path.

The final pre-commit acceptance passed the exact frozen lock and sync commands, all 34 targeted M1
tests, the unchanged `repoguard 0.1.0` version command, the dependency-free runtime tree, all 40
shared-gate tests, 90.71% coverage, Ruff, MyPy strict, and Git whitespace checks. Hypothesis 6.163.0
is development-only. Both distributions built successfully; standard-library wheel inspection found
the exact eight SHA-1/SHA-256 facade files, and an isolated installation from that wheel collected
evidence. A final independent review reported no blocking findings after additional linked-worktree,
alternates, object-format, fault-injection, and read-only snapshot diagnostics.

The implementation intentionally leaves blob, patch, and bundle capture unbounded; a very large
change can consume substantial memory. Missing-object partial clones have no real integration test,
although lazy fetch is disabled and missing data fails atomically. Linked worktree and alternates
coverage was diagnostic rather than a permanent regression. Normal filesystem installation and
POSIX `/dev/fd` or `/proc/self/fd` paths are required. GitHub-hosted CI has not run remotely, and no
external CVE or maintainer-health audit was performed.

No deterministic Finding engine, model call, retrieval, repair, GitHub product flow, benchmark,
training, frontend, deployment, or M2 behavior was added. The required local commit
`feat: add read-only evidence collection` preserves the complete M0 history; post-commit verification
must still confirm the recorded tree and clean status at its new SHA.
