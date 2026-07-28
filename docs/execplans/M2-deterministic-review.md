# M2: Deterministic Review Findings

Status: complete

This is the only active ExecPlan for M2 and follows `.agent/PLANS.md`. The M0 and M1 plans remain
complete and must not be edited.

## Purpose And Observable Outcome

Consume an M1 `EvidenceBundle` with a pure deterministic review engine and return immutable,
structured Findings for six fixed high-confidence review and security checks. The same logical
evidence must produce the same ordered Python result and canonical JSON without accessing Git,
reading the worktree, calling a model, using a network, writing an artifact, or returning a partial
result after failure.

The observable M2 result is a typed `repoguard.review` API with a versioned `ReviewResult`, stable
rule, category, severity, evidence-reference, and error contracts, plus canonical JSON. The existing
M0 CLI remains version-only. M1 evidence collection and serialization remain unchanged.

## Context, Scope, And Constraints

M1 is committed at `550a7bbf05a4a58bb3499ff3e8aba91041900c3a` on `main`, with M0 as its parent at
`853002cc223be1255d4945f0a8b3a24e99096917`. Recovery on 2026-07-28 confirmed a clean `main`
worktree, no remote, Python 3.12.3, uv 0.9.2, package version 0.1.0, no third-party runtime
dependencies, and Hypothesis 6.163.0 as a development-only dependency. The exact version output was
`repoguard 0.1.0`, and `uv tree --no-dev --frozen` printed only `repoguard v0.1.0`.

The restored M1 shared gate passed Ruff lint and formatting, MyPy strict, all 40 tests, 90.71%
coverage against the unchanged 90% floor, and Git whitespace checks. The first sandboxed
`uv lock --check` attempt failed with
`error: failed to open file '/home/k3nwong/.cache/uv/sdists-v9/.git': Read-only file system
(os error 30)`. The exact command then passed with access to the existing user cache, resolving 18
packages; no project cache setting changed. `uv sync --frozen` audited 17 packages.

M2 accepts only an already collected `EvidenceBundle`. M1 provides repository and revision identity,
ordered changed-file metadata, and UTF-8 diff hunks. It does not provide complete blobs or unchanged
file content, and binary, symlink, submodule, and other content has no text hunks. M2 therefore scans
only addition lines and head-side metadata already present in the bundle. It must not import private
`repoguard._git`, read `RepositoryEvidence.root`, or collect more data.

The package stays at version 0.1.0 and retains an empty runtime dependency list. All rules are fixed
and enabled. M2 has no configuration, path exclusion, inline suppression, severity override,
threshold, CLI command, artifact writer, plugin registry, or deserializer.

M2 does not implement LLM providers, prompts, LangGraph, Agent reasoning, retrieval, embeddings,
FTS5, vector or symbol search, patch generation, worktrees, sandboxes, approvals, GitHub writes,
GitHub Action product behavior, FastMCP, benchmarks, training, a frontend, deployment, monitoring,
or source migration from another project.

The M1 residual risks remain explicitly out of scope: no real missing-object partial-clone
integration, no blob/patch/bundle size limits, no persistent linked-worktree or alternates regression,
the normal-filesystem and POSIX descriptor-path requirement, no remote GitHub-hosted CI run, and no
external CVE or maintainer-health audit. M2 adds no input, scan, or Finding-count limit. Memory use is
linear in the supplied bundle and produced Findings. Rule matching is linear after addition
normalization; sorting addition coordinates and final Findings makes worst-case runtime
`O(N + A log A + F log F)` for total scanned evidence/content size `N`, `A` addition lines, and `F`
produced Findings.

## Public Interfaces And Review Schema

Add `repoguard.review` with these public entry points:

    review_evidence(bundle: EvidenceBundle) -> ReviewResult
    review_to_dict(result: ReviewResult) -> dict[str, object]
    review_to_json(result: ReviewResult) -> str

The module also exports `RuleId`, `FindingCategory`, `FindingSeverity`, `EvidenceSide`,
`EvidenceReference`, `Finding`, `ReviewResult`, `ReviewErrorCode`, and `ReviewError`. Public enums
inherit from `StrEnum` and use lowercase serialized values. Public models are frozen, slotted
dataclasses and use tuples for ordered collections. The package root continues to export only
`__version__`.

`RuleId` contains exactly:

- `private_key_material`
- `merge_conflict_marker`
- `executable_bit_added`
- `symlink_changed`
- `submodule_changed`
- `binary_content_changed`

`FindingCategory` contains `security`, `correctness`, `reviewability`, and `supply_chain`.
`FindingSeverity` contains `info`, `low`, `medium`, `high`, and `critical`; `critical` is part of the
public scale but is not assigned to an M2 rule. `EvidenceSide` contains `old` and `new`; all M2 v1
Findings use `new`.

`EvidenceReference` contains `path`, `side`, `oid`, `start_line`, and `end_line`. Every M2 v1
Finding contains exactly one new-side reference. A text-block reference uses an inclusive line range.
A file-level metadata reference uses JSON null for both line values. References never include source
content, modes, content kinds, or matched secrets.

`Finding` contains `rule_id`, `category`, `severity`, `title`, `message`, `remediation`, and a
non-empty tuple of `references`. It has no timestamp, count, fingerprint, random identifier, matched
text, or dynamic display string.

`ReviewResult` contains the exact input `RepositoryEvidence`, exact input `RevisionEvidence`, an
ordered tuple of Findings, and integer `schema_version` 1. Construction with another review schema
version raises `ValueError`, matching the M1 versioned-model convention. Empty review results retain
repository and revision identity and serialize Findings as an empty JSON array.

`review_to_dict` explicitly maps every field, emits enum values as lowercase strings, tuples as JSON
arrays, and absent line coordinates as null. `review_to_json` uses `ensure_ascii=False`, compact
separators, sorted object keys, and no trailing newline. It does not embed the complete
`EvidenceBundle`.

## Fixed Rule Catalog

### private_key_material

- Category and severity: `security`, `high`.
- Title: `Private key material added`
- Message: `Added lines contain a paired private-key block.`
- Remediation: `Remove the private key, rotate any exposed credential, and load the replacement from an approved secret store.`
- Scan only addition lines, ordered by their new line number within one file change.
- Match case-sensitive marker substrings anywhere in the line for these exact labels:
  `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`,
  `DSA PRIVATE KEY`, `OPENSSH PRIVATE KEY`, and `PGP PRIVATE KEY BLOCK`.
- Greedily pair each `-----BEGIN <label>-----` with a later, unmatched
  `-----END <label>-----` of the same label. A marker participates in at most one pair. Unmatched or
  mismatched labels do not produce a Finding. A same-line pair is valid.
- Produce one Finding for each pair, referencing the inclusive BEGIN-to-END new-line range.

### merge_conflict_marker

- Category and severity: `correctness`, `medium`.
- Title: `Unresolved merge conflict added`
- Message: `Added lines contain a complete unresolved merge-conflict block.`
- Remediation: `Resolve the conflict, remove the conflict markers, and verify the intended combined content.`
- Scan addition lines in new-line order within one file change.
- A start marker begins at column one with `N >= 7` less-than characters and is followed by either
  end-of-line or an ASCII space and label. Its separator is exactly `N` equals characters. Its end
  marker begins at column one with exactly `N` greater-than characters and is followed by either
  end-of-line or an ASCII space and label.
- Greedily pair the earliest unmatched start, its next valid separator, and its next valid end.
  Each marker participates in at most one block. Indented, incomplete, mismatched-length, or
  out-of-order markers do not produce a Finding.
- Produce one Finding for each complete block, referencing the inclusive start-to-end new-line range.

### executable_bit_added

- Category and severity: `security`, `low`.
- Title: `Executable permission introduced`
- Message: `The head version introduces executable permission for this file.`
- Remediation: `Confirm that executable permission is required; otherwise restore a non-executable regular-file mode.`
- Trigger when `new.mode == "100755"` and old is absent or `old.mode != "100755"`.
- Reference the new path and OID with null line coordinates.

### symlink_changed

- Category and severity: `security`, `medium`.
- Title: `Symbolic link introduced or changed`
- Message: `The head version introduces a symbolic link or changes its target object.`
- Remediation: `Verify that the link target is intentional and cannot escape or redirect access outside the expected repository path.`
- Trigger when new content is `symlink` and old is absent, old is not a symlink, or old/new OIDs differ.
- Reference the new path and OID with null line coordinates.

### submodule_changed

- Category and severity: `supply_chain`, `medium`.
- Title: `Submodule pointer introduced or changed`
- Message: `The head version introduces a submodule or changes its referenced commit.`
- Remediation: `Verify the submodule source and review the referenced commit before accepting the change.`
- Trigger when new content is `submodule` and old is absent, old is not a submodule, or old/new OIDs
  differ.
- Reference the new path and OID with null line coordinates.

### binary_content_changed

- Category and severity: `reviewability`, `info`.
- Title: `Opaque binary content introduced or changed`
- Message: `The head version introduces binary content or changes its object ID, so text review evidence is unavailable.`
- Remediation: `Verify the binary's provenance and inspect it with an appropriate trusted tool.`
- Trigger when new content is `binary` and old is absent, old is not binary, or old/new OIDs differ.
- Reference the new path and OID with null line coordinates.

Metadata rules do not trigger for deletions or content-kind/OID-preserving pure renames. A change that
satisfies more than one distinct rule produces each applicable Finding. For example, an added
executable binary produces executable and binary Findings.

## Ordering, Validation, And Error Behavior

The engine evaluates a fixed private rule tuple with no discovery or configuration. Before returning,
it deduplicates exact `rule_id + references` identities and sorts Findings by:

1. severity rank `critical`, `high`, `medium`, `low`, `info`;
2. the first reference path as UTF-8 bytes;
3. start line, treating a file-level null as zero;
4. end line, treating a file-level null as zero;
5. rule ID value;
6. the complete reference tuple as a final deterministic tie-breaker.

Changing only the input `changes` tuple order must not change the returned Python result or canonical
JSON. Hunk and line order are semantic input; text rules normalize addition lines by new line number
within each file change before matching.

`review_evidence` validates only the invariants required to build trustworthy M2 identity and
references, rather than duplicating every M1 parser check:

- the object is an `EvidenceBundle` with schema version 1;
- the `changes`, `hunks`, and `lines` ordered collections have the exact built-in tuple type, so
  validation and rule evaluation observe the same immutable sequences;
- repository root is absolute and UTF-8 encodable;
- object format is `sha1` or `sha256`;
- requested refs and all strings copied into the result are UTF-8 encodable;
- revision OIDs and every new-side OID are lowercase hexadecimal with the object-format length;
- every new-side path is non-empty and UTF-8 encodable;
- every addition line belongs to a change with a new side, has no old line number, and has a unique
  positive new line number within that change.

Unsupported content, absent hunks, deletions, and no matches are successful conditions. M2 does not
fully revalidate change-type/side, hunk-count, mode/content-kind, or old-side consistency already
owned by M1.

`ReviewErrorCode` contains exactly `unsupported_evidence_schema`, `invalid_evidence`, and
`rule_execution_failed`. `ReviewError` exposes its code. Unsupported schema and the listed input
violations fail before rules run. An unexpected exception from a fixed rule becomes
`rule_execution_failed` naming only the rule ID; its public message must not include source content.
All failures are atomic: no partial `ReviewResult` or Findings are returned and no external state is
written.

## Implementation Steps

1. Create this ExecPlan as the first M2 edit and record the restored M1 baseline and confirmed M2
   decisions before editing package or test code.
2. Add `src/repoguard/review.py` for public enums, frozen models, error types, canonical mapping and
   JSON, and a lazy `review_evidence` entry point.
3. Add `src/repoguard/_review.py` for focused input validation, the fixed rule definitions and
   evaluators, block pairing, exact deduplication, and canonical sorting. It imports only public M1
   evidence types and performs no I/O.
4. Add public-contract, rule, property, and collect-to-review integration tests in
   `tests/test_review.py`, `tests/test_review_properties.py`, and
   `tests/test_review_integration.py`.
5. Run focused static and behavioral checks. Record every failure with the exact command, error,
   hypothesis, and a materially changed next method before retrying.
6. Update README only with behavior proven by the focused tests and shared gate. Do not change the
   CLI, package root exports, dependencies, lock, shared gate, CI, M0 plan, or M1 plan.
7. Build and inspect distributions with Python 3.12 standard-library `zipfile`, exercise the public
   API from the built wheel, obtain an independent read-only review, reconcile all confirmed issues,
   and rerun complete acceptance.
8. Complete all four living sections, stage only M2 deliverables, run cached whitespace validation,
   create one local commit, and perform post-commit verification without a remote or push.

## Validation

Run from the repository root:

    uv lock --check
    uv sync --frozen
    uv run pytest tests/test_review.py tests/test_review_properties.py \
        tests/test_review_integration.py
    uv run python -m repoguard --version
    uv tree --no-dev --frozen
    ./scripts/check.sh
    git diff --check
    uv build --python 3.12

The targeted suite must cover:

- an empty result retaining exact repository and revision identity;
- one mixed golden bundle that hits all six rules and asserts exact fields, fixed strings,
  references, deduplication, and severity-first order;
- all seven private-key labels, multiple blocks, same-line pairs, unmatched/mismatched labels, and
  FIFO pairing, and deletion/context negatives;
- default, longer equal-sized, and CRLF conflict markers, multiple blocks, plus indented, incomplete,
  mismatched-length, out-of-order, FIFO pairing, unterminated-carriage-return, deletion, and context
  negatives;
- new and changed executable, symlink, submodule, and binary cases, plus deletion and unchanged-rename
  negatives and an overlapping executable-binary case;
- frozen models, fixed result schema, all three stable errors, non-tuple collection rejection, and
  atomic rule failure;
- Unicode and special paths, UTF-8 validation, exact deduplication, and no matched-content leakage.

Hypothesis remains development-only and uses `database=None`, `derandomize=True`, and 100 examples.
Properties verify repeated review and JSON byte stability, invariance under `changes` permutations,
non-interference from arbitrary deletion/context content, and
`json.loads(review_to_json(result)) == review_to_dict(result)` with UTF-8 encoding, no trailing
newline, and no generated secret body in output.

The integration test creates one disposable local Git repository whose head introduces all six rule
classes, calls `collect_evidence` followed by `review_evidence`, verifies the exact rule IDs and
stable repeat JSON, and confirms repository status is unchanged.

After `uv build --python 3.12`, inspect
`dist/repoguard-0.1.0-py3-none-any.whl` with Python 3.12 `zipfile` and require both
`repoguard/review.py` and `repoguard/_review.py`:

```bash
uv run python - <<'PY'
from pathlib import Path
from zipfile import ZipFile

wheel = Path("dist/repoguard-0.1.0-py3-none-any.whl")
with ZipFile(wheel) as archive:
    names = set(archive.namelist())
required = {"repoguard/review.py", "repoguard/_review.py"}
assert required <= names, required - names
PY
```

Run the current wheel in an isolated no-cache environment and verify an empty valid review:

```bash
uv run --no-project --isolated --no-cache \
    --with ./dist/repoguard-0.1.0-py3-none-any.whl \
    python - <<'PY'
from pathlib import Path

from repoguard.evidence import EvidenceBundle, RepositoryEvidence, RevisionEvidence
from repoguard.review import review_evidence

oid = "a" * 40
bundle = EvidenceBundle(
    repository=RepositoryEvidence(root=Path("/wheel-smoke/repo"), object_format="sha1"),
    revisions=RevisionEvidence(
        base_ref="base",
        head_ref="head",
        base_oid=oid,
        head_oid=oid,
        merge_base_oid=oid,
    ),
    changes=(),
)
result = review_evidence(bundle)
assert result.schema_version == 1
assert result.findings == ()
PY
```

Do not invoke the broken Homebrew `unzip` or install a system package.

The version command must still print `repoguard 0.1.0`; the frozen runtime tree must contain only
`repoguard v0.1.0`. `scripts/check.sh` remains the sole shared local/CI gate and must pass Ruff lint
and format, MyPy strict, every test, at least 90% total coverage, and Git whitespace checks. Record
the final actual test count and coverage rather than predicting them.

Before commit, inspect the complete diff, obtain and reconcile an independent read-only review,
stage only M2 files, and run:

    git diff --cached --check

Create the local commit with message:

    feat: add deterministic review findings

At the committed SHA, rerun the lock check, frozen sync, version command, runtime dependency tree,
and shared gate. Require `git status --short --branch` to report only `## main`. Do not amend M0 or
M1, create a remote, or push.

## Idempotency And Recovery

Review evaluation, canonical serialization, lock checking, frozen synchronization, tests, static
checks, wheel inspection, and all quality gates are safe to rerun. Test repositories and isolated
wheel environments are disposable. `uv build` writes only ignored `dist/` output. README editing,
staging, and the final local commit are deliberate one-time steps; inspect current state before
repeating them.

If the uv cache is read-only, record the exact error here and request only access to the existing
cache. Do not change project cache configuration. For any failure, record the full command and error,
current hypothesis, and changed next approach in Progress. A second attempt must test a different
hypothesis. After three materially different failures without new evidence, mark a blocker and move
to root-cause diagnosis while continuing independent work.

After interruption:

1. Read `AGENTS.md`, `.agent/PLANS.md`, the charter, M0, M1, this plan, and the recovery runbook.
2. Inspect branch, HEAD, status, recent commits, and the complete diff.
3. Rerun the latest successful acceptance command recorded in Progress.
4. Compare actual source, tests, and Git state with this plan.
5. Resume at the first incomplete step, recording any discrepancy before editing.

## Progress

- 2026-07-28: Fully read the repository instructions, ExecPlan protocol, project charter, complete M0
  and M1 plans, and recovery runbook. Confirmed no prior M2 ExecPlan or code existed.
- 2026-07-28: Restored M1 at `550a7bbf05a4a58bb3499ff3e8aba91041900c3a`. Exact lock, frozen
  sync, version, runtime-tree, and shared-gate checks passed; 40 tests passed at 90.71% coverage and
  the worktree remained `## main`.
- 2026-07-28: Confirmed the six-rule catalog, addition/head-side scan boundary, public schema,
  severity/category mappings, exact English copy, evidence-reference shape, ordering, deduplication,
  error behavior, property specifications, package/version boundary, and one-commit policy.
- 2026-07-28: Created this complete M2 ExecPlan as the first M2 edit. Next: add the public review
  contract, private deterministic engine, and focused tests without changing M1 interfaces.
- 2026-07-28: Integration-test static attempt 1 ran
  `uv run ruff check tests/test_review_integration.py` after adding the collect-to-review fixture.
  Ruff reported only `I001` because `repoguard.review` did not exist yet and was classified in a
  different import group from the existing first-party evidence module. Hypothesis: final import
  classification will be stable once the source module lands. Changed approach: defer the import
  reorder, finish the source module, then rerun Ruff on the combined M2 files rather than repeatedly
  formatting against an incomplete package.
- 2026-07-28: The first complete M2 targeted run collected 64 tests across the public contract,
  deterministic properties, and Git integration; all 64 passed. Combined Ruff lint and MyPy strict
  checks over the five M2 source/test files also passed. The matching
  `uv run ruff format --check ...` command failed only because `tests/test_review.py` had two
  non-canonical expression layouts. Hypothesis: this is isolated generated test formatting, not a
  behavior or typing defect. Changed approach: run Ruff's formatter on that one file, then rerun the
  complete five-file static set rather than hand-editing layout.
- 2026-07-28: A worker diagnostic attempted an inline
  `uv run python -c "...\\ntry:..."` fault injection and failed with
  `SyntaxError: unexpected character after line continuation character`; its literal newline
  escaping made the diagnostic invalid before RepoGuard ran. Changed approach: express the fault
  injection as a normal pytest case with monkeypatch and let the typed test suite validate it.
- 2026-07-28: The first focused node-id attempt for that regression ran
  `uv run pytest -q
  tests/test_review.py::test_rule_failure_is_atomic_and_uses_stable_secret_safe_error` and failed
  with `ERROR: not found` and `no tests ran` because the guessed name did not match the authored
  test. Changed approach: inspect the collected test name,
  `test_unexpected_rule_failure_is_atomic_stable_and_does_not_leak`, then run the full targeted
  suite so collection itself verifies every required case.
- 2026-07-28: Main-agent review found that FIFO private-key matching originally used `list.pop(0)`
  and conflict matching repeatedly searched the remainder of the line list, permitting quadratic
  behavior on marker-heavy evidence. The implementation changed to per-label/per-marker-length
  deques and a single pass while preserving greedy semantics. It also tightened exact-int review
  schema validation, unhashable object-format handling, and the non-empty conflict-label boundary.
- 2026-07-28: Hardening patch attempt 1 combined the schema, regex, object-format, and test edits in
  one `apply_patch`, but failed atomically because the completed worker had already inserted the
  object-format type guard and the old context no longer existed. Hypothesis: the desired guard was
  already present and only the remaining independent edits were pending. Changed approach: inspect
  each current snippet, apply smaller non-overlapping patches, and add focused regressions.
- 2026-07-28: The post-review targeted suite now passes all 69 tests. Ruff lint and format plus
  MyPy strict pass over both M2 modules and all three M2 test files. The four deterministic
  Hypothesis properties each execute 100 generated examples. Next: run the complete shared gate and
  exact acceptance sequence before making any README claim.
- 2026-07-28: Exact `uv lock --check` resolved 18 packages, `uv sync --frozen` audited 17 packages,
  the version remained `repoguard 0.1.0`, and the frozen runtime tree contained only
  `repoguard v0.1.0`. The first complete shared gate passed Ruff, MyPy strict, all 109 tests, 92.87%
  coverage, and Git whitespace checks. README was then updated only with those verified M2
  capabilities and limitations.
- 2026-07-28: `uv build --python 3.12` built the sdist and wheel. Python 3.12 standard-library
  `zipfile` found both `repoguard/review.py` and `repoguard/_review.py` in the wheel.
- 2026-07-28: Isolated-wheel smoke attempt 1 ran
  `uv run --no-project --with ./dist/repoguard-0.1.0-py3-none-any.whl python -c "...review_evidence..."`
  and failed with `ModuleNotFoundError: No module named 'repoguard.review'`. A changed diagnostic
  printed the imported module and distribution under uv archive
  `OW7s3N38Rsfyo_yTvGpEz`; listing it showed only the prior M1 package files. Hypothesis: uv reused
  an ephemeral installation cached earlier for the same local path and version, rather than reading
  the newly built wheel.
- 2026-07-28: Isolated-wheel smoke attempt 2 added
  `--reinstall-package repoguard` to the same local-wheel run but failed with the same
  `ModuleNotFoundError`, disproving that reinstall alone refreshes uv 0.9.2's cached local-wheel
  artifact. Changed approach: use command-local `--isolated --no-cache`, which neither changes nor
  deletes project/global cache configuration and must unpack the current wheel in a temporary
  environment.
- 2026-07-28: Isolated-wheel smoke attempt 3 ran the current wheel with
  `--no-project --isolated --no-cache`, installed one package, imported the public review API, and
  returned an empty schema-1 result successfully. Next: inspect the complete diff and obtain the
  required independent read-only review before final acceptance.
- 2026-07-28: Fresh independent read-only review reported one high behavior defect and two plan
  inconsistencies. M1 retains the carriage return in CRLF hunk content, while the conflict rule's
  anchored marker patterns rejected that terminal `\r`; the main wheel-smoke instruction still used
  the stale-cache-prone plain `--with` form; and the plan's linear-runtime claim ignored addition and
  Finding sorting. The reviewer made no edits and its targeted 69-test run plus whitespace check
  passed, but those results preceded the CRLF regression and do not establish acceptance.
- 2026-07-28: CRLF regression attempt 1 ran
  `uv run pytest -q
  tests/test_review.py::test_conflict_rule_treats_terminal_carriage_returns_as_crlf_line_endings
  tests/test_review_integration.py::test_reviews_collected_git_evidence_without_changing_repository`
  after adding both an in-memory boundary case and a real collect-to-review CRLF fixture. Both tests
  failed because no conflict Finding was returned, reproducing the review candidate. Hypothesis:
  the evidence content represents CRLF as terminal `\r` plus `has_trailing_newline=True`. Changed
  approach: normalize that paired terminator to logical-line content before text matching, preserve
  an un-terminated literal carriage return, and rerun the same focused command.
- 2026-07-28: CRLF regression attempt 2 applied that logical-line normalization and reran the same
  two focused nodes; both passed. The real Git fixture now proves collect-to-review behavior for
  CRLF conflicts without changing the evidence schema or M1 parser.
- 2026-07-28: The adversarial read-only review found a separate fail-open input shape: replacing a
  declared tuple collection with a one-shot iterator lets validation consume it before rules run,
  while `None` escapes as an untyped `TypeError`. A direct valid-private-key diagnostic confirmed
  that iterator-backed `changes` returned an empty Finding list. Regression attempt 1 then ran
  `uv run pytest -q tests/test_review.py -k
  'invalid_evidence_has_stable_error_code_without_source_leakage'`; the 14 existing invalid bundles
  passed and all six new iterator/`None` cases failed, three by returning normally and three with raw
  `TypeError`. Hypothesis confirmed: M2 must enforce the public tuple shape before iteration. Changed
  approach: validate `changes`, `hunks`, and `lines` as tuples before traversing them, then rerun the
  same stable-error set.
- 2026-07-28: Tuple-shape regression attempt 2 reran that stable-error set after adding preflight
  checks; all 20 invalid-bundle cases passed. The complete M2 behavioral suite then passed all 76
  tests. Its parallel static command stopped at Ruff `RUF005` because `_invalid_bundles` appended the
  six cases with list concatenation; MyPy and format did not run after the short-circuited lint
  command. Hypothesis: this is isolated test-fixture style, not behavior or typing. Changed approach:
  use iterable unpacking inside the returned list and rerun the full lint, format, and strict-MyPy
  sequence rather than invoking only the failed lint step.
- 2026-07-28: Unterminated-CR boundary attempt 1 ran
  `uv run pytest -q
  tests/test_review.py::test_conflict_rule_preserves_unterminated_carriage_return_as_content` and
  failed because the test put the CR after an end-marker label. That remains a valid non-empty label
  under the confirmed grammar, so the Finding was correct. Changed hypothesis: put the literal CR
  after the exact equals-only separator and mark only that line unterminated; this distinguishes
  source content from a CRLF terminator without changing the accepted label grammar.
- 2026-07-28: The adversarial review's post-fix pass found that `isinstance(collection, tuple)` still
  accepts a tuple subclass whose overridden iterator exposes evidence only on its first traversal.
  Validation sees the match, all rule traversals see an empty sequence, and the result is again
  fail-open. It also corrected the complexity expression to include linear scanning when additions
  and Findings are empty. Changed approach: add tuple-subclass regressions for all three collection
  levels, require the exact built-in tuple type, and state worst-case runtime as
  `O(N + A log A + F log F)`.
- 2026-07-28: Tuple-subclass regression attempt 1 ran
  `uv run pytest -q tests/test_review.py -k
  'invalid_evidence_has_stable_error_code_without_source_leakage'`; all 20 prior invalid shapes
  passed and the three new first-traversal-only tuple subclasses returned normally instead of
  raising. Hypothesis confirmed: subclass iteration can violate repeatability despite
  `isinstance(..., tuple)`. Changed approach: require `type(collection) is tuple` at each collection
  level, matching the exact public evidence representation, then rerun the same command.
- 2026-07-28: Unterminated-CR boundary attempt 2 moved the literal CR to an unterminated exact
  separator and reran the focused node; it passed, proving the normalization is conditional on an
  actual recorded line terminator. Tuple-subclass attempt 2 changed all three checks to exact
  built-in tuples and reran the stable-error set; all 23 cases passed. The subsequent complete M2
  suite passed all 80 tests, and Ruff lint, Ruff format, and MyPy strict passed across all five M2
  source/test files. Next: finish the adversarial review and run the complete exact acceptance and
  distribution checks.
- 2026-07-28: The adversarial read-only review completed after the exact-tuple fix with no remaining
  product-behavior findings. It identified one low test gap: existing multiple-block examples did not
  directly distinguish FIFO `popleft()` from LIFO `pop()` when same-label or same-length starts were
  simultaneously pending. The review made no edits. Next: add the two minimal FIFO assertions,
  mutation-check them, then restart final acceptance; the already passed lock and frozen-sync checks
  precede this test edit and are not final evidence.
- 2026-07-28: Both new FIFO nodes first passed on the deque implementation. A controlled mutation
  changed the two relevant start queues from `popleft()` to `pop()` and reran
  `uv run pytest -q tests/test_review.py::test_private_key_rule_pairs_same_label_markers_fifo
  tests/test_review.py::test_conflict_rule_pairs_same_length_markers_fifo`; both tests failed with
  the expected crossed reference ranges. Restoring `popleft()` and rerunning the identical command
  produced `2 passed`. The tests therefore distinguish the required FIFO semantics. Next: restart
  the full exact acceptance sequence from the lock check.
- 2026-07-28: Final exact pre-commit acceptance passed from the updated worktree. `uv lock --check`
  resolved 18 packages, `uv sync --frozen` audited 17 packages, and all 82 targeted M2 tests passed.
  The version output remained `repoguard 0.1.0`, and the frozen runtime tree contained only
  `repoguard v0.1.0`. `./scripts/check.sh` passed Ruff lint and format, MyPy strict, all 122 tests,
  92.96% coverage against the unchanged 90% floor, and Git whitespace checks; the separate
  `git diff --check` also passed.
- 2026-07-28: `uv build --python 3.12` rebuilt both distributions from the final source. The exact
  Python 3.12 `zipfile` check found `repoguard/review.py` and `repoguard/_review.py`, and the documented
  `uv run --no-project --isolated --no-cache --with <wheel>` smoke installed the current wheel and
  returned an empty schema-1 review. Both independent read-only reviews are fully reconciled, with no
  remaining product-behavior finding. This plan is complete. Next: rerun the shared gate after this
  final plan edit, inspect and stage only the seven M2 deliverables, create the required local commit,
  and perform post-commit verification without a remote or push.
- 2026-07-28: Three shared-gate runs after completing the plan all passed 122 tests, with exact
  coverage observations of 92.72%, 92.72%, and 92.96%. The preceding exact gate also reported
  92.96%. Thread scheduling conditionally executes M1 `_write_pipe`'s existing `BrokenPipeError`
  handler, moving lines 510-511 in or out of coverage. This is coverage-path variance in unchanged
  M1 concurrency cleanup, not a behavior or threshold failure; the observed range is 92.72%-92.96%.

## Surprises & Discoveries

- 2026-07-28: The first exact `uv lock --check` recovery attempt reproduced the documented
  read-only user-cache mount error. Repeating the unchanged command with access to the existing cache
  passed; this was an environment restriction, not a lock defect.
- 2026-07-28: M1 evidence has sufficient semantic coordinates for addition and head-metadata rules,
  but intentionally lacks complete text and special-object bodies. A pure M2 layer cannot correctly
  implement full-file or whole-repository scans without expanding the evidence contract.
- 2026-07-28: A manually constructed `EvidenceBundle` can violate cross-field semantics because M1
  validates only its schema version at model construction. M2 therefore validates the smaller set
  of invariants required for stable identity and references and leaves complete M1 validation with
  the evidence producer.
- 2026-07-28: Straightforward greedy block pairing can violate the documented linear-complexity
  boundary even when its outputs are correct on ordinary examples. Marker queues must use deques,
  and conflict pairing must advance in one pass rather than restart searches from every marker.
- 2026-07-28: uv 0.9.2 can reuse stale installed content for a rebuilt local wheel when its path and
  package version are unchanged, even with `--reinstall-package`. The wheel itself was correct;
  command-local isolated no-cache installation was required to test its current bytes.
- 2026-07-28: M1 patch parsing removes LF but deliberately leaves the preceding CR in CRLF content.
  Anchored logical-line rules must account for `has_trailing_newline` rather than assuming evidence
  content has no line-terminator bytes.
- 2026-07-28: Deterministic coordinate normalization and canonical Finding order require sorting;
  deque-based marker pairing is linear, but the review operation as a whole is not worst-case linear.
- 2026-07-28: Frozen dataclasses do not enforce tuple annotations at runtime. Without explicit
  collection-shape validation, one-shot iterators can be exhausted during preflight and make
  matching evidence appear clean; non-iterables can also bypass the stable error contract.
- 2026-07-28: M1 pipe-writer thread scheduling can move total coverage between 92.72% and 92.96% by
  conditionally exercising its `BrokenPipeError` cleanup branch. Both paths pass all behavior and
  quality gates; final reporting uses the repeated 92.72% observation rather than selecting the
  higher incidental measurement.

## Decision Log

- 2026-07-28: Accept only `EvidenceBundle` and expose `review_evidence`; do not add a repository/PR
  convenience wrapper. Reason: this preserves a pure deterministic boundary and keeps Git behavior
  owned by M1.
- 2026-07-28: Keep zero runtime dependencies and use six fixed rules with no configuration. Reason:
  M1 already supplies everything these rules need, while parsers, policy configuration, and product
  controls would expand the stage.
- 2026-07-28: Use a separate versioned `ReviewResult` with semantic references rather than extending
  or embedding M1 evidence. Reason: M1 schema 1 remains stable, empty results stay traceable, and
  review JSON does not duplicate an unbounded bundle.
- 2026-07-28: Omit fingerprints and matched text. Reason: the accepted rule-and-reference identity
  is sufficient for exact deduplication, avoids premature identity semantics, and prevents secret
  material from being copied into Findings.
- 2026-07-28: Use severity-first canonical ordering and make results invariant to change ordering.
  Reason: consumers see the highest-risk result first without depending on rule execution or caller
  tuple order.
- 2026-07-28: Fail atomically with three stable review error codes. Reason: silent skips or partial
  Findings could be misinterpreted as a complete clean review.
- 2026-07-28: Implement private-key and conflict pairing as single-pass FIFO state machines keyed by
  label or marker length. Reason: this preserves the confirmed greedy matching contract and keeps
  runtime linear for adversarial marker sequences.
- 2026-07-28: Keep package version 0.1.0, build one additive M2 commit, and preserve all M0/M1
  history. Reason: this follows the confirmed stage history policy without creating a release event.
- 2026-07-28: Use `uv run --no-project --isolated --no-cache --with <wheel>` for same-version local
  wheel smoke tests. Reason: this exercises current wheel bytes without mutating project cache
  policy or trusting uv's stale path/version archive entry.
- 2026-07-28: Treat a terminal `\r` as part of a CRLF terminator only when the evidence line reports
  a trailing newline. Reason: marker rules operate on logical lines, while an unterminated literal
  carriage return remains source content and must not be silently normalized.
- 2026-07-28: Reject evidence collections whose runtime type is not the exact built-in tuple with
  `invalid_evidence`. Reason: validation plus rule evaluation must traverse the same repeatable,
  immutable sequence rather than silently consume caller-supplied iterators or tuple subclasses with
  overridden traversal.

## Outcomes & Retrospective

M2 delivers a dependency-free, pure deterministic review layer over M1 `EvidenceBundle` values. The
public API returns frozen, versioned review results and canonical JSON for six fixed rules covering
paired private-key material, complete unresolved conflict blocks, newly executable files, changed
symlinks, changed submodules, and changed opaque binary content. Findings use stable rule/category/
severity values and semantic evidence references, omit matched content, deduplicate exact identities,
and sort independently of input change order. Validation fails atomically with three stable error
codes and rejects unsupported schemas, untrustworthy identities/references, and non-exact tuple
collection shapes before rule execution.

Final pre-commit acceptance passed the exact lock check, frozen sync, all 82 targeted M2 tests, the
unchanged version command, the dependency-free runtime tree, `git diff --check`, and the sole shared
gate. Every shared-gate run passed all 122 tests; exact coverage varied between 92.72% and 92.96%
only because of an existing M1 concurrent cleanup branch described above. Every run passed Ruff lint
and formatting, MyPy strict, and the unchanged 90% coverage floor. Hypothesis remains
development-only; four deterministic properties each run 100 examples.

Both distributions built successfully, standard-library `zipfile` found both M2 modules in the
wheel, and a command-local isolated no-cache installation exercised the current wheel's public API.

Two independent read-only reviews materially improved the result. Their CRLF conflict false
negative, stale wheel command, complexity overstatement, one-shot collection fail-open, tuple
subclass bypass, and missing FIFO mutation coverage were all reproduced and reconciled. The final
review found no remaining product-behavior issue. The engine modules still perform no Git, filesystem,
network, model, artifact, or external-system I/O, and M0/M1 interfaces, history, CLI behavior,
dependency metadata, lock, and quality thresholds remain unchanged.

M2 remains intentionally bounded by M1 evidence: it scans only addition lines and head-side metadata,
not complete files or unchanged repository content, and the six checks are not a comprehensive
security scanner. There are no bundle, text, or Finding-count limits; memory use is linear and
worst-case runtime includes deterministic sorting as documented above. M1's missing-object,
linked-worktree, alternates, descriptor-path, remote-CI, and external dependency-audit residual risks
also remain. A chained internal rule exception remains available through `ReviewError.__cause__` for
debugging even though the stable public error message excludes source content. No M3 or later-stage
provider, Agent, retrieval, repair, GitHub product, benchmark, training, frontend, deployment, or
monitoring behavior was introduced.
