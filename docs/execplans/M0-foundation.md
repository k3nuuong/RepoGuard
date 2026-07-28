# M0: Project Foundation And Development Governance

Status: complete

This is the only active ExecPlan for M0 and follows `.agent/PLANS.md`.

## Purpose And Observable Outcome

Create a new, independent Python 3.12 repository at
`/home/k3nwong/learning/LLM/code/RepoGuard`. A fresh checkout must install from `uv.lock`, expose a
no-key version command, and pass the shared Ruff, MyPy strict, pytest coverage, and Git whitespace
gate locally and in GitHub Actions.

## Context, Scope, And Constraints

The outer `/home/k3nwong/learning/LLM/code` directory is not a Git repository. The initial target path
unexpectedly contained an unborn `main` repository with staged M00 governance files that specified
event ledgers, leases, SQLite projections, and `repoguard-dev`. The user explicitly directed that
content to be deleted and the target rebuilt from M0.

M0 contains only package scaffolding, locked development tooling, tests, CI, governance documents, and
ignored state boundaries. It does not implement LLM providers, prompts, Agent workflows, retrieval,
GitHub APIs, patch generation, approval systems, benchmarks, training, development schedulers,
containers, frontends, deployment, monitoring, or source migration from sibling projects.

Python 3.12 is the development and CI version. M0 has no third-party runtime dependency. The only
direct development dependencies are pytest, pytest-cov, Ruff, and MyPy.

## Implementation Steps

1. Remove the conflicting unborn repository and initialize a new independent Git repository on
   `main`.
2. Create this plan and the ExecPlan protocol before package implementation.
3. Add the `src/repoguard` package, argparse module entry point, typed-package marker, and focused
   package and CLI tests.
4. Add `pyproject.toml`, `.python-version`, `uv.lock`, Ruff, MyPy strict, pytest, and coverage
   configuration.
5. Add the shared executable `scripts/check.sh` and a Python 3.12 GitHub Actions workflow that performs
   a frozen sync and invokes only that script for quality checks.
6. Add concise repository instructions, the stable project charter, recovery runbook, truthful
   README, and ignore rules for local state, secrets, caches, and build output.
7. Run every acceptance command, obtain a read-only review, update all living sections, rerun the
   gates, and create the initial local commit.

## Validation

Run from the repository root:

    uv lock --check
    uv sync --frozen
    uv run python -m repoguard --version
    ./scripts/check.sh
    git diff --cached --check

The version command must print `repoguard 0.1.0` and exit zero. `scripts/check.sh` must pass with at
least 90% coverage. Before commit, the staged file list must contain only the 17 M0 deliverables and
`scripts/check.sh` must have mode `100755`. After commit, rerun the frozen sync, version command, and
shared check at the committed SHA and require a clean worktree.

## Idempotency And Recovery

The initial deletion is a completed one-time action authorized by the user; do not repeat it after the
new repository contains M0 work. Locking, frozen synchronization, the version command, and all quality
checks are safe to rerun. If dependency resolution requires network access, request only the access
needed by uv and do not install system packages.

After interruption, follow `docs/runbooks/session-recovery.md` once it exists. Until then, read this
file and `.agent/PLANS.md`, then inspect `git status --short --branch`, the current branch, HEAD if one
exists, and the file list. Resume at the first incomplete Progress item.

For any failure, record the full command, error, hypothesis, and changed next approach below. After
three different approaches fail without new evidence, mark a blocker and switch to root-cause
diagnosis while continuing independent M0 work.

## Progress

- 2026-07-28T17:34:09+08:00: Confirmed the target path, outer Git boundary, uv 0.9.2, Git 2.43.0,
  Python 3.12.3, and configured Git identity.
- 2026-07-28T17:34:09+08:00: Deleted the conflicting staged M00 scaffold as explicitly directed and
  initialized a new independent unborn `main` repository.
- 2026-07-28T17:34:09+08:00: Created the ExecPlan protocol and this active M0 plan before package
  implementation. Next: create the required package, tooling, CI, and documentation files.
- 2026-07-28T17:37:27+08:00: Added the 16 authored M0 files: package metadata and entry point, tests,
  quality configuration, executable shared check, pinned-action CI, ignore policy, README, charter,
  and recovery runbook. Next: generate `uv.lock` with Python 3.12 and run the first full gate.
- 2026-07-28T17:39:11+08:00: Lock attempt 1 failed. Command:
  `uv lock --cache-dir /tmp/repoguard-uv-cache --python 3.12`. Error: fetching
  `https://pypi.org/simple/pytest-cov/` failed after three retries with a TCP
  `Operation not permitted`. Hypothesis: sandbox network policy blocked PyPI; attempt 2 will change
  the execution method by requesting network access only for `uv lock`.
- 2026-07-28T17:40:17+08:00: Lock attempt 2 with approved network access resolved 16 packages, and
  `uv lock --check --cache-dir /tmp/repoguard-uv-cache --python 3.12` passed. Frozen sync attempt 1,
  `uv sync --frozen --cache-dir /tmp/repoguard-uv-cache --python 3.12`, built the local package but
  failed to download locked `pluggy==1.6.0` after three retries with `Operation not permitted`.
  Hypothesis: the same sandbox network policy blocked wheel download; sync attempt 2 will request
  network access for the frozen install without changing the lock.
- 2026-07-28T17:41:16+08:00: Frozen sync attempt 2 with approved network access installed all 15
  packages, including RepoGuard 0.1.0. Version-command attempt 1,
  `uv run python -m repoguard --version`, failed before Python started because the Codex filesystem
  sandbox made `/home/k3nwong/.cache/uv/sdists-v9/.git` read-only. Hypothesis: this is a sandbox-only
  cache restriction; attempt 2 will run the exact same user-facing command with the required
  filesystem permission rather than alter the command or project configuration.
- 2026-07-28T17:43:38+08:00: The exact `uv lock --check`, `uv sync --frozen`, and
  `uv run python -m repoguard --version` commands passed; the version output was
  `repoguard 0.1.0`. The first `./scripts/check.sh` run passed Ruff lint and format, MyPy strict, five
  tests, 92.31% coverage, and `git diff --check`. The staged set contains exactly 17 files,
  `git diff --cached --check` passed, and `scripts/check.sh` is mode `100755`. Next: obtain the
  independent read-only M0 review.
- 2026-07-28T17:46:06+08:00: `uv tree --no-dev --frozen` showed only RepoGuard 0.1.0, and
  `uv build --python 3.12` built both sdist and wheel. The combined inspection command
  `unzip -l dist/repoguard-0.1.0-py3-none-any.whl; tar -tzf dist/repoguard-0.1.0.tar.gz` encountered
  `/home/linuxbrew/.linuxbrew/bin/unzip: cannot execute: required file not found`; the tar inspection
  still confirmed `py.typed` in the sdist. Hypothesis: the system unzip binary is broken, not the
  wheel. The changed verification method will inspect the wheel with Python 3.12's standard-library
  `zipfile` module.
- 2026-07-28T17:51:40+08:00: Standard-library `zipfile` inspection confirmed `py.typed` in the wheel.
  The independent read-only Reviewer found no issues and reran the lock check, frozen sync dry-run,
  version command, complete shared gate, cached whitespace check, tracked-ignore audit, dependency
  boundary audit, and documentation/scope review. Next: rerun the gate after this plan update, create
  the initial commit, and verify the committed SHA.

## Surprises & Discoveries

- 2026-07-28T17:34:09+08:00: Contrary to the supplied initial environment description, `RepoGuard`
  already existed with 20 staged files and no commit. Its planned ledger, lease, scheduler, evidence
  ref, and development CLI exceeded M0, so retaining it would have violated the requested boundary.
- 2026-07-28T17:34:09+08:00: Unqualified `python` and `python3` do not reliably select Python 3.12 in
  this environment. Project commands must rely on `.python-version` and uv.
- 2026-07-28T17:41:16+08:00: The Codex filesystem sandbox exposes the existing user uv cache as
  read-only, so exact `uv run` commands require the normal user permission context during this
  session. The commands themselves work unchanged outside that sandbox restriction.
- 2026-07-28T17:51:40+08:00: The locally installed Homebrew `unzip` entry point cannot execute, but
  Python 3.12's `zipfile` module verified the wheel without adding a system dependency.

## Decision Log

- 2026-07-28T17:34:09+08:00: Fully recreate the target, including Git metadata, without preserving a
  backup ref. Reason: the user explicitly requested a complete reset and a new M0 history.
- 2026-07-28T17:34:09+08:00: Use package version `0.1.0`, standard-library argparse, and
  `uv_build==0.9.2`. Reason: this is the smallest installable typed package aligned with the fixed uv
  tool version and adds no runtime dependency.
- 2026-07-28T17:34:09+08:00: Use a safety-first M1-M8 charter sequence. Reason: the user selected
  read-only evidence and deterministic review before model reasoning, retrieval, or write capability.
- 2026-07-28T17:34:09+08:00: Install uv 0.9.2 explicitly in CI and pin official actions by commit SHA.
  Reason: this keeps the tool version reproducible without relying on an unverified setup-uv tag.

## Outcomes & Retrospective

M0 delivered the 17 requested tracked files: a Python 3.12 `src` package, typed marker, argparse
version command, focused tests, uv lock, strict quality configuration, executable shared gate,
single-entry CI, ignored state boundaries, concise agent governance, stable charter, active-stage
history, recovery runbook, and truthful README. No M1 or later implementation was added.

Before the initial commit, the exact `uv lock --check`, `uv sync --frozen`,
`uv run python -m repoguard --version`, and `./scripts/check.sh` commands passed. Five tests passed with
92.31% coverage; Ruff, formatting, MyPy strict, working-tree whitespace, cached whitespace, the
17-file whitelist, script mode, runtime dependency tree, ignored-file tracking check, sdist, and wheel
also passed. A read-only Reviewer independently reported no findings.

GitHub-hosted Actions cannot be run without creating a remote, which M0 prohibits, so only the
workflow structure and immutable action pins were verified locally. The pinned v4.3.1 checkout and
v5.6.0 setup-python releases are valid but older than current upstream majors. No external CVE or
dependency-maintainer health audit was performed. These are residual maintenance risks, not failed M0
acceptance gates.

The reset removed an over-scoped bootstrap and kept the final foundation deliberately small. Recording
failed commands and changing the next method distinguished sandbox and host-tool faults from project
defects without weakening any gate.
