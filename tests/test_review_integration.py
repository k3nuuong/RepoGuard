"""Integration tests joining committed Git evidence to deterministic review."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence
from repoguard.review import RuleId, review_evidence, review_to_json


def _git_environment() -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update({"LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"})
    return environment


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        env=_git_environment(),
    )


def _commit(root: Path, message: str, *, add_all: bool = True) -> str:
    if add_all:
        _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=RepoGuard Tests",
        "-c",
        "user.email=repoguard@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD").stdout.decode("ascii").strip()


def test_reviews_collected_git_evidence_without_changing_repository(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "README.txt").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")

    _git(root, "switch", "-c", "feature")
    (root / "secrets.py").write_text(
        'key = """-----BEGIN PRIVATE KEY-----\n'
        "sensitive-body-not-for-output\n"
        '-----END PRIVATE KEY-----"""\n',
        encoding="utf-8",
    )
    (root / "conflicted.txt").write_bytes(
        b"<<<<<<< HEAD\r\nleft\r\n=======\r\nright\r\n>>>>>>> feature\r\n"
    )
    executable = root / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    os.symlink("README.txt", root / "current")
    (root / "binary.dat").write_bytes(b"prefix\0suffix")
    _git(root, "add", "--all")
    _git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        base_oid,
        "vendor/component",
    )
    head_oid = _commit(root, "feature", add_all=False)
    status_before = _git(root, "status", "--porcelain=v1", "-z").stdout

    evidence = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    first = review_evidence(evidence)
    second = review_evidence(evidence)

    assert [finding.rule_id for finding in first.findings] == [
        RuleId.PRIVATE_KEY_MATERIAL,
        RuleId.MERGE_CONFLICT_MARKER,
        RuleId.SYMLINK_CHANGED,
        RuleId.SUBMODULE_CHANGED,
        RuleId.EXECUTABLE_BIT_ADDED,
        RuleId.BINARY_CONTENT_CHANGED,
    ]
    assert first == second
    assert review_to_json(first) == review_to_json(second)
    assert "sensitive-body-not-for-output" not in review_to_json(first)
    assert _git(root, "status", "--porcelain=v1", "-z").stdout == status_before
