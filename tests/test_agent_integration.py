"""Integration tests joining Git evidence to controlled Agent review."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from repoguard.agent import (
    AgentNode,
    AgentReviewConfig,
    AgentReviewError,
    AgentReviewErrorCode,
    AgentRuleId,
    FindingSource,
    agent_review_to_json,
    review_with_agent,
)
from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence
from repoguard.providers import LLMRequest, LLMResponse
from repoguard.review import EvidenceSide, RuleId

_SECRET = "INTEGRATION-PRIVATE-KEY-BODY-DO-NOT-SEND"
_FORBIDDEN_ARTIFACTS = (".repoguard", "artifacts", ".worktrees")


class _RecordingProvider:
    def __init__(self, responses: Sequence[LLMResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[LLMRequest] = []

    @property
    def name(self) -> str:
        return "integration-fake"

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return self._responses.pop(0)


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


def _commit(root: Path, message: str) -> str:
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


def _create_repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "README.txt").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")

    _git(root, "switch", "-c", "feature")
    (root / "app.py").write_text(
        "def calculate() -> float:\n    return 1 / 0\n",
        encoding="utf-8",
    )
    (root / "private.pem").write_text(
        f"-----BEGIN PRIVATE KEY-----\n{_SECRET}\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    head_oid = _commit(root, "feature")
    return root, base_oid, head_oid


def _model_finding(path: str) -> dict[str, object]:
    return {
        "category": "correctness",
        "severity": "medium",
        "title": "Division by zero",
        "message": "The new return statement always divides by zero.",
        "remediation": "Use a non-zero divisor and add a regression test.",
        "references": [
            {
                "path": path,
                "side": "new",
                "start_line": 2,
                "end_line": 2,
            }
        ],
    }


def _response(findings: Sequence[dict[str, object]]) -> LLMResponse:
    return LLMResponse(
        output_text=json.dumps(
            {"schema_version": 1, "findings": list(findings)},
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _worktree_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and ".git" not in path.relative_to(root).parts
    }


def _assert_no_agent_artifacts(root: Path) -> None:
    for name in _FORBIDDEN_ARTIFACTS:
        assert not (root / name).exists()


def test_collected_evidence_agent_success_preserves_git_and_creates_no_artifact(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.clear()
    root, base_oid, head_oid = _create_repository(tmp_path)
    status_before = _git(root, "status", "--porcelain=v1", "-z").stdout
    files_before = _worktree_files(root)
    _assert_no_agent_artifacts(root)
    evidence = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    provider = _RecordingProvider([_response((_model_finding("app.py"),))])

    result = review_with_agent(
        evidence,
        provider=provider,
        config=AgentReviewConfig(model="integration-model"),
    )

    assert [(finding.source, finding.rule_id) for finding in result.findings] == [
        (FindingSource.DETERMINISTIC, RuleId.PRIVATE_KEY_MATERIAL),
        (FindingSource.AGENT, AgentRuleId.AGENT_REASONING),
    ]
    agent_finding = result.findings[1]
    assert agent_finding.references[0].path == "app.py"
    assert agent_finding.references[0].side is EvidenceSide.NEW
    assert agent_finding.references[0].start_line == 2
    assert agent_finding.references[0].oid != ""
    assert result.attempt_count == 1
    assert len(provider.requests) == 1
    assert _SECRET not in provider.requests[0].messages[1].content
    assert _SECRET not in agent_review_to_json(result)
    assert _SECRET not in "\n".join(record.getMessage() for record in caplog.records)
    assert _git(root, "status", "--porcelain=v1", "-z").stdout == status_before
    assert _worktree_files(root) == files_before
    _assert_no_agent_artifacts(root)


def test_collected_evidence_agent_failure_is_atomic_and_creates_no_artifact(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.clear()
    root, base_oid, head_oid = _create_repository(tmp_path)
    status_before = _git(root, "status", "--porcelain=v1", "-z").stdout
    files_before = _worktree_files(root)
    _assert_no_agent_artifacts(root)
    evidence = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    valid = _model_finding("app.py")
    invalid = _model_finding("not-in-evidence.py")
    provider = _RecordingProvider([_response((valid, invalid))])

    with pytest.raises(AgentReviewError) as exc_info:
        review_with_agent(
            evidence,
            provider=provider,
            config=AgentReviewConfig(model="integration-model"),
        )

    assert exc_info.value.code is AgentReviewErrorCode.INVALID_MODEL_OUTPUT
    assert exc_info.value.node is AgentNode.PARSE_RESPONSE
    assert exc_info.value.attempt_count == 1
    assert str(exc_info.value) == "model output is invalid"
    assert exc_info.value.__cause__ is None
    assert len(provider.requests) == 1
    assert _SECRET not in provider.requests[0].messages[1].content
    assert _SECRET not in str(exc_info.value)
    assert "not-in-evidence.py" not in str(exc_info.value)
    assert _SECRET not in "\n".join(record.getMessage() for record in caplog.records)
    assert _git(root, "status", "--porcelain=v1", "-z").stdout == status_before
    assert _worktree_files(root) == files_before
    _assert_no_agent_artifacts(root)
