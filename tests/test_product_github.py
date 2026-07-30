"""Product-orchestrator GitHub publication and Action-import boundaries."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, cast

import pytest

from repoguard.github import (
    GITHUB_CHECK_CONFIRMATION,
    GITHUB_PROPOSAL_MAX_BYTES,
    GITHUB_REPAIR_CONFIRMATION,
    GitHubApprovalInterface,
    GitHubPermission,
    GitHubProposal,
    GitHubProposalOrigin,
    GitHubPublicationResult,
    GitHubPublicationState,
    approve_github_proposal,
    build_github_check_proposal,
    build_github_repair_proposal,
    build_github_result,
    github_proposal_to_json,
)
from repoguard.github_publication import (
    GitHubPublicationError,
    GitHubPublicationErrorCode,
    GitHubPublicationErrorDomain,
    GitHubPublicationStage,
)
from repoguard.host_profile import (
    HostMCPWriters,
    HostProfile,
    HostRepository,
    ProductProviderKind,
    ProductReviewMode,
    ProductReviewProfile,
)
from repoguard.product import (
    ProductConclusion,
    ProductErrorDomain,
    ProductExitCode,
    ProductInterface,
    ProductOperation,
    ProductOrchestrator,
    ProductReviewResult,
    ProductStage,
    product_envelope_to_json,
    product_exit_code,
)
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    REPAIR_PUBLICATION_AUTHOR_EMAIL,
    REPAIR_PUBLICATION_AUTHOR_NAME,
    REPAIR_PUBLICATION_COMMIT_MESSAGE,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairPreview,
    RepairPromptIdentity,
    RepairSnapshot,
    RepairState,
    RepairValidation,
    ValidationCommandResult,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

_REPOSITORY_ID = 123456
_REPOSITORY_FULL_NAME = "owner/repository"
_BASE_OID = "1" * 40
_HEAD_OID = "2" * 40
_TREE_OID = "3" * 40
_CANDIDATE_ID = "4" * 64
_VALIDATION_SHA256 = "5" * 64
_SESSION_ID = "6" * 64
_APPLICATION_SHA256 = "7" * 64


def _profile(tmp_path: Path) -> HostProfile:
    repository = tmp_path / "repository"
    product_state = tmp_path / "product-state"
    repair_state = tmp_path / "repair-state"
    for directory in (repository, product_state, repair_state):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    return HostProfile(
        schema_version=1,
        repositories=(
            HostRepository(
                alias="repository",
                path=repository,
                github_repository_id=_REPOSITORY_ID,
                github_full_name=_REPOSITORY_FULL_NAME,
            ),
        ),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/true"),
        rootless_socket=tmp_path / "docker.sock",
        product_state_root=product_state,
        repair_state_root=repair_state,
        runner_labels=(),
        m4_caches=(),
        review_profiles=(
            ProductReviewProfile(
                name="deterministic",
                mode=ProductReviewMode.DETERMINISTIC,
                provider=ProductProviderKind.NONE,
                model=None,
                cache=None,
                device=EmbeddingDevice.CPU,
                fail_on=FindingSeverity.HIGH,
            ),
        ),
        repair_profiles=(),
        github_actions=None,
        mcp=HostMCPWriters(publish_check=True, publish_repair=True),
    )


def _review() -> ProductReviewResult:
    return ProductReviewResult(
        schema_version=1,
        repository_alias="repository",
        object_format="sha1",
        base_ref="main",
        head_ref="feature",
        base_oid=_BASE_OID,
        head_oid=_HEAD_OID,
        merge_base_oid=_BASE_OID,
        review_profile="deterministic",
        provider=None,
        model=None,
        evidence_sha256="8" * 64,
        deterministic_review_sha256="9" * 64,
        review_sha256="a" * 64,
        findings=(),
        finding_count=0,
        highest_severity=None,
        conclusion=ProductConclusion.SUCCESS,
    )


def _check_proposal(
    *,
    origin: GitHubProposalOrigin = GitHubProposalOrigin.ACTION,
    repository_id: int = _REPOSITORY_ID,
    repository_full_name: str = _REPOSITORY_FULL_NAME,
) -> GitHubProposal:
    return build_github_check_proposal(
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        pull_request_number=7,
        base_ref="main",
        origin=origin,
        review_result=_review(),
        policy_sha256="b" * 64,
        created_at_us=1_000_000,
    )


def _fixed_commit_oid() -> str:
    identity = f"{REPAIR_PUBLICATION_AUTHOR_NAME} <{REPAIR_PUBLICATION_AUTHOR_EMAIL}> 0 +0000"
    content = (
        f"tree {_TREE_OID}\n"
        f"parent {_HEAD_OID}\n"
        f"author {identity}\n"
        f"committer {identity}\n"
        "\n"
        f"{REPAIR_PUBLICATION_COMMIT_MESSAGE}"
    ).encode()
    header = f"commit {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


_COMMIT_OID = _fixed_commit_oid()


def _repair_proposal(
    *,
    origin: GitHubProposalOrigin = GitHubProposalOrigin.ACTION,
) -> GitHubProposal:
    prompt = RepairPromptIdentity(
        "repoguard_repair",
        1,
        "1" * 64,
        "2" * 64,
        "3" * 64,
    )
    context = RepairContextSummary(
        RepairContextOutcome.NOT_REQUESTED,
        None,
        None,
        0,
        0,
        0,
        None,
        None,
    )
    candidate = RepairCandidate(
        1,
        _CANDIDATE_ID,
        "c" * 64,
        prompt,
        context,
        "d" * 64,
        _TREE_OID,
        _COMMIT_OID,
        ("src/app.py",),
        1,
        0,
        0,
        0,
    )
    command = ValidationCommandResult(
        0,
        0,
        None,
        False,
        1,
        "e" * 64,
        0,
        False,
        "f" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        _VALIDATION_SHA256,
        _CANDIDATE_ID,
        "0" * 64,
        "1" * 64,
        f"sha256:{'2' * 64}",
        1,
        2,
        True,
        None,
        (command,),
        1,
        False,
        0,
        1,
        1,
        True,
    )
    snapshot = RepairSnapshot(
        1,
        _SESSION_ID,
        RepairState.VALIDATED,
        "c" * 64,
        1,
        2,
        1,
        ("src/app.py",),
        candidate,
        validation,
        None,
        None,
        None,
        None,
        False,
    )
    preview = RepairPreview(
        1,
        _SESSION_ID,
        RepairState.VALIDATED,
        _CANDIDATE_ID,
        _VALIDATION_SHA256,
        ("src/app.py",),
        "diff --git a/src/app.py b/src/app.py\n",
        REPAIR_APPROVAL_CONFIRMATION,
    )
    return build_github_repair_proposal(
        repository_id=_REPOSITORY_ID,
        repository_full_name=_REPOSITORY_FULL_NAME,
        pull_request_number=7,
        base_ref="main",
        origin=origin,
        review_result=_review(),
        profile_name="safe",
        snapshot=snapshot,
        preview=preview,
        created_at_us=1_000_000,
    )


def _check_result(
    proposal: GitHubProposal,
    *,
    interface: GitHubApprovalInterface,
) -> GitHubPublicationResult:
    approval = approve_github_proposal(
        proposal,
        actor_login="maintainer",
        actor_id=42,
        permission=GitHubPermission.WRITE,
        interface=interface,
        confirmation=GITHUB_CHECK_CONFIRMATION,
        approved_at_us=2_000_000,
    )
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.CHECK_PUBLISHED,
        application_sha256=None,
        readback={
            "repository_id": proposal.repository_id,
            "check_run_id": 17,
            "check_run_node_id": "CR_17",
            "head_oid": proposal.head_oid,
            "external_id": cast(str, proposal.payload["external_id"]),
            "status": "completed",
            "conclusion": "success",
            "check_run_url": f"https://github.com/{proposal.repository_full_name}/runs/17",
        },
        published_at_us=3_000_000,
    )


def _repair_result(
    proposal: GitHubProposal,
    *,
    interface: GitHubApprovalInterface,
) -> GitHubPublicationResult:
    approval = approve_github_proposal(
        proposal,
        actor_login="maintainer",
        actor_id=42,
        permission=GitHubPermission.MAINTAIN,
        interface=interface,
        confirmation=GITHUB_REPAIR_CONFIRMATION,
        approved_at_us=2_000_000,
    )
    branch = cast(str, proposal.payload["branch"])
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.REPAIR_PUBLISHED,
        application_sha256=_APPLICATION_SHA256,
        readback={
            "repository_id": proposal.repository_id,
            "branch_ref": f"refs/heads/{branch}",
            "commit_oid": cast(str, proposal.payload["commit_oid"]),
            "pull_request_id": 555,
            "pull_request_number": 8,
            "pull_request_node_id": "PR_node",
            "pull_request_url": f"https://github.com/{proposal.repository_full_name}/pull/8",
            "draft": True,
            "state": "open",
            "base_ref": proposal.base_ref,
            "head_ref": branch,
            "base_repository_id": proposal.repository_id,
            "head_repository_id": proposal.repository_id,
            "pull_request_title": cast(str, proposal.payload["pull_request_title"]),
            "pull_request_body": cast(str, proposal.payload["pull_request_body"]),
            "body_marker": f"<!-- repoguard-repair-candidate:{_CANDIDATE_ID} -->",
        },
        published_at_us=3_000_000,
    )


def _write_proposal(path: Path, proposal: GitHubProposal) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(github_proposal_to_json(proposal), encoding="utf-8")
    path.chmod(0o600)


def _assert_import_error(
    envelope: Any,
    *,
    code: str = "artifact_mismatch",
    exit_code: ProductExitCode = ProductExitCode.STALE_OR_CONFLICT,
) -> None:
    assert not envelope.ok
    assert envelope.result is None
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.GITHUB
    assert envelope.error.code == code
    assert envelope.error.stage is ProductStage.PROPOSAL
    assert envelope.error.retryable is False
    assert product_exit_code(envelope) is exit_code


def test_action_check_import_records_new_store_and_returns_exact_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal()
    result = _check_result(proposal, interface=GitHubApprovalInterface.ACTION)
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, proposal)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("REPOGUARD_ACTION_ACTOR", "maintainer")
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(proposal_path))

    def service_factory(
        *_args: object,
        store: Any = None,
        **_kwargs: object,
    ) -> object:
        assert store is not None
        assert store.status(proposal.proposal_sha256).proposal == proposal

        class Service:
            def publish_check(
                self,
                proposal_sha256: str,
                *,
                confirmation: str,
            ) -> GitHubPublicationResult:
                assert proposal_sha256 == proposal.proposal_sha256
                assert confirmation == GITHUB_CHECK_CONFIRMATION
                return result

        return Service()

    monkeypatch.setattr("repoguard._product._publication_service", service_factory)
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.ACTION)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    assert envelope.ok
    assert envelope.operation is ProductOperation.GITHUB_PUBLISH_CHECK
    assert envelope.error is None
    assert envelope.result == {
        "approval_sha256": result.approval.approval_sha256,
        "result_sha256": result.result_sha256,
        "state": "check_published",
    }
    assert product_exit_code(envelope) is ProductExitCode.SUCCESS
    status = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
    )
    assert status.ok
    assert status.result is not None
    assert status.result["state"] == "proposed"
    status_proposal = cast(dict[str, object], status.result["proposal"])
    assert status_proposal["proposal_sha256"] == proposal.proposal_sha256


@pytest.mark.parametrize(
    "case",
    (
        "relative",
        "foreign_owner",
        "directory",
        "hardlink",
        "wrong_mode",
        "file_symlink",
        "component_symlink",
        "too_large",
        "noncanonical",
        "repair_kind",
        "cli_origin",
        "wrong_digest",
        "wrong_repository",
    ),
)
def test_action_check_import_rejects_every_artifact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal()
    expected_sha256 = proposal.proposal_sha256
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, proposal)
    selected_path = proposal_path

    if case == "relative":
        selected_path = Path("proposal.json")
    elif case == "foreign_owner":
        target_stat = proposal_path.stat()
        original_fstat = os.fstat

        def foreign_owner(descriptor: int) -> os.stat_result:
            metadata = original_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (
                target_stat.st_dev,
                target_stat.st_ino,
            ):
                return metadata
            fields = list(metadata)
            fields[4] = metadata.st_uid + 1
            return os.stat_result(fields)

        monkeypatch.setattr(os, "fstat", foreign_owner)
    elif case == "directory":
        proposal_path.unlink()
        proposal_path.mkdir(mode=0o700)
    elif case == "hardlink":
        (proposal_path.parent / "second-link.json").hardlink_to(proposal_path)
    elif case == "wrong_mode":
        proposal_path.chmod(0o644)
    elif case == "file_symlink":
        symlink_target = proposal_path.parent / "target.json"
        proposal_path.replace(symlink_target)
        proposal_path.symlink_to(symlink_target)
    elif case == "component_symlink":
        target_directory = tmp_path / "real-artifact"
        target_path = target_directory / "proposal.json"
        _write_proposal(target_path, proposal)
        linked_directory = tmp_path / "linked-artifact"
        linked_directory.symlink_to(target_directory, target_is_directory=True)
        selected_path = linked_directory / "proposal.json"
    elif case == "too_large":
        proposal_path.write_bytes(b"x" * (GITHUB_PROPOSAL_MAX_BYTES + 1))
        proposal_path.chmod(0o600)
    elif case == "noncanonical":
        proposal_path.write_bytes(f"{github_proposal_to_json(proposal)}\n".encode())
        proposal_path.chmod(0o600)
    elif case == "repair_kind":
        proposal = _repair_proposal()
        expected_sha256 = proposal.proposal_sha256
        _write_proposal(proposal_path, proposal)
    elif case == "cli_origin":
        proposal = _check_proposal(origin=GitHubProposalOrigin.CLI)
        expected_sha256 = proposal.proposal_sha256
        _write_proposal(proposal_path, proposal)
    elif case == "wrong_digest":
        expected_sha256 = "f" * 64
    elif case == "wrong_repository":
        proposal = _check_proposal(
            repository_id=654321,
            repository_full_name="other/repository",
        )
        expected_sha256 = proposal.proposal_sha256
        _write_proposal(proposal_path, proposal)
    else:  # pragma: no cover - exhaustive parametrization
        raise AssertionError(case)

    service_calls = 0

    def forbidden_service(*_args: object, **_kwargs: object) -> object:
        nonlocal service_calls
        service_calls += 1
        return object()

    monkeypatch.setattr("repoguard._product._publication_service", forbidden_service)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(selected_path))
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.ACTION)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=expected_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    _assert_import_error(envelope)
    assert envelope.error is not None
    assert envelope.error.proposal_sha256 == expected_sha256
    assert service_calls == 0
    serialized = product_envelope_to_json(envelope)
    assert str(selected_path) not in serialized


@pytest.mark.parametrize("interface", (ProductInterface.CLI, ProductInterface.MCP))
def test_cli_and_mcp_cannot_import_action_check_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interface: ProductInterface,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal()
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, proposal)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(proposal_path))
    service_calls = 0

    def forbidden_service(*_args: object, **_kwargs: object) -> object:
        nonlocal service_calls
        service_calls += 1
        return object()

    monkeypatch.setattr("repoguard._product._publication_service", forbidden_service)
    orchestrator = ProductOrchestrator(profile, interface=interface)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    _assert_import_error(
        envelope,
        code="capability_unavailable",
        exit_code=ProductExitCode.CAPABILITY_UNAVAILABLE,
    )
    assert service_calls == 0
    status = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
    )
    assert not status.ok
    assert status.error is not None
    assert status.error.code == "not_found"


def test_action_import_requires_github_actions_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal()
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, proposal)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(proposal_path))
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.ACTION)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    _assert_import_error(
        envelope,
        code="capability_unavailable",
        exit_code=ProductExitCode.CAPABILITY_UNAVAILABLE,
    )


def test_repair_publication_never_imports_action_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    check = _check_proposal()
    repair = _repair_proposal()
    result = _repair_result(repair, interface=GitHubApprovalInterface.ACTION)
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, check)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("REPOGUARD_ACTION_ACTOR", "maintainer")
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(proposal_path))

    class Service:
        def publish_repair(
            self,
            proposal_sha256: str,
            *,
            confirmation: str,
        ) -> GitHubPublicationResult:
            assert proposal_sha256 == repair.proposal_sha256
            assert confirmation == GITHUB_REPAIR_CONFIRMATION
            return result

    monkeypatch.setattr(
        "repoguard._product._publication_service",
        lambda *_args, **_kwargs: Service(),
    )
    monkeypatch.setattr("repoguard._product._manager", lambda *_args: object())
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.ACTION)

    envelope = orchestrator.github_publish_repair(
        repository="repository",
        proposal_sha256=repair.proposal_sha256,
        confirmation=GITHUB_REPAIR_CONFIRMATION,
    )

    assert envelope.ok
    assert envelope.result == {
        "approval_sha256": result.approval.approval_sha256,
        "result_sha256": result.result_sha256,
        "state": "repair_published",
    }
    status = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256=check.proposal_sha256,
    )
    assert not status.ok
    assert status.error is not None
    assert status.error.code == "not_found"


def test_status_success_missing_and_invalid_digest_exit_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal()
    result = _check_result(proposal, interface=GitHubApprovalInterface.ACTION)
    proposal_path = tmp_path / "artifact" / "proposal.json"
    _write_proposal(proposal_path, proposal)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("REPOGUARD_ACTION_ACTOR", "maintainer")
    monkeypatch.setenv("REPOGUARD_ACTION_PROPOSAL_PATH", str(proposal_path))

    class Service:
        def publish_check(
            self,
            _proposal_sha256: str,
            *,
            confirmation: str,
        ) -> GitHubPublicationResult:
            assert confirmation == GITHUB_CHECK_CONFIRMATION
            return result

    monkeypatch.setattr(
        "repoguard._product._publication_service",
        lambda *_args, **_kwargs: Service(),
    )
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.ACTION)
    assert orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    ).ok

    status = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
    )
    assert status.ok
    assert status.operation is ProductOperation.GITHUB_PUBLICATION_STATUS
    assert status.result is not None
    assert set(status.result) == {
        "proposal",
        "approval",
        "partial_result",
        "result",
        "state",
    }
    missing = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256="e" * 64,
    )
    assert not missing.ok
    assert missing.error is not None
    assert missing.error.domain is ProductErrorDomain.GITHUB_STORE
    assert missing.error.code == "not_found"
    assert missing.error.stage is ProductStage.PERSISTENCE
    assert product_exit_code(missing) is ProductExitCode.BUSINESS_FAILURE
    invalid = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256="invalid",
    )
    assert not invalid.ok
    assert invalid.error is not None
    assert invalid.error.domain is ProductErrorDomain.CLI
    assert invalid.error.code == "invalid_proposal_digest"
    assert invalid.error.stage is ProductStage.INPUT
    assert product_exit_code(invalid) is ProductExitCode.PROFILE_OR_REQUEST


@pytest.mark.parametrize(
    ("method_name", "expected_operation"),
    (
        ("github_publish_check", ProductOperation.GITHUB_PUBLISH_CHECK),
        ("github_publish_repair", ProductOperation.GITHUB_PUBLISH_REPAIR),
        ("github_publication_recover", ProductOperation.GITHUB_PUBLICATION_RECOVER),
    ),
)
def test_publish_and_recover_return_only_exact_result_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    expected_operation: ProductOperation,
) -> None:
    profile = _profile(tmp_path)
    check = _check_proposal(origin=GitHubProposalOrigin.CLI)
    repair = _repair_proposal(origin=GitHubProposalOrigin.CLI)
    check_result = _check_result(check, interface=GitHubApprovalInterface.CLI)
    repair_result = _repair_result(repair, interface=GitHubApprovalInterface.CLI)

    class Service:
        def publish_check(
            self,
            proposal_sha256: str,
            *,
            confirmation: str,
        ) -> GitHubPublicationResult:
            assert proposal_sha256 == check.proposal_sha256
            assert confirmation == GITHUB_CHECK_CONFIRMATION
            return check_result

        def publish_repair(
            self,
            proposal_sha256: str,
            *,
            confirmation: str,
        ) -> GitHubPublicationResult:
            assert proposal_sha256 == repair.proposal_sha256
            assert confirmation == GITHUB_REPAIR_CONFIRMATION
            return repair_result

        def recover(self, proposal_sha256: str) -> GitHubPublicationResult:
            assert proposal_sha256 == repair.proposal_sha256
            return repair_result

    monkeypatch.delenv("REPOGUARD_ACTION_PROPOSAL_PATH", raising=False)
    monkeypatch.setattr(
        "repoguard._product._publication_service",
        lambda *_args, **_kwargs: Service(),
    )
    monkeypatch.setattr("repoguard._product._manager", lambda *_args: object())
    orchestrator = ProductOrchestrator(profile, interface=ProductInterface.CLI)
    if method_name == "github_publish_check":
        envelope = orchestrator.github_publish_check(
            repository="repository",
            proposal_sha256=check.proposal_sha256,
            confirmation=GITHUB_CHECK_CONFIRMATION,
        )
        expected = check_result
    elif method_name == "github_publish_repair":
        envelope = orchestrator.github_publish_repair(
            repository="repository",
            proposal_sha256=repair.proposal_sha256,
            confirmation=GITHUB_REPAIR_CONFIRMATION,
        )
        expected = repair_result
    else:
        envelope = orchestrator.github_publication_recover(
            repository="repository",
            proposal_sha256=repair.proposal_sha256,
        )
        expected = repair_result

    assert envelope.ok
    assert envelope.operation is expected_operation
    assert envelope.error is None
    assert envelope.result == {
        "approval_sha256": expected.approval.approval_sha256,
        "result_sha256": expected.result_sha256,
        "state": expected.state.value,
    }
    assert set(envelope.result) == {"approval_sha256", "result_sha256", "state"}
    assert product_exit_code(envelope) is ProductExitCode.SUCCESS


@pytest.mark.parametrize(
    ("publication_domain", "code", "retryable", "expected_domain", "expected_exit"),
    (
        (
            GitHubPublicationErrorDomain.TRANSPORT,
            "timeout",
            True,
            ProductErrorDomain.GITHUB_TRANSPORT,
            ProductExitCode.RETRYABLE,
        ),
        (
            GitHubPublicationErrorDomain.PUBLICATION,
            GitHubPublicationErrorCode.PERMISSION_DENIED.value,
            False,
            ProductErrorDomain.GITHUB_PUBLICATION,
            ProductExitCode.AUTH_OR_APPROVAL,
        ),
        (
            GitHubPublicationErrorDomain.STORE,
            "invalid_state",
            False,
            ProductErrorDomain.GITHUB_STORE,
            ProductExitCode.BUSINESS_FAILURE,
        ),
        (
            GitHubPublicationErrorDomain.REPAIR,
            "stale",
            False,
            ProductErrorDomain.REPAIR,
            ProductExitCode.STALE_OR_CONFLICT,
        ),
    ),
)
def test_publication_errors_map_to_stable_envelopes_and_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication_domain: GitHubPublicationErrorDomain,
    code: str,
    retryable: bool,
    expected_domain: ProductErrorDomain,
    expected_exit: ProductExitCode,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal(origin=GitHubProposalOrigin.CLI)

    class Service:
        def publish_check(
            self,
            _proposal_sha256: str,
            *,
            confirmation: str,
        ) -> GitHubPublicationResult:
            assert confirmation == GITHUB_CHECK_CONFIRMATION
            raise GitHubPublicationError(
                publication_domain,
                code,
                GitHubPublicationStage.CHECK,
                retryable=retryable,
                ambiguous=retryable,
            )

    monkeypatch.delenv("REPOGUARD_ACTION_PROPOSAL_PATH", raising=False)
    monkeypatch.setattr(
        "repoguard._product._publication_service",
        lambda *_args, **_kwargs: Service(),
    )
    orchestrator = ProductOrchestrator(profile)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    assert not envelope.ok
    assert envelope.result is None
    assert envelope.error is not None
    assert envelope.error.domain is expected_domain
    assert envelope.error.code == code
    assert envelope.error.stage is ProductStage.PUBLICATION
    assert envelope.error.retryable is retryable
    assert envelope.error.state is None
    assert envelope.error.session_id is None
    assert envelope.error.attempt_count == 0
    assert product_exit_code(envelope) is expected_exit


def test_recover_retryable_error_preserves_recovery_stage_and_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    proposal = _repair_proposal(origin=GitHubProposalOrigin.CLI)

    class Service:
        def recover(self, proposal_sha256: str) -> GitHubPublicationResult:
            assert proposal_sha256 == proposal.proposal_sha256
            raise GitHubPublicationError(
                GitHubPublicationErrorDomain.TRANSPORT,
                "timeout",
                GitHubPublicationStage.RECOVERY,
                retryable=True,
                ambiguous=True,
            )

    monkeypatch.setattr(
        "repoguard._product._publication_service",
        lambda *_args, **_kwargs: Service(),
    )
    monkeypatch.setattr("repoguard._product._manager", lambda *_args: object())
    orchestrator = ProductOrchestrator(profile)

    envelope = orchestrator.github_publication_recover(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
    )

    assert not envelope.ok
    assert envelope.operation is ProductOperation.GITHUB_PUBLICATION_RECOVER
    assert envelope.result is None
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.GITHUB_TRANSPORT
    assert envelope.error.code == "timeout"
    assert envelope.error.stage is ProductStage.RECOVERY
    assert envelope.error.retryable is True
    assert product_exit_code(envelope) is ProductExitCode.RETRYABLE


@pytest.mark.parametrize("token", (None, "", "secret\nvalue", "x" * 1_025))
def test_missing_or_invalid_github_token_is_detached_and_never_leaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    token: str | None,
) -> None:
    profile = _profile(tmp_path)
    proposal = _check_proposal(origin=GitHubProposalOrigin.CLI)
    monkeypatch.delenv("REPOGUARD_ACTION_PROPOSAL_PATH", raising=False)
    if token is None:
        monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    else:
        monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", token)
    orchestrator = ProductOrchestrator(profile)

    envelope = orchestrator.github_publish_check(
        repository="repository",
        proposal_sha256=proposal.proposal_sha256,
        confirmation=GITHUB_CHECK_CONFIRMATION,
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.GITHUB
    assert envelope.error.code == "authentication_failed"
    assert envelope.error.stage is ProductStage.TRANSPORT
    assert product_exit_code(envelope) is ProductExitCode.AUTH_OR_APPROVAL
    serialized = product_envelope_to_json(envelope)
    assert not token or token not in serialized
    assert str(profile.product_state_root) not in serialized
    assert str(profile.repositories[0].path) not in serialized
