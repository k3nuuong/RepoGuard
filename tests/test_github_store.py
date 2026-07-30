"""Owner-only persistence and CAS tests for M6 GitHub publications."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

from repoguard import _github_store as store_module
from repoguard._canonical import canonical_json_text, domain_sha256
from repoguard._github_store import (
    GitHubPublicationStore,
    GitHubStoreError,
    GitHubStoreErrorCode,
    GitHubStoreStage,
)
from repoguard.github import (
    GITHUB_CHECK_CONFIRMATION,
    GITHUB_REPAIR_CONFIRMATION,
    GitHubApproval,
    GitHubApprovalInterface,
    GitHubPermission,
    GitHubProposal,
    GitHubProposalKind,
    GitHubProposalOrigin,
    GitHubPublicationResult,
    GitHubPublicationState,
    approve_github_proposal,
    build_github_check_proposal,
    build_github_repair_proposal,
    build_github_result,
    github_approval_to_dict,
)
from repoguard.product import ProductConclusion, ProductReviewResult
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

_BASE_OID = "1" * 40
_HEAD_OID = "2" * 40
_CANDIDATE_ID = "3" * 64
_VALIDATION_SHA256 = "4" * 64
_TREE_OID = "5" * 40
_SESSION_ID = "b" * 64
_REQUEST_SHA256 = "a" * 64
_APPLICATION_SHA256 = "9" * 64


def _fixed_commit_oid() -> str:
    identity = f"{REPAIR_PUBLICATION_AUTHOR_NAME} <{REPAIR_PUBLICATION_AUTHOR_EMAIL}> 0 +0000"
    commit = (
        f"tree {_TREE_OID}\n"
        f"parent {_HEAD_OID}\n"
        f"author {identity}\n"
        f"committer {identity}\n"
        "\n"
        f"{REPAIR_PUBLICATION_COMMIT_MESSAGE}"
    ).encode()
    header = f"commit {len(commit)}\0".encode("ascii")
    return hashlib.sha1(header + commit, usedforsecurity=False).hexdigest()


_COMMIT_OID = _fixed_commit_oid()


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    root = tmp_path / "product-state"
    root.mkdir(mode=0o700)
    return root


def _store(
    state_root: Path,
    *,
    repository_alias: str = "repository",
    repository_id: int = 123456,
    repository_full_name: str = "owner/repository",
    timeout: float = 5.0,
) -> GitHubPublicationStore:
    return GitHubPublicationStore(
        product_state_root=state_root,
        repository_alias=repository_alias,
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        lock_timeout_seconds=timeout,
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
        evidence_sha256="d" * 64,
        deterministic_review_sha256="e" * 64,
        review_sha256="8" * 64,
        findings=(),
        finding_count=0,
        highest_severity=None,
        conclusion=ProductConclusion.SUCCESS,
    )


def _validated_repair() -> tuple[RepairSnapshot, RepairPreview]:
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
        _REQUEST_SHA256,
        prompt,
        context,
        "4" * 64,
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
        "5" * 64,
        0,
        False,
        "6" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        _VALIDATION_SHA256,
        _CANDIDATE_ID,
        "7" * 64,
        "8" * 64,
        f"sha256:{'9' * 64}",
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
        _REQUEST_SHA256,
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
    return snapshot, preview


def _proposal(
    kind: GitHubProposalKind = GitHubProposalKind.CHECK,
    *,
    created_at_us: int = 1_000_000,
) -> GitHubProposal:
    if kind is GitHubProposalKind.CHECK:
        return build_github_check_proposal(
            repository_id=123456,
            repository_full_name="owner/repository",
            pull_request_number=7,
            base_ref="main",
            origin=GitHubProposalOrigin.CLI,
            review_result=_review(),
            policy_sha256="7" * 64,
            created_at_us=created_at_us,
        )
    snapshot, preview = _validated_repair()
    return build_github_repair_proposal(
        repository_id=123456,
        repository_full_name="owner/repository",
        pull_request_number=7,
        base_ref="main",
        origin=GitHubProposalOrigin.CLI,
        review_result=_review(),
        profile_name="safe",
        snapshot=snapshot,
        preview=preview,
        created_at_us=created_at_us,
    )


def _approval(
    proposal: GitHubProposal,
    *,
    actor: str = "maintainer",
    actor_id: int = 99,
) -> GitHubApproval:
    return approve_github_proposal(
        proposal,
        actor_login=actor,
        actor_id=actor_id,
        permission=GitHubPermission.MAINTAIN,
        interface=GitHubApprovalInterface.CLI,
        confirmation=(
            GITHUB_CHECK_CONFIRMATION
            if proposal.kind is GitHubProposalKind.CHECK
            else GITHUB_REPAIR_CONFIRMATION
        ),
        approved_at_us=2_000_000,
    )


def _check_result(
    proposal: GitHubProposal,
    approval: GitHubApproval,
    *,
    check_run_id: int = 17,
) -> GitHubPublicationResult:
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.CHECK_PUBLISHED,
        application_sha256=None,
        readback={
            "repository_id": 123456,
            "check_run_id": check_run_id,
            "check_run_node_id": f"CR_{check_run_id}",
            "head_oid": _HEAD_OID,
            "external_id": cast(str, proposal.payload["external_id"]),
            "status": "completed",
            "conclusion": "success",
            "check_run_url": (f"https://github.com/owner/repository/runs/{check_run_id}"),
        },
        published_at_us=3_000_000,
    )


def _branch_result(
    proposal: GitHubProposal,
    approval: GitHubApproval,
) -> GitHubPublicationResult:
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.BRANCH_CREATED,
        application_sha256=_APPLICATION_SHA256,
        readback={
            "repository_id": 123456,
            "branch_ref": f"refs/heads/repoguard/repairs/{_CANDIDATE_ID}",
            "commit_oid": _COMMIT_OID,
        },
        published_at_us=3_000_000,
    )


def _repair_result(
    proposal: GitHubProposal,
    approval: GitHubApproval,
) -> GitHubPublicationResult:
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.REPAIR_PUBLISHED,
        application_sha256=_APPLICATION_SHA256,
        readback={
            "repository_id": 123456,
            "branch_ref": f"refs/heads/repoguard/repairs/{_CANDIDATE_ID}",
            "commit_oid": _COMMIT_OID,
            "pull_request_id": 555,
            "pull_request_number": 8,
            "pull_request_node_id": "PR_node",
            "pull_request_url": "https://github.com/owner/repository/pull/8",
            "draft": True,
            "state": "open",
            "base_ref": "main",
            "head_ref": f"repoguard/repairs/{_CANDIDATE_ID}",
            "base_repository_id": 123456,
            "head_repository_id": 123456,
            "pull_request_title": cast(str, proposal.payload["pull_request_title"]),
            "pull_request_body": cast(str, proposal.payload["pull_request_body"]),
            "body_marker": f"<!-- repoguard-repair-candidate:{_CANDIDATE_ID} -->",
        },
        published_at_us=4_000_000,
    )


def _semantically_foreign_result(
    result: GitHubPublicationResult,
) -> GitHubPublicationResult:
    readback = result.readback
    field = "head_oid" if result.kind is GitHubProposalKind.CHECK else "commit_oid"
    readback[field] = "f" * 40
    identity = {
        "schema_version": result.schema_version,
        "proposal_sha256": result.proposal_sha256,
        "kind": result.kind.value,
        "approval": github_approval_to_dict(result.approval),
        "state": result.state.value,
        "application_sha256": result.application_sha256,
        "readback": readback,
        "published_at_us": result.published_at_us,
    }
    return GitHubPublicationResult(
        schema_version=result.schema_version,
        result_sha256=domain_sha256("repoguard.m6.github_result.v1", identity),
        proposal_sha256=result.proposal_sha256,
        kind=result.kind,
        approval=result.approval,
        state=result.state,
        application_sha256=result.application_sha256,
        readback_json=canonical_json_text(readback),
        published_at_us=result.published_at_us,
    )


def _publication_path(state_root: Path, proposal: GitHubProposal) -> Path:
    return state_root / "github" / "repository" / "publications" / proposal.proposal_sha256


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_check_lifecycle_is_canonical_private_and_idempotent(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal()
    approval = _approval(proposal)
    result = _check_result(proposal, approval)

    created = store.record_proposal(proposal)
    approved = store.record_approval(proposal.proposal_sha256, approval)
    published = store.record_result(proposal.proposal_sha256, result)

    assert created.approval is None
    assert approved.approval == approval
    assert published.result == result
    assert store.record_proposal(proposal) == published
    assert store.record_approval(proposal.proposal_sha256, approval) == published
    assert store.record_result(proposal.proposal_sha256, result) == published
    publication = _publication_path(state_root, proposal)
    assert _mode(state_root / "github") == 0o700
    assert _mode(state_root / "github" / ".manager.lock") == 0o600
    assert _mode(state_root / "github" / "repository" / ".publisher.lock") == 0o600
    assert _mode(publication) == 0o700
    assert _mode(publication / "publication.lock") == 0o600
    for name in ("proposal.json", "approval.json", "result.json"):
        assert _mode(publication / name) == 0o400
        assert (publication / name).stat().st_nlink == 1
    assert not (publication / "binding.json").exists()


def test_repair_binding_is_private_and_recovery_uses_same_approval(
    state_root: Path,
) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    approval = _approval(proposal)
    partial = _branch_result(proposal, approval)
    result = _repair_result(proposal, approval)

    store.record_proposal(proposal, session_id=_SESSION_ID)
    store.record_approval(proposal.proposal_sha256, approval)
    branch_status = store.record_partial_result(proposal.proposal_sha256, partial)
    final_status = store.record_result(proposal.proposal_sha256, result)

    assert branch_status.partial_result == partial
    assert final_status.partial_result == partial
    assert final_status.result == result
    assert store.repair_session_id(proposal.proposal_sha256) == _SESSION_ID
    assert _SESSION_ID not in repr(final_status)
    binding = _publication_path(state_root, proposal) / "binding.json"
    assert _mode(binding) == 0o400
    assert _SESSION_ID in binding.read_text()
    assert _SESSION_ID not in repr(store)
    with store.locked_publication(proposal.proposal_sha256) as locked:
        assert locked.repair_session_id() == _SESSION_ID
        assert locked.record_result(result) == final_status


def test_different_binding_and_approval_are_cas_conflicts(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    approval = _approval(proposal)
    store.record_proposal(proposal, session_id=_SESSION_ID)
    store.record_approval(proposal.proposal_sha256, approval)

    with pytest.raises(GitHubStoreError) as binding_error:
        store.record_proposal(proposal, session_id="f" * 64)
    with pytest.raises(GitHubStoreError) as approval_error:
        store.record_approval(
            proposal.proposal_sha256,
            _approval(proposal, actor="other", actor_id=100),
        )

    assert binding_error.value.code is GitHubStoreErrorCode.STATE_CONFLICT
    assert approval_error.value.code is GitHubStoreErrorCode.STATE_CONFLICT
    assert store.repair_session_id(proposal.proposal_sha256) == _SESSION_ID
    assert store.status(proposal.proposal_sha256).approval == approval


@pytest.mark.parametrize("replacement_session", [_SESSION_ID, "f" * 64])
def test_existing_repair_proposal_with_missing_binding_fails_closed(
    state_root: Path,
    replacement_session: str,
) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    store.record_proposal(proposal, session_id=_SESSION_ID)
    binding = _publication_path(state_root, proposal) / "binding.json"
    binding.unlink()

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(proposal, session_id=replacement_session)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert not binding.exists()


def test_partial_and_final_require_the_exact_saved_approval(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    saved = _approval(proposal)
    foreign = _approval(proposal, actor="other", actor_id=100)
    store.record_proposal(proposal, session_id=_SESSION_ID)
    store.record_approval(proposal.proposal_sha256, saved)

    with pytest.raises(GitHubStoreError) as partial_error:
        store.record_partial_result(
            proposal.proposal_sha256,
            _branch_result(proposal, foreign),
        )
    with pytest.raises(GitHubStoreError) as final_error:
        store.record_result(
            proposal.proposal_sha256,
            _repair_result(proposal, foreign),
        )

    assert partial_error.value.code is GitHubStoreErrorCode.STATE_CONFLICT
    assert final_error.value.code is GitHubStoreErrorCode.STATE_CONFLICT
    status = store.status(proposal.proposal_sha256)
    assert status.partial_result is None
    assert status.result is None


@pytest.mark.parametrize(
    "kind",
    [GitHubProposalKind.CHECK, GitHubProposalKind.REPAIR],
)
def test_store_rejects_self_consistent_result_not_authorized_by_saved_proposal(
    state_root: Path,
    kind: GitHubProposalKind,
) -> None:
    store = _store(state_root)
    proposal = _proposal(kind)
    approval = _approval(proposal)
    store.record_proposal(
        proposal,
        session_id=_SESSION_ID if kind is GitHubProposalKind.REPAIR else None,
    )
    store.record_approval(proposal.proposal_sha256, approval)
    valid = (
        _check_result(proposal, approval)
        if kind is GitHubProposalKind.CHECK
        else _branch_result(proposal, approval)
    )

    with pytest.raises(GitHubStoreError) as captured:
        if kind is GitHubProposalKind.CHECK:
            store.record_result(
                proposal.proposal_sha256,
                _semantically_foreign_result(valid),
            )
        else:
            store.record_partial_result(
                proposal.proposal_sha256,
                _semantically_foreign_result(valid),
            )

    assert captured.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    status = store.status(proposal.proposal_sha256)
    assert status.partial_result is None
    assert status.result is None


def test_final_result_is_a_cas_and_does_not_replace_remote_identity(
    state_root: Path,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    approval = _approval(proposal)
    first = _check_result(proposal, approval, check_run_id=17)
    second = _check_result(proposal, approval, check_run_id=18)
    store.record_proposal(proposal)
    store.record_approval(proposal.proposal_sha256, approval)
    store.record_result(proposal.proposal_sha256, first)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_result(proposal.proposal_sha256, second)

    assert captured.value.code is GitHubStoreErrorCode.STATE_CONFLICT
    assert store.status(proposal.proposal_sha256).result == first


def test_store_revalidates_repository_semantics_on_load(state_root: Path) -> None:
    proposal = _proposal()
    _store(state_root).record_proposal(proposal)
    other = _store(
        state_root,
        repository_id=654321,
        repository_full_name="owner/other",
    )

    with pytest.raises(GitHubStoreError) as captured:
        other.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE


@pytest.mark.parametrize(
    "kind",
    [GitHubProposalKind.CHECK, GitHubProposalKind.REPAIR],
)
def test_store_rejects_a_proposal_for_another_profile_alias(
    state_root: Path,
    kind: GitHubProposalKind,
) -> None:
    store = _store(state_root, repository_alias="other")

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(
            _proposal(kind),
            session_id=_SESSION_ID if kind is GitHubProposalKind.REPAIR else None,
        )

    assert captured.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    assert not (state_root / "github").exists()


def test_existing_unsafe_directory_is_rejected_without_chmod(state_root: Path) -> None:
    store = _store(state_root)
    github = state_root / "github"
    github.mkdir(mode=0o755)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(_proposal())

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert _mode(github) == 0o755


def test_missing_status_is_read_only(state_root: Path) -> None:
    store = _store(state_root)

    with pytest.raises(GitHubStoreError) as captured:
        store.status("a" * 64)

    assert captured.value.code is GitHubStoreErrorCode.NOT_FOUND
    assert not (state_root / "github").exists()


def test_invalid_inputs_fail_before_creating_publication_state(state_root: Path) -> None:
    store = _store(state_root)
    repair = _proposal(GitHubProposalKind.REPAIR)

    with pytest.raises(GitHubStoreError) as digest_error:
        store.status("../escape")
    with pytest.raises(GitHubStoreError) as binding_error:
        store.record_proposal(repair)

    assert digest_error.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    assert binding_error.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    assert not (state_root / "github").exists()


@pytest.mark.parametrize("mutation", ["mode", "hardlink", "noncanonical", "oversize"])
def test_record_corruption_fails_closed_without_echoing_contents(
    state_root: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    record = _publication_path(state_root, proposal) / "proposal.json"
    secret = "do-not-echo-this-value"
    if mutation == "mode":
        record.chmod(0o600)
    elif mutation == "hardlink":
        os.link(record, tmp_path / "outside-link")
    else:
        raw = record.read_bytes()
        record.chmod(0o600)
        record.write_bytes(
            raw + (b"\n" + secret.encode() if mutation == "noncanonical" else b"x" * 4_194_305)
        )
        record.chmod(0o400)

    with pytest.raises(GitHubStoreError) as captured:
        store.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert secret not in str(captured.value)
    assert secret not in repr(captured.value)


def test_symlink_record_is_never_followed(state_root: Path, tmp_path: Path) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    record = _publication_path(state_root, proposal) / "proposal.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(record.read_bytes())
    record.unlink()
    record.symlink_to(outside)

    with pytest.raises(GitHubStoreError) as captured:
        store.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE


def test_unknown_record_is_corruption(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    publication = _publication_path(state_root, proposal)
    unknown = publication / "session.json"
    unknown.write_text('{"session_id":"' + _SESSION_ID + '"}')
    unknown.chmod(0o400)

    with pytest.raises(GitHubStoreError) as captured:
        store.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert _SESSION_ID not in str(captured.value)


def test_owner_only_root_rejects_mode_and_symlink_ancestors(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(GitHubStoreError) as mode_error:
        _store(unsafe)

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    real_root = real_parent / "state"
    real_root.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(GitHubStoreError) as link_error:
        _store(linked_parent / "state")

    assert mode_error.value.code is GitHubStoreErrorCode.INVALID_CONFIG
    assert link_error.value.code is GitHubStoreErrorCode.INVALID_CONFIG


def test_store_binds_the_state_root_inode_for_its_lifetime(
    state_root: Path,
    tmp_path: Path,
) -> None:
    store = _store(state_root)
    moved = tmp_path / "moved-state"
    state_root.rename(moved)
    state_root.mkdir(mode=0o700)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(_proposal())

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert not (state_root / "github").exists()


def test_root_open_uses_descriptor_relative_no_follow_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability_parent = tmp_path / "capability"
    capability_parent.mkdir()
    state_root = capability_parent / "state"
    state_root.mkdir(mode=0o700)
    original_identity = (state_root.stat().st_dev, state_root.stat().st_ino)
    moved_parent = tmp_path / "moved-capability"
    real_open = os.open
    swapped = False

    def racing_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        rendered = os.fspath(path) if not isinstance(path, int) else path
        if not swapped and rendered in {"state", str(state_root)}:
            capability_parent.rename(moved_parent)
            capability_parent.mkdir()
            replacement = capability_parent / "state"
            replacement.mkdir(mode=0o700)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    store = _store(state_root)

    assert swapped is True
    assert store._root_identity == original_identity
    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(_proposal())
    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert not (state_root / "github").exists()


@pytest.mark.parametrize(
    "lock_name",
    [".manager.lock", ".publisher.lock", "publication.lock"],
)
def test_missing_lock_is_corruption_and_is_never_recreated(
    state_root: Path,
    lock_name: str,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    lock = (
        state_root / "github" / lock_name
        if lock_name == ".manager.lock"
        else (
            state_root / "github" / "repository" / lock_name
            if lock_name == ".publisher.lock"
            else _publication_path(state_root, proposal) / lock_name
        )
    )
    lock.unlink()

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(proposal)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert not lock.exists()


@pytest.mark.parametrize("lock_kind", ["publisher", "proposal"])
def test_root_manager_gate_prevents_second_holder_after_named_lock_replacement(
    state_root: Path,
    lock_kind: str,
) -> None:
    store = _store(state_root, timeout=0.05)
    proposal = _proposal()
    store.record_proposal(proposal)
    publication = _publication_path(state_root, proposal)
    lock = (
        state_root / "github" / "repository" / ".publisher.lock"
        if lock_kind == "publisher"
        else publication / "publication.lock"
    )
    started = threading.Event()
    release = threading.Event()
    holder_errors: list[GitHubStoreErrorCode] = []

    def hold_original_lock_inodes() -> None:
        try:
            with store.locked_publication(proposal.proposal_sha256):
                started.set()
                assert release.wait(timeout=2.0)
        except GitHubStoreError as error:
            holder_errors.append(error.code)

    with ThreadPoolExecutor(max_workers=2) as executor:
        holding = executor.submit(hold_original_lock_inodes)
        assert started.wait(timeout=2.0)
        displaced = lock.with_name(f"{lock.name}.displaced")
        original_identity = (lock.stat().st_dev, lock.stat().st_ino)
        lock.rename(displaced)
        replacement_fd = os.open(
            lock,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(replacement_fd)
        replacement_identity = (lock.stat().st_dev, lock.stat().st_ino)
        assert replacement_identity != original_identity
        contender = _store(state_root, timeout=0.05)
        with pytest.raises(GitHubStoreError) as captured:
            contender.status(proposal.proposal_sha256)
        release.set()
        holding.result(timeout=2.0)

    assert captured.value.code is GitHubStoreErrorCode.LOCK_TIMEOUT
    assert captured.value.retryable is True
    assert holder_errors == [GitHubStoreErrorCode.CORRUPT_STATE]


def test_manager_lock_timeout_is_retryable_and_creates_no_proposal(
    state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    monkeypatch.setattr(store_module, "_acquire_flock", lambda _fd, _timeout: False)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(proposal)

    assert captured.value.code is GitHubStoreErrorCode.LOCK_TIMEOUT
    assert captured.value.stage is GitHubStoreStage.LOCK
    assert captured.value.retryable is True
    assert not (state_root / "github" / "repository").exists()


def test_failed_record_write_leaves_no_temporary_or_public_record(
    state_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(state_root)
    proposal = _proposal()

    def fail_write(_descriptor: int, _value: bytes) -> None:
        raise OSError("sensitive OS detail")

    monkeypatch.setattr(store_module, "_write_all", fail_write)
    with pytest.raises(GitHubStoreError) as captured:
        store.record_proposal(proposal)

    publication = _publication_path(state_root, proposal)
    assert captured.value.code is GitHubStoreErrorCode.IO_FAILED
    assert "sensitive" not in str(captured.value)
    assert {path.name for path in publication.iterdir()} == {"publication.lock"}


@pytest.mark.parametrize(
    "fault_stage",
    [
        "created",
        "write-partial",
        "written",
        "fsynced",
        "chmodded",
        "linked",
        "unlinked",
    ],
)
def test_reopen_recovers_every_atomic_record_crash_stage(
    state_root: Path,
    fault_stage: str,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    approval = _approval(proposal)
    store.record_proposal(proposal)
    child = os.fork()
    if child == 0:

        def terminate_at_stage(_stage: str) -> None:
            if _stage == fault_stage:
                os._exit(86)

        store_module._record_write_checkpoint = terminate_at_stage
        store.record_approval(proposal.proposal_sha256, approval)
        os._exit(87)
    waited, child_status = os.waitpid(child, 0)
    assert waited == child
    assert os.waitstatus_to_exitcode(child_status) == 86

    reopened = _store(state_root)
    status = reopened.status(proposal.proposal_sha256)
    publication = _publication_path(state_root, proposal)
    expected_published = fault_stage in {"linked", "unlinked"}
    assert (status.approval == approval) is expected_published
    assert not any(path.name.startswith(".record-") for path in publication.iterdir())
    if expected_published:
        approval_record = publication / "approval.json"
        assert _mode(approval_record) == 0o400
        assert approval_record.stat().st_nlink == 1


def test_first_repair_binding_crash_recovers_before_proposal_publication(
    state_root: Path,
) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    child = os.fork()
    if child == 0:

        def terminate_after_binding_link(_stage: str) -> None:
            if _stage == "linked":
                os._exit(86)

        store_module._record_write_checkpoint = terminate_after_binding_link
        store.record_proposal(proposal, session_id=_SESSION_ID)
        os._exit(87)
    waited, child_status = os.waitpid(child, 0)
    assert waited == child
    assert os.waitstatus_to_exitcode(child_status) == 86

    reopened = _store(state_root)
    status = reopened.record_proposal(proposal, session_id=_SESSION_ID)
    publication = _publication_path(state_root, proposal)
    assert status.proposal == proposal
    assert reopened.repair_session_id(proposal.proposal_sha256) == _SESSION_ID
    assert not any(path.name.startswith(".record-") for path in publication.iterdir())
    assert (publication / "binding.json").stat().st_nlink == 1


@pytest.mark.parametrize("corruption", ["unknown", "multiple", "external-hardlink"])
def test_temporary_recovery_fails_closed_for_ambiguous_links(
    state_root: Path,
    corruption: str,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    publication = _publication_path(state_root, proposal)
    first = publication / (".record-invalid" if corruption == "unknown" else f".record-{'a' * 32}")
    first.write_bytes(b"unfinished")
    first.chmod(0o600)
    if corruption == "multiple":
        second = publication / f".record-{'b' * 32}"
        second.write_bytes(b"unfinished")
        second.chmod(0o600)
    elif corruption == "external-hardlink":
        os.link(first, state_root / "external-record-link")

    with pytest.raises(GitHubStoreError) as captured:
        store.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert first.exists()


def test_proposal_lock_serializes_a_complete_publication_attempt(
    state_root: Path,
) -> None:
    store = _store(state_root, timeout=0.05)
    proposal = _proposal()
    store.record_proposal(proposal)
    started = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with store.locked_publication(proposal.proposal_sha256):
            started.set()
            assert release.wait(timeout=2.0)

    with ThreadPoolExecutor(max_workers=2) as executor:
        holding = executor.submit(hold_lock)
        assert started.wait(timeout=2.0)
        with pytest.raises(GitHubStoreError) as captured:
            store.status(proposal.proposal_sha256)
        release.set()
        holding.result(timeout=2.0)

    assert captured.value.code is GitHubStoreErrorCode.LOCK_TIMEOUT
    assert captured.value.retryable is True


def test_repository_publisher_lock_serializes_different_check_proposals(
    state_root: Path,
) -> None:
    store = _store(state_root, timeout=0.05)
    first = _proposal(created_at_us=1_000_000)
    second = _proposal(created_at_us=1_100_000)
    assert first.proposal_sha256 != second.proposal_sha256
    assert first.payload["external_id"] == second.payload["external_id"]
    store.record_proposal(first)
    store.record_proposal(second)
    started = threading.Event()
    release = threading.Event()

    def hold_first_publisher() -> None:
        with store.locked_publication(first.proposal_sha256):
            started.set()
            assert release.wait(timeout=2.0)

    with ThreadPoolExecutor(max_workers=2) as executor:
        holding = executor.submit(hold_first_publisher)
        assert started.wait(timeout=2.0)
        with pytest.raises(GitHubStoreError) as captured:
            store.status(second.proposal_sha256)
        release.set()
        holding.result(timeout=2.0)

    assert captured.value.code is GitHubStoreErrorCode.LOCK_TIMEOUT
    assert captured.value.stage is GitHubStoreStage.LOCK
    assert captured.value.retryable is True


def test_concurrent_same_proposal_creation_is_idempotent(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal(GitHubProposalKind.REPAIR)
    barrier = threading.Barrier(8)

    def create() -> str:
        barrier.wait(timeout=2.0)
        return store.record_proposal(
            proposal,
            session_id=_SESSION_ID,
        ).proposal.proposal_sha256

    with ThreadPoolExecutor(max_workers=8) as executor:
        identities = list(executor.map(lambda _index: create(), range(8)))

    assert identities == [proposal.proposal_sha256] * 8
    assert store.repair_session_id(proposal.proposal_sha256) == _SESSION_ID
    publication = _publication_path(state_root, proposal)
    assert not any(path.name.startswith(".record-") for path in publication.iterdir())


def test_record_permissions_are_revalidated_after_creation(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal()
    store.record_proposal(proposal)
    publication = _publication_path(state_root, proposal)
    lock = publication / "publication.lock"
    outside = state_root / "lock-link"
    os.link(lock, outside)

    with pytest.raises(GitHubStoreError) as captured:
        store.status(proposal.proposal_sha256)

    assert captured.value.code is GitHubStoreErrorCode.CORRUPT_STATE


def test_approval_time_is_revalidated_against_the_loaded_proposal(
    state_root: Path,
) -> None:
    store = _store(state_root)
    proposal = _proposal()
    fields: dict[str, object] = {
        "schema_version": 1,
        "proposal_sha256": proposal.proposal_sha256,
        "kind": proposal.kind.value,
        "actor_login": "maintainer",
        "actor_id": 99,
        "permission": GitHubPermission.MAINTAIN.value,
        "interface": GitHubApprovalInterface.CLI.value,
        "confirmation": GITHUB_CHECK_CONFIRMATION,
        "approved_at_us": proposal.expires_at_us,
    }
    late = GitHubApproval(
        schema_version=1,
        approval_sha256=domain_sha256("repoguard.m6.github_approval.v1", fields),
        proposal_sha256=proposal.proposal_sha256,
        kind=proposal.kind,
        actor_login="maintainer",
        actor_id=99,
        permission=GitHubPermission.MAINTAIN,
        interface=GitHubApprovalInterface.CLI,
        confirmation=GITHUB_CHECK_CONFIRMATION,
        approved_at_us=proposal.expires_at_us,
    )
    store.record_proposal(proposal)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_approval(proposal.proposal_sha256, late)

    assert captured.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    assert store.status(proposal.proposal_sha256).approval is None


def test_result_without_saved_approval_is_rejected(state_root: Path) -> None:
    store = _store(state_root)
    proposal = _proposal()
    approval = _approval(proposal)
    store.record_proposal(proposal)

    with pytest.raises(GitHubStoreError) as captured:
        store.record_result(
            proposal.proposal_sha256,
            _check_result(proposal, approval),
        )

    assert captured.value.code is GitHubStoreErrorCode.STATE_CONFLICT


def test_store_error_has_only_stable_public_fields() -> None:
    error = GitHubStoreError(
        GitHubStoreErrorCode.CORRUPT_STATE,
        GitHubStoreStage.READ,
    )

    assert str(error) == "GitHub publication state is invalid"
    assert error.code is GitHubStoreErrorCode.CORRUPT_STATE
    assert error.stage is GitHubStoreStage.READ
    assert error.retryable is False
    assert set(cast(tuple[str, ...], error.__slots__)) == {"code", "stage", "retryable"}
