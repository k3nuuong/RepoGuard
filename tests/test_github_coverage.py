"""Coverage-focused contract and security tests for the M6 GitHub boundary."""

from __future__ import annotations

import errno
import os
import socket
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from repoguard import _github_store as store_module
from repoguard import github as github_module
from repoguard import github_publication as publication_module
from repoguard import github_transport as transport_module
from repoguard import host_profile as profile_module
from repoguard._github_store import (
    GitHubPublicationStatus,
    GitHubStoreError,
    GitHubStoreErrorCode,
    GitHubStoreStage,
)
from repoguard.github import (
    GITHUB_CHECK_CONFIRMATION,
    GitHubApproval,
    GitHubApprovalInterface,
    GitHubPermission,
    GitHubProposal,
    GitHubProposalOrigin,
    GitHubPublicationResult,
    GitHubPublicationState,
    approve_github_proposal,
    build_github_check_proposal,
    build_github_result,
)
from repoguard.github_publication import (
    GitHubPublicationError,
    GitHubPublicationErrorCode,
    GitHubPublicationErrorDomain,
    GitHubPublicationService,
    GitHubPublicationStage,
    GitHubSourcePullRequest,
)
from repoguard.github_transport import (
    GitHubTransport,
    GitHubTransportError,
    GitHubTransportErrorCode,
)
from repoguard.host_profile import (
    HostGitHubActions,
    HostMCPWriters,
    HostProfile,
    HostPublisherRuntime,
    HostRepository,
    M4CacheProfile,
    ProductProviderKind,
    ProductRepairProfile,
    ProductReviewMode,
    ProductReviewProfile,
)
from repoguard.product import ProductConclusion, ProductReviewResult
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairStage,
    ValidationCommand,
    ValidationPolicy,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

_BASE_OID = "1" * 40
_HEAD_OID = "2" * 40
_REPOSITORY_ID = 123456
_REPOSITORY_FULL_NAME = "owner/repository"
_IMAGE_ID = f"sha256:{'3' * 64}"


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
        evidence_sha256="4" * 64,
        deterministic_review_sha256="5" * 64,
        review_sha256="6" * 64,
        findings=(),
        finding_count=0,
        highest_severity=None,
        conclusion=ProductConclusion.SUCCESS,
    )


@pytest.fixture
def proposal() -> GitHubProposal:
    return build_github_check_proposal(
        repository_id=_REPOSITORY_ID,
        repository_full_name=_REPOSITORY_FULL_NAME,
        pull_request_number=7,
        base_ref="main",
        origin=GitHubProposalOrigin.CLI,
        review_result=_review(),
        policy_sha256="7" * 64,
        created_at_us=100,
    )


@pytest.fixture
def approval(proposal: GitHubProposal) -> GitHubApproval:
    return approve_github_proposal(
        proposal,
        actor_login="octocat",
        actor_id=9,
        permission=GitHubPermission.WRITE,
        interface=GitHubApprovalInterface.CLI,
        confirmation=GITHUB_CHECK_CONFIRMATION,
        approved_at_us=101,
    )


def _check_readback(proposal: GitHubProposal) -> dict[str, object]:
    return {
        "repository_id": _REPOSITORY_ID,
        "check_run_id": 42,
        "check_run_node_id": "CR_node",
        "head_oid": _HEAD_OID,
        "external_id": proposal.payload["external_id"],
        "status": "completed",
        "conclusion": "success",
        "check_run_url": f"https://github.com/{_REPOSITORY_FULL_NAME}/runs/42",
    }


@pytest.fixture
def result(proposal: GitHubProposal, approval: GitHubApproval) -> GitHubPublicationResult:
    return build_github_result(
        proposal,
        approval,
        state=GitHubPublicationState.CHECK_PUBLISHED,
        application_sha256=None,
        readback=_check_readback(proposal),
        published_at_us=102,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kind", "check", "proposal kind"),
        ("origin", "cli", "proposal origin"),
        ("created_at_us", -1, "created_at_us"),
    ],
)
def test_proposal_rejects_invalid_exact_contract_fields(
    proposal: GitHubProposal,
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(proposal, **cast(Any, {field: value}))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kind", "check", "approval kind"),
        ("actor_login", "_invalid", "approval actor"),
        ("permission", "write", "approval permission"),
        ("interface", "cli", "approval interface"),
        ("approval_sha256", "0" * 64, "approval identity"),
    ],
)
def test_approval_rejects_invalid_exact_contract_fields(
    approval: GitHubApproval,
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(approval, **cast(Any, {field: value}))


def test_result_rejects_invalid_exact_contract_fields(
    result: GitHubPublicationResult,
    approval: GitHubApproval,
) -> None:
    invalid: tuple[tuple[str, object, str], ...] = (
        ("kind", "check", "result kind"),
        ("approval", cast(Any, object()), "result approval"),
        ("state", cast(Any, "check_published"), "publication state"),
        ("application_sha256", "8" * 64, "cannot bind"),
        ("published_at_us", approval.approved_at_us - 1, "precedes approval"),
        ("result_sha256", "0" * 64, "result identity"),
    )
    for field, value, message in invalid:
        with pytest.raises(ValueError, match=message):
            replace(result, **cast(Any, {field: value}))


def test_result_rejects_approval_for_another_proposal(
    result: GitHubPublicationResult,
    approval: GitHubApproval,
) -> None:
    other = object.__new__(GitHubApproval)
    for field in approval.__dataclass_fields__:
        object.__setattr__(other, field, getattr(approval, field))
    object.__setattr__(other, "proposal_sha256", "8" * 64)
    with pytest.raises(ValueError, match="does not match proposal"):
        replace(result, approval=other)


def test_github_serializers_reject_wrong_types_and_size(
    proposal: GitHubProposal,
    approval: GitHubApproval,
    result: GitHubPublicationResult,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = (
        (github_module.github_proposal_to_dict, object()),
        (github_module.github_approval_to_dict, object()),
        (github_module.github_result_to_dict, object()),
    )
    for function, value in calls:
        with pytest.raises(TypeError):
            function(cast(Any, value))

    oversized = "x" * (github_module.GITHUB_PROPOSAL_MAX_BYTES + 1)
    monkeypatch.setattr(github_module, "canonical_json_text", lambda _value: oversized)
    with pytest.raises(ValueError, match="byte limit"):
        github_module.github_proposal_to_json(proposal)

    assert approval.approval_sha256
    assert result.readback == _check_readback(proposal)


@pytest.mark.parametrize(
    "parser",
    [
        github_module.github_proposal_from_json,
        github_module.github_approval_from_json,
    ],
)
def test_github_json_parsers_normalize_malformed_records(parser: Any) -> None:
    with pytest.raises(ValueError):
        parser(b"{}")


def test_github_result_parser_normalizes_malformed_record(proposal: GitHubProposal) -> None:
    with pytest.raises(ValueError):
        github_module.github_result_from_json(b"{}", proposal=proposal)


@pytest.mark.parametrize(
    ("function", "args"),
    [
        (github_module._require_schema, (True,)),
        (github_module._require_sha256, ("bad", "digest")),
        (github_module._require_sha1, ("bad", "oid")),
        (github_module._require_positive_int, (False, "count")),
        (github_module._require_timestamp, (-1, "time")),
        (github_module._require_name, ("bad/name", "name")),
        (github_module._require_full_name, ("owner/../repo",)),
        (github_module._require_text, ("", "text")),
        (github_module._require_escaped_text, ("user@example.com", "text")),
        (github_module._require_repository_path, ("/absolute",)),
        (github_module._require_repository_path, ("a/.git/b",)),
        (github_module._require_paths, ([],)),
        (github_module._require_paths, (["b", "a"],)),
        (github_module._require_github_url, ("https://example.com/run",)),
        (github_module._as_object, ([],)),
        (github_module._as_str, (1,)),
        (github_module._as_int, (True,)),
        (github_module._string_list, ([1],)),
    ],
)
def test_github_low_level_contract_rejections(function: Any, args: tuple[object, ...]) -> None:
    keywords: dict[str, object] = {}
    if function is github_module._require_text:
        keywords["maximum"] = 10
    elif function is github_module._require_escaped_text:
        keywords["maximum"] = 100
    with pytest.raises(ValueError):
        function(*args, **keywords)


def test_github_text_contract_rejects_surrogates_and_controls() -> None:
    with pytest.raises(ValueError):
        github_module._require_text("\ud800", "text", maximum=10)
    with pytest.raises(ValueError):
        github_module._require_text("\n", "text", maximum=10)


def test_check_readback_rejects_fields_state_and_proposal_mismatch(
    proposal: GitHubProposal,
    approval: GitHubApproval,
) -> None:
    valid = _check_readback(proposal)
    invalid_values = (
        {**valid, "extra": True},
        {**valid, "status": "queued"},
        {**valid, "check_run_url": "https://github.com/owner/repository/runs/99"},
    )
    for readback in invalid_values:
        with pytest.raises(ValueError):
            build_github_result(
                proposal,
                approval,
                state=GitHubPublicationState.CHECK_PUBLISHED,
                application_sha256=None,
                readback=readback,
                published_at_us=102,
            )


def test_github_public_entrypoint_guards(
    proposal: GitHubProposal,
    approval: GitHubApproval,
    result: GitHubPublicationResult,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="check publication state"):
        replace(result, state=GitHubPublicationState.BRANCH_CREATED)
    with pytest.raises(TypeError):
        build_github_check_proposal(
            repository_id=1,
            repository_full_name="owner/repo",
            pull_request_number=1,
            base_ref="main",
            origin=GitHubProposalOrigin.CLI,
            review_result=cast(Any, object()),
            policy_sha256="a" * 64,
            created_at_us=1,
        )

    non_sha1 = object.__new__(ProductReviewResult)
    for field in _review().__dataclass_fields__:
        object.__setattr__(non_sha1, field, getattr(_review(), field))
    object.__setattr__(non_sha1, "object_format", "sha256")
    with pytest.raises(ValueError, match="SHA-1"):
        build_github_check_proposal(
            repository_id=1,
            repository_full_name="owner/repo",
            pull_request_number=1,
            base_ref="main",
            origin=GitHubProposalOrigin.CLI,
            review_result=non_sha1,
            policy_sha256="a" * 64,
            created_at_us=1,
        )

    repair_keywords = {
        "repository_id": 1,
        "repository_full_name": "owner/repo",
        "pull_request_number": 1,
        "base_ref": "main",
        "origin": GitHubProposalOrigin.CLI,
        "profile_name": "repair",
        "snapshot": object(),
        "preview": object(),
        "created_at_us": 1,
    }
    with pytest.raises(TypeError):
        github_module.build_github_repair_proposal(
            review_result=cast(Any, object()),
            **cast(Any, repair_keywords),
        )
    with pytest.raises(TypeError):
        github_module.build_github_repair_proposal(
            review_result=_review(),
            **cast(Any, repair_keywords),
        )
    with pytest.raises(TypeError):
        approve_github_proposal(
            cast(Any, object()),
            actor_login="actor",
            actor_id=1,
            permission=GitHubPermission.WRITE,
            interface=GitHubApprovalInterface.CLI,
            confirmation=GITHUB_CHECK_CONFIRMATION,
            approved_at_us=1,
        )
    with pytest.raises(TypeError):
        build_github_result(
            cast(Any, object()),
            approval,
            state=GitHubPublicationState.CHECK_PUBLISHED,
            application_sha256=None,
            readback={},
            published_at_us=102,
        )
    with pytest.raises(TypeError):
        github_module.github_proposal_artifact_name(cast(Any, object()))
    with pytest.raises(ValueError):
        github_module.github_result_from_json(b"{}", proposal=cast(Any, object()))
    with pytest.raises(TypeError):
        github_module.validate_github_result(cast(Any, object()), result)

    mismatched = object.__new__(GitHubPublicationResult)
    for field in result.__dataclass_fields__:
        object.__setattr__(mismatched, field, getattr(result, field))
    object.__setattr__(mismatched, "proposal_sha256", "9" * 64)
    with pytest.raises(ValueError, match="does not match"):
        github_module.validate_github_result(proposal, mismatched)

    monkeypatch.setattr(github_module, "REPAIR_PUBLICATION_COMMIT_TIMESTAMP", "invalid")
    with pytest.raises(ValueError, match="timestamp"):
        github_module._fixed_repair_commit_oid(tree_oid=_BASE_OID, head_oid=_HEAD_OID)
    monkeypatch.setattr(
        github_module,
        "REPAIR_PUBLICATION_COMMIT_TIMESTAMP",
        "1970-01-01T00:00:00+01:00",
    )
    with pytest.raises(ValueError, match="timestamp"):
        github_module._fixed_repair_commit_oid(tree_oid=_BASE_OID, head_oid=_HEAD_OID)


def test_github_internal_json_and_text_guards() -> None:
    with pytest.raises(ValueError):
        github_module._parse_payload_json(b"{}")
    with pytest.raises(ValueError):
        github_module._parse_readback_json(b"{}")
    with pytest.raises(ValueError):
        github_module._require_text("too long", "text", maximum=3)


def _source(**changes: object) -> GitHubSourcePullRequest:
    fields: dict[str, object] = {
        "repository_id": _REPOSITORY_ID,
        "repository_full_name": _REPOSITORY_FULL_NAME,
        "repository_is_fork": False,
        "pull_request_number": 7,
        "base_ref": "main",
        "base_oid": _BASE_OID,
        "head_oid": _HEAD_OID,
        "base_repository_id": _REPOSITORY_ID,
        "base_repository_full_name": _REPOSITORY_FULL_NAME,
        "head_repository_id": _REPOSITORY_ID,
        "head_repository_full_name": _REPOSITORY_FULL_NAME,
        "same_repository": True,
    }
    fields.update(changes)
    return GitHubSourcePullRequest(**cast(Any, fields))


def test_source_pull_request_exact_booleans_and_writable_identity() -> None:
    assert _source().writable is True
    assert _source(repository_is_fork=True).writable is False
    with pytest.raises(TypeError, match="repository_is_fork"):
        _source(repository_is_fork=1)
    with pytest.raises(TypeError, match="same_repository"):
        _source(same_repository=1)
    with pytest.raises(ValueError, match="same_repository"):
        _source(head_repository_id=999)


def _store(tmp_path: Path) -> store_module.GitHubPublicationStore:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return store_module.GitHubPublicationStore(
        product_state_root=root,
        repository_alias="repository",
        repository_id=_REPOSITORY_ID,
        repository_full_name=_REPOSITORY_FULL_NAME,
    )


def test_publication_service_constructor_and_input_contracts(tmp_path: Path) -> None:
    transport = GitHubTransport("token")
    store = _store(tmp_path)
    invalid = (
        {"transport": object(), "store": store, "interface": GitHubApprovalInterface.CLI},
        {"transport": transport, "store": object(), "interface": GitHubApprovalInterface.CLI},
        {"transport": transport, "store": store, "interface": "cli"},
        {
            "transport": transport,
            "store": store,
            "interface": GitHubApprovalInterface.CLI,
            "repair_manager": object(),
        },
        {
            "transport": transport,
            "store": store,
            "interface": GitHubApprovalInterface.CLI,
            "clock": 1,
        },
        {
            "transport": transport,
            "store": store,
            "interface": GitHubApprovalInterface.CLI,
            "expected_principal_login": "_bad",
        },
    )
    for keywords in invalid:
        with pytest.raises((TypeError, ValueError)):
            GitHubPublicationService(**cast(Any, keywords))

    service = GitHubPublicationService(
        transport=transport,
        store=store,
        interface=GitHubApprovalInterface.CLI,
    )
    with pytest.raises(GitHubPublicationError) as captured:
        service.read_source_pull_request(
            repository_id=0,
            repository_full_name="bad",
            pull_request_number=0,
            require_same_repository=cast(Any, 1),
        )
    assert captured.value.code == GitHubPublicationErrorCode.INVALID_INPUT


def _check_run(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": 1,
        "node_id": "node",
        "name": "RepoGuard",
        "head_sha": _HEAD_OID,
        "external_id": "8" * 64,
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/owner/repository/runs/1",
        "output": {"annotations_count": 0, "title": "title", "summary": "summary"},
    }
    value.update(changes)
    return value


def test_publication_check_parser_accepts_valid_and_rejects_invalid_states() -> None:
    parsed = publication_module._parse_check_run(cast(Any, _check_run()))
    assert parsed.check_run_id == 1
    assert parsed.conclusion == "success"

    invalid = (
        _check_run(status="unknown"),
        _check_run(conclusion="cancelled"),
        _check_run(status="queued", conclusion="success"),
        _check_run(output={"annotations_count": 1_001, "title": "title", "summary": "summary"}),
    )
    for value in invalid:
        with pytest.raises(ValueError):
            publication_module._parse_check_run(cast(Any, value))


def test_publication_pull_request_and_annotation_parsers() -> None:
    pull_request = {
        "id": 1,
        "number": 8,
        "node_id": "node",
        "html_url": "https://github.com/owner/repository/pull/8",
        "draft": True,
        "state": "open",
        "base": {"ref": "main", "repo": {"id": _REPOSITORY_ID}},
        "head": {"ref": "repair", "repo": {"id": _REPOSITORY_ID}},
        "title": "Repair",
        "body": None,
    }
    parsed = publication_module._parse_pull_request(cast(Any, pull_request))
    assert parsed.body == ""
    assert parsed.draft is True

    annotation = {
        "path": "src/app.py",
        "start_line": 1,
        "end_line": 2,
        "annotation_level": "notice",
        "title": "Title",
        "message": "Message",
        "ignored": "not projected",
    }
    assert publication_module._annotation_projection(cast(Any, annotation)) == {
        key: annotation[key]
        for key in (
            "path",
            "start_line",
            "end_line",
            "annotation_level",
            "title",
            "message",
        )
    }


def test_publication_ref_readback_rejects_ref_type_and_oid() -> None:
    valid = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": _HEAD_OID}}
    assert (
        publication_module._require_ref_response(
            cast(Any, valid),
            expected_ref="refs/heads/main",
            expected_oid=_HEAD_OID,
        )
        == _HEAD_OID
    )
    invalid = (
        ({**valid, "ref": "refs/heads/other"}, _HEAD_OID),
        ({**valid, "object": {"type": "tree", "sha": _HEAD_OID}}, _HEAD_OID),
        (valid, _BASE_OID),
    )
    for value, oid in invalid:
        with pytest.raises(ValueError):
            publication_module._require_ref_response(
                cast(Any, value),
                expected_ref="refs/heads/main",
                expected_oid=oid,
            )


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (publication_module._require_full_name, "owner/../repo"),
        (publication_module._require_ref, "refs//main"),
        (publication_module._require_sha1, "bad"),
        (publication_module._require_positive_int, True),
        (publication_module._object, {1: "value"}),
        (publication_module._list, ()),
        (publication_module._string, 1),
        (publication_module._nonnegative_int, -1),
        (publication_module._bool, 1),
        (publication_module._sha256, "bad"),
    ],
)
def test_publication_parser_primitive_rejections(function: Any, value: object) -> None:
    with pytest.raises(ValueError):
        function(value)


def test_publication_bounded_string_and_input_failures() -> None:
    for value in ("", "long", "nul\x00"):
        with pytest.raises(ValueError):
            publication_module._bounded_string(value, maximum=3)
    with pytest.raises(GitHubPublicationError) as digest:
        publication_module._require_sha256_input("bad")
    assert digest.value.stage is GitHubPublicationStage.INPUT
    with pytest.raises(GitHubPublicationError) as confirmation:
        publication_module._require_confirmation("no", "yes")
    assert confirmation.value.stage is GitHubPublicationStage.APPROVAL


def test_publication_error_domains_and_translation() -> None:
    publication = GitHubPublicationError(
        GitHubPublicationErrorDomain.PUBLICATION,
        "unknown",
        GitHubPublicationStage.INPUT,
    )
    transport = publication_module._transport_failure(
        GitHubTransportError(
            GitHubTransportErrorCode.TIMEOUT,
            status=None,
            retryable=True,
            ambiguous=True,
        ),
        GitHubPublicationStage.CHECK,
    )
    store = publication_module._store_failure(
        GitHubStoreError(
            GitHubStoreErrorCode.IO_FAILED,
            GitHubStoreStage.WRITE,
            retryable=True,
        ),
        GitHubPublicationStage.PERSISTENCE,
    )
    repair = publication_module._repair_failure(
        RepairError(RepairErrorCode.PROVIDER_TIMEOUT, RepairStage.PROVIDER),
        GitHubPublicationStage.LOCAL_REPAIR,
    )
    ambiguous = publication_module._ambiguous_failure(GitHubPublicationStage.CHECK)

    assert str(publication) == "GitHub publication failed."
    assert str(transport) == "GitHub publication transport failed."
    assert str(store) == "GitHub publication storage failed."
    assert str(repair) == "GitHub repair publication failed."
    assert ambiguous.retryable and ambiguous.ambiguous


def test_publication_status_and_store_constructor_contracts(
    proposal: GitHubProposal,
    result: GitHubPublicationResult,
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="proposal"):
        GitHubPublicationStatus(cast(Any, object()), None, None, None)
    with pytest.raises(TypeError, match="approval"):
        GitHubPublicationStatus(proposal, cast(Any, object()), None, None)
    with pytest.raises(TypeError, match="result"):
        GitHubPublicationStatus(proposal, None, cast(Any, object()), None)
    assert GitHubPublicationStatus(proposal, result.approval, None, result).result is result

    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    invalid = (
        {"product_state_root": Path("relative")},
        {"repository_alias": "bad/alias"},
        {"repository_id": 0},
        {"repository_full_name": "owner/../repo"},
        {"lock_timeout_seconds": 0},
    )
    defaults = {
        "product_state_root": root,
        "repository_alias": "repository",
        "repository_id": _REPOSITORY_ID,
        "repository_full_name": _REPOSITORY_FULL_NAME,
        "lock_timeout_seconds": 1.0,
    }
    for change in invalid:
        with pytest.raises(ValueError):
            store_module._validate_constructor_inputs(**cast(Any, defaults | change))


def test_store_real_cas_readback_conflict_and_corrupt_record(tmp_path: Path) -> None:
    directory = tmp_path / "records"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        store_module._write_cas_record(descriptor, "record", b"first", maximum=100)
        assert (
            store_module._read_record(
                descriptor,
                "record",
                maximum=100,
                required=True,
            )
            == b"first"
        )
        store_module._write_cas_record(descriptor, "record", b"first", maximum=100)
        with pytest.raises(GitHubStoreError) as conflict:
            store_module._write_cas_record(descriptor, "record", b"second", maximum=100)
        assert conflict.value.code is GitHubStoreErrorCode.STATE_CONFLICT
        assert (
            store_module._read_record(
                descriptor,
                "missing",
                maximum=100,
                required=False,
            )
            is None
        )
        with pytest.raises(GitHubStoreError) as missing:
            store_module._read_record(descriptor, "missing", maximum=100, required=True)
        assert missing.value.code is GitHubStoreErrorCode.CORRUPT_STATE
        os.chmod(directory / "record", 0o600)
        with pytest.raises(GitHubStoreError) as corrupt:
            store_module._read_record(descriptor, "record", maximum=100, required=True)
        assert corrupt.value.code is GitHubStoreErrorCode.CORRUPT_STATE
    finally:
        os.close(descriptor)


def test_store_cas_rejects_invalid_bytes_and_unsafe_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "records"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(GitHubStoreError) as invalid:
            store_module._write_cas_record(descriptor, "record", b"", maximum=10)
        assert invalid.value.code is GitHubStoreErrorCode.INVALID_IDENTITY

        monkeypatch.setattr(store_module, "_safe_record_metadata", lambda *_args, **_kwargs: False)
        with pytest.raises(GitHubStoreError) as unsafe:
            store_module._write_cas_record(descriptor, "unsafe", b"value", maximum=10)
        assert unsafe.value.code is GitHubStoreErrorCode.IO_FAILED
        assert not (directory / "unsafe").exists()
    finally:
        os.close(descriptor)


def test_store_cas_handles_competing_writer_and_inner_store_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "records"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)

    def competing_link(
        _source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        del src_dir_fd, follow_symlinks
        competing = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=dst_dir_fd,
        )
        os.write(competing, b"value")
        os.fchmod(competing, 0o400)
        os.close(competing)
        raise FileExistsError

    try:
        monkeypatch.setattr(os, "link", competing_link)
        store_module._write_cas_record(descriptor, "same", b"value", maximum=10)
        assert (directory / "same").read_bytes() == b"value"

        monkeypatch.setattr(
            store_module,
            "_record_write_checkpoint",
            lambda _stage: (_ for _ in ()).throw(
                GitHubStoreError(GitHubStoreErrorCode.IO_FAILED, GitHubStoreStage.WRITE)
            ),
        )
        with pytest.raises(GitHubStoreError) as captured:
            store_module._write_cas_record(descriptor, "failure", b"value", maximum=10)
        assert captured.value.code is GitHubStoreErrorCode.IO_FAILED
    finally:
        os.close(descriptor)


def test_store_cas_detects_unsafe_final_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "records"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    checks = iter((True, False))
    monkeypatch.setattr(
        store_module,
        "_safe_record_metadata",
        lambda *_args, **_kwargs: next(checks),
    )
    try:
        with pytest.raises(GitHubStoreError) as captured:
            store_module._write_cas_record(descriptor, "record", b"value", maximum=10)
        assert captured.value.code is GitHubStoreErrorCode.IO_FAILED
    finally:
        os.close(descriptor)


def test_store_write_and_errno_failure_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "write", lambda _descriptor, _value: 0)
    with pytest.raises(OSError, match="short record write"):
        store_module._write_all(1, b"value")
    assert store_module._open_error_code(OSError(errno.EIO, "io")) is GitHubStoreErrorCode.IO_FAILED
    assert (
        store_module._open_error_code(OSError(errno.EPERM, "permission"))
        is GitHubStoreErrorCode.CORRUPT_STATE
    )
    with pytest.raises(GitHubStoreError) as digest:
        store_module._validate_digest_input("bad")
    assert digest.value.code is GitHubStoreErrorCode.INVALID_IDENTITY
    assert repr(store_module._RepairBinding(1, "a" * 64, "b" * 64)) == "_RepairBinding(<private>)"


def _minimal_profile() -> HostProfile:
    review = ProductReviewProfile(
        name="deterministic",
        mode=ProductReviewMode.DETERMINISTIC,
        provider=ProductProviderKind.NONE,
        model=None,
        cache=None,
        device=EmbeddingDevice.CPU,
        fail_on=FindingSeverity.HIGH,
    )
    return HostProfile(
        schema_version=1,
        repositories=(HostRepository("repository", Path("/srv/repository"), 1, "owner/repo"),),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/docker"),
        rootless_socket=Path("/run/user/1000/docker.sock"),
        product_state_root=Path("/var/lib/repoguard/product"),
        repair_state_root=Path("/var/lib/repoguard/repair"),
        runner_labels=(),
        m4_caches=(),
        review_profiles=(review,),
        repair_profiles=(),
        github_actions=None,
        mcp=HostMCPWriters(False, False),
    )


def test_host_profile_dataclass_contracts() -> None:
    with pytest.raises(ValueError, match="repository ID"):
        HostRepository("repo", Path("/repo"), 0, "owner/repo")
    with pytest.raises(ValueError, match="full name"):
        HostRepository("repo", Path("/repo"), 1, "owner/../repo")
    with pytest.raises(ValueError, match="cache device"):
        M4CacheProfile("cache", Path("/cache"), cast(Any, "cpu"))

    base = {
        "name": "review",
        "mode": ProductReviewMode.DETERMINISTIC,
        "provider": ProductProviderKind.NONE,
        "model": None,
        "cache": None,
        "device": EmbeddingDevice.CPU,
        "fail_on": FindingSeverity.HIGH,
    }
    for change in (
        {"mode": "deterministic"},
        {"provider": "none"},
        {"device": "cpu"},
        {"fail_on": "high"},
        {"provider": ProductProviderKind.OPENAI},
        {
            "mode": ProductReviewMode.AGENT,
            "provider": ProductProviderKind.NONE,
            "model": None,
        },
        {
            "mode": ProductReviewMode.AGENT,
            "provider": ProductProviderKind.OPENAI,
            "model": "model",
            "cache": "cache",
        },
        {
            "mode": ProductReviewMode.RETRIEVAL,
            "provider": ProductProviderKind.OPENAI,
            "model": "model",
            "cache": None,
        },
    ):
        with pytest.raises(ValueError):
            ProductReviewProfile(**cast(Any, base | change))

    with pytest.raises(ValueError, match="writer flags"):
        HostMCPWriters(cast(Any, 1), False)
    with pytest.raises(ValueError, match="Action repository"):
        HostGitHubActions("owner/../action", "a" * 40, None)
    with pytest.raises(ValueError, match="Action SHA"):
        HostGitHubActions("owner/action", "bad", None)
    with pytest.raises(ValueError, match="publisher"):
        HostGitHubActions("owner/action", "a" * 40, cast(Any, object()))


def test_repair_and_publisher_profile_contracts() -> None:
    generation = RepairGenerationPolicy(
        mode=RepairGenerationMode.DETERMINISTIC,
        provider_kind=None,
        model=None,
    )
    validation = ValidationPolicy(
        image_id=_IMAGE_ID,
        commands=(ValidationCommand(argv=("/usr/bin/python", "-m", "pytest")),),
    )
    base = {
        "name": "repair",
        "review_profile": "review",
        "generation": generation,
        "validation": validation,
        "allowed_path_prefixes": ("src",),
    }
    for change in (
        {"generation": object()},
        {"validation": object()},
        {"allowed_path_prefixes": ()},
        {"allowed_path_prefixes": ("src", "src")},
    ):
        with pytest.raises(ValueError):
            ProductRepairProfile(**cast(Any, base | change))

    publisher = {
        "python_executable": Path("/runtime/bin/python"),
        "runtime_root": Path("/runtime"),
        "package_root": Path("/runtime/package"),
        "source_root": Path("/source"),
    }
    with pytest.raises(ValueError, match="Python executable"):
        HostPublisherRuntime(**cast(Any, publisher | {"python_executable": Path("/python")}))
    with pytest.raises(ValueError, match="package root"):
        HostPublisherRuntime(**cast(Any, publisher | {"package_root": Path("/package")}))
    with pytest.raises(ValueError, match="overlap"):
        HostPublisherRuntime(**cast(Any, publisher | {"source_root": Path("/runtime/source")}))


def test_host_profile_container_and_lookup_contracts() -> None:
    profile = _minimal_profile()
    assert profile.repository("repository") == profile.repositories[0]
    assert profile.review_profile("deterministic") == profile.review_profiles[0]
    for resolver, name in (
        (profile.repository, "unknown"),
        (profile.review_profile, "unknown"),
        (profile.repair_profile, "unknown"),
    ):
        with pytest.raises(ValueError, match="unknown"):
            resolver(name)

    for change in (
        {"schema_version": 2},
        {"runner_labels": cast(Any, [])},
        {"runner_labels": ("Linux", "X64", "self-hosted")},
        {"github_actions": cast(Any, object())},
        {"mcp": cast(Any, object())},
    ):
        with pytest.raises(ValueError):
            replace(profile, **change)
    with pytest.raises(TypeError, match="exact HostProfile"):
        profile_module.host_profile_to_dict(cast(Any, object()))


def test_host_profile_cross_reference_and_runner_contracts() -> None:
    profile = _minimal_profile()
    with pytest.raises(ValueError, match="runner labels"):
        replace(profile, runner_labels=("Linux", "X64", "custom", "other"))

    retrieval = ProductReviewProfile(
        name="retrieval",
        mode=ProductReviewMode.RETRIEVAL,
        provider=ProductProviderKind.OPENAI,
        model="model",
        cache="missing",
        device=EmbeddingDevice.CPU,
        fail_on=FindingSeverity.HIGH,
    )
    with pytest.raises(ValueError, match="profile cache"):
        replace(profile, review_profiles=(retrieval,))

    repair = ProductRepairProfile(
        name="repair",
        review_profile="missing",
        generation=RepairGenerationPolicy(
            mode=RepairGenerationMode.DETERMINISTIC,
            provider_kind=None,
            model=None,
        ),
        validation=ValidationPolicy(
            image_id=_IMAGE_ID,
            commands=(ValidationCommand(argv=("/usr/bin/python",)),),
        ),
        allowed_path_prefixes=("src",),
    )
    with pytest.raises(ValueError, match="review policy"):
        replace(profile, repair_profiles=(repair,))


def test_load_host_profile_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "profile.json"
    path.write_bytes(b"[]")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="host profile is invalid"):
        profile_module.load_host_profile(path)


@pytest.mark.parametrize(
    ("function", "args"),
    [
        (profile_module._require_absolute_path, (Path("relative"), "path")),
        (profile_module._require_sorted_unique, (("b", "a"), "values")),
        (profile_module._require_sorted_unique, (("a", "a"), "values")),
        (profile_module._require_typed_tuple, ([], str, "values")),
        (profile_module._require_typed_tuple, ((1,), str, "values")),
        (profile_module._require_alias, ("bad/name", "alias")),
        (profile_module._require_text, ("", "text")),
        (profile_module._require_repository_path, ("/absolute", "path")),
        (profile_module._require_repository_path, ("a/.git/b", "path")),
        (profile_module._as_object, ([],)),
        (profile_module._as_object_list, ([1],)),
        (profile_module._as_string_list, ([1],)),
        (profile_module._as_str, (1,)),
        (profile_module._as_int, (True,)),
        (profile_module._as_float, (1,)),
        (profile_module._as_bool, (1,)),
    ],
)
def test_host_profile_primitive_rejections(function: Any, args: tuple[object, ...]) -> None:
    keywords: dict[str, object] = {}
    if function is profile_module._require_text:
        keywords["max_bytes"] = 10
    with pytest.raises(ValueError):
        function(*args, **keywords)


def test_host_profile_text_surrogate_and_optional_string() -> None:
    with pytest.raises(ValueError):
        profile_module._require_text("\ud800", "text", max_bytes=10)
    assert profile_module._as_optional_str(None) is None
    assert profile_module._as_optional_str("value") == "value"
    with pytest.raises(ValueError):
        profile_module._require_text("x" * 11, "text", max_bytes=10)


def test_host_filesystem_security_rejects_modes_links_and_special_files(tmp_path: Path) -> None:
    executable = tmp_path / "tool"
    executable.write_text("tool", encoding="utf-8")
    executable.chmod(0o600)
    with pytest.raises(ValueError, match="executable capability"):
        profile_module._require_regular_executable(executable, "executable")

    private = tmp_path / "private"
    private.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="directory capability"):
        profile_module._require_owned_directory(private, "directory", mode=0o700)
    with pytest.raises(ValueError, match="protected capability"):
        profile_module._require_protected_directory(private, "protected")

    protected = tmp_path / "protected"
    protected.write_text("value", encoding="utf-8")
    protected.chmod(0o600)
    linked = tmp_path / "linked"
    os.link(protected, linked)
    with pytest.raises(ValueError, match="file capability"):
        profile_module._require_protected_regular_file(protected, "file")

    tree = tmp_path / "tree"
    tree.mkdir(mode=0o700)
    os.symlink(protected, tree / "link")
    with pytest.raises(ValueError, match="tree capability"):
        profile_module._require_protected_tree(tree, "tree")


def test_host_tree_accepts_protected_nested_tree_and_rejects_depth(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    child = tree / "child"
    child.mkdir(parents=True, mode=0o700)
    tree.chmod(0o700)
    child.chmod(0o700)
    value = child / "module.py"
    value.write_text("VALUE = 1\n", encoding="utf-8")
    value.chmod(0o600)
    profile_module._require_protected_tree(tree, "tree")

    descriptor = os.open(tree, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="tree capability"):
            profile_module._validate_tree_directory(
                descriptor,
                "tree",
                entries=[0],
                depth=65,
            )
    finally:
        os.close(descriptor)


def test_host_path_security_rejects_invalid_and_writable_ancestors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="host path"):
        profile_module._open_trusted_parent(Path("relative"))

    writable = tmp_path / "writable"
    writable.mkdir(mode=0o777)
    writable.chmod(0o777)
    with pytest.raises(ValueError, match="ancestor is writable"):
        profile_module._open_trusted_parent(writable / "record")

    bad_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid())
    with pytest.raises(ValueError, match="ancestor is invalid"):
        profile_module._require_trusted_directory_metadata(cast(Any, bad_metadata))


def test_transport_remaining_socket_and_response_limit_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_monotonic", lambda: 10.0)
    with pytest.raises(TimeoutError):
        transport_module._remaining(10.0)

    with pytest.raises(OSError):
        transport_module._set_socket_timeout(
            cast(Any, SimpleNamespace(sock=None)),
            11.0,
            1.0,
        )

    for headers in (
        (("Bad Header", "value"),),
        (("X-Test", "\ud800"),),
        (("X-Test", "x" * (70 * 1024)),),
    ):
        assert transport_module._valid_headers(headers) is False

    with pytest.raises(ValueError):
        transport_module._validate_json_limits({"items": list(range(10_001))})
    with pytest.raises(ValueError):
        transport_module._validate_json_limits({str(index): index for index in range(10_001)})


def test_transport_rejects_sender_returning_wrong_response_type() -> None:
    class WrongSender:
        def send(self, _request: object) -> object:
            return object()

    transport = GitHubTransport("token", sender=cast(Any, WrongSender()))
    with pytest.raises(GitHubTransportError) as captured:
        transport.request(transport_module.GitHubMethod.GET, "/user")
    assert captured.value.code is GitHubTransportErrorCode.MALFORMED_RESPONSE


def test_host_socket_capability_rejects_regular_file(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    path = tmp_path / "not-a-socket"
    path.write_text("value", encoding="utf-8")
    with pytest.raises(ValueError, match="socket capability"):
        profile_module._require_owned_socket(path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_path = tmp_path / "real.sock"
    try:
        server.bind(str(socket_path))
        profile_module._require_owned_socket(socket_path)
    finally:
        server.close()
