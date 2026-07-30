"""Coverage-focused behavior tests for the M6 product boundary layers."""

from __future__ import annotations

import argparse
import os
import runpy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.types import CallToolResult, ElicitResult, InputRequiredResult

import repoguard._product as product_core
import repoguard.cli as cli
import repoguard.mcp_server as mcp
from repoguard._github_store import (
    GitHubStoreError,
    GitHubStoreErrorCode,
    GitHubStoreStage,
)
from repoguard.agent import AgentNode, AgentReviewError, AgentReviewErrorCode, FindingSource
from repoguard.evidence import EvidenceCollectionError, EvidenceErrorCode
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
    ProductRepairProfile,
    ProductReviewMode,
    ProductReviewProfile,
)
from repoguard.product import (
    PRODUCT_RESULT_MAX_BYTES,
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductExitCode,
    ProductFinding,
    ProductOperation,
    ProductOrchestrator,
    ProductReference,
    ProductStage,
    product_envelope_to_json,
    product_error_message,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairStage,
    RepairState,
    RepairTarget,
    ValidationCommand,
    ValidationPolicy,
)
from repoguard.retrieval import (
    EmbeddingDevice,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
)
from repoguard.retrieval_agent import (
    RetrievalAgentNode,
    RetrievalAgentReviewError,
    RetrievalAgentReviewErrorCode,
)
from repoguard.review import (
    EvidenceSide,
    FindingCategory,
    FindingSeverity,
    ReviewError,
    ReviewErrorCode,
)

_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _profile(tmp_path: Path) -> HostProfile:
    return HostProfile(
        schema_version=1,
        repositories=(
            HostRepository(
                alias="repo",
                path=tmp_path / "repo",
                github_repository_id=123,
                github_full_name="owner/repo",
            ),
        ),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/true"),
        rootless_socket=tmp_path / "docker.sock",
        product_state_root=tmp_path / "product",
        repair_state_root=tmp_path / "repair",
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
        repair_profiles=(
            ProductRepairProfile(
                name="safe",
                review_profile="deterministic",
                generation=RepairGenerationPolicy(
                    mode=RepairGenerationMode.DETERMINISTIC,
                    provider_kind=None,
                    model=None,
                ),
                validation=ValidationPolicy(
                    image_id=f"sha256:{'c' * 64}",
                    commands=(ValidationCommand(argv=("/usr/bin/true",)),),
                ),
                allowed_path_prefixes=("src",),
            ),
        ),
        github_actions=None,
        mcp=HostMCPWriters(publish_check=False, publish_repair=False),
    )


def _success(
    operation: ProductOperation,
    result: dict[str, object] | None = None,
) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=True,
        result={} if result is None else result,
        error=None,
    )


def _raise(error: Exception) -> Any:
    raise error


def test_profile_validation_redacts_invalid_files_and_projects_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile(tmp_path)
    monkeypatch.setattr(product_core, "load_host_profile", lambda _path: profile)

    valid = product_core._profile_validate(tmp_path / "profile.json")

    assert valid.ok
    assert valid.result is not None
    assert valid.result["repositories"] == [
        {
            "alias": "repo",
            "github_repository_id": 123,
            "github_full_name": "owner/repo",
        }
    ]
    assert valid.result["review_profiles"] == ["deterministic"]
    assert valid.result["repair_profiles"] == ["safe"]
    assert valid.result["mcp_publish_check"] is False

    def invalid(_path: Path) -> HostProfile:
        raise ValueError("private parse detail")

    monkeypatch.setattr(product_core, "load_host_profile", invalid)
    failed = product_core._profile_validate(tmp_path / "bad-profile.json")

    assert not failed.ok
    assert failed.error is not None
    assert failed.error.domain is ProductErrorDomain.PROFILE
    assert failed.error.code == "invalid_profile"
    assert "private parse detail" not in failed.error.message


def test_public_facade_runs_the_complete_local_repair_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class Session:
        def approve(self, **arguments: object) -> object:
            calls.append(("approve", arguments))
            return SimpleNamespace(
                marker="approved",
                approval=SimpleNamespace(approval_sha256=_SHA_B),
                state=SimpleNamespace(value="approved"),
            )

        def apply(self, **arguments: object) -> object:
            calls.append(("apply", arguments))
            return SimpleNamespace(marker="applied")

        def reject(self, **arguments: object) -> object:
            calls.append(("reject", arguments))
            return SimpleNamespace(marker="rejected")

        def cancel(self, **arguments: object) -> object:
            calls.append(("cancel", arguments))
            return SimpleNamespace(marker="cancelled")

        def expire(self) -> object:
            calls.append(("expire", {}))
            return SimpleNamespace(marker="expired")

    class Manager:
        def open_session(self, session_id: str) -> Session:
            calls.append(("open", session_id))
            return Session()

        def recover(self) -> object:
            calls.append(("recover", {}))
            return SimpleNamespace(marker="recovered")

        def cleanup(self) -> object:
            calls.append(("cleanup", {}))
            return SimpleNamespace(marker="cleaned")

    monkeypatch.setattr(product_core, "_manager", lambda _profile, _repository: Manager())
    monkeypatch.setattr(
        product_core,
        "_repair_inputs",
        lambda _profile, _repository: ("repository-input", "manager-config"),
    )
    monkeypatch.setattr(
        product_core,
        "read_repair_snapshot",
        lambda repository, config, session: SimpleNamespace(
            marker=f"status:{repository}:{config}:{session}"
        ),
    )
    monkeypatch.setattr(
        product_core,
        "read_repair_preview",
        lambda repository, config, session: SimpleNamespace(
            marker=f"preview:{repository}:{config}:{session}"
        ),
    )
    monkeypatch.setattr(
        product_core,
        "repair_snapshot_to_dict",
        lambda value: {"marker": value.marker},
    )
    monkeypatch.setattr(
        product_core,
        "repair_preview_to_dict",
        lambda value: {"marker": value.marker},
    )
    monkeypatch.setattr(
        product_core,
        "repair_maintenance_report_to_dict",
        lambda value: {"marker": value.marker},
    )
    product = ProductOrchestrator(_profile(tmp_path))

    status = product.repair_status(repository="repo", session_id=_SHA_A)
    preview = product.repair_preview(repository="repo", session_id=_SHA_A)
    approved = product.repair_approve_local(
        repository="repo",
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
        confirmation="approve",
    )
    applied = product.repair_apply_local(
        repository="repo",
        session_id=_SHA_A,
        approval_sha256=_SHA_B,
    )
    combined = product.repair_approve_and_apply_local(
        repository="repo",
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
        confirmation="approve",
    )
    rejected = product.repair_reject(
        repository="repo",
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        reason="unsafe",
    )
    cancelled = product.repair_cancel(repository="repo", session_id=_SHA_A, reason="operator")
    expired = product.repair_expire(repository="repo", session_id=_SHA_A)
    recovered = product.repair_recover(repository="repo")
    cleaned = product.repair_cleanup(repository="repo")

    assert status.result == {
        "snapshot": {"marker": f"status:repository-input:manager-config:{_SHA_A}"}
    }
    assert preview.result == {
        "preview": {"marker": f"preview:repository-input:manager-config:{_SHA_A}"}
    }
    assert approved.result == {"snapshot": {"marker": "approved"}}
    assert applied.result == {"snapshot": {"marker": "applied"}}
    assert combined.result == {
        "approval_sha256": _SHA_B,
        "snapshot": {"marker": "applied"},
    }
    assert rejected.result == {"snapshot": {"marker": "rejected"}}
    assert cancelled.result == {"snapshot": {"marker": "cancelled"}}
    assert expired.result == {"snapshot": {"marker": "expired"}}
    assert recovered.result == {"maintenance": {"marker": "recovered"}}
    assert cleaned.result == {"maintenance": {"marker": "cleaned"}}
    assert (
        "cancel",
        {"subject": f"uid:{os.geteuid()}", "reason": "operator"},
    ) in calls


def test_combined_local_apply_fails_closed_when_approval_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Session:
        def approve(self, **_arguments: object) -> object:
            return SimpleNamespace(
                approval=None,
                state=SimpleNamespace(value="validated"),
            )

    manager = SimpleNamespace(open_session=lambda _session_id: Session())
    monkeypatch.setattr(product_core, "_manager", lambda _profile, _repository: manager)
    product = ProductOrchestrator(_profile(tmp_path))

    envelope = product.repair_approve_and_apply_local(
        repository="repo",
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
        confirmation="approve",
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.code == "session_corrupt"
    assert envelope.error.stage is ProductStage.APPROVAL
    assert envelope.error.state == "validated"
    assert envelope.error.session_id == _SHA_A


def test_repair_preparation_composes_review_target_validation_and_path_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    bundle = object()
    deterministic = object()
    review = SimpleNamespace(conclusion=SimpleNamespace(value="success"))
    snapshot = SimpleNamespace(
        session_id=_SHA_A,
        validation=SimpleNamespace(success=True),
    )
    preview = object()

    class Session:
        def propose(self, **arguments: object) -> object:
            calls.append(("propose", arguments))
            return snapshot

        def preview(self) -> object:
            calls.append(("preview", {}))
            return preview

    class Manager:
        def create_session(self, *arguments: object, **keywords: object) -> Session:
            calls.append(("create", (arguments, keywords)))
            return Session()

    monkeypatch.setattr(product_core, "collect_evidence", lambda *_args, **_kwargs: bundle)
    monkeypatch.setattr(product_core, "review_evidence", lambda value: deterministic)
    monkeypatch.setattr(
        product_core,
        "build_product_review_result",
        lambda *args, **kwargs: review,
    )
    monkeypatch.setattr(
        product_core,
        "resolve_repair_target",
        lambda _review, _deterministic, _target_id: RepairTarget(0, 0),
    )
    monkeypatch.setattr(product_core, "_manager", lambda _profile, _repository: Manager())
    monkeypatch.setattr(
        product_core,
        "product_review_to_dict",
        lambda value: {"review": value.conclusion.value},
    )
    monkeypatch.setattr(
        product_core,
        "repair_snapshot_to_dict",
        lambda value: {"session_id": value.session_id},
    )
    monkeypatch.setattr(
        product_core,
        "repair_preview_to_dict",
        lambda value: {"preview": value is preview},
    )
    product = ProductOrchestrator(_profile(tmp_path))

    prepared = product.repair_prepare(
        repository="repo",
        base_ref="base",
        head_ref="head",
        repair_profile="safe",
        target_ids=(_SHA_A,),
        allowed_paths=("src/example.py",),
    )

    assert prepared.ok
    assert prepared.result == {
        "review": {"review": "success"},
        "snapshot": {"session_id": _SHA_A},
        "preview": {"preview": True},
        "validation_success": True,
        "policy_passed": True,
    }
    create_call = next(value for name, value in calls if name == "create")
    _arguments, keywords = cast(
        tuple[tuple[object, ...], dict[str, object]],
        create_call,
    )
    assert keywords["targets"] == (RepairTarget(0, 0),)
    assert keywords["allowed_paths"] == ("src/example.py",)
    assert calls[-2:] == [
        ("propose", {"provider": None, "context_index": None}),
        ("preview", {}),
    ]

    unauthorized = product.repair_prepare(
        repository="repo",
        base_ref="base",
        head_ref="head",
        repair_profile="safe",
        target_ids=(_SHA_A,),
        allowed_paths=("tests/example.py",),
    )
    assert not unauthorized.ok
    assert unauthorized.error is not None
    assert unauthorized.error.code == "invalid_path"

    duplicated = product.repair_prepare(
        repository="repo",
        base_ref="base",
        head_ref="head",
        repair_profile="safe",
        target_ids=(_SHA_A, _SHA_B),
        allowed_paths=("src/example.py",),
    )
    assert not duplicated.ok
    assert duplicated.error is not None
    assert duplicated.error.code == "invalid_targets"


def test_public_facade_routes_github_status_recovery_and_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    result = SimpleNamespace(
        approval=SimpleNamespace(approval_sha256=_SHA_A),
        result_sha256=_SHA_B,
        state=SimpleNamespace(value="published"),
    )

    class Store:
        def status(self, proposal_sha256: str) -> object:
            calls.append(("status", proposal_sha256))
            return SimpleNamespace(marker="stored")

    class Service:
        def recover(self, proposal_sha256: str) -> object:
            calls.append(("recover", proposal_sha256))
            return result

        def publish_check(self, proposal_sha256: str, *, confirmation: str) -> object:
            calls.append(("check", (proposal_sha256, confirmation)))
            return result

        def publish_repair(self, proposal_sha256: str, *, confirmation: str) -> object:
            calls.append(("repair", (proposal_sha256, confirmation)))
            return result

    store = Store()
    monkeypatch.setattr(product_core, "_publication_store", lambda _profile, _repository: store)
    monkeypatch.setattr(product_core, "_publication_service", lambda *_args, **_kwargs: Service())
    monkeypatch.setattr(product_core, "_manager", lambda _profile, _repository: object())
    monkeypatch.setattr(
        product_core,
        "_github_status_to_dict",
        lambda value: {"state": value.marker},
    )
    monkeypatch.delenv("REPOGUARD_ACTION_PROPOSAL_PATH", raising=False)
    product = ProductOrchestrator(_profile(tmp_path))

    status = product.github_publication_status(repository="repo", proposal_sha256=_SHA_A)
    recovered = product.github_publication_recover(repository="repo", proposal_sha256=_SHA_A)
    checked = product.github_publish_check(
        repository="repo",
        proposal_sha256=_SHA_A,
        confirmation="publish check",
    )
    repaired = product.github_publish_repair(
        repository="repo",
        proposal_sha256=_SHA_A,
        confirmation="publish repair",
    )

    assert status.result == {"state": "stored"}
    expected = {
        "approval_sha256": _SHA_A,
        "result_sha256": _SHA_B,
        "state": "published",
    }
    assert recovered.result == expected
    assert checked.result == expected
    assert repaired.result == expected
    assert calls == [
        ("status", _SHA_A),
        ("recover", _SHA_A),
        ("check", (_SHA_A, "publish check")),
        ("repair", (_SHA_A, "publish repair")),
    ]


@pytest.mark.parametrize(
    ("error", "domain", "code", "stage", "retryable", "attempt_count"),
    (
        (
            EvidenceCollectionError(EvidenceErrorCode.GIT_TIMEOUT, "secret"),
            ProductErrorDomain.EVIDENCE,
            "git_timeout",
            ProductStage.EVIDENCE,
            True,
            0,
        ),
        (
            ReviewError(ReviewErrorCode.RULE_EXECUTION_FAILED, "secret"),
            ProductErrorDomain.REVIEW,
            "rule_execution_failed",
            ProductStage.REVIEW,
            False,
            0,
        ),
        (
            AgentReviewError(
                AgentReviewErrorCode.PROVIDER_TIMEOUT,
                AgentNode.INVOKE_PROVIDER,
                2,
                "secret",
            ),
            ProductErrorDomain.PROVIDER,
            "provider_timeout",
            ProductStage.INVOKE_PROVIDER,
            True,
            2,
        ),
        (
            AgentReviewError(
                AgentReviewErrorCode.INVALID_MODEL_OUTPUT,
                AgentNode.PARSE_RESPONSE,
                1,
                "secret",
            ),
            ProductErrorDomain.REVIEW,
            "invalid_model_output",
            ProductStage.PARSE_RESPONSE,
            False,
            1,
        ),
        (
            RetrievalAgentReviewError(
                RetrievalAgentReviewErrorCode.PROVIDER_UNAVAILABLE,
                RetrievalAgentNode.INVOKE_PROVIDER,
                3,
            ),
            ProductErrorDomain.PROVIDER,
            "provider_unavailable",
            ProductStage.INVOKE_PROVIDER,
            True,
            3,
        ),
        (
            RetrievalAgentReviewError(
                RetrievalAgentReviewErrorCode.INVALID_INDEX,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                0,
            ),
            ProductErrorDomain.RETRIEVAL,
            "invalid_index",
            ProductStage.RETRIEVE_CONTEXT,
            False,
            0,
        ),
        (
            RetrievalError(
                RetrievalErrorCode.DEADLINE_EXCEEDED,
                RetrievalStage.FUSE,
            ),
            ProductErrorDomain.RETRIEVAL,
            "deadline_exceeded",
            ProductStage.RETRIEVAL,
            True,
            0,
        ),
        (
            RepairError(
                RepairErrorCode.SESSION_LOCKED,
                RepairStage.SESSION,
                RepairState.CREATED,
                _SHA_A,
            ),
            ProductErrorDomain.REPAIR,
            "session_locked",
            ProductStage.SESSION,
            True,
            0,
        ),
        (
            GitHubPublicationError(
                GitHubPublicationErrorDomain.PUBLICATION,
                GitHubPublicationErrorCode.PERMISSION_DENIED.value,
                GitHubPublicationStage.APPROVAL,
                retryable=True,
            ),
            ProductErrorDomain.GITHUB_PUBLICATION,
            "permission_denied",
            ProductStage.APPROVAL,
            True,
            0,
        ),
        (
            GitHubStoreError(
                GitHubStoreErrorCode.LOCK_TIMEOUT,
                GitHubStoreStage.INPUT,
                retryable=True,
            ),
            ProductErrorDomain.GITHUB_STORE,
            "lock_timeout",
            ProductStage.INPUT,
            True,
            0,
        ),
        (
            RuntimeError("secret internal detail"),
            ProductErrorDomain.INTERNAL,
            "internal",
            ProductStage.INTERNAL,
            False,
            0,
        ),
    ),
)
def test_orchestration_detaches_subsystem_errors_into_stable_product_failures(
    error: Exception,
    domain: ProductErrorDomain,
    code: str,
    stage: ProductStage,
    retryable: bool,
    attempt_count: int,
) -> None:
    envelope = product_core._run(
        ProductOperation.REVIEW_RUN,
        lambda: _raise(error),
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is domain
    assert envelope.error.code == code
    assert envelope.error.stage is stage
    assert envelope.error.retryable is retryable
    assert envelope.error.attempt_count == attempt_count
    assert "secret" not in envelope.error.message
    if isinstance(error, RepairError):
        assert envelope.error.state == "created"
        assert envelope.error.session_id == _SHA_A


def test_orchestration_bounds_success_results_before_crossing_an_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        product_core,
        "canonical_json_bytes",
        lambda _value: b"x" * (PRODUCT_RESULT_MAX_BYTES + 1),
    )

    envelope = product_core._run(ProductOperation.REVIEW_RUN, lambda: {"value": "bounded"})

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.EVIDENCE
    assert envelope.error.code == "resource_limit"
    assert envelope.error.stage is ProductStage.FINALIZE


def test_product_records_reject_malformed_authorization_and_identity_fields(
    tmp_path: Path,
) -> None:
    message = product_error_message(ProductErrorDomain.CLI)
    base_error = ProductErrorRecord(
        domain=ProductErrorDomain.CLI,
        code="invalid_request",
        message=message,
        retryable=False,
        stage=ProductStage.INPUT,
        state=None,
        session_id=None,
        proposal_sha256=None,
        attempt_count=0,
    )
    bad_errors = (
        {"domain": "cli"},
        {"code": "INVALID"},
        {"message": "leaked detail"},
        {"retryable": 0},
        {"stage": "input"},
        {"state": "INVALID"},
        {"attempt_count": -1},
    )
    for changes in bad_errors:
        with pytest.raises(ValueError):
            replace(base_error, **cast(dict[str, Any], changes))

    with pytest.raises(ValueError):
        ProductEnvelope(1, cast(Any, "review.run"), True, {}, None)
    with pytest.raises(ValueError):
        ProductEnvelope(1, ProductOperation.REVIEW_RUN, cast(Any, 1), {}, None)
    with pytest.raises(ValueError):
        ProductEnvelope(1, ProductOperation.REVIEW_RUN, True, None, None)
    with pytest.raises(ValueError):
        ProductEnvelope(1, ProductOperation.REVIEW_RUN, False, {}, base_error)
    with pytest.raises(TypeError):
        ProductOrchestrator(cast(Any, object()))
    with pytest.raises(TypeError):
        ProductOrchestrator(_profile(tmp_path), interface=cast(Any, "cli"))


def test_product_findings_reject_noncanonical_evidence_and_agent_targets() -> None:
    reference = ProductReference(
        path="src/example.py",
        side=EvidenceSide.NEW,
        oid="a" * 40,
        start_line=1,
        end_line=1,
        repair_target_id=None,
    )
    with pytest.raises(ValueError):
        replace(reference, side=cast(Any, "new"))
    with pytest.raises(ValueError):
        replace(reference, oid="not-an-object-id")
    with pytest.raises(ValueError):
        replace(reference, start_line=2, end_line=1)

    finding = ProductFinding(
        source=FindingSource.DETERMINISTIC,
        rule_id="rule",
        category=FindingCategory.CORRECTNESS,
        severity=FindingSeverity.HIGH,
        title="title",
        message="message",
        remediation="remediation",
        references=(reference,),
    )
    for changes in (
        {"source": "deterministic"},
        {"category": "correctness"},
        {"severity": "high"},
        {"references": ()},
        {"references": (object(),)},
    ):
        with pytest.raises(ValueError):
            replace(finding, **cast(dict[str, Any], changes))
    targeted = replace(reference, repair_target_id=_SHA_A)
    with pytest.raises(ValueError):
        replace(finding, source=FindingSource.AGENT, references=(targeted,))


def test_mcp_completion_failures_are_canonical_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TypeError):
        mcp.create_mcp_server(cast(Any, object()))

    raised = mcp._complete_call(
        ProductOperation.REVIEW_RUN,
        lambda: _raise(RuntimeError("secret")),
    )
    mismatched = mcp._complete(
        _success(ProductOperation.REPAIR_STATUS),
        operation=ProductOperation.REVIEW_RUN,
    )

    assert raised.is_error
    assert raised.structured_content is not None
    assert cast(dict[str, object], raised.structured_content)["operation"] == "review.run"
    assert mismatched.is_error

    original_serializer = product_envelope_to_json
    serialization_calls = 0

    def fail_oversized_once(envelope: ProductEnvelope) -> str:
        nonlocal serialization_calls
        serialization_calls += 1
        if serialization_calls == 1:
            raise ValueError("product envelope result limit exceeded")
        return original_serializer(envelope)

    monkeypatch.setattr(
        mcp,
        "product_envelope_to_json",
        fail_oversized_once,
    )
    limited = mcp._complete(
        _success(ProductOperation.REVIEW_RUN),
        operation=ProductOperation.REVIEW_RUN,
    )
    assert limited.is_error
    assert cast(dict[str, object], limited.structured_content)["error"] == {
        "domain": "mcp",
        "code": "resource_limit",
        "message": "MCP operation failed",
        "retryable": False,
        "stage": "internal",
        "state": None,
        "session_id": None,
        "proposal_sha256": None,
        "attempt_count": 0,
    }

    serialization_calls = 0

    def fail_internal_once(envelope: ProductEnvelope) -> str:
        nonlocal serialization_calls
        serialization_calls += 1
        if serialization_calls == 1:
            raise RuntimeError("serializer secret")
        return original_serializer(envelope)

    monkeypatch.setattr(mcp, "product_envelope_to_json", fail_internal_once)
    internal = mcp._complete(
        _success(ProductOperation.REVIEW_RUN),
        operation=ProductOperation.REVIEW_RUN,
    )
    assert internal.is_error
    assert cast(dict[str, Any], internal.structured_content)["error"]["code"] == "internal"

    monkeypatch.undo()
    server = mcp.create_mcp_server(_profile(tmp_path), orchestrator=cast(Any, object()))
    assert server.name == "repoguard_mcp"


def test_mcp_confirmation_and_validated_session_guards_are_exact() -> None:
    operation = ProductOperation.GITHUB_PUBLISH_CHECK
    no_response = SimpleNamespace(input_responses=None, request_state=None)
    request = mcp._confirmed_or_request(
        cast(Any, no_response),
        operation=operation,
        expected_state="expected",
        expected_confirmation="confirm",
        prompt="approve",
        proposal_sha256=_SHA_A,
    )
    assert isinstance(request, InputRequiredResult)
    assert request.request_state == "expected"

    wrong_state = SimpleNamespace(
        input_responses={
            "confirmation": ElicitResult(
                action="accept",
                content={"confirmation": "confirm"},
            )
        },
        request_state="stale",
    )
    refused = mcp._confirmed_or_request(
        cast(Any, wrong_state),
        operation=operation,
        expected_state="expected",
        expected_confirmation="confirm",
        prompt="approve",
        proposal_sha256=_SHA_A,
    )
    assert isinstance(refused, CallToolResult)
    assert refused.is_error

    valid_status = _success(
        ProductOperation.REPAIR_STATUS,
        {
            "snapshot": {
                "schema_version": 1,
                "session_id": _SHA_A,
                "state": "validated",
                "approval": None,
                "application": None,
                "decision": None,
                "failure": None,
                "cleanup_pending": False,
                "candidate": {"candidate_id": _SHA_B},
                "validation": {
                    "candidate_id": _SHA_B,
                    "validation_sha256": _SHA_A,
                    "success": True,
                },
            }
        },
    )
    assert mcp._is_exact_validated_session(
        valid_status,
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
    )
    assert not mcp._is_exact_validated_session(
        _success(ProductOperation.REVIEW_RUN),
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
    )
    assert not mcp._is_exact_validated_session(
        _success(ProductOperation.REPAIR_STATUS, {"snapshot": {"schema_version": 1}}),
        session_id=_SHA_A,
        candidate_id=_SHA_B,
        validation_sha256=_SHA_A,
    )
    with pytest.raises(ValueError):
        mcp._failure_for_operation(valid_status, ProductOperation.REPAIR_APPLY_LOCAL)


def test_mcp_argument_guards_reject_ambiguous_or_noncanonical_values() -> None:
    assert not mcp._tool_arguments_are_valid("review_run", None)
    assert not mcp._tool_arguments_are_valid("review_run", {"repository": "repo"})
    assert not mcp._tool_arguments_are_valid(
        "review_run",
        {
            "repository": "repo",
            "base_ref": "base",
            "head_ref": "head",
            "review_profile": "deterministic",
            "github_pr": True,
        },
    )
    assert not mcp._tool_arguments_are_valid(
        "repair_reject",
        {
            "repository": "repo",
            "session_id": _SHA_A,
            "candidate_id": _SHA_B,
            "reason": "x" * 4_097,
        },
    )
    assert not mcp._matches_repository_path("\ud800")
    assert not mcp._matches_repository_path("/src/example.py")
    assert not mcp._is_sorted_unique(["value", 1])
    assert not mcp._is_sorted_unique(["b", "a"])
    assert mcp._argument_sha256(None, "session_id") is None
    assert mcp._argument_sha256({"session_id": _SHA_A}, "session_id") == _SHA_A

    unknown_method = SimpleNamespace(method="resources/list", params={})
    unknown_tool = SimpleNamespace(method="tools/call", params={"name": "unknown"})
    known = SimpleNamespace(
        method="tools/call",
        params={"name": "repair_status", "arguments": {"session_id": _SHA_A}},
    )
    assert mcp._known_tool_request(cast(Any, unknown_method)) is None
    assert mcp._known_tool_request(cast(Any, unknown_tool)) is None
    assert mcp._known_tool_request(cast(Any, known)) == (
        "repair_status",
        {"session_id": _SHA_A},
    )


def test_cli_failure_boundaries_and_module_entry_point_are_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        cli._positive_integer("not-an-integer")

    namespace = argparse.Namespace(
        operation=ProductOperation.REVIEW_RUN,
        profile=tmp_path / "profile.json",
        repository="repo",
    )
    monkeypatch.setattr(cli, "load_host_profile", lambda _path: _raise(ValueError("secret")))
    invalid_profile = cli._dispatch(namespace)
    assert invalid_profile.error is not None
    assert invalid_profile.error.code == "invalid_profile"

    profile = _profile(tmp_path)
    monkeypatch.setattr(cli, "load_host_profile", lambda _path: profile)
    namespace.repository = "missing"
    invalid_repository = cli._dispatch(namespace)
    assert invalid_repository.error is not None
    assert invalid_repository.error.code == "invalid_repository"

    namespace.operation = ProductOperation.MCP_SERVE
    namespace.repository = "repo"
    with pytest.raises(AssertionError):
        cli._dispatch(namespace)

    monkeypatch.setattr(
        "repoguard.mcp_server.serve_mcp_stdio",
        lambda _profile: _raise(RuntimeError("stdio secret")),
    )
    assert cli._serve_mcp(namespace) == ProductExitCode.INTERNAL

    import repoguard.__main__ as module_entry

    monkeypatch.setattr(cli, "main", lambda: 23)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(module_entry.__file__, run_name="__main__")
    assert exit_info.value.code == 23
