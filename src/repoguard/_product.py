"""Shared M6 orchestration implemented only through public M1-M5 APIs."""

from __future__ import annotations

import os
import re
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from repoguard._canonical import canonical_json_bytes, domain_sha256
from repoguard._github_store import (
    GitHubPublicationStatus,
    GitHubPublicationStore,
    GitHubStoreError,
    GitHubStoreStage,
)
from repoguard.agent import (
    AgentReviewConfig,
    AgentReviewError,
    AgentReviewErrorCode,
    AgentReviewResult,
)
from repoguard.evidence import (
    EvidenceBundle,
    EvidenceCollectionError,
    EvidenceCollectionLimits,
    EvidenceErrorCode,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.github import (
    GITHUB_PROPOSAL_MAX_BYTES,
    GitHubApprovalInterface,
    GitHubProposalKind,
    GitHubProposalOrigin,
    GitHubPublicationResult,
    build_github_check_proposal,
    build_github_repair_proposal,
    github_approval_to_dict,
    github_proposal_from_json,
    github_proposal_to_dict,
    github_result_to_dict,
)
from repoguard.github_publication import (
    GitHubPublicationError,
    GitHubPublicationErrorDomain,
    GitHubPublicationService,
    GitHubPublicationStage,
    GitHubSourcePullRequest,
)
from repoguard.github_transport import GitHubTransport
from repoguard.host_profile import (
    HostProfile,
    HostRepository,
    ProductProviderKind,
    ProductRepairProfile,
    ProductReviewMode,
    ProductReviewProfile,
    host_profile_to_dict,
    load_host_profile,
)
from repoguard.product import (
    PRODUCT_RESULT_MAX_BYTES,
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductInterface,
    ProductOperation,
    ProductReviewResult,
    ProductStage,
    build_product_review_result,
    product_error_message,
    product_review_to_dict,
    resolve_repair_target,
)
from repoguard.providers import AnthropicProvider, OpenAIProvider
from repoguard.repair import (
    RepairError,
    RepairGenerationMode,
    RepairManager,
    RepairManagerConfig,
    RepairProviderKind,
    RepairStage,
    read_repair_preview,
    read_repair_snapshot,
    repair_maintenance_report_to_dict,
    repair_preview_to_dict,
    repair_snapshot_to_dict,
)
from repoguard.retrieval import (
    ContextIndex,
    ContextIndexConfig,
    FastEmbedProvider,
    RetrievalError,
    RetrievalErrorCode,
    build_context_index,
)
from repoguard.retrieval_agent import (
    RetrievalAgentReviewConfig,
    RetrievalAgentReviewError,
    RetrievalAgentReviewErrorCode,
    RetrievalAgentReviewResult,
    review_with_retrieval,
)
from repoguard.review import ReviewError, review_evidence

_PRODUCT_LIMITS = EvidenceCollectionLimits(
    max_changed_files=1_000,
    max_blob_bytes=2 * 1024 * 1024,
    max_total_blob_bytes=64 * 1024 * 1024,
    max_diff_bytes=16 * 1024 * 1024,
    max_diff_lines=131_072,
    git_timeout_seconds=60.0,
)
_PRODUCT_CONTEXT_CONFIG = ContextIndexConfig(build_timeout_seconds=60.0)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_GITHUB_TOKEN_ENVIRONMENT = "REPOGUARD_GITHUB_TOKEN"
_ACTION_PROPOSAL_PATH_ENVIRONMENT = "REPOGUARD_ACTION_PROPOSAL_PATH"
_ACTION_ACTOR_ENVIRONMENT = "REPOGUARD_ACTION_ACTOR"
_GITHUB_ACTIONS_ENVIRONMENT = "GITHUB_ACTIONS"
_GITHUB_LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REVIEW_POLICY_DOMAIN = "repoguard.m6.review_policy.v1"
_RETRYABLE_AGENT_CODES = {
    AgentReviewErrorCode.PROVIDER_RATE_LIMITED,
    AgentReviewErrorCode.PROVIDER_TIMEOUT,
    AgentReviewErrorCode.PROVIDER_UNAVAILABLE,
}
_PROVIDER_AGENT_CODES = {
    AgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED,
    AgentReviewErrorCode.PROVIDER_RATE_LIMITED,
    AgentReviewErrorCode.PROVIDER_TIMEOUT,
    AgentReviewErrorCode.PROVIDER_UNAVAILABLE,
    AgentReviewErrorCode.PROVIDER_REQUEST_FAILED,
    AgentReviewErrorCode.PROVIDER_REFUSED,
}
_RETRYABLE_RETRIEVAL_AGENT_CODES = {
    RetrievalAgentReviewErrorCode.PROVIDER_RATE_LIMITED,
    RetrievalAgentReviewErrorCode.PROVIDER_TIMEOUT,
    RetrievalAgentReviewErrorCode.PROVIDER_UNAVAILABLE,
}
_PROVIDER_RETRIEVAL_AGENT_CODES = {
    RetrievalAgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED,
    RetrievalAgentReviewErrorCode.PROVIDER_RATE_LIMITED,
    RetrievalAgentReviewErrorCode.PROVIDER_TIMEOUT,
    RetrievalAgentReviewErrorCode.PROVIDER_UNAVAILABLE,
    RetrievalAgentReviewErrorCode.PROVIDER_REQUEST_FAILED,
    RetrievalAgentReviewErrorCode.PROVIDER_REFUSED,
}


@dataclass(frozen=True, slots=True)
class _ProductFailure(Exception):
    domain: ProductErrorDomain
    code: str
    stage: ProductStage
    retryable: bool = False
    state: str | None = None
    session_id: str | None = None
    proposal_sha256: str | None = None
    attempt_count: int = 0


@dataclass(frozen=True, slots=True)
class _GitHubPreparation:
    store: GitHubPublicationStore
    source: GitHubSourcePullRequest


type _Provider = OpenAIProvider | AnthropicProvider


def _profile_validate(path: Path) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        try:
            profile = load_host_profile(path)
        except ValueError:
            raise _ProductFailure(
                ProductErrorDomain.PROFILE,
                "invalid_profile",
                ProductStage.PROFILE,
            ) from None
        return {
            "profile_sha256": domain_sha256(
                "repoguard.m6.host_profile.v1", host_profile_to_dict(profile)
            ),
            "repositories": [
                {
                    "alias": repository.alias,
                    "github_repository_id": repository.github_repository_id,
                    "github_full_name": repository.github_full_name,
                }
                for repository in profile.repositories
            ],
            "review_profiles": [review.name for review in profile.review_profiles],
            "repair_profiles": [repair.name for repair in profile.repair_profiles],
            "runner_labels": list(profile.runner_labels),
            "mcp_publish_check": profile.mcp.publish_check,
            "mcp_publish_repair": profile.mcp.publish_repair,
        }

    return _run(ProductOperation.PROFILE_VALIDATE, operation)


def _review_run(
    profile: HostProfile,
    *,
    interface: ProductInterface,
    repository: str,
    base_ref: str,
    head_ref: str,
    review_profile: str,
    github_pr: int | None,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_github_pr(github_pr)
        repository_profile = _repository(profile, repository)
        policy = _review_profile(profile, review_profile)
        github: _GitHubPreparation | None = None
        if github_pr is not None:
            github = _prepare_github(
                profile,
                repository_profile,
                interface=interface,
                pull_request_number=github_pr,
                require_same_repository=False,
            )
        bundle = collect_evidence(
            RepositoryInput(repository_profile.path),
            PullRequestInput(base_ref=base_ref, head_ref=head_ref),
            limits=_PRODUCT_LIMITS,
            git_executable=profile.git_executable,
        )
        deterministic = review_evidence(bundle)
        agent_result: AgentReviewResult | RetrievalAgentReviewResult | None = None
        if policy.mode is not ProductReviewMode.DETERMINISTIC:
            provider = _review_provider(policy)
            if policy.mode is ProductReviewMode.AGENT:
                assert policy.model is not None
                agent_result = _run_agent_review(bundle, provider, model=policy.model)
            else:
                cache = _cache_path(profile, policy)
                embedding = FastEmbedProvider(
                    cache_dir=cache,
                    allow_download=False,
                    device=policy.device,
                )
                index = build_context_index(
                    bundle,
                    embedding_provider=embedding,
                    config=_PRODUCT_CONTEXT_CONFIG,
                    git_executable=profile.git_executable,
                )
                try:
                    assert policy.model is not None
                    agent_result = review_with_retrieval(
                        bundle,
                        index=index,
                        provider=provider,
                        config=RetrievalAgentReviewConfig(
                            agent=AgentReviewConfig(model=policy.model)
                        ),
                    )
                finally:
                    index.close()
        result = build_product_review_result(
            repository,
            review_profile,
            bundle,
            deterministic,
            agent_review=agent_result,
            fail_on=policy.fail_on,
        )
        if github is not None:
            _require_review_matches_source(result, github.source)
        mapping = product_review_to_dict(result)
        mapping["policy_passed"] = result.conclusion.value != "failure"
        if github is not None:
            assert github_pr is not None
            mapping["github_pr"] = github_pr
            mapping["github_write_supported"] = github.source.writable
            if github.source.writable:
                proposal = build_github_check_proposal(
                    repository_id=repository_profile.github_repository_id,
                    repository_full_name=repository_profile.github_full_name,
                    pull_request_number=github_pr,
                    base_ref=github.source.base_ref,
                    origin=_github_proposal_origin(interface),
                    review_result=result,
                    policy_sha256=_review_policy_sha256(policy),
                    created_at_us=_wall_clock_us(),
                )
                github.store.record_proposal(proposal)
                mapping["proposal"] = github_proposal_to_dict(proposal)
                mapping["proposal_sha256"] = proposal.proposal_sha256
        return mapping

    return _run(ProductOperation.REVIEW_RUN, operation)


def _repair_prepare(
    profile: HostProfile,
    *,
    interface: ProductInterface,
    repository: str,
    base_ref: str,
    head_ref: str,
    repair_profile: str,
    target_ids: tuple[str, ...],
    allowed_paths: tuple[str, ...],
    github_pr: int | None,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_github_pr(github_pr)
        repository_profile = _repository(profile, repository)
        repair_policy = _repair_profile(profile, repair_profile)
        review_policy = _review_profile(profile, repair_policy.review_profile)
        github: _GitHubPreparation | None = None
        if github_pr is not None:
            github = _prepare_github(
                profile,
                repository_profile,
                interface=interface,
                pull_request_number=github_pr,
                require_same_repository=True,
            )
        _validate_string_tuple(target_ids, "target IDs", minimum=1, maximum=16, sha256=True)
        _validate_string_tuple(
            allowed_paths,
            "allowed paths",
            minimum=1,
            maximum=32,
            repository_paths=True,
        )
        for path in allowed_paths:
            if not any(
                _path_matches_prefix(path, prefix) for prefix in repair_policy.allowed_path_prefixes
            ):
                raise _ProductFailure(
                    ProductErrorDomain.REPAIR,
                    "invalid_path",
                    ProductStage.INPUT,
                )

        bundle = collect_evidence(
            RepositoryInput(repository_profile.path),
            PullRequestInput(base_ref=base_ref, head_ref=head_ref),
            limits=_PRODUCT_LIMITS,
            git_executable=profile.git_executable,
        )
        deterministic = review_evidence(bundle)
        product_review = build_product_review_result(
            repository,
            repair_policy.review_profile,
            bundle,
            deterministic,
            fail_on=review_policy.fail_on,
        )
        if github is not None:
            _require_review_matches_source(product_review, github.source)
        targets = tuple(
            sorted(
                (
                    resolve_repair_target(product_review, deterministic, target_id)
                    for target_id in target_ids
                ),
                key=lambda target: (target.finding_index, target.reference_index),
            )
        )
        if len(targets) != len(set(targets)):
            raise _ProductFailure(
                ProductErrorDomain.REPAIR,
                "invalid_targets",
                ProductStage.INPUT,
            )

        context_index: ContextIndex | None = None
        if (
            review_policy.mode is ProductReviewMode.RETRIEVAL
            and repair_policy.generation.mode is not RepairGenerationMode.DETERMINISTIC
        ):
            embedding = FastEmbedProvider(
                cache_dir=_cache_path(profile, review_policy),
                allow_download=False,
                device=review_policy.device,
            )
            context_index = build_context_index(
                bundle,
                embedding_provider=embedding,
                config=_PRODUCT_CONTEXT_CONFIG,
                git_executable=profile.git_executable,
            )
        try:
            manager = _manager(profile, repository)
            session = manager.create_session(
                bundle,
                deterministic,
                targets=targets,
                allowed_paths=allowed_paths,
                generation=repair_policy.generation,
                validation=repair_policy.validation,
                context_index=context_index,
            )
            provider = _repair_provider(repair_policy.generation.provider_kind)
            snapshot = session.propose(provider=provider, context_index=context_index)
            preview = session.preview()
        finally:
            if context_index is not None:
                context_index.close()
        validation_success = bool(snapshot.validation is not None and snapshot.validation.success)
        result: dict[str, object] = {
            "review": product_review_to_dict(product_review),
            "snapshot": repair_snapshot_to_dict(snapshot),
            "preview": repair_preview_to_dict(preview),
            "validation_success": validation_success,
            "policy_passed": validation_success,
        }
        if github_pr is not None:
            result["github_pr"] = github_pr
            assert github is not None
            result["github_write_supported"] = True
            if validation_success:
                proposal = build_github_repair_proposal(
                    repository_id=repository_profile.github_repository_id,
                    repository_full_name=repository_profile.github_full_name,
                    pull_request_number=github_pr,
                    base_ref=github.source.base_ref,
                    origin=_github_proposal_origin(interface),
                    review_result=product_review,
                    profile_name=repair_policy.name,
                    snapshot=snapshot,
                    preview=preview,
                    created_at_us=_wall_clock_us(),
                )
                github.store.record_proposal(proposal, session_id=snapshot.session_id)
                result["proposal"] = github_proposal_to_dict(proposal)
                result["proposal_sha256"] = proposal.proposal_sha256
        return result

    return _run(ProductOperation.REPAIR_PREPARE, operation)


def _repair_status(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        repository_input, config = _repair_inputs(profile, repository)
        return {
            "snapshot": repair_snapshot_to_dict(
                read_repair_snapshot(repository_input, config, session_id)
            )
        }

    return _run(ProductOperation.REPAIR_STATUS, operation)


def _repair_preview(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        repository_input, config = _repair_inputs(profile, repository)
        return {
            "preview": repair_preview_to_dict(
                read_repair_preview(repository_input, config, session_id)
            )
        }

    return _run(ProductOperation.REPAIR_PREVIEW, operation)


def _repair_approve_local(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
    candidate_id: str,
    validation_sha256: str,
    confirmation: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        snapshot = (
            _manager(profile, repository)
            .open_session(session_id)
            .approve(
                subject=_local_subject(),
                expected_candidate_id=candidate_id,
                expected_validation_sha256=validation_sha256,
                confirmation=confirmation,
            )
        )
        return {"snapshot": repair_snapshot_to_dict(snapshot)}

    return _run(ProductOperation.REPAIR_APPROVE_LOCAL, operation)


def _repair_apply_local(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
    approval_sha256: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        snapshot = (
            _manager(profile, repository)
            .open_session(session_id)
            .apply(expected_approval_sha256=approval_sha256)
        )
        return {"snapshot": repair_snapshot_to_dict(snapshot)}

    return _run(ProductOperation.REPAIR_APPLY_LOCAL, operation)


def _repair_approve_and_apply_local(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
    candidate_id: str,
    validation_sha256: str,
    confirmation: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        session = _manager(profile, repository).open_session(session_id)
        approved = session.approve(
            subject=_local_subject(),
            expected_candidate_id=candidate_id,
            expected_validation_sha256=validation_sha256,
            confirmation=confirmation,
        )
        approval = approved.approval
        if approval is None:
            raise _ProductFailure(
                ProductErrorDomain.REPAIR,
                "session_corrupt",
                ProductStage.APPROVAL,
                state=approved.state.value,
                session_id=session_id,
            )
        applied = session.apply(expected_approval_sha256=approval.approval_sha256)
        return {
            "approval_sha256": approval.approval_sha256,
            "snapshot": repair_snapshot_to_dict(applied),
        }

    return _run(ProductOperation.REPAIR_APPLY_LOCAL, operation)


def _repair_reject(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
    candidate_id: str,
    reason: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        snapshot = (
            _manager(profile, repository)
            .open_session(session_id)
            .reject(
                subject=_local_subject(),
                reason=reason,
                expected_candidate_id=candidate_id,
            )
        )
        return {"snapshot": repair_snapshot_to_dict(snapshot)}

    return _run(ProductOperation.REPAIR_REJECT, operation)


def _repair_cancel(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
    reason: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        snapshot = (
            _manager(profile, repository)
            .open_session(session_id)
            .cancel(subject=_local_subject(), reason=reason)
        )
        return {"snapshot": repair_snapshot_to_dict(snapshot)}

    return _run(ProductOperation.REPAIR_CANCEL, operation)


def _repair_expire(
    profile: HostProfile,
    *,
    repository: str,
    session_id: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        snapshot = _manager(profile, repository).open_session(session_id).expire()
        return {"snapshot": repair_snapshot_to_dict(snapshot)}

    return _run(ProductOperation.REPAIR_EXPIRE, operation)


def _repair_recover(profile: HostProfile, *, repository: str) -> ProductEnvelope:
    return _run(
        ProductOperation.REPAIR_RECOVER,
        lambda: {
            "maintenance": repair_maintenance_report_to_dict(
                _manager(profile, repository).recover()
            )
        },
    )


def _repair_cleanup(profile: HostProfile, *, repository: str) -> ProductEnvelope:
    return _run(
        ProductOperation.REPAIR_CLEANUP,
        lambda: {
            "maintenance": repair_maintenance_report_to_dict(
                _manager(profile, repository).cleanup()
            )
        },
    )


def _github_publication_status(
    profile: HostProfile,
    *,
    repository: str,
    proposal_sha256: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_sha256(proposal_sha256, "proposal digest")
        repository_profile = _repository(profile, repository)
        status = _publication_store(profile, repository_profile).status(proposal_sha256)
        return _github_status_to_dict(status)

    return _run(ProductOperation.GITHUB_PUBLICATION_STATUS, operation)


def _github_publication_recover(
    profile: HostProfile,
    *,
    interface: ProductInterface,
    repository: str,
    proposal_sha256: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_sha256(proposal_sha256, "proposal digest")
        repository_profile = _repository(profile, repository)
        result = _publication_service(
            profile,
            repository_profile,
            interface=interface,
            repair_manager=_manager(profile, repository),
            expected_principal_login=_action_principal(interface),
        ).recover(proposal_sha256)
        return _github_result_summary(result)

    return _run(ProductOperation.GITHUB_PUBLICATION_RECOVER, operation)


def _github_publish_check(
    profile: HostProfile,
    *,
    interface: ProductInterface,
    repository: str,
    proposal_sha256: str,
    confirmation: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_sha256(proposal_sha256, "proposal digest")
        repository_profile = _repository(profile, repository)
        store = _publication_store(profile, repository_profile)
        _import_action_check_proposal(
            store,
            repository_profile,
            interface=interface,
            proposal_sha256=proposal_sha256,
        )
        result = _publication_service(
            profile,
            repository_profile,
            interface=interface,
            store=store,
            expected_principal_login=_action_principal(interface),
        ).publish_check(
            proposal_sha256,
            confirmation=confirmation,
        )
        return _github_result_summary(result)

    return _run(ProductOperation.GITHUB_PUBLISH_CHECK, operation)


def _github_publish_repair(
    profile: HostProfile,
    *,
    interface: ProductInterface,
    repository: str,
    proposal_sha256: str,
    confirmation: str,
) -> ProductEnvelope:
    def operation() -> dict[str, object]:
        _validate_sha256(proposal_sha256, "proposal digest")
        repository_profile = _repository(profile, repository)
        result = _publication_service(
            profile,
            repository_profile,
            interface=interface,
            repair_manager=_manager(profile, repository),
            expected_principal_login=_action_principal(interface),
        ).publish_repair(
            proposal_sha256,
            confirmation=confirmation,
        )
        return _github_result_summary(result)

    return _run(ProductOperation.GITHUB_PUBLISH_REPAIR, operation)


def _run(
    operation: ProductOperation,
    call: Callable[[], dict[str, object]],
) -> ProductEnvelope:
    try:
        result = call()
        if len(canonical_json_bytes(result)) > PRODUCT_RESULT_MAX_BYTES:
            raise _ProductFailure(
                ProductErrorDomain.EVIDENCE,
                "resource_limit",
                ProductStage.FINALIZE,
            )
        return ProductEnvelope(
            schema_version=1,
            operation=operation,
            ok=True,
            result=result,
            error=None,
        )
    except _ProductFailure as error:
        return _failure_envelope(operation, error)
    except EvidenceCollectionError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.EVIDENCE,
                error.code.value,
                ProductStage.EVIDENCE,
                retryable=error.code is EvidenceErrorCode.GIT_TIMEOUT,
            ),
        )
    except ReviewError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.REVIEW,
                error.code.value,
                ProductStage.REVIEW,
            ),
        )
    except AgentReviewError as error:
        domain = (
            ProductErrorDomain.PROVIDER
            if error.code in _PROVIDER_AGENT_CODES
            else ProductErrorDomain.REVIEW
        )
        return _failure_envelope(
            operation,
            _ProductFailure(
                domain,
                error.code.value,
                ProductStage(error.node.value),
                retryable=error.code in _RETRYABLE_AGENT_CODES,
                attempt_count=error.attempt_count,
            ),
        )
    except RetrievalAgentReviewError as error:
        domain = (
            ProductErrorDomain.PROVIDER
            if error.code in _PROVIDER_RETRIEVAL_AGENT_CODES
            else ProductErrorDomain.RETRIEVAL
        )
        return _failure_envelope(
            operation,
            _ProductFailure(
                domain,
                error.code.value,
                ProductStage(error.node.value),
                retryable=error.code in _RETRYABLE_RETRIEVAL_AGENT_CODES,
                attempt_count=error.attempt_count,
            ),
        )
    except RetrievalError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.RETRIEVAL,
                error.code.value,
                ProductStage.RETRIEVAL,
                retryable=error.code
                in (RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalErrorCode.BACKEND_FAILED),
            ),
        )
    except RepairError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.REPAIR,
                error.code.value,
                _repair_stage(error.stage),
                retryable=error.retryable,
                state=None if error.state is None else error.state.value,
                session_id=error.session_id,
            ),
        )
    except GitHubPublicationError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                _github_publication_domain(error.domain),
                error.code,
                _github_publication_stage(error.stage),
                retryable=error.retryable,
            ),
        )
    except GitHubStoreError as error:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.GITHUB_STORE,
                error.code.value,
                _github_store_stage(error.stage),
                retryable=error.retryable,
            ),
        )
    except Exception:
        return _failure_envelope(
            operation,
            _ProductFailure(
                ProductErrorDomain.INTERNAL,
                "internal",
                ProductStage.INTERNAL,
            ),
        )
    finally:
        del call


def _failure_envelope(
    operation: ProductOperation,
    failure: _ProductFailure,
) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=False,
        result=None,
        error=ProductErrorRecord(
            domain=failure.domain,
            code=failure.code,
            message=product_error_message(failure.domain),
            retryable=failure.retryable,
            stage=failure.stage,
            state=failure.state,
            session_id=failure.session_id,
            proposal_sha256=failure.proposal_sha256,
            attempt_count=failure.attempt_count,
        ),
    )


def _repository(profile: HostProfile, alias: str) -> HostRepository:
    try:
        return profile.repository(alias)
    except ValueError:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_repository",
            ProductStage.INPUT,
        ) from None


def _review_profile(profile: HostProfile, name: str) -> ProductReviewProfile:
    try:
        return profile.review_profile(name)
    except ValueError:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_review_profile",
            ProductStage.INPUT,
        ) from None


def _repair_profile(profile: HostProfile, name: str) -> ProductRepairProfile:
    try:
        return profile.repair_profile(name)
    except ValueError:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_repair_profile",
            ProductStage.INPUT,
        ) from None


def _manager(profile: HostProfile, repository: str) -> RepairManager:
    repository_input, config = _repair_inputs(profile, repository)
    return RepairManager(repository_input, config)


def _repair_inputs(
    profile: HostProfile,
    repository: str,
) -> tuple[RepositoryInput, RepairManagerConfig]:
    repository_profile = _repository(profile, repository)
    return (
        RepositoryInput(repository_profile.path),
        RepairManagerConfig(
            runtime_root=profile.repair_state_root / repository_profile.alias,
            git_executable=profile.git_executable,
            docker_executable=profile.docker_executable,
            rootless_socket=profile.rootless_socket,
        ),
    )


def _prepare_github(
    profile: HostProfile,
    repository: HostRepository,
    *,
    interface: ProductInterface,
    pull_request_number: int,
    require_same_repository: bool,
) -> _GitHubPreparation:
    store = _publication_store(profile, repository)
    source = _publication_service(
        profile,
        repository,
        interface=interface,
        store=store,
    ).read_source_pull_request(
        repository_id=repository.github_repository_id,
        repository_full_name=repository.github_full_name,
        pull_request_number=pull_request_number,
        require_same_repository=require_same_repository,
    )
    return _GitHubPreparation(store=store, source=source)


def _publication_store(
    profile: HostProfile,
    repository: HostRepository,
) -> GitHubPublicationStore:
    return GitHubPublicationStore(
        product_state_root=profile.product_state_root,
        repository_alias=repository.alias,
        repository_id=repository.github_repository_id,
        repository_full_name=repository.github_full_name,
    )


def _publication_service(
    profile: HostProfile,
    repository: HostRepository,
    *,
    interface: ProductInterface,
    store: GitHubPublicationStore | None = None,
    repair_manager: RepairManager | None = None,
    expected_principal_login: str | None = None,
) -> GitHubPublicationService:
    token = _github_token()
    try:
        transport = GitHubTransport(token)
    except (TypeError, ValueError):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "authentication_failed",
            ProductStage.TRANSPORT,
        ) from None
    finally:
        token = ""
    return GitHubPublicationService(
        transport=transport,
        store=(_publication_store(profile, repository) if store is None else store),
        interface=_github_approval_interface(interface),
        repair_manager=repair_manager,
        expected_principal_login=expected_principal_login,
    )


def _action_principal(interface: ProductInterface) -> str | None:
    if interface is not ProductInterface.ACTION:
        return None
    login = os.environ.get(_ACTION_ACTOR_ENVIRONMENT)
    if (
        os.environ.get(_GITHUB_ACTIONS_ENVIRONMENT) != "true"
        or login is None
        or _GITHUB_LOGIN_PATTERN.fullmatch(login) is None
    ):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "principal_mismatch",
            ProductStage.TRANSPORT,
        )
    return login


def _github_token() -> str:
    token = os.environ.get(_GITHUB_TOKEN_ENVIRONMENT)
    if (
        token is None
        or not 1 <= len(token) <= 1_024
        or any(not 0x21 <= ord(character) <= 0x7E for character in token)
    ):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "authentication_failed",
            ProductStage.TRANSPORT,
        )
    return token


def _github_proposal_origin(interface: ProductInterface) -> GitHubProposalOrigin:
    if type(interface) is not ProductInterface:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_interface",
            ProductStage.INPUT,
        )
    return GitHubProposalOrigin(interface.value)


def _github_approval_interface(interface: ProductInterface) -> GitHubApprovalInterface:
    if type(interface) is not ProductInterface:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_interface",
            ProductStage.INPUT,
        )
    return GitHubApprovalInterface(interface.value)


def _require_review_matches_source(
    review: ProductReviewResult,
    source: GitHubSourcePullRequest,
) -> None:
    if (
        review.object_format != "sha1"
        or review.base_oid != source.base_oid
        or review.head_oid != source.head_oid
    ):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "pull_request_stale",
            ProductStage.PROPOSAL,
        )


def _review_policy_sha256(policy: ProductReviewProfile) -> str:
    return domain_sha256(
        _REVIEW_POLICY_DOMAIN,
        {
            "name": policy.name,
            "mode": policy.mode.value,
            "provider": policy.provider.value,
            "model": policy.model,
            "cache": policy.cache,
            "device": policy.device.value,
            "fail_on": policy.fail_on.value,
        },
    )


def _github_status_to_dict(status: GitHubPublicationStatus) -> dict[str, object]:
    if status.result is not None:
        state = status.result.state.value
    elif status.partial_result is not None:
        state = status.partial_result.state.value
    elif status.approval is not None:
        state = "approved"
    else:
        state = "proposed"
    return {
        "proposal": github_proposal_to_dict(status.proposal),
        "approval": (None if status.approval is None else github_approval_to_dict(status.approval)),
        "partial_result": (
            None if status.partial_result is None else github_result_to_dict(status.partial_result)
        ),
        "result": None if status.result is None else github_result_to_dict(status.result),
        "state": state,
    }


def _github_result_summary(result: GitHubPublicationResult) -> dict[str, object]:
    return {
        "approval_sha256": result.approval.approval_sha256,
        "result_sha256": result.result_sha256,
        "state": result.state.value,
    }


def _import_action_check_proposal(
    store: GitHubPublicationStore,
    repository: HostRepository,
    *,
    interface: ProductInterface,
    proposal_sha256: str,
) -> None:
    raw_path = os.environ.get(_ACTION_PROPOSAL_PATH_ENVIRONMENT)
    if raw_path is None:
        return
    if (
        interface is not ProductInterface.ACTION
        or os.environ.get(_GITHUB_ACTIONS_ENVIRONMENT) != "true"
    ):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "capability_unavailable",
            ProductStage.PROPOSAL,
            proposal_sha256=proposal_sha256,
        )
    try:
        raw = _read_action_proposal(Path(raw_path))
        proposal = github_proposal_from_json(raw)
    except (OSError, TypeError, ValueError):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "artifact_mismatch",
            ProductStage.PROPOSAL,
            proposal_sha256=proposal_sha256,
        ) from None
    finally:
        raw_path = ""
    if (
        proposal.kind is not GitHubProposalKind.CHECK
        or proposal.origin is not GitHubProposalOrigin.ACTION
        or proposal.proposal_sha256 != proposal_sha256
        or proposal.repository_id != repository.github_repository_id
        or proposal.repository_full_name != repository.github_full_name
    ):
        raise _ProductFailure(
            ProductErrorDomain.GITHUB,
            "artifact_mismatch",
            ProductStage.PROPOSAL,
            proposal_sha256=proposal_sha256,
        )
    store.record_proposal(proposal)


def _read_action_proposal(path: Path) -> bytes:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ValueError("action proposal path is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | os.O_DIRECTORY | nofollow
    descriptors: list[int] = []
    try:
        descriptor = os.open("/", directory_flags)
        descriptors.append(descriptor)
        parts = path.parts[1:]
        if not parts:
            raise ValueError("action proposal path is invalid")
        for part in parts[:-1]:
            if part in ("", ".", ".."):
                raise ValueError("action proposal path is invalid")
            descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            descriptors.append(descriptor)
        file_descriptor = os.open(parts[-1], flags | nofollow, dir_fd=descriptor)
        descriptors.append(file_descriptor)
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 1 <= before.st_size <= GITHUB_PROPOSAL_MAX_BYTES
        ):
            raise ValueError("action proposal file is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("action proposal file changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_descriptor, 1):
            raise ValueError("action proposal file exceeds its bound")
        after = os.fstat(file_descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("action proposal file changed")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _review_provider(policy: ProductReviewProfile) -> _Provider:
    if policy.provider is ProductProviderKind.OPENAI:
        return _provider_from_environment(RepairProviderKind.OPENAI)
    if policy.provider is ProductProviderKind.ANTHROPIC:
        return _provider_from_environment(RepairProviderKind.ANTHROPIC)
    raise _ProductFailure(
        ProductErrorDomain.PROVIDER,
        "provider_required",
        ProductStage.PROVIDER,
    )


def _repair_provider(kind: RepairProviderKind | None) -> _Provider | None:
    if kind is None:
        return None
    return _provider_from_environment(kind)


def _provider_from_environment(kind: RepairProviderKind) -> _Provider:
    variable = (
        "REPOGUARD_OPENAI_API_KEY"
        if kind is RepairProviderKind.OPENAI
        else "REPOGUARD_ANTHROPIC_API_KEY"
    )
    key = os.environ.get(variable)
    if key is None or not key.strip():
        raise _ProductFailure(
            ProductErrorDomain.PROVIDER,
            "authentication_failed",
            ProductStage.PROVIDER,
        )
    try:
        provider: _Provider = (
            OpenAIProvider(key) if kind is RepairProviderKind.OPENAI else AnthropicProvider(key)
        )
    except ValueError:
        raise _ProductFailure(
            ProductErrorDomain.PROVIDER,
            "authentication_failed",
            ProductStage.PROVIDER,
        ) from None
    finally:
        key = ""
    return provider


def _run_agent_review(
    bundle: EvidenceBundle,
    provider: _Provider,
    *,
    model: str,
) -> AgentReviewResult:
    from repoguard.agent import review_with_agent

    return review_with_agent(bundle, provider=provider, config=AgentReviewConfig(model=model))


def _cache_path(profile: HostProfile, policy: ProductReviewProfile) -> Path:
    assert policy.cache is not None
    for cache in profile.m4_caches:
        if cache.name == policy.cache:
            return cache.path
    raise _ProductFailure(
        ProductErrorDomain.PROFILE,
        "invalid_profile",
        ProductStage.PROFILE,
    )


def _validate_github_pr(value: int | None) -> None:
    if value is not None and (type(value) is not int or value <= 0):
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )


def _validate_sha256(value: str, name: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            f"invalid_{name.replace(' ', '_')}",
            ProductStage.INPUT,
        )


def _validate_string_tuple(
    values: object,
    name: str,
    *,
    minimum: int,
    maximum: int,
    sha256: bool = False,
    repository_paths: bool = False,
) -> None:
    if type(values) is not tuple or not minimum <= len(values) <= maximum:
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )
    if any(type(value) is not str or not value for value in values):
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )
    strings = cast(tuple[str, ...], values)
    if (
        len(strings) != len(set(strings))
        or tuple(sorted(strings, key=lambda value: value.encode("utf-8"))) != strings
    ):
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )
    if sha256 and any(_SHA256_PATTERN.fullmatch(value) is None for value in strings):
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )
    if repository_paths and any(not _is_product_repository_path(value) for value in strings):
        raise _ProductFailure(
            ProductErrorDomain.CLI,
            "invalid_request",
            ProductStage.INPUT,
        )


def _is_product_repository_path(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if (
        not encoded
        or len(encoded) > 1_024
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        return False
    parts = value.split("/")
    return all(
        part and part.casefold() not in {".", "..", ".git"} and len(part.encode("utf-8")) <= 255
        for part in parts
    )


def _path_matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def _local_subject() -> str:
    return f"uid:{os.geteuid()}"


def _repair_stage(stage: RepairStage) -> ProductStage:
    try:
        return ProductStage(stage.value)
    except ValueError:
        return ProductStage.INTERNAL


def _github_publication_stage(stage: GitHubPublicationStage) -> ProductStage:
    return {
        GitHubPublicationStage.INPUT: ProductStage.INPUT,
        GitHubPublicationStage.STATUS: ProductStage.PUBLICATION,
        GitHubPublicationStage.PRINCIPAL: ProductStage.TRANSPORT,
        GitHubPublicationStage.REPOSITORY: ProductStage.TRANSPORT,
        GitHubPublicationStage.SOURCE_PULL_REQUEST: ProductStage.TRANSPORT,
        GitHubPublicationStage.APPROVAL: ProductStage.APPROVAL,
        GitHubPublicationStage.CHECK: ProductStage.PUBLICATION,
        GitHubPublicationStage.LOCAL_REPAIR: ProductStage.APPLICATION,
        GitHubPublicationStage.OBJECTS: ProductStage.PUBLICATION,
        GitHubPublicationStage.BRANCH: ProductStage.PUBLICATION,
        GitHubPublicationStage.PULL_REQUEST: ProductStage.PUBLICATION,
        GitHubPublicationStage.PERSISTENCE: ProductStage.PERSISTENCE,
        GitHubPublicationStage.RECOVERY: ProductStage.RECOVERY,
    }[stage]


def _github_publication_domain(
    domain: GitHubPublicationErrorDomain,
) -> ProductErrorDomain:
    return {
        GitHubPublicationErrorDomain.PUBLICATION: ProductErrorDomain.GITHUB_PUBLICATION,
        GitHubPublicationErrorDomain.TRANSPORT: ProductErrorDomain.GITHUB_TRANSPORT,
        GitHubPublicationErrorDomain.STORE: ProductErrorDomain.GITHUB_STORE,
        GitHubPublicationErrorDomain.REPAIR: ProductErrorDomain.REPAIR,
    }[domain]


def _github_store_stage(stage: GitHubStoreStage) -> ProductStage:
    if stage is GitHubStoreStage.INPUT:
        return ProductStage.INPUT
    return ProductStage.PERSISTENCE


def _wall_clock_us() -> int:
    return time.time_ns() // 1_000
