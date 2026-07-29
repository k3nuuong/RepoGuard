"""Private orchestration for durable safe repair sessions."""

from __future__ import annotations

import hashlib
import secrets
import time
from contextlib import suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from repoguard._repair_git import (
    _capture_repository,
    _export_candidate_projection,
    _materialize_candidate,
    _MaterializedCandidate,
    _open_materialized_candidate,
    _publish_repair_ref,
    _read_candidate_tree_files,
    _read_head_file,
    _read_materialized_files,
    _read_repair_ref,
    _RepositoryIdentity,
    _resolve_repository_layout,
)
from repoguard._repair_input import (
    _clone_evidence,
    _clone_review,
    _freeze_repair_request,
    _FrozenRepairRequest,
    _repair_request_from_dict,
    _RepairRepositoryIdentity,
)
from repoguard._repair_models import (
    _canonical_bytes,
    _domain_digest,
    _repair_preview_from_dict,
    _utc_now_us,
)
from repoguard._repair_patch import _parse_wire_patch, _ParsedPatch
from repoguard._repair_prompt import (
    _invoke_repair_provider,
    _render_repair_prompt,
    _RenderedRepairPrompt,
    _repair_prompt_identity,
    _RepairPromptFile,
    _RepairPromptFinding,
    _RepairPromptHit,
    _RepairProviderResult,
    _validate_provider_capability,
)
from repoguard._repair_retrieval import (
    _derive_repair_queries,
    _retrieve_repair_context,
    _validate_live_index,
)
from repoguard._repair_sandbox import (
    _load_sandbox_assets,
    _prepare_sandbox,
    _remove_exact_container,
    _run_sandbox_validation,
    _SandboxRunIdentity,
    _SandboxRunIntent,
    _SandboxRunRejected,
    _SandboxValidationOutcome,
    _stop_exact_container,
    _TrackedInput,
)
from repoguard._repair_secrets import (
    _prepare_private_key_plan,
    _PrivateKeyPlan,
    _redact_private_key_diff,
    _RepairFileContent,
    _SelectedPrivateKeyRange,
    _validate_final_changed_files,
)
from repoguard._repair_store import (
    _cleanup_staging_stores,
    _create_session_store,
    _initialize_runtime_root,
    _is_session_id,
    _list_session_ids,
    _locked_session,
    _manager_lock,
    _remove_session_store,
    _RuntimeRootIdentity,
    _session_path_guard,
    _SessionPathGuard,
    _SessionRemovalOutcome,
    _SessionStore,
    _ValidationRunLease,
)
from repoguard.evidence import EvidenceBundle, RepositoryInput
from repoguard.providers import AnthropicProvider, OpenAIProvider
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApplication,
    RepairApproval,
    RepairCandidate,
    RepairDecision,
    RepairError,
    RepairErrorCode,
    RepairFailure,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairMaintenanceReport,
    RepairManager,
    RepairManagerConfig,
    RepairPreview,
    RepairSession,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairTarget,
    RepairValidation,
    ValidationPolicy,
    repair_context_summary_to_dict,
    repair_preview_to_dict,
    repair_prompt_identity_to_dict,
    validation_command_result_to_dict,
)
from repoguard.retrieval import ContextIndex, IndexIdentity, RetrievalError
from repoguard.review import ReviewResult, RuleId


@dataclass(frozen=True, slots=True)
class _GeneratedCandidate:
    materialized: _MaterializedCandidate
    record: RepairCandidate
    preview: RepairPreview
    prompt_bytes: bytes | None
    response_bytes: bytes | None
    provider_patch_bytes: bytes | None
    deterministic_patch_bytes: bytes | None


class _LateSandboxResult(RuntimeError):
    """Internal marker used to make the sandbox remove a result rejected by state fencing."""

    def __init__(self) -> None:
        super().__init__("late sandbox result")


class _ApplicationRefOutcome(StrEnum):
    ABSENT = "absent"
    EXPECTED = "expected"
    FOREIGN = "foreign"


@dataclass(frozen=True, slots=True)
class _SessionMaintenanceResult:
    recovered: bool = False
    cleaned: bool = False
    removed: bool = False
    cleanup_pending: bool = False
    failed: bool = False


def _initialize_manager(
    repository: RepositoryInput,
    config: RepairManagerConfig,
) -> _RuntimeRootIdentity:
    if type(repository) is not RepositoryInput or type(config) is not RepairManagerConfig:
        _raise_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)
    layout = _resolve_repository_layout(repository, config.git_executable)
    return _initialize_runtime_root(
        config,
        repository_root=layout.root,
        common_dir=layout.common_dir,
    )


def _create_session(
    manager: RepairManager,
    bundle: EvidenceBundle,
    review: ReviewResult,
    *,
    targets: tuple[RepairTarget, ...],
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy,
    validation: ValidationPolicy,
    context_index: ContextIndex | None,
) -> str:
    frozen_bundle = _clone_evidence(bundle)
    frozen_review = _clone_review(review, frozen_bundle)
    source = _capture_repository(
        manager._repository,
        manager._config.git_executable,
        head_oid=frozen_bundle.revisions.head_oid,
        require_current_head=True,
    )
    repository_identity = _RepairRepositoryIdentity(
        source.root,
        source.common_dir,
        source.object_format,
        source.head_oid,
    )
    context_identity = _capture_context_identity(context_index)
    request = _freeze_repair_request(
        manager._repository,
        repository_identity,
        frozen_bundle,
        frozen_review,
        targets=targets,
        allowed_paths=allowed_paths,
        generation=generation,
        validation=validation,
        prompt=_repair_prompt_identity(),
        context_identity=context_identity,
    )
    request_sha256 = request.get("request_sha256")
    if type(request_sha256) is not str:
        _raise_error(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PERSISTENCE, None, None)
    frozen_request = _repair_request_from_dict(request)
    _prepare_request_private_plan(
        frozen_request,
        source,
        manager._config,
        state=None,
        session_id=None,
    )
    session_id = secrets.token_hex(32)
    created_at_us = _utc_now_us()
    snapshot = RepairSnapshot(
        1,
        session_id,
        RepairState.CREATED,
        request_sha256,
        created_at_us,
        created_at_us,
        len(targets),
        tuple(allowed_paths),
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )
    with _manager_lock(
        manager._config,
        runtime_root_identity=manager._runtime_root_identity,
    ):
        _create_session_store(
            manager._config,
            session_id,
            request=request,
            snapshot=snapshot,
            runtime_root_identity=manager._runtime_root_identity,
        )
    return session_id


def _open_session(manager: RepairManager, session_id: str) -> None:
    if not _is_session_id(session_id):
        _raise_error(RepairErrorCode.SESSION_NOT_FOUND, RepairStage.SESSION, None, None)
    with _locked_session(
        manager._config,
        session_id,
        runtime_root_identity=manager._runtime_root_identity,
    ) as storage:
        storage.load()


def _recover(manager: RepairManager) -> RepairMaintenanceReport:
    started_at_us = _utc_now_us()
    with _manager_lock(
        manager._config,
        runtime_root_identity=manager._runtime_root_identity,
    ) as runtime_root_fd:
        staging_removed, staging_failed = _cleanup_staging_stores(runtime_root_fd)
        session_ids = _list_session_ids(
            manager._config,
            runtime_root_identity=manager._runtime_root_identity,
        )
    recovered: list[str] = []
    cleaned: list[str] = []
    removed = list(staging_removed)
    cleanup_pending: list[str] = []
    failed = list(staging_failed)
    for session_id in session_ids:
        result = _recover_session(manager, session_id)
        if result.recovered:
            recovered.append(session_id)
        if result.cleaned:
            cleaned.append(session_id)
        if result.cleanup_pending:
            cleanup_pending.append(session_id)
        if result.failed:
            failed.append(session_id)
    return _maintenance_report(
        started_at_us,
        recovered=recovered,
        cleaned=cleaned,
        removed=removed,
        cleanup_pending=cleanup_pending,
        failed=failed,
    )


def _cleanup(manager: RepairManager) -> RepairMaintenanceReport:
    started_at_us = _utc_now_us()
    cleaned: list[str] = []
    removed: list[str] = []
    cleanup_pending: list[str] = []
    failed: list[str] = []
    with _manager_lock(
        manager._config,
        runtime_root_identity=manager._runtime_root_identity,
    ) as runtime_root_fd:
        staging_removed, staging_failed = _cleanup_staging_stores(runtime_root_fd)
        removed.extend(staging_removed)
        failed.extend(staging_failed)
        session_ids = _list_session_ids(
            manager._config,
            runtime_root_identity=manager._runtime_root_identity,
        )
        for session_id in session_ids:
            result = _cleanup_session(manager, session_id, now_us=started_at_us)
            if result.cleaned:
                cleaned.append(session_id)
            if result.removed:
                removed.append(session_id)
            if result.cleanup_pending:
                cleanup_pending.append(session_id)
            if result.failed:
                failed.append(session_id)
    return _maintenance_report(
        started_at_us,
        cleaned=cleaned,
        removed=removed,
        cleanup_pending=cleanup_pending,
        failed=failed,
    )


def _cleanup_session(
    manager: RepairManager,
    session_id: str,
    *,
    now_us: int,
) -> _SessionMaintenanceResult:
    cleaned = False
    remove_expired = False
    try:
        with _locked_session(
            manager._config,
            session_id,
            runtime_root_identity=manager._runtime_root_identity,
        ) as storage:
            loaded = storage.load()
            snapshot = loaded.snapshot
            if not _is_terminal(snapshot.state):
                return _SessionMaintenanceResult()
            snapshot, cleaned = _retry_terminal_cleanup(
                manager,
                storage,
                snapshot,
                loaded.validation_run,
            )
            if snapshot.cleanup_pending:
                return _SessionMaintenanceResult(cleanup_pending=True)
            terminal_at_us = _terminal_timestamp_us(snapshot)
            retention_us = manager._config.audit_retention_days * 24 * 60 * 60 * 1_000_000
            remove_expired = now_us >= terminal_at_us + retention_us
    except (RepairError, OSError, TypeError, ValueError):
        return _SessionMaintenanceResult(failed=True)
    if not remove_expired:
        return _SessionMaintenanceResult(cleaned=cleaned)
    outcome = _remove_session_store(
        manager._config,
        session_id,
        runtime_root_identity=manager._runtime_root_identity,
    )
    if outcome in {_SessionRemovalOutcome.REMOVED, _SessionRemovalOutcome.ABSENT}:
        return _SessionMaintenanceResult(cleaned=cleaned, removed=True)
    return _SessionMaintenanceResult(cleaned=cleaned, failed=True)


def _retry_terminal_cleanup(
    manager: RepairManager,
    storage: _SessionStore,
    snapshot: RepairSnapshot,
    lease: _ValidationRunLease | None,
) -> tuple[RepairSnapshot, bool]:
    if lease is not None and not _remove_validation_container(manager, lease):
        if snapshot.cleanup_pending:
            return snapshot, False
        pending = replace(
            snapshot,
            updated_at_us=_next_timestamp(snapshot),
            cleanup_pending=True,
        )
        return storage.append("cleanup_pending", pending).snapshot, False
    cleanup_succeeded = storage.cleanup_private()
    if cleanup_succeeded and not snapshot.cleanup_pending and lease is None:
        return snapshot, False
    updated = replace(
        snapshot,
        updated_at_us=_next_timestamp(snapshot),
        cleanup_pending=not cleanup_succeeded,
    )
    kind = "cleanup_complete" if cleanup_succeeded else "cleanup_pending"
    stored = storage.append(
        kind,
        updated,
        clear_validation_run=lease is not None,
    ).snapshot
    return stored, cleanup_succeeded


def _remove_validation_container(
    manager: RepairManager,
    lease: _ValidationRunLease,
) -> bool:
    if lease.container_id is None:
        return False
    identity = _sandbox_identity(lease)
    with suppress(RepairError, OSError, TypeError, ValueError):
        _stop_exact_container(manager._config, identity)
    try:
        return _remove_exact_container(manager._config, identity)
    except (RepairError, OSError, TypeError, ValueError):
        return False


def _terminal_timestamp_us(snapshot: RepairSnapshot) -> int:
    if snapshot.state is RepairState.APPLIED and snapshot.application is not None:
        return snapshot.application.applied_at_us
    if (
        snapshot.state
        in {
            RepairState.REJECTED,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
        }
        and snapshot.decision is not None
    ):
        return snapshot.decision.decided_at_us
    if snapshot.state is RepairState.FAILED and snapshot.failure is not None:
        return snapshot.failure.occurred_at_us
    raise ValueError("terminal snapshot lacks terminal timestamp")


def _recover_session(manager: RepairManager, session_id: str) -> _SessionMaintenanceResult:
    snapshot: RepairSnapshot | None = None
    try:
        with _locked_session(
            manager._config,
            session_id,
            runtime_root_identity=manager._runtime_root_identity,
        ) as storage:
            snapshot = storage.load().snapshot
    except (RepairError, OSError, TypeError, ValueError):
        return _SessionMaintenanceResult(failed=True)
    assert snapshot is not None
    if snapshot.state is RepairState.GENERATING:
        if snapshot.candidate is None:
            final = _recover_as_failed(manager, session_id)
        else:
            final = _recover_candidate_validation(manager, session_id)
        if final is None:
            return _SessionMaintenanceResult(failed=True)
        terminal = _is_terminal(final.state)
        return _SessionMaintenanceResult(
            recovered=True,
            cleaned=terminal and not final.cleanup_pending,
            cleanup_pending=final.cleanup_pending,
        )
    if snapshot.state is RepairState.VALIDATING:
        final = _recover_as_failed(manager, session_id)
        if final is None:
            return _SessionMaintenanceResult(failed=True)
        return _SessionMaintenanceResult(
            recovered=True,
            cleaned=not final.cleanup_pending,
            cleanup_pending=final.cleanup_pending,
        )
    if snapshot.state is RepairState.APPLYING:
        try:
            session = RepairSession(manager, session_id)
            with _locked_session(
                manager._config,
                session_id,
                runtime_root_identity=manager._runtime_root_identity,
            ) as storage:
                current = storage.load().snapshot
                if current.state is not RepairState.APPLYING:
                    return _SessionMaintenanceResult(
                        cleanup_pending=current.cleanup_pending,
                    )
                final, _ = _reconcile_applying_for_decision(session, storage, current)
        except (RepairError, OSError, TypeError, ValueError):
            return _SessionMaintenanceResult(failed=True)
        return _SessionMaintenanceResult(
            recovered=True,
            cleaned=final.state is RepairState.APPLIED and not final.cleanup_pending,
            cleanup_pending=final.cleanup_pending,
        )
    return _SessionMaintenanceResult(cleanup_pending=snapshot.cleanup_pending)


def _recover_as_failed(manager: RepairManager, session_id: str) -> RepairSnapshot | None:
    try:
        return _persist_proposal_failure(
            RepairSession(manager, session_id),
            RepairErrorCode.RECOVERY_FAILED,
            RepairStage.RECOVERY,
        )
    except (RepairError, OSError, TypeError, ValueError):
        return None


def _recover_candidate_validation(
    manager: RepairManager,
    session_id: str,
) -> RepairSnapshot | None:
    session = RepairSession(manager, session_id)
    failure_code: RepairErrorCode | None = None
    failure_stage: RepairStage | None = None
    try:
        with _session_path_guard(
            manager._config,
            session_id,
            runtime_root_identity=manager._runtime_root_identity,
        ) as runtime:
            private_root = runtime.io_path()
            repository_binding = runtime.capture_paths(((private_root / "repository", True),))[0]
            repository_root = runtime.io_path(repository_binding)
            with _locked_session(
                manager._config,
                session_id,
                runtime_root_identity=manager._runtime_root_identity,
                private_identity=runtime.private_identity(),
            ) as storage:
                checkpoint = storage.load().snapshot
                candidate = checkpoint.candidate
                if checkpoint.state is not RepairState.GENERATING or candidate is None:
                    return checkpoint
                request = _load_request(storage, checkpoint)
                source = _capture_frozen_source(
                    manager,
                    request,
                    checkpoint,
                    stage=RepairStage.RECOVERY,
                )
                canonical_diff = _read_candidate_diff(storage, checkpoint)
                materialized = _open_materialized_candidate(
                    source,
                    manager._config.git_executable,
                    repository_root,
                    canonical_diff=canonical_diff,
                    tree_oid=candidate.tree_oid,
                    commit_oid=candidate.commit_oid,
                    changed_paths=candidate.changed_paths,
                    changed_line_count=candidate.changed_line_count,
                )
                projection_files = _read_candidate_tree_files(
                    materialized,
                    manager._config.git_executable,
                )
            probe_bindings = runtime.capture_paths(
                (
                    (private_root / "probe.py", False),
                    (private_root / "seccomp-v1.json", False),
                )
            )
            probe_path = runtime.named_path(probe_bindings[0])
            probe_seccomp_path = runtime.named_path(probe_bindings[1])
            capabilities = _prepare_sandbox(
                manager._config,
                request.validation,
                probe_path=probe_path,
                seccomp_path=probe_seccomp_path,
                mount_identity_check=lambda: runtime.revalidate_paths(probe_bindings),
            )
            validating = _begin_validation(session, checkpoint)
            tracked_inputs = tuple(
                _TrackedInput(
                    item.path,
                    hashlib.sha256(item.content).hexdigest(),
                    item.executable,
                )
                for item in projection_files
            )
            index_sha256 = _sha256_file(materialized.index_file)
            validation_bindings = runtime.capture_paths(
                (
                    (private_root / "candidate-input", True),
                    (private_root / "repository" / ".git", True),
                    (
                        private_root / "repository" / ".git" / "repoguard-index",
                        False,
                    ),
                    (private_root / "runner.py", False),
                    (private_root / "seccomp-v1.json", False),
                )
            )
            runtime.require_same_target(
                validation_bindings[1],
                materialized.git_dir,
                directory=True,
            )
            runtime.require_same_target(
                validation_bindings[2],
                materialized.index_file,
                directory=False,
            )
            candidate_root = runtime.named_path(validation_bindings[0])
            git_dir = runtime.named_path(validation_bindings[1])
            index_file = runtime.named_path(validation_bindings[2])
            runner_path = runtime.named_path(validation_bindings[3])
            seccomp_path = runtime.named_path(validation_bindings[4])
            outcome = _run_sandbox_validation(
                manager._config,
                request.validation,
                capabilities,
                session_id=session_id,
                candidate_id=candidate.candidate_id,
                candidate_root=candidate_root,
                git_dir=git_dir,
                index_file=index_file,
                runner_path=runner_path,
                seccomp_path=seccomp_path,
                tracked_inputs=tracked_inputs,
                git_index_sha256=index_sha256,
                expected_tree_oid=candidate.tree_oid,
                register_intent=lambda intent: _register_validation_intent(
                    session,
                    candidate,
                    intent,
                ),
                register_run=lambda identity: _register_validation_run(
                    session,
                    candidate,
                    identity,
                ),
                release_intent=lambda intent: _release_validation_intent(
                    session,
                    candidate,
                    intent,
                ),
                release_run=lambda identity: _release_validation_run(
                    session,
                    candidate,
                    identity,
                ),
                before_remove=lambda value: _checkpoint_validation_result(
                    session,
                    candidate,
                    value,
                ),
                mount_identity_check=lambda: runtime.revalidate_paths(validation_bindings),
            )
            finalization = (candidate, outcome, validating)
        final_candidate, final_outcome, final_validating = finalization
        return _finish_validation(
            session,
            final_candidate,
            final_outcome,
            final_validating,
        )
    except _LateSandboxResult:
        return _snapshot(session)
    except _SandboxRunRejected:
        return _converge_rejected_sandbox_run(session)
    except RepairError as error:
        failure_code = error.code
        failure_stage = error.stage
    except (OSError, TypeError, ValueError, UnicodeError):
        failure_code = RepairErrorCode.RECOVERY_FAILED
        failure_stage = RepairStage.RECOVERY
    assert failure_code is not None and failure_stage is not None
    try:
        return _persist_proposal_failure(session, failure_code, failure_stage)
    except (RepairError, OSError, TypeError, ValueError):
        return None


def _maintenance_report(
    started_at_us: int,
    *,
    recovered: list[str] | None = None,
    cleaned: list[str] | None = None,
    removed: list[str] | None = None,
    cleanup_pending: list[str] | None = None,
    failed: list[str] | None = None,
) -> RepairMaintenanceReport:
    def sorted_ids(values: list[str] | None) -> tuple[str, ...]:
        return () if values is None else tuple(sorted(set(values)))

    return RepairMaintenanceReport(
        1,
        started_at_us,
        max(started_at_us, _utc_now_us()),
        sorted_ids(recovered),
        sorted_ids(cleaned),
        sorted_ids(removed),
        sorted_ids(cleanup_pending),
        sorted_ids(failed),
    )


def _is_terminal(state: RepairState) -> bool:
    return state in {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }


def _propose(
    session: RepairSession,
    *,
    provider: OpenAIProvider | AnthropicProvider | None,
    context_index: ContextIndex | None,
) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        snapshot = storage.load().snapshot
        if snapshot.state is not RepairState.CREATED:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, RepairStage.SESSION)
        request = _load_request(storage, snapshot)
        _validate_provider_capability(
            request.generation,
            provider,
            state=snapshot.state,
            session_id=snapshot.session_id,
        )
        _validate_context_capability(request, context_index, snapshot)
        generating = replace(
            snapshot,
            state=RepairState.GENERATING,
            updated_at_us=_next_timestamp(snapshot),
        )
        generating = storage.append("generating", generating).snapshot

    failure_code: RepairErrorCode | None = None
    failure_stage: RepairStage | None = None
    try:
        with _session_path_guard(
            session._manager._config,
            session._session_id,
            runtime_root_identity=session._manager._runtime_root_identity,
        ) as runtime:
            generated = _generate_candidate(
                session,
                request,
                generating,
                runtime=runtime,
                provider=provider,
                context_index=context_index,
            )
            private_root = runtime.io_path()
            projection_binding = runtime.create_directory("candidate-input")
            projection_root = runtime.io_path(projection_binding)
            projection_files = _export_candidate_projection(
                generated.materialized,
                session._manager._config.git_executable,
                projection_root,
                _destination_precreated=True,
            )
            assets = _load_sandbox_assets()
            checkpoint = _persist_candidate_checkpoint(
                session,
                generating,
                generated,
                assets.runner,
                assets.probe,
                assets.seccomp_json,
                private_identity=runtime.private_identity(),
            )
            probe_bindings = runtime.capture_paths(
                (
                    (private_root / "probe.py", False),
                    (private_root / "seccomp-v1.json", False),
                )
            )
            probe_path = runtime.named_path(probe_bindings[0])
            probe_seccomp_path = runtime.named_path(probe_bindings[1])
            capabilities = _prepare_sandbox(
                session._manager._config,
                request.validation,
                probe_path=probe_path,
                seccomp_path=probe_seccomp_path,
                mount_identity_check=lambda: runtime.revalidate_paths(probe_bindings),
            )
            validating = _begin_validation(session, checkpoint)
            tracked_inputs = tuple(
                _TrackedInput(
                    item.path,
                    hashlib.sha256(item.content).hexdigest(),
                    item.executable,
                )
                for item in projection_files
            )
            index_sha256 = _sha256_file(generated.materialized.index_file)
            validation_bindings = runtime.capture_paths(
                (
                    (private_root / "candidate-input", True),
                    (private_root / "repository" / ".git", True),
                    (
                        private_root / "repository" / ".git" / "repoguard-index",
                        False,
                    ),
                    (private_root / "runner.py", False),
                    (private_root / "seccomp-v1.json", False),
                )
            )
            runtime.require_same_target(
                validation_bindings[0],
                projection_root,
                directory=True,
            )
            runtime.require_same_target(
                validation_bindings[1],
                generated.materialized.git_dir,
                directory=True,
            )
            runtime.require_same_target(
                validation_bindings[2],
                generated.materialized.index_file,
                directory=False,
            )
            candidate_root = runtime.named_path(validation_bindings[0])
            git_dir = runtime.named_path(validation_bindings[1])
            index_file = runtime.named_path(validation_bindings[2])
            runner_path = runtime.named_path(validation_bindings[3])
            seccomp_path = runtime.named_path(validation_bindings[4])
            outcome = _run_sandbox_validation(
                session._manager._config,
                request.validation,
                capabilities,
                session_id=session._session_id,
                candidate_id=generated.record.candidate_id,
                candidate_root=candidate_root,
                git_dir=git_dir,
                index_file=index_file,
                runner_path=runner_path,
                seccomp_path=seccomp_path,
                tracked_inputs=tracked_inputs,
                git_index_sha256=index_sha256,
                expected_tree_oid=generated.record.tree_oid,
                register_intent=lambda intent: _register_validation_intent(
                    session,
                    generated.record,
                    intent,
                ),
                register_run=lambda identity: _register_validation_run(
                    session,
                    generated.record,
                    identity,
                ),
                release_intent=lambda intent: _release_validation_intent(
                    session,
                    generated.record,
                    intent,
                ),
                release_run=lambda identity: _release_validation_run(
                    session,
                    generated.record,
                    identity,
                ),
                before_remove=lambda value: _checkpoint_validation_result(
                    session,
                    generated.record,
                    value,
                ),
                mount_identity_check=lambda: runtime.revalidate_paths(validation_bindings),
            )
            finalization = (generated.record, outcome, validating)
        final_candidate, final_outcome, final_validating = finalization
        return _finish_validation(
            session,
            final_candidate,
            final_outcome,
            final_validating,
        )
    except _LateSandboxResult:
        return _snapshot(session)
    except _SandboxRunRejected:
        return _converge_rejected_sandbox_run(session)
    except RepairError as error:
        failure_code = error.code
        failure_stage = error.stage
    except (OSError, TypeError, ValueError, UnicodeError):
        failure_code = RepairErrorCode.INVALID_WORKFLOW
        failure_stage = RepairStage.SESSION
    assert failure_code is not None and failure_stage is not None
    failed = _persist_proposal_failure(session, failure_code, failure_stage)
    if failed.state in {RepairState.CANCELLED, RepairState.EXPIRED}:
        return failed
    _raise_error(failure_code, failure_stage, failed.state, failed.session_id)


def _converge_rejected_sandbox_run(session: RepairSession) -> RepairSnapshot:
    snapshot = _snapshot(session)
    if snapshot.state in {
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }:
        return snapshot
    _raise_error(
        RepairErrorCode.SESSION_CORRUPT,
        RepairStage.PERSISTENCE,
        snapshot.state,
        snapshot.session_id,
    )


def _preview(session: RepairSession) -> RepairPreview:
    invalid_preview = False
    preview: RepairPreview | None = None
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        snapshot = storage.load().snapshot
        candidate = snapshot.candidate
        if candidate is None:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, RepairStage.SESSION)
        try:
            preview = _repair_preview_from_dict(storage.read_preview())
        except (TypeError, ValueError):
            invalid_preview = True
        if preview is not None and (
            preview.session_id != snapshot.session_id
            or preview.candidate_id != candidate.candidate_id
            or preview.changed_paths != candidate.changed_paths
        ):
            invalid_preview = True
        if not invalid_preview and preview is not None:
            validation_sha256 = (
                None if snapshot.validation is None else snapshot.validation.validation_sha256
            )
            preview = replace(
                preview,
                state=snapshot.state,
                validation_sha256=validation_sha256,
            )
    if invalid_preview or preview is None:
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            session._session_id,
        )
    return preview


def _approve(
    session: RepairSession,
    *,
    subject: str,
    expected_candidate_id: str,
    expected_validation_sha256: str,
    confirmation: str,
) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        snapshot = storage.load().snapshot
        if snapshot.state is not RepairState.VALIDATED:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, RepairStage.APPROVAL)
        candidate = snapshot.candidate
        validation = snapshot.validation
        if candidate is None or validation is None or not validation.success:
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                snapshot.state,
                snapshot.session_id,
            )
        if (
            type(expected_candidate_id) is not str
            or type(expected_validation_sha256) is not str
            or expected_candidate_id != candidate.candidate_id
            or expected_validation_sha256 != validation.validation_sha256
            or type(confirmation) is not str
            or confirmation != REPAIR_APPROVAL_CONFIRMATION
        ):
            _raise_for_state(
                snapshot,
                RepairErrorCode.APPROVAL_MISMATCH,
                RepairStage.APPROVAL,
            )
        approved_at_us = _next_timestamp(snapshot)
        approval = _build_approval(
            snapshot,
            subject=subject,
            confirmation=confirmation,
            approved_at_us=approved_at_us,
        )
        approved = replace(
            snapshot,
            state=RepairState.APPROVED,
            updated_at_us=approved_at_us,
            approval=approval,
        )
        return storage.append("approved", approved).snapshot


def _apply(session: RepairSession, *, expected_approval_sha256: str) -> RepairSnapshot:
    result: RepairSnapshot | None = None
    error_code: RepairErrorCode | None = None
    error_state: RepairState | None = None
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        snapshot = storage.load().snapshot
        if snapshot.state is not RepairState.APPROVED:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, RepairStage.APPLICATION)
        approval = snapshot.approval
        candidate_record = snapshot.candidate
        if approval is None or candidate_record is None:
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                snapshot.state,
                snapshot.session_id,
            )
        if (
            type(expected_approval_sha256) is not str
            or expected_approval_sha256 != approval.approval_sha256
        ):
            _raise_for_state(
                snapshot,
                RepairErrorCode.APPROVAL_MISMATCH,
                RepairStage.APPLICATION,
            )
        with _session_path_guard(
            session._manager._config,
            session._session_id,
            runtime_root_identity=session._manager._runtime_root_identity,
            private_identity=storage.private_identity(),
        ) as runtime:
            private_root = runtime.io_path()
            repository_binding = runtime.capture_paths(((private_root / "repository", True),))[0]
            source, candidate = _open_application_candidate(
                session,
                storage,
                snapshot,
                runtime.io_path(repository_binding),
            )
            candidate_bindings = (repository_binding,)
            if type(candidate) is _MaterializedCandidate:
                runtime.require_same_target(
                    repository_binding,
                    candidate.root,
                    directory=True,
                )
            applying_at_us = _next_timestamp(snapshot)
            applying = replace(
                snapshot,
                state=RepairState.APPLYING,
                updated_at_us=applying_at_us,
            )
            applying = storage.append("applying", applying).snapshot
            runtime.revalidate_paths(candidate_bindings)
            try:
                _publish_repair_ref(
                    source,
                    candidate,
                    session._manager._config.git_executable,
                    candidate_record.candidate_id,
                    inherited_lock_fd=storage.publication_lock_fd(),
                )
            except RepairError:
                pass
            except (OSError, TypeError, ValueError):
                pass
            runtime.revalidate_paths(candidate_bindings)
            ref_outcome: _ApplicationRefOutcome | None = None
            with suppress(RepairError, OSError, TypeError, ValueError):
                ref_outcome = _read_application_ref_outcome(
                    session,
                    source,
                    candidate_record,
                )
            runtime.revalidate_paths(candidate_bindings)
        if ref_outcome is None:
            error_code = RepairErrorCode.PUBLICATION_FAILED
            error_state = RepairState.APPLYING
        else:
            result = _persist_application_ref_outcome(storage, applying, ref_outcome)
            if ref_outcome is _ApplicationRefOutcome.ABSENT:
                error_code = RepairErrorCode.PUBLICATION_FAILED
                error_state = RepairState.APPROVED
            elif ref_outcome is _ApplicationRefOutcome.FOREIGN:
                error_code = RepairErrorCode.REF_CONFLICT
                error_state = RepairState.APPROVED
    if result is not None and result.state is RepairState.APPLIED:
        return result
    assert error_code is not None and error_state is not None
    _raise_error(error_code, RepairStage.APPLICATION, error_state, session._session_id)


def _open_application_candidate(
    session: RepairSession,
    storage: _SessionStore,
    snapshot: RepairSnapshot,
    repository_root: Path,
) -> tuple[_RepositoryIdentity, _MaterializedCandidate]:
    candidate = snapshot.candidate
    approval = snapshot.approval
    if candidate is None or approval is None:
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            snapshot.session_id,
        )
    request = _load_request(storage, snapshot)
    source = _capture_frozen_source(
        session._manager,
        request,
        snapshot,
        stage=RepairStage.APPLICATION,
    )
    canonical_diff = _read_candidate_diff(storage, snapshot)
    materialized = _open_materialized_candidate(
        source,
        session._manager._config.git_executable,
        repository_root,
        canonical_diff=canonical_diff,
        tree_oid=candidate.tree_oid,
        commit_oid=candidate.commit_oid,
        changed_paths=candidate.changed_paths,
        changed_line_count=candidate.changed_line_count,
    )
    return source, materialized


def _read_application_ref_outcome(
    session: RepairSession,
    source: _RepositoryIdentity,
    candidate: RepairCandidate,
) -> _ApplicationRefOutcome:
    current = _read_repair_ref(
        source,
        session._manager._config.git_executable,
        candidate.candidate_id,
        expected_commit_oid=candidate.commit_oid,
    )
    if current is None:
        return _ApplicationRefOutcome.ABSENT
    if current == candidate.commit_oid:
        return _ApplicationRefOutcome.EXPECTED
    return _ApplicationRefOutcome.FOREIGN


def _persist_application_ref_outcome(
    storage: _SessionStore,
    applying: RepairSnapshot,
    outcome: _ApplicationRefOutcome,
) -> RepairSnapshot:
    candidate = applying.candidate
    approval = applying.approval
    if candidate is None or approval is None:
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            applying.state,
            applying.session_id,
        )
    if outcome is _ApplicationRefOutcome.EXPECTED:
        applied_at_us = _next_timestamp(applying)
        application = _build_application(
            applying,
            ref=f"refs/repoguard/repairs/{candidate.candidate_id}",
            commit_oid=candidate.commit_oid,
            applied_at_us=applied_at_us,
        )
        applied = replace(
            applying,
            state=RepairState.APPLIED,
            updated_at_us=applied_at_us,
            application=application,
            cleanup_pending=True,
        )
        return _persist_terminal(storage, "applied", applied)
    restored = replace(
        applying,
        state=RepairState.APPROVED,
        updated_at_us=_next_timestamp(applying),
    )
    kind = "application_conflict" if outcome is _ApplicationRefOutcome.FOREIGN else "recovered"
    return storage.append(kind, restored).snapshot


def _reconcile_applying_for_decision(
    session: RepairSession,
    storage: _SessionStore,
    applying: RepairSnapshot,
) -> tuple[RepairSnapshot, _ApplicationRefOutcome]:
    outcome: _ApplicationRefOutcome | None = None
    try:
        with _session_path_guard(
            session._manager._config,
            session._session_id,
            runtime_root_identity=session._manager._runtime_root_identity,
            private_identity=storage.private_identity(),
        ) as runtime:
            private_root = runtime.io_path()
            repository_binding = runtime.capture_paths(((private_root / "repository", True),))[0]
            source, materialized = _open_application_candidate(
                session,
                storage,
                applying,
                runtime.io_path(repository_binding),
            )
            candidate_bindings = (repository_binding,)
            if type(materialized) is _MaterializedCandidate:
                runtime.require_same_target(
                    repository_binding,
                    materialized.root,
                    directory=True,
                )
            candidate = applying.candidate
            assert candidate is not None
            outcome = _read_application_ref_outcome(session, source, candidate)
            runtime.revalidate_paths(candidate_bindings)
    except (RepairError, OSError, TypeError, ValueError):
        pass
    if outcome is None:
        _raise_error(
            RepairErrorCode.PUBLICATION_FAILED,
            RepairStage.APPLICATION,
            RepairState.APPLYING,
            applying.session_id,
        )
    return _persist_application_ref_outcome(storage, applying, outcome), outcome


def _reject(
    session: RepairSession,
    *,
    subject: str,
    reason: str,
    expected_candidate_id: str,
) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        snapshot = storage.load().snapshot
        if snapshot.state not in {RepairState.VALIDATED, RepairState.APPROVED}:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, RepairStage.APPROVAL)
        candidate = snapshot.candidate
        if (
            candidate is None
            or type(expected_candidate_id) is not str
            or expected_candidate_id != candidate.candidate_id
        ):
            _raise_for_state(
                snapshot,
                RepairErrorCode.INVALID_DECISION,
                RepairStage.APPROVAL,
            )
        decided_at_us = _next_timestamp(snapshot)
        decision = _build_decision(
            snapshot,
            state=RepairState.REJECTED,
            subject=subject,
            reason=reason,
            decided_at_us=decided_at_us,
        )
        rejected = replace(
            snapshot,
            state=RepairState.REJECTED,
            updated_at_us=decided_at_us,
            decision=decision,
            cleanup_pending=True,
        )
        return _persist_terminal(storage, "rejected", rejected)


def _cancel(session: RepairSession, *, subject: str, reason: str) -> RepairSnapshot:
    lease: _ValidationRunLease | None = None
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        _require_nonterminal(snapshot, RepairStage.SESSION)
        if snapshot.state is RepairState.APPLYING:
            snapshot, outcome = _reconcile_applying_for_decision(session, storage, snapshot)
            if outcome is _ApplicationRefOutcome.EXPECTED:
                return snapshot
            if outcome is _ApplicationRefOutcome.FOREIGN:
                _raise_error(
                    RepairErrorCode.REF_CONFLICT,
                    RepairStage.APPLICATION,
                    snapshot.state,
                    snapshot.session_id,
                )
        decided_at_us = _next_timestamp(snapshot)
        decision = _build_decision(
            snapshot,
            state=RepairState.CANCELLED,
            subject=subject,
            reason=reason,
            decided_at_us=decided_at_us,
        )
        cancelled = replace(
            snapshot,
            state=RepairState.CANCELLED,
            updated_at_us=decided_at_us,
            decision=decision,
            cleanup_pending=True,
        )
        lease = loaded.validation_run
        if lease is None:
            return _persist_terminal(storage, "cancelled", cancelled)
        cancelled = storage.append("cancelled", cancelled).snapshot
    return _cleanup_terminal_validation_run(session, cancelled, lease)


def _expire(session: RepairSession) -> RepairSnapshot:
    lease: _ValidationRunLease | None = None
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        _require_nonterminal(snapshot, RepairStage.SESSION)
        if snapshot.state is RepairState.APPLYING:
            snapshot, outcome = _reconcile_applying_for_decision(session, storage, snapshot)
            if outcome is _ApplicationRefOutcome.EXPECTED:
                return snapshot
            if outcome is _ApplicationRefOutcome.FOREIGN:
                _raise_error(
                    RepairErrorCode.REF_CONFLICT,
                    RepairStage.APPLICATION,
                    snapshot.state,
                    snapshot.session_id,
                )
        decided_at_us = _next_timestamp(snapshot)
        decision = _build_decision(
            snapshot,
            state=RepairState.EXPIRED,
            subject="RepoGuard expiration",
            reason="",
            decided_at_us=decided_at_us,
        )
        expired = replace(
            snapshot,
            state=RepairState.EXPIRED,
            updated_at_us=decided_at_us,
            decision=decision,
            cleanup_pending=True,
        )
        lease = loaded.validation_run
        if lease is None:
            return _persist_terminal(storage, "expired", expired)
        expired = storage.append("expired", expired).snapshot
    return _cleanup_terminal_validation_run(session, expired, lease)


def _snapshot(session: RepairSession) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        return storage.load().snapshot


def _capture_context_identity(context_index: ContextIndex | None) -> IndexIdentity | None:
    if context_index is None:
        return None
    if type(context_index) is not ContextIndex:
        _raise_error(RepairErrorCode.IDENTITY_MISMATCH, RepairStage.RETRIEVAL, None, None)
    identity: IndexIdentity | None = None
    invalid = False
    try:
        candidate = context_index.identity
        if type(candidate) is IndexIdentity:
            _validate_live_index(context_index, candidate, time.monotonic() + 5.0)
            identity = candidate
        else:
            invalid = True
    except (RetrievalError, TypeError, ValueError):
        invalid = True
    except Exception:
        invalid = True
    if invalid or identity is None:
        _raise_error(RepairErrorCode.IDENTITY_MISMATCH, RepairStage.RETRIEVAL, None, None)
    return identity


def _load_request(storage: _SessionStore, snapshot: RepairSnapshot) -> _FrozenRepairRequest:
    request: _FrozenRepairRequest | None = None
    invalid = False
    try:
        request = _repair_request_from_dict(storage.read_private_json("request.json"))
    except (TypeError, ValueError):
        invalid = True
    if (
        invalid
        or request is None
        or request.request_sha256 != snapshot.request_sha256
        or request.allowed_paths != snapshot.allowed_paths
        or len(request.targets) != snapshot.target_count
    ):
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            snapshot.session_id,
        )
    return request


def _capture_frozen_source(
    manager: RepairManager,
    request: _FrozenRepairRequest,
    snapshot: RepairSnapshot,
    *,
    stage: RepairStage,
) -> _RepositoryIdentity:
    source = _capture_repository(
        manager._repository,
        manager._config.git_executable,
        head_oid=request.repository.head_oid,
    )
    if (
        source.root != request.repository.worktree_root
        or source.common_dir != request.repository.common_dir
        or source.object_format != request.repository.object_format
        or source.head_oid != request.repository.head_oid
    ):
        _raise_error(
            RepairErrorCode.IDENTITY_MISMATCH,
            stage,
            snapshot.state,
            snapshot.session_id,
        )
    return source


def _generate_candidate(
    session: RepairSession,
    request: _FrozenRepairRequest,
    snapshot: RepairSnapshot,
    *,
    runtime: _SessionPathGuard,
    provider: OpenAIProvider | AnthropicProvider | None,
    context_index: ContextIndex | None,
) -> _GeneratedCandidate:
    if type(runtime) is not _SessionPathGuard:
        raise TypeError("runtime must be an exact _SessionPathGuard")
    source = _capture_frozen_source(
        session._manager,
        request,
        snapshot,
        stage=RepairStage.MATERIALIZATION,
    )
    private_plan = _prepare_request_private_plan(
        request,
        source,
        session._manager._config,
        state=snapshot.state,
        session_id=snapshot.session_id,
    )
    _validate_provider_capability(
        request.generation,
        provider,
        state=snapshot.state,
        session_id=snapshot.session_id,
    )
    deadline = time.monotonic() + request.generation.total_timeout_seconds
    queries = _derive_repair_queries(
        request.evidence,
        request.review,
        request.targets,
        request.generation,
    )
    context = _retrieve_repair_context(
        expected_identity=request.context_identity,
        index=context_index,
        queries=queries,
        policy=request.generation,
        deadline=deadline,
        state=snapshot.state,
        session_id=snapshot.session_id,
    )

    rendered: _RenderedRepairPrompt | None = None
    provider_result: _RepairProviderResult | None = None
    provider_patch: _ParsedPatch | None = None
    if request.generation.mode is not RepairGenerationMode.DETERMINISTIC:
        rendered = _render_repair_prompt(
            object_format=source.object_format,
            head_oid=source.head_oid,
            findings=_repair_prompt_findings(request),
            allowed_files=tuple(
                _RepairPromptFile(item.path, item.present, item.content)
                for item in private_plan.prompt_files
            ),
            context_hits=tuple(
                _RepairPromptHit(
                    item.path,
                    item.oid,
                    item.start_line,
                    item.end_line,
                    item.content,
                    item.definitions,
                    item.references,
                )
                for item in context.hits
            ),
            policy=request.generation,
            state=snapshot.state,
            session_id=snapshot.session_id,
        )
        if rendered.identity != request.prompt:
            _raise_error(
                RepairErrorCode.IDENTITY_MISMATCH,
                RepairStage.PROMPT,
                snapshot.state,
                snapshot.session_id,
            )
        assert provider is not None
        provider_result = _invoke_repair_provider(
            provider,
            rendered,
            request.generation,
            deadline=deadline,
            state=snapshot.state,
            session_id=snapshot.session_id,
        )
        provider_patch = _parse_wire_patch(
            provider_result.patch,
            allowed_paths=request.allowed_paths,
            policy=request.generation,
        )

    patches = tuple(
        patch for patch in (private_plan.deterministic_patch, provider_patch) if patch is not None
    )
    if not patches:
        _raise_error(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.PATCH,
            snapshot.state,
            snapshot.session_id,
        )
    repository_binding = runtime.create_directory("repository")
    materialized = _materialize_candidate(
        source,
        session._manager._config.git_executable,
        runtime.io_path(repository_binding),
        patches,
        _destination_precreated=True,
    )
    final_files = _read_materialized_files(
        materialized,
        session._manager._config.git_executable,
    )
    _validate_final_changed_files(
        tuple(_RepairFileContent(item.path, item.content) for item in final_files),
        state=snapshot.state,
        session_id=snapshot.session_id,
    )
    diff_bytes = materialized.canonical_diff.encode("utf-8")
    diff_sha256 = hashlib.sha256(diff_bytes).hexdigest()
    candidate_payload: dict[str, object] = {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "prompt": repair_prompt_identity_to_dict(request.prompt),
        "context": repair_context_summary_to_dict(context.summary),
        "diff_sha256": diff_sha256,
        "tree_oid": materialized.tree_oid,
        "commit_oid": materialized.commit_oid,
    }
    record = RepairCandidate(
        1,
        _domain_digest("candidate", candidate_payload),
        request.request_sha256,
        request.prompt,
        context.summary,
        diff_sha256,
        materialized.tree_oid,
        materialized.commit_oid,
        materialized.changed_paths,
        materialized.changed_line_count,
        0 if provider_result is None else provider_result.attempt_count,
        0 if provider_result is None else provider_result.input_tokens,
        0 if provider_result is None else provider_result.output_tokens,
    )
    preview = RepairPreview(
        1,
        snapshot.session_id,
        RepairState.GENERATING,
        record.candidate_id,
        None,
        record.changed_paths,
        _redact_private_key_diff(
            materialized.canonical_diff,
            private_plan.protected_ranges,
            state=snapshot.state,
            session_id=snapshot.session_id,
        ),
        REPAIR_APPROVAL_CONFIRMATION,
    )
    return _GeneratedCandidate(
        materialized,
        record,
        preview,
        None if rendered is None else _repair_prompt_bytes(rendered),
        None if provider_result is None else provider_result.response_text.encode("utf-8"),
        None if provider_patch is None else provider_patch.source.encode("utf-8"),
        (
            None
            if private_plan.deterministic_patch is None
            else private_plan.deterministic_patch.source.encode("utf-8")
        ),
    )


def _repair_prompt_findings(
    request: _FrozenRepairRequest,
) -> tuple[_RepairPromptFinding, ...]:
    result: list[_RepairPromptFinding] = []
    for target in request.targets:
        finding = request.review.findings[target.finding_index]
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL:
            continue
        reference = finding.references[target.reference_index]
        if reference.start_line is None or reference.end_line is None:
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                None,
            )
        result.append(
            _RepairPromptFinding(
                finding.rule_id.value,
                finding.category.value,
                finding.severity.value,
                finding.title,
                finding.remediation,
                reference.path,
                reference.start_line,
                reference.end_line,
            )
        )
    if not result:
        _raise_error(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROMPT, None, None)
    return tuple(result)


def _repair_prompt_bytes(rendered: _RenderedRepairPrompt) -> bytes:
    return _canonical_bytes(
        {
            "schema_version": 1,
            "messages": [
                {"role": message.role.value, "content": message.content}
                for message in rendered.messages
            ],
        }
    )


def _validate_context_capability(
    request: _FrozenRepairRequest,
    context_index: ContextIndex | None,
    snapshot: RepairSnapshot,
) -> None:
    invalid = False
    if request.context_identity is None:
        invalid = context_index is not None
    elif type(context_index) is not ContextIndex:
        invalid = True
    else:
        try:
            identity = context_index.identity
            invalid = type(identity) is not IndexIdentity or identity != request.context_identity
        except Exception:
            invalid = True
    if invalid:
        _raise_error(
            RepairErrorCode.IDENTITY_MISMATCH,
            RepairStage.RETRIEVAL,
            snapshot.state,
            snapshot.session_id,
        )


def _persist_candidate_checkpoint(
    session: RepairSession,
    generating: RepairSnapshot,
    generated: _GeneratedCandidate,
    runner: bytes,
    probe: bytes,
    seccomp_json: bytes,
    *,
    private_identity: _RuntimeRootIdentity,
) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
        private_identity=private_identity,
    ) as storage:
        current = storage.load().snapshot
        if current.state is not RepairState.GENERATING:
            raise _LateSandboxResult
        if (
            current != generating
            or current.candidate is not None
            or generated.record.request_sha256 != current.request_sha256
        ):
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                current.state,
                current.session_id,
            )
        payloads: tuple[tuple[str, bytes | None], ...] = (
            ("prompt.json", generated.prompt_bytes),
            ("response.json", generated.response_bytes),
            ("provider.patch", generated.provider_patch_bytes),
            ("private-key.patch", generated.deterministic_patch_bytes),
            ("candidate.diff", generated.materialized.canonical_diff.encode("utf-8")),
            ("runner.py", runner),
            ("probe.py", probe),
            ("seccomp-v1.json", seccomp_json),
        )
        for name, value in payloads:
            if value is not None:
                storage.write_private_bytes(name, value)
        storage.write_preview(repair_preview_to_dict(generated.preview))
        checkpoint = replace(
            current,
            updated_at_us=_next_timestamp(current),
            candidate=generated.record,
        )
        return storage.append("candidate", checkpoint).snapshot


def _begin_validation(session: RepairSession, checkpoint: RepairSnapshot) -> RepairSnapshot:
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        current = storage.load().snapshot
        if current.state is not RepairState.GENERATING:
            raise _LateSandboxResult
        if current != checkpoint or current.candidate is None:
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                current.state,
                current.session_id,
            )
        validating = replace(
            current,
            state=RepairState.VALIDATING,
            updated_at_us=_next_timestamp(current),
        )
        return storage.append("validating", validating).snapshot


def _register_validation_run(
    session: RepairSession,
    candidate: RepairCandidate,
    identity: _SandboxRunIdentity,
) -> bool:
    if (
        type(identity) is not _SandboxRunIdentity
        or identity.session_id != session._session_id
        or identity.candidate_id != candidate.candidate_id
    ):
        return False
    lease = _validation_lease(identity)
    expected_intent = replace(lease, container_id=None)
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if (
            snapshot.candidate != candidate
            or snapshot.validation is not None
            or loaded.validation_run != expected_intent
            or snapshot.state
            not in {
                RepairState.VALIDATING,
                RepairState.CANCELLED,
                RepairState.EXPIRED,
                RepairState.FAILED,
            }
        ):
            return False
        registered = replace(snapshot, updated_at_us=_next_timestamp(snapshot))
        storage.append("validation_run", registered, validation_run=lease)
    return snapshot.state is RepairState.VALIDATING


def _register_validation_intent(
    session: RepairSession,
    candidate: RepairCandidate,
    intent: _SandboxRunIntent,
) -> bool:
    if (
        type(intent) is not _SandboxRunIntent
        or intent.session_id != session._session_id
        or intent.candidate_id != candidate.candidate_id
    ):
        return False
    lease = _validation_intent_lease(intent)
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if (
            snapshot.state is not RepairState.VALIDATING
            or snapshot.candidate != candidate
            or snapshot.validation is not None
            or loaded.validation_run is not None
        ):
            return False
        registered = replace(snapshot, updated_at_us=_next_timestamp(snapshot))
        storage.append("validation_intent", registered, validation_run=lease)
    return True


def _release_validation_intent(
    session: RepairSession,
    candidate: RepairCandidate,
    intent: _SandboxRunIntent,
) -> bool:
    if (
        type(intent) is not _SandboxRunIntent
        or intent.session_id != session._session_id
        or intent.candidate_id != candidate.candidate_id
    ):
        return False
    expected = _validation_intent_lease(intent)
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if loaded.validation_run is None:
            return True
        if snapshot.candidate != candidate or loaded.validation_run != expected:
            return False
        if snapshot.state is RepairState.VALIDATING:
            abandoned = replace(snapshot, updated_at_us=_next_timestamp(snapshot))
            storage.append(
                "validation_intent_abandoned",
                abandoned,
                clear_validation_run=True,
            )
            return True
        if not _is_terminal(snapshot.state):
            return False
        cleanup_succeeded = storage.cleanup_private()
        cleaned = replace(
            snapshot,
            updated_at_us=_next_timestamp(snapshot),
            cleanup_pending=not cleanup_succeeded,
        )
        kind = "cleanup_complete" if cleanup_succeeded else "cleanup_pending"
        storage.append(kind, cleaned, clear_validation_run=True)
    return True


def _release_validation_run(
    session: RepairSession,
    candidate: RepairCandidate,
    identity: _SandboxRunIdentity,
) -> bool:
    if (
        type(identity) is not _SandboxRunIdentity
        or identity.session_id != session._session_id
        or identity.candidate_id != candidate.candidate_id
    ):
        return False
    expected = _validation_lease(identity)
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if loaded.validation_run is None:
            return True
        if (
            snapshot.candidate != candidate
            or loaded.validation_run != expected
            or not _is_terminal(snapshot.state)
        ):
            return False
        cleanup_succeeded = storage.cleanup_private()
        cleaned = replace(
            snapshot,
            updated_at_us=_next_timestamp(snapshot),
            cleanup_pending=not cleanup_succeeded,
        )
        kind = "cleanup_complete" if cleanup_succeeded else "cleanup_pending"
        storage.append(kind, cleaned, clear_validation_run=True)
    return True


def _checkpoint_validation_result(
    session: RepairSession,
    candidate: RepairCandidate,
    outcome: _SandboxValidationOutcome,
) -> None:
    validation = _build_validation(outcome)
    expected_lease = _validation_lease(outcome.run_identity)
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if (
            snapshot.state is not RepairState.VALIDATING
            or snapshot.candidate != candidate
            or snapshot.validation is not None
            or loaded.validation_run != expected_lease
        ):
            raise _LateSandboxResult
        checkpoint = replace(
            snapshot,
            updated_at_us=_next_timestamp(snapshot),
            validation=validation,
        )
        storage.append("validation_result", checkpoint)


def _finish_validation(
    session: RepairSession,
    candidate: RepairCandidate,
    outcome: _SandboxValidationOutcome,
    validating: RepairSnapshot,
) -> RepairSnapshot:
    validation = _build_validation(outcome)
    expected_lease = _validation_lease(outcome.run_identity)
    cleanup_failed = False
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if snapshot.state is not RepairState.VALIDATING:
            return snapshot
        if (
            validating.candidate != candidate
            or snapshot.candidate != candidate
            or snapshot.validation != validation
            or loaded.validation_run != expected_lease
        ):
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                snapshot.state,
                snapshot.session_id,
            )
        if outcome.cleanup_pending:
            occurred_at_us = _next_timestamp(snapshot)
            failed = replace(
                snapshot,
                state=RepairState.FAILED,
                updated_at_us=occurred_at_us,
                failure=_build_failure(
                    RepairErrorCode.CLEANUP_FAILED,
                    RepairStage.CLEANUP,
                    occurred_at_us,
                ),
                cleanup_pending=True,
            )
            result = storage.append("failed", failed).snapshot
            cleanup_failed = True
        elif validation.success:
            validated = replace(
                snapshot,
                state=RepairState.VALIDATED,
                updated_at_us=_next_timestamp(snapshot),
            )
            result = storage.append(
                "validated",
                validated,
                clear_validation_run=True,
            ).snapshot
        else:
            occurred_at_us = _next_timestamp(snapshot)
            failed = replace(
                snapshot,
                state=RepairState.FAILED,
                updated_at_us=occurred_at_us,
                failure=_build_failure(
                    RepairErrorCode.VALIDATION_FAILED,
                    RepairStage.VALIDATION,
                    occurred_at_us,
                ),
                cleanup_pending=True,
            )
            result = _persist_terminal(
                storage,
                "failed",
                failed,
                clear_validation_run=True,
            )
    if cleanup_failed:
        _raise_error(
            RepairErrorCode.CLEANUP_FAILED,
            RepairStage.CLEANUP,
            result.state,
            result.session_id,
        )
    return result


def _build_validation(outcome: _SandboxValidationOutcome) -> RepairValidation:
    report = outcome.report
    payload: dict[str, object] = {
        "schema_version": 1,
        "candidate_id": outcome.candidate_id,
        "policy_sha256": outcome.policy_sha256,
        "sandbox_manifest_sha256": outcome.sandbox_manifest_sha256,
        "image_id": outcome.image_id,
        "started_at_us": report.started_at_us,
        "finished_at_us": report.finished_at_us,
        "success": report.success,
        "failure_kind": None if report.failure_kind is None else report.failure_kind.value,
        "command_results": [
            validation_command_result_to_dict(result) for result in report.command_results
        ],
        "peak_memory_bytes": report.peak_memory_bytes,
        "oom_killed": report.oom_killed,
        "residual_process_count": report.residual_process_count,
        "workspace_entry_count": report.workspace_entry_count,
        "workspace_inode_count": report.workspace_inode_count,
        "tracked_tree_clean": report.tracked_tree_clean,
    }
    return RepairValidation(
        1,
        _domain_digest("validation", payload),
        outcome.candidate_id,
        outcome.policy_sha256,
        outcome.sandbox_manifest_sha256,
        outcome.image_id,
        report.started_at_us,
        report.finished_at_us,
        report.success,
        report.failure_kind,
        report.command_results,
        report.peak_memory_bytes,
        report.oom_killed,
        report.residual_process_count,
        report.workspace_entry_count,
        report.workspace_inode_count,
        report.tracked_tree_clean,
    )


def _validation_lease(identity: _SandboxRunIdentity) -> _ValidationRunLease:
    return _ValidationRunLease(
        identity.container_id,
        identity.container_name,
        tuple(sorted(identity.labels)),
        identity.session_id,
        identity.candidate_id,
        identity.run_token_sha256,
    )


def _validation_intent_lease(intent: _SandboxRunIntent) -> _ValidationRunLease:
    return _ValidationRunLease(
        None,
        intent.container_name,
        tuple(sorted(intent.labels)),
        intent.session_id,
        intent.candidate_id,
        intent.run_token_sha256,
    )


def _sandbox_identity(lease: _ValidationRunLease) -> _SandboxRunIdentity:
    if lease.container_id is None:
        raise ValueError("validation intent has no container identity")
    return _SandboxRunIdentity(
        lease.container_id,
        lease.container_name,
        lease.labels,
        lease.session_id,
        lease.candidate_id,
        lease.run_token_sha256,
    )


def _sha256_file(path: Path) -> str:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError("digest path is invalid")
    content: bytes | None = None
    with suppress(OSError):
        content = path.read_bytes()
    if content is None:
        _raise_error(RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX, None, None)
    return hashlib.sha256(content).hexdigest()


def _build_failure(
    code: RepairErrorCode,
    stage: RepairStage,
    occurred_at_us: int,
) -> RepairFailure:
    retryable = RepairError(code, stage).retryable
    return RepairFailure(1, code, stage, retryable, occurred_at_us)


def _persist_proposal_failure(
    session: RepairSession,
    code: RepairErrorCode,
    stage: RepairStage,
) -> RepairSnapshot:
    lease: _ValidationRunLease | None = None
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        snapshot = loaded.snapshot
        if snapshot.state in {
            RepairState.APPLIED,
            RepairState.REJECTED,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
            RepairState.FAILED,
        }:
            return snapshot
        if snapshot.state not in {RepairState.GENERATING, RepairState.VALIDATING}:
            _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, stage)
        occurred_at_us = _next_timestamp(snapshot)
        failed = replace(
            snapshot,
            state=RepairState.FAILED,
            updated_at_us=occurred_at_us,
            failure=_build_failure(code, stage, occurred_at_us),
            cleanup_pending=True,
        )
        lease = loaded.validation_run
        if lease is None:
            return _persist_terminal(storage, "failed", failed)
        result = storage.append("failed", failed).snapshot
    return _cleanup_terminal_validation_run(session, result, lease)


def _cleanup_terminal_validation_run(
    session: RepairSession,
    terminal: RepairSnapshot,
    lease: _ValidationRunLease,
) -> RepairSnapshot:
    if not _remove_validation_container(session._manager, lease):
        return terminal
    with _locked_session(
        session._manager._config,
        session._session_id,
        runtime_root_identity=session._manager._runtime_root_identity,
    ) as storage:
        loaded = storage.load()
        if loaded.snapshot != terminal or loaded.validation_run != lease:
            return loaded.snapshot
        cleanup_succeeded = storage.cleanup_private()
        cleaned = replace(
            terminal,
            updated_at_us=_next_timestamp(terminal),
            cleanup_pending=not cleanup_succeeded,
        )
        kind = "cleanup_complete" if cleanup_succeeded else "cleanup_pending"
        return storage.append(
            kind,
            cleaned,
            clear_validation_run=True,
        ).snapshot


def _prepare_request_private_plan(
    request: _FrozenRepairRequest,
    source: _RepositoryIdentity,
    config: RepairManagerConfig,
    *,
    state: RepairState | None,
    session_id: str | None,
) -> _PrivateKeyPlan:
    files = tuple(
        _RepairFileContent(
            path,
            _read_head_file(
                source,
                config.git_executable,
                path,
                maximum_bytes=request.generation.max_file_bytes,
            ),
        )
        for path in request.allowed_paths
    )
    selected: list[_SelectedPrivateKeyRange] = []
    for target in request.targets:
        finding = request.review.findings[target.finding_index]
        if finding.rule_id is not RuleId.PRIVATE_KEY_MATERIAL:
            continue
        reference = finding.references[target.reference_index]
        if reference.start_line is None or reference.end_line is None:
            _raise_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                state,
                session_id,
            )
        selected.append(
            _SelectedPrivateKeyRange(
                reference.path,
                reference.start_line,
                reference.end_line,
            )
        )
    return _prepare_private_key_plan(
        files,
        tuple(selected),
        policy=request.generation,
        state=state,
        session_id=session_id,
    )


def _read_candidate_diff(storage: _SessionStore, snapshot: RepairSnapshot) -> str:
    invalid = False
    diff_bytes = b""
    try:
        diff_bytes = storage.read_private_bytes("candidate.diff")
        canonical_diff = diff_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        invalid = True
        canonical_diff = ""
    candidate = snapshot.candidate
    if (
        invalid
        or not canonical_diff
        or candidate is None
        or hashlib.sha256(diff_bytes).hexdigest() != candidate.diff_sha256
    ):
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            snapshot.session_id,
        )
    return canonical_diff


def _build_application(
    snapshot: RepairSnapshot,
    *,
    ref: str,
    commit_oid: str,
    applied_at_us: int,
) -> RepairApplication:
    approval = snapshot.approval
    if approval is None:
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            snapshot.session_id,
        )
    payload: dict[str, object] = {
        "schema_version": 1,
        "approval_sha256": approval.approval_sha256,
        "ref": ref,
        "commit_oid": commit_oid,
        "applied_at_us": applied_at_us,
    }
    application: RepairApplication | None = None
    try:
        application = RepairApplication(
            1,
            _domain_digest("application", payload),
            approval.approval_sha256,
            ref,
            commit_oid,
            applied_at_us,
        )
    except (TypeError, ValueError, UnicodeError):
        application = None
    if application is None:
        _raise_error(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.APPLICATION,
            snapshot.state,
            snapshot.session_id,
        )
    return application


def _build_approval(
    snapshot: RepairSnapshot,
    *,
    subject: str,
    confirmation: str,
    approved_at_us: int,
) -> RepairApproval:
    candidate = snapshot.candidate
    validation = snapshot.validation
    if candidate is None or validation is None:
        _raise_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            snapshot.state,
            snapshot.session_id,
        )
    approval: RepairApproval | None = None
    try:
        payload: dict[str, object] = {
            "schema_version": 1,
            "candidate_id": candidate.candidate_id,
            "validation_sha256": validation.validation_sha256,
            "subject": subject,
            "confirmation": confirmation,
            "approved_at_us": approved_at_us,
        }
        approval = RepairApproval(
            1,
            _domain_digest("approval", payload),
            candidate.candidate_id,
            validation.validation_sha256,
            subject,
            confirmation,
            approved_at_us,
        )
    except (TypeError, ValueError, UnicodeError):
        approval = None
    if approval is None:
        _raise_for_state(
            snapshot,
            RepairErrorCode.INVALID_DECISION,
            RepairStage.APPROVAL,
        )
    return approval


def _build_decision(
    snapshot: RepairSnapshot,
    *,
    state: RepairState,
    subject: str,
    reason: str,
    decided_at_us: int,
) -> RepairDecision:
    candidate_id = None if snapshot.candidate is None else snapshot.candidate.candidate_id
    decision: RepairDecision | None = None
    try:
        payload: dict[str, object] = {
            "schema_version": 1,
            "state": state.value,
            "subject": subject,
            "reason": reason,
            "candidate_id": candidate_id,
            "decided_at_us": decided_at_us,
        }
        decision = RepairDecision(
            1,
            _domain_digest("decision", payload),
            state,
            subject,
            reason,
            candidate_id,
            decided_at_us,
        )
    except (TypeError, ValueError, UnicodeError):
        decision = None
    if decision is None:
        _raise_for_state(
            snapshot,
            RepairErrorCode.INVALID_DECISION,
            RepairStage.APPROVAL,
        )
    return decision


def _persist_terminal(
    storage: _SessionStore,
    kind: str,
    snapshot: RepairSnapshot,
    *,
    clear_validation_run: bool = False,
) -> RepairSnapshot:
    stored = storage.append(
        kind,
        snapshot,
        clear_validation_run=clear_validation_run,
    ).snapshot
    cleanup_succeeded = storage.cleanup_private()
    cleaned = replace(
        stored,
        updated_at_us=_next_timestamp(stored),
        cleanup_pending=not cleanup_succeeded,
    )
    cleanup_kind = "cleanup_complete" if cleanup_succeeded else "cleanup_pending"
    return storage.append(cleanup_kind, cleaned).snapshot


def _next_timestamp(snapshot: RepairSnapshot) -> int:
    return max(snapshot.updated_at_us, _utc_now_us())


def _require_nonterminal(snapshot: RepairSnapshot, stage: RepairStage) -> None:
    if snapshot.state in {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }:
        _raise_for_state(snapshot, RepairErrorCode.INVALID_STATE, stage)


def _raise_for_state(
    snapshot: RepairSnapshot,
    code: RepairErrorCode,
    stage: RepairStage,
) -> NoReturn:
    if snapshot.state is RepairState.CANCELLED:
        code = RepairErrorCode.CANCELLED
    elif snapshot.state is RepairState.EXPIRED:
        code = RepairErrorCode.EXPIRED
    _raise_error(code, stage, snapshot.state, snapshot.session_id)


def _raise_error(
    code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    error = RepairError(code, stage, state, session_id)
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    raise error from None
