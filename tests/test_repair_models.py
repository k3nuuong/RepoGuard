"""Focused tests for public safe-repair contracts and deterministic primitives."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from repoguard._repair_models import (
    _can_transition,
    _canonical_bytes,
    _domain_digest,
    _is_terminal,
    _repair_generation_policy_from_dict,
    _repair_manager_config_from_dict,
    _repair_preview_from_dict,
    _repair_snapshot_from_dict,
    _require_transition,
    _validation_policy_from_dict,
)
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApplication,
    RepairApproval,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairDecision,
    RepairError,
    RepairErrorCode,
    RepairFailure,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairMaintenanceReport,
    RepairManagerConfig,
    RepairPreview,
    RepairPromptIdentity,
    RepairProviderKind,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairTarget,
    RepairValidation,
    ValidationCommand,
    ValidationCommandResult,
    ValidationFailureKind,
    ValidationPolicy,
    repair_application_to_json,
    repair_approval_to_json,
    repair_candidate_to_json,
    repair_context_summary_to_json,
    repair_decision_to_json,
    repair_failure_to_json,
    repair_generation_policy_to_json,
    repair_maintenance_report_to_json,
    repair_manager_config_to_json,
    repair_preview_to_json,
    repair_prompt_identity_to_json,
    repair_snapshot_to_json,
    repair_target_to_json,
    repair_validation_to_json,
    validation_command_result_to_json,
    validation_command_to_json,
    validation_policy_to_json,
)

_SHA = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64
_OID = "1" * 40
_IMAGE = f"sha256:{'2' * 64}"


class _StringSubclass(str):
    pass


def _prompt() -> RepairPromptIdentity:
    return RepairPromptIdentity("agent_repair", 1, _SHA, _SHA_B, _SHA_C)


def _no_context() -> RepairContextSummary:
    return RepairContextSummary(
        RepairContextOutcome.NOT_REQUESTED,
        None,
        None,
        0,
        0,
        0,
        None,
        None,
    )


def _candidate() -> RepairCandidate:
    return RepairCandidate(
        1,
        _SHA,
        _SHA_B,
        _prompt(),
        _no_context(),
        _SHA_C,
        _OID,
        _OID,
        ("src/app.py",),
        2,
        0,
        0,
        0,
    )


def _command_result() -> ValidationCommandResult:
    return ValidationCommandResult(0, 0, None, False, 10, _SHA, 0, False, _SHA_B, 0, False)


def _validation(*, success: bool = True) -> RepairValidation:
    return RepairValidation(
        1,
        _SHA,
        _SHA,
        _SHA_B,
        _SHA_C,
        _IMAGE,
        1,
        2,
        success,
        None if success else ValidationFailureKind.COMMAND_EXIT_NONZERO,
        (_command_result(),),
        1,
        False,
        0,
        2,
        2,
        True,
    )


def _approval() -> RepairApproval:
    return RepairApproval(1, _SHA, _SHA, _SHA, "local reviewer", REPAIR_APPROVAL_CONFIRMATION, 3)


def _application() -> RepairApplication:
    return RepairApplication(
        1,
        _SHA,
        _SHA,
        f"refs/repoguard/repairs/{_SHA}",
        _OID,
        4,
    )


def _snapshot(state: RepairState = RepairState.CREATED) -> RepairSnapshot:
    candidate = _candidate() if state is not RepairState.CREATED else None
    validation = (
        _validation()
        if state
        in {
            RepairState.VALIDATED,
            RepairState.APPROVED,
            RepairState.APPLYING,
            RepairState.APPLIED,
        }
        else None
    )
    approval = (
        _approval()
        if state in {RepairState.APPROVED, RepairState.APPLYING, RepairState.APPLIED}
        else None
    )
    application = _application() if state is RepairState.APPLIED else None
    return RepairSnapshot(
        1,
        _SHA,
        state,
        _SHA_B,
        1,
        4,
        1,
        ("src/app.py",),
        candidate,
        validation,
        approval,
        application,
        None,
        None,
        False,
    )


def test_public_enum_values_are_closed_and_exact() -> None:
    assert tuple(item.value for item in RepairState) == (
        "created",
        "generating",
        "validating",
        "validated",
        "approved",
        "applying",
        "applied",
        "rejected",
        "cancelled",
        "expired",
        "failed",
    )
    assert tuple(item.value for item in RepairStage) == (
        "input",
        "session",
        "materialization",
        "retrieval",
        "prompt",
        "provider",
        "patch",
        "sandbox",
        "validation",
        "approval",
        "application",
        "persistence",
        "recovery",
        "cleanup",
    )
    assert tuple(item.value for item in RepairProviderKind) == ("openai", "anthropic")
    assert tuple(item.value for item in RepairGenerationMode) == (
        "deterministic",
        "provider",
        "mixed",
    )
    assert tuple(item.value for item in RepairContextOutcome) == (
        "not_requested",
        "used",
        "degraded",
    )
    assert tuple(item.value for item in ValidationFailureKind) == (
        "command_exit_nonzero",
        "command_timeout",
        "command_signal",
        "output_limit",
        "resource_limit",
        "residual_process",
        "tracked_tree_changed",
        "sandbox_report_invalid",
        "sandbox_runtime_failed",
    )
    assert tuple(item.value for item in RepairErrorCode) == (
        "unsupported_evidence_schema",
        "invalid_evidence",
        "unsupported_review_schema",
        "invalid_review",
        "identity_mismatch",
        "invalid_targets",
        "invalid_config",
        "invalid_path",
        "session_not_found",
        "session_locked",
        "invalid_state",
        "session_expired",
        "session_corrupt",
        "persistence_failed",
        "git_unavailable",
        "git_failed",
        "missing_object",
        "materialization_failed",
        "resource_limit",
        "provider_required",
        "provider_mismatch",
        "provider_rate_limited",
        "provider_timeout",
        "provider_unavailable",
        "provider_authentication",
        "provider_permission",
        "provider_bad_request",
        "provider_invalid_response",
        "provider_failed",
        "model_response_invalid",
        "patch_invalid",
        "patch_limit",
        "unsupported_platform",
        "sandbox_unavailable",
        "image_unavailable",
        "image_mismatch",
        "validation_failed",
        "approval_required",
        "approval_mismatch",
        "invalid_decision",
        "ref_conflict",
        "publication_failed",
        "recovery_failed",
        "cleanup_failed",
        "cancelled",
        "expired",
        "invalid_workflow",
    )


@pytest.mark.parametrize(
    "record",
    [
        RepairTarget(0, 0),
        _prompt(),
        _no_context(),
        _candidate(),
        _command_result(),
        _validation(),
        _approval(),
        _application(),
        RepairDecision(1, _SHA, RepairState.CANCELLED, "subject", "", None, 1),
        RepairFailure(1, RepairErrorCode.GIT_FAILED, RepairStage.MATERIALIZATION, False, 1),
        _snapshot(),
        RepairPreview(
            1,
            _SHA,
            RepairState.GENERATING,
            _SHA,
            None,
            ("src/app.py",),
            "diff --git a/src/app.py b/src/app.py\n",
            REPAIR_APPROVAL_CONFIRMATION,
        ),
        RepairMaintenanceReport(1, 1, 2, (), (), (), (), ()),
    ],
)
def test_public_records_are_frozen_slotted_dataclasses(record: object) -> None:
    assert is_dataclass(record)
    assert not hasattr(record, "__dict__")
    assert fields(record)
    with pytest.raises((AttributeError, TypeError)):
        setattr(record, fields(record)[0].name, None)


def test_generation_policy_requires_consistent_provider_identity() -> None:
    deterministic = RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)
    provider = RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "gpt-fixed",
    )
    assert json.loads(repair_generation_policy_to_json(deterministic))["model"] is None
    assert json.loads(repair_generation_policy_to_json(provider))["provider_kind"] == "openai"

    with pytest.raises(ValueError, match="cannot name"):
        RepairGenerationPolicy(
            RepairGenerationMode.DETERMINISTIC,
            RepairProviderKind.OPENAI,
            "model",
        )
    with pytest.raises(ValueError, match="require provider"):
        RepairGenerationPolicy(RepairGenerationMode.MIXED, None, None)
    with pytest.raises(ValueError, match="max_queries"):
        RepairGenerationPolicy(
            RepairGenerationMode.PROVIDER,
            RepairProviderKind.ANTHROPIC,
            "model",
            max_queries=17,
        )


@pytest.mark.parametrize("field", ["attempt_timeout_seconds", "total_timeout_seconds"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_generation_policy_rejects_non_finite_timeouts(field: str, value: float) -> None:
    with pytest.raises(ValueError, match=field):
        if field == "attempt_timeout_seconds":
            RepairGenerationPolicy(
                RepairGenerationMode.PROVIDER,
                RepairProviderKind.OPENAI,
                "gpt-fixed",
                attempt_timeout_seconds=value,
            )
        else:
            RepairGenerationPolicy(
                RepairGenerationMode.PROVIDER,
                RepairProviderKind.OPENAI,
                "gpt-fixed",
                total_timeout_seconds=value,
            )


def test_generation_policy_serializer_rejects_tampered_non_finite_value() -> None:
    policy = RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "gpt-fixed",
    )
    object.__setattr__(policy, "attempt_timeout_seconds", float("nan"))

    with pytest.raises(ValueError):
        repair_generation_policy_to_json(policy)


def test_manager_and_validation_policy_are_canonical_and_bounded(tmp_path: Path) -> None:
    config = RepairManagerConfig(
        tmp_path.resolve(),
        Path("/usr/bin/git"),
        Path("/usr/bin/docker"),
        Path("/run/user/1000/docker.sock"),
    )
    command = ValidationCommand(("/usr/local/bin/python3.12", "-V"))
    policy = ValidationPolicy(_IMAGE, (command,))

    assert json.loads(repair_manager_config_to_json(config))["lock_timeout_seconds"] == 5.0
    assert json.loads(validation_command_to_json(command))["cwd"] == "/workspace/repository"
    assert json.loads(validation_policy_to_json(policy))["pids_limit"] == 128

    with pytest.raises(ValueError, match=r"5\.0"):
        RepairManagerConfig(
            tmp_path.resolve(),
            Path("/usr/bin/git"),
            Path("/usr/bin/docker"),
            Path("/run/user/1000/docker.sock"),
            lock_timeout_seconds=4.0,
        )
    with pytest.raises(ValueError, match="absolute"):
        ValidationCommand(("python3.12", "-V"))
    with pytest.raises(ValueError, match="pids_limit"):
        ValidationPolicy(_IMAGE, (command,), pids_limit=129)


def test_repository_paths_preserve_unicode_and_require_utf8_order() -> None:
    paths = ("a file.py", "z.py", "源/代码.py")
    candidate = RepairCandidate(
        1,
        _SHA,
        _SHA_B,
        _prompt(),
        _no_context(),
        _SHA_C,
        _OID,
        _OID,
        paths,
        1,
        0,
        0,
        0,
    )
    assert json.loads(repair_candidate_to_json(candidate))["changed_paths"] == list(paths)

    for invalid in ("../x", ".git/config", "a\\b", "/absolute", " trailing", "a//b"):
        with pytest.raises(ValueError):
            RepairCandidate(
                1,
                _SHA,
                _SHA_B,
                _prompt(),
                _no_context(),
                _SHA_C,
                _OID,
                _OID,
                (invalid,),
                1,
                0,
                0,
                0,
            )


def test_context_outcomes_have_unambiguous_shapes() -> None:
    used = RepairContextSummary(
        RepairContextOutcome.USED,
        _SHA,
        _SHA_B,
        1,
        2,
        0,
        _SHA_C,
        None,
    )
    degraded = RepairContextSummary(
        RepairContextOutcome.DEGRADED,
        _SHA,
        _SHA_B,
        1,
        0,
        0,
        None,
        "backend_failure",
    )
    assert json.loads(repair_context_summary_to_json(used))["outcome"] == "used"
    assert json.loads(repair_context_summary_to_json(degraded))["degradation_code"] == (
        "backend_failure"
    )
    with pytest.raises(ValueError, match="not-requested"):
        RepairContextSummary(
            RepairContextOutcome.NOT_REQUESTED,
            _SHA,
            None,
            0,
            0,
            0,
            None,
            None,
        )


def test_validation_result_enforces_success_and_failure_invariants() -> None:
    assert json.loads(repair_validation_to_json(_validation()))["success"] is True
    assert json.loads(repair_validation_to_json(_validation(success=False)))["failure_kind"] == (
        "command_exit_nonzero"
    )

    with pytest.raises(ValueError, match="requires failure_kind"):
        RepairValidation(
            1,
            _SHA,
            _SHA,
            _SHA_B,
            _SHA_C,
            _IMAGE,
            1,
            2,
            False,
            None,
            (),
            0,
            False,
            0,
            0,
            0,
            True,
        )


@pytest.mark.parametrize(
    "command_result",
    (
        replace(_command_result(), exit_code=1),
        replace(_command_result(), exit_code=None),
        replace(_command_result(), exit_code=None, signal=9),
        replace(_command_result(), exit_code=None, timed_out=True),
        replace(_command_result(), stdout_truncated=True),
        replace(_command_result(), stderr_truncated=True),
    ),
)
def test_successful_validation_rejects_failed_command_state(
    command_result: ValidationCommandResult,
) -> None:
    with pytest.raises(ValueError, match="successful validation"):
        replace(_validation(), command_results=(command_result,))


def test_successful_validation_requires_a_command_result() -> None:
    with pytest.raises(ValueError, match="successful validation"):
        replace(_validation(), command_results=())


def test_snapshot_shape_rejects_impossible_record_combinations() -> None:
    assert json.loads(repair_snapshot_to_json(_snapshot(RepairState.APPLIED)))["state"] == "applied"
    for state in (RepairState.APPROVED, RepairState.APPLYING):
        with pytest.raises(ValueError, match="application requires applied state"):
            replace(_snapshot(state), application=_application())
    for cleanup_pending in (False, True):
        assert (
            replace(
                _snapshot(RepairState.APPLIED),
                cleanup_pending=cleanup_pending,
            ).application
            is not None
        )

    invalid_mapping = json.loads(repair_snapshot_to_json(_snapshot(RepairState.APPLIED)))
    invalid_mapping["state"] = "approved"
    with pytest.raises(ValueError, match="application requires applied state"):
        _repair_snapshot_from_dict(invalid_mapping)

    forged = _snapshot(RepairState.APPROVED)
    object.__setattr__(forged, "application", _application())
    with pytest.raises(ValueError, match="application requires applied state"):
        repair_snapshot_to_json(forged)
    with pytest.raises(ValueError, match="validation requires"):
        RepairSnapshot(
            1,
            _SHA,
            RepairState.VALIDATED,
            _SHA_B,
            1,
            2,
            1,
            ("src/app.py",),
            None,
            _validation(),
            None,
            None,
            None,
            None,
            False,
        )
    with pytest.raises(ValueError, match="application does not match"):
        replace(
            _snapshot(RepairState.APPLIED),
            application=replace(
                _application(),
                ref=f"refs/repoguard/repairs/{_SHA_B}",
            ),
        )
    with pytest.raises(ValueError, match="cleanup_pending"):
        RepairSnapshot(
            1,
            _SHA,
            RepairState.CREATED,
            _SHA_B,
            1,
            2,
            1,
            ("src/app.py",),
            None,
            None,
            None,
            None,
            None,
            None,
            True,
        )


def test_every_top_level_serializer_is_canonical_and_independent(tmp_path: Path) -> None:
    _assert_canonical_serializer(
        RepairManagerConfig(
            tmp_path.resolve(),
            Path("/usr/bin/git"),
            Path("/usr/bin/docker"),
            Path("/run/user/1000/docker.sock"),
        ),
        repair_manager_config_to_json,
    )
    _assert_canonical_serializer(
        RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None),
        repair_generation_policy_to_json,
    )
    _assert_canonical_serializer(ValidationCommand(("/bin/true",)), validation_command_to_json)
    _assert_canonical_serializer(
        ValidationPolicy(_IMAGE, (ValidationCommand(("/bin/true",)),)),
        validation_policy_to_json,
    )
    _assert_canonical_serializer(RepairTarget(0, 0), repair_target_to_json)
    _assert_canonical_serializer(_prompt(), repair_prompt_identity_to_json)
    _assert_canonical_serializer(_no_context(), repair_context_summary_to_json)
    _assert_canonical_serializer(_candidate(), repair_candidate_to_json)
    _assert_canonical_serializer(_command_result(), validation_command_result_to_json)
    _assert_canonical_serializer(_validation(), repair_validation_to_json)
    _assert_canonical_serializer(_approval(), repair_approval_to_json)
    _assert_canonical_serializer(_application(), repair_application_to_json)
    _assert_canonical_serializer(
        RepairDecision(1, _SHA, RepairState.CANCELLED, "subject", "", None, 1),
        repair_decision_to_json,
    )
    _assert_canonical_serializer(
        RepairFailure(1, RepairErrorCode.GIT_FAILED, RepairStage.MATERIALIZATION, False, 1),
        repair_failure_to_json,
    )
    _assert_canonical_serializer(_snapshot(), repair_snapshot_to_json)
    _assert_canonical_serializer(
        RepairPreview(
            1,
            _SHA,
            RepairState.GENERATING,
            _SHA,
            None,
            ("src/app.py",),
            "diff\n",
            REPAIR_APPROVAL_CONFIRMATION,
        ),
        repair_preview_to_json,
    )
    _assert_canonical_serializer(
        RepairMaintenanceReport(1, 1, 2, (), (), (), (), ()),
        repair_maintenance_report_to_json,
    )


def _assert_canonical_serializer[T](value: T, serializer: Callable[[T], str]) -> None:
    encoded = serializer(value)
    assert encoded == serializer(value)
    assert not encoded.endswith("\n")
    assert (
        json.dumps(
            json.loads(encoded),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        == encoded
    )
    with pytest.raises(TypeError):
        serializer(cast(T, object()))


def test_error_taxonomy_has_fixed_messages_and_retryability() -> None:
    timeout = RepairError(
        RepairErrorCode.PROVIDER_TIMEOUT,
        RepairStage.PROVIDER,
        RepairState.GENERATING,
        _SHA,
    )
    failed = RepairError(RepairErrorCode.GIT_FAILED, RepairStage.MATERIALIZATION)
    assert str(timeout) == "repair provider timed out"
    assert timeout.retryable is True
    assert timeout.session_id == _SHA
    assert failed.retryable is False
    assert failed.__cause__ is None
    assert failed.__context__ is None


def test_digest_domains_are_deterministic_and_separate() -> None:
    value = {"schema_version": 1, "value": "修复"}
    request = _domain_digest("request", value)
    assert request == _domain_digest("request", value)
    assert request != _domain_digest("candidate", value)
    assert _canonical_bytes(value).decode() == '{"schema_version":1,"value":"修复"}'
    with pytest.raises(ValueError, match="kind"):
        _domain_digest("unknown", value)
    with pytest.raises(ValueError, match="valid JSON"):
        _canonical_bytes({"bad": float("nan")})


def test_state_transition_table_and_terminal_absorption() -> None:
    assert _can_transition(RepairState.CREATED, RepairState.GENERATING)
    assert _can_transition(RepairState.APPLYING, RepairState.APPROVED)
    assert not _can_transition(RepairState.CREATED, RepairState.APPROVED)
    terminal = {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }
    assert {state for state in RepairState if _is_terminal(state)} == terminal
    assert all(not _can_transition(state, target) for state in terminal for target in RepairState)
    with pytest.raises(RepairError) as captured:
        _require_transition(RepairState.VALIDATED, RepairState.APPLIED, session_id=_SHA)
    assert captured.value.code is RepairErrorCode.INVALID_STATE


def test_decision_subject_reason_and_confirmation_byte_limits() -> None:
    assert RepairDecision(1, _SHA, RepairState.CANCELLED, "s", "", None, 1).reason == ""
    with pytest.raises(ValueError, match="byte size"):
        RepairDecision(1, _SHA, RepairState.REJECTED, "s", "", _SHA, 1)
    with pytest.raises(ValueError, match="control"):
        RepairDecision(1, _SHA, RepairState.CANCELLED, "bad\nsubject", "", None, 1)
    with pytest.raises(ValueError, match="confirmation"):
        RepairApproval(1, _SHA, _SHA, _SHA, "s", "approve", 1)


def test_public_records_reject_non_exact_state_and_string_fields() -> None:
    with pytest.raises(TypeError, match="degradation_code"):
        RepairContextSummary(
            RepairContextOutcome.DEGRADED,
            _SHA,
            _SHA_B,
            1,
            0,
            0,
            None,
            _StringSubclass("closed_index"),
        )
    with pytest.raises(TypeError, match="confirmation"):
        RepairApproval(
            1,
            _SHA,
            _SHA,
            _SHA,
            "s",
            _StringSubclass(REPAIR_APPROVAL_CONFIRMATION),
            1,
        )
    with pytest.raises(TypeError, match="ref"):
        RepairApplication(
            1,
            _SHA,
            _SHA,
            _StringSubclass(f"refs/repoguard/repairs/{_SHA}"),
            _OID,
            1,
        )
    with pytest.raises(TypeError, match="state"):
        RepairDecision(1, _SHA, cast(RepairState, "cancelled"), "s", "", None, 1)
    with pytest.raises(TypeError, match="reason"):
        RepairDecision(
            1,
            _SHA,
            RepairState.CANCELLED,
            "s",
            _StringSubclass(""),
            None,
            1,
        )
    with pytest.raises(TypeError, match="confirmation"):
        RepairPreview(
            1,
            _SHA,
            RepairState.VALIDATED,
            _SHA,
            _SHA_B,
            ("src/app.py",),
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
            _StringSubclass(REPAIR_APPROVAL_CONFIRMATION),
        )


def test_exact_decoders_roundtrip_nested_snapshot_and_policies(tmp_path: Path) -> None:
    manager = RepairManagerConfig(
        tmp_path.resolve(),
        Path("/usr/bin/git"),
        Path("/usr/bin/docker"),
        Path("/run/user/1000/docker.sock"),
    )
    generation = RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "gpt-fixed",
    )
    validation = ValidationPolicy(_IMAGE, (ValidationCommand(("/bin/true",)),))
    snapshot = _snapshot(RepairState.APPLIED)
    preview = RepairPreview(
        1,
        _SHA,
        RepairState.VALIDATED,
        _SHA,
        _SHA_B,
        ("src/app.py",),
        "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
        REPAIR_APPROVAL_CONFIRMATION,
    )

    assert (
        _repair_manager_config_from_dict(json.loads(repair_manager_config_to_json(manager)))
        == manager
    )
    assert (
        _repair_generation_policy_from_dict(
            json.loads(repair_generation_policy_to_json(generation))
        )
        == generation
    )
    assert _validation_policy_from_dict(json.loads(validation_policy_to_json(validation))) == (
        validation
    )
    assert _repair_snapshot_from_dict(json.loads(repair_snapshot_to_json(snapshot))) == snapshot
    assert _repair_preview_from_dict(json.loads(repair_preview_to_json(preview))) == preview


def test_exact_decoders_reject_extra_missing_and_bool_as_int() -> None:
    mapping = json.loads(repair_snapshot_to_json(_snapshot()))
    mapping["extra"] = "unsafe"
    with pytest.raises(ValueError, match="fields"):
        _repair_snapshot_from_dict(mapping)

    mapping = json.loads(repair_snapshot_to_json(_snapshot()))
    del mapping["request_sha256"]
    with pytest.raises(ValueError, match="fields"):
        _repair_snapshot_from_dict(mapping)

    mapping = json.loads(repair_snapshot_to_json(_snapshot()))
    mapping["target_count"] = True
    with pytest.raises(TypeError, match="integer"):
        _repair_snapshot_from_dict(mapping)
