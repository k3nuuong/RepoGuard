"""Deterministic primitives shared by repair persistence and workflow."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from enum import StrEnum
from pathlib import Path

from repoguard.repair import (
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
)

_DOMAIN_KINDS = frozenset(
    {
        "request",
        "prompt",
        "context",
        "candidate",
        "validation",
        "approval",
        "application",
        "decision",
        "event",
        "preview",
        "policy",
        "sandbox-manifest",
        "run-token",
    }
)

_TERMINAL_STATES = frozenset(
    {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }
)

_TRANSITIONS: dict[RepairState, frozenset[RepairState]] = {
    RepairState.CREATED: frozenset(
        {RepairState.GENERATING, RepairState.CANCELLED, RepairState.EXPIRED}
    ),
    RepairState.GENERATING: frozenset(
        {
            RepairState.VALIDATING,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
            RepairState.FAILED,
        }
    ),
    RepairState.VALIDATING: frozenset(
        {
            RepairState.VALIDATED,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
            RepairState.FAILED,
        }
    ),
    RepairState.VALIDATED: frozenset(
        {
            RepairState.APPROVED,
            RepairState.REJECTED,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
        }
    ),
    RepairState.APPROVED: frozenset(
        {
            RepairState.APPLYING,
            RepairState.REJECTED,
            RepairState.CANCELLED,
            RepairState.EXPIRED,
        }
    ),
    RepairState.APPLYING: frozenset(
        {
            RepairState.APPLIED,
            RepairState.APPROVED,
            RepairState.CANCELLED,
            RepairState.FAILED,
        }
    ),
    RepairState.APPLIED: frozenset(),
    RepairState.REJECTED: frozenset(),
    RepairState.CANCELLED: frozenset(),
    RepairState.EXPIRED: frozenset(),
    RepairState.FAILED: frozenset(),
}


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    if type(value) is not dict:
        raise TypeError("canonical value must be an exact dict")
    try:
        text = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("canonical value is not valid JSON") from error


def _domain_digest(kind: str, value: Mapping[str, object]) -> str:
    if type(kind) is not str or kind not in _DOMAIN_KINDS:
        raise ValueError("repair digest kind is invalid")
    domain = f"repoguard.m5.{kind}.v1".encode()
    return hashlib.sha256(domain + b"\x00" + _canonical_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    if type(value) is not bytes:
        raise TypeError("value must be exact bytes")
    return hashlib.sha256(value).hexdigest()


def _utc_now_us() -> int:
    return time.time_ns() // 1_000


def _is_terminal(state: RepairState) -> bool:
    if type(state) is not RepairState:
        raise TypeError("state must be a RepairState")
    return state in _TERMINAL_STATES


def _can_transition(current: RepairState, target: RepairState) -> bool:
    if type(current) is not RepairState or type(target) is not RepairState:
        raise TypeError("transition states must be RepairState values")
    return target in _TRANSITIONS[current]


def _require_transition(
    current: RepairState,
    target: RepairState,
    *,
    session_id: str | None,
) -> None:
    if not _can_transition(current, target):
        raise RepairError(
            RepairErrorCode.INVALID_STATE,
            RepairStage.SESSION,
            current,
            session_id,
        ) from None


def _repair_manager_config_from_dict(value: object) -> RepairManagerConfig:
    mapping = _exact_mapping(
        value,
        {
            "runtime_root",
            "git_executable",
            "docker_executable",
            "rootless_socket",
            "lock_timeout_seconds",
            "audit_retention_days",
        },
    )
    return RepairManagerConfig(
        Path(_exact_str(mapping["runtime_root"])),
        Path(_exact_str(mapping["git_executable"])),
        Path(_exact_str(mapping["docker_executable"])),
        Path(_exact_str(mapping["rootless_socket"])),
        _exact_float(mapping["lock_timeout_seconds"]),
        _exact_int(mapping["audit_retention_days"]),
    )


def _repair_generation_policy_from_dict(value: object) -> RepairGenerationPolicy:
    mapping = _exact_mapping(
        value,
        {
            "mode",
            "provider_kind",
            "model",
            "max_file_bytes",
            "max_prompt_bytes",
            "max_response_bytes",
            "max_output_tokens",
            "max_queries",
            "max_query_bytes",
            "max_context_hits",
            "max_patch_bytes",
            "max_patch_paths",
            "max_changed_lines",
            "attempt_timeout_seconds",
            "total_timeout_seconds",
        },
    )
    provider_value = _optional_str(mapping["provider_kind"])
    return RepairGenerationPolicy(
        _enum_value(RepairGenerationMode, mapping["mode"]),
        None if provider_value is None else _enum_value(RepairProviderKind, provider_value),
        _optional_str(mapping["model"]),
        _exact_int(mapping["max_file_bytes"]),
        _exact_int(mapping["max_prompt_bytes"]),
        _exact_int(mapping["max_response_bytes"]),
        _exact_int(mapping["max_output_tokens"]),
        _exact_int(mapping["max_queries"]),
        _exact_int(mapping["max_query_bytes"]),
        _exact_int(mapping["max_context_hits"]),
        _exact_int(mapping["max_patch_bytes"]),
        _exact_int(mapping["max_patch_paths"]),
        _exact_int(mapping["max_changed_lines"]),
        _exact_float(mapping["attempt_timeout_seconds"]),
        _exact_float(mapping["total_timeout_seconds"]),
    )


def _validation_command_from_dict(value: object) -> ValidationCommand:
    mapping = _exact_mapping(value, {"argv", "cwd"})
    return ValidationCommand(
        tuple(_exact_str(item) for item in _exact_list(mapping["argv"])),
        _exact_str(mapping["cwd"]),
    )


def _validation_policy_from_dict(value: object) -> ValidationPolicy:
    mapping = _exact_mapping(
        value,
        {
            "image_id",
            "commands",
            "command_timeout_seconds",
            "total_timeout_seconds",
            "memory_bytes",
            "nano_cpus",
            "pids_limit",
            "stream_output_bytes",
            "workspace_bytes",
            "workspace_inodes",
            "workspace_entries",
            "tmp_bytes",
            "tmp_inodes",
            "home_bytes",
            "home_inodes",
            "run_bytes",
            "run_inodes",
        },
    )
    return ValidationPolicy(
        _exact_str(mapping["image_id"]),
        tuple(_validation_command_from_dict(item) for item in _exact_list(mapping["commands"])),
        _exact_int(mapping["command_timeout_seconds"]),
        _exact_int(mapping["total_timeout_seconds"]),
        _exact_int(mapping["memory_bytes"]),
        _exact_int(mapping["nano_cpus"]),
        _exact_int(mapping["pids_limit"]),
        _exact_int(mapping["stream_output_bytes"]),
        _exact_int(mapping["workspace_bytes"]),
        _exact_int(mapping["workspace_inodes"]),
        _exact_int(mapping["workspace_entries"]),
        _exact_int(mapping["tmp_bytes"]),
        _exact_int(mapping["tmp_inodes"]),
        _exact_int(mapping["home_bytes"]),
        _exact_int(mapping["home_inodes"]),
        _exact_int(mapping["run_bytes"]),
        _exact_int(mapping["run_inodes"]),
    )


def _repair_target_from_dict(value: object) -> RepairTarget:
    mapping = _exact_mapping(value, {"finding_index", "reference_index"})
    return RepairTarget(
        _exact_int(mapping["finding_index"]),
        _exact_int(mapping["reference_index"]),
    )


def _repair_prompt_identity_from_dict(value: object) -> RepairPromptIdentity:
    mapping = _exact_mapping(
        value,
        {"name", "version", "system_sha256", "response_schema_sha256", "combined_sha256"},
    )
    return RepairPromptIdentity(
        _exact_str(mapping["name"]),
        _exact_int(mapping["version"]),
        _exact_str(mapping["system_sha256"]),
        _exact_str(mapping["response_schema_sha256"]),
        _exact_str(mapping["combined_sha256"]),
    )


def _repair_context_summary_from_dict(value: object) -> RepairContextSummary:
    mapping = _exact_mapping(
        value,
        {
            "outcome",
            "index_identity_sha256",
            "query_sha256",
            "query_count",
            "candidate_count",
            "selected_hit_count",
            "hit_identity_sha256",
            "degradation_code",
        },
    )
    return RepairContextSummary(
        _enum_value(RepairContextOutcome, mapping["outcome"]),
        _optional_str(mapping["index_identity_sha256"]),
        _optional_str(mapping["query_sha256"]),
        _exact_int(mapping["query_count"]),
        _exact_int(mapping["candidate_count"]),
        _exact_int(mapping["selected_hit_count"]),
        _optional_str(mapping["hit_identity_sha256"]),
        _optional_str(mapping["degradation_code"]),
    )


def _repair_candidate_from_dict(value: object) -> RepairCandidate:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "candidate_id",
            "request_sha256",
            "prompt",
            "context",
            "diff_sha256",
            "tree_oid",
            "commit_oid",
            "changed_paths",
            "changed_line_count",
            "provider_attempt_count",
            "input_tokens",
            "output_tokens",
        },
    )
    return RepairCandidate(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["candidate_id"]),
        _exact_str(mapping["request_sha256"]),
        _repair_prompt_identity_from_dict(mapping["prompt"]),
        _repair_context_summary_from_dict(mapping["context"]),
        _exact_str(mapping["diff_sha256"]),
        _exact_str(mapping["tree_oid"]),
        _exact_str(mapping["commit_oid"]),
        tuple(_exact_str(item) for item in _exact_list(mapping["changed_paths"])),
        _exact_int(mapping["changed_line_count"]),
        _exact_int(mapping["provider_attempt_count"]),
        _exact_int(mapping["input_tokens"]),
        _exact_int(mapping["output_tokens"]),
    )


def _validation_command_result_from_dict(value: object) -> ValidationCommandResult:
    mapping = _exact_mapping(
        value,
        {
            "command_index",
            "exit_code",
            "signal",
            "timed_out",
            "duration_us",
            "stdout_sha256",
            "stdout_bytes",
            "stdout_truncated",
            "stderr_sha256",
            "stderr_bytes",
            "stderr_truncated",
        },
    )
    return ValidationCommandResult(
        _exact_int(mapping["command_index"]),
        _optional_int(mapping["exit_code"]),
        _optional_int(mapping["signal"]),
        _exact_bool(mapping["timed_out"]),
        _exact_int(mapping["duration_us"]),
        _exact_str(mapping["stdout_sha256"]),
        _exact_int(mapping["stdout_bytes"]),
        _exact_bool(mapping["stdout_truncated"]),
        _exact_str(mapping["stderr_sha256"]),
        _exact_int(mapping["stderr_bytes"]),
        _exact_bool(mapping["stderr_truncated"]),
    )


def _repair_validation_from_dict(value: object) -> RepairValidation:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "validation_sha256",
            "candidate_id",
            "policy_sha256",
            "sandbox_manifest_sha256",
            "image_id",
            "started_at_us",
            "finished_at_us",
            "success",
            "failure_kind",
            "command_results",
            "peak_memory_bytes",
            "oom_killed",
            "residual_process_count",
            "workspace_entry_count",
            "workspace_inode_count",
            "tracked_tree_clean",
        },
    )
    failure_value = _optional_str(mapping["failure_kind"])
    return RepairValidation(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["validation_sha256"]),
        _exact_str(mapping["candidate_id"]),
        _exact_str(mapping["policy_sha256"]),
        _exact_str(mapping["sandbox_manifest_sha256"]),
        _exact_str(mapping["image_id"]),
        _exact_int(mapping["started_at_us"]),
        _exact_int(mapping["finished_at_us"]),
        _exact_bool(mapping["success"]),
        None if failure_value is None else _enum_value(ValidationFailureKind, failure_value),
        tuple(
            _validation_command_result_from_dict(item)
            for item in _exact_list(mapping["command_results"])
        ),
        _exact_int(mapping["peak_memory_bytes"]),
        _exact_bool(mapping["oom_killed"]),
        _exact_int(mapping["residual_process_count"]),
        _exact_int(mapping["workspace_entry_count"]),
        _exact_int(mapping["workspace_inode_count"]),
        _exact_bool(mapping["tracked_tree_clean"]),
    )


def _repair_approval_from_dict(value: object) -> RepairApproval:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "approval_sha256",
            "candidate_id",
            "validation_sha256",
            "subject",
            "confirmation",
            "approved_at_us",
        },
    )
    return RepairApproval(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["approval_sha256"]),
        _exact_str(mapping["candidate_id"]),
        _exact_str(mapping["validation_sha256"]),
        _exact_str(mapping["subject"]),
        _exact_str(mapping["confirmation"]),
        _exact_int(mapping["approved_at_us"]),
    )


def _repair_application_from_dict(value: object) -> RepairApplication:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "application_sha256",
            "approval_sha256",
            "ref",
            "commit_oid",
            "applied_at_us",
        },
    )
    return RepairApplication(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["application_sha256"]),
        _exact_str(mapping["approval_sha256"]),
        _exact_str(mapping["ref"]),
        _exact_str(mapping["commit_oid"]),
        _exact_int(mapping["applied_at_us"]),
    )


def _repair_decision_from_dict(value: object) -> RepairDecision:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "decision_sha256",
            "state",
            "subject",
            "reason",
            "candidate_id",
            "decided_at_us",
        },
    )
    return RepairDecision(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["decision_sha256"]),
        _enum_value(RepairState, mapping["state"]),
        _exact_str(mapping["subject"]),
        _exact_str(mapping["reason"]),
        _optional_str(mapping["candidate_id"]),
        _exact_int(mapping["decided_at_us"]),
    )


def _repair_failure_from_dict(value: object) -> RepairFailure:
    mapping = _exact_mapping(
        value,
        {"schema_version", "code", "stage", "retryable", "occurred_at_us"},
    )
    return RepairFailure(
        _exact_int(mapping["schema_version"]),
        _enum_value(RepairErrorCode, mapping["code"]),
        _enum_value(RepairStage, mapping["stage"]),
        _exact_bool(mapping["retryable"]),
        _exact_int(mapping["occurred_at_us"]),
    )


def _repair_snapshot_from_dict(value: object) -> RepairSnapshot:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "session_id",
            "state",
            "request_sha256",
            "created_at_us",
            "updated_at_us",
            "target_count",
            "allowed_paths",
            "candidate",
            "validation",
            "approval",
            "application",
            "decision",
            "failure",
            "cleanup_pending",
        },
    )
    return RepairSnapshot(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["session_id"]),
        _enum_value(RepairState, mapping["state"]),
        _exact_str(mapping["request_sha256"]),
        _exact_int(mapping["created_at_us"]),
        _exact_int(mapping["updated_at_us"]),
        _exact_int(mapping["target_count"]),
        tuple(_exact_str(item) for item in _exact_list(mapping["allowed_paths"])),
        _optional_record(mapping["candidate"], _repair_candidate_from_dict),
        _optional_record(mapping["validation"], _repair_validation_from_dict),
        _optional_record(mapping["approval"], _repair_approval_from_dict),
        _optional_record(mapping["application"], _repair_application_from_dict),
        _optional_record(mapping["decision"], _repair_decision_from_dict),
        _optional_record(mapping["failure"], _repair_failure_from_dict),
        _exact_bool(mapping["cleanup_pending"]),
    )


def _repair_preview_from_dict(value: object) -> RepairPreview:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "session_id",
            "state",
            "candidate_id",
            "validation_sha256",
            "changed_paths",
            "canonical_diff",
            "confirmation",
        },
    )
    return RepairPreview(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["session_id"]),
        _enum_value(RepairState, mapping["state"]),
        _exact_str(mapping["candidate_id"]),
        _optional_str(mapping["validation_sha256"]),
        tuple(_exact_str(item) for item in _exact_list(mapping["changed_paths"])),
        _exact_str(mapping["canonical_diff"]),
        _exact_str(mapping["confirmation"]),
    )


def _exact_mapping(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ValueError("record mapping has invalid fields")
    return value


def _exact_list(value: object) -> list[object]:
    if type(value) is not list:
        raise TypeError("record value must be an exact list")
    return value


def _exact_str(value: object) -> str:
    if type(value) is not str:
        raise TypeError("record value must be an exact string")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return _exact_str(value)


def _exact_int(value: object) -> int:
    if type(value) is not int:
        raise TypeError("record value must be an exact integer")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return _exact_int(value)


def _exact_float(value: object) -> float:
    if type(value) is not float:
        raise TypeError("record value must be an exact float")
    return value


def _exact_bool(value: object) -> bool:
    if type(value) is not bool:
        raise TypeError("record value must be an exact boolean")
    return value


def _enum_value[E: StrEnum](enum_type: type[E], value: object) -> E:
    text = _exact_str(value)
    try:
        return enum_type(text)
    except ValueError as error:
        raise ValueError("record enum value is invalid") from error


def _optional_record[T](value: object, decoder: Callable[[object], T]) -> T | None:
    if value is None:
        return None
    return decoder(value)
