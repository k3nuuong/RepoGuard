"""Public contracts for the durable, ref-only safe repair workflow."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from repoguard._repair_paths import (
    _canonical_repository_paths,
    _validate_container_path,
)
from repoguard.evidence import EvidenceBundle, RepositoryInput
from repoguard.providers import AnthropicProvider, OpenAIProvider
from repoguard.review import ReviewResult

if TYPE_CHECKING:
    from repoguard.retrieval import ContextIndex

__all__ = [
    "REPAIR_APPROVAL_CONFIRMATION",
    "RepairApplication",
    "RepairApproval",
    "RepairCandidate",
    "RepairContextOutcome",
    "RepairContextSummary",
    "RepairDecision",
    "RepairError",
    "RepairErrorCode",
    "RepairFailure",
    "RepairGenerationMode",
    "RepairGenerationPolicy",
    "RepairMaintenanceReport",
    "RepairManager",
    "RepairManagerConfig",
    "RepairPreview",
    "RepairPromptIdentity",
    "RepairProviderKind",
    "RepairSession",
    "RepairSnapshot",
    "RepairStage",
    "RepairState",
    "RepairTarget",
    "RepairValidation",
    "ValidationCommand",
    "ValidationCommandResult",
    "ValidationFailureKind",
    "ValidationPolicy",
    "repair_application_to_dict",
    "repair_application_to_json",
    "repair_approval_to_dict",
    "repair_approval_to_json",
    "repair_candidate_to_dict",
    "repair_candidate_to_json",
    "repair_context_summary_to_dict",
    "repair_context_summary_to_json",
    "repair_decision_to_dict",
    "repair_decision_to_json",
    "repair_failure_to_dict",
    "repair_failure_to_json",
    "repair_generation_policy_to_dict",
    "repair_generation_policy_to_json",
    "repair_maintenance_report_to_dict",
    "repair_maintenance_report_to_json",
    "repair_manager_config_to_dict",
    "repair_manager_config_to_json",
    "repair_preview_to_dict",
    "repair_preview_to_json",
    "repair_prompt_identity_to_dict",
    "repair_prompt_identity_to_json",
    "repair_snapshot_to_dict",
    "repair_snapshot_to_json",
    "repair_target_to_dict",
    "repair_target_to_json",
    "repair_validation_to_dict",
    "repair_validation_to_json",
    "validation_command_result_to_dict",
    "validation_command_result_to_json",
    "validation_command_to_dict",
    "validation_command_to_json",
    "validation_policy_to_dict",
    "validation_policy_to_json",
]

REPAIR_APPROVAL_CONFIRMATION = (
    "I approve this exact RepoGuard candidate and validation result for ref-only application."
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IMAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SESSION_PATTERN = _SHA256_PATTERN


class RepairState(StrEnum):
    """Durable state of one repair session."""

    CREATED = "created"
    GENERATING = "generating"
    VALIDATING = "validating"
    VALIDATED = "validated"
    APPROVED = "approved"
    APPLYING = "applying"
    APPLIED = "applied"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class RepairStage(StrEnum):
    """Stable public location of a repair failure."""

    INPUT = "input"
    SESSION = "session"
    MATERIALIZATION = "materialization"
    RETRIEVAL = "retrieval"
    PROMPT = "prompt"
    PROVIDER = "provider"
    PATCH = "patch"
    SANDBOX = "sandbox"
    VALIDATION = "validation"
    APPROVAL = "approval"
    APPLICATION = "application"
    PERSISTENCE = "persistence"
    RECOVERY = "recovery"
    CLEANUP = "cleanup"


class RepairProviderKind(StrEnum):
    """Built-in provider identity accepted by production repair."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class RepairGenerationMode(StrEnum):
    """How selected repair targets produce a candidate."""

    DETERMINISTIC = "deterministic"
    PROVIDER = "provider"
    MIXED = "mixed"


class RepairContextOutcome(StrEnum):
    """Outcome of the optional exact-index context capability."""

    NOT_REQUESTED = "not_requested"
    USED = "used"
    DEGRADED = "degraded"


class ValidationFailureKind(StrEnum):
    """Stable failed-validation result independent of Docker substeps."""

    COMMAND_EXIT_NONZERO = "command_exit_nonzero"
    COMMAND_TIMEOUT = "command_timeout"
    COMMAND_SIGNAL = "command_signal"
    OUTPUT_LIMIT = "output_limit"
    RESOURCE_LIMIT = "resource_limit"
    RESIDUAL_PROCESS = "residual_process"
    TRACKED_TREE_CHANGED = "tracked_tree_changed"
    SANDBOX_REPORT_INVALID = "sandbox_report_invalid"
    SANDBOX_RUNTIME_FAILED = "sandbox_runtime_failed"


class RepairErrorCode(StrEnum):
    """Closed public taxonomy for safe repair failures."""

    UNSUPPORTED_EVIDENCE_SCHEMA = "unsupported_evidence_schema"
    INVALID_EVIDENCE = "invalid_evidence"
    UNSUPPORTED_REVIEW_SCHEMA = "unsupported_review_schema"
    INVALID_REVIEW = "invalid_review"
    IDENTITY_MISMATCH = "identity_mismatch"
    INVALID_TARGETS = "invalid_targets"
    INVALID_CONFIG = "invalid_config"
    INVALID_PATH = "invalid_path"
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_LOCKED = "session_locked"
    INVALID_STATE = "invalid_state"
    SESSION_EXPIRED = "session_expired"
    SESSION_CORRUPT = "session_corrupt"
    PERSISTENCE_FAILED = "persistence_failed"
    GIT_UNAVAILABLE = "git_unavailable"
    GIT_FAILED = "git_failed"
    MISSING_OBJECT = "missing_object"
    MATERIALIZATION_FAILED = "materialization_failed"
    RESOURCE_LIMIT = "resource_limit"
    PROVIDER_REQUIRED = "provider_required"
    PROVIDER_MISMATCH = "provider_mismatch"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_AUTHENTICATION = "provider_authentication"
    PROVIDER_PERMISSION = "provider_permission"
    PROVIDER_BAD_REQUEST = "provider_bad_request"
    PROVIDER_INVALID_RESPONSE = "provider_invalid_response"
    PROVIDER_FAILED = "provider_failed"
    MODEL_RESPONSE_INVALID = "model_response_invalid"
    PATCH_INVALID = "patch_invalid"
    PATCH_LIMIT = "patch_limit"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    IMAGE_UNAVAILABLE = "image_unavailable"
    IMAGE_MISMATCH = "image_mismatch"
    VALIDATION_FAILED = "validation_failed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_MISMATCH = "approval_mismatch"
    INVALID_DECISION = "invalid_decision"
    REF_CONFLICT = "ref_conflict"
    PUBLICATION_FAILED = "publication_failed"
    RECOVERY_FAILED = "recovery_failed"
    CLEANUP_FAILED = "cleanup_failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    INVALID_WORKFLOW = "invalid_workflow"


_ERROR_MESSAGES: dict[RepairErrorCode, str] = {
    RepairErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA: "repair evidence schema is unsupported",
    RepairErrorCode.INVALID_EVIDENCE: "repair evidence is invalid",
    RepairErrorCode.UNSUPPORTED_REVIEW_SCHEMA: "repair review schema is unsupported",
    RepairErrorCode.INVALID_REVIEW: "repair review is invalid",
    RepairErrorCode.IDENTITY_MISMATCH: "repair identity does not match",
    RepairErrorCode.INVALID_TARGETS: "repair targets are invalid",
    RepairErrorCode.INVALID_CONFIG: "repair configuration is invalid",
    RepairErrorCode.INVALID_PATH: "repair path is invalid",
    RepairErrorCode.SESSION_NOT_FOUND: "repair session was not found",
    RepairErrorCode.SESSION_LOCKED: "repair session is locked",
    RepairErrorCode.INVALID_STATE: "repair state does not allow this operation",
    RepairErrorCode.SESSION_EXPIRED: "repair session is expired",
    RepairErrorCode.SESSION_CORRUPT: "repair session is corrupt",
    RepairErrorCode.PERSISTENCE_FAILED: "repair state could not be persisted",
    RepairErrorCode.GIT_UNAVAILABLE: "repair Git executable is unavailable",
    RepairErrorCode.GIT_FAILED: "repair Git operation failed",
    RepairErrorCode.MISSING_OBJECT: "repair requires a missing Git object",
    RepairErrorCode.MATERIALIZATION_FAILED: "repair candidate could not be materialized",
    RepairErrorCode.RESOURCE_LIMIT: "repair resource limit was exceeded",
    RepairErrorCode.PROVIDER_REQUIRED: "repair provider is required",
    RepairErrorCode.PROVIDER_MISMATCH: "repair provider does not match",
    RepairErrorCode.PROVIDER_RATE_LIMITED: "repair provider rate limit was reached",
    RepairErrorCode.PROVIDER_TIMEOUT: "repair provider timed out",
    RepairErrorCode.PROVIDER_UNAVAILABLE: "repair provider is unavailable",
    RepairErrorCode.PROVIDER_AUTHENTICATION: "repair provider authentication failed",
    RepairErrorCode.PROVIDER_PERMISSION: "repair provider permission was denied",
    RepairErrorCode.PROVIDER_BAD_REQUEST: "repair provider rejected the request",
    RepairErrorCode.PROVIDER_INVALID_RESPONSE: "repair provider response is invalid",
    RepairErrorCode.PROVIDER_FAILED: "repair provider failed",
    RepairErrorCode.MODEL_RESPONSE_INVALID: "repair model response is invalid",
    RepairErrorCode.PATCH_INVALID: "repair patch is invalid",
    RepairErrorCode.PATCH_LIMIT: "repair patch limit was exceeded",
    RepairErrorCode.UNSUPPORTED_PLATFORM: "repair platform is unsupported",
    RepairErrorCode.SANDBOX_UNAVAILABLE: "repair sandbox is unavailable",
    RepairErrorCode.IMAGE_UNAVAILABLE: "repair validation image is unavailable",
    RepairErrorCode.IMAGE_MISMATCH: "repair validation image does not match",
    RepairErrorCode.VALIDATION_FAILED: "repair validation failed",
    RepairErrorCode.APPROVAL_REQUIRED: "repair approval is required",
    RepairErrorCode.APPROVAL_MISMATCH: "repair approval does not match",
    RepairErrorCode.INVALID_DECISION: "repair decision is invalid",
    RepairErrorCode.REF_CONFLICT: "repair publication conflicted",
    RepairErrorCode.PUBLICATION_FAILED: "repair publication failed",
    RepairErrorCode.RECOVERY_FAILED: "repair recovery failed",
    RepairErrorCode.CLEANUP_FAILED: "repair cleanup failed",
    RepairErrorCode.CANCELLED: "repair session is cancelled",
    RepairErrorCode.EXPIRED: "repair session is expired",
    RepairErrorCode.INVALID_WORKFLOW: "repair workflow is invalid",
}

_RETRYABLE_CODES = {
    RepairErrorCode.SESSION_LOCKED,
    RepairErrorCode.PROVIDER_RATE_LIMITED,
    RepairErrorCode.PROVIDER_TIMEOUT,
    RepairErrorCode.PROVIDER_UNAVAILABLE,
}


class RepairError(RuntimeError):
    """Detached, secret-safe repair failure with stable public fields."""

    code: RepairErrorCode
    stage: RepairStage
    state: RepairState | None
    session_id: str | None
    retryable: bool

    def __init__(
        self,
        code: RepairErrorCode,
        stage: RepairStage,
        state: RepairState | None = None,
        session_id: str | None = None,
    ) -> None:
        if type(code) is not RepairErrorCode:
            raise TypeError("code must be a RepairErrorCode")
        if type(stage) is not RepairStage:
            raise TypeError("stage must be a RepairStage")
        if state is not None and type(state) is not RepairState:
            raise TypeError("state must be a RepairState or None")
        if session_id is not None:
            _require_pattern(session_id, _SESSION_PATTERN, "session_id")
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code
        self.stage = stage
        self.state = state
        self.session_id = session_id
        self.retryable = code in _RETRYABLE_CODES
        self.__cause__ = None
        self.__context__ = None
        self.__traceback__ = None
        self.__suppress_context__ = True


@dataclass(frozen=True, slots=True)
class _PublicCallSuccess[PublicResult]:
    value: PublicResult


@dataclass(frozen=True, slots=True)
class _PublicCallFailure:
    code: str
    stage: str
    state: str | None
    session_id: str | None


type _PublicCallOutcome[PublicResult] = _PublicCallSuccess[PublicResult] | _PublicCallFailure


def _public_call[PublicResult](
    operation: Callable[[], PublicResult],
) -> _PublicCallOutcome[PublicResult]:
    """Return a value or primitive error fields without exporting a private traceback."""
    try:
        return _PublicCallSuccess(operation())
    except RepairError as error:
        return _PublicCallFailure(
            code=error.code.value,
            stage=error.stage.value,
            state=None if error.state is None else error.state.value,
            session_id=error.session_id,
        )
    finally:
        del operation


def _unwrap_public_outcome[PublicResult](
    outcome: _PublicCallOutcome[PublicResult],
) -> PublicResult:
    """Return a public result or raise a new error from primitive fields only."""
    if isinstance(outcome, _PublicCallSuccess):
        return outcome.value
    state = None if outcome.state is None else RepairState(outcome.state)
    raise RepairError(
        RepairErrorCode(outcome.code),
        RepairStage(outcome.stage),
        state,
        outcome.session_id,
    ) from None


@dataclass(frozen=True, slots=True)
class RepairManagerConfig:
    """Host paths and fixed persistence policy for one repair manager."""

    runtime_root: Path
    git_executable: Path
    docker_executable: Path
    rootless_socket: Path
    lock_timeout_seconds: float = 5.0
    audit_retention_days: int = 30

    def __post_init__(self) -> None:
        for name in ("runtime_root", "git_executable", "docker_executable", "rootless_socket"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute pathlib.Path")
            _require_utf8(str(value), name)
        if type(self.lock_timeout_seconds) is not float or self.lock_timeout_seconds != 5.0:
            raise ValueError("lock_timeout_seconds must be 5.0")
        if type(self.audit_retention_days) is not int or self.audit_retention_days != 30:
            raise ValueError("audit_retention_days must be 30")


@dataclass(frozen=True, slots=True)
class RepairGenerationPolicy:
    """Frozen provider, context, prompt, and patch ceilings."""

    mode: RepairGenerationMode
    provider_kind: RepairProviderKind | None
    model: str | None
    max_file_bytes: int = 1_048_576
    max_prompt_bytes: int = 1_048_576
    max_response_bytes: int = 524_288
    max_output_tokens: int = 16_384
    max_queries: int = 16
    max_query_bytes: int = 2_048
    max_context_hits: int = 12
    max_patch_bytes: int = 262_144
    max_patch_paths: int = 32
    max_changed_lines: int = 10_000
    attempt_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 95.0

    def __post_init__(self) -> None:
        if type(self.mode) is not RepairGenerationMode:
            raise TypeError("mode must be a RepairGenerationMode")
        if self.provider_kind is not None and type(self.provider_kind) is not RepairProviderKind:
            raise TypeError("provider_kind must be a RepairProviderKind or None")
        if self.mode is RepairGenerationMode.DETERMINISTIC:
            if self.provider_kind is not None or self.model is not None:
                raise ValueError("deterministic generation cannot name a provider")
        elif self.provider_kind is None or self.model is None:
            raise ValueError("provider and mixed generation require provider identity")
        if self.model is not None:
            _require_text(self.model, "model", min_bytes=1, max_bytes=256)
        ceilings = {
            "max_file_bytes": 1_048_576,
            "max_prompt_bytes": 1_048_576,
            "max_response_bytes": 524_288,
            "max_output_tokens": 16_384,
            "max_queries": 16,
            "max_query_bytes": 2_048,
            "max_context_hits": 12,
            "max_patch_bytes": 262_144,
            "max_patch_paths": 32,
            "max_changed_lines": 10_000,
        }
        for name, ceiling in ceilings.items():
            _require_bounded_int(getattr(self, name), name, minimum=1, maximum=ceiling)
        _require_bounded_float(
            self.attempt_timeout_seconds,
            "attempt_timeout_seconds",
            maximum=30.0,
        )
        _require_bounded_float(
            self.total_timeout_seconds,
            "total_timeout_seconds",
            maximum=95.0,
        )
        if self.total_timeout_seconds < self.attempt_timeout_seconds:
            raise ValueError("total_timeout_seconds must cover one attempt")


@dataclass(frozen=True, slots=True)
class ValidationCommand:
    """One exact command executed by the packaged container runner."""

    argv: tuple[str, ...]
    cwd: str = "/workspace/repository"

    def __post_init__(self) -> None:
        _require_tuple(self.argv, "argv", minimum=1, maximum=64)
        for index, argument in enumerate(self.argv):
            _require_text(argument, f"argv[{index}]", min_bytes=1, max_bytes=4_096)
        if not self.argv[0].startswith("/"):
            raise ValueError("argv[0] must be an absolute container path")
        _validate_container_path(self.argv[0], "argv[0]")
        _validate_container_path(self.cwd, "cwd")
        if self.cwd != "/workspace" and not self.cwd.startswith("/workspace/"):
            raise ValueError("cwd must be /workspace or a descendant")


@dataclass(frozen=True, slots=True)
class ValidationPolicy:
    """Frozen image, command, resource, and output policy."""

    image_id: str
    commands: tuple[ValidationCommand, ...]
    command_timeout_seconds: int = 300
    total_timeout_seconds: int = 900
    memory_bytes: int = 2_147_483_648
    nano_cpus: int = 2_000_000_000
    pids_limit: int = 128
    stream_output_bytes: int = 1_048_576
    workspace_bytes: int = 1_073_741_824
    workspace_inodes: int = 65_536
    workspace_entries: int = 50_000
    tmp_bytes: int = 268_435_456
    tmp_inodes: int = 16_384
    home_bytes: int = 67_108_864
    home_inodes: int = 4_096
    run_bytes: int = 16_777_216
    run_inodes: int = 1_024

    def __post_init__(self) -> None:
        _require_pattern(self.image_id, _IMAGE_PATTERN, "image_id")
        _require_tuple(self.commands, "commands", minimum=1, maximum=8)
        if any(type(command) is not ValidationCommand for command in self.commands):
            raise TypeError("commands must contain exact ValidationCommand values")
        ceilings = {
            "command_timeout_seconds": 300,
            "total_timeout_seconds": 900,
            "memory_bytes": 2_147_483_648,
            "nano_cpus": 2_000_000_000,
            "pids_limit": 128,
            "stream_output_bytes": 1_048_576,
            "workspace_bytes": 1_073_741_824,
            "workspace_inodes": 65_536,
            "workspace_entries": 50_000,
            "tmp_bytes": 268_435_456,
            "tmp_inodes": 16_384,
            "home_bytes": 67_108_864,
            "home_inodes": 4_096,
            "run_bytes": 16_777_216,
            "run_inodes": 1_024,
        }
        for name, ceiling in ceilings.items():
            _require_bounded_int(getattr(self, name), name, minimum=1, maximum=ceiling)
        if self.total_timeout_seconds < self.command_timeout_seconds:
            raise ValueError("total_timeout_seconds must cover one command")


@dataclass(frozen=True, slots=True)
class RepairTarget:
    """Stable indices selecting one exact M2 finding reference."""

    finding_index: int
    reference_index: int

    def __post_init__(self) -> None:
        _require_bounded_int(self.finding_index, "finding_index", minimum=0)
        _require_bounded_int(self.reference_index, "reference_index", minimum=0)


@dataclass(frozen=True, slots=True)
class RepairPromptIdentity:
    """Immutable identity of the packaged repair prompt resources."""

    name: str
    version: int
    system_sha256: str
    response_schema_sha256: str
    combined_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.name, "name", min_bytes=1, max_bytes=128)
        if type(self.version) is not int or self.version != 1:
            raise ValueError("version must be 1")
        _require_sha256_fields(self, "system_sha256", "response_schema_sha256", "combined_sha256")


@dataclass(frozen=True, slots=True)
class RepairContextSummary:
    """Content-free summary of optional M4 context use."""

    outcome: RepairContextOutcome
    index_identity_sha256: str | None
    query_sha256: str | None
    query_count: int
    candidate_count: int
    selected_hit_count: int
    hit_identity_sha256: str | None
    degradation_code: str | None

    def __post_init__(self) -> None:
        if type(self.outcome) is not RepairContextOutcome:
            raise TypeError("outcome must be a RepairContextOutcome")
        if self.degradation_code is not None and type(self.degradation_code) is not str:
            raise TypeError("degradation_code must be a string")
        for name in ("index_identity_sha256", "query_sha256", "hit_identity_sha256"):
            value = getattr(self, name)
            if value is not None:
                _require_pattern(value, _SHA256_PATTERN, name)
        _require_bounded_int(self.query_count, "query_count", minimum=0, maximum=16)
        _require_bounded_int(self.candidate_count, "candidate_count", minimum=0)
        _require_bounded_int(self.selected_hit_count, "selected_hit_count", minimum=0, maximum=12)
        if self.outcome is RepairContextOutcome.NOT_REQUESTED:
            if any(
                value is not None
                for value in (
                    self.index_identity_sha256,
                    self.query_sha256,
                    self.hit_identity_sha256,
                    self.degradation_code,
                )
            ) or any((self.query_count, self.candidate_count, self.selected_hit_count)):
                raise ValueError("not-requested context must be empty")
        elif self.outcome is RepairContextOutcome.USED:
            if (
                self.index_identity_sha256 is None
                or self.query_sha256 is None
                or self.hit_identity_sha256 is None
                or self.degradation_code is not None
            ):
                raise ValueError("used context identity is incomplete")
        else:
            if (
                self.index_identity_sha256 is None
                or self.query_sha256 is None
                or self.degradation_code
                not in {"closed_index", "deadline_exceeded", "backend_failure"}
                or self.candidate_count != 0
                or self.selected_hit_count != 0
                or self.hit_identity_sha256 is not None
            ):
                raise ValueError("degraded context identity is invalid")


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    """Content-free identity of one complete fixed repair commit."""

    schema_version: int
    candidate_id: str
    request_sha256: str
    prompt: RepairPromptIdentity
    context: RepairContextSummary
    diff_sha256: str
    tree_oid: str
    commit_oid: str
    changed_paths: tuple[str, ...]
    changed_line_count: int
    provider_attempt_count: int
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256_fields(self, "candidate_id", "request_sha256", "diff_sha256")
        if type(self.prompt) is not RepairPromptIdentity:
            raise TypeError("prompt must be a RepairPromptIdentity")
        if type(self.context) is not RepairContextSummary:
            raise TypeError("context must be a RepairContextSummary")
        _require_pattern(self.tree_oid, _OID_PATTERN, "tree_oid")
        _require_pattern(self.commit_oid, _OID_PATTERN, "commit_oid")
        _require_paths(self.changed_paths, "changed_paths", minimum=1, maximum=32)
        _require_bounded_int(
            self.changed_line_count,
            "changed_line_count",
            minimum=1,
            maximum=10_000,
        )
        _require_bounded_int(
            self.provider_attempt_count,
            "provider_attempt_count",
            minimum=0,
            maximum=3,
        )
        _require_bounded_int(self.input_tokens, "input_tokens", minimum=0)
        _require_bounded_int(self.output_tokens, "output_tokens", minimum=0)


@dataclass(frozen=True, slots=True)
class ValidationCommandResult:
    """Raw-output-free result for one validation command."""

    command_index: int
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_us: int
    stdout_sha256: str
    stdout_bytes: int
    stdout_truncated: bool
    stderr_sha256: str
    stderr_bytes: int
    stderr_truncated: bool

    def __post_init__(self) -> None:
        _require_bounded_int(self.command_index, "command_index", minimum=0, maximum=7)
        for name in ("exit_code", "signal"):
            value = getattr(self, name)
            if value is not None:
                _require_bounded_int(value, name, minimum=0)
        _require_bool(self.timed_out, "timed_out")
        _require_bounded_int(self.duration_us, "duration_us", minimum=0)
        _require_sha256_fields(self, "stdout_sha256", "stderr_sha256")
        _require_bounded_int(self.stdout_bytes, "stdout_bytes", minimum=0)
        _require_bool(self.stdout_truncated, "stdout_truncated")
        _require_bounded_int(self.stderr_bytes, "stderr_bytes", minimum=0)
        _require_bool(self.stderr_truncated, "stderr_truncated")
        if self.exit_code is not None and self.signal is not None:
            raise ValueError("exit_code and signal are mutually exclusive")


@dataclass(frozen=True, slots=True)
class RepairValidation:
    """Authenticated, raw-output-free validation result."""

    schema_version: int
    validation_sha256: str
    candidate_id: str
    policy_sha256: str
    sandbox_manifest_sha256: str
    image_id: str
    started_at_us: int
    finished_at_us: int
    success: bool
    failure_kind: ValidationFailureKind | None
    command_results: tuple[ValidationCommandResult, ...]
    peak_memory_bytes: int
    oom_killed: bool
    residual_process_count: int
    workspace_entry_count: int
    workspace_inode_count: int
    tracked_tree_clean: bool

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256_fields(
            self,
            "validation_sha256",
            "candidate_id",
            "policy_sha256",
            "sandbox_manifest_sha256",
        )
        _require_pattern(self.image_id, _IMAGE_PATTERN, "image_id")
        _require_timestamp_order(self.started_at_us, self.finished_at_us)
        _require_bool(self.success, "success")
        if self.failure_kind is not None and type(self.failure_kind) is not ValidationFailureKind:
            raise TypeError("failure_kind must be a ValidationFailureKind or None")
        _require_tuple(self.command_results, "command_results", minimum=0, maximum=8)
        if any(type(item) is not ValidationCommandResult for item in self.command_results):
            raise TypeError("command_results must contain exact ValidationCommandResult values")
        if tuple(item.command_index for item in self.command_results) != tuple(
            range(len(self.command_results))
        ):
            raise ValueError("command result indices must be contiguous")
        _require_bounded_int(self.peak_memory_bytes, "peak_memory_bytes", minimum=0)
        _require_bool(self.oom_killed, "oom_killed")
        _require_bounded_int(self.residual_process_count, "residual_process_count", minimum=0)
        _require_bounded_int(self.workspace_entry_count, "workspace_entry_count", minimum=0)
        _require_bounded_int(self.workspace_inode_count, "workspace_inode_count", minimum=0)
        _require_bool(self.tracked_tree_clean, "tracked_tree_clean")
        if self.success:
            if (
                self.failure_kind is not None
                or not self.command_results
                or any(
                    result.exit_code != 0
                    or result.signal is not None
                    or result.timed_out
                    or result.stdout_truncated
                    or result.stderr_truncated
                    for result in self.command_results
                )
                or self.oom_killed
                or self.residual_process_count != 0
                or not self.tracked_tree_clean
            ):
                raise ValueError("successful validation cannot contain failure state")
        elif self.failure_kind is None:
            raise ValueError("failed validation requires failure_kind")


@dataclass(frozen=True, slots=True)
class RepairApproval:
    """One exact local approval declaration."""

    schema_version: int
    approval_sha256: str
    candidate_id: str
    validation_sha256: str
    subject: str
    confirmation: str
    approved_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256_fields(self, "approval_sha256", "candidate_id", "validation_sha256")
        _require_subject(self.subject)
        _require_utf8(self.confirmation, "confirmation")
        if self.confirmation != REPAIR_APPROVAL_CONFIRMATION:
            raise ValueError("confirmation does not match")
        _require_bounded_int(self.approved_at_us, "approved_at_us", minimum=0)


@dataclass(frozen=True, slots=True)
class RepairApplication:
    """Read-back-confirmed publication of one approved repair ref."""

    schema_version: int
    application_sha256: str
    approval_sha256: str
    ref: str
    commit_oid: str
    applied_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256_fields(self, "application_sha256", "approval_sha256")
        _require_utf8(self.ref, "ref")
        if not self.ref.startswith("refs/repoguard/repairs/"):
            raise ValueError("application ref is invalid")
        _require_pattern(self.ref.removeprefix("refs/repoguard/repairs/"), _SHA256_PATTERN, "ref")
        _require_pattern(self.commit_oid, _OID_PATTERN, "commit_oid")
        _require_bounded_int(self.applied_at_us, "applied_at_us", minimum=0)


@dataclass(frozen=True, slots=True)
class RepairDecision:
    """Local rejection, cancellation, or expiry declaration."""

    schema_version: int
    decision_sha256: str
    state: RepairState
    subject: str
    reason: str
    candidate_id: str | None
    decided_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_pattern(self.decision_sha256, _SHA256_PATTERN, "decision_sha256")
        if type(self.state) is not RepairState:
            raise TypeError("state must be a RepairState")
        if self.state not in {RepairState.REJECTED, RepairState.CANCELLED, RepairState.EXPIRED}:
            raise ValueError("decision state is invalid")
        _require_subject(self.subject)
        if type(self.reason) is not str:
            raise TypeError("reason must be a string")
        if self.state is RepairState.REJECTED:
            _require_text(self.reason, "reason", min_bytes=1, max_bytes=1_000)
            if self.candidate_id is None:
                raise ValueError("rejection requires candidate_id")
        elif self.reason:
            _require_text(self.reason, "reason", min_bytes=1, max_bytes=1_000)
        if self.candidate_id is not None:
            _require_pattern(self.candidate_id, _SHA256_PATTERN, "candidate_id")
        _require_bounded_int(self.decided_at_us, "decided_at_us", minimum=0)


@dataclass(frozen=True, slots=True)
class RepairFailure:
    """Safe terminal failure metadata."""

    schema_version: int
    code: RepairErrorCode
    stage: RepairStage
    retryable: bool
    occurred_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        if type(self.code) is not RepairErrorCode:
            raise TypeError("code must be a RepairErrorCode")
        if type(self.stage) is not RepairStage:
            raise TypeError("stage must be a RepairStage")
        _require_bool(self.retryable, "retryable")
        if self.retryable != (self.code in _RETRYABLE_CODES):
            raise ValueError("retryable does not match error code")
        _require_bounded_int(self.occurred_at_us, "occurred_at_us", minimum=0)


@dataclass(frozen=True, slots=True)
class RepairSnapshot:
    """Complete content-free projection of current durable session state."""

    schema_version: int
    session_id: str
    state: RepairState
    request_sha256: str
    created_at_us: int
    updated_at_us: int
    target_count: int
    allowed_paths: tuple[str, ...]
    candidate: RepairCandidate | None
    validation: RepairValidation | None
    approval: RepairApproval | None
    application: RepairApplication | None
    decision: RepairDecision | None
    failure: RepairFailure | None
    cleanup_pending: bool

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_pattern(self.session_id, _SESSION_PATTERN, "session_id")
        if type(self.state) is not RepairState:
            raise TypeError("state must be a RepairState")
        _require_pattern(self.request_sha256, _SHA256_PATTERN, "request_sha256")
        _require_timestamp_order(self.created_at_us, self.updated_at_us)
        _require_bounded_int(self.target_count, "target_count", minimum=1, maximum=16)
        _require_paths(self.allowed_paths, "allowed_paths", minimum=1, maximum=32)
        optional_types: tuple[tuple[str, type[object]], ...] = (
            ("candidate", RepairCandidate),
            ("validation", RepairValidation),
            ("approval", RepairApproval),
            ("application", RepairApplication),
            ("decision", RepairDecision),
            ("failure", RepairFailure),
        )
        for name, expected in optional_types:
            value = getattr(self, name)
            if value is not None and type(value) is not expected:
                raise TypeError(f"{name} has an invalid type")
        _require_bool(self.cleanup_pending, "cleanup_pending")
        _validate_snapshot_shape(self)


@dataclass(frozen=True, slots=True)
class RepairPreview:
    """Secret-redacted candidate diff and approval instruction."""

    schema_version: int
    session_id: str
    state: RepairState
    candidate_id: str
    validation_sha256: str | None
    changed_paths: tuple[str, ...]
    canonical_diff: str
    confirmation: str

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_pattern(self.session_id, _SESSION_PATTERN, "session_id")
        if type(self.state) is not RepairState:
            raise TypeError("state must be a RepairState")
        _require_pattern(self.candidate_id, _SHA256_PATTERN, "candidate_id")
        if self.validation_sha256 is not None:
            _require_pattern(self.validation_sha256, _SHA256_PATTERN, "validation_sha256")
        _require_paths(self.changed_paths, "changed_paths", minimum=1, maximum=32)
        _require_utf8(self.canonical_diff, "canonical_diff")
        if "\r" in self.canonical_diff or "\x00" in self.canonical_diff:
            raise ValueError("canonical_diff contains forbidden bytes")
        _require_utf8(self.confirmation, "confirmation")
        if self.confirmation != REPAIR_APPROVAL_CONFIRMATION:
            raise ValueError("confirmation does not match")


@dataclass(frozen=True, slots=True)
class RepairMaintenanceReport:
    """Content-free result of one manager recovery or cleanup pass."""

    schema_version: int
    started_at_us: int
    finished_at_us: int
    recovered_session_ids: tuple[str, ...]
    cleaned_session_ids: tuple[str, ...]
    removed_session_ids: tuple[str, ...]
    cleanup_pending_session_ids: tuple[str, ...]
    failed_session_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_timestamp_order(self.started_at_us, self.finished_at_us)
        for name in (
            "recovered_session_ids",
            "cleaned_session_ids",
            "removed_session_ids",
            "cleanup_pending_session_ids",
            "failed_session_ids",
        ):
            _require_ids(getattr(self, name), name)


class RepairManager:
    """Manager bound to one local repository and one private runtime root."""

    __slots__ = ("_config", "_repository", "_runtime_root_identity")

    def __init__(self, repository: RepositoryInput, config: RepairManagerConfig) -> None:
        if type(repository) is not RepositoryInput:
            raise TypeError("repository must be an exact RepositoryInput")
        if type(config) is not RepairManagerConfig:
            raise TypeError("config must be an exact RepairManagerConfig")
        from repoguard._repair_workflow import _initialize_manager

        outcome = _public_call(lambda: _initialize_manager(repository, config))
        if isinstance(outcome, _PublicCallFailure):
            repository = cast(RepositoryInput, None)
            config = cast(RepairManagerConfig, None)
        runtime_root_identity = _unwrap_public_outcome(outcome)
        self._repository = repository
        self._config = config
        self._runtime_root_identity = runtime_root_identity

    def create_session(
        self,
        bundle: EvidenceBundle,
        review: ReviewResult,
        *,
        targets: tuple[RepairTarget, ...],
        allowed_paths: tuple[str, ...],
        generation: RepairGenerationPolicy,
        validation: ValidationPolicy,
        context_index: ContextIndex | None = None,
    ) -> RepairSession:
        """Freeze an exact schema-1 repair request in a new durable session."""
        from repoguard._repair_workflow import _create_session

        outcome = _public_call(
            lambda: _create_session(
                self,
                bundle,
                review,
                targets=targets,
                allowed_paths=allowed_paths,
                generation=generation,
                validation=validation,
                context_index=context_index,
            )
        )
        bundle = cast(EvidenceBundle, None)
        review = cast(ReviewResult, None)
        targets = ()
        allowed_paths = ()
        generation = cast(RepairGenerationPolicy, None)
        validation = cast(ValidationPolicy, None)
        context_index = None
        session_id = _unwrap_public_outcome(outcome)
        return RepairSession(self, session_id)

    def open_session(self, session_id: str) -> RepairSession:
        """Open an existing session after validating its immutable event chain."""
        from repoguard._repair_workflow import _open_session

        outcome = _public_call(lambda: _open_session(self, session_id))
        _unwrap_public_outcome(outcome)
        return RepairSession(self, session_id)

    def recover(self) -> RepairMaintenanceReport:
        """Converge interrupted sessions without repeating provider or validation work."""
        from repoguard._repair_workflow import _recover

        return _unwrap_public_outcome(_public_call(lambda: _recover(self)))

    def cleanup(self) -> RepairMaintenanceReport:
        """Retry private cleanup and remove expired safe audit records."""
        from repoguard._repair_workflow import _cleanup

        return _unwrap_public_outcome(_public_call(lambda: _cleanup(self)))


class RepairSession:
    """Lightweight handle whose operations always reload authoritative state."""

    __slots__ = ("_manager", "_session_id")

    def __init__(self, manager: RepairManager, session_id: str) -> None:
        if type(manager) is not RepairManager:
            raise TypeError("manager must be an exact RepairManager")
        _require_pattern(session_id, _SESSION_PATTERN, "session_id")
        self._manager = manager
        self._session_id = session_id

    def propose(
        self,
        *,
        provider: OpenAIProvider | AnthropicProvider | None = None,
        context_index: ContextIndex | None = None,
    ) -> RepairSnapshot:
        """Generate and perform the sole validation attempt for this session."""
        from repoguard._repair_workflow import _propose

        outcome = _public_call(
            lambda: _propose(self, provider=provider, context_index=context_index)
        )
        provider = None
        context_index = None
        return _unwrap_public_outcome(outcome)

    def preview(self) -> RepairPreview:
        """Return the durable secret-redacted candidate preview."""
        from repoguard._repair_workflow import _preview

        return _unwrap_public_outcome(_public_call(lambda: _preview(self)))

    def approve(
        self,
        *,
        subject: str,
        expected_candidate_id: str,
        expected_validation_sha256: str,
        confirmation: str,
    ) -> RepairSnapshot:
        """Approve one exact successful candidate and validation result."""
        from repoguard._repair_workflow import _approve

        outcome = _public_call(
            lambda: _approve(
                self,
                subject=subject,
                expected_candidate_id=expected_candidate_id,
                expected_validation_sha256=expected_validation_sha256,
                confirmation=confirmation,
            )
        )
        subject = ""
        expected_candidate_id = ""
        expected_validation_sha256 = ""
        confirmation = ""
        return _unwrap_public_outcome(outcome)

    def apply(self, *, expected_approval_sha256: str) -> RepairSnapshot:
        """Publish the approved commit only to its dedicated local repair ref."""
        from repoguard._repair_workflow import _apply

        outcome = _public_call(
            lambda: _apply(self, expected_approval_sha256=expected_approval_sha256)
        )
        expected_approval_sha256 = ""
        return _unwrap_public_outcome(outcome)

    def reject(
        self,
        *,
        subject: str,
        reason: str,
        expected_candidate_id: str,
    ) -> RepairSnapshot:
        """Reject one exact validated or approved candidate."""
        from repoguard._repair_workflow import _reject

        outcome = _public_call(
            lambda: _reject(
                self,
                subject=subject,
                reason=reason,
                expected_candidate_id=expected_candidate_id,
            )
        )
        subject = ""
        reason = ""
        expected_candidate_id = ""
        return _unwrap_public_outcome(outcome)

    def cancel(self, *, subject: str, reason: str = "") -> RepairSnapshot:
        """Cancel a nonterminal session and discard late external results."""
        from repoguard._repair_workflow import _cancel

        outcome = _public_call(lambda: _cancel(self, subject=subject, reason=reason))
        subject = ""
        reason = ""
        return _unwrap_public_outcome(outcome)

    def expire(self) -> RepairSnapshot:
        """Explicitly expire a nonterminal local session."""
        from repoguard._repair_workflow import _expire

        return _unwrap_public_outcome(_public_call(lambda: _expire(self)))

    def snapshot(self) -> RepairSnapshot:
        """Return the latest fully verified content-free state projection."""
        from repoguard._repair_workflow import _snapshot

        return _unwrap_public_outcome(_public_call(lambda: _snapshot(self)))


def repair_manager_config_to_dict(value: RepairManagerConfig) -> dict[str, object]:
    """Convert manager configuration to its canonical mapping."""
    _require_exact(value, RepairManagerConfig, "value")
    return {
        "runtime_root": str(value.runtime_root),
        "git_executable": str(value.git_executable),
        "docker_executable": str(value.docker_executable),
        "rootless_socket": str(value.rootless_socket),
        "lock_timeout_seconds": value.lock_timeout_seconds,
        "audit_retention_days": value.audit_retention_days,
    }


def repair_manager_config_to_json(value: RepairManagerConfig) -> str:
    """Serialize manager configuration as canonical JSON."""
    return _canonical_json(repair_manager_config_to_dict(value))


def repair_generation_policy_to_dict(value: RepairGenerationPolicy) -> dict[str, object]:
    """Convert generation policy to its canonical mapping."""
    _require_exact(value, RepairGenerationPolicy, "value")
    return {
        "mode": value.mode.value,
        "provider_kind": None if value.provider_kind is None else value.provider_kind.value,
        "model": value.model,
        "max_file_bytes": value.max_file_bytes,
        "max_prompt_bytes": value.max_prompt_bytes,
        "max_response_bytes": value.max_response_bytes,
        "max_output_tokens": value.max_output_tokens,
        "max_queries": value.max_queries,
        "max_query_bytes": value.max_query_bytes,
        "max_context_hits": value.max_context_hits,
        "max_patch_bytes": value.max_patch_bytes,
        "max_patch_paths": value.max_patch_paths,
        "max_changed_lines": value.max_changed_lines,
        "attempt_timeout_seconds": value.attempt_timeout_seconds,
        "total_timeout_seconds": value.total_timeout_seconds,
    }


def repair_generation_policy_to_json(value: RepairGenerationPolicy) -> str:
    """Serialize generation policy as canonical JSON."""
    return _canonical_json(repair_generation_policy_to_dict(value))


def validation_command_to_dict(value: ValidationCommand) -> dict[str, object]:
    """Convert one validation command to its canonical mapping."""
    _require_exact(value, ValidationCommand, "value")
    return {"argv": list(value.argv), "cwd": value.cwd}


def validation_command_to_json(value: ValidationCommand) -> str:
    """Serialize one validation command as canonical JSON."""
    return _canonical_json(validation_command_to_dict(value))


def validation_policy_to_dict(value: ValidationPolicy) -> dict[str, object]:
    """Convert validation policy to its canonical mapping."""
    _require_exact(value, ValidationPolicy, "value")
    return {
        "image_id": value.image_id,
        "commands": [validation_command_to_dict(command) for command in value.commands],
        "command_timeout_seconds": value.command_timeout_seconds,
        "total_timeout_seconds": value.total_timeout_seconds,
        "memory_bytes": value.memory_bytes,
        "nano_cpus": value.nano_cpus,
        "pids_limit": value.pids_limit,
        "stream_output_bytes": value.stream_output_bytes,
        "workspace_bytes": value.workspace_bytes,
        "workspace_inodes": value.workspace_inodes,
        "workspace_entries": value.workspace_entries,
        "tmp_bytes": value.tmp_bytes,
        "tmp_inodes": value.tmp_inodes,
        "home_bytes": value.home_bytes,
        "home_inodes": value.home_inodes,
        "run_bytes": value.run_bytes,
        "run_inodes": value.run_inodes,
    }


def validation_policy_to_json(value: ValidationPolicy) -> str:
    """Serialize validation policy as canonical JSON."""
    return _canonical_json(validation_policy_to_dict(value))


def repair_target_to_dict(value: RepairTarget) -> dict[str, object]:
    """Convert a repair target to its canonical mapping."""
    _require_exact(value, RepairTarget, "value")
    return {"finding_index": value.finding_index, "reference_index": value.reference_index}


def repair_target_to_json(value: RepairTarget) -> str:
    """Serialize a repair target as canonical JSON."""
    return _canonical_json(repair_target_to_dict(value))


def repair_prompt_identity_to_dict(value: RepairPromptIdentity) -> dict[str, object]:
    """Convert a prompt identity to its canonical mapping."""
    _require_exact(value, RepairPromptIdentity, "value")
    return {
        "name": value.name,
        "version": value.version,
        "system_sha256": value.system_sha256,
        "response_schema_sha256": value.response_schema_sha256,
        "combined_sha256": value.combined_sha256,
    }


def repair_prompt_identity_to_json(value: RepairPromptIdentity) -> str:
    """Serialize a prompt identity as canonical JSON."""
    return _canonical_json(repair_prompt_identity_to_dict(value))


def repair_context_summary_to_dict(value: RepairContextSummary) -> dict[str, object]:
    """Convert a context summary to its canonical mapping."""
    _require_exact(value, RepairContextSummary, "value")
    return {
        "outcome": value.outcome.value,
        "index_identity_sha256": value.index_identity_sha256,
        "query_sha256": value.query_sha256,
        "query_count": value.query_count,
        "candidate_count": value.candidate_count,
        "selected_hit_count": value.selected_hit_count,
        "hit_identity_sha256": value.hit_identity_sha256,
        "degradation_code": value.degradation_code,
    }


def repair_context_summary_to_json(value: RepairContextSummary) -> str:
    """Serialize a context summary as canonical JSON."""
    return _canonical_json(repair_context_summary_to_dict(value))


def repair_candidate_to_dict(value: RepairCandidate) -> dict[str, object]:
    """Convert a repair candidate to its canonical mapping."""
    _require_exact(value, RepairCandidate, "value")
    return {
        "schema_version": value.schema_version,
        "candidate_id": value.candidate_id,
        "request_sha256": value.request_sha256,
        "prompt": repair_prompt_identity_to_dict(value.prompt),
        "context": repair_context_summary_to_dict(value.context),
        "diff_sha256": value.diff_sha256,
        "tree_oid": value.tree_oid,
        "commit_oid": value.commit_oid,
        "changed_paths": list(value.changed_paths),
        "changed_line_count": value.changed_line_count,
        "provider_attempt_count": value.provider_attempt_count,
        "input_tokens": value.input_tokens,
        "output_tokens": value.output_tokens,
    }


def repair_candidate_to_json(value: RepairCandidate) -> str:
    """Serialize a repair candidate as canonical JSON."""
    return _canonical_json(repair_candidate_to_dict(value))


def validation_command_result_to_dict(value: ValidationCommandResult) -> dict[str, object]:
    """Convert one validation command result to its canonical mapping."""
    _require_exact(value, ValidationCommandResult, "value")
    return {
        "command_index": value.command_index,
        "exit_code": value.exit_code,
        "signal": value.signal,
        "timed_out": value.timed_out,
        "duration_us": value.duration_us,
        "stdout_sha256": value.stdout_sha256,
        "stdout_bytes": value.stdout_bytes,
        "stdout_truncated": value.stdout_truncated,
        "stderr_sha256": value.stderr_sha256,
        "stderr_bytes": value.stderr_bytes,
        "stderr_truncated": value.stderr_truncated,
    }


def validation_command_result_to_json(value: ValidationCommandResult) -> str:
    """Serialize one validation command result as canonical JSON."""
    return _canonical_json(validation_command_result_to_dict(value))


def repair_validation_to_dict(value: RepairValidation) -> dict[str, object]:
    """Convert a repair validation to its canonical mapping."""
    _require_exact(value, RepairValidation, "value")
    return {
        "schema_version": value.schema_version,
        "validation_sha256": value.validation_sha256,
        "candidate_id": value.candidate_id,
        "policy_sha256": value.policy_sha256,
        "sandbox_manifest_sha256": value.sandbox_manifest_sha256,
        "image_id": value.image_id,
        "started_at_us": value.started_at_us,
        "finished_at_us": value.finished_at_us,
        "success": value.success,
        "failure_kind": None if value.failure_kind is None else value.failure_kind.value,
        "command_results": [
            validation_command_result_to_dict(result) for result in value.command_results
        ],
        "peak_memory_bytes": value.peak_memory_bytes,
        "oom_killed": value.oom_killed,
        "residual_process_count": value.residual_process_count,
        "workspace_entry_count": value.workspace_entry_count,
        "workspace_inode_count": value.workspace_inode_count,
        "tracked_tree_clean": value.tracked_tree_clean,
    }


def repair_validation_to_json(value: RepairValidation) -> str:
    """Serialize a repair validation as canonical JSON."""
    return _canonical_json(repair_validation_to_dict(value))


def repair_approval_to_dict(value: RepairApproval) -> dict[str, object]:
    """Convert a repair approval to its canonical mapping."""
    _require_exact(value, RepairApproval, "value")
    return {
        "schema_version": value.schema_version,
        "approval_sha256": value.approval_sha256,
        "candidate_id": value.candidate_id,
        "validation_sha256": value.validation_sha256,
        "subject": value.subject,
        "confirmation": value.confirmation,
        "approved_at_us": value.approved_at_us,
    }


def repair_approval_to_json(value: RepairApproval) -> str:
    """Serialize a repair approval as canonical JSON."""
    return _canonical_json(repair_approval_to_dict(value))


def repair_application_to_dict(value: RepairApplication) -> dict[str, object]:
    """Convert a repair application to its canonical mapping."""
    _require_exact(value, RepairApplication, "value")
    return {
        "schema_version": value.schema_version,
        "application_sha256": value.application_sha256,
        "approval_sha256": value.approval_sha256,
        "ref": value.ref,
        "commit_oid": value.commit_oid,
        "applied_at_us": value.applied_at_us,
    }


def repair_application_to_json(value: RepairApplication) -> str:
    """Serialize a repair application as canonical JSON."""
    return _canonical_json(repair_application_to_dict(value))


def repair_decision_to_dict(value: RepairDecision) -> dict[str, object]:
    """Convert a repair decision to its canonical mapping."""
    _require_exact(value, RepairDecision, "value")
    return {
        "schema_version": value.schema_version,
        "decision_sha256": value.decision_sha256,
        "state": value.state.value,
        "subject": value.subject,
        "reason": value.reason,
        "candidate_id": value.candidate_id,
        "decided_at_us": value.decided_at_us,
    }


def repair_decision_to_json(value: RepairDecision) -> str:
    """Serialize a repair decision as canonical JSON."""
    return _canonical_json(repair_decision_to_dict(value))


def repair_failure_to_dict(value: RepairFailure) -> dict[str, object]:
    """Convert safe repair failure metadata to its canonical mapping."""
    _require_exact(value, RepairFailure, "value")
    return {
        "schema_version": value.schema_version,
        "code": value.code.value,
        "stage": value.stage.value,
        "retryable": value.retryable,
        "occurred_at_us": value.occurred_at_us,
    }


def repair_failure_to_json(value: RepairFailure) -> str:
    """Serialize safe repair failure metadata as canonical JSON."""
    return _canonical_json(repair_failure_to_dict(value))


def repair_snapshot_to_dict(value: RepairSnapshot) -> dict[str, object]:
    """Convert a complete session snapshot to its canonical mapping."""
    _require_exact(value, RepairSnapshot, "value")
    value.__post_init__()
    return {
        "schema_version": value.schema_version,
        "session_id": value.session_id,
        "state": value.state.value,
        "request_sha256": value.request_sha256,
        "created_at_us": value.created_at_us,
        "updated_at_us": value.updated_at_us,
        "target_count": value.target_count,
        "allowed_paths": list(value.allowed_paths),
        "candidate": None if value.candidate is None else repair_candidate_to_dict(value.candidate),
        "validation": (
            None if value.validation is None else repair_validation_to_dict(value.validation)
        ),
        "approval": None if value.approval is None else repair_approval_to_dict(value.approval),
        "application": (
            None if value.application is None else repair_application_to_dict(value.application)
        ),
        "decision": None if value.decision is None else repair_decision_to_dict(value.decision),
        "failure": None if value.failure is None else repair_failure_to_dict(value.failure),
        "cleanup_pending": value.cleanup_pending,
    }


def repair_snapshot_to_json(value: RepairSnapshot) -> str:
    """Serialize a complete session snapshot as canonical JSON."""
    return _canonical_json(repair_snapshot_to_dict(value))


def repair_preview_to_dict(value: RepairPreview) -> dict[str, object]:
    """Convert a secret-redacted candidate preview to its canonical mapping."""
    _require_exact(value, RepairPreview, "value")
    return {
        "schema_version": value.schema_version,
        "session_id": value.session_id,
        "state": value.state.value,
        "candidate_id": value.candidate_id,
        "validation_sha256": value.validation_sha256,
        "changed_paths": list(value.changed_paths),
        "canonical_diff": value.canonical_diff,
        "confirmation": value.confirmation,
    }


def repair_preview_to_json(value: RepairPreview) -> str:
    """Serialize a secret-redacted candidate preview as canonical JSON."""
    return _canonical_json(repair_preview_to_dict(value))


def repair_maintenance_report_to_dict(value: RepairMaintenanceReport) -> dict[str, object]:
    """Convert a maintenance report to its canonical mapping."""
    _require_exact(value, RepairMaintenanceReport, "value")
    return {
        "schema_version": value.schema_version,
        "started_at_us": value.started_at_us,
        "finished_at_us": value.finished_at_us,
        "recovered_session_ids": list(value.recovered_session_ids),
        "cleaned_session_ids": list(value.cleaned_session_ids),
        "removed_session_ids": list(value.removed_session_ids),
        "cleanup_pending_session_ids": list(value.cleanup_pending_session_ids),
        "failed_session_ids": list(value.failed_session_ids),
    }


def repair_maintenance_report_to_json(value: RepairMaintenanceReport) -> str:
    """Serialize a maintenance report as canonical JSON."""
    return _canonical_json(repair_maintenance_report_to_dict(value))


def _canonical_json(mapping: dict[str, object]) -> str:
    return json.dumps(
        mapping,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _require_exact(value: object, expected: type[object], name: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{name} must be an exact {expected.__name__}")


def _require_schema(value: int) -> None:
    if type(value) is not int or value != 1:
        raise ValueError("schema_version must be 1")


def _require_bool(value: bool, name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a boolean")


def _require_bounded_int(
    value: int,
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> None:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{name} is outside its allowed range")


def _require_bounded_float(value: float, name: str, *, maximum: float) -> None:
    if type(value) is not float or not math.isfinite(value) or value <= 0.0 or value > maximum:
        raise ValueError(f"{name} is outside its allowed range")


def _require_tuple(value: object, name: str, *, minimum: int, maximum: int) -> None:
    if type(value) is not tuple or not minimum <= len(value) <= maximum:
        raise ValueError(f"{name} must be an exact tuple within its allowed size")


def _require_pattern(value: str, pattern: re.Pattern[str], name: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} has an invalid format")


def _require_utf8(value: str, name: str) -> bytes:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be valid UTF-8") from error


def _require_text(value: str, name: str, *, min_bytes: int, max_bytes: int) -> None:
    encoded = _require_utf8(value, name)
    if not min_bytes <= len(encoded) <= max_bytes:
        raise ValueError(f"{name} is outside its allowed byte size")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} contains a control character")


def _require_subject(value: str) -> None:
    _require_text(value, "subject", min_bytes=1, max_bytes=256)


def _require_sha256_fields(value: object, *names: str) -> None:
    for name in names:
        _require_pattern(getattr(value, name), _SHA256_PATTERN, name)


def _require_paths(value: tuple[str, ...], name: str, *, minimum: int, maximum: int) -> None:
    _canonical_repository_paths(value, name, minimum=minimum, maximum=maximum)


def _require_ids(value: tuple[str, ...], name: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    for item in value:
        _require_pattern(item, _SESSION_PATTERN, name)
    if tuple(sorted(value)) != value or len(set(value)) != len(value):
        raise ValueError(f"{name} must be unique and sorted")


def _require_timestamp_order(started_at_us: int, finished_at_us: int) -> None:
    _require_bounded_int(started_at_us, "started_at_us", minimum=0)
    _require_bounded_int(finished_at_us, "finished_at_us", minimum=0)
    if finished_at_us < started_at_us:
        raise ValueError("finish timestamp precedes start timestamp")


def _validate_snapshot_shape(value: RepairSnapshot) -> None:
    candidate = value.candidate
    validation = value.validation
    approval = value.approval
    application = value.application
    if candidate is not None and value.state is RepairState.CREATED:
        raise ValueError("candidate is inconsistent with state")
    if validation is not None:
        if candidate is None:
            raise ValueError("validation requires candidate")
        if validation.candidate_id != candidate.candidate_id:
            raise ValueError("validation candidate does not match snapshot")
    if approval is not None:
        if candidate is None or validation is None or not validation.success:
            raise ValueError("approval requires successful validation")
        if (
            approval.candidate_id != candidate.candidate_id
            or approval.validation_sha256 != validation.validation_sha256
        ):
            raise ValueError("approval does not match snapshot")
    if application is not None:
        if value.state is not RepairState.APPLIED:
            raise ValueError("application requires applied state")
        if candidate is None or approval is None:
            raise ValueError("application requires approval")
        if (
            application.approval_sha256 != approval.approval_sha256
            or application.commit_oid != candidate.commit_oid
            or application.ref != f"refs/repoguard/repairs/{candidate.candidate_id}"
        ):
            raise ValueError("application does not match snapshot")
    if value.decision is not None and value.decision.state is not value.state:
        raise ValueError("decision does not match state")
    if value.failure is not None and value.state is not RepairState.FAILED:
        raise ValueError("failure metadata requires failed state")
    if candidate is not None and candidate.request_sha256 != value.request_sha256:
        raise ValueError("candidate request does not match snapshot")
    if value.decision is not None and (
        value.decision.candidate_id is not None
        and (candidate is None or value.decision.candidate_id != candidate.candidate_id)
    ):
        raise ValueError("decision candidate does not match snapshot")
    requires_candidate = {
        RepairState.VALIDATING,
        RepairState.VALIDATED,
        RepairState.APPROVED,
        RepairState.APPLYING,
        RepairState.APPLIED,
        RepairState.REJECTED,
    }
    if value.state in requires_candidate and candidate is None:
        raise ValueError("state requires candidate")
    requires_successful_validation = {
        RepairState.VALIDATED,
        RepairState.APPROVED,
        RepairState.APPLYING,
        RepairState.APPLIED,
        RepairState.REJECTED,
    }
    if value.state in requires_successful_validation and (
        validation is None or not validation.success
    ):
        raise ValueError("state requires successful validation")
    if value.state in {RepairState.APPROVED, RepairState.APPLYING, RepairState.APPLIED} and (
        approval is None
    ):
        raise ValueError("state requires approval")
    if value.state is RepairState.APPLIED and application is None:
        raise ValueError("applied state requires application")
    if value.state in {RepairState.REJECTED, RepairState.CANCELLED, RepairState.EXPIRED} and (
        value.decision is None
    ):
        raise ValueError("decision state requires decision")
    if value.state is RepairState.FAILED and value.failure is None:
        raise ValueError("failed state requires failure metadata")
    terminal = {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }
    if value.cleanup_pending and value.state not in terminal:
        raise ValueError("cleanup_pending requires terminal state")
