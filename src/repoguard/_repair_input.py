"""Exact input freezing and persisted request decoding for safe repair."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from repoguard._repair_models import (
    _canonical_bytes,
    _domain_digest,
    _exact_bool,
    _exact_int,
    _exact_list,
    _exact_mapping,
    _exact_str,
    _optional_int,
    _repair_generation_policy_from_dict,
    _repair_prompt_identity_from_dict,
    _repair_target_from_dict,
    _validation_policy_from_dict,
)
from repoguard._repair_paths import _canonical_repository_paths
from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    FileChangeEvidence,
    FileVersion,
    RepositoryEvidence,
    RepositoryInput,
    RevisionEvidence,
    evidence_to_dict,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairPromptIdentity,
    RepairStage,
    RepairTarget,
    ValidationPolicy,
    repair_generation_policy_to_dict,
    repair_prompt_identity_to_dict,
    repair_target_to_dict,
    validation_policy_to_dict,
)
from repoguard.retrieval import (
    EmbeddingDevice,
    IndexIdentity,
    RetrievalChannel,
)
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReviewResult,
    RuleId,
    review_to_dict,
)

_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODE = re.compile(r"^[0-7]{6}$")
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
_DEGRADATION_CODES = (
    "backend_failure",
    "closed_index",
    "deadline_exceeded",
)


@dataclass(frozen=True, slots=True)
class _RepairRepositoryIdentity:
    """Resolved Git identity captured before request validation."""

    worktree_root: Path
    common_dir: Path
    object_format: str
    head_oid: str

    def __post_init__(self) -> None:
        for name in ("worktree_root", "common_dir"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute pathlib.Path")
            if not _is_utf8(str(value)):
                raise ValueError(f"{name} must be valid UTF-8")
        oid_length = _OID_LENGTHS.get(self.object_format)
        if type(self.object_format) is not str or oid_length is None:
            raise ValueError("object_format must be sha1 or sha256")
        if not _is_oid(self.head_oid, oid_length):
            raise ValueError("head_oid must match object_format")


@dataclass(frozen=True, slots=True)
class _FrozenRepairRequest:
    """Deeply reconstructed private request read from canonical storage."""

    schema_version: int
    request_sha256: str
    repository: _RepairRepositoryIdentity
    evidence: EvidenceBundle
    review: ReviewResult
    targets: tuple[RepairTarget, ...]
    allowed_paths: tuple[str, ...]
    generation: RepairGenerationPolicy
    validation: ValidationPolicy
    prompt: RepairPromptIdentity
    context_identity: IndexIdentity | None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        if type(self.request_sha256) is not str or _SHA256.fullmatch(self.request_sha256) is None:
            raise ValueError("request_sha256 is invalid")
        if type(self.repository) is not _RepairRepositoryIdentity:
            raise TypeError("repository must be an exact _RepairRepositoryIdentity")
        if type(self.evidence) is not EvidenceBundle:
            raise TypeError("evidence must be an exact EvidenceBundle")
        if type(self.review) is not ReviewResult:
            raise TypeError("review must be an exact ReviewResult")
        if type(self.targets) is not tuple:
            raise TypeError("targets must be an exact tuple")
        if type(self.allowed_paths) is not tuple:
            raise TypeError("allowed_paths must be an exact tuple")
        if type(self.generation) is not RepairGenerationPolicy:
            raise TypeError("generation must be an exact RepairGenerationPolicy")
        if type(self.validation) is not ValidationPolicy:
            raise TypeError("validation must be an exact ValidationPolicy")
        if type(self.prompt) is not RepairPromptIdentity:
            raise TypeError("prompt must be an exact RepairPromptIdentity")
        if self.context_identity is not None and type(self.context_identity) is not IndexIdentity:
            raise TypeError("context_identity must be an exact IndexIdentity or None")


def _freeze_repair_request(
    repository: RepositoryInput,
    current: _RepairRepositoryIdentity,
    bundle: EvidenceBundle,
    review: ReviewResult,
    *,
    targets: tuple[RepairTarget, ...],
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy,
    validation: ValidationPolicy,
    prompt: RepairPromptIdentity,
    context_identity: IndexIdentity | None = None,
) -> dict[str, object]:
    """Validate and freeze one create-session request as a canonical mapping."""
    _validate_manager_binding(repository, current)
    frozen_repository = _clone_repository_identity(current, RepairErrorCode.INVALID_CONFIG)
    frozen_evidence = _clone_evidence(bundle)
    frozen_review = _clone_review(review, frozen_evidence)
    _validate_request_identity(frozen_repository, frozen_evidence, frozen_review)
    frozen_generation = _clone_generation(generation)
    frozen_validation = _clone_validation(validation)
    frozen_prompt = _clone_prompt(prompt)
    frozen_context = _clone_context_identity(context_identity)
    _validate_context_identity(frozen_repository, frozen_context)
    frozen_paths = _clone_allowed_paths(allowed_paths)
    frozen_targets = _clone_targets(
        targets,
        review=frozen_review,
        evidence=frozen_evidence,
        allowed_paths=frozen_paths,
        generation=frozen_generation,
    )
    payload = _request_payload_to_dict(
        frozen_repository,
        frozen_evidence,
        frozen_review,
        frozen_targets,
        frozen_paths,
        frozen_generation,
        frozen_validation,
        frozen_prompt,
        frozen_context,
    )
    return {"request_sha256": _domain_digest("request", payload), **payload}


def _repair_request_to_dict(value: _FrozenRepairRequest) -> dict[str, object]:
    """Convert a validated frozen request back to its canonical mapping."""
    if type(value) is not _FrozenRepairRequest:
        raise TypeError("value must be an exact _FrozenRepairRequest")
    _validate_decoded_request(value)
    payload = _request_payload_to_dict(
        value.repository,
        value.evidence,
        value.review,
        value.targets,
        value.allowed_paths,
        value.generation,
        value.validation,
        value.prompt,
        value.context_identity,
    )
    expected = _domain_digest("request", payload)
    if value.request_sha256 != expected:
        raise ValueError("request digest does not match request content")
    return {"request_sha256": value.request_sha256, **payload}


def _repair_request_from_dict(value: object) -> _FrozenRepairRequest:
    """Decode an exact persisted request and revalidate all semantic bindings."""
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "request_sha256",
            "repository",
            "evidence",
            "review",
            "targets",
            "allowed_paths",
            "generation",
            "validation",
            "prompt",
            "context_identity",
            "retrieval_policy",
            "patch_policy",
            "commit_policy",
        },
    )
    generation = _repair_generation_policy_from_dict(mapping["generation"])
    request = _FrozenRepairRequest(
        _exact_int(mapping["schema_version"]),
        _exact_str(mapping["request_sha256"]),
        _repository_identity_from_dict(mapping["repository"]),
        _evidence_from_dict(mapping["evidence"]),
        _review_from_dict(mapping["review"]),
        tuple(_repair_target_from_dict(item) for item in _exact_list(mapping["targets"])),
        tuple(_exact_str(item) for item in _exact_list(mapping["allowed_paths"])),
        generation,
        _validation_policy_from_dict(mapping["validation"]),
        _repair_prompt_identity_from_dict(mapping["prompt"]),
        _optional_context_identity_from_dict(mapping["context_identity"]),
    )
    _require_exact_policy(
        mapping["retrieval_policy"],
        _retrieval_policy_to_dict(generation),
    )
    _require_exact_policy(mapping["patch_policy"], _patch_policy_to_dict(generation))
    _require_exact_policy(mapping["commit_policy"], _commit_policy_to_dict())
    _validate_decoded_request(request)
    payload = _request_payload_to_dict(
        request.repository,
        request.evidence,
        request.review,
        request.targets,
        request.allowed_paths,
        request.generation,
        request.validation,
        request.prompt,
        request.context_identity,
    )
    if request.request_sha256 != _domain_digest("request", payload):
        raise ValueError("request digest does not match request content")
    return request


def _request_payload_to_dict(
    repository: _RepairRepositoryIdentity,
    evidence: EvidenceBundle,
    review: ReviewResult,
    targets: tuple[RepairTarget, ...],
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy,
    validation: ValidationPolicy,
    prompt: RepairPromptIdentity,
    context_identity: IndexIdentity | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "repository": _repository_identity_to_dict(repository),
        "evidence": evidence_to_dict(evidence),
        "review": review_to_dict(review),
        "targets": [repair_target_to_dict(target) for target in targets],
        "allowed_paths": list(allowed_paths),
        "generation": repair_generation_policy_to_dict(generation),
        "validation": validation_policy_to_dict(validation),
        "prompt": repair_prompt_identity_to_dict(prompt),
        "context_identity": (
            None if context_identity is None else _context_identity_to_dict(context_identity)
        ),
        "retrieval_policy": _retrieval_policy_to_dict(generation),
        "patch_policy": _patch_policy_to_dict(generation),
        "commit_policy": _commit_policy_to_dict(),
    }


def _retrieval_policy_to_dict(generation: RepairGenerationPolicy) -> dict[str, object]:
    return {
        "schema_version": 1,
        "algorithm": "m4_batch_rrf",
        "max_queries": generation.max_queries,
        "max_query_bytes": generation.max_query_bytes,
        "max_context_hits": generation.max_context_hits,
        "degradation_codes": list(_DEGRADATION_CODES),
    }


def _patch_policy_to_dict(generation: RepairGenerationPolicy) -> dict[str, object]:
    return {
        "schema_version": 1,
        "grammar": "minimal_unified_diff",
        "line_endings": "lf",
        "allow_modified_files": True,
        "allow_new_files": True,
        "allow_deletions": False,
        "allow_extended_headers": False,
        "max_patch_bytes": generation.max_patch_bytes,
        "max_patch_paths": generation.max_patch_paths,
        "max_changed_lines": generation.max_changed_lines,
    }


def _commit_policy_to_dict() -> dict[str, object]:
    return {
        "schema_version": 1,
        "author_name": "RepoGuard",
        "author_email": "repoguard@localhost",
        "committer_name": "RepoGuard",
        "committer_email": "repoguard@localhost",
        "timestamp": 0,
        "timezone": "+0000",
        "message": "RepoGuard safe repair candidate\n",
    }


def _validate_decoded_request(value: _FrozenRepairRequest) -> None:
    failed = False
    try:
        _validate_evidence(value.evidence)
        _validate_review(value.review, value.evidence)
        _validate_request_identity(value.repository, value.evidence, value.review)
        _validate_policy_records(value.generation, value.validation, value.prompt)
        _validate_context_identity(value.repository, value.context_identity)
        _validate_allowed_paths(value.allowed_paths)
        _validate_targets(
            value.targets,
            review=value.review,
            evidence=value.evidence,
            allowed_paths=value.allowed_paths,
            generation=value.generation,
        )
    except RepairError:
        failed = True
    if failed:
        raise ValueError("persisted repair request is invalid")


def _validate_manager_binding(
    repository: RepositoryInput,
    current: _RepairRepositoryIdentity,
) -> None:
    if type(repository) is not RepositoryInput:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    if type(current) is not _RepairRepositoryIdentity:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    if not isinstance(repository.path, Path) or not _is_utf8(str(repository.path)):
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    resolve_failed = False
    try:
        resolved = repository.path.resolve(strict=False)
    except OSError:
        resolve_failed = True
        resolved = repository.path
    if resolve_failed:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    mismatch = False
    try:
        resolved.relative_to(current.worktree_root)
    except ValueError:
        mismatch = True
    if mismatch:
        _raise_input(RepairErrorCode.IDENTITY_MISMATCH)


def _validate_request_identity(
    current: _RepairRepositoryIdentity,
    bundle: EvidenceBundle,
    review: ReviewResult,
) -> None:
    if (
        bundle.repository != review.repository
        or bundle.revisions != review.revisions
        or bundle.repository.root != current.worktree_root
        or bundle.repository.object_format != current.object_format
        or bundle.revisions.head_oid != current.head_oid
    ):
        _raise_input(RepairErrorCode.IDENTITY_MISMATCH)


def _clone_repository_identity(
    value: _RepairRepositoryIdentity,
    code: RepairErrorCode,
) -> _RepairRepositoryIdentity:
    failed = False
    try:
        cloned = _repository_identity_from_dict(_repository_identity_to_dict(value))
    except (AttributeError, TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(code)
    return cloned


def _clone_evidence(value: EvidenceBundle) -> EvidenceBundle:
    if type(value) is not EvidenceBundle:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    if type(value.schema_version) is not int or value.schema_version != 1:
        _raise_input(RepairErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA)
    _validate_evidence(value)
    failed = False
    try:
        cloned = _evidence_from_dict(evidence_to_dict(value))
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    _validate_evidence(cloned)
    return cloned


def _clone_review(value: ReviewResult, evidence: EvidenceBundle) -> ReviewResult:
    if type(value) is not ReviewResult:
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    if type(value.schema_version) is not int or value.schema_version != 1:
        _raise_input(RepairErrorCode.UNSUPPORTED_REVIEW_SCHEMA)
    _validate_review(value, evidence)
    failed = False
    try:
        cloned = _review_from_dict(review_to_dict(value))
    except (AttributeError, TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    _validate_review(cloned, evidence)
    return cloned


def _clone_generation(value: RepairGenerationPolicy) -> RepairGenerationPolicy:
    if type(value) is not RepairGenerationPolicy:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    failed = False
    try:
        cloned = _repair_generation_policy_from_dict(repair_generation_policy_to_dict(value))
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    return cloned


def _clone_validation(value: ValidationPolicy) -> ValidationPolicy:
    if type(value) is not ValidationPolicy:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    failed = False
    try:
        cloned = _validation_policy_from_dict(validation_policy_to_dict(value))
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    return cloned


def _clone_prompt(value: RepairPromptIdentity) -> RepairPromptIdentity:
    if type(value) is not RepairPromptIdentity:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    failed = False
    try:
        cloned = _repair_prompt_identity_from_dict(repair_prompt_identity_to_dict(value))
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    return cloned


def _clone_context_identity(value: IndexIdentity | None) -> IndexIdentity | None:
    if value is None:
        return None
    if type(value) is not IndexIdentity:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    failed = False
    try:
        cloned = _context_identity_from_dict(_context_identity_to_dict(value))
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    return cloned


def _clone_allowed_paths(value: tuple[str, ...]) -> tuple[str, ...]:
    _validate_allowed_paths(value)
    return tuple(value)


def _validate_allowed_paths(value: tuple[str, ...]) -> None:
    failed = False
    try:
        _canonical_repository_paths(value, "allowed_paths", minimum=1, maximum=32)
    except (TypeError, ValueError):
        failed = True
    if failed:
        _raise_input(RepairErrorCode.INVALID_PATH)


def _clone_targets(
    value: tuple[RepairTarget, ...],
    *,
    review: ReviewResult,
    evidence: EvidenceBundle,
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy,
) -> tuple[RepairTarget, ...]:
    _validate_targets(
        value,
        review=review,
        evidence=evidence,
        allowed_paths=allowed_paths,
        generation=generation,
    )
    failed = False
    try:
        cloned = tuple(_repair_target_from_dict(repair_target_to_dict(target)) for target in value)
    except (TypeError, ValueError):
        failed = True
        cloned = value
    if failed:
        _raise_input(RepairErrorCode.INVALID_TARGETS)
    return cloned


def _validate_targets(
    value: tuple[RepairTarget, ...],
    *,
    review: ReviewResult,
    evidence: EvidenceBundle,
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy,
) -> None:
    if type(value) is not tuple or not 1 <= len(value) <= 16:
        _raise_input(RepairErrorCode.INVALID_TARGETS)
    if any(type(target) is not RepairTarget for target in value):
        _raise_input(RepairErrorCode.INVALID_TARGETS)
    coordinates = tuple((target.finding_index, target.reference_index) for target in value)
    if (
        tuple(sorted(coordinates)) != coordinates
        or len(set(coordinates)) != len(coordinates)
        or any(
            type(finding_index) is not int
            or type(reference_index) is not int
            or finding_index < 0
            or reference_index < 0
            for finding_index, reference_index in coordinates
        )
    ):
        _raise_input(RepairErrorCode.INVALID_TARGETS)

    versions = _evidence_versions(evidence)
    private_count = 0
    for target in value:
        if target.finding_index >= len(review.findings):
            _raise_input(RepairErrorCode.INVALID_TARGETS)
        finding = review.findings[target.finding_index]
        if target.reference_index >= len(finding.references):
            _raise_input(RepairErrorCode.INVALID_TARGETS)
        reference = finding.references[target.reference_index]
        version = versions.get((reference.path, reference.side))
        if (
            reference.side is not EvidenceSide.NEW
            or reference.start_line is None
            or reference.end_line is None
            or version is None
            or version.content_kind is not ContentKind.TEXT
            or not version.mode.startswith("100")
            or reference.path not in allowed_paths
        ):
            _raise_input(RepairErrorCode.INVALID_TARGETS)
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL:
            private_count += 1

    if generation.mode is RepairGenerationMode.DETERMINISTIC:
        valid_mode = private_count == len(value)
    elif generation.mode is RepairGenerationMode.PROVIDER:
        valid_mode = private_count == 0
    else:
        valid_mode = 0 < private_count < len(value)
    if not valid_mode:
        _raise_input(RepairErrorCode.INVALID_TARGETS)


def _validate_evidence(value: EvidenceBundle) -> None:
    if type(value) is not EvidenceBundle:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    if type(value.schema_version) is not int or value.schema_version != 1:
        _raise_input(RepairErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA)
    if (
        type(value.repository) is not RepositoryEvidence
        or type(value.revisions) is not RevisionEvidence
        or type(value.changes) is not tuple
    ):
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    _validate_repository_record(value.repository, RepairErrorCode.INVALID_EVIDENCE)
    oid_length = _OID_LENGTHS[value.repository.object_format]
    _validate_revision_record(value.revisions, oid_length, RepairErrorCode.INVALID_EVIDENCE)

    seen_versions: set[tuple[EvidenceSide, str]] = set()
    for change in value.changes:
        _validate_change(change, oid_length, seen_versions)
    if tuple(sorted(value.changes, key=_change_sort_key)) != value.changes:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)


def _validate_repository_record(
    value: RepositoryEvidence,
    code: RepairErrorCode,
) -> None:
    if type(value) is not RepositoryEvidence:
        _raise_input(code)
    if not isinstance(value.root, Path) or not value.root.is_absolute():
        _raise_input(code)
    if not _is_utf8(str(value.root)):
        _raise_input(code)
    if type(value.object_format) is not str or value.object_format not in _OID_LENGTHS:
        _raise_input(code)


def _validate_revision_record(
    value: RevisionEvidence,
    oid_length: int,
    code: RepairErrorCode,
) -> None:
    if type(value) is not RevisionEvidence:
        _raise_input(code)
    for ref in (value.base_ref, value.head_ref):
        if type(ref) is not str or not ref or "\0" in ref or not _is_utf8(ref):
            _raise_input(code)
    for oid in (value.base_oid, value.head_oid, value.merge_base_oid):
        if not _is_oid(oid, oid_length):
            _raise_input(code)


def _validate_change(
    value: object,
    oid_length: int,
    seen_versions: set[tuple[EvidenceSide, str]],
) -> None:
    if (
        type(value) is not FileChangeEvidence
        or type(value.change_type) is not ChangeType
        or type(value.hunks) is not tuple
    ):
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    if value.change_type is ChangeType.RENAMED:
        if type(value.rename_similarity) is not int or not 0 <= value.rename_similarity <= 100:
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    elif value.rename_similarity is not None:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)

    if value.change_type is ChangeType.ADDED:
        valid_sides = value.old is None and value.new is not None
    elif value.change_type is ChangeType.DELETED:
        valid_sides = value.old is not None and value.new is None
    else:
        valid_sides = value.old is not None and value.new is not None
    if not valid_sides:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)

    for side, version in ((EvidenceSide.OLD, value.old), (EvidenceSide.NEW, value.new)):
        if version is None:
            continue
        _validate_version(version, oid_length)
        key = (side, version.path)
        if key in seen_versions:
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
        seen_versions.add(key)

    if value.old is not None and value.new is not None:
        same_path = value.old.path == value.new.path
        if (value.change_type is ChangeType.RENAMED) == same_path:
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    existing = tuple(version for version in (value.old, value.new) if version is not None)
    if value.hunks and any(version.content_kind is not ContentKind.TEXT for version in existing):
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)

    old_numbers: set[int] = set()
    new_numbers: set[int] = set()
    hunk_coordinates: list[tuple[int, int]] = []
    for hunk in value.hunks:
        _validate_hunk(hunk, old_numbers, new_numbers)
        hunk_coordinates.append((hunk.old_start, hunk.new_start))
    if hunk_coordinates != sorted(hunk_coordinates) or len(set(hunk_coordinates)) != len(
        hunk_coordinates
    ):
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)


def _validate_version(value: object, oid_length: int) -> None:
    if (
        type(value) is not FileVersion
        or type(value.path) is not str
        or type(value.mode) is not str
        or type(value.content_kind) is not ContentKind
        or _MODE.fullmatch(value.mode) is None
        or not _is_oid(value.oid, oid_length)
        or not _is_evidence_path(value.path)
    ):
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    expected: tuple[ContentKind, ...]
    if value.mode == "120000":
        expected = (ContentKind.SYMLINK,)
    elif value.mode == "160000":
        expected = (ContentKind.SUBMODULE,)
    elif value.mode.startswith("100"):
        expected = (ContentKind.TEXT, ContentKind.BINARY)
    else:
        expected = (ContentKind.OTHER,)
    if value.content_kind not in expected:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)


def _validate_hunk(
    value: object,
    old_numbers: set[int],
    new_numbers: set[int],
) -> None:
    if type(value) is not DiffHunkEvidence or type(value.lines) is not tuple:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    for coordinate in (value.old_start, value.old_count, value.new_start, value.new_count):
        if type(coordinate) is not int or coordinate < 0:
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
    expected_old = value.old_start
    expected_new = value.new_start
    observed_old = 0
    observed_new = 0
    for line in value.lines:
        if (
            type(line) is not DiffLineEvidence
            or type(line.kind) is not DiffLineKind
            or type(line.content) is not str
            or type(line.has_trailing_newline) is not bool
            or not _is_utf8(line.content)
        ):
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
        required_old = None if line.kind is DiffLineKind.ADDITION else expected_old
        required_new = None if line.kind is DiffLineKind.DELETION else expected_new
        if line.old_line_number != required_old or line.new_line_number != required_new:
            _raise_input(RepairErrorCode.INVALID_EVIDENCE)
        if line.old_line_number is not None:
            if (
                type(line.old_line_number) is not int
                or line.old_line_number < 1
                or line.old_line_number in old_numbers
            ):
                _raise_input(RepairErrorCode.INVALID_EVIDENCE)
            old_numbers.add(line.old_line_number)
            expected_old += 1
            observed_old += 1
        if line.new_line_number is not None:
            if (
                type(line.new_line_number) is not int
                or line.new_line_number < 1
                or line.new_line_number in new_numbers
            ):
                _raise_input(RepairErrorCode.INVALID_EVIDENCE)
            new_numbers.add(line.new_line_number)
            expected_new += 1
            observed_new += 1
    if observed_old != value.old_count or observed_new != value.new_count:
        _raise_input(RepairErrorCode.INVALID_EVIDENCE)


def _validate_review(value: ReviewResult, evidence: EvidenceBundle) -> None:
    if type(value) is not ReviewResult:
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    if type(value.schema_version) is not int or value.schema_version != 1:
        _raise_input(RepairErrorCode.UNSUPPORTED_REVIEW_SCHEMA)
    if (
        type(value.repository) is not RepositoryEvidence
        or type(value.revisions) is not RevisionEvidence
        or type(value.findings) is not tuple
    ):
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    _validate_repository_record(value.repository, RepairErrorCode.INVALID_REVIEW)
    oid_length = _OID_LENGTHS[value.repository.object_format]
    _validate_revision_record(value.revisions, oid_length, RepairErrorCode.INVALID_REVIEW)
    versions = _evidence_versions(evidence)
    line_ranges = _evidence_line_ranges(evidence)

    seen_findings: set[tuple[RuleId, tuple[EvidenceReference, ...]]] = set()
    for finding in value.findings:
        _validate_finding(finding, oid_length, versions, line_ranges)
        key = (finding.rule_id, finding.references)
        if key in seen_findings:
            _raise_input(RepairErrorCode.INVALID_REVIEW)
        seen_findings.add(key)
    if tuple(sorted(value.findings, key=_finding_sort_key)) != value.findings:
        _raise_input(RepairErrorCode.INVALID_REVIEW)


def _validate_finding(
    value: object,
    oid_length: int,
    versions: dict[tuple[str, EvidenceSide], FileVersion],
    line_ranges: dict[tuple[str, EvidenceSide], tuple[frozenset[int], ...]],
) -> None:
    if (
        type(value) is not Finding
        or type(value.rule_id) is not RuleId
        or type(value.category) is not FindingCategory
        or type(value.severity) is not FindingSeverity
        or type(value.references) is not tuple
        or not value.references
    ):
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    for text in (value.title, value.message, value.remediation):
        if not _is_safe_review_text(text):
            _raise_input(RepairErrorCode.INVALID_REVIEW)
    for reference in value.references:
        _validate_reference(reference, oid_length, versions, line_ranges)
    if tuple(sorted(value.references, key=_reference_sort_key)) != value.references or len(
        set(value.references)
    ) != len(value.references):
        _raise_input(RepairErrorCode.INVALID_REVIEW)


def _validate_reference(
    value: object,
    oid_length: int,
    versions: dict[tuple[str, EvidenceSide], FileVersion],
    line_ranges: dict[tuple[str, EvidenceSide], tuple[frozenset[int], ...]],
) -> None:
    if (
        type(value) is not EvidenceReference
        or type(value.path) is not str
        or type(value.side) is not EvidenceSide
        or not _is_evidence_path(value.path)
        or not _is_oid(value.oid, oid_length)
    ):
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    version = versions.get((value.path, value.side))
    if version is None or version.oid != value.oid:
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    start = value.start_line
    end = value.end_line
    if start is None or end is None:
        if start is not None or end is not None:
            _raise_input(RepairErrorCode.INVALID_REVIEW)
        return
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        _raise_input(RepairErrorCode.INVALID_REVIEW)
    required = range(start, end + 1)
    if not any(
        all(line in hunk_lines for line in required)
        for hunk_lines in line_ranges[(value.path, value.side)]
    ):
        _raise_input(RepairErrorCode.INVALID_REVIEW)


def _validate_policy_records(
    generation: RepairGenerationPolicy,
    validation: ValidationPolicy,
    prompt: RepairPromptIdentity,
) -> None:
    if (
        type(generation) is not RepairGenerationPolicy
        or type(validation) is not ValidationPolicy
        or type(prompt) is not RepairPromptIdentity
    ):
        _raise_input(RepairErrorCode.INVALID_CONFIG)


def _validate_context_identity(
    repository: _RepairRepositoryIdentity,
    context: IndexIdentity | None,
) -> None:
    if context is None:
        return
    if type(context) is not IndexIdentity:
        _raise_input(RepairErrorCode.INVALID_CONFIG)
    if (
        context.repository_root != repository.worktree_root
        or context.object_format != repository.object_format
        or context.head_oid != repository.head_oid
    ):
        _raise_input(RepairErrorCode.IDENTITY_MISMATCH)


def _evidence_versions(evidence: EvidenceBundle) -> dict[tuple[str, EvidenceSide], FileVersion]:
    result: dict[tuple[str, EvidenceSide], FileVersion] = {}
    for change in evidence.changes:
        if change.old is not None:
            result[(change.old.path, EvidenceSide.OLD)] = change.old
        if change.new is not None:
            result[(change.new.path, EvidenceSide.NEW)] = change.new
    return result


def _evidence_line_ranges(
    evidence: EvidenceBundle,
) -> dict[tuple[str, EvidenceSide], tuple[frozenset[int], ...]]:
    result: dict[tuple[str, EvidenceSide], tuple[frozenset[int], ...]] = {}
    for change in evidence.changes:
        for side, version in (
            (EvidenceSide.OLD, change.old),
            (EvidenceSide.NEW, change.new),
        ):
            if version is None:
                continue
            ranges: list[frozenset[int]] = []
            for hunk in change.hunks:
                numbers = frozenset(
                    number
                    for line in hunk.lines
                    for number in (
                        line.old_line_number if side is EvidenceSide.OLD else line.new_line_number,
                    )
                    if number is not None
                )
                ranges.append(numbers)
            result[(version.path, side)] = tuple(ranges)
    return result


def _change_sort_key(value: FileChangeEvidence) -> tuple[bytes, bytes]:
    if value.new is not None:
        primary = value.new.path
    elif value.old is not None:
        primary = value.old.path
    else:
        raise ValueError("change has no side")
    secondary = value.old.path if value.old is not None else primary
    return primary.encode("utf-8"), secondary.encode("utf-8")


def _finding_sort_key(value: Finding) -> tuple[object, ...]:
    first = value.references[0]
    return (
        _SEVERITY_RANK[value.severity],
        first.path.encode("utf-8"),
        _line_sort_value(first.start_line),
        _line_sort_value(first.end_line),
        value.rule_id.value,
        tuple(_reference_sort_key(reference) for reference in value.references),
    )


def _reference_sort_key(value: EvidenceReference) -> tuple[object, ...]:
    return (
        value.path.encode("utf-8"),
        value.side.value,
        value.oid,
        _line_sort_value(value.start_line),
        _line_sort_value(value.end_line),
    )


def _line_sort_value(value: int | None) -> int:
    return 0 if value is None else value


def _repository_identity_to_dict(value: _RepairRepositoryIdentity) -> dict[str, object]:
    if type(value) is not _RepairRepositoryIdentity:
        raise TypeError("value must be an exact _RepairRepositoryIdentity")
    return {
        "worktree_root": str(value.worktree_root),
        "common_dir": str(value.common_dir),
        "object_format": value.object_format,
        "head_oid": value.head_oid,
    }


def _repository_identity_from_dict(value: object) -> _RepairRepositoryIdentity:
    mapping = _exact_mapping(
        value,
        {"worktree_root", "common_dir", "object_format", "head_oid"},
    )
    return _RepairRepositoryIdentity(
        Path(_exact_str(mapping["worktree_root"])),
        Path(_exact_str(mapping["common_dir"])),
        _exact_str(mapping["object_format"]),
        _exact_str(mapping["head_oid"]),
    )


def _context_identity_to_dict(value: IndexIdentity) -> dict[str, object]:
    if type(value) is not IndexIdentity:
        raise TypeError("value must be an exact IndexIdentity")
    return {
        "schema_version": value.schema_version,
        "repository_root": str(value.repository_root),
        "object_format": value.object_format,
        "head_oid": value.head_oid,
        "channels": [channel.value for channel in value.channels],
        "config_sha256": value.config_sha256,
        "model": value.model,
        "model_revision": value.model_revision,
        "manifest_sha256": value.manifest_sha256,
        "dimension": value.dimension,
        "actual_device": value.actual_device.value,
    }


def _context_identity_from_dict(value: object) -> IndexIdentity:
    mapping = _exact_mapping(
        value,
        {
            "schema_version",
            "repository_root",
            "object_format",
            "head_oid",
            "channels",
            "config_sha256",
            "model",
            "model_revision",
            "manifest_sha256",
            "dimension",
            "actual_device",
        },
    )
    return IndexIdentity(
        Path(_exact_str(mapping["repository_root"])),
        _exact_str(mapping["object_format"]),
        _exact_str(mapping["head_oid"]),
        tuple(
            _enum_from_value(RetrievalChannel, item) for item in _exact_list(mapping["channels"])
        ),
        _exact_str(mapping["config_sha256"]),
        _exact_str(mapping["model"]),
        _exact_str(mapping["model_revision"]),
        _exact_str(mapping["manifest_sha256"]),
        _exact_int(mapping["dimension"]),
        _enum_from_value(EmbeddingDevice, mapping["actual_device"]),
        _exact_int(mapping["schema_version"]),
    )


def _optional_context_identity_from_dict(value: object) -> IndexIdentity | None:
    if value is None:
        return None
    return _context_identity_from_dict(value)


def _evidence_from_dict(value: object) -> EvidenceBundle:
    mapping = _exact_mapping(value, {"schema_version", "repository", "revisions", "changes"})
    return EvidenceBundle(
        _repository_evidence_from_dict(mapping["repository"]),
        _revision_evidence_from_dict(mapping["revisions"]),
        tuple(_change_from_dict(item) for item in _exact_list(mapping["changes"])),
        _exact_int(mapping["schema_version"]),
    )


def _repository_evidence_from_dict(value: object) -> RepositoryEvidence:
    mapping = _exact_mapping(value, {"root", "object_format"})
    return RepositoryEvidence(
        Path(_exact_str(mapping["root"])),
        _exact_str(mapping["object_format"]),
    )


def _revision_evidence_from_dict(value: object) -> RevisionEvidence:
    mapping = _exact_mapping(
        value,
        {"base_ref", "head_ref", "base_oid", "head_oid", "merge_base_oid"},
    )
    return RevisionEvidence(
        _exact_str(mapping["base_ref"]),
        _exact_str(mapping["head_ref"]),
        _exact_str(mapping["base_oid"]),
        _exact_str(mapping["head_oid"]),
        _exact_str(mapping["merge_base_oid"]),
    )


def _change_from_dict(value: object) -> FileChangeEvidence:
    mapping = _exact_mapping(
        value,
        {"change_type", "rename_similarity", "old", "new", "hunks"},
    )
    return FileChangeEvidence(
        _enum_from_value(ChangeType, mapping["change_type"]),
        _optional_int(mapping["rename_similarity"]),
        _optional_version_from_dict(mapping["old"]),
        _optional_version_from_dict(mapping["new"]),
        tuple(_hunk_from_dict(item) for item in _exact_list(mapping["hunks"])),
    )


def _optional_version_from_dict(value: object) -> FileVersion | None:
    if value is None:
        return None
    mapping = _exact_mapping(value, {"path", "mode", "oid", "content_kind"})
    return FileVersion(
        _exact_str(mapping["path"]),
        _exact_str(mapping["mode"]),
        _exact_str(mapping["oid"]),
        _enum_from_value(ContentKind, mapping["content_kind"]),
    )


def _hunk_from_dict(value: object) -> DiffHunkEvidence:
    mapping = _exact_mapping(
        value,
        {"old_start", "old_count", "new_start", "new_count", "lines"},
    )
    return DiffHunkEvidence(
        _exact_int(mapping["old_start"]),
        _exact_int(mapping["old_count"]),
        _exact_int(mapping["new_start"]),
        _exact_int(mapping["new_count"]),
        tuple(_line_from_dict(item) for item in _exact_list(mapping["lines"])),
    )


def _line_from_dict(value: object) -> DiffLineEvidence:
    mapping = _exact_mapping(
        value,
        {
            "kind",
            "old_line_number",
            "new_line_number",
            "content",
            "has_trailing_newline",
        },
    )
    return DiffLineEvidence(
        _enum_from_value(DiffLineKind, mapping["kind"]),
        _optional_int(mapping["old_line_number"]),
        _optional_int(mapping["new_line_number"]),
        _exact_str(mapping["content"]),
        _exact_bool(mapping["has_trailing_newline"]),
    )


def _review_from_dict(value: object) -> ReviewResult:
    mapping = _exact_mapping(value, {"schema_version", "repository", "revisions", "findings"})
    return ReviewResult(
        _repository_evidence_from_dict(mapping["repository"]),
        _revision_evidence_from_dict(mapping["revisions"]),
        tuple(_finding_from_dict(item) for item in _exact_list(mapping["findings"])),
        _exact_int(mapping["schema_version"]),
    )


def _finding_from_dict(value: object) -> Finding:
    mapping = _exact_mapping(
        value,
        {
            "rule_id",
            "category",
            "severity",
            "title",
            "message",
            "remediation",
            "references",
        },
    )
    return Finding(
        _enum_from_value(RuleId, mapping["rule_id"]),
        _enum_from_value(FindingCategory, mapping["category"]),
        _enum_from_value(FindingSeverity, mapping["severity"]),
        _exact_str(mapping["title"]),
        _exact_str(mapping["message"]),
        _exact_str(mapping["remediation"]),
        tuple(_reference_from_dict(item) for item in _exact_list(mapping["references"])),
    )


def _reference_from_dict(value: object) -> EvidenceReference:
    mapping = _exact_mapping(
        value,
        {"path", "side", "oid", "start_line", "end_line"},
    )
    return EvidenceReference(
        _exact_str(mapping["path"]),
        _enum_from_value(EvidenceSide, mapping["side"]),
        _exact_str(mapping["oid"]),
        _optional_int(mapping["start_line"]),
        _optional_int(mapping["end_line"]),
    )


def _require_exact_policy(value: object, expected: dict[str, object]) -> None:
    if type(value) is not dict:
        raise TypeError("request policy must be an exact mapping")
    if _canonical_bytes(value) != _canonical_bytes(expected):
        raise ValueError("request policy does not match the fixed policy")


def _enum_from_value[E: StrEnum](enum_type: type[E], value: object) -> E:
    text = _exact_str(value)
    try:
        return enum_type(text)
    except ValueError:
        raise ValueError("record enum value is invalid") from None


def _is_oid(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and _LOWER_HEX.fullmatch(value) is not None


def _is_utf8(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _is_evidence_path(value: object) -> bool:
    if type(value) is not str or not value or not _is_utf8(value):
        return False
    return not (
        value.startswith("/")
        or "\0" in value
        or value in {".", ".."}
        or any(component in {"", ".", ".."} for component in value.split("/"))
    )


def _is_safe_review_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and _is_utf8(value)
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _raise_input(code: RepairErrorCode) -> NoReturn:
    error = RepairError(code, RepairStage.INPUT)
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    error.__suppress_context__ = True
    raise error from None
