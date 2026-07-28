"""Immutable public models for deterministic repository review findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from repoguard.evidence import EvidenceBundle, RepositoryEvidence, RevisionEvidence

__all__ = [
    "EvidenceReference",
    "EvidenceSide",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "ReviewError",
    "ReviewErrorCode",
    "ReviewResult",
    "RuleId",
    "review_evidence",
    "review_to_dict",
    "review_to_json",
]


class RuleId(StrEnum):
    """Stable identifier for a deterministic review rule."""

    PRIVATE_KEY_MATERIAL = "private_key_material"
    MERGE_CONFLICT_MARKER = "merge_conflict_marker"
    EXECUTABLE_BIT_ADDED = "executable_bit_added"
    SYMLINK_CHANGED = "symlink_changed"
    SUBMODULE_CHANGED = "submodule_changed"
    BINARY_CONTENT_CHANGED = "binary_content_changed"


class FindingCategory(StrEnum):
    """Stable category assigned to a review finding."""

    SECURITY = "security"
    CORRECTNESS = "correctness"
    REVIEWABILITY = "reviewability"
    SUPPLY_CHAIN = "supply_chain"


class FindingSeverity(StrEnum):
    """Ordered public severity scale for review findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceSide(StrEnum):
    """Side of a repository change referenced by a finding."""

    OLD = "old"
    NEW = "new"


class ReviewErrorCode(StrEnum):
    """Stable category for a deterministic review failure."""

    UNSUPPORTED_EVIDENCE_SCHEMA = "unsupported_evidence_schema"
    INVALID_EVIDENCE = "invalid_evidence"
    RULE_EXECUTION_FAILED = "rule_execution_failed"


class ReviewError(RuntimeError):
    """Atomic review failure with a stable machine-readable code."""

    code: ReviewErrorCode

    def __init__(self, code: ReviewErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Location in collected evidence supporting a finding."""

    path: str
    side: EvidenceSide
    oid: str
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True, slots=True)
class Finding:
    """One deterministic review or security finding."""

    rule_id: RuleId
    category: FindingCategory
    severity: FindingSeverity
    title: str
    message: str
    remediation: str
    references: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        if not self.references:
            msg = "references must not be empty"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ReviewResult:
    """Versioned result of reviewing one evidence bundle."""

    repository: RepositoryEvidence
    revisions: RevisionEvidence
    findings: tuple[Finding, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)


def review_evidence(bundle: EvidenceBundle) -> ReviewResult:
    """Review collected evidence with the fixed deterministic rule catalog."""
    from repoguard._review import _review_evidence

    return _review_evidence(bundle)


def review_to_dict(result: ReviewResult) -> dict[str, object]:
    """Convert a review result to its canonical JSON-compatible mapping."""
    return {
        "schema_version": result.schema_version,
        "repository": _repository_to_dict(result.repository),
        "revisions": _revisions_to_dict(result.revisions),
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }


def review_to_json(result: ReviewResult) -> str:
    """Serialize review output as compact UTF-8 JSON without a trailing newline."""
    return json.dumps(
        review_to_dict(result),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _repository_to_dict(repository: RepositoryEvidence) -> dict[str, object]:
    return {
        "root": str(repository.root),
        "object_format": repository.object_format,
    }


def _revisions_to_dict(revisions: RevisionEvidence) -> dict[str, object]:
    return {
        "base_ref": revisions.base_ref,
        "head_ref": revisions.head_ref,
        "base_oid": revisions.base_oid,
        "head_oid": revisions.head_oid,
        "merge_base_oid": revisions.merge_base_oid,
    }


def _reference_to_dict(reference: EvidenceReference) -> dict[str, object]:
    return {
        "path": reference.path,
        "side": reference.side.value,
        "oid": reference.oid,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
    }


def _finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "references": [_reference_to_dict(reference) for reference in finding.references],
    }
