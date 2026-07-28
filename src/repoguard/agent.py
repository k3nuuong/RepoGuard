"""Immutable public models for controlled Agent review."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum

from repoguard.evidence import EvidenceBundle, RepositoryEvidence, RevisionEvidence
from repoguard.providers import LLMProvider, TokenUsage
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    FindingCategory,
    FindingSeverity,
    RuleId,
)

__all__ = [
    "AgentFinding",
    "AgentNode",
    "AgentReviewConfig",
    "AgentReviewError",
    "AgentReviewErrorCode",
    "AgentReviewResult",
    "AgentRuleId",
    "FindingSource",
    "PromptIdentity",
    "agent_review_to_dict",
    "agent_review_to_json",
    "review_with_agent",
]

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class FindingSource(StrEnum):
    """Origin of a finding in an Agent review."""

    DETERMINISTIC = "deterministic"
    AGENT = "agent"


class AgentRuleId(StrEnum):
    """Stable identifier assigned to model-derived findings."""

    AGENT_REASONING = "agent_reasoning"


class AgentNode(StrEnum):
    """Stable location in the controlled Agent workflow."""

    VALIDATE = "validate"
    DETERMINISTIC_REVIEW = "deterministic_review"
    BUILD_PROMPT = "build_prompt"
    INVOKE_PROVIDER = "invoke_provider"
    PARSE_RESPONSE = "parse_response"
    MERGE_FINDINGS = "merge_findings"
    FINALIZE = "finalize"


class AgentReviewErrorCode(StrEnum):
    """Stable category for a controlled Agent review failure."""

    UNSUPPORTED_EVIDENCE_SCHEMA = "unsupported_evidence_schema"
    INVALID_EVIDENCE = "invalid_evidence"
    INVALID_CONFIGURATION = "invalid_configuration"
    CONTEXT_LIMIT_EXCEEDED = "context_limit_exceeded"
    PROVIDER_AUTHENTICATION_FAILED = "provider_authentication_failed"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_REQUEST_FAILED = "provider_request_failed"
    PROVIDER_REFUSED = "provider_refused"
    INVALID_MODEL_OUTPUT = "invalid_model_output"
    BUDGET_EXCEEDED = "budget_exceeded"
    WORKFLOW_EXECUTION_FAILED = "workflow_execution_failed"


class AgentReviewError(RuntimeError):
    """Atomic Agent review failure with a stable, secret-safe contract."""

    code: AgentReviewErrorCode
    node: AgentNode
    attempt_count: int

    def __init__(
        self,
        code: AgentReviewErrorCode,
        node: AgentNode,
        attempt_count: int,
        message: str,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.node = node
        self.attempt_count = attempt_count


@dataclass(frozen=True, slots=True)
class AgentReviewConfig:
    """Explicit model selection and hard workflow budgets."""

    model: str
    max_prompt_bytes: int = 131_072
    max_output_tokens: int = 4_096
    max_response_bytes: int = 524_288
    max_model_findings: int = 100
    max_references_per_finding: int = 8
    max_title_chars: int = 120
    max_message_chars: int = 1_000
    max_remediation_chars: int = 1_000
    per_attempt_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 95.0
    max_attempts: int = 3


@dataclass(frozen=True, slots=True)
class PromptIdentity:
    """Version and content digest of the trusted prompt resources."""

    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if self.name != "agent_review":
            msg = "prompt name must be agent_review"
            raise ValueError(msg)
        if self.version != "v1":
            msg = "prompt version must be v1"
            raise ValueError(msg)
        if _SHA256_PATTERN.fullmatch(self.sha256) is None:
            msg = "prompt sha256 must be lowercase hexadecimal"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class AgentFinding:
    """One deterministic or locally validated model finding."""

    source: FindingSource
    rule_id: RuleId | AgentRuleId
    category: FindingCategory
    severity: FindingSeverity
    title: str
    message: str
    remediation: str
    references: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, FindingSource):
            msg = "source must be a FindingSource"
            raise ValueError(msg)
        if not isinstance(self.category, FindingCategory):
            msg = "category must be a FindingCategory"
            raise ValueError(msg)
        if not isinstance(self.severity, FindingSeverity):
            msg = "severity must be a FindingSeverity"
            raise ValueError(msg)
        if type(self.references) is not tuple or not self.references:
            msg = "references must be a non-empty built-in tuple"
            raise ValueError(msg)
        if not all(isinstance(reference, EvidenceReference) for reference in self.references):
            msg = "references must contain EvidenceReference values"
            raise ValueError(msg)
        if not all(isinstance(reference.side, EvidenceSide) for reference in self.references):
            msg = "reference side must be an EvidenceSide"
            raise ValueError(msg)
        for reference in self.references:
            if type(reference.path) is not str or not reference.path:
                msg = "reference path must be a non-empty string"
                raise ValueError(msg)
            try:
                reference.path.encode("utf-8")
            except UnicodeEncodeError as error:
                msg = "reference path must be valid UTF-8"
                raise ValueError(msg) from error
            if type(reference.oid) is not str or _OID_PATTERN.fullmatch(reference.oid) is None:
                msg = "reference oid must be a lowercase Git object ID"
                raise ValueError(msg)
            start = reference.start_line
            end = reference.end_line
            if not (
                (start is None and end is None)
                or (type(start) is int and type(end) is int and 1 <= start <= end)
            ):
                msg = "reference lines must be null or an ordered positive range"
                raise ValueError(msg)
        if any(type(value) is not str for value in (self.title, self.message, self.remediation)):
            msg = "finding text fields must be strings"
            raise ValueError(msg)
        if self.source is FindingSource.DETERMINISTIC and not isinstance(self.rule_id, RuleId):
            msg = "deterministic findings require an M2 RuleId"
            raise ValueError(msg)
        if self.source is FindingSource.AGENT and not isinstance(self.rule_id, AgentRuleId):
            msg = "agent findings require an AgentRuleId"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class AgentReviewResult:
    """Versioned result of one complete controlled Agent review."""

    repository: RepositoryEvidence
    revisions: RevisionEvidence
    provider: str
    model: str
    prompt: PromptIdentity
    attempt_count: int
    usage: TokenUsage | None
    prompt_bytes: int
    response_bytes: int
    findings: tuple[AgentFinding, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)
        if type(self.attempt_count) is not int or self.attempt_count < 1:
            msg = "attempt_count must be a positive integer"
            raise ValueError(msg)
        if type(self.prompt_bytes) is not int or self.prompt_bytes < 0:
            msg = "prompt_bytes must be a non-negative integer"
            raise ValueError(msg)
        if type(self.response_bytes) is not int or self.response_bytes < 0:
            msg = "response_bytes must be a non-negative integer"
            raise ValueError(msg)
        if type(self.findings) is not tuple:
            msg = "findings must be a built-in tuple"
            raise ValueError(msg)


def review_with_agent(
    bundle: EvidenceBundle,
    *,
    provider: LLMProvider,
    config: AgentReviewConfig,
) -> AgentReviewResult:
    """Run one bounded Agent review over immutable M1 evidence."""
    from repoguard._agent import _review_with_agent

    return _review_with_agent(bundle, provider=provider, config=config)


def agent_review_to_dict(result: AgentReviewResult) -> dict[str, object]:
    """Convert an Agent review result to its canonical JSON-compatible mapping."""
    return {
        "schema_version": result.schema_version,
        "repository": {
            "root": str(result.repository.root),
            "object_format": result.repository.object_format,
        },
        "revisions": {
            "base_ref": result.revisions.base_ref,
            "head_ref": result.revisions.head_ref,
            "base_oid": result.revisions.base_oid,
            "head_oid": result.revisions.head_oid,
            "merge_base_oid": result.revisions.merge_base_oid,
        },
        "provider": result.provider,
        "model": result.model,
        "prompt": {
            "name": result.prompt.name,
            "version": result.prompt.version,
            "sha256": result.prompt.sha256,
        },
        "attempt_count": result.attempt_count,
        "usage": None if result.usage is None else _usage_to_dict(result.usage),
        "prompt_bytes": result.prompt_bytes,
        "response_bytes": result.response_bytes,
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }


def agent_review_to_json(result: AgentReviewResult) -> str:
    """Serialize Agent review as compact canonical UTF-8 JSON."""
    return json.dumps(
        agent_review_to_dict(result),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _usage_to_dict(usage: TokenUsage) -> dict[str, object]:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.total_tokens,
    }


def _finding_to_dict(finding: AgentFinding) -> dict[str, object]:
    return {
        "source": finding.source.value,
        "rule_id": finding.rule_id.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "references": [
            {
                "path": reference.path,
                "side": reference.side.value,
                "oid": reference.oid,
                "start_line": reference.start_line,
                "end_line": reference.end_line,
            }
            for reference in finding.references
        ],
    }
