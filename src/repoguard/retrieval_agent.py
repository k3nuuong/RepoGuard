"""Public contracts for Agent review with hybrid repository context."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum

from repoguard.agent import AgentFinding, AgentReviewConfig
from repoguard.evidence import EvidenceBundle, RepositoryEvidence, RevisionEvidence
from repoguard.providers import LLMProvider, TokenUsage
from repoguard.retrieval import (
    ChunkProvenance,
    ContextIndex,
    EmbeddingDevice,
    IndexIdentity,
    RetrievalChannel,
    RetrievalErrorCode,
)
from repoguard.review import EvidenceReference

__all__ = [
    "RetrievalAgentNode",
    "RetrievalAgentReviewConfig",
    "RetrievalAgentReviewError",
    "RetrievalAgentReviewErrorCode",
    "RetrievalAgentReviewResult",
    "RetrievalChunkSummary",
    "RetrievalPromptIdentity",
    "RetrievalSummary",
    "retrieval_agent_review_to_dict",
    "retrieval_agent_review_to_json",
    "review_with_retrieval",
]

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHANNEL_ORDER = {
    RetrievalChannel.TEXT: 0,
    RetrievalChannel.VECTOR: 1,
    RetrievalChannel.SYMBOL: 2,
}


class RetrievalAgentNode(StrEnum):
    """Stable location in an Agent review with retrieval."""

    VALIDATE = "validate"
    DETERMINISTIC_REVIEW = "deterministic_review"
    RETRIEVE_CONTEXT = "retrieve_context"
    BUILD_PROMPT = "build_prompt"
    INVOKE_PROVIDER = "invoke_provider"
    PARSE_RESPONSE = "parse_response"
    MERGE_FINDINGS = "merge_findings"
    FINALIZE = "finalize"


class RetrievalAgentReviewErrorCode(StrEnum):
    """Stable category for a retrieval-enhanced Agent review failure."""

    UNSUPPORTED_EVIDENCE_SCHEMA = "unsupported_evidence_schema"
    INVALID_EVIDENCE = "invalid_evidence"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_INDEX = "invalid_index"
    RETRIEVAL_FAILED = "retrieval_failed"
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


_ERROR_MESSAGES = {
    RetrievalAgentReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA: ("unsupported evidence schema"),
    RetrievalAgentReviewErrorCode.INVALID_EVIDENCE: "invalid review evidence",
    RetrievalAgentReviewErrorCode.INVALID_CONFIGURATION: (
        "invalid retrieval Agent review configuration"
    ),
    RetrievalAgentReviewErrorCode.INVALID_INDEX: "invalid context index",
    RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED: "context retrieval failed",
    RetrievalAgentReviewErrorCode.CONTEXT_LIMIT_EXCEEDED: (
        "retrieval Agent review context limit exceeded"
    ),
    RetrievalAgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED: (
        "provider authentication failed"
    ),
    RetrievalAgentReviewErrorCode.PROVIDER_RATE_LIMITED: ("provider rate limit exceeded"),
    RetrievalAgentReviewErrorCode.PROVIDER_TIMEOUT: "provider request timed out",
    RetrievalAgentReviewErrorCode.PROVIDER_UNAVAILABLE: "provider is unavailable",
    RetrievalAgentReviewErrorCode.PROVIDER_REQUEST_FAILED: "provider request failed",
    RetrievalAgentReviewErrorCode.PROVIDER_REFUSED: ("provider refused the review request"),
    RetrievalAgentReviewErrorCode.INVALID_MODEL_OUTPUT: "model output is invalid",
    RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED: ("retrieval Agent review budget exceeded"),
    RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED: (
        "retrieval Agent review workflow failed"
    ),
}


class RetrievalAgentReviewError(RuntimeError):
    """Atomic retrieval Agent failure with stable, secret-safe fields."""

    code: RetrievalAgentReviewErrorCode
    node: RetrievalAgentNode
    attempt_count: int
    retrieval_code: RetrievalErrorCode | None

    def __init__(
        self,
        code: RetrievalAgentReviewErrorCode,
        node: RetrievalAgentNode,
        attempt_count: int,
        retrieval_code: RetrievalErrorCode | None = None,
    ) -> None:
        if not isinstance(code, RetrievalAgentReviewErrorCode):
            msg = "code must be RetrievalAgentReviewErrorCode"
            raise TypeError(msg)
        if not isinstance(node, RetrievalAgentNode):
            msg = "node must be RetrievalAgentNode"
            raise TypeError(msg)
        if type(attempt_count) is not int or attempt_count < 0:
            msg = "attempt_count must be a non-negative integer"
            raise ValueError(msg)
        if code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED:
            if not isinstance(retrieval_code, RetrievalErrorCode):
                msg = "retrieval_failed requires a RetrievalErrorCode"
                raise ValueError(msg)
        elif retrieval_code is not None:
            msg = "retrieval_code is only valid for retrieval_failed"
            raise ValueError(msg)
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code
        self.node = node
        self.attempt_count = attempt_count
        self.retrieval_code = retrieval_code


@dataclass(frozen=True, slots=True)
class RetrievalAgentReviewConfig:
    """M3 review policy plus caller-lowerable retrieval prompt ceilings."""

    agent: AgentReviewConfig
    max_queries: int = 256
    max_query_bytes: int = 2_048
    max_retrieved_prompt_bytes: int = 65_536


@dataclass(frozen=True, slots=True)
class RetrievalPromptIdentity:
    """Version and digest of the trusted v2 prompt resources."""

    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if self.name != "agent_review":
            msg = "prompt name must be agent_review"
            raise ValueError(msg)
        if self.version != "v2":
            msg = "prompt version must be v2"
            raise ValueError(msg)
        if type(self.sha256) is not str or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            msg = "prompt sha256 must be lowercase hexadecimal"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RetrievalChunkSummary:
    """Content-free identity and fused ranks for one prompt chunk."""

    provenance: ChunkProvenance
    channels: tuple[RetrievalChannel, ...]
    text_rank: int | None
    vector_rank: int | None
    symbol_rank: int | None
    matched_query_count: int
    rrf_score: int

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, ChunkProvenance):
            msg = "provenance must be ChunkProvenance"
            raise ValueError(msg)
        _validate_channels(self.channels)
        ranks = {
            RetrievalChannel.TEXT: self.text_rank,
            RetrievalChannel.VECTOR: self.vector_rank,
            RetrievalChannel.SYMBOL: self.symbol_rank,
        }
        for channel, rank in ranks.items():
            if channel in self.channels:
                if type(rank) is not int or rank <= 0:
                    msg = "contributing channel ranks must be positive integers"
                    raise ValueError(msg)
            elif rank is not None:
                msg = "non-contributing channel ranks must be None"
                raise ValueError(msg)
        if type(self.matched_query_count) is not int or self.matched_query_count <= 0:
            msg = "matched_query_count must be a positive integer"
            raise ValueError(msg)
        if type(self.rrf_score) is not int or self.rrf_score <= 0:
            msg = "rrf_score must be a positive integer"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RetrievalSummary:
    """Content-free aggregate retrieval evidence sent to the provider."""

    index: IndexIdentity
    actual_device: EmbeddingDevice
    query_count: int
    candidate_count: int
    selected_count: int
    omitted_count: int
    excluded_file_count: int
    unparsed_python_file_count: int
    original_blob_bytes: int
    redacted_chunk_bytes: int
    metadata_bytes: int
    dense_matrix_bytes: int
    logical_index_bytes: int
    chunks: tuple[RetrievalChunkSummary, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.index, IndexIdentity):
            msg = "index must be IndexIdentity"
            raise ValueError(msg)
        if self.actual_device is not self.index.actual_device:
            msg = "actual_device must match index identity"
            raise ValueError(msg)
        values = (
            self.query_count,
            self.candidate_count,
            self.selected_count,
            self.omitted_count,
            self.excluded_file_count,
            self.unparsed_python_file_count,
            self.original_blob_bytes,
            self.redacted_chunk_bytes,
            self.metadata_bytes,
            self.dense_matrix_bytes,
            self.logical_index_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            msg = "retrieval summary counts must be non-negative integers"
            raise ValueError(msg)
        if self.candidate_count != self.selected_count + self.omitted_count:
            msg = "candidate_count must equal selected_count plus omitted_count"
            raise ValueError(msg)
        if type(self.chunks) is not tuple or not all(
            isinstance(chunk, RetrievalChunkSummary) for chunk in self.chunks
        ):
            msg = "chunks must be a built-in tuple of RetrievalChunkSummary values"
            raise ValueError(msg)
        if self.selected_count != len(self.chunks):
            msg = "selected_count must equal the number of chunk summaries"
            raise ValueError(msg)
        components = (
            self.original_blob_bytes
            + self.redacted_chunk_bytes
            + self.metadata_bytes
            + self.dense_matrix_bytes
        )
        if self.logical_index_bytes != components:
            msg = "logical_index_bytes must equal its byte components"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RetrievalAgentReviewResult:
    """Versioned result of one complete retrieval-enhanced Agent review."""

    repository: RepositoryEvidence
    revisions: RevisionEvidence
    provider: str
    model: str
    prompt: RetrievalPromptIdentity
    attempt_count: int
    usage: TokenUsage | None
    prompt_bytes: int
    response_bytes: int
    retrieval: RetrievalSummary
    findings: tuple[AgentFinding, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)
        if not isinstance(self.repository, RepositoryEvidence):
            msg = "repository must be RepositoryEvidence"
            raise ValueError(msg)
        if not isinstance(self.revisions, RevisionEvidence):
            msg = "revisions must be RevisionEvidence"
            raise ValueError(msg)
        if type(self.provider) is not str or not self.provider:
            msg = "provider must be a non-empty string"
            raise ValueError(msg)
        if type(self.model) is not str or not self.model:
            msg = "model must be a non-empty string"
            raise ValueError(msg)
        if not isinstance(self.prompt, RetrievalPromptIdentity):
            msg = "prompt must be RetrievalPromptIdentity"
            raise ValueError(msg)
        if type(self.attempt_count) is not int or self.attempt_count < 1:
            msg = "attempt_count must be a positive integer"
            raise ValueError(msg)
        if self.usage is not None and not isinstance(self.usage, TokenUsage):
            msg = "usage must be TokenUsage or None"
            raise ValueError(msg)
        if type(self.prompt_bytes) is not int or self.prompt_bytes < 0:
            msg = "prompt_bytes must be a non-negative integer"
            raise ValueError(msg)
        if type(self.response_bytes) is not int or self.response_bytes < 0:
            msg = "response_bytes must be a non-negative integer"
            raise ValueError(msg)
        if not isinstance(self.retrieval, RetrievalSummary):
            msg = "retrieval must be RetrievalSummary"
            raise ValueError(msg)
        if type(self.findings) is not tuple or not all(
            isinstance(finding, AgentFinding) for finding in self.findings
        ):
            msg = "findings must be a built-in tuple of AgentFinding values"
            raise ValueError(msg)


def review_with_retrieval(
    bundle: EvidenceBundle,
    *,
    index: ContextIndex,
    provider: LLMProvider,
    config: RetrievalAgentReviewConfig,
) -> RetrievalAgentReviewResult:
    """Run one bounded Agent review with auxiliary committed-head context."""
    from repoguard._retrieval_agent import _review_with_retrieval

    return _review_with_retrieval(
        bundle,
        index=index,
        provider=provider,
        config=config,
    )


def retrieval_agent_review_to_dict(
    result: RetrievalAgentReviewResult,
) -> dict[str, object]:
    """Convert a retrieval Agent result to its canonical JSON-compatible mapping."""
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
        "retrieval": _retrieval_summary_to_dict(result.retrieval),
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }


def retrieval_agent_review_to_json(result: RetrievalAgentReviewResult) -> str:
    """Serialize retrieval Agent review as compact canonical UTF-8 JSON."""
    return json.dumps(
        retrieval_agent_review_to_dict(result),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _retrieval_summary_to_dict(summary: RetrievalSummary) -> dict[str, object]:
    return {
        "index": {
            "schema_version": summary.index.schema_version,
            "repository_root": str(summary.index.repository_root),
            "object_format": summary.index.object_format,
            "head_oid": summary.index.head_oid,
            "channels": [channel.value for channel in summary.index.channels],
            "config_sha256": summary.index.config_sha256,
            "model": summary.index.model,
            "model_revision": summary.index.model_revision,
            "manifest_sha256": summary.index.manifest_sha256,
            "dimension": summary.index.dimension,
            "actual_device": summary.index.actual_device.value,
        },
        "actual_device": summary.actual_device.value,
        "query_count": summary.query_count,
        "candidate_count": summary.candidate_count,
        "selected_count": summary.selected_count,
        "omitted_count": summary.omitted_count,
        "excluded_file_count": summary.excluded_file_count,
        "unparsed_python_file_count": summary.unparsed_python_file_count,
        "original_blob_bytes": summary.original_blob_bytes,
        "redacted_chunk_bytes": summary.redacted_chunk_bytes,
        "metadata_bytes": summary.metadata_bytes,
        "dense_matrix_bytes": summary.dense_matrix_bytes,
        "logical_index_bytes": summary.logical_index_bytes,
        "chunks": [_chunk_summary_to_dict(chunk) for chunk in summary.chunks],
    }


def _chunk_summary_to_dict(summary: RetrievalChunkSummary) -> dict[str, object]:
    provenance = summary.provenance
    return {
        "provenance": {
            "chunk_id": provenance.chunk_id,
            "path": provenance.path,
            "oid": provenance.oid,
            "start_byte": provenance.start_byte,
            "end_byte": provenance.end_byte,
            "start_line": provenance.start_line,
            "end_line": provenance.end_line,
        },
        "channels": [channel.value for channel in summary.channels],
        "text_rank": summary.text_rank,
        "vector_rank": summary.vector_rank,
        "symbol_rank": summary.symbol_rank,
        "matched_query_count": summary.matched_query_count,
        "rrf_score": summary.rrf_score,
    }


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
        "references": [_reference_to_dict(reference) for reference in finding.references],
    }


def _reference_to_dict(reference: EvidenceReference) -> dict[str, object]:
    return {
        "path": reference.path,
        "side": reference.side.value,
        "oid": reference.oid,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
    }


def _validate_channels(channels: object) -> None:
    if (
        type(channels) is not tuple
        or not channels
        or not all(isinstance(channel, RetrievalChannel) for channel in channels)
        or len(set(channels)) != len(channels)
        or tuple(sorted(channels, key=_CHANNEL_ORDER.__getitem__)) != channels
    ):
        msg = "channels must be a non-empty canonical tuple of RetrievalChannel values"
        raise ValueError(msg)
