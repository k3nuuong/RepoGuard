"""M5 query derivation and exact live M4 batch-retrieval adapter."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import NoReturn

from repoguard._repair_input import _context_identity_to_dict
from repoguard._repair_models import _domain_digest
from repoguard._retrieval_agent import _identifier_parts, _path_terms, _safe_python_identifiers
from repoguard.evidence import DiffLineKind, EvidenceBundle
from repoguard.repair import (
    RepairContextOutcome,
    RepairContextSummary,
    RepairError,
    RepairErrorCode,
    RepairGenerationPolicy,
    RepairStage,
    RepairState,
    RepairTarget,
)
from repoguard.retrieval import (
    ContextIndex,
    ContextQuery,
    IndexIdentity,
    IndexStatistics,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
)
from repoguard.review import EvidenceSide, ReviewResult, RuleId

_WORD_PATTERN = re.compile(r"[^\W_][\w]*", re.UNICODE)
_DEGRADED_CODES = {
    RetrievalErrorCode.INDEX_CLOSED: "closed_index",
    RetrievalErrorCode.DEADLINE_EXCEEDED: "deadline_exceeded",
    RetrievalErrorCode.BACKEND_FAILED: "backend_failure",
}

_monotonic = time.monotonic


@dataclass(frozen=True, slots=True)
class _RepairContextHit:
    path: str
    oid: str
    start_line: int
    end_line: int
    content: str
    definitions: tuple[str, ...]
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RepairContextResult:
    summary: RepairContextSummary
    hits: tuple[_RepairContextHit, ...]


def _derive_repair_queries(
    bundle: EvidenceBundle,
    review: ReviewResult,
    targets: tuple[RepairTarget, ...],
    policy: RepairGenerationPolicy,
) -> tuple[ContextQuery, ...]:
    if (
        type(bundle) is not EvidenceBundle
        or type(review) is not ReviewResult
        or type(targets) is not tuple
        or any(type(target) is not RepairTarget for target in targets)
        or type(policy) is not RepairGenerationPolicy
    ):
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.RETRIEVAL, None, None)
    queries: list[ContextQuery] = []
    seen: set[str] = set()
    for target in targets:
        if target.finding_index >= len(review.findings):
            _raise_repair(RepairErrorCode.INVALID_TARGETS, RepairStage.RETRIEVAL, None, None)
        finding = review.findings[target.finding_index]
        if target.reference_index >= len(finding.references):
            _raise_repair(RepairErrorCode.INVALID_TARGETS, RepairStage.RETRIEVAL, None, None)
        reference = finding.references[target.reference_index]
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL:
            continue
        if (
            reference.side is not EvidenceSide.NEW
            or reference.start_line is None
            or reference.end_line is None
        ):
            _raise_repair(RepairErrorCode.INVALID_TARGETS, RepairStage.RETRIEVAL, None, None)
        terms: list[str] = [
            finding.rule_id.value,
            finding.category.value,
            finding.severity.value,
            *_identifier_parts(finding.rule_id.value),
            *_path_terms(reference.path),
            *_text_terms(finding.title),
            *_text_terms(finding.remediation),
            *_new_python_identifiers(
                bundle,
                reference.path,
                reference.start_line,
                reference.end_line,
            ),
        ]
        query_text = _fit_terms(tuple(terms), policy.max_query_bytes)
        if query_text and query_text not in seen:
            seen.add(query_text)
            queries.append(ContextQuery(query_text))
        if len(queries) == policy.max_queries:
            break
    return tuple(queries)


def _context_index_identity_sha256(value: IndexIdentity) -> str:
    if type(value) is not IndexIdentity:
        raise TypeError("value must be an exact IndexIdentity")
    return _domain_digest("context", {"index_identity": _context_identity_to_dict(value)})


def _retrieve_repair_context(
    *,
    expected_identity: IndexIdentity | None,
    index: ContextIndex | None,
    queries: tuple[ContextQuery, ...],
    policy: RepairGenerationPolicy,
    deadline: float,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> _RepairContextResult:
    if type(policy) is not RepairGenerationPolicy or type(deadline) is not float:
        _raise_repair(RepairErrorCode.INVALID_CONFIG, RepairStage.RETRIEVAL, state, session_id)
    if type(queries) is not tuple or any(type(query) is not ContextQuery for query in queries):
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.RETRIEVAL, state, session_id)
    if expected_identity is None:
        if index is not None:
            _raise_repair(
                RepairErrorCode.IDENTITY_MISMATCH,
                RepairStage.RETRIEVAL,
                state,
                session_id,
            )
        return _RepairContextResult(
            RepairContextSummary(
                RepairContextOutcome.NOT_REQUESTED,
                None,
                None,
                0,
                0,
                0,
                None,
                None,
            ),
            (),
        )
    if type(expected_identity) is not IndexIdentity or type(index) is not ContextIndex:
        _raise_repair(
            RepairErrorCode.IDENTITY_MISMATCH,
            RepairStage.RETRIEVAL,
            state,
            session_id,
        )
    identity_sha256 = _context_index_identity_sha256(expected_identity)
    query_sha256 = _domain_digest("context", {"queries": [query.text for query in queries]})
    retrieval_error: RetrievalErrorCode | None = None
    invalid_identity = False
    unexpected_failure = False
    result: RetrievalResult | None = None
    backend_query_sha256: str | None = None
    try:
        _validate_live_index(index, expected_identity, deadline)
        if queries:
            from repoguard._retrieval import (
                _retrieve_context_queries,
                _validated_query_digest,
            )

            result = _retrieve_context_queries(index, queries, deadline=deadline)
            backend_query_sha256 = _validated_query_digest(tuple(query.text for query in queries))
    except RetrievalError as error:
        retrieval_error = error.code if type(error.code) is RetrievalErrorCode else None
        if retrieval_error is None:
            invalid_identity = True
    except (TypeError, ValueError):
        invalid_identity = True
    except Exception:
        unexpected_failure = True
    if invalid_identity:
        _raise_repair(
            RepairErrorCode.IDENTITY_MISMATCH,
            RepairStage.RETRIEVAL,
            state,
            session_id,
        )
    if unexpected_failure:
        _raise_repair(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.RETRIEVAL,
            state,
            session_id,
        )
    if retrieval_error is not None:
        degradation = _DEGRADED_CODES.get(retrieval_error)
        if degradation is not None:
            return _RepairContextResult(
                RepairContextSummary(
                    RepairContextOutcome.DEGRADED,
                    identity_sha256,
                    query_sha256,
                    len(queries),
                    0,
                    0,
                    None,
                    degradation,
                ),
                (),
            )
        _raise_retrieval_error(retrieval_error, state, session_id)
    if result is None:
        hit_identity_sha256 = _domain_digest("context", {"hits": []})
        return _RepairContextResult(
            RepairContextSummary(
                RepairContextOutcome.USED,
                identity_sha256,
                query_sha256,
                0,
                0,
                0,
                hit_identity_sha256,
                None,
            ),
            (),
        )
    if (
        type(result) is not RetrievalResult
        or result.index != expected_identity
        or result.query_sha256 != backend_query_sha256
        or type(result.hits) is not tuple
        or any(type(hit) is not RetrievalHit for hit in result.hits)
        or result.selected_count != len(result.hits)
        or len(result.hits) > policy.max_context_hits
    ):
        _raise_repair(
            RepairErrorCode.IDENTITY_MISMATCH,
            RepairStage.RETRIEVAL,
            state,
            session_id,
        )
    hits = tuple(_project_hit(hit) for hit in result.hits)
    hit_identity_sha256 = _domain_digest(
        "context",
        {"hits": [_hit_identity_mapping(hit) for hit in hits]},
    )
    return _RepairContextResult(
        RepairContextSummary(
            RepairContextOutcome.USED,
            identity_sha256,
            query_sha256,
            len(queries),
            result.candidate_count,
            len(hits),
            hit_identity_sha256,
            None,
        ),
        hits,
    )


def _validate_live_index(index: ContextIndex, expected: IndexIdentity, deadline: float) -> None:
    from repoguard._retrieval import (
        _config_sha256,
        _model_identity,
        _validate_initialized_provider,
        _validated_state,
    )

    index_state = _validated_state(index)
    remaining = deadline - _monotonic()
    if remaining <= 0 or not index_state._lock.acquire(timeout=max(0.0, remaining)):
        raise RetrievalError(RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalStage.VALIDATE)
    try:
        identity = index_state.identity
        statistics = index_state.statistics
        _provider_name, actual_device = _validate_initialized_provider(index_state._provider)
        model, revision, manifest, dimension = _model_identity(index_state._provider)
        if (
            type(identity) is not IndexIdentity
            or type(statistics) is not IndexStatistics
            or replace(identity) != identity
            or replace(statistics) != statistics
            or identity != expected
            or identity.channels != index_state._config.channels
            or identity.config_sha256 != _config_sha256(index_state._config)
            or identity.actual_device is not actual_device
            or (
                identity.model,
                identity.model_revision,
                identity.manifest_sha256,
                identity.dimension,
            )
            != (model, revision, manifest, dimension)
        ):
            raise ValueError("live context index identity is invalid")
    finally:
        index_state._lock.release()


def _new_python_identifiers(
    bundle: EvidenceBundle,
    path: str,
    start_line: int,
    end_line: int,
) -> tuple[str, ...]:
    if PurePosixPath(path).suffix not in {".py", ".pyi"}:
        return ()
    result: list[str] = []
    for change in bundle.changes:
        if change.new is None or change.new.path != path:
            continue
        for hunk in change.hunks:
            for line in hunk.lines:
                if (
                    line.kind is DiffLineKind.ADDITION
                    and line.new_line_number is not None
                    and start_line <= line.new_line_number <= end_line
                ):
                    result.extend(_safe_python_identifiers(line.content.lstrip(" \t\f")))
    return tuple(sorted(set(result), key=_utf8))


def _text_terms(value: str) -> tuple[str, ...]:
    result: list[str] = []
    for match in _WORD_PATTERN.finditer(value):
        result.extend(_identifier_parts(match.group(0)))
    return tuple(sorted(set(result), key=_utf8))


def _fit_terms(terms: tuple[str, ...], maximum_bytes: int) -> str:
    selected: list[str] = []
    for term in sorted(set(terms), key=_utf8):
        if not term or any(character.isspace() for character in term):
            continue
        try:
            term_size = len(term.encode("utf-8"))
        except UnicodeEncodeError:
            continue
        if term_size > maximum_bytes:
            continue
        candidate = " ".join((*selected, term))
        if len(candidate.encode("utf-8")) <= maximum_bytes:
            selected.append(term)
    return " ".join(selected)


def _project_hit(value: RetrievalHit) -> _RepairContextHit:
    chunk = value.chunk
    provenance = chunk.provenance
    return _RepairContextHit(
        provenance.path,
        provenance.oid,
        provenance.start_line,
        provenance.end_line,
        chunk.content,
        chunk.definitions,
        chunk.references,
    )


def _hit_identity_mapping(value: _RepairContextHit) -> dict[str, object]:
    return {
        "path": value.path,
        "oid": value.oid,
        "start_line": value.start_line,
        "end_line": value.end_line,
        "content_sha256": hashlib.sha256(value.content.encode("utf-8")).hexdigest(),
        "definitions": list(value.definitions),
        "references": list(value.references),
    }


def _raise_retrieval_error(
    code: RetrievalErrorCode,
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    repair_code = {
        RetrievalErrorCode.GIT_UNAVAILABLE: RepairErrorCode.GIT_UNAVAILABLE,
        RetrievalErrorCode.READ_FAILED: RepairErrorCode.GIT_FAILED,
        RetrievalErrorCode.MISSING_OBJECT: RepairErrorCode.MISSING_OBJECT,
        RetrievalErrorCode.QUERY_LIMIT_EXCEEDED: RepairErrorCode.RESOURCE_LIMIT,
    }.get(code, RepairErrorCode.INVALID_WORKFLOW)
    _raise_repair(repair_code, RepairStage.RETRIEVAL, state, session_id)


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _raise_repair(
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
