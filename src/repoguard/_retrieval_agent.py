"""Private retrieval-enhanced Agent workflow."""

from __future__ import annotations

import ast
import io
import keyword
import re
import time
import tokenize
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Never, Protocol, cast

from langgraph.graph.state import CompiledStateGraph

import repoguard._agent as agent_impl
from repoguard._agent import _AgentState, _ProviderBinding
from repoguard._retrieval_prompt import (
    _render_retrieval_prompt,
    _RenderedRetrievalPrompt,
    _RetrievalPromptLimitError,
)
from repoguard._review import _PRIVATE_KEY_MARKER_PATTERN
from repoguard.agent import AgentNode, AgentReviewError, AgentReviewErrorCode
from repoguard.evidence import (
    ContentKind,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    FileChangeEvidence,
)
from repoguard.providers import LLMProvider
from repoguard.retrieval import (
    ContextIndex,
    ContextQuery,
    EmbeddingProvider,
    IndexIdentity,
    IndexStatistics,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
)
from repoguard.retrieval_agent import (
    RetrievalAgentNode,
    RetrievalAgentReviewConfig,
    RetrievalAgentReviewError,
    RetrievalAgentReviewErrorCode,
    RetrievalAgentReviewResult,
    RetrievalChunkSummary,
    RetrievalSummary,
)
from repoguard.review import EvidenceSide, ReviewResult, RuleId

if TYPE_CHECKING:
    from repoguard._retrieval import _PythonLineTerms

_MAX_AUTOMATIC_QUERIES = 256
_MAX_AUTOMATIC_QUERY_BYTES = 2_048
_MAX_RETRIEVED_PROMPT_BYTES = 65_536
_MAX_QUERY_MODEL_TOKENS = 384
_PATH_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_CAMEL_PART = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|\d|\Z)|[A-Z]?[a-z]+|[A-Z]+|\d+",
)


@dataclass(frozen=True, slots=True)
class _RetrievalExtension:
    index: ContextIndex
    query_count: int = 0
    result: RetrievalResult | None = None


@dataclass(frozen=True, slots=True)
class _LineTerms:
    identifiers: tuple[str, ...]
    enclosing_symbol: str | None


@dataclass(frozen=True, slots=True)
class _QuerySeed:
    sort_key: tuple[object, ...]
    terms: tuple[str, ...]


class _TokenSpans(Protocol):
    def __call__(
        self,
        provider: EmbeddingProvider,
        text: str,
        *,
        deadline: float,
        stage: RetrievalStage,
    ) -> tuple[tuple[int, int], ...]: ...


def _review_with_retrieval(
    bundle: EvidenceBundle,
    *,
    index: ContextIndex,
    provider: LLMProvider,
    config: RetrievalAgentReviewConfig,
) -> RetrievalAgentReviewResult:
    final_state: _AgentState | None = None
    failure: (
        tuple[
            RetrievalAgentReviewErrorCode,
            RetrievalAgentNode,
            int,
            RetrievalErrorCode | None,
        ]
        | None
    ) = None
    try:
        invocation_deadline = _validate_inputs(bundle, index=index, config=config)
        initial_state: _AgentState = {
            "bundle": bundle,
            "review": None,
            "rendered": None,
            "extension": _RetrievalExtension(index=index),
            "response": None,
            "candidates": (),
            "findings": (),
            "attempt_count": 0,
            "provider_error": None,
            "deadline": invocation_deadline,
            "response_bytes": 0,
            "usage": None,
            "result": None,
        }
        graph = _build_retrieval_graph(
            provider=provider,
            config=config,
            total_deadline=invocation_deadline,
        )
        final_state = agent_impl._invoke_graph_without_tracing(graph, initial_state)
    except RetrievalAgentReviewError as error:
        if (
            isinstance(error.code, RetrievalAgentReviewErrorCode)
            and isinstance(error.node, RetrievalAgentNode)
            and type(error.attempt_count) is int
            and error.attempt_count >= 0
            and (
                (
                    error.code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
                    and isinstance(error.retrieval_code, RetrievalErrorCode)
                )
                or (
                    error.code is not RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
                    and error.retrieval_code is None
                )
            )
        ):
            failure = (
                error.code,
                error.node,
                error.attempt_count,
                error.retrieval_code,
            )
        else:
            failure = _workflow_failure()
    except AgentReviewError as error:
        failure = _mapped_agent_failure(error)
    except Exception:
        failure = _workflow_failure()

    if failure is not None:
        raise _error(*failure) from None
    if final_state is None:
        raise _error(*_workflow_failure()) from None
    result = final_state.get("result")
    if not isinstance(result, RetrievalAgentReviewResult):
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.FINALIZE,
            _attempt_count(final_state),
        ) from None
    return result


def _build_retrieval_graph(
    *,
    provider: LLMProvider,
    config: RetrievalAgentReviewConfig,
    total_deadline: float,
) -> CompiledStateGraph[_AgentState, None, _AgentState, _AgentState]:
    return agent_impl._build_graph_variant(
        provider=provider,
        config=config.agent,
        retrieval_node=lambda state: _retrieve_context_node(
            state,
            config=config,
            total_deadline=total_deadline,
        ),
        build_prompt_node=lambda state: _build_prompt_node(state, config=config),
        finalize_node=lambda state, binding: _finalize_node(
            state,
            provider_binding=binding,
            config=config,
        ),
        graph_name="repoguard-agent-review-v2",
    )


def _validate_inputs(
    bundle: object,
    *,
    index: object,
    config: object,
) -> float:
    try:
        _validate_configuration(config)
        assert isinstance(config, RetrievalAgentReviewConfig)
        total_deadline = agent_impl._monotonic() + config.agent.total_timeout_seconds
        agent_impl._validate_context_evidence(cast(EvidenceBundle, bundle))
    except AgentReviewError as error:
        raise _error(
            _map_agent_code(error.code),
            RetrievalAgentNode.VALIDATE,
            0,
        ) from None
    except RetrievalAgentReviewError:
        raise
    except Exception:
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.VALIDATE,
            0,
        ) from None

    assert isinstance(bundle, EvidenceBundle)
    try:
        from repoguard._retrieval import (
            _config_sha256,
            _model_identity,
            _validate_initialized_provider,
            _validated_state,
        )

        state = _validated_state(index)
        total_remaining = total_deadline - agent_impl._monotonic()
        if total_remaining <= 0:
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.VALIDATE,
                0,
            )
        query_deadline = time.monotonic() + min(
            total_remaining,
            state._config.query_timeout_seconds,
        )
        lock_timeout = max(0.0, query_deadline - time.monotonic())
        if not state._lock.acquire(timeout=lock_timeout):
            if agent_impl._monotonic() >= total_deadline:
                raise _error(
                    RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                    RetrievalAgentNode.VALIDATE,
                    0,
                )
            raise _error(
                RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED,
                RetrievalAgentNode.VALIDATE,
                0,
                RetrievalErrorCode.DEADLINE_EXCEEDED,
            )
        try:
            identity = state.identity
            statistics = state.statistics
            _provider_name, actual_device = _validate_initialized_provider(state._provider)
            model, revision, manifest, dimension = _model_identity(state._provider)
            if (
                state._closed
                or type(identity) is not IndexIdentity
                or type(statistics) is not IndexStatistics
                or replace(identity) != identity
                or replace(statistics) != statistics
                or identity.repository_root != bundle.repository.root
                or identity.object_format != bundle.repository.object_format
                or identity.head_oid != bundle.revisions.head_oid
                or identity.channels != state._config.channels
                or identity.config_sha256 != _config_sha256(state._config)
                or identity.actual_device is not actual_device
                or (
                    identity.model,
                    identity.model_revision,
                    identity.manifest_sha256,
                    identity.dimension,
                )
                != (model, revision, manifest, dimension)
            ):
                raise ValueError
        finally:
            state._lock.release()
        if agent_impl._monotonic() >= total_deadline:
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.VALIDATE,
                0,
            )
        if time.monotonic() > query_deadline:
            raise _error(
                RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED,
                RetrievalAgentNode.VALIDATE,
                0,
                RetrievalErrorCode.DEADLINE_EXCEEDED,
            )
    except (RetrievalError, TypeError, ValueError):
        raise _error(
            RetrievalAgentReviewErrorCode.INVALID_INDEX,
            RetrievalAgentNode.VALIDATE,
            0,
        ) from None
    except RetrievalAgentReviewError:
        raise
    except Exception:
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.VALIDATE,
            0,
        ) from None
    return total_deadline


def _validate_configuration(value: object) -> None:
    if type(value) is not RetrievalAgentReviewConfig:
        _invalid_configuration()
    assert isinstance(value, RetrievalAgentReviewConfig)
    try:
        agent_impl._validate_configuration(value.agent)
    except AgentReviewError:
        _invalid_configuration()
    limits = (
        (value.max_queries, _MAX_AUTOMATIC_QUERIES),
        (value.max_query_bytes, _MAX_AUTOMATIC_QUERY_BYTES),
        (value.max_retrieved_prompt_bytes, _MAX_RETRIEVED_PROMPT_BYTES),
    )
    if any(type(current) is not int or not 1 <= current <= maximum for current, maximum in limits):
        _invalid_configuration()


def _retrieve_context_node(
    state: _AgentState,
    *,
    config: RetrievalAgentReviewConfig,
    total_deadline: float,
) -> dict[str, object]:
    effective_total_deadline = total_deadline
    try:
        review = state["review"]
        extension = _extension(state)
        if review is None:
            raise RuntimeError
        effective_total_deadline = min(state["deadline"], total_deadline)
        remaining = effective_total_deadline - agent_impl._monotonic()
        if remaining <= 0:
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                state["attempt_count"],
            )
        from repoguard._retrieval import (
            _retrieve_context_queries,
            _token_spans,
            _validated_state,
        )

        index_state = _validated_state(extension.index)
        retrieval_deadline = time.monotonic() + min(
            remaining,
            index_state._config.query_timeout_seconds,
        )
        lock_timeout = max(0.0, retrieval_deadline - time.monotonic())
        if not index_state._lock.acquire(timeout=lock_timeout):
            raise RetrievalError(
                RetrievalErrorCode.DEADLINE_EXCEEDED,
                RetrievalStage.VALIDATE,
            )
        try:
            if index_state._closed:
                raise RetrievalError(
                    RetrievalErrorCode.INDEX_CLOSED,
                    RetrievalStage.VALIDATE,
                )
            seeds = _automatic_query_seeds(
                state["bundle"],
                review,
                head_line_terms=index_state._python_line_terms,
                deadline=retrieval_deadline,
            )
            _check_retrieval_deadline(retrieval_deadline)
            queries = _queries_from_seeds(
                seeds,
                provider=index_state._provider,
                max_queries=config.max_queries,
                max_bytes=config.max_query_bytes,
                deadline=retrieval_deadline,
                token_spans=_token_spans,
            )
            _check_retrieval_deadline(retrieval_deadline)
            result = (
                None
                if not queries
                else _retrieve_context_queries(
                    extension.index,
                    queries,
                    deadline=retrieval_deadline,
                )
            )
        finally:
            index_state._lock.release()
        if agent_impl._monotonic() >= effective_total_deadline:
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                state["attempt_count"],
            )
        return {
            "extension": replace(
                extension,
                query_count=len(queries),
                result=result,
            ),
            "deadline": effective_total_deadline,
        }
    except RetrievalAgentReviewError:
        raise
    except RetrievalError as error:
        if error.code in (RetrievalErrorCode.INVALID_INDEX, RetrievalErrorCode.INDEX_CLOSED):
            raise _error(
                RetrievalAgentReviewErrorCode.INVALID_INDEX,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                state["attempt_count"],
            ) from None
        if (
            error.code is RetrievalErrorCode.DEADLINE_EXCEEDED
            and agent_impl._monotonic() >= effective_total_deadline
        ):
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                state["attempt_count"],
            ) from None
        if isinstance(error.code, RetrievalErrorCode):
            raise _error(
                RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED,
                RetrievalAgentNode.RETRIEVE_CONTEXT,
                state["attempt_count"],
                error.code,
            ) from None
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.RETRIEVE_CONTEXT,
            state["attempt_count"],
        ) from None
    except Exception:
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.RETRIEVE_CONTEXT,
            state["attempt_count"],
        ) from None


def _build_prompt_node(
    state: _AgentState,
    *,
    config: RetrievalAgentReviewConfig,
) -> dict[str, object]:
    try:
        review = state["review"]
        extension = _extension(state)
        if review is None:
            raise RuntimeError
        hits = () if extension.result is None else extension.result.hits
        rendered = _render_retrieval_prompt(
            state["bundle"],
            review,
            hits,
            max_retrieved_content_bytes=config.max_retrieved_prompt_bytes,
            max_prompt_bytes=config.agent.max_prompt_bytes,
        )
        return {"rendered": rendered}
    except RetrievalAgentReviewError:
        raise
    except _RetrievalPromptLimitError:
        raise _error(
            RetrievalAgentReviewErrorCode.CONTEXT_LIMIT_EXCEEDED,
            RetrievalAgentNode.BUILD_PROMPT,
            state["attempt_count"],
        ) from None
    except (TypeError, UnicodeError, ValueError):
        raise _error(
            RetrievalAgentReviewErrorCode.INVALID_EVIDENCE,
            RetrievalAgentNode.BUILD_PROMPT,
            state["attempt_count"],
        ) from None
    except Exception:
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.BUILD_PROMPT,
            state["attempt_count"],
        ) from None


def _finalize_node(
    state: _AgentState,
    *,
    provider_binding: _ProviderBinding,
    config: RetrievalAgentReviewConfig,
) -> dict[str, object]:
    try:
        rendered = state["rendered"]
        response = state["response"]
        extension = _extension(state)
        provider_name = provider_binding.name
        if (
            not isinstance(rendered, _RenderedRetrievalPrompt)
            or response is None
            or provider_name is None
        ):
            raise RuntimeError
        if agent_impl._monotonic() >= state["deadline"]:
            raise _error(
                RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED,
                RetrievalAgentNode.FINALIZE,
                state["attempt_count"],
            )
        result = RetrievalAgentReviewResult(
            repository=state["bundle"].repository,
            revisions=state["bundle"].revisions,
            provider=provider_name,
            model=config.agent.model,
            prompt=rendered.identity,
            attempt_count=state["attempt_count"],
            usage=state["usage"],
            prompt_bytes=rendered.byte_count,
            response_bytes=state["response_bytes"],
            retrieval=_retrieval_summary(extension, rendered),
            findings=state["findings"],
        )
        return {
            "result": result,
            "rendered": None,
            "response": None,
            "extension": None,
        }
    except RetrievalAgentReviewError:
        raise
    except Exception:
        raise _error(
            RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            RetrievalAgentNode.FINALIZE,
            state["attempt_count"],
        ) from None


def _retrieval_summary(
    extension: _RetrievalExtension,
    rendered: _RenderedRetrievalPrompt,
) -> RetrievalSummary:
    identity = extension.index.identity
    statistics = extension.index.statistics
    candidate_count = 0 if extension.result is None else extension.result.candidate_count
    chunks = tuple(_chunk_summary(hit) for hit in rendered.sent_hits)
    return RetrievalSummary(
        index=identity,
        actual_device=identity.actual_device,
        query_count=extension.query_count,
        candidate_count=candidate_count,
        selected_count=len(chunks),
        omitted_count=candidate_count - len(chunks),
        excluded_file_count=statistics.excluded_file_count,
        unparsed_python_file_count=statistics.unparsed_python_file_count,
        original_blob_bytes=statistics.original_blob_bytes,
        redacted_chunk_bytes=statistics.redacted_chunk_bytes,
        metadata_bytes=statistics.metadata_bytes,
        dense_matrix_bytes=statistics.dense_matrix_bytes,
        logical_index_bytes=statistics.logical_index_bytes,
        chunks=chunks,
    )


def _chunk_summary(hit: RetrievalHit) -> RetrievalChunkSummary:
    return RetrievalChunkSummary(
        provenance=hit.chunk.provenance,
        channels=hit.channels,
        text_rank=hit.text_rank,
        vector_rank=hit.vector_rank,
        symbol_rank=hit.symbol_rank,
        matched_query_count=hit.matched_query_count,
        rrf_score=hit.rrf_score,
    )


def _automatic_query_seeds(
    bundle: EvidenceBundle,
    review: ReviewResult,
    *,
    head_line_terms: Mapping[tuple[str, int], _PythonLineTerms] | None = None,
    deadline: float,
) -> tuple[_QuerySeed, ...]:
    _check_retrieval_deadline(deadline)
    redactions = _private_key_ranges(bundle, review, deadline=deadline)
    line_terms = _changed_line_terms(
        bundle,
        redactions,
        head_line_terms=head_line_terms,
        deadline=deadline,
    )
    seeds: list[_QuerySeed] = []
    for change in bundle.changes:
        _check_retrieval_deadline(deadline)
        versions = tuple(version for version in (change.old, change.new) if version is not None)
        if not versions or not any(
            version.content_kind is ContentKind.TEXT for version in versions
        ):
            continue
        paths = tuple(sorted({version.path for version in versions}, key=_utf8))
        code_terms: list[str] = []
        for (path, _side, _line), terms in line_terms.items():
            _check_retrieval_deadline(deadline)
            if path not in paths:
                continue
            code_terms.extend(terms.identifiers)
            if terms.enclosing_symbol is not None:
                code_terms.append(terms.enclosing_symbol)
        query_terms = _unique_terms(
            (
                *(_path_terms(path) for path in paths),
                tuple(sorted(set(code_terms), key=_utf8)),
            )
        )
        seeds.append(
            _QuerySeed(
                sort_key=(0, tuple(_utf8(path) for path in paths), b"", 0, 0),
                terms=query_terms,
            )
        )

    for finding in review.findings:
        _check_retrieval_deadline(deadline)
        reference_terms: list[str] = []
        reference_keys: list[tuple[bytes, bytes, int, int]] = []
        for reference in finding.references:
            _check_retrieval_deadline(deadline)
            reference_terms.extend(_path_terms(reference.path))
            reference_terms.append(reference.side.value)
            start = 0 if reference.start_line is None else reference.start_line
            end = 0 if reference.end_line is None else reference.end_line
            reference_keys.append((_utf8(reference.path), _utf8(reference.side.value), start, end))
            if reference.start_line is None or reference.end_line is None:
                continue
            for line_number in range(reference.start_line, reference.end_line + 1):
                _check_retrieval_deadline(deadline)
                line_info = line_terms.get((reference.path, reference.side, line_number))
                if line_info is None:
                    continue
                reference_terms.extend(line_info.identifiers)
                if line_info.enclosing_symbol is not None:
                    reference_terms.append(line_info.enclosing_symbol)
        metadata_terms = (
            finding.rule_id.value,
            *_identifier_parts(finding.rule_id.value),
            finding.category.value,
        )
        seeds.append(
            _QuerySeed(
                sort_key=(
                    1,
                    tuple(sorted(reference_keys)),
                    _utf8(finding.rule_id.value),
                    _utf8(finding.category.value),
                    len(finding.references),
                ),
                terms=_unique_terms(
                    (
                        metadata_terms,
                        tuple(sorted(set(reference_terms), key=_utf8)),
                    )
                ),
            )
        )
    result = tuple(sorted(seeds, key=lambda seed: seed.sort_key))
    _check_retrieval_deadline(deadline)
    return result


def _changed_line_terms(
    bundle: EvidenceBundle,
    redactions: dict[tuple[str, EvidenceSide], tuple[tuple[int, int], ...]],
    *,
    head_line_terms: Mapping[tuple[str, int], _PythonLineTerms] | None = None,
    deadline: float,
) -> dict[tuple[str, EvidenceSide, int], _LineTerms]:
    result: dict[tuple[str, EvidenceSide, int], _LineTerms] = {}
    for change in bundle.changes:
        _check_retrieval_deadline(deadline)
        for side, path in _change_sides(change):
            if not _is_python_path(path):
                continue
            for hunk in change.hunks:
                visible_lines = tuple(
                    (line, _line_number(line, side))
                    for line in hunk.lines
                    if _line_number(line, side) is not None
                )
                trust_diff_identifiers = bool(visible_lines and visible_lines[0][1] == 1)
                source_lines = tuple(line.content for line, _number in visible_lines)
                if trust_diff_identifiers:
                    identifiers_by_line = _safe_python_hunk_identifiers(
                        source_lines,
                        deadline=deadline,
                    )
                    enclosing_by_line = _python_hunk_enclosing_symbols(
                        source_lines,
                        deadline=deadline,
                    )
                else:
                    identifiers_by_line = tuple(() for _ in visible_lines)
                    enclosing_by_line = tuple(None for _ in visible_lines)
                for (line, optional_number), identifiers, enclosing_symbol in zip(
                    visible_lines,
                    identifiers_by_line,
                    enclosing_by_line,
                    strict=True,
                ):
                    _check_retrieval_deadline(deadline)
                    assert optional_number is not None
                    number = optional_number
                    indexed_terms = (
                        None
                        if side is EvidenceSide.OLD or head_line_terms is None
                        else head_line_terms.get((path, number))
                    )
                    if indexed_terms is not None:
                        identifiers = indexed_terms.identifiers
                        enclosing_symbol = indexed_terms.enclosing_symbol
                    redacted = _line_is_redacted(path, side, number, redactions)
                    if redacted:
                        if _is_changed_line(line, side):
                            result[(path, side, number)] = _LineTerms(
                                identifiers=(),
                                enclosing_symbol=enclosing_symbol,
                            )
                        continue
                    if not _is_changed_line(line, side):
                        continue
                    result[(path, side, number)] = _LineTerms(
                        identifiers=identifiers,
                        enclosing_symbol=enclosing_symbol,
                    )
    return result


def _private_key_ranges(
    bundle: EvidenceBundle,
    review: ReviewResult,
    *,
    deadline: float,
) -> dict[tuple[str, EvidenceSide], tuple[tuple[int, int], ...]]:
    ranges: dict[tuple[str, EvidenceSide], list[tuple[int, int]]] = defaultdict(list)
    for finding in review.findings:
        _check_retrieval_deadline(deadline)
        if finding.rule_id is not RuleId.PRIVATE_KEY_MATERIAL:
            continue
        for reference in finding.references:
            if reference.start_line is not None and reference.end_line is not None:
                ranges[(reference.path, reference.side)].append(
                    (reference.start_line, reference.end_line)
                )
    for change in bundle.changes:
        _check_retrieval_deadline(deadline)
        for side, path in _change_sides(change):
            unmatched: dict[str, deque[int]] = defaultdict(deque)
            for hunk in change.hunks:
                for line in hunk.lines:
                    _check_retrieval_deadline(deadline)
                    number = _line_number(line, side)
                    if number is None:
                        continue
                    for match in _PRIVATE_KEY_MARKER_PATTERN.finditer(line.content):
                        kind, label = match.groups()
                        if kind == "BEGIN":
                            unmatched[label].append(number)
                        elif unmatched[label]:
                            ranges[(path, side)].append((unmatched[label].popleft(), number))
    return {key: tuple(sorted(set(values))) for key, values in ranges.items()}


def _change_sides(
    change: FileChangeEvidence,
) -> tuple[tuple[EvidenceSide, str], ...]:
    result: list[tuple[EvidenceSide, str]] = []
    if change.old is not None and change.old.content_kind is ContentKind.TEXT:
        result.append((EvidenceSide.OLD, change.old.path))
    if change.new is not None and change.new.content_kind is ContentKind.TEXT:
        result.append((EvidenceSide.NEW, change.new.path))
    return tuple(result)


def _line_number(line: DiffLineEvidence, side: EvidenceSide) -> int | None:
    return line.old_line_number if side is EvidenceSide.OLD else line.new_line_number


def _is_changed_line(line: DiffLineEvidence, side: EvidenceSide) -> bool:
    if side is EvidenceSide.OLD:
        return line.kind is DiffLineKind.DELETION
    return line.kind is DiffLineKind.ADDITION


def _line_is_redacted(
    path: str,
    side: EvidenceSide,
    line_number: int,
    redactions: dict[tuple[str, EvidenceSide], tuple[tuple[int, int], ...]],
) -> bool:
    return any(start <= line_number <= end for start, end in redactions.get((path, side), ()))


def _safe_python_identifiers(source_line: str) -> tuple[str, ...]:
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source_line).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return ()
    identifiers = (
        token.string
        for token in tokens
        if token.type == tokenize.NAME
        and token.string.isidentifier()
        and not keyword.iskeyword(token.string)
    )
    return _unique_terms((tuple(identifiers),))


def _safe_python_hunk_identifiers(
    source_lines: tuple[str, ...],
    *,
    deadline: float,
) -> tuple[tuple[str, ...], ...]:
    _check_retrieval_deadline(deadline)
    if not source_lines:
        return ()
    try:
        tokens = tuple(
            tokenize.generate_tokens(io.StringIO("\n".join(source_lines) + "\n").readline)
        )
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return tuple(() for _ in source_lines)
    identifiers: list[list[str]] = [[] for _ in source_lines]
    for token in tokens:
        _check_retrieval_deadline(deadline)
        if (
            token.type == tokenize.NAME
            and token.string.isidentifier()
            and not keyword.iskeyword(token.string)
            and 1 <= token.start[0] <= len(source_lines)
        ):
            identifiers[token.start[0] - 1].append(token.string)
    return tuple(
        (
            _unique_terms((tuple(line_identifiers),))
            if _is_syntactic_python_line(source_line, deadline=deadline)
            else ()
        )
        for source_line, line_identifiers in zip(source_lines, identifiers, strict=True)
    )


def _is_syntactic_python_line(source_line: str, *, deadline: float) -> bool:
    _check_retrieval_deadline(deadline)
    stripped = source_line.lstrip(" \t\f")
    if not stripped:
        return False
    candidates = (
        f"{stripped}\n",
        f"{stripped}\n    pass\n",
        f"async def __repoguard_scope__():\n    {stripped}\n",
        f"async def __repoguard_scope__():\n    {stripped}\n        pass\n",
    )
    for candidate in candidates:
        try:
            ast.parse(
                candidate,
                filename="<repoguard-query-line>",
                mode="exec",
                feature_version=(3, 12),
            )
        except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
            _check_retrieval_deadline(deadline)
            continue
        _check_retrieval_deadline(deadline)
        return True
    return False


def _python_hunk_enclosing_symbols(
    source_lines: tuple[str, ...],
    *,
    deadline: float,
) -> tuple[str | None, ...]:
    _check_retrieval_deadline(deadline)
    try:
        module = ast.parse(
            "\n".join(source_lines) + "\n",
            filename="<repoguard-query-hunk>",
            mode="exec",
            feature_version=(3, 12),
        )
    except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
        return tuple(None for _ in source_lines)
    _check_retrieval_deadline(deadline)
    scopes_by_start: dict[int, list[tuple[int, str]]] = defaultdict(list)
    for node in ast.walk(module):
        _check_retrieval_deadline(deadline)
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = getattr(node, "decorator_list", ())
        start_line = min(
            (decorator.lineno for decorator in decorators),
            default=node.lineno,
        )
        end_line = node.end_lineno
        if end_line is None:
            continue
        scopes_by_start[start_line].append((min(end_line, len(source_lines)), node.name))

    active_scopes: list[tuple[int, int, str]] = []
    result: list[str | None] = []
    for line_number in range(1, len(source_lines) + 1):
        _check_retrieval_deadline(deadline)
        active_scopes = [scope for scope in active_scopes if scope[0] >= line_number]
        active_scopes.extend(
            (end_line, line_number, name) for end_line, name in scopes_by_start.get(line_number, ())
        )
        enclosing = (
            min(
                active_scopes,
                key=lambda scope: (
                    scope[0] - scope[1],
                    -scope[1],
                    _utf8(scope[2]),
                ),
            )[2]
            if active_scopes
            else None
        )
        result.append(enclosing)
    return tuple(result)


def _definition_name(source_line: str) -> str | None:
    identifiers = _safe_python_identifiers(source_line)
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source_line).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return None
    meaningful = tuple(
        token.string
        for token in tokens
        if token.type
        not in {
            tokenize.ENCODING,
            tokenize.ENDMARKER,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.COMMENT,
        }
    )
    offset = 1 if meaningful[:2] == ("async", "def") else 0
    if len(meaningful) > offset + 1 and meaningful[offset] in {"def", "class"}:
        candidate = meaningful[offset + 1]
        if candidate in identifiers:
            return candidate
    return None


def _is_python_path(path: str) -> bool:
    return PurePosixPath(path).suffix in {".py", ".pyi"}


def _path_terms(path: str) -> tuple[str, ...]:
    terms: list[str] = []
    for match in _PATH_WORD.finditer(path):
        terms.extend(_identifier_parts(match.group(0)))
    return _unique_terms((tuple(terms),))


def _identifier_parts(value: str) -> tuple[str, ...]:
    result = [value]
    for underscore_part in value.split("_"):
        result.extend(_CAMEL_PART.findall(underscore_part))
    return tuple(result)


def _unique_terms(groups: Iterable[Iterable[str]]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for term in group:
            if term in seen or not term or any(character.isspace() for character in term):
                continue
            seen.add(term)
            result.append(term)
    return tuple(result)


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _queries_from_seeds(
    seeds: tuple[_QuerySeed, ...],
    *,
    provider: EmbeddingProvider,
    max_queries: int,
    max_bytes: int,
    deadline: float,
    token_spans: _TokenSpans,
) -> tuple[ContextQuery, ...]:
    queries: list[ContextQuery] = []
    seen: set[str] = set()
    for seed in seeds:
        if time.monotonic() > deadline:
            raise RetrievalError(
                RetrievalErrorCode.DEADLINE_EXCEEDED,
                RetrievalStage.VALIDATE,
            )
        selected: list[str] = []
        for term in seed.terms:
            candidate = " ".join((*selected, term))
            if len(candidate.encode("utf-8")) > max_bytes:
                break
            spans = token_spans(
                provider,
                candidate,
                deadline=deadline,
                stage=RetrievalStage.VALIDATE,
            )
            if len(spans) > _MAX_QUERY_MODEL_TOKENS:
                break
            selected.append(term)
        if not selected:
            continue
        text = " ".join(selected)
        if text in seen:
            continue
        seen.add(text)
        queries.append(ContextQuery(text=text))
        if len(queries) == max_queries:
            break
    return tuple(queries)


def _check_retrieval_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise RetrievalError(
            RetrievalErrorCode.DEADLINE_EXCEEDED,
            RetrievalStage.VALIDATE,
        )


def _extension(state: _AgentState) -> _RetrievalExtension:
    extension = state["extension"]
    if not isinstance(extension, _RetrievalExtension):
        raise RuntimeError
    return extension


def _mapped_agent_failure(
    error: AgentReviewError,
) -> tuple[
    RetrievalAgentReviewErrorCode,
    RetrievalAgentNode,
    int,
    RetrievalErrorCode | None,
]:
    if (
        not isinstance(error.code, AgentReviewErrorCode)
        or not isinstance(error.node, AgentNode)
        or type(error.attempt_count) is not int
        or error.attempt_count < 0
    ):
        return _workflow_failure()
    return (
        _map_agent_code(error.code),
        RetrievalAgentNode(error.node.value),
        error.attempt_count,
        None,
    )


def _map_agent_code(code: AgentReviewErrorCode) -> RetrievalAgentReviewErrorCode:
    try:
        return RetrievalAgentReviewErrorCode(code.value)
    except (AttributeError, ValueError):
        return RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED


def _attempt_count(state: _AgentState) -> int:
    attempt_count = state.get("attempt_count", 0)
    return attempt_count if type(attempt_count) is int and attempt_count >= 0 else 0


def _workflow_failure() -> tuple[
    RetrievalAgentReviewErrorCode,
    RetrievalAgentNode,
    int,
    RetrievalErrorCode | None,
]:
    return (
        RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
        RetrievalAgentNode.FINALIZE,
        0,
        None,
    )


def _invalid_configuration() -> Never:
    raise _error(
        RetrievalAgentReviewErrorCode.INVALID_CONFIGURATION,
        RetrievalAgentNode.VALIDATE,
        0,
    )


def _error(
    code: RetrievalAgentReviewErrorCode,
    node: RetrievalAgentNode,
    attempt_count: int,
    retrieval_code: RetrievalErrorCode | None = None,
) -> RetrievalAgentReviewError:
    return RetrievalAgentReviewError(
        code=code,
        node=node,
        attempt_count=attempt_count,
        retrieval_code=retrieval_code,
    )
