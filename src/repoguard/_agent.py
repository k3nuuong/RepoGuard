"""Controlled in-memory LangGraph review workflow."""

from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from collections.abc import Callable
from contextvars import Context
from dataclasses import dataclass
from pathlib import Path
from typing import Never, TypedDict, cast

from langchain_core.tracers.stdout import ConsoleCallbackHandler
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langsmith import tracing_context

from repoguard._prompt import _ReferenceTarget, _render_review_prompt, _RenderedPrompt
from repoguard.agent import (
    AgentFinding,
    AgentNode,
    AgentReviewConfig,
    AgentReviewError,
    AgentReviewErrorCode,
    AgentReviewResult,
    AgentRuleId,
    FindingSource,
)
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
    RevisionEvidence,
)
from repoguard.providers import (
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ProviderError,
    ProviderErrorCode,
    TokenUsage,
)
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReviewError,
    ReviewErrorCode,
    ReviewResult,
    review_evidence,
)

_MAX_MODEL_CHARS = 256
_MAX_PROVIDER_NAME_CHARS = 64
_MAX_CONFIG_VALUES = {
    "max_prompt_bytes": 131_072,
    "max_output_tokens": 4_096,
    "max_response_bytes": 524_288,
    "max_model_findings": 100,
    "max_references_per_finding": 8,
    "max_title_chars": 120,
    "max_message_chars": 1_000,
    "max_remediation_chars": 1_000,
    "max_attempts": 3,
}
_MAX_TIMEOUT_VALUES = {
    "per_attempt_timeout_seconds": 30.0,
    "total_timeout_seconds": 95.0,
}
_BACKOFF_SECONDS = {2: 0.5, 3: 1.0}
_LOWERCASE_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
_SOURCE_RANK = {
    FindingSource.DETERMINISTIC: 0,
    FindingSource.AGENT: 1,
}
_RETRYABLE_PROVIDER_CODES = {
    ProviderErrorCode.RATE_LIMITED,
    ProviderErrorCode.TIMEOUT,
    ProviderErrorCode.UNAVAILABLE,
}
_PROVIDER_ERROR_CODES = {
    ProviderErrorCode.AUTHENTICATION_FAILED: (AgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED),
    ProviderErrorCode.RATE_LIMITED: AgentReviewErrorCode.PROVIDER_RATE_LIMITED,
    ProviderErrorCode.TIMEOUT: AgentReviewErrorCode.PROVIDER_TIMEOUT,
    ProviderErrorCode.UNAVAILABLE: AgentReviewErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorCode.REQUEST_FAILED: AgentReviewErrorCode.PROVIDER_REQUEST_FAILED,
    ProviderErrorCode.REFUSED: AgentReviewErrorCode.PROVIDER_REFUSED,
    ProviderErrorCode.INVALID_RESPONSE: AgentReviewErrorCode.INVALID_MODEL_OUTPUT,
}
_ERROR_MESSAGES = {
    AgentReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA: "unsupported evidence schema",
    AgentReviewErrorCode.INVALID_EVIDENCE: "invalid review evidence",
    AgentReviewErrorCode.INVALID_CONFIGURATION: "invalid Agent review configuration",
    AgentReviewErrorCode.CONTEXT_LIMIT_EXCEEDED: "Agent review context limit exceeded",
    AgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED: "provider authentication failed",
    AgentReviewErrorCode.PROVIDER_RATE_LIMITED: "provider rate limit exceeded",
    AgentReviewErrorCode.PROVIDER_TIMEOUT: "provider request timed out",
    AgentReviewErrorCode.PROVIDER_UNAVAILABLE: "provider is unavailable",
    AgentReviewErrorCode.PROVIDER_REQUEST_FAILED: "provider request failed",
    AgentReviewErrorCode.PROVIDER_REFUSED: "provider refused the review request",
    AgentReviewErrorCode.INVALID_MODEL_OUTPUT: "model output is invalid",
    AgentReviewErrorCode.BUDGET_EXCEEDED: "Agent review budget exceeded",
    AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED: "Agent review workflow failed",
}

_monotonic: Callable[[], float] = time.monotonic
_sleep: Callable[[float], None] = time.sleep


class _AgentState(TypedDict):
    bundle: EvidenceBundle
    review: ReviewResult | None
    rendered: _RenderedPrompt | None
    response: LLMResponse | None
    candidates: tuple[AgentFinding, ...]
    findings: tuple[AgentFinding, ...]
    attempt_count: int
    provider_error: ProviderError | None
    deadline: float
    response_bytes: int
    usage: TokenUsage | None
    result: AgentReviewResult | None


@dataclass(slots=True)
class _ProviderBinding:
    name: str | None = None
    complete: Callable[[LLMRequest], LLMResponse] | None = None


class _DiscardingConsoleCallbackHandler(ConsoleCallbackHandler):
    """Block host global debug output from observing graph state."""

    @property
    def ignore_llm(self) -> bool:
        return True

    @property
    def ignore_retry(self) -> bool:
        return True

    @property
    def ignore_chain(self) -> bool:
        return True

    @property
    def ignore_agent(self) -> bool:
        return True

    @property
    def ignore_retriever(self) -> bool:
        return True

    @property
    def ignore_chat_model(self) -> bool:
        return True

    @property
    def ignore_custom_event(self) -> bool:
        return True


def _review_with_agent(
    bundle: EvidenceBundle,
    *,
    provider: LLMProvider,
    config: AgentReviewConfig,
) -> AgentReviewResult:
    initial_state: _AgentState = {
        "bundle": bundle,
        "review": None,
        "rendered": None,
        "response": None,
        "candidates": (),
        "findings": (),
        "attempt_count": 0,
        "provider_error": None,
        "deadline": 0.0,
        "response_bytes": 0,
        "usage": None,
        "result": None,
    }
    final_state: _AgentState | None = None
    failure: tuple[AgentReviewErrorCode, AgentNode, int] | None = None
    try:
        graph = _build_graph(provider=provider, config=config)
        final_state = _invoke_graph_without_tracing(graph, initial_state)
    except AgentReviewError as error:
        if (
            isinstance(error.code, AgentReviewErrorCode)
            and isinstance(error.node, AgentNode)
            and type(error.attempt_count) is int
            and error.attempt_count >= 0
        ):
            failure = (error.code, error.node, error.attempt_count)
        else:
            failure = (
                AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
                AgentNode.FINALIZE,
                0,
            )
    except Exception:
        failure = (
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.FINALIZE,
            0,
        )

    if failure is not None:
        raise _error(*failure) from None
    if final_state is None:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.FINALIZE,
            0,
        ) from None

    result = final_state.get("result")
    if not isinstance(result, AgentReviewResult):
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.FINALIZE,
            final_state.get("attempt_count", 0),
        ) from None
    return result


def _invoke_graph_without_tracing(
    graph: CompiledStateGraph[_AgentState, None, _AgentState, _AgentState],
    initial_state: _AgentState,
) -> _AgentState:
    def invoke() -> _AgentState:
        # LangGraph otherwise inherits callback contexts that can expose raw evidence.
        with tracing_context(enabled=False, parent=False):
            return cast(
                _AgentState,
                graph.invoke(
                    initial_state,
                    {"callbacks": [_DiscardingConsoleCallbackHandler()]},
                ),
            )

    return Context().run(invoke)


def _build_graph(
    *,
    provider: LLMProvider,
    config: AgentReviewConfig,
) -> CompiledStateGraph[_AgentState, None, _AgentState, _AgentState]:
    provider_binding = _ProviderBinding()
    builder = StateGraph(_AgentState)
    builder.add_node(
        AgentNode.VALIDATE.value,
        lambda state: _validate_node(
            state,
            provider=provider,
            provider_binding=provider_binding,
            config=config,
        ),
    )
    builder.add_node(AgentNode.DETERMINISTIC_REVIEW.value, _deterministic_review_node)
    builder.add_node(
        AgentNode.BUILD_PROMPT.value,
        lambda state: _build_prompt_node(state, config=config),
    )
    builder.add_node(
        AgentNode.INVOKE_PROVIDER.value,
        lambda state: _invoke_provider_node(
            state,
            provider_binding=provider_binding,
            config=config,
        ),
    )
    builder.add_node(
        AgentNode.PARSE_RESPONSE.value,
        lambda state: _parse_response_node(state, config=config),
    )
    builder.add_node(AgentNode.MERGE_FINDINGS.value, _merge_findings_node)
    builder.add_node(
        AgentNode.FINALIZE.value,
        lambda state: _finalize_node(
            state,
            provider_binding=provider_binding,
            config=config,
        ),
    )

    builder.add_edge(START, AgentNode.VALIDATE.value)
    builder.add_edge(AgentNode.VALIDATE.value, AgentNode.DETERMINISTIC_REVIEW.value)
    builder.add_edge(
        AgentNode.DETERMINISTIC_REVIEW.value,
        AgentNode.BUILD_PROMPT.value,
    )
    builder.add_edge(AgentNode.BUILD_PROMPT.value, AgentNode.INVOKE_PROVIDER.value)
    builder.add_conditional_edges(
        AgentNode.INVOKE_PROVIDER.value,
        lambda state: _provider_route(state, config=config),
        {
            "retry": AgentNode.INVOKE_PROVIDER.value,
            "parse": AgentNode.PARSE_RESPONSE.value,
        },
    )
    builder.add_edge(AgentNode.PARSE_RESPONSE.value, AgentNode.MERGE_FINDINGS.value)
    builder.add_edge(AgentNode.MERGE_FINDINGS.value, AgentNode.FINALIZE.value)
    builder.add_edge(AgentNode.FINALIZE.value, END)
    return builder.compile(
        checkpointer=None, store=None, debug=False, name="repoguard-agent-review"
    )


def _validate_node(
    state: _AgentState,
    *,
    provider: LLMProvider,
    provider_binding: _ProviderBinding,
    config: AgentReviewConfig,
) -> dict[str, object]:
    try:
        _validate_configuration(config)
        provider_binding.name, provider_binding.complete = _validate_provider(provider)
        _validate_context_evidence(state["bundle"])
        return {"deadline": _monotonic() + config.total_timeout_seconds}
    except AgentReviewError:
        raise
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.VALIDATE,
            state["attempt_count"],
        ) from None


def _deterministic_review_node(state: _AgentState) -> dict[str, object]:
    try:
        return {"review": review_evidence(state["bundle"])}
    except ReviewError as error:
        if error.code is ReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA:
            code = AgentReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA
        elif error.code is ReviewErrorCode.INVALID_EVIDENCE:
            code = AgentReviewErrorCode.INVALID_EVIDENCE
        else:
            code = AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
        raise _error(
            code,
            AgentNode.DETERMINISTIC_REVIEW,
            state["attempt_count"],
        ) from None
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.DETERMINISTIC_REVIEW,
            state["attempt_count"],
        ) from None


def _build_prompt_node(
    state: _AgentState,
    *,
    config: AgentReviewConfig,
) -> dict[str, object]:
    try:
        review = state["review"]
        if review is None:
            raise RuntimeError
        rendered = _render_review_prompt(state["bundle"], review)
        if rendered.byte_count > config.max_prompt_bytes:
            raise _error(
                AgentReviewErrorCode.CONTEXT_LIMIT_EXCEEDED,
                AgentNode.BUILD_PROMPT,
                state["attempt_count"],
            )
        return {"rendered": rendered}
    except AgentReviewError:
        raise
    except (TypeError, UnicodeError, ValueError):
        raise _error(
            AgentReviewErrorCode.INVALID_EVIDENCE,
            AgentNode.BUILD_PROMPT,
            state["attempt_count"],
        ) from None
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.BUILD_PROMPT,
            state["attempt_count"],
        ) from None


def _invoke_provider_node(
    state: _AgentState,
    *,
    provider_binding: _ProviderBinding,
    config: AgentReviewConfig,
) -> dict[str, object]:
    attempt = state["attempt_count"] + 1
    try:
        rendered = state["rendered"]
        if rendered is None:
            raise RuntimeError
        if attempt > 1:
            delay = _BACKOFF_SECONDS[attempt]
            if _monotonic() + delay >= state["deadline"]:
                raise _error(
                    AgentReviewErrorCode.BUDGET_EXCEEDED,
                    AgentNode.INVOKE_PROVIDER,
                    state["attempt_count"],
                )
            _sleep(delay)
        remaining = state["deadline"] - _monotonic()
        if remaining <= 0:
            raise _error(
                AgentReviewErrorCode.BUDGET_EXCEEDED,
                AgentNode.INVOKE_PROVIDER,
                state["attempt_count"],
            )
        timeout = min(config.per_attempt_timeout_seconds, remaining)
        request = LLMRequest(
            model=config.model,
            messages=rendered.messages,
            max_output_tokens=config.max_output_tokens,
            timeout_seconds=timeout,
        )
        complete = provider_binding.complete
        if complete is None:
            raise RuntimeError
        try:
            response = complete(request)
        except ProviderError as error:
            return {
                "attempt_count": attempt,
                "provider_error": error,
                "response": None,
            }
        except Exception:
            raise _error(
                AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
                AgentNode.INVOKE_PROVIDER,
                attempt,
            ) from None
        if _monotonic() >= state["deadline"]:
            raise _error(
                AgentReviewErrorCode.BUDGET_EXCEEDED,
                AgentNode.INVOKE_PROVIDER,
                attempt,
            )
        return {
            "attempt_count": attempt,
            "provider_error": None,
            "response": response,
        }
    except AgentReviewError:
        raise
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.INVOKE_PROVIDER,
            attempt,
        ) from None


def _provider_route(
    state: _AgentState,
    *,
    config: AgentReviewConfig,
) -> str:
    try:
        if state["response"] is not None:
            return "parse"
        error = state["provider_error"]
        if error is None:
            raise _error(
                AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
                AgentNode.INVOKE_PROVIDER,
                state["attempt_count"],
            )
        next_attempt = state["attempt_count"] + 1
        if (
            error.code in _RETRYABLE_PROVIDER_CODES
            and state["attempt_count"] < config.max_attempts
            and next_attempt in _BACKOFF_SECONDS
        ):
            delay = _BACKOFF_SECONDS[next_attempt]
            if _monotonic() + delay < state["deadline"]:
                return "retry"
            raise _error(
                AgentReviewErrorCode.BUDGET_EXCEEDED,
                AgentNode.INVOKE_PROVIDER,
                state["attempt_count"],
            )
        raise _error(
            _PROVIDER_ERROR_CODES[error.code],
            AgentNode.INVOKE_PROVIDER,
            state["attempt_count"],
        )
    except AgentReviewError:
        raise
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.INVOKE_PROVIDER,
            state["attempt_count"],
        ) from None


def _parse_response_node(
    state: _AgentState,
    *,
    config: AgentReviewConfig,
) -> dict[str, object]:
    try:
        response = state["response"]
        rendered = state["rendered"]
        if response is None or rendered is None:
            raise RuntimeError
        if type(response) is not LLMResponse:
            _raise_model_output_error(state["attempt_count"])
        output_text = response.output_text
        usage = response.usage
        if type(output_text) is not str or (usage is not None and type(usage) is not TokenUsage):
            _raise_model_output_error(state["attempt_count"])
        try:
            response_bytes = len(output_text.encode("utf-8"))
        except UnicodeEncodeError:
            _raise_model_output_error(state["attempt_count"])
        if response_bytes > config.max_response_bytes:
            _raise_model_output_error(state["attempt_count"])
        candidates = _parse_model_findings(
            output_text,
            targets=rendered.targets,
            config=config,
            attempt_count=state["attempt_count"],
        )
        return {
            "candidates": candidates,
            "response_bytes": response_bytes,
            "usage": usage,
        }
    except AgentReviewError:
        raise
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.PARSE_RESPONSE,
            state["attempt_count"],
        ) from None


def _merge_findings_node(state: _AgentState) -> dict[str, object]:
    try:
        review = state["review"]
        if review is None:
            raise RuntimeError
        deterministic = tuple(_promote_finding(finding) for finding in review.findings)
        unique_agent = tuple(dict.fromkeys(state["candidates"]))
        findings = tuple(sorted((*deterministic, *unique_agent), key=_finding_sort_key))
        return {"findings": findings}
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.MERGE_FINDINGS,
            state["attempt_count"],
        ) from None


def _finalize_node(
    state: _AgentState,
    *,
    provider_binding: _ProviderBinding,
    config: AgentReviewConfig,
) -> dict[str, object]:
    try:
        rendered = state["rendered"]
        response = state["response"]
        provider_name = provider_binding.name
        if rendered is None or response is None or provider_name is None:
            raise RuntimeError
        if _monotonic() >= state["deadline"]:
            raise _error(
                AgentReviewErrorCode.BUDGET_EXCEEDED,
                AgentNode.FINALIZE,
                state["attempt_count"],
            )
        result = AgentReviewResult(
            repository=state["bundle"].repository,
            revisions=state["bundle"].revisions,
            provider=provider_name,
            model=config.model,
            prompt=rendered.identity,
            attempt_count=state["attempt_count"],
            usage=state["usage"],
            prompt_bytes=rendered.byte_count,
            response_bytes=state["response_bytes"],
            findings=state["findings"],
        )
        return {
            "result": result,
            "rendered": None,
            "response": None,
        }
    except AgentReviewError:
        raise
    except Exception:
        raise _error(
            AgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED,
            AgentNode.FINALIZE,
            state["attempt_count"],
        ) from None


def _validate_configuration(config: AgentReviewConfig) -> None:
    if type(config) is not AgentReviewConfig:
        _raise_invalid_configuration()
    _validate_identifier(config.model, _MAX_MODEL_CHARS)
    for name, maximum in _MAX_CONFIG_VALUES.items():
        value = getattr(config, name)
        if type(value) is not int or not 1 <= value <= maximum:
            _raise_invalid_configuration()
    for name, timeout_maximum in _MAX_TIMEOUT_VALUES.items():
        value = getattr(config, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 < value <= timeout_maximum
        ):
            _raise_invalid_configuration()


def _validate_provider(
    provider: LLMProvider,
) -> tuple[str, Callable[[LLMRequest], LLMResponse]]:
    if not isinstance(provider, LLMProvider):
        _raise_invalid_configuration()
    name = provider.name
    _validate_identifier(name, _MAX_PROVIDER_NAME_CHARS)
    complete = provider.complete
    if not callable(complete):
        _raise_invalid_configuration()
    return name, cast(Callable[[LLMRequest], LLMResponse], complete)


def _validate_identifier(value: object, maximum: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        _raise_invalid_configuration()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _raise_invalid_configuration()
    if any(unicodedata.category(character) == "Cc" for character in value):
        _raise_invalid_configuration()


def _validate_context_evidence(bundle: EvidenceBundle) -> None:
    if not isinstance(bundle, EvidenceBundle):
        _raise_invalid_evidence()
    if type(bundle.schema_version) is not int or bundle.schema_version != 1:
        raise _error(
            AgentReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA,
            AgentNode.VALIDATE,
            0,
        )
    if type(bundle.changes) is not tuple:
        _raise_invalid_evidence()
    repository = bundle.repository
    revisions = bundle.revisions
    if not isinstance(repository, RepositoryEvidence):
        _raise_invalid_evidence()
    if not isinstance(revisions, RevisionEvidence):
        _raise_invalid_evidence()
    if not isinstance(repository.root, Path) or not repository.root.is_absolute():
        _raise_invalid_evidence()
    _require_utf8(str(repository.root))
    if type(repository.object_format) is not str:
        _raise_invalid_evidence()
    oid_length = _OID_LENGTHS.get(repository.object_format)
    if oid_length is None:
        _raise_invalid_evidence()
    _require_utf8(revisions.base_ref)
    _require_utf8(revisions.head_ref)
    for oid in (revisions.base_oid, revisions.head_oid, revisions.merge_base_oid):
        _validate_oid(oid, oid_length)
    seen_targets: set[tuple[str, EvidenceSide]] = set()
    for change in bundle.changes:
        _validate_context_change(change, oid_length, seen_targets)


def _validate_context_change(
    change: object,
    oid_length: int,
    seen_targets: set[tuple[str, EvidenceSide]],
) -> None:
    if not isinstance(change, FileChangeEvidence) or type(change.hunks) is not tuple:
        _raise_invalid_evidence()
    if not isinstance(change.change_type, ChangeType):
        _raise_invalid_evidence()
    if change.change_type is ChangeType.RENAMED:
        if type(change.rename_similarity) is not int or not 0 <= change.rename_similarity <= 100:
            _raise_invalid_evidence()
    elif change.rename_similarity is not None:
        _raise_invalid_evidence()
    if change.change_type is ChangeType.ADDED:
        valid_sides = change.old is None and change.new is not None
    elif change.change_type is ChangeType.DELETED:
        valid_sides = change.old is not None and change.new is None
    else:
        valid_sides = change.old is not None and change.new is not None
    if not valid_sides:
        _raise_invalid_evidence()
    for side, version in (
        (EvidenceSide.OLD, change.old),
        (EvidenceSide.NEW, change.new),
    ):
        if version is None:
            continue
        _validate_context_version(version, oid_length)
        key = (version.path, side)
        if key in seen_targets:
            _raise_invalid_evidence()
        seen_targets.add(key)
    existing_versions = tuple(
        version for version in (change.old, change.new) if version is not None
    )
    if change.hunks and any(
        version.content_kind is not ContentKind.TEXT for version in existing_versions
    ):
        _raise_invalid_evidence()
    old_numbers: set[int] = set()
    new_numbers: set[int] = set()
    for hunk in change.hunks:
        _validate_context_hunk(
            hunk,
            old_numbers=old_numbers,
            new_numbers=new_numbers,
        )


def _validate_context_version(version: object, oid_length: int) -> None:
    if not isinstance(version, FileVersion):
        _raise_invalid_evidence()
    if (
        type(version.path) is not str
        or not version.path
        or type(version.mode) is not str
        or not version.mode
        or not isinstance(version.content_kind, ContentKind)
    ):
        _raise_invalid_evidence()
    _require_utf8(version.path)
    _require_utf8(version.mode)
    _validate_oid(version.oid, oid_length)


def _validate_oid(value: object, oid_length: int) -> None:
    if (
        type(value) is not str
        or len(value) != oid_length
        or _LOWERCASE_HEX_PATTERN.fullmatch(value) is None
    ):
        _raise_invalid_evidence()


def _validate_context_hunk(
    hunk: object,
    *,
    old_numbers: set[int],
    new_numbers: set[int],
) -> None:
    if not isinstance(hunk, DiffHunkEvidence) or type(hunk.lines) is not tuple:
        _raise_invalid_evidence()
    for value in (hunk.old_start, hunk.new_start):
        if type(value) is not int or value < 0:
            _raise_invalid_evidence()
    for value in (hunk.old_count, hunk.new_count):
        if type(value) is not int or value < 0:
            _raise_invalid_evidence()
    expected_old = hunk.old_start
    expected_new = hunk.new_start
    observed_old = 0
    observed_new = 0
    for line in hunk.lines:
        expected_old, expected_new = _validate_context_line(
            line,
            expected_old=expected_old,
            expected_new=expected_new,
            old_numbers=old_numbers,
            new_numbers=new_numbers,
        )
        if line.kind is not DiffLineKind.ADDITION:
            observed_old += 1
        if line.kind is not DiffLineKind.DELETION:
            observed_new += 1
    if observed_old != hunk.old_count or observed_new != hunk.new_count:
        _raise_invalid_evidence()


def _validate_context_line(
    line: object,
    *,
    expected_old: int,
    expected_new: int,
    old_numbers: set[int],
    new_numbers: set[int],
) -> tuple[int, int]:
    if (
        not isinstance(line, DiffLineEvidence)
        or not isinstance(line.kind, DiffLineKind)
        or type(line.content) is not str
        or type(line.has_trailing_newline) is not bool
    ):
        _raise_invalid_evidence()
    _require_utf8(line.content)
    old = line.old_line_number
    new = line.new_line_number
    required_old = None if line.kind is DiffLineKind.ADDITION else expected_old
    required_new = None if line.kind is DiffLineKind.DELETION else expected_new
    if old != required_old or new != required_new:
        _raise_invalid_evidence()
    if old is not None:
        if type(old) is not int or old < 1 or old in old_numbers:
            _raise_invalid_evidence()
        old_numbers.add(old)
        expected_old += 1
    if new is not None:
        if type(new) is not int or new < 1 or new in new_numbers:
            _raise_invalid_evidence()
        new_numbers.add(new)
        expected_new += 1
    return expected_old, expected_new


def _require_utf8(value: object) -> None:
    if type(value) is not str:
        _raise_invalid_evidence()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _raise_invalid_evidence()


def _parse_model_findings(
    output_text: str,
    *,
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget],
    config: AgentReviewConfig,
    attempt_count: int,
) -> tuple[AgentFinding, ...]:
    if output_text != output_text.strip():
        _raise_model_output_error(attempt_count)
    try:
        value = json.loads(
            output_text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (RecursionError, TypeError, ValueError):
        _raise_model_output_error(attempt_count)
    if type(value) is not dict or set(value) != {"schema_version", "findings"}:
        _raise_model_output_error(attempt_count)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _raise_model_output_error(attempt_count)
    raw_findings = value["findings"]
    if type(raw_findings) is not list or len(raw_findings) > config.max_model_findings:
        _raise_model_output_error(attempt_count)
    return tuple(
        _parse_model_finding(
            raw,
            targets=targets,
            config=config,
            attempt_count=attempt_count,
        )
        for raw in raw_findings
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_json_constant(_: str) -> Never:
    raise ValueError


def _parse_model_finding(
    value: object,
    *,
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget],
    config: AgentReviewConfig,
    attempt_count: int,
) -> AgentFinding:
    required = {
        "category",
        "severity",
        "title",
        "message",
        "remediation",
        "references",
    }
    if type(value) is not dict or set(value) != required:
        _raise_model_output_error(attempt_count)
    raw = cast(dict[str, object], value)
    category_value = raw["category"]
    severity_value = raw["severity"]
    if type(category_value) is not str or type(severity_value) is not str:
        _raise_model_output_error(attempt_count)
    try:
        category = FindingCategory(category_value)
        severity = FindingSeverity(severity_value)
    except ValueError:
        _raise_model_output_error(attempt_count)
    title = _validated_text(
        raw["title"],
        maximum=config.max_title_chars,
        attempt_count=attempt_count,
    )
    message = _validated_text(
        raw["message"],
        maximum=config.max_message_chars,
        attempt_count=attempt_count,
    )
    remediation = _validated_text(
        raw["remediation"],
        maximum=config.max_remediation_chars,
        attempt_count=attempt_count,
    )
    raw_references = raw["references"]
    if (
        type(raw_references) is not list
        or not raw_references
        or len(raw_references) > config.max_references_per_finding
    ):
        _raise_model_output_error(attempt_count)
    references = tuple(
        sorted(
            {
                _parse_model_reference(
                    reference,
                    targets=targets,
                    attempt_count=attempt_count,
                )
                for reference in raw_references
            },
            key=_reference_sort_key,
        ),
    )
    return AgentFinding(
        source=FindingSource.AGENT,
        rule_id=AgentRuleId.AGENT_REASONING,
        category=category,
        severity=severity,
        title=title,
        message=message,
        remediation=remediation,
        references=references,
    )


def _validated_text(
    value: object,
    *,
    maximum: int,
    attempt_count: int,
) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        _raise_model_output_error(attempt_count)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _raise_model_output_error(attempt_count)
    if "\0" in value:
        _raise_model_output_error(attempt_count)
    return value


def _parse_model_reference(
    value: object,
    *,
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget],
    attempt_count: int,
) -> EvidenceReference:
    required = {"path", "side", "start_line", "end_line"}
    if type(value) is not dict or set(value) != required:
        _raise_model_output_error(attempt_count)
    raw = cast(dict[str, object], value)
    if type(raw["path"]) is not str:
        _raise_model_output_error(attempt_count)
    side_value = raw["side"]
    if type(side_value) is not str:
        _raise_model_output_error(attempt_count)
    try:
        side = EvidenceSide(side_value)
    except ValueError:
        _raise_model_output_error(attempt_count)
    target = targets.get((raw["path"], side))
    if target is None:
        _raise_model_output_error(attempt_count)
    start = raw["start_line"]
    end = raw["end_line"]
    if not (
        (start is None and end is None)
        or (
            type(start) is int
            and type(end) is int
            and 1 <= start <= end
            and _range_is_in_one_hunk(start, end, target.hunk_line_numbers)
        )
    ):
        _raise_model_output_error(attempt_count)
    return EvidenceReference(
        path=target.path,
        side=target.side,
        oid=target.oid,
        start_line=start,
        end_line=end,
    )


def _range_is_in_one_hunk(
    start: int,
    end: int,
    hunk_line_numbers: tuple[frozenset[int], ...],
) -> bool:
    length = end - start + 1
    for numbers in hunk_line_numbers:
        if length <= len(numbers) and all(number in numbers for number in range(start, end + 1)):
            return True
    return False


def _promote_finding(finding: Finding) -> AgentFinding:
    return AgentFinding(
        source=FindingSource.DETERMINISTIC,
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        message=finding.message,
        remediation=finding.remediation,
        references=finding.references,
    )


def _finding_sort_key(finding: AgentFinding) -> tuple[object, ...]:
    first = finding.references[0]
    return (
        _SEVERITY_RANK[finding.severity],
        first.path.encode("utf-8"),
        _line_sort_value(first.start_line),
        _line_sort_value(first.end_line),
        _SOURCE_RANK[finding.source],
        finding.rule_id.value,
        tuple(_reference_sort_key(reference) for reference in finding.references),
        finding.category.value,
        finding.title,
        finding.message,
        finding.remediation,
    )


def _reference_sort_key(reference: EvidenceReference) -> tuple[object, ...]:
    return (
        reference.path.encode("utf-8"),
        reference.side.value,
        reference.oid,
        _line_sort_value(reference.start_line),
        _line_sort_value(reference.end_line),
    )


def _line_sort_value(value: int | None) -> int:
    return 0 if value is None else value


def _raise_invalid_configuration() -> Never:
    raise _error(
        AgentReviewErrorCode.INVALID_CONFIGURATION,
        AgentNode.VALIDATE,
        0,
    )


def _raise_invalid_evidence() -> Never:
    raise _error(
        AgentReviewErrorCode.INVALID_EVIDENCE,
        AgentNode.VALIDATE,
        0,
    )


def _raise_model_output_error(attempt_count: int) -> Never:
    raise _error(
        AgentReviewErrorCode.INVALID_MODEL_OUTPUT,
        AgentNode.PARSE_RESPONSE,
        attempt_count,
    )


def _error(
    code: AgentReviewErrorCode,
    node: AgentNode,
    attempt_count: int,
) -> AgentReviewError:
    return AgentReviewError(
        code=code,
        node=node,
        attempt_count=attempt_count,
        message=_ERROR_MESSAGES[code],
    )
