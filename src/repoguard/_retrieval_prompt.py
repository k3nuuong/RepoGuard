"""Trusted v2 prompt resources and bounded retrieved-context projection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files

from repoguard._prompt import (
    _canonical_mapping_bytes,
    _change_to_prompt_dict,
    _deterministic_finding_to_dict,
    _private_key_redactions,
    _reference_targets,
    _ReferenceTarget,
)
from repoguard.evidence import EvidenceBundle
from repoguard.providers import LLMMessage, MessageRole
from repoguard.retrieval import RetrievalHit
from repoguard.retrieval_agent import RetrievalPromptIdentity
from repoguard.review import EvidenceSide, ReviewResult

_PROMPT_DIRECTORY = ("prompts", "agent_review", "v2")
_SYSTEM_RESOURCE = "system.md"
_SCHEMA_RESOURCE = "response-schema.json"


class _RetrievalPromptLimitError(ValueError):
    """The complete untruncated evidence cannot fit the prompt budget."""


@dataclass(frozen=True, slots=True)
class _RenderedRetrievalPrompt:
    messages: tuple[LLMMessage, ...]
    identity: RetrievalPromptIdentity
    byte_count: int
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget]
    sent_hits: tuple[RetrievalHit, ...]
    omitted_hit_count: int


def _render_retrieval_prompt(
    bundle: EvidenceBundle,
    review: ReviewResult,
    hits: tuple[RetrievalHit, ...],
    *,
    max_retrieved_content_bytes: int,
    max_prompt_bytes: int,
) -> _RenderedRetrievalPrompt:
    system_bytes, schema_bytes = _read_prompt_resources()
    trusted_content = (
        f"{system_bytes.decode('utf-8')}\nResponse schema:\n{schema_bytes.decode('utf-8')}"
    )
    redactions = _private_key_redactions(review.findings)
    changes = [_change_to_prompt_dict(change, redactions) for change in bundle.changes]
    changes.sort(key=_canonical_mapping_bytes)
    base_data: dict[str, object] = {
        "schema_version": 2,
        "repository": {"object_format": bundle.repository.object_format},
        "revisions": {
            "base_oid": bundle.revisions.base_oid,
            "head_oid": bundle.revisions.head_oid,
            "merge_base_oid": bundle.revisions.merge_base_oid,
        },
        "deterministic_findings": [
            _deterministic_finding_to_dict(finding) for finding in review.findings
        ],
        "changes": changes,
        "retrieved_context": [],
    }
    empty_messages = _messages(trusted_content, base_data)
    if _message_bytes(empty_messages) > max_prompt_bytes:
        raise _RetrievalPromptLimitError

    selected: list[RetrievalHit] = []
    selected_data: list[dict[str, object]] = []
    content_bytes = 0
    rendered_messages = empty_messages
    for hit in hits:
        next_content_bytes = len(hit.chunk.content.encode("utf-8"))
        if content_bytes + next_content_bytes > max_retrieved_content_bytes:
            break
        candidate_data = [*selected_data, _hit_to_prompt_dict(hit)]
        base_data["retrieved_context"] = candidate_data
        candidate_messages = _messages(trusted_content, base_data)
        if _message_bytes(candidate_messages) > max_prompt_bytes:
            break
        selected.append(hit)
        selected_data = candidate_data
        content_bytes += next_content_bytes
        rendered_messages = candidate_messages

    digest = hashlib.sha256(system_bytes + b"\0" + schema_bytes).hexdigest()
    return _RenderedRetrievalPrompt(
        messages=rendered_messages,
        identity=RetrievalPromptIdentity(
            name="agent_review",
            version="v2",
            sha256=digest,
        ),
        byte_count=_message_bytes(rendered_messages),
        targets=_reference_targets(bundle),
        sent_hits=tuple(selected),
        omitted_hit_count=len(hits) - len(selected),
    )


def _read_prompt_resources() -> tuple[bytes, bytes]:
    root = files("repoguard")
    for part in _PROMPT_DIRECTORY:
        root = root.joinpath(part)
    return (
        root.joinpath(_SYSTEM_RESOURCE).read_bytes(),
        root.joinpath(_SCHEMA_RESOURCE).read_bytes(),
    )


def _messages(
    trusted_content: str,
    user_data: dict[str, object],
) -> tuple[LLMMessage, LLMMessage]:
    user_content = json.dumps(
        user_data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        LLMMessage(role=MessageRole.SYSTEM, content=trusted_content),
        LLMMessage(role=MessageRole.USER, content=user_content),
    )


def _message_bytes(messages: tuple[LLMMessage, ...]) -> int:
    return sum(len(message.content.encode("utf-8")) for message in messages)


def _hit_to_prompt_dict(hit: RetrievalHit) -> dict[str, object]:
    provenance = hit.chunk.provenance
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
        "content": hit.chunk.content,
        "redacted_line_ranges": [
            {"start_line": start, "end_line": end} for start, end in hit.chunk.redacted_line_ranges
        ],
        "definitions": list(hit.chunk.definitions),
        "references": list(hit.chunk.references),
        "channels": [channel.value for channel in hit.channels],
        "text_rank": hit.text_rank,
        "vector_rank": hit.vector_rank,
        "symbol_rank": hit.symbol_rank,
        "matched_query_count": hit.matched_query_count,
        "rrf_score": hit.rrf_score,
    }
