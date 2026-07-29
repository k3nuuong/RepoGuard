"""Public contract tests for Agent review with hybrid context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from importlib.resources import files
from pathlib import Path
from typing import cast

import pytest

from repoguard._prompt import _render_review_prompt
from repoguard._retrieval_prompt import (
    _render_retrieval_prompt,
    _RetrievalPromptLimitError,
)
from repoguard.agent import AgentReviewConfig, PromptIdentity
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
from repoguard.retrieval import (
    ChunkProvenance,
    ContextChunk,
    EmbeddingDevice,
    IndexIdentity,
    RetrievalChannel,
    RetrievalErrorCode,
    RetrievalHit,
)
from repoguard.retrieval_agent import (
    RetrievalAgentNode,
    RetrievalAgentReviewConfig,
    RetrievalAgentReviewError,
    RetrievalAgentReviewErrorCode,
    RetrievalAgentReviewResult,
    RetrievalChunkSummary,
    RetrievalPromptIdentity,
    RetrievalSummary,
    retrieval_agent_review_to_dict,
    retrieval_agent_review_to_json,
)
from repoguard.review import review_evidence

MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"


def _identity() -> IndexIdentity:
    return IndexIdentity(
        repository_root=Path("/work/repository"),
        object_format="sha1",
        head_oid="a" * 40,
        channels=(
            RetrievalChannel.TEXT,
            RetrievalChannel.VECTOR,
            RetrievalChannel.SYMBOL,
        ),
        config_sha256="b" * 64,
        model="BAAI/bge-small-en-v1.5",
        model_revision=MODEL_REVISION,
        manifest_sha256="c" * 64,
        dimension=384,
        actual_device=EmbeddingDevice.CPU,
    )


def _chunk_summary() -> RetrievalChunkSummary:
    return RetrievalChunkSummary(
        provenance=ChunkProvenance(
            chunk_id="d" * 64,
            path="src/module.py",
            oid="e" * 40,
            start_byte=0,
            end_byte=10,
            start_line=1,
            end_line=1,
        ),
        channels=(RetrievalChannel.VECTOR, RetrievalChannel.SYMBOL),
        text_rank=None,
        vector_rank=1,
        symbol_rank=3,
        matched_query_count=2,
        rrf_score=32_274_193,
    )


def _summary() -> RetrievalSummary:
    return RetrievalSummary(
        index=_identity(),
        actual_device=EmbeddingDevice.CPU,
        query_count=2,
        candidate_count=2,
        selected_count=1,
        omitted_count=1,
        excluded_file_count=3,
        unparsed_python_file_count=1,
        original_blob_bytes=10,
        redacted_chunk_bytes=11,
        metadata_bytes=12,
        dense_matrix_bytes=1_536,
        logical_index_bytes=1_569,
        chunks=(_chunk_summary(),),
    )


def _result() -> RetrievalAgentReviewResult:
    return RetrievalAgentReviewResult(
        repository=RepositoryEvidence(
            root=Path("/work/repository"),
            object_format="sha1",
        ),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid="1" * 40,
            head_oid="a" * 40,
            merge_base_oid="2" * 40,
        ),
        provider="fake",
        model="fake-model",
        prompt=RetrievalPromptIdentity(
            name="agent_review",
            version="v2",
            sha256="f" * 64,
        ),
        attempt_count=1,
        usage=None,
        prompt_bytes=100,
        response_bytes=34,
        retrieval=_summary(),
        findings=(),
    )


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        repository=RepositoryEvidence(
            root=Path("/work/repository"),
            object_format="sha1",
        ),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid="1" * 40,
            head_oid="a" * 40,
            merge_base_oid="2" * 40,
        ),
        changes=(
            FileChangeEvidence(
                change_type=ChangeType.MODIFIED,
                rename_similarity=None,
                old=FileVersion(
                    path="src/changed.py",
                    mode="100644",
                    oid="3" * 40,
                    content_kind=ContentKind.TEXT,
                ),
                new=FileVersion(
                    path="src/changed.py",
                    mode="100644",
                    oid="4" * 40,
                    content_kind=ContentKind.TEXT,
                ),
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=1,
                        new_start=1,
                        new_count=1,
                        lines=(
                            DiffLineEvidence(
                                kind=DiffLineKind.ADDITION,
                                old_line_number=None,
                                new_line_number=1,
                                content="result = helper()",
                                has_trailing_newline=True,
                            ),
                            DiffLineEvidence(
                                kind=DiffLineKind.DELETION,
                                old_line_number=1,
                                new_line_number=None,
                                content="result = None",
                                has_trailing_newline=True,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def _retrieval_hit() -> RetrievalHit:
    return RetrievalHit(
        chunk=ContextChunk(
            provenance=ChunkProvenance(
                chunk_id="9" * 64,
                path="src/helper.py",
                oid="8" * 40,
                start_byte=0,
                end_byte=25,
                start_line=1,
                end_line=2,
            ),
            content="def helper():\n    return 1\n",
            redacted_line_ranges=(),
            definitions=("helper",),
            references=(),
        ),
        channels=(RetrievalChannel.TEXT, RetrievalChannel.VECTOR),
        text_rank=2,
        vector_rank=1,
        symbol_rank=None,
        matched_query_count=1,
        rrf_score=32_522_474,
    )


def test_retrieval_agent_enums_are_closed() -> None:
    assert tuple(RetrievalAgentNode) == (
        RetrievalAgentNode.VALIDATE,
        RetrievalAgentNode.DETERMINISTIC_REVIEW,
        RetrievalAgentNode.RETRIEVE_CONTEXT,
        RetrievalAgentNode.BUILD_PROMPT,
        RetrievalAgentNode.INVOKE_PROVIDER,
        RetrievalAgentNode.PARSE_RESPONSE,
        RetrievalAgentNode.MERGE_FINDINGS,
        RetrievalAgentNode.FINALIZE,
    )
    assert {code.value for code in RetrievalAgentReviewErrorCode} == {
        "unsupported_evidence_schema",
        "invalid_evidence",
        "invalid_configuration",
        "invalid_index",
        "retrieval_failed",
        "context_limit_exceeded",
        "provider_authentication_failed",
        "provider_rate_limited",
        "provider_timeout",
        "provider_unavailable",
        "provider_request_failed",
        "provider_refused",
        "invalid_model_output",
        "budget_exceeded",
        "workflow_execution_failed",
    }


def test_retrieval_error_carries_only_retrieval_failure_code() -> None:
    error = RetrievalAgentReviewError(
        RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED,
        RetrievalAgentNode.RETRIEVE_CONTEXT,
        0,
        RetrievalErrorCode.DEADLINE_EXCEEDED,
    )

    assert str(error) == "context retrieval failed"
    assert error.retrieval_code is RetrievalErrorCode.DEADLINE_EXCEEDED
    with pytest.raises(ValueError, match="requires"):
        RetrievalAgentReviewError(
            RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED,
            RetrievalAgentNode.RETRIEVE_CONTEXT,
            0,
        )
    with pytest.raises(ValueError, match="only valid"):
        RetrievalAgentReviewError(
            RetrievalAgentReviewErrorCode.INVALID_INDEX,
            RetrievalAgentNode.VALIDATE,
            0,
            RetrievalErrorCode.INVALID_INDEX,
        )


def test_retrieval_error_rejects_invalid_public_fields() -> None:
    with pytest.raises(TypeError, match="code"):
        RetrievalAgentReviewError(
            "invalid_index",  # type: ignore[arg-type]
            RetrievalAgentNode.VALIDATE,
            0,
        )
    with pytest.raises(TypeError, match="node"):
        RetrievalAgentReviewError(
            RetrievalAgentReviewErrorCode.INVALID_INDEX,
            "validate",  # type: ignore[arg-type]
            0,
        )
    with pytest.raises(ValueError, match="attempt_count"):
        RetrievalAgentReviewError(
            RetrievalAgentReviewErrorCode.INVALID_INDEX,
            RetrievalAgentNode.VALIDATE,
            -1,
        )


def test_retrieval_agent_config_preserves_the_m3_policy() -> None:
    agent = AgentReviewConfig(model="fake-model")
    config = RetrievalAgentReviewConfig(agent=agent)

    assert config.agent is agent
    assert config.max_queries == 256
    assert config.max_query_bytes == 2_048
    assert config.max_retrieved_prompt_bytes == 65_536
    with pytest.raises(FrozenInstanceError):
        config.max_queries = 1  # type: ignore[misc]


def test_v2_identity_does_not_expand_the_m3_prompt_contract() -> None:
    identity = RetrievalPromptIdentity(
        name="agent_review",
        version="v2",
        sha256="a" * 64,
    )

    assert identity.version == "v2"
    with pytest.raises(ValueError, match="version must be v1"):
        PromptIdentity(name="agent_review", version="v2", sha256="a" * 64)
    with pytest.raises(ValueError, match="version must be v2"):
        replace(identity, version="v1")
    with pytest.raises(ValueError, match="name"):
        replace(identity, name="other")
    with pytest.raises(ValueError, match="sha256"):
        replace(identity, sha256="A" * 64)
    with pytest.raises(ValueError, match="sha256"):
        replace(identity, sha256=[])  # type: ignore[arg-type]


def test_packaged_v2_prompt_resources_are_immutable() -> None:
    root = files("repoguard").joinpath("prompts", "agent_review")
    v1_schema = root.joinpath("v1", "response-schema.json").read_bytes()
    system = root.joinpath("v2", "system.md").read_bytes()
    schema = root.joinpath("v2", "response-schema.json").read_bytes()

    assert (
        hashlib.sha256(system + b"\0" + schema).hexdigest()
        == "5da44918793e7cdae7e411e5f811e311fe604afb9710db24584fde9da21f1560"
    )
    assert schema == v1_schema
    system_text = system.decode("utf-8")
    assert "Retrieved context is auxiliary committed-head evidence." in system_text
    assert "never cite a retrieved chunk or an unchanged line" in " ".join(system_text.split())


def test_summary_models_reject_inconsistent_ranks_counts_and_bytes() -> None:
    with pytest.raises(ValueError, match="non-contributing"):
        replace(_chunk_summary(), text_rank=1)
    with pytest.raises(ValueError, match="candidate_count"):
        replace(_summary(), candidate_count=3)
    with pytest.raises(ValueError, match="number of chunk"):
        replace(_summary(), selected_count=0, omitted_count=2)
    with pytest.raises(ValueError, match="logical_index_bytes"):
        replace(_summary(), logical_index_bytes=0)
    with pytest.raises(ValueError, match="actual_device"):
        replace(_summary(), actual_device=EmbeddingDevice.CUDA)


def test_chunk_summary_rejects_invalid_public_fields() -> None:
    with pytest.raises(ValueError, match="provenance"):
        replace(_chunk_summary(), provenance=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="canonical tuple"):
        replace(_chunk_summary(), channels=())
    with pytest.raises(ValueError, match="positive integers"):
        replace(_chunk_summary(), vector_rank=None)
    with pytest.raises(ValueError, match="matched_query_count"):
        replace(_chunk_summary(), matched_query_count=0)
    with pytest.raises(ValueError, match="rrf_score"):
        replace(_chunk_summary(), rrf_score=0)


def test_retrieval_summary_rejects_invalid_public_fields() -> None:
    with pytest.raises(ValueError, match="index"):
        replace(_summary(), index=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative"):
        replace(_summary(), query_count=-1)
    with pytest.raises(ValueError, match="built-in tuple"):
        replace(_summary(), chunks=[])  # type: ignore[arg-type]


def test_retrieval_agent_result_rejects_invalid_public_fields() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        replace(_result(), schema_version=2)
    with pytest.raises(ValueError, match="repository"):
        replace(_result(), repository=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="revisions"):
        replace(_result(), revisions=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="provider"):
        replace(_result(), provider="")
    with pytest.raises(ValueError, match="model"):
        replace(_result(), model="")
    with pytest.raises(ValueError, match="prompt"):
        replace(_result(), prompt=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="attempt_count"):
        replace(_result(), attempt_count=0)
    with pytest.raises(ValueError, match="usage"):
        replace(_result(), usage=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="prompt_bytes"):
        replace(_result(), prompt_bytes=-1)
    with pytest.raises(ValueError, match="response_bytes"):
        replace(_result(), response_bytes=-1)
    with pytest.raises(ValueError, match="retrieval"):
        replace(_result(), retrieval=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="findings"):
        replace(_result(), findings=[])  # type: ignore[arg-type]


def test_retrieval_agent_serialization_is_canonical_and_content_free() -> None:
    result = _result()

    mapping = retrieval_agent_review_to_dict(result)
    serialized = retrieval_agent_review_to_json(result)

    assert json.loads(serialized) == mapping
    assert serialized == retrieval_agent_review_to_json(result)
    assert not serialized.endswith("\n")
    retrieval = cast(dict[str, object], mapping["retrieval"])
    chunks = cast(list[dict[str, object]], retrieval["chunks"])
    assert "content" not in chunks[0]
    assert "raw_query" not in retrieval
    assert "query_sha256" not in retrieval
    assert mapping["prompt"] == {
        "name": "agent_review",
        "version": "v2",
        "sha256": "f" * 64,
    }


def test_v2_prompt_preserves_changed_evidence_and_adds_auxiliary_context() -> None:
    bundle = _bundle()
    review = review_evidence(bundle)

    rendered = _render_retrieval_prompt(
        bundle,
        review,
        (_retrieval_hit(),),
        max_retrieved_content_bytes=65_536,
        max_prompt_bytes=131_072,
    )
    user_data = json.loads(rendered.messages[1].content)

    assert rendered.identity.version == "v2"
    assert rendered.sent_hits == (_retrieval_hit(),)
    assert rendered.omitted_hit_count == 0
    assert user_data["schema_version"] == 2
    assert user_data["changes"][0]["hunks"][0]["lines"] == [
        {
            "kind": "addition",
            "old_line_number": None,
            "new_line_number": 1,
            "content": "result = helper()",
            "has_trailing_newline": True,
        },
        {
            "kind": "deletion",
            "old_line_number": 1,
            "new_line_number": None,
            "content": "result = None",
            "has_trailing_newline": True,
        },
    ]
    assert user_data["retrieved_context"][0]["content"] == ("def helper():\n    return 1\n")
    assert user_data["retrieved_context"][0]["provenance"]["path"] == "src/helper.py"


def test_v2_prompt_omits_only_whole_chunks_at_each_byte_boundary() -> None:
    bundle = _bundle()
    review = review_evidence(bundle)
    hit = _retrieval_hit()
    baseline = _render_retrieval_prompt(
        bundle,
        review,
        (),
        max_retrieved_content_bytes=65_536,
        max_prompt_bytes=131_072,
    )

    content_limited = _render_retrieval_prompt(
        bundle,
        review,
        (hit,),
        max_retrieved_content_bytes=len(hit.chunk.content.encode("utf-8")) - 1,
        max_prompt_bytes=131_072,
    )
    prompt_limited = _render_retrieval_prompt(
        bundle,
        review,
        (hit,),
        max_retrieved_content_bytes=65_536,
        max_prompt_bytes=baseline.byte_count,
    )

    assert content_limited.sent_hits == ()
    assert content_limited.omitted_hit_count == 1
    assert prompt_limited.sent_hits == ()
    assert prompt_limited.omitted_hit_count == 1
    assert prompt_limited.byte_count == baseline.byte_count
    with pytest.raises(_RetrievalPromptLimitError):
        _render_retrieval_prompt(
            bundle,
            review,
            (),
            max_retrieved_content_bytes=65_536,
            max_prompt_bytes=baseline.byte_count - 1,
        )


def test_v2_prompt_never_bypasses_a_higher_ranked_oversized_chunk() -> None:
    bundle = _bundle()
    review = review_evidence(bundle)
    high_ranked = _retrieval_hit()
    low_ranked = replace(
        high_ranked,
        chunk=ContextChunk(
            provenance=ChunkProvenance(
                chunk_id="7" * 64,
                path="a.py",
                oid="6" * 40,
                start_byte=0,
                end_byte=1,
                start_line=1,
                end_line=1,
            ),
            content="x",
            redacted_line_ranges=(),
            definitions=(),
            references=(),
        ),
        text_rank=3,
        vector_rank=2,
        rrf_score=31_754_032,
    )
    low_only = _render_retrieval_prompt(
        bundle,
        review,
        (low_ranked,),
        max_retrieved_content_bytes=65_536,
        max_prompt_bytes=131_072,
    )

    content_limited = _render_retrieval_prompt(
        bundle,
        review,
        (high_ranked, low_ranked),
        max_retrieved_content_bytes=1,
        max_prompt_bytes=131_072,
    )
    prompt_limited = _render_retrieval_prompt(
        bundle,
        review,
        (high_ranked, low_ranked),
        max_retrieved_content_bytes=65_536,
        max_prompt_bytes=low_only.byte_count,
    )

    assert content_limited.sent_hits == ()
    assert content_limited.omitted_hit_count == 2
    assert prompt_limited.sent_hits == ()
    assert prompt_limited.omitted_hit_count == 2


def test_v1_prompt_bytes_and_identity_are_unchanged_by_v2() -> None:
    bundle = _bundle()
    rendered = _render_review_prompt(bundle, review_evidence(bundle))

    assert rendered.identity.version == "v1"
    assert (
        rendered.identity.sha256
        == "a8597f69c987b5ef45e59133d750f7fce94b9d455ef70d7cfb4e15054c2c10a6"
    )
