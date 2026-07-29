"""Public contract tests for bounded hybrid context retrieval."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from repoguard.retrieval import (
    ChunkProvenance,
    ContextChunk,
    ContextIndex,
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    FastEmbedProvider,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
    retrieval_to_dict,
    retrieval_to_json,
)

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


def _statistics() -> IndexStatistics:
    return IndexStatistics(
        eligible_file_count=2,
        excluded_file_count=1,
        unparsed_python_file_count=0,
        chunk_count=1,
        original_blob_bytes=10,
        redacted_chunk_bytes=11,
        metadata_bytes=12,
        dense_matrix_bytes=1_536,
        logical_index_bytes=1_569,
    )


def _provenance() -> ChunkProvenance:
    return ChunkProvenance(
        chunk_id="d" * 64,
        path="src/example.py",
        oid="e" * 40,
        start_byte=3,
        end_byte=18,
        start_line=2,
        end_line=4,
    )


def _chunk() -> ContextChunk:
    return ContextChunk(
        provenance=_provenance(),
        content="def useful():\n",
        redacted_line_ranges=((3, 3),),
        definitions=("useful",),
        references=("helper",),
    )


def _hit() -> RetrievalHit:
    return RetrievalHit(
        chunk=_chunk(),
        channels=(RetrievalChannel.TEXT, RetrievalChannel.SYMBOL),
        text_rank=1,
        vector_rank=None,
        symbol_rank=2,
        matched_query_count=1,
        rrf_score=32_522_474,
    )


def _result() -> RetrievalResult:
    return RetrievalResult(
        index=_identity(),
        query_sha256="f" * 64,
        candidate_count=2,
        selected_count=1,
        omitted_count=1,
        hits=(_hit(),),
    )


def test_public_enums_and_error_messages_are_closed_and_stable() -> None:
    assert tuple(RetrievalChannel) == (
        RetrievalChannel.TEXT,
        RetrievalChannel.VECTOR,
        RetrievalChannel.SYMBOL,
    )
    assert tuple(EmbeddingDevice) == (
        EmbeddingDevice.AUTO,
        EmbeddingDevice.CPU,
        EmbeddingDevice.CUDA,
    )
    assert {stage.value for stage in RetrievalStage} == {
        "validate",
        "read_corpus",
        "chunk",
        "embed",
        "build_text",
        "build_vector",
        "build_symbol",
        "query_text",
        "query_vector",
        "query_symbol",
        "fuse",
        "close",
    }
    assert {code.value for code in RetrievalErrorCode} == {
        "unsupported_evidence_schema",
        "invalid_evidence",
        "invalid_configuration",
        "invalid_index",
        "index_closed",
        "git_unavailable",
        "read_failed",
        "missing_object",
        "text_backend_unavailable",
        "model_unavailable",
        "embedding_failed",
        "corpus_limit_exceeded",
        "index_limit_exceeded",
        "query_limit_exceeded",
        "deadline_exceeded",
        "backend_failed",
    }

    error = RetrievalError(
        RetrievalErrorCode.EMBEDDING_FAILED,
        RetrievalStage.EMBED,
        RetrievalChannel.VECTOR,
    )

    assert str(error) == "embedding operation failed"
    assert error.code is RetrievalErrorCode.EMBEDDING_FAILED
    assert error.stage is RetrievalStage.EMBED
    assert error.channel is RetrievalChannel.VECTOR


def test_default_configuration_and_query_are_exact_value_objects() -> None:
    config = ContextIndexConfig()

    assert config.channels == (
        RetrievalChannel.TEXT,
        RetrievalChannel.VECTOR,
        RetrievalChannel.SYMBOL,
    )
    assert config.max_files == 10_000
    assert config.max_file_bytes == 2 * 1024 * 1024
    assert config.max_corpus_bytes == 64 * 1024 * 1024
    assert config.max_chunks == 20_000
    assert config.max_index_bytes == 128 * 1024 * 1024
    assert config.build_timeout_seconds == 180.0
    assert config.query_timeout_seconds == 10.0
    assert config.chunk_tokens == 384
    assert config.chunk_overlap_tokens == 64
    assert config.max_candidates_per_channel == 32
    assert config.max_results == 12
    assert ContextQuery("lookup") == ContextQuery("lookup")
    with pytest.raises(FrozenInstanceError):
        config.max_files = 1  # type: ignore[misc]


def test_fastembed_provider_construction_is_lazy_and_explicit() -> None:
    provider = FastEmbedProvider(
        cache_dir=Path("/external/model-cache"),
        device=EmbeddingDevice.CPU,
    )

    assert provider.name == "fastembed"
    assert provider.model == "BAAI/bge-small-en-v1.5"
    assert provider.dimension == 384
    with pytest.raises(RuntimeError, match="has not been initialized"):
        _ = provider.actual_device


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    [
        ({"cache_dir": "/tmp/model"}, TypeError),
        ({"cache_dir": Path("/tmp/model"), "allow_download": 1}, TypeError),
        ({"cache_dir": Path("/tmp/model"), "device": "cpu"}, TypeError),
    ],
)
def test_fastembed_provider_rejects_invalid_constructor_values(
    kwargs: dict[str, object],
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        FastEmbedProvider(**kwargs)  # type: ignore[arg-type]


def test_fastembed_provider_rejects_non_utf8_cache_path() -> None:
    with pytest.raises(ValueError, match="valid UTF-8"):
        FastEmbedProvider(cache_dir=Path("/external/\ud800"))


def test_result_models_reject_inconsistent_invariants() -> None:
    with pytest.raises(ValueError, match="logical_index_bytes"):
        replace(_statistics(), logical_index_bytes=1)
    with pytest.raises(ValueError, match="head_oid"):
        replace(_identity(), head_oid="A" * 40)
    with pytest.raises(ValueError, match="canonical tuple"):
        replace(
            _identity(),
            channels=(RetrievalChannel.SYMBOL, RetrievalChannel.TEXT),
        )
    with pytest.raises(ValueError, match="Git-relative"):
        replace(_provenance(), path="../escape.py")
    with pytest.raises(ValueError, match="ordered disjoint"):
        replace(_chunk(), redacted_line_ranges=((3, 4), (4, 4)))
    with pytest.raises(ValueError, match="non-contributing"):
        replace(_hit(), vector_rank=1)
    with pytest.raises(ValueError, match="candidate_count"):
        replace(_result(), candidate_count=3)


def test_index_identity_rejects_every_noncanonical_identity_component() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        replace(_identity(), schema_version=2)
    with pytest.raises(ValueError, match="absolute"):
        replace(_identity(), repository_root=Path("relative"))
    with pytest.raises(ValueError, match="valid UTF-8"):
        replace(_identity(), repository_root=Path("/work/\ud800"))
    with pytest.raises(ValueError, match="config_sha256"):
        replace(_identity(), config_sha256="A" * 64)
    with pytest.raises(ValueError, match="fixed BGE"):
        replace(_identity(), model="other")
    with pytest.raises(ValueError, match="fixed model revision"):
        replace(_identity(), model_revision="other")
    with pytest.raises(ValueError, match="manifest_sha256"):
        replace(_identity(), manifest_sha256="short")
    with pytest.raises(ValueError, match="dimension"):
        replace(_identity(), dimension=True)
    with pytest.raises(ValueError, match="actual_device"):
        replace(_identity(), actual_device=EmbeddingDevice.AUTO)


def test_index_statistics_rejects_invalid_counts() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        replace(_statistics(), eligible_file_count=-1)
    with pytest.raises(ValueError, match="unparsed_python_file_count"):
        replace(
            _statistics(),
            eligible_file_count=0,
            unparsed_python_file_count=1,
        )


def test_chunk_models_reject_invalid_provenance_content_and_symbols() -> None:
    with pytest.raises(ValueError, match="chunk_id"):
        replace(_provenance(), chunk_id="bad")
    with pytest.raises(ValueError, match="object ID"):
        replace(_provenance(), oid="A" * 40)
    with pytest.raises(ValueError, match="byte offsets"):
        replace(_provenance(), start_byte=18)
    with pytest.raises(ValueError, match="line numbers"):
        replace(_provenance(), start_line=0)
    with pytest.raises(ValueError, match="provenance"):
        replace(_chunk(), provenance=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty"):
        replace(_chunk(), content="")
    with pytest.raises(ValueError, match="valid UTF-8"):
        replace(_chunk(), content="\ud800")
    with pytest.raises(ValueError, match="built-in tuple"):
        replace(_chunk(), redacted_line_ranges=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ordered disjoint"):
        replace(_chunk(), redacted_line_ranges=((1, 1),))
    with pytest.raises(ValueError, match="unique tuple"):
        replace(_chunk(), definitions=("useful", "useful"))


def test_hit_and_result_models_reject_invalid_ranks_and_counts() -> None:
    with pytest.raises(ValueError, match="chunk"):
        replace(_hit(), chunk=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="integers from 1 through 32"):
        replace(_hit(), text_rank=None)
    with pytest.raises(ValueError, match="integers from 1 through 32"):
        replace(_hit(), text_rank=33)
    with pytest.raises(ValueError, match="matched_query_count"):
        replace(_hit(), matched_query_count=0)
    with pytest.raises(ValueError, match="matched_query_count"):
        replace(_hit(), matched_query_count=257)
    with pytest.raises(ValueError, match="rrf_score"):
        replace(_hit(), rrf_score=0)
    with pytest.raises(ValueError, match="schema_version"):
        replace(_result(), schema_version=2)
    with pytest.raises(ValueError, match="index"):
        replace(_result(), index=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="query_sha256"):
        replace(_result(), query_sha256="bad")
    with pytest.raises(ValueError, match="non-negative"):
        replace(_result(), omitted_count=-1)
    with pytest.raises(ValueError, match="built-in tuple"):
        replace(_result(), hits=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at most 12"):
        replace(
            _result(),
            candidate_count=13,
            selected_count=13,
            omitted_count=0,
            hits=tuple(
                replace(
                    _hit(),
                    chunk=replace(
                        _chunk(),
                        provenance=replace(
                            _provenance(),
                            chunk_id=f"{index:064x}",
                        ),
                    ),
                )
                for index in range(13)
            ),
        )
    with pytest.raises(ValueError, match="selected_count"):
        replace(_result(), selected_count=0, omitted_count=2)
    with pytest.raises(ValueError, match="unique chunk IDs"):
        replace(
            _result(),
            candidate_count=2,
            selected_count=2,
            omitted_count=0,
            hits=(_hit(), _hit()),
        )


def test_index_identity_rejects_unhashable_values_with_stable_validation() -> None:
    with pytest.raises(ValueError, match="object_format"):
        replace(_identity(), object_format=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="actual_device"):
        replace(_identity(), actual_device=[])  # type: ignore[arg-type]


def test_retrieval_serialization_is_canonical_and_omits_raw_query() -> None:
    result = _result()

    mapping = retrieval_to_dict(result)
    serialized = retrieval_to_json(result)

    assert json.loads(serialized) == mapping
    assert serialized == retrieval_to_json(result)
    assert serialized.encode("utf-8")
    assert not serialized.endswith("\n")
    assert "lookup" not in serialized
    assert mapping["query_sha256"] == "f" * 64
    assert mapping["index"] == {
        "schema_version": 1,
        "repository_root": "/work/repository",
        "object_format": "sha1",
        "head_oid": "a" * 40,
        "channels": ["text", "vector", "symbol"],
        "config_sha256": "b" * 64,
        "model": "BAAI/bge-small-en-v1.5",
        "model_revision": MODEL_REVISION,
        "manifest_sha256": "c" * 64,
        "dimension": 384,
        "actual_device": "cpu",
    }


class _FakeIndexState:
    def __init__(self) -> None:
        self.identity = _identity()
        self.statistics = _statistics()
        self.closed = False
        self.close_count = 0

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.close_count += 1


def test_context_index_delegates_identity_statistics_and_lifecycle() -> None:
    state = _FakeIndexState()
    index = ContextIndex(state)

    assert index.identity == _identity()
    assert index.statistics == _statistics()
    assert not state.closed

    with index as entered:
        assert entered is index

    assert state.closed
    assert state.close_count == 1
    index.close()
    assert state.close_count == 1
