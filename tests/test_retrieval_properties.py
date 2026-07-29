"""Deterministic properties for M4 chunking, redaction, and fusion math."""

from __future__ import annotations

import itertools
import time
from typing import Literal

from hypothesis import example, given, settings
from hypothesis import strategies as st

from repoguard._retrieval import (
    _build_chunks,
    _CorpusFile,
    _prepare_file,
    _ranges_cover,
    _rrf_contribution,
)
from repoguard.retrieval import (
    ContextIndexConfig,
    EmbeddingDevice,
    RetrievalChannel,
)

PROPERTY_SETTINGS = settings(database=None, derandomize=True, max_examples=100)
SURROGATE_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
UTF8_TEXT = st.text(
    alphabet=st.characters(
        exclude_categories=SURROGATE_CATEGORIES,
        exclude_characters="-\x00\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029",
    ),
    min_size=1,
    max_size=40,
)


class _TokenProvider:
    @property
    def name(self) -> str:
        return "property-fake"

    @property
    def model(self) -> str:
        return "BAAI/bge-small-en-v1.5"

    @property
    def dimension(self) -> int:
        return 384

    @property
    def actual_device(self) -> EmbeddingDevice:
        return EmbeddingDevice.CPU

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        return ((0, 0), *((index, index + 1) for index in range(len(text))), (0, 0))

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        raise AssertionError(texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        raise AssertionError(texts)

    def close(self) -> None:
        pass


class _ContextSensitiveTokenProvider(_TokenProvider):
    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        width = 2 if text.endswith("\n") else 1
        return (
            (0, 0),
            *((start, min(len(text), start + width)) for start in range(0, len(text), width)),
            (0, 0),
        )


@PROPERTY_SETTINGS
@example(lines=["a"])
@example(lines=["é", "中文", "emoji 😀"])
@given(lines=st.lists(UTF8_TEXT, min_size=1, max_size=10))
def test_chunking_covers_every_original_byte_with_bounded_tokens(
    lines: list[str],
) -> None:
    content = ("\n".join(lines) + "\n").encode("utf-8")
    provider = _TokenProvider()
    config = ContextIndexConfig(
        channels=(RetrievalChannel.TEXT,),
        chunk_tokens=8,
        chunk_overlap_tokens=2,
    )

    chunks, unparsed, python_line_terms = _build_chunks(
        (_CorpusFile(path="notes.txt", oid="a" * 40, content=content),),
        head_oid="b" * 40,
        provider=provider,
        config=config,
        deadline=time.monotonic() + 10.0,
    )

    ranges = tuple((chunk.provenance.start_byte, chunk.provenance.end_byte) for chunk in chunks)
    assert _ranges_cover(ranges, len(content))
    assert unparsed == 0
    assert python_line_terms == {}
    assert all(len(provider.token_spans(chunk.content)) <= config.chunk_tokens for chunk in chunks)
    assert all(
        content[chunk.provenance.start_byte : chunk.provenance.end_byte].decode("utf-8")
        for chunk in chunks
    )


@PROPERTY_SETTINGS
@example(size=40)
@example(size=160)
@given(size=st.integers(min_value=20, max_value=300))
def test_context_sensitive_retokenization_preserves_chunk_invariants(size: int) -> None:
    content = ("a" * size + "\n").encode()
    provider = _ContextSensitiveTokenProvider()
    config = ContextIndexConfig(
        channels=(RetrievalChannel.TEXT,),
        chunk_tokens=16,
        chunk_overlap_tokens=4,
    )

    first, first_unparsed, first_line_terms = _build_chunks(
        (_CorpusFile(path="context.txt", oid="a" * 40, content=content),),
        head_oid="b" * 40,
        provider=provider,
        config=config,
        deadline=time.monotonic() + 10.0,
    )
    second, second_unparsed, second_line_terms = _build_chunks(
        (_CorpusFile(path="context.txt", oid="a" * 40, content=content),),
        head_oid="b" * 40,
        provider=provider,
        config=config,
        deadline=time.monotonic() + 10.0,
    )

    ranges = tuple((chunk.provenance.start_byte, chunk.provenance.end_byte) for chunk in first)
    assert first == second
    assert first_unparsed == second_unparsed == 0
    assert first_line_terms == second_line_terms == {}
    assert _ranges_cover(ranges, len(content))
    assert all(len(provider.token_spans(chunk.content)) <= config.chunk_tokens for chunk in first)
    assert all(
        right.provenance.start_byte < left.provenance.end_byte
        for left, right in itertools.pairwise(first)
    )


@PROPERTY_SETTINGS
@example(secret_body="SENSITIVE_IDENTIFIER = 1")
@example(secret_body="é中😀")
@given(secret_body=UTF8_TEXT)
def test_private_key_projection_never_contains_generated_secret_body(
    secret_body: str,
) -> None:
    secret_marker = f"ZXQ{secret_body.encode().hex()}QXZ"
    content = (
        "safe prefix\n"
        "-----BEGIN PRIVATE KEY-----\n"
        f"{secret_marker}\n"
        "-----END PRIVATE KEY-----\n"
        "safe suffix\n"
    ).encode()

    prepared = _prepare_file(
        _CorpusFile(
            path="secrets/material.txt",
            oid="a" * 40,
            content=content,
        )
    )

    assert prepared.redacted_ranges == ((2, 4),)
    assert secret_marker not in prepared.projection
    assert prepared.projection.count("[REDACTED_PRIVATE_KEY_MATERIAL]") == 3
    assert prepared.projection.startswith("safe prefix\n")
    assert prepared.projection.endswith("safe suffix\n")


@PROPERTY_SETTINGS
@example(rank=1)
@example(rank=32)
@given(rank=st.integers(min_value=1, max_value=31))
def test_rrf_contribution_is_positive_and_strictly_decreases(rank: int) -> None:
    contribution = _rrf_contribution(rank)
    next_contribution = _rrf_contribution(rank + 1)

    assert contribution > next_contribution > 0
    assert contribution == 1_000_000_000 // (60 + rank)


@PROPERTY_SETTINGS
@example(size=1, ranges=[(0, 1)])
@example(size=5, ranges=[(2, 5), (0, 3)])
@given(
    size=st.integers(min_value=1, max_value=100),
    ranges=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=100),
            st.integers(min_value=0, max_value=100),
        ),
        max_size=8,
    ),
)
def test_range_coverage_is_permutation_invariant_and_monotone(
    size: int,
    ranges: list[tuple[int, int]],
) -> None:
    normalized = tuple(
        (min(start, end, size), min(max(start, end), size))
        for start, end in ranges
        if min(start, end, size) < min(max(start, end), size)
    )
    baseline = _ranges_cover(normalized, size)

    for permutation in itertools.islice(itertools.permutations(normalized), 24):
        assert _ranges_cover(permutation, size) is baseline
    if baseline:
        assert _ranges_cover((*normalized, (0, size)), size)
