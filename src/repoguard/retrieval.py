"""Public contracts for bounded hybrid repository context retrieval."""

from __future__ import annotations

import json
import re
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Protocol, runtime_checkable

from repoguard.evidence import EvidenceBundle

__all__ = [
    "ChunkProvenance",
    "ContextChunk",
    "ContextIndex",
    "ContextIndexConfig",
    "ContextQuery",
    "EmbeddingDevice",
    "EmbeddingProvider",
    "FastEmbedProvider",
    "IndexIdentity",
    "IndexStatistics",
    "RetrievalChannel",
    "RetrievalError",
    "RetrievalErrorCode",
    "RetrievalHit",
    "RetrievalResult",
    "RetrievalStage",
    "build_context_index",
    "retrieval_to_dict",
    "retrieval_to_json",
    "retrieve_context",
]

_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class RetrievalChannel(StrEnum):
    """One independently ranked retrieval channel."""

    TEXT = "text"
    VECTOR = "vector"
    SYMBOL = "symbol"


_CHANNEL_ORDER = {
    RetrievalChannel.TEXT: 0,
    RetrievalChannel.VECTOR: 1,
    RetrievalChannel.SYMBOL: 2,
}


class RetrievalStage(StrEnum):
    """Stable location of a retrieval failure."""

    VALIDATE = "validate"
    READ_CORPUS = "read_corpus"
    CHUNK = "chunk"
    EMBED = "embed"
    BUILD_TEXT = "build_text"
    BUILD_VECTOR = "build_vector"
    BUILD_SYMBOL = "build_symbol"
    QUERY_TEXT = "query_text"
    QUERY_VECTOR = "query_vector"
    QUERY_SYMBOL = "query_symbol"
    FUSE = "fuse"
    CLOSE = "close"


class RetrievalErrorCode(StrEnum):
    """Stable category for an atomic retrieval failure."""

    UNSUPPORTED_EVIDENCE_SCHEMA = "unsupported_evidence_schema"
    INVALID_EVIDENCE = "invalid_evidence"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_INDEX = "invalid_index"
    INDEX_CLOSED = "index_closed"
    GIT_UNAVAILABLE = "git_unavailable"
    READ_FAILED = "read_failed"
    MISSING_OBJECT = "missing_object"
    TEXT_BACKEND_UNAVAILABLE = "text_backend_unavailable"
    MODEL_UNAVAILABLE = "model_unavailable"
    EMBEDDING_FAILED = "embedding_failed"
    CORPUS_LIMIT_EXCEEDED = "corpus_limit_exceeded"
    INDEX_LIMIT_EXCEEDED = "index_limit_exceeded"
    QUERY_LIMIT_EXCEEDED = "query_limit_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    BACKEND_FAILED = "backend_failed"


_ERROR_MESSAGES = {
    RetrievalErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA: "evidence schema is unsupported",
    RetrievalErrorCode.INVALID_EVIDENCE: "retrieval evidence is invalid",
    RetrievalErrorCode.INVALID_CONFIGURATION: "retrieval configuration is invalid",
    RetrievalErrorCode.INVALID_INDEX: "context index is invalid",
    RetrievalErrorCode.INDEX_CLOSED: "context index is closed",
    RetrievalErrorCode.GIT_UNAVAILABLE: "Git executable is unavailable",
    RetrievalErrorCode.READ_FAILED: "committed corpus could not be read",
    RetrievalErrorCode.MISSING_OBJECT: "a required committed object is unavailable",
    RetrievalErrorCode.TEXT_BACKEND_UNAVAILABLE: "text retrieval backend is unavailable",
    RetrievalErrorCode.MODEL_UNAVAILABLE: "embedding model is unavailable",
    RetrievalErrorCode.EMBEDDING_FAILED: "embedding operation failed",
    RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED: "retrieval corpus limit exceeded",
    RetrievalErrorCode.INDEX_LIMIT_EXCEEDED: "context index limit exceeded",
    RetrievalErrorCode.QUERY_LIMIT_EXCEEDED: "retrieval query limit exceeded",
    RetrievalErrorCode.DEADLINE_EXCEEDED: "retrieval deadline exceeded",
    RetrievalErrorCode.BACKEND_FAILED: "retrieval backend failed",
}


class RetrievalError(RuntimeError):
    """Secret-safe retrieval failure with stable machine-readable fields."""

    code: RetrievalErrorCode
    stage: RetrievalStage
    channel: RetrievalChannel | None

    def __init__(
        self,
        code: RetrievalErrorCode,
        stage: RetrievalStage,
        channel: RetrievalChannel | None = None,
    ) -> None:
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code
        self.stage = stage
        self.channel = channel


class EmbeddingDevice(StrEnum):
    """Requested or selected ONNX execution device."""

    AUTO = "auto"
    CPU = "cpu"
    CUDA = "cuda"


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Synchronous tokenizer and embedding contract owned by one context index."""

    @property
    def name(self) -> str:
        """Return a stable provider name."""

    @property
    def model(self) -> str:
        """Return the fixed model identity."""

    @property
    def dimension(self) -> int:
        """Return the exact embedding dimension."""

    @property
    def actual_device(self) -> EmbeddingDevice:
        """Return the selected execution device."""

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        """Return tokenizer offsets as half-open Python string indices."""

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        """Return one normalized vector per document."""

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        """Return one normalized vector per query."""

    def close(self) -> None:
        """Release provider-owned model and runtime state."""


class FastEmbedProvider:
    """Fixed, explicit-cache BGE Small provider backed by FastEmbed."""

    __slots__ = (
        "__weakref__",
        "_actual_device",
        "_allow_download",
        "_backend",
        "_cache_dir",
        "_requested_device",
    )

    def __init__(
        self,
        *,
        cache_dir: Path,
        allow_download: bool = False,
        device: EmbeddingDevice = EmbeddingDevice.AUTO,
    ) -> None:
        if not isinstance(cache_dir, Path):
            msg = "cache_dir must be a pathlib.Path"
            raise TypeError(msg)
        try:
            str(cache_dir).encode("utf-8")
        except UnicodeEncodeError as error:
            msg = "cache_dir must be valid UTF-8"
            raise ValueError(msg) from error
        if type(allow_download) is not bool:
            msg = "allow_download must be a boolean"
            raise TypeError(msg)
        if not isinstance(device, EmbeddingDevice):
            msg = "device must be an EmbeddingDevice"
            raise TypeError(msg)
        self._cache_dir = cache_dir
        self._allow_download = allow_download
        self._requested_device = device
        self._actual_device: EmbeddingDevice | None = None
        self._backend: object | None = None

    @property
    def name(self) -> str:
        return "fastembed"

    @property
    def model(self) -> str:
        return _MODEL

    @property
    def dimension(self) -> int:
        return 384

    @property
    def actual_device(self) -> EmbeddingDevice:
        if self._actual_device is None:
            msg = "FastEmbedProvider has not been initialized"
            raise RuntimeError(msg)
        return self._actual_device

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        from repoguard._embedding import _token_spans

        return _token_spans(self, text)

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        from repoguard._embedding import _embed_documents

        return _embed_documents(self, texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        from repoguard._embedding import _embed_queries

        return _embed_queries(self, texts)

    def close(self) -> None:
        from repoguard._embedding import _close_fastembed

        _close_fastembed(self)


@dataclass(frozen=True, slots=True)
class ContextIndexConfig:
    """Caller-lowerable limits and channel selection for one index."""

    channels: tuple[RetrievalChannel, ...] = (
        RetrievalChannel.TEXT,
        RetrievalChannel.VECTOR,
        RetrievalChannel.SYMBOL,
    )
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = ()
    max_files: int = 10_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_corpus_bytes: int = 64 * 1024 * 1024
    max_chunks: int = 20_000
    max_index_bytes: int = 128 * 1024 * 1024
    build_timeout_seconds: float = 180.0
    query_timeout_seconds: float = 10.0
    chunk_tokens: int = 384
    chunk_overlap_tokens: int = 64
    max_candidates_per_channel: int = 32
    max_results: int = 12


@dataclass(frozen=True, slots=True)
class ContextQuery:
    """Explicit untrusted query for standalone retrieval."""

    text: str


_DEFAULT_CONTEXT_INDEX_CONFIG = ContextIndexConfig()


@dataclass(frozen=True, slots=True)
class IndexIdentity:
    """Immutable identity of an in-memory context index."""

    repository_root: Path
    object_format: str
    head_oid: str
    channels: tuple[RetrievalChannel, ...]
    config_sha256: str
    model: str
    model_revision: str
    manifest_sha256: str
    dimension: int
    actual_device: EmbeddingDevice
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)
        if not isinstance(self.repository_root, Path) or not self.repository_root.is_absolute():
            msg = "repository_root must be an absolute pathlib.Path"
            raise ValueError(msg)
        _validate_utf8(str(self.repository_root), "repository_root must be valid UTF-8")
        if type(self.object_format) is not str or self.object_format not in ("sha1", "sha256"):
            msg = "object_format must be sha1 or sha256"
            raise ValueError(msg)
        expected_oid_length = 40 if self.object_format == "sha1" else 64
        if (
            type(self.head_oid) is not str
            or len(self.head_oid) != expected_oid_length
            or _OID_PATTERN.fullmatch(self.head_oid) is None
        ):
            msg = "head_oid must match object_format"
            raise ValueError(msg)
        _validate_channels(self.channels)
        _validate_sha256(self.config_sha256, "config_sha256")
        if self.model != _MODEL:
            msg = "model must identify the fixed BGE model"
            raise ValueError(msg)
        if self.model_revision != _MODEL_REVISION:
            msg = "model_revision must identify the fixed model revision"
            raise ValueError(msg)
        _validate_sha256(self.manifest_sha256, "manifest_sha256")
        if type(self.dimension) is not int or self.dimension != 384:
            msg = "dimension must be 384"
            raise ValueError(msg)
        if not isinstance(self.actual_device, EmbeddingDevice) or self.actual_device not in (
            EmbeddingDevice.CPU,
            EmbeddingDevice.CUDA,
        ):
            msg = "actual_device must be cpu or cuda"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class IndexStatistics:
    """Deterministic counts and logical byte accounting."""

    eligible_file_count: int
    excluded_file_count: int
    unparsed_python_file_count: int
    chunk_count: int
    original_blob_bytes: int
    redacted_chunk_bytes: int
    metadata_bytes: int
    dense_matrix_bytes: int
    logical_index_bytes: int

    def __post_init__(self) -> None:
        values = (
            self.eligible_file_count,
            self.excluded_file_count,
            self.unparsed_python_file_count,
            self.chunk_count,
            self.original_blob_bytes,
            self.redacted_chunk_bytes,
            self.metadata_bytes,
            self.dense_matrix_bytes,
            self.logical_index_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            msg = "index statistics must be non-negative integers"
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
        if self.unparsed_python_file_count > self.eligible_file_count:
            msg = "unparsed_python_file_count cannot exceed eligible_file_count"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ChunkProvenance:
    """Exact committed identity and original byte/line range of one chunk."""

    chunk_id: str
    path: str
    oid: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        _validate_sha256(self.chunk_id, "chunk_id")
        _validate_git_path(self.path)
        if type(self.oid) is not str or _OID_PATTERN.fullmatch(self.oid) is None:
            msg = "oid must be a lowercase Git object ID"
            raise ValueError(msg)
        if (
            type(self.start_byte) is not int
            or type(self.end_byte) is not int
            or not 0 <= self.start_byte < self.end_byte
        ):
            msg = "byte offsets must be a non-empty ordered range"
            raise ValueError(msg)
        if (
            type(self.start_line) is not int
            or type(self.end_line) is not int
            or not 1 <= self.start_line <= self.end_line
        ):
            msg = "line numbers must be an ordered positive range"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ContextChunk:
    """Redacted context projection with committed provenance and symbols."""

    provenance: ChunkProvenance
    content: str
    redacted_line_ranges: tuple[tuple[int, int], ...]
    definitions: tuple[str, ...]
    references: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, ChunkProvenance):
            msg = "provenance must be ChunkProvenance"
            raise ValueError(msg)
        if type(self.content) is not str or not self.content:
            msg = "content must be a non-empty string"
            raise ValueError(msg)
        _validate_utf8(self.content, "content must be valid UTF-8")
        if type(self.redacted_line_ranges) is not tuple:
            msg = "redacted_line_ranges must be a built-in tuple"
            raise ValueError(msg)
        previous_end = 0
        for line_range in self.redacted_line_ranges:
            if (
                type(line_range) is not tuple
                or len(line_range) != 2
                or type(line_range[0]) is not int
                or type(line_range[1]) is not int
                or not self.provenance.start_line <= line_range[0] <= line_range[1]
                or line_range[1] > self.provenance.end_line
                or line_range[0] <= previous_end
            ):
                msg = "redacted_line_ranges must be ordered disjoint line ranges"
                raise ValueError(msg)
            previous_end = line_range[1]
        _validate_symbols(self.definitions, "definitions")
        _validate_symbols(self.references, "references")


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    """One fused context hit."""

    chunk: ContextChunk
    channels: tuple[RetrievalChannel, ...]
    text_rank: int | None
    vector_rank: int | None
    symbol_rank: int | None
    matched_query_count: int
    rrf_score: int

    def __post_init__(self) -> None:
        if not isinstance(self.chunk, ContextChunk):
            msg = "chunk must be ContextChunk"
            raise ValueError(msg)
        _validate_channels(self.channels)
        ranks = {
            RetrievalChannel.TEXT: self.text_rank,
            RetrievalChannel.VECTOR: self.vector_rank,
            RetrievalChannel.SYMBOL: self.symbol_rank,
        }
        for channel, rank in ranks.items():
            if channel in self.channels:
                if type(rank) is not int or not 1 <= rank <= 32:
                    msg = "contributing channel ranks must be integers from 1 through 32"
                    raise ValueError(msg)
            elif rank is not None:
                msg = "non-contributing channel ranks must be None"
                raise ValueError(msg)
        if type(self.matched_query_count) is not int or not 1 <= self.matched_query_count <= 256:
            msg = "matched_query_count must be an integer from 1 through 256"
            raise ValueError(msg)
        if type(self.rrf_score) is not int or self.rrf_score <= 0:
            msg = "rrf_score must be a positive integer"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    """Versioned result of one complete retrieval call."""

    index: IndexIdentity
    query_sha256: str
    candidate_count: int
    selected_count: int
    omitted_count: int
    hits: tuple[RetrievalHit, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)
        if not isinstance(self.index, IndexIdentity):
            msg = "index must be IndexIdentity"
            raise ValueError(msg)
        _validate_sha256(self.query_sha256, "query_sha256")
        counts = (self.candidate_count, self.selected_count, self.omitted_count)
        if any(type(value) is not int or value < 0 for value in counts):
            msg = "retrieval counts must be non-negative integers"
            raise ValueError(msg)
        if type(self.hits) is not tuple or not all(
            isinstance(hit, RetrievalHit) for hit in self.hits
        ):
            msg = "hits must be a built-in tuple of RetrievalHit values"
            raise ValueError(msg)
        if len(self.hits) > 12:
            msg = "hits must contain at most 12 values"
            raise ValueError(msg)
        if self.selected_count != len(self.hits):
            msg = "selected_count must equal the number of hits"
            raise ValueError(msg)
        if self.candidate_count != self.selected_count + self.omitted_count:
            msg = "candidate_count must equal selected_count plus omitted_count"
            raise ValueError(msg)
        chunk_ids = tuple(hit.chunk.provenance.chunk_id for hit in self.hits)
        if len(set(chunk_ids)) != len(chunk_ids):
            msg = "hits must have unique chunk IDs"
            raise ValueError(msg)


@runtime_checkable
class _ContextIndexState(Protocol):
    @property
    def identity(self) -> IndexIdentity: ...

    @property
    def statistics(self) -> IndexStatistics: ...

    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


class ContextIndex:
    """Opaque process-local owner of immutable native retrieval state."""

    __slots__ = ("_state",)

    def __init__(self, state: _ContextIndexState) -> None:
        self._state = state

    @property
    def identity(self) -> IndexIdentity:
        return self._state.identity

    @property
    def statistics(self) -> IndexStatistics:
        return self._state.statistics

    def close(self) -> None:
        self._state.close()

    def __enter__(self) -> ContextIndex:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


def build_context_index(
    bundle: EvidenceBundle,
    *,
    embedding_provider: EmbeddingProvider,
    config: ContextIndexConfig = _DEFAULT_CONTEXT_INDEX_CONFIG,
    git_executable: Path | None = None,
) -> ContextIndex:
    """Build one atomic in-memory index over an immutable committed head tree."""
    from repoguard._retrieval import _build_context_index

    return _build_context_index(
        bundle,
        embedding_provider=embedding_provider,
        config=config,
        git_executable=git_executable,
    )


def retrieve_context(index: ContextIndex, query: ContextQuery) -> RetrievalResult:
    """Retrieve hybrid context from an existing live index."""
    from repoguard._retrieval import _retrieve_context

    return _retrieve_context(index, query)


def retrieval_to_dict(result: RetrievalResult) -> dict[str, object]:
    """Convert a retrieval result to its canonical JSON-compatible mapping."""
    return {
        "schema_version": result.schema_version,
        "index": _identity_to_dict(result.index),
        "query_sha256": result.query_sha256,
        "candidate_count": result.candidate_count,
        "selected_count": result.selected_count,
        "omitted_count": result.omitted_count,
        "hits": [_hit_to_dict(hit) for hit in result.hits],
    }


def retrieval_to_json(result: RetrievalResult) -> str:
    """Serialize a retrieval result as canonical compact UTF-8 JSON."""
    return json.dumps(
        retrieval_to_dict(result),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _identity_to_dict(identity: IndexIdentity) -> dict[str, object]:
    return {
        "schema_version": identity.schema_version,
        "repository_root": str(identity.repository_root),
        "object_format": identity.object_format,
        "head_oid": identity.head_oid,
        "channels": [channel.value for channel in identity.channels],
        "config_sha256": identity.config_sha256,
        "model": identity.model,
        "model_revision": identity.model_revision,
        "manifest_sha256": identity.manifest_sha256,
        "dimension": identity.dimension,
        "actual_device": identity.actual_device.value,
    }


def _provenance_to_dict(provenance: ChunkProvenance) -> dict[str, object]:
    return {
        "chunk_id": provenance.chunk_id,
        "path": provenance.path,
        "oid": provenance.oid,
        "start_byte": provenance.start_byte,
        "end_byte": provenance.end_byte,
        "start_line": provenance.start_line,
        "end_line": provenance.end_line,
    }


def _chunk_to_dict(chunk: ContextChunk) -> dict[str, object]:
    return {
        "provenance": _provenance_to_dict(chunk.provenance),
        "content": chunk.content,
        "redacted_line_ranges": [
            {"start_line": start, "end_line": end} for start, end in chunk.redacted_line_ranges
        ],
        "definitions": list(chunk.definitions),
        "references": list(chunk.references),
    }


def _hit_to_dict(hit: RetrievalHit) -> dict[str, object]:
    return {
        "chunk": _chunk_to_dict(hit.chunk),
        "channels": [channel.value for channel in hit.channels],
        "text_rank": hit.text_rank,
        "vector_rank": hit.vector_rank,
        "symbol_rank": hit.symbol_rank,
        "matched_query_count": hit.matched_query_count,
        "rrf_score": hit.rrf_score,
    }


def _validate_sha256(value: object, name: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        msg = f"{name} must be lowercase SHA-256 hexadecimal"
        raise ValueError(msg)


def _validate_utf8(value: str, message: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(message) from error


def _validate_git_path(path: object) -> None:
    if (
        type(path) is not str
        or not path
        or path.startswith("/")
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        msg = "path must be a non-empty Git-relative POSIX path"
        raise ValueError(msg)
    _validate_utf8(path, "path must be valid UTF-8")


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


def _validate_symbols(symbols: object, name: str) -> None:
    if (
        type(symbols) is not tuple
        or not all(type(symbol) is str and symbol.isidentifier() for symbol in symbols)
        or len(set(symbols)) != len(symbols)
    ):
        msg = f"{name} must be a unique tuple of Python identifiers"
        raise ValueError(msg)
