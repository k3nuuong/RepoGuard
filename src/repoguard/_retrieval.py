"""Private implementation of bounded hybrid repository context retrieval."""

from __future__ import annotations

import ast
import codecs
import hashlib
import importlib
import io
import json
import keyword
import math
import os
import re
import selectors
import sqlite3
import subprocess
import threading
import time
import tokenize
import unicodedata
import weakref
from bisect import bisect_right
from collections import defaultdict, deque
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from importlib.resources import files
from itertools import pairwise
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Never, Protocol, cast

import numpy as np
from numpy.typing import NDArray

from repoguard._review import _PRIVATE_KEY_MARKER_PATTERN
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
    ContextIndex,
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    EmbeddingProvider,
    FastEmbedProvider,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
)

_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"
_DIMENSION = 384
_REDACTION_SENTINEL = "[REDACTED_PRIVATE_KEY_MATERIAL]"
_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_LOWERCASE_HEX = re.compile(r"^[0-9a-f]+$")
_WORD = re.compile(r"\w+", re.UNICODE)
_IDENTIFIER = re.compile(r"[^\W\d]\w*", re.UNICODE)
_CAMEL_PART = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|\d|\Z)|[A-Z]?[a-z]+|[A-Z]+|\d+",
)
_LINE_ENDINGS = (
    "\r\n",
    "\n",
    "\r",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)
_CHANNEL_ORDER = {
    RetrievalChannel.TEXT: 0,
    RetrievalChannel.VECTOR: 1,
    RetrievalChannel.SYMBOL: 2,
}
_MAX_CONFIG = {
    "max_files": 10_000,
    "max_file_bytes": 2 * 1024 * 1024,
    "max_corpus_bytes": 64 * 1024 * 1024,
    "max_chunks": 20_000,
    "max_index_bytes": 128 * 1024 * 1024,
    "chunk_tokens": 384,
    "chunk_overlap_tokens": 64,
    "max_candidates_per_channel": 32,
    "max_results": 12,
}
_MAX_BUILD_SECONDS = 180.0
_MAX_QUERY_SECONDS = 10.0
_MAX_QUERY_BYTES = 4096
_MAX_QUERY_TOKENS = 384
_MAX_EMBEDDING_DOCUMENT_TOKENS = 512
_MAX_BATCH_QUERIES = 256
_RRF_K = 60
_RRF_SCALE = 1_000_000_000
_EMBED_BATCH_SIZE = 128
_GIT_READ_BYTES = 64 * 1024
_GIT_CONTROL_OUTPUT_BYTES = 4096
_GIT_TREE_OUTPUT_BYTES = 128 * 1024 * 1024
_NORMALIZATION_TOLERANCE = 1e-3
_FLOAT32_MAX = float(np.finfo(np.float32).max)

type _FloatMatrix = NDArray[np.float32]
type _Rankings = dict[RetrievalChannel, tuple[int, ...]]
type _ProviderReference = Callable[[], object | None]
type _ProviderRegistryEntry = tuple[_ProviderReference, object | None]


class _FaissIndex(Protocol):
    @property
    def ntotal(self) -> int: ...

    @property
    def d(self) -> int: ...

    def add(self, values: _FloatMatrix) -> None: ...

    def search(
        self,
        values: _FloatMatrix,
        count: int,
    ) -> tuple[_FloatMatrix, NDArray[np.int64]]: ...

    def reset(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    mode: str
    kind: str
    oid: str
    path: str


@dataclass(frozen=True, slots=True)
class _CorpusFile:
    path: str
    oid: str
    content: bytes


@dataclass(frozen=True, slots=True)
class _ProjectedLine:
    number: int
    original_start: int
    original_end: int
    projected_start: int
    projected_end: int
    original_text: str
    projected_text: str
    redacted: bool


@dataclass(frozen=True, slots=True)
class _SymbolOccurrence:
    name: str
    byte_offset: int


@dataclass(frozen=True, slots=True)
class _PythonLineTerms:
    identifiers: tuple[str, ...]
    enclosing_symbol: str | None


@dataclass(frozen=True, slots=True)
class _PreparedFile:
    path: str
    oid: str
    content: bytes
    projection: str
    lines: tuple[_ProjectedLine, ...]
    redacted_ranges: tuple[tuple[int, int], ...]
    definitions: tuple[_SymbolOccurrence, ...]
    references: tuple[_SymbolOccurrence, ...]
    python_line_terms: tuple[_PythonLineTerms, ...]
    regions: tuple[tuple[int, int], ...]
    unparsed_python: bool


@dataclass(frozen=True, slots=True)
class _Fused:
    hits: tuple[RetrievalHit, ...]
    candidate_count: int
    omitted_count: int


_PROVIDER_REGISTRY: dict[int, _ProviderRegistryEntry] = {}
_PROVIDER_REGISTRY_LOCK = threading.RLock()


def _failure(
    code: RetrievalErrorCode,
    stage: RetrievalStage,
    channel: RetrievalChannel | None = None,
) -> RetrievalError:
    error = RetrievalError(code, stage, channel)
    error.__cause__ = None
    error.__context__ = None
    return error


def _detached_failure(
    error: RetrievalError,
    *,
    fallback_stage: RetrievalStage,
) -> RetrievalError:
    if (
        not isinstance(error.code, RetrievalErrorCode)
        or not isinstance(error.stage, RetrievalStage)
        or (error.channel is not None and not isinstance(error.channel, RetrievalChannel))
    ):
        return _failure(RetrievalErrorCode.BACKEND_FAILED, fallback_stage)
    return _failure(error.code, error.stage, error.channel)


def _fail(
    code: RetrievalErrorCode,
    stage: RetrievalStage,
    channel: RetrievalChannel | None = None,
) -> Never:
    raise _failure(code, stage, channel)


def _check_deadline(deadline: float, stage: RetrievalStage) -> None:
    if time.monotonic() > deadline:
        _fail(RetrievalErrorCode.DEADLINE_EXCEEDED, stage)


def _bind_provider(provider: EmbeddingProvider, owner: object) -> None:
    with _PROVIDER_REGISTRY_LOCK:
        key = id(provider)
        existing = _PROVIDER_REGISTRY.get(key)
        if existing is not None:
            existing_provider = existing[0]()
            if existing_provider is not None:
                _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
            del _PROVIDER_REGISTRY[key]

        def forget_provider(
            expired: weakref.ReferenceType[EmbeddingProvider],
        ) -> None:
            _forget_provider(key, expired)

        try:
            reference: _ProviderReference = weakref.ref(
                provider,
                forget_provider,
            )
        except TypeError:

            def strong_reference() -> object:
                return provider

            reference = strong_reference
        _PROVIDER_REGISTRY[key] = (reference, owner)


def _forget_provider(provider_id: int, expired: _ProviderReference) -> None:
    with _PROVIDER_REGISTRY_LOCK:
        current = _PROVIDER_REGISTRY.get(provider_id)
        if current is not None and current[0] is expired:
            del _PROVIDER_REGISTRY[provider_id]


def _transfer_provider(provider: EmbeddingProvider, old_owner: object, new_owner: object) -> None:
    with _PROVIDER_REGISTRY_LOCK:
        current = _PROVIDER_REGISTRY.get(id(provider))
        if current is None or current[0]() is not provider or current[1] is not old_owner:
            _fail(RetrievalErrorCode.INVALID_INDEX, RetrievalStage.VALIDATE)
        _PROVIDER_REGISTRY[id(provider)] = (current[0], new_owner)


def _release_provider(provider: EmbeddingProvider, owner: object) -> None:
    with _PROVIDER_REGISTRY_LOCK:
        current = _PROVIDER_REGISTRY.get(id(provider))
        if current is not None and current[0]() is provider and current[1] is owner:
            _PROVIDER_REGISTRY[id(provider)] = (current[0], None)


class _IndexState:
    """Concrete owner of all native and provider state for one public index."""

    __slots__ = (
        "_chunks",
        "_closed",
        "_config",
        "_faiss",
        "_identity",
        "_lock",
        "_provider",
        "_python_line_terms",
        "_sqlite",
        "_statistics",
        "_symbol_definitions",
        "_symbol_references",
    )

    def __init__(
        self,
        *,
        identity: IndexIdentity,
        statistics: IndexStatistics,
        config: ContextIndexConfig,
        chunks: tuple[ContextChunk, ...],
        provider: EmbeddingProvider,
        sqlite: sqlite3.Connection | None,
        faiss: _FaissIndex | None,
        symbol_definitions: dict[str, tuple[int, ...]],
        symbol_references: dict[str, tuple[int, ...]],
        python_line_terms: dict[tuple[str, int], _PythonLineTerms],
    ) -> None:
        self._identity = identity
        self._statistics = statistics
        self._config = config
        self._chunks = chunks
        self._provider = provider
        self._sqlite = sqlite
        self._faiss = faiss
        self._symbol_definitions = MappingProxyType(symbol_definitions)
        self._symbol_references = MappingProxyType(symbol_references)
        self._python_line_terms = MappingProxyType(python_line_terms)
        self._lock = threading.RLock()
        self._closed = False

    @property
    def identity(self) -> IndexIdentity:
        return self._identity

    @property
    def statistics(self) -> IndexStatistics:
        return self._statistics

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        sqlite_backend: sqlite3.Connection | None
        faiss_backend: _FaissIndex | None
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sqlite_backend = self._sqlite
            faiss_backend = self._faiss
            self._sqlite = None
            self._faiss = None

        failed = False
        if sqlite_backend is not None:
            try:
                sqlite_backend.close()
            except sqlite3.Error:
                failed = True
        if faiss_backend is not None:
            try:
                faiss_backend.reset()
            except Exception:
                failed = True
        try:
            self._provider.close()
        except Exception:
            failed = True
        _release_provider(self._provider, self)
        if failed:
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CLOSE)


def _build_context_index(
    bundle: object,
    *,
    embedding_provider: EmbeddingProvider,
    config: ContextIndexConfig,
) -> ContextIndex:
    """Detach every implementation failure at the public private boundary."""
    failure: RetrievalError | None = None
    try:
        return _build_context_index_impl(
            bundle,
            embedding_provider=embedding_provider,
            config=config,
        )
    except RetrievalError as error:
        failure = _detached_failure(error, fallback_stage=RetrievalStage.VALIDATE)
    except Exception:
        failure = _failure(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.VALIDATE)
    assert failure is not None
    raise failure


def _build_context_index_impl(
    bundle: object,
    *,
    embedding_provider: EmbeddingProvider,
    config: ContextIndexConfig,
) -> ContextIndex:
    """Build and atomically publish one concrete context index."""
    _validate_evidence(bundle)
    assert isinstance(bundle, EvidenceBundle)
    normalized_config = _validate_configuration(config)
    provider = _validate_provider_shape(embedding_provider)
    deadline = time.monotonic() + normalized_config.build_timeout_seconds
    token = object()
    _bind_provider(provider, token)

    sqlite_backend: sqlite3.Connection | None = None
    faiss_backend: _FaissIndex | None = None
    published = False
    try:
        corpus, excluded_count = _read_committed_corpus(
            bundle,
            normalized_config,
            deadline,
        )
        _initialize_provider(provider, bundle.repository.root, deadline)
        provider_name, actual_device = _validate_initialized_provider(provider)
        del provider_name
        model, revision, manifest_sha256, dimension = _model_identity(provider)
        chunks, unparsed_count, python_line_terms = _build_chunks(
            corpus,
            head_oid=bundle.revisions.head_oid,
            provider=provider,
            config=normalized_config,
            deadline=deadline,
        )
        statistics_without_dense = _statistics(
            corpus,
            chunks,
            python_line_terms=python_line_terms,
            excluded_count=excluded_count,
            unparsed_count=unparsed_count,
            dense_matrix_bytes=0,
        )
        dense_bytes = (
            len(chunks) * dimension * np.dtype(np.float32).itemsize
            if RetrievalChannel.VECTOR in normalized_config.channels
            else 0
        )
        statistics = replace(
            statistics_without_dense,
            dense_matrix_bytes=dense_bytes,
            logical_index_bytes=statistics_without_dense.logical_index_bytes + dense_bytes,
        )
        if statistics.logical_index_bytes > normalized_config.max_index_bytes:
            _fail(RetrievalErrorCode.INDEX_LIMIT_EXCEEDED, RetrievalStage.CHUNK)

        if RetrievalChannel.TEXT in normalized_config.channels:
            sqlite_backend = _build_text_index(chunks, deadline)
        if RetrievalChannel.VECTOR in normalized_config.channels:
            faiss_backend = _build_vector_index(
                chunks,
                provider=provider,
                dimension=dimension,
                deadline=deadline,
            )
        symbol_definitions, symbol_references = _build_symbol_index(
            chunks,
            enabled=RetrievalChannel.SYMBOL in normalized_config.channels,
            deadline=deadline,
        )
        identity = IndexIdentity(
            repository_root=bundle.repository.root,
            object_format=bundle.repository.object_format,
            head_oid=bundle.revisions.head_oid,
            channels=normalized_config.channels,
            config_sha256=_config_sha256(normalized_config),
            model=model,
            model_revision=revision,
            manifest_sha256=manifest_sha256,
            dimension=dimension,
            actual_device=actual_device,
        )
        state = _IndexState(
            identity=identity,
            statistics=statistics,
            config=normalized_config,
            chunks=chunks,
            provider=provider,
            sqlite=sqlite_backend,
            faiss=faiss_backend,
            symbol_definitions=symbol_definitions,
            symbol_references=symbol_references,
            python_line_terms=python_line_terms,
        )
        _transfer_provider(provider, token, state)
        published = True
        return ContextIndex(state)
    finally:
        if not published:
            if sqlite_backend is not None:
                with suppress(sqlite3.Error):
                    sqlite_backend.close()
            if faiss_backend is not None:
                with suppress(Exception):
                    faiss_backend.reset()
            with suppress(Exception):
                provider.close()
            _release_provider(provider, token)


def _validate_evidence(value: object) -> None:
    if not isinstance(value, EvidenceBundle):
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    if type(value.schema_version) is not int or value.schema_version != 1:
        _fail(RetrievalErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA, RetrievalStage.VALIDATE)
    if (
        not isinstance(value.repository, RepositoryEvidence)
        or not isinstance(value.revisions, RevisionEvidence)
        or type(value.changes) is not tuple
    ):
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    root = value.repository.root
    if not isinstance(root, Path) or not root.is_absolute():
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    root_failed = False
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        root_failed = True
        resolved_root = root
    if root_failed or resolved_root != root or not root.is_dir():
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    _require_utf8(root.as_posix(), RetrievalErrorCode.INVALID_EVIDENCE)
    object_format = value.repository.object_format
    if type(object_format) is not str or object_format not in _OID_LENGTHS:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    oid_length = _OID_LENGTHS[object_format]
    revisions = value.revisions
    for ref in (revisions.base_ref, revisions.head_ref):
        if type(ref) is not str or not ref:
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
        _require_utf8(ref, RetrievalErrorCode.INVALID_EVIDENCE)
    for oid in (revisions.base_oid, revisions.head_oid, revisions.merge_base_oid):
        _validate_oid(oid, oid_length, RetrievalErrorCode.INVALID_EVIDENCE)

    seen_versions: set[tuple[str, str]] = set()
    for change in value.changes:
        _validate_change(change, oid_length, seen_versions)


def _validate_change(
    value: object,
    oid_length: int,
    seen_versions: set[tuple[str, str]],
) -> None:
    if (
        not isinstance(value, FileChangeEvidence)
        or not isinstance(value.change_type, ChangeType)
        or type(value.hunks) is not tuple
    ):
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    if value.change_type is ChangeType.RENAMED:
        similarity = value.rename_similarity
        if type(similarity) is not int or not 0 <= similarity <= 100:
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    elif value.rename_similarity is not None:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    if value.change_type is ChangeType.ADDED:
        sides_valid = value.old is None and value.new is not None
    elif value.change_type is ChangeType.DELETED:
        sides_valid = value.old is not None and value.new is None
    else:
        sides_valid = value.old is not None and value.new is not None
    if not sides_valid:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)

    for side, version in (("old", value.old), ("new", value.new)):
        if version is None:
            continue
        _validate_version(version, oid_length)
        key = (side, version.path)
        if key in seen_versions:
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
        seen_versions.add(key)
    present = tuple(version for version in (value.old, value.new) if version is not None)
    if value.hunks and any(version.content_kind is not ContentKind.TEXT for version in present):
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)

    old_numbers: set[int] = set()
    new_numbers: set[int] = set()
    for hunk in value.hunks:
        _validate_hunk(hunk, old_numbers, new_numbers)


def _validate_version(value: object, oid_length: int) -> None:
    if (
        not isinstance(value, FileVersion)
        or type(value.path) is not str
        or not value.path
        or type(value.mode) is not str
        or not value.mode
        or not isinstance(value.content_kind, ContentKind)
    ):
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    _validate_git_path(value.path, RetrievalErrorCode.INVALID_EVIDENCE)
    _require_utf8(value.mode, RetrievalErrorCode.INVALID_EVIDENCE)
    _validate_oid(value.oid, oid_length, RetrievalErrorCode.INVALID_EVIDENCE)
    expected_kinds: tuple[ContentKind, ...]
    if value.mode == "120000":
        expected_kinds = (ContentKind.SYMLINK,)
    elif value.mode == "160000":
        expected_kinds = (ContentKind.SUBMODULE,)
    elif value.mode.startswith("100"):
        expected_kinds = (ContentKind.TEXT, ContentKind.BINARY)
    else:
        expected_kinds = (ContentKind.OTHER,)
    if value.content_kind not in expected_kinds:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)


def _validate_hunk(
    value: object,
    old_numbers: set[int],
    new_numbers: set[int],
) -> None:
    if not isinstance(value, DiffHunkEvidence) or type(value.lines) is not tuple:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    for coordinate in (value.old_start, value.new_start, value.old_count, value.new_count):
        if type(coordinate) is not int or coordinate < 0:
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
    expected_old = value.old_start
    expected_new = value.new_start
    observed_old = 0
    observed_new = 0
    for line in value.lines:
        if (
            not isinstance(line, DiffLineEvidence)
            or not isinstance(line.kind, DiffLineKind)
            or type(line.content) is not str
            or type(line.has_trailing_newline) is not bool
        ):
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
        _require_utf8(line.content, RetrievalErrorCode.INVALID_EVIDENCE)
        required_old = None if line.kind is DiffLineKind.ADDITION else expected_old
        required_new = None if line.kind is DiffLineKind.DELETION else expected_new
        if line.old_line_number != required_old or line.new_line_number != required_new:
            _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
        if line.old_line_number is not None:
            if (
                type(line.old_line_number) is not int
                or line.old_line_number < 1
                or line.old_line_number in old_numbers
            ):
                _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
            old_numbers.add(line.old_line_number)
            expected_old += 1
            observed_old += 1
        if line.new_line_number is not None:
            if (
                type(line.new_line_number) is not int
                or line.new_line_number < 1
                or line.new_line_number in new_numbers
            ):
                _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)
            new_numbers.add(line.new_line_number)
            expected_new += 1
            observed_new += 1
    if observed_old != value.old_count or observed_new != value.new_count:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.VALIDATE)


def _validate_configuration(value: object) -> ContextIndexConfig:
    if type(value) is not ContextIndexConfig:
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    assert isinstance(value, ContextIndexConfig)
    if type(value.channels) is not tuple or not value.channels:
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    channels: list[RetrievalChannel] = []
    for channel in value.channels:
        if not isinstance(channel, RetrievalChannel) or channel in channels:
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
        channels.append(channel)
    channels.sort(key=_CHANNEL_ORDER.__getitem__)

    include_globs = _validate_globs(value.include_globs)
    exclude_globs = _validate_globs(value.exclude_globs)
    for name, maximum in _MAX_CONFIG.items():
        number = getattr(value, name)
        if type(number) is not int:
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
        minimum = 0 if name == "chunk_overlap_tokens" else 1
        if not minimum <= number <= maximum:
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    if value.chunk_tokens < 3 or value.chunk_overlap_tokens >= value.chunk_tokens - 2:
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    for timeout, timeout_maximum in (
        (value.build_timeout_seconds, _MAX_BUILD_SECONDS),
        (value.query_timeout_seconds, _MAX_QUERY_SECONDS),
    ):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= timeout_maximum
        ):
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    return replace(
        value,
        channels=tuple(channels),
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        build_timeout_seconds=float(value.build_timeout_seconds),
        query_timeout_seconds=float(value.query_timeout_seconds),
    )


def _validate_globs(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    normalized: list[str] = []
    for pattern in value:
        if type(pattern) is not str or not pattern or "\0" in pattern:
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
        _require_utf8(pattern, RetrievalErrorCode.INVALID_CONFIGURATION)
        try:
            PurePosixPath("probe").match(pattern, case_sensitive=True)
        except (TypeError, ValueError):
            _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
        normalized.append(pattern)
    if len(normalized) != len(set(normalized)):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    return tuple(sorted(normalized, key=lambda item: item.encode("utf-8")))


def _validate_provider_shape(value: object) -> EmbeddingProvider:
    if not isinstance(value, EmbeddingProvider):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    provider = value
    failed = False
    methods: tuple[Callable[..., object], ...]
    try:
        name = provider.name
        model = provider.model
        dimension = provider.dimension
        methods = (
            provider.token_spans,
            provider.embed_documents,
            provider.embed_queries,
            provider.close,
        )
    except Exception:
        failed = True
        name = ""
        model = ""
        dimension = 0
        methods = ()
    if failed:
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    if type(name) is not str or not name.strip():
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    _require_utf8(name, RetrievalErrorCode.INVALID_CONFIGURATION)
    if any(unicodedata.category(character) == "Cc" for character in name):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    if (
        type(model) is not str
        or model != _MODEL
        or type(dimension) is not int
        or dimension != _DIMENSION
    ):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    if not all(callable(method) for method in cast(tuple[object, ...], methods)):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    return provider


def _initialize_provider(
    provider: EmbeddingProvider,
    repository_root: Path,
    deadline: float,
) -> None:
    _check_deadline(deadline, RetrievalStage.EMBED)
    failed = False
    provider_failure: RetrievalError | None = None
    if isinstance(provider, FastEmbedProvider):
        try:
            embedding = importlib.import_module("repoguard._embedding")
            initializer = cast(Callable[..., None], embedding._initialize_fastembed)
            initializer(provider, repository_root=repository_root, deadline=deadline)
        except RetrievalError as error:
            provider_failure = _detached_failure(
                error,
                fallback_stage=RetrievalStage.EMBED,
            )
        except Exception:
            failed = True
    _check_deadline(deadline, RetrievalStage.EMBED)
    if provider_failure is not None:
        raise provider_failure
    if failed:
        _fail(
            RetrievalErrorCode.MODEL_UNAVAILABLE,
            RetrievalStage.EMBED,
            RetrievalChannel.VECTOR,
        )


def _validate_initialized_provider(
    provider: EmbeddingProvider,
) -> tuple[str, EmbeddingDevice]:
    failed = False
    try:
        name = provider.name
        model = provider.model
        dimension = provider.dimension
        actual_device = provider.actual_device
    except Exception:
        failed = True
        name = ""
        model = ""
        dimension = 0
        actual_device = EmbeddingDevice.AUTO
    if (
        failed
        or type(name) is not str
        or not name.strip()
        or type(model) is not str
        or model != _MODEL
        or type(dimension) is not int
        or dimension != _DIMENSION
        or not isinstance(actual_device, EmbeddingDevice)
        or actual_device not in (EmbeddingDevice.CPU, EmbeddingDevice.CUDA)
    ):
        _fail(RetrievalErrorCode.INVALID_CONFIGURATION, RetrievalStage.VALIDATE)
    return name, actual_device


def _model_identity(
    provider: EmbeddingProvider,
) -> tuple[str, str, str, int]:
    if isinstance(provider, FastEmbedProvider):
        failed = False
        try:
            embedding = importlib.import_module("repoguard._embedding")
            identity = cast(
                Callable[[FastEmbedProvider], tuple[str, str]],
                embedding._provider_model_identity,
            )
            revision, manifest_sha256 = identity(provider)
        except Exception:
            failed = True
            revision = ""
            manifest_sha256 = ""
        if (
            failed
            or revision != _MODEL_REVISION
            or _LOWERCASE_HEX.fullmatch(manifest_sha256) is None
            or len(manifest_sha256) != 64
        ):
            _fail(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        return _MODEL, revision, manifest_sha256, _DIMENSION

    manifest = files("repoguard").joinpath(
        "models",
        "bge_small_en_v1_5",
        "manifest.json",
    )
    failed = False
    try:
        manifest_bytes = manifest.read_bytes()
        value = json.loads(manifest_bytes)
    except (OSError, TypeError, ValueError):
        failed = True
        manifest_bytes = b""
        value = None
    if (
        failed
        or type(value) is not dict
        or value.get("model") != _MODEL
        or value.get("revision") != _MODEL_REVISION
        or value.get("schema_version") != 1
    ):
        _fail(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    return (
        _MODEL,
        _MODEL_REVISION,
        hashlib.sha256(manifest_bytes).hexdigest(),
        _DIMENSION,
    )


def _require_utf8(value: str, code: RetrievalErrorCode) -> bytes:
    failed = False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        failed = True
        encoded = b""
    if failed:
        _fail(code, RetrievalStage.VALIDATE)
    return encoded


def _validate_oid(value: object, length: int, code: RetrievalErrorCode) -> None:
    if type(value) is not str or len(value) != length or _LOWERCASE_HEX.fullmatch(value) is None:
        _fail(code, RetrievalStage.VALIDATE)


def _validate_git_path(value: str, code: RetrievalErrorCode) -> None:
    _require_utf8(value, code)
    path = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\0" in value
        or value in (".", "..")
        or any(part in ("", ".", "..") for part in value.split("/"))
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        _fail(code, RetrievalStage.VALIDATE)


def _config_sha256(config: ContextIndexConfig) -> str:
    value = {
        "schema_version": 1,
        "channels": [channel.value for channel in config.channels],
        "include_globs": list(config.include_globs),
        "exclude_globs": list(config.exclude_globs),
        "max_files": config.max_files,
        "max_file_bytes": config.max_file_bytes,
        "max_corpus_bytes": config.max_corpus_bytes,
        "max_chunks": config.max_chunks,
        "max_index_bytes": config.max_index_bytes,
        "build_timeout_seconds": config.build_timeout_seconds,
        "query_timeout_seconds": config.query_timeout_seconds,
        "chunk_tokens": config.chunk_tokens,
        "chunk_overlap_tokens": config.chunk_overlap_tokens,
        "max_candidates_per_channel": config.max_candidates_per_channel,
        "max_results": config.max_results,
        "rrf_k": _RRF_K,
        "rrf_scale": _RRF_SCALE,
    }
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_committed_corpus(
    bundle: EvidenceBundle,
    config: ContextIndexConfig,
    deadline: float,
) -> tuple[tuple[_CorpusFile, ...], int]:
    root = bundle.repository.root
    oid_length = _OID_LENGTHS[bundle.repository.object_format]
    actual_root = _run_git(
        root,
        ("rev-parse", "--show-toplevel"),
        deadline=deadline,
        stage=RetrievalStage.READ_CORPUS,
    )
    actual_format = _run_git(
        root,
        ("rev-parse", "--show-object-format"),
        deadline=deadline,
        stage=RetrievalStage.READ_CORPUS,
    )
    root_failed = False
    try:
        root_text = _single_git_line(actual_root).decode("utf-8", "strict")
        format_text = _single_git_line(actual_format).decode("ascii", "strict")
        resolved = Path(root_text).resolve(strict=True)
    except (OSError, UnicodeDecodeError, ValueError):
        root_failed = True
        resolved = root
        format_text = ""
    if root_failed or resolved != root or format_text != bundle.repository.object_format:
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.READ_CORPUS)

    _verify_head_commit(root, bundle.revisions.head_oid, deadline)
    tree = _run_git(
        root,
        ("ls-tree", "-r", "-z", "--full-tree", bundle.revisions.head_oid),
        deadline=deadline,
        stage=RetrievalStage.READ_CORPUS,
        missing_is_object=True,
        stdout_limit=_GIT_TREE_OUTPUT_BYTES,
        output_limit_code=RetrievalErrorCode.INDEX_LIMIT_EXCEEDED,
    )
    entries = _parse_tree(tree, oid_length)
    selected: list[_TreeEntry] = []
    excluded_count = 0
    for entry in entries:
        _check_deadline(deadline, RetrievalStage.READ_CORPUS)
        if (
            entry.kind != "blob"
            or entry.mode not in ("100644", "100755")
            or not _path_selected(entry.path, config)
        ):
            excluded_count += 1
            continue
        if len(selected) >= config.max_files:
            _fail(RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED, RetrievalStage.READ_CORPUS)
        selected.append(entry)

    corpus, content_exclusions = _read_blobs(
        root,
        selected,
        config=config,
        deadline=deadline,
    )
    return corpus, excluded_count + content_exclusions


def _git_environment() -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update(
        {
            "GIT_ATTR_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _git_command(root: Path, args: Sequence[str]) -> list[str]:
    return [
        "git",
        "--literal-pathspecs",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(root),
        *args,
    ]


def _run_git(
    root: Path,
    args: Sequence[str],
    *,
    deadline: float,
    stage: RetrievalStage,
    missing_is_object: bool = False,
    stdout_limit: int = _GIT_CONTROL_OUTPUT_BYTES,
    output_limit_code: RetrievalErrorCode = RetrievalErrorCode.READ_FAILED,
) -> bytes:
    _check_deadline(deadline, stage)
    if type(stdout_limit) is not int or stdout_limit <= 0:
        _fail(RetrievalErrorCode.READ_FAILED, stage)
    unavailable = False
    start_failed = False
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            _git_command(root, args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=os.path.abspath(os.sep),
            env=_git_environment(),
        )
    except FileNotFoundError:
        unavailable = True
    except (OSError, ValueError):
        start_failed = True
    if unavailable:
        _fail(RetrievalErrorCode.GIT_UNAVAILABLE, stage)
    if start_failed or process is None or process.stdout is None:
        _fail(RetrievalErrorCode.READ_FAILED, stage)

    output: bytes | None = None
    output_limited = False
    read_failed = False
    timed_out = False
    try:
        output, output_limited = _read_bounded_process_output(
            process,
            limit=stdout_limit,
            deadline=deadline,
        )
    except TimeoutError:
        timed_out = True
    except OSError:
        read_failed = True
    finally:
        if timed_out or read_failed or output_limited:
            _stop_process(process)
        else:
            _close_process_pipes(process)
    if timed_out:
        _fail(RetrievalErrorCode.DEADLINE_EXCEEDED, stage)
    if output_limited:
        _fail(output_limit_code, stage)
    if read_failed or output is None:
        _fail(RetrievalErrorCode.READ_FAILED, stage)
    if process.returncode != 0:
        code = (
            RetrievalErrorCode.MISSING_OBJECT
            if missing_is_object
            else RetrievalErrorCode.READ_FAILED
        )
        _fail(code, stage)
    return output


def _read_bounded_process_output(
    process: subprocess.Popen[bytes],
    *,
    limit: int,
    deadline: float,
) -> tuple[bytes, bool]:
    stream = process.stdout
    if stream is None:
        raise OSError
    descriptor = stream.fileno()
    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            events = selector.select(timeout=remaining)
            if not events:
                raise TimeoutError
            block = os.read(
                descriptor,
                min(_GIT_READ_BYTES, limit - len(output) + 1),
            )
            if not block:
                break
            output.extend(block)
            if len(output) > limit:
                return bytes(output), True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise TimeoutError from None
    finally:
        selector.close()
    return bytes(output), False


def _single_git_line(value: bytes) -> bytes:
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError
    return lines[0]


def _verify_head_commit(root: Path, oid: str, deadline: float) -> None:
    object_type = _run_git(
        root,
        ("cat-file", "-t", oid),
        deadline=deadline,
        stage=RetrievalStage.READ_CORPUS,
        missing_is_object=True,
    )
    try:
        kind = _single_git_line(object_type).decode("ascii", "strict")
    except (UnicodeDecodeError, ValueError):
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
    if kind != "commit":
        _fail(RetrievalErrorCode.INVALID_EVIDENCE, RetrievalStage.READ_CORPUS)


def _parse_tree(value: bytes, oid_length: int) -> tuple[_TreeEntry, ...]:
    result: list[_TreeEntry] = []
    seen_paths: set[str] = set()
    failed = False
    for raw_entry in value.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode_bytes, kind_bytes, oid_bytes = metadata.split(b" ")
            mode = mode_bytes.decode("ascii", "strict")
            kind = kind_bytes.decode("ascii", "strict")
            oid = oid_bytes.decode("ascii", "strict")
            path = raw_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            failed = True
            break
        if (
            not mode
            or kind not in ("blob", "commit")
            or len(oid) != oid_length
            or _LOWERCASE_HEX.fullmatch(oid) is None
            or path in seen_paths
        ):
            failed = True
            break
        try:
            _validate_git_path(path, RetrievalErrorCode.READ_FAILED)
        except RetrievalError:
            failed = True
            break
        seen_paths.add(path)
        result.append(_TreeEntry(mode=mode, kind=kind, oid=oid, path=path))
    if failed:
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
    return tuple(sorted(result, key=lambda entry: entry.path.encode("utf-8")))


def _path_selected(path: str, config: ContextIndexConfig) -> bool:
    pure_path = PurePosixPath(path)
    if config.include_globs and not any(
        pure_path.match(pattern, case_sensitive=True) for pattern in config.include_globs
    ):
        return False
    return not any(
        pure_path.match(pattern, case_sensitive=True) for pattern in config.exclude_globs
    )


def _start_cat_file(
    root: Path,
) -> subprocess.Popen[bytes]:
    unavailable = False
    start_failed = False
    try:
        process = subprocess.Popen(
            _git_command(root, ("cat-file", "--batch")),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.abspath(os.sep),
            env=_git_environment(),
        )
    except FileNotFoundError:
        unavailable = True
        process = None
    except (OSError, ValueError):
        start_failed = True
        process = None
    if unavailable:
        _fail(RetrievalErrorCode.GIT_UNAVAILABLE, RetrievalStage.READ_CORPUS)
    if start_failed or process is None:
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
    return process


def _read_blobs(
    root: Path,
    entries: Sequence[_TreeEntry],
    *,
    config: ContextIndexConfig,
    deadline: float,
) -> tuple[tuple[_CorpusFile, ...], int]:
    if not entries:
        return (), 0
    process = _start_cat_file(root)
    stdin = cast(BinaryIO | None, process.stdin)
    stdout = cast(BinaryIO | None, process.stdout)
    if stdin is None or stdout is None:
        _stop_process(process)
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)

    corpus: list[_CorpusFile] = []
    excluded = 0
    corpus_bytes = 0
    inspected_bytes = 0
    finished = False
    try:
        for entry in entries:
            _check_deadline(deadline, RetrievalStage.READ_CORPUS)
            io_failed = False
            try:
                stdin.write(entry.oid.encode("ascii") + b"\n")
                stdin.flush()
                header = stdout.readline()
            except (BrokenPipeError, OSError):
                io_failed = True
                header = b""
            if io_failed:
                _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
            _check_deadline(deadline, RetrievalStage.READ_CORPUS)
            object_oid, object_kind, object_size = _parse_batch_header(
                header,
                expected_oid=entry.oid,
            )
            if object_oid is None:
                _fail(RetrievalErrorCode.MISSING_OBJECT, RetrievalStage.READ_CORPUS)
            if object_kind != "blob" or object_size is None:
                _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
            if object_size > config.max_file_bytes:
                _fail(RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED, RetrievalStage.READ_CORPUS)
            if inspected_bytes + object_size > config.max_corpus_bytes:
                _fail(RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED, RetrievalStage.READ_CORPUS)
            content, binary = _read_blob_content(
                stdout,
                object_size,
                retain_limit=config.max_file_bytes,
                deadline=deadline,
            )
            inspected_bytes += object_size
            if binary:
                excluded += 1
                continue
            if content is None:
                _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
            corpus.append(_CorpusFile(path=entry.path, oid=entry.oid, content=content))
            corpus_bytes += len(content)

        close_failed = False
        try:
            stdin.close()
            remaining = max(0.0, deadline - time.monotonic())
            return_code = process.wait(timeout=remaining)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            close_failed = True
            return_code = -1
        _check_deadline(deadline, RetrievalStage.READ_CORPUS)
        if close_failed or return_code != 0:
            _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
        finished = True
    finally:
        if not finished:
            _stop_process(process)
        else:
            _close_process_pipes(process)
    return tuple(corpus), excluded


def _read_blob_content(
    stream: BinaryIO,
    size: int,
    *,
    retain_limit: int,
    deadline: float,
) -> tuple[bytes | None, bool]:
    remaining = size
    retained = bytearray()
    binary = False
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    while remaining:
        _check_deadline(deadline, RetrievalStage.READ_CORPUS)
        read_failed = False
        try:
            block = stream.read(min(remaining, _GIT_READ_BYTES))
        except OSError:
            read_failed = True
            block = b""
        if read_failed or not block:
            _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
        remaining -= len(block)
        if len(retained) < retain_limit:
            retained.extend(block[: retain_limit - len(retained)])
        if not binary:
            if b"\0" in block:
                binary = True
            else:
                try:
                    decoder.decode(block, final=False)
                except UnicodeDecodeError:
                    binary = True
        _check_deadline(deadline, RetrievalStage.READ_CORPUS)
    if not binary:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            binary = True
    read_failed = False
    try:
        separator = stream.read(1)
    except OSError:
        read_failed = True
        separator = b""
    if read_failed or separator != b"\n":
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
    _check_deadline(deadline, RetrievalStage.READ_CORPUS)
    if binary:
        return None, True
    if size > retain_limit:
        return None, False
    return bytes(retained), False


def _parse_batch_header(
    value: bytes,
    *,
    expected_oid: str,
) -> tuple[str | None, str | None, int | None]:
    missing = f"{expected_oid} missing\n".encode("ascii")
    if value == missing:
        return None, None, None
    failed = False
    try:
        oid_bytes, kind_bytes, size_bytes = value.rstrip(b"\n").split(b" ")
        oid = oid_bytes.decode("ascii", "strict")
        kind = kind_bytes.decode("ascii", "strict")
        size_text = size_bytes.decode("ascii", "strict")
        size = int(size_text, 10)
    except (UnicodeDecodeError, ValueError):
        failed = True
        oid = ""
        kind = ""
        size = -1
        size_text = ""
    if failed or oid != expected_oid or kind != "blob" or size < 0 or str(size) != size_text:
        _fail(RetrievalErrorCode.READ_FAILED, RetrievalStage.READ_CORPUS)
    return oid, kind, size


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        with suppress(OSError):
            process.terminate()
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            with suppress(OSError):
                process.kill()
            with suppress(OSError, subprocess.TimeoutExpired):
                process.wait(timeout=1.0)
    finally:
        _close_process_pipes(process)


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def _build_chunks(
    corpus: Sequence[_CorpusFile],
    *,
    head_oid: str,
    provider: EmbeddingProvider,
    config: ContextIndexConfig,
    deadline: float,
) -> tuple[
    tuple[ContextChunk, ...],
    int,
    dict[tuple[str, int], _PythonLineTerms],
]:
    chunks: list[ContextChunk] = []
    unparsed_count = 0
    python_line_terms: dict[tuple[str, int], _PythonLineTerms] = {}
    for corpus_file in corpus:
        _check_deadline(deadline, RetrievalStage.CHUNK)
        prepared = _prepare_file(corpus_file)
        _check_deadline(deadline, RetrievalStage.CHUNK)
        if prepared.unparsed_python:
            unparsed_count += 1
        for line_number, terms in enumerate(prepared.python_line_terms, start=1):
            if terms.identifiers or terms.enclosing_symbol is not None:
                python_line_terms[(prepared.path, line_number)] = terms
        file_ranges: list[tuple[int, int]] = []
        for region_start, region_end in prepared.regions:
            for projected_start, projected_end in _window_projection(
                prepared,
                region_start,
                region_end,
                provider=provider,
                config=config,
                deadline=deadline,
            ):
                start_byte = _projection_byte_offset(
                    prepared,
                    projected_start,
                    ending=False,
                )
                end_byte = _projection_byte_offset(
                    prepared,
                    projected_end,
                    ending=True,
                )
                if start_byte >= end_byte:
                    _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
                content = prepared.projection[projected_start:projected_end]
                if not content:
                    _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
                start_line, end_line = _chunk_lines(prepared.lines, start_byte, end_byte)
                redacted_ranges = tuple(
                    (max(start_line, start), min(end_line, end))
                    for start, end in prepared.redacted_ranges
                    if start <= end_line and end >= start_line
                )
                definitions = _symbols_for_chunk(
                    prepared.definitions,
                    start_byte=start_byte,
                    end_byte=end_byte,
                )
                references = _symbols_for_chunk(
                    prepared.references,
                    start_byte=start_byte,
                    end_byte=end_byte,
                )
                chunk_id = _chunk_id(
                    head_oid=head_oid,
                    path=prepared.path,
                    oid=prepared.oid,
                    start_byte=start_byte,
                    end_byte=end_byte,
                )
                chunks.append(
                    ContextChunk(
                        provenance=ChunkProvenance(
                            chunk_id=chunk_id,
                            path=prepared.path,
                            oid=prepared.oid,
                            start_byte=start_byte,
                            end_byte=end_byte,
                            start_line=start_line,
                            end_line=end_line,
                        ),
                        content=content,
                        redacted_line_ranges=redacted_ranges,
                        definitions=definitions,
                        references=references,
                    )
                )
                file_ranges.append((start_byte, end_byte))
                if len(chunks) > config.max_chunks:
                    _fail(RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED, RetrievalStage.CHUNK)
                _check_deadline(deadline, RetrievalStage.CHUNK)
        if corpus_file.content and not _ranges_cover(file_ranges, len(corpus_file.content)):
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    chunks.sort(key=_chunk_sort_key)
    if len({chunk.provenance.chunk_id for chunk in chunks}) != len(chunks):
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    return tuple(chunks), unparsed_count, python_line_terms


def _prepare_file(corpus_file: _CorpusFile) -> _PreparedFile:
    text = corpus_file.content.decode("utf-8", "strict")
    original_lines = tuple(text.splitlines(keepends=True))
    if "".join(original_lines) != text:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    redacted_ranges = _private_key_ranges(original_lines)
    redacted_numbers = {
        line_number for start, end in redacted_ranges for line_number in range(start, end + 1)
    }
    projected_lines: list[_ProjectedLine] = []
    original_offset = 0
    projected_offset = 0
    for number, original_text in enumerate(original_lines, start=1):
        original_bytes = original_text.encode("utf-8")
        redacted = number in redacted_numbers
        projected_text = (
            _REDACTION_SENTINEL + _line_ending(original_text) if redacted else original_text
        )
        projected_lines.append(
            _ProjectedLine(
                number=number,
                original_start=original_offset,
                original_end=original_offset + len(original_bytes),
                projected_start=projected_offset,
                projected_end=projected_offset + len(projected_text),
                original_text=original_text,
                projected_text=projected_text,
                redacted=redacted,
            )
        )
        original_offset += len(original_bytes)
        projected_offset += len(projected_text)
    if original_offset != len(corpus_file.content):
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    projection = "".join(line.projected_text for line in projected_lines)

    definitions: tuple[_SymbolOccurrence, ...] = ()
    references: tuple[_SymbolOccurrence, ...] = ()
    python_line_terms: tuple[_PythonLineTerms, ...] = ()
    unparsed = False
    top_level_regions: tuple[tuple[int, int], ...] = ()
    if corpus_file.path.endswith((".py", ".pyi")) and text:
        parsed: ast.Module | None = None
        syntax_error = False
        parser_failed = False
        try:
            parsed = ast.parse(
                text,
                filename=corpus_file.path,
                mode="exec",
                feature_version=(3, 12),
            )
        except SyntaxError:
            syntax_error = True
        except Exception:
            parser_failed = True
        if parser_failed:
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
        if syntax_error:
            unparsed = True
        elif parsed is not None:
            definitions, references = _python_symbols(parsed, projected_lines)
            python_line_terms = _python_line_query_terms(parsed, projected_lines)
            top_level_regions = _python_regions(parsed, projected_lines)

    regions = top_level_regions or ((0, len(projection)),) if projection else ()
    return _PreparedFile(
        path=corpus_file.path,
        oid=corpus_file.oid,
        content=corpus_file.content,
        projection=projection,
        lines=tuple(projected_lines),
        redacted_ranges=redacted_ranges,
        definitions=definitions,
        references=references,
        python_line_terms=python_line_terms,
        regions=regions,
        unparsed_python=unparsed,
    )


def _line_ending(value: str) -> str:
    for ending in _LINE_ENDINGS:
        if value.endswith(ending):
            return ending
    return ""


def _private_key_ranges(lines: Sequence[str]) -> tuple[tuple[int, int], ...]:
    unmatched: dict[str, deque[int]] = defaultdict(deque)
    ranges: list[tuple[int, int]] = []
    for line_number, line in enumerate(lines, start=1):
        body = line[: len(line) - len(_line_ending(line))] if _line_ending(line) else line
        for match in _PRIVATE_KEY_MARKER_PATTERN.finditer(body):
            marker_kind, label = match.groups()
            if marker_kind == "BEGIN":
                unmatched[label].append(line_number)
                continue
            starts = unmatched[label]
            if starts:
                ranges.append((starts.popleft(), line_number))
    if not ranges:
        return ()
    ranges.sort()
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _python_regions(
    module: ast.Module,
    lines: Sequence[_ProjectedLine],
) -> tuple[tuple[int, int], ...]:
    if not lines:
        return ()
    preferred: list[tuple[int, int]] = []
    for node in module.body:
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = getattr(node, "decorator_list", ())
        start_line = min(
            (decorator.lineno for decorator in decorators),
            default=node.lineno,
        )
        end_line = node.end_lineno
        if end_line is None:
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
        preferred.append((start_line, end_line))
    preferred.sort()
    regions: list[tuple[int, int]] = []
    cursor = 1
    for start_line, end_line in preferred:
        if start_line < cursor or end_line < start_line or end_line > len(lines):
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
        if cursor < start_line:
            regions.append(
                (
                    lines[cursor - 1].projected_start,
                    lines[start_line - 2].projected_end,
                )
            )
        regions.append(
            (
                lines[start_line - 1].projected_start,
                lines[end_line - 1].projected_end,
            )
        )
        cursor = end_line + 1
    if cursor <= len(lines):
        regions.append((lines[cursor - 1].projected_start, lines[-1].projected_end))
    return tuple(region for region in regions if region[0] < region[1])


def _python_symbols(
    module: ast.Module,
    lines: Sequence[_ProjectedLine],
) -> tuple[tuple[_SymbolOccurrence, ...], tuple[_SymbolOccurrence, ...]]:
    definitions: list[_SymbolOccurrence] = []
    references: list[_SymbolOccurrence] = []
    for node in ast.walk(module):
        if (
            isinstance(
                node,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            )
            and not lines[node.lineno - 1].redacted
        ):
            definitions.append(
                _SymbolOccurrence(
                    name=node.name,
                    byte_offset=_ast_byte_offset(lines, node.lineno, node.col_offset),
                )
            )
        if isinstance(node, ast.Name) and not lines[node.lineno - 1].redacted:
            references.append(
                _SymbolOccurrence(
                    name=node.id,
                    byte_offset=_ast_byte_offset(lines, node.lineno, node.col_offset),
                )
            )
        elif isinstance(node, ast.Attribute):
            line_number = node.end_lineno if node.end_lineno is not None else node.lineno
            if lines[line_number - 1].redacted:
                continue
            end_column = node.end_col_offset if node.end_col_offset is not None else node.col_offset
            attribute_bytes = len(node.attr.encode("utf-8"))
            references.append(
                _SymbolOccurrence(
                    name=node.attr,
                    byte_offset=_ast_byte_offset(
                        lines,
                        line_number,
                        max(0, end_column - attribute_bytes),
                    ),
                )
            )
    definitions.sort(key=lambda item: (item.byte_offset, item.name.encode("utf-8")))
    references.sort(key=lambda item: (item.byte_offset, item.name.encode("utf-8")))
    return tuple(definitions), tuple(references)


def _python_line_query_terms(
    module: ast.Module,
    lines: Sequence[_ProjectedLine],
) -> tuple[_PythonLineTerms, ...]:
    identifiers: list[list[str]] = [[] for _ in lines]
    source = "".join(line.original_text for line in lines)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            line_number = token.start[0]
            if (
                token.type == tokenize.NAME
                and token.string.isidentifier()
                and not keyword.iskeyword(token.string)
                and 1 <= line_number <= len(lines)
                and not lines[line_number - 1].redacted
                and token.string not in identifiers[line_number - 1]
            ):
                identifiers[line_number - 1].append(token.string)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)

    scopes_by_start: dict[int, list[tuple[int, str]]] = defaultdict(list)
    for node in ast.walk(module):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = node.end_lineno
        if (
            end_line is None
            or not 1 <= node.lineno <= end_line <= len(lines)
            or lines[node.lineno - 1].redacted
        ):
            if end_line is None or not 1 <= node.lineno <= end_line <= len(lines):
                _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
            continue
        decorators = getattr(node, "decorator_list", ())
        start_line = min(
            (decorator.lineno for decorator in decorators),
            default=node.lineno,
        )
        scopes_by_start[start_line].append((end_line, node.name))

    active_scopes: list[tuple[int, int, str]] = []
    result: list[_PythonLineTerms] = []
    for line_number, line_identifiers in enumerate(identifiers, start=1):
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
                    scope[2].encode("utf-8"),
                ),
            )[2]
            if active_scopes
            else None
        )
        result.append(
            _PythonLineTerms(
                identifiers=tuple(line_identifiers),
                enclosing_symbol=enclosing,
            )
        )
    return tuple(result)


def _ast_byte_offset(
    lines: Sequence[_ProjectedLine],
    line_number: int,
    utf8_column: int,
) -> int:
    if not 1 <= line_number <= len(lines) or utf8_column < 0:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    line = lines[line_number - 1]
    body_size = len(line.original_text.encode("utf-8"))
    if utf8_column > body_size:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    return line.original_start + utf8_column


def _window_projection(
    prepared: _PreparedFile,
    region_start: int,
    region_end: int,
    *,
    provider: EmbeddingProvider,
    config: ContextIndexConfig,
    deadline: float,
) -> tuple[tuple[int, int], ...]:
    region = prepared.projection[region_start:region_end]
    if not region:
        return ()
    initial_spans = _token_spans(
        provider,
        region,
        deadline=deadline,
        stage=RetrievalStage.CHUNK,
    )
    if len(initial_spans) <= config.chunk_tokens:
        return ((region_start, region_end),)

    windows: list[tuple[int, int]] = []
    local_start = 0
    while local_start < len(region):
        remaining = region[local_start:]
        spans = _token_spans(
            provider,
            remaining,
            deadline=deadline,
            stage=RetrievalStage.CHUNK,
        )
        content_spans = tuple(span for span in spans if span[0] < span[1])
        special_count = len(spans) - len(content_spans)
        capacity = config.chunk_tokens - special_count
        if capacity <= config.chunk_overlap_tokens or not content_spans:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        if len(spans) <= config.chunk_tokens:
            local_end = len(region)
        else:
            if len(content_spans) <= capacity:
                _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
            local_end = local_start + content_spans[capacity][0]
        expanded_start, expanded_end = _expand_to_complete_lines(
            prepared,
            region_start=region_start + local_start,
            local_start=0,
            local_end=local_end - local_start,
            region_length=len(region) - local_start,
            provider=provider,
            token_limit=config.chunk_tokens,
            deadline=deadline,
        )
        if expanded_start != 0:
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
        local_end = local_start + expanded_end
        local_end, final_spans = _fit_projection_window(
            prepared,
            region=region,
            region_start=region_start,
            local_start=local_start,
            local_end=local_end,
            provider=provider,
            token_limit=config.chunk_tokens,
            deadline=deadline,
        )
        if local_start >= local_end:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        absolute = (region_start + local_start, region_start + local_end)
        if not windows or absolute != windows[-1]:
            windows.append(absolute)
        if local_end == len(region):
            break
        final_content_spans = tuple(span for span in final_spans if span[0] < span[1])
        if len(final_content_spans) <= config.chunk_overlap_tokens:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        next_start = local_start + final_content_spans[-config.chunk_overlap_tokens][0]
        next_start, _ = _protect_redacted_boundaries(
            prepared,
            region_start,
            next_start,
            local_end,
        )
        if not local_start < next_start < local_end:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        local_start = next_start
    if not windows or windows[0][0] != region_start or windows[-1][1] != region_end:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    if any(right_start > left_end for (_, left_end), (right_start, _) in pairwise(windows)):
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    return tuple(windows)


def _fit_projection_window(
    prepared: _PreparedFile,
    *,
    region: str,
    region_start: int,
    local_start: int,
    local_end: int,
    provider: EmbeddingProvider,
    token_limit: int,
    deadline: float,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    while local_start < local_end:
        spans = _token_spans(
            provider,
            region[local_start:local_end],
            deadline=deadline,
            stage=RetrievalStage.CHUNK,
        )
        if len(spans) <= token_limit:
            return local_end, spans
        content_spans = tuple(span for span in spans if span[0] < span[1])
        special_count = len(spans) - len(content_spans)
        capacity = token_limit - special_count
        if capacity <= 0 or len(content_spans) <= capacity:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        next_end = local_start + content_spans[capacity][0]
        absolute_start = region_start + local_start
        absolute_end = region_start + next_end
        for line in prepared.lines:
            if line.redacted and line.projected_start < absolute_end < line.projected_end:
                absolute_end = (
                    line.projected_start
                    if line.projected_start > absolute_start
                    else line.projected_end
                )
                break
        next_end = absolute_end - region_start
        if not local_start < next_end < local_end:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        local_end = next_end
    _fail(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)


def _expand_to_complete_lines(
    prepared: _PreparedFile,
    *,
    region_start: int,
    local_start: int,
    local_end: int,
    region_length: int,
    provider: EmbeddingProvider,
    token_limit: int,
    deadline: float,
) -> tuple[int, int]:
    absolute_start = region_start + local_start
    absolute_end = region_start + local_end
    expanded_start = _containing_line_start(prepared.lines, absolute_start)
    expanded_end = _containing_line_end(prepared.lines, absolute_end)
    snapped_start = max(region_start, expanded_start) - region_start
    snapped_end = min(region_start + region_length, expanded_end) - region_start
    for candidate_start, candidate_end in (
        (snapped_start, snapped_end),
        (snapped_start, local_end),
        (local_start, snapped_end),
    ):
        if candidate_start >= candidate_end:
            continue
        candidate = prepared.projection[
            region_start + candidate_start : region_start + candidate_end
        ]
        if (
            len(
                _token_spans(
                    provider,
                    candidate,
                    deadline=deadline,
                    stage=RetrievalStage.CHUNK,
                )
            )
            <= token_limit
        ):
            return candidate_start, candidate_end
    return _protect_redacted_boundaries(
        prepared,
        region_start,
        local_start,
        local_end,
    )


def _protect_redacted_boundaries(
    prepared: _PreparedFile,
    region_start: int,
    local_start: int,
    local_end: int,
) -> tuple[int, int]:
    absolute_start = region_start + local_start
    absolute_end = region_start + local_end
    for line in prepared.lines:
        if line.redacted and line.projected_start < absolute_start < line.projected_end:
            absolute_start = line.projected_start
        if line.redacted and line.projected_start < absolute_end < line.projected_end:
            absolute_end = line.projected_end
    return absolute_start - region_start, absolute_end - region_start


def _containing_line_start(lines: Sequence[_ProjectedLine], offset: int) -> int:
    for line in lines:
        if line.projected_start <= offset < line.projected_end:
            return line.projected_start
    return offset


def _containing_line_end(lines: Sequence[_ProjectedLine], offset: int) -> int:
    for line in lines:
        if line.projected_start < offset <= line.projected_end:
            return line.projected_end
        if offset == line.projected_start:
            return offset
    return offset


def _token_spans(
    provider: EmbeddingProvider,
    text: str,
    *,
    deadline: float,
    stage: RetrievalStage,
) -> tuple[tuple[int, int], ...]:
    _check_deadline(deadline, stage)
    failed = False
    provider_failure: RetrievalError | None = None
    try:
        value = provider.token_spans(text)
    except RetrievalError:
        provider_failure = _failure(
            RetrievalErrorCode.EMBEDDING_FAILED,
            stage,
            RetrievalChannel.VECTOR,
        )
        value = ()
    except Exception:
        failed = True
        value = ()
    _check_deadline(deadline, stage)
    if provider_failure is not None:
        raise provider_failure
    if failed or type(value) is not tuple:
        _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
    previous: tuple[int, int] | None = None
    for span in value:
        if (
            type(span) is not tuple
            or len(span) != 2
            or type(span[0]) is not int
            or type(span[1]) is not int
            or not 0 <= span[0] <= span[1] <= len(text)
        ):
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
        if span[0] < span[1]:
            if previous is not None and (span[0] < previous[0] or span[1] < previous[1]):
                _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
            previous = span
    return value


def _projection_byte_offset(
    prepared: _PreparedFile,
    projected_offset: int,
    *,
    ending: bool,
) -> int:
    if projected_offset == len(prepared.projection):
        return len(prepared.content)
    if not 0 <= projected_offset < len(prepared.projection):
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    starts = [line.projected_start for line in prepared.lines]
    index = bisect_right(starts, projected_offset) - 1
    if index < 0:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    line = prepared.lines[index]
    if projected_offset == line.projected_end:
        return line.original_end
    relative = projected_offset - line.projected_start
    if line.redacted:
        if relative == 0:
            return line.original_start
        if projected_offset == line.projected_end:
            return line.original_end
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    prefix = line.projected_text[:relative].encode("utf-8")
    result = line.original_start + len(prefix)
    if ending and projected_offset == line.projected_end:
        return line.original_end
    return result


def _chunk_lines(
    lines: Sequence[_ProjectedLine],
    start_byte: int,
    end_byte: int,
) -> tuple[int, int]:
    overlapping = tuple(
        line.number
        for line in lines
        if line.original_start < end_byte and line.original_end > start_byte
    )
    if not overlapping:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.CHUNK)
    return overlapping[0], overlapping[-1]


def _symbols_for_chunk(
    symbols: Sequence[_SymbolOccurrence],
    *,
    start_byte: int,
    end_byte: int,
) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for symbol in symbols:
        if start_byte <= symbol.byte_offset < end_byte and symbol.name not in seen:
            seen.add(symbol.name)
            result.append(symbol.name)
    return tuple(result)


def _chunk_id(
    *,
    head_oid: str,
    path: str,
    oid: str,
    start_byte: int,
    end_byte: int,
) -> str:
    value = {
        "schema_version": 1,
        "head_oid": head_oid,
        "path": path,
        "oid": oid,
        "start_byte": start_byte,
        "end_byte": end_byte,
    }
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ranges_cover(ranges: Sequence[tuple[int, int]], size: int) -> bool:
    if size == 0:
        return True
    if not ranges:
        return False
    ordered = sorted(ranges)
    covered_until = 0
    for start, end in ordered:
        if start > covered_until:
            return False
        covered_until = max(covered_until, end)
        if covered_until >= size:
            return True
    return False


def _chunk_sort_key(chunk: ContextChunk) -> tuple[bytes, int, int, int, int, str]:
    provenance = chunk.provenance
    return (
        provenance.path.encode("utf-8"),
        provenance.start_byte,
        provenance.end_byte,
        provenance.start_line,
        provenance.end_line,
        provenance.chunk_id,
    )


def _statistics(
    corpus: Sequence[_CorpusFile],
    chunks: Sequence[ContextChunk],
    *,
    python_line_terms: dict[tuple[str, int], _PythonLineTerms],
    excluded_count: int,
    unparsed_count: int,
    dense_matrix_bytes: int,
) -> IndexStatistics:
    original_blob_bytes = sum(len(item.content) for item in corpus)
    redacted_chunk_bytes = sum(len(chunk.content.encode("utf-8")) for chunk in chunks)
    metadata_bytes = sum(len(_chunk_metadata_bytes(chunk)) for chunk in chunks) + len(
        _python_line_metadata_bytes(python_line_terms)
    )
    logical_index_bytes = (
        original_blob_bytes + redacted_chunk_bytes + metadata_bytes + dense_matrix_bytes
    )
    return IndexStatistics(
        eligible_file_count=len(corpus),
        excluded_file_count=excluded_count,
        unparsed_python_file_count=unparsed_count,
        chunk_count=len(chunks),
        original_blob_bytes=original_blob_bytes,
        redacted_chunk_bytes=redacted_chunk_bytes,
        metadata_bytes=metadata_bytes,
        dense_matrix_bytes=dense_matrix_bytes,
        logical_index_bytes=logical_index_bytes,
    )


def _chunk_metadata_bytes(chunk: ContextChunk) -> bytes:
    provenance = chunk.provenance
    value = {
        "schema_version": 1,
        "chunk_id": provenance.chunk_id,
        "path": provenance.path,
        "oid": provenance.oid,
        "start_byte": provenance.start_byte,
        "end_byte": provenance.end_byte,
        "start_line": provenance.start_line,
        "end_line": provenance.end_line,
        "redacted_line_ranges": [
            {"start_line": start, "end_line": end} for start, end in chunk.redacted_line_ranges
        ],
        "definitions": list(chunk.definitions),
        "references": list(chunk.references),
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _python_line_metadata_bytes(
    terms: dict[tuple[str, int], _PythonLineTerms],
) -> bytes:
    if not terms:
        return b""
    by_path: dict[str, list[dict[str, object]]] = defaultdict(list)
    for (path, line_number), line_terms in sorted(
        terms.items(),
        key=lambda item: (item[0][0].encode("utf-8"), item[0][1]),
    ):
        by_path[path].append(
            {
                "line": line_number,
                "identifiers": list(line_terms.identifiers),
                "enclosing_symbol": line_terms.enclosing_symbol,
            }
        )
    value = {
        "schema_version": 1,
        "python_line_terms": [
            {"path": path, "lines": by_path[path]}
            for path in sorted(by_path, key=lambda item: item.encode("utf-8"))
        ],
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _build_text_index(
    chunks: Sequence[ContextChunk],
    deadline: float,
) -> sqlite3.Connection:
    _check_deadline(deadline, RetrievalStage.BUILD_TEXT)
    failed = False
    complete = False
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", check_same_thread=False)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute(
            "CREATE VIRTUAL TABLE retrieval_chunks "
            "USING fts5(path, symbols, content, tokenize='unicode61')"
        )
        rows = (
            (
                index + 1,
                chunk.provenance.path,
                " ".join((*chunk.definitions, *chunk.references)),
                chunk.content,
            )
            for index, chunk in enumerate(chunks)
        )
        connection.executemany(
            "INSERT INTO retrieval_chunks(rowid, path, symbols, content) VALUES (?, ?, ?, ?)",
            rows,
        )
        connection.commit()
        connection.execute("PRAGMA query_only=ON")
    except sqlite3.Error:
        failed = True
    try:
        _check_deadline(deadline, RetrievalStage.BUILD_TEXT)
        if failed or connection is None:
            _fail(
                RetrievalErrorCode.TEXT_BACKEND_UNAVAILABLE,
                RetrievalStage.BUILD_TEXT,
                RetrievalChannel.TEXT,
            )
        complete = True
        return connection
    finally:
        if not complete and connection is not None:
            with suppress(sqlite3.Error):
                connection.close()


def _build_vector_index(
    chunks: Sequence[ContextChunk],
    *,
    provider: EmbeddingProvider,
    dimension: int,
    deadline: float,
) -> _FaissIndex:
    _check_deadline(deadline, RetrievalStage.BUILD_VECTOR)
    module_failed = False
    try:
        faiss = importlib.import_module("faiss")
        constructor = cast(Callable[[int], _FaissIndex], faiss.IndexFlatIP)
        backend = constructor(dimension)
    except Exception:
        module_failed = True
        backend = None
    if module_failed or backend is None:
        _fail(
            RetrievalErrorCode.BACKEND_FAILED,
            RetrievalStage.BUILD_VECTOR,
            RetrievalChannel.VECTOR,
        )
    complete = False
    try:
        if backend.d != dimension or backend.ntotal != 0:
            _fail(
                RetrievalErrorCode.BACKEND_FAILED,
                RetrievalStage.BUILD_VECTOR,
                RetrievalChannel.VECTOR,
            )
        if not chunks:
            complete = True
            return backend

        matrices: list[_FloatMatrix] = []
        for offset in range(0, len(chunks), _EMBED_BATCH_SIZE):
            batch = chunks[offset : offset + _EMBED_BATCH_SIZE]
            documents = tuple(_embedding_document(chunk) for chunk in batch)
            for document in documents:
                if (
                    len(
                        _token_spans(
                            provider,
                            document,
                            deadline=deadline,
                            stage=RetrievalStage.EMBED,
                        )
                    )
                    > _MAX_EMBEDDING_DOCUMENT_TOKENS
                ):
                    _fail(
                        RetrievalErrorCode.EMBEDDING_FAILED,
                        RetrievalStage.EMBED,
                        RetrievalChannel.VECTOR,
                    )
            _check_deadline(deadline, RetrievalStage.EMBED)
            failed = False
            provider_failure: RetrievalError | None = None
            try:
                raw_vectors = provider.embed_documents(documents)
            except RetrievalError:
                provider_failure = _failure(
                    RetrievalErrorCode.EMBEDDING_FAILED,
                    RetrievalStage.EMBED,
                    RetrievalChannel.VECTOR,
                )
                raw_vectors = ()
            except Exception:
                failed = True
                raw_vectors = ()
            _check_deadline(deadline, RetrievalStage.EMBED)
            if provider_failure is not None:
                raise provider_failure
            if failed:
                _fail(
                    RetrievalErrorCode.EMBEDDING_FAILED,
                    RetrievalStage.EMBED,
                    RetrievalChannel.VECTOR,
                )
            matrices.append(
                _validated_matrix(
                    raw_vectors,
                    expected_count=len(batch),
                    dimension=dimension,
                    stage=RetrievalStage.EMBED,
                )
            )
        matrix = np.ascontiguousarray(np.concatenate(matrices, axis=0), dtype=np.float32)
        if matrix.shape != (len(chunks), dimension):
            _fail(
                RetrievalErrorCode.EMBEDDING_FAILED,
                RetrievalStage.EMBED,
                RetrievalChannel.VECTOR,
            )
        add_failed = False
        try:
            backend.add(matrix)
        except Exception:
            add_failed = True
        _check_deadline(deadline, RetrievalStage.BUILD_VECTOR)
        if add_failed or backend.ntotal != len(chunks):
            _fail(
                RetrievalErrorCode.BACKEND_FAILED,
                RetrievalStage.BUILD_VECTOR,
                RetrievalChannel.VECTOR,
            )
        complete = True
        return backend
    finally:
        if not complete:
            with suppress(Exception):
                backend.reset()


def _embedding_document(chunk: ContextChunk) -> str:
    value = {
        "path": chunk.provenance.path,
        "definitions": list(chunk.definitions),
        "references": list(chunk.references),
        "content": chunk.content,
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validated_matrix(
    value: object,
    *,
    expected_count: int,
    dimension: int,
    stage: RetrievalStage,
) -> _FloatMatrix:
    if type(value) is not tuple or len(value) != expected_count:
        _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
    rows: list[tuple[float, ...]] = []
    for vector in value:
        if type(vector) is not tuple or len(vector) != dimension:
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
        row: list[float] = []
        for component in vector:
            if isinstance(component, bool) or not isinstance(
                component,
                (int, float, np.floating),
            ):
                _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
            try:
                numeric = float(component)
            except (OverflowError, TypeError, ValueError):
                _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
            if not math.isfinite(numeric) or abs(numeric) > _FLOAT32_MAX:
                _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
            row.append(numeric)
        rows.append(tuple(row))
    with np.errstate(over="ignore", invalid="ignore", divide="ignore", under="ignore"):
        matrix = np.asarray(rows, dtype=np.float32)
    if matrix.shape != (expected_count, dimension) or not np.isfinite(matrix).all():
        _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
    if expected_count:
        with np.errstate(over="ignore", invalid="ignore", divide="ignore", under="ignore"):
            norms = np.linalg.norm(matrix.astype(np.float64), axis=1)
        if not np.isfinite(norms).all() or not np.allclose(
            norms,
            np.ones(expected_count, dtype=np.float32),
            rtol=0.0,
            atol=_NORMALIZATION_TOLERANCE,
        ):
            _fail(RetrievalErrorCode.EMBEDDING_FAILED, stage, RetrievalChannel.VECTOR)
    return np.ascontiguousarray(matrix, dtype=np.float32)


def _build_symbol_index(
    chunks: Sequence[ContextChunk],
    *,
    enabled: bool,
    deadline: float,
) -> tuple[dict[str, tuple[int, ...]], dict[str, tuple[int, ...]]]:
    _check_deadline(deadline, RetrievalStage.BUILD_SYMBOL)
    if not enabled:
        return {}, {}
    definitions: dict[str, list[int]] = defaultdict(list)
    references: dict[str, list[int]] = defaultdict(list)
    for index, chunk in enumerate(chunks):
        for symbol in chunk.definitions:
            if symbol.isidentifier():
                definitions[symbol].append(index)
        for symbol in chunk.references:
            if symbol.isidentifier():
                references[symbol].append(index)
    _check_deadline(deadline, RetrievalStage.BUILD_SYMBOL)
    return (
        {
            name: tuple(indices)
            for name, indices in sorted(
                definitions.items(),
                key=lambda item: item[0].encode("utf-8"),
            )
        },
        {
            name: tuple(indices)
            for name, indices in sorted(
                references.items(),
                key=lambda item: item[0].encode("utf-8"),
            )
        },
    )


def _retrieve_context(index: ContextIndex, query: ContextQuery) -> RetrievalResult:
    """Retrieve one query with one complete shared query deadline."""
    failure: RetrievalError | None = None
    try:
        return _retrieve_context_impl(index, query)
    except RetrievalError as error:
        failure = _detached_failure(error, fallback_stage=RetrievalStage.FUSE)
    except Exception:
        failure = _failure(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.FUSE)
    assert failure is not None
    raise failure


def _retrieve_context_impl(
    index: ContextIndex,
    query: ContextQuery,
) -> RetrievalResult:
    state = _validated_state(index)
    deadline = time.monotonic() + state._config.query_timeout_seconds
    return _retrieve_queries(
        state,
        (query,),
        deadline=deadline,
        query_digest=None,
    )


def _retrieve_context_queries(
    index: ContextIndex,
    queries: tuple[ContextQuery, ...],
    *,
    deadline: float | None = None,
) -> RetrievalResult:
    """Private multi-query entry point used by the opt-in M4 Agent workflow."""
    failure: RetrievalError | None = None
    try:
        return _retrieve_context_queries_impl(index, queries, deadline=deadline)
    except RetrievalError as error:
        failure = _detached_failure(error, fallback_stage=RetrievalStage.FUSE)
    except Exception:
        failure = _failure(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.FUSE)
    assert failure is not None
    raise failure


def _retrieve_context_queries_impl(
    index: ContextIndex,
    queries: tuple[ContextQuery, ...],
    *,
    deadline: float | None = None,
) -> RetrievalResult:
    state = _validated_state(index)
    if type(queries) is not tuple or not queries or len(queries) > _MAX_BATCH_QUERIES:
        _fail(RetrievalErrorCode.QUERY_LIMIT_EXCEEDED, RetrievalStage.VALIDATE)
    local_deadline = time.monotonic() + state._config.query_timeout_seconds
    effective_deadline = local_deadline if deadline is None else min(local_deadline, deadline)
    return _retrieve_queries(
        state,
        queries,
        deadline=effective_deadline,
        query_digest=None,
    )


def _validated_state(value: object) -> _IndexState:
    if type(value) is not ContextIndex:
        _fail(RetrievalErrorCode.INVALID_INDEX, RetrievalStage.VALIDATE)
    assert isinstance(value, ContextIndex)
    state = value._state
    if type(state) is not _IndexState:
        _fail(RetrievalErrorCode.INVALID_INDEX, RetrievalStage.VALIDATE)
    return state


def _retrieve_queries(
    state: _IndexState,
    queries: tuple[ContextQuery, ...],
    *,
    deadline: float,
    query_digest: str | None,
) -> RetrievalResult:
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not state._lock.acquire(timeout=remaining):
        _fail(RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalStage.VALIDATE)
    try:
        if state._closed:
            _fail(RetrievalErrorCode.INDEX_CLOSED, RetrievalStage.VALIDATE)
        _check_deadline(deadline, RetrievalStage.VALIDATE)
        validated = tuple(
            _validate_query(
                query,
                provider=state._provider,
                deadline=deadline,
            )
            for query in queries
        )
        if query_digest is None:
            query_digest = _validated_query_digest(validated)
        aggregate: dict[int, dict[str, object]] = {}
        for query_number, text in enumerate(validated):
            _check_deadline(deadline, RetrievalStage.FUSE)
            rankings = _channel_rankings(state, text, deadline)
            matched_this_query: set[int] = set()
            for channel in state._config.channels:
                for rank, chunk_index in enumerate(rankings.get(channel, ()), start=1):
                    item = aggregate.setdefault(
                        chunk_index,
                        {
                            "channels": set(),
                            "text_rank": None,
                            "vector_rank": None,
                            "symbol_rank": None,
                            "query_numbers": set(),
                            "score": 0,
                        },
                    )
                    cast(set[RetrievalChannel], item["channels"]).add(channel)
                    rank_key = f"{channel.value}_rank"
                    current_rank = cast(int | None, item[rank_key])
                    if current_rank is None or rank < current_rank:
                        item[rank_key] = rank
                    item["score"] = cast(int, item["score"]) + _rrf_contribution(rank)
                    matched_this_query.add(chunk_index)
            for chunk_index in matched_this_query:
                cast(set[int], aggregate[chunk_index]["query_numbers"]).add(query_number)
        fused = _fuse(state, aggregate, deadline)
        return RetrievalResult(
            index=state._identity,
            query_sha256=query_digest,
            candidate_count=fused.candidate_count,
            selected_count=len(fused.hits),
            omitted_count=fused.omitted_count,
            hits=fused.hits,
        )
    finally:
        state._lock.release()


def _validated_query_digest(queries: tuple[str, ...]) -> str:
    hashes = tuple(hashlib.sha256(query.encode("utf-8")).hexdigest() for query in queries)
    if len(hashes) == 1:
        return hashes[0]
    return hashlib.sha256(
        json.dumps(
            hashes,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _validate_query(
    value: object,
    *,
    provider: EmbeddingProvider,
    deadline: float,
) -> str:
    if (
        not isinstance(value, ContextQuery)
        or type(value.text) is not str
        or not value.text
        or len(value.text) > _MAX_QUERY_BYTES
    ):
        _fail(RetrievalErrorCode.QUERY_LIMIT_EXCEEDED, RetrievalStage.VALIDATE)
    failed = False
    try:
        encoded = value.text.encode("utf-8")
    except UnicodeEncodeError:
        failed = True
        encoded = b""
    if (
        failed
        or len(encoded) > _MAX_QUERY_BYTES
        or any(unicodedata.category(character) == "Cc" for character in value.text)
    ):
        _fail(RetrievalErrorCode.QUERY_LIMIT_EXCEEDED, RetrievalStage.VALIDATE)
    spans = _token_spans(
        provider,
        value.text,
        deadline=deadline,
        stage=RetrievalStage.VALIDATE,
    )
    if len(spans) > _MAX_QUERY_TOKENS:
        _fail(RetrievalErrorCode.QUERY_LIMIT_EXCEEDED, RetrievalStage.VALIDATE)
    return value.text


def _channel_rankings(
    state: _IndexState,
    query: str,
    deadline: float,
) -> _Rankings:
    rankings: _Rankings = {}
    for channel in state._config.channels:
        if channel is RetrievalChannel.TEXT:
            rankings[channel] = _query_text(state, query, deadline)
        elif channel is RetrievalChannel.VECTOR:
            rankings[channel] = _query_vector(state, query, deadline)
        else:
            rankings[channel] = _query_symbol(state, query, deadline)
    return rankings


def _query_text(
    state: _IndexState,
    query: str,
    deadline: float,
) -> tuple[int, ...]:
    _check_deadline(deadline, RetrievalStage.QUERY_TEXT)
    backend = state._sqlite
    if backend is None:
        _fail(
            RetrievalErrorCode.INVALID_INDEX,
            RetrievalStage.QUERY_TEXT,
            RetrievalChannel.TEXT,
        )
    expression = _fts_expression(query)
    if expression is None:
        return ()
    failed = False
    try:
        rows = backend.execute(
            "SELECT rowid, bm25(retrieval_chunks, 5.0, 3.0, 1.0) AS score "
            "FROM retrieval_chunks WHERE retrieval_chunks MATCH ? "
            "ORDER BY score ASC, rowid ASC LIMIT ?",
            (expression, state._config.max_candidates_per_channel),
        ).fetchall()
    except sqlite3.Error:
        failed = True
        rows = []
    _check_deadline(deadline, RetrievalStage.QUERY_TEXT)
    if failed:
        _fail(
            RetrievalErrorCode.BACKEND_FAILED,
            RetrievalStage.QUERY_TEXT,
            RetrievalChannel.TEXT,
        )
    result: list[int] = []
    for row in rows:
        if (
            type(row) is not tuple
            or len(row) != 2
            or type(row[0]) is not int
            or not 1 <= row[0] <= len(state._chunks)
            or isinstance(row[1], bool)
            or not isinstance(row[1], (int, float))
            or not math.isfinite(float(row[1]))
        ):
            _fail(
                RetrievalErrorCode.BACKEND_FAILED,
                RetrievalStage.QUERY_TEXT,
                RetrievalChannel.TEXT,
            )
        result.append(row[0] - 1)
    if len(result) != len(set(result)):
        _fail(
            RetrievalErrorCode.BACKEND_FAILED,
            RetrievalStage.QUERY_TEXT,
            RetrievalChannel.TEXT,
        )
    return tuple(result)


def _fts_expression(query: str) -> str | None:
    terms: list[str] = []
    seen: set[str] = set()
    for match in _WORD.finditer(query):
        term = match.group(0)
        if term in seen:
            continue
        seen.add(term)
        escaped = term.replace('"', '""')
        terms.append(f'"{escaped}"')
    if not terms:
        return None
    return " OR ".join(terms)


def _query_vector(
    state: _IndexState,
    query: str,
    deadline: float,
) -> tuple[int, ...]:
    _check_deadline(deadline, RetrievalStage.QUERY_VECTOR)
    backend = state._faiss
    if backend is None:
        _fail(
            RetrievalErrorCode.INVALID_INDEX,
            RetrievalStage.QUERY_VECTOR,
            RetrievalChannel.VECTOR,
        )
    failed = False
    provider_failure: RetrievalError | None = None
    try:
        raw_vectors = state._provider.embed_queries((query,))
    except RetrievalError:
        provider_failure = _failure(
            RetrievalErrorCode.EMBEDDING_FAILED,
            RetrievalStage.QUERY_VECTOR,
            RetrievalChannel.VECTOR,
        )
        raw_vectors = ()
    except Exception:
        failed = True
        raw_vectors = ()
    _check_deadline(deadline, RetrievalStage.QUERY_VECTOR)
    if provider_failure is not None:
        raise provider_failure
    if failed:
        _fail(
            RetrievalErrorCode.EMBEDDING_FAILED,
            RetrievalStage.QUERY_VECTOR,
            RetrievalChannel.VECTOR,
        )
    query_matrix = _validated_matrix(
        raw_vectors,
        expected_count=1,
        dimension=state._identity.dimension,
        stage=RetrievalStage.QUERY_VECTOR,
    )
    if not state._chunks:
        return ()
    search_failed = False
    try:
        scores, indices = backend.search(query_matrix, len(state._chunks))
    except Exception:
        search_failed = True
        scores = np.empty((0, 0), dtype=np.float32)
        indices = np.empty((0, 0), dtype=np.int64)
    _check_deadline(deadline, RetrievalStage.QUERY_VECTOR)
    if (
        search_failed
        or scores.shape != (1, len(state._chunks))
        or indices.shape != (1, len(state._chunks))
        or not np.isfinite(scores).all()
    ):
        _fail(
            RetrievalErrorCode.BACKEND_FAILED,
            RetrievalStage.QUERY_VECTOR,
            RetrievalChannel.VECTOR,
        )
    candidates: list[tuple[float, tuple[bytes, int, int, int, int, str], int]] = []
    seen: set[int] = set()
    for score, raw_index in zip(scores[0], indices[0], strict=True):
        chunk_index = int(raw_index)
        if not 0 <= chunk_index < len(state._chunks) or chunk_index in seen:
            _fail(
                RetrievalErrorCode.BACKEND_FAILED,
                RetrievalStage.QUERY_VECTOR,
                RetrievalChannel.VECTOR,
            )
        seen.add(chunk_index)
        candidates.append(
            (
                -float(score),
                _chunk_sort_key(state._chunks[chunk_index]),
                chunk_index,
            )
        )
    candidates.sort()
    return tuple(item[2] for item in candidates[: state._config.max_candidates_per_channel])


def _query_symbol(
    state: _IndexState,
    query: str,
    deadline: float,
) -> tuple[int, ...]:
    _check_deadline(deadline, RetrievalStage.QUERY_SYMBOL)
    identifiers = _query_identifiers(query)
    definitions: list[int] = []
    references: list[int] = []
    seen_definitions: set[int] = set()
    seen_references: set[int] = set()
    for identifier in identifiers:
        for index in state._symbol_definitions.get(identifier, ()):
            if index not in seen_definitions:
                seen_definitions.add(index)
                definitions.append(index)
    for identifier in identifiers:
        for index in state._symbol_references.get(identifier, ()):
            if index not in seen_definitions and index not in seen_references:
                seen_references.add(index)
                references.append(index)
    _check_deadline(deadline, RetrievalStage.QUERY_SYMBOL)
    return tuple((*definitions, *references)[: state._config.max_candidates_per_channel])


def _query_identifiers(query: str) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for match in _IDENTIFIER.finditer(query):
        identifier = match.group(0)
        candidates = [identifier]
        for underscore_part in identifier.split("_"):
            candidates.extend(_CAMEL_PART.findall(underscore_part))
        for candidate in candidates:
            if candidate and candidate.isidentifier() and candidate not in seen:
                seen.add(candidate)
                result.append(candidate)
    return tuple(result)


def _rrf_contribution(rank: int) -> int:
    if type(rank) is not int or rank < 1:
        _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.FUSE)
    return _RRF_SCALE // (_RRF_K + rank)


def _fuse(
    state: _IndexState,
    aggregate: dict[int, dict[str, object]],
    deadline: float,
) -> _Fused:
    _check_deadline(deadline, RetrievalStage.FUSE)
    hits: list[RetrievalHit] = []
    for chunk_index, item in aggregate.items():
        if not 0 <= chunk_index < len(state._chunks):
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.FUSE)
        channels = tuple(
            channel
            for channel in state._config.channels
            if channel in cast(set[RetrievalChannel], item["channels"])
        )
        query_numbers = cast(set[int], item["query_numbers"])
        score = cast(int, item["score"])
        if not channels or not query_numbers or score <= 0:
            _fail(RetrievalErrorCode.BACKEND_FAILED, RetrievalStage.FUSE)
        hits.append(
            RetrievalHit(
                chunk=state._chunks[chunk_index],
                channels=channels,
                text_rank=cast(int | None, item["text_rank"]),
                vector_rank=cast(int | None, item["vector_rank"]),
                symbol_rank=cast(int | None, item["symbol_rank"]),
                matched_query_count=len(query_numbers),
                rrf_score=score,
            )
        )
    hits.sort(
        key=lambda hit: (
            -hit.rrf_score,
            *_chunk_sort_key(hit.chunk),
        )
    )
    selected = tuple(hits[: state._config.max_results])
    _check_deadline(deadline, RetrievalStage.FUSE)
    return _Fused(
        hits=selected,
        candidate_count=len(hits),
        omitted_count=len(hits) - len(selected),
    )
