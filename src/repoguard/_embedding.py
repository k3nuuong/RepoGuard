"""Private fixed-model embedding implementation for M4 retrieval."""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import ssl
import stat
import tempfile
import threading
import time
import warnings
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Protocol, cast
from urllib import request
from urllib.parse import urlsplit

import numpy as np
import onnxruntime as ort  # type: ignore[import-untyped]
from fastembed import TextEmbedding
from fastembed.common.types import NumpyArray
from huggingface_hub import hf_hub_url
from tokenizers import Tokenizer

from repoguard.retrieval import (
    EmbeddingDevice,
    FastEmbedProvider,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
)

_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REPOSITORY = "Qdrant/bge-small-en-v1.5-onnx-Q"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"
_MODEL_ENDPOINT = "https://huggingface.co"
_MODEL_DIMENSION = 384
_MANIFEST_RESOURCE = "models/bge_small_en_v1_5/manifest.json"
_EXPECTED_MODEL_FILES = frozenset(
    {
        "config.json",
        "model_optimized.onnx",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
    }
)
_CACHE_NAMESPACE = f"bge-small-en-v1.5-{_MODEL_REVISION}"
_DOWNLOAD_READ_BYTES = 1024 * 1024
_NETWORK_OPERATION_TIMEOUT_SECONDS = 30.0
_NORMALIZATION_ABSOLUTE_TOLERANCE = 1e-4
_LOWERCASE_HEX = frozenset("0123456789abcdef")
_MODEL_LOCK = threading.RLock()
_monotonic: Callable[[], float] = time.monotonic


@dataclass(frozen=True, slots=True)
class _ManifestFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _ModelManifest:
    files: tuple[_ManifestFile, ...]
    sha256: str


@dataclass(slots=True)
class _ModelSnapshot:
    path: Path
    temporary: tempfile.TemporaryDirectory[str]

    def close(self) -> None:
        with suppress(OSError):
            self.path.chmod(0o700)
        self.temporary.cleanup()


@dataclass(slots=True)
class _FastEmbedState:
    embedding: TextEmbedding | None
    tokenizer: Tokenizer | None
    manifest_sha256: str
    closed: bool = False


@dataclass(frozen=True, slots=True)
class _ClosedFastEmbedState:
    pass


_CLOSED = _ClosedFastEmbedState()


class _InferenceSession(Protocol):
    def get_providers(self) -> list[str]: ...


class _OnnxTextEmbedding(Protocol):
    model: _InferenceSession | None
    tokenizer: Tokenizer | None


class _TextEmbeddingOwner(Protocol):
    model: object | None


class _DownloadResponse(Protocol):
    def read(self, amount: int = -1) -> bytes: ...

    def getcode(self) -> int | None: ...

    def __enter__(self) -> _DownloadResponse: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None: ...


class _UrlOpener(Protocol):
    def open(
        self,
        fullurl: request.Request,
        data: bytes | None = None,
        timeout: float | object = ...,
    ) -> _DownloadResponse: ...


def _initialize_fastembed(
    provider: FastEmbedProvider,
    *,
    repository_root: Path,
    deadline: float,
) -> None:
    """Validate, load, and bind one fixed FastEmbed model to ``provider``."""
    validation_failure = _validate_initialization(provider, repository_root, deadline)
    if validation_failure is not None:
        raise validation_failure from None

    cache_dir = provider._cache_dir.resolve(strict=False)
    manifest: _ModelManifest | None = None
    model_dir: Path | None = None
    embedding: TextEmbedding | None = None
    tokenizer: Tokenizer | None = None
    actual_device: EmbeddingDevice | None = None
    failure: RetrievalError | None = None
    snapshot: _ModelSnapshot | None = None

    remaining = deadline - _monotonic()
    if remaining <= 0 or not _MODEL_LOCK.acquire(timeout=remaining):
        raise _error(RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalStage.EMBED) from None
    try:
        try:
            _check_deadline(deadline)
            manifest = _load_manifest(deadline)
            model_dir = _prepare_model_directory(
                cache_dir=cache_dir,
                manifest=manifest,
                allow_download=provider._allow_download,
                deadline=deadline,
            )
            snapshot = _snapshot_model_directory(model_dir, manifest, deadline)
            selected_device = _select_device(provider._requested_device, deadline)
            _preflight_cuda_provider(selected_device, deadline)
            tokenizer = _load_tokenizer(snapshot.path, deadline)
            embedding = _load_fastembed(snapshot.path, cache_dir, selected_device, deadline)
            _verify_actual_provider(embedding, selected_device, deadline)
            actual_device = selected_device
        except RetrievalError as error:
            failure = _detached_error(error)
        except Exception:
            failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    finally:
        if snapshot is not None:
            try:
                snapshot.close()
            except Exception:
                if failure is None:
                    failure = _error(
                        RetrievalErrorCode.MODEL_UNAVAILABLE,
                        RetrievalStage.EMBED,
                    )
        _MODEL_LOCK.release()

    if (
        failure is not None
        or manifest is None
        or model_dir is None
        or embedding is None
        or tokenizer is None
        or actual_device is None
    ):
        _release_embedding(embedding)
        provider._backend = _CLOSED
        provider._actual_device = None
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        ) from None

    provider._backend = _FastEmbedState(
        embedding=embedding,
        tokenizer=tokenizer,
        manifest_sha256=manifest.sha256,
    )
    provider._actual_device = actual_device


def _provider_model_identity(provider: FastEmbedProvider) -> tuple[str, str]:
    """Return the fixed revision and verified manifest digest for a live provider."""
    state = _live_state(provider, RetrievalStage.VALIDATE)
    return _MODEL_REVISION, state.manifest_sha256


def _token_spans(
    provider: FastEmbedProvider,
    text: str,
) -> tuple[tuple[int, int], ...]:
    """Return independent tokenizer offsets, including zero-width special tokens."""
    state = _live_state(provider, RetrievalStage.CHUNK)
    failure: RetrievalError | None = None
    spans: tuple[tuple[int, int], ...] | None = None
    try:
        if type(text) is not str:
            raise TypeError
        text.encode("utf-8", errors="strict")
        tokenizer = state.tokenizer
        if tokenizer is None:
            raise RuntimeError
        raw_spans = tokenizer.encode(text, add_special_tokens=True).offsets
        if any(
            type(start) is not int
            or type(end) is not int
            or start < 0
            or end < start
            or end > len(text)
            for start, end in raw_spans
        ):
            raise ValueError
        spans = tuple(raw_spans)
    except Exception:
        failure = _error(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
    if failure is not None or spans is None:
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.EMBEDDING_FAILED, RetrievalStage.CHUNK)
        ) from None
    return spans


def _embed_documents(
    provider: FastEmbedProvider,
    texts: tuple[str, ...],
) -> tuple[tuple[float, ...], ...]:
    """Embed documents through FastEmbed's passage path."""
    state = _live_state(provider, RetrievalStage.EMBED)
    embedding = state.embedding
    if embedding is None:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None
    return _run_embedding(
        lambda: embedding.passage_embed(texts, parallel=None),
        texts,
        stage=RetrievalStage.EMBED,
    )


def _embed_queries(
    provider: FastEmbedProvider,
    texts: tuple[str, ...],
) -> tuple[tuple[float, ...], ...]:
    """Embed queries through FastEmbed's query path."""
    state = _live_state(provider, RetrievalStage.QUERY_VECTOR)
    embedding = state.embedding
    if embedding is None:
        raise _error(
            RetrievalErrorCode.MODEL_UNAVAILABLE,
            RetrievalStage.QUERY_VECTOR,
        ) from None
    return _run_embedding(
        lambda: embedding.query_embed(texts, parallel=None),
        texts,
        stage=RetrievalStage.QUERY_VECTOR,
    )


def _close_fastembed(provider: FastEmbedProvider) -> None:
    """Release native model references without deleting caller-owned cache files."""
    backend = provider._backend
    if backend is _CLOSED:
        return
    if backend is None:
        provider._backend = _CLOSED
        return
    if not isinstance(backend, _FastEmbedState):
        provider._backend = _CLOSED
        provider._actual_device = None
        return

    embedding = backend.embedding
    backend.embedding = None
    backend.tokenizer = None
    backend.closed = True
    provider._backend = _CLOSED
    _release_embedding(embedding)


def _validate_initialization(
    provider: FastEmbedProvider,
    repository_root: Path,
    deadline: float,
) -> RetrievalError | None:
    try:
        if not isinstance(provider, FastEmbedProvider):
            raise TypeError
        if provider._backend is not None or provider._actual_device is not None:
            raise ValueError
        if not isinstance(provider._cache_dir, Path):
            raise TypeError
        if type(provider._allow_download) is not bool:
            raise TypeError
        if type(provider._requested_device) is not EmbeddingDevice:
            raise TypeError
        if not isinstance(repository_root, Path):
            raise TypeError
        if type(deadline) is not float or not math.isfinite(deadline):
            raise TypeError
        _check_deadline(deadline)
        repository = repository_root.resolve(strict=True)
        if not repository.is_dir():
            raise ValueError
        cache = provider._cache_dir.resolve(strict=False)
        if cache == Path(cache.anchor) or cache == repository or cache.is_relative_to(repository):
            raise ValueError
    except RetrievalError as error:
        return _detached_error(error)
    except Exception:
        return _error(
            RetrievalErrorCode.INVALID_CONFIGURATION,
            RetrievalStage.VALIDATE,
        )
    return None


def _load_manifest(deadline: float) -> _ModelManifest:
    raw: bytes | None = None
    parsed: object = None
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        raw = resources.files("repoguard").joinpath(_MANIFEST_RESOURCE).read_bytes()
        _check_deadline(deadline)
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(text, object_pairs_hook=_strict_json_object)
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None or raw is None:
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        ) from None

    try:
        manifest = _parse_manifest(parsed, hashlib.sha256(raw).hexdigest())
    except Exception:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None
    return manifest


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_manifest(value: object, digest: str) -> _ModelManifest:
    if type(value) is not dict:
        raise ValueError
    root = cast(dict[object, object], value)
    if set(root) != {"schema_version", "model", "repository", "revision", "files"}:
        raise ValueError
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError
    if root["model"] != _MODEL:
        raise ValueError
    if root["repository"] != _MODEL_REPOSITORY:
        raise ValueError
    if root["revision"] != _MODEL_REVISION:
        raise ValueError

    raw_files = root["files"]
    if type(raw_files) is not list:
        raise ValueError
    files: list[_ManifestFile] = []
    seen: set[str] = set()
    for raw_file in cast(list[object], raw_files):
        if type(raw_file) is not dict:
            raise ValueError
        item = cast(dict[object, object], raw_file)
        if set(item) != {"path", "size", "sha256"}:
            raise ValueError
        path = item["path"]
        size = item["size"]
        sha256 = item["sha256"]
        if (
            type(path) is not str
            or not path
            or path in seen
            or Path(path).name != path
            or "/" in path
            or "\\" in path
        ):
            raise ValueError
        path.encode("utf-8", errors="strict")
        if type(size) is not int or size <= 0:
            raise ValueError
        if (
            type(sha256) is not str
            or len(sha256) != 64
            or any(character not in _LOWERCASE_HEX for character in sha256)
        ):
            raise ValueError
        seen.add(path)
        files.append(_ManifestFile(path=path, size=size, sha256=sha256))
    if seen != _EXPECTED_MODEL_FILES:
        raise ValueError
    if tuple(file.path for file in files) != tuple(
        sorted(_EXPECTED_MODEL_FILES, key=lambda path: path.encode("utf-8"))
    ):
        raise ValueError
    return _ModelManifest(files=tuple(files), sha256=digest)


def _prepare_model_directory(
    *,
    cache_dir: Path,
    manifest: _ModelManifest,
    allow_download: bool,
    deadline: float,
) -> Path:
    _check_deadline(deadline)
    _ensure_directory(cache_dir)
    namespace = cache_dir / _CACHE_NAMESPACE
    _ensure_directory(namespace)
    model_dir = namespace / "model"
    if model_dir.exists() or model_dir.is_symlink():
        _verify_model_directory(model_dir, manifest, deadline)
        return model_dir
    if not allow_download:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None

    partial_dir = namespace / "partial"
    _ensure_directory(partial_dir)
    opener: _UrlOpener | None = None
    for item in manifest.files:
        _check_deadline(deadline)
        completed = partial_dir / item.path
        if completed.exists() or completed.is_symlink():
            _verify_model_file(completed, item, deadline)
            continue
        if opener is None:
            opener = _build_url_opener()
        _download_model_file(
            opener=opener,
            namespace=namespace,
            destination=completed,
            item=item,
            deadline=deadline,
        )
    _verify_model_directory(partial_dir, manifest, deadline)
    try:
        partial_dir.rename(model_dir)
    except FileExistsError:
        _verify_model_directory(model_dir, manifest, deadline)
    except OSError:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None
    _verify_model_directory(model_dir, manifest, deadline)
    return model_dir


def _ensure_directory(path: Path) -> None:
    failure = False
    try:
        if path.exists() or path.is_symlink():
            details = path.lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                failure = True
        else:
            path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        failure = True
    if failure:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None


def _verify_model_directory(
    model_dir: Path,
    manifest: _ModelManifest,
    deadline: float,
) -> None:
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        details = model_dir.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError
        names = {entry.name for entry in model_dir.iterdir()}
        if names != _EXPECTED_MODEL_FILES:
            raise ValueError
        for item in manifest.files:
            _verify_model_file(model_dir / item.path, item, deadline)
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None:
        raise failure from None


def _verify_model_file(path: Path, item: _ManifestFile, deadline: float) -> None:
    file_descriptor: int | None = None
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        path_details = path.lstat()
        if stat.S_ISLNK(path_details.st_mode) or not stat.S_ISREG(path_details.st_mode):
            raise ValueError
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_descriptor = os.open(path, flags)
        details = os.fstat(file_descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size != item.size:
            raise ValueError
        digest = hashlib.sha256()
        with os.fdopen(file_descriptor, "rb", closefd=True) as stream:
            file_descriptor = None
            while block := stream.read(_DOWNLOAD_READ_BYTES):
                digest.update(block)
                _check_deadline(deadline)
        if digest.hexdigest() != item.sha256:
            raise ValueError
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
    if failure is not None:
        raise failure from None


def _snapshot_model_directory(
    model_dir: Path,
    manifest: _ModelManifest,
    deadline: float,
) -> _ModelSnapshot:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    failure: RetrievalError | None = None
    snapshot: _ModelSnapshot | None = None
    try:
        _check_deadline(deadline)
        details = model_dir.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError
        if {entry.name for entry in model_dir.iterdir()} != _EXPECTED_MODEL_FILES:
            raise ValueError
        temporary = tempfile.TemporaryDirectory(
            prefix=".snapshot-",
            dir=model_dir.parent,
        )
        snapshot_path = Path(temporary.name)
        snapshot_details = snapshot_path.lstat()
        if stat.S_ISLNK(snapshot_details.st_mode) or not stat.S_ISDIR(snapshot_details.st_mode):
            raise ValueError
        snapshot_path.chmod(0o700)
        for item in manifest.files:
            _copy_verified_model_file(
                source=model_dir / item.path,
                destination=snapshot_path / item.path,
                item=item,
                deadline=deadline,
            )
        snapshot_path.chmod(0o500)
        _check_deadline(deadline)
        snapshot = _ModelSnapshot(path=snapshot_path, temporary=temporary)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None or snapshot is None:
        if temporary is not None:
            with suppress(Exception):
                path = Path(temporary.name)
                with suppress(OSError):
                    path.chmod(0o700)
                temporary.cleanup()
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        ) from None
    return snapshot


def _copy_verified_model_file(
    *,
    source: Path,
    destination: Path,
    item: _ManifestFile,
    deadline: float,
) -> None:
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        _check_deadline(deadline)
        source_flags = os.O_RDONLY
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
            destination_flags |= os.O_NOFOLLOW
        source_descriptor = os.open(source, source_flags)
        source_details = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_details.st_mode) or source_details.st_size != item.size:
            raise ValueError
        destination_descriptor = os.open(destination, destination_flags, 0o400)
        digest = hashlib.sha256()
        total = 0
        with (
            os.fdopen(source_descriptor, "rb", closefd=True) as input_stream,
            os.fdopen(destination_descriptor, "wb", closefd=True) as output_stream,
        ):
            source_descriptor = None
            destination_descriptor = None
            while block := input_stream.read(_DOWNLOAD_READ_BYTES):
                total += len(block)
                if total > item.size:
                    raise ValueError
                digest.update(block)
                output_stream.write(block)
                _check_deadline(deadline)
            output_stream.flush()
        if total != item.size or digest.hexdigest() != item.sha256:
            raise ValueError
        _check_deadline(deadline)
    finally:
        if source_descriptor is not None:
            with suppress(OSError):
                os.close(source_descriptor)
        if destination_descriptor is not None:
            with suppress(OSError):
                os.close(destination_descriptor)


def _build_url_opener() -> _UrlOpener:
    proxies: dict[str, str] = {}
    for scheme in ("http", "https"):
        value = os.environ.get(f"{scheme}_proxy")
        if value is None:
            value = os.environ.get(f"{scheme.upper()}_PROXY")
        if value is None or not value:
            continue
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.fragment
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None
        proxies[scheme] = value
    ssl_context = ssl.create_default_context()
    return cast(
        _UrlOpener,
        request.build_opener(
            request.ProxyHandler(proxies),
            request.HTTPSHandler(context=ssl_context),
        ),
    )


def _download_model_file(
    *,
    opener: _UrlOpener,
    namespace: Path,
    destination: Path,
    item: _ManifestFile,
    deadline: float,
) -> None:
    temporary = namespace / f".{item.path}.partial"
    file_descriptor: int | None = None
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        url = hf_hub_url(
            repo_id=_MODEL_REPOSITORY,
            filename=item.path,
            repo_type="model",
            revision=_MODEL_REVISION,
            endpoint=_MODEL_ENDPOINT,
        )
        expected_url = (
            f"{_MODEL_ENDPOINT}/{_MODEL_REPOSITORY}/resolve/{_MODEL_REVISION}/{item.path}"
        )
        if url != expected_url:
            raise ValueError
        outbound = request.Request(
            url,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "repoguard/0.1.0",
            },
            method="GET",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_descriptor = os.open(temporary, flags, 0o600)
        timeout = min(
            _NETWORK_OPERATION_TIMEOUT_SECONDS,
            _remaining_seconds(deadline),
        )
        digest = hashlib.sha256()
        total = 0
        with (
            os.fdopen(file_descriptor, "wb", closefd=True) as output,
            opener.open(outbound, timeout=timeout) as response,
        ):
            file_descriptor = None
            if response.getcode() != 200:
                raise OSError
            while True:
                block = response.read(min(_DOWNLOAD_READ_BYTES, item.size - total + 1))
                _check_deadline(deadline)
                if not block:
                    break
                total += len(block)
                if total > item.size:
                    raise ValueError
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if total != item.size or digest.hexdigest() != item.sha256:
            raise ValueError
        os.replace(temporary, destination)
        _verify_model_file(destination, item, deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        code = (
            RetrievalErrorCode.DEADLINE_EXCEEDED
            if _monotonic() >= deadline
            else RetrievalErrorCode.MODEL_UNAVAILABLE
        )
        failure = _error(code, RetrievalStage.EMBED)
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
    if failure is not None:
        raise failure from None


def _select_device(requested: EmbeddingDevice, deadline: float) -> EmbeddingDevice:
    failure: RetrievalError | None = None
    available: tuple[str, ...] = ()
    try:
        _check_deadline(deadline)
        available = _available_onnx_providers()
        _check_deadline(deadline)
        if (
            not available
            or any(type(provider) is not str or not provider for provider in available)
            or "CPUExecutionProvider" not in available
        ):
            raise RuntimeError
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None:
        raise failure from None

    if requested is EmbeddingDevice.AUTO:
        return EmbeddingDevice.CUDA if "CUDAExecutionProvider" in available else EmbeddingDevice.CPU
    if requested is EmbeddingDevice.CUDA and "CUDAExecutionProvider" not in available:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED) from None
    return requested


def _available_onnx_providers() -> tuple[str, ...]:
    return tuple(ort.get_available_providers())


def _preflight_cuda_provider(device: EmbeddingDevice, deadline: float) -> None:
    if device is not EmbeddingDevice.CUDA:
        return
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        package_file = ort.__file__
        if type(package_file) is not str:
            raise ValueError
        library = Path(package_file).resolve(strict=True).parent / (
            "capi/libonnxruntime_providers_cuda.so"
        )
        details = library.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ValueError
        mode = getattr(os, "RTLD_LOCAL", 0) | getattr(os, "RTLD_NOW", 0)
        handle = ctypes.CDLL(str(library), mode=mode)
        _check_deadline(deadline)
        del handle
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None:
        raise failure from None


def _load_tokenizer(model_dir: Path, deadline: float) -> Tokenizer:
    tokenizer: Tokenizer | None = None
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None or tokenizer is None:
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        ) from None
    return tokenizer


def _load_fastembed(
    model_dir: Path,
    cache_dir: Path,
    device: EmbeddingDevice,
    deadline: float,
) -> TextEmbedding:
    embedding: TextEmbedding | None = None
    failure: RetrievalError | None = None
    provider_name = (
        "CUDAExecutionProvider" if device is EmbeddingDevice.CUDA else "CPUExecutionProvider"
    )
    try:
        _check_deadline(deadline)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            embedding = TextEmbedding(
                model_name=_MODEL,
                cache_dir=str(cache_dir),
                providers=[provider_name],
                lazy_load=False,
                specific_model_path=str(model_dir),
                local_files_only=True,
            )
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None or embedding is None:
        _release_embedding(embedding)
        raise (
            failure
            if failure is not None
            else _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
        ) from None
    return embedding


def _verify_actual_provider(
    embedding: TextEmbedding,
    selected: EmbeddingDevice,
    deadline: float,
) -> None:
    failure: RetrievalError | None = None
    try:
        _check_deadline(deadline)
        inner = cast(_OnnxTextEmbedding, cast(object, embedding.model))
        session = inner.model
        if session is None:
            raise RuntimeError
        providers = tuple(session.get_providers())
        expected = (
            "CUDAExecutionProvider" if selected is EmbeddingDevice.CUDA else "CPUExecutionProvider"
        )
        if not providers or providers[0] != expected:
            raise RuntimeError
        if selected is EmbeddingDevice.CPU and "CUDAExecutionProvider" in providers:
            raise RuntimeError
        _check_deadline(deadline)
    except RetrievalError as error:
        failure = _detached_error(error)
    except Exception:
        failure = _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
    if failure is not None:
        raise failure from None


def _run_embedding(
    call: Callable[[], Iterable[NumpyArray]],
    texts: tuple[str, ...],
    *,
    stage: RetrievalStage,
) -> tuple[tuple[float, ...], ...]:
    failure: RetrievalError | None = None
    result: tuple[tuple[float, ...], ...] | None = None
    try:
        if type(texts) is not tuple or any(type(text) is not str for text in texts):
            raise TypeError
        for text in texts:
            text.encode("utf-8", errors="strict")
        if not texts:
            return ()
        vectors = tuple(call())
        if len(vectors) != len(texts):
            raise ValueError
        converted: list[tuple[float, ...]] = []
        for vector in vectors:
            with np.errstate(all="ignore"):
                array = np.asarray(vector, dtype=np.float32)
                if (
                    array.shape != (_MODEL_DIMENSION,)
                    or not bool(np.isfinite(array).all())
                    or not math.isclose(
                        float(np.linalg.vector_norm(array)),
                        1.0,
                        rel_tol=0.0,
                        abs_tol=_NORMALIZATION_ABSOLUTE_TOLERANCE,
                    )
                ):
                    raise ValueError
            converted.append(tuple(float(value) for value in array))
        result = tuple(converted)
    except Exception:
        failure = _error(RetrievalErrorCode.EMBEDDING_FAILED, stage)
    if failure is not None or result is None:
        raise (
            failure if failure is not None else _error(RetrievalErrorCode.EMBEDDING_FAILED, stage)
        ) from None
    return result


def _live_state(
    provider: FastEmbedProvider,
    stage: RetrievalStage,
) -> _FastEmbedState:
    backend = provider._backend
    if not isinstance(backend, _FastEmbedState) or backend.closed:
        raise _error(RetrievalErrorCode.MODEL_UNAVAILABLE, stage) from None
    return backend


def _release_embedding(embedding: TextEmbedding | None) -> None:
    if embedding is None:
        return
    try:
        inner = cast(_OnnxTextEmbedding, cast(object, embedding.model))
        inner.model = None
        inner.tokenizer = None
        outer = cast(_TextEmbeddingOwner, cast(object, embedding))
        outer.model = None
    except Exception:
        pass


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - _monotonic()
    if remaining <= 0:
        raise _error(RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalStage.EMBED) from None
    return remaining


def _check_deadline(deadline: float) -> None:
    if _monotonic() >= deadline:
        raise _error(RetrievalErrorCode.DEADLINE_EXCEEDED, RetrievalStage.EMBED) from None


def _error(code: RetrievalErrorCode, stage: RetrievalStage) -> RetrievalError:
    return RetrievalError(code, stage, RetrievalChannel.VECTOR)


def _detached_error(error: RetrievalError) -> RetrievalError:
    if (
        type(error.code) is RetrievalErrorCode
        and type(error.stage) is RetrievalStage
        and (error.channel is None or type(error.channel) is RetrievalChannel)
    ):
        return RetrievalError(error.code, error.stage, error.channel)
    return _error(RetrievalErrorCode.MODEL_UNAVAILABLE, RetrievalStage.EMBED)
