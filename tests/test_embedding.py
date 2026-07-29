from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import math
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib import request

import numpy as np
import pytest
from fastembed import TextEmbedding
from pytest import MonkeyPatch
from tokenizers import Tokenizer

import repoguard._embedding as embedding_impl
from repoguard.retrieval import (
    EmbeddingDevice,
    FastEmbedProvider,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
)


@dataclass(frozen=True)
class _Encoding:
    offsets: list[tuple[int, int]]


class _FakeTokenizer:
    def encode(self, text: str, *, add_special_tokens: bool) -> _Encoding:
        assert add_special_tokens
        return _Encoding([(0, 0), (0, len(text)), (0, 0)])


class _BadTokenizer:
    def __init__(self, offsets: list[tuple[object, object]]) -> None:
        self.offsets = offsets

    def encode(self, text: str, *, add_special_tokens: bool) -> _Encoding:
        assert add_special_tokens
        return _Encoding(cast(list[tuple[int, int]], self.offsets))


class _FakeSession:
    def __init__(self, providers: tuple[str, ...]) -> None:
        self.providers = providers

    def get_providers(self) -> list[str]:
        return list(self.providers)


class _FakeInner:
    def __init__(self, providers: tuple[str, ...]) -> None:
        self.model: _FakeSession | None = _FakeSession(providers)
        self.tokenizer: object | None = object()


class _FakeEmbedding:
    def __init__(
        self,
        providers: tuple[str, ...] = ("CPUExecutionProvider",),
        *,
        vectors: tuple[np.ndarray[tuple[int], np.dtype[np.float32]], ...] | None = None,
    ) -> None:
        self.model: _FakeInner | None = _FakeInner(providers)
        self.vectors = vectors
        self.document_calls: list[tuple[tuple[str, ...], int | None]] = []
        self.query_calls: list[tuple[tuple[str, ...], int | None]] = []

    def passage_embed(
        self,
        texts: tuple[str, ...],
        *,
        parallel: int | None,
    ) -> tuple[np.ndarray[tuple[int], np.dtype[np.float32]], ...]:
        self.document_calls.append((texts, parallel))
        return self.vectors or tuple(_unit_vector() for _ in texts)

    def query_embed(
        self,
        texts: tuple[str, ...],
        *,
        parallel: int | None,
    ) -> tuple[np.ndarray[tuple[int], np.dtype[np.float32]], ...]:
        self.query_calls.append((texts, parallel))
        return self.vectors or tuple(_unit_vector() for _ in texts)


class _FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self._body = body
        self._offset = 0
        self._status = status

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body)
        block = self._body[self._offset : self._offset + amount]
        self._offset += len(block)
        return block

    def getcode(self) -> int:
        return self._status

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        return None


class _FakeOpener:
    def __init__(self, files: dict[str, bytes], *, status: int = 200) -> None:
        self.files = files
        self.status = status
        self.requests: list[tuple[request.Request, float]] = []

    def open(
        self,
        fullurl: request.Request,
        data: bytes | None = None,
        timeout: float | object = 0.0,
    ) -> _FakeResponse:
        assert data is None
        assert type(timeout) is float
        self.requests.append((fullurl, timeout))
        name = fullurl.full_url.rsplit("/", maxsplit=1)[-1]
        return _FakeResponse(self.files[name], status=self.status)


class _HandlerOwner(Protocol):
    handlers: list[object]


class _ProxyOwner(Protocol):
    proxies: dict[str, str]


def _unit_vector() -> np.ndarray[tuple[int], np.dtype[np.float32]]:
    vector = np.zeros(384, dtype=np.float32)
    vector[0] = 1.0
    return vector


def _manifest() -> tuple[embedding_impl._ModelManifest, dict[str, bytes]]:
    payloads = {
        name: f"fixed:{name}".encode() for name in sorted(embedding_impl._EXPECTED_MODEL_FILES)
    }
    files = tuple(
        embedding_impl._ManifestFile(
            path=name,
            size=len(payloads[name]),
            sha256=hashlib.sha256(payloads[name]).hexdigest(),
        )
        for name in sorted(payloads)
    )
    return embedding_impl._ModelManifest(files=files, sha256="d" * 64), payloads


def _install_model(cache: Path, payloads: dict[str, bytes]) -> Path:
    model_dir = cache / embedding_impl._CACHE_NAMESPACE / "model"
    model_dir.mkdir(parents=True)
    for name, payload in payloads.items():
        (model_dir / name).write_bytes(payload)
    return model_dir


def _patch_model_load(
    monkeypatch: MonkeyPatch,
    manifest: embedding_impl._ModelManifest,
    fake: _FakeEmbedding,
    *,
    available: tuple[str, ...] = ("CPUExecutionProvider",),
) -> None:
    monkeypatch.setattr(embedding_impl, "_load_manifest", lambda deadline: manifest)
    monkeypatch.setattr(
        embedding_impl,
        "_load_tokenizer",
        lambda model_dir, deadline: cast(Tokenizer, _FakeTokenizer()),
    )
    monkeypatch.setattr(
        embedding_impl,
        "_load_fastembed",
        lambda model_dir, cache_dir, device, deadline: cast(TextEmbedding, fake),
    )
    monkeypatch.setattr(embedding_impl, "_available_onnx_providers", lambda: available)
    monkeypatch.setattr(embedding_impl, "_preflight_cuda_provider", lambda device, deadline: None)


def _initialize(
    provider: FastEmbedProvider,
    repository: Path,
) -> None:
    embedding_impl._initialize_fastembed(
        provider,
        repository_root=repository,
        deadline=time.monotonic() + 5.0,
    )


def _assert_detached(
    error: RetrievalError,
    code: RetrievalErrorCode,
    stage: RetrievalStage,
) -> None:
    assert error.code is code
    assert error.stage is stage
    assert error.channel is RetrievalChannel.VECTOR
    assert error.__cause__ is None
    assert error.__context__ is None


def test_packaged_manifest_is_strict_and_has_fixed_identity() -> None:
    manifest = embedding_impl._load_manifest(time.monotonic() + 1.0)

    assert manifest.sha256 == "7b2e75de0e055bdb3e1da2e92fa92063eb5e69277fb615723eed443aaeaedd44"
    assert tuple(item.path for item in manifest.files) == tuple(
        sorted(embedding_impl._EXPECTED_MODEL_FILES)
    )
    raw = json.loads(Path("src/repoguard/models/bge_small_en_v1_5/manifest.json").read_text())
    raw["repository"] = "attacker/model"
    with pytest.raises(ValueError):
        embedding_impl._parse_manifest(raw, "f" * 64)
    with pytest.raises(ValueError):
        json.loads('{"a":1,"a":2}', object_pairs_hook=embedding_impl._strict_json_object)


@pytest.mark.parametrize(
    "case",
    [
        "not-object",
        "root-keys",
        "schema",
        "model",
        "repository",
        "revision",
        "files-shape",
        "file-shape",
        "file-keys",
        "path",
        "duplicate",
        "size",
        "sha",
        "missing",
        "order",
    ],
)
def test_manifest_rejects_every_ambiguous_shape(case: str) -> None:
    manifest, _ = _manifest()
    value: object = {
        "schema_version": 1,
        "model": embedding_impl._MODEL,
        "repository": embedding_impl._MODEL_REPOSITORY,
        "revision": embedding_impl._MODEL_REVISION,
        "files": [
            {"path": item.path, "size": item.size, "sha256": item.sha256} for item in manifest.files
        ],
    }
    if case == "not-object":
        value = []
    else:
        root = cast(dict[str, object], value)
        files = cast(list[object], root["files"])
        first = cast(dict[str, object], files[0])
        if case == "root-keys":
            root["extra"] = True
        elif case == "schema":
            root["schema_version"] = True
        elif case == "model":
            root["model"] = "other"
        elif case == "repository":
            root["repository"] = "other"
        elif case == "revision":
            root["revision"] = "0" * 40
        elif case == "files-shape":
            root["files"] = {}
        elif case == "file-shape":
            files[0] = []
        elif case == "file-keys":
            first["extra"] = True
        elif case == "path":
            first["path"] = "../config.json"
        elif case == "duplicate":
            second = cast(dict[str, object], files[1])
            second["path"] = first["path"]
        elif case == "size":
            first["size"] = False
        elif case == "sha":
            first["sha256"] = "F" * 64
        elif case == "missing":
            files.pop()
        elif case == "order":
            files.reverse()

    with pytest.raises(ValueError):
        embedding_impl._parse_manifest(value, "a" * 64)


def test_initialize_cpu_tokenizes_embeds_and_closes(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    _install_model(cache, payloads)
    fake = _FakeEmbedding()
    _patch_model_load(monkeypatch, manifest, fake)
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CPU)

    _initialize(provider, repository)

    assert provider.actual_device is EmbeddingDevice.CPU
    assert embedding_impl._provider_model_identity(provider) == (
        embedding_impl._MODEL_REVISION,
        "d" * 64,
    )
    assert provider.token_spans("héllo") == ((0, 0), (0, 5), (0, 0))
    documents = provider.embed_documents(("one", "two"))
    queries = provider.embed_queries(("question",))
    assert len(documents) == 2
    assert len(documents[0]) == 384
    assert documents[0][0] == 1.0
    assert queries[0][0] == 1.0
    assert fake.document_calls == [(("one", "two"), None)]
    assert fake.query_calls == [(("question",), None)]
    assert provider.embed_documents(()) == ()

    provider.close()
    provider.close()
    assert fake.model is None
    with pytest.raises(RetrievalError) as raised:
        provider.embed_queries(("closed",))
    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.QUERY_VECTOR,
    )


def test_initialization_loads_only_from_verified_ephemeral_snapshot(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    cached_model = _install_model(cache, payloads)
    fake = _FakeEmbedding()
    loaded_paths: list[Path] = []
    monkeypatch.setattr(embedding_impl, "_load_manifest", lambda deadline: manifest)
    monkeypatch.setattr(
        embedding_impl, "_available_onnx_providers", lambda: ("CPUExecutionProvider",)
    )

    def load_tokenizer(model_dir: Path, deadline: float) -> Tokenizer:
        assert deadline > time.monotonic()
        (cached_model / "tokenizer.json").write_bytes(b"replaced-after-verification")
        loaded_paths.append(model_dir)
        assert (model_dir / "tokenizer.json").read_bytes() == payloads["tokenizer.json"]
        return cast(Tokenizer, _FakeTokenizer())

    def load_fastembed(
        model_dir: Path,
        cache_dir: Path,
        device: EmbeddingDevice,
        deadline: float,
    ) -> TextEmbedding:
        assert cache_dir == cache.resolve()
        assert device is EmbeddingDevice.CPU
        assert deadline > time.monotonic()
        loaded_paths.append(model_dir)
        assert (model_dir / "tokenizer.json").read_bytes() == payloads["tokenizer.json"]
        return cast(TextEmbedding, fake)

    monkeypatch.setattr(embedding_impl, "_load_tokenizer", load_tokenizer)
    monkeypatch.setattr(embedding_impl, "_load_fastembed", load_fastembed)
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CPU)

    _initialize(provider, repository)

    assert len(loaded_paths) == 2
    assert loaded_paths[0] == loaded_paths[1]
    assert loaded_paths[0] != cached_model
    assert loaded_paths[0].parent == cached_model.parent
    assert not loaded_paths[0].exists()
    assert not tuple(cached_model.parent.glob(".snapshot-*"))
    provider.close()


def test_initialization_rejects_repository_cache_before_model_activity(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    called = False

    def forbidden_manifest(deadline: float) -> embedding_impl._ModelManifest:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(embedding_impl, "_load_manifest", forbidden_manifest)
    provider = FastEmbedProvider(cache_dir=repository / ".cache")

    with pytest.raises(RetrievalError) as raised:
        _initialize(provider, repository)

    _assert_detached(
        raised.value,
        RetrievalErrorCode.INVALID_CONFIGURATION,
        RetrievalStage.VALIDATE,
    )
    assert not called
    assert not (repository / ".cache").exists()


def test_initialization_validation_rejects_malformed_private_state(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    cases: list[tuple[FastEmbedProvider, object, object]] = [
        (FastEmbedProvider(cache_dir=tmp_path / "cache-b"), repository, float("inf")),
        (FastEmbedProvider(cache_dir=tmp_path / "cache-c"), repository, 1),
        (FastEmbedProvider(cache_dir=tmp_path / "cache-d"), "repository", time.monotonic() + 1.0),
    ]
    bad_cache = FastEmbedProvider(cache_dir=tmp_path / "cache-e")
    bad_cache._cache_dir = cast(Path, "cache")
    cases.append((bad_cache, repository, time.monotonic() + 1.0))
    bad_download = FastEmbedProvider(cache_dir=tmp_path / "cache-f")
    bad_download._allow_download = cast(bool, 1)
    cases.append((bad_download, repository, time.monotonic() + 1.0))
    bad_device = FastEmbedProvider(cache_dir=tmp_path / "cache-g")
    bad_device._requested_device = cast(EmbeddingDevice, "cpu")
    cases.append((bad_device, repository, time.monotonic() + 1.0))
    bound = FastEmbedProvider(cache_dir=tmp_path / "cache-h")
    bound._backend = object()
    cases.append((bound, repository, time.monotonic() + 1.0))
    repository_file = tmp_path / "file"
    repository_file.write_text("not a directory")
    cases.append(
        (
            FastEmbedProvider(cache_dir=tmp_path / "cache-i"),
            repository_file,
            time.monotonic() + 1.0,
        )
    )

    for provider, root, deadline in cases:
        error = embedding_impl._validate_initialization(
            provider,
            cast(Path, root),
            cast(float, deadline),
        )
        assert error is not None
        assert error.code is RetrievalErrorCode.INVALID_CONFIGURATION


@pytest.mark.parametrize("corruption", ["extra", "hash", "symlink"])
def test_verified_model_tree_rejects_identity_ambiguity(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    corruption: str,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    model_dir = _install_model(cache, payloads)
    if corruption == "extra":
        (model_dir / "unexpected.json").write_text("{}")
    elif corruption == "hash":
        (model_dir / "config.json").write_bytes(b"x" * len(payloads["config.json"]))
    else:
        target = tmp_path / "outside"
        target.write_bytes(payloads["config.json"])
        (model_dir / "config.json").unlink()
        (model_dir / "config.json").symlink_to(target)
    fake = _FakeEmbedding()
    _patch_model_load(monkeypatch, manifest, fake)

    with pytest.raises(RetrievalError) as raised:
        _initialize(FastEmbedProvider(cache_dir=cache), repository)

    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )
    assert fake.model is not None


def test_missing_offline_model_and_resumable_completed_partial(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    manifest, payloads = _manifest()
    monkeypatch.setattr(embedding_impl, "_load_manifest", lambda deadline: manifest)
    offline = FastEmbedProvider(cache_dir=tmp_path / "offline")

    with pytest.raises(RetrievalError) as missing:
        _initialize(offline, repository)
    _assert_detached(
        missing.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )

    cache = tmp_path / "resumed"
    partial = cache / embedding_impl._CACHE_NAMESPACE / "partial"
    partial.mkdir(parents=True)
    for name, payload in payloads.items():
        (partial / name).write_bytes(payload)
    fake = _FakeEmbedding()
    _patch_model_load(monkeypatch, manifest, fake)
    monkeypatch.setattr(
        embedding_impl,
        "_build_url_opener",
        lambda: pytest.fail("completed partial files must not access the network"),
    )
    provider = FastEmbedProvider(
        cache_dir=cache,
        allow_download=True,
        device=EmbeddingDevice.CPU,
    )

    _initialize(provider, repository)

    assert (cache / embedding_impl._CACHE_NAMESPACE / "model").is_dir()
    assert not partial.exists()


def test_cache_model_directory_symlink_and_invalid_cache_node_are_rejected(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    manifest, payloads = _manifest()
    outside = tmp_path / "outside"
    _install_model(outside, payloads)
    cache = tmp_path / "cache"
    namespace = cache / embedding_impl._CACHE_NAMESPACE
    namespace.mkdir(parents=True)
    (namespace / "model").symlink_to(
        outside / embedding_impl._CACHE_NAMESPACE / "model",
        target_is_directory=True,
    )
    monkeypatch.setattr(embedding_impl, "_load_manifest", lambda deadline: manifest)

    with pytest.raises(RetrievalError) as model_error:
        _initialize(FastEmbedProvider(cache_dir=cache), repository)
    _assert_detached(
        model_error.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )

    invalid_cache = tmp_path / "invalid-cache"
    invalid_cache.write_text("not a directory")
    with pytest.raises(RetrievalError) as cache_error:
        _initialize(FastEmbedProvider(cache_dir=invalid_cache), repository)
    _assert_detached(
        cache_error.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )


def test_explicit_download_uses_only_fixed_anonymous_urls(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    fake_embedding = _FakeEmbedding()
    opener = _FakeOpener(payloads)
    _patch_model_load(monkeypatch, manifest, fake_embedding)
    monkeypatch.setattr(embedding_impl, "_build_url_opener", lambda: opener)

    _initialize(
        FastEmbedProvider(
            cache_dir=cache,
            allow_download=True,
            device=EmbeddingDevice.CPU,
        ),
        repository,
    )

    assert len(opener.requests) == len(payloads)
    for outbound, timeout in opener.requests:
        assert outbound.full_url.startswith(
            "https://huggingface.co/Qdrant/bge-small-en-v1.5-onnx-Q/resolve/"
            f"{embedding_impl._MODEL_REVISION}/"
        )
        assert outbound.get_header("Authorization") is None
        assert outbound.get_header("Accept-encoding") == "identity"
        assert 0 < timeout <= 30.0
    model_dir = cache / embedding_impl._CACHE_NAMESPACE / "model"
    assert {path.name for path in model_dir.iterdir()} == set(payloads)


def test_cuda_fallback_is_rejected_without_cpu_retry(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    _install_model(cache, payloads)
    fake = _FakeEmbedding(("CPUExecutionProvider",))
    _patch_model_load(
        monkeypatch,
        manifest,
        fake,
        available=("CUDAExecutionProvider", "CPUExecutionProvider"),
    )
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CUDA)

    with pytest.raises(RetrievalError) as raised:
        _initialize(provider, repository)

    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )
    assert fake.model is None
    assert not tuple((cache / embedding_impl._CACHE_NAMESPACE).glob(".snapshot-*"))
    with pytest.raises(RetrievalError):
        _initialize(provider, repository)


def test_auto_device_selection_and_unavailable_cuda_are_explicit(
    monkeypatch: MonkeyPatch,
) -> None:
    deadline = time.monotonic() + 2.0
    monkeypatch.setattr(
        embedding_impl,
        "_available_onnx_providers",
        lambda: ("CUDAExecutionProvider", "CPUExecutionProvider"),
    )
    assert embedding_impl._select_device(EmbeddingDevice.AUTO, deadline) is EmbeddingDevice.CUDA
    monkeypatch.setattr(
        embedding_impl,
        "_available_onnx_providers",
        lambda: ("CPUExecutionProvider",),
    )
    assert embedding_impl._select_device(EmbeddingDevice.AUTO, deadline) is EmbeddingDevice.CPU
    with pytest.raises(RetrievalError) as unavailable:
        embedding_impl._select_device(EmbeddingDevice.CUDA, deadline)
    _assert_detached(
        unavailable.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )
    monkeypatch.setattr(embedding_impl, "_available_onnx_providers", lambda: ())
    with pytest.raises(RetrievalError) as invalid_runtime:
        embedding_impl._select_device(EmbeddingDevice.CPU, deadline)
    _assert_detached(
        invalid_runtime.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )


def test_cuda_library_preflight_is_silent_and_secret_safe(
    monkeypatch: MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[tuple[str, int]] = []

    def fail_load(path: str, mode: int) -> object:
        calls.append((path, mode))
        raise OSError(f"SENSITIVE_ABSOLUTE_PATH:{path}")

    monkeypatch.setattr(ctypes, "CDLL", fail_load)
    caplog.set_level(logging.DEBUG)

    with pytest.raises(RetrievalError) as raised:
        embedding_impl._preflight_cuda_provider(
            EmbeddingDevice.CUDA,
            time.monotonic() + 1.0,
        )

    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )
    assert len(calls) == 1
    assert calls[0][0].endswith("/capi/libonnxruntime_providers_cuda.so")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert caplog.records == []

    monkeypatch.setattr(
        ctypes,
        "CDLL",
        lambda path, mode: pytest.fail("CPU must not preflight CUDA libraries"),
    )
    embedding_impl._preflight_cuda_provider(
        EmbeddingDevice.CPU,
        time.monotonic() + 1.0,
    )


@pytest.mark.parametrize(
    ("vectors", "method", "stage"),
    [
        (
            (np.zeros(384, dtype=np.float32),),
            "embed_documents",
            RetrievalStage.EMBED,
        ),
        (
            (np.full(384, math.nan, dtype=np.float32),),
            "embed_queries",
            RetrievalStage.QUERY_VECTOR,
        ),
        (
            (np.ones(383, dtype=np.float32),),
            "embed_documents",
            RetrievalStage.EMBED,
        ),
        (
            (_unit_vector(), _unit_vector()),
            "embed_queries",
            RetrievalStage.QUERY_VECTOR,
        ),
    ],
)
def test_embedding_output_validation_is_atomic_and_stable(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    vectors: tuple[np.ndarray[tuple[int], np.dtype[np.float32]], ...],
    method: str,
    stage: RetrievalStage,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    _install_model(cache, payloads)
    fake = _FakeEmbedding(vectors=vectors)
    _patch_model_load(monkeypatch, manifest, fake)
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CPU)
    _initialize(provider, repository)

    with pytest.raises(RetrievalError) as raised:
        getattr(provider, method)(("only-one",))

    _assert_detached(raised.value, RetrievalErrorCode.EMBEDDING_FAILED, stage)


def test_embedding_overflow_is_atomic_silent_and_preserves_numpy_error_state(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    _install_model(cache, payloads)
    hostile = np.full(384, np.finfo(np.float64).max, dtype=np.float64)
    fake = _FakeEmbedding(
        vectors=cast(tuple[np.ndarray[tuple[int], np.dtype[np.float32]], ...], (hostile,))
    )
    _patch_model_load(monkeypatch, manifest, fake)
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CPU)
    _initialize(provider, repository)
    caplog.set_level(logging.DEBUG)

    with (
        np.errstate(over="warn", invalid="raise", divide="raise", under="ignore"),
        warnings.catch_warnings(record=True) as caught_warnings,
    ):
        warnings.simplefilter("always")
        expected_error_state = np.geterr()
        with pytest.raises(RetrievalError) as raised:
            provider.embed_queries(("hostile",))
        assert np.geterr() == expected_error_state

    _assert_detached(
        raised.value,
        RetrievalErrorCode.EMBEDDING_FAILED,
        RetrievalStage.QUERY_VECTOR,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert caplog.records == []
    assert caught_warnings == []


def test_invalid_proxy_and_download_failure_are_secret_safe(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository-SENSITIVE"
    cache = tmp_path / "cache-SENSITIVE"
    repository.mkdir()
    manifest, _ = _manifest()
    monkeypatch.setattr(embedding_impl, "_load_manifest", lambda deadline: manifest)
    monkeypatch.setenv("HTTPS_PROXY", "socks5h://SENSITIVE-proxy")
    monkeypatch.delenv("https_proxy", raising=False)

    with pytest.raises(RetrievalError) as raised:
        _initialize(
            FastEmbedProvider(cache_dir=cache, allow_download=True),
            repository,
        )

    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )
    rendered = f"{raised.value!s} {raised.value!r} {capsys.readouterr()}"
    assert "SENSITIVE" not in rendered


@pytest.mark.parametrize("failure", ["status", "oversize", "hash", "open", "deadline"])
def test_download_failure_is_atomic_and_retains_only_partial_file(
    tmp_path: Path,
    failure: str,
) -> None:
    payload = b"model"
    item = embedding_impl._ManifestFile(
        path="model_optimized.onnx",
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    namespace = tmp_path / "namespace"
    destination = tmp_path / "destination"
    namespace.mkdir()
    body = payload
    status = 200
    if failure == "status":
        status = 500
    elif failure == "oversize":
        body += b"x"
    elif failure == "hash":
        body = b"x" * len(payload)

    class _ExplodingOpener:
        def open(
            self,
            fullurl: request.Request,
            data: bytes | None = None,
            timeout: float | object = 0.0,
        ) -> _FakeResponse:
            raise OSError("SENSITIVE")

    opener: object = (
        _ExplodingOpener() if failure == "open" else _FakeOpener({item.path: body}, status=status)
    )
    deadline = 0.0 if failure == "deadline" else time.monotonic() + 2.0

    with pytest.raises(RetrievalError) as raised:
        embedding_impl._download_model_file(
            opener=cast(embedding_impl._UrlOpener, opener),
            namespace=namespace,
            destination=destination,
            item=item,
            deadline=deadline,
        )

    expected = (
        RetrievalErrorCode.DEADLINE_EXCEEDED
        if failure == "deadline"
        else RetrievalErrorCode.MODEL_UNAVAILABLE
    )
    _assert_detached(raised.value, expected, RetrievalStage.EMBED)
    assert not destination.exists()


def test_proxy_opener_ignores_all_proxy_and_prefers_lowercase(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("http_proxy", "http://lower-http.invalid:8000/")
    monkeypatch.setenv("HTTP_PROXY", "http://upper-http.invalid:8000/")
    monkeypatch.setenv("https_proxy", "https://lower-https.invalid:8443/")
    monkeypatch.setenv("HTTPS_PROXY", "https://upper-https.invalid:8443/")
    monkeypatch.setenv("ALL_PROXY", "socks5h://ignored.invalid:9000/")

    opener = embedding_impl._build_url_opener()

    proxy_handler = next(
        handler
        for handler in cast(_HandlerOwner, cast(object, opener)).handlers
        if isinstance(handler, request.ProxyHandler)
    )
    assert cast(_ProxyOwner, cast(object, proxy_handler)).proxies == {
        "http": "http://lower-http.invalid:8000/",
        "https": "https://lower-https.invalid:8443/",
    }


def test_local_loader_arguments_and_failures_are_fixed(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    cache_dir = tmp_path / "cache"
    model_dir.mkdir()
    tokenizer = cast(Tokenizer, _FakeTokenizer())
    tokenizer_paths: list[str] = []

    def token_factory(path: str) -> Tokenizer:
        tokenizer_paths.append(path)
        return tokenizer

    monkeypatch.setattr(Tokenizer, "from_file", token_factory)
    assert embedding_impl._load_tokenizer(model_dir, time.monotonic() + 1.0) is tokenizer
    assert tokenizer_paths == [str(model_dir / "tokenizer.json")]

    fake = _FakeEmbedding()
    calls: list[dict[str, object]] = []

    def embedding_factory(**kwargs: object) -> TextEmbedding:
        calls.append(kwargs)
        return cast(TextEmbedding, fake)

    monkeypatch.setattr(embedding_impl, "TextEmbedding", embedding_factory)
    loaded = embedding_impl._load_fastembed(
        model_dir,
        cache_dir,
        EmbeddingDevice.CUDA,
        time.monotonic() + 1.0,
    )
    assert loaded is cast(TextEmbedding, fake)
    assert calls == [
        {
            "model_name": embedding_impl._MODEL,
            "cache_dir": str(cache_dir),
            "providers": ["CUDAExecutionProvider"],
            "lazy_load": False,
            "specific_model_path": str(model_dir),
            "local_files_only": True,
        }
    ]

    def explode(**kwargs: object) -> TextEmbedding:
        raise RuntimeError("SENSITIVE")

    monkeypatch.setattr(embedding_impl, "TextEmbedding", explode)
    with pytest.raises(RetrievalError) as raised:
        embedding_impl._load_fastembed(
            model_dir,
            cache_dir,
            EmbeddingDevice.CPU,
            time.monotonic() + 1.0,
        )
    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )


def test_tokenizer_and_provider_runtime_failures_are_stable(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cache = tmp_path / "cache"
    repository.mkdir()
    manifest, payloads = _manifest()
    _install_model(cache, payloads)
    fake = _FakeEmbedding()
    _patch_model_load(monkeypatch, manifest, fake)
    provider = FastEmbedProvider(cache_dir=cache, device=EmbeddingDevice.CPU)
    _initialize(provider, repository)
    state = cast(embedding_impl._FastEmbedState, provider._backend)

    for tokenizer, text in [
        (_BadTokenizer([(0.0, 1)]), "x"),
        (_BadTokenizer([(0, 2)]), "x"),
        (None, "x"),
    ]:
        state.tokenizer = cast(Tokenizer | None, tokenizer)
        with pytest.raises(RetrievalError) as raised:
            provider.token_spans(text)
        _assert_detached(
            raised.value,
            RetrievalErrorCode.EMBEDDING_FAILED,
            RetrievalStage.CHUNK,
        )
    state.tokenizer = cast(Tokenizer, _FakeTokenizer())
    with pytest.raises(RetrievalError):
        provider.token_spans(cast(str, b"not-text"))

    inner = cast(_FakeInner, fake.model)
    inner.model = None
    with pytest.raises(RetrievalError) as missing_session:
        embedding_impl._verify_actual_provider(
            cast(TextEmbedding, fake),
            EmbeddingDevice.CPU,
            time.monotonic() + 1.0,
        )
    _assert_detached(
        missing_session.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )


def test_unexpected_initialization_failure_and_invalid_close_are_sanitized(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    provider = FastEmbedProvider(cache_dir=tmp_path / "cache")

    def explode(deadline: float) -> embedding_impl._ModelManifest:
        raise RuntimeError("SENSITIVE")

    monkeypatch.setattr(embedding_impl, "_load_manifest", explode)
    with pytest.raises(RetrievalError) as raised:
        _initialize(provider, repository)
    _assert_detached(
        raised.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.EMBED,
    )

    invalid = FastEmbedProvider(cache_dir=tmp_path / "other-cache")
    invalid._backend = object()
    invalid._actual_device = EmbeddingDevice.CPU
    invalid.close()
    invalid.close()
    with pytest.raises(RuntimeError):
        _ = FastEmbedProvider(cache_dir=tmp_path / "new-cache").actual_device
    embedding_impl._release_embedding(cast(TextEmbedding, object()))


def test_deadline_and_uninitialized_calls_have_stable_errors(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    provider = FastEmbedProvider(cache_dir=tmp_path / "cache")

    with pytest.raises(RetrievalError) as deadline_error:
        embedding_impl._initialize_fastembed(
            provider,
            repository_root=repository,
            deadline=0.0,
        )
    _assert_detached(
        deadline_error.value,
        RetrievalErrorCode.DEADLINE_EXCEEDED,
        RetrievalStage.EMBED,
    )
    with pytest.raises(RetrievalError) as token_error:
        provider.token_spans("not-loaded")
    _assert_detached(
        token_error.value,
        RetrievalErrorCode.MODEL_UNAVAILABLE,
        RetrievalStage.CHUNK,
    )
    provider.close()
    provider.close()
    assert "CPUExecutionProvider" in embedding_impl._available_onnx_providers()
    with pytest.raises(RetrievalError):
        embedding_impl._remaining_seconds(0.0)
