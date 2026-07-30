"""Focused algorithm and Git integration tests for the private retrieval core."""

from __future__ import annotations

import hashlib
import math
import re
import shlex
import shutil
import subprocess
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from itertools import pairwise, permutations
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import repoguard._embedding as embedding_impl
import repoguard._retrieval as retrieval_impl
from repoguard._retrieval import (
    _build_chunks,
    _build_vector_index,
    _config_sha256,
    _CorpusFile,
    _fuse,
    _IndexState,
    _model_identity,
    _prepare_file,
    _rrf_contribution,
    _validate_configuration,
    _validate_initialized_provider,
    _validate_provider_shape,
    _validated_matrix,
)
from repoguard.evidence import (
    EvidenceBundle,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.retrieval import (
    ChunkProvenance,
    ContextChunk,
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    FastEmbedProvider,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
    build_context_index,
    retrieve_context,
)

_PROPERTY_SETTINGS = settings(database=None, derandomize=True, max_examples=100)
_WORD = re.compile(r"[^\W_]+", re.UNICODE)


class _FakeEmbedding:
    name = "fake-bge"
    model = "BAAI/bge-small-en-v1.5"
    dimension = 384
    actual_device = EmbeddingDevice.CPU

    def __init__(self) -> None:
        self.close_count = 0

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        return (
            (0, 0),
            *((match.start(), match.end()) for match in _WORD.finditer(text)),
            (0, 0),
        )

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple(self._embed(text) for text in texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple(self._embed(text) for text in texts)

    def close(self) -> None:
        self.close_count += 1

    @staticmethod
    def _embed(text: str) -> tuple[float, ...]:
        values = [0.0] * 384
        for match in _WORD.finditer(text):
            token = match.group(0).casefold().encode("utf-8")
            index = int.from_bytes(hashlib.sha256(token).digest()[:4], "big") % 384
            values[index] += 1.0
        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0.0:
            values[0] = 1.0
            norm = 1.0
        return tuple(value / norm for value in values)


class _BgeBoundaryEmbedding(_FakeEmbedding):
    """Model the fixed BGE wordpiece boundary that expands after slicing."""

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        spans: list[tuple[int, int]] = []
        for match in _WORD.finditer(text):
            start, end = match.span()
            if match.group(0) == "xboundary":
                spans.extend(((start, start + 1), (start + 1, end)))
            elif match.group(0) == "boundary":
                spans.extend(
                    (
                        (start, start + 1),
                        (start + 1, start + 3),
                        (start + 3, start + 5),
                        (start + 5, end),
                    )
                )
            else:
                spans.append((start, end))
        return ((0, 0), *spans, (0, 0))


class _CoordinatedEmbedding(_FakeEmbedding):
    def __init__(self, *, block_query: bool = False, block_close: bool = False) -> None:
        super().__init__()
        self.block_query = block_query
        self.block_close = block_close
        self.query_entered = Event()
        self.release_query = Event()
        self.close_entered = Event()
        self.release_close = Event()

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        self.query_entered.set()
        if self.block_query and not self.release_query.wait(timeout=2.0):
            raise RuntimeError
        return super().embed_queries(texts)

    def close(self) -> None:
        self.close_entered.set()
        if self.block_close and not self.release_close.wait(timeout=2.0):
            raise RuntimeError
        super().close()


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


@pytest.fixture
def repository_bundle(tmp_path: Path) -> tuple[Path, EvidenceBundle]:
    root = (tmp_path / "repository").resolve()
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "retrieval@example.com")
    _git(root, "config", "user.name", "Retrieval Test")
    (root / "helper.py").write_text(
        "def stable_helper(value: int) -> int:\n    return value + 1\n",
        encoding="utf-8",
    )
    (root / "caller.py").write_text(
        "from helper import stable_helper\n\ndef caller() -> int:\n    return stable_helper(1)\n",
        encoding="utf-8",
    )
    (root / "secret.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nM4_SECRET_BODY_MUST_NOT_ESCAPE\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (root / "binary.bin").write_bytes(b"prefix\0suffix")
    (root / "invalid.txt").write_bytes(b"\xff")
    (root / "link").symlink_to("helper.py")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "base")
    base = _git(root, "rev-parse", "HEAD")

    (root / "caller.py").write_text(
        "from helper import stable_helper\n\ndef caller() -> int:\n    return stable_helper(2)\n",
        encoding="utf-8",
    )
    _git(root, "add", "caller.py")
    _git(root, "commit", "-qm", "head")
    head = _git(root, "rev-parse", "HEAD")
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base, head),
    )
    return root, bundle


def test_build_reads_exact_head_and_fuses_all_channels(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    root, bundle = repository_bundle
    provider = _FakeEmbedding()
    (root / "helper.py").write_text("DIRTY_WORKTREE_MARKER\n", encoding="utf-8")

    index = build_context_index(
        bundle,
        embedding_provider=provider,
        config=ContextIndexConfig(
            channels=(
                RetrievalChannel.SYMBOL,
                RetrievalChannel.VECTOR,
                RetrievalChannel.TEXT,
            )
        ),
    )
    result = retrieve_context(index, ContextQuery("stable_helper"))

    helper_hits = [hit for hit in result.hits if hit.chunk.provenance.path == "helper.py"]
    assert helper_hits
    assert any(
        hit.channels
        == (
            RetrievalChannel.TEXT,
            RetrievalChannel.VECTOR,
            RetrievalChannel.SYMBOL,
        )
        for hit in helper_hits
    )
    assert all("DIRTY_WORKTREE_MARKER" not in hit.chunk.content for hit in result.hits)
    assert index.identity.head_oid == bundle.revisions.head_oid
    assert index.identity.channels == (
        RetrievalChannel.TEXT,
        RetrievalChannel.VECTOR,
        RetrievalChannel.SYMBOL,
    )
    assert index.statistics.eligible_file_count == 3
    assert index.statistics.excluded_file_count == 3
    index.close()
    assert provider.close_count == 1


def test_build_uses_fixed_git_and_strips_product_secrets(
    repository_bundle: tuple[Path, EvidenceBundle],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, bundle = repository_bundle
    real_git = shutil.which("git")
    assert real_git is not None
    fixed_log = tmp_path / "fixed-log"
    leaked_marker = tmp_path / "secret-leaked"
    fixed_git = tmp_path / "fixed-git"
    fixed_git.write_text(
        "#!/bin/sh\n"
        'if [ -n "${REPOGUARD_GITHUB_TOKEN+x}" ]; then\n'
        f"  printf leaked > {shlex.quote(str(leaked_marker))}\n"
        "fi\n"
        f"printf x >> {shlex.quote(str(fixed_log))}\n"
        f'exec {shlex.quote(real_git)} "$@"\n',
        encoding="ascii",
    )
    fixed_git.chmod(0o700)
    hostile_directory = tmp_path / "hostile"
    hostile_directory.mkdir()
    hostile_marker = tmp_path / "path-used"
    hostile_git = hostile_directory / "git"
    hostile_git.write_text(
        f"#!/bin/sh\nprintf used > {shlex.quote(str(hostile_marker))}\nexit 99\n",
        encoding="ascii",
    )
    hostile_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile_directory))
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "sentinel")
    monkeypatch.setenv("REPOGUARD_OPENAI_API_KEY", "sentinel")
    monkeypatch.setenv("REPOGUARD_ANTHROPIC_API_KEY", "sentinel")

    with build_context_index(
        bundle,
        embedding_provider=_FakeEmbedding(),
        git_executable=fixed_git,
    ):
        pass

    assert fixed_log.read_text(encoding="ascii")
    assert not hostile_marker.exists()
    assert not leaked_marker.exists()
    environment = retrieval_impl._git_environment()
    assert not any(name.startswith("REPOGUARD_") for name in environment)


def test_private_key_range_is_redacted_before_any_result_boundary(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    index = build_context_index(bundle, embedding_provider=_FakeEmbedding())

    result = retrieve_context(index, ContextQuery("PRIVATE KEY"))
    contents = "\n".join(hit.chunk.content for hit in result.hits)

    assert "M4_SECRET_BODY_MUST_NOT_ESCAPE" not in contents
    assert "[REDACTED_PRIVATE_KEY_MATERIAL]" in contents
    secret_hits = [hit for hit in result.hits if hit.chunk.provenance.path == "secret.pem"]
    assert secret_hits
    assert all(hit.chunk.redacted_line_ranges == ((1, 3),) for hit in secret_hits)
    index.close()


def test_lower_max_results_reports_exact_candidate_selected_and_omitted_counts(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    index = build_context_index(
        bundle,
        embedding_provider=_FakeEmbedding(),
        config=ContextIndexConfig(
            channels=(RetrievalChannel.VECTOR,),
            max_results=1,
        ),
    )

    result = retrieve_context(index, ContextQuery("stable_helper"))

    assert index.statistics.chunk_count == 4
    assert result.candidate_count == 4
    assert result.selected_count == 1
    assert result.omitted_count == 3
    assert len(result.hits) == 1
    index.close()


def test_live_provider_cannot_be_bound_twice_and_closed_index_rejects_query(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    provider = _FakeEmbedding()
    first = build_context_index(bundle, embedding_provider=provider)

    with pytest.raises(RetrievalError) as bind_error:
        build_context_index(bundle, embedding_provider=provider)
    assert bind_error.value.code is RetrievalErrorCode.INVALID_CONFIGURATION
    assert bind_error.value.stage is RetrievalStage.VALIDATE
    assert provider.close_count == 0

    first.close()
    with pytest.raises(RetrievalError) as query_error:
        retrieve_context(first, ContextQuery("stable_helper"))
    assert query_error.value.code is RetrievalErrorCode.INDEX_CLOSED
    assert query_error.value.stage is RetrievalStage.VALIDATE
    assert provider.close_count == 1


def test_standalone_query_completes_before_concurrent_close(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    provider = _CoordinatedEmbedding(block_query=True)
    index = build_context_index(
        bundle,
        embedding_provider=provider,
        config=ContextIndexConfig(channels=(RetrievalChannel.VECTOR,)),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        query_future = executor.submit(
            retrieve_context,
            index,
            ContextQuery("stable_helper"),
        )
        assert provider.query_entered.wait(timeout=1.0)
        close_future = executor.submit(index.close)
        try:
            assert not close_future.done()
        finally:
            provider.release_query.set()
        result = query_future.result(timeout=2.0)
        close_future.result(timeout=2.0)

    assert result.selected_count == len(result.hits)
    assert result.candidate_count == result.selected_count + result.omitted_count
    assert provider.close_count == 1


def test_standalone_query_observes_closed_index_during_concurrent_close(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    provider = _CoordinatedEmbedding(block_close=True)
    index = build_context_index(
        bundle,
        embedding_provider=provider,
        config=ContextIndexConfig(channels=(RetrievalChannel.VECTOR,)),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        close_future = executor.submit(index.close)
        assert provider.close_entered.wait(timeout=1.0)
        try:
            with pytest.raises(RetrievalError) as caught:
                retrieve_context(index, ContextQuery("stable_helper"))
        finally:
            provider.release_close.set()
        close_future.result(timeout=2.0)

    assert caught.value.code is RetrievalErrorCode.INDEX_CLOSED
    assert caught.value.stage is RetrievalStage.VALIDATE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert provider.close_count == 1


def test_invalid_evidence_fails_before_provider_ownership_transfer(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    provider = _FakeEmbedding()
    unsupported = replace(bundle)
    object.__setattr__(unsupported, "schema_version", 2)
    invalid_values = (
        object(),
        unsupported,
        replace(
            bundle,
            repository=replace(bundle.repository, root=Path("relative")),
        ),
        replace(
            bundle,
            revisions=replace(bundle.revisions, base_ref=""),
        ),
        replace(
            bundle,
            revisions=replace(bundle.revisions, head_oid="A" * 40),
        ),
    )

    for value in invalid_values:
        with pytest.raises(RetrievalError) as caught:
            build_context_index(value, embedding_provider=provider)  # type: ignore[arg-type]
        expected = (
            RetrievalErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA
            if isinstance(value, EvidenceBundle) and value.schema_version != 1
            else RetrievalErrorCode.INVALID_EVIDENCE
        )
        assert caught.value.code is expected
        assert caught.value.stage is RetrievalStage.VALIDATE
        assert provider.close_count == 0


def test_exclude_wins_and_empty_corpus_is_successful(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    index = build_context_index(
        bundle,
        embedding_provider=_FakeEmbedding(),
        config=ContextIndexConfig(
            include_globs=("*.py",),
            exclude_globs=("*.py",),
        ),
    )

    result = retrieve_context(index, ContextQuery("stable_helper"))

    assert index.statistics.eligible_file_count == 0
    assert index.statistics.chunk_count == 0
    assert result.candidate_count == 0
    assert result.hits == ()
    index.close()


def test_binary_is_excluded_within_budget_and_oversized_text_fails_before_body(
    repository_bundle: tuple[Path, EvidenceBundle],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle = repository_bundle
    binary_provider = _FakeEmbedding()
    index = build_context_index(
        bundle,
        embedding_provider=binary_provider,
        config=ContextIndexConfig(
            channels=(RetrievalChannel.TEXT,),
            include_globs=("binary.bin",),
        ),
    )
    assert index.statistics.eligible_file_count == 0
    assert index.statistics.excluded_file_count == 6
    index.close()

    text_provider = _FakeEmbedding()
    monkeypatch.setattr(
        retrieval_impl,
        "_read_blob_content",
        lambda *args, **kwargs: pytest.fail("oversized blob body must not be read"),
    )
    with pytest.raises(RetrievalError) as error_info:
        build_context_index(
            bundle,
            embedding_provider=text_provider,
            config=ContextIndexConfig(
                channels=(RetrievalChannel.TEXT,),
                include_globs=("helper.py",),
                max_file_bytes=1,
            ),
        )
    assert error_info.value.code is RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED
    assert error_info.value.stage is RetrievalStage.READ_CORPUS
    assert text_provider.close_count == 1


@pytest.mark.parametrize(
    ("config", "stage"),
    [
        (
            ContextIndexConfig(
                channels=(RetrievalChannel.TEXT,),
                max_files=1,
            ),
            RetrievalStage.READ_CORPUS,
        ),
        (
            ContextIndexConfig(
                channels=(RetrievalChannel.TEXT,),
                max_corpus_bytes=1,
            ),
            RetrievalStage.READ_CORPUS,
        ),
        (
            ContextIndexConfig(
                channels=(RetrievalChannel.TEXT,),
                max_chunks=1,
            ),
            RetrievalStage.CHUNK,
        ),
        (
            ContextIndexConfig(
                channels=(RetrievalChannel.TEXT,),
                max_index_bytes=1,
            ),
            RetrievalStage.CHUNK,
        ),
    ],
)
def test_corpus_chunk_and_logical_index_limits_fail_atomically(
    repository_bundle: tuple[Path, EvidenceBundle],
    config: ContextIndexConfig,
    stage: RetrievalStage,
) -> None:
    _, bundle = repository_bundle
    provider = _FakeEmbedding()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(
            bundle,
            embedding_provider=provider,
            config=config,
        )

    assert caught.value.code in {
        RetrievalErrorCode.CORPUS_LIMIT_EXCEEDED,
        RetrievalErrorCode.INDEX_LIMIT_EXCEEDED,
    }
    assert caught.value.stage is stage
    assert provider.close_count == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_missing_head_object_fails_atomically_without_fetch(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    provider = _FakeEmbedding()
    missing = replace(
        bundle,
        revisions=replace(bundle.revisions, head_oid="f" * 40),
    )

    with pytest.raises(RetrievalError) as caught:
        build_context_index(missing, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.MISSING_OBJECT
    assert caught.value.stage is RetrievalStage.READ_CORPUS
    assert provider.close_count == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_annotated_tag_oid_is_not_accepted_as_head_commit_identity(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    root, bundle = repository_bundle
    _git(root, "tag", "-a", "annotated-head", "-m", "annotated head", bundle.revisions.head_oid)
    tag_oid = _git(root, "rev-parse", "refs/tags/annotated-head")
    tagged = replace(
        bundle,
        revisions=replace(bundle.revisions, head_oid=tag_oid),
    )
    provider = _FakeEmbedding()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(tagged, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.INVALID_EVIDENCE
    assert caught.value.stage is RetrievalStage.READ_CORPUS
    assert provider.close_count == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_missing_internal_tree_is_classified_as_missing_object(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    root, bundle = repository_bundle
    tree_oid = _git(root, "rev-parse", f"{bundle.revisions.head_oid}^{{tree}}")
    tree_path = root / ".git" / "objects" / tree_oid[:2] / tree_oid[2:]
    assert tree_path.is_file()
    tree_path.unlink()
    provider = _FakeEmbedding()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(bundle, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.MISSING_OBJECT
    assert caught.value.stage is RetrievalStage.READ_CORPUS
    assert provider.close_count == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_recursive_tree_output_is_bounded_before_provider_initialization(
    repository_bundle: tuple[Path, EvidenceBundle],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle = repository_bundle
    monkeypatch.setattr(retrieval_impl, "_GIT_TREE_OUTPUT_BYTES", 1)
    provider = _FakeEmbedding()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(bundle, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.INDEX_LIMIT_EXCEEDED
    assert caught.value.stage is RetrievalStage.READ_CORPUS
    assert provider.close_count == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_configuration_validation_normalizes_and_rejects_invalid_limits() -> None:
    normalized = _validate_configuration(
        ContextIndexConfig(
            channels=(RetrievalChannel.SYMBOL, RetrievalChannel.TEXT),
            include_globs=("z/**", "a/**"),
            exclude_globs=("vendor/**",),
            build_timeout_seconds=1,
            query_timeout_seconds=2,
        )
    )

    assert normalized.channels == (RetrievalChannel.TEXT, RetrievalChannel.SYMBOL)
    assert normalized.include_globs == ("a/**", "z/**")
    assert normalized.build_timeout_seconds == 1.0
    assert normalized.query_timeout_seconds == 2.0
    assert _config_sha256(normalized) == _config_sha256(normalized)

    invalid = (
        ContextIndexConfig(channels=()),
        ContextIndexConfig(channels=(RetrievalChannel.TEXT, RetrievalChannel.TEXT)),
        ContextIndexConfig(include_globs=("",)),
        ContextIndexConfig(exclude_globs=("vendor/**", "vendor/**")),
        ContextIndexConfig(max_files=0),
        ContextIndexConfig(max_files=True),
        ContextIndexConfig(chunk_tokens=3, chunk_overlap_tokens=1),
        ContextIndexConfig(build_timeout_seconds=math.nan),
        ContextIndexConfig(query_timeout_seconds=False),
    )
    for config in invalid:
        with pytest.raises(RetrievalError) as caught:
            _validate_configuration(config)
        assert caught.value.code is RetrievalErrorCode.INVALID_CONFIGURATION
        assert caught.value.stage is RetrievalStage.VALIDATE


def test_provider_validation_rejects_malformed_protocol_values() -> None:
    valid = _FakeEmbedding()
    assert _validate_provider_shape(valid) is valid
    assert _validate_initialized_provider(valid) == ("fake-bge", EmbeddingDevice.CPU)

    malformed = (
        object(),
        SimpleNamespace(
            name="",
            model=valid.model,
            dimension=valid.dimension,
            actual_device=EmbeddingDevice.CPU,
            token_spans=valid.token_spans,
            embed_documents=valid.embed_documents,
            embed_queries=valid.embed_queries,
            close=valid.close,
        ),
        SimpleNamespace(
            name="bad\nname",
            model=valid.model,
            dimension=valid.dimension,
            actual_device=EmbeddingDevice.CPU,
            token_spans=valid.token_spans,
            embed_documents=valid.embed_documents,
            embed_queries=valid.embed_queries,
            close=valid.close,
        ),
        SimpleNamespace(
            name="fake",
            model="wrong",
            dimension=valid.dimension,
            actual_device=EmbeddingDevice.CPU,
            token_spans=valid.token_spans,
            embed_documents=valid.embed_documents,
            embed_queries=valid.embed_queries,
            close=valid.close,
        ),
        SimpleNamespace(
            name="fake",
            model=valid.model,
            dimension=valid.dimension,
            actual_device=EmbeddingDevice.CPU,
            token_spans=None,
            embed_documents=valid.embed_documents,
            embed_queries=valid.embed_queries,
            close=valid.close,
        ),
    )
    for provider in malformed:
        with pytest.raises(RetrievalError) as caught:
            _validate_provider_shape(provider)
        assert caught.value.code is RetrievalErrorCode.INVALID_CONFIGURATION

    invalid_device = _FakeEmbedding()
    invalid_device.actual_device = EmbeddingDevice.AUTO
    with pytest.raises(RetrievalError) as caught:
        _validate_initialized_provider(invalid_device)
    assert caught.value.code is RetrievalErrorCode.INVALID_CONFIGURATION


def test_fastembed_model_identity_is_fixed_and_manifest_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FastEmbedProvider(cache_dir=tmp_path / "cache")
    expected_digest = "f" * 64
    monkeypatch.setattr(
        embedding_impl,
        "_provider_model_identity",
        lambda _: ("52398278842ec682c6f32300af41344b1c0b0bb2", expected_digest),
    )

    assert _model_identity(provider) == (
        "BAAI/bge-small-en-v1.5",
        "52398278842ec682c6f32300af41344b1c0b0bb2",
        expected_digest,
        384,
    )

    monkeypatch.setattr(
        embedding_impl,
        "_provider_model_identity",
        lambda _: ("moving-revision", expected_digest),
    )
    with pytest.raises(RetrievalError) as caught:
        _model_identity(provider)
    assert caught.value.code is RetrievalErrorCode.MODEL_UNAVAILABLE
    assert caught.value.stage is RetrievalStage.EMBED


@_PROPERTY_SETTINGS
@example(nonce=0)
@given(nonce=st.integers(min_value=0, max_value=2**128 - 1))
def test_generated_paired_private_key_body_never_survives_projection(
    nonce: int,
) -> None:
    secret = f"SENSITIVE_{nonce:032x}_DO_NOT_COPY"
    content = (f"-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----\n").encode()
    prepared = _prepare_file(_CorpusFile(path="secret.pem", oid="a" * 40, content=content))

    assert prepared.redacted_ranges == ((1, 3),)
    assert secret not in prepared.projection
    assert prepared.projection.count("[REDACTED_PRIVATE_KEY_MATERIAL]") == 3
    assert prepared.content == content


def test_python_line_terms_use_full_source_lexing_and_innermost_scope() -> None:
    content = (
        b"@decorate\n"
        b"class Service:\n"
        b'    class_value = "STRING_SECRET"\n'
        b"    # COMMENT_SECRET\n"
        b"    def outer(self, safe_arg):\n"
        b"        local_value = safe_arg\n"
        b"        def inner(inner_arg):\n"
        b"            return inner_arg + local_value\n"
        b"        return inner(local_value)\n"
    )

    prepared = _prepare_file(_CorpusFile(path="service.py", oid="a" * 40, content=content))

    terms = prepared.python_line_terms
    assert terms[0].identifiers == ("decorate",)
    assert terms[0].enclosing_symbol == "Service"
    assert terms[1].identifiers == ("Service",)
    assert terms[1].enclosing_symbol == "Service"
    assert terms[2].identifiers == ("class_value",)
    assert terms[2].enclosing_symbol == "Service"
    assert terms[3].identifiers == ()
    assert terms[3].enclosing_symbol == "Service"
    assert terms[4].identifiers == ("outer", "self", "safe_arg")
    assert terms[4].enclosing_symbol == "outer"
    assert terms[6].identifiers == ("inner", "inner_arg")
    assert terms[6].enclosing_symbol == "inner"
    assert terms[7].identifiers == ("inner_arg", "local_value")
    assert terms[7].enclosing_symbol == "inner"
    assert terms[8].identifiers == ("inner", "local_value")
    assert terms[8].enclosing_symbol == "outer"
    assert all(
        "STRING_SECRET" not in line.identifiers and "COMMENT_SECRET" not in line.identifiers
        for line in terms
    )


def test_structured_embedding_document_overflow_fails_before_provider_call() -> None:
    class RecordingProvider(_FakeEmbedding):
        def __init__(self) -> None:
            super().__init__()
            self.documents_called = False

        def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
            return ((0, 0), *((index, index + 1) for index in range(len(text))), (0, 0))

        def embed_documents(
            self,
            texts: tuple[str, ...],
        ) -> tuple[tuple[float, ...], ...]:
            self.documents_called = True
            return super().embed_documents(texts)

    provider = RecordingProvider()
    chunk = ContextChunk(
        provenance=ChunkProvenance(
            chunk_id="c" * 64,
            path=f"{'long/' * 40}module.py",
            oid="a" * 40,
            start_byte=0,
            end_byte=350,
            start_line=1,
            end_line=1,
        ),
        content="x" * 350,
        redacted_line_ranges=(),
        definitions=(),
        references=(),
    )

    with pytest.raises(RetrievalError) as caught:
        _build_vector_index(
            (chunk,),
            provider=provider,
            dimension=384,
            deadline=float("inf"),
        )

    assert caught.value.code is RetrievalErrorCode.EMBEDDING_FAILED
    assert caught.value.stage is RetrievalStage.EMBED
    assert caught.value.channel is RetrievalChannel.VECTOR
    assert not provider.documents_called


@pytest.mark.parametrize("component", [1e308, 1e38])
def test_invalid_embedding_numbers_fail_without_numpy_warnings_or_output(
    component: float,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vector = (component, *(0.0 for _ in range(383)))

    with (
        warnings.catch_warnings(record=True) as caught_warnings,
        pytest.raises(RetrievalError) as caught,
    ):
        warnings.simplefilter("always")
        _validated_matrix(
            (vector,),
            expected_count=1,
            dimension=384,
            stage=RetrievalStage.EMBED,
        )

    captured = capsys.readouterr()
    assert caught.value.code is RetrievalErrorCode.EMBEDDING_FAILED
    assert caught.value.stage is RetrievalStage.EMBED
    assert caught_warnings == []
    assert captured.out == ""
    assert captured.err == ""


@_PROPERTY_SETTINGS
@given(rank=st.integers(min_value=1, max_value=31))
def test_rrf_contribution_is_positive_and_strictly_rank_monotonic(rank: int) -> None:
    assert _rrf_contribution(rank) > _rrf_contribution(rank + 1) > 0


@_PROPERTY_SETTINGS
@example(words=["a"] * 20)
@given(
    words=st.lists(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
            ),
            min_size=1,
            max_size=12,
        ),
        min_size=1,
        max_size=40,
    )
)
def test_token_windows_cover_original_bytes_and_respect_overlap(
    words: list[str],
) -> None:
    content = (" ".join(words) + "\n").encode()
    provider = _FakeEmbedding()
    chunks, unparsed, python_line_terms = _build_chunks(
        (_CorpusFile(path="generated.txt", oid="a" * 40, content=content),),
        head_oid="b" * 40,
        provider=provider,
        config=ContextIndexConfig(
            channels=(RetrievalChannel.TEXT,),
            chunk_tokens=8,
            chunk_overlap_tokens=2,
        ),
        deadline=float("inf"),
    )

    assert unparsed == 0
    assert python_line_terms == {}
    assert chunks
    covered: set[int] = set()
    for chunk in chunks:
        provenance = chunk.provenance
        covered.update(range(provenance.start_byte, provenance.end_byte))
        assert len(provider.token_spans(chunk.content)) <= 8
    assert covered == set(range(len(content)))
    for left, right in pairwise(chunks):
        assert right.provenance.start_byte <= left.provenance.end_byte


def test_context_sensitive_bge_boundary_is_refit_after_window_slicing() -> None:
    provider = _BgeBoundaryEmbedding()
    text = (
        " ".join(
            (
                *("a" for _ in range(317)),
                "xboundary",
                *("a" for _ in range(381)),
            )
        )
        + "\n"
    )
    content = text.encode()
    whole_content_spans = tuple(span for span in provider.token_spans(text) if span[0] < span[1])
    nominal_start = whole_content_spans[318][0]
    nominal_slice = text[nominal_start:]

    assert len(whole_content_spans) == 700
    assert len(whole_content_spans[318:]) == 382
    assert sum(start < end for start, end in provider.token_spans(nominal_slice)) == 385

    runs = tuple(
        _build_chunks(
            (_CorpusFile(path="boundary.txt", oid="a" * 40, content=content),),
            head_oid="b" * 40,
            provider=provider,
            config=ContextIndexConfig(channels=(RetrievalChannel.TEXT,)),
            deadline=float("inf"),
        )[0]
        for _ in range(2)
    )

    assert len(runs[0]) == 3
    assert tuple(chunk.provenance.chunk_id for chunk in runs[0]) == tuple(
        chunk.provenance.chunk_id for chunk in runs[1]
    )
    assert all(len(provider.token_spans(chunk.content)) <= 384 for chunk in runs[0])
    covered = {
        byte
        for chunk in runs[0]
        for byte in range(chunk.provenance.start_byte, chunk.provenance.end_byte)
    }
    assert covered == set(range(len(content)))


def test_fusion_is_invariant_to_aggregate_insertion_order(
    repository_bundle: tuple[Path, EvidenceBundle],
) -> None:
    _, bundle = repository_bundle
    index = build_context_index(
        bundle,
        embedding_provider=_FakeEmbedding(),
        config=ContextIndexConfig(
            channels=(RetrievalChannel.TEXT,),
            max_results=3,
        ),
    )
    state = index._state
    assert isinstance(state, _IndexState)
    assert len(state._chunks) == 4
    items = tuple(
        (
            chunk_index,
            {
                "channels": {RetrievalChannel.TEXT},
                "text_rank": 1,
                "vector_rank": None,
                "symbol_rank": None,
                "query_numbers": {0},
                "score": _rrf_contribution(1),
            },
        )
        for chunk_index in range(len(state._chunks))
    )
    baseline = _fuse(state, dict(items), float("inf"))

    assert all(
        _fuse(state, dict(permutation), float("inf")) == baseline
        for permutation in permutations(items)
    )
    index.close()
