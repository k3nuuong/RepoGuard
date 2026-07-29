"""Git and backend integration tests for M4 context retrieval."""

from __future__ import annotations

import hashlib
import math
import re
import subprocess
from pathlib import Path

import pytest

import repoguard._retrieval as retrieval_impl
from repoguard.evidence import (
    EvidenceBundle,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.retrieval import (
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
    build_context_index,
    retrieve_context,
)

_MODEL = "BAAI/bge-small-en-v1.5"
_TOKEN = re.compile(r"\S+")


class _FakeEmbeddingProvider:
    def __init__(self) -> None:
        self.closed = False
        self.close_count = 0

    @property
    def name(self) -> str:
        return "deterministic-fake"

    @property
    def model(self) -> str:
        return _MODEL

    @property
    def dimension(self) -> int:
        return 384

    @property
    def actual_device(self) -> EmbeddingDevice:
        return EmbeddingDevice.CPU

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        return ((0, 0), *(match.span() for match in _TOKEN.finditer(text)), (0, 0))

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple(_fake_vector(text) for text in texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple(_fake_vector(text) for text in texts)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.close_count += 1


class _FailingEmbeddingProvider(_FakeEmbeddingProvider):
    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        del texts
        try:
            raise ValueError("SENSITIVE_PROVIDER_DETAIL")
        except ValueError as error:
            raise RetrievalError(
                RetrievalErrorCode.BACKEND_FAILED,
                RetrievalStage.CLOSE,
                RetrievalChannel.VECTOR,
            ) from error


def _fake_vector(text: str) -> tuple[float, ...]:
    values = [0.0] * 384
    for token in re.findall(r"[^\W_]+", text.casefold()):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        values[int.from_bytes(digest[:2], "big") % len(values)] += 1.0
    if not any(values):
        values[0] = 1.0
    norm = math.sqrt(sum(value * value for value in values))
    return tuple(value / norm for value in values)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="")


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(
        root,
        "-c",
        "user.name=RepoGuard Test",
        "-c",
        "user.email=repoguard@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, EvidenceBundle]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root / "seed.txt", "seed\n")
    _write(
        root / "src" / "helper.py",
        "def committed_helper_marker(value: int) -> int:\n    return value + 1\n",
    )
    _write(
        root / "secrets" / "key.pem",
        "metadata\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "ULTRA_SECRET_VALUE_DO_NOT_COPY\n"
        "-----END PRIVATE KEY-----\n",
    )
    _write(
        root / "secrets" / "config.py",
        "# -----BEGIN PRIVATE KEY-----\n"
        "leaked_identifier = 'SENSITIVE_SYMBOL_VALUE'\n"
        "# -----END PRIVATE KEY-----\n\n"
        "def public_identifier() -> int:\n"
        "    return 1\n",
    )
    base_oid = _commit(root, "base")

    _write(
        root / "src" / "changed.py",
        "from .helper import committed_helper_marker\n\n"
        "def calculate(value: int) -> int:\n"
        "    return committed_helper_marker(value)\n",
    )
    _write(root / "src" / "broken.py", "def syntax_error(:\n    pass\n")
    _write(root / "empty.txt", "")
    (root / "binary.dat").write_bytes(b"\x00\xffopaque")
    (root / "helper-link").symlink_to("src/helper.py")
    head_oid = _commit(root, "head")
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    return root, bundle


def test_index_reads_exact_committed_head_and_retrieves_unchanged_context(
    tmp_path: Path,
) -> None:
    root, bundle = _repository(tmp_path)
    _write(
        root / "src" / "helper.py",
        "DIRTY_WORKTREE_VALUE_SHOULD_NEVER_APPEAR\n",
    )
    _write(root / "untracked.py", "UNTRACKED_VALUE_SHOULD_NEVER_APPEAR\n")
    provider = _FakeEmbeddingProvider()

    with build_context_index(bundle, embedding_provider=provider) as index:
        result = retrieve_context(index, ContextQuery("committed_helper_marker"))

        assert index.identity.repository_root == root.resolve()
        assert index.identity.head_oid == bundle.revisions.head_oid
        assert index.statistics.eligible_file_count == 7
        assert index.statistics.excluded_file_count == 2
        assert index.statistics.unparsed_python_file_count == 1
        assert index.statistics.chunk_count >= 6
        assert result.selected_count == len(result.hits)
        assert result.candidate_count == result.selected_count + result.omitted_count
        assert any(
            hit.chunk.provenance.path == "src/helper.py"
            and "committed_helper_marker" in hit.chunk.content
            for hit in result.hits
        )
        all_content = "\n".join(hit.chunk.content for hit in result.hits)
        assert "DIRTY_WORKTREE_VALUE_SHOULD_NEVER_APPEAR" not in all_content
        assert "UNTRACKED_VALUE_SHOULD_NEVER_APPEAR" not in all_content
        helper_oid = _git(root, "rev-parse", f"{bundle.revisions.head_oid}:src/helper.py")
        assert any(
            hit.chunk.provenance.path == "src/helper.py" and hit.chunk.provenance.oid == helper_oid
            for hit in result.hits
        )

    assert provider.closed
    assert provider.close_count == 1


def test_successful_corpus_read_closes_all_git_batch_pipes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle = _repository(tmp_path)
    processes: list[subprocess.Popen[bytes]] = []
    original = retrieval_impl._start_cat_file

    def record_process(root: Path) -> subprocess.Popen[bytes]:
        process = original(root)
        processes.append(process)
        return process

    monkeypatch.setattr(retrieval_impl, "_start_cat_file", record_process)

    with build_context_index(
        bundle,
        embedding_provider=_FakeEmbeddingProvider(),
        config=ContextIndexConfig(channels=(RetrievalChannel.TEXT,)),
    ):
        pass

    assert len(processes) == 1
    process = processes[0]
    streams = (process.stdin, process.stdout, process.stderr)
    for stream in streams:
        assert stream is not None
        assert stream.closed


def test_whole_corpus_private_key_ranges_are_redacted_before_results(
    tmp_path: Path,
) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FakeEmbeddingProvider()

    with build_context_index(bundle, embedding_provider=provider) as index:
        result = retrieve_context(index, ContextQuery("PRIVATE KEY"))

    secret_hits = [hit for hit in result.hits if hit.chunk.provenance.path == "secrets/key.pem"]
    assert secret_hits
    assert any("[REDACTED_PRIVATE_KEY_MATERIAL]" in hit.chunk.content for hit in secret_hits)
    assert all("ULTRA_SECRET_VALUE_DO_NOT_COPY" not in hit.chunk.content for hit in result.hits)
    assert any(hit.chunk.redacted_line_ranges == ((2, 4),) for hit in secret_hits)


def test_redacted_python_lines_do_not_leak_symbol_metadata(tmp_path: Path) -> None:
    _, bundle = _repository(tmp_path)

    with build_context_index(
        bundle,
        embedding_provider=_FakeEmbeddingProvider(),
        config=ContextIndexConfig(channels=(RetrievalChannel.SYMBOL,)),
    ) as index:
        secret = retrieve_context(index, ContextQuery("leaked_identifier"))
        public = retrieve_context(index, ContextQuery("public_identifier"))

    assert secret.hits == ()
    assert public.hits
    assert all(
        "leaked_identifier" not in hit.chunk.definitions
        and "leaked_identifier" not in hit.chunk.references
        for hit in public.hits
    )


@pytest.mark.parametrize(
    "channels",
    [
        (RetrievalChannel.TEXT,),
        (RetrievalChannel.VECTOR,),
        (RetrievalChannel.SYMBOL,),
        (
            RetrievalChannel.TEXT,
            RetrievalChannel.VECTOR,
            RetrievalChannel.SYMBOL,
        ),
    ],
)
def test_each_configured_channel_builds_and_returns_only_its_own_ranks(
    tmp_path: Path,
    channels: tuple[RetrievalChannel, ...],
) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FakeEmbeddingProvider()

    with build_context_index(
        bundle,
        embedding_provider=provider,
        config=ContextIndexConfig(channels=channels),
    ) as index:
        result = retrieve_context(index, ContextQuery("committed_helper_marker"))

    assert result.hits
    for hit in result.hits:
        assert set(hit.channels).issubset(channels)
        assert (hit.text_rank is not None) is (RetrievalChannel.TEXT in hit.channels)
        assert (hit.vector_rank is not None) is (RetrievalChannel.VECTOR in hit.channels)
        assert (hit.symbol_rank is not None) is (RetrievalChannel.SYMBOL in hit.channels)


def test_include_and_exclude_globs_are_case_sensitive_and_exclude_wins(
    tmp_path: Path,
) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FakeEmbeddingProvider()
    config = ContextIndexConfig(
        channels=(RetrievalChannel.TEXT,),
        include_globs=("src/*.py",),
        exclude_globs=("src/broken.py",),
    )

    with build_context_index(bundle, embedding_provider=provider, config=config) as index:
        result = retrieve_context(index, ContextQuery("committed_helper_marker"))

        assert index.statistics.eligible_file_count == 2
        assert index.statistics.unparsed_python_file_count == 0
        assert {hit.chunk.provenance.path for hit in result.hits} == {
            "src/helper.py",
            "src/changed.py",
        }


def test_closed_index_rejects_queries_with_stable_detached_error(tmp_path: Path) -> None:
    _, bundle = _repository(tmp_path)
    index = build_context_index(bundle, embedding_provider=_FakeEmbeddingProvider())
    index.close()
    index.close()

    with pytest.raises(RetrievalError) as caught:
        retrieve_context(index, ContextQuery("helper"))

    assert caught.value.code is RetrievalErrorCode.INDEX_CLOSED
    assert caught.value.stage is RetrievalStage.VALIDATE
    assert caught.value.channel is None
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_provider_cannot_be_owned_by_two_live_indexes(tmp_path: Path) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FakeEmbeddingProvider()
    first = build_context_index(bundle, embedding_provider=provider)
    try:
        with pytest.raises(RetrievalError) as caught:
            build_context_index(bundle, embedding_provider=provider)
        assert caught.value.code is RetrievalErrorCode.INVALID_CONFIGURATION
        assert caught.value.stage is RetrievalStage.VALIDATE
        assert not provider.closed
    finally:
        first.close()


def test_provider_cannot_be_rebound_after_its_first_index_closes(tmp_path: Path) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FakeEmbeddingProvider()
    first = build_context_index(bundle, embedding_provider=provider)
    first.close()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(bundle, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.INVALID_CONFIGURATION
    assert caught.value.stage is RetrievalStage.VALIDATE
    assert provider.closed


def test_custom_provider_failures_are_mapped_and_detached(tmp_path: Path) -> None:
    _, bundle = _repository(tmp_path)
    provider = _FailingEmbeddingProvider()

    with pytest.raises(RetrievalError) as caught:
        build_context_index(bundle, embedding_provider=provider)

    assert caught.value.code is RetrievalErrorCode.EMBEDDING_FAILED
    assert caught.value.stage is RetrievalStage.EMBED
    assert caught.value.channel is RetrievalChannel.VECTOR
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "SENSITIVE_PROVIDER_DETAIL" not in str(caught.value)
    assert provider.closed


def test_invalid_query_is_rejected_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle = _repository(tmp_path)

    def fail_digest(_: object) -> str:
        raise AssertionError("invalid query reached hashing")

    with build_context_index(
        bundle,
        embedding_provider=_FakeEmbeddingProvider(),
        config=ContextIndexConfig(channels=(RetrievalChannel.TEXT,)),
    ) as index:
        monkeypatch.setattr(retrieval_impl, "_validated_query_digest", fail_digest)
        with pytest.raises(RetrievalError) as caught:
            retrieve_context(index, ContextQuery("line\nbreak"))

    assert caught.value.code is RetrievalErrorCode.QUERY_LIMIT_EXCEEDED
    assert caught.value.stage is RetrievalStage.VALIDATE


@pytest.mark.parametrize(
    "query",
    [
        ContextQuery(""),
        ContextQuery("line\nbreak"),
        ContextQuery("x" * 4_097),
        ContextQuery("é" * 2_049),
        ContextQuery("\ud800"),
        ContextQuery(" ".join(f"token{number}" for number in range(383))),
    ],
)
def test_query_limits_fail_before_any_result(
    tmp_path: Path,
    query: ContextQuery,
) -> None:
    _, bundle = _repository(tmp_path)
    with (
        build_context_index(
            bundle,
            embedding_provider=_FakeEmbeddingProvider(),
            config=ContextIndexConfig(channels=(RetrievalChannel.TEXT,)),
        ) as index,
        pytest.raises(RetrievalError) as caught,
    ):
        retrieve_context(index, query)

    assert caught.value.code is RetrievalErrorCode.QUERY_LIMIT_EXCEEDED
    assert caught.value.stage is RetrievalStage.VALIDATE
