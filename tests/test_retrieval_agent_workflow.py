"""Workflow tests for Agent review with hybrid context."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Never, cast

import pytest
from langchain_core.globals import get_debug, set_debug
from langchain_core.tracers.context import collect_runs

import repoguard._agent as base_agent_impl
import repoguard._retrieval as retrieval_impl
import repoguard._retrieval_agent as retrieval_agent_impl
from repoguard.agent import AgentReviewConfig
from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    FileChangeEvidence,
    FileVersion,
    PullRequestInput,
    RepositoryEvidence,
    RepositoryInput,
    RevisionEvidence,
    collect_evidence,
)
from repoguard.providers import (
    LLMRequest,
    LLMResponse,
    ProviderError,
    ProviderErrorCode,
)
from repoguard.retrieval import (
    ChunkProvenance,
    ContextChunk,
    ContextIndex,
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    EmbeddingProvider,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
    build_context_index,
)
from repoguard.retrieval_agent import (
    RetrievalAgentNode,
    RetrievalAgentReviewConfig,
    RetrievalAgentReviewError,
    RetrievalAgentReviewErrorCode,
    review_with_retrieval,
)
from repoguard.review import EvidenceSide, review_evidence

_EMPTY_RESPONSE = '{"schema_version":1,"findings":[]}'
_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class _FakeEmbeddingProvider:
    name = "fake-embedding"
    model = _MODEL
    dimension = 384
    actual_device = EmbeddingDevice.CPU

    def __init__(self) -> None:
        self.tokenized_texts: list[str] = []

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        self.tokenized_texts.append(text)
        return tuple(match.span() for match in re.finditer(r"\S+", text))

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple((1.0, *([0.0] * 383)) for _ in texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return self.embed_documents(texts)

    def close(self) -> None:
        pass


class _CapturingLLMProvider:
    name = "fake-llm"

    def __init__(self, output_text: str = _EMPTY_RESPONSE) -> None:
        self.requests: list[LLMRequest] = []
        self.output_text = output_text

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return LLMResponse(output_text=self.output_text)


def _line(
    kind: DiffLineKind,
    content: str,
    *,
    old: int | None,
    new: int | None,
) -> DiffLineEvidence:
    return DiffLineEvidence(
        kind=kind,
        old_line_number=old,
        new_line_number=new,
        content=content,
        has_trailing_newline=True,
    )


def _bundle(root: Path, *, head_oid: str = "b" * 40) -> EvidenceBundle:
    lines = (
        _line(DiffLineKind.DELETION, "result = old_value", old=1, new=None),
        _line(
            DiffLineKind.ADDITION,
            "-----BEGIN PRIVATE KEY-----",
            old=None,
            new=1,
        ),
        _line(
            DiffLineKind.ADDITION,
            "SUPERSECRETIDENTIFIER",
            old=None,
            new=2,
        ),
        _line(
            DiffLineKind.ADDITION,
            "-----END PRIVATE KEY-----",
            old=None,
            new=3,
        ),
        _line(
            DiffLineKind.ADDITION,
            'result = helper("STRINGSECRET")  # COMMENTSECRET',
            old=None,
            new=4,
        ),
    )
    return EvidenceBundle(
        repository=RepositoryEvidence(root=root, object_format="sha1"),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid="a" * 40,
            head_oid=head_oid,
            merge_base_oid="a" * 40,
        ),
        changes=(
            FileChangeEvidence(
                change_type=ChangeType.MODIFIED,
                rename_similarity=None,
                old=FileVersion(
                    path="src/changed.py",
                    mode="100644",
                    oid="c" * 40,
                    content_kind=ContentKind.TEXT,
                ),
                new=FileVersion(
                    path="src/changed.py",
                    mode="100644",
                    oid="d" * 40,
                    content_kind=ContentKind.TEXT,
                ),
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=1,
                        new_start=1,
                        new_count=4,
                        lines=lines,
                    ),
                ),
            ),
        ),
    )


def _two_hunk_string_bundle(root: Path, body: str) -> EvidenceBundle:
    bundle = _bundle(root)
    return replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=1,
                        new_start=1,
                        new_count=2,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                'payload = """',
                                old=1,
                                new=1,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "intro prose",
                                old=None,
                                new=2,
                            ),
                        ),
                    ),
                    DiffHunkEvidence(
                        old_start=10,
                        old_count=2,
                        new_start=11,
                        new_count=3,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                "existing docstring prose",
                                old=10,
                                new=11,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                body,
                                old=None,
                                new=12,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "more docstring prose",
                                old=11,
                                new=13,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def _metadata_chunk(
    *,
    path: str = "src/changed.py",
    oid: str = "d" * 40,
    definitions: tuple[str, ...] = (),
    references: tuple[str, ...] = ("result", "helper"),
    start_line: int = 1,
    end_line: int = 4,
) -> ContextChunk:
    return ContextChunk(
        provenance=ChunkProvenance(
            chunk_id=hashlib.sha256(path.encode("utf-8")).hexdigest(),
            path=path,
            oid=oid,
            start_byte=0,
            end_byte=1,
            start_line=start_line,
            end_line=end_line,
        ),
        content="x",
        redacted_line_ranges=(),
        definitions=definitions,
        references=references,
    )


def _index(
    root: Path,
    *,
    head_oid: str = "b" * 40,
    query_timeout_seconds: float = 10.0,
    python_line_terms: (dict[tuple[str, int], retrieval_impl._PythonLineTerms] | None) = None,
) -> ContextIndex:
    provider = _FakeEmbeddingProvider()
    config = ContextIndexConfig(
        channels=(RetrievalChannel.TEXT,),
        query_timeout_seconds=query_timeout_seconds,
    )
    statistics = IndexStatistics(
        eligible_file_count=1,
        excluded_file_count=2,
        unparsed_python_file_count=0,
        chunk_count=1,
        original_blob_bytes=24,
        redacted_chunk_bytes=24,
        metadata_bytes=12,
        dense_matrix_bytes=0,
        logical_index_bytes=60,
    )
    identity = IndexIdentity(
        repository_root=root,
        object_format="sha1",
        head_oid=head_oid,
        channels=config.channels,
        config_sha256=retrieval_impl._config_sha256(config),
        model=_MODEL,
        model_revision=_MODEL_REVISION,
        manifest_sha256=retrieval_impl._model_identity(provider)[2],
        dimension=384,
        actual_device=EmbeddingDevice.CPU,
    )
    state = retrieval_impl._IndexState(
        identity=identity,
        statistics=statistics,
        config=config,
        chunks=(_metadata_chunk(),),
        provider=provider,
        sqlite=None,
        faiss=None,
        symbol_definitions={},
        symbol_references={},
        python_line_terms={} if python_line_terms is None else python_line_terms,
    )
    return ContextIndex(state)


def _hit() -> RetrievalHit:
    return RetrievalHit(
        chunk=ContextChunk(
            provenance=ChunkProvenance(
                chunk_id="e" * 64,
                path="src/helper.py",
                oid="f" * 40,
                start_byte=0,
                end_byte=27,
                start_line=1,
                end_line=2,
            ),
            content="def helper():\n    return 1\n",
            redacted_line_ranges=(),
            definitions=("helper",),
            references=(),
        ),
        channels=(RetrievalChannel.TEXT,),
        text_rank=1,
        vector_rank=None,
        symbol_rank=None,
        matched_query_count=2,
        rrf_score=32_786_884,
    )


def _successful_retrieval(
    index: ContextIndex,
    captured: list[tuple[str, ...]],
) -> Callable[..., RetrievalResult]:
    def retrieve(
        actual_index: ContextIndex,
        queries: tuple[ContextQuery, ...],
        *,
        deadline: float | None = None,
    ) -> RetrievalResult:
        assert actual_index is index
        assert deadline is not None
        texts = tuple(cast_query.text for cast_query in queries)
        captured.append(texts)
        return RetrievalResult(
            index=index.identity,
            query_sha256=hashlib.sha256(b"batch").hexdigest(),
            candidate_count=1,
            selected_count=1,
            omitted_count=0,
            hits=(_hit(),),
        )

    return retrieve


def test_retrieval_workflow_uses_safe_queries_and_returns_content_free_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root)
    captured_queries: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, captured_queries),
    )
    provider = _CapturingLLMProvider()

    result = review_with_retrieval(
        bundle,
        index=index,
        provider=provider,
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="fake-model"),
        ),
    )

    query_text = " ".join(captured_queries[0])
    assert "helper" in query_text
    assert "old_value" in query_text
    assert "SUPERSECRETIDENTIFIER" not in query_text
    assert "STRINGSECRET" not in query_text
    assert "COMMENTSECRET" not in query_text
    assert result.prompt.version == "v2"
    assert result.retrieval.query_count == 2
    assert result.retrieval.candidate_count == 1
    assert result.retrieval.selected_count == 1
    assert result.retrieval.omitted_count == 0
    assert result.retrieval.chunks[0].provenance.path == "src/helper.py"
    assert result.findings[0].rule_id.value == "private_key_material"
    user_data = json.loads(provider.requests[0].messages[1].content)
    assert user_data["retrieved_context"][0]["content"] == _hit().chunk.content
    index.close()


def test_uncertain_hunk_content_never_reaches_embedding_query_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")

    def run(body: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        index = _index(root)
        index_state = retrieval_impl._validated_state(index)
        embedding_provider = index_state._provider
        assert isinstance(embedding_provider, _FakeEmbeddingProvider)
        captured_queries: list[tuple[str, ...]] = []
        monkeypatch.setattr(
            retrieval_impl,
            "_retrieve_context_queries",
            _successful_retrieval(index, captured_queries),
        )

        review_with_retrieval(
            _two_hunk_string_bundle(root, body),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

        queries = captured_queries[0]
        tokenized = tuple(embedding_provider.tokenized_texts)
        index.close()
        return queries, tokenized

    first_queries, first_tokenized = run("result")
    second_queries, second_tokenized = run("DIFFERENTSTRINGPROSE")

    assert first_queries == second_queries
    assert first_tokenized == second_tokenized
    assert first_queries == ("src changed py",)
    assert all("result" not in text for text in first_tokenized)
    assert all("DIFFERENTSTRINGPROSE" not in text for text in second_tokenized)


def test_real_index_line_metadata_keeps_docstring_collisions_out_of_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_retrieve = retrieval_impl._retrieve_context_queries

    def run(body: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        root = (tmp_path / body).resolve()
        root.mkdir()
        _git(root, "init", "-q")
        _git(root, "config", "user.email", "retrieval-agent@example.com")
        _git(root, "config", "user.name", "Retrieval Agent Test")
        docstring_lines = tuple(
            "old prose" if line_number == 6 else f"stable prose {line_number}"
            for line_number in range(12)
        )

        def source(lines: tuple[str, ...]) -> str:
            docstring = "\n".join(f"    {line}" for line in lines)
            return (
                "def real_result() -> int:\n"
                "    result = 1\n"
                "    return result\n\n"
                "def caller() -> int:\n"
                '    payload = """\n'
                f"{docstring}\n"
                '    """\n'
                "    return real_result()\n"
            )

        (root / "caller.py").write_text(source(docstring_lines), encoding="utf-8")
        _git(root, "add", "caller.py")
        _git(root, "commit", "-qm", "base")
        base = _git(root, "rev-parse", "HEAD")
        head_lines = tuple(body if line == "old prose" else line for line in docstring_lines)
        (root / "caller.py").write_text(source(head_lines), encoding="utf-8")
        _git(root, "add", "caller.py")
        _git(root, "commit", "-qm", "head")
        head = _git(root, "rev-parse", "HEAD")
        bundle = collect_evidence(
            RepositoryInput(root),
            PullRequestInput(base, head),
        )
        embedding_provider = _FakeEmbeddingProvider()
        captured_queries: list[tuple[str, ...]] = []

        def capture_queries(
            index: ContextIndex,
            queries: tuple[ContextQuery, ...],
            *,
            deadline: float | None = None,
        ) -> RetrievalResult:
            captured_queries.append(tuple(query.text for query in queries))
            return original_retrieve(index, queries, deadline=deadline)

        monkeypatch.setattr(
            retrieval_impl,
            "_retrieve_context_queries",
            capture_queries,
        )
        with build_context_index(
            bundle,
            embedding_provider=embedding_provider,
            config=ContextIndexConfig(
                channels=(RetrievalChannel.TEXT, RetrievalChannel.SYMBOL),
            ),
        ) as index:
            embedding_provider.tokenized_texts.clear()
            review_with_retrieval(
                bundle,
                index=index,
                provider=_CapturingLLMProvider(),
                config=RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(model="fake-model"),
                ),
            )
            tokenized_queries = tuple(embedding_provider.tokenized_texts)

        assert bundle.changes[0].hunks[0].new_start > 1
        return captured_queries[0], tokenized_queries

    first_queries, first_tokenized = run("result")
    second_queries, second_tokenized = run("DIFFERENTSTRINGPROSE")

    assert first_queries == second_queries
    assert first_tokenized == second_tokenized
    assert all("result" not in query.split() for query in first_queries)
    assert all("result" not in text.split() for text in first_tokenized)
    assert all("DIFFERENTSTRINGPROSE" not in query for query in second_queries)
    assert all("DIFFERENTSTRINGPROSE" not in text for text in second_tokenized)


def test_head_line_metadata_recovers_safe_later_hunk_terms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    later_change = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=10,
                        old_count=1,
                        new_start=10,
                        new_count=1,
                        lines=(
                            _line(
                                DiffLineKind.DELETION,
                                "obsolete_api()",
                                old=10,
                                new=None,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "result = helper()",
                                old=None,
                                new=10,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    index = _index(
        root,
        python_line_terms={
            ("src/changed.py", 10): retrieval_impl._PythonLineTerms(
                identifiers=("result", "helper"),
                enclosing_symbol="outer",
            )
        },
    )
    captured_queries: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, captured_queries),
    )

    review_with_retrieval(
        later_change,
        index=index,
        provider=_CapturingLLMProvider(),
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="fake-model"),
        ),
    )

    query_terms = captured_queries[0][0].split()
    assert query_terms == ["src", "changed", "py", "helper", "outer", "result"]
    assert "obsolete_api" not in query_terms
    index.close()


def test_retrieval_workflow_runs_against_the_real_in_memory_core(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repository").resolve()
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "retrieval-agent@example.com")
    _git(root, "config", "user.name", "Retrieval Agent Test")
    (root / "helper.py").write_text(
        "def stable_helper(value: int) -> int:\n    return value + 1\n",
        encoding="utf-8",
    )
    preamble = "".join(f"# stable preamble {line}\n" for line in range(12))
    (root / "caller.py").write_text(
        f"{preamble}\ndef caller() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "caller.py").write_text(
        (
            f"{preamble}\nfrom helper import stable_helper\n\n"
            "def caller() -> int:\n    return stable_helper(2)\n"
        ),
        encoding="utf-8",
    )
    _git(root, "add", "caller.py")
    _git(root, "commit", "-qm", "head")
    head = _git(root, "rev-parse", "HEAD")
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base, head),
    )
    provider = _CapturingLLMProvider()
    captured_queries: list[tuple[str, ...]] = []
    original_retrieve = retrieval_impl._retrieve_context_queries

    def capture_queries(
        index: ContextIndex,
        queries: tuple[ContextQuery, ...],
        *,
        deadline: float | None = None,
    ) -> RetrievalResult:
        captured_queries.append(tuple(query.text for query in queries))
        return original_retrieve(index, queries, deadline=deadline)

    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        capture_queries,
    )

    with build_context_index(
        bundle,
        embedding_provider=_FakeEmbeddingProvider(),
        config=ContextIndexConfig(
            channels=(RetrievalChannel.TEXT, RetrievalChannel.SYMBOL),
        ),
    ) as index:
        result = review_with_retrieval(
            bundle,
            index=index,
            provider=provider,
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    user_data = json.loads(provider.requests[0].messages[1].content)
    retrieved_paths = {item["provenance"]["path"] for item in user_data["retrieved_context"]}
    assert bundle.changes[0].hunks[0].new_start > 1
    assert "stable_helper" in captured_queries[0][0].split()
    assert result.retrieval.query_count == 1
    assert result.retrieval.selected_count > 0
    assert "helper.py" in retrieved_paths


def test_prompt_omission_is_reflected_in_retrieval_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root)
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )
    provider = _CapturingLLMProvider()

    result = review_with_retrieval(
        bundle,
        index=index,
        provider=provider,
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="fake-model"),
            max_retrieved_prompt_bytes=1,
        ),
    )

    assert result.retrieval.candidate_count == 1
    assert result.retrieval.selected_count == 0
    assert result.retrieval.omitted_count == 1
    assert result.retrieval.chunks == ()
    assert _hit().chunk.content not in provider.requests[0].messages[1].content
    index.close()


def test_retrieved_content_cannot_escape_through_tracing_or_global_debug(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root)
    secret = "RETRIEVED-CONTEXT-MUST-NOT-ESCAPE"
    hit = replace(
        _hit(),
        chunk=replace(
            _hit().chunk,
            content=f"def helper():\n    return {secret!r}\n",
        ),
    )

    def retrieve(
        actual_index: ContextIndex,
        queries: tuple[ContextQuery, ...],
        *,
        deadline: float | None = None,
    ) -> RetrievalResult:
        assert actual_index is index
        assert queries
        assert deadline is not None
        return RetrievalResult(
            index=index.identity,
            query_sha256=hashlib.sha256(b"batch").hexdigest(),
            candidate_count=1,
            selected_count=1,
            omitted_count=0,
            hits=(hit,),
        )

    monkeypatch.setattr(retrieval_impl, "_retrieve_context_queries", retrieve)
    provider = _CapturingLLMProvider()
    previous_debug = get_debug()
    set_debug(True)
    try:
        with collect_runs() as runs:
            result = review_with_retrieval(
                bundle,
                index=index,
                provider=provider,
                config=RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(model="fake-model"),
                ),
            )
        assert get_debug() is True
    finally:
        set_debug(previous_debug)

    captured = capsys.readouterr()
    user_data = json.loads(provider.requests[0].messages[1].content)
    assert user_data["retrieved_context"][0]["content"] == hit.chunk.content
    assert result.retrieval.selected_count == 1
    assert result.findings[0].rule_id.value == "private_key_material"
    assert runs.traced_runs == []
    assert secret not in captured.out
    assert secret not in captured.err
    assert captured.out == ""
    assert captured.err == ""
    index.close()


def test_model_cannot_cite_a_retrieved_only_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root)
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )
    output = json.dumps(
        {
            "schema_version": 1,
            "findings": [
                {
                    "category": "correctness",
                    "severity": "medium",
                    "title": "Retrieved-only target",
                    "message": "This target is not changed evidence.",
                    "remediation": "Cite a changed hunk.",
                    "references": [
                        {
                            "path": "src/helper.py",
                            "side": "new",
                            "start_line": 1,
                            "end_line": 1,
                        }
                    ],
                }
            ],
        },
        separators=(",", ":"),
    )
    provider = _CapturingLLMProvider(output)

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            bundle,
            index=index,
            provider=provider,
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    user_data = json.loads(provider.requests[0].messages[1].content)
    assert user_data["retrieved_context"][0]["provenance"]["path"] == "src/helper.py"
    changed_paths = {
        version["path"]
        for change in user_data["changes"]
        for version in (change["old"], change["new"])
        if version is not None
    }
    assert "src/helper.py" not in changed_paths
    assert exc_info.value.code is RetrievalAgentReviewErrorCode.INVALID_MODEL_OUTPUT
    assert exc_info.value.node is RetrievalAgentNode.PARSE_RESPONSE
    assert exc_info.value.attempt_count == 1
    index.close()


def test_index_identity_mismatch_fails_before_retrieval() -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root, head_oid="9" * 40)

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            bundle,
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.INVALID_INDEX
    assert exc_info.value.node is RetrievalAgentNode.VALIDATE
    assert exc_info.value.attempt_count == 0
    index.close()


def test_retrieval_failure_retains_only_the_stable_core_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    index = _index(root)

    def fail_retrieval(*_: object, **__: object) -> Never:
        raise RetrievalError(
            RetrievalErrorCode.EMBEDDING_FAILED,
            RetrievalStage.QUERY_VECTOR,
            RetrievalChannel.VECTOR,
        )

    monkeypatch.setattr(retrieval_impl, "_retrieve_context_queries", fail_retrieval)

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            bundle,
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
    assert exc_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert exc_info.value.retrieval_code is RetrievalErrorCode.EMBEDDING_FAILED
    assert str(exc_info.value) == "context retrieval failed"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    index.close()


def test_retrieval_workflow_rejects_non_lowering_configuration() -> None:
    root = Path("/work/repository")
    index = _index(root)

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
                max_queries=257,
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.INVALID_CONFIGURATION
    assert exc_info.value.node is RetrievalAgentNode.VALIDATE

    with pytest.raises(RetrievalAgentReviewError) as agent_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=replace(
                RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(model="fake-model"),
                ),
                agent=object(),  # type: ignore[arg-type]
            ),
        )
    assert agent_info.value.code is RetrievalAgentReviewErrorCode.INVALID_CONFIGURATION

    with pytest.raises(RetrievalAgentReviewError) as evidence_info:
        review_with_retrieval(
            object(),  # type: ignore[arg-type]
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert evidence_info.value.code is RetrievalAgentReviewErrorCode.INVALID_EVIDENCE

    with pytest.raises(RetrievalAgentReviewError) as config_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=object(),  # type: ignore[arg-type]
        )
    assert config_info.value.code is RetrievalAgentReviewErrorCode.INVALID_CONFIGURATION
    index.close()


def test_shared_provider_failure_is_mapped_to_the_retrieval_agent_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )

    class _FailingProvider:
        name = "failing"

        def complete(self, request: LLMRequest) -> LLMResponse:
            del request
            raise ProviderError(ProviderErrorCode.AUTHENTICATION_FAILED)

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_FailingProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.PROVIDER_AUTHENTICATION_FAILED
    assert exc_info.value.node is RetrievalAgentNode.INVOKE_PROVIDER
    assert exc_info.value.attempt_count == 1
    index.close()


def test_provider_retries_do_not_repeat_retrieval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    captured_queries: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, captured_queries),
    )
    delays: list[float] = []
    monkeypatch.setattr(base_agent_impl, "_sleep", delays.append)

    class _RetryingProvider:
        name = "retrying"

        def __init__(self) -> None:
            self.requests: list[LLMRequest] = []
            self.outcomes: list[LLMResponse | ProviderError] = [
                ProviderError(ProviderErrorCode.RATE_LIMITED),
                ProviderError(ProviderErrorCode.TIMEOUT),
                LLMResponse(output_text=_EMPTY_RESPONSE),
            ]

        def complete(self, request: LLMRequest) -> LLMResponse:
            self.requests.append(request)
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, ProviderError):
                raise outcome
            return outcome

    provider = _RetryingProvider()
    result = review_with_retrieval(
        _bundle(root),
        index=index,
        provider=provider,
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="fake-model"),
        ),
    )

    assert result.attempt_count == 3
    assert len(provider.requests) == 3
    assert len(captured_queries) == 1
    assert delays == [0.5, 1.0]
    assert all(request.timeout_seconds <= 30.0 for request in provider.requests)
    index.close()


def test_complete_changed_evidence_must_fit_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    provider = _CapturingLLMProvider()
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=provider,
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(
                    model="fake-model",
                    max_prompt_bytes=1,
                ),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.CONTEXT_LIMIT_EXCEEDED
    assert exc_info.value.node is RetrievalAgentNode.BUILD_PROMPT
    assert provider.requests == []
    index.close()


def test_prompt_projection_failures_are_mapped_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    provider = _CapturingLLMProvider()
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )

    def fail_invalid_projection(*_: object, **__: object) -> Never:
        raise ValueError("SENSITIVE-INVALID-PROJECTION")

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_render_retrieval_prompt",
        fail_invalid_projection,
    )
    with pytest.raises(RetrievalAgentReviewError) as invalid_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=provider,
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert invalid_info.value.code is RetrievalAgentReviewErrorCode.INVALID_EVIDENCE
    assert invalid_info.value.node is RetrievalAgentNode.BUILD_PROMPT
    assert "SENSITIVE" not in str(invalid_info.value)
    assert invalid_info.value.__cause__ is None
    assert provider.requests == []

    def fail_unexpected_projection(*_: object, **__: object) -> Never:
        raise RuntimeError("SENSITIVE-UNEXPECTED-PROJECTION")

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_render_retrieval_prompt",
        fail_unexpected_projection,
    )
    with pytest.raises(RetrievalAgentReviewError) as unexpected_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=provider,
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert unexpected_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert unexpected_info.value.node is RetrievalAgentNode.BUILD_PROMPT
    assert "SENSITIVE" not in str(unexpected_info.value)
    assert unexpected_info.value.__cause__ is None
    assert provider.requests == []
    index.close()


def test_finalize_failure_does_not_publish_a_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        _successful_retrieval(index, []),
    )

    def fail_summary(*_: object, **__: object) -> Never:
        raise RuntimeError("SENSITIVE-SUMMARY-FAILURE")

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_retrieval_summary",
        fail_summary,
    )
    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert exc_info.value.node is RetrievalAgentNode.FINALIZE
    assert exc_info.value.attempt_count == 1
    assert "SENSITIVE" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    index.close()


def test_total_deadline_can_expire_before_retrieval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    moments = iter((0.0, 96.0))
    monkeypatch.setattr(
        base_agent_impl,
        "_monotonic",
        lambda: next(moments),
    )

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED
    assert exc_info.value.node is RetrievalAgentNode.VALIDATE
    assert exc_info.value.attempt_count == 0
    index.close()


def test_total_deadline_expiry_discards_a_completed_retrieval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    now = [0.0]
    captured_queries: list[tuple[str, ...]] = []
    successful_retrieval = _successful_retrieval(index, captured_queries)
    original_validate_provider = retrieval_impl._validate_initialized_provider

    def validate_provider_after_elapsed_time(
        provider: EmbeddingProvider,
    ) -> tuple[str, EmbeddingDevice]:
        result = original_validate_provider(provider)
        now[0] = 94.0
        return result

    def retrieve_then_expire(
        actual_index: ContextIndex,
        queries: tuple[ContextQuery, ...],
        *,
        deadline: float | None = None,
    ) -> RetrievalResult:
        result = successful_retrieval(
            actual_index,
            queries,
            deadline=deadline,
        )
        now[0] = 96.0
        return result

    monkeypatch.setattr(
        retrieval_impl,
        "_retrieve_context_queries",
        retrieve_then_expire,
    )
    monkeypatch.setattr(
        retrieval_impl,
        "_validate_initialized_provider",
        validate_provider_after_elapsed_time,
    )
    monkeypatch.setattr(
        base_agent_impl,
        "_monotonic",
        lambda: now[0],
    )

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED
    assert exc_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert exc_info.value.attempt_count == 0
    assert captured_queries
    index.close()


def test_index_closed_after_validation_is_rejected_before_querying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    original_build = retrieval_agent_impl._build_retrieval_graph

    def build_then_close(**kwargs: object) -> object:
        graph = original_build(**kwargs)  # type: ignore[arg-type]
        index.close()
        return graph

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_build_retrieval_graph",
        build_then_close,
    )

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.INVALID_INDEX
    assert exc_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert exc_info.value.attempt_count == 0


def test_retrieval_lock_contention_obeys_the_query_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root, query_timeout_seconds=0.05)
    state = retrieval_impl._validated_state(index)
    locked = threading.Event()
    release = threading.Event()
    threads: list[threading.Thread] = []

    def hold_lock() -> None:
        with state._lock:
            locked.set()
            release.wait(timeout=2)

    original_build = retrieval_agent_impl._build_retrieval_graph

    def build_after_lock(**kwargs: object) -> object:
        graph = original_build(**kwargs)  # type: ignore[arg-type]
        thread = threading.Thread(target=hold_lock)
        threads.append(thread)
        thread.start()
        assert locked.wait(timeout=1)
        return graph

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_build_retrieval_graph",
        build_after_lock,
    )
    started = time.monotonic()
    try:
        with pytest.raises(RetrievalAgentReviewError) as exc_info:
            review_with_retrieval(
                _bundle(root),
                index=index,
                provider=_CapturingLLMProvider(),
                config=RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(model="fake-model"),
                ),
            )
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=1)

    elapsed = time.monotonic() - started
    assert exc_info.value.code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
    assert exc_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert exc_info.value.retrieval_code is RetrievalErrorCode.DEADLINE_EXCEEDED
    assert elapsed < 0.5
    index.close()


def test_index_prevalidation_lock_contention_obeys_the_query_deadline() -> None:
    root = Path("/work/repository")
    index = _index(root, query_timeout_seconds=0.02)
    state = retrieval_impl._validated_state(index)
    locked = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with state._lock:
            locked.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold_lock)
    thread.start()
    assert locked.wait(timeout=1)
    started = time.monotonic()
    try:
        with pytest.raises(RetrievalAgentReviewError) as exc_info:
            review_with_retrieval(
                _bundle(root),
                index=index,
                provider=_CapturingLLMProvider(),
                config=RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(model="fake-model"),
                ),
            )
    finally:
        release.set()
        thread.join(timeout=1)

    elapsed = time.monotonic() - started
    assert exc_info.value.code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
    assert exc_info.value.node is RetrievalAgentNode.VALIDATE
    assert exc_info.value.attempt_count == 0
    assert exc_info.value.retrieval_code is RetrievalErrorCode.DEADLINE_EXCEEDED
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert elapsed < 0.5
    index.close()


def test_index_prevalidation_lock_contention_obeys_the_total_deadline() -> None:
    root = Path("/work/repository")
    index = _index(root, query_timeout_seconds=1.0)
    state = retrieval_impl._validated_state(index)
    locked = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with state._lock:
            locked.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold_lock)
    thread.start()
    assert locked.wait(timeout=1)
    started = time.monotonic()
    try:
        with pytest.raises(RetrievalAgentReviewError) as exc_info:
            review_with_retrieval(
                _bundle(root),
                index=index,
                provider=_CapturingLLMProvider(),
                config=RetrievalAgentReviewConfig(
                    agent=AgentReviewConfig(
                        model="fake-model",
                        total_timeout_seconds=0.02,
                    ),
                ),
            )
    finally:
        release.set()
        thread.join(timeout=1)

    elapsed = time.monotonic() - started
    assert exc_info.value.code is RetrievalAgentReviewErrorCode.BUDGET_EXCEEDED
    assert exc_info.value.node is RetrievalAgentNode.VALIDATE
    assert exc_info.value.attempt_count == 0
    assert exc_info.value.retrieval_code is None
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert elapsed < 0.5
    index.close()


def test_zero_query_derivation_still_obeys_the_query_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root, query_timeout_seconds=0.02)

    def slow_empty_seeds(*_: object, **__: object) -> tuple[object, ...]:
        time.sleep(0.05)
        return ()

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_automatic_query_seeds",
        slow_empty_seeds,
    )

    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            replace(_bundle(root), changes=()),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )

    assert exc_info.value.code is RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED
    assert exc_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert exc_info.value.retrieval_code is RetrievalErrorCode.DEADLINE_EXCEEDED
    index.close()


def test_empty_evidence_uses_no_queries_and_still_returns_a_complete_summary() -> None:
    root = Path("/work/repository")
    bundle = replace(_bundle(root), changes=())
    index = _index(root)

    result = review_with_retrieval(
        bundle,
        index=index,
        provider=_CapturingLLMProvider(),
        config=RetrievalAgentReviewConfig(
            agent=AgentReviewConfig(model="fake-model"),
        ),
    )

    assert result.retrieval.query_count == 0
    assert result.retrieval.candidate_count == 0
    assert result.retrieval.chunks == ()
    index.close()


def test_unexpected_graph_build_and_forged_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    original_build = retrieval_agent_impl._build_retrieval_graph

    def fail_build(**_: object) -> Never:
        raise RuntimeError("SENSITIVE-GRAPH-FAILURE")

    monkeypatch.setattr(retrieval_agent_impl, "_build_retrieval_graph", fail_build)
    with pytest.raises(RetrievalAgentReviewError) as exc_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert exc_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert "SENSITIVE" not in str(exc_info.value)

    forged = RetrievalAgentReviewError(
        RetrievalAgentReviewErrorCode.INVALID_INDEX,
        RetrievalAgentNode.VALIDATE,
        0,
    )
    forged.code = RetrievalAgentReviewErrorCode.RETRIEVAL_FAILED

    def raise_forged(**_: object) -> Never:
        raise forged

    monkeypatch.setattr(retrieval_agent_impl, "_build_retrieval_graph", raise_forged)
    with pytest.raises(RetrievalAgentReviewError) as forged_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert forged_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert forged_info.value.retrieval_code is None

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_build_retrieval_graph",
        original_build,
    )
    monkeypatch.setattr(
        base_agent_impl,
        "_invoke_graph_without_tracing",
        lambda *_: None,
    )
    with pytest.raises(RetrievalAgentReviewError) as missing_state_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert missing_state_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert missing_state_info.value.node is RetrievalAgentNode.FINALIZE
    assert missing_state_info.value.attempt_count == 0

    monkeypatch.setattr(
        base_agent_impl,
        "_invoke_graph_without_tracing",
        lambda *_: {"result": object(), "attempt_count": -1},
    )
    with pytest.raises(RetrievalAgentReviewError) as forged_state_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert forged_state_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert forged_state_info.value.node is RetrievalAgentNode.FINALIZE
    assert forged_state_info.value.attempt_count == 0
    index.close()


def test_unexpected_validation_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    original_validate = base_agent_impl._validate_context_evidence

    def fail_evidence_validation(*_: object, **__: object) -> Never:
        raise RuntimeError("SENSITIVE-EVIDENCE-VALIDATION")

    monkeypatch.setattr(
        base_agent_impl,
        "_validate_context_evidence",
        fail_evidence_validation,
    )
    with pytest.raises(RetrievalAgentReviewError) as evidence_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert evidence_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert evidence_info.value.node is RetrievalAgentNode.VALIDATE
    assert "SENSITIVE" not in str(evidence_info.value)
    assert evidence_info.value.__cause__ is None

    monkeypatch.setattr(
        base_agent_impl,
        "_validate_context_evidence",
        original_validate,
    )

    def fail_index_validation(*_: object, **__: object) -> Never:
        raise RuntimeError("SENSITIVE-INDEX-VALIDATION")

    monkeypatch.setattr(retrieval_impl, "_validated_state", fail_index_validation)
    with pytest.raises(RetrievalAgentReviewError) as index_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert index_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert index_info.value.node is RetrievalAgentNode.VALIDATE
    assert "SENSITIVE" not in str(index_info.value)
    assert index_info.value.__cause__ is None
    index.close()


def test_unexpected_and_forged_retrieval_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/work/repository")
    index = _index(root)
    original_seeds = retrieval_agent_impl._automatic_query_seeds

    def fail_query_derivation(*_: object, **__: object) -> Never:
        raise RuntimeError("SENSITIVE-QUERY-DERIVATION")

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_automatic_query_seeds",
        fail_query_derivation,
    )
    with pytest.raises(RetrievalAgentReviewError) as unexpected_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert unexpected_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert unexpected_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert "SENSITIVE" not in str(unexpected_info.value)
    assert unexpected_info.value.__cause__ is None

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_automatic_query_seeds",
        original_seeds,
    )
    forged = RetrievalError(
        RetrievalErrorCode.BACKEND_FAILED,
        RetrievalStage.FUSE,
    )
    forged.code = cast(RetrievalErrorCode, "forged")

    def raise_forged(*_: object, **__: object) -> Never:
        raise forged

    monkeypatch.setattr(
        retrieval_agent_impl,
        "_automatic_query_seeds",
        raise_forged,
    )
    with pytest.raises(RetrievalAgentReviewError) as forged_info:
        review_with_retrieval(
            _bundle(root),
            index=index,
            provider=_CapturingLLMProvider(),
            config=RetrievalAgentReviewConfig(
                agent=AgentReviewConfig(model="fake-model"),
            ),
        )
    assert forged_info.value.code is RetrievalAgentReviewErrorCode.WORKFLOW_EXECUTION_FAILED
    assert forged_info.value.node is RetrievalAgentNode.RETRIEVE_CONTEXT
    assert forged_info.value.retrieval_code is None
    assert forged_info.value.__cause__ is None
    index.close()


def test_automatic_query_helpers_are_bounded_deduplicated_and_fail_closed() -> None:
    embedding_provider = _FakeEmbeddingProvider()
    seeds = (
        retrieval_agent_impl._QuerySeed(sort_key=(0,), terms=("too-long",)),
        retrieval_agent_impl._QuerySeed(sort_key=(1,), terms=("overflow",)),
        retrieval_agent_impl._QuerySeed(sort_key=(2,), terms=("safe",)),
        retrieval_agent_impl._QuerySeed(sort_key=(3,), terms=("safe",)),
        retrieval_agent_impl._QuerySeed(sort_key=(4,), terms=("second",)),
    )

    def spans(
        provider: EmbeddingProvider,
        text: str,
        *,
        deadline: float,
        stage: RetrievalStage,
    ) -> tuple[tuple[int, int], ...]:
        assert provider is embedding_provider
        assert deadline > 0
        assert stage is RetrievalStage.VALIDATE
        if text == "overflow":
            return tuple((0, 0) for _ in range(385))
        return ((0, len(text)),)

    queries = retrieval_agent_impl._queries_from_seeds(
        seeds,
        provider=embedding_provider,
        max_queries=2,
        max_bytes=6,
        deadline=time.monotonic() + 10,
        token_spans=spans,
    )

    assert tuple(query.text for query in queries) == ("safe", "second")
    assert (
        retrieval_agent_impl._safe_python_hunk_identifiers(
            (),
            deadline=time.monotonic() + 10,
        )
        == ()
    )
    assert retrieval_agent_impl._safe_python_hunk_identifiers(
        ('"""unterminated',),
        deadline=time.monotonic() + 10,
    ) == ((),)
    long_identifier = "x" * 129
    assert retrieval_agent_impl._unique_terms(((long_identifier,),)) == (long_identifier,)
    long_query = retrieval_agent_impl._queries_from_seeds(
        (
            retrieval_agent_impl._QuerySeed(
                sort_key=(0,),
                terms=(long_identifier,),
            ),
        ),
        provider=embedding_provider,
        max_queries=1,
        max_bytes=2_048,
        deadline=time.monotonic() + 10,
        token_spans=spans,
    )
    assert long_query == (ContextQuery(text=long_identifier),)
    token_limited_query = retrieval_agent_impl._queries_from_seeds(
        (
            retrieval_agent_impl._QuerySeed(
                sort_key=(0,),
                terms=("overflow",),
            ),
        ),
        provider=embedding_provider,
        max_queries=1,
        max_bytes=8,
        deadline=time.monotonic() + 10,
        token_spans=spans,
    )
    assert token_limited_query == ()
    with pytest.raises(RetrievalError) as exc_info:
        retrieval_agent_impl._queries_from_seeds(
            seeds,
            provider=embedding_provider,
            max_queries=2,
            max_bytes=6,
            deadline=time.monotonic() - 1,
            token_spans=spans,
        )
    assert exc_info.value.code is RetrievalErrorCode.DEADLINE_EXCEEDED
    with pytest.raises(RuntimeError):
        retrieval_agent_impl._extension(
            {"extension": None}  # type: ignore[typeddict-item]
        )


def test_python_query_parsing_checks_deadline_after_native_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    line_moments = iter((0.0, 2.0))
    monkeypatch.setattr(
        "repoguard._retrieval_agent.time.monotonic",
        lambda: next(line_moments),
    )
    with pytest.raises(RetrievalError) as line_info:
        retrieval_agent_impl._is_syntactic_python_line(
            "value = helper()",
            deadline=1.0,
        )
    assert line_info.value.code is RetrievalErrorCode.DEADLINE_EXCEEDED

    hunk_moments = iter((0.0, 2.0))
    monkeypatch.setattr(
        "repoguard._retrieval_agent.time.monotonic",
        lambda: next(hunk_moments),
    )
    with pytest.raises(RetrievalError) as hunk_info:
        retrieval_agent_impl._python_hunk_enclosing_symbols(
            ("def outer():", "    return 1"),
            deadline=1.0,
        )
    assert hunk_info.value.code is RetrievalErrorCode.DEADLINE_EXCEEDED


def test_python_query_terms_track_symbols_but_reject_unsafe_lexical_content() -> None:
    assert retrieval_agent_impl._safe_python_identifiers(
        'result = helper("STRING")  # COMMENT'
    ) == ("result", "helper")
    assert retrieval_agent_impl._safe_python_identifiers('"""unterminated') == ()
    assert retrieval_agent_impl._definition_name("async def load_value():") == ("load_value")
    assert retrieval_agent_impl._definition_name("class Service:") == "Service"
    assert retrieval_agent_impl._definition_name('"""unterminated') is None
    assert retrieval_agent_impl._safe_python_hunk_identifiers(
        ("<<<<<<< ours",),
        deadline=time.monotonic() + 10,
    ) == ((),)
    assert retrieval_agent_impl._safe_python_hunk_identifiers(
        ("arbitrary source prose",),
        deadline=time.monotonic() + 10,
    ) == ((),)

    root = Path("/work/repository")
    bundle = _bundle(root)
    review = review_evidence(bundle)
    seeds = retrieval_agent_impl._automatic_query_seeds(
        bundle,
        review,
        deadline=time.monotonic() + 10,
    )

    rendered = " ".join(term for seed in seeds for term in seed.terms)
    assert "helper" in rendered
    assert "SUPERSECRETIDENTIFIER" not in rendered
    assert "STRINGSECRET" not in rendered
    assert "COMMENTSECRET" not in rendered

    context_wrapped = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=2,
                        new_start=1,
                        new_count=3,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                "-----BEGIN PRIVATE KEY-----",
                                old=1,
                                new=1,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "CONTEXTWRAPPEDSECRET",
                                old=None,
                                new=2,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "-----END PRIVATE KEY-----",
                                old=2,
                                new=3,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    context_seeds = retrieval_agent_impl._automatic_query_seeds(
        context_wrapped,
        review_evidence(context_wrapped),
        deadline=time.monotonic() + 10,
    )
    context_terms = tuple(term for seed in context_seeds for term in seed.terms)
    assert "CONTEXTWRAPPEDSECRET" not in context_terms

    multiline_string = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=2,
                        new_start=1,
                        new_count=3,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                'payload = """',
                                old=1,
                                new=1,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "MULTILINESTRINGSECRET",
                                old=None,
                                new=2,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                '"""',
                                old=2,
                                new=3,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    multiline_seeds = retrieval_agent_impl._automatic_query_seeds(
        multiline_string,
        review_evidence(multiline_string),
        deadline=time.monotonic() + 10,
    )
    multiline_terms = tuple(term for seed in multiline_seeds for term in seed.terms)
    assert "MULTILINESTRINGSECRET" not in multiline_terms

    outside_hunk_string = _two_hunk_string_bundle(root, "result")
    outside_seeds = retrieval_agent_impl._automatic_query_seeds(
        outside_hunk_string,
        review_evidence(outside_hunk_string),
        deadline=time.monotonic() + 10,
    )
    outside_terms = tuple(term for seed in outside_seeds for term in seed.terms)
    assert "result" not in outside_terms

    uncertain_code = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=10,
                        old_count=1,
                        new_start=10,
                        new_count=1,
                        lines=(
                            _line(
                                DiffLineKind.DELETION,
                                "obsolete_api()",
                                old=10,
                                new=None,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "result = helper()",
                                old=None,
                                new=10,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    uncertain_seeds = retrieval_agent_impl._automatic_query_seeds(
        uncertain_code,
        review_evidence(uncertain_code),
        deadline=time.monotonic() + 10,
    )
    uncertain_terms = tuple(term for seed in uncertain_seeds for term in seed.terms)
    assert "obsolete_api" not in uncertain_terms
    assert "result" not in uncertain_terms
    assert "helper" not in uncertain_terms


def test_changed_line_terms_use_only_ast_proven_enclosing_symbols() -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    scoped = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=3,
                        new_start=1,
                        new_count=4,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                "def outer():",
                                old=1,
                                new=1,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "    value = helper()",
                                old=None,
                                new=2,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "    return 0",
                                old=2,
                                new=3,
                            ),
                            _line(
                                DiffLineKind.DELETION,
                                "module_value = 0",
                                old=3,
                                new=None,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "module_value = changed()",
                                old=None,
                                new=4,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    terms = retrieval_agent_impl._changed_line_terms(
        scoped,
        {},
        deadline=time.monotonic() + 10,
    )

    assert terms[("src/changed.py", EvidenceSide.NEW, 2)] == retrieval_agent_impl._LineTerms(
        identifiers=("value", "helper"),
        enclosing_symbol="outer",
    )
    assert terms[("src/changed.py", EvidenceSide.NEW, 4)] == retrieval_agent_impl._LineTerms(
        identifiers=("module_value", "changed"),
        enclosing_symbol=None,
    )
    assert terms[("src/changed.py", EvidenceSide.OLD, 3)] == retrieval_agent_impl._LineTerms(
        identifiers=("module_value",),
        enclosing_symbol=None,
    )


def test_changed_old_line_terms_choose_the_innermost_nested_scope() -> None:
    root = Path("/work/repository")
    bundle = _bundle(root)
    nested = replace(
        bundle,
        changes=(
            replace(
                bundle.changes[0],
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=5,
                        new_start=1,
                        new_count=5,
                        lines=(
                            _line(
                                DiffLineKind.CONTEXT,
                                "def outer():",
                                old=1,
                                new=1,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "    def inner():",
                                old=2,
                                new=2,
                            ),
                            _line(
                                DiffLineKind.DELETION,
                                "        value = old_value()",
                                old=3,
                                new=None,
                            ),
                            _line(
                                DiffLineKind.ADDITION,
                                "        value = new_value()",
                                old=None,
                                new=3,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "        return value",
                                old=4,
                                new=4,
                            ),
                            _line(
                                DiffLineKind.CONTEXT,
                                "    return inner()",
                                old=5,
                                new=5,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    terms = retrieval_agent_impl._changed_line_terms(
        nested,
        {},
        deadline=time.monotonic() + 10,
    )

    assert terms[("src/changed.py", EvidenceSide.OLD, 3)] == retrieval_agent_impl._LineTerms(
        identifiers=("value", "old_value"),
        enclosing_symbol="inner",
    )
    assert terms[("src/changed.py", EvidenceSide.NEW, 3)] == retrieval_agent_impl._LineTerms(
        identifiers=("value", "new_value"),
        enclosing_symbol="inner",
    )


def test_query_seeds_cover_enclosing_symbols_and_ignore_non_text_content() -> None:
    root = Path("/work/repository")
    python_change = FileChangeEvidence(
        change_type=ChangeType.MODIFIED,
        rename_similarity=None,
        old=FileVersion(
            path="src/service.py",
            mode="100644",
            oid="1" * 40,
            content_kind=ContentKind.TEXT,
        ),
        new=FileVersion(
            path="src/service.py",
            mode="100644",
            oid="2" * 40,
            content_kind=ContentKind.TEXT,
        ),
        hunks=(
            DiffHunkEvidence(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=4,
                lines=(
                    _line(
                        DiffLineKind.CONTEXT,
                        "def reconcile():",
                        old=1,
                        new=1,
                    ),
                    _line(DiffLineKind.ADDITION, "<<<<<<< ours", old=None, new=2),
                    _line(DiffLineKind.ADDITION, "=======", old=None, new=3),
                    _line(DiffLineKind.ADDITION, ">>>>>>> theirs", old=None, new=4),
                ),
            ),
        ),
    )
    binary_change = FileChangeEvidence(
        change_type=ChangeType.MODIFIED,
        rename_similarity=None,
        old=FileVersion(
            path="assets/data.bin",
            mode="100644",
            oid="3" * 40,
            content_kind=ContentKind.BINARY,
        ),
        new=FileVersion(
            path="assets/data.bin",
            mode="100644",
            oid="4" * 40,
            content_kind=ContentKind.BINARY,
        ),
        hunks=(),
    )
    bundle = EvidenceBundle(
        repository=RepositoryEvidence(root=root, object_format="sha1"),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid="a" * 40,
            head_oid="b" * 40,
            merge_base_oid="a" * 40,
        ),
        changes=(python_change, binary_change),
    )

    seeds = retrieval_agent_impl._automatic_query_seeds(
        bundle,
        review_evidence(bundle),
        deadline=time.monotonic() + 10,
    )
    terms = tuple(term for seed in seeds for term in seed.terms)

    assert "reconcile" not in terms
    assert "ours" not in terms
    assert "theirs" not in terms
    assert "merge_conflict_marker" in terms
    assert "assets" in terms
