"""Focused tests for M5 query derivation and retrieval degradation."""

from __future__ import annotations

from pathlib import Path

import pytest

import repoguard._repair_retrieval as repair_retrieval
import repoguard._retrieval as retrieval_core
from repoguard._repair_retrieval import _derive_repair_queries, _retrieve_repair_context
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
from repoguard.repair import (
    RepairContextOutcome,
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairProviderKind,
    RepairTarget,
)
from repoguard.retrieval import (
    ContextIndex,
    ContextQuery,
    EmbeddingDevice,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalResult,
    RetrievalStage,
)
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReviewResult,
    RuleId,
)

_HEAD = "1" * 40
_BLOB = "2" * 40
_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "repair-model",
    )


def _bundle_and_review() -> tuple[EvidenceBundle, ReviewResult]:
    repository = RepositoryEvidence(Path("/repository"), "sha1")
    revisions = RevisionEvidence("base", "head", "0" * 40, _HEAD, "0" * 40)
    version = FileVersion("src/app.py", "100644", _BLOB, ContentKind.TEXT)
    line = DiffLineEvidence(
        DiffLineKind.ADDITION,
        None,
        1,
        "def VulnerableThing():",
        True,
    )
    change = FileChangeEvidence(
        ChangeType.ADDED,
        None,
        None,
        version,
        (DiffHunkEvidence(0, 0, 1, 1, (line,)),),
    )
    bundle = EvidenceBundle(repository, revisions, (change,))
    finding = Finding(
        RuleId.MERGE_CONFLICT_MARKER,
        FindingCategory.CORRECTNESS,
        FindingSeverity.HIGH,
        "Resolve merge marker near VulnerableThing",
        "marker",
        "Remove the conflict marker",
        (EvidenceReference("src/app.py", EvidenceSide.NEW, _BLOB, 1, 1),),
    )
    return bundle, ReviewResult(repository, revisions, (finding,))


def _identity() -> IndexIdentity:
    return IndexIdentity(
        Path("/repository"),
        "sha1",
        _HEAD,
        (RetrievalChannel.TEXT,),
        "3" * 64,
        _MODEL,
        _MODEL_REVISION,
        "4" * 64,
        384,
        EmbeddingDevice.CPU,
    )


class _FakeIndexState:
    def __init__(self, identity: IndexIdentity) -> None:
        self._identity = identity
        self._closed = False

    @property
    def identity(self) -> IndexIdentity:
        return self._identity

    @property
    def statistics(self) -> IndexStatistics:
        return IndexStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True


def test_queries_bind_selected_metadata_path_and_new_identifiers() -> None:
    bundle, review = _bundle_and_review()
    queries = _derive_repair_queries(bundle, review, (RepairTarget(0, 0),), _policy())
    assert len(queries) == 1
    assert len(queries[0].text.encode("utf-8")) <= 2_048
    assert "merge" in queries[0].text
    assert "app" in queries[0].text
    assert "Vulnerable" in queries[0].text
    assert queries == _derive_repair_queries(
        bundle,
        review,
        (RepairTarget(0, 0),),
        _policy(),
    )


def test_absent_index_identity_is_explicitly_not_requested() -> None:
    result = _retrieve_repair_context(
        expected_identity=None,
        index=None,
        queries=(),
        policy=_policy(),
        deadline=1.0,
    )
    assert result.summary.outcome is RepairContextOutcome.NOT_REQUESTED
    assert result.hits == ()


@pytest.mark.parametrize(
    ("code", "degradation"),
    [
        (RetrievalErrorCode.INDEX_CLOSED, "closed_index"),
        (RetrievalErrorCode.DEADLINE_EXCEEDED, "deadline_exceeded"),
        (RetrievalErrorCode.BACKEND_FAILED, "backend_failure"),
    ],
)
def test_only_known_retrieval_failures_degrade(
    monkeypatch: pytest.MonkeyPatch,
    code: RetrievalErrorCode,
    degradation: str,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))

    def fail_validation(_: ContextIndex, __: IndexIdentity, ___: float) -> None:
        raise RetrievalError(code, RetrievalStage.VALIDATE)

    monkeypatch.setattr(repair_retrieval, "_validate_live_index", fail_validation)
    result = _retrieve_repair_context(
        expected_identity=identity,
        index=index,
        queries=(ContextQuery("query"),),
        policy=_policy(),
        deadline=1.0,
    )
    assert result.summary.outcome is RepairContextOutcome.DEGRADED
    assert result.summary.degradation_code == degradation
    assert result.summary.selected_hit_count == 0
    assert result.hits == ()


def test_unknown_retrieval_failure_is_not_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))

    def fail_validation(_: ContextIndex, __: IndexIdentity, ___: float) -> None:
        raise RetrievalError(RetrievalErrorCode.INVALID_INDEX, RetrievalStage.VALIDATE)

    monkeypatch.setattr(repair_retrieval, "_validate_live_index", fail_validation)
    with pytest.raises(RepairError) as captured:
        _retrieve_repair_context(
            expected_identity=identity,
            index=index,
            queries=(ContextQuery("query"),),
            policy=_policy(),
            deadline=1.0,
        )
    assert captured.value.code is RepairErrorCode.INVALID_WORKFLOW
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_unknown_python_failure_is_not_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))

    def fail_validation(_: ContextIndex, __: IndexIdentity, ___: float) -> None:
        raise RuntimeError("native backend detail")

    monkeypatch.setattr(repair_retrieval, "_validate_live_index", fail_validation)
    with pytest.raises(RepairError) as captured:
        _retrieve_repair_context(
            expected_identity=identity,
            index=index,
            queries=(ContextQuery("query"),),
            policy=_policy(),
            deadline=1.0,
        )
    assert captured.value.code is RepairErrorCode.INVALID_WORKFLOW
    assert captured.value.stage.value == "retrieval"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_retrieval_result_must_bind_the_exact_query_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))
    monkeypatch.setattr(repair_retrieval, "_validate_live_index", lambda *_: None)
    monkeypatch.setattr(
        retrieval_core,
        "_retrieve_context_queries",
        lambda *_args, **_kwargs: RetrievalResult(identity, "f" * 64, 0, 0, 0, ()),
    )

    with pytest.raises(RepairError) as captured:
        _retrieve_repair_context(
            expected_identity=identity,
            index=index,
            queries=(ContextQuery("current query"),),
            policy=_policy(),
            deadline=1.0,
        )

    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
