"""Deterministic intrinsic evaluation tests for M4 retrieval."""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from importlib import resources
from pathlib import Path
from typing import Never, cast

import pytest

import repoguard._retrieval_evaluation as evaluation
from repoguard.retrieval import (
    ChunkProvenance,
    EmbeddingDevice,
    EmbeddingProvider,
    FastEmbedProvider,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalStage,
)

_OID = "a" * 40


@pytest.fixture(scope="module")
def fake_report() -> evaluation.EvaluationReport:
    return evaluation.run_evaluation()


def _resource_bytes() -> bytes:
    return resources.files("repoguard").joinpath("evaluation_data/m4_retrieval.json").read_bytes()


def _dataset_object() -> dict[str, object]:
    parsed: object = json.loads(_resource_bytes())
    assert type(parsed) is dict
    return cast(dict[str, object], parsed)


def _corpus(value: dict[str, object]) -> list[dict[str, object]]:
    raw = value["corpus"]
    assert type(raw) is list
    return cast(list[dict[str, object]], raw)


def _cases(value: dict[str, object]) -> list[dict[str, object]]:
    raw = value["cases"]
    assert type(raw) is list
    return cast(list[dict[str, object]], raw)


def _relevance(value: dict[str, object]) -> list[dict[str, object]]:
    raw = value["relevance"]
    assert type(raw) is list
    return cast(list[dict[str, object]], raw)


def _encoded(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _provenance(
    number: int,
    *,
    path: str = "src/example.py",
    oid: str = _OID,
    start_byte: int,
    end_byte: int,
    start_line: int,
    end_line: int,
) -> ChunkProvenance:
    return ChunkProvenance(
        chunk_id=f"{number:064x}",
        path=path,
        oid=oid,
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=start_line,
        end_line=end_line,
    )


def _group(
    run: evaluation.EvaluationRun,
    name: str,
) -> evaluation.EvaluationMetrics:
    return next(group.metrics for group in run.by_stratum if group.name == name)


def test_packaged_dataset_has_the_fixed_schema_and_stratification() -> None:
    dataset = evaluation.load_evaluation_dataset()

    assert len(dataset.corpus) == 20
    assert len(dataset.cases) == 60
    assert len({entry.path for entry in dataset.corpus}) == 20
    assert Counter(case.stratum for case in dataset.cases) == {
        "lexical": 20,
        "symbol": 20,
        "semantic": 20,
    }
    for stratum in ("lexical", "symbol", "semantic"):
        assert Counter(case.difficulty for case in dataset.cases if case.stratum == stratum) == {
            "simple": 7,
            "medium": 7,
            "complex": 6,
        }
    assert tuple(case.case_id for case in dataset.cases) == tuple(
        f"{stratum}-{number:02d}"
        for stratum in ("lexical", "symbol", "semantic")
        for number in range(1, 21)
    )


def test_materialized_corpus_has_verified_git_identity(tmp_path: Path) -> None:
    dataset = evaluation.load_evaluation_dataset()
    root = tmp_path / "fixed-corpus"

    bundle = evaluation._materialize_dataset(dataset, root)

    assert bundle.repository.root == root.resolve()
    assert bundle.repository.object_format == "sha1"
    assert len(bundle.revisions.head_oid) == 40
    assert len(bundle.changes) == 20
    for entry in dataset.corpus:
        assert (root / entry.path).read_text(encoding="utf-8") == entry.content

    with pytest.raises(
        evaluation.EvaluationDataError,
        match="target must not exist",
    ):
        evaluation._materialize_dataset(dataset, root)


def test_semantic_fake_is_normalized_repeatable_and_topic_aware() -> None:
    provider = evaluation.SemanticFakeEmbeddingProvider()
    documents = provider.embed_documents(
        (
            "Credential authentication establishes a protected account session.",
            "Memoization stores computed results for later reuse.",
        )
    )
    queries = provider.embed_queries(("confirm who is logging on",))

    assert provider.name == "m4-semantic-fake"
    assert provider.model == "BAAI/bge-small-en-v1.5"
    assert provider.dimension == 384
    assert provider.actual_device.value == "cpu"
    assert provider.token_spans("two words") == ((0, 0), (0, 3), (4, 9), (0, 0))
    assert all(len(vector) == 384 for vector in (*documents, *queries))
    assert all(
        math.sqrt(math.fsum(component * component for component in vector)) == pytest.approx(1.0)
        for vector in (*documents, *queries)
    )
    authentication_similarity = math.fsum(
        left * right for left, right in zip(queries[0], documents[0], strict=True)
    )
    memoization_similarity = math.fsum(
        left * right for left, right in zip(queries[0], documents[1], strict=True)
    )
    assert authentication_similarity > memoization_similarity
    assert provider.embed_queries(("confirm who is logging on",)) == queries
    provider.close()
    provider.close()
    assert provider.closed


def test_semantic_fake_rejects_malformed_inputs_and_handles_empty_text() -> None:
    provider = evaluation.SemanticFakeEmbeddingProvider()

    with pytest.raises(TypeError, match="text must be a string"):
        provider.token_spans(cast(str, b"not text"))
    with pytest.raises(TypeError, match="tuple of strings"):
        provider.embed_documents(cast(tuple[str, ...], ["not", "a", "tuple"]))

    vector = provider.embed_queries(("",))[0]
    assert vector[-1] == 1.0
    assert math.fsum(component * component for component in vector) == 1.0


@pytest.mark.parametrize(
    "arguments",
    (
        (0, 0.0, 0.0, 0.0),
        (1, math.nan, 0.0, 0.0),
        (1, 0.0, -0.1, 0.0),
        (1, 0.0, 0.0, 1.1),
    ),
)
def test_metric_values_reject_invalid_counts_and_scores(
    arguments: tuple[int, float, float, float],
) -> None:
    with pytest.raises(ValueError):
        evaluation.EvaluationMetrics(*arguments)


def test_metric_arithmetic_credits_each_relevance_span_once() -> None:
    case = evaluation._EvaluationCase(
        case_id="lexical-01",
        stratum="lexical",
        difficulty="simple",
        query="query",
        relevance=(
            evaluation._RelevantSpan("src/example.py", _OID, 0, 10, 1, 1),
            evaluation._RelevantSpan("src/example.py", _OID, 20, 30, 3, 3),
        ),
    )
    ranked = (
        _provenance(
            1,
            start_byte=10,
            end_byte=20,
            start_line=2,
            end_line=2,
        ),
        _provenance(
            2,
            start_byte=0,
            end_byte=10,
            start_line=1,
            end_line=1,
        ),
        _provenance(
            3,
            start_byte=0,
            end_byte=8,
            start_line=1,
            end_line=1,
        ),
    )

    metrics = evaluation._score_case(case, ranked, cutoff=12)

    ideal_dcg = 1.0 + 1.0 / math.log2(3)
    assert metrics.case_count == 1
    assert metrics.recall_at_12 == 0.5
    assert metrics.mrr_at_12 == 0.5
    assert metrics.ndcg_at_12 == pytest.approx((1.0 / math.log2(3)) / ideal_dcg)

    with pytest.raises(ValueError, match="cutoff"):
        evaluation._score_case(case, ranked, cutoff=0)
    with pytest.raises(ValueError, match="at least one"):
        evaluation._average_metrics(())


def test_relevance_requires_exact_identity_and_both_span_overlaps() -> None:
    relevant = evaluation._RelevantSpan("src/example.py", _OID, 5, 15, 2, 3)

    assert evaluation._overlaps(
        _provenance(
            1,
            start_byte=10,
            end_byte=20,
            start_line=3,
            end_line=4,
        ),
        relevant,
    )
    assert not evaluation._overlaps(
        _provenance(
            2,
            path="src/other.py",
            start_byte=10,
            end_byte=20,
            start_line=3,
            end_line=4,
        ),
        relevant,
    )
    assert not evaluation._overlaps(
        _provenance(
            3,
            oid="b" * 40,
            start_byte=10,
            end_byte=20,
            start_line=3,
            end_line=4,
        ),
        relevant,
    )
    assert not evaluation._overlaps(
        _provenance(
            4,
            start_byte=15,
            end_byte=20,
            start_line=3,
            end_line=4,
        ),
        relevant,
    )
    assert not evaluation._overlaps(
        _provenance(
            5,
            start_byte=10,
            end_byte=20,
            start_line=4,
            end_line=4,
        ),
        relevant,
    )


def test_parser_rejects_duplicate_json_keys_and_invalid_utf8() -> None:
    duplicate = b'{"schema_version":1,"schema_version":1,"corpus":[],"cases":[]}'
    with pytest.raises(evaluation.EvaluationDataError, match="duplicate object keys"):
        evaluation._parse_dataset(duplicate)
    with pytest.raises(evaluation.EvaluationDataError, match="strict UTF-8 JSON"):
        evaluation._parse_dataset(b"\xff")
    with pytest.raises(TypeError, match="must be bytes"):
        evaluation._parse_dataset(cast(bytes, "not bytes"))


def test_packaged_dataset_read_failure_is_stable(monkeypatch: pytest.MonkeyPatch) -> None:
    class _UnreadableResource:
        def read_bytes(self) -> bytes:
            raise OSError

    class _ResourceRoot:
        def joinpath(self, _: str) -> _UnreadableResource:
            return _UnreadableResource()

    monkeypatch.setattr(
        "repoguard._retrieval_evaluation.resources.files",
        lambda _: _ResourceRoot(),
    )

    with pytest.raises(evaluation.EvaluationDataError, match="could not be read"):
        evaluation.load_evaluation_dataset()


@pytest.mark.parametrize(
    "mutation",
    (
        "unsupported_schema",
        "extra_root_key",
        "wrong_corpus_shape",
        "wrong_corpus_count",
        "duplicate_corpus_path",
        "wrong_case_count",
        "duplicate_case_id",
        "noncanonical_case_order",
        "wrong_blob_oid",
        "malformed_blob_oid",
        "empty_corpus_content",
        "nul_corpus_content",
        "malformed_case_id",
        "mismatched_stratum",
        "invalid_difficulty",
        "unbalanced_difficulty",
        "oversized_query",
        "controlled_query",
        "empty_relevance",
        "empty_span",
        "non_integer_span",
        "unknown_relevance_path",
        "git_metadata_path",
        "invalid_query_unicode",
        "duplicate_relevance",
        "noncanonical_relevance",
    ),
)
def test_parser_rejects_malformed_dataset_invariants(mutation: str) -> None:
    value = _dataset_object()
    corpus = _corpus(value)
    cases = _cases(value)
    first_relevance = _relevance(cases[0])

    if mutation == "unsupported_schema":
        value["schema_version"] = 2
    elif mutation == "extra_root_key":
        value["unexpected"] = True
    elif mutation == "wrong_corpus_shape":
        value["corpus"] = {}
    elif mutation == "wrong_corpus_count":
        corpus.pop()
    elif mutation == "duplicate_corpus_path":
        corpus[1]["path"] = corpus[0]["path"]
    elif mutation == "wrong_case_count":
        cases.pop()
    elif mutation == "duplicate_case_id":
        cases[1]["id"] = cases[0]["id"]
    elif mutation == "noncanonical_case_order":
        cases[0], cases[1] = cases[1], cases[0]
    elif mutation == "wrong_blob_oid":
        corpus[0]["oid"] = "0" * 40
    elif mutation == "malformed_blob_oid":
        corpus[0]["oid"] = "not-an-oid"
    elif mutation == "empty_corpus_content":
        corpus[0]["content"] = ""
    elif mutation == "nul_corpus_content":
        corpus[0]["content"] = "\x00"
    elif mutation == "malformed_case_id":
        cases[0]["id"] = "bad-id"
    elif mutation == "mismatched_stratum":
        cases[0]["stratum"] = "symbol"
    elif mutation == "invalid_difficulty":
        cases[0]["difficulty"] = "impossible"
    elif mutation == "unbalanced_difficulty":
        cases[0]["difficulty"] = "medium"
    elif mutation == "oversized_query":
        cases[0]["query"] = "q" * 4097
    elif mutation == "controlled_query":
        cases[0]["query"] = "query\nwith control"
    elif mutation == "empty_relevance":
        cases[0]["relevance"] = []
    elif mutation == "empty_span":
        first_relevance[0]["end_byte"] = first_relevance[0]["start_byte"]
    elif mutation == "non_integer_span":
        first_relevance[0]["end_byte"] = True
    elif mutation == "unknown_relevance_path":
        first_relevance[0]["path"] = "missing.txt"
    elif mutation == "git_metadata_path":
        corpus[0]["path"] = ".git/config"
    elif mutation == "invalid_query_unicode":
        cases[0]["query"] = "\ud800"
    elif mutation == "duplicate_relevance":
        first_relevance.append(dict(first_relevance[0]))
    else:
        shorter = dict(first_relevance[0])
        shorter["end_byte"] = 1
        first_relevance.append(shorter)

    with pytest.raises(evaluation.EvaluationDataError):
        evaluation._parse_dataset(_encoded(value))


def test_relevance_parser_rejects_utf8_boundary_line_and_consistency_errors() -> None:
    content = "é\nsecond\n"
    oid = evaluation._git_blob_oid(content.encode("utf-8"))
    corpus = {"unicode.txt": evaluation._CorpusEntry("unicode.txt", content, oid)}
    base: dict[str, object] = {
        "path": "unicode.txt",
        "oid": oid,
        "start_byte": 0,
        "end_byte": 2,
        "start_line": 1,
        "end_line": 1,
    }

    inside_code_point = dict(base)
    inside_code_point["start_byte"] = 1
    with pytest.raises(evaluation.EvaluationDataError):
        evaluation._parse_relevance(inside_code_point, corpus)

    missing_line = dict(base)
    missing_line["start_line"] = 3
    missing_line["end_line"] = 3
    with pytest.raises(evaluation.EvaluationDataError):
        evaluation._parse_relevance(missing_line, corpus)

    inconsistent = dict(base)
    inconsistent["start_line"] = 2
    inconsistent["end_line"] = 2
    with pytest.raises(evaluation.EvaluationDataError):
        evaluation._parse_relevance(inconsistent, corpus)


def test_evaluation_rejects_invalid_provider_factories() -> None:
    with pytest.raises(TypeError, match="must be callable"):
        evaluation.run_evaluation(cast(Callable[[], EmbeddingProvider], 42))

    def invalid_provider() -> EmbeddingProvider:
        return cast(EmbeddingProvider, object())

    with pytest.raises(TypeError, match="return an EmbeddingProvider"):
        evaluation.run_evaluation(invalid_provider)


def test_fake_evaluation_runs_fixed_ablations_and_value_dimensions(
    fake_report: evaluation.EvaluationReport,
) -> None:
    assert fake_report.schema_version == 1
    assert fake_report.dataset_sha256 == (
        "ba1360486c9e5c5b6943680b136fdc3fd31a06a48d84c187671d8576111daa56"
    )
    assert fake_report.head_oid == "eeae5b7572836466abb18c9f0c24acdeca572524"
    assert tuple(run.mode for run in fake_report.runs) == (
        evaluation.EvaluationMode.TEXT,
        evaluation.EvaluationMode.TEXT_SYMBOL,
        evaluation.EvaluationMode.TEXT_VECTOR,
        evaluation.EvaluationMode.HYBRID,
    )
    assert tuple(run.channels for run in fake_report.runs) == (
        (RetrievalChannel.TEXT,),
        (RetrievalChannel.TEXT, RetrievalChannel.SYMBOL),
        (RetrievalChannel.TEXT, RetrievalChannel.VECTOR),
        (
            RetrievalChannel.TEXT,
            RetrievalChannel.VECTOR,
            RetrievalChannel.SYMBOL,
        ),
    )
    assert all(run.actual_device.value == "cpu" for run in fake_report.runs)
    assert all(run.overall.case_count == 60 for run in fake_report.runs)
    assert all(len(run.cases) == 60 for run in fake_report.runs)

    text, text_symbol, text_vector, hybrid = fake_report.runs
    assert hybrid.overall.recall_at_12 == 1.0
    assert hybrid.overall.mrr_at_12 > 0.75
    assert hybrid.overall.ndcg_at_12 > 0.80
    assert hybrid.overall.ndcg_at_12 - text.overall.ndcg_at_12 > 0.05
    assert _group(text_vector, "semantic").ndcg_at_12 - _group(text, "semantic").ndcg_at_12 > 0.05
    assert _group(text_symbol, "symbol").ndcg_at_12 - _group(text, "symbol").ndcg_at_12 > 0.05
    assert all(group.metrics.recall_at_12 == 1.0 for group in hybrid.by_stratum)
    evaluation.validate_evaluation_gates(fake_report)


def test_value_gate_rejects_each_failed_dimension(
    fake_report: evaluation.EvaluationReport,
) -> None:
    text, text_symbol, text_vector, hybrid = fake_report.runs
    failed_hybrid = replace(
        hybrid,
        overall=replace(hybrid.overall, recall_at_12=0.89),
    )
    failed_vector_groups = tuple(
        replace(
            group,
            metrics=replace(group.metrics, ndcg_at_12=0.0),
        )
        if group.name == "semantic"
        else group
        for group in text_vector.by_stratum
    )
    failed_reports = (
        replace(fake_report, runs=(*fake_report.runs[:3], failed_hybrid)),
        replace(
            fake_report,
            runs=(
                text,
                text_symbol,
                replace(text_vector, by_stratum=failed_vector_groups),
                hybrid,
            ),
        ),
    )

    for report in failed_reports:
        with pytest.raises(evaluation.EvaluationDataError, match="value gates failed"):
            evaluation.validate_evaluation_gates(report)


def test_device_parity_uses_fixed_stratified_case_subset(
    fake_report: evaluation.EvaluationReport,
) -> None:
    cuda_report = replace(
        fake_report,
        runs=tuple(replace(run, actual_device=EmbeddingDevice.CUDA) for run in fake_report.runs),
    )

    evaluation.validate_device_parity(fake_report, cuda_report)

    hybrid = cuda_report.runs[-1]
    parity_cases = tuple(
        replace(case, chunk_ids=("f" * 64,)) if case.case_id == "symbol-18" else case
        for case in hybrid.cases
    )
    with pytest.raises(evaluation.EvaluationDataError, match="device parity failed"):
        evaluation.validate_device_parity(
            fake_report,
            replace(
                cuda_report,
                runs=(*cuda_report.runs[:-1], replace(hybrid, cases=parity_cases)),
            ),
        )

    non_subset_cases = tuple(
        replace(case, chunk_ids=("e" * 64,)) if case.case_id == "symbol-09" else case
        for case in hybrid.cases
    )
    evaluation.validate_device_parity(
        fake_report,
        replace(
            cuda_report,
            runs=(*cuda_report.runs[:-1], replace(hybrid, cases=non_subset_cases)),
        ),
    )


def test_evaluation_output_is_canonical_content_safe_and_repeatable(
    fake_report: evaluation.EvaluationReport,
) -> None:
    first = evaluation.evaluation_to_json(fake_report)
    second_report = evaluation.run_evaluation()
    second = evaluation.evaluation_to_json(second_report)

    assert first == second
    assert not first.endswith("\n")
    assert first == json.dumps(
        evaluation.evaluation_to_dict(fake_report),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert "/tmp/" not in first
    assert "user sign in security" not in first
    assert "cache_dir" not in first
    assert tuple(case.case_id for case in fake_report.runs[0].cases) == tuple(
        f"{stratum}-{number:02d}"
        for stratum in ("lexical", "symbol", "semantic")
        for number in range(1, 21)
    )

    with pytest.raises(TypeError, match="EvaluationReport"):
        evaluation.evaluation_to_dict(cast(evaluation.EvaluationReport, object()))


def test_fake_module_entry_point_prints_the_canonical_report(
    fake_report: evaluation.EvaluationReport,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fixed_run(
        provider_factory: object = evaluation.SemanticFakeEmbeddingProvider,
    ) -> evaluation.EvaluationReport:
        assert provider_factory is evaluation.SemanticFakeEmbeddingProvider
        return fake_report

    monkeypatch.setattr(evaluation, "run_evaluation", fixed_run)

    assert evaluation.main(()) == 0
    captured = capsys.readouterr()
    assert captured.out == f"{evaluation.evaluation_to_json(fake_report)}\n"
    assert captured.err == ""


def test_fixed_model_entry_point_builds_an_offline_explicit_provider(
    fake_report: evaluation.EvaluationReport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_dir = tmp_path / "cache"

    def inspect_factory(
        provider_factory: Callable[[], EmbeddingProvider],
    ) -> evaluation.EvaluationReport:
        provider = provider_factory()
        assert isinstance(provider, FastEmbedProvider)
        assert provider.model == "BAAI/bge-small-en-v1.5"
        provider.close()
        return fake_report

    monkeypatch.setattr(evaluation, "run_evaluation", inspect_factory)

    assert (
        evaluation.main(
            (
                "--provider",
                "fastembed",
                "--cache-dir",
                str(cache_dir),
                "--device",
                "cuda",
            )
        )
        == 0
    )
    assert capsys.readouterr().out == f"{evaluation.evaluation_to_json(fake_report)}\n"


@pytest.mark.parametrize(
    "arguments",
    (
        ("--provider", "fake", "--cache-dir", "/tmp/not-used"),
        ("--provider", "fastembed"),
    ),
)
def test_entry_point_rejects_inconsistent_cache_arguments(
    arguments: tuple[str, ...],
) -> None:
    with pytest.raises(SystemExit) as caught:
        evaluation.main(arguments)
    assert caught.value.code == 2


@pytest.mark.parametrize(
    "failure",
    (
        evaluation.EvaluationDataError("/private/evaluation/path"),
        RetrievalError(
            RetrievalErrorCode.MODEL_UNAVAILABLE,
            RetrievalStage.EMBED,
        ),
    ),
)
def test_entry_point_maps_expected_failures_without_a_traceback(
    failure: Exception,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_run(provider_factory: object = evaluation.SemanticFakeEmbeddingProvider) -> Never:
        del provider_factory
        raise failure

    monkeypatch.setattr(evaluation, "run_evaluation", fail_run)

    with pytest.raises(SystemExit) as caught:
        evaluation.main(())

    assert caught.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "retrieval evaluation failed\n"
    assert "/private/evaluation/path" not in captured.err
