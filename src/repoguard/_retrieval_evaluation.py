"""Deterministic intrinsic evaluation for M4 hybrid context retrieval."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Never, cast

from repoguard.evidence import (
    EvidenceBundle,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.retrieval import (
    ChunkProvenance,
    ContextIndexConfig,
    ContextQuery,
    EmbeddingDevice,
    EmbeddingProvider,
    FastEmbedProvider,
    RetrievalChannel,
    RetrievalError,
    build_context_index,
    retrieve_context,
)

_DATASET_RESOURCE = "evaluation_data/m4_retrieval.json"
_MODEL = "BAAI/bge-small-en-v1.5"
_DIMENSION = 384
_CUTOFF = 12
_EXPECTED_CORPUS_COUNT = 20
_EXPECTED_CASE_COUNT = 60
_EXPECTED_CASES_PER_STRATUM = 20
_EXPECTED_DIFFICULTIES = {"simple": 7, "medium": 7, "complex": 6}
_STRATA = ("lexical", "symbol", "semantic")
_DIFFICULTIES = ("simple", "medium", "complex")
_MIN_RECALL_AT_12 = 0.90
_MIN_MRR_AT_12 = 0.75
_MIN_NDCG_AT_12 = 0.80
_MIN_NDCG_CONTRIBUTION = 0.05
_MAX_STRATUM_RECALL_REGRESSION = 0.02
_DEVICE_PARITY_CASE_IDS = (
    "lexical-01",
    "lexical-09",
    "lexical-15",
    "symbol-01",
    "symbol-08",
    "symbol-18",
    "semantic-01",
    "semantic-08",
    "semantic-15",
)
_CASE_ID = re.compile(r"^(lexical|symbol|semantic)-([0-9]{2})$")
_OID = re.compile(r"^[0-9a-f]{40}$")
_TOKEN_SPAN = re.compile(r"\S+")
_VECTOR_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
_GIT_TIMEOUT_SECONDS = 30.0
_FIXED_GIT_DATE = "2000-01-01T00:00:00+0000"


class EvaluationDataError(ValueError):
    """A fixed evaluation resource or materialization invariant failed."""


class EvaluationMode(StrEnum):
    """One fixed channel ablation."""

    TEXT = "text"
    TEXT_SYMBOL = "text_symbol"
    TEXT_VECTOR = "text_vector"
    HYBRID = "hybrid"


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """Macro-averaged retrieval metrics at the fixed cutoff."""

    case_count: int
    recall_at_12: float
    mrr_at_12: float
    ndcg_at_12: float

    def __post_init__(self) -> None:
        if type(self.case_count) is not int or self.case_count <= 0:
            raise ValueError("case_count must be a positive integer")
        for value in (self.recall_at_12, self.mrr_at_12, self.ndcg_at_12):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise ValueError("evaluation metrics must be finite values in [0, 1]")


@dataclass(frozen=True, slots=True)
class EvaluationGroup:
    """Metrics for one case stratum or difficulty."""

    name: str
    metrics: EvaluationMetrics


@dataclass(frozen=True, slots=True)
class EvaluationCaseResult:
    """One query's ranked outcome without raw query content."""

    case_id: str
    stratum: str
    difficulty: str
    chunk_ids: tuple[str, ...]
    metrics: EvaluationMetrics


@dataclass(frozen=True, slots=True)
class EvaluationRun:
    """One complete channel ablation over all fixed cases."""

    mode: EvaluationMode
    channels: tuple[RetrievalChannel, ...]
    actual_device: EmbeddingDevice
    overall: EvaluationMetrics
    by_stratum: tuple[EvaluationGroup, ...]
    by_difficulty: tuple[EvaluationGroup, ...]
    cases: tuple[EvaluationCaseResult, ...]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Deterministic report for all four M4 channel ablations."""

    dataset_sha256: str
    head_oid: str
    runs: tuple[EvaluationRun, ...]
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class _CorpusEntry:
    path: str
    content: str
    oid: str


@dataclass(frozen=True, slots=True)
class _RelevantSpan:
    path: str
    oid: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class _EvaluationCase:
    case_id: str
    stratum: str
    difficulty: str
    query: str
    relevance: tuple[_RelevantSpan, ...]


@dataclass(frozen=True, slots=True)
class _EvaluationDataset:
    corpus: tuple[_CorpusEntry, ...]
    cases: tuple[_EvaluationCase, ...]
    sha256: str


class SemanticFakeEmbeddingProvider:
    """Offline deterministic encoder with explicit semantic topic features."""

    __slots__ = ("_closed",)

    def __init__(self) -> None:
        self._closed = False

    @property
    def name(self) -> str:
        return "m4-semantic-fake"

    @property
    def model(self) -> str:
        return _MODEL

    @property
    def dimension(self) -> int:
        return _DIMENSION

    @property
    def actual_device(self) -> EmbeddingDevice:
        return EmbeddingDevice.CPU

    @property
    def closed(self) -> bool:
        return self._closed

    def token_spans(self, text: str) -> tuple[tuple[int, int], ...]:
        if type(text) is not str:
            raise TypeError("text must be a string")
        text.encode("utf-8", errors="strict")
        return ((0, 0), *(match.span() for match in _TOKEN_SPAN.finditer(text)), (0, 0))

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return _fake_embeddings(texts)

    def embed_queries(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        return _fake_embeddings(texts)

    def close(self) -> None:
        self._closed = True


_SEMANTIC_TOPICS: tuple[frozenset[str], ...] = (
    frozenset(
        {
            "access",
            "account",
            "authentication",
            "confirm",
            "credential",
            "granting",
            "identity",
            "logged",
            "logging",
            "people",
            "protect",
            "protected",
            "recognize",
            "security",
            "session",
            "sign",
            "user",
            "visitors",
            "who",
        }
    ),
    frozenset(
        {
            "answer",
            "cache",
            "calculation",
            "calculations",
            "computation",
            "computed",
            "duplicate",
            "earlier",
            "expensive",
            "function",
            "memoization",
            "output",
            "prior",
            "remember",
            "repeating",
            "results",
            "reuse",
            "saved",
            "skip",
            "stores",
            "values",
            "work",
        }
    ),
    frozenset(
        {
            "backoff",
            "calls",
            "connection",
            "delays",
            "exponential",
            "failed",
            "failures",
            "flaky",
            "longer",
            "network",
            "outage",
            "pause",
            "recover",
            "remote",
            "repeat",
            "requests",
            "retries",
            "retry",
            "service",
            "temporary",
            "transient",
            "unstable",
            "wait",
        }
    ),
    frozenset(
        {
            "all",
            "atomically",
            "changes",
            "commits",
            "database",
            "error",
            "every",
            "fails",
            "failure",
            "grouped",
            "indivisible",
            "nothing",
            "persistence",
            "revert",
            "rollback",
            "rolls",
            "transaction",
            "undo",
            "update",
            "updates",
            "writes",
        }
    ),
    frozenset(
        {
            "act",
            "bursts",
            "callers",
            "capacity",
            "caps",
            "endpoint",
            "enforce",
            "flooding",
            "limit",
            "limiter",
            "minute",
            "often",
            "protect",
            "rate",
            "request",
            "requests",
            "service",
            "stop",
            "throttle",
            "traffic",
            "volume",
            "window",
        }
    ),
)

_ABLATIONS: tuple[tuple[EvaluationMode, tuple[RetrievalChannel, ...]], ...] = (
    (EvaluationMode.TEXT, (RetrievalChannel.TEXT,)),
    (
        EvaluationMode.TEXT_SYMBOL,
        (RetrievalChannel.TEXT, RetrievalChannel.SYMBOL),
    ),
    (
        EvaluationMode.TEXT_VECTOR,
        (RetrievalChannel.TEXT, RetrievalChannel.VECTOR),
    ),
    (
        EvaluationMode.HYBRID,
        (
            RetrievalChannel.TEXT,
            RetrievalChannel.VECTOR,
            RetrievalChannel.SYMBOL,
        ),
    ),
)


def load_evaluation_dataset() -> _EvaluationDataset:
    """Load and strictly validate the packaged fixed evaluation resource."""
    try:
        raw = resources.files("repoguard").joinpath(_DATASET_RESOURCE).read_bytes()
    except (OSError, TypeError):
        raise EvaluationDataError("evaluation dataset could not be read") from None
    return _parse_dataset(raw)


def run_evaluation(
    provider_factory: Callable[[], EmbeddingProvider] = SemanticFakeEmbeddingProvider,
) -> EvaluationReport:
    """Run the four fixed ablations against one deterministic temporary Git corpus."""
    if not callable(provider_factory):
        raise TypeError("provider_factory must be callable")
    dataset = load_evaluation_dataset()
    with tempfile.TemporaryDirectory(prefix="repoguard-m4-evaluation-") as temporary:
        bundle = _materialize_dataset(dataset, Path(temporary) / "repository")
        runs = tuple(
            _run_ablation(
                dataset,
                bundle=bundle,
                mode=mode,
                channels=channels,
                provider_factory=provider_factory,
            )
            for mode, channels in _ABLATIONS
        )
    return EvaluationReport(
        dataset_sha256=dataset.sha256,
        head_oid=bundle.revisions.head_oid,
        runs=runs,
    )


def evaluation_to_dict(report: EvaluationReport) -> dict[str, object]:
    """Convert one report to a deterministic JSON-compatible mapping."""
    if not isinstance(report, EvaluationReport):
        raise TypeError("report must be EvaluationReport")
    return {
        "schema_version": report.schema_version,
        "dataset_sha256": report.dataset_sha256,
        "head_oid": report.head_oid,
        "runs": [_run_to_dict(run) for run in report.runs],
    }


def evaluation_to_json(report: EvaluationReport) -> str:
    """Serialize one report as canonical compact UTF-8 JSON."""
    return json.dumps(
        evaluation_to_dict(report),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def validate_evaluation_gates(report: EvaluationReport) -> None:
    """Fail unless one complete report clears every fixed M4 value gate."""
    text, text_symbol, text_vector, hybrid = _validated_report_runs(report)
    if (
        hybrid.overall.recall_at_12 < _MIN_RECALL_AT_12
        or hybrid.overall.mrr_at_12 < _MIN_MRR_AT_12
        or hybrid.overall.ndcg_at_12 < _MIN_NDCG_AT_12
        or hybrid.overall.ndcg_at_12 - text.overall.ndcg_at_12 < _MIN_NDCG_CONTRIBUTION
        or _group_metrics(text_vector, "semantic").ndcg_at_12
        - _group_metrics(text, "semantic").ndcg_at_12
        < _MIN_NDCG_CONTRIBUTION
        or _group_metrics(text_symbol, "symbol").ndcg_at_12
        - _group_metrics(text, "symbol").ndcg_at_12
        < _MIN_NDCG_CONTRIBUTION
        or any(
            _group_metrics(text, stratum).recall_at_12
            - _group_metrics(hybrid, stratum).recall_at_12
            > _MAX_STRATUM_RECALL_REGRESSION
            for stratum in _STRATA
        )
    ):
        raise EvaluationDataError("evaluation value gates failed")


def validate_device_parity(
    cpu_report: EvaluationReport,
    cuda_report: EvaluationReport,
) -> None:
    """Require exact fixed-subset top-12 IDs across explicit CPU and CUDA runs."""
    cpu_runs = _validated_report_runs(cpu_report)
    cuda_runs = _validated_report_runs(cuda_report)
    validate_evaluation_gates(cpu_report)
    validate_evaluation_gates(cuda_report)
    if (
        cpu_report.dataset_sha256 != cuda_report.dataset_sha256
        or cpu_report.head_oid != cuda_report.head_oid
        or any(run.actual_device is not EmbeddingDevice.CPU for run in cpu_runs)
        or any(run.actual_device is not EmbeddingDevice.CUDA for run in cuda_runs)
    ):
        raise EvaluationDataError("evaluation device parity failed")
    for cpu_run, cuda_run in zip(cpu_runs, cuda_runs, strict=True):
        cpu_cases = {case.case_id: case for case in cpu_run.cases}
        cuda_cases = {case.case_id: case for case in cuda_run.cases}
        for case_id in _DEVICE_PARITY_CASE_IDS:
            cpu_case = cpu_cases.get(case_id)
            cuda_case = cuda_cases.get(case_id)
            if (
                cpu_case is None
                or cuda_case is None
                or cpu_case.stratum != cuda_case.stratum
                or cpu_case.difficulty != cuda_case.difficulty
                or cpu_case.chunk_ids != cuda_case.chunk_ids
            ):
                raise EvaluationDataError("evaluation device parity failed")


def _validated_report_runs(
    report: EvaluationReport,
) -> tuple[EvaluationRun, EvaluationRun, EvaluationRun, EvaluationRun]:
    if (
        type(report) is not EvaluationReport
        or type(report.schema_version) is not int
        or report.schema_version != 1
        or _OID.fullmatch(report.head_oid) is None
        or len(report.dataset_sha256) != 64
        or any(character not in "0123456789abcdef" for character in report.dataset_sha256)
        or type(report.runs) is not tuple
        or len(report.runs) != len(_ABLATIONS)
    ):
        raise EvaluationDataError("evaluation report is invalid")
    for run, (mode, channels) in zip(report.runs, _ABLATIONS, strict=True):
        if (
            type(run) is not EvaluationRun
            or run.mode is not mode
            or run.channels != channels
            or type(run.actual_device) is not EmbeddingDevice
            or type(run.cases) is not tuple
            or len(run.cases) != _EXPECTED_CASE_COUNT
            or tuple(case.case_id for case in run.cases)
            != tuple(
                f"{stratum}-{number:02d}"
                for stratum in _STRATA
                for number in range(1, _EXPECTED_CASES_PER_STRATUM + 1)
            )
        ):
            raise EvaluationDataError("evaluation report is invalid")
    return cast(
        tuple[EvaluationRun, EvaluationRun, EvaluationRun, EvaluationRun],
        report.runs,
    )


def _group_metrics(run: EvaluationRun, name: str) -> EvaluationMetrics:
    matches = tuple(group.metrics for group in run.by_stratum if group.name == name)
    if len(matches) != 1:
        raise EvaluationDataError("evaluation report is invalid")
    return matches[0]


def _run_ablation(
    dataset: _EvaluationDataset,
    *,
    bundle: EvidenceBundle,
    mode: EvaluationMode,
    channels: tuple[RetrievalChannel, ...],
    provider_factory: Callable[[], EmbeddingProvider],
) -> EvaluationRun:
    provider = provider_factory()
    if not isinstance(provider, EmbeddingProvider):
        raise TypeError("provider_factory must return an EmbeddingProvider")
    config = ContextIndexConfig(channels=channels)
    with build_context_index(
        bundle,
        embedding_provider=provider,
        config=config,
    ) as index:
        results: list[EvaluationCaseResult] = []
        for case in dataset.cases:
            retrieval = retrieve_context(index, ContextQuery(case.query))
            provenances = tuple(hit.chunk.provenance for hit in retrieval.hits)
            results.append(
                EvaluationCaseResult(
                    case_id=case.case_id,
                    stratum=case.stratum,
                    difficulty=case.difficulty,
                    chunk_ids=tuple(item.chunk_id for item in provenances),
                    metrics=_score_case(case, provenances, cutoff=_CUTOFF),
                )
            )
        case_results = tuple(results)
        return EvaluationRun(
            mode=mode,
            channels=channels,
            actual_device=index.identity.actual_device,
            overall=_average_metrics(case_results),
            by_stratum=tuple(
                EvaluationGroup(
                    name=stratum,
                    metrics=_average_metrics(
                        tuple(item for item in case_results if item.stratum == stratum)
                    ),
                )
                for stratum in _STRATA
            ),
            by_difficulty=tuple(
                EvaluationGroup(
                    name=difficulty,
                    metrics=_average_metrics(
                        tuple(item for item in case_results if item.difficulty == difficulty)
                    ),
                )
                for difficulty in _DIFFICULTIES
            ),
            cases=case_results,
        )


def _score_case(
    case: _EvaluationCase,
    ranked: Sequence[ChunkProvenance],
    *,
    cutoff: int,
) -> EvaluationMetrics:
    if type(cutoff) is not int or cutoff <= 0:
        raise ValueError("cutoff must be a positive integer")
    recovered: set[int] = set()
    gains: list[float] = []
    first_relevant_rank: int | None = None
    for rank, provenance in enumerate(ranked[:cutoff], start=1):
        newly_recovered = {
            index
            for index, relevance in enumerate(case.relevance)
            if index not in recovered and _overlaps(provenance, relevance)
        }
        if newly_recovered:
            recovered.update(newly_recovered)
            gains.append(1.0)
            if first_relevant_rank is None:
                first_relevant_rank = rank
        else:
            gains.append(0.0)

    recall = len(recovered) / len(case.relevance)
    reciprocal_rank = 0.0 if first_relevant_rank is None else 1.0 / first_relevant_rank
    dcg = math.fsum(gain / math.log2(rank + 1) for rank, gain in enumerate(gains, start=1) if gain)
    ideal_count = min(len(case.relevance), cutoff)
    ideal_dcg = math.fsum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_count + 1))
    ndcg = dcg / ideal_dcg
    return EvaluationMetrics(
        case_count=1,
        recall_at_12=recall,
        mrr_at_12=reciprocal_rank,
        ndcg_at_12=ndcg,
    )


def _overlaps(provenance: ChunkProvenance, relevance: _RelevantSpan) -> bool:
    return (
        provenance.path == relevance.path
        and provenance.oid == relevance.oid
        and provenance.start_byte < relevance.end_byte
        and relevance.start_byte < provenance.end_byte
        and provenance.start_line <= relevance.end_line
        and relevance.start_line <= provenance.end_line
    )


def _average_metrics(cases: tuple[EvaluationCaseResult, ...]) -> EvaluationMetrics:
    if not cases:
        raise ValueError("metric groups must contain at least one case")
    count = len(cases)
    return EvaluationMetrics(
        case_count=count,
        recall_at_12=math.fsum(item.metrics.recall_at_12 for item in cases) / count,
        mrr_at_12=math.fsum(item.metrics.mrr_at_12 for item in cases) / count,
        ndcg_at_12=math.fsum(item.metrics.ndcg_at_12 for item in cases) / count,
    )


def _parse_dataset(raw: bytes) -> _EvaluationDataset:
    if type(raw) is not bytes:
        raise TypeError("raw dataset must be bytes")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed: object = json.loads(text, object_pairs_hook=_strict_json_object)
    except EvaluationDataError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise EvaluationDataError("evaluation dataset is not strict UTF-8 JSON") from None

    root = _require_object(parsed, {"schema_version", "corpus", "cases"})
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        _invalid()

    corpus_values = _require_array(root["corpus"])
    if len(corpus_values) != _EXPECTED_CORPUS_COUNT:
        _invalid()
    corpus = tuple(_parse_corpus_entry(value) for value in corpus_values)
    corpus_paths = tuple(item.path for item in corpus)
    if len(set(corpus_paths)) != len(corpus_paths):
        _invalid()
    by_path = {entry.path: entry for entry in corpus}

    case_values = _require_array(root["cases"])
    if len(case_values) != _EXPECTED_CASE_COUNT:
        _invalid()
    cases = tuple(_parse_case(value, by_path) for value in case_values)
    _validate_case_set(cases)
    return _EvaluationDataset(corpus=corpus, cases=cases, sha256=digest)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationDataError("evaluation JSON contains duplicate object keys")
        result[key] = value
    return result


def _parse_corpus_entry(value: object) -> _CorpusEntry:
    item = _require_object(value, {"path", "content", "oid"})
    path = _require_path(item["path"])
    content = _require_utf8_string(item["content"], allow_empty=False, allow_controls=True)
    if "\x00" in content:
        _invalid()
    oid = _require_oid(item["oid"])
    if _git_blob_oid(content.encode("utf-8")) != oid:
        _invalid()
    return _CorpusEntry(path=path, content=content, oid=oid)


def _parse_case(
    value: object,
    corpus: dict[str, _CorpusEntry],
) -> _EvaluationCase:
    item = _require_object(
        value,
        {"id", "stratum", "difficulty", "query", "relevance"},
    )
    case_id = _require_utf8_string(item["id"], allow_empty=False, allow_controls=False)
    match = _CASE_ID.fullmatch(case_id)
    if match is None:
        _invalid()
    stratum = _require_utf8_string(
        item["stratum"],
        allow_empty=False,
        allow_controls=False,
    )
    if stratum not in _STRATA or stratum != match.group(1):
        _invalid()
    difficulty = _require_utf8_string(
        item["difficulty"],
        allow_empty=False,
        allow_controls=False,
    )
    if difficulty not in _DIFFICULTIES:
        _invalid()
    query = _require_utf8_string(item["query"], allow_empty=False, allow_controls=False)
    if len(query.encode("utf-8")) > 4096:
        _invalid()

    relevance_values = _require_array(item["relevance"])
    if not relevance_values:
        _invalid()
    relevance = tuple(_parse_relevance(entry, corpus) for entry in relevance_values)
    keys = tuple(
        (
            entry.path,
            entry.oid,
            entry.start_byte,
            entry.end_byte,
            entry.start_line,
            entry.end_line,
        )
        for entry in relevance
    )
    if len(set(keys)) != len(keys):
        _invalid()
    canonical = tuple(sorted(relevance, key=_relevance_sort_key))
    if relevance != canonical:
        _invalid()
    return _EvaluationCase(
        case_id=case_id,
        stratum=stratum,
        difficulty=difficulty,
        query=query,
        relevance=relevance,
    )


def _parse_relevance(
    value: object,
    corpus: dict[str, _CorpusEntry],
) -> _RelevantSpan:
    item = _require_object(
        value,
        {"path", "oid", "start_byte", "end_byte", "start_line", "end_line"},
    )
    path = _require_path(item["path"])
    oid = _require_oid(item["oid"])
    start_byte = _require_int(item["start_byte"])
    end_byte = _require_int(item["end_byte"])
    start_line = _require_int(item["start_line"])
    end_line = _require_int(item["end_line"])
    corpus_entry = corpus.get(path)
    if corpus_entry is None or corpus_entry.oid != oid:
        _invalid()

    content = corpus_entry.content
    encoded = content.encode("utf-8")
    if not 0 <= start_byte < end_byte <= len(encoded):
        _invalid()
    boundaries = {0}
    offset = 0
    for character in content:
        offset += len(character.encode("utf-8"))
        boundaries.add(offset)
    if start_byte not in boundaries or end_byte not in boundaries:
        _invalid()

    line_ranges = _line_byte_ranges(content)
    if not 1 <= start_line <= end_line <= len(line_ranges):
        _invalid()
    relevant_line_start = line_ranges[start_line - 1][0]
    relevant_line_end = line_ranges[end_line - 1][1]
    if not start_byte < relevant_line_end or not relevant_line_start < end_byte:
        _invalid()
    return _RelevantSpan(
        path=path,
        oid=oid,
        start_byte=start_byte,
        end_byte=end_byte,
        start_line=start_line,
        end_line=end_line,
    )


def _validate_case_set(cases: tuple[_EvaluationCase, ...]) -> None:
    ids = tuple(case.case_id for case in cases)
    if len(ids) != len(set(ids)):
        _invalid()
    expected_ids = tuple(
        f"{stratum}-{number:02d}"
        for stratum in _STRATA
        for number in range(1, _EXPECTED_CASES_PER_STRATUM + 1)
    )
    if ids != expected_ids:
        _invalid()
    stratum_counts = Counter(case.stratum for case in cases)
    if stratum_counts != Counter({stratum: _EXPECTED_CASES_PER_STRATUM for stratum in _STRATA}):
        _invalid()
    for stratum in _STRATA:
        difficulties = Counter(case.difficulty for case in cases if case.stratum == stratum)
        if difficulties != Counter(_EXPECTED_DIFFICULTIES):
            _invalid()


def _materialize_dataset(
    dataset: _EvaluationDataset,
    repository_root: Path,
) -> EvidenceBundle:
    if repository_root.exists():
        raise EvaluationDataError("evaluation repository target must not exist")
    repository_root.mkdir(parents=True)
    _git(repository_root, "init", "-q")
    _git(repository_root, "commit", "--allow-empty", "-q", "-m", "evaluation base")
    base_oid = _git(repository_root, "rev-parse", "HEAD").decode("ascii")

    for entry in sorted(dataset.corpus, key=lambda item: item.path.encode("utf-8")):
        destination = repository_root.joinpath(*entry.path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(entry.content.encode("utf-8"))
    _git(repository_root, "add", "--all")
    _git(repository_root, "commit", "-q", "-m", "evaluation corpus")
    head_oid = _git(repository_root, "rev-parse", "HEAD").decode("ascii")

    if _git(repository_root, "rev-parse", "--show-object-format") != b"sha1":
        raise EvaluationDataError("evaluation repository object format is not sha1")
    if _OID.fullmatch(base_oid) is None or _OID.fullmatch(head_oid) is None:
        raise EvaluationDataError("evaluation repository commit identity is invalid")
    _verify_materialized_tree(dataset, repository_root, head_oid)

    bundle = collect_evidence(
        RepositoryInput(repository_root.resolve()),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    if (
        bundle.repository.object_format != "sha1"
        or bundle.revisions.base_oid != base_oid
        or bundle.revisions.head_oid != head_oid
    ):
        raise EvaluationDataError("evaluation evidence identity is invalid")
    return bundle


def _verify_materialized_tree(
    dataset: _EvaluationDataset,
    repository_root: Path,
    head_oid: str,
) -> None:
    raw = _git(repository_root, "ls-tree", "-rz", "--full-tree", head_oid)
    observed: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            raw_mode, raw_kind, raw_oid = header.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            oid = raw_oid.decode("ascii", errors="strict")
            decoded_mode = raw_mode.decode("ascii", errors="strict")
            decoded_kind = raw_kind.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            raise EvaluationDataError("evaluation Git tree is malformed") from None
        if path in observed:
            raise EvaluationDataError("evaluation Git tree contains duplicate paths")
        observed[path] = (decoded_mode, decoded_kind, oid)

    expected = {entry.path: entry for entry in dataset.corpus}
    if set(observed) != set(expected):
        raise EvaluationDataError("evaluation Git tree does not match the fixed corpus")
    for path, entry in expected.items():
        mode, kind, oid = observed[path]
        if mode != "100644" or kind != "blob" or oid != entry.oid:
            raise EvaluationDataError("evaluation Git blob identity is invalid")
        if (repository_root / path).read_bytes() != entry.content.encode("utf-8"):
            raise EvaluationDataError("evaluation corpus bytes changed during materialization")


def _git(repository_root: Path, *arguments: str) -> bytes:
    command = (
        "git",
        "-C",
        str(repository_root),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "user.name=RepoGuard Evaluation",
        "-c",
        "user.email=repoguard-evaluation@example.invalid",
        *arguments,
    )
    environment = {
        "GIT_AUTHOR_DATE": _FIXED_GIT_DATE,
        "GIT_COMMITTER_DATE": _FIXED_GIT_DATE,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=environment,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        raise EvaluationDataError("evaluation Git materialization failed") from None
    if completed.returncode != 0:
        raise EvaluationDataError("evaluation Git materialization failed")
    return completed.stdout.rstrip(b"\n")


def _fake_embeddings(texts: tuple[str, ...]) -> tuple[tuple[float, ...], ...]:
    if type(texts) is not tuple or not all(type(text) is str for text in texts):
        raise TypeError("texts must be a tuple of strings")
    return tuple(_fake_vector(text) for text in texts)


def _fake_vector(text: str) -> tuple[float, ...]:
    text.encode("utf-8", errors="strict")
    tokens = tuple(match.group(0).casefold() for match in _VECTOR_TOKEN.finditer(text))
    values = [0.0] * _DIMENSION
    for index, vocabulary in enumerate(_SEMANTIC_TOPICS):
        values[index] = 8.0 * sum(token in vocabulary for token in tokens)
    hashed_dimensions = _DIMENSION - len(_SEMANTIC_TOPICS)
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        coordinate = len(_SEMANTIC_TOPICS) + (int.from_bytes(digest[:4], "big") % hashed_dimensions)
        values[coordinate] += 1.0
    if not any(values):
        values[-1] = 1.0
    norm = math.sqrt(math.fsum(value * value for value in values))
    return tuple(value / norm for value in values)


def _run_to_dict(run: EvaluationRun) -> dict[str, object]:
    return {
        "mode": run.mode.value,
        "channels": [channel.value for channel in run.channels],
        "actual_device": run.actual_device.value,
        "overall": _metrics_to_dict(run.overall),
        "by_stratum": [_group_to_dict(group) for group in run.by_stratum],
        "by_difficulty": [_group_to_dict(group) for group in run.by_difficulty],
        "cases": [_case_to_dict(case) for case in run.cases],
    }


def _metrics_to_dict(metrics: EvaluationMetrics) -> dict[str, object]:
    return {
        "case_count": metrics.case_count,
        "recall_at_12": metrics.recall_at_12,
        "mrr_at_12": metrics.mrr_at_12,
        "ndcg_at_12": metrics.ndcg_at_12,
    }


def _group_to_dict(group: EvaluationGroup) -> dict[str, object]:
    return {"name": group.name, "metrics": _metrics_to_dict(group.metrics)}


def _case_to_dict(case: EvaluationCaseResult) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "stratum": case.stratum,
        "difficulty": case.difficulty,
        "chunk_ids": list(case.chunk_ids),
        "metrics": _metrics_to_dict(case.metrics),
    }


def _require_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict:
        _invalid()
    raw = cast(dict[object, object], value)
    if any(type(key) is not str for key in raw) or set(raw) != keys:
        _invalid()
    return cast(dict[str, object], raw)


def _require_array(value: object) -> list[object]:
    if type(value) is not list:
        _invalid()
    return cast(list[object], value)


def _require_utf8_string(
    value: object,
    *,
    allow_empty: bool,
    allow_controls: bool,
) -> str:
    if type(value) is not str or (not allow_empty and not value):
        _invalid()
    text = value
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _invalid()
    if not allow_controls and any(unicodedata.category(character) == "Cc" for character in text):
        _invalid()
    return text


def _require_path(value: object) -> str:
    path = _require_utf8_string(value, allow_empty=False, allow_controls=False)
    parts = path.split("/")
    if (
        path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in parts)
        or any(part.casefold() == ".git" for part in parts)
    ):
        _invalid()
    return path


def _require_oid(value: object) -> str:
    if type(value) is not str or _OID.fullmatch(value) is None:
        _invalid()
    return value


def _require_int(value: object) -> int:
    if type(value) is not int:
        _invalid()
    return value


def _line_byte_ranges(content: str) -> tuple[tuple[int, int], ...]:
    lines = content.splitlines(keepends=True)
    if not lines:
        _invalid()
    ranges: list[tuple[int, int]] = []
    offset = 0
    for line in lines:
        end = offset + len(line.encode("utf-8"))
        ranges.append((offset, end))
        offset = end
    if offset != len(content.encode("utf-8")):
        _invalid()
    return tuple(ranges)


def _git_blob_oid(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _relevance_sort_key(
    relevance: _RelevantSpan,
) -> tuple[bytes, str, int, int, int, int]:
    return (
        relevance.path.encode("utf-8"),
        relevance.oid,
        relevance.start_byte,
        relevance.end_byte,
        relevance.start_line,
        relevance.end_line,
    )


def _invalid() -> Never:
    raise EvaluationDataError("evaluation dataset is invalid")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the deterministic fake or one explicit offline fixed-model evaluation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        choices=("fake", "fastembed"),
        default="fake",
    )
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument(
        "--device",
        choices=(EmbeddingDevice.CPU.value, EmbeddingDevice.CUDA.value),
        default=EmbeddingDevice.CPU.value,
    )
    arguments = parser.parse_args(argv)

    provider_factory: Callable[[], EmbeddingProvider]
    if arguments.provider == "fake":
        if arguments.cache_dir is not None:
            parser.error("--cache-dir is valid only with --provider fastembed")
        provider_factory = SemanticFakeEmbeddingProvider
    else:
        cache_dir = cast(Path | None, arguments.cache_dir)
        if cache_dir is None:
            parser.error("--cache-dir is required with --provider fastembed")
        device = EmbeddingDevice(cast(str, arguments.device))

        def fixed_provider() -> EmbeddingProvider:
            return FastEmbedProvider(
                cache_dir=cache_dir,
                allow_download=False,
                device=device,
            )

        provider_factory = fixed_provider

    try:
        report = run_evaluation(provider_factory)
        validate_evaluation_gates(report)
    except (EvaluationDataError, RetrievalError):
        parser.exit(status=1, message="retrieval evaluation failed\n")
    print(evaluation_to_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
