"""Deterministic properties for controlled Agent review."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from repoguard.agent import (
    AgentFinding,
    AgentNode,
    AgentReviewConfig,
    AgentReviewError,
    AgentReviewErrorCode,
    AgentReviewResult,
    AgentRuleId,
    FindingSource,
    PromptIdentity,
    agent_review_to_dict,
    agent_review_to_json,
    review_with_agent,
)
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
from repoguard.providers import LLMRequest, LLMResponse, TokenUsage
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    FindingCategory,
    FindingSeverity,
)

_OID_A = "a" * 40
_OID_B = "b" * 40
_EMPTY_RESPONSE = '{"schema_version":1,"findings":[]}'
_PROPERTY_SETTINGS = settings(database=None, derandomize=True, max_examples=100)
_SURROGATE_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
_UTF8_CHARACTER = st.characters(
    exclude_categories=_SURROGATE_CATEGORIES,
    exclude_characters="\x00",
)
_UTF8_FRAGMENT: SearchStrategy[str] = st.text(_UTF8_CHARACTER, max_size=32)
_OPTIONAL_TOKEN_COUNT: SearchStrategy[int | None] = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=100_000),
)


class _RecordingProvider:
    def __init__(self, responses: Sequence[LLMResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[LLMRequest] = []

    @property
    def name(self) -> str:
        return "property-fake"

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return self._responses.pop(0)


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _bundle(*changes: FileChangeEvidence) -> EvidenceBundle:
    return EvidenceBundle(
        repository=RepositoryEvidence(root=Path("/repo/测试"), object_format="sha1"),
        revisions=RevisionEvidence(
            base_ref="refs/heads/main",
            head_ref="refs/heads/feature",
            base_oid=_OID_A,
            head_oid=_OID_B,
            merge_base_oid=_OID_A,
        ),
        changes=changes,
    )


def _added_text_change(path: str, contents: Sequence[str]) -> FileChangeEvidence:
    lines = tuple(
        DiffLineEvidence(
            kind=DiffLineKind.ADDITION,
            old_line_number=None,
            new_line_number=index,
            content=content,
            has_trailing_newline=True,
        )
        for index, content in enumerate(contents, start=1)
    )
    return FileChangeEvidence(
        change_type=ChangeType.ADDED,
        rename_similarity=None,
        old=None,
        new=FileVersion(
            path=path,
            mode="100644",
            oid=_OID_B,
            content_kind=ContentKind.TEXT,
        ),
        hunks=(
            DiffHunkEvidence(
                old_start=0,
                old_count=0,
                new_start=1,
                new_count=len(lines),
                lines=lines,
            ),
        ),
    )


def _raw_reference(
    path: str,
    *,
    start_line: int | None = 1,
    end_line: int | None = 1,
) -> dict[str, object]:
    return {
        "path": path,
        "side": "new",
        "start_line": start_line,
        "end_line": end_line,
    }


def _raw_finding(
    *,
    category: str,
    severity: str,
    title: str,
    references: Sequence[dict[str, object]],
) -> dict[str, object]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "message": f"Evidence for {title}.",
        "remediation": f"Correct {title} and add a regression test.",
        "references": list(references),
    }


def _response(findings: Sequence[dict[str, object]]) -> LLMResponse:
    return LLMResponse(
        output_text=json.dumps(
            {"schema_version": 1, "findings": list(findings)},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        usage=TokenUsage(input_tokens=100, output_tokens=20, total_tokens=120),
    )


@_PROPERTY_SETTINGS
@example(
    path="src/特殊.py",
    title="标题",
    message="说明",
    remediation="修复",
    category=FindingCategory.CORRECTNESS,
    severity=FindingSeverity.HIGH,
    attempt_count=1,
    input_tokens=None,
    output_tokens=0,
    total_tokens=0,
    prompt_bytes=0,
    response_bytes=0,
)
@given(
    path=_UTF8_FRAGMENT.map(lambda value: f"src/x{value}.py"),
    title=_UTF8_FRAGMENT.map(lambda value: f"title {value}"),
    message=_UTF8_FRAGMENT.map(lambda value: f"message {value}"),
    remediation=_UTF8_FRAGMENT.map(lambda value: f"remediation {value}"),
    category=st.sampled_from(tuple(FindingCategory)),
    severity=st.sampled_from(tuple(FindingSeverity)),
    attempt_count=st.integers(min_value=1, max_value=3),
    input_tokens=_OPTIONAL_TOKEN_COUNT,
    output_tokens=_OPTIONAL_TOKEN_COUNT,
    total_tokens=_OPTIONAL_TOKEN_COUNT,
    prompt_bytes=st.integers(min_value=0, max_value=131_072),
    response_bytes=st.integers(min_value=0, max_value=524_288),
)
def test_agent_result_json_matches_mapping_and_is_byte_stable(
    path: str,
    title: str,
    message: str,
    remediation: str,
    category: FindingCategory,
    severity: FindingSeverity,
    attempt_count: int,
    input_tokens: int | None,
    output_tokens: int | None,
    total_tokens: int | None,
    prompt_bytes: int,
    response_bytes: int,
) -> None:
    reference = EvidenceReference(
        path=path,
        side=EvidenceSide.NEW,
        oid=_OID_B,
        start_line=1,
        end_line=1,
    )
    result = AgentReviewResult(
        repository=_bundle().repository,
        revisions=_bundle().revisions,
        provider="property-fake",
        model="model/ü",
        prompt=PromptIdentity(name="agent_review", version="v1", sha256="a" * 64),
        attempt_count=attempt_count,
        usage=TokenUsage(input_tokens, output_tokens, total_tokens),
        prompt_bytes=prompt_bytes,
        response_bytes=response_bytes,
        findings=(
            AgentFinding(
                source=FindingSource.AGENT,
                rule_id=AgentRuleId.AGENT_REASONING,
                category=category,
                severity=severity,
                title=title,
                message=message,
                remediation=remediation,
                references=(reference,),
            ),
        ),
    )

    first = agent_review_to_json(result)
    second = agent_review_to_json(result)

    assert first == second
    assert json.loads(first) == agent_review_to_dict(result)
    assert not first.endswith("\n")
    first.encode("utf-8")


@_PROPERTY_SETTINGS
@example(
    change_order=[0, 1, 2],
    finding_order=[0, 1, 2],
    reference_order=[0, 1],
)
@example(
    change_order=[2, 1, 0],
    finding_order=[2, 1, 0],
    reference_order=[1, 0],
)
@given(
    change_order=st.permutations((0, 1, 2)),
    finding_order=st.permutations((0, 1, 2)),
    reference_order=st.permutations((0, 1)),
)
def test_review_is_invariant_under_change_finding_and_reference_permutations(
    change_order: list[int],
    finding_order: list[int],
    reference_order: list[int],
) -> None:
    changes = (
        _added_text_change("src/a.py", ("a = 1",)),
        _added_text_change("src/b.py", ("b = 2",)),
        _added_text_change("src/c.py", ("c = 3",)),
    )
    first_references = (
        _raw_reference("src/a.py"),
        _raw_reference("src/b.py"),
    )
    baseline_findings = (
        _raw_finding(
            category="security",
            severity="high",
            title="Finding A",
            references=first_references,
        ),
        _raw_finding(
            category="correctness",
            severity="medium",
            title="Finding B",
            references=(_raw_reference("src/c.py"),),
        ),
        _raw_finding(
            category="reviewability",
            severity="info",
            title="Finding C",
            references=(_raw_reference("src/b.py"),),
        ),
    )
    permuted_first = dict(baseline_findings[0])
    permuted_first["references"] = [first_references[index] for index in reference_order]
    permutable_findings = (
        permuted_first,
        baseline_findings[1],
        baseline_findings[2],
    )
    baseline_provider = _RecordingProvider([_response(baseline_findings)])
    permuted_provider = _RecordingProvider(
        [_response(tuple(permutable_findings[index] for index in finding_order))]
    )
    config = AgentReviewConfig(model="review-model")

    baseline = review_with_agent(
        _bundle(*changes),
        provider=baseline_provider,
        config=config,
    )
    permuted = review_with_agent(
        _bundle(*(changes[index] for index in change_order)),
        provider=permuted_provider,
        config=config,
    )

    assert permuted == baseline
    assert agent_review_to_json(permuted) == agent_review_to_json(baseline)
    assert (
        permuted_provider.requests[0].messages[1].content
        == baseline_provider.requests[0].messages[1].content
    )


@_PROPERTY_SETTINGS
@example(nonce=0)
@given(nonce=st.integers(min_value=0, max_value=2**128 - 1))
def test_generated_private_key_body_never_crosses_public_boundaries(
    nonce: int,
) -> None:
    secret = f"SENSITIVE_BODY_{nonce:032x}_DO_NOT_COPY"
    bundle = _bundle(
        _added_text_change(
            "secrets/key.pem",
            (
                "-----BEGIN PRIVATE KEY-----",
                secret,
                "-----END PRIVATE KEY-----",
            ),
        )
    )
    provider = _RecordingProvider([LLMResponse(output_text=_EMPTY_RESPONSE)])
    handler = _RecordingHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)

    try:
        result = review_with_agent(
            bundle,
            provider=provider,
            config=AgentReviewConfig(model="review-model"),
        )

        prompt = provider.requests[0].messages[1].content
        serialized = agent_review_to_json(result)
        assert secret not in prompt
        assert prompt.count("[REDACTED_PRIVATE_KEY_MATERIAL]") == 3
        assert secret not in serialized
        assert bundle.changes[0].hunks[0].lines[1].content == secret

        failing_provider = _RecordingProvider([LLMResponse(output_text=secret)])
        with pytest.raises(AgentReviewError) as exc_info:
            review_with_agent(
                bundle,
                provider=failing_provider,
                config=AgentReviewConfig(model="review-model"),
            )
    finally:
        root_logger.removeHandler(handler)

    assert exc_info.value.code is AgentReviewErrorCode.INVALID_MODEL_OUTPUT
    assert exc_info.value.node is AgentNode.PARSE_RESPONSE
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert secret not in "\n".join(record.getMessage() for record in handler.records)


@_PROPERTY_SETTINGS
@example(nonce=0)
@given(nonce=st.integers(min_value=0, max_value=2**128 - 1))
def test_mixed_valid_and_hallucinated_findings_fail_atomically(nonce: int) -> None:
    missing_path = f"missing/{nonce:032x}.py"
    bundle = _bundle(_added_text_change("src/existing.py", ("return wrong",)))
    output = _response(
        (
            _raw_finding(
                category="correctness",
                severity="medium",
                title="Valid sibling",
                references=(_raw_reference("src/existing.py"),),
            ),
            _raw_finding(
                category="security",
                severity="high",
                title="Hallucinated target",
                references=(_raw_reference(missing_path),),
            ),
        )
    )
    provider = _RecordingProvider([output])

    with pytest.raises(AgentReviewError) as exc_info:
        review_with_agent(
            bundle,
            provider=provider,
            config=AgentReviewConfig(model="review-model"),
        )

    assert exc_info.value.code is AgentReviewErrorCode.INVALID_MODEL_OUTPUT
    assert exc_info.value.node is AgentNode.PARSE_RESPONSE
    assert exc_info.value.attempt_count == 1
    assert missing_path not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert len(provider.requests) == 1
