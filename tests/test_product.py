"""Focused tests for M6 product contracts and path-free review results."""

from dataclasses import replace
from pathlib import Path

import pytest

from repoguard._canonical import canonical_json_bytes
from repoguard.agent import (
    AgentFinding,
    AgentReviewResult,
    AgentRuleId,
    FindingSource,
    PromptIdentity,
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
from repoguard.product import (
    PRODUCT_ENVELOPE_MAX_BYTES,
    PRODUCT_RESULT_MAX_BYTES,
    ProductConclusion,
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductExitCode,
    ProductOperation,
    ProductStage,
    build_product_review_result,
    product_envelope_from_json,
    product_envelope_to_json,
    product_error_message,
    product_exit_code,
    product_review_from_json,
    product_review_to_json,
    resolve_repair_target,
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

_OID_A = "a" * 40
_OID_B = "b" * 40
_OID_C = "c" * 40


def _records(root: Path = Path("/private/owner/repository")) -> tuple[EvidenceBundle, ReviewResult]:
    repository = RepositoryEvidence(root=root, object_format="sha1")
    revisions = RevisionEvidence(
        base_ref="refs/pull/7/base",
        head_ref="refs/pull/7/head",
        base_oid=_OID_A,
        head_oid=_OID_B,
        merge_base_oid=_OID_A,
    )
    reference = EvidenceReference(
        path="src/example.py",
        side=EvidenceSide.NEW,
        oid=_OID_C,
        start_line=1,
        end_line=1,
    )
    finding = Finding(
        rule_id=RuleId.MERGE_CONFLICT_MARKER,
        category=FindingCategory.CORRECTNESS,
        severity=FindingSeverity.HIGH,
        title="Merge conflict marker",
        message="A committed conflict marker remains.",
        remediation="Resolve the conflict marker.",
        references=(reference,),
    )
    bundle = EvidenceBundle(
        repository=repository,
        revisions=revisions,
        changes=(
            FileChangeEvidence(
                change_type=ChangeType.MODIFIED,
                rename_similarity=None,
                old=FileVersion(
                    path="src/example.py",
                    mode="100644",
                    oid=_OID_A,
                    content_kind=ContentKind.TEXT,
                ),
                new=FileVersion(
                    path="src/example.py",
                    mode="100644",
                    oid=_OID_C,
                    content_kind=ContentKind.TEXT,
                ),
                hunks=(
                    DiffHunkEvidence(
                        old_start=1,
                        old_count=1,
                        new_start=1,
                        new_count=1,
                        lines=(
                            DiffLineEvidence(
                                kind=DiffLineKind.DELETION,
                                old_line_number=1,
                                new_line_number=None,
                                content="old",
                                has_trailing_newline=True,
                            ),
                            DiffLineEvidence(
                                kind=DiffLineKind.ADDITION,
                                old_line_number=None,
                                new_line_number=1,
                                content="<<<<<<< HEAD",
                                has_trailing_newline=True,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    return bundle, ReviewResult(
        repository=repository,
        revisions=revisions,
        findings=(finding,),
    )


def _agent_review(bundle: EvidenceBundle, deterministic: ReviewResult) -> AgentReviewResult:
    deterministic_finding = deterministic.findings[0]
    return AgentReviewResult(
        repository=bundle.repository,
        revisions=bundle.revisions,
        provider="openai",
        model="gpt-test",
        prompt=PromptIdentity(name="agent_review", version="v1", sha256="d" * 64),
        attempt_count=1,
        usage=None,
        prompt_bytes=100,
        response_bytes=100,
        findings=(
            AgentFinding(
                source=FindingSource.DETERMINISTIC,
                rule_id=deterministic_finding.rule_id,
                category=deterministic_finding.category,
                severity=deterministic_finding.severity,
                title=deterministic_finding.title,
                message=deterministic_finding.message,
                remediation=deterministic_finding.remediation,
                references=deterministic_finding.references,
            ),
            AgentFinding(
                source=FindingSource.AGENT,
                rule_id=AgentRuleId.AGENT_REASONING,
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.MEDIUM,
                title="Model observation",
                message="A bounded model-derived observation.",
                remediation="Inspect the referenced code.",
                references=deterministic_finding.references,
            ),
        ),
    )


def test_product_review_is_path_free_and_target_maps_to_exact_m2_reference() -> None:
    bundle, deterministic = _records()

    result = build_product_review_result(
        "repository",
        "deterministic",
        bundle,
        deterministic,
    )

    serialized = product_review_to_json(result)
    target_id = result.findings[0].references[0].repair_target_id
    assert "/private/owner/repository" not in serialized
    assert product_review_from_json(serialized.encode("utf-8")) == result
    assert target_id is not None
    assert resolve_repair_target(result, deterministic, target_id).finding_index == 0
    assert resolve_repair_target(result, deterministic, target_id).reference_index == 0
    assert result.finding_count == 1
    assert result.highest_severity is FindingSeverity.HIGH
    assert result.conclusion is ProductConclusion.FAILURE


def test_product_review_digests_ignore_absolute_root_but_bind_review_content() -> None:
    first_bundle, first_review = _records(Path("/one/repository"))
    second_bundle, second_review = _records(Path("/two/repository"))

    first = build_product_review_result("repository", "deterministic", first_bundle, first_review)
    second = build_product_review_result(
        "repository", "deterministic", second_bundle, second_review
    )
    changed_review = replace(
        first_review,
        findings=(
            replace(
                first_review.findings[0],
                message="A different deterministic message.",
            ),
        ),
    )
    changed = build_product_review_result(
        "repository", "deterministic", first_bundle, changed_review
    )

    assert first.evidence_sha256 == second.evidence_sha256
    assert first.deterministic_review_sha256 == second.deterministic_review_sha256
    assert first.review_sha256 == second.review_sha256
    assert changed.evidence_sha256 == first.evidence_sha256
    assert changed.deterministic_review_sha256 != first.deterministic_review_sha256
    assert changed.review_sha256 != first.review_sha256
    assert (
        len(
            {
                first.evidence_sha256,
                first.deterministic_review_sha256,
                first.review_sha256,
            }
        )
        == 3
    )


def test_model_finding_has_no_repair_target() -> None:
    bundle, deterministic = _records()
    result = build_product_review_result(
        "repository",
        "agent",
        bundle,
        deterministic,
        agent_review=_agent_review(bundle, deterministic),
    )

    deterministic_product = next(
        finding for finding in result.findings if finding.source is FindingSource.DETERMINISTIC
    )
    model_product = next(
        finding for finding in result.findings if finding.source is FindingSource.AGENT
    )
    assert deterministic_product.references[0].repair_target_id is not None
    assert model_product.references[0].repair_target_id is None


def test_target_id_fails_closed_for_review_or_result_mismatch() -> None:
    bundle, deterministic = _records()
    result = build_product_review_result("repository", "deterministic", bundle, deterministic)
    target_id = result.findings[0].references[0].repair_target_id
    assert target_id is not None
    changed = replace(
        deterministic,
        findings=(replace(deterministic.findings[0], title="Changed title"),),
    )

    with pytest.raises(ValueError, match="identity mismatch"):
        resolve_repair_target(result, changed, target_id)
    with pytest.raises(ValueError, match="repair target is invalid"):
        resolve_repair_target(result, deterministic, "0" * 64)


def test_envelope_round_trip_is_canonical_and_complete() -> None:
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.REVIEW_RUN,
        ok=True,
        result={"z": 1, "a": "value"},
        error=None,
    )

    serialized = product_envelope_to_json(envelope)

    assert serialized == (
        '{"error":null,"ok":true,"operation":"review.run",'
        '"result":{"a":"value","z":1},"schema_version":1}'
    )
    assert product_envelope_from_json(serialized.encode()) == envelope


def test_failed_envelope_requires_fixed_domain_message_and_all_error_fields() -> None:
    error = ProductErrorRecord(
        domain=ProductErrorDomain.REPAIR,
        code="validation_failed",
        message=product_error_message(ProductErrorDomain.REPAIR),
        retryable=False,
        stage=ProductStage.VALIDATION,
        state="validated",
        session_id="1" * 64,
        proposal_sha256=None,
        attempt_count=1,
    )
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.REPAIR_PREPARE,
        ok=False,
        result=None,
        error=error,
    )

    assert product_envelope_from_json(product_envelope_to_json(envelope).encode()) == envelope
    with pytest.raises(ValueError, match="error message"):
        replace(error, message="native path /secret leaked")


@pytest.mark.parametrize(
    "mutation",
    [
        b'{"error":null,"ok":true,"operation":"review.run","result":{},"schema_version":1}\n',
        b'{"error":null,"ok":true,"operation":"review.run","result":{"x":NaN},"schema_version":1}',
        b'{"error":null,"ok":true,"operation":"review.run","operation":"review.run","result":{},"schema_version":1}',
        b'{"error":null,"extra":0,"ok":true,"operation":"review.run","result":{},"schema_version":1}',
        b'\xef\xbb\xbf{"error":null,"ok":true,"operation":"review.run","result":{},"schema_version":1}',
    ],
)
def test_envelope_parser_rejects_noncanonical_or_unknown_data(mutation: bytes) -> None:
    with pytest.raises(ValueError, match="product envelope is invalid"):
        product_envelope_from_json(mutation)


def test_envelope_accepts_exact_four_mib_result_and_rejects_one_byte_more() -> None:
    empty_result = {"payload": ""}
    payload_size = PRODUCT_RESULT_MAX_BYTES - len(canonical_json_bytes(empty_result))
    result: dict[str, object] = {"payload": "x" * payload_size}
    assert len(canonical_json_bytes(result)) == PRODUCT_RESULT_MAX_BYTES
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.REVIEW_RUN,
        ok=True,
        result=result,
        error=None,
    )

    rendered = product_envelope_to_json(envelope)

    assert len(rendered.encode("utf-8")) > PRODUCT_RESULT_MAX_BYTES
    assert len(rendered.encode("utf-8")) <= PRODUCT_ENVELOPE_MAX_BYTES
    assert product_envelope_from_json(rendered.encode("utf-8")) == envelope

    over_limit = replace(envelope, result={"payload": f"{result['payload']}x"})
    with pytest.raises(ValueError, match="result limit exceeded"):
        product_envelope_to_json(over_limit)


def test_product_result_rejects_absolute_reference_path() -> None:
    bundle, deterministic = _records()
    bad_reference = replace(deterministic.findings[0].references[0], path="/host/private.py")
    bad_review = replace(
        deterministic,
        findings=(replace(deterministic.findings[0], references=(bad_reference,)),),
    )

    with pytest.raises(ValueError, match="repository path"):
        build_product_review_result("repository", "deterministic", bundle, bad_review)


@pytest.mark.parametrize(
    ("domain", "code", "retryable", "expected"),
    [
        (ProductErrorDomain.PROFILE, "invalid_profile", False, ProductExitCode.PROFILE_OR_REQUEST),
        (ProductErrorDomain.REPAIR, "invalid_state", False, ProductExitCode.BUSINESS_FAILURE),
        (ProductErrorDomain.REPAIR, "approval_required", False, ProductExitCode.AUTH_OR_APPROVAL),
        (ProductErrorDomain.REPAIR, "ref_conflict", False, ProductExitCode.STALE_OR_CONFLICT),
        (
            ProductErrorDomain.REPAIR,
            "sandbox_unavailable",
            False,
            ProductExitCode.CAPABILITY_UNAVAILABLE,
        ),
        (ProductErrorDomain.INTERNAL, "internal", False, ProductExitCode.INTERNAL),
        (ProductErrorDomain.GITHUB, "transport", True, ProductExitCode.RETRYABLE),
    ],
)
def test_failed_envelope_exit_mapping_is_stable(
    domain: ProductErrorDomain,
    code: str,
    retryable: bool,
    expected: ProductExitCode,
) -> None:
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.REPAIR_PREPARE,
        ok=False,
        result=None,
        error=ProductErrorRecord(
            domain=domain,
            code=code,
            message=product_error_message(domain),
            retryable=retryable,
            stage=ProductStage.INPUT,
            state=None,
            session_id=None,
            proposal_sha256=None,
            attempt_count=0,
        ),
    )

    assert product_exit_code(envelope) is expected


@pytest.mark.parametrize(
    "result",
    [
        {"policy_passed": False},
        {"validation_success": False},
        {"conclusion": "failure"},
    ],
)
def test_normal_policy_or_validation_failure_uses_exit_six(result: dict[str, object]) -> None:
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.REVIEW_RUN,
        ok=True,
        result=result,
        error=None,
    )

    assert product_exit_code(envelope) is ProductExitCode.POLICY_OR_VALIDATION
