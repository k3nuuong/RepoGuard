"""Deterministic 100-example properties for M6 canonical product contracts."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from repoguard._canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    parse_canonical_json,
)
from repoguard.evidence import (
    EvidenceBundle,
    RepositoryEvidence,
    RevisionEvidence,
)
from repoguard.product import (
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductOperation,
    ProductStage,
    build_product_review_result,
    product_envelope_from_json,
    product_envelope_to_json,
    product_error_message,
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

_PROPERTY_SETTINGS = settings(max_examples=100, derandomize=True, database=None, deadline=None)
_SAFE_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters="/\\"),
    min_size=1,
    max_size=40,
)
_JSON_SCALAR = st.none() | st.booleans() | st.integers() | _SAFE_TEXT
_JSON_OBJECTS = st.dictionaries(
    keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
    values=_JSON_SCALAR,
    max_size=12,
)


@_PROPERTY_SETTINGS
@given(value=_JSON_OBJECTS)
def test_canonical_json_round_trips_exact_generated_values(value: dict[str, object]) -> None:
    encoded = canonical_json_bytes(value)

    assert parse_canonical_json(encoded, max_bytes=4096) == value
    assert not encoded.endswith(b"\n")
    assert not encoded.startswith(b"\xef\xbb\xbf")


@_PROPERTY_SETTINGS
@given(value=_JSON_OBJECTS, whitespace=st.text(alphabet=" \t\r\n", min_size=1, max_size=8))
def test_any_trailing_json_whitespace_invalidates_canonical_input(
    value: dict[str, object],
    whitespace: str,
) -> None:
    encoded = canonical_json_bytes(value) + whitespace.encode("ascii")

    with pytest.raises(CanonicalJSONError):
        parse_canonical_json(encoded, max_bytes=4096)


@_PROPERTY_SETTINGS
@given(code=st.from_regex(r"[a-z][a-z0-9_]{0,30}", fullmatch=True), attempt=st.integers(0, 9))
def test_generated_error_envelopes_preserve_every_stable_field(
    code: str,
    attempt: int,
) -> None:
    error = ProductErrorRecord(
        domain=ProductErrorDomain.GITHUB,
        code=code,
        message=product_error_message(ProductErrorDomain.GITHUB),
        retryable=bool(attempt % 2),
        stage=ProductStage.TRANSPORT,
        state=None,
        session_id=None,
        proposal_sha256="a" * 64,
        attempt_count=attempt,
    )
    envelope = ProductEnvelope(
        schema_version=1,
        operation=ProductOperation.GITHUB_PUBLISH_CHECK,
        ok=False,
        result=None,
        error=error,
    )

    assert product_envelope_from_json(product_envelope_to_json(envelope).encode()) == envelope


@_PROPERTY_SETTINGS
@given(title=_SAFE_TEXT, line=st.integers(min_value=1, max_value=100_000))
def test_any_exact_m2_target_field_change_invalidates_target_id(title: str, line: int) -> None:
    repository = RepositoryEvidence(root=Path("/not/published"), object_format="sha1")
    revisions = RevisionEvidence(
        base_ref="base",
        head_ref="head",
        base_oid="a" * 40,
        head_oid="b" * 40,
        merge_base_oid="a" * 40,
    )
    bundle = EvidenceBundle(repository=repository, revisions=revisions, changes=())
    reference = EvidenceReference(
        path="src/value.py",
        side=EvidenceSide.NEW,
        oid="c" * 40,
        start_line=line,
        end_line=line,
    )
    finding = Finding(
        rule_id=RuleId.MERGE_CONFLICT_MARKER,
        category=FindingCategory.CORRECTNESS,
        severity=FindingSeverity.HIGH,
        title=title,
        message="message",
        remediation="remediation",
        references=(reference,),
    )
    review = ReviewResult(repository=repository, revisions=revisions, findings=(finding,))
    changed_finding = Finding(
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity,
        title=f"{title}!",
        message=finding.message,
        remediation=finding.remediation,
        references=finding.references,
    )
    changed_review = ReviewResult(
        repository=repository,
        revisions=revisions,
        findings=(changed_finding,),
    )

    result = build_product_review_result("repository", "deterministic", bundle, review)
    changed = build_product_review_result("repository", "deterministic", bundle, changed_review)
    target = result.findings[0].references[0].repair_target_id
    changed_target = changed.findings[0].references[0].repair_target_id

    assert target is not None
    assert changed_target is not None
    assert target != changed_target
    assert resolve_repair_target(result, review, target).reference_index == 0
