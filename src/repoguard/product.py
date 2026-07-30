"""Public M6 product contracts and path-free review projection."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import cast

from repoguard._canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_json_text,
    domain_sha256,
    parse_canonical_json,
    require_exact_keys,
)
from repoguard.agent import AgentFinding, AgentReviewResult, FindingSource
from repoguard.evidence import EvidenceBundle, evidence_to_dict
from repoguard.host_profile import HostProfile
from repoguard.repair import RepairTarget
from repoguard.retrieval_agent import RetrievalAgentReviewResult
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReviewResult,
    RuleId,
    review_to_dict,
)

__all__ = [
    "PRODUCT_ENVELOPE_MAX_BYTES",
    "PRODUCT_RESULT_MAX_BYTES",
    "ProductConclusion",
    "ProductEnvelope",
    "ProductErrorDomain",
    "ProductErrorRecord",
    "ProductExitCode",
    "ProductFinding",
    "ProductInterface",
    "ProductOperation",
    "ProductOrchestrator",
    "ProductReference",
    "ProductReviewResult",
    "ProductStage",
    "build_product_review_result",
    "product_envelope_from_json",
    "product_envelope_to_dict",
    "product_envelope_to_json",
    "product_error_message",
    "product_exit_code",
    "product_review_from_json",
    "product_review_to_dict",
    "product_review_to_json",
    "profile_validate",
    "resolve_repair_target",
]

PRODUCT_RESULT_MAX_BYTES = 4 * 1024 * 1024
PRODUCT_ENVELOPE_MAX_BYTES = PRODUCT_RESULT_MAX_BYTES + 4 * 1024
_MAX_FINDINGS = 1_000
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_STATE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

_EVIDENCE_DOMAIN = "repoguard.m6.evidence.v1"
_DETERMINISTIC_REVIEW_DOMAIN = "repoguard.m6.deterministic_review.v1"
_REVIEW_DOMAIN = "repoguard.m6.review.v1"
_REPAIR_TARGET_DOMAIN = "repoguard.m6.repair_target.v1"


class ProductOperation(StrEnum):
    """Stable product operation names shared by CLI, Actions, and MCP."""

    PROFILE_VALIDATE = "profile.validate"
    REVIEW_RUN = "review.run"
    REPAIR_PREPARE = "repair.prepare"
    REPAIR_STATUS = "repair.status"
    REPAIR_PREVIEW = "repair.preview"
    REPAIR_APPROVE_LOCAL = "repair.approve_local"
    REPAIR_APPLY_LOCAL = "repair.apply_local"
    REPAIR_REJECT = "repair.reject"
    REPAIR_CANCEL = "repair.cancel"
    REPAIR_EXPIRE = "repair.expire"
    REPAIR_RECOVER = "repair.recover"
    REPAIR_CLEANUP = "repair.cleanup"
    GITHUB_PUBLICATION_STATUS = "github.publication.status"
    GITHUB_PUBLICATION_RECOVER = "github.publication.recover"
    GITHUB_PUBLISH_CHECK = "github.publish_check"
    GITHUB_PUBLISH_REPAIR = "github.publish_repair"
    MCP_SERVE = "mcp.serve"


class ProductInterface(StrEnum):
    """Trusted adapter provenance recorded in GitHub proposal and approval identities."""

    ACTION = "action"
    CLI = "cli"
    MCP = "mcp"


class ProductErrorDomain(StrEnum):
    """Owner of one stable product error code."""

    CLI = "cli"
    PROFILE = "profile"
    EVIDENCE = "evidence"
    REVIEW = "review"
    PROVIDER = "provider"
    RETRIEVAL = "retrieval"
    REPAIR = "repair"
    GITHUB = "github"
    GITHUB_PUBLICATION = "github_publication"
    GITHUB_TRANSPORT = "github_transport"
    GITHUB_STORE = "github_store"
    MCP = "mcp"
    INTERNAL = "internal"


class ProductStage(StrEnum):
    """Stable stage at which a product operation stopped."""

    INPUT = "input"
    PROFILE = "profile"
    EVIDENCE = "evidence"
    REVIEW = "review"
    VALIDATE = "validate"
    DETERMINISTIC_REVIEW = "deterministic_review"
    BUILD_PROMPT = "build_prompt"
    INVOKE_PROVIDER = "invoke_provider"
    PARSE_RESPONSE = "parse_response"
    MERGE_FINDINGS = "merge_findings"
    FINALIZE = "finalize"
    RETRIEVAL = "retrieval"
    RETRIEVE_CONTEXT = "retrieve_context"
    SESSION = "session"
    MATERIALIZATION = "materialization"
    GENERATION = "generation"
    PROMPT = "prompt"
    PROVIDER = "provider"
    PATCH = "patch"
    SANDBOX = "sandbox"
    VALIDATION = "validation"
    APPROVAL = "approval"
    APPLICATION = "application"
    PERSISTENCE = "persistence"
    PROPOSAL = "proposal"
    PUBLICATION = "publication"
    TRANSPORT = "transport"
    RECOVERY = "recovery"
    CLEANUP = "cleanup"
    INTERNAL = "internal"


class ProductConclusion(StrEnum):
    """Policy conclusion for a completed review."""

    SUCCESS = "success"
    NEUTRAL = "neutral"
    FAILURE = "failure"


class ProductExitCode(IntEnum):
    """Stable process exit statuses for parsed product operations."""

    SUCCESS = 0
    SYNTAX = 2
    PROFILE_OR_REQUEST = 3
    BUSINESS_FAILURE = 4
    AUTH_OR_APPROVAL = 5
    POLICY_OR_VALIDATION = 6
    STALE_OR_CONFLICT = 7
    CAPABILITY_UNAVAILABLE = 8
    INTERNAL = 70
    RETRYABLE = 75


_ERROR_MESSAGES = {
    ProductErrorDomain.CLI: "product request is invalid",
    ProductErrorDomain.PROFILE: "product profile is invalid",
    ProductErrorDomain.EVIDENCE: "evidence collection failed",
    ProductErrorDomain.REVIEW: "review failed",
    ProductErrorDomain.PROVIDER: "provider request failed",
    ProductErrorDomain.RETRIEVAL: "context retrieval failed",
    ProductErrorDomain.REPAIR: "repair operation failed",
    ProductErrorDomain.GITHUB: "GitHub operation failed",
    ProductErrorDomain.GITHUB_PUBLICATION: "GitHub publication failed",
    ProductErrorDomain.GITHUB_TRANSPORT: "GitHub transport failed",
    ProductErrorDomain.GITHUB_STORE: "GitHub publication state failed",
    ProductErrorDomain.MCP: "MCP operation failed",
    ProductErrorDomain.INTERNAL: "internal product failure",
}

_AUTH_OR_APPROVAL_CODES = {
    "authentication_failed",
    "forbidden",
    "permission_denied",
    "provider_authentication",
    "provider_authentication_failed",
    "provider_permission",
    "approval_required",
    "invalid_confirmation",
    "principal_mismatch",
}
_STALE_OR_CONFLICT_CODES = {
    "approval_mismatch",
    "artifact_mismatch",
    "conflict",
    "cas_conflict",
    "head_changed",
    "pull_request_stale",
    "proposal_mismatch",
    "proposal_expired",
    "ref_conflict",
    "remote_conflict",
    "remote_invalid",
    "repository_mismatch",
    "stale",
    "state_conflict",
    "validation_failed",
}
_CAPABILITY_CODES = {
    "capability_unavailable",
    "elicitation_unavailable",
    "fork_unsupported",
    "git_unavailable",
    "image_unavailable",
    "sandbox_unavailable",
    "unsupported_platform",
}


@dataclass(frozen=True, slots=True)
class ProductErrorRecord:
    """Content-free schema-1 error carried by every product interface."""

    domain: ProductErrorDomain
    code: str
    message: str
    retryable: bool
    stage: ProductStage
    state: str | None
    session_id: str | None
    proposal_sha256: str | None
    attempt_count: int

    def __post_init__(self) -> None:
        if type(self.domain) is not ProductErrorDomain:
            raise ValueError("error domain is invalid")
        if type(self.code) is not str or _CODE_PATTERN.fullmatch(self.code) is None:
            raise ValueError("error code is invalid")
        if type(self.message) is not str or self.message != _ERROR_MESSAGES[self.domain]:
            raise ValueError("error message is invalid")
        if type(self.retryable) is not bool:
            raise ValueError("error retryable flag is invalid")
        if type(self.stage) is not ProductStage:
            raise ValueError("error stage is invalid")
        if self.state is not None and (
            type(self.state) is not str or _STATE_PATTERN.fullmatch(self.state) is None
        ):
            raise ValueError("error state is invalid")
        _require_optional_sha256(self.session_id, "session_id")
        _require_optional_sha256(self.proposal_sha256, "proposal_sha256")
        if type(self.attempt_count) is not int or self.attempt_count < 0:
            raise ValueError("error attempt count is invalid")


@dataclass(frozen=True, slots=True)
class ProductEnvelope:
    """One canonical schema-1 operation result."""

    schema_version: int
    operation: ProductOperation
    ok: bool
    result: dict[str, object] | None
    error: ProductErrorRecord | None

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        if type(self.operation) is not ProductOperation:
            raise ValueError("operation is invalid")
        if type(self.ok) is not bool:
            raise ValueError("ok is invalid")
        if self.ok:
            if type(self.result) is not dict or self.error is not None:
                raise ValueError("successful envelope fields are invalid")
        elif self.result is not None or type(self.error) is not ProductErrorRecord:
            raise ValueError("failed envelope fields are invalid")
        canonical_json_bytes(self.result)


@dataclass(frozen=True, slots=True)
class ProductReference:
    """Path-free-host evidence reference with an optional deterministic repair target."""

    path: str
    side: EvidenceSide
    oid: str
    start_line: int | None
    end_line: int | None
    repair_target_id: str | None

    def __post_init__(self) -> None:
        _require_repository_path(self.path)
        if type(self.side) is not EvidenceSide:
            raise ValueError("reference side is invalid")
        if type(self.oid) is not str or _OID_PATTERN.fullmatch(self.oid) is None:
            raise ValueError("reference object ID is invalid")
        if not (
            (self.start_line is None and self.end_line is None)
            or (
                type(self.start_line) is int
                and type(self.end_line) is int
                and 1 <= self.start_line <= self.end_line
            )
        ):
            raise ValueError("reference line range is invalid")
        _require_optional_sha256(self.repair_target_id, "repair_target_id")


@dataclass(frozen=True, slots=True)
class ProductFinding:
    """Unified deterministic or model finding for product consumers."""

    source: FindingSource
    rule_id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    message: str
    remediation: str
    references: tuple[ProductReference, ...]

    def __post_init__(self) -> None:
        if type(self.source) is not FindingSource:
            raise ValueError("finding source is invalid")
        _require_text(self.rule_id, "finding rule ID", max_bytes=128)
        if type(self.category) is not FindingCategory:
            raise ValueError("finding category is invalid")
        if type(self.severity) is not FindingSeverity:
            raise ValueError("finding severity is invalid")
        _require_text(self.title, "finding title", max_bytes=1_000)
        _require_text(self.message, "finding message", max_bytes=8_192)
        _require_text(self.remediation, "finding remediation", max_bytes=8_192)
        if type(self.references) is not tuple or not self.references:
            raise ValueError("finding references are invalid")
        if any(type(reference) is not ProductReference for reference in self.references):
            raise ValueError("finding references are invalid")
        if self.source is FindingSource.AGENT and any(
            reference.repair_target_id is not None for reference in self.references
        ):
            raise ValueError("model findings cannot be repair targets")


@dataclass(frozen=True, slots=True)
class ProductReviewResult:
    """Canonical path-free product result for one exact review."""

    schema_version: int
    repository_alias: str
    object_format: str
    base_ref: str
    head_ref: str
    base_oid: str
    head_oid: str
    merge_base_oid: str
    review_profile: str
    provider: str | None
    model: str | None
    evidence_sha256: str
    deterministic_review_sha256: str
    review_sha256: str
    findings: tuple[ProductFinding, ...]
    finding_count: int
    highest_severity: FindingSeverity | None
    conclusion: ProductConclusion

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_alias(self.repository_alias, "repository alias")
        if self.object_format not in ("sha1", "sha256"):
            raise ValueError("object format is invalid")
        for name in ("base_ref", "head_ref"):
            _require_text(getattr(self, name), name, max_bytes=1_024)
        oid_length = 40 if self.object_format == "sha1" else 64
        for name in ("base_oid", "head_oid", "merge_base_oid"):
            value = getattr(self, name)
            if type(value) is not str or re.fullmatch(f"[0-9a-f]{{{oid_length}}}", value) is None:
                raise ValueError(f"{name} is invalid")
        _require_alias(self.review_profile, "review profile")
        if (self.provider is None) != (self.model is None):
            raise ValueError("provider and model must both be set or both be null")
        if self.provider is not None:
            _require_text(self.provider, "provider", max_bytes=64)
            _require_text(cast(str, self.model), "model", max_bytes=256)
        for name in ("evidence_sha256", "deterministic_review_sha256", "review_sha256"):
            _require_sha256(getattr(self, name), name)
        if type(self.findings) is not tuple or len(self.findings) > _MAX_FINDINGS:
            raise ValueError("product findings are invalid")
        if any(type(finding) is not ProductFinding for finding in self.findings):
            raise ValueError("product findings are invalid")
        if type(self.finding_count) is not int or self.finding_count != len(self.findings):
            raise ValueError("finding count is invalid")
        expected_highest = _highest_severity(self.findings)
        if self.highest_severity is not expected_highest:
            raise ValueError("highest severity is invalid")
        if type(self.conclusion) is not ProductConclusion:
            raise ValueError("review conclusion is invalid")
        target_ids = [
            reference.repair_target_id
            for finding in self.findings
            for reference in finding.references
            if reference.repair_target_id is not None
        ]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("repair target IDs are not unique")


class ProductOrchestrator:
    """Shared product workflow used by every stateful interface adapter."""

    __slots__ = ("_interface", "_profile")

    def __init__(
        self,
        profile: HostProfile,
        *,
        interface: ProductInterface = ProductInterface.CLI,
    ) -> None:
        if type(profile) is not HostProfile:
            raise TypeError("profile must be an exact HostProfile")
        if type(interface) is not ProductInterface:
            raise TypeError("interface must be an exact ProductInterface")
        self._profile = profile
        self._interface = interface

    def review_run(
        self,
        *,
        repository: str,
        base_ref: str,
        head_ref: str,
        review_profile: str,
        github_pr: int | None = None,
    ) -> ProductEnvelope:
        """Run one bounded product review."""
        from repoguard._product import _review_run

        return _review_run(
            self._profile,
            interface=self._interface,
            repository=repository,
            base_ref=base_ref,
            head_ref=head_ref,
            review_profile=review_profile,
            github_pr=github_pr,
        )

    def repair_prepare(
        self,
        *,
        repository: str,
        base_ref: str,
        head_ref: str,
        repair_profile: str,
        target_ids: tuple[str, ...],
        allowed_paths: tuple[str, ...],
        github_pr: int | None = None,
    ) -> ProductEnvelope:
        """Collect, resolve, propose, validate, and preview one repair in-process."""
        from repoguard._product import _repair_prepare

        return _repair_prepare(
            self._profile,
            interface=self._interface,
            repository=repository,
            base_ref=base_ref,
            head_ref=head_ref,
            repair_profile=repair_profile,
            target_ids=target_ids,
            allowed_paths=allowed_paths,
            github_pr=github_pr,
        )

    def repair_status(self, *, repository: str, session_id: str) -> ProductEnvelope:
        """Read one durable local repair snapshot."""
        from repoguard._product import _repair_status

        return _repair_status(self._profile, repository=repository, session_id=session_id)

    def repair_preview(self, *, repository: str, session_id: str) -> ProductEnvelope:
        """Read one secret-redacted durable repair preview."""
        from repoguard._product import _repair_preview

        return _repair_preview(self._profile, repository=repository, session_id=session_id)

    def repair_approve_local(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        validation_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        """Record one exact local M5 approval."""
        from repoguard._product import _repair_approve_local

        return _repair_approve_local(
            self._profile,
            repository=repository,
            session_id=session_id,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
            confirmation=confirmation,
        )

    def repair_apply_local(
        self,
        *,
        repository: str,
        session_id: str,
        approval_sha256: str,
    ) -> ProductEnvelope:
        """Apply one exact local approval only to the M5 dedicated ref."""
        from repoguard._product import _repair_apply_local

        return _repair_apply_local(
            self._profile,
            repository=repository,
            session_id=session_id,
            approval_sha256=approval_sha256,
        )

    def repair_approve_and_apply_local(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        validation_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        """Approve and apply one exact local repair after an interactive confirmation."""
        from repoguard._product import _repair_approve_and_apply_local

        return _repair_approve_and_apply_local(
            self._profile,
            repository=repository,
            session_id=session_id,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
            confirmation=confirmation,
        )

    def repair_reject(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        reason: str,
    ) -> ProductEnvelope:
        """Reject one exact local candidate."""
        from repoguard._product import _repair_reject

        return _repair_reject(
            self._profile,
            repository=repository,
            session_id=session_id,
            candidate_id=candidate_id,
            reason=reason,
        )

    def repair_cancel(
        self,
        *,
        repository: str,
        session_id: str,
        reason: str = "",
    ) -> ProductEnvelope:
        """Cancel one nonterminal local repair session."""
        from repoguard._product import _repair_cancel

        return _repair_cancel(
            self._profile,
            repository=repository,
            session_id=session_id,
            reason=reason,
        )

    def repair_expire(self, *, repository: str, session_id: str) -> ProductEnvelope:
        """Expire one nonterminal local repair session."""
        from repoguard._product import _repair_expire

        return _repair_expire(self._profile, repository=repository, session_id=session_id)

    def repair_recover(self, *, repository: str) -> ProductEnvelope:
        """Recover interrupted sessions for one repository."""
        from repoguard._product import _repair_recover

        return _repair_recover(self._profile, repository=repository)

    def repair_cleanup(self, *, repository: str) -> ProductEnvelope:
        """Clean terminal private data and expired audit records."""
        from repoguard._product import _repair_cleanup

        return _repair_cleanup(self._profile, repository=repository)

    def github_publication_status(
        self,
        *,
        repository: str,
        proposal_sha256: str,
    ) -> ProductEnvelope:
        """Read durable publication state without contacting GitHub."""
        from repoguard._product import _github_publication_status

        return _github_publication_status(
            self._profile,
            repository=repository,
            proposal_sha256=proposal_sha256,
        )

    def github_publication_recover(
        self,
        *,
        repository: str,
        proposal_sha256: str,
    ) -> ProductEnvelope:
        """Recover one exact partial repair publication under its saved approval."""
        from repoguard._product import _github_publication_recover

        return _github_publication_recover(
            self._profile,
            interface=self._interface,
            repository=repository,
            proposal_sha256=proposal_sha256,
        )

    def github_publish_check(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        """Approve and publish one exact Check proposal."""
        from repoguard._product import _github_publish_check

        return _github_publish_check(
            self._profile,
            interface=self._interface,
            repository=repository,
            proposal_sha256=proposal_sha256,
            confirmation=confirmation,
        )

    def github_publish_repair(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        """Approve and publish one exact repair proposal."""
        from repoguard._product import _github_publish_repair

        return _github_publish_repair(
            self._profile,
            interface=self._interface,
            repository=repository,
            proposal_sha256=proposal_sha256,
            confirmation=confirmation,
        )


def profile_validate(path: Path) -> ProductEnvelope:
    """Validate an owner-only host profile without exposing host paths."""
    from repoguard._product import _profile_validate

    return _profile_validate(path)


def build_product_review_result(
    repository_alias: str,
    review_profile: str,
    bundle: EvidenceBundle,
    deterministic_review: ReviewResult,
    *,
    agent_review: AgentReviewResult | RetrievalAgentReviewResult | None = None,
    fail_on: FindingSeverity = FindingSeverity.HIGH,
) -> ProductReviewResult:
    """Build one bounded path-free product result from exact public M1-M3 records."""
    _require_alias(repository_alias, "repository alias")
    _require_alias(review_profile, "review profile")
    if type(bundle) is not EvidenceBundle or type(deterministic_review) is not ReviewResult:
        raise TypeError("bundle and deterministic review must be exact public records")
    if agent_review is not None and type(agent_review) not in (
        AgentReviewResult,
        RetrievalAgentReviewResult,
    ):
        raise TypeError("agent review must be an exact public Agent result")
    if type(fail_on) is not FindingSeverity:
        raise TypeError("fail_on must be a FindingSeverity")
    if (
        deterministic_review.repository != bundle.repository
        or deterministic_review.revisions != bundle.revisions
    ):
        raise ValueError("deterministic review identity does not match evidence")
    if agent_review is not None and (
        agent_review.repository != bundle.repository or agent_review.revisions != bundle.revisions
    ):
        raise ValueError("agent review identity does not match evidence")

    evidence_projection = _path_free_evidence_projection(bundle)
    deterministic_projection = _path_free_review_projection(deterministic_review)
    evidence_sha256 = domain_sha256(_EVIDENCE_DOMAIN, evidence_projection)
    deterministic_sha256 = domain_sha256(_DETERMINISTIC_REVIEW_DOMAIN, deterministic_projection)
    findings = _build_product_findings(
        deterministic_review,
        agent_review,
        evidence_sha256=evidence_sha256,
        deterministic_review_sha256=deterministic_sha256,
    )
    if len(findings) > _MAX_FINDINGS:
        raise ValueError("product finding limit exceeded")
    provider = None if agent_review is None else agent_review.provider
    model = None if agent_review is None else agent_review.model
    review_projection: dict[str, object] = {
        "schema_version": 1,
        "repository_alias": repository_alias,
        "object_format": bundle.repository.object_format,
        "base_ref": bundle.revisions.base_ref,
        "head_ref": bundle.revisions.head_ref,
        "base_oid": bundle.revisions.base_oid,
        "head_oid": bundle.revisions.head_oid,
        "merge_base_oid": bundle.revisions.merge_base_oid,
        "review_profile": review_profile,
        "provider": provider,
        "model": model,
        "evidence_sha256": evidence_sha256,
        "deterministic_review_sha256": deterministic_sha256,
        "findings": [_product_finding_to_dict(finding) for finding in findings],
    }
    review_sha256 = domain_sha256(_REVIEW_DOMAIN, review_projection)
    highest = _highest_severity(findings)
    conclusion = (
        ProductConclusion.FAILURE
        if highest is not None and _SEVERITY_RANK[highest] >= _SEVERITY_RANK[fail_on]
        else ProductConclusion.SUCCESS
    )
    result = ProductReviewResult(
        schema_version=1,
        repository_alias=repository_alias,
        object_format=bundle.repository.object_format,
        base_ref=bundle.revisions.base_ref,
        head_ref=bundle.revisions.head_ref,
        base_oid=bundle.revisions.base_oid,
        head_oid=bundle.revisions.head_oid,
        merge_base_oid=bundle.revisions.merge_base_oid,
        review_profile=review_profile,
        provider=provider,
        model=model,
        evidence_sha256=evidence_sha256,
        deterministic_review_sha256=deterministic_sha256,
        review_sha256=review_sha256,
        findings=findings,
        finding_count=len(findings),
        highest_severity=highest,
        conclusion=conclusion,
    )
    if len(product_review_to_json(result).encode("utf-8")) > PRODUCT_RESULT_MAX_BYTES:
        raise ValueError("product review result limit exceeded")
    return result


def resolve_repair_target(
    result: ProductReviewResult,
    deterministic_review: ReviewResult,
    repair_target_id: str,
) -> RepairTarget:
    """Map one authenticated M6 target ID back to exact M2 coordinates."""
    if type(result) is not ProductReviewResult or type(deterministic_review) is not ReviewResult:
        raise TypeError("result and deterministic review must be exact public records")
    _require_sha256(repair_target_id, "repair_target_id")
    deterministic_sha256 = domain_sha256(
        _DETERMINISTIC_REVIEW_DOMAIN,
        _path_free_review_projection(deterministic_review),
    )
    if deterministic_sha256 != result.deterministic_review_sha256:
        raise ValueError("deterministic review identity mismatch")
    available_ids = {
        reference.repair_target_id
        for finding in result.findings
        for reference in finding.references
        if finding.source is FindingSource.DETERMINISTIC
    }
    for finding_index, finding in enumerate(deterministic_review.findings):
        for reference_index, reference in enumerate(finding.references):
            expected = _repair_target_id(
                evidence_sha256=result.evidence_sha256,
                deterministic_review_sha256=deterministic_sha256,
                finding_index=finding_index,
                reference_index=reference_index,
                finding=finding,
                reference=reference,
            )
            if expected == repair_target_id and expected in available_ids:
                return RepairTarget(
                    finding_index=finding_index,
                    reference_index=reference_index,
                )
    raise ValueError("repair target is invalid")


def product_review_to_dict(result: ProductReviewResult) -> dict[str, object]:
    """Return the strict path-free product review mapping."""
    if type(result) is not ProductReviewResult:
        raise TypeError("result must be an exact ProductReviewResult")
    return {
        "schema_version": result.schema_version,
        "repository_alias": result.repository_alias,
        "object_format": result.object_format,
        "base_ref": result.base_ref,
        "head_ref": result.head_ref,
        "base_oid": result.base_oid,
        "head_oid": result.head_oid,
        "merge_base_oid": result.merge_base_oid,
        "review_profile": result.review_profile,
        "provider": result.provider,
        "model": result.model,
        "evidence_sha256": result.evidence_sha256,
        "deterministic_review_sha256": result.deterministic_review_sha256,
        "review_sha256": result.review_sha256,
        "findings": [_product_finding_to_dict(finding) for finding in result.findings],
        "finding_count": result.finding_count,
        "highest_severity": (
            None if result.highest_severity is None else result.highest_severity.value
        ),
        "conclusion": result.conclusion.value,
    }


def product_review_to_json(result: ProductReviewResult) -> str:
    """Serialize a product review as canonical UTF-8 JSON without a newline."""
    encoded = canonical_json_text(product_review_to_dict(result))
    if len(encoded.encode("utf-8")) > PRODUCT_RESULT_MAX_BYTES:
        raise ValueError("product review result limit exceeded")
    return encoded


def product_review_from_json(raw: bytes) -> ProductReviewResult:
    """Parse one exact canonical path-free product review result."""
    try:
        decoded = parse_canonical_json(raw, max_bytes=PRODUCT_RESULT_MAX_BYTES)
        if type(decoded) is not dict:
            raise ValueError("product review must be an object")
        require_exact_keys(
            decoded,
            (
                "schema_version",
                "repository_alias",
                "object_format",
                "base_ref",
                "head_ref",
                "base_oid",
                "head_oid",
                "merge_base_oid",
                "review_profile",
                "provider",
                "model",
                "evidence_sha256",
                "deterministic_review_sha256",
                "review_sha256",
                "findings",
                "finding_count",
                "highest_severity",
                "conclusion",
            ),
            name="product review",
        )
        findings_value = decoded["findings"]
        if type(findings_value) is not list:
            raise ValueError("product findings must be an array")
        provider_value = decoded["provider"]
        model_value = decoded["model"]
        highest_value = decoded["highest_severity"]
        return ProductReviewResult(
            schema_version=_exact_int(decoded["schema_version"]),
            repository_alias=_exact_str(decoded["repository_alias"]),
            object_format=_exact_str(decoded["object_format"]),
            base_ref=_exact_str(decoded["base_ref"]),
            head_ref=_exact_str(decoded["head_ref"]),
            base_oid=_exact_str(decoded["base_oid"]),
            head_oid=_exact_str(decoded["head_oid"]),
            merge_base_oid=_exact_str(decoded["merge_base_oid"]),
            review_profile=_exact_str(decoded["review_profile"]),
            provider=None if provider_value is None else _exact_str(provider_value),
            model=None if model_value is None else _exact_str(model_value),
            evidence_sha256=_exact_str(decoded["evidence_sha256"]),
            deterministic_review_sha256=_exact_str(decoded["deterministic_review_sha256"]),
            review_sha256=_exact_str(decoded["review_sha256"]),
            findings=tuple(_product_finding_from_dict(value) for value in findings_value),
            finding_count=_exact_int(decoded["finding_count"]),
            highest_severity=(
                None if highest_value is None else FindingSeverity(_exact_str(highest_value))
            ),
            conclusion=ProductConclusion(_exact_str(decoded["conclusion"])),
        )
    except (CanonicalJSONError, KeyError, TypeError, ValueError) as error:
        raise ValueError("product review result is invalid") from error


def product_envelope_to_dict(envelope: ProductEnvelope) -> dict[str, object]:
    """Return the exact schema-1 product envelope mapping."""
    if type(envelope) is not ProductEnvelope:
        raise TypeError("envelope must be an exact ProductEnvelope")
    return {
        "schema_version": envelope.schema_version,
        "operation": envelope.operation.value,
        "ok": envelope.ok,
        "result": envelope.result,
        "error": None if envelope.error is None else _error_to_dict(envelope.error),
    }


def product_envelope_to_json(envelope: ProductEnvelope) -> str:
    """Serialize an envelope as canonical UTF-8 JSON without a newline."""
    mapping = product_envelope_to_dict(envelope)
    if mapping["result"] is not None and (
        len(canonical_json_bytes(mapping["result"])) > PRODUCT_RESULT_MAX_BYTES
    ):
        raise ValueError("product envelope result limit exceeded")
    encoded = canonical_json_text(mapping)
    if len(encoded.encode("utf-8")) > PRODUCT_ENVELOPE_MAX_BYTES:
        raise ValueError("product envelope wire limit exceeded")
    return encoded


def product_envelope_from_json(raw: bytes) -> ProductEnvelope:
    """Parse an exact canonical schema-1 product envelope."""
    try:
        decoded = parse_canonical_json(raw, max_bytes=PRODUCT_ENVELOPE_MAX_BYTES)
        if type(decoded) is not dict:
            raise ValueError("product envelope must be an object")
        require_exact_keys(
            decoded,
            ("schema_version", "operation", "ok", "result", "error"),
            name="product envelope",
        )
        operation_value = decoded["operation"]
        if type(operation_value) is not str:
            raise ValueError("product operation must be a string")
        operation = ProductOperation(operation_value)
        error_value = decoded["error"]
        error = None if error_value is None else _error_from_dict(error_value)
        result_value = decoded["result"]
        if result_value is not None and type(result_value) is not dict:
            raise ValueError("product result must be an object or null")
        if result_value is not None and (
            len(canonical_json_bytes(result_value)) > PRODUCT_RESULT_MAX_BYTES
        ):
            raise ValueError("product result exceeds its bound")
        return ProductEnvelope(
            schema_version=cast(int, decoded["schema_version"]),
            operation=operation,
            ok=cast(bool, decoded["ok"]),
            result=cast(dict[str, object] | None, result_value),
            error=error,
        )
    except (CanonicalJSONError, KeyError, TypeError, ValueError) as error:
        raise ValueError("product envelope is invalid") from error


def product_error_message(domain: ProductErrorDomain) -> str:
    """Return the only permitted public message for an error domain."""
    if type(domain) is not ProductErrorDomain:
        raise TypeError("domain must be a ProductErrorDomain")
    return _ERROR_MESSAGES[domain]


def product_exit_code(envelope: ProductEnvelope) -> ProductExitCode:
    """Map one complete envelope to the fixed product process status."""
    if type(envelope) is not ProductEnvelope:
        raise TypeError("envelope must be an exact ProductEnvelope")
    if envelope.ok:
        assert envelope.result is not None
        if (
            envelope.result.get("policy_passed") is False
            or envelope.result.get("validation_success") is False
            or envelope.result.get("conclusion") == ProductConclusion.FAILURE.value
        ):
            return ProductExitCode.POLICY_OR_VALIDATION
        return ProductExitCode.SUCCESS
    assert envelope.error is not None
    error = envelope.error
    if error.retryable:
        return ProductExitCode.RETRYABLE
    if error.domain in (ProductErrorDomain.CLI, ProductErrorDomain.PROFILE):
        return ProductExitCode.PROFILE_OR_REQUEST
    if error.domain is ProductErrorDomain.INTERNAL:
        return ProductExitCode.INTERNAL
    if error.code in _AUTH_OR_APPROVAL_CODES:
        return ProductExitCode.AUTH_OR_APPROVAL
    if error.code in _STALE_OR_CONFLICT_CODES:
        return ProductExitCode.STALE_OR_CONFLICT
    if error.code in _CAPABILITY_CODES:
        return ProductExitCode.CAPABILITY_UNAVAILABLE
    return ProductExitCode.BUSINESS_FAILURE


def _path_free_evidence_projection(bundle: EvidenceBundle) -> dict[str, object]:
    mapping = evidence_to_dict(bundle)
    repository = cast(dict[str, object], mapping["repository"])
    mapping["repository"] = {"object_format": repository["object_format"]}
    return mapping


def _path_free_review_projection(result: ReviewResult) -> dict[str, object]:
    mapping = review_to_dict(result)
    repository = cast(dict[str, object], mapping["repository"])
    mapping["repository"] = {"object_format": repository["object_format"]}
    return mapping


def _build_product_findings(
    deterministic: ReviewResult,
    agent: AgentReviewResult | RetrievalAgentReviewResult | None,
    *,
    evidence_sha256: str,
    deterministic_review_sha256: str,
) -> tuple[ProductFinding, ...]:
    deterministic_indices = {
        _finding_key(finding): index for index, finding in enumerate(deterministic.findings)
    }
    if len(deterministic_indices) != len(deterministic.findings):
        raise ValueError("deterministic findings are not unique")
    source_findings: tuple[Finding | AgentFinding, ...]
    if agent is None:
        source_findings = deterministic.findings
    else:
        source_findings = agent.findings
        observed = {
            _agent_finding_key(finding)
            for finding in agent.findings
            if finding.source is FindingSource.DETERMINISTIC
        }
        if observed != set(deterministic_indices):
            raise ValueError("agent deterministic findings do not match M2")

    output: list[ProductFinding] = []
    for source_finding in source_findings:
        finding_index: int | None
        if isinstance(source_finding, Finding):
            source = FindingSource.DETERMINISTIC
            finding_index = deterministic_indices[_finding_key(source_finding)]
            rule_id = source_finding.rule_id.value
        else:
            source = source_finding.source
            rule_id = source_finding.rule_id.value
            matched_finding_index = (
                deterministic_indices[_agent_finding_key(source_finding)]
                if source is FindingSource.DETERMINISTIC
                else None
            )
            finding_index = matched_finding_index
        references: list[ProductReference] = []
        for reference_index, reference in enumerate(source_finding.references):
            target_id = None
            if finding_index is not None:
                m2_finding = deterministic.findings[finding_index]
                try:
                    m2_reference_index = m2_finding.references.index(reference)
                except ValueError as error:
                    raise ValueError("deterministic reference does not match M2") from error
                if isinstance(source_finding, Finding):
                    m2_reference_index = reference_index
                target_id = _repair_target_id(
                    evidence_sha256=evidence_sha256,
                    deterministic_review_sha256=deterministic_review_sha256,
                    finding_index=finding_index,
                    reference_index=m2_reference_index,
                    finding=m2_finding,
                    reference=reference,
                )
            references.append(
                ProductReference(
                    path=reference.path,
                    side=reference.side,
                    oid=reference.oid,
                    start_line=reference.start_line,
                    end_line=reference.end_line,
                    repair_target_id=target_id,
                )
            )
        output.append(
            ProductFinding(
                source=source,
                rule_id=rule_id,
                category=source_finding.category,
                severity=source_finding.severity,
                title=source_finding.title,
                message=source_finding.message,
                remediation=source_finding.remediation,
                references=tuple(references),
            )
        )
    return tuple(output)


def _repair_target_id(
    *,
    evidence_sha256: str,
    deterministic_review_sha256: str,
    finding_index: int,
    reference_index: int,
    finding: Finding,
    reference: EvidenceReference,
) -> str:
    return domain_sha256(
        _REPAIR_TARGET_DOMAIN,
        {
            "evidence_sha256": evidence_sha256,
            "deterministic_review_sha256": deterministic_review_sha256,
            "finding_index": finding_index,
            "reference_index": reference_index,
            "finding": _m2_finding_to_dict(finding),
            "reference": _m2_reference_to_dict(reference),
        },
    )


def _finding_key(finding: Finding) -> tuple[object, ...]:
    return (
        finding.rule_id.value,
        finding.category.value,
        finding.severity.value,
        finding.title,
        finding.message,
        finding.remediation,
        tuple(_reference_key(reference) for reference in finding.references),
    )


def _agent_finding_key(finding: AgentFinding) -> tuple[object, ...]:
    if finding.source is not FindingSource.DETERMINISTIC or type(finding.rule_id) is not RuleId:
        return ("agent", id(finding))
    return (
        finding.rule_id.value,
        finding.category.value,
        finding.severity.value,
        finding.title,
        finding.message,
        finding.remediation,
        tuple(_reference_key(reference) for reference in finding.references),
    )


def _reference_key(reference: EvidenceReference) -> tuple[object, ...]:
    return (
        reference.path,
        reference.side.value,
        reference.oid,
        reference.start_line,
        reference.end_line,
    )


def _m2_finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "references": [_m2_reference_to_dict(reference) for reference in finding.references],
    }


def _m2_reference_to_dict(reference: EvidenceReference) -> dict[str, object]:
    return {
        "path": reference.path,
        "side": reference.side.value,
        "oid": reference.oid,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
    }


def _product_finding_to_dict(finding: ProductFinding) -> dict[str, object]:
    return {
        "source": finding.source.value,
        "rule_id": finding.rule_id,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "references": [
            {
                "path": reference.path,
                "side": reference.side.value,
                "oid": reference.oid,
                "start_line": reference.start_line,
                "end_line": reference.end_line,
                "repair_target_id": reference.repair_target_id,
            }
            for reference in finding.references
        ],
    }


def _product_finding_from_dict(value: object) -> ProductFinding:
    if type(value) is not dict:
        raise ValueError("product finding must be an object")
    require_exact_keys(
        value,
        (
            "source",
            "rule_id",
            "category",
            "severity",
            "title",
            "message",
            "remediation",
            "references",
        ),
        name="product finding",
    )
    references_value = value["references"]
    if type(references_value) is not list:
        raise ValueError("product references must be an array")
    return ProductFinding(
        source=FindingSource(_exact_str(value["source"])),
        rule_id=_exact_str(value["rule_id"]),
        category=FindingCategory(_exact_str(value["category"])),
        severity=FindingSeverity(_exact_str(value["severity"])),
        title=_exact_str(value["title"]),
        message=_exact_str(value["message"]),
        remediation=_exact_str(value["remediation"]),
        references=tuple(_product_reference_from_dict(reference) for reference in references_value),
    )


def _product_reference_from_dict(value: object) -> ProductReference:
    if type(value) is not dict:
        raise ValueError("product reference must be an object")
    require_exact_keys(
        value,
        (
            "path",
            "side",
            "oid",
            "start_line",
            "end_line",
            "repair_target_id",
        ),
        name="product reference",
    )
    start_value = value["start_line"]
    end_value = value["end_line"]
    target_value = value["repair_target_id"]
    return ProductReference(
        path=_exact_str(value["path"]),
        side=EvidenceSide(_exact_str(value["side"])),
        oid=_exact_str(value["oid"]),
        start_line=None if start_value is None else _exact_int(start_value),
        end_line=None if end_value is None else _exact_int(end_value),
        repair_target_id=None if target_value is None else _exact_str(target_value),
    )


def _exact_str(value: object) -> str:
    if type(value) is not str:
        raise ValueError("product JSON string is invalid")
    return value


def _exact_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("product JSON integer is invalid")
    return value


def _error_to_dict(error: ProductErrorRecord) -> dict[str, object]:
    return {
        "domain": error.domain.value,
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
        "stage": error.stage.value,
        "state": error.state,
        "session_id": error.session_id,
        "proposal_sha256": error.proposal_sha256,
        "attempt_count": error.attempt_count,
    }


def _error_from_dict(value: object) -> ProductErrorRecord:
    if type(value) is not dict:
        raise ValueError("product error must be an object")
    require_exact_keys(
        value,
        (
            "domain",
            "code",
            "message",
            "retryable",
            "stage",
            "state",
            "session_id",
            "proposal_sha256",
            "attempt_count",
        ),
        name="product error",
    )
    return ProductErrorRecord(
        domain=ProductErrorDomain(value["domain"]),
        code=cast(str, value["code"]),
        message=cast(str, value["message"]),
        retryable=cast(bool, value["retryable"]),
        stage=ProductStage(value["stage"]),
        state=cast(str | None, value["state"]),
        session_id=cast(str | None, value["session_id"]),
        proposal_sha256=cast(str | None, value["proposal_sha256"]),
        attempt_count=cast(int, value["attempt_count"]),
    )


def _highest_severity(findings: tuple[ProductFinding, ...]) -> FindingSeverity | None:
    if not findings:
        return None
    return max((finding.severity for finding in findings), key=_SEVERITY_RANK.__getitem__)


def _require_schema(value: object) -> None:
    if type(value) is not int or value != 1:
        raise ValueError("schema_version must be 1")


def _require_sha256(value: object, name: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_optional_sha256(value: object, name: str) -> None:
    if value is not None:
        _require_sha256(value, name)


def _require_alias(value: object, name: str) -> None:
    if type(value) is not str or _ALIAS_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_text(value: object, name: str, *, max_bytes: int) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{name} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} is invalid") from error
    if len(encoded) > max_bytes or any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"{name} is invalid")


def _require_repository_path(value: object) -> None:
    _require_text(value, "repository path", max_bytes=1_024)
    if cast(str, value).startswith("/") or "\\" in cast(str, value):
        raise ValueError("repository path is invalid")
    parts = cast(str, value).split("/")
    if any(
        not part
        or part in (".", "..")
        or part.casefold() == ".git"
        or len(part.encode("utf-8")) > 255
        for part in parts
    ):
        raise ValueError("repository path is invalid")
