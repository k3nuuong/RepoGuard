"""Strict M6 GitHub proposal, approval, and publication result contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import cast

from repoguard._canonical import (
    JSONValue,
    canonical_json_bytes,
    canonical_json_text,
    domain_sha256,
    parse_canonical_json,
    require_exact_keys,
)
from repoguard.product import (
    ProductFinding,
    ProductReference,
    ProductReviewResult,
    product_review_from_json,
    product_review_to_dict,
)
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    REPAIR_PUBLICATION_AUTHOR_EMAIL,
    REPAIR_PUBLICATION_AUTHOR_NAME,
    REPAIR_PUBLICATION_COMMIT_MESSAGE,
    REPAIR_PUBLICATION_COMMIT_TIMESTAMP,
    RepairPreview,
    RepairSnapshot,
    RepairState,
)
from repoguard.review import EvidenceSide, FindingSeverity

__all__ = [
    "GITHUB_CHECK_CONFIRMATION",
    "GITHUB_PROPOSAL_MAX_BYTES",
    "GITHUB_REPAIR_CONFIRMATION",
    "GitHubApproval",
    "GitHubApprovalInterface",
    "GitHubPermission",
    "GitHubProposal",
    "GitHubProposalKind",
    "GitHubProposalOrigin",
    "GitHubPublicationResult",
    "GitHubPublicationState",
    "approve_github_proposal",
    "build_github_check_proposal",
    "build_github_proposal",
    "build_github_repair_proposal",
    "build_github_result",
    "github_approval_from_json",
    "github_approval_to_dict",
    "github_approval_to_json",
    "github_proposal_artifact_name",
    "github_proposal_from_json",
    "github_proposal_to_dict",
    "github_proposal_to_json",
    "github_result_from_json",
    "github_result_to_dict",
    "github_result_to_json",
    "validate_github_result",
]

GITHUB_CHECK_CONFIRMATION = (
    "I approve publishing this exact RepoGuard review as a GitHub Check Run."
)
GITHUB_REPAIR_CONFIRMATION = (
    "I approve publishing this exact RepoGuard repair commit to its dedicated branch and "
    "draft pull request."
)
GITHUB_PROPOSAL_MAX_BYTES = 4 * 1024 * 1024
_CHECK_SUMMARY_MAX_BYTES = 60 * 1024
_PROPOSAL_LIFETIME_US = 24 * 60 * 60 * 1_000_000
_PROPOSAL_DOMAIN = "repoguard.m6.github_proposal.v1"
_APPROVAL_DOMAIN = "repoguard.m6.github_approval.v1"
_RESULT_DOMAIN = "repoguard.m6.github_result.v1"
_PREVIEW_DOMAIN = "repoguard.m6.repair_preview.v1"
_CHECK_EXTERNAL_ID_DOMAIN = "repoguard.m6.github_check_external.v1"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FULL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_PATH_FORBIDDEN = {"", ".", "..", ".git"}
_CHECK_PAYLOAD_FIELDS = {
    "review_result",
    "policy_sha256",
    "external_id",
    "summary",
    "annotations",
    "omitted_count",
}
_REPAIR_PAYLOAD_FIELDS = {
    "repository_alias",
    "candidate_id",
    "validation_sha256",
    "preview_sha256",
    "tree_oid",
    "commit_oid",
    "changed_paths",
    "preview",
    "branch",
    "pull_request_title",
    "pull_request_body",
}
_PREVIEW_FIELDS = {
    "schema_version",
    "state",
    "candidate_id",
    "validation_sha256",
    "changed_paths",
    "canonical_diff",
    "confirmation",
}
_ANNOTATION_FIELDS = {
    "path",
    "start_line",
    "end_line",
    "annotation_level",
    "title",
    "message",
}
_ANNOTATION_RANK = {"failure": 0, "warning": 1, "notice": 2}
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
_ANNOTATION_LEVEL = {
    FindingSeverity.CRITICAL: "failure",
    FindingSeverity.HIGH: "failure",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "notice",
    FindingSeverity.INFO: "notice",
}


class GitHubProposalKind(StrEnum):
    """Write authorized by one exact proposal."""

    CHECK = "check"
    REPAIR = "repair"


class GitHubProposalOrigin(StrEnum):
    """Interface that created a proposal without authorizing publication."""

    ACTION = "action"
    CLI = "cli"
    MCP = "mcp"


class GitHubPermission(StrEnum):
    """GitHub repository permissions accepted for active publication."""

    WRITE = "write"
    MAINTAIN = "maintain"
    ADMIN = "admin"


class GitHubApprovalInterface(StrEnum):
    """Interface that obtained exact human publication confirmation."""

    ACTION = "action"
    CLI = "cli"
    MCP = "mcp"


class GitHubPublicationState(StrEnum):
    """Stable terminal or recoverable publication state."""

    CHECK_PUBLISHED = "check_published"
    BRANCH_CREATED = "branch_created"
    REPAIR_PUBLISHED = "repair_published"


@dataclass(frozen=True, slots=True)
class GitHubProposal:
    """Immutable two-phase GitHub publication proposal."""

    schema_version: int
    proposal_sha256: str
    kind: GitHubProposalKind
    repository_id: int
    repository_full_name: str
    pull_request_number: int
    base_ref: str
    base_oid: str
    head_oid: str
    origin: GitHubProposalOrigin
    profile_name: str
    created_at_us: int
    expires_at_us: int
    payload_json: str

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256(self.proposal_sha256, "proposal_sha256")
        if type(self.kind) is not GitHubProposalKind:
            raise ValueError("proposal kind is invalid")
        _require_positive_int(self.repository_id, "repository_id")
        _require_full_name(self.repository_full_name)
        _require_positive_int(self.pull_request_number, "pull_request_number")
        _require_text(self.base_ref, "base_ref", maximum=255)
        _require_sha1(self.base_oid, "base_oid")
        _require_sha1(self.head_oid, "head_oid")
        if type(self.origin) is not GitHubProposalOrigin:
            raise ValueError("proposal origin is invalid")
        _require_name(self.profile_name, "profile_name")
        _require_timestamp(self.created_at_us, "created_at_us")
        _require_timestamp(self.expires_at_us, "expires_at_us")
        if self.expires_at_us != self.created_at_us + _PROPOSAL_LIFETIME_US:
            raise ValueError("proposal expiry is invalid")
        payload = _parse_payload_json(self.payload_json)
        _validate_proposal_payload(
            self.kind,
            payload,
            repository_id=self.repository_id,
            repository_full_name=self.repository_full_name,
            base_oid=self.base_oid,
            head_oid=self.head_oid,
            profile_name=self.profile_name,
        )
        expected = domain_sha256(_PROPOSAL_DOMAIN, _proposal_identity_mapping(self, payload))
        if not hmac.compare_digest(expected, self.proposal_sha256):
            raise ValueError("proposal identity is invalid")

    @property
    def payload(self) -> dict[str, JSONValue]:
        """Return a fresh parsed copy of the canonical proposal payload."""
        return _parse_payload_json(self.payload_json)


@dataclass(frozen=True, slots=True)
class GitHubApproval:
    """Immutable approval of one exact unexpired proposal."""

    schema_version: int
    approval_sha256: str
    proposal_sha256: str
    kind: GitHubProposalKind
    actor_login: str
    actor_id: int
    permission: GitHubPermission
    interface: GitHubApprovalInterface
    confirmation: str
    approved_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256(self.approval_sha256, "approval_sha256")
        _require_sha256(self.proposal_sha256, "proposal_sha256")
        if type(self.kind) is not GitHubProposalKind:
            raise ValueError("approval kind is invalid")
        if type(self.actor_login) is not str or _LOGIN_PATTERN.fullmatch(self.actor_login) is None:
            raise ValueError("approval actor is invalid")
        _require_positive_int(self.actor_id, "actor_id")
        if type(self.permission) is not GitHubPermission:
            raise ValueError("approval permission is invalid")
        if type(self.interface) is not GitHubApprovalInterface:
            raise ValueError("approval interface is invalid")
        if self.confirmation != _confirmation_for_kind(self.kind):
            raise ValueError("approval confirmation is invalid")
        _require_timestamp(self.approved_at_us, "approved_at_us")
        expected = domain_sha256(_APPROVAL_DOMAIN, _approval_identity_mapping(self))
        if not hmac.compare_digest(expected, self.approval_sha256):
            raise ValueError("approval identity is invalid")


@dataclass(frozen=True, slots=True)
class GitHubPublicationResult:
    """Read-back-confirmed identity of one approved GitHub publication."""

    schema_version: int
    result_sha256: str
    proposal_sha256: str
    kind: GitHubProposalKind
    approval: GitHubApproval
    state: GitHubPublicationState
    application_sha256: str | None
    readback_json: str
    published_at_us: int

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_sha256(self.result_sha256, "result_sha256")
        _require_sha256(self.proposal_sha256, "proposal_sha256")
        if type(self.kind) is not GitHubProposalKind:
            raise ValueError("result kind is invalid")
        if type(self.approval) is not GitHubApproval:
            raise ValueError("result approval is invalid")
        if (
            self.approval.proposal_sha256 != self.proposal_sha256
            or self.approval.kind is not self.kind
        ):
            raise ValueError("result approval does not match proposal")
        if type(self.state) is not GitHubPublicationState:
            raise ValueError("publication state is invalid")
        if self.kind is GitHubProposalKind.CHECK:
            if self.state is not GitHubPublicationState.CHECK_PUBLISHED:
                raise ValueError("check publication state is invalid")
            if self.application_sha256 is not None:
                raise ValueError("check result cannot bind a repair application")
        else:
            if self.state not in {
                GitHubPublicationState.BRANCH_CREATED,
                GitHubPublicationState.REPAIR_PUBLISHED,
            }:
                raise ValueError("repair publication state is invalid")
            _require_sha256(self.application_sha256, "application_sha256")
        _require_timestamp(self.published_at_us, "published_at_us")
        if self.published_at_us < self.approval.approved_at_us:
            raise ValueError("publication time precedes approval")
        readback = _parse_readback_json(self.readback_json)
        _validate_readback(self.kind, self.state, readback)
        expected = domain_sha256(_RESULT_DOMAIN, _result_identity_mapping(self, readback))
        if not hmac.compare_digest(expected, self.result_sha256):
            raise ValueError("result identity is invalid")

    @property
    def readback(self) -> dict[str, JSONValue]:
        """Return a fresh parsed copy of the canonical GitHub read-back identity."""
        return _parse_readback_json(self.readback_json)


def build_github_check_proposal(
    *,
    repository_id: int,
    repository_full_name: str,
    pull_request_number: int,
    base_ref: str,
    origin: GitHubProposalOrigin,
    review_result: ProductReviewResult,
    policy_sha256: str,
    created_at_us: int,
) -> GitHubProposal:
    """Build a Check proposal only from one exact, path-free product review."""
    if type(review_result) is not ProductReviewResult:
        raise TypeError("review_result must be an exact ProductReviewResult")
    if review_result.object_format != "sha1":
        raise ValueError("GitHub Check proposals require SHA-1 review identities")
    _require_sha256(policy_sha256, "policy_sha256")
    annotations, omitted_count = _check_annotations(review_result)
    payload: dict[str, object] = {
        "review_result": product_review_to_dict(review_result),
        "policy_sha256": policy_sha256,
        "external_id": _check_external_id(
            repository_id=repository_id,
            repository_full_name=repository_full_name,
            head_oid=review_result.head_oid,
            review_sha256=review_result.review_sha256,
            policy_sha256=policy_sha256,
        ),
        "summary": _check_summary(
            review_result,
            annotation_count=len(annotations),
            omitted_count=omitted_count,
        ),
        "annotations": annotations,
        "omitted_count": omitted_count,
    }
    return build_github_proposal(
        kind=GitHubProposalKind.CHECK,
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        pull_request_number=pull_request_number,
        base_ref=base_ref,
        base_oid=review_result.base_oid,
        head_oid=review_result.head_oid,
        origin=origin,
        profile_name=review_result.review_profile,
        payload=payload,
        created_at_us=created_at_us,
    )


def build_github_repair_proposal(
    *,
    repository_id: int,
    repository_full_name: str,
    pull_request_number: int,
    base_ref: str,
    origin: GitHubProposalOrigin,
    review_result: ProductReviewResult,
    profile_name: str,
    snapshot: RepairSnapshot,
    preview: RepairPreview,
    created_at_us: int,
) -> GitHubProposal:
    """Build a session-free repair proposal from exact validated M5 records."""
    if type(review_result) is not ProductReviewResult:
        raise TypeError("review_result must be an exact ProductReviewResult")
    if type(snapshot) is not RepairSnapshot or type(preview) is not RepairPreview:
        raise TypeError("snapshot and preview must be exact M5 records")
    if review_result.object_format != "sha1":
        raise ValueError("GitHub repair proposals require SHA-1 review identities")
    _require_name(profile_name, "profile_name")
    candidate = snapshot.candidate
    validation = snapshot.validation
    if (
        snapshot.state is not RepairState.VALIDATED
        or candidate is None
        or validation is None
        or not validation.success
        or snapshot.approval is not None
        or snapshot.application is not None
        or snapshot.decision is not None
        or snapshot.failure is not None
    ):
        raise ValueError("repair proposal requires successful VALIDATED state")
    if (
        preview.state is not RepairState.VALIDATED
        or preview.session_id != snapshot.session_id
        or preview.candidate_id != candidate.candidate_id
        or preview.validation_sha256 != validation.validation_sha256
        or preview.changed_paths != candidate.changed_paths
        or preview.confirmation != REPAIR_APPROVAL_CONFIRMATION
    ):
        raise ValueError("repair proposal preview does not match snapshot")
    if validation.candidate_id != candidate.candidate_id:
        raise ValueError("repair proposal validation does not match candidate")
    if any(path not in snapshot.allowed_paths for path in candidate.changed_paths):
        raise ValueError("repair proposal paths exceed the validated allowlist")
    expected_commit_oid = _fixed_repair_commit_oid(
        tree_oid=candidate.tree_oid,
        head_oid=review_result.head_oid,
    )
    if not hmac.compare_digest(candidate.commit_oid, expected_commit_oid):
        raise ValueError("repair proposal commit does not match the reviewed head")

    preview_payload: dict[str, object] = {
        "schema_version": preview.schema_version,
        "state": preview.state.value,
        "candidate_id": preview.candidate_id,
        "validation_sha256": preview.validation_sha256,
        "changed_paths": list(preview.changed_paths),
        "canonical_diff": preview.canonical_diff,
        "confirmation": preview.confirmation,
    }
    marker = _repair_pull_request_marker(candidate.candidate_id)
    payload: dict[str, object] = {
        "repository_alias": review_result.repository_alias,
        "candidate_id": candidate.candidate_id,
        "validation_sha256": validation.validation_sha256,
        "preview_sha256": domain_sha256(_PREVIEW_DOMAIN, preview_payload),
        "tree_oid": candidate.tree_oid,
        "commit_oid": candidate.commit_oid,
        "changed_paths": list(candidate.changed_paths),
        "preview": preview_payload,
        "branch": _repair_branch(candidate.candidate_id),
        "pull_request_title": _repair_pull_request_title(candidate.candidate_id),
        "pull_request_body": _repair_pull_request_body(marker),
    }
    return build_github_proposal(
        kind=GitHubProposalKind.REPAIR,
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        pull_request_number=pull_request_number,
        base_ref=base_ref,
        base_oid=review_result.base_oid,
        head_oid=review_result.head_oid,
        origin=origin,
        profile_name=profile_name,
        payload=payload,
        created_at_us=created_at_us,
    )


def build_github_proposal(
    *,
    kind: GitHubProposalKind,
    repository_id: int,
    repository_full_name: str,
    pull_request_number: int,
    base_ref: str,
    base_oid: str,
    head_oid: str,
    origin: GitHubProposalOrigin,
    profile_name: str,
    payload: dict[str, object],
    created_at_us: int,
) -> GitHubProposal:
    """Build a domain-separated proposal with an exact 24-hour lifetime."""
    payload_json = canonical_json_text(payload)
    decoded = _parse_payload_json(payload_json)
    fields: dict[str, object] = {
        "schema_version": 1,
        "kind": kind.value if type(kind) is GitHubProposalKind else kind,
        "repository_id": repository_id,
        "repository_full_name": repository_full_name,
        "pull_request_number": pull_request_number,
        "base_ref": base_ref,
        "base_oid": base_oid,
        "head_oid": head_oid,
        "origin": origin.value if type(origin) is GitHubProposalOrigin else origin,
        "profile_name": profile_name,
        "created_at_us": created_at_us,
        "expires_at_us": created_at_us + _PROPOSAL_LIFETIME_US,
        "payload": decoded,
    }
    digest = domain_sha256(_PROPOSAL_DOMAIN, fields)
    return GitHubProposal(
        schema_version=1,
        proposal_sha256=digest,
        kind=kind,
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        pull_request_number=pull_request_number,
        base_ref=base_ref,
        base_oid=base_oid,
        head_oid=head_oid,
        origin=origin,
        profile_name=profile_name,
        created_at_us=created_at_us,
        expires_at_us=created_at_us + _PROPOSAL_LIFETIME_US,
        payload_json=payload_json,
    )


def approve_github_proposal(
    proposal: GitHubProposal,
    *,
    actor_login: str,
    actor_id: int,
    permission: GitHubPermission,
    interface: GitHubApprovalInterface,
    confirmation: str,
    approved_at_us: int,
) -> GitHubApproval:
    """Approve one exact proposal after expiry, permission, and confirmation checks."""
    if type(proposal) is not GitHubProposal:
        raise TypeError("proposal must be an exact GitHubProposal")
    if not proposal.created_at_us <= approved_at_us < proposal.expires_at_us:
        raise ValueError("GitHub proposal is expired")
    fields: dict[str, object] = {
        "schema_version": 1,
        "proposal_sha256": proposal.proposal_sha256,
        "kind": proposal.kind.value,
        "actor_login": actor_login,
        "actor_id": actor_id,
        "permission": permission.value if type(permission) is GitHubPermission else permission,
        "interface": (interface.value if type(interface) is GitHubApprovalInterface else interface),
        "confirmation": confirmation,
        "approved_at_us": approved_at_us,
    }
    digest = domain_sha256(_APPROVAL_DOMAIN, fields)
    return GitHubApproval(
        schema_version=1,
        approval_sha256=digest,
        proposal_sha256=proposal.proposal_sha256,
        kind=proposal.kind,
        actor_login=actor_login,
        actor_id=actor_id,
        permission=permission,
        interface=interface,
        confirmation=confirmation,
        approved_at_us=approved_at_us,
    )


def build_github_result(
    proposal: GitHubProposal,
    approval: GitHubApproval,
    *,
    state: GitHubPublicationState,
    application_sha256: str | None,
    readback: dict[str, object],
    published_at_us: int,
) -> GitHubPublicationResult:
    """Build a result only from an approval matching the complete proposal identity."""
    if type(proposal) is not GitHubProposal or type(approval) is not GitHubApproval:
        raise TypeError("proposal and approval must be exact GitHub records")
    if approval.proposal_sha256 != proposal.proposal_sha256 or approval.kind is not proposal.kind:
        raise ValueError("approval does not match proposal")
    readback_json = canonical_json_text(readback)
    decoded = _parse_readback_json(readback_json)
    _validate_readback_against_proposal(proposal, state=state, readback=decoded)
    fields = {
        "schema_version": 1,
        "proposal_sha256": proposal.proposal_sha256,
        "kind": proposal.kind.value,
        "approval": github_approval_to_dict(approval),
        "state": state.value if type(state) is GitHubPublicationState else state,
        "application_sha256": application_sha256,
        "readback": decoded,
        "published_at_us": published_at_us,
    }
    digest = domain_sha256(_RESULT_DOMAIN, fields)
    return GitHubPublicationResult(
        schema_version=1,
        result_sha256=digest,
        proposal_sha256=proposal.proposal_sha256,
        kind=proposal.kind,
        approval=approval,
        state=state,
        application_sha256=application_sha256,
        readback_json=readback_json,
        published_at_us=published_at_us,
    )


def github_proposal_to_dict(value: GitHubProposal) -> dict[str, object]:
    """Return one complete canonical proposal mapping including bounded payload."""
    if type(value) is not GitHubProposal:
        raise TypeError("value must be an exact GitHubProposal")
    return {
        "schema_version": value.schema_version,
        "proposal_sha256": value.proposal_sha256,
        **_proposal_identity_mapping(value, value.payload),
    }


def github_proposal_to_json(value: GitHubProposal) -> str:
    """Serialize one proposal without a trailing newline."""
    encoded = canonical_json_text(github_proposal_to_dict(value))
    if len(encoded.encode("utf-8")) > GITHUB_PROPOSAL_MAX_BYTES:
        raise ValueError("GitHub proposal exceeds its byte limit")
    return encoded


def github_proposal_from_json(raw: bytes) -> GitHubProposal:
    """Parse exact canonical proposal bytes and reject every unknown field."""
    try:
        mapping = _as_object(parse_canonical_json(raw, max_bytes=GITHUB_PROPOSAL_MAX_BYTES))
        require_exact_keys(
            mapping,
            (
                "schema_version",
                "proposal_sha256",
                "kind",
                "repository_id",
                "repository_full_name",
                "pull_request_number",
                "base_ref",
                "base_oid",
                "head_oid",
                "origin",
                "profile_name",
                "created_at_us",
                "expires_at_us",
                "payload",
            ),
            name="GitHub proposal",
        )
        return GitHubProposal(
            schema_version=_as_int(mapping["schema_version"]),
            proposal_sha256=_as_str(mapping["proposal_sha256"]),
            kind=GitHubProposalKind(_as_str(mapping["kind"])),
            repository_id=_as_int(mapping["repository_id"]),
            repository_full_name=_as_str(mapping["repository_full_name"]),
            pull_request_number=_as_int(mapping["pull_request_number"]),
            base_ref=_as_str(mapping["base_ref"]),
            base_oid=_as_str(mapping["base_oid"]),
            head_oid=_as_str(mapping["head_oid"]),
            origin=GitHubProposalOrigin(_as_str(mapping["origin"])),
            profile_name=_as_str(mapping["profile_name"]),
            created_at_us=_as_int(mapping["created_at_us"]),
            expires_at_us=_as_int(mapping["expires_at_us"]),
            payload_json=canonical_json_text(_as_object(mapping["payload"])),
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("GitHub proposal is invalid") from None


def github_proposal_artifact_name(value: GitHubProposal) -> str:
    """Return the fixed one-day proposal artifact name."""
    if type(value) is not GitHubProposal:
        raise TypeError("value must be an exact GitHubProposal")
    return f"repoguard-proposal-v1-{value.proposal_sha256}"


def github_approval_to_dict(value: GitHubApproval) -> dict[str, object]:
    """Return one complete approval mapping."""
    if type(value) is not GitHubApproval:
        raise TypeError("value must be an exact GitHubApproval")
    return {"approval_sha256": value.approval_sha256, **_approval_identity_mapping(value)}


def github_approval_to_json(value: GitHubApproval) -> str:
    """Serialize one approval without a trailing newline."""
    return canonical_json_text(github_approval_to_dict(value))


def github_approval_from_json(raw: bytes) -> GitHubApproval:
    """Parse one exact canonical approval record."""
    try:
        mapping = _as_object(parse_canonical_json(raw, max_bytes=64 * 1024))
        require_exact_keys(
            mapping,
            (
                "schema_version",
                "approval_sha256",
                "proposal_sha256",
                "kind",
                "actor_login",
                "actor_id",
                "permission",
                "interface",
                "confirmation",
                "approved_at_us",
            ),
            name="GitHub approval",
        )
        return GitHubApproval(
            schema_version=_as_int(mapping["schema_version"]),
            approval_sha256=_as_str(mapping["approval_sha256"]),
            proposal_sha256=_as_str(mapping["proposal_sha256"]),
            kind=GitHubProposalKind(_as_str(mapping["kind"])),
            actor_login=_as_str(mapping["actor_login"]),
            actor_id=_as_int(mapping["actor_id"]),
            permission=GitHubPermission(_as_str(mapping["permission"])),
            interface=GitHubApprovalInterface(_as_str(mapping["interface"])),
            confirmation=_as_str(mapping["confirmation"]),
            approved_at_us=_as_int(mapping["approved_at_us"]),
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("GitHub approval is invalid") from None


def github_result_to_dict(value: GitHubPublicationResult) -> dict[str, object]:
    """Return one complete publication-result mapping."""
    if type(value) is not GitHubPublicationResult:
        raise TypeError("value must be an exact GitHubPublicationResult")
    return {
        "schema_version": value.schema_version,
        "result_sha256": value.result_sha256,
        **_result_identity_mapping(value, value.readback),
    }


def github_result_to_json(value: GitHubPublicationResult) -> str:
    """Serialize one publication result without a trailing newline."""
    return canonical_json_text(github_result_to_dict(value))


def github_result_from_json(
    raw: bytes,
    *,
    proposal: GitHubProposal,
) -> GitHubPublicationResult:
    """Parse a publication result and revalidate it against its exact proposal."""
    try:
        if type(proposal) is not GitHubProposal:
            raise TypeError("proposal must be an exact GitHubProposal")
        mapping = _as_object(parse_canonical_json(raw, max_bytes=1024 * 1024))
        require_exact_keys(
            mapping,
            (
                "schema_version",
                "result_sha256",
                "proposal_sha256",
                "kind",
                "approval",
                "state",
                "application_sha256",
                "readback",
                "published_at_us",
            ),
            name="GitHub result",
        )
        approval = github_approval_from_json(canonical_json_bytes(_as_object(mapping["approval"])))
        application_value = mapping["application_sha256"]
        result = GitHubPublicationResult(
            schema_version=_as_int(mapping["schema_version"]),
            result_sha256=_as_str(mapping["result_sha256"]),
            proposal_sha256=_as_str(mapping["proposal_sha256"]),
            kind=GitHubProposalKind(_as_str(mapping["kind"])),
            approval=approval,
            state=GitHubPublicationState(_as_str(mapping["state"])),
            application_sha256=(None if application_value is None else _as_str(application_value)),
            readback_json=canonical_json_text(_as_object(mapping["readback"])),
            published_at_us=_as_int(mapping["published_at_us"]),
        )
        validate_github_result(proposal, result)
        return result
    except (KeyError, TypeError, ValueError):
        raise ValueError("GitHub publication result is invalid") from None


def validate_github_result(
    proposal: GitHubProposal,
    result: GitHubPublicationResult,
) -> None:
    """Revalidate a publication result against the complete authorized proposal."""
    if type(proposal) is not GitHubProposal or type(result) is not GitHubPublicationResult:
        raise TypeError("proposal and result must be exact GitHub records")
    if (
        result.proposal_sha256 != proposal.proposal_sha256
        or result.kind is not proposal.kind
        or result.approval.proposal_sha256 != proposal.proposal_sha256
    ):
        raise ValueError("publication result does not match proposal")
    _validate_readback_against_proposal(
        proposal,
        state=result.state,
        readback=result.readback,
    )


def _proposal_identity_mapping(
    value: GitHubProposal,
    payload: dict[str, JSONValue],
) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "kind": value.kind.value,
        "repository_id": value.repository_id,
        "repository_full_name": value.repository_full_name,
        "pull_request_number": value.pull_request_number,
        "base_ref": value.base_ref,
        "base_oid": value.base_oid,
        "head_oid": value.head_oid,
        "origin": value.origin.value,
        "profile_name": value.profile_name,
        "created_at_us": value.created_at_us,
        "expires_at_us": value.expires_at_us,
        "payload": payload,
    }


def _approval_identity_mapping(value: GitHubApproval) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "proposal_sha256": value.proposal_sha256,
        "kind": value.kind.value,
        "actor_login": value.actor_login,
        "actor_id": value.actor_id,
        "permission": value.permission.value,
        "interface": value.interface.value,
        "confirmation": value.confirmation,
        "approved_at_us": value.approved_at_us,
    }


def _result_identity_mapping(
    value: GitHubPublicationResult,
    readback: dict[str, JSONValue],
) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "proposal_sha256": value.proposal_sha256,
        "kind": value.kind.value,
        "approval": github_approval_to_dict(value.approval),
        "state": value.state.value,
        "application_sha256": value.application_sha256,
        "readback": readback,
        "published_at_us": value.published_at_us,
    }


def _check_external_id(
    *,
    repository_id: int,
    repository_full_name: str,
    head_oid: str,
    review_sha256: str,
    policy_sha256: str,
) -> str:
    _require_positive_int(repository_id, "repository_id")
    _require_full_name(repository_full_name)
    _require_sha1(head_oid, "head_oid")
    _require_sha256(review_sha256, "review_sha256")
    _require_sha256(policy_sha256, "policy_sha256")
    return domain_sha256(
        _CHECK_EXTERNAL_ID_DOMAIN,
        {
            "schema_version": 1,
            "repository": {
                "repository_id": repository_id,
                "repository_full_name": repository_full_name,
            },
            "head_oid": head_oid,
            "review_sha256": review_sha256,
            "policy_sha256": policy_sha256,
        },
    )


def _check_summary(
    review: ProductReviewResult,
    *,
    annotation_count: int,
    omitted_count: int,
) -> str:
    highest = "none" if review.highest_severity is None else review.highest_severity.value
    return (
        "RepoGuard review\n"
        f"Conclusion: {review.conclusion.value}\n"
        f"Findings: {review.finding_count}\n"
        f"Highest severity: {highest}\n"
        f"Annotations: {annotation_count}\n"
        f"Omitted annotations: {omitted_count}"
    )


def _check_annotations(
    review: ProductReviewResult,
) -> tuple[list[dict[str, object]], int]:
    candidates: list[tuple[tuple[object, ...], dict[str, object]]] = []
    reference_count = 0
    for finding in review.findings:
        for reference in finding.references:
            reference_count += 1
            if (
                reference.side is not EvidenceSide.NEW
                or reference.start_line is None
                or reference.end_line is None
            ):
                continue
            annotation = _check_annotation(finding, reference)
            key = (
                _SEVERITY_RANK[finding.severity],
                reference.path.encode("utf-8"),
                reference.start_line,
                reference.end_line,
                cast(str, annotation["title"]),
                cast(str, annotation["message"]),
            )
            candidates.append((key, annotation))
    candidates.sort(key=lambda item: item[0])
    selected = [annotation for _, annotation in candidates[:1_000]]
    return selected, reference_count - len(selected)


def _check_annotation(
    finding: ProductFinding,
    reference: ProductReference,
) -> dict[str, object]:
    title = _escape_github_plain_text(
        f"RepoGuard {finding.severity.value}: {finding.title}",
        maximum=255,
    )
    message = _escape_github_plain_text(
        (
            f"Source: {finding.source.value}\n"
            f"Rule: {finding.rule_id}\n"
            f"{finding.message}\n"
            f"Remediation: {finding.remediation}"
        ),
        maximum=64 * 1024,
    )
    return {
        "path": reference.path,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
        "annotation_level": _ANNOTATION_LEVEL[finding.severity],
        "title": title,
        "message": message,
    }


def _escape_github_plain_text(value: str, *, maximum: int) -> str:
    fragments = [
        (
            "\uff20"
            if character == "@"
            else (
                character
                if character == "\n"
                or character == " "
                or character.isalnum()
                or ord(character) > 127
                else f"&#{ord(character)};"
            )
        )
        for character in value
    ]
    encoded_size = sum(len(fragment.encode("utf-8")) for fragment in fragments)
    if encoded_size <= maximum:
        return "".join(fragments)
    suffix = "&#8230;"
    budget = maximum - len(suffix)
    bounded: list[str] = []
    used = 0
    for fragment in fragments:
        size = len(fragment.encode("utf-8"))
        if used + size > budget:
            break
        bounded.append(fragment)
        used += size
    return "".join((*bounded, suffix))


def _fixed_repair_commit_oid(*, tree_oid: str, head_oid: str) -> str:
    _require_sha1(tree_oid, "tree_oid")
    _require_sha1(head_oid, "head_oid")
    try:
        timestamp = datetime.fromisoformat(
            REPAIR_PUBLICATION_COMMIT_TIMESTAMP.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("M5 publication timestamp is invalid") from error
    offset = timestamp.strftime("%z")
    if timestamp.utcoffset() is None or offset != "+0000":
        raise ValueError("M5 publication timestamp is invalid")
    seconds = int(timestamp.timestamp())
    identity = (
        f"{REPAIR_PUBLICATION_AUTHOR_NAME} <{REPAIR_PUBLICATION_AUTHOR_EMAIL}> {seconds} {offset}"
    )
    commit = (
        f"tree {tree_oid}\n"
        f"parent {head_oid}\n"
        f"author {identity}\n"
        f"committer {identity}\n"
        "\n"
        f"{REPAIR_PUBLICATION_COMMIT_MESSAGE}"
    ).encode()
    header = f"commit {len(commit)}\0".encode("ascii")
    return hashlib.sha1(header + commit, usedforsecurity=False).hexdigest()


def _repair_branch(candidate_id: str) -> str:
    return f"repoguard/repairs/{candidate_id}"


def _repair_pull_request_marker(candidate_id: str) -> str:
    return f"<!-- repoguard-repair-candidate:{candidate_id} -->"


def _repair_pull_request_title(candidate_id: str) -> str:
    return f"[RepoGuard] Repair candidate {candidate_id[:12]}"


def _repair_pull_request_body(marker: str) -> str:
    return f"{marker}\nDraft replacement repair generated by RepoGuard."


def _validate_proposal_payload(
    kind: GitHubProposalKind,
    payload: dict[str, JSONValue],
    *,
    repository_id: int,
    repository_full_name: str,
    base_oid: str,
    head_oid: str,
    profile_name: str,
) -> None:
    if kind is GitHubProposalKind.CHECK:
        _validate_check_payload(
            payload,
            repository_id=repository_id,
            repository_full_name=repository_full_name,
            base_oid=base_oid,
            head_oid=head_oid,
            profile_name=profile_name,
        )
    else:
        _validate_repair_payload(payload, head_oid=head_oid)


def _validate_check_payload(
    payload: dict[str, JSONValue],
    *,
    repository_id: int,
    repository_full_name: str,
    base_oid: str,
    head_oid: str,
    profile_name: str,
) -> None:
    if set(payload) != _CHECK_PAYLOAD_FIELDS:
        raise ValueError("check proposal payload fields are invalid")
    review = _as_object(payload["review_result"])
    if len(canonical_json_bytes(review)) > GITHUB_PROPOSAL_MAX_BYTES:
        raise ValueError("check proposal review result is too large")
    parsed_review = product_review_from_json(canonical_json_bytes(review))
    if (
        parsed_review.object_format != "sha1"
        or parsed_review.base_oid != base_oid
        or parsed_review.head_oid != head_oid
        or parsed_review.review_profile != profile_name
    ):
        raise ValueError("check review revisions do not match proposal")
    policy_sha256 = _as_str(payload["policy_sha256"])
    _require_sha256(policy_sha256, "policy_sha256")
    external_id = _as_str(payload["external_id"])
    expected_external_id = _check_external_id(
        repository_id=repository_id,
        repository_full_name=repository_full_name,
        head_oid=head_oid,
        review_sha256=parsed_review.review_sha256,
        policy_sha256=policy_sha256,
    )
    if not hmac.compare_digest(external_id, expected_external_id):
        raise ValueError("check external_id is invalid")
    summary = _as_str(payload["summary"])
    _require_escaped_text(summary, "check summary", maximum=_CHECK_SUMMARY_MAX_BYTES)
    omitted = _as_int(payload["omitted_count"])
    if omitted < 0:
        raise ValueError("check omitted_count is invalid")
    raw_annotations = payload["annotations"]
    if type(raw_annotations) is not list or len(raw_annotations) > 1_000:
        raise ValueError("check annotations are invalid")
    annotations = [_as_object(item) for item in raw_annotations]
    keys = [_validate_annotation(item) for item in annotations]
    if keys != sorted(keys):
        raise ValueError("check annotations are not stably ordered")
    expected_annotations, expected_omitted = _check_annotations(parsed_review)
    if annotations != expected_annotations or omitted != expected_omitted:
        raise ValueError("check annotations do not match review")
    expected_summary = _check_summary(
        parsed_review,
        annotation_count=len(expected_annotations),
        omitted_count=expected_omitted,
    )
    if summary != expected_summary:
        raise ValueError("check summary does not match review")


def _validate_annotation(value: dict[str, JSONValue]) -> tuple[object, ...]:
    if set(value) != _ANNOTATION_FIELDS:
        raise ValueError("check annotation fields are invalid")
    path = _as_str(value["path"])
    _require_repository_path(path)
    start = _as_int(value["start_line"])
    end = _as_int(value["end_line"])
    if not 1 <= start <= end:
        raise ValueError("check annotation lines are invalid")
    level = _as_str(value["annotation_level"])
    if level not in _ANNOTATION_RANK:
        raise ValueError("check annotation level is invalid")
    title = _as_str(value["title"])
    message = _as_str(value["message"])
    _require_escaped_text(title, "check annotation title", maximum=255)
    _require_escaped_text(message, "check annotation message", maximum=64 * 1024)
    severity = next(
        (item for item in FindingSeverity if title.startswith(f"RepoGuard {item.value}&#58; ")),
        None,
    )
    if severity is None or _ANNOTATION_LEVEL[severity] != level:
        raise ValueError("check annotation severity is invalid")
    return (_SEVERITY_RANK[severity], path.encode("utf-8"), start, end, title, message)


def _validate_repair_payload(
    payload: dict[str, JSONValue],
    *,
    head_oid: str,
) -> None:
    if set(payload) != _REPAIR_PAYLOAD_FIELDS:
        raise ValueError("repair proposal payload fields are invalid")
    _require_name(_as_str(payload["repository_alias"]), "repository_alias")
    candidate_id = _as_str(payload["candidate_id"])
    validation_sha256 = _as_str(payload["validation_sha256"])
    preview_sha256 = _as_str(payload["preview_sha256"])
    _require_sha256(candidate_id, "candidate_id")
    _require_sha256(validation_sha256, "validation_sha256")
    _require_sha256(preview_sha256, "preview_sha256")
    tree_oid = _as_str(payload["tree_oid"])
    commit_oid = _as_str(payload["commit_oid"])
    _require_sha1(tree_oid, "tree_oid")
    _require_sha1(commit_oid, "commit_oid")
    if not hmac.compare_digest(
        commit_oid,
        _fixed_repair_commit_oid(tree_oid=tree_oid, head_oid=head_oid),
    ):
        raise ValueError("repair proposal commit does not match head")
    paths = _string_list(payload["changed_paths"])
    _require_paths(paths)
    preview = _as_object(payload["preview"])
    if set(preview) != _PREVIEW_FIELDS:
        raise ValueError("repair proposal preview fields are invalid")
    if (
        preview.get("schema_version") != 1
        or preview.get("state") != RepairState.VALIDATED.value
        or preview.get("candidate_id") != candidate_id
        or preview.get("validation_sha256") != validation_sha256
        or preview.get("changed_paths") != paths
        or preview.get("confirmation") != REPAIR_APPROVAL_CONFIRMATION
    ):
        raise ValueError("repair proposal preview identity is invalid")
    if domain_sha256(_PREVIEW_DOMAIN, preview) != preview_sha256:
        raise ValueError("repair proposal preview digest is invalid")
    _require_text(
        _as_str(preview["canonical_diff"]),
        "preview diff",
        maximum=GITHUB_PROPOSAL_MAX_BYTES,
        allow_controls=True,
    )
    branch = _as_str(payload["branch"])
    if branch != _repair_branch(candidate_id):
        raise ValueError("repair proposal branch is invalid")
    title = _as_str(payload["pull_request_title"])
    expected_title = _repair_pull_request_title(candidate_id)
    if title != expected_title:
        raise ValueError("repair proposal pull request title is invalid")
    body = _as_str(payload["pull_request_body"])
    marker = _repair_pull_request_marker(candidate_id)
    if body != _repair_pull_request_body(marker):
        raise ValueError("repair proposal pull request body is invalid")
    _require_text(body, "pull request body", maximum=64 * 1024, allow_controls=True)


def _validate_readback(
    kind: GitHubProposalKind,
    state: GitHubPublicationState,
    value: dict[str, JSONValue],
) -> None:
    if kind is GitHubProposalKind.CHECK:
        expected = {
            "repository_id",
            "check_run_id",
            "check_run_node_id",
            "head_oid",
            "external_id",
            "status",
            "conclusion",
            "check_run_url",
        }
        if set(value) != expected:
            raise ValueError("check readback fields are invalid")
        _require_positive_int(_as_int(value["repository_id"]), "repository_id")
        _require_positive_int(_as_int(value["check_run_id"]), "check_run_id")
        _require_text(_as_str(value["check_run_node_id"]), "check_run_node_id", maximum=255)
        _require_sha1(value["head_oid"], "head_oid")
        _require_sha256(value["external_id"], "external_id")
        if value["status"] != "completed" or value["conclusion"] not in {
            "success",
            "neutral",
            "failure",
        }:
            raise ValueError("check readback state is invalid")
        _require_github_url(_as_str(value["check_run_url"]))
        return
    base_fields = {"repository_id", "branch_ref", "commit_oid"}
    expected = base_fields
    if state is GitHubPublicationState.REPAIR_PUBLISHED:
        expected = base_fields | {
            "pull_request_id",
            "pull_request_number",
            "pull_request_node_id",
            "pull_request_url",
            "draft",
            "state",
            "base_ref",
            "head_ref",
            "base_repository_id",
            "head_repository_id",
            "pull_request_title",
            "pull_request_body",
            "body_marker",
        }
    if set(value) != expected:
        raise ValueError("repair readback fields are invalid")
    _require_positive_int(_as_int(value["repository_id"]), "repository_id")
    ref = _as_str(value["branch_ref"])
    if not ref.startswith("refs/heads/repoguard/repairs/"):
        raise ValueError("repair readback ref is invalid")
    _require_sha256(ref.removeprefix("refs/heads/repoguard/repairs/"), "candidate_id")
    _require_sha1(value["commit_oid"], "commit_oid")
    if state is GitHubPublicationState.REPAIR_PUBLISHED:
        _require_positive_int(_as_int(value["pull_request_id"]), "pull_request_id")
        _require_positive_int(_as_int(value["pull_request_number"]), "pull_request_number")
        _require_text(
            _as_str(value["pull_request_node_id"]),
            "pull_request_node_id",
            maximum=255,
        )
        _require_github_url(_as_str(value["pull_request_url"]))
        if value["draft"] is not True:
            raise ValueError("repair pull request must be draft")
        if value["state"] != "open":
            raise ValueError("repair pull request must be open")
        _require_text(_as_str(value["base_ref"]), "base_ref", maximum=255)
        _require_text(_as_str(value["head_ref"]), "head_ref", maximum=255)
        _require_positive_int(
            _as_int(value["base_repository_id"]),
            "base_repository_id",
        )
        _require_positive_int(
            _as_int(value["head_repository_id"]),
            "head_repository_id",
        )
        _require_text(
            _as_str(value["pull_request_title"]),
            "pull_request_title",
            maximum=255,
        )
        _require_text(
            _as_str(value["pull_request_body"]),
            "pull_request_body",
            maximum=64 * 1024,
            allow_controls=True,
        )
        _require_text(
            _as_str(value["body_marker"]),
            "body_marker",
            maximum=255,
            allow_controls=False,
        )


def _validate_readback_against_proposal(
    proposal: GitHubProposal,
    *,
    state: GitHubPublicationState,
    readback: dict[str, JSONValue],
) -> None:
    if readback.get("repository_id") != proposal.repository_id:
        raise ValueError("publication repository does not match proposal")
    payload = proposal.payload
    if proposal.kind is GitHubProposalKind.CHECK:
        review = _as_object(payload["review_result"])
        if (
            state is not GitHubPublicationState.CHECK_PUBLISHED
            or readback.get("head_oid") != proposal.head_oid
            or readback.get("external_id") != payload["external_id"]
            or readback.get("conclusion") != review["conclusion"]
        ):
            raise ValueError("check readback does not match proposal")
        check_run_id = _as_int(readback["check_run_id"])
        expected_url = f"https://github.com/{proposal.repository_full_name}/runs/{check_run_id}"
        if readback.get("check_run_url") != expected_url:
            raise ValueError("check readback URL does not match proposal")
        return
    candidate_id = _as_str(payload["candidate_id"])
    branch = _as_str(payload["branch"])
    if (
        readback.get("branch_ref") != f"refs/heads/{branch}"
        or readback.get("commit_oid") != payload["commit_oid"]
    ):
        raise ValueError("repair readback does not match proposal")
    if state is GitHubPublicationState.BRANCH_CREATED:
        return
    pull_request_number = _as_int(readback["pull_request_number"])
    marker = _repair_pull_request_marker(candidate_id)
    if (
        pull_request_number == proposal.pull_request_number
        or readback.get("pull_request_url")
        != f"https://github.com/{proposal.repository_full_name}/pull/{pull_request_number}"
        or readback.get("base_ref") != proposal.base_ref
        or readback.get("head_ref") != branch
        or readback.get("base_repository_id") != proposal.repository_id
        or readback.get("head_repository_id") != proposal.repository_id
        or readback.get("pull_request_title") != payload["pull_request_title"]
        or readback.get("pull_request_body") != payload["pull_request_body"]
        or readback.get("body_marker") != marker
    ):
        raise ValueError("repair pull request readback does not match proposal")


def _parse_payload_json(value: object) -> dict[str, JSONValue]:
    if type(value) is not str:
        raise ValueError("proposal payload JSON is invalid")
    return _as_object(
        parse_canonical_json(value.encode("utf-8"), max_bytes=GITHUB_PROPOSAL_MAX_BYTES)
    )


def _parse_readback_json(value: object) -> dict[str, JSONValue]:
    if type(value) is not str:
        raise ValueError("publication readback JSON is invalid")
    return _as_object(parse_canonical_json(value.encode("utf-8"), max_bytes=1024 * 1024))


def _confirmation_for_kind(kind: GitHubProposalKind) -> str:
    return (
        GITHUB_CHECK_CONFIRMATION
        if kind is GitHubProposalKind.CHECK
        else GITHUB_REPAIR_CONFIRMATION
    )


def _require_schema(value: object) -> None:
    if type(value) is not int or value != 1:
        raise ValueError("schema_version must be 1")


def _require_sha256(value: object, name: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_sha1(value: object, name: str) -> None:
    if type(value) is not str or _SHA1_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_positive_int(value: object, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} is invalid")


def _require_timestamp(value: object, name: str) -> None:
    if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_807:
        raise ValueError(f"{name} is invalid")


def _require_name(value: object, name: str) -> None:
    if type(value) is not str or _NAME_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_full_name(value: object) -> None:
    if type(value) is not str or _FULL_NAME_PATTERN.fullmatch(value) is None or ".." in value:
        raise ValueError("repository full name is invalid")


def _require_text(
    value: object,
    name: str,
    *,
    maximum: int,
    allow_controls: bool = False,
) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{name} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} is invalid") from error
    if len(encoded) > maximum or "\x00" in value or "\r" in value:
        raise ValueError(f"{name} is invalid")
    if not allow_controls and any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError(f"{name} is invalid")


def _require_escaped_text(value: str, name: str, *, maximum: int) -> None:
    _require_text(value, name, maximum=maximum, allow_controls=True)
    if any(character in value for character in ("@", "<", ">")):
        raise ValueError(f"{name} is not escaped")


def _require_repository_path(value: str) -> None:
    _require_text(value, "repository path", maximum=1024)
    if value.startswith("/") or value.endswith("/") or "\\" in value:
        raise ValueError("repository path is invalid")
    parts = value.split("/")
    if any(part.casefold() in _PATH_FORBIDDEN or len(part.encode("utf-8")) > 255 for part in parts):
        raise ValueError("repository path is invalid")


def _require_paths(value: list[str]) -> None:
    if not value or len(value) > 32:
        raise ValueError("changed paths are invalid")
    for path in value:
        _require_repository_path(path)
    if value != sorted(value, key=str.encode) or len(value) != len(set(value)):
        raise ValueError("changed paths are invalid")


def _require_github_url(value: str) -> None:
    _require_text(value, "GitHub URL", maximum=2048)
    if not value.startswith("https://github.com/") or "?" in value or "#" in value:
        raise ValueError("GitHub URL is invalid")


def _as_object(value: JSONValue) -> dict[str, JSONValue]:
    if type(value) is not dict:
        raise ValueError("GitHub JSON object is invalid")
    return value


def _as_str(value: JSONValue) -> str:
    if type(value) is not str:
        raise ValueError("GitHub JSON string is invalid")
    return value


def _as_int(value: JSONValue) -> int:
    if type(value) is not int:
        raise ValueError("GitHub JSON integer is invalid")
    return value


def _string_list(value: JSONValue) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError("GitHub JSON string list is invalid")
    return cast(list[str], value)
