"""Approval-bound publication to the fixed GitHub.com REST API.

This module is the public M6 writer facade.  It deliberately keeps GitHub
transport, durable publication state, and the M5 repair manager injectable so
that publication state transitions can be exercised without ambient
credentials or network discovery.
"""

from __future__ import annotations

import base64
import hmac
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import quote

from repoguard._github_store import (
    GitHubPublicationStatus,
    GitHubPublicationStore,
    GitHubStoreError,
    LockedGitHubPublication,
)
from repoguard.github import (
    GITHUB_CHECK_CONFIRMATION,
    GITHUB_REPAIR_CONFIRMATION,
    GitHubApproval,
    GitHubApprovalInterface,
    GitHubPermission,
    GitHubProposal,
    GitHubProposalKind,
    GitHubPublicationResult,
    GitHubPublicationState,
    approve_github_proposal,
    build_github_result,
    validate_github_result,
)
from repoguard.github_transport import (
    GitHubJSONValue,
    GitHubMethod,
    GitHubTransport,
    GitHubTransportError,
    GitHubTransportErrorCode,
    GitHubTransportResponse,
)
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    REPAIR_PUBLICATION_AUTHOR_EMAIL,
    REPAIR_PUBLICATION_AUTHOR_NAME,
    REPAIR_PUBLICATION_COMMIT_MESSAGE,
    REPAIR_PUBLICATION_COMMIT_TIMESTAMP,
    RepairError,
    RepairPublicationBlob,
    RepairPublicationEntry,
    RepairPublicationManifest,
    RepairSnapshot,
    RepairState,
)

__all__ = [
    "GitHubPublicationError",
    "GitHubPublicationErrorCode",
    "GitHubPublicationErrorDomain",
    "GitHubPublicationService",
    "GitHubPublicationStage",
    "GitHubPublicationStatus",
    "GitHubPublicationStore",
    "GitHubSourcePullRequest",
]

_CHECK_NAME = "RepoGuard review"
_CHECK_ANNOTATION_BATCH = 50
_CHECK_ANNOTATION_PAGE = 100
_MAX_CHECK_ANNOTATIONS = 1_000
_MAX_CHECK_SUMMARY_BYTES = 60 * 1024
_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FULL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class GitHubPublicationErrorDomain(StrEnum):
    """Domain that produced a detached publication failure."""

    PUBLICATION = "github_publication"
    TRANSPORT = "github_transport"
    STORE = "github_store"
    REPAIR = "repair"


class GitHubPublicationErrorCode(StrEnum):
    """Stable service-owned publication failures."""

    INVALID_INPUT = "invalid_input"
    KIND_MISMATCH = "kind_mismatch"
    PROPOSAL_EXPIRED = "proposal_expired"
    APPROVAL_MISMATCH = "approval_mismatch"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    PERMISSION_DENIED = "permission_denied"
    REPOSITORY_MISMATCH = "repository_mismatch"
    FORK_UNSUPPORTED = "fork_unsupported"
    PULL_REQUEST_STALE = "pull_request_stale"
    REMOTE_CONFLICT = "remote_conflict"
    REMOTE_INVALID = "remote_invalid"
    AMBIGUOUS_WRITE = "ambiguous_write"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"


class GitHubPublicationStage(StrEnum):
    """Stable service stage, independent of request or response content."""

    INPUT = "input"
    STATUS = "status"
    PRINCIPAL = "principal"
    REPOSITORY = "repository"
    SOURCE_PULL_REQUEST = "source_pull_request"
    APPROVAL = "approval"
    CHECK = "check"
    LOCAL_REPAIR = "local_repair"
    OBJECTS = "objects"
    BRANCH = "branch"
    PULL_REQUEST = "pull_request"
    PERSISTENCE = "persistence"
    RECOVERY = "recovery"


_PUBLICATION_MESSAGES: dict[GitHubPublicationErrorCode, str] = {
    GitHubPublicationErrorCode.INVALID_INPUT: "GitHub publication input is invalid.",
    GitHubPublicationErrorCode.KIND_MISMATCH: "GitHub publication kind does not match.",
    GitHubPublicationErrorCode.PROPOSAL_EXPIRED: "GitHub publication proposal is expired.",
    GitHubPublicationErrorCode.APPROVAL_MISMATCH: "GitHub publication approval does not match.",
    GitHubPublicationErrorCode.PRINCIPAL_MISMATCH: ("GitHub publication principal does not match."),
    GitHubPublicationErrorCode.PERMISSION_DENIED: "GitHub publication permission is insufficient.",
    GitHubPublicationErrorCode.REPOSITORY_MISMATCH: (
        "GitHub publication repository does not match."
    ),
    GitHubPublicationErrorCode.FORK_UNSUPPORTED: ("GitHub publication is unavailable for a fork."),
    GitHubPublicationErrorCode.PULL_REQUEST_STALE: (
        "GitHub source pull request no longer matches."
    ),
    GitHubPublicationErrorCode.REMOTE_CONFLICT: "GitHub publication state conflicts.",
    GitHubPublicationErrorCode.REMOTE_INVALID: "GitHub publication read-back is invalid.",
    GitHubPublicationErrorCode.AMBIGUOUS_WRITE: ("GitHub publication write outcome is unresolved."),
    GitHubPublicationErrorCode.CAPABILITY_UNAVAILABLE: (
        "GitHub repair publication capability is unavailable."
    ),
}


class GitHubPublicationError(RuntimeError):
    """Content-free publication failure preserving the underlying stable code."""

    __slots__ = ("ambiguous", "code", "domain", "retryable", "stage")

    domain: GitHubPublicationErrorDomain
    code: str
    stage: GitHubPublicationStage
    retryable: bool
    ambiguous: bool

    def __init__(
        self,
        domain: GitHubPublicationErrorDomain,
        code: str,
        stage: GitHubPublicationStage,
        *,
        retryable: bool = False,
        ambiguous: bool = False,
    ) -> None:
        self.domain = domain
        self.code = code
        self.stage = stage
        self.retryable = retryable
        self.ambiguous = ambiguous
        if domain is GitHubPublicationErrorDomain.PUBLICATION:
            try:
                message = _PUBLICATION_MESSAGES[GitHubPublicationErrorCode(code)]
            except (KeyError, ValueError):
                message = "GitHub publication failed."
        elif domain is GitHubPublicationErrorDomain.TRANSPORT:
            message = "GitHub publication transport failed."
        elif domain is GitHubPublicationErrorDomain.STORE:
            message = "GitHub publication storage failed."
        else:
            message = "GitHub repair publication failed."
        super().__init__(message)
        self.__cause__ = None
        self.__context__ = None
        self.__traceback__ = None
        self.__suppress_context__ = True


@dataclass(frozen=True, slots=True)
class GitHubSourcePullRequest:
    """Strict content-free identity read from one GitHub source pull request."""

    repository_id: int
    repository_full_name: str
    repository_is_fork: bool
    pull_request_number: int
    base_ref: str
    base_oid: str
    head_oid: str
    base_repository_id: int
    base_repository_full_name: str
    head_repository_id: int
    head_repository_full_name: str
    same_repository: bool

    def __post_init__(self) -> None:
        _require_positive_int(self.repository_id)
        _require_full_name(self.repository_full_name)
        if type(self.repository_is_fork) is not bool:
            raise TypeError("repository_is_fork must be a bool")
        _require_positive_int(self.pull_request_number)
        _require_ref(self.base_ref)
        _require_sha1(self.base_oid)
        _require_sha1(self.head_oid)
        _require_positive_int(self.base_repository_id)
        _require_full_name(self.base_repository_full_name)
        _require_positive_int(self.head_repository_id)
        _require_full_name(self.head_repository_full_name)
        if type(self.same_repository) is not bool:
            raise TypeError("same_repository must be a bool")
        expected_same = (
            self.base_repository_id == self.repository_id
            and self.head_repository_id == self.repository_id
            and self.base_repository_full_name == self.repository_full_name
            and self.head_repository_full_name == self.repository_full_name
        )
        if self.same_repository != expected_same:
            raise ValueError("same_repository is invalid")

    @property
    def writable(self) -> bool:
        """Whether custom Check and repair publication are allowed."""
        return self.same_repository and not self.repository_is_fork


@dataclass(frozen=True, slots=True)
class _Principal:
    login: str
    actor_id: int
    permission: GitHubPermission


@dataclass(frozen=True, slots=True)
class _CheckRun:
    check_run_id: int
    node_id: str
    name: str
    head_oid: str
    external_id: str
    status: str
    conclusion: str | None
    url: str
    annotation_count: int
    output_title: str
    output_summary: str


@dataclass(frozen=True, slots=True)
class _PullRequest:
    pull_request_id: int
    number: int
    node_id: str
    url: str
    draft: bool
    state: str
    base_ref: str
    head_ref: str
    base_repository_id: int
    head_repository_id: int
    title: str
    body: str = field(repr=False)


class _Transport(Protocol):
    def request(
        self,
        method: GitHubMethod,
        path: str,
        body: dict[str, GitHubJSONValue] | None = None,
    ) -> GitHubTransportResponse: ...


class _RepairSession(Protocol):
    def snapshot(self) -> RepairSnapshot: ...

    def approve(
        self,
        *,
        subject: str,
        expected_candidate_id: str,
        expected_validation_sha256: str,
        confirmation: str,
    ) -> RepairSnapshot: ...

    def apply(self, *, expected_approval_sha256: str) -> RepairSnapshot: ...

    def publication_manifest(
        self,
        *,
        expected_application_sha256: str,
    ) -> RepairPublicationManifest: ...

    def publication_blob(
        self,
        *,
        manifest: RepairPublicationManifest,
        entry: RepairPublicationEntry,
    ) -> RepairPublicationBlob: ...


class _RepairManager(Protocol):
    def open_session(self, session_id: str) -> _RepairSession: ...


class GitHubPublicationService:
    """Synchronous approval-bound GitHub publication facade."""

    __slots__ = (
        "_clock",
        "_expected_principal_login",
        "_interface",
        "_repair_manager",
        "_store",
        "_transport",
    )

    def __init__(
        self,
        *,
        transport: GitHubTransport,
        store: GitHubPublicationStore,
        interface: GitHubApprovalInterface,
        repair_manager: _RepairManager | None = None,
        clock: Callable[[], int] | None = None,
        expected_principal_login: str | None = None,
    ) -> None:
        if not isinstance(transport, GitHubTransport):
            raise TypeError("transport must be a GitHubTransport")
        if not isinstance(store, GitHubPublicationStore):
            raise TypeError("store must be a GitHubPublicationStore")
        if type(interface) is not GitHubApprovalInterface:
            raise TypeError("interface must be a GitHubApprovalInterface")
        if repair_manager is not None and not callable(
            getattr(repair_manager, "open_session", None)
        ):
            raise TypeError("repair_manager must provide open_session or be None")
        selected_clock = _wall_clock_us if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("clock must be callable")
        if expected_principal_login is not None and (
            type(expected_principal_login) is not str
            or _LOGIN_PATTERN.fullmatch(expected_principal_login) is None
        ):
            raise ValueError("expected_principal_login is invalid")
        self._transport: _Transport = transport
        self._store = store
        self._interface = interface
        self._repair_manager: _RepairManager | None = repair_manager
        self._clock = selected_clock
        self._expected_principal_login = expected_principal_login

    def status(self, proposal_sha256: str) -> GitHubPublicationStatus:
        """Return durable public status without the private M5 session binding."""
        _require_sha256_input(proposal_sha256)
        try:
            return self._store.status(proposal_sha256)
        except GitHubStoreError as error:
            raise _store_failure(error, GitHubPublicationStage.STATUS) from None

    def read_source_pull_request(
        self,
        *,
        repository_id: int,
        repository_full_name: str,
        pull_request_number: int,
        require_same_repository: bool = False,
    ) -> GitHubSourcePullRequest:
        """Read exact source-PR identity without creating a proposal or write."""
        try:
            _require_positive_int(repository_id)
            _require_full_name(repository_full_name)
            _require_positive_int(pull_request_number)
            if type(require_same_repository) is not bool:
                raise TypeError
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.INVALID_INPUT,
                GitHubPublicationStage.INPUT,
            ) from None
        repository = self._read_repository(
            repository_id=repository_id,
            repository_full_name=repository_full_name,
        )
        source = self._read_source_pull_request(
            repository=repository,
            pull_request_number=pull_request_number,
        )
        if require_same_repository and not source.writable:
            code = (
                GitHubPublicationErrorCode.FORK_UNSUPPORTED
                if source.repository_is_fork
                else GitHubPublicationErrorCode.REPOSITORY_MISMATCH
            )
            raise _publication_failure(code, GitHubPublicationStage.SOURCE_PULL_REQUEST)
        return source

    def publish_check(
        self,
        proposal_sha256: str,
        *,
        confirmation: str,
    ) -> GitHubPublicationResult:
        """Approve and idempotently publish one exact Check Run."""
        _require_sha256_input(proposal_sha256)
        _require_confirmation(confirmation, GITHUB_CHECK_CONFIRMATION)
        try:
            with self._store.locked_publication(proposal_sha256) as publication:
                status = publication.status()
                proposal = _require_kind(status.proposal, GitHubProposalKind.CHECK)
                if status.result is not None:
                    self._revalidate_final_result(
                        publication,
                        proposal,
                        approval=status.approval,
                        result=status.result,
                    )
                    return status.result
                principal, source = self._authorize(
                    proposal,
                    saved_approval=status.approval,
                    stage=GitHubPublicationStage.CHECK,
                )
                approval = self._approval(
                    publication,
                    proposal=proposal,
                    saved=status.approval,
                    principal=principal,
                    confirmation=confirmation,
                )
                result = self._publish_check_locked(
                    proposal,
                    approval,
                    source=source,
                )
                return publication.record_result(result).result or result
        except GitHubPublicationError:
            raise
        except GitHubStoreError as error:
            raise _store_failure(error, GitHubPublicationStage.PERSISTENCE) from None

    def publish_repair(
        self,
        proposal_sha256: str,
        *,
        confirmation: str,
    ) -> GitHubPublicationResult:
        """Approve, locally apply, and publish one exact repair draft PR."""
        _require_sha256_input(proposal_sha256)
        _require_confirmation(confirmation, GITHUB_REPAIR_CONFIRMATION)
        return self._publish_repair(proposal_sha256, confirmation=confirmation, recover=False)

    def recover_repair(self, proposal_sha256: str) -> GitHubPublicationResult:
        """Resume a branch-created repair using only its stored exact approval."""
        _require_sha256_input(proposal_sha256)
        return self._publish_repair(proposal_sha256, confirmation=None, recover=True)

    def recover(self, proposal_sha256: str) -> GitHubPublicationResult:
        """Resume a stored partial repair publication without a new approval."""
        return self.recover_repair(proposal_sha256)

    def _publish_repair(
        self,
        proposal_sha256: str,
        *,
        confirmation: str | None,
        recover: bool,
    ) -> GitHubPublicationResult:
        try:
            with self._store.locked_publication(proposal_sha256) as publication:
                status = publication.status()
                proposal = _require_kind(status.proposal, GitHubProposalKind.REPAIR)
                if status.result is not None:
                    self._revalidate_final_result(
                        publication,
                        proposal,
                        approval=status.approval,
                        result=status.result,
                    )
                    return status.result
                if recover and status.partial_result is None:
                    raise _publication_failure(
                        GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                        GitHubPublicationStage.RECOVERY,
                    )
                principal, source = self._authorize(
                    proposal,
                    saved_approval=status.approval,
                    stage=(
                        GitHubPublicationStage.RECOVERY
                        if recover
                        else GitHubPublicationStage.LOCAL_REPAIR
                    ),
                )
                if recover:
                    approval = _require_saved_approval(status.approval, principal)
                else:
                    assert confirmation is not None
                    approval = self._approval(
                        publication,
                        proposal=proposal,
                        saved=status.approval,
                        principal=principal,
                        confirmation=confirmation,
                    )
                result = self._publish_repair_locked(
                    publication,
                    proposal=proposal,
                    approval=approval,
                    source=source,
                    partial=status.partial_result,
                )
                saved = publication.record_result(result).result
                return result if saved is None else saved
        except GitHubPublicationError:
            raise
        except GitHubStoreError as error:
            raise _store_failure(error, GitHubPublicationStage.PERSISTENCE) from None
        except RepairError as error:
            raise _repair_failure(error, GitHubPublicationStage.LOCAL_REPAIR) from None

    def _authorize(
        self,
        proposal: GitHubProposal,
        *,
        saved_approval: GitHubApproval | None,
        stage: GitHubPublicationStage,
    ) -> tuple[_Principal, GitHubSourcePullRequest]:
        principal = self._read_principal(proposal.repository_full_name)
        if saved_approval is not None:
            _require_saved_approval(saved_approval, principal)
        source = self.read_source_pull_request(
            repository_id=proposal.repository_id,
            repository_full_name=proposal.repository_full_name,
            pull_request_number=proposal.pull_request_number,
            require_same_repository=True,
        )
        if (
            source.base_ref != proposal.base_ref
            or source.base_oid != proposal.base_oid
            or source.head_oid != proposal.head_oid
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.PULL_REQUEST_STALE,
                stage,
            )
        return principal, source

    def _revalidate_final_result(
        self,
        publication: LockedGitHubPublication,
        proposal: GitHubProposal,
        *,
        approval: GitHubApproval | None,
        result: GitHubPublicationResult,
    ) -> None:
        principal = self._read_principal(proposal.repository_full_name)
        saved = _require_saved_approval(approval, principal)
        self._read_repository(
            repository_id=proposal.repository_id,
            repository_full_name=proposal.repository_full_name,
        )
        try:
            if result.approval != saved:
                raise ValueError
            validate_github_result(proposal, result)
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                GitHubPublicationStage.STATUS,
            ) from None
        if proposal.kind is GitHubProposalKind.CHECK:
            self._revalidate_final_check(proposal, result)
        else:
            self._revalidate_final_repair(
                publication,
                proposal,
                approval=saved,
                result=result,
            )

    def _revalidate_final_check(
        self,
        proposal: GitHubProposal,
        result: GitHubPublicationResult,
    ) -> None:
        payload = proposal.payload
        readback = result.readback
        try:
            check_run_id = _positive_int(readback.get("check_run_id"))
            external_id = _sha256(payload.get("external_id"))
            summary = _string(payload.get("summary"))
            review = _object(payload.get("review_result"))
            conclusion = _string(review.get("conclusion"))
            annotations = _list(payload.get("annotations"))
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.CHECK,
            ) from None
        check = self._read_check_run(proposal, check_run_id)
        self._require_check_identity(
            proposal,
            check,
            external_id=external_id,
            summary=summary,
            conclusion=conclusion,
            final=True,
        )
        if self._read_check_annotations(proposal, check) != annotations:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        current: dict[str, object] = {
            "repository_id": proposal.repository_id,
            "check_run_id": check.check_run_id,
            "check_run_node_id": check.node_id,
            "head_oid": check.head_oid,
            "external_id": check.external_id,
            "status": check.status,
            "conclusion": check.conclusion,
            "check_run_url": check.url,
        }
        if current != readback:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )

    def _revalidate_final_repair(
        self,
        publication: LockedGitHubPublication,
        proposal: GitHubProposal,
        *,
        approval: GitHubApproval,
        result: GitHubPublicationResult,
    ) -> None:
        payload = proposal.payload
        readback = result.readback
        try:
            branch = _string(payload.get("branch"))
            title = _string(payload.get("pull_request_title"))
            body = _string(payload.get("pull_request_body"))
            candidate_id = _sha256(payload.get("candidate_id"))
            marker = f"<!-- repoguard-repair-candidate:{candidate_id} -->"
            validation_sha256 = _sha256(payload.get("validation_sha256"))
            tree_oid = _sha1(payload.get("tree_oid"))
            commit_oid = _sha1(payload.get("commit_oid"))
            pull_request_number = _positive_int(readback.get("pull_request_number"))
            application_sha256 = _sha256(result.application_sha256)
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.PULL_REQUEST,
            ) from None
        if self._repair_manager is None:
            raise _publication_failure(
                GitHubPublicationErrorCode.CAPABILITY_UNAVAILABLE,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        session = self._repair_manager.open_session(publication.repair_session_id())
        snapshot = session.snapshot()
        self._require_local_snapshot(
            snapshot,
            proposal=proposal,
            subject=f"github:{approval.actor_login}:{approval.actor_id}",
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
            allow_validated=False,
        )
        if (
            snapshot.state is not RepairState.APPLIED
            or snapshot.application is None
            or snapshot.application.application_sha256 != application_sha256
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        manifest = session.publication_manifest(
            expected_application_sha256=application_sha256,
        )
        changed_paths = tuple(_string(item) for item in _list(payload.get("changed_paths")))
        self._require_manifest(
            manifest,
            proposal=proposal,
            snapshot=snapshot,
            changed_paths=changed_paths,
            expected_tree_oid=tree_oid,
            expected_commit_oid=commit_oid,
        )
        for entry in manifest.entries:
            blob = session.publication_blob(manifest=manifest, entry=entry)
            if (
                type(blob) is not RepairPublicationBlob
                or blob.manifest_sha256 != manifest.manifest_sha256
                or blob.entry != entry
                or not self._blob_exists(proposal, entry)
            ):
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_CONFLICT,
                    GitHubPublicationStage.OBJECTS,
                )
            blob = cast(RepairPublicationBlob, None)
        if not self._git_object_exists(
            proposal,
            kind="trees",
            object_oid=tree_oid,
            stage=GitHubPublicationStage.OBJECTS,
        ) or not self._commit_exists(
            proposal,
            commit_oid=commit_oid,
            tree_oid=tree_oid,
            parent_oid=proposal.head_oid,
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.OBJECTS,
            )
        branch_ref = f"refs/heads/{branch}"
        if (
            self._read_branch(
                proposal,
                branch_ref=branch_ref,
                allow_missing=False,
            )
            != commit_oid
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.BRANCH,
            )
        pull_request = self._read_replacement_pull_request(
            proposal,
            pull_request_number,
        )
        self._require_replacement_pull_request(
            proposal,
            pull_request,
            branch=branch,
            title=title,
            body=body,
            marker=marker,
        )
        current: dict[str, object] = {
            "repository_id": proposal.repository_id,
            "branch_ref": branch_ref,
            "commit_oid": commit_oid,
            "pull_request_id": pull_request.pull_request_id,
            "pull_request_number": pull_request.number,
            "pull_request_node_id": pull_request.node_id,
            "pull_request_url": pull_request.url,
            "draft": pull_request.draft,
            "state": pull_request.state,
            "base_ref": pull_request.base_ref,
            "head_ref": pull_request.head_ref,
            "base_repository_id": pull_request.base_repository_id,
            "head_repository_id": pull_request.head_repository_id,
            "pull_request_title": pull_request.title,
            "pull_request_body": pull_request.body,
            "body_marker": marker,
        }
        if current != readback:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.PULL_REQUEST,
            )

    def _approval(
        self,
        publication: LockedGitHubPublication,
        *,
        proposal: GitHubProposal,
        saved: GitHubApproval | None,
        principal: _Principal,
        confirmation: str,
    ) -> GitHubApproval:
        if saved is not None:
            _require_saved_approval(saved, principal)
            if not hmac.compare_digest(saved.confirmation, confirmation):
                raise _publication_failure(
                    GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                    GitHubPublicationStage.APPROVAL,
                )
            return saved
        now = self._now()
        if not proposal.created_at_us <= now < proposal.expires_at_us:
            raise _publication_failure(
                GitHubPublicationErrorCode.PROPOSAL_EXPIRED,
                GitHubPublicationStage.APPROVAL,
            )
        try:
            approval = approve_github_proposal(
                proposal,
                actor_login=principal.login,
                actor_id=principal.actor_id,
                permission=principal.permission,
                interface=self._interface,
                confirmation=confirmation,
                approved_at_us=now,
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                GitHubPublicationStage.APPROVAL,
            ) from None
        saved_status = publication.record_approval(approval)
        if saved_status.approval != approval:
            raise _publication_failure(
                GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                GitHubPublicationStage.PERSISTENCE,
            )
        return approval

    def _read_principal(self, repository_full_name: str) -> _Principal:
        user = _object(
            self._request(GitHubMethod.GET, "/user", stage=GitHubPublicationStage.PRINCIPAL)
        )
        try:
            login = _string(user.get("login"))
            actor_id = _positive_int(user.get("id"))
            if _LOGIN_PATTERN.fullmatch(login) is None:
                raise ValueError
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.PRINCIPAL,
            ) from None
        if self._expected_principal_login is not None and not hmac.compare_digest(
            login, self._expected_principal_login
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.PRINCIPAL_MISMATCH,
                GitHubPublicationStage.PRINCIPAL,
            )
        permission_path = f"/repos/{repository_full_name}/collaborators/{login}/permission"
        permission_body = _object(
            self._request(
                GitHubMethod.GET,
                permission_path,
                stage=GitHubPublicationStage.PRINCIPAL,
            )
        )
        try:
            raw_permission = _string(permission_body.get("permission"))
            permission_user = _object(permission_body.get("user"))
            if (
                _string(permission_user.get("login")) != login
                or _positive_int(permission_user.get("id")) != actor_id
            ):
                raise ValueError
            permission = GitHubPermission(raw_permission)
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.PERMISSION_DENIED,
                GitHubPublicationStage.PRINCIPAL,
            ) from None
        return _Principal(login, actor_id, permission)

    def _read_repository(
        self,
        *,
        repository_id: int,
        repository_full_name: str,
    ) -> tuple[int, str, bool]:
        body = _object(
            self._request(
                GitHubMethod.GET,
                f"/repos/{repository_full_name}",
                stage=GitHubPublicationStage.REPOSITORY,
            )
        )
        try:
            remote_id = _positive_int(body.get("id"))
            remote_name = _string(body.get("full_name"))
            is_fork = _bool(body.get("fork"))
            if remote_id != repository_id or remote_name != repository_full_name:
                raise ValueError
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REPOSITORY_MISMATCH,
                GitHubPublicationStage.REPOSITORY,
            ) from None
        return remote_id, remote_name, is_fork

    def _read_source_pull_request(
        self,
        *,
        repository: tuple[int, str, bool],
        pull_request_number: int,
    ) -> GitHubSourcePullRequest:
        repository_id, repository_full_name, is_fork = repository
        body = _object(
            self._request(
                GitHubMethod.GET,
                f"/repos/{repository_full_name}/pulls/{pull_request_number}",
                stage=GitHubPublicationStage.SOURCE_PULL_REQUEST,
            )
        )
        try:
            if _positive_int(body.get("number")) != pull_request_number:
                raise ValueError
            if _string(body.get("state")) != "open":
                raise ValueError
            base = _object(body.get("base"))
            head = _object(body.get("head"))
            base_repo = _object(base.get("repo"))
            head_repo = _object(head.get("repo"))
            base_ref = _string(base.get("ref"))
            base_oid = _string(base.get("sha"))
            head_oid = _string(head.get("sha"))
            base_repository_id = _positive_int(base_repo.get("id"))
            base_repository_full_name = _string(base_repo.get("full_name"))
            head_repository_id = _positive_int(head_repo.get("id"))
            head_repository_full_name = _string(head_repo.get("full_name"))
            source = GitHubSourcePullRequest(
                repository_id=repository_id,
                repository_full_name=repository_full_name,
                repository_is_fork=is_fork,
                pull_request_number=pull_request_number,
                base_ref=base_ref,
                base_oid=base_oid,
                head_oid=head_oid,
                base_repository_id=base_repository_id,
                base_repository_full_name=base_repository_full_name,
                head_repository_id=head_repository_id,
                head_repository_full_name=head_repository_full_name,
                same_repository=(
                    base_repository_id == repository_id
                    and head_repository_id == repository_id
                    and base_repository_full_name == repository_full_name
                    and head_repository_full_name == repository_full_name
                ),
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.PULL_REQUEST_STALE,
                GitHubPublicationStage.SOURCE_PULL_REQUEST,
            ) from None
        return source

    def _publish_check_locked(
        self,
        proposal: GitHubProposal,
        approval: GitHubApproval,
        *,
        source: GitHubSourcePullRequest,
    ) -> GitHubPublicationResult:
        _require_source_matches_proposal(source, proposal)
        payload = proposal.payload
        try:
            external_id = _sha256(payload.get("external_id"))
            summary = _string(payload.get("summary"))
            if len(summary.encode("utf-8")) > _MAX_CHECK_SUMMARY_BYTES:
                raise ValueError
            review = _object(payload.get("review_result"))
            conclusion = _string(review.get("conclusion"))
            if conclusion not in {"success", "neutral", "failure"}:
                raise ValueError
            annotations_value = payload.get("annotations")
            if type(annotations_value) is not list:
                raise ValueError
            annotations = annotations_value
            if len(annotations) > _MAX_CHECK_ANNOTATIONS or any(
                type(item) is not dict for item in annotations
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.INVALID_INPUT,
                GitHubPublicationStage.CHECK,
            ) from None

        check = self._find_check_run(proposal, external_id=external_id)
        if check is None:
            first = annotations[:_CHECK_ANNOTATION_BATCH]
            check = self._create_check_run(
                proposal,
                external_id=external_id,
                summary=summary,
                annotations=first,
            )
        self._require_check_identity(
            proposal,
            check,
            external_id=external_id,
            summary=summary,
            conclusion=conclusion,
            final=False,
        )

        current_annotations = self._read_check_annotations(
            proposal,
            check,
        )
        if current_annotations != annotations[: len(current_annotations)]:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        if len(current_annotations) > len(annotations):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        if check.status == "completed" and len(current_annotations) != len(annotations):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        while len(current_annotations) < len(annotations):
            start = len(current_annotations)
            end = min(start + _CHECK_ANNOTATION_BATCH, len(annotations))
            expected = annotations[:end]
            self._append_check_annotations(
                proposal,
                check,
                summary=summary,
                annotations=annotations[start:end],
                expected=expected,
            )
            check = self._read_check_run(proposal, check.check_run_id)
            current_annotations = self._read_check_annotations(proposal, check)
            if current_annotations != expected:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_CONFLICT,
                    GitHubPublicationStage.CHECK,
                )

        if check.status == "completed":
            self._require_check_identity(
                proposal,
                check,
                external_id=external_id,
                summary=summary,
                conclusion=conclusion,
                final=True,
            )
        else:
            check = self._complete_check_run(
                proposal,
                check,
                summary=summary,
                conclusion=conclusion,
            )
        final = self._read_check_run(proposal, check.check_run_id)
        self._require_check_identity(
            proposal,
            final,
            external_id=external_id,
            summary=summary,
            conclusion=conclusion,
            final=True,
        )
        final_annotations = self._read_check_annotations(proposal, final)
        if final_annotations != annotations:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        readback: dict[str, object] = {
            "repository_id": proposal.repository_id,
            "check_run_id": final.check_run_id,
            "check_run_node_id": final.node_id,
            "head_oid": final.head_oid,
            "external_id": final.external_id,
            "status": final.status,
            "conclusion": final.conclusion,
            "check_run_url": final.url,
        }
        try:
            return build_github_result(
                proposal,
                approval,
                state=GitHubPublicationState.CHECK_PUBLISHED,
                application_sha256=None,
                readback=readback,
                published_at_us=max(self._now(), approval.approved_at_us),
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.CHECK,
            ) from None

    def _find_check_run(
        self,
        proposal: GitHubProposal,
        *,
        external_id: str,
    ) -> _CheckRun | None:
        name = quote(_CHECK_NAME, safe="")
        body = _object(
            self._request(
                GitHubMethod.GET,
                (
                    f"/repos/{proposal.repository_full_name}/commits/{proposal.head_oid}"
                    f"/check-runs?check_name={name}&filter=all&per_page=100"
                ),
                stage=GitHubPublicationStage.CHECK,
            )
        )
        try:
            total_count = _nonnegative_int(body.get("total_count"))
            values = _list(body.get("check_runs"))
            if total_count > 100 or len(values) > 100:
                raise ValueError
            matching = [
                _parse_check_run(_object(value))
                for value in values
                if _object(value).get("external_id") == external_id
            ]
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.CHECK,
            ) from None
        if len(matching) > 1:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )
        return None if not matching else matching[0]

    def _read_check_run(self, proposal: GitHubProposal, check_run_id: int) -> _CheckRun:
        body = _object(
            self._request(
                GitHubMethod.GET,
                f"/repos/{proposal.repository_full_name}/check-runs/{check_run_id}",
                stage=GitHubPublicationStage.CHECK,
            )
        )
        try:
            return _parse_check_run(body)
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.CHECK,
            ) from None

    def _read_check_annotations(
        self,
        proposal: GitHubProposal,
        check: _CheckRun,
    ) -> list[GitHubJSONValue]:
        if not 0 <= check.annotation_count <= _MAX_CHECK_ANNOTATIONS:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.CHECK,
            )
        result: list[GitHubJSONValue] = []
        page = 1
        while len(result) < check.annotation_count:
            body = _list(
                self._request(
                    GitHubMethod.GET,
                    (
                        f"/repos/{proposal.repository_full_name}/check-runs/"
                        f"{check.check_run_id}/annotations"
                        f"?per_page={_CHECK_ANNOTATION_PAGE}&page={page}"
                    ),
                    stage=GitHubPublicationStage.CHECK,
                )
            )
            if not body or len(body) > _CHECK_ANNOTATION_PAGE:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.CHECK,
                )
            try:
                result.extend(_annotation_projection(_object(value)) for value in body)
            except (TypeError, ValueError):
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.CHECK,
                ) from None
            if len(result) > check.annotation_count:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.CHECK,
                )
            page += 1
        return result

    def _create_check_run(
        self,
        proposal: GitHubProposal,
        *,
        external_id: str,
        summary: str,
        annotations: list[GitHubJSONValue],
    ) -> _CheckRun:
        path = f"/repos/{proposal.repository_full_name}/check-runs"
        request: dict[str, GitHubJSONValue] = {
            "name": _CHECK_NAME,
            "head_sha": proposal.head_oid,
            "external_id": external_id,
            "status": "in_progress",
            "output": {
                "title": _CHECK_NAME,
                "summary": summary,
                "annotations": annotations,
            },
        }
        try:
            response = self._transport.request(GitHubMethod.POST, path, request)
            return _parse_check_run(_object(response.body))
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.CHECK) from None
        except (TypeError, ValueError):
            pass
        readback = self._find_check_run(proposal, external_id=external_id)
        if readback is None:
            raise _ambiguous_failure(GitHubPublicationStage.CHECK)
        return readback

    def _append_check_annotations(
        self,
        proposal: GitHubProposal,
        check: _CheckRun,
        *,
        summary: str,
        annotations: list[GitHubJSONValue],
        expected: list[GitHubJSONValue],
    ) -> None:
        request: dict[str, GitHubJSONValue] = {
            "status": "in_progress",
            "output": {
                "title": _CHECK_NAME,
                "summary": summary,
                "annotations": annotations,
            },
        }
        try:
            response = self._transport.request(
                GitHubMethod.PATCH,
                (f"/repos/{proposal.repository_full_name}/check-runs/{check.check_run_id}"),
                request,
            )
            parsed = _parse_check_run(_object(response.body))
            if parsed.check_run_id != check.check_run_id:
                raise ValueError
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.CHECK) from None
            current = self._read_check_run(proposal, check.check_run_id)
            actual = self._read_check_annotations(proposal, current)
            if actual == expected:
                return
            raise _ambiguous_failure(GitHubPublicationStage.CHECK) from None
        except (TypeError, ValueError):
            current = self._read_check_run(proposal, check.check_run_id)
            actual = self._read_check_annotations(proposal, current)
            if actual == expected:
                return
            raise _ambiguous_failure(GitHubPublicationStage.CHECK) from None

    def _complete_check_run(
        self,
        proposal: GitHubProposal,
        check: _CheckRun,
        *,
        summary: str,
        conclusion: str,
    ) -> _CheckRun:
        request: dict[str, GitHubJSONValue] = {
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": _CHECK_NAME, "summary": summary},
        }
        try:
            response = self._transport.request(
                GitHubMethod.PATCH,
                (f"/repos/{proposal.repository_full_name}/check-runs/{check.check_run_id}"),
                request,
            )
            parsed = _parse_check_run(_object(response.body))
            if parsed.check_run_id != check.check_run_id:
                raise ValueError
            return parsed
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.CHECK) from None
        except (TypeError, ValueError):
            pass
        readback = self._read_check_run(proposal, check.check_run_id)
        if readback.status == "completed" and readback.conclusion == conclusion:
            return readback
        raise _ambiguous_failure(GitHubPublicationStage.CHECK)

    def _require_check_identity(
        self,
        proposal: GitHubProposal,
        check: _CheckRun,
        *,
        external_id: str,
        summary: str,
        conclusion: str,
        final: bool,
    ) -> None:
        expected_url = (
            f"https://github.com/{proposal.repository_full_name}/runs/{check.check_run_id}"
        )
        if (
            check.name != _CHECK_NAME
            or check.head_oid != proposal.head_oid
            or check.external_id != external_id
            or check.url != expected_url
            or check.output_title != _CHECK_NAME
            or check.output_summary != summary
            or (check.status not in {"queued", "in_progress", "completed"})
            or (final and (check.status != "completed" or check.conclusion != conclusion))
            or (not final and check.status == "completed" and check.conclusion != conclusion)
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.CHECK,
            )

    def _publish_repair_locked(
        self,
        publication: LockedGitHubPublication,
        *,
        proposal: GitHubProposal,
        approval: GitHubApproval,
        source: GitHubSourcePullRequest,
        partial: GitHubPublicationResult | None,
    ) -> GitHubPublicationResult:
        _require_source_matches_proposal(source, proposal)
        if self._repair_manager is None:
            raise _publication_failure(
                GitHubPublicationErrorCode.CAPABILITY_UNAVAILABLE,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        payload = proposal.payload
        try:
            candidate_id = _sha256(payload.get("candidate_id"))
            validation_sha256 = _sha256(payload.get("validation_sha256"))
            expected_tree_oid = _sha1(payload.get("tree_oid"))
            expected_commit_oid = _sha1(payload.get("commit_oid"))
            branch = _string(payload.get("branch"))
            changed_paths_value = payload.get("changed_paths")
            if type(changed_paths_value) is not list:
                raise ValueError
            changed_paths = tuple(_string(item) for item in changed_paths_value)
            title = _string(payload.get("pull_request_title"))
            pull_request_body = _string(payload.get("pull_request_body"))
            marker = f"<!-- repoguard-repair-candidate:{candidate_id} -->"
            if branch != f"repoguard/repairs/{candidate_id}" or marker not in pull_request_body:
                raise ValueError
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.INVALID_INPUT,
                GitHubPublicationStage.LOCAL_REPAIR,
            ) from None

        session_id = publication.repair_session_id()
        session = self._repair_manager.open_session(session_id)
        snapshot = self._apply_local_repair(
            session,
            proposal=proposal,
            approval=approval,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
        )
        application = snapshot.application
        if application is None:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        if partial is not None and (
            partial.approval != approval
            or partial.application_sha256 != application.application_sha256
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                GitHubPublicationStage.RECOVERY,
            )
        manifest = session.publication_manifest(
            expected_application_sha256=application.application_sha256
        )
        self._require_manifest(
            manifest,
            proposal=proposal,
            snapshot=snapshot,
            changed_paths=changed_paths,
            expected_tree_oid=expected_tree_oid,
            expected_commit_oid=expected_commit_oid,
        )
        self._publish_git_objects(
            proposal,
            session=session,
            manifest=manifest,
            changed_paths=changed_paths,
        )
        self._refresh_source(proposal)

        branch_ref = f"refs/heads/{branch}"
        branch_oid = self._ensure_branch(
            proposal,
            branch_ref=branch_ref,
            commit_oid=expected_commit_oid,
        )
        if not hmac.compare_digest(branch_oid, expected_commit_oid):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.BRANCH,
            )
        if partial is None:
            partial = self._build_repair_result(
                proposal,
                approval,
                state=GitHubPublicationState.BRANCH_CREATED,
                application_sha256=application.application_sha256,
                readback={
                    "repository_id": proposal.repository_id,
                    "branch_ref": branch_ref,
                    "commit_oid": expected_commit_oid,
                },
            )
            saved = publication.record_partial_result(partial).partial_result
            if saved is None:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.PERSISTENCE,
                )
            partial = saved

        self._refresh_source(proposal)
        replacement = self._find_replacement_pull_request(
            proposal,
            branch=branch,
            marker=marker,
        )
        if replacement is None:
            replacement = self._create_replacement_pull_request(
                proposal,
                branch=branch,
                title=title,
                body=pull_request_body,
                marker=marker,
            )
        self._require_replacement_pull_request(
            proposal,
            replacement,
            branch=branch,
            title=title,
            body=pull_request_body,
            marker=marker,
        )
        final_branch_oid = self._read_branch(
            proposal,
            branch_ref=branch_ref,
            allow_missing=False,
        )
        if final_branch_oid != expected_commit_oid:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.BRANCH,
            )
        final_pr = self._read_replacement_pull_request(proposal, replacement.number)
        self._require_replacement_pull_request(
            proposal,
            final_pr,
            branch=branch,
            title=title,
            body=pull_request_body,
            marker=marker,
        )
        self._refresh_source(proposal)
        return self._build_repair_result(
            proposal,
            approval,
            state=GitHubPublicationState.REPAIR_PUBLISHED,
            application_sha256=application.application_sha256,
            readback={
                "repository_id": proposal.repository_id,
                "branch_ref": branch_ref,
                "commit_oid": expected_commit_oid,
                "pull_request_id": final_pr.pull_request_id,
                "pull_request_number": final_pr.number,
                "pull_request_node_id": final_pr.node_id,
                "pull_request_url": final_pr.url,
                "draft": final_pr.draft,
                "state": final_pr.state,
                "base_ref": final_pr.base_ref,
                "head_ref": final_pr.head_ref,
                "base_repository_id": final_pr.base_repository_id,
                "head_repository_id": final_pr.head_repository_id,
                "pull_request_title": final_pr.title,
                "pull_request_body": final_pr.body,
                "body_marker": marker,
            },
        )

    def _apply_local_repair(
        self,
        session: _RepairSession,
        *,
        proposal: GitHubProposal,
        approval: GitHubApproval,
        candidate_id: str,
        validation_sha256: str,
    ) -> RepairSnapshot:
        subject = f"github:{approval.actor_login}:{approval.actor_id}"
        snapshot = session.snapshot()
        self._require_local_snapshot(
            snapshot,
            proposal=proposal,
            subject=subject,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
            allow_validated=True,
        )
        if snapshot.state is RepairState.VALIDATED:
            snapshot = session.approve(
                subject=subject,
                expected_candidate_id=candidate_id,
                expected_validation_sha256=validation_sha256,
                confirmation=REPAIR_APPROVAL_CONFIRMATION,
            )
            self._require_local_snapshot(
                snapshot,
                proposal=proposal,
                subject=subject,
                candidate_id=candidate_id,
                validation_sha256=validation_sha256,
                allow_validated=False,
            )
        if snapshot.state is RepairState.APPROVED:
            local_approval = snapshot.approval
            if local_approval is None:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.LOCAL_REPAIR,
                )
            snapshot = session.apply(
                expected_approval_sha256=local_approval.approval_sha256,
            )
        self._require_local_snapshot(
            snapshot,
            proposal=proposal,
            subject=subject,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
            allow_validated=False,
        )
        if snapshot.state is not RepairState.APPLIED:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        return snapshot

    def _require_local_snapshot(
        self,
        snapshot: RepairSnapshot,
        *,
        proposal: GitHubProposal,
        subject: str,
        candidate_id: str,
        validation_sha256: str,
        allow_validated: bool,
    ) -> None:
        candidate = snapshot.candidate
        validation = snapshot.validation
        allowed_states = {RepairState.APPROVED, RepairState.APPLIED}
        if allow_validated:
            allowed_states.add(RepairState.VALIDATED)
        if (
            type(snapshot) is not RepairSnapshot
            or snapshot.state not in allowed_states
            or candidate is None
            or validation is None
            or not validation.success
            or candidate.candidate_id != candidate_id
            or validation.validation_sha256 != validation_sha256
            or validation.candidate_id != candidate_id
            or candidate.tree_oid != proposal.payload.get("tree_oid")
            or candidate.commit_oid != proposal.payload.get("commit_oid")
            or tuple(candidate.changed_paths)
            != tuple(cast(list[object], proposal.payload.get("changed_paths")))
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.LOCAL_REPAIR,
            )
        if snapshot.state in {RepairState.APPROVED, RepairState.APPLIED}:
            local_approval = snapshot.approval
            if (
                local_approval is None
                or local_approval.subject != subject
                or local_approval.candidate_id != candidate_id
                or local_approval.validation_sha256 != validation_sha256
                or local_approval.confirmation != REPAIR_APPROVAL_CONFIRMATION
            ):
                raise _publication_failure(
                    GitHubPublicationErrorCode.APPROVAL_MISMATCH,
                    GitHubPublicationStage.LOCAL_REPAIR,
                )
        if snapshot.state is RepairState.APPLIED:
            application = snapshot.application
            local_approval = snapshot.approval
            if (
                application is None
                or local_approval is None
                or application.approval_sha256 != local_approval.approval_sha256
                or application.commit_oid != candidate.commit_oid
                or application.ref != f"refs/repoguard/repairs/{candidate_id}"
            ):
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_CONFLICT,
                    GitHubPublicationStage.LOCAL_REPAIR,
                )

    def _require_manifest(
        self,
        manifest: RepairPublicationManifest,
        *,
        proposal: GitHubProposal,
        snapshot: RepairSnapshot,
        changed_paths: tuple[str, ...],
        expected_tree_oid: str,
        expected_commit_oid: str,
    ) -> None:
        application = snapshot.application
        local_approval = snapshot.approval
        if (
            type(manifest) is not RepairPublicationManifest
            or application is None
            or local_approval is None
            or manifest.object_format != "sha1"
            or manifest.application_sha256 != application.application_sha256
            or manifest.approval_sha256 != local_approval.approval_sha256
            or manifest.candidate_id != proposal.payload.get("candidate_id")
            or manifest.parent_oid != proposal.head_oid
            or manifest.tree_oid != expected_tree_oid
            or manifest.commit_oid != expected_commit_oid
            or manifest.ref != f"refs/repoguard/repairs/{proposal.payload.get('candidate_id')}"
            or not set(entry.path for entry in manifest.entries).issubset(changed_paths)
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.OBJECTS,
            )

    def _publish_git_objects(
        self,
        proposal: GitHubProposal,
        *,
        session: _RepairSession,
        manifest: RepairPublicationManifest,
        changed_paths: tuple[str, ...],
    ) -> None:
        parent_tree_oid = self._read_commit_tree(proposal, proposal.head_oid)
        entries_by_path = {entry.path: entry for entry in manifest.entries}
        tree_entries: list[GitHubJSONValue] = []
        for path in changed_paths:
            entry = entries_by_path.get(path)
            if entry is None:
                tree_entries.append({"path": path, "sha": None})
                continue
            blob = session.publication_blob(manifest=manifest, entry=entry)
            if (
                type(blob) is not RepairPublicationBlob
                or blob.manifest_sha256 != manifest.manifest_sha256
                or blob.entry != entry
            ):
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.OBJECTS,
                )
            self._ensure_blob(proposal, blob)
            tree_entries.append(
                {
                    "path": entry.path,
                    "mode": entry.mode,
                    "type": "blob",
                    "sha": entry.blob_oid,
                }
            )
            blob = cast(RepairPublicationBlob, None)
        self._ensure_tree(
            proposal,
            base_tree_oid=parent_tree_oid,
            tree_oid=manifest.tree_oid,
            entries=tree_entries,
        )
        self._ensure_commit(
            proposal,
            commit_oid=manifest.commit_oid,
            tree_oid=manifest.tree_oid,
            parent_oid=manifest.parent_oid,
        )

    def _read_commit_tree(self, proposal: GitHubProposal, commit_oid: str) -> str:
        body = _object(
            self._request(
                GitHubMethod.GET,
                f"/repos/{proposal.repository_full_name}/git/commits/{commit_oid}",
                stage=GitHubPublicationStage.OBJECTS,
            )
        )
        try:
            if _sha1(body.get("sha")) != commit_oid:
                raise ValueError
            tree = _object(body.get("tree"))
            return _sha1(tree.get("sha"))
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.OBJECTS,
            ) from None

    def _ensure_blob(
        self,
        proposal: GitHubProposal,
        blob: RepairPublicationBlob,
    ) -> None:
        if self._blob_exists(proposal, blob.entry):
            return
        encoded = base64.b64encode(blob.content).decode("ascii")
        request: dict[str, GitHubJSONValue] = {
            "content": encoded,
            "encoding": "base64",
        }
        path = f"/repos/{proposal.repository_full_name}/git/blobs"
        try:
            response = self._transport.request(GitHubMethod.POST, path, request)
            body = _object(response.body)
            if _sha1(body.get("sha")) == blob.entry.blob_oid:
                return
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.OBJECTS) from None
        except (TypeError, ValueError):
            pass
        finally:
            encoded = ""
            request = {}
        if self._blob_exists(proposal, blob.entry):
            return
        raise _ambiguous_failure(GitHubPublicationStage.OBJECTS)

    def _blob_exists(
        self,
        proposal: GitHubProposal,
        entry: RepairPublicationEntry,
    ) -> bool:
        body = self._optional_get(
            f"/repos/{proposal.repository_full_name}/git/blobs/{entry.blob_oid}",
            stage=GitHubPublicationStage.OBJECTS,
        )
        if body is None:
            return False
        try:
            value = _object(body)
            return (
                _sha1(value.get("sha")) == entry.blob_oid
                and _nonnegative_int(value.get("size")) == entry.size
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.OBJECTS,
            ) from None

    def _ensure_tree(
        self,
        proposal: GitHubProposal,
        *,
        base_tree_oid: str,
        tree_oid: str,
        entries: list[GitHubJSONValue],
    ) -> None:
        if self._git_object_exists(
            proposal,
            kind="trees",
            object_oid=tree_oid,
            stage=GitHubPublicationStage.OBJECTS,
        ):
            return
        request: dict[str, GitHubJSONValue] = {
            "base_tree": base_tree_oid,
            "tree": entries,
        }
        try:
            response = self._transport.request(
                GitHubMethod.POST,
                f"/repos/{proposal.repository_full_name}/git/trees",
                request,
            )
            if _sha1(_object(response.body).get("sha")) == tree_oid:
                return
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.OBJECTS) from None
        except (TypeError, ValueError):
            pass
        if self._git_object_exists(
            proposal,
            kind="trees",
            object_oid=tree_oid,
            stage=GitHubPublicationStage.OBJECTS,
        ):
            return
        raise _ambiguous_failure(GitHubPublicationStage.OBJECTS)

    def _ensure_commit(
        self,
        proposal: GitHubProposal,
        *,
        commit_oid: str,
        tree_oid: str,
        parent_oid: str,
    ) -> None:
        if self._commit_exists(
            proposal,
            commit_oid=commit_oid,
            tree_oid=tree_oid,
            parent_oid=parent_oid,
        ):
            return
        signature: dict[str, GitHubJSONValue] = {
            "name": REPAIR_PUBLICATION_AUTHOR_NAME,
            "email": REPAIR_PUBLICATION_AUTHOR_EMAIL,
            "date": REPAIR_PUBLICATION_COMMIT_TIMESTAMP,
        }
        request: dict[str, GitHubJSONValue] = {
            "message": REPAIR_PUBLICATION_COMMIT_MESSAGE,
            "tree": tree_oid,
            "parents": [parent_oid],
            "author": signature,
            "committer": signature,
        }
        try:
            response = self._transport.request(
                GitHubMethod.POST,
                f"/repos/{proposal.repository_full_name}/git/commits",
                request,
            )
            body = _object(response.body)
            if (
                _sha1(body.get("sha")) == commit_oid
                and _sha1(_object(body.get("tree")).get("sha")) == tree_oid
            ):
                return
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise _transport_failure(error, GitHubPublicationStage.OBJECTS) from None
        except (TypeError, ValueError):
            pass
        if self._commit_exists(
            proposal,
            commit_oid=commit_oid,
            tree_oid=tree_oid,
            parent_oid=parent_oid,
        ):
            return
        raise _ambiguous_failure(GitHubPublicationStage.OBJECTS)

    def _commit_exists(
        self,
        proposal: GitHubProposal,
        *,
        commit_oid: str,
        tree_oid: str,
        parent_oid: str,
    ) -> bool:
        body = self._optional_get(
            f"/repos/{proposal.repository_full_name}/git/commits/{commit_oid}",
            stage=GitHubPublicationStage.OBJECTS,
        )
        if body is None:
            return False
        try:
            value = _object(body)
            parents = _list(value.get("parents"))
            return (
                _sha1(value.get("sha")) == commit_oid
                and _sha1(_object(value.get("tree")).get("sha")) == tree_oid
                and len(parents) == 1
                and _sha1(_object(parents[0]).get("sha")) == parent_oid
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.OBJECTS,
            ) from None

    def _git_object_exists(
        self,
        proposal: GitHubProposal,
        *,
        kind: str,
        object_oid: str,
        stage: GitHubPublicationStage,
    ) -> bool:
        body = self._optional_get(
            f"/repos/{proposal.repository_full_name}/git/{kind}/{object_oid}",
            stage=stage,
        )
        if body is None:
            return False
        try:
            return _sha1(_object(body).get("sha")) == object_oid
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                stage,
            ) from None

    def _ensure_branch(
        self,
        proposal: GitHubProposal,
        *,
        branch_ref: str,
        commit_oid: str,
    ) -> str:
        current = self._read_branch(proposal, branch_ref=branch_ref, allow_missing=True)
        if current is not None:
            if current != commit_oid:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_CONFLICT,
                    GitHubPublicationStage.BRANCH,
                )
            return current
        request: dict[str, GitHubJSONValue] = {"ref": branch_ref, "sha": commit_oid}
        ambiguous = False
        try:
            response = self._transport.request(
                GitHubMethod.POST,
                f"/repos/{proposal.repository_full_name}/git/refs",
                request,
            )
            _require_ref_response(
                _object(response.body),
                expected_ref=branch_ref,
                expected_oid=commit_oid,
            )
        except GitHubTransportError as error:
            if not error.ambiguous and error.code not in {
                GitHubTransportErrorCode.CONFLICT,
                GitHubTransportErrorCode.VALIDATION_FAILED,
            }:
                raise _transport_failure(error, GitHubPublicationStage.BRANCH) from None
            ambiguous = error.ambiguous
        except (TypeError, ValueError):
            ambiguous = True
        readback = self._read_branch(
            proposal,
            branch_ref=branch_ref,
            allow_missing=True,
        )
        if readback == commit_oid:
            return readback
        if readback is not None:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.BRANCH,
            )
        if ambiguous:
            raise _ambiguous_failure(GitHubPublicationStage.BRANCH)
        raise _publication_failure(
            GitHubPublicationErrorCode.REMOTE_CONFLICT,
            GitHubPublicationStage.BRANCH,
        )

    def _read_branch(
        self,
        proposal: GitHubProposal,
        *,
        branch_ref: str,
        allow_missing: bool,
    ) -> str | None:
        short_ref = branch_ref.removeprefix("refs/")
        body = self._optional_get(
            f"/repos/{proposal.repository_full_name}/git/ref/{short_ref}",
            stage=GitHubPublicationStage.BRANCH,
        )
        if body is None:
            if allow_missing:
                return None
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.BRANCH,
            )
        try:
            return _require_ref_response(
                _object(body),
                expected_ref=branch_ref,
                expected_oid=None,
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.BRANCH,
            ) from None

    def _find_replacement_pull_request(
        self,
        proposal: GitHubProposal,
        *,
        branch: str,
        marker: str,
    ) -> _PullRequest | None:
        owner = proposal.repository_full_name.split("/", 1)[0]
        head = quote(f"{owner}:{branch}", safe="")
        base = quote(proposal.base_ref, safe="")
        matching: list[_PullRequest] = []
        for page in range(1, 12):
            values = _list(
                self._request(
                    GitHubMethod.GET,
                    (
                        f"/repos/{proposal.repository_full_name}/pulls"
                        f"?state=all&head={head}&base={base}&per_page=100&page={page}"
                    ),
                    stage=GitHubPublicationStage.PULL_REQUEST,
                )
            )
            if len(values) > 100:
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.PULL_REQUEST,
                )
            try:
                for value in values:
                    raw = _object(value)
                    raw_body = raw.get("body")
                    raw_head = _object(raw.get("head"))
                    if raw_head.get("ref") == branch or (
                        type(raw_body) is str and marker in raw_body
                    ):
                        matching.append(_parse_pull_request(raw))
            except (TypeError, ValueError):
                raise _publication_failure(
                    GitHubPublicationErrorCode.REMOTE_INVALID,
                    GitHubPublicationStage.PULL_REQUEST,
                ) from None
            if len(values) < 100:
                break
        else:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.PULL_REQUEST,
            )
        if len(matching) > 1:
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.PULL_REQUEST,
            )
        return None if not matching else matching[0]

    def _create_replacement_pull_request(
        self,
        proposal: GitHubProposal,
        *,
        branch: str,
        title: str,
        body: str,
        marker: str,
    ) -> _PullRequest:
        request: dict[str, GitHubJSONValue] = {
            "title": title,
            "head": branch,
            "base": proposal.base_ref,
            "body": body,
            "draft": True,
        }
        ambiguous = False
        try:
            response = self._transport.request(
                GitHubMethod.POST,
                f"/repos/{proposal.repository_full_name}/pulls",
                request,
            )
            return _parse_pull_request(_object(response.body))
        except GitHubTransportError as error:
            if not error.ambiguous and error.code is not GitHubTransportErrorCode.VALIDATION_FAILED:
                raise _transport_failure(
                    error,
                    GitHubPublicationStage.PULL_REQUEST,
                ) from None
            ambiguous = error.ambiguous
        except (TypeError, ValueError):
            ambiguous = True
        readback = self._find_replacement_pull_request(
            proposal,
            branch=branch,
            marker=marker,
        )
        if readback is None:
            if ambiguous:
                raise _ambiguous_failure(GitHubPublicationStage.PULL_REQUEST)
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.PULL_REQUEST,
            )
        return readback

    def _read_replacement_pull_request(
        self,
        proposal: GitHubProposal,
        pull_request_number: int,
    ) -> _PullRequest:
        body = _object(
            self._request(
                GitHubMethod.GET,
                (f"/repos/{proposal.repository_full_name}/pulls/{pull_request_number}"),
                stage=GitHubPublicationStage.PULL_REQUEST,
            )
        )
        try:
            return _parse_pull_request(body)
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.PULL_REQUEST,
            ) from None

    def _require_replacement_pull_request(
        self,
        proposal: GitHubProposal,
        pull_request: _PullRequest,
        *,
        branch: str,
        title: str,
        body: str,
        marker: str,
    ) -> None:
        expected_url = (
            f"https://github.com/{proposal.repository_full_name}/pull/{pull_request.number}"
        )
        if (
            pull_request.number == proposal.pull_request_number
            or pull_request.url != expected_url
            or not pull_request.draft
            or pull_request.state != "open"
            or pull_request.base_ref != proposal.base_ref
            or pull_request.head_ref != branch
            or pull_request.base_repository_id != proposal.repository_id
            or pull_request.head_repository_id != proposal.repository_id
            or pull_request.title != title
            or pull_request.body != body
            or marker not in pull_request.body
        ):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_CONFLICT,
                GitHubPublicationStage.PULL_REQUEST,
            )

    def _build_repair_result(
        self,
        proposal: GitHubProposal,
        approval: GitHubApproval,
        *,
        state: GitHubPublicationState,
        application_sha256: str,
        readback: dict[str, object],
    ) -> GitHubPublicationResult:
        try:
            return build_github_result(
                proposal,
                approval,
                state=state,
                application_sha256=application_sha256,
                readback=readback,
                published_at_us=max(self._now(), approval.approved_at_us),
            )
        except (TypeError, ValueError):
            raise _publication_failure(
                GitHubPublicationErrorCode.REMOTE_INVALID,
                GitHubPublicationStage.PERSISTENCE,
            ) from None

    def _refresh_source(self, proposal: GitHubProposal) -> GitHubSourcePullRequest:
        source = self.read_source_pull_request(
            repository_id=proposal.repository_id,
            repository_full_name=proposal.repository_full_name,
            pull_request_number=proposal.pull_request_number,
            require_same_repository=True,
        )
        _require_source_matches_proposal(source, proposal)
        return source

    def _optional_get(
        self,
        path: str,
        *,
        stage: GitHubPublicationStage,
    ) -> GitHubJSONValue | None:
        try:
            return self._transport.request(GitHubMethod.GET, path).body
        except GitHubTransportError as error:
            if error.code is GitHubTransportErrorCode.NOT_FOUND:
                return None
            raise _transport_failure(error, stage) from None

    def _request(
        self,
        method: GitHubMethod,
        path: str,
        body: dict[str, GitHubJSONValue] | None = None,
        *,
        stage: GitHubPublicationStage,
    ) -> GitHubJSONValue:
        try:
            return self._transport.request(method, path, body).body
        except GitHubTransportError as error:
            raise _transport_failure(error, stage) from None

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception:
            raise _publication_failure(
                GitHubPublicationErrorCode.CAPABILITY_UNAVAILABLE,
                GitHubPublicationStage.INPUT,
            ) from None
        if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_807:
            raise _publication_failure(
                GitHubPublicationErrorCode.CAPABILITY_UNAVAILABLE,
                GitHubPublicationStage.INPUT,
            )
        return value


def _wall_clock_us() -> int:
    return time.time_ns() // 1_000


def _parse_check_run(value: dict[str, GitHubJSONValue]) -> _CheckRun:
    output = _object(value.get("output"))
    conclusion_value = value.get("conclusion")
    conclusion = None if conclusion_value is None else _string(conclusion_value)
    result = _CheckRun(
        check_run_id=_positive_int(value.get("id")),
        node_id=_bounded_string(value.get("node_id"), maximum=255),
        name=_bounded_string(value.get("name"), maximum=255),
        head_oid=_sha1(value.get("head_sha")),
        external_id=_sha256(value.get("external_id")),
        status=_bounded_string(value.get("status"), maximum=32),
        conclusion=conclusion,
        url=_bounded_string(value.get("html_url"), maximum=2_048),
        annotation_count=_nonnegative_int(output.get("annotations_count")),
        output_title=_bounded_string(output.get("title"), maximum=255),
        output_summary=_bounded_string(
            output.get("summary"),
            maximum=_MAX_CHECK_SUMMARY_BYTES,
        ),
    )
    if result.status not in {"queued", "in_progress", "completed"}:
        raise ValueError
    if result.status == "completed":
        if result.conclusion not in {"success", "neutral", "failure"}:
            raise ValueError
    elif result.conclusion is not None:
        raise ValueError
    if result.annotation_count > _MAX_CHECK_ANNOTATIONS:
        raise ValueError
    return result


def _annotation_projection(value: dict[str, GitHubJSONValue]) -> GitHubJSONValue:
    return {
        "path": _bounded_string(value.get("path"), maximum=1_024),
        "start_line": _positive_int(value.get("start_line")),
        "end_line": _positive_int(value.get("end_line")),
        "annotation_level": _bounded_string(value.get("annotation_level"), maximum=16),
        "title": _bounded_string(value.get("title"), maximum=255),
        "message": _bounded_string(value.get("message"), maximum=64 * 1024),
    }


def _parse_pull_request(value: dict[str, GitHubJSONValue]) -> _PullRequest:
    base = _object(value.get("base"))
    head = _object(value.get("head"))
    base_repository = _object(base.get("repo"))
    head_repository = _object(head.get("repo"))
    body_value = value.get("body")
    body = "" if body_value is None else _bounded_string(body_value, maximum=64 * 1024)
    return _PullRequest(
        pull_request_id=_positive_int(value.get("id")),
        number=_positive_int(value.get("number")),
        node_id=_bounded_string(value.get("node_id"), maximum=255),
        url=_bounded_string(value.get("html_url"), maximum=2_048),
        draft=_bool(value.get("draft")),
        state=_bounded_string(value.get("state"), maximum=32),
        base_ref=_bounded_string(base.get("ref"), maximum=255),
        head_ref=_bounded_string(head.get("ref"), maximum=255),
        base_repository_id=_positive_int(base_repository.get("id")),
        head_repository_id=_positive_int(head_repository.get("id")),
        title=_bounded_string(value.get("title"), maximum=255),
        body=body,
    )


def _require_ref_response(
    value: dict[str, GitHubJSONValue],
    *,
    expected_ref: str,
    expected_oid: str | None,
) -> str:
    if _string(value.get("ref")) != expected_ref:
        raise ValueError
    target = _object(value.get("object"))
    if _string(target.get("type")) != "commit":
        raise ValueError
    oid = _sha1(target.get("sha"))
    if expected_oid is not None and oid != expected_oid:
        raise ValueError
    return oid


def _require_source_matches_proposal(
    source: GitHubSourcePullRequest,
    proposal: GitHubProposal,
) -> None:
    if (
        not source.writable
        or source.repository_id != proposal.repository_id
        or source.repository_full_name != proposal.repository_full_name
        or source.pull_request_number != proposal.pull_request_number
        or source.base_ref != proposal.base_ref
        or source.base_oid != proposal.base_oid
        or source.head_oid != proposal.head_oid
    ):
        raise _publication_failure(
            GitHubPublicationErrorCode.PULL_REQUEST_STALE,
            GitHubPublicationStage.SOURCE_PULL_REQUEST,
        )


def _require_kind(
    proposal: GitHubProposal,
    expected: GitHubProposalKind,
) -> GitHubProposal:
    if type(proposal) is not GitHubProposal or proposal.kind is not expected:
        raise _publication_failure(
            GitHubPublicationErrorCode.KIND_MISMATCH,
            GitHubPublicationStage.INPUT,
        )
    return proposal


def _require_saved_approval(
    approval: GitHubApproval | None,
    principal: _Principal,
) -> GitHubApproval:
    if (
        approval is None
        or approval.actor_login != principal.login
        or approval.actor_id != principal.actor_id
        or principal.permission
        not in {
            GitHubPermission.WRITE,
            GitHubPermission.MAINTAIN,
            GitHubPermission.ADMIN,
        }
    ):
        raise _publication_failure(
            GitHubPublicationErrorCode.APPROVAL_MISMATCH,
            GitHubPublicationStage.APPROVAL,
        )
    return approval


def _require_confirmation(value: object, expected: str) -> None:
    if type(value) is not str or not hmac.compare_digest(value, expected):
        raise _publication_failure(
            GitHubPublicationErrorCode.APPROVAL_MISMATCH,
            GitHubPublicationStage.APPROVAL,
        )


def _require_sha256_input(value: object) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise _publication_failure(
            GitHubPublicationErrorCode.INVALID_INPUT,
            GitHubPublicationStage.INPUT,
        )


def _require_full_name(value: object) -> None:
    if type(value) is not str or _FULL_NAME_PATTERN.fullmatch(value) is None or ".." in value:
        raise ValueError


def _require_ref(value: object) -> None:
    if (
        type(value) is not str
        or _REF_PATTERN.fullmatch(value) is None
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(part in {"", ".", "..", ".git"} for part in value.split("/"))
    ):
        raise ValueError


def _require_sha1(value: object) -> None:
    if type(value) is not str or _SHA1_PATTERN.fullmatch(value) is None:
        raise ValueError


def _require_positive_int(value: object) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError


def _object(value: object) -> dict[str, GitHubJSONValue]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError
    return cast(dict[str, GitHubJSONValue], value)


def _list(value: object) -> list[GitHubJSONValue]:
    if type(value) is not list:
        raise ValueError
    return cast(list[GitHubJSONValue], value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    return value


def _bounded_string(value: object, *, maximum: int) -> str:
    result = _string(value)
    if not result or len(result.encode("utf-8")) > maximum or "\x00" in result or "\r" in result:
        raise ValueError
    return result


def _positive_int(value: object) -> int:
    _require_positive_int(value)
    return cast(int, value)


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError
    return value


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError
    return value


def _sha1(value: object) -> str:
    _require_sha1(value)
    return cast(str, value)


def _sha256(value: object) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError
    return value


def _publication_failure(
    code: GitHubPublicationErrorCode,
    stage: GitHubPublicationStage,
    *,
    retryable: bool = False,
    ambiguous: bool = False,
) -> GitHubPublicationError:
    return GitHubPublicationError(
        GitHubPublicationErrorDomain.PUBLICATION,
        code.value,
        stage,
        retryable=retryable,
        ambiguous=ambiguous,
    )


def _ambiguous_failure(stage: GitHubPublicationStage) -> GitHubPublicationError:
    return _publication_failure(
        GitHubPublicationErrorCode.AMBIGUOUS_WRITE,
        stage,
        retryable=True,
        ambiguous=True,
    )


def _transport_failure(
    error: GitHubTransportError,
    stage: GitHubPublicationStage,
) -> GitHubPublicationError:
    return GitHubPublicationError(
        GitHubPublicationErrorDomain.TRANSPORT,
        error.code.value,
        stage,
        retryable=error.retryable,
        ambiguous=error.ambiguous,
    )


def _store_failure(
    error: GitHubStoreError,
    stage: GitHubPublicationStage,
) -> GitHubPublicationError:
    return GitHubPublicationError(
        GitHubPublicationErrorDomain.STORE,
        error.code.value,
        stage,
        retryable=error.retryable,
        ambiguous=False,
    )


def _repair_failure(
    error: RepairError,
    stage: GitHubPublicationStage,
) -> GitHubPublicationError:
    return GitHubPublicationError(
        GitHubPublicationErrorDomain.REPAIR,
        error.code.value,
        stage,
        retryable=error.retryable,
        ambiguous=False,
    )
