"""Owner-only durable storage for approved GitHub publications."""

from __future__ import annotations

import errno
import fcntl
import hmac
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from repoguard._canonical import (
    canonical_json_bytes,
    parse_canonical_json,
    require_exact_keys,
)
from repoguard.github import (
    GITHUB_PROPOSAL_MAX_BYTES,
    GitHubApproval,
    GitHubProposal,
    GitHubProposalKind,
    GitHubPublicationResult,
    GitHubPublicationState,
    github_approval_from_json,
    github_approval_to_json,
    github_proposal_from_json,
    github_proposal_to_json,
    github_result_from_json,
    github_result_to_json,
    validate_github_result,
)

__all__ = [
    "GitHubPublicationStatus",
    "GitHubPublicationStore",
    "GitHubStoreError",
    "GitHubStoreErrorCode",
    "GitHubStoreStage",
    "LockedGitHubPublication",
]

_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FULL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TEMP_RECORD_PATTERN = re.compile(r"^\.record-[0-9a-f]{32}$")
_RECORD_NAMES = frozenset(
    {
        "publication.lock",
        "proposal.json",
        "binding.json",
        "approval.json",
        "branch.json",
        "result.json",
    }
)
_BINDING_MAX_BYTES = 1_024
_APPROVAL_MAX_BYTES = 64 * 1_024
_RESULT_MAX_BYTES = 1_024 * 1_024
_RECORD_LIMITS = {
    "proposal.json": GITHUB_PROPOSAL_MAX_BYTES,
    "binding.json": _BINDING_MAX_BYTES,
    "approval.json": _APPROVAL_MAX_BYTES,
    "branch.json": _RESULT_MAX_BYTES,
    "result.json": _RESULT_MAX_BYTES,
}
_DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
_MANAGER_LOCK_NAME = ".manager.lock"
_PUBLISHER_LOCK_NAME = ".publisher.lock"


class GitHubStoreErrorCode(StrEnum):
    """Stable, content-free publication-store failures."""

    INVALID_CONFIG = "invalid_config"
    INVALID_IDENTITY = "invalid_identity"
    NOT_FOUND = "not_found"
    STATE_CONFLICT = "state_conflict"
    CORRUPT_STATE = "corrupt_state"
    LOCK_TIMEOUT = "lock_timeout"
    IO_FAILED = "io_failed"


class GitHubStoreStage(StrEnum):
    """Stable stage at which a publication-store operation failed."""

    INPUT = "input"
    OPEN = "open"
    LOCK = "lock"
    READ = "read"
    WRITE = "write"


_ERROR_MESSAGES: dict[GitHubStoreErrorCode, str] = {
    GitHubStoreErrorCode.INVALID_CONFIG: "GitHub publication storage is unavailable",
    GitHubStoreErrorCode.INVALID_IDENTITY: "GitHub publication identity is invalid",
    GitHubStoreErrorCode.NOT_FOUND: "GitHub publication was not found",
    GitHubStoreErrorCode.STATE_CONFLICT: "GitHub publication state conflicts",
    GitHubStoreErrorCode.CORRUPT_STATE: "GitHub publication state is invalid",
    GitHubStoreErrorCode.LOCK_TIMEOUT: "GitHub publication storage is busy",
    GitHubStoreErrorCode.IO_FAILED: "GitHub publication storage failed",
}


class GitHubStoreError(RuntimeError):
    """A stable store error that never incorporates record or OS contents."""

    __slots__ = ("code", "retryable", "stage")

    code: GitHubStoreErrorCode
    retryable: bool
    stage: GitHubStoreStage

    def __init__(
        self,
        code: GitHubStoreErrorCode,
        stage: GitHubStoreStage,
        *,
        retryable: bool = False,
    ) -> None:
        self.code = code
        self.stage = stage
        self.retryable = retryable
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class GitHubPublicationStatus:
    """Public durable status without the private repair-session binding."""

    proposal: GitHubProposal
    approval: GitHubApproval | None
    partial_result: GitHubPublicationResult | None
    result: GitHubPublicationResult | None

    def __post_init__(self) -> None:
        if type(self.proposal) is not GitHubProposal:
            raise TypeError("proposal must be an exact GitHubProposal")
        if self.approval is not None and type(self.approval) is not GitHubApproval:
            raise TypeError("approval must be an exact GitHubApproval")
        for value in (self.partial_result, self.result):
            if value is not None and type(value) is not GitHubPublicationResult:
                raise TypeError("result must be an exact GitHubPublicationResult")


@dataclass(frozen=True, slots=True, repr=False)
class _RepairBinding:
    schema_version: int
    proposal_sha256: str
    session_id: str

    def __repr__(self) -> str:
        return "_RepairBinding(<private>)"


@dataclass(frozen=True, slots=True)
class _OpenPublication:
    root_fd: int
    github_fd: int
    manager_lock_fd: int
    repository_fd: int
    publisher_lock_fd: int
    publications_fd: int
    proposal_fd: int
    lock_fd: int


class GitHubPublicationStore:
    """Repository-scoped publication store rooted in one owner-only capability."""

    __slots__ = (
        "_lock_timeout_seconds",
        "_product_state_root",
        "_repository_alias",
        "_repository_full_name",
        "_repository_id",
        "_root_identity",
    )

    def __init__(
        self,
        *,
        product_state_root: Path,
        repository_alias: str,
        repository_id: int,
        repository_full_name: str,
        lock_timeout_seconds: float = _DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        try:
            _validate_constructor_inputs(
                product_state_root=product_state_root,
                repository_alias=repository_alias,
                repository_id=repository_id,
                repository_full_name=repository_full_name,
                lock_timeout_seconds=lock_timeout_seconds,
            )
            root_fd = _open_root(product_state_root)
            root_identity = _fd_identity(root_fd)
        except (OSError, TypeError, ValueError):
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_CONFIG,
                GitHubStoreStage.INPUT,
            )
        else:
            os.close(root_fd)
        self._product_state_root = product_state_root
        self._repository_alias = repository_alias
        self._repository_id = repository_id
        self._repository_full_name = repository_full_name
        self._lock_timeout_seconds = lock_timeout_seconds
        self._root_identity = root_identity

    def record_proposal(
        self,
        proposal: GitHubProposal,
        *,
        session_id: str | None = None,
    ) -> GitHubPublicationStatus:
        """Persist one exact proposal and its private repair-session binding."""
        self._validate_proposal_input(proposal, session_id=session_id)
        with self._locked(
            proposal.proposal_sha256,
            create=True,
        ) as publication:
            publication._record_proposal(proposal, session_id=session_id)
            return publication.status()

    def status(self, proposal_sha256: str) -> GitHubPublicationStatus:
        """Load and fully revalidate one public publication status."""
        with self.locked_publication(proposal_sha256) as publication:
            return publication.status()

    def repair_session_id(self, proposal_sha256: str) -> str:
        """Resolve the private authoritative binding for a repair publisher."""
        with self.locked_publication(proposal_sha256) as publication:
            return publication.repair_session_id()

    def record_approval(
        self,
        proposal_sha256: str,
        approval: GitHubApproval,
    ) -> GitHubPublicationStatus:
        """Persist one approval under the matching proposal CAS."""
        with self.locked_publication(proposal_sha256) as publication:
            return publication.record_approval(approval)

    def record_partial_result(
        self,
        proposal_sha256: str,
        result: GitHubPublicationResult,
    ) -> GitHubPublicationStatus:
        """Persist a recoverable branch-created result."""
        with self.locked_publication(proposal_sha256) as publication:
            return publication.record_partial_result(result)

    def record_result(
        self,
        proposal_sha256: str,
        result: GitHubPublicationResult,
    ) -> GitHubPublicationStatus:
        """Persist a final read-back-confirmed publication result."""
        with self.locked_publication(proposal_sha256) as publication:
            return publication.record_result(result)

    @contextmanager
    def locked_publication(
        self,
        proposal_sha256: str,
    ) -> Iterator[LockedGitHubPublication]:
        """Hold the proposal lock across remote publication and local CAS writes."""
        _validate_digest_input(proposal_sha256)
        with self._locked(proposal_sha256, create=False) as publication:
            publication.status()
            yield publication

    @contextmanager
    def _locked(
        self,
        proposal_sha256: str,
        *,
        create: bool,
    ) -> Iterator[LockedGitHubPublication]:
        opened: _OpenPublication | None = None
        manager_lock_fd: int | None = None
        root_manager_locked = False
        manager_marker_locked = False
        publisher_lock_fd: int | None = None
        publisher_locked = False
        publication_locked = False
        descriptors: list[int] = []
        try:
            root_fd = _open_root(self._product_state_root)
            descriptors.append(root_fd)
            if _fd_identity(root_fd) != self._root_identity:
                _raise_store_error(
                    GitHubStoreErrorCode.CORRUPT_STATE,
                    GitHubStoreStage.OPEN,
                )
            if not _acquire_flock(root_fd, self._lock_timeout_seconds):
                _raise_store_error(
                    GitHubStoreErrorCode.LOCK_TIMEOUT,
                    GitHubStoreStage.LOCK,
                    retryable=True,
                )
            root_manager_locked = True
            _revalidate_root(
                self._product_state_root,
                root_fd,
                expected_identity=self._root_identity,
            )
            github_fd = _open_or_create_directory(root_fd, "github", create=create)
            descriptors.append(github_fd)
            manager_lock_fd = _open_state_lock(
                github_fd,
                _MANAGER_LOCK_NAME,
                create=create,
            )
            descriptors.append(manager_lock_fd)
            if not _acquire_flock(manager_lock_fd, self._lock_timeout_seconds):
                _raise_store_error(
                    GitHubStoreErrorCode.LOCK_TIMEOUT,
                    GitHubStoreStage.LOCK,
                    retryable=True,
                )
            manager_marker_locked = True
            _revalidate_root(
                self._product_state_root,
                root_fd,
                expected_identity=self._root_identity,
            )
            _revalidate_named(github_fd, root_fd, "github", directory=True, mode=0o700)
            _revalidate_named(
                manager_lock_fd,
                github_fd,
                _MANAGER_LOCK_NAME,
                directory=False,
                mode=0o600,
            )
            repository_fd = _open_or_create_directory(
                github_fd,
                self._repository_alias,
                create=create,
            )
            descriptors.append(repository_fd)
            publisher_lock_fd = _open_state_lock(
                repository_fd,
                _PUBLISHER_LOCK_NAME,
                create=create,
            )
            descriptors.append(publisher_lock_fd)
            if not _acquire_flock(publisher_lock_fd, self._lock_timeout_seconds):
                _raise_store_error(
                    GitHubStoreErrorCode.LOCK_TIMEOUT,
                    GitHubStoreStage.LOCK,
                    retryable=True,
                )
            publisher_locked = True
            _revalidate_named(
                publisher_lock_fd,
                repository_fd,
                _PUBLISHER_LOCK_NAME,
                directory=False,
                mode=0o600,
            )
            publications_fd = _open_or_create_directory(
                repository_fd,
                "publications",
                create=create,
            )
            descriptors.append(publications_fd)
            proposal_fd = _open_or_create_directory(
                publications_fd,
                proposal_sha256,
                create=create,
            )
            descriptors.append(proposal_fd)
            lock_fd = _open_state_lock(
                proposal_fd,
                "publication.lock",
                create=create,
            )
            descriptors.append(lock_fd)
            opened = _OpenPublication(
                root_fd=root_fd,
                github_fd=github_fd,
                manager_lock_fd=manager_lock_fd,
                repository_fd=repository_fd,
                publisher_lock_fd=publisher_lock_fd,
                publications_fd=publications_fd,
                proposal_fd=proposal_fd,
                lock_fd=lock_fd,
            )
            _revalidate_named(
                manager_lock_fd,
                github_fd,
                _MANAGER_LOCK_NAME,
                directory=False,
                mode=0o600,
            )
            if not _acquire_flock(lock_fd, self._lock_timeout_seconds):
                _raise_store_error(
                    GitHubStoreErrorCode.LOCK_TIMEOUT,
                    GitHubStoreStage.LOCK,
                    retryable=True,
                )
            publication_locked = True
            self._revalidate_open_publication(opened, proposal_sha256)
            _recover_record_temporary(proposal_fd)
            self._revalidate_open_publication(opened, proposal_sha256)
            publication = LockedGitHubPublication(
                self,
                proposal_sha256,
                proposal_fd,
                opened,
            )
            try:
                yield publication
            except BaseException:
                raise
            else:
                publication._revalidate()
        except GitHubStoreError:
            raise
        except FileNotFoundError:
            _raise_store_error(
                GitHubStoreErrorCode.NOT_FOUND,
                GitHubStoreStage.OPEN,
            )
        except OSError as error:
            _raise_store_error(
                _open_error_code(error),
                GitHubStoreStage.OPEN,
            )
        finally:
            if publication_locked and opened is not None:
                with suppress(OSError):
                    fcntl.flock(opened.lock_fd, fcntl.LOCK_UN)
            if publisher_locked and publisher_lock_fd is not None:
                with suppress(OSError):
                    fcntl.flock(publisher_lock_fd, fcntl.LOCK_UN)
            if manager_marker_locked and manager_lock_fd is not None:
                with suppress(OSError):
                    fcntl.flock(manager_lock_fd, fcntl.LOCK_UN)
            if root_manager_locked and descriptors:
                with suppress(OSError):
                    fcntl.flock(descriptors[0], fcntl.LOCK_UN)
            for descriptor in reversed(descriptors):
                with suppress(OSError):
                    os.close(descriptor)

    def _validate_proposal_input(
        self,
        proposal: GitHubProposal,
        *,
        session_id: str | None,
    ) -> None:
        if type(proposal) is not GitHubProposal or not self._proposal_matches_store(proposal):
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_IDENTITY,
                GitHubStoreStage.INPUT,
            )
        if proposal.kind is GitHubProposalKind.REPAIR:
            if not _is_sha256(session_id):
                _raise_store_error(
                    GitHubStoreErrorCode.INVALID_IDENTITY,
                    GitHubStoreStage.INPUT,
                )
        elif session_id is not None:
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_IDENTITY,
                GitHubStoreStage.INPUT,
            )

    def _validate_loaded_proposal(
        self,
        proposal: GitHubProposal,
        proposal_sha256: str,
    ) -> None:
        if proposal.proposal_sha256 != proposal_sha256 or not self._proposal_matches_store(
            proposal
        ):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )

    def _proposal_matches_store(self, proposal: GitHubProposal) -> bool:
        if (
            proposal.repository_id != self._repository_id
            or proposal.repository_full_name != self._repository_full_name
        ):
            return False
        payload = proposal.payload
        if proposal.kind is GitHubProposalKind.CHECK:
            review = payload.get("review_result")
            alias = None if type(review) is not dict else review.get("repository_alias")
        else:
            alias = payload.get("repository_alias")
        return alias == self._repository_alias

    def _revalidate_open_publication(
        self,
        opened: _OpenPublication,
        proposal_sha256: str,
    ) -> None:
        _revalidate_root(
            self._product_state_root,
            opened.root_fd,
            expected_identity=self._root_identity,
        )
        _revalidate_named(
            opened.github_fd,
            opened.root_fd,
            "github",
            directory=True,
            mode=0o700,
        )
        _revalidate_named(
            opened.manager_lock_fd,
            opened.github_fd,
            _MANAGER_LOCK_NAME,
            directory=False,
            mode=0o600,
        )
        _revalidate_named(
            opened.repository_fd,
            opened.github_fd,
            self._repository_alias,
            directory=True,
            mode=0o700,
        )
        _revalidate_named(
            opened.publisher_lock_fd,
            opened.repository_fd,
            _PUBLISHER_LOCK_NAME,
            directory=False,
            mode=0o600,
        )
        _revalidate_named(
            opened.publications_fd,
            opened.repository_fd,
            "publications",
            directory=True,
            mode=0o700,
        )
        _revalidate_named(
            opened.proposal_fd,
            opened.publications_fd,
            proposal_sha256,
            directory=True,
            mode=0o700,
        )
        _revalidate_named(
            opened.lock_fd,
            opened.proposal_fd,
            "publication.lock",
            directory=False,
            mode=0o600,
        )


class LockedGitHubPublication:
    """One proposal-scoped lock held across a complete publication attempt."""

    __slots__ = ("_opened", "_proposal_fd", "_proposal_sha256", "_store")

    def __init__(
        self,
        store: GitHubPublicationStore,
        proposal_sha256: str,
        proposal_fd: int,
        opened: _OpenPublication,
    ) -> None:
        self._store = store
        self._proposal_sha256 = proposal_sha256
        self._proposal_fd = proposal_fd
        self._opened = opened

    def status(self) -> GitHubPublicationStatus:
        """Load the proposal and every optional publication record."""
        return self._load_status()

    def repair_session_id(self) -> str:
        """Return the private session binding without adding it to public status."""
        status = self._load_status()
        if status.proposal.kind is not GitHubProposalKind.REPAIR:
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.READ,
            )
        binding = self._load_binding(required=True)
        assert binding is not None
        return binding.session_id

    def record_approval(self, approval: GitHubApproval) -> GitHubPublicationStatus:
        """CAS-persist the one approval used by all subsequent writes."""
        status = self._load_status()
        if type(approval) is not GitHubApproval or not _approval_matches_proposal(
            status.proposal, approval
        ):
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_IDENTITY,
                GitHubStoreStage.INPUT,
            )
        _write_cas_record(
            self._proposal_fd,
            "approval.json",
            github_approval_to_json(approval).encode("utf-8"),
            maximum=_APPROVAL_MAX_BYTES,
        )
        return self._load_status()

    def record_partial_result(
        self,
        result: GitHubPublicationResult,
    ) -> GitHubPublicationStatus:
        """CAS-persist a branch-created repair result for exact-approval recovery."""
        status = self._load_status()
        if (
            type(result) is not GitHubPublicationResult
            or result.proposal_sha256 != status.proposal.proposal_sha256
            or result.kind is not GitHubProposalKind.REPAIR
            or result.state is not GitHubPublicationState.BRANCH_CREATED
        ):
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_IDENTITY,
                GitHubStoreStage.INPUT,
            )
        _require_result_matches_proposal(status.proposal, result)
        _require_saved_approval(status, result)
        if status.partial_result is not None:
            if status.partial_result == result:
                return status
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.WRITE,
            )
        if status.result is not None:
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.WRITE,
            )
        _write_cas_record(
            self._proposal_fd,
            "branch.json",
            github_result_to_json(result).encode("utf-8"),
            maximum=_RESULT_MAX_BYTES,
        )
        return self._load_status()

    def record_result(
        self,
        result: GitHubPublicationResult,
    ) -> GitHubPublicationStatus:
        """CAS-persist a final check or draft-repair-PR publication result."""
        status = self._load_status()
        if (
            type(result) is not GitHubPublicationResult
            or result.proposal_sha256 != status.proposal.proposal_sha256
            or result.kind is not status.proposal.kind
            or result.state is GitHubPublicationState.BRANCH_CREATED
        ):
            _raise_store_error(
                GitHubStoreErrorCode.INVALID_IDENTITY,
                GitHubStoreStage.INPUT,
            )
        _require_result_matches_proposal(status.proposal, result)
        _require_saved_approval(status, result)
        if status.result is not None:
            if status.result == result:
                return status
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.WRITE,
            )
        if status.partial_result is not None:
            _require_same_recovery(status.partial_result, result)
        _write_cas_record(
            self._proposal_fd,
            "result.json",
            github_result_to_json(result).encode("utf-8"),
            maximum=_RESULT_MAX_BYTES,
        )
        return self._load_status()

    def _record_proposal(
        self,
        proposal: GitHubProposal,
        *,
        session_id: str | None,
    ) -> None:
        self._revalidate()
        names = _directory_names(self._proposal_fd)
        if not names <= _RECORD_NAMES:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        if (
            names - {"publication.lock", "proposal.json", "binding.json"}
            and "proposal.json" not in names
        ):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        proposal_bytes = github_proposal_to_json(proposal).encode("utf-8")
        _require_cas_compatible(
            self._proposal_fd,
            "proposal.json",
            proposal_bytes,
            maximum=GITHUB_PROPOSAL_MAX_BYTES,
        )
        if proposal.kind is GitHubProposalKind.REPAIR:
            assert session_id is not None
            if "proposal.json" in names and "binding.json" not in names:
                _raise_store_error(
                    GitHubStoreErrorCode.CORRUPT_STATE,
                    GitHubStoreStage.READ,
                )
            binding = _binding_bytes(proposal.proposal_sha256, session_id)
            _require_cas_compatible(
                self._proposal_fd,
                "binding.json",
                binding,
                maximum=_BINDING_MAX_BYTES,
            )
            _write_cas_record(
                self._proposal_fd,
                "binding.json",
                binding,
                maximum=_BINDING_MAX_BYTES,
            )
        elif "binding.json" in names:
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.WRITE,
            )
        _write_cas_record(
            self._proposal_fd,
            "proposal.json",
            proposal_bytes,
            maximum=GITHUB_PROPOSAL_MAX_BYTES,
        )
        self._revalidate()

    def _load_status(self) -> GitHubPublicationStatus:
        self._revalidate()
        names = _directory_names(self._proposal_fd)
        if not names <= _RECORD_NAMES:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        proposal_raw = _read_record(
            self._proposal_fd,
            "proposal.json",
            maximum=GITHUB_PROPOSAL_MAX_BYTES,
            required=True,
        )
        assert proposal_raw is not None
        try:
            proposal = github_proposal_from_json(proposal_raw)
        except ValueError:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        self._store._validate_loaded_proposal(proposal, self._proposal_sha256)
        binding = self._load_binding(required=proposal.kind is GitHubProposalKind.REPAIR)
        if (proposal.kind is GitHubProposalKind.CHECK) != (binding is None):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        approval = self._load_approval(proposal)
        partial = self._load_result(proposal, "branch.json")
        result = self._load_result(proposal, "result.json")
        _validate_loaded_state(
            proposal=proposal,
            approval=approval,
            partial=partial,
            result=result,
        )
        status = GitHubPublicationStatus(
            proposal=proposal,
            approval=approval,
            partial_result=partial,
            result=result,
        )
        self._revalidate()
        return status

    def _revalidate(self) -> None:
        self._store._revalidate_open_publication(
            self._opened,
            self._proposal_sha256,
        )

    def _load_binding(self, *, required: bool) -> _RepairBinding | None:
        raw = _read_record(
            self._proposal_fd,
            "binding.json",
            maximum=_BINDING_MAX_BYTES,
            required=required,
        )
        if raw is None:
            return None
        try:
            decoded = parse_canonical_json(raw, max_bytes=_BINDING_MAX_BYTES)
            if type(decoded) is not dict:
                raise ValueError("binding is invalid")
            require_exact_keys(
                decoded,
                ("schema_version", "proposal_sha256", "session_id"),
                name="GitHub binding",
            )
            schema_version = decoded["schema_version"]
            proposal_sha256 = decoded["proposal_sha256"]
            session_id = decoded["session_id"]
            if (
                type(schema_version) is not int
                or schema_version != 1
                or type(proposal_sha256) is not str
                or proposal_sha256 != self._proposal_sha256
                or type(session_id) is not str
                or _SHA256_PATTERN.fullmatch(session_id) is None
            ):
                raise ValueError("binding is invalid")
            return _RepairBinding(
                schema_version=schema_version,
                proposal_sha256=proposal_sha256,
                session_id=session_id,
            )
        except (KeyError, TypeError, ValueError):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )

    def _load_approval(self, proposal: GitHubProposal) -> GitHubApproval | None:
        raw = _read_record(
            self._proposal_fd,
            "approval.json",
            maximum=_APPROVAL_MAX_BYTES,
            required=False,
        )
        if raw is None:
            return None
        try:
            approval = github_approval_from_json(raw)
        except ValueError:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        if not _approval_matches_proposal(proposal, approval):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        return approval

    def _load_result(
        self,
        proposal: GitHubProposal,
        name: str,
    ) -> GitHubPublicationResult | None:
        raw = _read_record(
            self._proposal_fd,
            name,
            maximum=_RESULT_MAX_BYTES,
            required=False,
        )
        if raw is None:
            return None
        try:
            return github_result_from_json(raw, proposal=proposal)
        except ValueError:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )


def _validate_loaded_state(
    *,
    proposal: GitHubProposal,
    approval: GitHubApproval | None,
    partial: GitHubPublicationResult | None,
    result: GitHubPublicationResult | None,
) -> None:
    if partial is not None and (
        proposal.kind is not GitHubProposalKind.REPAIR
        or partial.state is not GitHubPublicationState.BRANCH_CREATED
        or approval is None
        or partial.approval != approval
    ):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    if result is not None:
        expected_state = (
            GitHubPublicationState.CHECK_PUBLISHED
            if proposal.kind is GitHubProposalKind.CHECK
            else GitHubPublicationState.REPAIR_PUBLISHED
        )
        if result.state is not expected_state or approval is None or result.approval != approval:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
    if partial is not None and result is not None:
        try:
            _require_same_recovery(partial, result)
        except GitHubStoreError:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )


def _approval_matches_proposal(
    proposal: GitHubProposal,
    approval: GitHubApproval,
) -> bool:
    return (
        approval.proposal_sha256 == proposal.proposal_sha256
        and approval.kind is proposal.kind
        and proposal.created_at_us <= approval.approved_at_us < proposal.expires_at_us
    )


def _require_saved_approval(
    status: GitHubPublicationStatus,
    result: GitHubPublicationResult,
) -> None:
    if status.approval is None or result.approval != status.approval:
        _raise_store_error(
            GitHubStoreErrorCode.STATE_CONFLICT,
            GitHubStoreStage.WRITE,
        )


def _require_result_matches_proposal(
    proposal: GitHubProposal,
    result: GitHubPublicationResult,
) -> None:
    try:
        validate_github_result(proposal, result)
    except (TypeError, ValueError):
        _raise_store_error(
            GitHubStoreErrorCode.INVALID_IDENTITY,
            GitHubStoreStage.INPUT,
        )


def _require_same_recovery(
    partial: GitHubPublicationResult,
    result: GitHubPublicationResult,
) -> None:
    if (
        result.approval != partial.approval
        or result.application_sha256 != partial.application_sha256
        or result.published_at_us < partial.published_at_us
    ):
        _raise_store_error(
            GitHubStoreErrorCode.STATE_CONFLICT,
            GitHubStoreStage.WRITE,
        )


def _binding_bytes(proposal_sha256: str, session_id: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": 1,
            "proposal_sha256": proposal_sha256,
            "session_id": session_id,
        }
    )


def _validate_constructor_inputs(
    *,
    product_state_root: Path,
    repository_alias: str,
    repository_id: int,
    repository_full_name: str,
    lock_timeout_seconds: float,
) -> None:
    if (
        not isinstance(product_state_root, Path)
        or not product_state_root.is_absolute()
        or Path(os.path.normpath(str(product_state_root))) != product_state_root
        or len(str(product_state_root).encode("utf-8")) > 4_096
    ):
        raise ValueError("state root is invalid")
    if type(repository_alias) is not str or _ALIAS_PATTERN.fullmatch(repository_alias) is None:
        raise ValueError("repository alias is invalid")
    if type(repository_id) is not int or repository_id <= 0:
        raise ValueError("repository ID is invalid")
    if (
        type(repository_full_name) is not str
        or _FULL_NAME_PATTERN.fullmatch(repository_full_name) is None
        or ".." in repository_full_name
    ):
        raise ValueError("repository full name is invalid")
    if type(lock_timeout_seconds) is not float or not 0.0 < lock_timeout_seconds <= 30.0:
        raise ValueError("lock timeout is invalid")


def _validate_digest_input(value: str) -> None:
    if not _is_sha256(value):
        _raise_store_error(
            GitHubStoreErrorCode.INVALID_IDENTITY,
            GitHubStoreStage.INPUT,
        )


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _open_root(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(
        "/",
        flags,
    )
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            parent = descriptor
            descriptor = child
            os.close(parent)
        _validate_root_fd(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_root_fd(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 2
    ):
        raise OSError("unsafe publication root")


def _revalidate_root(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
) -> None:
    current = _open_root(path)
    try:
        if (
            _fd_identity(descriptor) != expected_identity
            or _fd_identity(current) != expected_identity
        ):
            raise OSError("state root changed")
    finally:
        os.close(current)


def _open_or_create_directory(
    parent_fd: int,
    name: str,
    *,
    create: bool,
) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        if not create:
            raise
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            created = True
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        if created:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
            _fsync(parent_fd)
    try:
        _validate_fd(descriptor, directory=True, mode=0o700)
        _revalidate_named(
            descriptor,
            parent_fd,
            name,
            directory=True,
            mode=0o700,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_or_create_lock(
    directory_fd: int,
    name: str,
    *,
    create: bool,
) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        if not create:
            raise
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
        else:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync(directory_fd)
    try:
        _validate_fd(descriptor, directory=False, mode=0o600)
        _revalidate_named(
            descriptor,
            directory_fd,
            name,
            directory=False,
            mode=0o600,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_state_lock(
    directory_fd: int,
    name: str,
    *,
    create: bool,
) -> int:
    exists = _entry_exists(directory_fd, name)
    if not exists and (
        not create
        or (not _directory_is_empty(directory_fd) and not _entry_exists(directory_fd, name))
    ):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.OPEN,
        )
    return _open_or_create_lock(directory_fd, name, create=create)


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _directory_is_empty(directory_fd: int) -> bool:
    with os.scandir(directory_fd) as entries:
        return next(entries, None) is None


def _revalidate_named(
    descriptor: int,
    parent_fd: int,
    name: str,
    *,
    directory: bool,
    mode: int,
) -> None:
    _validate_fd(descriptor, directory=directory, mode=mode)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(named.st_mode)
        or named.st_uid != os.geteuid()
        or stat.S_IMODE(named.st_mode) != mode
        or (not directory and named.st_nlink != 1)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise OSError("unsafe publication path")


def _validate_fd(descriptor: int, *, directory: bool, mode: int) -> None:
    metadata = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or (not directory and metadata.st_nlink != 1)
        or (not directory and metadata.st_size != 0)
    ):
        raise OSError("unsafe publication metadata")


def _fd_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def _directory_names(directory_fd: int) -> frozenset[str]:
    return _bounded_directory_names(
        directory_fd,
        maximum_entries=len(_RECORD_NAMES),
    )


def _bounded_directory_names(
    directory_fd: int,
    *,
    maximum_entries: int,
) -> frozenset[str]:
    try:
        names: list[str] = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum_entries:
                    _raise_store_error(
                        GitHubStoreErrorCode.CORRUPT_STATE,
                        GitHubStoreStage.READ,
                    )
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.IO_FAILED,
            GitHubStoreStage.READ,
        )
    if any(type(name) is not str for name in names):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    return frozenset(names)


def _recover_record_temporary(directory_fd: int) -> None:
    names = _bounded_directory_names(
        directory_fd,
        maximum_entries=len(_RECORD_NAMES) + 1,
    )
    temporary_names = tuple(name for name in names if name.startswith(".record-"))
    if not temporary_names:
        return
    if (
        len(temporary_names) != 1
        or _TEMP_RECORD_PATTERN.fullmatch(temporary_names[0]) is None
        or names - _RECORD_NAMES - set(temporary_names)
    ):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    temporary = temporary_names[0]
    descriptor = _open_temporary_record(directory_fd, temporary)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_nlink == 1:
            _recover_unpublished_temporary(
                directory_fd,
                temporary,
                descriptor,
                metadata,
            )
            return
        if metadata.st_nlink != 2 or not _safe_linked_record_metadata(
            metadata,
            maximum=GITHUB_PROPOSAL_MAX_BYTES,
        ):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        matching = [
            name
            for name in _RECORD_LIMITS
            if name in names and _named_identity(directory_fd, name) == _stat_identity(metadata)
        ]
        if len(matching) != 1:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        _recover_linked_temporary(
            directory_fd,
            temporary,
            descriptor,
            metadata,
            final_name=matching[0],
            maximum=_RECORD_LIMITS[matching[0]],
        )
    finally:
        os.close(descriptor)


def _open_temporary_record(directory_fd: int, name: str) -> int:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _stat_identity(metadata) != _stat_identity(named)
            or not _safe_temporary_metadata(metadata)
            or _stat_signature(metadata) != _stat_signature(named)
        ):
            raise OSError("unsafe temporary record")
        return descriptor
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )


def _safe_temporary_metadata(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and mode in {0o400, 0o600}
        and metadata.st_nlink in {1, 2}
        and 0 <= metadata.st_size <= GITHUB_PROPOSAL_MAX_BYTES
        and not (mode == 0o400 and metadata.st_size == 0)
    )


def _safe_linked_record_metadata(
    metadata: os.stat_result,
    *,
    maximum: int,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == 2
        and 0 < metadata.st_size <= maximum
    )


def _recover_unpublished_temporary(
    directory_fd: int,
    name: str,
    descriptor: int,
    metadata: os.stat_result,
) -> None:
    if not _safe_temporary_metadata(metadata):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    _require_named_signature(directory_fd, name, metadata)
    os.unlink(name, dir_fd=directory_fd)
    after = os.fstat(descriptor)
    if _stat_identity(after) != _stat_identity(metadata) or after.st_nlink != 0:
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    _fsync(directory_fd)


def _recover_linked_temporary(
    directory_fd: int,
    temporary: str,
    temporary_fd: int,
    temporary_metadata: os.stat_result,
    *,
    final_name: str,
    maximum: int,
) -> None:
    if not _safe_linked_record_metadata(temporary_metadata, maximum=maximum):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    try:
        final_fd = os.open(
            final_name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    try:
        final_metadata = os.fstat(final_fd)
        if _stat_identity(final_metadata) != _stat_identity(temporary_metadata) or _stat_signature(
            final_metadata
        ) != _stat_signature(temporary_metadata):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        _require_named_signature(directory_fd, temporary, temporary_metadata)
        _require_named_signature(directory_fd, final_name, final_metadata)
        os.unlink(temporary, dir_fd=directory_fd)
        after_temporary = os.fstat(temporary_fd)
        after_final = os.fstat(final_fd)
        named_final = os.stat(
            final_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            _stat_identity(after_temporary) != _stat_identity(temporary_metadata)
            or _stat_identity(after_final) != _stat_identity(temporary_metadata)
            or after_temporary.st_nlink != 1
            or after_final.st_nlink != 1
            or not _safe_record_metadata(named_final, maximum=maximum)
            or _stat_identity(named_final) != _stat_identity(temporary_metadata)
        ):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        _fsync(directory_fd)
    finally:
        os.close(final_fd)


def _require_named_signature(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
) -> None:
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _stat_signature(named) != _stat_signature(expected):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )


def _named_identity(directory_fd: int, name: str) -> tuple[int, int]:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    return _stat_identity(metadata)


def _read_record(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    required: bool,
) -> bytes | None:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if required:
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        return None
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.IO_FAILED,
            GitHubStoreStage.READ,
        )
    if not _safe_record_metadata(before, maximum=maximum):
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.CORRUPT_STATE,
            GitHubStoreStage.READ,
        )
    try:
        opened = os.fstat(descriptor)
        if not _safe_record_metadata(opened, maximum=maximum) or _stat_identity(
            opened
        ) != _stat_identity(before):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        after_fd = os.fstat(descriptor)
        after_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not raw
            or len(raw) > maximum
            or len(raw) != opened.st_size
            or _stat_signature(opened) != _stat_signature(after_fd)
            or _stat_signature(opened) != _stat_signature(after_name)
        ):
            _raise_store_error(
                GitHubStoreErrorCode.CORRUPT_STATE,
                GitHubStoreStage.READ,
            )
        return raw
    except GitHubStoreError:
        raise
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.IO_FAILED,
            GitHubStoreStage.READ,
        )
    finally:
        os.close(descriptor)


def _safe_record_metadata(metadata: os.stat_result, *, maximum: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == 1
        and 0 < metadata.st_size <= maximum
    )


def _stat_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _stat_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_cas_record(
    directory_fd: int,
    name: str,
    value: bytes,
    *,
    maximum: int,
) -> None:
    if type(value) is not bytes or not value or len(value) > maximum:
        _raise_store_error(
            GitHubStoreErrorCode.INVALID_IDENTITY,
            GitHubStoreStage.INPUT,
        )
    existing = _read_record(
        directory_fd,
        name,
        maximum=maximum,
        required=False,
    )
    if existing is not None:
        if hmac.compare_digest(existing, value):
            return
        _raise_store_error(
            GitHubStoreErrorCode.STATE_CONFLICT,
            GitHubStoreStage.WRITE,
        )
    temporary = f".record-{secrets.token_hex(16)}"
    descriptor: int | None = None
    linked = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        _record_write_checkpoint("created")
        split = max(1, len(value) // 2)
        _write_all(descriptor, value[:split])
        _record_write_checkpoint("write-partial")
        _write_all(descriptor, value[split:])
        _record_write_checkpoint("written")
        os.fsync(descriptor)
        _record_write_checkpoint("fsynced")
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        _record_write_checkpoint("chmodded")
        temporary_metadata = os.fstat(descriptor)
        if not _safe_record_metadata(
            temporary_metadata, maximum=maximum
        ) or temporary_metadata.st_size != len(value):
            raise OSError("unsafe temporary record")
        os.link(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        linked = True
        _record_write_checkpoint("linked")
        os.unlink(temporary, dir_fd=directory_fd)
        _record_write_checkpoint("unlinked")
        final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not _safe_record_metadata(final, maximum=maximum) or _stat_identity(
            final
        ) != _stat_identity(temporary_metadata):
            raise OSError("unsafe final record")
        _fsync(directory_fd)
    except FileExistsError:
        existing = _read_record(
            directory_fd,
            name,
            maximum=maximum,
            required=True,
        )
        if existing is None or not hmac.compare_digest(existing, value):
            _raise_store_error(
                GitHubStoreErrorCode.STATE_CONFLICT,
                GitHubStoreStage.WRITE,
            )
    except GitHubStoreError:
        raise
    except OSError:
        _raise_store_error(
            GitHubStoreErrorCode.IO_FAILED,
            GitHubStoreStage.WRITE,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not linked:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory_fd)


def _require_cas_compatible(
    directory_fd: int,
    name: str,
    value: bytes,
    *,
    maximum: int,
) -> None:
    existing = _read_record(
        directory_fd,
        name,
        maximum=maximum,
        required=False,
    )
    if existing is not None and not hmac.compare_digest(existing, value):
        _raise_store_error(
            GitHubStoreErrorCode.STATE_CONFLICT,
            GitHubStoreStage.WRITE,
        )


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("short record write")
        offset += written


def _record_write_checkpoint(_stage: str) -> None:
    """Test seam for process-crash recovery at durable write boundaries."""


def _acquire_flock(descriptor: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def _open_error_code(error: OSError) -> GitHubStoreErrorCode:
    if error.errno in {
        errno.EIO,
        errno.ENOSPC,
        errno.EDQUOT,
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOMEM,
    }:
        return GitHubStoreErrorCode.IO_FAILED
    return GitHubStoreErrorCode.CORRUPT_STATE


def _fsync(descriptor: int) -> None:
    os.fsync(descriptor)


def _raise_store_error(
    code: GitHubStoreErrorCode,
    stage: GitHubStoreStage,
    *,
    retryable: bool = False,
) -> NoReturn:
    raise GitHubStoreError(code, stage, retryable=retryable) from None
