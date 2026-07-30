"""Immutable public models for read-only repository evidence."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

__all__ = [
    "ChangeType",
    "ContentKind",
    "DiffHunkEvidence",
    "DiffLineEvidence",
    "DiffLineKind",
    "EvidenceBundle",
    "EvidenceCollectionError",
    "EvidenceCollectionLimits",
    "EvidenceErrorCode",
    "FileChangeEvidence",
    "FileVersion",
    "PullRequestInput",
    "RepositoryEvidence",
    "RepositoryInput",
    "RevisionEvidence",
    "collect_evidence",
    "evidence_to_dict",
    "evidence_to_json",
]


class ChangeType(StrEnum):
    """Kind of committed file change."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    TYPE_CHANGED = "type_changed"


class ContentKind(StrEnum):
    """Kind of content represented by a Git tree entry."""

    TEXT = "text"
    BINARY = "binary"
    SYMLINK = "symlink"
    SUBMODULE = "submodule"
    OTHER = "other"


class DiffLineKind(StrEnum):
    """Kind of line in a unified diff hunk."""

    CONTEXT = "context"
    ADDITION = "addition"
    DELETION = "deletion"


class EvidenceErrorCode(StrEnum):
    """Stable category for an evidence collection failure."""

    GIT_UNAVAILABLE = "git_unavailable"
    REPOSITORY_PATH_MISSING = "repository_path_missing"
    NOT_A_WORKTREE = "not_a_worktree"
    INVALID_BASE_REF = "invalid_base_ref"
    INVALID_HEAD_REF = "invalid_head_ref"
    NO_MERGE_BASE = "no_merge_base"
    AMBIGUOUS_MERGE_BASE = "ambiguous_merge_base"
    UNSUPPORTED_PATH_ENCODING = "unsupported_path_encoding"
    GIT_COMMAND_FAILED = "git_command_failed"
    GIT_TIMEOUT = "git_timeout"
    MALFORMED_GIT_OUTPUT = "malformed_git_output"
    RESOURCE_LIMIT = "resource_limit"


class EvidenceCollectionError(RuntimeError):
    """Atomic evidence collection failure with a stable machine-readable code."""

    code: EvidenceErrorCode

    def __init__(self, code: EvidenceErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class EvidenceCollectionLimits:
    """Caller-lowerable resource ceilings for one atomic evidence collection."""

    max_changed_files: int = 1_000
    max_blob_bytes: int = 2 * 1024 * 1024
    max_total_blob_bytes: int = 64 * 1024 * 1024
    max_diff_bytes: int = 16 * 1024 * 1024
    max_diff_lines: int = 131_072
    git_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        ceilings = {
            "max_changed_files": 1_000,
            "max_blob_bytes": 2 * 1024 * 1024,
            "max_total_blob_bytes": 64 * 1024 * 1024,
            "max_diff_bytes": 16 * 1024 * 1024,
            "max_diff_lines": 131_072,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be an integer from 1 through {ceiling}")
        timeout = self.git_timeout_seconds
        if type(timeout) is not float or not math.isfinite(timeout) or not 0.0 < timeout <= 60.0:
            raise ValueError(
                "git_timeout_seconds must be a finite float greater than 0 and at most 60"
            )


@dataclass(frozen=True, slots=True)
class RepositoryInput:
    """Local worktree supplied for evidence collection."""

    path: Path


@dataclass(frozen=True, slots=True)
class PullRequestInput:
    """Committed base and head refs defining a pull-request comparison."""

    base_ref: str
    head_ref: str


@dataclass(frozen=True, slots=True)
class RepositoryEvidence:
    """Canonical identity of the inspected Git worktree."""

    root: Path
    object_format: str


@dataclass(frozen=True, slots=True)
class RevisionEvidence:
    """Requested refs and the immutable commits used for collection."""

    base_ref: str
    head_ref: str
    base_oid: str
    head_oid: str
    merge_base_oid: str


@dataclass(frozen=True, slots=True)
class FileVersion:
    """Metadata for one side of a changed Git tree entry."""

    path: str
    mode: str
    oid: str
    content_kind: ContentKind


@dataclass(frozen=True, slots=True)
class DiffLineEvidence:
    """One line of traceable unified-diff evidence."""

    kind: DiffLineKind
    old_line_number: int | None
    new_line_number: int | None
    content: str
    has_trailing_newline: bool


@dataclass(frozen=True, slots=True)
class DiffHunkEvidence:
    """A unified-diff hunk and its source coordinates."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[DiffLineEvidence, ...]


@dataclass(frozen=True, slots=True)
class FileChangeEvidence:
    """Metadata and optional text hunks for one committed file change."""

    change_type: ChangeType
    rename_similarity: int | None
    old: FileVersion | None
    new: FileVersion | None
    hunks: tuple[DiffHunkEvidence, ...]


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Complete evidence collected for one base/head comparison."""

    repository: RepositoryEvidence
    revisions: RevisionEvidence
    changes: tuple[FileChangeEvidence, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            msg = "schema_version must be 1"
            raise ValueError(msg)


def collect_evidence(
    repository: RepositoryInput,
    pull_request: PullRequestInput,
    *,
    limits: EvidenceCollectionLimits | None = None,
    git_executable: Path | None = None,
) -> EvidenceBundle:
    """Collect committed evidence, optionally using one bounded fixed-Git capability."""
    from repoguard._git import _collect_evidence

    if limits is not None and type(limits) is not EvidenceCollectionLimits:
        raise TypeError("limits must be an exact EvidenceCollectionLimits or None")
    if git_executable is not None and not isinstance(git_executable, Path):
        raise TypeError("git_executable must be a Path or None")
    if git_executable is not None and limits is None:
        raise ValueError("git_executable requires explicit evidence collection limits")
    if limits is None:
        return _collect_evidence(repository, pull_request)
    if git_executable is not None:
        return _collect_evidence(
            repository,
            pull_request,
            limits=limits,
            git_executable=git_executable,
        )
    return _collect_evidence(repository, pull_request, limits=limits)


def evidence_to_dict(bundle: EvidenceBundle) -> dict[str, object]:
    """Convert an evidence bundle to its canonical JSON-compatible mapping."""
    return {
        "schema_version": bundle.schema_version,
        "repository": _repository_to_dict(bundle.repository),
        "revisions": _revisions_to_dict(bundle.revisions),
        "changes": [_change_to_dict(change) for change in bundle.changes],
    }


def evidence_to_json(bundle: EvidenceBundle) -> str:
    """Serialize evidence as canonical compact UTF-8 JSON without a trailing newline."""
    return json.dumps(
        evidence_to_dict(bundle),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _repository_to_dict(repository: RepositoryEvidence) -> dict[str, object]:
    return {
        "root": _require_utf8_path(str(repository.root)),
        "object_format": repository.object_format,
    }


def _revisions_to_dict(revisions: RevisionEvidence) -> dict[str, object]:
    return {
        "base_ref": revisions.base_ref,
        "head_ref": revisions.head_ref,
        "base_oid": revisions.base_oid,
        "head_oid": revisions.head_oid,
        "merge_base_oid": revisions.merge_base_oid,
    }


def _file_version_to_dict(version: FileVersion) -> dict[str, object]:
    return {
        "path": _require_utf8_path(version.path),
        "mode": version.mode,
        "oid": version.oid,
        "content_kind": version.content_kind.value,
    }


def _line_to_dict(line: DiffLineEvidence) -> dict[str, object]:
    return {
        "kind": line.kind.value,
        "old_line_number": line.old_line_number,
        "new_line_number": line.new_line_number,
        "content": line.content,
        "has_trailing_newline": line.has_trailing_newline,
    }


def _hunk_to_dict(hunk: DiffHunkEvidence) -> dict[str, object]:
    return {
        "old_start": hunk.old_start,
        "old_count": hunk.old_count,
        "new_start": hunk.new_start,
        "new_count": hunk.new_count,
        "lines": [_line_to_dict(line) for line in hunk.lines],
    }


def _change_to_dict(change: FileChangeEvidence) -> dict[str, object]:
    return {
        "change_type": change.change_type.value,
        "rename_similarity": change.rename_similarity,
        "old": None if change.old is None else _file_version_to_dict(change.old),
        "new": None if change.new is None else _file_version_to_dict(change.new),
        "hunks": [_hunk_to_dict(hunk) for hunk in change.hunks],
    }


def _require_utf8_path(path: str) -> str:
    try:
        path.encode("utf-8")
    except UnicodeEncodeError as error:
        msg = "evidence paths must be valid UTF-8"
        raise EvidenceCollectionError(
            EvidenceErrorCode.UNSUPPORTED_PATH_ENCODING,
            msg,
        ) from error
    return path
