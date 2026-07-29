"""Isolated Git object materialization and ref-only repair publication."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, NoReturn

from repoguard._repair_patch import _ParsedPatch
from repoguard._repair_paths import _canonical_repository_paths, _validate_repository_path
from repoguard.evidence import RepositoryInput
from repoguard.repair import RepairError, RepairErrorCode, RepairStage

_OBJECT_FORMAT_LENGTHS = {"sha1": 40, "sha256": 64}
_OID_PATTERN = re.compile(r"^[0-9a-f]+$")
_CANDIDATE_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PROC_SELF_FD_PATTERN = re.compile(r"(?:^|[=,:])(/proc/self/fd/([1-9][0-9]*))(?=/|$)")
_PACKED_REF_SEPARATORS = frozenset((ord(" "), ord("\t"), ord("\r")))
_PACKED_REF_FORBIDDEN = frozenset(b" ~^:?*[\\")
_PACKED_REFS_HEADER = b"# pack-refs with:"
_COMMIT_MESSAGE = b"RepoGuard safe repair candidate\n"
_IDENTITY = "RepoGuard <repoguard@localhost>"
_MINIMUM_FREE_BYTES = 4 * 1_024 * 1_024 * 1_024
_MAX_HEAD_ENTRIES = 20_000
_MAX_HEAD_BLOB_BYTES = 512 * 1_024 * 1_024
_MAX_BLOB_BYTES = 16 * 1_024 * 1_024
_MAX_HOST_BYTES = 2 * 1_024 * 1_024 * 1_024
_MAX_HOST_ENTRIES = 50_000
_MAX_CHANGED_PATHS = 32
_MAX_CHANGED_LINES = 10_000
_CONTROL_OUTPUT_BYTES = 2 * 1_024 * 1_024
_TREE_OUTPUT_BYTES = 32 * 1_024 * 1_024
_DIFF_OUTPUT_BYTES = 4 * 1_024 * 1_024
_LOOSE_REF_BYTES = max(_OBJECT_FORMAT_LENGTHS.values()) + 1
_GIT_TIMEOUT_SECONDS = 30.0
_PACK_TIMEOUT_SECONDS = 180.0
_POLL_SECONDS = 0.02
_READ_CHUNK_BYTES = 64 * 1_024

_FIXED_CONFIG: tuple[tuple[str, str], ...] = (
    ("advice.detachedHead", "false"),
    ("commit.gpgSign", "false"),
    ("core.askPass", "/bin/false"),
    ("core.hooksPath", "/dev/null"),
    ("core.logAllRefUpdates", "false"),
    ("credential.helper", ""),
    ("credential.interactive", "never"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("protocol.file.allow", "always"),
    ("push.gpgSign", "false"),
    ("receive.advertisePushOptions", "false"),
    ("receive.autogc", "false"),
    ("receive.updateServerInfo", "false"),
    ("tag.gpgSign", "false"),
)


@dataclass(frozen=True, slots=True)
class _GitLimits:
    minimum_free_bytes: int = _MINIMUM_FREE_BYTES
    max_head_entries: int = _MAX_HEAD_ENTRIES
    max_head_blob_bytes: int = _MAX_HEAD_BLOB_BYTES
    max_blob_bytes: int = _MAX_BLOB_BYTES
    max_host_bytes: int = _MAX_HOST_BYTES
    max_host_entries: int = _MAX_HOST_ENTRIES
    max_changed_paths: int = _MAX_CHANGED_PATHS
    max_changed_lines: int = _MAX_CHANGED_LINES


_DEFAULT_LIMITS = _GitLimits()


@dataclass(frozen=True, slots=True)
class _HeadEntry:
    mode: str
    kind: str
    oid: str
    size: int | None
    path: str


@dataclass(frozen=True, slots=True)
class _RepositoryIdentity:
    root: Path
    git_dir: Path
    common_dir: Path
    object_format: str
    head_oid: str
    root_device: int
    root_inode: int
    common_dir_device: int
    common_dir_inode: int
    entries: tuple[_HeadEntry, ...]
    ordinary_blob_bytes: int
    object_oids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RepositoryLayout:
    root: Path
    common_dir: Path


@dataclass(frozen=True, slots=True)
class _MaterializedCandidate:
    source: _RepositoryIdentity
    root: Path
    git_dir: Path
    index_file: Path
    canonical_diff: str
    tree_oid: str
    commit_oid: str
    changed_paths: tuple[str, ...]
    changed_line_count: int


@dataclass(frozen=True, slots=True)
class _MaterializedFile:
    path: str
    content: bytes
    executable: bool


class _PublicationOutcome(StrEnum):
    PUBLISHED = "published"
    ALREADY_PRESENT = "already_present"


@dataclass(frozen=True, slots=True)
class _PublicationResult:
    outcome: _PublicationOutcome
    ref: str
    commit_oid: str


@dataclass(frozen=True, slots=True)
class _GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(slots=True)
class _DrainState:
    output: bytearray
    total: int = 0
    failed: bool = False


@dataclass(slots=True)
class _InputState:
    failed: bool = False


class _UnsafeCandidateTreeError(Exception):
    """Private marker for candidate-tree metadata that cannot be hardened."""


class _CandidateTreePass(StrEnum):
    PREFLIGHT = "preflight"
    HARDEN = "harden"
    VERIFY = "verify"


def _resolve_repository_layout(
    repository: RepositoryInput,
    git_executable: Path,
) -> _RepositoryLayout:
    """Resolve the configured worktree and common directory without reading HEAD."""
    if type(repository) is not RepositoryInput:
        raise TypeError("repository must be an exact RepositoryInput")
    _require_git_executable(git_executable)
    input_path = _resolved_directory(repository.path, RepairStage.INPUT)
    root = _read_git_path(
        git_executable,
        input_path,
        ("rev-parse", "--path-format=absolute", "--show-toplevel"),
        RepairStage.INPUT,
    )
    common_dir = _read_git_path(
        git_executable,
        root,
        ("rev-parse", "--path-format=absolute", "--git-common-dir"),
        RepairStage.INPUT,
    )
    return _RepositoryLayout(root, common_dir)


def _capture_repository(
    repository: RepositoryInput,
    git_executable: Path,
    *,
    head_oid: str,
    require_current_head: bool = False,
    _limits: _GitLimits = _DEFAULT_LIMITS,
) -> _RepositoryIdentity:
    """Capture one exact commit and every object needed to reproduce its tree."""
    if type(repository) is not RepositoryInput:
        raise TypeError("repository must be an exact RepositoryInput")
    _require_git_executable(git_executable)
    _require_limits(_limits)
    input_path = _resolved_directory(repository.path, RepairStage.INPUT)
    root = _read_git_path(
        git_executable,
        input_path,
        ("rev-parse", "--path-format=absolute", "--show-toplevel"),
        RepairStage.INPUT,
    )
    git_dir = _read_git_path(
        git_executable,
        root,
        ("rev-parse", "--path-format=absolute", "--git-dir"),
        RepairStage.INPUT,
    )
    common_dir = _read_git_path(
        git_executable,
        root,
        ("rev-parse", "--path-format=absolute", "--git-common-dir"),
        RepairStage.INPUT,
    )
    object_format = _read_ascii_line(
        _run_required(
            git_executable,
            root,
            ("rev-parse", "--show-object-format"),
            stage=RepairStage.INPUT,
            failure_code=RepairErrorCode.GIT_FAILED,
        ).stdout,
        RepairStage.INPUT,
    )
    if object_format not in _OBJECT_FORMAT_LENGTHS:
        _raise(RepairErrorCode.GIT_FAILED, RepairStage.INPUT)
    _require_oid(head_oid, object_format, RepairStage.INPUT)
    if type(require_current_head) is not bool:
        raise TypeError("require_current_head must be an exact bool")
    if require_current_head:
        current_head = _parse_oid_line(
            _run_required(
                git_executable,
                root,
                ("rev-parse", "--verify", "HEAD^{commit}"),
                stage=RepairStage.INPUT,
                failure_code=RepairErrorCode.GIT_FAILED,
            ).stdout,
            object_format,
            RepairStage.INPUT,
        )
        if current_head != head_oid:
            _raise(RepairErrorCode.IDENTITY_MISMATCH, RepairStage.INPUT)
    commit_type = _run_required(
        git_executable,
        root,
        ("cat-file", "-t", head_oid),
        stage=RepairStage.INPUT,
        failure_code=RepairErrorCode.MISSING_OBJECT,
    )
    if _read_ascii_line(commit_type.stdout, RepairStage.INPUT) != "commit":
        _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.INPUT)
    entries, ordinary_blob_bytes, object_oids = _read_head_entries(
        git_executable,
        root,
        object_format,
        head_oid,
        stage=RepairStage.INPUT,
        limits=_limits,
    )
    if require_current_head:
        current_head = _parse_oid_line(
            _run_required(
                git_executable,
                root,
                ("rev-parse", "--verify", "HEAD^{commit}"),
                stage=RepairStage.INPUT,
                failure_code=RepairErrorCode.GIT_FAILED,
            ).stdout,
            object_format,
            RepairStage.INPUT,
        )
        if current_head != head_oid:
            _raise(RepairErrorCode.IDENTITY_MISMATCH, RepairStage.INPUT)
    root_stat = _directory_stat(root, RepairStage.INPUT)
    common_stat = _directory_stat(common_dir, RepairStage.INPUT)
    return _RepositoryIdentity(
        root=root,
        git_dir=git_dir,
        common_dir=common_dir,
        object_format=object_format,
        head_oid=head_oid,
        root_device=root_stat.st_dev,
        root_inode=root_stat.st_ino,
        common_dir_device=common_stat.st_dev,
        common_dir_inode=common_stat.st_ino,
        entries=entries,
        ordinary_blob_bytes=ordinary_blob_bytes,
        object_oids=(head_oid, *object_oids),
    )


def _read_head_file(
    source: _RepositoryIdentity,
    git_executable: Path,
    path: str,
    *,
    maximum_bytes: int = 1_048_576,
) -> bytes | None:
    """Read one ordinary exact-HEAD blob without consulting the worktree."""
    _require_repository_identity(source)
    _require_git_executable(git_executable)
    invalid_path = False
    try:
        _validate_repository_path(path)
    except (TypeError, ValueError):
        invalid_path = True
    if invalid_path:
        _raise(RepairErrorCode.INVALID_PATH, RepairStage.INPUT)
    if type(maximum_bytes) is not int or maximum_bytes <= 0 or maximum_bytes > _MAX_BLOB_BYTES:
        raise ValueError("maximum_bytes is outside its private bound")
    entry = _entry_for_path(source.entries, path)
    if entry is None:
        return None
    if entry.kind != "blob" or entry.mode not in {"100644", "100755"} or entry.size is None:
        _raise(RepairErrorCode.INVALID_PATH, RepairStage.INPUT)
    if entry.size > maximum_bytes:
        _raise(RepairErrorCode.RESOURCE_LIMIT, RepairStage.INPUT)
    result = _run_required(
        git_executable,
        source.root,
        ("cat-file", "blob", entry.oid),
        stage=RepairStage.INPUT,
        failure_code=RepairErrorCode.MISSING_OBJECT,
        stdout_limit=maximum_bytes + 1,
    )
    if len(result.stdout) != entry.size:
        _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.INPUT)
    return result.stdout


def _materialize_candidate(
    source: _RepositoryIdentity,
    git_executable: Path,
    destination: Path,
    patches: tuple[_ParsedPatch, ...],
    *,
    _destination_precreated: bool = False,
    _limits: _GitLimits = _DEFAULT_LIMITS,
) -> _MaterializedCandidate:
    """Copy exact objects, apply patches to an isolated index, and fix the commit."""
    _require_repository_identity(source)
    _require_git_executable(git_executable)
    _require_limits(_limits)
    if type(_destination_precreated) is not bool:
        raise TypeError("_destination_precreated must be an exact bool")
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise ValueError("destination must be an absolute pathlib.Path")
    if type(patches) is not tuple or not 1 <= len(patches) <= 2:
        raise ValueError("patches must be an exact tuple containing one or two patches")
    if any(type(patch) is not _ParsedPatch for patch in patches):
        raise TypeError("patches must contain exact parsed patch values")
    _revalidate_source(source, git_executable, RepairStage.MATERIALIZATION)
    _require_destination(destination, source, precreated=_destination_precreated)
    _require_free_space(destination if _destination_precreated else destination.parent, _limits)
    if not _destination_precreated:
        destination_failed = False
        try:
            destination.mkdir(mode=0o700)
            destination.chmod(0o700)
        except OSError:
            destination_failed = True
        if destination_failed:
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)

    try:
        return _materialize_candidate_contents(
            source,
            git_executable,
            destination,
            patches,
            _limits,
        )
    except RepairError:
        _try_harden_candidate_tree(
            destination,
            destination / ".git" / "repoguard-index",
            _candidate_worktree_modes(source.entries),
            require_index=False,
        )
        raise


def _materialize_candidate_contents(
    source: _RepositoryIdentity,
    git_executable: Path,
    destination: Path,
    patches: tuple[_ParsedPatch, ...],
    limits: _GitLimits,
) -> _MaterializedCandidate:
    _initialize_isolated(source, git_executable, destination)
    git_dir = destination / ".git"
    index_file = git_dir / "repoguard-index"
    _copy_exact_objects(source, git_executable, destination)
    _write_private_file(git_dir / "HEAD", f"{source.head_oid}\n".encode("ascii"))
    _write_private_file(git_dir / "shallow", f"{source.head_oid}\n".encode("ascii"))
    isolated_entries, ordinary_bytes, _ = _read_head_entries(
        git_executable,
        destination,
        source.object_format,
        source.head_oid,
        stage=RepairStage.MATERIALIZATION,
        limits=limits,
    )
    if isolated_entries != source.entries or ordinary_bytes != source.ordinary_blob_bytes:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)

    index_environment = {"GIT_INDEX_FILE": str(index_file)}
    _run_required(
        git_executable,
        destination,
        ("read-tree", source.head_oid),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=index_environment,
    )
    _checkout_index(git_executable, destination, index_environment)
    _require_host_limits(destination, limits)

    for patch in patches:
        _validate_patch_preconditions(source.entries, patch)
        _apply_patch(git_executable, destination, index_environment, patch)

    empty_attributes_tree = _write_empty_tree(git_executable, destination)
    diff_environment = {
        **index_environment,
        "GIT_ATTR_SOURCE": empty_attributes_tree,
    }
    canonical_diff = _canonical_diff(
        git_executable,
        destination,
        source.head_oid,
        diff_environment,
    )
    changed_paths, changed_line_count = _read_numstat(
        git_executable,
        destination,
        source.head_oid,
        diff_environment,
        limits,
    )
    tree_oid = _write_tree(git_executable, destination, index_environment, source.object_format)
    commit_oid = _write_commit(
        git_executable,
        destination,
        source,
        tree_oid,
        index_environment,
    )
    _verify_commit(git_executable, destination, source, tree_oid, commit_oid)
    _checkout_index(git_executable, destination, index_environment)
    _require_host_limits(destination, limits)
    _verify_index_tree(
        git_executable,
        destination,
        index_environment,
        source.object_format,
        tree_oid,
    )
    _harden_candidate_tree(
        destination,
        index_file,
        _candidate_worktree_modes(source.entries, changed_paths),
    )
    return _MaterializedCandidate(
        source=source,
        root=destination,
        git_dir=git_dir,
        index_file=index_file,
        canonical_diff=canonical_diff,
        tree_oid=tree_oid,
        commit_oid=commit_oid,
        changed_paths=changed_paths,
        changed_line_count=changed_line_count,
    )


def _open_materialized_candidate(
    source: _RepositoryIdentity,
    git_executable: Path,
    root: Path,
    *,
    canonical_diff: str,
    tree_oid: str,
    commit_oid: str,
    changed_paths: tuple[str, ...],
    changed_line_count: int,
) -> _MaterializedCandidate:
    """Reopen and verify a persisted isolated candidate before application."""
    _require_repository_identity(source)
    _require_git_executable(git_executable)
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("root must be an absolute pathlib.Path")
    if type(canonical_diff) is not str:
        raise TypeError("canonical_diff must be an exact string")
    invalid_candidate = False
    canonical_bytes = b""
    try:
        canonical_bytes = canonical_diff.encode("utf-8")
        _canonical_repository_paths(
            changed_paths,
            "changed_paths",
            minimum=1,
            maximum=_MAX_CHANGED_PATHS,
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        invalid_candidate = True
    if invalid_candidate:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    if (
        not canonical_bytes
        or not canonical_bytes.endswith(b"\n")
        or b"\0" in canonical_bytes
        or type(changed_line_count) is not int
        or not 1 <= changed_line_count <= _MAX_CHANGED_LINES
    ):
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    _require_oid(tree_oid, source.object_format, RepairStage.APPLICATION)
    _require_oid(commit_oid, source.object_format, RepairStage.APPLICATION)
    invalid_root = False
    resolved_root: Path | None = None
    root_stat: os.stat_result | None = None
    try:
        resolved_root = root.resolve(strict=True)
        root_stat = root.stat()
    except (OSError, RuntimeError):
        invalid_root = True
    if invalid_root:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    assert resolved_root is not None and root_stat is not None
    proc_descriptor = _proc_fd_root_descriptor(root)
    proc_identity_mismatch = False
    if proc_descriptor is not None:
        try:
            descriptor_stat = os.fstat(proc_descriptor)
            proc_identity_mismatch = (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
                root_stat.st_dev,
                root_stat.st_ino,
            )
        except OSError:
            proc_identity_mismatch = True
    if (
        (proc_descriptor is None and resolved_root != root)
        or proc_identity_mismatch
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.geteuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    index_file = root / ".git" / "repoguard-index"
    _verify_hardened_candidate_tree(
        root,
        index_file,
        _candidate_worktree_modes(source.entries, changed_paths),
    )
    _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
    discovered_root = _read_git_path(
        git_executable,
        root,
        ("rev-parse", "--path-format=absolute", "--show-toplevel"),
        RepairStage.APPLICATION,
    )
    discovered_git_dir = _read_git_path(
        git_executable,
        root,
        ("rev-parse", "--path-format=absolute", "--git-dir"),
        RepairStage.APPLICATION,
    )
    object_format = _read_ascii_line(
        _run_required(
            git_executable,
            root,
            ("rev-parse", "--show-object-format"),
            stage=RepairStage.APPLICATION,
            failure_code=RepairErrorCode.PUBLICATION_FAILED,
        ).stdout,
        RepairStage.APPLICATION,
    )
    git_dir = root / ".git"
    if (
        discovered_root != resolved_root
        or discovered_git_dir != resolved_root / ".git"
        or object_format != source.object_format
    ):
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    _verify_isolated_controls(source, git_executable, root, git_dir)
    invalid_index = False
    index_stat: os.stat_result | None = None
    try:
        index_stat = index_file.lstat()
    except OSError:
        invalid_index = True
    if invalid_index:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    assert index_stat is not None
    if (
        not stat.S_ISREG(index_stat.st_mode)
        or index_stat.st_uid != os.geteuid()
        or index_stat.st_nlink != 1
        or stat.S_IMODE(index_stat.st_mode) != 0o600
    ):
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    tree_type = _run_required(
        git_executable,
        root,
        ("cat-file", "-t", tree_oid),
        stage=RepairStage.APPLICATION,
        failure_code=RepairErrorCode.PUBLICATION_FAILED,
    )
    if _read_ascii_line(tree_type.stdout, RepairStage.APPLICATION) != "tree":
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    _verify_commit(
        git_executable,
        root,
        source,
        tree_oid,
        commit_oid,
        stage=RepairStage.APPLICATION,
        failure_code=RepairErrorCode.PUBLICATION_FAILED,
    )
    return _MaterializedCandidate(
        source,
        root,
        git_dir,
        index_file,
        canonical_diff,
        tree_oid,
        commit_oid,
        changed_paths,
        changed_line_count,
    )


def _read_materialized_files(
    candidate: _MaterializedCandidate,
    git_executable: Path,
) -> tuple[_MaterializedFile, ...]:
    """Read changed ordinary files from the fixed candidate tree object."""
    if type(candidate) is not _MaterializedCandidate:
        raise TypeError("candidate must be an exact _MaterializedCandidate")
    _require_git_executable(git_executable)
    entries, _, _ = _read_head_entries(
        git_executable,
        candidate.root,
        candidate.source.object_format,
        candidate.tree_oid,
        stage=RepairStage.PATCH,
        limits=_DEFAULT_LIMITS,
    )
    result: list[_MaterializedFile] = []
    for path in candidate.changed_paths:
        entry = _entry_for_path(entries, path)
        if (
            entry is None
            or entry.kind != "blob"
            or entry.mode not in {"100644", "100755"}
            or entry.size is None
        ):
            _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)
        blob = _run_required(
            git_executable,
            candidate.root,
            ("cat-file", "blob", entry.oid),
            stage=RepairStage.PATCH,
            failure_code=RepairErrorCode.MISSING_OBJECT,
            stdout_limit=entry.size + 1,
        ).stdout
        if len(blob) != entry.size:
            _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.PATCH)
        result.append(_MaterializedFile(path, blob, entry.mode == "100755"))
    return tuple(result)


def _read_candidate_tree_files(
    candidate: _MaterializedCandidate,
    git_executable: Path,
) -> tuple[_MaterializedFile, ...]:
    """Read every ordinary blob from the fixed candidate tree for recovery."""
    if type(candidate) is not _MaterializedCandidate:
        raise TypeError("candidate must be an exact _MaterializedCandidate")
    _require_git_executable(git_executable)
    entries, _, _ = _read_head_entries(
        git_executable,
        candidate.root,
        candidate.source.object_format,
        candidate.tree_oid,
        stage=RepairStage.RECOVERY,
        limits=_DEFAULT_LIMITS,
    )
    result: list[_MaterializedFile] = []
    for entry in entries:
        if entry.kind == "tree" and entry.mode == "040000":
            continue
        if entry.kind != "blob" or entry.mode not in {"100644", "100755"} or entry.size is None:
            _raise(RepairErrorCode.RECOVERY_FAILED, RepairStage.RECOVERY)
        blob = _run_required(
            git_executable,
            candidate.root,
            ("cat-file", "blob", entry.oid),
            stage=RepairStage.RECOVERY,
            failure_code=RepairErrorCode.MISSING_OBJECT,
            stdout_limit=entry.size + 1,
        ).stdout
        if len(blob) != entry.size:
            _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.RECOVERY)
        result.append(_MaterializedFile(entry.path, blob, entry.mode == "100755"))
    return tuple(result)


def _export_candidate_projection(
    candidate: _MaterializedCandidate,
    git_executable: Path,
    destination: Path,
    *,
    _destination_precreated: bool = False,
) -> tuple[_MaterializedFile, ...]:
    """Export every ordinary fixed-tree blob to a no-.git sandbox projection."""
    if type(candidate) is not _MaterializedCandidate:
        raise TypeError("candidate must be an exact _MaterializedCandidate")
    _require_git_executable(git_executable)
    if type(_destination_precreated) is not bool:
        raise TypeError("_destination_precreated must be an exact bool")
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise ValueError("candidate projection destination is invalid")
    invalid_destination = False
    candidate_parent: Path | None = None
    resolved_destination: Path | None = None
    try:
        candidate_parent = candidate.root.resolve(strict=True).parent
        resolved_destination = destination.resolve(strict=_destination_precreated)
    except (OSError, RuntimeError):
        invalid_destination = True
    if (
        invalid_destination
        or candidate_parent is None
        or resolved_destination is None
        or resolved_destination.parent != candidate_parent
        or (resolved_destination.name if _destination_precreated else destination.name)
        != "candidate-input"
    ):
        raise ValueError("candidate projection destination is invalid")
    destination_exists = False
    destination_check_failed = False
    if _destination_precreated:
        try:
            metadata = destination.stat()
            destination_exists = True
            destination_check_failed = (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or bool(os.listdir(destination))
            )
        except OSError:
            destination_check_failed = True
    else:
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            destination_check_failed = True
        else:
            destination_exists = True
    if destination_check_failed or (not _destination_precreated and destination_exists):
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)

    entries, _, _ = _read_head_entries(
        git_executable,
        candidate.root,
        candidate.source.object_format,
        candidate.tree_oid,
        stage=RepairStage.MATERIALIZATION,
        limits=_DEFAULT_LIMITS,
    )
    if not _destination_precreated:
        destination_create_failed = False
        try:
            destination.mkdir(mode=0o700)
            destination.chmod(0o700)
        except OSError:
            destination_create_failed = True
        if destination_create_failed:
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    root_fd = -1
    result: list[_MaterializedFile] = []
    projection_failed = False
    try:
        root_fd = _open_owned_directory_path(destination)
        for entry in entries:
            if entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
                continue
            if entry.size is None:
                _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.MATERIALIZATION)
            blob = _run_required(
                git_executable,
                candidate.root,
                ("cat-file", "blob", entry.oid),
                stage=RepairStage.MATERIALIZATION,
                failure_code=RepairErrorCode.MISSING_OBJECT,
                stdout_limit=entry.size + 1,
            ).stdout
            if len(blob) != entry.size:
                _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.MATERIALIZATION)
            executable = entry.mode == "100755"
            _write_projection_blob(root_fd, entry.path, blob, executable=executable)
            result.append(_MaterializedFile(entry.path, blob, executable))
        os.fsync(root_fd)
        _require_host_limits_for_roots(
            (candidate.root, destination),
            _DEFAULT_LIMITS,
        )
    except RepairError:
        if root_fd >= 0:
            os.close(root_fd)
            root_fd = -1
        _remove_candidate_projection(destination)
        raise
    except OSError:
        if root_fd >= 0:
            os.close(root_fd)
            root_fd = -1
        _remove_candidate_projection(destination)
        projection_failed = True
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    if projection_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    return tuple(result)


def _write_projection_blob(
    root_fd: int,
    path: str,
    content: bytes,
    *,
    executable: bool,
) -> None:
    components = path.split("/")
    current_fd = root_fd
    opened: list[int] = []
    file_fd = -1
    failed = False
    try:
        for component in components[:-1]:
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
                os.fsync(current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            details = os.fstat(next_fd)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o700
            ):
                raise OSError
            opened.append(next_fd)
            current_fd = next_fd
        file_fd = os.open(
            components[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o500 if executable else 0o400,
            dir_fd=current_fd,
        )
        view = memoryview(content)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_fd, 0o500 if executable else 0o400)
        os.fsync(file_fd)
        os.fsync(current_fd)
    except OSError:
        failed = True
    finally:
        if file_fd >= 0:
            with suppress(OSError):
                os.close(file_fd)
        for descriptor in reversed(opened):
            with suppress(OSError):
                os.close(descriptor)
    if failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _remove_candidate_projection(destination: Path) -> None:
    try:
        metadata = destination.lstat()
        if (
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
        ):
            shutil.rmtree(destination)
    except OSError:
        return


def _read_repair_ref(
    source: _RepositoryIdentity,
    git_executable: Path,
    candidate_id: str,
    *,
    expected_commit_oid: str | None = None,
) -> str | None:
    """Read the dedicated ref without resolving symbolic or replacement objects."""
    _require_repository_identity(source)
    _require_git_executable(git_executable)
    if expected_commit_oid is not None:
        _require_oid(expected_commit_oid, source.object_format, RepairStage.APPLICATION)
    _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
    with _pinned_common_dir(source) as (common_dir, common_fd):
        result = _read_repair_ref_at(
            source,
            git_executable,
            candidate_id,
            common_dir,
            common_fd,
            expected_commit_oid=expected_commit_oid,
        )
        _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
    return result


def _read_repair_ref_at(
    source: _RepositoryIdentity,
    git_executable: Path,
    candidate_id: str,
    common_dir: Path,
    common_fd: int,
    *,
    expected_commit_oid: str | None,
    pinned_namespace_fd: int | None = None,
) -> str | None:
    ref = _repair_ref(candidate_id)
    _require_files_ref_storage(
        git_executable,
        git_dir=common_dir,
        inherited_fds=(common_fd,),
    )
    if pinned_namespace_fd is not None and (
        type(pinned_namespace_fd) is not int or pinned_namespace_fd < 0
    ):
        raise TypeError("pinned_namespace_fd must be an open directory descriptor")
    opened: list[int] = []
    directories: list[tuple[int, str, int]] = []
    files: list[tuple[int, str, int, tuple[int, int, int, int, int], int | None]] = []
    absent: list[tuple[int, str]] = []
    current: str | None = None
    failed = False
    try:
        _require_named_entry_absent(common_fd, "packed-refs.lock")
        absent.append((common_fd, "packed-refs.lock"))

        packed_oid: str | None = None
        try:
            packed_fd = os.open(
                "packed-refs",
                os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=common_fd,
            )
        except FileNotFoundError:
            absent.append((common_fd, "packed-refs"))
        else:
            opened.append(packed_fd)
            packed_snapshot = _ref_file_snapshot(packed_fd, maximum=None)
            files.append((common_fd, "packed-refs", packed_fd, packed_snapshot, None))
            _require_named_ref_file(
                common_fd,
                "packed-refs",
                packed_fd,
                packed_snapshot,
                maximum=None,
            )
            packed_oid = _read_packed_repair_ref(
                packed_fd,
                ref,
                source.object_format,
                expected_size=packed_snapshot[2],
            )
            _require_named_ref_file(
                common_fd,
                "packed-refs",
                packed_fd,
                packed_snapshot,
                maximum=None,
            )

        if pinned_namespace_fd is None:
            namespace_fd = os.dup(common_fd)
            opened.append(namespace_fd)
            namespace_complete = True
            for component in ("refs", "repoguard", "repairs"):
                try:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=namespace_fd,
                    )
                except FileNotFoundError:
                    absent.append((namespace_fd, component))
                    namespace_complete = False
                    break
                opened.append(next_fd)
                directories.append((namespace_fd, component, next_fd))
                _require_named_ref_directory(namespace_fd, component, next_fd)
                namespace_fd = next_fd
        else:
            namespace_fd = pinned_namespace_fd
            namespace_metadata = os.fstat(namespace_fd)
            if (
                not stat.S_ISDIR(namespace_metadata.st_mode)
                or namespace_metadata.st_uid != os.geteuid()
            ):
                raise ValueError("pinned repair namespace is invalid")
            namespace_complete = True

        loose_oid: str | None = None
        loose_present = False
        if namespace_complete:
            _require_named_entry_absent(namespace_fd, f"{candidate_id}.lock")
            absent.append((namespace_fd, f"{candidate_id}.lock"))
            try:
                loose_fd = os.open(
                    candidate_id,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=namespace_fd,
                )
            except FileNotFoundError:
                absent.append((namespace_fd, candidate_id))
            else:
                opened.append(loose_fd)
                loose_snapshot = _ref_file_snapshot(loose_fd, maximum=_LOOSE_REF_BYTES)
                files.append(
                    (namespace_fd, candidate_id, loose_fd, loose_snapshot, _LOOSE_REF_BYTES)
                )
                _require_named_ref_file(
                    namespace_fd,
                    candidate_id,
                    loose_fd,
                    loose_snapshot,
                    maximum=_LOOSE_REF_BYTES,
                )
                loose_payload = _read_ref_file(loose_fd, maximum=_LOOSE_REF_BYTES)
                _require_named_ref_file(
                    namespace_fd,
                    candidate_id,
                    loose_fd,
                    loose_snapshot,
                    maximum=_LOOSE_REF_BYTES,
                )
                loose_oid = _parse_loose_repair_ref(loose_payload, source.object_format)
                loose_present = True

        current = loose_oid if loose_present else packed_oid
        _require_repair_reflog_absent(source, candidate_id, common_fd=common_fd)
        if current is not None and current == expected_commit_oid:
            _require_source_commit(
                source,
                git_executable,
                current,
                git_dir=common_dir,
                inherited_fds=(common_fd,),
            )
        _require_repair_reflog_absent(source, candidate_id, common_fd=common_fd)
        for parent_fd, name, descriptor, snapshot, maximum in files:
            _require_named_ref_file(
                parent_fd,
                name,
                descriptor,
                snapshot,
                maximum=maximum,
            )
        for parent_fd, name, descriptor in reversed(directories):
            _require_named_ref_directory(parent_fd, name, descriptor)
        for parent_fd, name in absent:
            _require_named_entry_absent(parent_fd, name)
    except RepairError:
        raise
    except (OSError, TypeError, ValueError):
        failed = True
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                failed = True
    if failed:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    return current


def _publish_repair_ref(
    source: _RepositoryIdentity,
    candidate: _MaterializedCandidate,
    git_executable: Path,
    candidate_id: str,
    *,
    inherited_lock_fd: int | None = None,
) -> _PublicationResult:
    """Publish exactly one candidate commit under an absent-only dedicated ref."""
    inherited_fds = _inherited_lock_fds(inherited_lock_fd)
    _require_repository_identity(source)
    if type(candidate) is not _MaterializedCandidate or candidate.source != source:
        raise TypeError("candidate does not belong to the exact source identity")
    _require_git_executable(git_executable)
    ref = _repair_ref(candidate_id)
    _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
    _verify_commit(
        git_executable,
        candidate.root,
        source,
        candidate.tree_oid,
        candidate.commit_oid,
        stage=RepairStage.APPLICATION,
        failure_code=RepairErrorCode.PUBLICATION_FAILED,
    )
    with _pinned_common_dir(source) as (common_dir, common_fd):
        current = _read_repair_ref_at(
            source,
            git_executable,
            candidate_id,
            common_dir,
            common_fd,
            expected_commit_oid=candidate.commit_oid,
        )
        if current == candidate.commit_oid:
            _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
            return _PublicationResult(
                _PublicationOutcome.ALREADY_PRESENT,
                ref,
                candidate.commit_oid,
            )
        if current is not None:
            _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
            _raise(RepairErrorCode.REF_CONFLICT, RepairStage.APPLICATION)

        _reject_proc_receive_config(
            source,
            git_executable,
            git_dir=common_dir,
            inherited_fds=(common_fd,),
        )
        with _pinned_repair_ref_namespace(
            source,
            candidate_id,
            common_fd=common_fd,
        ) as namespace_fd:
            zero_oid = "0" * _OBJECT_FORMAT_LENGTHS[source.object_format]
            result = _invoke_git(
                git_executable,
                candidate.root,
                (
                    "push",
                    "--porcelain",
                    "--no-progress",
                    "--no-thin",
                    "--no-verify",
                    f"--receive-pack={_receive_pack_command(git_executable)}",
                    f"--force-with-lease={ref}:{zero_oid}",
                    "--",
                    str(common_dir),
                    f"{candidate.commit_oid}:{ref}",
                ),
                stage=RepairStage.APPLICATION,
                timeout_seconds=_PACK_TIMEOUT_SECONDS,
                stdout_limit=_CONTROL_OUTPUT_BYTES,
                stderr_limit=_CONTROL_OUTPUT_BYTES,
                inherited_fds=tuple(dict.fromkeys((*inherited_fds, common_fd))),
            )
            read_back = _read_repair_ref_at(
                source,
                git_executable,
                candidate_id,
                common_dir,
                common_fd,
                expected_commit_oid=candidate.commit_oid,
                pinned_namespace_fd=namespace_fd,
            )
            _revalidate_source(source, git_executable, RepairStage.APPLICATION, traverse=False)
    if read_back == candidate.commit_oid:
        outcome = (
            _PublicationOutcome.PUBLISHED
            if result.returncode == 0
            else _PublicationOutcome.ALREADY_PRESENT
        )
        return _PublicationResult(outcome, ref, candidate.commit_oid)
    if read_back is not None:
        _raise(RepairErrorCode.REF_CONFLICT, RepairStage.APPLICATION)
    _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _receive_pack_command(git_executable: Path) -> str:
    arguments = [str(git_executable), "--literal-pathspecs"]
    for key, value in _FIXED_CONFIG:
        arguments.extend(("-c", f"{key}={value}"))
    arguments.append("receive-pack")
    return shlex.join(arguments)


def _require_files_ref_storage(
    git_executable: Path,
    *,
    git_dir: Path,
    inherited_fds: tuple[int, ...],
) -> None:
    result = _invoke_git(
        git_executable,
        None,
        (
            f"--git-dir={git_dir}",
            "config",
            "--get-all",
            "--null",
            "extensions.refStorage",
        ),
        stage=RepairStage.APPLICATION,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
        stderr_limit=_CONTROL_OUTPUT_BYTES,
        inherited_fds=inherited_fds,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return
    _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _reject_proc_receive_config(
    source: _RepositoryIdentity,
    git_executable: Path,
    *,
    git_dir: Path | None = None,
    inherited_fds: tuple[int, ...] = (),
) -> None:
    root = source.root if git_dir is None else None
    for key in (
        "receive.procReceiveRefs",
        "receive.fsck.skipList",
        "fsck.skipList",
    ):
        arguments = (
            ("config", "--get-all", "--null", key)
            if git_dir is None
            else (
                f"--git-dir={git_dir}",
                "config",
                "--get-all",
                "--null",
                key,
            )
        )
        result = _invoke_git(
            git_executable,
            root,
            arguments,
            stage=RepairStage.APPLICATION,
            stdout_limit=_CONTROL_OUTPUT_BYTES,
            stderr_limit=_CONTROL_OUTPUT_BYTES,
            inherited_fds=inherited_fds,
        )
        if result.returncode not in {0, 1} or result.stdout or result.stderr:
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _repair_ref(candidate_id: str) -> str:
    if type(candidate_id) is not str or _CANDIDATE_ID_PATTERN.fullmatch(candidate_id) is None:
        raise ValueError("candidate_id must be 64 lowercase hexadecimal characters")
    return f"refs/repoguard/repairs/{candidate_id}"


def _require_source_commit(
    source: _RepositoryIdentity,
    git_executable: Path,
    commit_oid: str,
    *,
    git_dir: Path | None = None,
    inherited_fds: tuple[int, ...] = (),
) -> None:
    _require_oid(commit_oid, source.object_format, RepairStage.APPLICATION)
    root = source.root if git_dir is None else None
    arguments = (
        ("cat-file", "-t", commit_oid)
        if git_dir is None
        else (f"--git-dir={git_dir}", "cat-file", "-t", commit_oid)
    )
    result = _invoke_git(
        git_executable,
        root,
        arguments,
        stage=RepairStage.APPLICATION,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
        stderr_limit=_CONTROL_OUTPUT_BYTES,
        inherited_fds=inherited_fds,
    )
    if result.returncode != 0 or result.stdout != b"commit\n" or result.stderr:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _require_repair_reflog_absent(
    source: _RepositoryIdentity,
    candidate_id: str,
    *,
    common_fd: int,
) -> None:
    _require_repository_identity(source)
    _repair_ref(candidate_id)
    if type(common_fd) is not int or common_fd < 0:
        raise TypeError("common_fd must be an open directory descriptor")
    opened: list[int] = []
    directories: list[tuple[int, str, int]] = []
    absent: list[tuple[int, str]] = []
    namespace_complete = True
    failed = False
    try:
        current_fd = os.dup(common_fd)
        opened.append(current_fd)
        for component in ("logs", "refs", "repoguard", "repairs"):
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                absent.append((current_fd, component))
                namespace_complete = False
                break
            opened.append(next_fd)
            directories.append((current_fd, component, next_fd))
            _require_named_ref_directory(current_fd, component, next_fd)
            current_fd = next_fd
        if namespace_complete:
            _require_named_entry_absent(current_fd, f"{candidate_id}.lock")
            absent.append((current_fd, f"{candidate_id}.lock"))
            try:
                os.stat(candidate_id, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                absent.append((current_fd, candidate_id))
            else:
                failed = True
        for parent_fd, name, descriptor in reversed(directories):
            _require_named_ref_directory(parent_fd, name, descriptor)
        for parent_fd, name in absent:
            _require_named_entry_absent(parent_fd, name)
    except (OSError, TypeError, ValueError):
        failed = True
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                failed = True
    if failed:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _parse_packed_repair_ref(payload: bytes, ref: str, object_format: str) -> str | None:
    """Return the exact direct target entry from complete packed-refs bytes."""
    if type(payload) is not bytes:
        raise ValueError("packed refs input is invalid")
    result, total = _scan_packed_repair_ref((payload,), ref, object_format)
    if total != len(payload):
        raise ValueError("packed refs input is invalid")
    return result


def _read_packed_repair_ref(
    descriptor: int,
    ref: str,
    object_format: str,
    *,
    expected_size: int,
) -> str | None:
    os.lseek(descriptor, 0, os.SEEK_SET)

    def chunks() -> Iterator[bytes]:
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk

    result, total = _scan_packed_repair_ref(chunks(), ref, object_format)
    if total != expected_size:
        raise ValueError("packed refs size changed while reading")
    return result


def _scan_packed_repair_ref(
    chunks: Iterable[bytes],
    ref: str,
    object_format: str,
) -> tuple[str | None, int]:
    """Select the exact target while retaining only its bounded record state."""
    expected_length = _OBJECT_FORMAT_LENGTHS.get(object_format)
    if type(ref) is not str or expected_length is None:
        raise ValueError("packed refs input is invalid")
    try:
        target = ref.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("packed ref target is invalid") from None
    if not target.startswith(b"refs/"):
        raise ValueError("packed refs input is invalid")

    found: str | None = None
    total = 0
    first_byte: int | None = None
    raw_oid = bytearray()
    raw_peeled_oid = bytearray()
    separator_seen = False
    raw_ref_matches = False
    raw_ref_length = 0
    raw_ref_valid = True
    raw_ref_previous: int | None = None
    raw_component_suffix = bytearray()
    previous_line_was_direct = False
    line_number = 0
    raw_header_prefix = bytearray()
    comment_valid = True
    ended_at_newline = True

    def finish_line() -> None:
        nonlocal found
        nonlocal first_byte
        nonlocal raw_oid
        nonlocal raw_peeled_oid
        nonlocal separator_seen
        nonlocal raw_ref_matches
        nonlocal raw_ref_length
        nonlocal raw_ref_valid
        nonlocal raw_ref_previous
        nonlocal raw_component_suffix
        nonlocal previous_line_was_direct
        nonlocal line_number
        nonlocal raw_header_prefix
        nonlocal comment_valid
        if first_byte is None:
            raise ValueError("packed refs input is invalid")
        elif first_byte == ord("#"):
            if (
                line_number != 0
                or not comment_valid
                or bytes(raw_header_prefix) != _PACKED_REFS_HEADER
            ):
                raise ValueError("packed refs input is invalid")
            previous_line_was_direct = False
        elif first_byte == ord("^"):
            if not previous_line_was_direct:
                raise ValueError("packed refs input is invalid")
            _parse_packed_oid(bytes(raw_peeled_oid), expected_length)
            previous_line_was_direct = False
        else:
            oid = _parse_packed_oid(bytes(raw_oid), expected_length)
            if (
                not separator_seen
                or raw_ref_length == 0
                or not raw_ref_valid
                or raw_ref_previous in {ord("/"), ord(".")}
                or raw_component_suffix.endswith(b".lock")
                or (raw_ref_length == 1 and raw_ref_previous == ord("@"))
            ):
                raise ValueError("packed refs input is invalid")
            previous_line_was_direct = True
            if raw_ref_matches and raw_ref_length == len(target):
                if found is not None:
                    raise ValueError("packed repair ref is duplicated")
                found = oid
        first_byte = None
        raw_oid = bytearray()
        raw_peeled_oid = bytearray()
        separator_seen = False
        raw_ref_matches = False
        raw_ref_length = 0
        raw_ref_valid = True
        raw_ref_previous = None
        raw_component_suffix = bytearray()
        raw_header_prefix = bytearray()
        comment_valid = True
        line_number += 1

    def consume_ref_byte(byte: int) -> None:
        nonlocal raw_ref_matches
        nonlocal raw_ref_length
        nonlocal raw_ref_valid
        nonlocal raw_ref_previous
        if raw_ref_length >= len(target) or byte != target[raw_ref_length]:
            raw_ref_matches = False
        if (
            byte < 0x20
            or byte == 0x7F
            or byte in _PACKED_REF_FORBIDDEN
            or (raw_ref_previous == ord(".") and byte == ord("."))
            or (raw_ref_previous == ord("@") and byte == ord("{"))
        ):
            raw_ref_valid = False
        if byte == ord("/"):
            if raw_ref_length == 0 or raw_ref_previous == ord("/"):
                raw_ref_valid = False
            if raw_component_suffix.endswith(b".lock"):
                raw_ref_valid = False
            raw_component_suffix.clear()
        else:
            if not raw_component_suffix and byte == ord("."):
                raw_ref_valid = False
            raw_component_suffix.append(byte)
            if len(raw_component_suffix) > len(b".lock"):
                del raw_component_suffix[0]
        raw_ref_previous = byte
        raw_ref_length += 1

    def consume_oid_byte(raw: bytearray, byte: int) -> None:
        if len(raw) <= expected_length:
            raw.append(byte)

    for chunk in chunks:
        if type(chunk) is not bytes:
            raise ValueError("packed refs input is invalid")
        total += len(chunk)
        for byte in chunk:
            if byte == ord("\n"):
                finish_line()
                ended_at_newline = True
                continue
            ended_at_newline = False
            if first_byte is None:
                first_byte = byte
                if byte == ord("#"):
                    raw_header_prefix.append(byte)
                    continue
                if byte == ord("^"):
                    continue
            if first_byte == ord("#"):
                if len(raw_header_prefix) < len(_PACKED_REFS_HEADER):
                    raw_header_prefix.append(byte)
                if byte == 0:
                    comment_valid = False
                continue
            if first_byte == ord("^"):
                consume_oid_byte(raw_peeled_oid, byte)
                continue
            if not separator_seen:
                if byte in _PACKED_REF_SEPARATORS:
                    separator_seen = True
                    raw_ref_matches = True
                else:
                    consume_oid_byte(raw_oid, byte)
                continue
            consume_ref_byte(byte)

    if not ended_at_newline:
        raise ValueError("packed refs input is invalid")
    return found, total


def _parse_packed_oid(raw: bytes, expected_length: int) -> str:
    if type(raw) is not bytes or len(raw) != expected_length:
        raise ValueError("packed object ID is invalid")
    try:
        oid = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("packed object ID is invalid") from None
    normalized = oid.lower()
    if _OID_PATTERN.fullmatch(normalized) is None or set(normalized) == {"0"}:
        raise ValueError("packed object ID is invalid")
    return normalized


def _parse_loose_repair_ref(payload: bytes, object_format: str) -> str:
    expected_length = _OBJECT_FORMAT_LENGTHS.get(object_format)
    if type(payload) is not bytes or expected_length is None or len(payload) != expected_length + 1:
        raise ValueError("loose repair ref is invalid")
    if not payload.endswith(b"\n"):
        raise ValueError("loose repair ref is invalid")
    return _parse_stored_oid(payload[:-1], expected_length)


def _parse_stored_oid(raw: bytes, expected_length: int) -> str:
    if type(raw) is not bytes or len(raw) != expected_length:
        raise ValueError("stored object ID is invalid")
    try:
        oid = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("stored object ID is invalid") from None
    normalized = oid.lower()
    if _OID_PATTERN.fullmatch(normalized) is None or set(normalized) == {"0"}:
        raise ValueError("stored object ID is invalid")
    return normalized


def _read_ref_file(descriptor: int, *, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    expected_size = os.fstat(descriptor).st_size
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > maximum or len(payload) != expected_size:
        raise ValueError("ref storage exceeds its bound")
    return payload


def _ref_file_snapshot(
    descriptor: int,
    *,
    maximum: int | None,
) -> tuple[int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or (maximum is not None and metadata.st_size > maximum)
    ):
        raise ValueError("ref storage metadata is invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_named_ref_file(
    parent_fd: int,
    name: str,
    descriptor: int,
    expected: tuple[int, int, int, int, int],
    *,
    maximum: int | None,
) -> None:
    current = _ref_file_snapshot(descriptor, maximum=maximum)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        current != expected
        or not stat.S_ISREG(named.st_mode)
        or named.st_uid != os.geteuid()
        or named.st_nlink != 1
        or (named.st_dev, named.st_ino) != expected[:2]
        or named.st_size != expected[2]
        or named.st_mtime_ns != expected[3]
        or named.st_ctime_ns != expected[4]
    ):
        raise ValueError("named ref storage changed")


def _require_named_ref_directory(parent_fd: int, name: str, descriptor: int) -> None:
    current = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(current.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or current.st_uid != os.geteuid()
        or named.st_uid != os.geteuid()
        or (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ValueError("named ref directory changed")


def _require_named_entry_absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("unexpected ref storage entry")


@contextmanager
def _pinned_repair_ref_namespace(
    source: _RepositoryIdentity,
    candidate_id: str,
    *,
    common_fd: int,
) -> Iterator[int]:
    """Keep the exact loose repair namespace pinned across receive-pack and read-back."""
    _require_repository_identity(source)
    _repair_ref(candidate_id)
    if type(common_fd) is not int or common_fd < 0:
        raise TypeError("repair ref namespace arguments are invalid")
    current_fd = -1
    opened: list[int] = []
    directories: list[tuple[int, str, int]] = []
    failed = False
    try:
        current_fd = os.dup(common_fd)
        opened.append(current_fd)
        for component in ("refs", "repoguard", "repairs"):
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            opened.append(next_fd)
            directories.append((current_fd, component, next_fd))
            _require_named_ref_directory(current_fd, component, next_fd)
            current_fd = next_fd
        _require_named_entry_absent(current_fd, f"{candidate_id}.lock")
        try:
            leaf = os.stat(candidate_id, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(leaf.st_mode) or leaf.st_uid != os.geteuid() or leaf.st_nlink != 1:
                raise ValueError("repair ref leaf is invalid")
    except (OSError, TypeError, ValueError):
        failed = True
    if failed or not opened:
        for descriptor in reversed(opened):
            with suppress(OSError):
                os.close(descriptor)
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    body_failed = False
    try:
        yield current_fd
    except BaseException:
        body_failed = True
        raise
    finally:
        close_failed = False
        if not body_failed:
            try:
                for parent_fd, name, descriptor in reversed(directories):
                    _require_named_ref_directory(parent_fd, name, descriptor)
                _require_named_entry_absent(current_fd, f"{candidate_id}.lock")
            except (OSError, TypeError, ValueError):
                close_failed = True
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                close_failed = True
        if close_failed and not body_failed:
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


@contextmanager
def _pinned_common_dir(source: _RepositoryIdentity) -> Iterator[tuple[Path, int]]:
    descriptor = -1
    path: Path | None = None
    failed = False
    try:
        descriptor = os.open(
            source.common_dir,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        path = Path("/proc/self/fd") / str(descriptor)
        path_metadata = path.stat()
        failed = (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or (metadata.st_dev, metadata.st_ino)
            != (source.common_dir_device, source.common_dir_inode)
            or (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino)
        )
    except OSError:
        failed = True
    if failed or descriptor < 0 or path is None:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    body_failed = False
    try:
        yield path, descriptor
    except BaseException:
        body_failed = True
        raise
    finally:
        close_failed = False
        try:
            os.close(descriptor)
        except OSError:
            close_failed = True
        if close_failed and not body_failed:
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _read_head_entries(
    git_executable: Path,
    root: Path,
    object_format: str,
    head_oid: str,
    *,
    stage: RepairStage,
    limits: _GitLimits,
) -> tuple[tuple[_HeadEntry, ...], int, tuple[str, ...]]:
    tree_result = _run_required(
        git_executable,
        root,
        ("rev-parse", f"{head_oid}^{{tree}}"),
        stage=stage,
        failure_code=RepairErrorCode.MISSING_OBJECT,
    )
    root_tree_oid = _parse_oid_line(tree_result.stdout, object_format, stage)
    result = _run_required(
        git_executable,
        root,
        ("ls-tree", "-r", "-t", "-z", "--full-tree", "--long", head_oid),
        stage=stage,
        failure_code=RepairErrorCode.MISSING_OBJECT,
        stdout_limit=_TREE_OUTPUT_BYTES,
        timeout_seconds=_PACK_TIMEOUT_SECONDS,
    )
    records = result.stdout.split(b"\0")
    if not records or records[-1] != b"":
        _raise(RepairErrorCode.GIT_FAILED, stage)
    entries: list[_HeadEntry] = []
    ordinary_blob_bytes = 0
    for raw_record in records[:-1]:
        if len(entries) >= limits.max_head_entries:
            _raise(RepairErrorCode.RESOURCE_LIMIT, stage)
        metadata, separator, raw_path = raw_record.partition(b"\t")
        parts = metadata.split()
        if not separator or len(parts) != 4:
            _raise(RepairErrorCode.GIT_FAILED, stage)
        raw_mode, raw_kind, raw_oid, raw_size = parts
        invalid_encoding = False
        mode = kind = oid = path = ""
        try:
            mode = raw_mode.decode("ascii")
            kind = raw_kind.decode("ascii")
            oid = raw_oid.decode("ascii")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            invalid_encoding = True
        if invalid_encoding:
            _raise(RepairErrorCode.INVALID_PATH, stage)
        _require_oid(oid, object_format, stage)
        invalid_path = False
        try:
            _validate_repository_path(path)
        except (TypeError, ValueError):
            invalid_path = True
        if invalid_path:
            _raise(RepairErrorCode.INVALID_PATH, stage)
        size = _parse_tree_entry(mode, kind, raw_size, stage)
        if size is not None and size > limits.max_blob_bytes:
            _raise(RepairErrorCode.RESOURCE_LIMIT, stage)
        if mode in {"100644", "100755"}:
            if size is None:
                _raise(RepairErrorCode.MISSING_OBJECT, stage)
            ordinary_blob_bytes += size
            if ordinary_blob_bytes > limits.max_head_blob_bytes:
                _raise(RepairErrorCode.RESOURCE_LIMIT, stage)
        entries.append(_HeadEntry(mode, kind, oid, size, path))
    sorted_entries = tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8")))
    if len({entry.path for entry in sorted_entries}) != len(sorted_entries):
        _raise(RepairErrorCode.GIT_FAILED, stage)
    object_oids = (
        root_tree_oid,
        *(entry.oid for entry in sorted_entries if entry.kind != "commit"),
    )
    return sorted_entries, ordinary_blob_bytes, tuple(dict.fromkeys(object_oids))


def _parse_tree_entry(mode: str, kind: str, raw_size: bytes, stage: RepairStage) -> int | None:
    allowed = {
        ("040000", "tree"),
        ("100644", "blob"),
        ("100755", "blob"),
        ("120000", "blob"),
        ("160000", "commit"),
    }
    if (mode, kind) not in allowed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, stage)
    if kind in {"tree", "commit"}:
        if raw_size != b"-":
            _raise(RepairErrorCode.GIT_FAILED, stage)
        return None
    if not raw_size.isdigit():
        _raise(RepairErrorCode.MISSING_OBJECT, stage)
    invalid_size = False
    size = 0
    try:
        size = int(raw_size)
    except ValueError:
        invalid_size = True
    if invalid_size:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    return size


def _initialize_isolated(
    source: _RepositoryIdentity,
    git_executable: Path,
    destination: Path,
) -> None:
    result = _invoke_git(
        git_executable,
        destination,
        (
            "init",
            "--quiet",
            f"--object-format={source.object_format}",
            "--initial-branch=repoguard",
        ),
        stage=RepairStage.MATERIALIZATION,
    )
    if result.returncode != 0:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    git_dir = destination / ".git"
    initialization_failed = False
    try:
        git_dir.chmod(0o700)
        hooks = git_dir / "hooks"
        if hooks.exists():
            shutil.rmtree(hooks)
        hooks.mkdir(mode=0o700)
        _write_private_file(git_dir / "config", _isolated_config(source.object_format))
        for forbidden in (
            git_dir / "objects" / "info" / "alternates",
            git_dir / "info" / "grafts",
        ):
            if forbidden.exists() or forbidden.is_symlink():
                forbidden.unlink()
        replace_root = git_dir / "refs" / "replace"
        if replace_root.exists():
            shutil.rmtree(replace_root)
    except OSError:
        initialization_failed = True
    if initialization_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _isolated_config(object_format: str) -> bytes:
    return (
        b"[core]\n"
        + (
            b"\trepositoryformatversion = 1\n"
            if object_format == "sha256"
            else b"\trepositoryformatversion = 0\n"
        )
        + b"\tfilemode = true\n"
        + b"\tbare = false\n"
        + b"\tlogallrefupdates = false\n"
        + (b"[extensions]\n\tobjectformat = sha256\n" if object_format == "sha256" else b"")
    )


def _verify_isolated_controls(
    source: _RepositoryIdentity,
    git_executable: Path,
    root: Path,
    git_dir: Path,
) -> None:
    control_read_failed = False
    try:
        if (git_dir / "config").read_bytes() != _isolated_config(source.object_format):
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
        if (git_dir / "HEAD").read_bytes() != f"{source.head_oid}\n".encode("ascii"):
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
        if (git_dir / "shallow").read_bytes() != f"{source.head_oid}\n".encode("ascii"):
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
        hooks = git_dir / "hooks"
        if not hooks.is_dir() or any(hooks.iterdir()):
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
        if any(
            path.exists() or path.is_symlink()
            for path in (
                git_dir / "objects" / "info" / "alternates",
                git_dir / "info" / "grafts",
                git_dir / "refs" / "replace",
            )
        ):
            _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    except OSError:
        control_read_failed = True
    if control_read_failed:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)
    remotes = _run_required(
        git_executable,
        root,
        ("remote",),
        stage=RepairStage.APPLICATION,
        failure_code=RepairErrorCode.PUBLICATION_FAILED,
    )
    if remotes.stdout:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _copy_exact_objects(
    source: _RepositoryIdentity,
    git_executable: Path,
    destination: Path,
) -> None:
    pack_base = destination / ".git" / "objects" / "pack" / "repoguard"
    object_input = "".join(f"{oid}\n" for oid in source.object_oids).encode("ascii")
    result = _invoke_git(
        git_executable,
        source.root,
        (
            "pack-objects",
            "--compression=1",
            "--window=0",
            "--no-reuse-delta",
            "--no-reuse-object",
            str(pack_base),
        ),
        stage=RepairStage.MATERIALIZATION,
        input_bytes=object_input,
        timeout_seconds=_PACK_TIMEOUT_SECONDS,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
        stderr_limit=_CONTROL_OUTPUT_BYTES,
    )
    if result.returncode != 0:
        _raise(RepairErrorCode.MISSING_OBJECT, RepairStage.MATERIALIZATION)
    pack_hash = _read_ascii_line(result.stdout, RepairStage.MATERIALIZATION)
    expected_length = _OBJECT_FORMAT_LENGTHS[source.object_format]
    if len(pack_hash) != expected_length or _OID_PATTERN.fullmatch(pack_hash) is None:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    pack_directory = pack_base.parent
    expected_pack = pack_directory / f"repoguard-{pack_hash}.pack"
    expected_index = pack_directory / f"repoguard-{pack_hash}.idx"
    pack_metadata_failed = False
    try:
        if not expected_pack.is_file() or not expected_index.is_file():
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
        expected_pack.chmod(0o600)
        expected_index.chmod(0o600)
    except OSError:
        pack_metadata_failed = True
    if pack_metadata_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _checkout_index(
    git_executable: Path,
    root: Path,
    environment: dict[str, str],
) -> None:
    _run_required(
        git_executable,
        root,
        ("checkout-index", "--all", "--force"),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=environment,
        timeout_seconds=_PACK_TIMEOUT_SECONDS,
    )


def _validate_patch_preconditions(
    entries: tuple[_HeadEntry, ...],
    patch: _ParsedPatch,
) -> None:
    for patched_file in patch.files:
        entry = _entry_for_path(entries, patched_file.path)
        if patched_file.is_new:
            if entry is not None:
                _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)
        elif entry is None or entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
            _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)


def _apply_patch(
    git_executable: Path,
    root: Path,
    environment: dict[str, str],
    patch: _ParsedPatch,
) -> None:
    common = (
        "apply",
        "--cached",
        "--whitespace=nowarn",
        "--unidiff-zero",
    )
    checked = _invoke_git(
        git_executable,
        root,
        (*common, "--check", "-"),
        stage=RepairStage.PATCH,
        input_bytes=patch.source.encode("utf-8"),
        extra_environment=environment,
    )
    if checked.returncode != 0:
        _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)
    applied = _invoke_git(
        git_executable,
        root,
        (*common, "-"),
        stage=RepairStage.PATCH,
        input_bytes=patch.source.encode("utf-8"),
        extra_environment=environment,
    )
    if applied.returncode != 0:
        _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)


def _write_empty_tree(git_executable: Path, root: Path) -> str:
    result = _run_required(
        git_executable,
        root,
        ("hash-object", "-w", "-t", "tree", "--stdin"),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        input_bytes=b"",
    )
    object_format = _read_ascii_line(
        _run_required(
            git_executable,
            root,
            ("rev-parse", "--show-object-format"),
            stage=RepairStage.MATERIALIZATION,
            failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        ).stdout,
        RepairStage.MATERIALIZATION,
    )
    return _parse_oid_line(result.stdout, object_format, RepairStage.MATERIALIZATION)


def _canonical_diff(
    git_executable: Path,
    root: Path,
    head_oid: str,
    environment: dict[str, str],
) -> str:
    result = _run_required(
        git_executable,
        root,
        (
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--patch",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--diff-algorithm=myers",
            "--no-indent-heuristic",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            head_oid,
            "--",
        ),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=environment,
        stdout_limit=_DIFF_OUTPUT_BYTES,
    )
    if not result.stdout or not result.stdout.endswith(b"\n") or b"\0" in result.stdout:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    invalid_diff_encoding = False
    canonical_diff = ""
    try:
        canonical_diff = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        invalid_diff_encoding = True
    if invalid_diff_encoding:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    return canonical_diff


def _read_numstat(
    git_executable: Path,
    root: Path,
    head_oid: str,
    environment: dict[str, str],
    limits: _GitLimits,
) -> tuple[tuple[str, ...], int]:
    result = _run_required(
        git_executable,
        root,
        (
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--numstat",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            head_oid,
            "--",
        ),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=environment,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    records = result.stdout.split(b"\0")
    if not records or records[-1] != b"":
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    paths: list[str] = []
    changed_lines = 0
    seen_paths: set[str] = set()
    for record in records[:-1]:
        additions, separator, remainder = record.partition(b"\t")
        deletions, separator_two, raw_path = remainder.partition(b"\t")
        if not separator or not separator_two or not additions.isdigit() or not deletions.isdigit():
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
        invalid_path_encoding = False
        path = ""
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            invalid_path_encoding = True
        if invalid_path_encoding:
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
        invalid_path = False
        try:
            _validate_repository_path(path)
        except (TypeError, ValueError):
            invalid_path = True
        if invalid_path:
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
        if path in seen_paths:
            _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
        seen_paths.add(path)
        paths.append(path)
        changed_lines += int(additions) + int(deletions)
        if len(paths) > limits.max_changed_paths or changed_lines > limits.max_changed_lines:
            _raise(RepairErrorCode.RESOURCE_LIMIT, RepairStage.MATERIALIZATION)
    if not paths or changed_lines == 0:
        _raise(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)
    return tuple(sorted(paths, key=str.encode)), changed_lines


def _write_tree(
    git_executable: Path,
    root: Path,
    environment: dict[str, str],
    object_format: str,
) -> str:
    result = _run_required(
        git_executable,
        root,
        ("write-tree",),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=environment,
    )
    return _parse_oid_line(result.stdout, object_format, RepairStage.MATERIALIZATION)


def _write_commit(
    git_executable: Path,
    root: Path,
    source: _RepositoryIdentity,
    tree_oid: str,
    index_environment: dict[str, str],
) -> str:
    environment = {
        **index_environment,
        "GIT_AUTHOR_NAME": "RepoGuard",
        "GIT_AUTHOR_EMAIL": "repoguard@localhost",
        "GIT_AUTHOR_DATE": "@0 +0000",
        "GIT_COMMITTER_NAME": "RepoGuard",
        "GIT_COMMITTER_EMAIL": "repoguard@localhost",
        "GIT_COMMITTER_DATE": "@0 +0000",
    }
    result = _run_required(
        git_executable,
        root,
        ("commit-tree", tree_oid, "-p", source.head_oid),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        input_bytes=_COMMIT_MESSAGE,
        extra_environment=environment,
    )
    return _parse_oid_line(result.stdout, source.object_format, RepairStage.MATERIALIZATION)


def _verify_commit(
    git_executable: Path,
    root: Path,
    source: _RepositoryIdentity,
    tree_oid: str,
    commit_oid: str,
    *,
    stage: RepairStage = RepairStage.MATERIALIZATION,
    failure_code: RepairErrorCode = RepairErrorCode.MATERIALIZATION_FAILED,
) -> None:
    _require_oid(tree_oid, source.object_format, stage)
    _require_oid(commit_oid, source.object_format, stage)
    result = _run_required(
        git_executable,
        root,
        ("cat-file", "commit", commit_oid),
        stage=stage,
        failure_code=failure_code,
    )
    expected = (
        f"tree {tree_oid}\n"
        f"parent {source.head_oid}\n"
        f"author {_IDENTITY} 0 +0000\n"
        f"committer {_IDENTITY} 0 +0000\n"
        "\n"
    ).encode("ascii") + _COMMIT_MESSAGE
    if result.stdout != expected:
        _raise(failure_code, stage)


def _verify_index_tree(
    git_executable: Path,
    root: Path,
    environment: dict[str, str],
    object_format: str,
    expected_tree: str,
) -> None:
    _run_required(
        git_executable,
        root,
        ("update-index", "--refresh"),
        stage=RepairStage.MATERIALIZATION,
        failure_code=RepairErrorCode.MATERIALIZATION_FAILED,
        extra_environment=environment,
    )
    actual_tree = _write_tree(git_executable, root, environment, object_format)
    if actual_tree != expected_tree:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    result = _invoke_git(
        git_executable,
        root,
        ("diff-files", "--quiet", "--"),
        stage=RepairStage.MATERIALIZATION,
        extra_environment=environment,
    )
    if result.returncode != 0:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    index_metadata_failed = False
    try:
        Path(environment["GIT_INDEX_FILE"]).chmod(0o600)
    except (KeyError, OSError):
        index_metadata_failed = True
    if index_metadata_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _revalidate_source(
    source: _RepositoryIdentity,
    git_executable: Path,
    stage: RepairStage,
    *,
    traverse: bool = True,
) -> None:
    current_root = _read_git_path(
        git_executable,
        source.root,
        ("rev-parse", "--path-format=absolute", "--show-toplevel"),
        stage,
    )
    current_common = _read_git_path(
        git_executable,
        source.root,
        ("rev-parse", "--path-format=absolute", "--git-common-dir"),
        stage,
    )
    current_format = _read_ascii_line(
        _run_required(
            git_executable,
            source.root,
            ("rev-parse", "--show-object-format"),
            stage=stage,
            failure_code=RepairErrorCode.GIT_FAILED,
        ).stdout,
        stage,
    )
    root_stat = _directory_stat(current_root, stage)
    common_stat = _directory_stat(current_common, stage)
    if (
        current_root != source.root
        or current_common != source.common_dir
        or current_format != source.object_format
        or root_stat.st_dev != source.root_device
        or root_stat.st_ino != source.root_inode
        or common_stat.st_dev != source.common_dir_device
        or common_stat.st_ino != source.common_dir_inode
    ):
        _raise(RepairErrorCode.IDENTITY_MISMATCH, stage)
    commit_type = _run_required(
        git_executable,
        source.root,
        ("cat-file", "-t", source.head_oid),
        stage=stage,
        failure_code=RepairErrorCode.MISSING_OBJECT,
    )
    if _read_ascii_line(commit_type.stdout, stage) != "commit":
        _raise(RepairErrorCode.MISSING_OBJECT, stage)
    if traverse:
        entries, ordinary_bytes, object_oids = _read_head_entries(
            git_executable,
            source.root,
            source.object_format,
            source.head_oid,
            stage=stage,
            limits=_DEFAULT_LIMITS,
        )
        if (
            entries != source.entries
            or ordinary_bytes != source.ordinary_blob_bytes
            or (source.head_oid, *object_oids) != source.object_oids
        ):
            _raise(RepairErrorCode.IDENTITY_MISMATCH, stage)


def _read_git_path(
    git_executable: Path,
    root: Path,
    arguments: tuple[str, ...],
    stage: RepairStage,
) -> Path:
    result = _run_required(
        git_executable,
        root,
        arguments,
        stage=stage,
        failure_code=RepairErrorCode.GIT_FAILED,
    )
    raw_path = _single_path_bytes(result.stdout, stage)
    invalid_path = False
    path: Path | None = None
    try:
        path = Path(raw_path.decode("utf-8")).resolve(strict=True)
    except (OSError, UnicodeDecodeError, ValueError):
        invalid_path = True
    if invalid_path:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    assert path is not None
    _directory_stat(path, stage)
    return path


def _resolved_directory(path: Path, stage: RepairStage) -> Path:
    if not isinstance(path, Path):
        raise TypeError("repository path must be a pathlib.Path")
    resolution_failed = False
    resolved: Path | None = None
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        resolution_failed = True
    if resolution_failed:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    assert resolved is not None
    _directory_stat(resolved, stage)
    return resolved


def _directory_stat(path: Path, stage: RepairStage) -> os.stat_result:
    stat_failed = False
    result: os.stat_result | None = None
    try:
        result = path.stat()
    except OSError:
        stat_failed = True
    if stat_failed:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    assert result is not None
    if not stat.S_ISDIR(result.st_mode):
        _raise(RepairErrorCode.GIT_FAILED, stage)
    return result


def _require_destination(
    destination: Path,
    source: _RepositoryIdentity,
    *,
    precreated: bool = False,
) -> None:
    resolution_failed = False
    resolved_destination: Path | None = None
    try:
        if precreated:
            resolved_destination = destination.resolve(strict=True)
        else:
            resolved_destination = destination.parent.resolve(strict=True) / destination.name
    except (OSError, RuntimeError):
        resolution_failed = True
    if resolution_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    assert resolved_destination is not None
    invalid_destination = False
    try:
        if precreated:
            metadata = destination.stat()
            proc_descriptor = _proc_fd_root_descriptor(destination)
            proc_identity_matches = True
            if proc_descriptor is not None:
                descriptor_metadata = os.fstat(proc_descriptor)
                proc_identity_matches = (
                    descriptor_metadata.st_dev,
                    descriptor_metadata.st_ino,
                ) == (metadata.st_dev, metadata.st_ino)
            invalid_destination = (
                (proc_descriptor is None and resolved_destination != destination)
                or not proc_identity_matches
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or bool(os.listdir(destination))
            )
        else:
            invalid_destination = (
                resolved_destination.parent != destination.parent
                or destination.exists()
                or destination.is_symlink()
            )
    except OSError:
        invalid_destination = True
    if invalid_destination:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    if (
        _paths_overlap(resolved_destination, source.root)
        or _paths_overlap(resolved_destination, source.common_dir)
        or _paths_overlap(source.root, resolved_destination)
        or _paths_overlap(source.common_dir, resolved_destination)
    ):
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _paths_overlap(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_free_space(parent: Path, limits: _GitLimits) -> None:
    disk_usage_failed = False
    available = 0
    try:
        available = shutil.disk_usage(parent).free
    except OSError:
        disk_usage_failed = True
    if disk_usage_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)
    if available < limits.minimum_free_bytes:
        _raise(RepairErrorCode.RESOURCE_LIMIT, RepairStage.MATERIALIZATION)


def _require_host_limits(root: Path, limits: _GitLimits) -> None:
    _require_host_limits_for_roots((root,), limits)


def _require_host_limits_for_roots(
    roots: tuple[Path, ...],
    limits: _GitLimits,
) -> None:
    if type(roots) is not tuple or not roots or any(not isinstance(root, Path) for root in roots):
        raise TypeError("host limit roots must be an exact non-empty tuple of Paths")
    entries = 0
    total_bytes = 0
    pending = list(roots)
    traversal_failed = False
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > limits.max_host_entries:
                        _raise(RepairErrorCode.RESOURCE_LIMIT, RepairStage.MATERIALIZATION)
                    details = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(details.st_mode):
                        pending.append(Path(entry.path))
                    else:
                        total_bytes += details.st_size
                        if total_bytes > limits.max_host_bytes:
                            _raise(RepairErrorCode.RESOURCE_LIMIT, RepairStage.MATERIALIZATION)
    except RepairError:
        raise
    except OSError:
        traversal_failed = True
    if traversal_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _proc_fd_root_descriptor(path: Path) -> int | None:
    parts = path.parts
    if len(parts) != 5 or parts[:4] != ("/", "proc", "self", "fd"):
        return None
    raw_descriptor = parts[4]
    if not raw_descriptor.isdecimal() or raw_descriptor.startswith("0"):
        return None
    descriptor = int(raw_descriptor)
    if descriptor < 3:
        return None
    return descriptor


def _open_owned_directory_path(path: Path) -> int:
    proc_descriptor = _proc_fd_root_descriptor(path)
    if proc_descriptor is None:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    else:
        descriptor = os.dup(proc_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError("unsafe owned directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _candidate_worktree_modes(
    entries: tuple[_HeadEntry, ...],
    changed_paths: tuple[str, ...] = (),
) -> dict[tuple[str, ...], int]:
    modes = {
        tuple(entry.path.split("/")): 0o500 if entry.mode == "100755" else 0o400
        for entry in entries
        if entry.kind == "blob" and entry.mode in {"100644", "100755"}
    }
    for path in changed_paths:
        modes.setdefault(tuple(path.split("/")), 0o400)
    return modes


def _harden_candidate_tree(
    root: Path,
    index_file: Path,
    worktree_modes: dict[tuple[str, ...], int],
) -> None:
    if not _try_harden_candidate_tree(
        root,
        index_file,
        worktree_modes,
        require_index=True,
        require_worktree=True,
    ):
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _verify_hardened_candidate_tree(
    root: Path,
    index_file: Path,
    worktree_modes: dict[tuple[str, ...], int],
) -> None:
    verified = False
    try:
        _candidate_tree_pass(
            root,
            index_file,
            worktree_modes,
            operation=_CandidateTreePass.VERIFY,
            require_index=True,
            require_worktree=True,
        )
        verified = True
    except (OSError, ValueError, _UnsafeCandidateTreeError):
        pass
    if not verified:
        _raise(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)


def _try_harden_candidate_tree(
    root: Path,
    index_file: Path,
    worktree_modes: dict[tuple[str, ...], int],
    *,
    require_index: bool,
    require_worktree: bool = False,
) -> bool:
    try:
        _candidate_tree_pass(
            root,
            index_file,
            worktree_modes,
            operation=_CandidateTreePass.PREFLIGHT,
            require_index=require_index,
            require_worktree=require_worktree,
        )
        _candidate_tree_pass(
            root,
            index_file,
            worktree_modes,
            operation=_CandidateTreePass.HARDEN,
            require_index=require_index,
            require_worktree=require_worktree,
        )
        _candidate_tree_pass(
            root,
            index_file,
            worktree_modes,
            operation=_CandidateTreePass.VERIFY,
            require_index=require_index,
            require_worktree=require_worktree,
        )
    except (OSError, ValueError, _UnsafeCandidateTreeError):
        return False
    return True


def _candidate_tree_pass(
    root: Path,
    index_file: Path,
    worktree_modes: dict[tuple[str, ...], int],
    *,
    operation: _CandidateTreePass,
    require_index: bool,
    require_worktree: bool,
) -> None:
    index_parts = index_file.relative_to(root).parts
    if (
        index_parts != (".git", "repoguard-index")
        or type(worktree_modes) is not dict
        or any(mode not in {0o400, 0o500} for mode in worktree_modes.values())
    ):
        raise _UnsafeCandidateTreeError
    parent_fd = -1
    root_fd = -1
    try:
        if _proc_fd_root_descriptor(root) is not None:
            root_fd = _open_owned_directory_path(root)
            before = os.fstat(root_fd)
            mount_id = _candidate_mount_id(root_fd)
        else:
            parent_fd = os.open(
                root.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            parent_details = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(parent_details.st_mode)
                or parent_details.st_uid != os.geteuid()
                or stat.S_IMODE(parent_details.st_mode) != 0o700
            ):
                raise _UnsafeCandidateTreeError
            mount_id = _candidate_mount_id(parent_fd)
            before = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            root_fd = os.open(
                root.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        try:
            current = os.fstat(root_fd)
            _require_candidate_metadata(before, current, directory=True)
            _require_candidate_mount(root_fd, mount_id)
            if operation is _CandidateTreePass.HARDEN:
                os.fchmod(root_fd, 0o700)
            elif operation is _CandidateTreePass.VERIFY and (
                stat.S_IMODE(current.st_mode) != 0o700
            ):
                raise _UnsafeCandidateTreeError
            seen_worktree: set[tuple[str, ...]] = set()
            index_found = _candidate_tree_directory_pass(
                root_fd,
                (),
                index_parts,
                worktree_modes,
                seen_worktree,
                mount_id,
                operation,
            )
            if require_index and not index_found:
                raise _UnsafeCandidateTreeError
            if require_worktree and seen_worktree != set(worktree_modes):
                raise _UnsafeCandidateTreeError
            if operation is _CandidateTreePass.HARDEN:
                os.fsync(root_fd)
                if parent_fd >= 0:
                    os.fsync(parent_fd)
            if parent_fd >= 0:
                _require_candidate_named_entry(
                    parent_fd,
                    root.name,
                    os.fstat(root_fd),
                    directory=True,
                )
        finally:
            if root_fd >= 0:
                os.close(root_fd)
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _candidate_tree_directory_pass(
    directory_fd: int,
    relative_parts: tuple[str, ...],
    index_parts: tuple[str, ...],
    worktree_modes: dict[tuple[str, ...], int],
    seen_worktree: set[tuple[str, ...]],
    mount_id: int,
    operation: _CandidateTreePass,
) -> bool:
    index_found = False
    for name in sorted(os.listdir(directory_fd), key=os.fsencode):
        child_parts = (*relative_parts, name)
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                current = os.fstat(child_fd)
                _require_candidate_metadata(before, current, directory=True)
                _require_candidate_mount(child_fd, mount_id)
                if operation is _CandidateTreePass.HARDEN:
                    os.fchmod(child_fd, 0o700)
                elif operation is _CandidateTreePass.VERIFY and (
                    stat.S_IMODE(current.st_mode) != 0o700
                ):
                    raise _UnsafeCandidateTreeError
                if _candidate_tree_directory_pass(
                    child_fd,
                    child_parts,
                    index_parts,
                    worktree_modes,
                    seen_worktree,
                    mount_id,
                    operation,
                ):
                    index_found = True
                if operation is _CandidateTreePass.HARDEN:
                    os.fsync(child_fd)
                _require_candidate_named_entry(
                    directory_fd, name, os.fstat(child_fd), directory=True
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise _UnsafeCandidateTreeError
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            current = os.fstat(child_fd)
            _require_candidate_metadata(before, current, directory=False)
            _require_candidate_mount(child_fd, mount_id)
            expected_mode = worktree_modes.get(child_parts, 0o400)
            if child_parts == index_parts:
                expected_mode = 0o600
                index_found = True
            elif child_parts in worktree_modes:
                seen_worktree.add(child_parts)
            if operation is _CandidateTreePass.HARDEN:
                os.fchmod(child_fd, expected_mode)
                os.fsync(child_fd)
            elif operation is _CandidateTreePass.VERIFY and (
                stat.S_IMODE(current.st_mode) != expected_mode
            ):
                raise _UnsafeCandidateTreeError
            _require_candidate_named_entry(directory_fd, name, os.fstat(child_fd), directory=False)
        finally:
            os.close(child_fd)
    return index_found


def _require_candidate_metadata(
    expected: os.stat_result,
    current: os.stat_result,
    *,
    directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(expected.st_mode)
        or not expected_type(current.st_mode)
        or expected.st_uid != os.geteuid()
        or current.st_uid != os.geteuid()
        or (not directory and (expected.st_nlink != 1 or current.st_nlink != 1))
        or (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise _UnsafeCandidateTreeError


def _require_candidate_named_entry(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    *,
    directory: bool,
) -> None:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require_candidate_metadata(expected, current, directory=directory)


def _candidate_mount_id(descriptor: int) -> int:
    fdinfo = -1
    read_failed = False
    payload = b""
    try:
        fdinfo = os.open(
            f"/proc/self/fdinfo/{descriptor}",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        payload = os.read(fdinfo, 8_193)
    except OSError:
        read_failed = True
    finally:
        if fdinfo >= 0:
            try:
                os.close(fdinfo)
            except OSError:
                read_failed = True
    if read_failed or len(payload) > 8_192:
        raise _UnsafeCandidateTreeError
    invalid_payload = False
    lines: list[str] = []
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError:
        invalid_payload = True
    if invalid_payload:
        raise _UnsafeCandidateTreeError
    values = [
        line.partition(":")[2].strip() for line in lines if line.partition(":")[0] == "mnt_id"
    ]
    if len(values) != 1 or not values[0].isdecimal():
        raise _UnsafeCandidateTreeError
    return int(values[0])


def _require_candidate_mount(descriptor: int, expected_mount_id: int) -> None:
    if _candidate_mount_id(descriptor) != expected_mount_id:
        raise _UnsafeCandidateTreeError


def _entry_for_path(entries: tuple[_HeadEntry, ...], path: str) -> _HeadEntry | None:
    for entry in entries:
        if entry.path == path:
            return entry
    return None


def _write_private_file(path: Path, content: bytes) -> None:
    descriptor = -1
    write_failed = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except OSError:
        write_failed = True
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    if write_failed:
        _raise(RepairErrorCode.MATERIALIZATION_FAILED, RepairStage.MATERIALIZATION)


def _run_required(
    git_executable: Path,
    root: Path | None,
    arguments: Sequence[str],
    *,
    stage: RepairStage,
    failure_code: RepairErrorCode,
    input_bytes: bytes | None = None,
    extra_environment: dict[str, str] | None = None,
    timeout_seconds: float = _GIT_TIMEOUT_SECONDS,
    stdout_limit: int = _CONTROL_OUTPUT_BYTES,
    stderr_limit: int = _CONTROL_OUTPUT_BYTES,
) -> _GitResult:
    result = _invoke_git(
        git_executable,
        root,
        arguments,
        stage=stage,
        input_bytes=input_bytes,
        extra_environment=extra_environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )
    if result.returncode != 0:
        _raise(failure_code, stage)
    return result


def _invoke_git(
    git_executable: Path,
    root: Path | None,
    arguments: Sequence[str],
    *,
    stage: RepairStage,
    input_bytes: bytes | None = None,
    extra_environment: dict[str, str] | None = None,
    timeout_seconds: float = _GIT_TIMEOUT_SECONDS,
    stdout_limit: int = _CONTROL_OUTPUT_BYTES,
    stderr_limit: int = _CONTROL_OUTPUT_BYTES,
    inherited_fds: tuple[int, ...] = (),
) -> _GitResult:
    if type(stage) is not RepairStage:
        raise TypeError("stage must be an exact RepairStage")
    if (
        type(timeout_seconds) is not float
        or timeout_seconds <= 0.0
        or type(stdout_limit) is not int
        or stdout_limit <= 0
        or type(stderr_limit) is not int
        or stderr_limit <= 0
    ):
        raise ValueError("Git process bounds are invalid")
    if input_bytes is not None and type(input_bytes) is not bytes:
        raise TypeError("input_bytes must be exact bytes or None")
    _require_inherited_fds(inherited_fds)
    proc_fds = _proc_fd_references(
        root,
        arguments,
        extra_environment,
        trusted_fds=inherited_fds,
    )
    inherited_fds = tuple(dict.fromkeys((*inherited_fds, *proc_fds)))
    _require_inherited_fds(inherited_fds)
    command = [str(git_executable), "--literal-pathspecs"]
    if root is not None:
        command.extend(("-C", str(root)))
    command.extend(arguments)
    environment = _git_environment(extra_environment)
    process: subprocess.Popen[bytes] | None = None
    stdout_state = _DrainState(bytearray())
    stderr_state = _DrainState(bytearray())
    input_state = _InputState()
    limit_reached = threading.Event()
    threads: list[threading.Thread] = []
    start_failed = False
    unavailable = False
    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.abspath(os.sep),
                env=environment,
                shell=False,
                close_fds=True,
                pass_fds=inherited_fds,
                start_new_session=True,
                umask=0o077,
            )
        except FileNotFoundError:
            unavailable = True
        except (OSError, ValueError):
            start_failed = True
        if unavailable:
            _raise(RepairErrorCode.GIT_UNAVAILABLE, stage)
        if (
            start_failed
            or process is None
            or process.stdout is None
            or process.stderr is None
            or (input_bytes is not None and process.stdin is None)
        ):
            _raise(RepairErrorCode.GIT_FAILED, stage)
        threads = [
            threading.Thread(
                target=_drain_stream,
                args=(process.stdout, stdout_limit, stdout_state, limit_reached),
                daemon=True,
            ),
            threading.Thread(
                target=_drain_stream,
                args=(process.stderr, stderr_limit, stderr_state, limit_reached),
                daemon=True,
            ),
        ]
        if input_bytes is not None and process.stdin is not None:
            threads.append(
                threading.Thread(
                    target=_write_process_input,
                    args=(process.stdin, input_bytes, input_state),
                    daemon=True,
                )
            )
        thread_start_failed = False
        try:
            for thread in threads:
                thread.start()
        except RuntimeError:
            _stop_process(process)
            thread_start_failed = True
        if thread_start_failed:
            _raise(RepairErrorCode.GIT_FAILED, stage)
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        output_limited = False
        residual_processes = False
        while process.poll() is None or any(thread.is_alive() for thread in threads):
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                timed_out = True
                _stop_process(process)
                break
            if limit_reached.wait(timeout=min(_POLL_SECONDS, remaining)):
                output_limited = True
                _stop_process(process)
                break
        if not timed_out and not output_limited:
            residual_processes = _stop_process(process)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _stop_process(process)
        for thread in threads:
            thread.join(timeout=1.0)
        if (
            any(thread.is_alive() for thread in threads)
            or stdout_state.failed
            or stderr_state.failed
            or input_state.failed
        ):
            _raise(RepairErrorCode.GIT_FAILED, stage)
        if output_limited:
            _raise(RepairErrorCode.RESOURCE_LIMIT, stage)
        if timed_out:
            _raise(RepairErrorCode.GIT_FAILED, stage)
        if residual_processes:
            _raise(RepairErrorCode.GIT_FAILED, stage)
        if process.returncode is None:
            _raise(RepairErrorCode.GIT_FAILED, stage)
        return _GitResult(
            process.returncode,
            bytes(stdout_state.output),
            bytes(stderr_state.output),
        )
    finally:
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    with suppress(OSError):
                        stream.close()


def _inherited_lock_fds(value: int | None) -> tuple[int, ...]:
    if value is None:
        return ()
    if type(value) is not int:
        raise TypeError("inherited_lock_fd must be an exact int or None")
    inherited_fds = (value,)
    _require_inherited_fds(inherited_fds)
    return inherited_fds


def _proc_fd_references(
    root: Path | None,
    arguments: Sequence[str],
    extra_environment: dict[str, str] | None,
    *,
    trusted_fds: tuple[int, ...],
) -> tuple[int, ...]:
    values: list[str] = []
    if root is not None:
        values.append(str(root))
    values.extend(item for item in arguments if type(item) is str)
    if type(extra_environment) is dict:
        values.extend(item for item in extra_environment.values() if type(item) is str)
    descriptors = tuple(
        sorted(
            {
                int(match.group(2))
                for value in values
                for match in _PROC_SELF_FD_PATTERN.finditer(value)
            }
        )
    )
    _require_inherited_fds(trusted_fds)
    _require_inherited_fds(descriptors)
    trusted = frozenset(trusted_fds)
    for descriptor in descriptors:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or (descriptor not in trusted and stat.S_IMODE(metadata.st_mode) != 0o700)
        ):
            raise ValueError("proc-fd paths must reference trusted owned directories")
    return descriptors


def _require_inherited_fds(value: tuple[int, ...]) -> None:
    if type(value) is not tuple or any(type(descriptor) is not int for descriptor in value):
        raise TypeError("inherited_fds must be an exact tuple of exact ints")
    if len(set(value)) != len(value) or any(descriptor < 3 for descriptor in value):
        raise ValueError("inherited_fds must contain unique non-stdio descriptors")
    try:
        for descriptor in value:
            os.fstat(descriptor)
    except OSError:
        raise ValueError("inherited_fds must contain open descriptors") from None


def _drain_stream(
    stream: BinaryIO,
    limit: int,
    state: _DrainState,
    limit_reached: threading.Event,
) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                return
            state.total += len(chunk)
            remaining = limit - len(state.output)
            if remaining > 0:
                state.output.extend(chunk[:remaining])
            if state.total > limit:
                limit_reached.set()
    except OSError:
        state.failed = True
        limit_reached.set()


def _write_process_input(stream: BinaryIO, content: bytes, state: _InputState) -> None:
    try:
        stream.write(content)
        stream.flush()
    except BrokenPipeError:
        pass
    except OSError:
        state.failed = True
    finally:
        with suppress(OSError):
            stream.close()


def _stop_process(process: subprocess.Popen[bytes]) -> bool:
    group_existed = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        group_existed = False
    except OSError:
        with suppress(OSError):
            process.kill()
    deadline = time.monotonic() + 1.0
    while group_existed and time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except OSError:
            break
        time.sleep(0.01)
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=1.0)
    return group_existed


def _git_environment(extra: dict[str, str] | None) -> dict[str, str]:
    environment = {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ATTR_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    environment["GIT_CONFIG_COUNT"] = str(len(_FIXED_CONFIG))
    for index, (key, value) in enumerate(_FIXED_CONFIG):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    if extra is not None:
        if type(extra) is not dict or any(
            type(key) is not str or type(value) is not str for key, value in extra.items()
        ):
            raise TypeError("extra_environment must contain exact strings")
        environment.update(extra)
    return environment


def _single_line_bytes(output: bytes, stage: RepairStage) -> bytes:
    value = _single_path_bytes(output, stage)
    if b"\n" in value:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    return value


def _single_path_bytes(output: bytes, stage: RepairStage) -> bytes:
    if not output.endswith(b"\n"):
        _raise(RepairErrorCode.GIT_FAILED, stage)
    value = output[:-1]
    if not value or b"\0" in value:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    return value


def _read_ascii_line(output: bytes, stage: RepairStage) -> str:
    raw = _single_line_bytes(output, stage)
    invalid_ascii = False
    value = ""
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        invalid_ascii = True
    if invalid_ascii:
        _raise(RepairErrorCode.GIT_FAILED, stage)
    return value


def _parse_oid_line(output: bytes, object_format: str, stage: RepairStage) -> str:
    oid = _read_ascii_line(output, stage)
    _require_oid(oid, object_format, stage)
    return oid


def _require_oid(oid: str, object_format: str, stage: RepairStage) -> None:
    expected_length = _OBJECT_FORMAT_LENGTHS.get(object_format)
    if (
        type(oid) is not str
        or expected_length is None
        or len(oid) != expected_length
        or _OID_PATTERN.fullmatch(oid) is None
        or set(oid) == {"0"}
    ):
        _raise(RepairErrorCode.GIT_FAILED, stage)


def _require_repository_identity(source: _RepositoryIdentity) -> None:
    if type(source) is not _RepositoryIdentity:
        raise TypeError("source must be an exact repository identity")


def _require_git_executable(git_executable: Path) -> None:
    if not isinstance(git_executable, Path) or not git_executable.is_absolute():
        raise ValueError("git_executable must be an absolute pathlib.Path")


def _require_limits(limits: _GitLimits) -> None:
    if type(limits) is not _GitLimits:
        raise TypeError("_limits must be an exact _GitLimits")
    values = tuple(getattr(limits, field) for field in limits.__dataclass_fields__)
    if any(type(value) is not int or value <= 0 for value in values):
        raise ValueError("Git limits must be positive exact integers")


def _raise(code: RepairErrorCode, stage: RepairStage) -> NoReturn:
    raise RepairError(code, stage) from None
