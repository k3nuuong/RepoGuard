"""Hardened read-only Git evidence collection."""

from __future__ import annotations

import os
import re
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO, Never

from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    EvidenceCollectionError,
    EvidenceCollectionLimits,
    EvidenceErrorCode,
    FileChangeEvidence,
    FileVersion,
    PullRequestInput,
    RepositoryEvidence,
    RepositoryInput,
    RevisionEvidence,
)

_MODE_PATTERN = re.compile(rb"^[0-7]{6}$")
_HUNK_PATTERN = re.compile(
    rb"^@@ -(?P<old_start>[0-9]+)(?:,(?P<old_count>[0-9]+))?"
    rb" \+(?P<new_start>[0-9]+)(?:,(?P<new_count>[0-9]+))? @@(?: .*)?\n?$"
)
_NO_NEWLINE_MARKER = b"\\ No newline at end of file\n"
_OBJECT_FORMAT_LENGTHS = {"sha1": 40, "sha256": 64}
_GIT_FACADE_ROOT = Path(__file__).with_name("_git_facades")
_CONTROL_OUTPUT_BYTES = 1024 * 1024
_RAW_CHANGE_OUTPUT_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_POLL_SECONDS = 0.01
_PROCESS_CLEANUP_SECONDS = 0.25


@dataclass(frozen=True, slots=True)
class _RawChange:
    change_type: ChangeType
    rename_similarity: int | None
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    old_path: str
    new_path: str


@dataclass(slots=True)
class _CollectionBudget:
    limits: EvidenceCollectionLimits
    deadline: float
    git_executable: str = "git"
    blob_bytes: int = 0
    diff_bytes: int = 0
    diff_lines: int = 0


@dataclass(slots=True)
class _DrainState:
    output: bytearray
    total: int = 0
    overflowed: bool = False
    error: Exception | None = None


def _validate_git_executable(path: Path) -> str:
    if not path.is_absolute():
        raise ValueError("git_executable must be an absolute regular executable")
    try:
        str(path).encode("utf-8", "strict")
        current = Path(path.anchor)
        metadata = os.lstat(current)
        for part in path.parts[1:]:
            current /= part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("git_executable cannot contain symbolic links")
    except (OSError, UnicodeEncodeError, ValueError) as error:
        raise ValueError("git_executable is invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o111 == 0
    ):
        raise ValueError("git_executable is invalid")
    return str(path)


def _check_deadline(budget: _CollectionBudget | None) -> None:
    if budget is not None and time.monotonic() >= budget.deadline:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_TIMEOUT,
            "Git evidence collection exceeded its shared timeout",
        )


def _parse_blob_size(output: bytes) -> int:
    encoded_size = _single_output_line(output, "blob size")
    if not encoded_size.isdigit():
        _raise_malformed("Git blob size is not an unsigned decimal integer")
    try:
        return int(encoded_size)
    except ValueError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
            "Git blob size is too large to parse",
        ) from error


def _reserve_blob_bytes(budget: _CollectionBudget, size: int) -> None:
    _check_deadline(budget)
    if size > budget.limits.max_blob_bytes:
        _raise_resource_limit("per-blob byte limit exceeded")
    if size > budget.limits.max_total_blob_bytes - budget.blob_bytes:
        _raise_resource_limit("total blob byte limit exceeded")
    budget.blob_bytes += size


def _reserve_diff_bytes(budget: _CollectionBudget, size: int) -> None:
    _check_deadline(budget)
    if size > budget.limits.max_diff_bytes - budget.diff_bytes:
        _raise_resource_limit("diff byte limit exceeded")
    budget.diff_bytes += size


def _reserve_diff_line(budget: _CollectionBudget) -> None:
    _check_deadline(budget)
    if budget.diff_lines >= budget.limits.max_diff_lines:
        _raise_resource_limit("diff line limit exceeded")
    budget.diff_lines += 1


def _drain_bounded_stream(
    stream: BinaryIO,
    limit: int,
    state: _DrainState,
    stop_event: threading.Event,
) -> None:
    try:
        file_descriptor = stream.fileno()
        while not stop_event.is_set():
            remaining = limit - state.total
            try:
                chunk = os.read(file_descriptor, min(_READ_CHUNK_BYTES, remaining + 1))
            except BlockingIOError:
                stop_event.wait(_POLL_SECONDS)
                continue
            if not chunk:
                return
            state.total += len(chunk)
            retained = min(len(chunk), remaining)
            state.output.extend(chunk[:retained])
            if state.total > limit:
                state.overflowed = True
                stop_event.set()
                return
    except (OSError, ValueError) as error:
        if not stop_event.is_set():
            state.error = error
            stop_event.set()
    finally:
        with suppress(OSError):
            stream.close()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        with suppress(OSError):
            process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=_PROCESS_CLEANUP_SECONDS)


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def _join_threads(threads: Sequence[threading.Thread], failure_message: str) -> None:
    cleanup_deadline = time.monotonic() + _PROCESS_CLEANUP_SECONDS
    for thread in threads:
        remaining = cleanup_deadline - time.monotonic()
        if remaining > 0:
            thread.join(remaining)
    if any(thread.is_alive() for thread in threads):
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            failure_message,
        )


def _invoke_bounded_process(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: str | None,
    pass_fds: Sequence[int] = (),
    budget: _CollectionBudget,
    stdout_limit: int,
    stderr_limit: int,
    stdout_overflow_code: EvidenceErrorCode = EvidenceErrorCode.RESOURCE_LIMIT,
) -> subprocess.CompletedProcess[bytes]:
    _check_deadline(budget)
    if stdout_limit < 0 or stderr_limit < 0:
        _raise_resource_limit("Git output byte limit exhausted")
    try:
        process = subprocess.Popen(
            list(command),
            bufsize=0,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            cwd=cwd,
            env=environment,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
        )
    except FileNotFoundError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_UNAVAILABLE,
            "Git executable is not available",
        ) from error
    except (OSError, ValueError) as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git command could not be started",
        ) from error

    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        _terminate_process_group(process)
        _close_process_streams(process)
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git output pipes could not be created",
        )
    try:
        os.set_blocking(stdout.fileno(), False)
        os.set_blocking(stderr.fileno(), False)
    except (OSError, ValueError) as error:
        _terminate_process_group(process)
        _close_process_streams(process)
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git output pipes could not be made non-blocking",
        ) from error

    stop_event = threading.Event()
    stdout_state = _DrainState(bytearray())
    stderr_state = _DrainState(bytearray())
    drain_threads = (
        threading.Thread(
            target=_drain_bounded_stream,
            args=(stdout, stdout_limit, stdout_state, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded_stream,
            args=(stderr, stderr_limit, stderr_state, stop_event),
            daemon=True,
        ),
    )
    started_threads = 0
    try:
        for thread in drain_threads:
            thread.start()
            started_threads += 1
    except (OSError, RuntimeError) as error:
        stop_event.set()
        _terminate_process_group(process)
        _close_process_streams(process)
        _join_threads(
            drain_threads[:started_threads],
            "Git output reader threads did not stop",
        )
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git output reader threads could not be started",
        ) from error

    failure: EvidenceErrorCode | None = None
    while True:
        if stdout_state.overflowed:
            failure = stdout_overflow_code
            break
        if stderr_state.overflowed:
            failure = EvidenceErrorCode.RESOURCE_LIMIT
            break
        if stdout_state.error is not None or stderr_state.error is not None:
            failure = EvidenceErrorCode.GIT_COMMAND_FAILED
            break
        remaining = budget.deadline - time.monotonic()
        if remaining <= 0:
            failure = EvidenceErrorCode.GIT_TIMEOUT
            break
        if process.poll() is not None and not any(thread.is_alive() for thread in drain_threads):
            break
        stop_event.wait(min(_POLL_SECONDS, remaining))

    if failure is not None:
        stop_event.set()
        _terminate_process_group(process)
        _close_process_streams(process)
        return_code = process.returncode if process.returncode is not None else -signal.SIGKILL
    else:
        return_code = process.returncode
        if return_code is None:
            raise EvidenceCollectionError(
                EvidenceErrorCode.GIT_COMMAND_FAILED,
                "Git process completion could not be observed",
            )
    _join_threads(drain_threads, "Git output reader threads did not stop")
    _close_process_streams(process)

    if failure is EvidenceErrorCode.RESOURCE_LIMIT:
        _raise_resource_limit("Git command output byte limit exceeded")
    if failure is EvidenceErrorCode.GIT_TIMEOUT:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_TIMEOUT,
            "Git evidence collection exceeded its shared timeout",
        )
    if failure is EvidenceErrorCode.GIT_COMMAND_FAILED:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git command output could not be read",
        )
    if failure is EvidenceErrorCode.MALFORMED_GIT_OUTPUT:
        _raise_malformed("Git command stdout exceeded its declared byte size")
    completed = subprocess.CompletedProcess(
        list(command),
        return_code,
        stdout=bytes(stdout_state.output),
        stderr=bytes(stderr_state.output),
    )
    _check_deadline(budget)
    return completed


def _collect_evidence(
    repository: RepositoryInput,
    pull_request: PullRequestInput,
    *,
    limits: EvidenceCollectionLimits | None = None,
    git_executable: Path | None = None,
) -> EvidenceBundle:
    if limits is not None and type(limits) is not EvidenceCollectionLimits:
        raise TypeError("limits must be an exact EvidenceCollectionLimits or None")
    if git_executable is not None and not isinstance(git_executable, Path):
        raise TypeError("git_executable must be a Path or None")
    if git_executable is not None and limits is None:
        raise ValueError("git_executable requires explicit evidence collection limits")
    executable = "git" if git_executable is None else _validate_git_executable(git_executable)
    validated_limits = (
        None
        if limits is None
        else EvidenceCollectionLimits(
            max_changed_files=limits.max_changed_files,
            max_blob_bytes=limits.max_blob_bytes,
            max_total_blob_bytes=limits.max_total_blob_bytes,
            max_diff_bytes=limits.max_diff_bytes,
            max_diff_lines=limits.max_diff_lines,
            git_timeout_seconds=limits.git_timeout_seconds,
        )
    )
    budget = (
        None
        if validated_limits is None
        else _CollectionBudget(
            validated_limits,
            time.monotonic() + validated_limits.git_timeout_seconds,
            executable,
        )
    )
    root = _resolve_worktree(repository.path, _budget=budget)
    object_format = _read_object_format(root, _budget=budget)
    object_directory = _read_object_directory(root, _budget=budget)
    oid_length = _OBJECT_FORMAT_LENGTHS[object_format]
    base_oid = _resolve_ref(
        root,
        pull_request.base_ref,
        EvidenceErrorCode.INVALID_BASE_REF,
        oid_length,
        _budget=budget,
    )
    head_oid = _resolve_ref(
        root,
        pull_request.head_ref,
        EvidenceErrorCode.INVALID_HEAD_REF,
        oid_length,
        _budget=budget,
    )
    merge_base_oid = _resolve_merge_base(
        root,
        base_oid,
        head_oid,
        oid_length,
        _budget=budget,
    )
    raw_changes = _read_raw_changes(
        object_format,
        object_directory,
        merge_base_oid,
        head_oid,
        oid_length,
        _budget=budget,
    )
    content_cache: dict[tuple[str, str], tuple[ContentKind, bytes | None]] = {}
    changes = tuple(
        sorted(
            (
                _materialize_change(
                    root,
                    raw_change,
                    content_cache,
                    _budget=budget,
                )
                for raw_change in raw_changes
            ),
            key=_change_sort_key,
        )
    )
    _check_deadline(budget)
    return EvidenceBundle(
        repository=RepositoryEvidence(root=root, object_format=object_format),
        revisions=RevisionEvidence(
            base_ref=pull_request.base_ref,
            head_ref=pull_request.head_ref,
            base_oid=base_oid,
            head_oid=head_oid,
            merge_base_oid=merge_base_oid,
        ),
        changes=changes,
    )


def _resolve_worktree(path: Path, *, _budget: _CollectionBudget | None = None) -> Path:
    _check_deadline(_budget)
    try:
        if not path.exists() or not path.is_dir():
            raise EvidenceCollectionError(
                EvidenceErrorCode.REPOSITORY_PATH_MISSING,
                f"repository path does not exist or is not a directory: {path}",
            )
        candidate = path.resolve(strict=True)
    except EvidenceCollectionError:
        raise
    except OSError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.REPOSITORY_PATH_MISSING,
            f"repository path cannot be resolved: {path}",
        ) from error

    completed = _invoke_git_with_budget(
        candidate,
        ("rev-parse", "--show-toplevel"),
        budget=_budget,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    if completed.returncode != 0:
        raise EvidenceCollectionError(
            EvidenceErrorCode.NOT_A_WORKTREE,
            f"repository path is not inside a Git worktree: {candidate}",
        )
    root_bytes = _single_path_output(completed.stdout, "worktree root")
    root_text = _decode_path(root_bytes)
    return Path(root_text)


def _read_object_format(root: Path, *, _budget: _CollectionBudget | None = None) -> str:
    output = _run_required(
        root,
        ("rev-parse", "--show-object-format"),
        _budget=_budget,
        _stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    try:
        object_format = _single_output_line(output, "object format").decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
            "Git object format is not ASCII",
        ) from error
    if object_format not in _OBJECT_FORMAT_LENGTHS:
        raise EvidenceCollectionError(
            EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
            f"unsupported Git object format: {object_format}",
        )
    return object_format


def _read_object_directory(root: Path, *, _budget: _CollectionBudget | None = None) -> Path:
    output = _run_required(
        root,
        ("rev-parse", "--path-format=absolute", "--git-path", "objects"),
        _budget=_budget,
        _stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    object_directory = Path(_decode_path(_single_path_output(output, "object directory")))
    if not object_directory.is_absolute():
        _raise_malformed("object directory is not absolute")
    return object_directory


def _resolve_ref(
    root: Path,
    ref: str,
    invalid_code: EvidenceErrorCode,
    oid_length: int,
    *,
    _budget: _CollectionBudget | None = None,
) -> str:
    _validate_ref(ref, invalid_code)
    completed = _invoke_git_with_budget(
        root,
        ("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"),
        budget=_budget,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    if completed.returncode != 0:
        raise EvidenceCollectionError(invalid_code, f"Git ref does not resolve to a commit: {ref}")
    return _parse_oid(_single_output_line(completed.stdout, "resolved ref"), oid_length)


def _validate_ref(ref: str, invalid_code: EvidenceErrorCode) -> None:
    try:
        valid_utf8 = ref.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EvidenceCollectionError(invalid_code, "Git ref must be valid UTF-8") from error
    if not valid_utf8 or b"\0" in valid_utf8:
        raise EvidenceCollectionError(invalid_code, "Git ref must be non-empty and contain no NUL")


def _resolve_merge_base(
    root: Path,
    base_oid: str,
    head_oid: str,
    oid_length: int,
    *,
    _budget: _CollectionBudget | None = None,
) -> str:
    completed = _invoke_git_with_budget(
        root,
        ("merge-base", "--all", base_oid, head_oid),
        budget=_budget,
        stdout_limit=_CONTROL_OUTPUT_BYTES,
    )
    if completed.returncode == 1:
        raise EvidenceCollectionError(
            EvidenceErrorCode.NO_MERGE_BASE,
            "base and head commits do not have a merge base",
        )
    if completed.returncode != 0:
        _raise_command_failed(("merge-base", "--all", base_oid, head_oid), completed)
    merge_bases = _parse_merge_bases(completed.stdout, oid_length)
    if not merge_bases:
        raise EvidenceCollectionError(
            EvidenceErrorCode.NO_MERGE_BASE,
            "base and head commits do not have a merge base",
        )
    if len(merge_bases) != 1:
        raise EvidenceCollectionError(
            EvidenceErrorCode.AMBIGUOUS_MERGE_BASE,
            "base and head commits have multiple merge bases",
        )
    return merge_bases[0]


def _parse_merge_bases(output: bytes, oid_length: int) -> tuple[str, ...]:
    if not output:
        return ()
    if not output.endswith(b"\n"):
        raise EvidenceCollectionError(
            EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
            "merge-base output is not newline terminated",
        )
    lines = output[:-1].split(b"\n")
    return tuple(_parse_oid(line, oid_length) for line in lines)


def _read_raw_changes(
    object_format: str,
    object_directory: Path,
    merge_base_oid: str,
    head_oid: str,
    oid_length: int,
    *,
    _budget: _CollectionBudget | None = None,
) -> tuple[_RawChange, ...]:
    stdout_limit = _CONTROL_OUTPUT_BYTES if _budget is None else _RAW_CHANGE_OUTPUT_BYTES
    output = _run_object_git_required(
        object_format,
        object_directory,
        (
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-textconv",
            "--text",
            "--ignore-submodules=none",
            "--diff-algorithm=myers",
            "--no-indent-heuristic",
            "--find-renames=50%",
            "-l0",
            merge_base_oid,
            head_oid,
        ),
        attribute_source=head_oid,
        _budget=_budget,
        _stdout_limit=stdout_limit,
    )
    return _parse_raw_changes(output, oid_length, _budget=_budget)


def _parse_raw_changes(
    output: bytes,
    oid_length: int,
    *,
    _budget: _CollectionBudget | None = None,
) -> tuple[_RawChange, ...]:
    if not output:
        return ()
    if not output.endswith(b"\0"):
        _raise_malformed("raw diff is not NUL terminated")
    fields = output[:-1].split(b"\0")
    changes: list[_RawChange] = []
    index = 0
    while index < len(fields):
        _check_deadline(_budget)
        if _budget is not None and len(changes) >= _budget.limits.max_changed_files:
            _raise_resource_limit("changed file limit exceeded")
        header = fields[index]
        index += 1
        if not header.startswith(b":"):
            _raise_malformed("raw diff record does not start with ':'")
        parts = header[1:].split()
        if len(parts) != 5:
            _raise_malformed("raw diff record has an unexpected field count")
        old_mode_bytes, new_mode_bytes, old_oid_bytes, new_oid_bytes, status = parts
        old_mode = _parse_mode(old_mode_bytes)
        new_mode = _parse_mode(new_mode_bytes)
        old_oid = _parse_oid(old_oid_bytes, oid_length, allow_zero=True)
        new_oid = _parse_oid(new_oid_bytes, oid_length, allow_zero=True)
        change_type, similarity, path_count = _parse_status(status)
        if index + path_count > len(fields):
            _raise_malformed("raw diff record is missing a path")
        paths = tuple(_decode_path(path) for path in fields[index : index + path_count])
        index += path_count
        old_path, new_path = _paths_for_change(change_type, paths)
        _validate_absent_side(old_mode, old_oid, "old")
        _validate_absent_side(new_mode, new_oid, "new")
        _validate_change_sides(change_type, old_mode, new_mode)
        changes.append(
            _RawChange(
                change_type=change_type,
                rename_similarity=similarity,
                old_mode=old_mode,
                new_mode=new_mode,
                old_oid=old_oid,
                new_oid=new_oid,
                old_path=old_path,
                new_path=new_path,
            )
        )
    return tuple(changes)


def _parse_mode(mode: bytes) -> str:
    if _MODE_PATTERN.fullmatch(mode) is None:
        _raise_malformed("raw diff contains an invalid mode")
    return mode.decode("ascii")


def _parse_status(status: bytes) -> tuple[ChangeType, int | None, int]:
    if status == b"A":
        return ChangeType.ADDED, None, 1
    if status == b"M":
        return ChangeType.MODIFIED, None, 1
    if status == b"D":
        return ChangeType.DELETED, None, 1
    if status == b"T":
        return ChangeType.TYPE_CHANGED, None, 1
    if status.startswith(b"R") and status[1:].isdigit():
        similarity = int(status[1:])
        if 0 <= similarity <= 100:
            return ChangeType.RENAMED, similarity, 2
    _raise_malformed(f"raw diff contains an unsupported status: {status!r}")


def _paths_for_change(change_type: ChangeType, paths: tuple[str, ...]) -> tuple[str, str]:
    if change_type is ChangeType.RENAMED:
        if len(paths) != 2:
            _raise_malformed("rename record does not contain two paths")
        return paths[0], paths[1]
    if len(paths) != 1:
        _raise_malformed("file-change record does not contain one path")
    return paths[0], paths[0]


def _validate_absent_side(mode: str, oid: str, side: str) -> None:
    mode_absent = mode == "000000"
    oid_absent = set(oid) == {"0"}
    if mode_absent != oid_absent:
        _raise_malformed(f"{side} mode and object ID disagree about absence")


def _validate_change_sides(change_type: ChangeType, old_mode: str, new_mode: str) -> None:
    old_exists = old_mode != "000000"
    new_exists = new_mode != "000000"
    if change_type is ChangeType.ADDED:
        valid = not old_exists and new_exists
    elif change_type is ChangeType.DELETED:
        valid = old_exists and not new_exists
    else:
        valid = old_exists and new_exists
    if not valid:
        _raise_malformed("raw diff status disagrees with its present sides")


def _materialize_change(
    root: Path,
    raw: _RawChange,
    content_cache: dict[tuple[str, str], tuple[ContentKind, bytes | None]],
    *,
    _budget: _CollectionBudget | None = None,
) -> FileChangeEvidence:
    _check_deadline(_budget)
    old = _materialize_version(
        root,
        raw.old_path,
        raw.old_mode,
        raw.old_oid,
        content_cache,
        _budget=_budget,
    )
    new = _materialize_version(
        root,
        raw.new_path,
        raw.new_mode,
        raw.new_oid,
        content_cache,
        _budget=_budget,
    )
    existing_versions = tuple(version for version in (old, new) if version is not None)
    hunks: tuple[DiffHunkEvidence, ...] = ()
    if existing_versions and all(
        version.content_kind is ContentKind.TEXT for version in existing_versions
    ):
        old_content = _text_content(old, content_cache)
        new_content = _text_content(new, content_cache)
        patch = _read_patch(
            old_content,
            new_content,
            _budget=_budget,
        )
        hunks = _parse_hunks(patch, _budget=_budget)
        if _budget is not None and old_content != new_content and not hunks:
            _raise_malformed("Git diff reported different text blobs without a hunk")
    return FileChangeEvidence(
        change_type=raw.change_type,
        rename_similarity=raw.rename_similarity,
        old=old,
        new=new,
        hunks=hunks,
    )


def _materialize_version(
    root: Path,
    path: str,
    mode: str,
    oid: str,
    content_cache: dict[tuple[str, str], tuple[ContentKind, bytes | None]],
    *,
    _budget: _CollectionBudget | None = None,
) -> FileVersion | None:
    if mode == "000000":
        return None
    cache_key = _content_cache_key(mode, oid)
    cached_content = content_cache.get(cache_key)
    if cached_content is None:
        cached_content = _classify_content(root, mode, oid, _budget=_budget)
        content_cache[cache_key] = cached_content
    content_kind, _ = cached_content
    return FileVersion(path=path, mode=mode, oid=oid, content_kind=content_kind)


def _classify_content(
    root: Path,
    mode: str,
    oid: str,
    *,
    _budget: _CollectionBudget | None = None,
) -> tuple[ContentKind, bytes | None]:
    _check_deadline(_budget)
    is_symlink = mode == "120000"
    if is_symlink and _budget is None:
        return ContentKind.SYMLINK, None
    if mode == "160000":
        return ContentKind.SUBMODULE, None
    if not is_symlink and not mode.startswith("100"):
        return ContentKind.OTHER, None
    if _budget is None:
        content = _run_required(root, ("cat-file", "blob", oid))
    else:
        size_output = _run_required(
            root,
            ("cat-file", "-s", oid),
            _budget=_budget,
            _stdout_limit=_CONTROL_OUTPUT_BYTES,
        )
        size = _parse_blob_size(size_output)
        _reserve_blob_bytes(_budget, size)
        if is_symlink:
            return ContentKind.SYMLINK, None
        content = _run_required(
            root,
            ("cat-file", "blob", oid),
            _budget=_budget,
            _stdout_limit=size,
            _stdout_overflow_code=EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
        )
        if len(content) != size:
            _raise_malformed("Git blob size changed during collection")
    if b"\0" in content:
        return ContentKind.BINARY, None
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return ContentKind.BINARY, None
    return ContentKind.TEXT, content


def _text_content(
    version: FileVersion | None,
    content_cache: dict[tuple[str, str], tuple[ContentKind, bytes | None]],
) -> bytes:
    if version is None:
        return b""
    content_kind, content = content_cache[_content_cache_key(version.mode, version.oid)]
    if content_kind is not ContentKind.TEXT or content is None:
        _raise_malformed("text evidence is missing its cached blob content")
    return content


def _content_cache_key(mode: str, oid: str) -> tuple[str, str]:
    return ("regular", oid) if mode.startswith("100") else (mode, oid)


def _read_patch(
    old_content: bytes,
    new_content: bytes,
    *,
    _budget: _CollectionBudget | None = None,
) -> bytes:
    _check_deadline(_budget)
    if old_content == new_content:
        return b""
    if _budget is not None and _budget.diff_bytes >= _budget.limits.max_diff_bytes:
        _raise_resource_limit("diff byte limit exceeded")
    old_read, old_write, new_read, new_write = _open_patch_pipes()
    writer_errors: list[Exception] = []
    write_descriptors = (old_write, new_write)
    writer_stop_event = threading.Event()
    if _budget is None:
        writers = (
            threading.Thread(
                target=_write_pipe,
                args=(old_write, old_content, writer_errors),
                daemon=True,
            ),
            threading.Thread(
                target=_write_pipe,
                args=(new_write, new_content, writer_errors),
                daemon=True,
            ),
        )
    else:
        writers = (
            threading.Thread(
                target=_write_pipe_bounded,
                args=(
                    old_write,
                    old_content,
                    writer_errors,
                    writer_stop_event,
                    _budget,
                ),
                daemon=True,
            ),
            threading.Thread(
                target=_write_pipe_bounded,
                args=(
                    new_write,
                    new_content,
                    writer_errors,
                    writer_stop_event,
                    _budget,
                ),
                daemon=True,
            ),
        )
    started_writers = 0
    try:
        try:
            for writer in writers:
                writer.start()
                started_writers += 1
        except (OSError, RuntimeError) as error:
            raise EvidenceCollectionError(
                EvidenceErrorCode.GIT_COMMAND_FAILED,
                "patch writer threads could not be started",
            ) from error
        if _budget is None:
            completed = _invoke_no_index_diff(old_read, new_read)
        else:
            completed = _invoke_no_index_diff(
                old_read,
                new_read,
                _budget=_budget,
            )
    finally:
        writer_stop_event.set()
        os.close(old_read)
        os.close(new_read)
        started: list[threading.Thread] = []
        for index, writer in enumerate(writers):
            if index < started_writers:
                started.append(writer)
            else:
                os.close(write_descriptors[index])
        _join_threads(started, "patch writer threads did not stop")
    if writer_errors:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "text blob could not be sent to Git diff",
        ) from writer_errors[0]
    if completed.returncode != 1 or completed.stderr:
        _raise_command_failed(("diff", "--no-index"), completed)
    if _budget is not None:
        _reserve_diff_bytes(_budget, len(completed.stdout))
    if _budget is None and not _parse_hunks(completed.stdout):
        _raise_malformed("Git diff reported different text blobs without a hunk")
    if _budget is not None and not completed.stdout:
        _raise_malformed("Git diff reported different text blobs without a hunk")
    return completed.stdout


def _open_patch_pipes() -> tuple[int, int, int, int]:
    try:
        old_read, old_write = os.pipe()
    except OSError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "anonymous patch pipes could not be created",
        ) from error
    try:
        new_read, new_write = os.pipe()
    except OSError as error:
        os.close(old_read)
        os.close(old_write)
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "anonymous patch pipes could not be created",
        ) from error
    return old_read, old_write, new_read, new_write


def _write_pipe(file_descriptor: int, content: bytes, errors: list[Exception]) -> None:
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(content)
    except BrokenPipeError:
        pass
    except OSError as error:
        errors.append(error)


def _write_pipe_bounded(
    file_descriptor: int,
    content: bytes,
    errors: list[Exception],
    stop_event: threading.Event,
    budget: _CollectionBudget,
) -> None:
    offset = 0
    view = memoryview(content)
    try:
        os.set_blocking(file_descriptor, False)
        while offset < len(view):
            if stop_event.is_set():
                errors.append(OSError("bounded patch writer was cancelled"))
                return
            remaining = budget.deadline - time.monotonic()
            if remaining <= 0:
                errors.append(TimeoutError("bounded patch writer exceeded its deadline"))
                return
            try:
                written = os.write(
                    file_descriptor,
                    view[offset : offset + _READ_CHUNK_BYTES],
                )
            except BlockingIOError:
                stop_event.wait(min(_POLL_SECONDS, remaining))
                continue
            if written == 0:
                errors.append(OSError("bounded patch writer made no progress"))
                return
            offset += written
    except BrokenPipeError:
        pass
    except (OSError, ValueError) as error:
        errors.append(error)
    finally:
        with suppress(OSError):
            os.close(file_descriptor)


def _invoke_no_index_diff(
    old_file_descriptor: int,
    new_file_descriptor: int,
    *,
    _budget: _CollectionBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    descriptor_root = _descriptor_root()
    environment = _git_environment()
    environment.update(
        {
            "GIT_ATTR_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_DIR": str(_GIT_FACADE_ROOT / "sha1"),
        }
    )
    executable = "git" if _budget is None else _budget.git_executable
    command = [
        executable,
        "--literal-pathspecs",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"diff.orderFile={os.devnull}",
        "-c",
        "diff.suppressBlankEmpty=false",
        "diff",
        "--no-index",
        "--patch",
        "--text",
        "--unified=3",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--full-index",
        "--diff-algorithm=myers",
        "--no-indent-heuristic",
        "--inter-hunk-context=0",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--output-indicator-new=+",
        "--output-indicator-old=-",
        "--output-indicator-context= ",
        "--",
        f"{descriptor_root}/{old_file_descriptor}",
        f"{descriptor_root}/{new_file_descriptor}",
    ]
    if _budget is not None:
        stdout_limit = _budget.limits.max_diff_bytes - _budget.diff_bytes
        return _invoke_bounded_process(
            command,
            environment=environment,
            cwd=os.path.abspath(os.sep),
            pass_fds=(old_file_descriptor, new_file_descriptor),
            budget=_budget,
            stdout_limit=stdout_limit,
            stderr_limit=_CONTROL_OUTPUT_BYTES,
        )
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            cwd=os.path.abspath(os.sep),
            env=environment,
            pass_fds=(old_file_descriptor, new_file_descriptor),
        )
    except FileNotFoundError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_UNAVAILABLE,
            "Git executable is not available",
        ) from error
    except (OSError, ValueError) as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "Git no-index diff could not be started",
        ) from error


def _descriptor_root() -> str:
    for candidate in ("/dev/fd", "/proc/self/fd"):
        if Path(candidate).is_dir():
            return candidate
    raise EvidenceCollectionError(
        EvidenceErrorCode.GIT_COMMAND_FAILED,
        "anonymous file-descriptor paths are unavailable",
    )


def _parse_hunks(
    patch: bytes,
    *,
    _budget: _CollectionBudget | None = None,
) -> tuple[DiffHunkEvidence, ...]:
    hunks: list[DiffHunkEvidence] = []
    current_header: tuple[int, int, int, int] | None = None
    current_lines: list[DiffLineEvidence] = []
    old_line = 0
    new_line = 0

    def finish_current() -> None:
        nonlocal current_header, current_lines
        _check_deadline(_budget)
        if current_header is None:
            return
        old_start, old_count, new_start, new_count = current_header
        observed_old = sum(line.kind is not DiffLineKind.ADDITION for line in current_lines)
        observed_new = sum(line.kind is not DiffLineKind.DELETION for line in current_lines)
        if observed_old != old_count or observed_new != new_count:
            _raise_malformed("diff hunk line counts do not match its header")
        hunks.append(
            DiffHunkEvidence(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=tuple(current_lines),
            )
        )
        current_header = None
        current_lines = []

    for raw_line in _split_lf(patch):
        _check_deadline(_budget)
        header_match = _HUNK_PATTERN.match(raw_line)
        if header_match is not None:
            finish_current()
            old_start = int(header_match.group("old_start"))
            new_start = int(header_match.group("new_start"))
            old_count_group = header_match.group("old_count")
            new_count_group = header_match.group("new_count")
            old_count = 1 if old_count_group is None else int(old_count_group)
            new_count = 1 if new_count_group is None else int(new_count_group)
            current_header = (old_start, old_count, new_start, new_count)
            current_lines = []
            old_line = old_start
            new_line = new_start
            continue
        if current_header is None:
            continue
        if raw_line == _NO_NEWLINE_MARKER:
            if not current_lines:
                _raise_malformed("no-newline marker does not follow a diff line")
            current_lines[-1] = replace(
                current_lines[-1],
                has_trailing_newline=False,
            )
            continue
        if not raw_line:
            _raise_malformed("patch ends inside a hunk")
        marker = raw_line[:1]
        if marker == b" ":
            kind = DiffLineKind.CONTEXT
            old_number: int | None = old_line
            new_number: int | None = new_line
            old_line += 1
            new_line += 1
        elif marker == b"-":
            kind = DiffLineKind.DELETION
            old_number = old_line
            new_number = None
            old_line += 1
        elif marker == b"+":
            kind = DiffLineKind.ADDITION
            old_number = None
            new_number = new_line
            new_line += 1
        else:
            finish_current()
            continue
        if _budget is not None:
            _reserve_diff_line(_budget)
        payload = raw_line[1:]
        if payload.endswith(b"\n"):
            payload = payload[:-1]
        try:
            content = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceCollectionError(
                EvidenceErrorCode.MALFORMED_GIT_OUTPUT,
                "text patch contains invalid UTF-8",
            ) from error
        current_lines.append(
            DiffLineEvidence(
                kind=kind,
                old_line_number=old_number,
                new_line_number=new_number,
                content=content,
                has_trailing_newline=True,
            )
        )
    finish_current()
    return tuple(hunks)


def _split_lf(data: bytes) -> Iterator[bytes]:
    position = 0
    while position < len(data):
        newline = data.find(b"\n", position)
        if newline < 0:
            yield data[position:]
            return
        end = newline + 1
        yield data[position:end]
        position = end


def _change_sort_key(change: FileChangeEvidence) -> tuple[bytes, bytes]:
    primary = change.new.path if change.new is not None else change.old.path  # type: ignore[union-attr]
    secondary = change.old.path if change.old is not None else primary
    return primary.encode("utf-8"), secondary.encode("utf-8")


def _single_output_line(output: bytes, label: str) -> bytes:
    if not output.endswith(b"\n"):
        _raise_malformed(f"{label} output is not newline terminated")
    line = output[:-1]
    if not line or b"\n" in line or b"\0" in line:
        _raise_malformed(f"{label} output is not exactly one line")
    return line


def _single_path_output(output: bytes, label: str) -> bytes:
    if not output.endswith(b"\n"):
        _raise_malformed(f"{label} output is not newline terminated")
    path = output[:-1]
    if not path or b"\0" in path:
        _raise_malformed(f"{label} output is not exactly one path")
    return path


def _parse_oid(oid: bytes, oid_length: int, *, allow_zero: bool = False) -> str:
    if len(oid) != oid_length or any(byte not in b"0123456789abcdef" for byte in oid):
        _raise_malformed("Git output contains an invalid object ID")
    value = oid.decode("ascii")
    if not allow_zero and set(value) == {"0"}:
        _raise_malformed("Git output contains a zero object ID")
    return value


def _decode_path(path: bytes) -> str:
    try:
        return path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.UNSUPPORTED_PATH_ENCODING,
            "repository and changed paths must be valid UTF-8",
        ) from error


def _invoke_git_with_budget(
    root: Path,
    args: Sequence[str],
    *,
    budget: _CollectionBudget | None,
    stdout_limit: int,
    attribute_source: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if budget is None:
        if attribute_source is None:
            return _invoke_git(root, args)
        return _invoke_git(root, args, attribute_source=attribute_source)
    return _invoke_git(
        root,
        args,
        attribute_source=attribute_source,
        _budget=budget,
        _stdout_limit=stdout_limit,
    )


def _run_required(
    root: Path,
    args: Sequence[str],
    *,
    attribute_source: str | None = None,
    _budget: _CollectionBudget | None = None,
    _stdout_limit: int = _CONTROL_OUTPUT_BYTES,
    _stdout_overflow_code: EvidenceErrorCode = EvidenceErrorCode.RESOURCE_LIMIT,
) -> bytes:
    if _budget is None:
        completed = _invoke_git(root, args, attribute_source=attribute_source)
    else:
        completed = _invoke_git(
            root,
            args,
            attribute_source=attribute_source,
            _budget=_budget,
            _stdout_limit=_stdout_limit,
            _stdout_overflow_code=_stdout_overflow_code,
        )
    if completed.returncode != 0:
        _raise_command_failed(args, completed)
    return completed.stdout


def _run_object_git_required(
    object_format: str,
    object_directory: Path,
    args: Sequence[str],
    *,
    attribute_source: str,
    _budget: _CollectionBudget | None = None,
    _stdout_limit: int = _CONTROL_OUTPUT_BYTES,
) -> bytes:
    if _budget is None:
        completed = _invoke_object_git(
            object_format,
            object_directory,
            args,
            attribute_source=attribute_source,
        )
    else:
        completed = _invoke_object_git(
            object_format,
            object_directory,
            args,
            attribute_source=attribute_source,
            _budget=_budget,
            _stdout_limit=_stdout_limit,
        )
    if completed.returncode != 0:
        _raise_command_failed(args, completed)
    return completed.stdout


def _invoke_object_git(
    object_format: str,
    object_directory: Path,
    args: Sequence[str],
    *,
    attribute_source: str,
    _budget: _CollectionBudget | None = None,
    _stdout_limit: int = _CONTROL_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    environment = _git_environment(attribute_source=attribute_source)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_DIR": str(_GIT_FACADE_ROOT / object_format),
            "GIT_OBJECT_DIRECTORY": str(object_directory),
        }
    )
    executable = "git" if _budget is None else _budget.git_executable
    command = [
        executable,
        "--literal-pathspecs",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"diff.orderFile={os.devnull}",
        "-c",
        "diff.suppressBlankEmpty=false",
        *args,
    ]
    if _budget is not None:
        return _invoke_bounded_process(
            command,
            environment=environment,
            cwd=os.path.abspath(os.sep),
            budget=_budget,
            stdout_limit=_stdout_limit,
            stderr_limit=_CONTROL_OUTPUT_BYTES,
        )
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            cwd=os.path.abspath(os.sep),
            env=environment,
        )
    except FileNotFoundError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_UNAVAILABLE,
            "Git executable is not available",
        ) from error
    except (OSError, ValueError) as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            f"Git object command could not be started: {args[0]}",
        ) from error


def _invoke_git(
    root: Path,
    args: Sequence[str],
    *,
    attribute_source: str | None = None,
    _budget: _CollectionBudget | None = None,
    _stdout_limit: int = _CONTROL_OUTPUT_BYTES,
    _stdout_overflow_code: EvidenceErrorCode = EvidenceErrorCode.RESOURCE_LIMIT,
) -> subprocess.CompletedProcess[bytes]:
    environment = _git_environment(attribute_source=attribute_source)
    executable = "git" if _budget is None else _budget.git_executable
    command = [
        executable,
        "--literal-pathspecs",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"diff.orderFile={os.devnull}",
        "-c",
        "diff.suppressBlankEmpty=false",
        "-C",
        str(root),
        *args,
    ]
    if _budget is not None:
        return _invoke_bounded_process(
            command,
            environment=environment,
            cwd=None,
            budget=_budget,
            stdout_limit=_stdout_limit,
            stderr_limit=_CONTROL_OUTPUT_BYTES,
            stdout_overflow_code=_stdout_overflow_code,
        )
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
        )
    except FileNotFoundError as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_UNAVAILABLE,
            "Git executable is not available",
        ) from error
    except (OSError, ValueError) as error:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            f"Git command could not be started: {args[0]}",
        ) from error


def _git_environment(*, attribute_source: str | None = None) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("GIT_", "REPOGUARD_"))
    }
    environment.update(
        {
            "GIT_ATTR_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    if attribute_source is not None:
        environment["GIT_ATTR_SOURCE"] = attribute_source
    return environment


def _raise_command_failed(
    args: Sequence[str],
    completed: subprocess.CompletedProcess[bytes],
) -> Never:
    stderr = completed.stderr.decode("utf-8", "replace").strip()
    detail = f": {stderr}" if stderr else ""
    raise EvidenceCollectionError(
        EvidenceErrorCode.GIT_COMMAND_FAILED,
        f"Git command failed ({args[0]}){detail}",
    )


def _raise_malformed(message: str) -> Never:
    raise EvidenceCollectionError(EvidenceErrorCode.MALFORMED_GIT_OUTPUT, message)


def _raise_resource_limit(message: str) -> Never:
    raise EvidenceCollectionError(EvidenceErrorCode.RESOURCE_LIMIT, message)
