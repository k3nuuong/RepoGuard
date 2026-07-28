"""Hardened read-only Git evidence collection."""

from __future__ import annotations

import os
import re
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Never

from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    EvidenceCollectionError,
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


def _collect_evidence(
    repository: RepositoryInput,
    pull_request: PullRequestInput,
) -> EvidenceBundle:
    root = _resolve_worktree(repository.path)
    object_format = _read_object_format(root)
    object_directory = _read_object_directory(root)
    oid_length = _OBJECT_FORMAT_LENGTHS[object_format]
    base_oid = _resolve_ref(
        root,
        pull_request.base_ref,
        EvidenceErrorCode.INVALID_BASE_REF,
        oid_length,
    )
    head_oid = _resolve_ref(
        root,
        pull_request.head_ref,
        EvidenceErrorCode.INVALID_HEAD_REF,
        oid_length,
    )
    merge_base_oid = _resolve_merge_base(root, base_oid, head_oid, oid_length)
    raw_changes = _read_raw_changes(
        object_format,
        object_directory,
        merge_base_oid,
        head_oid,
        oid_length,
    )
    content_cache: dict[tuple[str, str], tuple[ContentKind, bytes | None]] = {}
    changes = tuple(
        sorted(
            (
                _materialize_change(
                    root,
                    raw_change,
                    content_cache,
                )
                for raw_change in raw_changes
            ),
            key=_change_sort_key,
        )
    )
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


def _resolve_worktree(path: Path) -> Path:
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

    completed = _invoke_git(candidate, ("rev-parse", "--show-toplevel"))
    if completed.returncode != 0:
        raise EvidenceCollectionError(
            EvidenceErrorCode.NOT_A_WORKTREE,
            f"repository path is not inside a Git worktree: {candidate}",
        )
    root_bytes = _single_path_output(completed.stdout, "worktree root")
    root_text = _decode_path(root_bytes)
    return Path(root_text)


def _read_object_format(root: Path) -> str:
    output = _run_required(root, ("rev-parse", "--show-object-format"))
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


def _read_object_directory(root: Path) -> Path:
    output = _run_required(
        root,
        ("rev-parse", "--path-format=absolute", "--git-path", "objects"),
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
) -> str:
    _validate_ref(ref, invalid_code)
    completed = _invoke_git(
        root,
        ("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"),
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


def _resolve_merge_base(root: Path, base_oid: str, head_oid: str, oid_length: int) -> str:
    completed = _invoke_git(root, ("merge-base", "--all", base_oid, head_oid))
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
) -> tuple[_RawChange, ...]:
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
    )
    return _parse_raw_changes(output, oid_length)


def _parse_raw_changes(output: bytes, oid_length: int) -> tuple[_RawChange, ...]:
    if not output:
        return ()
    if not output.endswith(b"\0"):
        _raise_malformed("raw diff is not NUL terminated")
    fields = output[:-1].split(b"\0")
    changes: list[_RawChange] = []
    index = 0
    while index < len(fields):
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
) -> FileChangeEvidence:
    old = _materialize_version(
        root,
        raw.old_path,
        raw.old_mode,
        raw.old_oid,
        content_cache,
    )
    new = _materialize_version(
        root,
        raw.new_path,
        raw.new_mode,
        raw.new_oid,
        content_cache,
    )
    existing_versions = tuple(version for version in (old, new) if version is not None)
    hunks: tuple[DiffHunkEvidence, ...] = ()
    if existing_versions and all(
        version.content_kind is ContentKind.TEXT for version in existing_versions
    ):
        patch = _read_patch(
            _text_content(old, content_cache),
            _text_content(new, content_cache),
        )
        hunks = _parse_hunks(patch)
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
) -> FileVersion | None:
    if mode == "000000":
        return None
    cache_key = (mode, oid)
    cached_content = content_cache.get(cache_key)
    if cached_content is None:
        cached_content = _classify_content(root, mode, oid)
        content_cache[cache_key] = cached_content
    content_kind, _ = cached_content
    return FileVersion(path=path, mode=mode, oid=oid, content_kind=content_kind)


def _classify_content(root: Path, mode: str, oid: str) -> tuple[ContentKind, bytes | None]:
    if mode == "120000":
        return ContentKind.SYMLINK, None
    if mode == "160000":
        return ContentKind.SUBMODULE, None
    if not mode.startswith("100"):
        return ContentKind.OTHER, None
    content = _run_required(root, ("cat-file", "blob", oid))
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
    content_kind, content = content_cache[(version.mode, version.oid)]
    if content_kind is not ContentKind.TEXT or content is None:
        _raise_malformed("text evidence is missing its cached blob content")
    return content


def _read_patch(old_content: bytes, new_content: bytes) -> bytes:
    if old_content == new_content:
        return b""
    old_read, old_write, new_read, new_write = _open_patch_pipes()
    writer_errors: list[OSError] = []
    write_descriptors = (old_write, new_write)
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
        completed = _invoke_no_index_diff(old_read, new_read)
    finally:
        os.close(old_read)
        os.close(new_read)
        for index, writer in enumerate(writers):
            if index < started_writers:
                writer.join()
            else:
                os.close(write_descriptors[index])
    if writer_errors:
        raise EvidenceCollectionError(
            EvidenceErrorCode.GIT_COMMAND_FAILED,
            "text blob could not be sent to Git diff",
        ) from writer_errors[0]
    if completed.returncode != 1 or completed.stderr:
        _raise_command_failed(("diff", "--no-index"), completed)
    if not _parse_hunks(completed.stdout):
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


def _write_pipe(file_descriptor: int, content: bytes, errors: list[OSError]) -> None:
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(content)
    except BrokenPipeError:
        pass
    except OSError as error:
        errors.append(error)


def _invoke_no_index_diff(
    old_file_descriptor: int,
    new_file_descriptor: int,
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
    command = [
        "git",
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


def _parse_hunks(patch: bytes) -> tuple[DiffHunkEvidence, ...]:
    hunks: list[DiffHunkEvidence] = []
    current_header: tuple[int, int, int, int] | None = None
    current_lines: list[DiffLineEvidence] = []
    old_line = 0
    new_line = 0

    def finish_current() -> None:
        nonlocal current_header, current_lines
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


def _split_lf(data: bytes) -> tuple[bytes, ...]:
    parts = data.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return tuple(lines)


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


def _run_required(
    root: Path,
    args: Sequence[str],
    *,
    attribute_source: str | None = None,
) -> bytes:
    completed = _invoke_git(root, args, attribute_source=attribute_source)
    if completed.returncode != 0:
        _raise_command_failed(args, completed)
    return completed.stdout


def _run_object_git_required(
    object_format: str,
    object_directory: Path,
    args: Sequence[str],
    *,
    attribute_source: str,
) -> bytes:
    completed = _invoke_object_git(
        object_format,
        object_directory,
        args,
        attribute_source=attribute_source,
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
    command = [
        "git",
        "--literal-pathspecs",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"diff.orderFile={os.devnull}",
        "-c",
        "diff.suppressBlankEmpty=false",
        *args,
    ]
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
) -> subprocess.CompletedProcess[bytes]:
    environment = _git_environment(attribute_source=attribute_source)
    command = [
        "git",
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
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
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
