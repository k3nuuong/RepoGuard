"""Fail-closed parser for the minimal provider repair patch grammar."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from repoguard._repair_paths import _canonical_repository_paths, _validate_repository_path
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationPolicy,
    RepairStage,
)

_HUNK_HEADER = re.compile(
    r"^@@ -(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? "
    r"\+(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? @@$"
)
_NO_NEWLINE_MARKER = "\\ No newline at end of file"


class _PatchLineKind(StrEnum):
    CONTEXT = "context"
    ADDITION = "addition"
    DELETION = "deletion"
    NO_NEWLINE = "no_newline"


@dataclass(frozen=True, slots=True)
class _PatchLine:
    kind: _PatchLineKind
    content: str


@dataclass(frozen=True, slots=True)
class _PatchHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[_PatchLine, ...]


@dataclass(frozen=True, slots=True)
class _PatchFile:
    path: str
    is_new: bool
    hunks: tuple[_PatchHunk, ...]


@dataclass(frozen=True, slots=True)
class _ParsedPatch:
    source: str
    files: tuple[_PatchFile, ...]
    changed_line_count: int


def _parse_wire_patch(
    patch: str,
    *,
    allowed_paths: tuple[str, ...],
    policy: RepairGenerationPolicy,
) -> _ParsedPatch:
    if type(policy) is not RepairGenerationPolicy:
        raise TypeError("policy must be an exact RepairGenerationPolicy")
    invalid_allowed_paths = False
    try:
        _canonical_repository_paths(allowed_paths, "allowed_paths", minimum=1, maximum=32)
    except (TypeError, ValueError):
        invalid_allowed_paths = True
    if invalid_allowed_paths:
        _raise_invalid()
    encoded = _validated_patch_bytes(patch, policy)
    lines = patch.splitlines(keepends=True)
    if not lines or sum(len(line.encode("utf-8")) for line in lines) != len(encoded):
        _raise_invalid()

    parsed_files: list[_PatchFile] = []
    changed_line_count = 0
    cursor = 0
    previous_path: str | None = None
    while cursor < len(lines):
        old_header = _strip_lf(lines[cursor])
        if not old_header.startswith("--- "):
            _raise_invalid()
        cursor += 1
        if cursor >= len(lines):
            _raise_invalid()
        new_header = _strip_lf(lines[cursor])
        if not new_header.startswith("+++ "):
            _raise_invalid()
        cursor += 1
        path, is_new = _parse_file_headers(old_header[4:], new_header[4:])
        if path not in allowed_paths:
            _raise_invalid()
        if previous_path is not None and path.encode("utf-8") <= previous_path.encode("utf-8"):
            _raise_invalid()
        previous_path = path
        if len(parsed_files) >= policy.max_patch_paths:
            _raise_limit()

        hunks: list[_PatchHunk] = []
        previous_old_end: int | None = None
        previous_new_end: int | None = None
        file_changed_lines = 0
        while cursor < len(lines) and lines[cursor].startswith("@@ "):
            header = _strip_lf(lines[cursor])
            cursor += 1
            coordinates = _parse_hunk_header(header)
            hunk_lines: list[_PatchLine] = []
            old_seen = 0
            new_seen = 0
            changed_seen = 0
            previous_was_content = False
            previous_was_marker = False
            while cursor < len(lines):
                raw = lines[cursor]
                if raw.startswith("@@ ") or raw.startswith("--- "):
                    break
                line = _parse_hunk_line(_strip_lf(raw))
                if line.kind is _PatchLineKind.NO_NEWLINE:
                    if not previous_was_content or previous_was_marker:
                        _raise_invalid()
                    previous_was_marker = True
                else:
                    previous_was_content = True
                    previous_was_marker = False
                    if line.kind is _PatchLineKind.CONTEXT:
                        old_seen += 1
                        new_seen += 1
                    elif line.kind is _PatchLineKind.ADDITION:
                        new_seen += 1
                        changed_seen += 1
                    else:
                        old_seen += 1
                        changed_seen += 1
                hunk_lines.append(line)
                cursor += 1
            old_start, old_count, new_start, new_count = coordinates
            if (
                not hunk_lines
                or old_seen != old_count
                or new_seen != new_count
                or changed_seen == 0
            ):
                _raise_invalid()
            if is_new and (old_start != 0 or old_count != 0 or old_seen != 0):
                _raise_invalid()
            if (old_count > 0 and old_start == 0) or (new_count > 0 and new_start == 0):
                _raise_invalid()
            old_end = old_start + old_count
            new_end = new_start + new_count
            if (
                previous_old_end is not None
                and previous_new_end is not None
                and (old_start < previous_old_end or new_start < previous_new_end)
            ):
                _raise_invalid()
            previous_old_end = old_end
            previous_new_end = new_end
            file_changed_lines += changed_seen
            changed_line_count += changed_seen
            if changed_line_count > policy.max_changed_lines:
                _raise_limit()
            hunks.append(_PatchHunk(old_start, old_count, new_start, new_count, tuple(hunk_lines)))
        if not hunks or file_changed_lines == 0:
            _raise_invalid()
        parsed_files.append(_PatchFile(path, is_new, tuple(hunks)))
        if cursor < len(lines) and not lines[cursor].startswith("--- "):
            _raise_invalid()

    if not parsed_files:
        _raise_invalid()
    return _ParsedPatch(patch, tuple(parsed_files), changed_line_count)


def _validated_patch_bytes(patch: str, policy: RepairGenerationPolicy) -> bytes:
    if type(patch) is not str:
        _raise_invalid()
    invalid_encoding = False
    try:
        encoded = patch.encode("utf-8")
    except UnicodeEncodeError:
        invalid_encoding = True
        encoded = b""
    if invalid_encoding:
        _raise_invalid()
    if len(encoded) > policy.max_patch_bytes:
        _raise_limit()
    if not encoded or not patch.endswith("\n") or "\r" in patch or "\x00" in patch:
        _raise_invalid()
    if any(
        character not in {"\n", "\t"} and unicodedata.category(character).startswith("C")
        for character in patch
    ):
        _raise_invalid()
    return encoded


def _parse_file_headers(old_value: str, new_value: str) -> tuple[str, bool]:
    if "\t" in old_value or "\t" in new_value:
        _raise_invalid()
    is_new = old_value == "/dev/null"
    if is_new:
        if not new_value.startswith("b/"):
            _raise_invalid()
        path = new_value[2:]
    else:
        if not old_value.startswith("a/") or not new_value.startswith("b/"):
            _raise_invalid()
        path = old_value[2:]
        if new_value[2:] != path:
            _raise_invalid()
    invalid = False
    try:
        _validate_repository_path(path)
    except (TypeError, ValueError):
        invalid = True
    if invalid:
        _raise_invalid()
    return path, is_new


def _parse_hunk_header(value: str) -> tuple[int, int, int, int]:
    match = _HUNK_HEADER.fullmatch(value)
    if match is None:
        _raise_invalid()
    invalid_coordinates = False
    try:
        old_start = int(match.group(1))
        old_count = 1 if match.group(2) is None else int(match.group(2))
        new_start = int(match.group(3))
        new_count = 1 if match.group(4) is None else int(match.group(4))
    except (ValueError, IndexError):
        invalid_coordinates = True
        old_start = old_count = new_start = new_count = 0
    if invalid_coordinates:
        _raise_invalid()
    return old_start, old_count, new_start, new_count


def _parse_hunk_line(value: str) -> _PatchLine:
    if value == _NO_NEWLINE_MARKER:
        return _PatchLine(_PatchLineKind.NO_NEWLINE, "")
    if not value:
        _raise_invalid()
    prefix = value[0]
    kinds = {
        " ": _PatchLineKind.CONTEXT,
        "+": _PatchLineKind.ADDITION,
        "-": _PatchLineKind.DELETION,
    }
    if prefix not in kinds:
        _raise_invalid()
    return _PatchLine(kinds[prefix], value[1:])


def _strip_lf(value: str) -> str:
    if not value.endswith("\n"):
        _raise_invalid()
    return value[:-1]


def _raise_invalid() -> NoReturn:
    raise RepairError(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH) from None


def _raise_limit() -> NoReturn:
    raise RepairError(RepairErrorCode.PATCH_LIMIT, RepairStage.PATCH) from None
