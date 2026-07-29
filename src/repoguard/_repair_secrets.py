"""Private-key boundaries for deterministic and mixed safe repair."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import NoReturn

from repoguard._repair_patch import _parse_wire_patch, _ParsedPatch
from repoguard._repair_paths import (
    _canonical_repository_paths,
    _validate_repository_path,
)
from repoguard._review import _PRIVATE_KEY_MARKER_PATTERN
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationPolicy,
    RepairStage,
    RepairState,
)

_REDACTION_SENTINEL = "[REDACTED_PRIVATE_KEY_MATERIAL]"
_MAX_ALLOWED_FILES = 32
_MAX_FINAL_FILE_BYTES = 16_777_216
_MAX_PROTECTED_LINES = 10_000
_NO_NEWLINE_MARKER = "\\ No newline at end of file\n"
_CANONICAL_HUNK_HEADER = re.compile(
    r"^@@ -(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? "
    r"\+(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? @@\n$"
)
_CANONICAL_INDEX_HEADER = re.compile(
    r"^index ([0-9a-f]{40}|[0-9a-f]{64})\.\."
    r"([0-9a-f]{40}|[0-9a-f]{64})(?: 100(?:644|755))?\n$"
)


@dataclass(frozen=True, slots=True)
class _RepairFileContent:
    """One complete ordinary file, or one prospective absent allowed path."""

    path: str
    content: bytes | None

    def __post_init__(self) -> None:
        if type(self.path) is not str:
            raise TypeError("path must be an exact string")
        if self.content is not None and type(self.content) is not bytes:
            raise TypeError("content must be exact bytes or None")


@dataclass(frozen=True, slots=True)
class _SelectedPrivateKeyRange:
    """One selected private-key finding reference projected onto exact HEAD."""

    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if type(self.path) is not str:
            raise TypeError("path must be an exact string")
        if (
            type(self.start_line) is not int
            or type(self.end_line) is not int
            or not 1 <= self.start_line <= self.end_line
        ):
            raise ValueError("selected private-key range is invalid")


@dataclass(frozen=True, slots=True)
class _PrivateKeyMatch:
    """One exact FIFO marker pairing before coordinate coalescing."""

    path: str
    label: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class _ProtectedPrivateKeyRange:
    """One unique old-side line range protected from provider and preview."""

    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class _SanitizedRepairFile:
    """A complete prompt-safe allowed-file projection."""

    path: str
    content: str | None

    @property
    def present(self) -> bool:
        return self.content is not None


@dataclass(frozen=True, slots=True)
class _PrivateKeyPlan:
    """Validated private-key projection used by candidate generation."""

    matches: tuple[_PrivateKeyMatch, ...]
    protected_ranges: tuple[_ProtectedPrivateKeyRange, ...]
    prompt_files: tuple[_SanitizedRepairFile, ...]
    deterministic_patch: _ParsedPatch | None


def _scan_private_key_ranges(
    path: str,
    content: bytes,
    *,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> tuple[_PrivateKeyMatch, ...]:
    """Scan one complete LF UTF-8 file with M2's exact FIFO semantics."""
    _validate_one_path(path, RepairErrorCode.INVALID_PATH, RepairStage.INPUT, state, session_id)
    text = _decode_lf_utf8(
        content,
        maximum_bytes=_MAX_FINAL_FILE_BYTES,
        limit_code=RepairErrorCode.RESOURCE_LIMIT,
        invalid_code=RepairErrorCode.INVALID_PATH,
        stage=RepairStage.INPUT,
        state=state,
        session_id=session_id,
    )
    return _paired_ranges(path, text)


def _prepare_private_key_plan(
    allowed_files: tuple[_RepairFileContent, ...],
    selected_ranges: tuple[_SelectedPrivateKeyRange, ...],
    *,
    policy: RepairGenerationPolicy,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> _PrivateKeyPlan:
    """Validate selected ranges and build sanitized prompt/patch projections."""
    if type(policy) is not RepairGenerationPolicy:
        raise TypeError("policy must be an exact RepairGenerationPolicy")
    paths = _validate_allowed_files(allowed_files, state, session_id)
    selected = _validate_selections(selected_ranges, paths, state, session_id)

    matches: list[_PrivateKeyMatch] = []
    decoded: dict[str, str | None] = {}
    for item in allowed_files:
        if item.content is None:
            decoded[item.path] = None
            continue
        text = _decode_lf_utf8(
            item.content,
            maximum_bytes=policy.max_file_bytes,
            limit_code=RepairErrorCode.RESOURCE_LIMIT,
            invalid_code=RepairErrorCode.INVALID_PATH,
            stage=RepairStage.INPUT,
            state=state,
            session_id=session_id,
        )
        decoded[item.path] = text
        matches.extend(_paired_ranges(item.path, text))

    matches.sort(key=_match_sort_key)
    protected = _unique_protected_ranges(matches)
    if set(selected) != {(item.path, item.start_line, item.end_line) for item in protected}:
        _raise_repair(
            RepairErrorCode.INVALID_TARGETS,
            RepairStage.INPUT,
            state,
            session_id,
        )

    coalesced = _coalesce_ranges(protected)
    prompt_files = tuple(
        _SanitizedRepairFile(
            item.path,
            _remove_ranges(decoded[item.path], coalesced.get(item.path, ())),
        )
        for item in allowed_files
    )
    patch_source = _deletion_patch_source(decoded, coalesced)
    deterministic_patch = (
        None
        if patch_source is None
        else _parse_wire_patch(
            patch_source,
            allowed_paths=paths,
            policy=policy,
        )
    )
    return _PrivateKeyPlan(
        tuple(matches),
        protected,
        prompt_files,
        deterministic_patch,
    )


def _validate_final_changed_files(
    changed_files: tuple[_RepairFileContent, ...],
    *,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> None:
    """Reject paired private-key material in complete final changed files."""
    if (
        type(changed_files) is not tuple
        or not 1 <= len(changed_files) <= _MAX_ALLOWED_FILES
        or any(type(item) is not _RepairFileContent for item in changed_files)
        or any(item.content is None for item in changed_files)
    ):
        _raise_repair(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.PATCH,
            state,
            session_id,
        )
    paths = tuple(item.path for item in changed_files)
    invalid_paths = False
    try:
        _canonical_repository_paths(
            paths,
            "changed_files",
            minimum=1,
            maximum=_MAX_ALLOWED_FILES,
        )
    except (TypeError, ValueError):
        invalid_paths = True
    if invalid_paths:
        _raise_repair(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.PATCH,
            state,
            session_id,
        )
    for item in changed_files:
        assert item.content is not None
        text = _decode_lf_utf8(
            item.content,
            maximum_bytes=_MAX_FINAL_FILE_BYTES,
            limit_code=RepairErrorCode.RESOURCE_LIMIT,
            invalid_code=RepairErrorCode.PATCH_INVALID,
            stage=RepairStage.PATCH,
            state=state,
            session_id=session_id,
        )
        if _paired_ranges(item.path, text):
            _raise_repair(
                RepairErrorCode.PATCH_INVALID,
                RepairStage.PATCH,
                state,
                session_id,
            )


def _redact_private_key_diff(
    canonical_diff: str,
    protected_ranges: tuple[_ProtectedPrivateKeyRange, ...],
    *,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> str:
    """Redact protected old-side hunk lines from a canonical Git diff."""
    protected = _protected_line_map(protected_ranges, state, session_id)
    lines = _canonical_diff_lines(canonical_diff, state, session_id)
    output: list[str] = []
    seen: set[tuple[str, int]] = set()
    cursor = 0
    previous_path: bytes | None = None

    while cursor < len(lines):
        file_start = cursor
        if not lines[cursor].startswith("diff --git "):
            _raise_patch(state, session_id)
        cursor += 1
        if cursor < len(lines) and lines[cursor].startswith("new file mode "):
            if lines[cursor] != "new file mode 100644\n":
                _raise_patch(state, session_id)
            cursor += 1
        index_match = (
            None if cursor >= len(lines) else _CANONICAL_INDEX_HEADER.fullmatch(lines[cursor])
        )
        if index_match is None or len(index_match.group(1)) != len(index_match.group(2)):
            _raise_patch(state, session_id)
        cursor += 1
        if cursor + 1 >= len(lines):
            _raise_patch(state, session_id)
        old_header = lines[cursor]
        new_header = lines[cursor + 1]
        path = _canonical_file_path(old_header, new_header, state, session_id)
        path_bytes = path.encode("utf-8")
        if previous_path is not None and path_bytes <= previous_path:
            _raise_patch(state, session_id)
        previous_path = path_bytes
        old_token = f"a/{path}"
        new_token = f"b/{path}"
        expected_diff_headers = {
            f"diff --git {old_token} {new_token}\n",
            f"diff --git {_quote_git_path(old_token)} {_quote_git_path(new_token)}\n",
        }
        if lines[file_start] not in expected_diff_headers:
            _raise_patch(state, session_id)
        output.extend(lines[file_start : cursor + 2])
        cursor += 2
        protected_lines = protected.get(path, frozenset())

        hunk_count = 0
        while cursor < len(lines) and lines[cursor].startswith("@@ "):
            hunk_count += 1
            header = lines[cursor]
            coordinates = _canonical_hunk_coordinates(header, state, session_id)
            output.append(header)
            cursor += 1
            old_line, old_count, _new_line, new_count = coordinates
            old_seen = 0
            new_seen = 0
            while old_seen < old_count or new_seen < new_count:
                if cursor >= len(lines):
                    _raise_patch(state, session_id)
                raw = lines[cursor]
                if raw == _NO_NEWLINE_MARKER or not raw:
                    _raise_patch(state, session_id)
                kind = raw[0]
                if kind == " ":
                    old_number = old_line + old_seen
                    if old_number in protected_lines:
                        _raise_patch(state, session_id)
                    old_seen += 1
                    new_seen += 1
                    rendered = raw
                elif kind == "-":
                    old_number = old_line + old_seen
                    old_seen += 1
                    if old_number in protected_lines:
                        rendered = f"-{_REDACTION_SENTINEL}\n"
                        seen.add((path, old_number))
                    else:
                        rendered = raw
                elif kind == "+":
                    new_seen += 1
                    rendered = raw
                else:
                    _raise_patch(state, session_id)
                if old_seen > old_count or new_seen > new_count:
                    _raise_patch(state, session_id)
                output.append(rendered)
                cursor += 1
                if cursor < len(lines) and lines[cursor] == _NO_NEWLINE_MARKER:
                    output.append(lines[cursor])
                    cursor += 1
        if hunk_count == 0:
            _raise_patch(state, session_id)
        if cursor < len(lines) and not lines[cursor].startswith("diff --git "):
            _raise_patch(state, session_id)

    expected = {
        (path, line_number)
        for path, line_numbers in protected.items()
        for line_number in line_numbers
    }
    if seen != expected:
        _raise_patch(state, session_id)
    return "".join(output)


def _validate_allowed_files(
    value: tuple[_RepairFileContent, ...],
    state: RepairState | None,
    session_id: str | None,
) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or not 1 <= len(value) <= _MAX_ALLOWED_FILES
        or any(type(item) is not _RepairFileContent for item in value)
    ):
        _raise_repair(
            RepairErrorCode.INVALID_PATH,
            RepairStage.INPUT,
            state,
            session_id,
        )
    paths = tuple(item.path for item in value)
    invalid = False
    try:
        canonical = _canonical_repository_paths(
            paths,
            "allowed_files",
            minimum=1,
            maximum=_MAX_ALLOWED_FILES,
        )
    except (TypeError, ValueError):
        invalid = True
        canonical = paths
    if invalid:
        _raise_repair(
            RepairErrorCode.INVALID_PATH,
            RepairStage.INPUT,
            state,
            session_id,
        )
    return canonical


def _validate_selections(
    value: tuple[_SelectedPrivateKeyRange, ...],
    allowed_paths: tuple[str, ...],
    state: RepairState | None,
    session_id: str | None,
) -> frozenset[tuple[str, int, int]]:
    if type(value) is not tuple or any(
        type(item) is not _SelectedPrivateKeyRange for item in value
    ):
        _raise_repair(
            RepairErrorCode.INVALID_TARGETS,
            RepairStage.INPUT,
            state,
            session_id,
        )
    coordinates: list[tuple[str, int, int]] = []
    for item in value:
        invalid = item.path not in allowed_paths
        try:
            _validate_repository_path(item.path)
        except (TypeError, ValueError):
            invalid = True
        if (
            invalid
            or type(item.start_line) is not int
            or type(item.end_line) is not int
            or not 1 <= item.start_line <= item.end_line
        ):
            _raise_repair(
                RepairErrorCode.INVALID_TARGETS,
                RepairStage.INPUT,
                state,
                session_id,
            )
        coordinates.append((item.path, item.start_line, item.end_line))
    if len(set(coordinates)) != len(coordinates):
        _raise_repair(
            RepairErrorCode.INVALID_TARGETS,
            RepairStage.INPUT,
            state,
            session_id,
        )
    return frozenset(coordinates)


def _decode_lf_utf8(
    content: bytes,
    *,
    maximum_bytes: int,
    limit_code: RepairErrorCode,
    invalid_code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> str:
    if type(content) is not bytes:
        raise TypeError("content must be exact bytes")
    if len(content) > maximum_bytes:
        _raise_repair(limit_code, stage, state, session_id)
    invalid = b"\x00" in content or b"\r" in content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        invalid = True
        text = ""
    if invalid:
        _raise_repair(invalid_code, stage, state, session_id)
    return text


def _paired_ranges(path: str, text: str) -> tuple[_PrivateKeyMatch, ...]:
    unmatched: dict[str, deque[int]] = defaultdict(deque)
    matches: list[_PrivateKeyMatch] = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if text == "":
        lines = []
    for line_number, line in enumerate(lines, start=1):
        for marker in _PRIVATE_KEY_MARKER_PATTERN.finditer(line):
            kind, label = marker.groups()
            if kind == "BEGIN":
                unmatched[label].append(line_number)
            elif unmatched[label]:
                matches.append(
                    _PrivateKeyMatch(
                        path,
                        label,
                        unmatched[label].popleft(),
                        line_number,
                    )
                )
    return tuple(sorted(matches, key=_match_sort_key))


def _unique_protected_ranges(
    matches: list[_PrivateKeyMatch],
) -> tuple[_ProtectedPrivateKeyRange, ...]:
    coordinates = {(item.path, item.start_line, item.end_line) for item in matches}
    return tuple(
        _ProtectedPrivateKeyRange(path, start, end)
        for path, start, end in sorted(
            coordinates,
            key=lambda item: (item[0].encode("utf-8"), item[1], item[2]),
        )
    )


def _coalesce_ranges(
    ranges: tuple[_ProtectedPrivateKeyRange, ...],
) -> dict[str, tuple[tuple[int, int], ...]]:
    pending: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for item in ranges:
        current = pending[item.path]
        if current and item.start_line <= current[-1][1] + 1:
            start, end = current[-1]
            current[-1] = (start, max(end, item.end_line))
        else:
            current.append((item.start_line, item.end_line))
    return {path: tuple(items) for path, items in pending.items()}


def _remove_ranges(
    text: str | None,
    ranges: tuple[tuple[int, int], ...],
) -> str | None:
    if text is None or not ranges:
        return text
    lines = _lf_lines(text)
    protected = {line_number for start, end in ranges for line_number in range(start, end + 1)}
    return "".join(
        line for line_number, line in enumerate(lines, start=1) if line_number not in protected
    )


def _deletion_patch_source(
    decoded: dict[str, str | None],
    ranges_by_path: dict[str, tuple[tuple[int, int], ...]],
) -> str | None:
    if not ranges_by_path:
        return None
    output: list[str] = []
    for path in sorted(ranges_by_path, key=lambda value: value.encode("utf-8")):
        text = decoded[path]
        if text is None:
            raise AssertionError("protected path cannot be absent")
        lines = _lf_lines(text)
        output.extend((f"--- a/{path}\n", f"+++ b/{path}\n"))
        deleted_before = 0
        for start, end in ranges_by_path[path]:
            count = end - start + 1
            new_start = start - deleted_before - 1
            output.append(f"@@ -{start},{count} +{new_start},0 @@\n")
            for line in lines[start - 1 : end]:
                if line.endswith("\n"):
                    output.append(f"-{line}")
                else:
                    output.extend((f"-{line}\n", _NO_NEWLINE_MARKER))
            deleted_before += count
    return "".join(output)


def _protected_line_map(
    value: tuple[_ProtectedPrivateKeyRange, ...],
    state: RepairState | None,
    session_id: str | None,
) -> dict[str, frozenset[int]]:
    if type(value) is not tuple or any(
        type(item) is not _ProtectedPrivateKeyRange for item in value
    ):
        _raise_repair(
            RepairErrorCode.INVALID_WORKFLOW,
            RepairStage.PATCH,
            state,
            session_id,
        )
    previous: tuple[bytes, int, int] | None = None
    pending: dict[str, set[int]] = defaultdict(set)
    total = 0
    for item in value:
        invalid = False
        path_bytes = b""
        try:
            _validate_repository_path(item.path)
            path_bytes = item.path.encode("utf-8")
        except (TypeError, ValueError):
            invalid = True
        key = (path_bytes, item.start_line, item.end_line)
        if (
            invalid
            or type(item.start_line) is not int
            or type(item.end_line) is not int
            or not 1 <= item.start_line <= item.end_line
            or (previous is not None and key <= previous)
        ):
            _raise_repair(
                RepairErrorCode.INVALID_WORKFLOW,
                RepairStage.PATCH,
                state,
                session_id,
            )
        previous = key
        before = len(pending[item.path])
        for line_number in range(item.start_line, item.end_line + 1):
            pending[item.path].add(line_number)
        total += len(pending[item.path]) - before
        if total > _MAX_PROTECTED_LINES:
            _raise_repair(
                RepairErrorCode.INVALID_WORKFLOW,
                RepairStage.PATCH,
                state,
                session_id,
            )
    return {path: frozenset(lines) for path, lines in pending.items()}


def _canonical_diff_lines(
    value: str,
    state: RepairState | None,
    session_id: str | None,
) -> list[str]:
    if type(value) is not str:
        _raise_patch(state, session_id)
    invalid = not value or not value.endswith("\n") or "\r" in value or "\x00" in value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        invalid = True
    lines = _lf_lines(value) if not invalid else []
    if invalid or any(not line.endswith("\n") for line in lines):
        _raise_patch(state, session_id)
    return lines


def _canonical_file_path(
    old_header: str,
    new_header: str,
    state: RepairState | None,
    session_id: str | None,
) -> str:
    if not old_header.startswith("--- ") or not new_header.startswith("+++ "):
        _raise_patch(state, session_id)
    old_value = old_header[4:-1]
    new_value = new_header[4:-1]
    path = _decode_git_path(new_value, "b/", state, session_id)
    if old_value != "/dev/null":
        old_path = _decode_git_path(old_value, "a/", state, session_id)
        if old_path != path:
            _raise_patch(state, session_id)
    invalid = False
    try:
        validated = _validate_repository_path(path)
    except (TypeError, ValueError):
        invalid = True
        validated = path
    if invalid:
        _raise_patch(state, session_id)
    return validated


def _decode_git_path(
    value: str,
    prefix: str,
    state: RepairState | None,
    session_id: str | None,
) -> str:
    token = value
    if value.startswith('"'):
        if len(value) < 2 or not value.endswith('"'):
            _raise_patch(state, session_id)
        inner = value[1:-1]
        decoded: list[str] = []
        cursor = 0
        while cursor < len(inner):
            character = inner[cursor]
            if character != "\\":
                decoded.append(character)
                cursor += 1
                continue
            if cursor + 1 >= len(inner) or inner[cursor + 1] != '"':
                _raise_patch(state, session_id)
            decoded.append('"')
            cursor += 2
        token = "".join(decoded)
    elif '"' in value:
        _raise_patch(state, session_id)
    if not token.startswith(prefix):
        _raise_patch(state, session_id)
    return token[len(prefix) :]


def _quote_git_path(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _canonical_hunk_coordinates(
    header: str,
    state: RepairState | None,
    session_id: str | None,
) -> tuple[int, int, int, int]:
    match = _CANONICAL_HUNK_HEADER.fullmatch(header)
    if match is None:
        _raise_patch(state, session_id)
    old_start = int(match.group(1))
    old_count = 1 if match.group(2) is None else int(match.group(2))
    new_start = int(match.group(3))
    new_count = 1 if match.group(4) is None else int(match.group(4))
    if (
        (old_count > 0 and old_start == 0)
        or (new_count > 0 and new_start == 0)
        or old_count == new_count == 0
    ):
        _raise_patch(state, session_id)
    return old_start, old_count, new_start, new_count


def _validate_one_path(
    path: str,
    code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> None:
    invalid = False
    try:
        _validate_repository_path(path)
    except (TypeError, ValueError):
        invalid = True
    if invalid:
        _raise_repair(code, stage, state, session_id)


def _lf_lines(value: str) -> list[str]:
    """Split only on LF while preserving every other Unicode code point."""
    if value == "":
        return []
    parts = value.split("\n")
    lines = [f"{part}\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _match_sort_key(value: _PrivateKeyMatch) -> tuple[bytes, int, int, bytes]:
    return (
        value.path.encode("utf-8"),
        value.start_line,
        value.end_line,
        value.label.encode("utf-8"),
    )


def _raise_patch(
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    _raise_repair(RepairErrorCode.PATCH_INVALID, RepairStage.PATCH, state, session_id)


def _raise_repair(
    code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    raise RepairError(code, stage, state, session_id) from None
