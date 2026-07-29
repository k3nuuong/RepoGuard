"""Focused tests for strict repair paths and provider patch parsing."""

from __future__ import annotations

from dataclasses import replace

import pytest

from repoguard._repair_patch import _parse_wire_patch, _ParsedPatch, _PatchLineKind
from repoguard._repair_paths import (
    _canonical_repository_paths,
    _validate_container_path,
    _validate_repository_path,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
)

_MODIFIED = """--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,2 @@
-old
+new
 keep
"""

_NEW = """--- /dev/null
+++ b/new file.py
@@ -0,0 +1,2 @@
+one
+two
"""


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)


def _parse(
    patch: str,
    *,
    allowed_paths: tuple[str, ...] = ("src/app.py",),
    policy: RepairGenerationPolicy | None = None,
) -> _ParsedPatch:
    return _parse_wire_patch(
        patch,
        allowed_paths=allowed_paths,
        policy=_policy() if policy is None else policy,
    )


def _assert_error(
    patch: str,
    code: RepairErrorCode,
    *,
    allowed_paths: tuple[str, ...] = ("src/app.py",),
    policy: RepairGenerationPolicy | None = None,
) -> None:
    with pytest.raises(RepairError) as captured:
        _parse(patch, allowed_paths=allowed_paths, policy=policy)
    assert captured.value.code is code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_parses_modified_new_and_multi_file_minimal_diffs() -> None:
    modified = _parse(_MODIFIED)
    assert modified.source == _MODIFIED
    assert modified.changed_line_count == 2
    assert modified.files[0].path == "src/app.py"
    assert modified.files[0].is_new is False
    assert tuple(line.kind for line in modified.files[0].hunks[0].lines) == (
        _PatchLineKind.DELETION,
        _PatchLineKind.ADDITION,
        _PatchLineKind.CONTEXT,
    )

    new = _parse(_NEW, allowed_paths=("new file.py",))
    assert new.changed_line_count == 2
    assert new.files[0].is_new is True

    multi = _parse(
        _NEW + _MODIFIED,
        allowed_paths=("new file.py", "src/app.py"),
    )
    assert tuple(file.path for file in multi.files) == ("new file.py", "src/app.py")
    assert multi.changed_line_count == 4


def test_accepts_unicode_internal_spaces_and_exact_no_newline_marker() -> None:
    patch = """--- a/源/旧 file.py
+++ b/源/旧 file.py
@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
    parsed = _parse(patch, allowed_paths=("源/旧 file.py",))
    assert parsed.files[0].path == "源/旧 file.py"
    assert parsed.changed_line_count == 2
    assert [line.kind for line in parsed.files[0].hunks[0].lines].count(
        _PatchLineKind.NO_NEWLINE
    ) == 2


@pytest.mark.parametrize(
    "patch",
    [
        _MODIFIED.replace("\n", "\r\n"),
        _MODIFIED.replace("old", "old\x00"),
        "diff --git a/src/app.py b/src/app.py\n" + _MODIFIED,
        "index 111..222 100644\n" + _MODIFIED,
        _MODIFIED.replace("@@ -1,2 +1,2 @@", "@@ -1,2 +1,2 @@ function"),
        _MODIFIED.replace("--- a/src/app.py", "--- a/src/app.py\t2026-01-01"),
        _MODIFIED.removesuffix("\n"),
        "",
    ],
)
def test_rejects_nonminimal_encoding_and_extended_headers(patch: str) -> None:
    _assert_error(patch, RepairErrorCode.PATCH_INVALID)


@pytest.mark.parametrize(
    ("patch", "allowed"),
    [
        (
            "--- a/src/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
            ("src/app.py",),
        ),
        (
            "--- a/src/app.py\n+++ b/src/renamed.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("src/app.py", "src/renamed.py"),
        ),
        (
            "--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-old\n+new\n",
            ("src/app.py",),
        ),
        (
            "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("src/app.py",),
        ),
        (
            "--- a/src\\app.py\n+++ b/src\\app.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("src/app.py",),
        ),
    ],
)
def test_rejects_delete_rename_and_unsafe_paths(patch: str, allowed: tuple[str, ...]) -> None:
    _assert_error(patch, RepairErrorCode.PATCH_INVALID, allowed_paths=allowed)


@pytest.mark.parametrize(
    "patch",
    [
        _MODIFIED.replace("@@ -1,2 +1,2 @@", "@@ -1,3 +1,2 @@"),
        _MODIFIED.replace("@@ -1,2 +1,2 @@", "@@ -0,2 +1,2 @@"),
        _NEW.replace("@@ -0,0 +1,2 @@", "@@ -1,0 +1,2 @@"),
        _MODIFIED.replace("-old\n", ""),
        _MODIFIED.replace(
            " keep\n",
            "\\ No newline at end of file\n\\ No newline at end of file\n",
        ),
        _MODIFIED.replace("-old\n", "?old\n"),
    ],
)
def test_rejects_malformed_hunks_and_markers(patch: str) -> None:
    _assert_error(patch, RepairErrorCode.PATCH_INVALID)


def test_requires_canonical_file_and_hunk_order() -> None:
    _assert_error(
        _MODIFIED + _NEW,
        RepairErrorCode.PATCH_INVALID,
        allowed_paths=("new file.py", "src/app.py"),
    )
    overlapping = """--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-a
+b
@@ -1 +1 @@
-c
+d
"""
    _assert_error(overlapping, RepairErrorCode.PATCH_INVALID)


def test_patch_byte_path_and_changed_line_boundaries() -> None:
    exact_bytes = replace(_policy(), max_patch_bytes=len(_MODIFIED.encode("utf-8")))
    assert _parse(_MODIFIED, policy=exact_bytes).changed_line_count == 2
    _assert_error(
        _MODIFIED,
        RepairErrorCode.PATCH_LIMIT,
        policy=replace(exact_bytes, max_patch_bytes=exact_bytes.max_patch_bytes - 1),
    )

    assert _parse(_MODIFIED, policy=replace(_policy(), max_changed_lines=2)).changed_line_count == 2
    _assert_error(
        _MODIFIED,
        RepairErrorCode.PATCH_LIMIT,
        policy=replace(_policy(), max_changed_lines=1),
    )

    _assert_error(
        _NEW + _MODIFIED,
        RepairErrorCode.PATCH_LIMIT,
        allowed_paths=("new file.py", "src/app.py"),
        policy=replace(_policy(), max_patch_paths=1),
    )


def test_path_boundaries_do_not_normalize_unicode() -> None:
    component = "x" * 255
    path = f"{component}/{component}/{component}"
    assert _validate_repository_path(path) == path
    assert _validate_repository_path("café.py") == "café.py"
    assert _validate_repository_path("café.py") == "café.py"
    assert len("café.py".encode()) != len("café.py".encode())
    with pytest.raises(ValueError):
        _validate_repository_path("x" * 256)
    with pytest.raises(ValueError):
        _validate_repository_path(f"{path}/y/{'z' * 255}")


def test_container_paths_and_allowed_path_tuple_are_exact() -> None:
    assert _validate_container_path("/workspace/repository") == "/workspace/repository"
    with pytest.raises(ValueError):
        _validate_container_path("/workspace/../etc")
    with pytest.raises(ValueError):
        _canonical_repository_paths(("z.py", "a.py"), "paths", minimum=1, maximum=2)
    with pytest.raises(ValueError):
        _canonical_repository_paths(("a.py", "a.py"), "paths", minimum=1, maximum=2)


def test_invalid_surrogate_is_detached_from_public_patch_error() -> None:
    _assert_error("\ud800\n", RepairErrorCode.PATCH_INVALID)
