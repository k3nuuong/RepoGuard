"""Focused adversarial tests for M5 private-key boundaries."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import repoguard._repair_secrets as secrets_module
from repoguard._repair_secrets import (
    _prepare_private_key_plan,
    _PrivateKeyMatch,
    _ProtectedPrivateKeyRange,
    _redact_private_key_diff,
    _RepairFileContent,
    _scan_private_key_ranges,
    _SelectedPrivateKeyRange,
    _validate_final_changed_files,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairStage,
    RepairState,
)

_LABELS = (
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)


def _file(path: str, content: str | None) -> _RepairFileContent:
    return _RepairFileContent(path, None if content is None else content.encode("utf-8"))


def _selection(path: str, start: int, end: int) -> _SelectedPrivateKeyRange:
    return _SelectedPrivateKeyRange(path, start, end)


def _assert_error(
    captured: pytest.ExceptionInfo[RepairError],
    code: RepairErrorCode,
    stage: RepairStage,
) -> None:
    error = captured.value
    assert error.code is code
    assert error.stage is stage
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__
    assert "SECRET-BYTES" not in str(error)


@pytest.mark.parametrize("label", _LABELS)
def test_scanner_reuses_every_m2_label_with_embedded_markers(label: str) -> None:
    content = (
        f'前缀 "-----BEGIN {label}-----"\nSECRET-BYTES\n"-----END {label}-----" 后缀\n'
    ).encode()

    assert _scan_private_key_ranges("密钥 file.pem", content) == (
        _PrivateKeyMatch("密钥 file.pem", label, 1, 3),
    )


def test_scanner_is_fifo_per_label_and_ignores_unpaired_or_mismatched_markers() -> None:
    content = """-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
-----END PRIVATE KEY-----
-----END EC PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY----- body -----END EC PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
"""

    assert _scan_private_key_ranges("keys.pem", content.encode()) == (
        _PrivateKeyMatch("keys.pem", "PRIVATE KEY", 2, 5),
        _PrivateKeyMatch("keys.pem", "RSA PRIVATE KEY", 3, 9),
        _PrivateKeyMatch("keys.pem", "PRIVATE KEY", 4, 6),
        _PrivateKeyMatch("keys.pem", "EC PRIVATE KEY", 8, 8),
    )


def test_same_line_multi_label_pair_is_protected_and_deleted_once() -> None:
    content = (
        "-----BEGIN PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY----- "
        "SECRET-BYTES -----END PRIVATE KEY----- -----END RSA PRIVATE KEY-----\n"
        "safe\n"
    )
    plan = _prepare_private_key_plan(
        (_file("keys.pem", content),),
        (_selection("keys.pem", 1, 1),),
        policy=_policy(),
    )

    assert len(plan.matches) == 2
    assert plan.protected_ranges == (_ProtectedPrivateKeyRange("keys.pem", 1, 1),)
    assert plan.prompt_files[0].content == "safe\n"
    assert plan.deterministic_patch is not None
    assert plan.deterministic_patch.changed_line_count == 1


def test_selected_ranges_must_exactly_cover_every_allowed_head_pair() -> None:
    files = (
        _file(
            "a.pem",
            "safe\n-----BEGIN PRIVATE KEY-----\nSECRET-BYTES\n-----END PRIVATE KEY-----\n",
        ),
        _file("new.pem", None),
    )
    plan = _prepare_private_key_plan(
        files,
        (_selection("a.pem", 2, 4),),
        policy=_policy(),
    )
    assert plan.protected_ranges == (_ProtectedPrivateKeyRange("a.pem", 2, 4),)

    for selected in (
        (),
        (_selection("a.pem", 2, 3),),
        (_selection("a.pem", 2, 4), _selection("a.pem", 2, 4)),
        (_selection("new.pem", 2, 4),),
    ):
        with pytest.raises(RepairError) as captured:
            _prepare_private_key_plan(files, selected, policy=_policy())
        _assert_error(captured, RepairErrorCode.INVALID_TARGETS, RepairStage.INPUT)


def test_unselected_second_pair_rejects_before_any_prompt_projection() -> None:
    files = (
        _file(
            "keys.pem",
            "-----BEGIN PRIVATE KEY-----\nSECRET-BYTES\n-----END PRIVATE KEY-----\n"
            "-----BEGIN RSA PRIVATE KEY-----\nOTHER\n-----END RSA PRIVATE KEY-----\n",
        ),
    )

    with pytest.raises(RepairError) as captured:
        _prepare_private_key_plan(
            files,
            (_selection("keys.pem", 1, 3),),
            policy=_policy(),
        )

    _assert_error(captured, RepairErrorCode.INVALID_TARGETS, RepairStage.INPUT)


def test_adjacent_selected_blocks_share_one_deterministic_hunk() -> None:
    content = (
        "-----BEGIN PRIVATE KEY----- one -----END PRIVATE KEY-----\n"
        "-----BEGIN RSA PRIVATE KEY----- two -----END RSA PRIVATE KEY-----\n"
        "safe\n"
    )
    plan = _prepare_private_key_plan(
        (_file("keys.pem", content),),
        (
            _selection("keys.pem", 1, 1),
            _selection("keys.pem", 2, 2),
        ),
        policy=_policy(),
    )

    assert plan.deterministic_patch is not None
    assert plan.deterministic_patch.source.count("@@ ") == 1
    assert "@@ -1,2 +0,0 @@\n" in plan.deterministic_patch.source
    assert plan.prompt_files[0].content == "safe\n"


def test_mixed_projection_coalesces_overlap_and_builds_strict_deletion_patch() -> None:
    content = """safe-before
-----BEGIN PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
SECRET-BYTES
-----END PRIVATE KEY-----
-----END PRIVATE KEY-----
safe-after
"""
    plan = _prepare_private_key_plan(
        (_file("keys.pem", content),),
        (
            _selection("keys.pem", 2, 5),
            _selection("keys.pem", 3, 6),
        ),
        policy=_policy(),
    )

    assert plan.prompt_files[0].content == "safe-before\nsafe-after\n"
    assert "PRIVATE KEY" not in plan.prompt_files[0].content
    assert "SECRET-BYTES" not in plan.prompt_files[0].content
    assert plan.deterministic_patch is not None
    assert plan.deterministic_patch.changed_line_count == 5
    assert (
        plan.deterministic_patch.source
        == """--- a/keys.pem
+++ b/keys.pem
@@ -2,5 +1,0 @@
------BEGIN PRIVATE KEY-----
------BEGIN PRIVATE KEY-----
-SECRET-BYTES
------END PRIVATE KEY-----
------END PRIVATE KEY-----
"""
    )


def test_deletion_patch_preserves_no_final_newline_marker() -> None:
    plan = _prepare_private_key_plan(
        (
            _file(
                "key.pem",
                "safe\n-----BEGIN PRIVATE KEY-----\nSECRET-BYTES\n-----END PRIVATE KEY-----",
            ),
        ),
        (_selection("key.pem", 2, 4),),
        policy=_policy(),
    )

    assert plan.prompt_files[0].content == "safe\n"
    assert plan.deterministic_patch is not None
    assert plan.deterministic_patch.source.endswith(
        "------END PRIVATE KEY-----\n\\ No newline at end of file\n"
    )


def test_complete_final_scan_rejects_key_assembled_across_patch_boundary() -> None:
    assembled = (
        "safe\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "SECRET-BYTES\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    with pytest.raises(RepairError) as captured:
        _validate_final_changed_files((_file("assembled.pem", assembled),))

    _assert_error(captured, RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)
    _validate_final_changed_files(
        (
            _file("unicode.txt", "普通 Unicode\n"),
            _file("unpaired.pem", "-----BEGIN PRIVATE KEY-----\nsafe\n"),
        )
    )


def test_clean_or_absent_allowed_files_need_no_private_patch() -> None:
    plan = _prepare_private_key_plan(
        (
            _file("clean.txt", ""),
            _file("future.txt", None),
        ),
        (),
        policy=_policy(),
    )

    assert plan.matches == ()
    assert plan.protected_ranges == ()
    assert plan.deterministic_patch is None
    assert plan.prompt_files[0].present
    assert not plan.prompt_files[1].present


def test_public_diff_redacts_only_protected_old_lines_and_keeps_markers() -> None:
    canonical = """diff --git a/key.pem b/key.pem
index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644
--- a/key.pem
+++ b/key.pem
@@ -1,4 +1,2 @@
 safe
------BEGIN PRIVATE KEY-----
-SECRET-BYTES
------END PRIVATE KEY-----
\\ No newline at end of file
+replacement
diff --git a/普通 file.txt b/普通 file.txt
index 3333333333333333333333333333333333333333..4444444444444444444444444444444444444444 100644
--- a/普通 file.txt
+++ b/普通 file.txt
@@ -1 +1 @@
-旧
+新
"""
    redacted = _redact_private_key_diff(
        canonical,
        (_ProtectedPrivateKeyRange("key.pem", 2, 4),),
    )

    assert "SECRET-BYTES" not in redacted
    assert "PRIVATE KEY-----" not in redacted
    assert redacted.count("-[REDACTED_PRIVATE_KEY_MATERIAL]\n") == 3
    assert "\\ No newline at end of file\n+replacement\n" in redacted
    assert "@@ -1,4 +1,2 @@\n" in redacted
    assert "-旧\n+新\n" in redacted


def test_public_diff_without_secrets_preserves_new_unicode_file_exactly() -> None:
    canonical = """diff --git a/new file.txt b/new file.txt
new file mode 100644
index 0000000000000000000000000000000000000000..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
--- /dev/null
+++ b/new file.txt
@@ -0,0 +1,2 @@
+普通\u2028line
+second
"""

    assert _redact_private_key_diff(canonical, ()) == canonical


def test_public_diff_accepts_git_quoted_safe_path() -> None:
    canonical = (
        'diff --git "a/quo\\"te.txt" "b/quo\\"te.txt"\n'
        "index 1111111111111111111111111111111111111111"
        "..2222222222222222222222222222222222222222 100644\n"
        '--- "a/quo\\"te.txt"\n'
        '+++ "b/quo\\"te.txt"\n'
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )

    assert _redact_private_key_diff(canonical, ()) == canonical


def test_public_diff_fails_closed_if_a_protected_line_is_context_or_missing() -> None:
    canonical = """diff --git a/key.pem b/key.pem
index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644
--- a/key.pem
+++ b/key.pem
@@ -1,2 +1,2 @@
 safe
 SECRET-BYTES
"""
    for ranges in (
        (_ProtectedPrivateKeyRange("key.pem", 2, 2),),
        (_ProtectedPrivateKeyRange("other.pem", 1, 1),),
    ):
        with pytest.raises(RepairError) as captured:
            _redact_private_key_diff(canonical, ranges)
        _assert_error(captured, RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)


def _simple_canonical_diff(path: str = "file.txt") -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 1111111111111111111111111111111111111111"
        "..2222222222222222222222222222222222222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )


@pytest.mark.parametrize(
    "canonical",
    [
        "not a diff\n",
        (
            "diff --git a/file.txt b/file.txt\n"
            "new file mode 100755\n"
            "index 0000000000000000000000000000000000000000"
            "..2222222222222222222222222222222222222222\n"
            "--- /dev/null\n"
            "+++ b/file.txt\n"
            "@@ -0,0 +1 @@\n"
            "+new\n"
        ),
        (
            "diff --git a/file.txt b/file.txt\n"
            "index 1..2 100644\n"
            "--- a/file.txt\n"
            "+++ b/file.txt\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        ),
        (
            "diff --git a/file.txt b/file.txt\n"
            "index 1111111111111111111111111111111111111111"
            "..2222222222222222222222222222222222222222 100644\n"
            "--- a/file.txt\n"
        ),
        _simple_canonical_diff().replace(
            "diff --git a/file.txt b/file.txt",
            "diff --git a/other.txt b/other.txt",
        ),
        _simple_canonical_diff().replace("@@ -1 +1 @@", "@@ -0,0 +0,0 @@"),
        _simple_canonical_diff().replace("@@ -1 +1 @@", "@@ -1 +1 @@ function"),
        _simple_canonical_diff().replace("-old\n+new\n", "\\ No newline at end of file\n"),
        _simple_canonical_diff().replace("-old\n+new\n", "?old\n+new\n"),
        _simple_canonical_diff().replace(
            "@@ -1 +1 @@\n-old\n+new\n",
            "@@ -1,1 +1,2 @@\n old\n extra\n",
        ),
        _simple_canonical_diff().replace("@@ -1 +1 @@\n-old\n+new\n", ""),
        f"{_simple_canonical_diff()}junk\n",
        f"{_simple_canonical_diff('z.txt')}{_simple_canonical_diff('a.txt')}",
    ],
)
def test_malformed_canonical_diff_is_never_returned(canonical: str) -> None:
    with pytest.raises(RepairError) as captured:
        _redact_private_key_diff(canonical, ())
    _assert_error(captured, RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)


@pytest.mark.parametrize(
    "canonical",
    [
        "",
        "no-final-lf",
        "bad\r\n",
        "bad\x00\n",
        "\ud800\n",
    ],
)
def test_canonical_diff_requires_nonempty_lf_utf8(canonical: str) -> None:
    with pytest.raises(RepairError) as captured:
        _redact_private_key_diff(canonical, ())
    _assert_error(captured, RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)


def test_redaction_rejects_invalid_or_excessive_protected_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = _simple_canonical_diff()
    invalid_ranges = (
        cast(tuple[_ProtectedPrivateKeyRange, ...], (object(),)),
        (_ProtectedPrivateKeyRange("../file.txt", 1, 1),),
        (
            _ProtectedPrivateKeyRange("z.txt", 1, 1),
            _ProtectedPrivateKeyRange("a.txt", 1, 1),
        ),
        (_ProtectedPrivateKeyRange("file.txt", 0, 1),),
    )
    for ranges in invalid_ranges:
        with pytest.raises(RepairError) as captured:
            _redact_private_key_diff(canonical, ranges)
        assert captured.value.code is RepairErrorCode.INVALID_WORKFLOW
        assert captured.value.stage is RepairStage.PATCH

    monkeypatch.setattr(secrets_module, "_MAX_PROTECTED_LINES", 2)
    with pytest.raises(RepairError) as captured:
        _redact_private_key_diff(
            canonical,
            (_ProtectedPrivateKeyRange("file.txt", 1, 3),),
        )
    assert captured.value.code is RepairErrorCode.INVALID_WORKFLOW


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"\xff", RepairErrorCode.INVALID_PATH),
        (b"line\r\n", RepairErrorCode.INVALID_PATH),
        (b"line\x00\n", RepairErrorCode.INVALID_PATH),
    ],
)
def test_head_scan_requires_complete_lf_utf8(content: bytes, code: RepairErrorCode) -> None:
    with pytest.raises(RepairError) as captured:
        _scan_private_key_ranges("key.pem", content)
    _assert_error(captured, code, RepairStage.INPUT)


def test_head_file_budget_rejects_without_truncation() -> None:
    policy = replace(_policy(), max_file_bytes=8)
    with pytest.raises(RepairError) as captured:
        _prepare_private_key_plan(
            (_RepairFileContent("key.pem", b"123456789"),),
            (),
            policy=policy,
        )
    _assert_error(captured, RepairErrorCode.RESOURCE_LIMIT, RepairStage.INPUT)


def test_private_record_and_input_shape_guards_are_exact() -> None:
    with pytest.raises(TypeError):
        _RepairFileContent(cast(str, 1), b"")
    with pytest.raises(TypeError):
        _RepairFileContent("file.txt", cast(bytes, bytearray()))
    with pytest.raises(TypeError):
        _SelectedPrivateKeyRange(cast(str, 1), 1, 1)
    with pytest.raises(ValueError):
        _SelectedPrivateKeyRange("file.txt", 0, 1)
    with pytest.raises(TypeError):
        _prepare_private_key_plan(
            (_file("file.txt", ""),),
            (),
            policy=cast(RepairGenerationPolicy, object()),
        )

    for files in (
        (),
        (_file("z.txt", ""), _file("a.txt", "")),
    ):
        with pytest.raises(RepairError) as captured:
            _prepare_private_key_plan(files, (), policy=_policy())
        assert captured.value.code is RepairErrorCode.INVALID_PATH

    with pytest.raises(RepairError) as captured:
        _prepare_private_key_plan(
            (_file("file.txt", ""),),
            cast(tuple[_SelectedPrivateKeyRange, ...], (object(),)),
            policy=_policy(),
        )
    assert captured.value.code is RepairErrorCode.INVALID_TARGETS

    with pytest.raises(RepairError) as captured:
        _prepare_private_key_plan(
            (_file("file.txt", ""),),
            (_selection("../file.txt", 1, 1),),
            policy=_policy(),
        )
    assert captured.value.code is RepairErrorCode.INVALID_TARGETS


def test_final_file_shape_encoding_and_resource_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for files in (
        (),
        (_file("file.txt", None),),
        (_file("z.txt", "safe\n"), _file("a.txt", "safe\n")),
    ):
        with pytest.raises(RepairError) as captured:
            _validate_final_changed_files(files)
        assert captured.value.code is RepairErrorCode.INVALID_WORKFLOW
        assert captured.value.stage is RepairStage.PATCH

    with pytest.raises(RepairError) as captured:
        _validate_final_changed_files((_RepairFileContent("file.txt", b"\xff"),))
    _assert_error(captured, RepairErrorCode.PATCH_INVALID, RepairStage.PATCH)

    monkeypatch.setattr(secrets_module, "_MAX_FINAL_FILE_BYTES", 4)
    with pytest.raises(RepairError) as captured:
        _validate_final_changed_files((_RepairFileContent("file.txt", b"12345"),))
    _assert_error(captured, RepairErrorCode.RESOURCE_LIMIT, RepairStage.PATCH)


def test_scanner_propagates_safe_session_fields_and_rejects_bad_path() -> None:
    session_id = "a" * 64
    with pytest.raises(RepairError) as captured:
        _scan_private_key_ranges(
            "../key.pem",
            b"SECRET-BYTES",
            state=RepairState.CREATED,
            session_id=session_id,
        )
    assert captured.value.code is RepairErrorCode.INVALID_PATH
    assert captured.value.stage is RepairStage.INPUT
    assert captured.value.state is RepairState.CREATED
    assert captured.value.session_id == session_id
    assert captured.value.__context__ is None


_SAFE_TEXT = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    max_size=24,
)


@given(
    prefix=st.lists(_SAFE_TEXT, max_size=8),
    body=_SAFE_TEXT,
    suffix=st.lists(_SAFE_TEXT, max_size=8),
)
@settings(max_examples=100, derandomize=True, deadline=None)
def test_sanitized_projection_preserves_all_nonprotected_unicode_lines(
    prefix: list[str],
    body: str,
    suffix: list[str],
) -> None:
    lines = [
        *prefix,
        "-----BEGIN PRIVATE KEY-----",
        body,
        "-----END PRIVATE KEY-----",
        *suffix,
    ]
    content = "".join(f"{line}\n" for line in lines)
    start = len(prefix) + 1
    plan = _prepare_private_key_plan(
        (_file("unicode.pem", content),),
        (_selection("unicode.pem", start, start + 2),),
        policy=_policy(),
    )

    expected = "".join(f"{line}\n" for line in (*prefix, *suffix))
    assert plan.prompt_files[0].content == expected
    assert "-----BEGIN PRIVATE KEY-----" not in expected
    assert "-----END PRIVATE KEY-----" not in expected
