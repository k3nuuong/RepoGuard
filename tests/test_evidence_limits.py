"""Resource-boundary tests for optional evidence collection limits."""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import tracemalloc
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, cast

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import repoguard._git as git_evidence
from repoguard.evidence import (
    DiffHunkEvidence,
    EvidenceCollectionError,
    EvidenceCollectionLimits,
    EvidenceErrorCode,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
    evidence_to_json,
)

_MIB = 1024 * 1024
_LIMIT_PROPERTIES = settings(database=None, derandomize=True, max_examples=100)


def _git_environment() -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LANG": "C", "LC_ALL": "C"})
    return environment


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        env=_git_environment(),
    ).stdout


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=RepoGuard Tests",
        "-c",
        "user.email=repoguard@example.invalid",
        "commit",
        "-m",
        message,
    )


def _added_file_repository(
    tmp_path: Path,
    files: Mapping[str, bytes],
) -> tuple[RepositoryInput, PullRequestInput]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "anchor").write_bytes(b"base\n")
    _commit(root, "base")
    _git(root, "switch", "-c", "feature")
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _commit(root, "feature")
    return RepositoryInput(root), PullRequestInput(base_ref="main", head_ref="feature")


def _assert_resource_limit(
    repository: RepositoryInput,
    request: PullRequestInput,
    limits: EvidenceCollectionLimits,
) -> None:
    with pytest.raises(EvidenceCollectionError) as error_info:
        collect_evidence(repository, request, limits=limits)

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT


@_LIMIT_PROPERTIES
@example(
    max_changed_files=1,
    max_blob_bytes=1,
    max_total_blob_bytes=1,
    max_diff_bytes=1,
    max_diff_lines=1,
    timeout_milliseconds=1,
)
@example(
    max_changed_files=1_000,
    max_blob_bytes=2 * _MIB,
    max_total_blob_bytes=64 * _MIB,
    max_diff_bytes=16 * _MIB,
    max_diff_lines=131_072,
    timeout_milliseconds=60_000,
)
@given(
    max_changed_files=st.integers(min_value=1, max_value=1_000),
    max_blob_bytes=st.integers(min_value=1, max_value=2 * _MIB),
    max_total_blob_bytes=st.integers(min_value=1, max_value=64 * _MIB),
    max_diff_bytes=st.integers(min_value=1, max_value=16 * _MIB),
    max_diff_lines=st.integers(min_value=1, max_value=131_072),
    timeout_milliseconds=st.integers(min_value=1, max_value=60_000),
)
def test_generated_valid_limits_preserve_every_requested_ceiling(
    max_changed_files: int,
    max_blob_bytes: int,
    max_total_blob_bytes: int,
    max_diff_bytes: int,
    max_diff_lines: int,
    timeout_milliseconds: int,
) -> None:
    timeout = timeout_milliseconds / 1_000.0

    limits = EvidenceCollectionLimits(
        max_changed_files=max_changed_files,
        max_blob_bytes=max_blob_bytes,
        max_total_blob_bytes=max_total_blob_bytes,
        max_diff_bytes=max_diff_bytes,
        max_diff_lines=max_diff_lines,
        git_timeout_seconds=timeout,
    )

    assert limits == EvidenceCollectionLimits(
        max_changed_files=max_changed_files,
        max_blob_bytes=max_blob_bytes,
        max_total_blob_bytes=max_total_blob_bytes,
        max_diff_bytes=max_diff_bytes,
        max_diff_lines=max_diff_lines,
        git_timeout_seconds=timeout,
    )
    assert 1 <= limits.max_changed_files <= 1_000
    assert 1 <= limits.max_blob_bytes <= 2 * _MIB
    assert 1 <= limits.max_total_blob_bytes <= 64 * _MIB
    assert 1 <= limits.max_diff_bytes <= 16 * _MIB
    assert 1 <= limits.max_diff_lines <= 131_072
    assert 0.0 < limits.git_timeout_seconds <= 60.0
    assert (
        limits.max_changed_files,
        limits.max_blob_bytes,
        limits.max_total_blob_bytes,
        limits.max_diff_bytes,
        limits.max_diff_lines,
        limits.git_timeout_seconds,
    ) == (
        max_changed_files,
        max_blob_bytes,
        max_total_blob_bytes,
        max_diff_bytes,
        max_diff_lines,
        timeout,
    )


def test_default_limits_are_frozen_slotted_product_ceilings() -> None:
    limits = EvidenceCollectionLimits()

    assert limits == EvidenceCollectionLimits(
        max_changed_files=1_000,
        max_blob_bytes=2 * _MIB,
        max_total_blob_bytes=64 * _MIB,
        max_diff_bytes=16 * _MIB,
        max_diff_lines=131_072,
        git_timeout_seconds=60.0,
    )
    assert not hasattr(limits, "__dict__")
    with pytest.raises(FrozenInstanceError):
        setattr(limits, "max_changed_files", 1)  # noqa: B010 - exercise runtime freezing


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_changed_files", 0),
        ("max_changed_files", 1_001),
        ("max_changed_files", True),
        ("max_changed_files", 1.0),
        ("max_blob_bytes", 0),
        ("max_blob_bytes", 2 * _MIB + 1),
        ("max_total_blob_bytes", 0),
        ("max_total_blob_bytes", 64 * _MIB + 1),
        ("max_diff_bytes", 0),
        ("max_diff_bytes", 16 * _MIB + 1),
        ("max_diff_lines", 0),
        ("max_diff_lines", 131_073),
        ("max_diff_lines", True),
        ("max_diff_lines", 1.0),
        ("git_timeout_seconds", 0.0),
        ("git_timeout_seconds", 60.000_001),
        ("git_timeout_seconds", float("inf")),
        ("git_timeout_seconds", float("nan")),
        ("git_timeout_seconds", 1),
        ("git_timeout_seconds", True),
    ],
)
def test_limits_reject_out_of_range_and_non_exact_types(field: str, value: object) -> None:
    arguments: Any = {field: value}

    with pytest.raises(ValueError):
        EvidenceCollectionLimits(**arguments)


def test_collect_evidence_rejects_non_exact_limits_before_git_access(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="exact EvidenceCollectionLimits"):
        collect_evidence(
            RepositoryInput(tmp_path / "missing"),
            PullRequestInput(base_ref="main", head_ref="feature"),
            limits=cast(EvidenceCollectionLimits, object()),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("git_timeout_seconds", float("nan")),
        ("max_blob_bytes", 2 * _MIB + 1),
        ("max_diff_lines", 131_073),
    ],
)
def test_collect_evidence_revalidates_a_tampered_exact_limits_instance(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    limits = EvidenceCollectionLimits()
    object.__setattr__(limits, field, value)

    with pytest.raises(ValueError):
        collect_evidence(
            RepositoryInput(tmp_path / "missing"),
            PullRequestInput(base_ref="main", head_ref="feature"),
            limits=limits,
        )


def test_omitted_none_and_explicit_default_limits_are_canonically_identical(
    tmp_path: Path,
) -> None:
    repository, request = _added_file_repository(tmp_path, {"change.txt": b"content\n"})

    omitted = collect_evidence(repository, request)
    explicit_none = collect_evidence(repository, request, limits=None)
    explicit_defaults = collect_evidence(
        repository,
        request,
        limits=EvidenceCollectionLimits(),
    )

    assert evidence_to_json(omitted) == evidence_to_json(explicit_none)
    assert evidence_to_json(omitted) == evidence_to_json(explicit_defaults)


def test_fixed_git_executable_cannot_be_hijacked_through_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, request = _added_file_repository(tmp_path, {"change.txt": b"content\n"})
    real_git = shutil.which("git")
    assert real_git is not None
    fixed_log = tmp_path / "fixed-git-log"
    fixed_git = tmp_path / "fixed-git"
    fixed_git.write_text(
        "#!/bin/sh\n"
        f"printf x >> {shlex.quote(str(fixed_log))}\n"
        f'exec {shlex.quote(real_git)} "$@"\n',
        encoding="ascii",
    )
    fixed_git.chmod(0o700)
    hostile_directory = tmp_path / "hostile-bin"
    hostile_directory.mkdir()
    hostile_marker = tmp_path / "path-was-used"
    hostile_git = hostile_directory / "git"
    hostile_git.write_text(
        f"#!/bin/sh\nprintf hijacked > {shlex.quote(str(hostile_marker))}\nexit 99\n",
        encoding="ascii",
    )
    hostile_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile_directory))

    bundle = collect_evidence(
        repository,
        request,
        limits=EvidenceCollectionLimits(),
        git_executable=fixed_git,
    )

    assert len(bundle.changes) == 1
    assert bundle.changes[0].hunks
    assert len(fixed_log.read_text(encoding="ascii")) >= 8
    assert not hostile_marker.exists()


def test_fixed_git_executable_is_validated_before_repository_access(tmp_path: Path) -> None:
    repository = RepositoryInput(tmp_path / "missing-repository")
    request = PullRequestInput(base_ref="main", head_ref="feature")
    limits = EvidenceCollectionLimits()
    non_executable = tmp_path / "not-executable"
    non_executable.write_text("git", encoding="ascii")
    executable = tmp_path / "executable"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    executable.chmod(0o700)
    symbolic_link = tmp_path / "git-link"
    symbolic_link.symlink_to(executable)
    hard_link = tmp_path / "git-hardlink"
    os.link(executable, hard_link)

    for invalid in (
        Path("relative/git"),
        non_executable,
        symbolic_link,
        hard_link,
        tmp_path,
    ):
        with pytest.raises(ValueError, match="git_executable"):
            collect_evidence(
                repository,
                request,
                limits=limits,
                git_executable=invalid,
            )


def test_fixed_git_executable_requires_limits_and_a_path(tmp_path: Path) -> None:
    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    executable.chmod(0o700)
    repository = RepositoryInput(tmp_path / "missing-repository")
    request = PullRequestInput(base_ref="main", head_ref="feature")

    with pytest.raises(ValueError, match="requires explicit"):
        collect_evidence(repository, request, git_executable=executable)
    with pytest.raises(TypeError, match="must be a Path"):
        collect_evidence(
            repository,
            request,
            limits=EvidenceCollectionLimits(),
            git_executable=cast(Path, str(executable)),
        )


def test_changed_file_limit_accepts_exact_count_and_rejects_one_less(tmp_path: Path) -> None:
    repository, request = _added_file_repository(
        tmp_path,
        {"one.bin": b"a\0", "two.bin": b"b\0"},
    )
    exact = EvidenceCollectionLimits(
        max_changed_files=2,
        max_blob_bytes=2,
        max_total_blob_bytes=4,
        max_diff_bytes=1,
    )

    assert len(collect_evidence(repository, request, limits=exact).changes) == 2
    _assert_resource_limit(repository, request, replace(exact, max_changed_files=1))


def test_per_blob_limit_accepts_exact_size_and_rejects_one_less(tmp_path: Path) -> None:
    repository, request = _added_file_repository(tmp_path, {"blob.bin": b"abc\0"})
    exact = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=4,
        max_total_blob_bytes=4,
        max_diff_bytes=1,
    )

    assert len(collect_evidence(repository, request, limits=exact).changes) == 1
    _assert_resource_limit(repository, request, replace(exact, max_blob_bytes=3))


def test_symlink_blob_is_preflighted_and_counted_without_reading_its_body(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "anchor").write_bytes(b"base\n")
    _commit(root, "base")
    _git(root, "switch", "-c", "feature")
    oversized_target = b"x" * 5
    oid = subprocess.run(
        ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
        check=True,
        input=oversized_target,
        capture_output=True,
        env=_git_environment(),
    ).stdout.strip()
    _git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        "120000",
        oid.decode("ascii"),
        "large-link",
    )
    _git(
        root,
        "-c",
        "user.name=RepoGuard Tests",
        "-c",
        "user.email=repoguard@example.invalid",
        "commit",
        "-m",
        "feature",
    )
    repository = RepositoryInput(root)
    request = PullRequestInput(base_ref="main", head_ref="feature")
    exact = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=5,
        max_total_blob_bytes=5,
        max_diff_bytes=1,
    )

    bundle = collect_evidence(repository, request, limits=exact)

    assert bundle.changes[0].new is not None
    assert bundle.changes[0].new.content_kind.value == "symlink"
    _assert_resource_limit(repository, request, replace(exact, max_blob_bytes=4))


def test_zero_length_blob_accepts_a_zero_stdout_limit(tmp_path: Path) -> None:
    repository, request = _added_file_repository(tmp_path, {"empty.txt": b""})
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=1,
        max_total_blob_bytes=1,
        max_diff_bytes=1,
    )

    bundle = collect_evidence(repository, request, limits=limits)

    assert len(bundle.changes) == 1
    assert bundle.changes[0].new is not None
    assert bundle.changes[0].new.path == "empty.txt"


def test_deleted_zero_length_blob_accepts_a_zero_stdout_limit(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "empty.txt").write_bytes(b"")
    _commit(root, "base")
    _git(root, "switch", "-c", "feature")
    (root / "empty.txt").unlink()
    _commit(root, "feature")
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=1,
        max_total_blob_bytes=1,
        max_diff_bytes=1,
    )

    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref="main", head_ref="feature"),
        limits=limits,
    )

    assert len(bundle.changes) == 1
    assert bundle.changes[0].old is not None
    assert bundle.changes[0].old.path == "empty.txt"


def test_total_blob_limit_accepts_exact_sum_and_rejects_one_less(tmp_path: Path) -> None:
    repository, request = _added_file_repository(
        tmp_path,
        {"one.bin": b"a\0", "two.bin": b"bc\0"},
    )
    exact = EvidenceCollectionLimits(
        max_changed_files=2,
        max_blob_bytes=3,
        max_total_blob_bytes=5,
        max_diff_bytes=1,
    )

    assert len(collect_evidence(repository, request, limits=exact).changes) == 2
    _assert_resource_limit(repository, request, replace(exact, max_total_blob_bytes=4))


def test_same_git_blob_is_reserved_once_across_a_mode_change(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    changed = root / "changed.bin"
    changed.write_bytes(b"abc\0")
    _commit(root, "base")
    _git(root, "switch", "-c", "feature")
    changed.chmod(0o755)
    _commit(root, "feature")
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=4,
        max_total_blob_bytes=4,
        max_diff_bytes=1,
    )

    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref="main", head_ref="feature"),
        limits=limits,
    )

    assert len(bundle.changes) == 1


def test_aggregate_diff_limit_accepts_exact_sum_and_rejects_one_less(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, request = _added_file_repository(
        tmp_path,
        {"one.txt": b"one\n", "two.txt": b"two\n"},
    )
    patch = b"@@ -0,0 +1 @@\n+fixed\n"
    exact_diff_bytes = len(patch) * 2
    exact = EvidenceCollectionLimits(
        max_changed_files=2,
        max_blob_bytes=4,
        max_total_blob_bytes=8,
        max_diff_bytes=exact_diff_bytes,
    )

    def fixed_diff(
        old_file_descriptor: int,
        new_file_descriptor: int,
        *,
        _budget: git_evidence._CollectionBudget | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del _budget
        for file_descriptor in (old_file_descriptor, new_file_descriptor):
            while os.read(file_descriptor, 1024):
                pass
        return subprocess.CompletedProcess(
            ("git", "diff", "--no-index"),
            1,
            stdout=patch,
            stderr=b"",
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(git_evidence, "_invoke_no_index_diff", fixed_diff)
        assert len(collect_evidence(repository, request, limits=exact).changes) == 2
        _assert_resource_limit(
            repository,
            request,
            replace(exact, max_diff_bytes=exact_diff_bytes - 1),
        )


def _added_lines_patch(line_count: int) -> bytes:
    return f"@@ -0,0 +1,{line_count} @@\n".encode("ascii") + b"+\n" * line_count


def _diff_line_budget(line_limit: int) -> git_evidence._CollectionBudget:
    limits = EvidenceCollectionLimits(
        max_diff_lines=line_limit,
        git_timeout_seconds=5.0,
    )
    return git_evidence._CollectionBudget(limits, time.monotonic() + 5.0)


def test_diff_line_limit_accepts_exact_count_and_rejects_one_more() -> None:
    exact_lines = 4
    exact_budget = _diff_line_budget(exact_lines)

    hunks = git_evidence._parse_hunks(
        _added_lines_patch(exact_lines),
        _budget=exact_budget,
    )

    assert len(hunks) == 1
    assert len(hunks[0].lines) == exact_lines
    assert exact_budget.diff_lines == exact_lines

    overflow_budget = _diff_line_budget(exact_lines)
    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._parse_hunks(
            _added_lines_patch(exact_lines + 1),
            _budget=overflow_budget,
        )

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT
    assert overflow_budget.diff_lines == exact_lines


def test_diff_line_limit_is_aggregate_across_patches() -> None:
    exact_budget = _diff_line_budget(3)

    git_evidence._parse_hunks(_added_lines_patch(2), _budget=exact_budget)
    git_evidence._parse_hunks(_added_lines_patch(1), _budget=exact_budget)

    assert exact_budget.diff_lines == 3

    overflow_budget = _diff_line_budget(2)
    git_evidence._parse_hunks(_added_lines_patch(2), _budget=overflow_budget)
    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._parse_hunks(_added_lines_patch(1), _budget=overflow_budget)

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT
    assert overflow_budget.diff_lines == 2


@_LIMIT_PROPERTIES
@given(line_limit=st.integers(min_value=1, max_value=512))
def test_generated_diff_line_limit_enforces_exact_n_and_rejects_n_plus_one(
    line_limit: int,
) -> None:
    exact_budget = _diff_line_budget(line_limit)
    exact = git_evidence._parse_hunks(
        _added_lines_patch(line_limit),
        _budget=exact_budget,
    )

    assert sum(len(hunk.lines) for hunk in exact) == line_limit
    assert exact_budget.diff_lines == line_limit

    overflow_budget = _diff_line_budget(line_limit)
    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._parse_hunks(
            _added_lines_patch(line_limit + 1),
            _budget=overflow_budget,
        )

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT
    assert overflow_budget.diff_lines == line_limit


def test_dense_diff_rejects_early_without_whole_patch_line_copy() -> None:
    declared_lines = 262_144
    retained_lines = 1_024
    patch = _added_lines_patch(declared_lines)
    budget = _diff_line_budget(retained_lines)

    tracemalloc.start()
    try:
        with pytest.raises(EvidenceCollectionError) as error_info:
            git_evidence._parse_hunks(patch, _budget=budget)
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT
    assert budget.diff_lines == retained_lines
    # The input was allocated before tracing. A whole-patch split/list/tuple copy exceeds
    # this generous relative bound, while incremental line parsing remains far below it.
    assert peak_bytes < len(patch) * 16


def test_bounded_collection_materializes_each_patch_once_but_legacy_stays_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, request = _added_file_repository(tmp_path, {"change.txt": b"content\n"})
    real_parse_hunks = git_evidence._parse_hunks
    bounded_calls: list[bool] = []

    def observed_parse_hunks(
        patch: bytes,
        *,
        _budget: git_evidence._CollectionBudget | None = None,
    ) -> tuple[DiffHunkEvidence, ...]:
        bounded_calls.append(_budget is not None)
        return real_parse_hunks(patch, _budget=_budget)

    monkeypatch.setattr(git_evidence, "_parse_hunks", observed_parse_hunks)

    collect_evidence(repository, request, limits=EvidenceCollectionLimits())
    collect_evidence(repository, request)

    assert bounded_calls == [True, False, False]


def test_bounded_materialization_rejects_different_text_without_a_hunk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, request = _added_file_repository(tmp_path, {"change.txt": b"content\n"})

    def invalid_diff(
        old_file_descriptor: int,
        new_file_descriptor: int,
        *,
        _budget: git_evidence._CollectionBudget | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del _budget
        for file_descriptor in (old_file_descriptor, new_file_descriptor):
            while os.read(file_descriptor, 1_024):
                pass
        return subprocess.CompletedProcess(
            ("git", "diff", "--no-index"),
            1,
            stdout=b"not a hunk\n",
            stderr=b"",
        )

    monkeypatch.setattr(git_evidence, "_invoke_no_index_diff", invalid_diff)

    with pytest.raises(EvidenceCollectionError) as error_info:
        collect_evidence(repository, request, limits=EvidenceCollectionLimits())

    assert error_info.value.code is EvidenceErrorCode.MALFORMED_GIT_OUTPUT


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [(b"0\n", 0), (b"0004\n", 4), (b"2097152\n", 2 * _MIB)],
)
def test_blob_size_parser_accepts_unsigned_decimal_lines(encoded: bytes, expected: int) -> None:
    assert git_evidence._parse_blob_size(encoded) == expected


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\n",
        b"-1\n",
        b"+1\n",
        b"1 \n",
        b"1\x00\n",
        b"1\n2\n",
        b"9" * 5_000 + b"\n",
    ],
)
def test_blob_size_parser_maps_malformed_values_to_stable_error(encoded: bytes) -> None:
    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._parse_blob_size(encoded)

    assert error_info.value.code is EvidenceErrorCode.MALFORMED_GIT_OUTPUT


@pytest.mark.parametrize("body", [b"ab", b"abcd"])
def test_blob_body_under_and_over_read_are_malformed_git_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    fake_git = executable_directory / "git"
    fake_git.write_text(
        "#!/usr/bin/python3\n"
        "import os\n"
        "import sys\n"
        "if '-s' in sys.argv:\n"
        "    os.write(1, b'3\\n')\n"
        "else:\n"
        f"    os.write(1, bytes.fromhex('{body.hex()}'))\n",
        encoding="ascii",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable_directory))
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=3,
        max_total_blob_bytes=3,
        max_diff_bytes=1,
        git_timeout_seconds=2.0,
    )
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 2.0)

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._classify_content(
            tmp_path,
            "100644",
            "a" * 40,
            _budget=budget,
        )

    assert error_info.value.code is EvidenceErrorCode.MALFORMED_GIT_OUTPUT


def test_raw_change_output_budget_does_not_scale_down_with_file_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "p" * 20_000
    head_oid = "b" * 40
    raw = f":000000 100644 {'0' * 40} {head_oid} A".encode() + b"\0" + path.encode() + b"\0"
    observed_stdout_limits: list[int] = []

    def fake_run_object_git_required(
        object_format: str,
        object_directory: Path,
        arguments: Sequence[str],
        *,
        attribute_source: str,
        _budget: git_evidence._CollectionBudget | None = None,
        _stdout_limit: int = 1024 * 1024,
    ) -> bytes:
        del object_format, object_directory, arguments, attribute_source, _budget
        observed_stdout_limits.append(_stdout_limit)
        return raw

    monkeypatch.setattr(
        git_evidence,
        "_run_object_git_required",
        fake_run_object_git_required,
    )
    limits = EvidenceCollectionLimits(max_changed_files=1)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 1.0)

    changes = git_evidence._read_raw_changes(
        "sha1",
        tmp_path,
        "a" * 40,
        head_oid,
        40,
        _budget=budget,
    )

    assert observed_stdout_limits == [16 * _MIB]
    assert len(changes) == 1
    assert changes[0].new_path == path


def test_git_environment_strips_all_repoguard_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REPOGUARD_OPENAI_API_KEY", "openai-secret")
    monkeypatch.setenv("REPOGUARD_ANTHROPIC_API_KEY", "anthropic-secret")
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "github-secret")
    monkeypatch.setenv("REPOGUARD_UNRECOGNIZED_SECRET", "other-secret")
    monkeypatch.setenv("EVIDENCE_SAFE_VALUE", "preserved")

    environment = git_evidence._git_environment()

    assert not any(name.startswith("REPOGUARD_") for name in environment)
    assert environment["EVIDENCE_SAFE_VALUE"] == "preserved"


def test_oversized_blob_fails_after_size_preflight_without_reading_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oid = "a" * 40
    calls: list[tuple[str, ...]] = []

    def fake_run_required(
        root: Path,
        arguments: Sequence[str],
        *,
        attribute_source: str | None = None,
        _budget: git_evidence._CollectionBudget | None = None,
        _stdout_limit: int = 1024 * 1024,
    ) -> bytes:
        del root, attribute_source, _budget, _stdout_limit
        calls.append(tuple(arguments))
        return b"4\n"

    monkeypatch.setattr(git_evidence, "_run_required", fake_run_required)
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=3,
        max_total_blob_bytes=3,
        max_diff_bytes=1,
    )
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 1.0)

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._classify_content(
            tmp_path,
            "100644",
            oid,
            _budget=budget,
        )

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT
    assert calls == [("cat-file", "-s", oid)]


def test_bounded_runner_drains_stdout_and_stderr_without_pipe_deadlock() -> None:
    output_bytes = 128 * 1024
    limits = EvidenceCollectionLimits(git_timeout_seconds=2.0)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 2.0)
    script = (
        "import sys\n"
        f"sys.stdout.buffer.write(b'o' * {output_bytes})\n"
        "sys.stdout.buffer.flush()\n"
        f"sys.stderr.buffer.write(b'e' * {output_bytes})\n"
    )

    completed = git_evidence._invoke_bounded_process(
        (sys.executable, "-c", script),
        environment=os.environ.copy(),
        cwd=None,
        budget=budget,
        stdout_limit=output_bytes,
        stderr_limit=output_bytes,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"o" * output_bytes
    assert completed.stderr == b"e" * output_bytes


def test_bounded_runner_rejects_one_byte_over_stdout_limit() -> None:
    output_limit = 4_096
    limits = EvidenceCollectionLimits(git_timeout_seconds=2.0)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 2.0)
    script = f"import sys; sys.stdout.buffer.write(b'x' * {output_limit + 1})"

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._invoke_bounded_process(
            (sys.executable, "-c", script),
            environment=os.environ.copy(),
            cwd=None,
            budget=budget,
            stdout_limit=output_limit,
            stderr_limit=output_limit,
        )

    assert error_info.value.code is EvidenceErrorCode.RESOURCE_LIMIT


def test_bounded_runner_checks_deadline_before_late_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = EvidenceCollectionLimits(git_timeout_seconds=0.05)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 0.05)

    def delayed_wait(event: threading.Event, timeout: float | None = None) -> bool:
        del event, timeout
        time.sleep(0.15)
        return False

    monkeypatch.setattr(threading.Event, "wait", delayed_wait)

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._invoke_bounded_process(
            (sys.executable, "-c", "print('finished')"),
            environment=os.environ.copy(),
            cwd=None,
            budget=budget,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_TIMEOUT


def test_bounded_runner_reader_failure_stops_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = EvidenceCollectionLimits(git_timeout_seconds=2.0)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 2.0)

    def failed_read(file_descriptor: int, byte_count: int) -> bytes:
        del file_descriptor, byte_count
        raise OSError("synthetic reader failure")

    monkeypatch.setattr(os, "read", failed_read)
    started = time.monotonic()

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._invoke_bounded_process(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            environment=os.environ.copy(),
            cwd=None,
            budget=budget,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED
    assert time.monotonic() - started < 1.0


def test_bounded_runner_thread_start_failure_stops_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = EvidenceCollectionLimits(git_timeout_seconds=2.0)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 2.0)
    real_start = threading.Thread.start
    starts = 0

    def fail_second_start(thread: threading.Thread) -> None:
        nonlocal starts
        starts += 1
        if starts == 2:
            raise RuntimeError("synthetic thread start failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_second_start)
    started = time.monotonic()

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._invoke_bounded_process(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            environment=os.environ.copy(),
            cwd=None,
            budget=budget,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED
    assert time.monotonic() - started < 1.0


def test_shared_deadline_applies_across_multiple_short_git_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, request = _added_file_repository(tmp_path, {"change.bin": b"a\0"})
    real_git = shutil.which("git")
    assert real_git is not None
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    invocation_log = tmp_path / "git-invocations"
    fake_git = executable_directory / "git"
    fake_git.write_text(
        "#!/bin/sh\n"
        f"printf x >> {shlex.quote(str(invocation_log))}\n"
        "/bin/sleep 0.03\n"
        f'exec {shlex.quote(real_git)} "$@"\n',
        encoding="ascii",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable_directory))

    with pytest.raises(EvidenceCollectionError) as error_info:
        collect_evidence(
            repository,
            request,
            limits=EvidenceCollectionLimits(git_timeout_seconds=0.12),
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_TIMEOUT
    assert len(invocation_log.read_text(encoding="ascii")) >= 2


def test_deadline_kills_descendants_that_keep_output_pipes_open() -> None:
    limits = EvidenceCollectionLimits(git_timeout_seconds=0.1)
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 0.1)
    script = "import subprocess; subprocess.Popen(['/bin/sleep', '5'])"
    started = time.monotonic()

    with pytest.raises(EvidenceCollectionError) as error_info:
        git_evidence._invoke_bounded_process(
            (sys.executable, "-c", script),
            environment=os.environ.copy(),
            cwd=None,
            budget=budget,
            stdout_limit=1,
            stderr_limit=1,
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_TIMEOUT
    assert time.monotonic() - started < 2.0


def test_timeout_cancels_pipe_io_held_by_an_escaped_git_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    child_pid_path = tmp_path / "escaped-child-pid"
    fake_git = executable_directory / "git"
    fake_git.write_text(
        "#!/usr/bin/python3\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n"
        "fds = tuple(int(path.rsplit('/', 1)[1]) for path in sys.argv[-2:])\n"
        "child = subprocess.Popen(['/bin/sleep', '5'], pass_fds=fds, start_new_session=True)\n"
        "pid_path = Path(os.environ['EVIDENCE_TEST_PID_PATH'])\n"
        "pid_path.write_text(str(child.pid), encoding='ascii')\n",
        encoding="ascii",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable_directory))
    monkeypatch.setenv("EVIDENCE_TEST_PID_PATH", str(child_pid_path))
    limits = EvidenceCollectionLimits(
        max_changed_files=1,
        max_blob_bytes=2 * _MIB,
        max_total_blob_bytes=4 * _MIB,
        max_diff_bytes=1024,
        git_timeout_seconds=0.1,
    )
    budget = git_evidence._CollectionBudget(limits, time.monotonic() + 0.1)
    started = time.monotonic()

    try:
        with pytest.raises(EvidenceCollectionError) as error_info:
            git_evidence._read_patch(
                b"a" * (2 * _MIB),
                b"b" * (2 * _MIB),
                _budget=budget,
            )

        assert error_info.value.code is EvidenceErrorCode.GIT_TIMEOUT
        assert time.monotonic() - started < 1.0
    finally:
        if child_pid_path.exists():
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_shared_git_deadline_terminates_a_sleeping_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    fake_git = executable_directory / "git"
    fake_git.write_text("#!/bin/sh\nexec /bin/sleep 5\n", encoding="ascii")
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable_directory))
    started = time.monotonic()

    with pytest.raises(EvidenceCollectionError) as error_info:
        collect_evidence(
            RepositoryInput(tmp_path),
            PullRequestInput(base_ref="main", head_ref="feature"),
            limits=EvidenceCollectionLimits(git_timeout_seconds=0.05),
        )

    assert error_info.value.code is EvidenceErrorCode.GIT_TIMEOUT
    assert time.monotonic() - started < 2.0
