"""Regression tests for detached public failures in M5 Git primitives."""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

import repoguard._repair_git as git_module
from repoguard._repair_git import (
    _canonical_diff,
    _directory_stat,
    _export_candidate_projection,
    _GitResult,
    _materialize_candidate,
    _MaterializedCandidate,
    _open_materialized_candidate,
    _parse_tree_entry,
    _read_ascii_line,
    _read_git_path,
    _read_head_file,
    _read_numstat,
    _RepositoryIdentity,
    _require_destination,
    _require_free_space,
    _require_host_limits,
    _resolved_directory,
    _write_private_file,
)
from repoguard._repair_patch import _parse_wire_patch, _ParsedPatch
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairStage,
)

_GIT = Path("/usr/bin/git")


class _ExceptRaiseVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.handler_depth = 0
        self.lines: list[int] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.handler_depth += 1
        for statement in node.body:
            self.visit(statement)
        self.handler_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self.handler_depth and isinstance(node.func, ast.Name) and node.func.id == "_raise":
            self.lines.append(node.lineno)
        self.generic_visit(node)


def _source(tmp_path: Path) -> _RepositoryIdentity:
    root = tmp_path / "source"
    common = root / ".git"
    return _RepositoryIdentity(
        root,
        common,
        common,
        "sha1",
        "1" * 40,
        1,
        2,
        1,
        3,
        (),
        0,
        ("1" * 40,),
    )


def _candidate(tmp_path: Path) -> _MaterializedCandidate:
    source = _source(tmp_path)
    root = tmp_path / "missing-parent" / "candidate"
    return _MaterializedCandidate(
        source,
        root,
        root / ".git",
        root / ".git" / "repoguard-index",
        "diff\n",
        "2" * 40,
        "3" * 40,
        ("src/app.py",),
        1,
    )


def _assert_detached(
    action: Callable[[], object],
    code: RepairErrorCode,
    stage: RepairStage,
) -> None:
    with pytest.raises(RepairError) as captured:
        action()
    error = captured.value
    assert error.code is code
    assert error.stage is stage
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__


def test_exception_handlers_never_raise_public_repair_errors_directly() -> None:
    source = Path(git_module.__file__).read_text(encoding="utf-8")
    visitor = _ExceptRaiseVisitor()
    visitor.visit(ast.parse(source))
    assert visitor.lines == []


def test_input_application_and_parse_failures_are_detached(tmp_path: Path) -> None:
    source = _source(tmp_path)
    _assert_detached(
        lambda: _read_head_file(source, _GIT, "../escape.py"),
        RepairErrorCode.INVALID_PATH,
        RepairStage.INPUT,
    )
    _assert_detached(
        lambda: _open_materialized_candidate(
            source,
            _GIT,
            tmp_path / "candidate",
            canonical_diff="\ud800\n",
            tree_oid="2" * 40,
            commit_oid="3" * 40,
            changed_paths=("src/app.py",),
            changed_line_count=1,
        ),
        RepairErrorCode.PUBLICATION_FAILED,
        RepairStage.APPLICATION,
    )
    _assert_detached(
        lambda: _parse_tree_entry(
            "100644",
            "blob",
            b"9" * 5_000,
            RepairStage.MATERIALIZATION,
        ),
        RepairErrorCode.GIT_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _read_ascii_line(b"\xff\n", RepairStage.RECOVERY),
        RepairErrorCode.GIT_FAILED,
        RepairStage.RECOVERY,
    )


def test_git_output_decode_failures_are_detached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        git_module,
        "_run_required",
        lambda *_args, **_kwargs: _GitResult(0, b"\xff\n", b""),
    )
    _assert_detached(
        lambda: _canonical_diff(_GIT, tmp_path, "1" * 40, {}),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _read_numstat(
            _GIT,
            tmp_path,
            "1" * 40,
            {},
            git_module._DEFAULT_LIMITS,
        ),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _read_git_path(
            _GIT,
            tmp_path,
            ("rev-parse", "--show-toplevel"),
            RepairStage.RECOVERY,
        ),
        RepairErrorCode.GIT_FAILED,
        RepairStage.RECOVERY,
    )


def test_filesystem_failures_are_detached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    source = _source(tmp_path)
    _assert_detached(
        lambda: _resolved_directory(missing, RepairStage.INPUT),
        RepairErrorCode.GIT_FAILED,
        RepairStage.INPUT,
    )
    _assert_detached(
        lambda: _directory_stat(missing, RepairStage.RECOVERY),
        RepairErrorCode.GIT_FAILED,
        RepairStage.RECOVERY,
    )
    _assert_detached(
        lambda: _require_destination(missing / "candidate", source),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _require_free_space(missing, git_module._DEFAULT_LIMITS),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _require_host_limits(missing, git_module._DEFAULT_LIMITS),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )
    _assert_detached(
        lambda: _write_private_file(missing / "record", b"value"),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )

    monkeypatch.setattr(git_module, "_revalidate_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        git_module,
        "_require_destination",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(git_module, "_require_free_space", lambda *_args: None)
    _assert_detached(
        lambda: _materialize_candidate(
            source,
            _GIT,
            missing / "candidate",
            (_parsed_patch(),),
        ),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )

    monkeypatch.setattr(git_module, "_read_head_entries", lambda *_args, **_kwargs: ((), 0, ()))
    candidate = _candidate(tmp_path)
    candidate.root.mkdir(parents=True, mode=0o700)
    projection = candidate.root.parent / "candidate-input"
    projection.write_bytes(b"not a directory")
    _assert_detached(
        lambda: _export_candidate_projection(
            candidate,
            _GIT,
            projection,
        ),
        RepairErrorCode.MATERIALIZATION_FAILED,
        RepairStage.MATERIALIZATION,
    )


def _parsed_patch() -> _ParsedPatch:
    return _parse_wire_patch(
        "--- /dev/null\n+++ b/src/app.py\n@@ -0,0 +1 @@\n+new\n",
        allowed_paths=("src/app.py",),
        policy=RepairGenerationPolicy(
            RepairGenerationMode.DETERMINISTIC,
            None,
            None,
        ),
    )
