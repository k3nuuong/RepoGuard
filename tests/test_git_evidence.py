"""Integration tests for committed, read-only Git evidence collection."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffLineKind,
    EvidenceCollectionError,
    EvidenceErrorCode,
    FileChangeEvidence,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
    evidence_to_json,
)


@dataclass(frozen=True, slots=True)
class _RepositoryGraph:
    root: Path
    merge_base_oid: str
    base_oid: str
    head_oid: str


def _git_environment() -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update({"LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"})
    return environment


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        env=_git_environment(),
    )


def _commit(root: Path, message: str, *, add_all: bool = True) -> str:
    if add_all:
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
    return _git(root, "rev-parse", "HEAD").stdout.decode("ascii").strip()


def _write(root: Path, relative_path: str, content: str) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_bytes(root: Path, relative_path: str, content: bytes) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _initialize_repository(root: Path) -> None:
    root.mkdir()
    _git(root, "init", "-b", "main")


def _build_repository_graph(tmp_path: Path) -> _RepositoryGraph:
    root = tmp_path / "repository"
    _initialize_repository(root)
    _write(root, "modified.txt", "one\n\nthree\nfour\nfive\n")
    _write(
        root,
        "separated.txt",
        "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\n"
        "line 7\nline 8\nline 9\nline 10\nline 11\nline 12\n",
    )
    _write(root, "deleted.txt", "delete me\n")
    _write(root, "rename-old.txt", "rename content\n")
    _write(root, "mode.txt", "executable\n")
    _write(root, "no-newline.txt", "first\nold")
    _write(root, "type-change", "regular file\n")
    merge_base_oid = _commit(root, "base")

    _git(root, "switch", "-c", "feature")
    _write(root, "modified.txt", "one\n\nchanged\nfour\nfive\n")
    _write(
        root,
        "separated.txt",
        "line 1\nchanged 2\nline 3\nline 4\nline 5\nline 6\n"
        "line 7\nline 8\nline 9\nline 10\nchanged 11\nline 12\n",
    )
    (root / "deleted.txt").unlink()
    (root / "rename-old.txt").rename(root / "rename-new.txt")
    (root / "mode.txt").chmod(0o755)
    _write(root, "no-newline.txt", "first\nnew")
    _write(root, "added.txt", "added\n")
    _write(root, ":(glob)*.txt", "literal pathspec\n")
    _write(root, "unicodé\nname.txt", "unicode path\n")
    _write_bytes(root, "binary.dat", b"prefix\0suffix")
    _write_bytes(root, "legacy.txt", b"\xff\n")
    os.symlink("added.txt", root / "link")
    (root / "type-change").unlink()
    os.symlink("added.txt", root / "type-change")
    _git(root, "add", "--all")
    _git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        merge_base_oid,
        "vendor/component",
    )
    head_oid = _commit(root, "feature", add_all=False)

    _git(root, "switch", "main")
    _write(root, "base-only.txt", "not in the pull request\n")
    base_oid = _commit(root, "base advances")
    return _RepositoryGraph(
        root=root,
        merge_base_oid=merge_base_oid,
        base_oid=base_oid,
        head_oid=head_oid,
    )


def _path_for(change: FileChangeEvidence) -> str:
    if change.new is not None:
        return change.new.path
    if change.old is not None:
        return change.old.path
    raise AssertionError("a file change must contain an old or new version")


def test_collects_merge_base_evidence_and_ignores_dirty_worktree(tmp_path: Path) -> None:
    graph = _build_repository_graph(tmp_path)
    request = PullRequestInput(base_ref="main", head_ref="feature")
    repository = RepositoryInput(path=graph.root)

    clean_bundle = collect_evidence(repository, request)
    clean_json = evidence_to_json(clean_bundle)

    assert clean_bundle.repository.root == graph.root.resolve()
    assert clean_bundle.repository.object_format == "sha1"
    assert clean_bundle.revisions.base_oid == graph.base_oid
    assert clean_bundle.revisions.head_oid == graph.head_oid
    assert clean_bundle.revisions.merge_base_oid == graph.merge_base_oid
    paths = [_path_for(change) for change in clean_bundle.changes]
    assert paths == sorted(paths, key=str.encode)
    assert "base-only.txt" not in paths

    changes = {_path_for(change): change for change in clean_bundle.changes}
    assert changes["added.txt"].change_type is ChangeType.ADDED
    assert changes["deleted.txt"].change_type is ChangeType.DELETED
    rename = changes["rename-new.txt"]
    assert rename.change_type is ChangeType.RENAMED
    assert rename.rename_similarity == 100
    assert rename.old is not None
    assert rename.old.path == "rename-old.txt"
    assert rename.new is not None
    assert rename.new.path == "rename-new.txt"

    modified = changes["modified.txt"]
    changed_lines = [
        line
        for hunk in modified.hunks
        for line in hunk.lines
        if line.kind is not DiffLineKind.CONTEXT
    ]
    assert [
        (line.kind, line.old_line_number, line.new_line_number, line.content)
        for line in changed_lines
    ] == [
        (DiffLineKind.DELETION, 3, None, "three"),
        (DiffLineKind.ADDITION, None, 3, "changed"),
    ]

    mode_change = changes["mode.txt"]
    assert mode_change.old is not None
    assert mode_change.old.mode == "100644"
    assert mode_change.new is not None
    assert mode_change.new.mode == "100755"
    assert mode_change.hunks == ()

    type_change = changes["type-change"]
    assert type_change.change_type is ChangeType.TYPE_CHANGED
    assert type_change.old is not None
    assert type_change.old.content_kind is ContentKind.TEXT
    assert type_change.new is not None
    assert type_change.new.content_kind is ContentKind.SYMLINK
    assert type_change.hunks == ()

    assert changes["binary.dat"].new is not None
    assert changes["binary.dat"].new.content_kind is ContentKind.BINARY
    assert changes["binary.dat"].hunks == ()
    assert changes["legacy.txt"].new is not None
    assert changes["legacy.txt"].new.content_kind is ContentKind.BINARY
    assert changes["legacy.txt"].hunks == ()
    assert changes["link"].new is not None
    assert changes["link"].new.content_kind is ContentKind.SYMLINK
    assert changes["vendor/component"].new is not None
    assert changes["vendor/component"].new.content_kind is ContentKind.SUBMODULE

    no_newline = changes["no-newline.txt"]
    changed_no_newline = [
        line
        for hunk in no_newline.hunks
        for line in hunk.lines
        if line.kind is not DiffLineKind.CONTEXT
    ]
    assert [line.has_trailing_newline for line in changed_no_newline] == [False, False]
    assert ":(glob)*.txt" in changes
    assert "unicodé\nname.txt" in changes

    _write(graph.root, ".gitattributes", "*.txt binary\n")
    (graph.root / ".git" / "info" / "attributes").write_text(
        "*.txt binary\n",
        encoding="utf-8",
    )
    (graph.root / ".git" / "info" / "grafts").write_text(
        f"{graph.head_oid}\n",
        encoding="ascii",
    )
    external_attributes = tmp_path / "external-attributes"
    external_attributes.write_text("*.txt binary\n", encoding="utf-8")
    _git(graph.root, "config", "core.attributesFile", str(external_attributes))
    _git(graph.root, "config", "diff.ignoreSubmodules", "all")
    _git(graph.root, "config", "diff.interHunkContext", "100")
    _git(graph.root, "config", "diff.orderFile", str(tmp_path / "missing-order-file"))
    _git(graph.root, "config", "diff.suppressBlankEmpty", "true")
    _write(graph.root, "base-only.txt", "dirty tracked content\n")
    _write(graph.root, "untracked.txt", "dirty untracked content\n")
    status_before = _git(
        graph.root,
        "-c",
        f"diff.orderFile={os.devnull}",
        "status",
        "--porcelain=v1",
        "-z",
    ).stdout

    dirty_bundle = collect_evidence(repository, request)
    status_after = _git(
        graph.root,
        "-c",
        f"diff.orderFile={os.devnull}",
        "status",
        "--porcelain=v1",
        "-z",
    ).stdout

    assert evidence_to_json(dirty_bundle) == clean_json
    assert status_after == status_before


def test_same_ref_produces_empty_evidence(tmp_path: Path) -> None:
    graph = _build_repository_graph(tmp_path)

    bundle = collect_evidence(
        RepositoryInput(graph.root),
        PullRequestInput(base_ref="main", head_ref="main"),
    )

    assert bundle.revisions.base_oid == graph.base_oid
    assert bundle.revisions.head_oid == graph.base_oid
    assert bundle.revisions.merge_base_oid == graph.base_oid
    assert bundle.changes == ()


def test_supports_sha256_objects_and_subdirectory_input(tmp_path: Path) -> None:
    root = tmp_path / "sha256"
    root.mkdir()
    _git(root, "init", "--object-format=sha256", "-b", "main")
    _write(root, "nested/file.txt", "base\n")
    base_oid = _commit(root, "base")
    _git(root, "switch", "-c", "feature")
    _write(root, "nested/file.txt", "feature\n")
    head_oid = _commit(root, "feature")

    bundle = collect_evidence(
        RepositoryInput(root / "nested"),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )

    assert bundle.repository.root == root.resolve()
    assert bundle.repository.object_format == "sha256"
    assert len(bundle.revisions.base_oid) == 64
    assert len(bundle.revisions.head_oid) == 64
    assert len(bundle.changes) == 1
    assert bundle.changes[0].new is not None
    assert bundle.changes[0].new.path == "nested/file.txt"


def test_supports_utf8_repository_root_with_newline(tmp_path: Path) -> None:
    root = tmp_path / "repository\nroot"
    _initialize_repository(root)
    _write(root, "file.txt", "base\n")
    base_oid = _commit(root, "base")
    _write(root, "file.txt", "head\n")
    head_oid = _commit(root, "head")

    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )

    assert bundle.repository.root == root.resolve()
    assert len(bundle.changes) == 1


def test_disables_repository_configured_external_diff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = _build_repository_graph(tmp_path)
    _git(graph.root, "switch", "feature")
    _write(graph.root, ".gitattributes", "*.txt diff=repoguard-test\n")
    _commit(graph.root, "configure diff attribute")
    _git(graph.root, "config", "diff.repoguard-test.command", "false")
    _git(graph.root, "config", "diff.repoguard-test.xfuncname", "[invalid")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "wrong-git-dir"))
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "false")

    bundle = collect_evidence(
        RepositoryInput(graph.root),
        PullRequestInput(base_ref="main", head_ref="feature"),
    )

    assert any(change.hunks for change in bundle.changes)


def test_similarity_rename_ignores_uncommitted_info_attributes(tmp_path: Path) -> None:
    root = tmp_path / "similarity-rename"
    _initialize_repository(root)
    original = "".join(f"line {number}\n" for number in range(100))
    _write(root, "old-name.txt", original)
    base_oid = _commit(root, "base")
    (root / "old-name.txt").rename(root / "new-name.txt")
    _write(root, "new-name.txt", original + "changed\n")
    head_oid = _commit(root, "rename and modify")
    info_attributes = root / ".git" / "info" / "attributes"
    os.mkfifo(info_attributes)
    script = """
import sys
from pathlib import Path
from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence, evidence_to_json

bundle = collect_evidence(
    RepositoryInput(Path(sys.argv[1])),
    PullRequestInput(base_ref=sys.argv[2], head_ref=sys.argv[3]),
)
print(evidence_to_json(bundle))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(root), base_oid, head_oid],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_git_environment(),
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        pytest.fail("evidence collection read the uncommitted info attributes FIFO")

    assert process.returncode == 0, stderr
    payload = json.loads(stdout)
    changes = payload["changes"]
    assert len(changes) == 1
    assert changes[0]["change_type"] == "renamed"
    assert 50 <= changes[0]["rename_similarity"] < 100


def test_reports_repository_and_revision_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(EvidenceCollectionError) as missing_error:
        collect_evidence(
            RepositoryInput(missing),
            PullRequestInput(base_ref="main", head_ref="feature"),
        )
    assert missing_error.value.code is EvidenceErrorCode.REPOSITORY_PATH_MISSING

    plain_directory = tmp_path / "plain"
    plain_directory.mkdir()
    with pytest.raises(EvidenceCollectionError) as worktree_error:
        collect_evidence(
            RepositoryInput(plain_directory),
            PullRequestInput(base_ref="main", head_ref="feature"),
        )
    assert worktree_error.value.code is EvidenceErrorCode.NOT_A_WORKTREE

    graph = _build_repository_graph(tmp_path)
    with pytest.raises(EvidenceCollectionError) as base_error:
        collect_evidence(
            RepositoryInput(graph.root),
            PullRequestInput(base_ref="missing", head_ref="feature"),
        )
    assert base_error.value.code is EvidenceErrorCode.INVALID_BASE_REF

    with pytest.raises(EvidenceCollectionError) as head_error:
        collect_evidence(
            RepositoryInput(graph.root),
            PullRequestInput(base_ref="main", head_ref="--help"),
        )
    assert head_error.value.code is EvidenceErrorCode.INVALID_HEAD_REF

    monkeypatch.setenv("PATH", "")
    with pytest.raises(EvidenceCollectionError) as git_error:
        collect_evidence(
            RepositoryInput(graph.root),
            PullRequestInput(base_ref="main", head_ref="feature"),
        )
    assert git_error.value.code is EvidenceErrorCode.GIT_UNAVAILABLE


def test_bare_and_unrelated_repositories_fail_atomically(tmp_path: Path) -> None:
    bare = tmp_path / "bare.git"
    bare.mkdir()
    _git(bare, "init", "--bare")
    with pytest.raises(EvidenceCollectionError) as bare_error:
        collect_evidence(
            RepositoryInput(bare),
            PullRequestInput(base_ref="main", head_ref="feature"),
        )
    assert bare_error.value.code is EvidenceErrorCode.NOT_A_WORKTREE

    root = tmp_path / "unrelated"
    _initialize_repository(root)
    _write(root, "main.txt", "main\n")
    _commit(root, "main")
    _git(root, "switch", "--orphan", "unrelated")
    _write(root, "unrelated.txt", "unrelated\n")
    _commit(root, "unrelated")

    with pytest.raises(EvidenceCollectionError) as merge_base_error:
        collect_evidence(
            RepositoryInput(root),
            PullRequestInput(base_ref="main", head_ref="unrelated"),
        )
    assert merge_base_error.value.code is EvidenceErrorCode.NO_MERGE_BASE
