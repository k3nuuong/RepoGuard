"""Focused tests for isolated repair Git materialization and publication."""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import pytest

import repoguard._repair_git as repair_git
from repoguard._repair_git import (
    _capture_repository,
    _export_candidate_projection,
    _GitLimits,
    _materialize_candidate,
    _open_materialized_candidate,
    _PublicationOutcome,
    _publish_repair_ref,
    _read_head_file,
    _read_materialized_files,
    _read_repair_ref,
)
from repoguard._repair_patch import _parse_wire_patch, _ParsedPatch
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairStage,
)

_GIT = Path("/usr/bin/git")
_CANDIDATE_ID = "a" * 64
_FOREIGN_ID = "b" * 64


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        (_GIT, "-C", root, *arguments),
        check=True,
        capture_output=True,
        input=input_bytes,
        env=environment,
    ).stdout


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Repair Test",
        "-c",
        "user.email=repair@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _repository(tmp_path: Path, *, object_format: str = "sha1") -> tuple[Path, str]:
    root = tmp_path / "source"
    root.mkdir(parents=True)
    _git(root, "init", "--quiet", f"--object-format={object_format}", "-b", "main")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    executable = root / "tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    head = _commit(root, "base")
    return root, head


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)


def _patch(source: str, allowed_paths: tuple[str, ...]) -> _ParsedPatch:
    return _parse_wire_patch(source, allowed_paths=allowed_paths, policy=_policy())


def _source_fingerprint(root: Path) -> tuple[str, bytes, bytes, bytes, tuple[str, ...]]:
    return (
        _git(root, "rev-parse", "HEAD").decode("ascii").strip(),
        _git(root, "status", "--porcelain=v1", "-z"),
        (root / ".git" / "config").read_bytes(),
        _git(root, "show-ref"),
        tuple(
            sorted(
                str(path.relative_to(root / ".git"))
                for path in (root / ".git" / "logs").rglob("*")
                if path.is_file()
            )
        ),
    )


def test_materializes_exact_head_with_fixed_commit_and_ignores_dirty_worktree(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    (root / "app.py").write_text("DIRTY\n", encoding="utf-8")
    (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    before = _source_fingerprint(root)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )

    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )

    assert source.object_format == "sha1"
    assert _read_head_file(source, _GIT, "app.py") == b"value = 1\n"
    assert _read_head_file(source, _GIT, "missing.py") is None
    assert candidate.changed_paths == ("app.py",)
    assert candidate.changed_line_count == 2
    assert _read_materialized_files(candidate, _GIT) == (
        repair_git._MaterializedFile("app.py", b"value = 2\n", False),
    )
    projection = candidate.root.parent / "candidate-input"
    assert _export_candidate_projection(candidate, _GIT, projection) == (
        repair_git._MaterializedFile("app.py", b"value = 2\n", False),
        repair_git._MaterializedFile("tool.sh", b"#!/bin/sh\nexit 0\n", True),
    )
    assert not (projection / ".git").exists()
    assert (projection / "app.py").read_bytes() == b"value = 2\n"
    assert stat_mode(projection / "app.py") == 0o400
    assert stat_mode(projection / "tool.sh") == 0o500
    assert (candidate.root / "app.py").read_text(encoding="utf-8") == "value = 2\n"
    assert "DIRTY" not in candidate.canonical_diff
    assert candidate.canonical_diff.endswith("-value = 1\n+value = 2\n")
    raw_commit = _git(candidate.root, "cat-file", "commit", candidate.commit_oid)
    assert raw_commit == (
        f"tree {candidate.tree_oid}\n"
        f"parent {head}\n"
        "author RepoGuard <repoguard@localhost> 0 +0000\n"
        "committer RepoGuard <repoguard@localhost> 0 +0000\n"
        "\n"
        "RepoGuard safe repair candidate\n"
    ).encode("ascii")
    _assert_hardened_candidate_tree(candidate.root, executable_paths={"tool.sh"})
    assert not any((candidate.git_dir / "hooks").iterdir())
    assert not (candidate.git_dir / "objects" / "info" / "alternates").exists()
    assert _git(candidate.root, "remote").strip() == b""
    assert (candidate.git_dir / "shallow").read_text(encoding="ascii") == f"{head}\n"
    assert _source_fingerprint(root) == before


def test_materialization_and_reads_stay_on_an_inherited_candidate_directory_fd(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    repository = private / "repository"
    repository.mkdir(mode=0o700)
    repository_fd = os.open(
        repository,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        fd_root = Path("/proc/self/fd") / str(repository_fd)
        candidate = _materialize_candidate(
            source,
            _GIT,
            fd_root,
            (parsed,),
            _destination_precreated=True,
        )
        displaced = private / "repository-displaced"
        repository.rename(displaced)
        repository.mkdir(mode=0o700)
        try:
            assert _read_materialized_files(candidate, _GIT) == (
                repair_git._MaterializedFile("app.py", b"value = 2\n", False),
            )
            assert not any(repository.iterdir())
        finally:
            repository.rmdir()
            displaced.rename(repository)
    finally:
        os.close(repository_fd)


def test_applies_new_and_second_patch_against_the_isolated_index(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    first = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py", "new file.py"),
    )
    second = _patch(
        """--- /dev/null
+++ b/new file.py
@@ -0,0 +1 @@
+created = True
""",
        ("app.py", "new file.py"),
    )

    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (first, second),
    )

    assert candidate.changed_paths == ("app.py", "new file.py")
    assert candidate.changed_line_count == 3
    assert (candidate.root / "new file.py").read_text(encoding="utf-8") == "created = True\n"
    assert _git(candidate.root, "diff", "--quiet", candidate.commit_oid, candidate.tree_oid) == b""


@pytest.mark.parametrize(
    "wire_patch",
    [
        """--- a/missing.py
+++ b/missing.py
@@ -1 +1 @@
-old
+new
""",
        """--- /dev/null
+++ b/app.py
@@ -0,0 +1 @@
+new
""",
    ],
)
def test_rejects_head_path_precondition_mismatch(tmp_path: Path, wire_patch: str) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(wire_patch, ("app.py", "missing.py"))

    with pytest.raises(RepairError) as captured:
        _materialize_candidate(
            source,
            _GIT,
            tmp_path / "candidate",
            (parsed,),
        )

    assert captured.value.code is RepairErrorCode.PATCH_INVALID
    assert captured.value.stage is RepairStage.PATCH
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    _assert_cleanup_compatible_candidate_tree(tmp_path / "candidate")


def test_head_and_host_limits_fail_closed(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    tiny_head = replace(_GitLimits(), max_head_entries=1)
    with pytest.raises(RepairError) as captured:
        _capture_repository(
            RepositoryInput(root),
            _GIT,
            head_oid=head,
            _limits=tiny_head,
        )
    assert captured.value.code is RepairErrorCode.RESOURCE_LIMIT

    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    tiny_host = replace(_GitLimits(), max_host_entries=1)
    with pytest.raises(RepairError) as host_error:
        _materialize_candidate(
            source,
            _GIT,
            tmp_path / "candidate",
            (parsed,),
            _limits=tiny_host,
        )
    assert host_error.value.code is RepairErrorCode.RESOURCE_LIMIT
    assert host_error.value.stage is RepairStage.MATERIALIZATION


def test_ref_only_publication_is_idempotent_and_preserves_foreign_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )
    with pytest.raises(ValueError):
        _open_materialized_candidate(
            source,
            _GIT,
            Path("relative"),
            canonical_diff=candidate.canonical_diff,
            tree_oid=candidate.tree_oid,
            commit_oid=candidate.commit_oid,
            changed_paths=candidate.changed_paths,
            changed_line_count=candidate.changed_line_count,
        )
    with pytest.raises(TypeError):
        _open_materialized_candidate(
            source,
            _GIT,
            candidate.root,
            canonical_diff=object(),  # type: ignore[arg-type]
            tree_oid=candidate.tree_oid,
            commit_oid=candidate.commit_oid,
            changed_paths=candidate.changed_paths,
            changed_line_count=candidate.changed_line_count,
        )
    with pytest.raises(RepairError) as invalid_diff:
        _open_materialized_candidate(
            source,
            _GIT,
            candidate.root,
            canonical_diff="",
            tree_oid=candidate.tree_oid,
            commit_oid=candidate.commit_oid,
            changed_paths=candidate.changed_paths,
            changed_line_count=candidate.changed_line_count,
        )
    assert invalid_diff.value.code is RepairErrorCode.PUBLICATION_FAILED
    with pytest.raises(RepairError) as invalid_paths:
        _open_materialized_candidate(
            source,
            _GIT,
            candidate.root,
            canonical_diff=candidate.canonical_diff,
            tree_oid=candidate.tree_oid,
            commit_oid=candidate.commit_oid,
            changed_paths=("../bad",),
            changed_line_count=candidate.changed_line_count,
        )
    assert invalid_paths.value.code is RepairErrorCode.PUBLICATION_FAILED
    with pytest.raises(RepairError) as missing_root:
        _open_materialized_candidate(
            source,
            _GIT,
            tmp_path / "missing-candidate",
            canonical_diff=candidate.canonical_diff,
            tree_oid=candidate.tree_oid,
            commit_oid=candidate.commit_oid,
            changed_paths=candidate.changed_paths,
            changed_line_count=candidate.changed_line_count,
        )
    assert missing_root.value.code is RepairErrorCode.PUBLICATION_FAILED
    candidate.root.chmod(0o755)
    try:
        with pytest.raises(RepairError) as permissions:
            _open_materialized_candidate(
                source,
                _GIT,
                candidate.root,
                canonical_diff=candidate.canonical_diff,
                tree_oid=candidate.tree_oid,
                commit_oid=candidate.commit_oid,
                changed_paths=candidate.changed_paths,
                changed_line_count=candidate.changed_line_count,
            )
        assert permissions.value.code is RepairErrorCode.PUBLICATION_FAILED
    finally:
        candidate.root.chmod(0o700)
    config_file = candidate.git_dir / "config"
    config_file.chmod(0o600)

    def unexpected_git(*_args: object, **_kwargs: object) -> repair_git._GitResult:
        raise AssertionError("candidate verification must precede Git execution")

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(repair_git, "_invoke_git", unexpected_git)
            with pytest.raises(RepairError) as nested_permissions:
                _open_materialized_candidate(
                    source,
                    _GIT,
                    candidate.root,
                    canonical_diff=candidate.canonical_diff,
                    tree_oid=candidate.tree_oid,
                    commit_oid=candidate.commit_oid,
                    changed_paths=candidate.changed_paths,
                    changed_line_count=candidate.changed_line_count,
                )
        assert nested_permissions.value.code is RepairErrorCode.PUBLICATION_FAILED
    finally:
        config_file.chmod(0o400)
    moved_index = candidate.index_file.with_name("moved-index")
    candidate.index_file.rename(moved_index)
    try:
        with pytest.raises(RepairError) as missing_index:
            _open_materialized_candidate(
                source,
                _GIT,
                candidate.root,
                canonical_diff=candidate.canonical_diff,
                tree_oid=candidate.tree_oid,
                commit_oid=candidate.commit_oid,
                changed_paths=candidate.changed_paths,
                changed_line_count=candidate.changed_line_count,
            )
        assert missing_index.value.code is RepairErrorCode.PUBLICATION_FAILED
    finally:
        moved_index.rename(candidate.index_file)
    before_head = _git(root, "rev-parse", "HEAD")
    before_status = _git(root, "status", "--porcelain=v1", "-z")
    before_config = (root / ".git" / "config").read_bytes()
    reopened = _open_materialized_candidate(
        source,
        _GIT,
        candidate.root,
        canonical_diff=candidate.canonical_diff,
        tree_oid=candidate.tree_oid,
        commit_oid=candidate.commit_oid,
        changed_paths=candidate.changed_paths,
        changed_line_count=candidate.changed_line_count,
    )

    original_invoke = repair_git._invoke_git
    observed_fds: list[tuple[tuple[str, ...], tuple[int, ...]]] = []

    def recording_invoke(
        git_executable: Path,
        invocation_root: Path | None,
        arguments: Sequence[str],
        *,
        stage: RepairStage,
        input_bytes: bytes | None = None,
        extra_environment: dict[str, str] | None = None,
        timeout_seconds: float = repair_git._GIT_TIMEOUT_SECONDS,
        stdout_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        stderr_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        inherited_fds: tuple[int, ...] = (),
    ) -> repair_git._GitResult:
        observed_fds.append((tuple(arguments), inherited_fds))
        return original_invoke(
            git_executable,
            invocation_root,
            arguments,
            stage=stage,
            input_bytes=input_bytes,
            extra_environment=extra_environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            inherited_fds=inherited_fds,
        )

    monkeypatch.setattr(repair_git, "_invoke_git", recording_invoke)
    with pytest.raises(TypeError):
        _publish_repair_ref(
            source,
            reopened,
            _GIT,
            _CANDIDATE_ID,
            inherited_lock_fd=True,
        )
    lock_fd = os.open(tmp_path / "session.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        published = _publish_repair_ref(
            source,
            reopened,
            _GIT,
            _CANDIDATE_ID,
            inherited_lock_fd=lock_fd,
        )
    finally:
        os.close(lock_fd)
    again = _publish_repair_ref(source, reopened, _GIT, _CANDIDATE_ID)

    assert published.outcome is _PublicationOutcome.PUBLISHED
    assert again.outcome is _PublicationOutcome.ALREADY_PRESENT
    for arguments, inherited_fds in observed_fds:
        referenced_fds = {
            int(match.group(2))
            for argument in arguments
            for match in repair_git._PROC_SELF_FD_PATTERN.finditer(argument)
        }
        assert referenced_fds.issubset(inherited_fds)
    push_fds = next(
        inherited_fds for arguments, inherited_fds in observed_fds if arguments[0] == "push"
    )
    assert lock_fd in push_fds
    assert len(push_fds) == 2
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID) == candidate.commit_oid
    assert _git(root, "rev-parse", "HEAD") == before_head
    assert _git(root, "status", "--porcelain=v1", "-z") == before_status
    assert (root / ".git" / "config").read_bytes() == before_config
    assert not (root / ".git" / "logs" / "refs" / "repoguard").exists()

    foreign_ref = f"refs/repoguard/repairs/{_FOREIGN_ID}"
    _git(root, "update-ref", foreign_ref, head)
    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _FOREIGN_ID)
    assert captured.value.code is RepairErrorCode.REF_CONFLICT
    assert captured.value.stage is RepairStage.APPLICATION
    assert _git(root, "rev-parse", foreign_ref).decode("ascii").strip() == head

    proc_receive = source.common_dir / "hooks" / "proc-receive"
    proc_receive.write_text('#!/bin/sh\n: > "$0.ran"\nexit 77\n', encoding="utf-8")
    proc_receive.chmod(0o700)
    _git(
        root,
        "config",
        "--add",
        "receive.procReceiveRefs",
        "refs/repoguard/repairs/",
    )
    configured_again = _publish_repair_ref(source, reopened, _GIT, _CANDIDATE_ID)
    assert configured_again.outcome is _PublicationOutcome.ALREADY_PRESENT
    assert not proc_receive.with_name("proc-receive.ran").exists()


def test_publication_disables_receive_hooks_and_server_side_effects(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )
    hooks = source.common_dir / "hooks"
    hook_names = (
        "pre-receive",
        "update",
        "post-receive",
        "post-update",
        "reference-transaction",
        "push-to-checkout",
    )
    for name in hook_names:
        hook = hooks / name
        hook.write_text('#!/bin/sh\n: > "$0.ran"\nexit 77\n', encoding="utf-8")
        hook.chmod(0o700)
    _git(root, "config", "core.hooksPath", str(hooks))
    _git(root, "config", "receive.updateServerInfo", "true")
    _git(root, "config", "core.logAllRefUpdates", "true")
    _git(root, "config", "gc.auto", "1")
    before = _source_fingerprint(root)
    before_index = (source.git_dir / "index").read_bytes()

    published = _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert published.outcome is _PublicationOutcome.PUBLISHED
    assert all(not (hooks / f"{name}.ran").exists() for name in hook_names)
    after = _source_fingerprint(root)
    assert after[:3] == before[:3]
    assert after[4] == before[4]
    assert (source.git_dir / "index").read_bytes() == before_index
    before_refs = set(before[3].decode("ascii").splitlines())
    after_refs = set(after[3].decode("ascii").splitlines())
    assert after_refs - before_refs == {
        f"{candidate.commit_oid} refs/repoguard/repairs/{_CANDIDATE_ID}"
    }
    assert before_refs <= after_refs


def test_publication_receive_pack_stays_on_the_pinned_common_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    original_invoke = repair_git._invoke_git
    displaced = tmp_path / "source-displaced"
    replacement = tmp_path / "source-replacement"

    def swapping_invoke(
        git_executable: Path,
        invocation_root: Path | None,
        arguments: Sequence[str],
        *,
        stage: RepairStage,
        input_bytes: bytes | None = None,
        extra_environment: dict[str, str] | None = None,
        timeout_seconds: float = repair_git._GIT_TIMEOUT_SECONDS,
        stdout_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        stderr_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        inherited_fds: tuple[int, ...] = (),
    ) -> repair_git._GitResult:
        if next(iter(arguments)) != "push":
            return original_invoke(
                git_executable,
                invocation_root,
                arguments,
                stage=stage,
                input_bytes=input_bytes,
                extra_environment=extra_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                inherited_fds=inherited_fds,
            )
        root.rename(displaced)
        shutil.copytree(displaced, root)
        try:
            return original_invoke(
                git_executable,
                invocation_root,
                arguments,
                stage=stage,
                input_bytes=input_bytes,
                extra_environment=extra_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                inherited_fds=inherited_fds,
            )
        finally:
            root.rename(replacement)
            displaced.rename(root)

    monkeypatch.setattr(repair_git, "_invoke_git", swapping_invoke)
    published = _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert published.outcome is _PublicationOutcome.PUBLISHED
    assert (
        _read_repair_ref(
            source,
            _GIT,
            _CANDIDATE_ID,
            expected_commit_oid=candidate.commit_oid,
        )
        == candidate.commit_oid
    )
    assert not (replacement / ".git" / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID).exists()


def test_publication_keeps_the_repair_namespace_pinned_through_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    original_invoke = repair_git._invoke_git
    namespace = source.common_dir / "refs" / "repoguard" / "repairs"
    displaced = source.common_dir / "refs" / "repoguard" / "repairs-displaced"
    transient = tmp_path / "transient-repairs"
    swapped = False

    def swapping_invoke(
        git_executable: Path,
        invocation_root: Path | None,
        arguments: Sequence[str],
        *,
        stage: RepairStage,
        input_bytes: bytes | None = None,
        extra_environment: dict[str, str] | None = None,
        timeout_seconds: float = repair_git._GIT_TIMEOUT_SECONDS,
        stdout_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        stderr_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        inherited_fds: tuple[int, ...] = (),
    ) -> repair_git._GitResult:
        nonlocal swapped
        if next(iter(arguments)) != "push":
            return original_invoke(
                git_executable,
                invocation_root,
                arguments,
                stage=stage,
                input_bytes=input_bytes,
                extra_environment=extra_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                inherited_fds=inherited_fds,
            )
        namespace.rename(displaced)
        namespace.mkdir()
        swapped = True
        return original_invoke(
            git_executable,
            invocation_root,
            arguments,
            stage=stage,
            input_bytes=input_bytes,
            extra_environment=extra_environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            inherited_fds=inherited_fds,
        )

    monkeypatch.setattr(repair_git, "_invoke_git", swapping_invoke)
    try:
        with pytest.raises(RepairError) as captured:
            _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)
    finally:
        if swapped:
            namespace.rename(transient)
            displaced.rename(namespace)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert not (namespace / _CANDIDATE_ID).exists()
    assert (transient / _CANDIDATE_ID).read_text(encoding="ascii") == f"{candidate.commit_oid}\n"


def test_publication_rejects_symlinked_repair_ref_namespace_without_external_write(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    external_refs = tmp_path / "external-refs"
    (external_refs / "repairs").mkdir(parents=True)
    namespace = source.common_dir / "refs" / "repoguard"
    namespace.symlink_to(external_refs, target_is_directory=True)
    before_head = _git(root, "rev-parse", "HEAD")
    before_index = (source.git_dir / "index").read_bytes()
    before_config = (source.git_dir / "config").read_bytes()

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert namespace.is_symlink()
    assert not (external_refs / "repairs" / _CANDIDATE_ID).exists()
    assert _git(root, "rev-parse", "HEAD") == before_head
    assert (source.git_dir / "index").read_bytes() == before_index
    assert (source.git_dir / "config").read_bytes() == before_config


def test_publication_rejects_symlinked_packed_refs_without_forged_idempotency(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    assert (
        _publish_repair_ref(source, candidate, _GIT, _FOREIGN_ID).outcome
        is _PublicationOutcome.PUBLISHED
    )
    candidate_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    external_packed_refs = tmp_path / "external-packed-refs"
    external_bytes = (
        f"# pack-refs with: peeled fully-peeled sorted\n{candidate.commit_oid} {candidate_ref}\n"
    ).encode("ascii")
    external_packed_refs.write_bytes(external_bytes)
    packed_refs = source.common_dir / "packed-refs"
    packed_refs.symlink_to(external_packed_refs)

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert packed_refs.is_symlink()
    assert external_packed_refs.read_bytes() == external_bytes
    assert not (source.common_dir / candidate_ref).exists()


def test_publication_accepts_regular_packed_direct_ref_idempotently(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    assert (
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID).outcome
        is _PublicationOutcome.PUBLISHED
    )
    _git(root, "pack-refs", "--all", "--prune")
    packed_refs = source.common_dir / "packed-refs"
    assert packed_refs.is_file()
    assert not (source.common_dir / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID).exists()

    repeated = _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert repeated.outcome is _PublicationOutcome.ALREADY_PRESENT
    assert repeated.commit_oid == candidate.commit_oid


def test_repair_ref_reader_streams_large_packed_refs_without_unrelated_record_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    lines = [f"{head} refs/heads/unrelated-{index:05d}\n" for index in range(50_001)]
    long_ref = "refs/heads/" + "/".join(f"{index:03d}{'x' * 196}" for index in range(24))
    lines.append(f"{head} {long_ref}\n")
    lines.append(f"{head} {target_ref}\n")
    payload = "".join(lines).encode("ascii")
    assert len(payload) > 2 * 1_024 * 1_024
    assert len(long_ref.encode("ascii")) > 4_096
    (source.common_dir / "packed-refs").write_bytes(payload)
    monkeypatch.setattr(repair_git, "_MAX_HOST_BYTES", 1)

    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID) == head


@pytest.mark.parametrize("separator", (b" ", b"\t", b"\r"))
def test_repair_ref_reader_accepts_git_valid_single_whitespace_separator(
    tmp_path: Path,
    separator: bytes,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    (source.common_dir / "packed-refs").write_bytes(
        head.encode("ascii") + separator + target_ref.encode("ascii") + b"\n"
    )

    assert f"{head} {target_ref}".encode("ascii") in _git(root, "show-ref").splitlines()
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head) == head


@pytest.mark.parametrize("separator", (b"\v", b"\f"))
def test_repair_ref_reader_rejects_whitespace_not_accepted_by_complete_git_reads(
    tmp_path: Path,
    separator: bytes,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    (source.common_dir / "packed-refs").write_bytes(
        head.encode("ascii") + separator + target_ref.encode("ascii") + b"\n"
    )

    with pytest.raises(subprocess.CalledProcessError):
        _git(root, "show-ref")
    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION


def test_repair_ref_reader_rejects_a_durably_malformed_packed_ref_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    packed_refs = source.common_dir / "packed-refs"
    durable = tmp_path / "durable-packed-refs"
    clean = tmp_path / "clean-packed-refs"
    malformed_payload = f"not-a-record\n{head} {target_ref}\n".encode("ascii")
    clean_payload = f"{head} {target_ref}\n".encode("ascii")
    packed_refs.write_bytes(malformed_payload)
    clean.write_bytes(clean_payload)
    original_invoke = repair_git._invoke_git
    original_reader = repair_git._read_packed_repair_ref
    descriptor_scanned = False
    pre_scan_query_count = 0
    post_scan_query_swapped = False

    def recording_reader(
        descriptor: int,
        ref: str,
        object_format: str,
        *,
        expected_size: int,
    ) -> str | None:
        nonlocal descriptor_scanned
        descriptor_scanned = True
        return original_reader(
            descriptor,
            ref,
            object_format,
            expected_size=expected_size,
        )

    def swapping_invoke(
        git_executable: Path,
        invoke_root: Path | None,
        arguments: Sequence[str],
        *,
        stage: RepairStage,
        input_bytes: bytes | None = None,
        extra_environment: dict[str, str] | None = None,
        timeout_seconds: float = repair_git._GIT_TIMEOUT_SECONDS,
        stdout_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        stderr_limit: int = repair_git._CONTROL_OUTPUT_BYTES,
        inherited_fds: tuple[int, ...] = (),
    ) -> repair_git._GitResult:
        nonlocal post_scan_query_swapped, pre_scan_query_count
        if "cat-file" not in arguments:
            return original_invoke(
                git_executable,
                invoke_root,
                arguments,
                stage=stage,
                input_bytes=input_bytes,
                extra_environment=extra_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                inherited_fds=inherited_fds,
            )
        packed_refs.rename(durable)
        clean.rename(packed_refs)
        if descriptor_scanned:
            post_scan_query_swapped = True
        else:
            pre_scan_query_count += 1
        try:
            return original_invoke(
                git_executable,
                invoke_root,
                arguments,
                stage=stage,
                input_bytes=input_bytes,
                extra_environment=extra_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                inherited_fds=inherited_fds,
            )
        finally:
            packed_refs.rename(clean)
            durable.rename(packed_refs)

    monkeypatch.setattr(repair_git, "_read_packed_repair_ref", recording_reader)
    monkeypatch.setattr(repair_git, "_invoke_git", swapping_invoke)

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert pre_scan_query_count > 0
    assert post_scan_query_swapped is False
    assert packed_refs.read_bytes() == malformed_payload
    assert clean.read_bytes() == clean_payload


@pytest.mark.parametrize(
    "payload",
    (
        (
            f"{'1' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n"
            f"{'2' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n"
        ).encode("ascii"),
        f"{'0' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"ref: refs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"not-a-record\n{'1' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"# local comment\n{'1' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"\n{'1' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"{'1' * 40} refs/repoguard/repairs/{_CANDIDATE_ID}\n\n".encode("ascii"),
        f"{'1' * 40}\vrefs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
        f"{'1' * 40}\frefs/repoguard/repairs/{_CANDIDATE_ID}\n".encode("ascii"),
    ),
)
def test_packed_repair_ref_parser_rejects_duplicate_or_malformed_target(payload: bytes) -> None:
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"

    with pytest.raises(ValueError, match=r"packed|stored"):
        repair_git._parse_packed_repair_ref(payload, target_ref, "sha1")


def test_packed_repair_ref_parser_normalizes_a_git_valid_uppercase_oid() -> None:
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    payload = f"{'A' * 40}\t{target_ref}\n".encode("ascii")

    assert repair_git._parse_packed_repair_ref(payload, target_ref, "sha1") == "a" * 40


def test_repair_ref_reader_normalizes_uppercase_loose_and_packed_oids_equally(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    loose_ref = source.common_dir / target_ref
    loose_ref.parent.mkdir(parents=True)
    loose_ref.write_text(f"{head.upper()}\n", encoding="ascii")

    assert _git(root, "show-ref", "--verify", target_ref) == (
        f"{head} {target_ref}\n".encode("ascii")
    )
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head) == head

    loose_ref.unlink()
    (source.common_dir / "packed-refs").write_text(
        f"{head.upper()}\t{target_ref}\n",
        encoding="ascii",
    )
    assert _git(root, "show-ref", "--verify", target_ref) == (
        f"{head} {target_ref}\n".encode("ascii")
    )
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head) == head


def test_loose_repair_ref_overrides_a_packed_entry(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    assert (
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID).outcome
        is _PublicationOutcome.PUBLISHED
    )
    _git(root, "pack-refs", "--all", "--prune")
    loose_ref = source.common_dir / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID
    loose_ref.parent.mkdir(parents=True)
    loose_ref.write_text(f"{head}\n", encoding="ascii")

    assert (
        _read_repair_ref(
            source,
            _GIT,
            _CANDIDATE_ID,
            expected_commit_oid=candidate.commit_oid,
        )
        == head
    )


def test_repair_ref_read_rejects_an_in_progress_candidate_lock(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    namespace = source.common_dir / "refs" / "repoguard" / "repairs"
    namespace.mkdir(parents=True)
    lock = namespace / f"{_CANDIDATE_ID}.lock"
    lock.write_bytes(b"in-progress ref update\n")

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert lock.read_bytes() == b"in-progress ref update\n"


def test_repair_ref_read_uses_the_open_packed_descriptor_during_name_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    packed_refs = source.common_dir / "packed-refs"
    original_packed_refs = tmp_path / "original-packed-refs"
    observed_replacement = tmp_path / "observed-replacement-packed-refs"
    replacement = tmp_path / "replacement-packed-refs"
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    packed_refs.write_bytes(f"{head} refs/heads/original\n".encode("ascii"))
    replacement.write_bytes(f"{head} {target_ref}\n".encode("ascii"))
    original_reader = repair_git._read_packed_repair_ref
    replacement_observed = False
    descriptor_result: str | None = head

    def replacing_reader(
        descriptor: int,
        ref: str,
        object_format: str,
        *,
        expected_size: int,
    ) -> str | None:
        nonlocal descriptor_result, replacement_observed
        packed_refs.rename(original_packed_refs)
        replacement.rename(packed_refs)
        replacement_observed = True
        try:
            descriptor_result = original_reader(
                descriptor,
                ref,
                object_format,
                expected_size=expected_size,
            )
            return descriptor_result
        finally:
            packed_refs.rename(observed_replacement)
            original_packed_refs.rename(packed_refs)

    monkeypatch.setattr(repair_git, "_read_packed_repair_ref", replacing_reader)

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert replacement_observed is True
    assert descriptor_result is None
    assert packed_refs.read_bytes() == f"{head} refs/heads/original\n".encode("ascii")
    assert observed_replacement.read_bytes() == f"{head} {target_ref}\n".encode("ascii")


def test_repair_ref_read_revalidates_source_binding_after_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    replacement = tmp_path / "source-replacement"
    displaced = tmp_path / "source-displaced"
    shutil.copytree(root, replacement)
    target_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    target = source.common_dir / target_ref
    target.parent.mkdir(parents=True)
    target.write_text(f"{head}\n", encoding="ascii")
    original_reader = repair_git._read_repair_ref_at
    source_replaced = False

    def replacing_reader(
        source_value: repair_git._RepositoryIdentity,
        git_executable: Path,
        candidate_id: str,
        common_dir: Path,
        common_fd: int,
        *,
        expected_commit_oid: str | None,
        pinned_namespace_fd: int | None = None,
    ) -> str | None:
        nonlocal source_replaced
        result = original_reader(
            source_value,
            git_executable,
            candidate_id,
            common_dir,
            common_fd,
            expected_commit_oid=expected_commit_oid,
            pinned_namespace_fd=pinned_namespace_fd,
        )
        root.rename(displaced)
        replacement.rename(root)
        source_replaced = True
        return result

    monkeypatch.setattr(repair_git, "_read_repair_ref_at", replacing_reader)

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID, expected_commit_oid=head)

    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert captured.value.stage is RepairStage.APPLICATION
    assert source_replaced is True
    assert not (root / ".git" / target_ref).exists()
    assert (displaced / ".git" / target_ref).read_bytes() == f"{head}\n".encode("ascii")


def test_publication_rejects_symbolic_repair_ref_without_mutating_target(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    target_ref = f"refs/repoguard/repairs/{_FOREIGN_ID}"
    assert (
        _publish_repair_ref(source, candidate, _GIT, _FOREIGN_ID).outcome
        is _PublicationOutcome.PUBLISHED
    )
    symbolic_ref = f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    symbolic_path = source.common_dir / symbolic_ref
    symbolic_bytes = f"ref: {target_ref}\n".encode("ascii")
    symbolic_path.write_bytes(symbolic_bytes)
    target_oid = _git(root, "rev-parse", target_ref)

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert symbolic_path.read_bytes() == symbolic_bytes
    assert _git(root, "rev-parse", target_ref) == target_oid
    assert _git(root, "symbolic-ref", symbolic_ref).decode("ascii").strip() == target_ref


def test_publication_rejects_preexisting_dedicated_reflog_without_writes(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )
    reflog = source.common_dir / "logs" / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID
    reflog.parent.mkdir(parents=True)
    original = b"preexisting audit bytes\n"
    reflog.write_bytes(original)

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert reflog.read_bytes() == original
    with pytest.raises(RepairError) as readback:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID)
    assert readback.value.code is RepairErrorCode.PUBLICATION_FAILED


def test_repair_ref_read_rejects_an_in_progress_dedicated_reflog(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    namespace = source.common_dir / "logs" / "refs" / "repoguard" / "repairs"
    namespace.mkdir(parents=True)
    lock = namespace / f"{_CANDIDATE_ID}.lock"
    lock.write_bytes(b"in-progress reflog update\n")

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert lock.read_bytes() == b"in-progress reflog update\n"


def test_expected_ref_idempotency_still_rejects_a_dedicated_reflog(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    assert (
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID).outcome
        is _PublicationOutcome.PUBLISHED
    )
    reflog = source.common_dir / "logs" / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID
    reflog.parent.mkdir(parents=True, exist_ok=True)
    original = b"preexisting audit bytes\n"
    reflog.write_bytes(original)

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert reflog.read_bytes() == original


def test_foreign_non_commit_ref_is_classified_without_accepting_it(
    tmp_path: Path,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    blob_oid = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"foreign blob\n")
    foreign_ref = f"refs/repoguard/repairs/{_FOREIGN_ID}"
    _git(root, "update-ref", foreign_ref, blob_oid.decode("ascii").strip())

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _FOREIGN_ID)

    assert captured.value.code is RepairErrorCode.REF_CONFLICT
    assert _read_repair_ref(source, _GIT, _FOREIGN_ID) == blob_oid.decode("ascii").strip()


def test_expected_repair_ref_requires_commit_object_in_source(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )
    published = _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)
    assert published.outcome is _PublicationOutcome.PUBLISHED
    objects = source.common_dir / "objects"
    object_path = objects / candidate.commit_oid[:2] / candidate.commit_oid[2:]
    assert object_path.is_file()
    object_path.unlink()

    with pytest.raises(RepairError) as captured:
        _read_repair_ref(
            source,
            _GIT,
            _CANDIDATE_ID,
            expected_commit_oid=candidate.commit_oid,
        )

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)
    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION


def test_publication_rejects_proc_receive_config_without_writes(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "candidate",
        (parsed,),
    )
    hook = source.common_dir / "hooks" / "proc-receive"
    hook.write_text('#!/bin/sh\n: > "$0.ran"\nexit 0\n', encoding="utf-8")
    hook.chmod(0o700)
    _git(
        root,
        "config",
        "--add",
        "receive.procReceiveRefs",
        "refs/repoguard/repairs/",
    )
    before = _source_fingerprint(root)
    before_index = (source.git_dir / "index").read_bytes()

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert not hook.with_name("proc-receive.ran").exists()
    assert _source_fingerprint(root) == before
    assert (source.git_dir / "index").read_bytes() == before_index
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID) is None


def test_publication_rejects_configured_ref_storage_before_receive_pack(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    _git(root, "config", "extensions.refStorage", "files")
    before = _source_fingerprint(root)

    with pytest.raises(RepairError) as readback:
        _read_repair_ref(source, _GIT, _CANDIDATE_ID)
    assert readback.value.code is RepairErrorCode.PUBLICATION_FAILED

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert _source_fingerprint(root) == before
    assert not (source.common_dir / "refs" / "repoguard" / "repairs" / _CANDIDATE_ID).exists()


def test_publication_rejects_fifo_fsck_skip_list_without_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    skip_list = tmp_path / "receive-fsck-skip-list"
    os.mkfifo(skip_list, 0o600)
    _git(root, "config", "receive.fsckObjects", "true")
    _git(root, "config", "receive.fsck.skipList", str(skip_list))
    objects = source.common_dir / "objects"
    quarantine_sentinel = objects / "tmp_objdir-incoming-foreign"
    quarantine_sentinel.mkdir(mode=0o700)
    before_entries = {entry.name for entry in objects.iterdir()}
    monkeypatch.setattr(repair_git, "_PACK_TIMEOUT_SECONDS", 0.25)

    with pytest.raises(RepairError) as captured:
        _publish_repair_ref(source, candidate, _GIT, _CANDIDATE_ID)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert {entry.name for entry in objects.iterdir()} == before_entries
    assert quarantine_sentinel.is_dir()
    assert (
        tuple(path for path in objects.glob("tmp_objdir-incoming-*") if path != quarantine_sentinel)
        == ()
    )
    assert _read_repair_ref(source, _GIT, _CANDIDATE_ID) is None


def test_sha256_candidate_when_supported(tmp_path: Path) -> None:
    probe = subprocess.run(
        (_GIT, "init", "--bare", "--quiet", "--object-format=sha256", tmp_path / "probe.git"),
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip("installed Git does not support SHA-256 repositories")
    root, head = _repository(tmp_path / "sha256", object_format="sha256")
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )

    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "sha256-candidate",
        (parsed,),
    )

    assert source.object_format == "sha256"
    assert len(source.head_oid) == 64
    assert len(candidate.tree_oid) == 64
    assert len(candidate.commit_oid) == 64
    _assert_hardened_candidate_tree(candidate.root, executable_paths={"tool.sh"})


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _assert_cleanup_compatible_candidate_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        details = path.lstat()
        assert details.st_uid == os.geteuid()
        if stat.S_ISDIR(details.st_mode):
            assert stat.S_IMODE(details.st_mode) == 0o700
            continue
        assert stat.S_ISREG(details.st_mode)
        assert details.st_nlink == 1
        assert stat.S_IMODE(details.st_mode) in {0o400, 0o500, 0o600}


def _assert_hardened_candidate_tree(root: Path, *, executable_paths: set[str]) -> None:
    parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        mount_id = repair_git._candidate_mount_id(parent_fd)
    finally:
        os.close(parent_fd)
    for path in (root, *root.rglob("*")):
        details = path.lstat()
        assert details.st_uid == os.geteuid()
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if stat.S_ISDIR(details.st_mode):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            assert repair_git._candidate_mount_id(descriptor) == mount_id
        finally:
            os.close(descriptor)
        if stat.S_ISDIR(details.st_mode):
            assert stat.S_IMODE(details.st_mode) == 0o700
            continue
        assert stat.S_ISREG(details.st_mode)
        assert details.st_nlink == 1
        relative = path.relative_to(root).as_posix()
        if relative == ".git/repoguard-index":
            expected_mode = 0o600
        elif relative in executable_paths:
            expected_mode = 0o500
        else:
            expected_mode = 0o400
        assert stat.S_IMODE(details.st_mode) == expected_mode


def _hardening_tree(tmp_path: Path) -> tuple[Path, Path, dict[tuple[str, ...], int]]:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    root = private / "candidate"
    root.mkdir(mode=0o700)
    git_dir = root / ".git"
    git_dir.mkdir(mode=0o700)
    index = git_dir / "repoguard-index"
    index.write_bytes(b"index")
    index.chmod(0o600)
    app = root / "app.py"
    app.write_text("value = 1\n", encoding="utf-8")
    app.chmod(0o600)
    return root, index, {("app.py",): 0o400}


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "fifo"])
def test_candidate_hardening_rejects_unsafe_entry_types_and_links(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    root, index, worktree_modes = _hardening_tree(tmp_path)
    unsafe = root / "unsafe"
    if unsafe_kind == "symlink":
        unsafe.symlink_to("app.py")
    elif unsafe_kind == "hardlink":
        os.link(root / "app.py", unsafe)
    else:
        os.mkfifo(unsafe)

    with pytest.raises(RepairError) as captured:
        repair_git._harden_candidate_tree(root, index, worktree_modes)

    assert captured.value.code is RepairErrorCode.MATERIALIZATION_FAILED
    assert captured.value.stage is RepairStage.MATERIALIZATION
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert stat_mode(root / "app.py") == 0o600


def test_candidate_hardening_rejects_cross_mount_and_foreign_effective_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, index, worktree_modes = _hardening_tree(tmp_path)
    app_inode = (root / "app.py").stat().st_ino
    real_mount_id = repair_git._candidate_mount_id

    def cross_mount(descriptor: int) -> int:
        mount_id = real_mount_id(descriptor)
        if os.fstat(descriptor).st_ino == app_inode:
            return mount_id + 1
        return mount_id

    monkeypatch.setattr(repair_git, "_candidate_mount_id", cross_mount)
    with pytest.raises(RepairError) as mounted:
        repair_git._harden_candidate_tree(root, index, worktree_modes)
    assert mounted.value.code is RepairErrorCode.MATERIALIZATION_FAILED

    monkeypatch.setattr(repair_git, "_candidate_mount_id", real_mount_id)
    effective_uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: effective_uid + 1)
    with pytest.raises(RepairError) as foreign:
        repair_git._harden_candidate_tree(root, index, worktree_modes)
    assert foreign.value.code is RepairErrorCode.MATERIALIZATION_FAILED


@pytest.mark.parametrize("tamper_kind", ["symlink", "hardlink", "fifo"])
def test_candidate_reopen_verifier_rejects_post_hardening_entries(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    root, index, worktree_modes = _hardening_tree(tmp_path)
    repair_git._harden_candidate_tree(root, index, worktree_modes)
    unsafe = root / "unsafe"
    if tamper_kind == "symlink":
        unsafe.symlink_to("app.py")
    elif tamper_kind == "hardlink":
        os.link(root / "app.py", unsafe)
    else:
        os.mkfifo(unsafe)

    with pytest.raises(RepairError) as captured:
        repair_git._verify_hardened_candidate_tree(root, index, worktree_modes)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.stage is RepairStage.APPLICATION
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_candidate_hardening_rejects_stat_open_inode_exchange(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, index, worktree_modes = _hardening_tree(tmp_path)
    replacement = tmp_path / "replacement.py"
    replacement.write_text("replacement = True\n", encoding="utf-8")
    replacement.chmod(0o600)
    app = root / "app.py"
    real_open = os.open
    exchanged = False

    def exchange_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal exchanged
        if path == "app.py" and dir_fd is not None and not exchanged:
            app.unlink()
            replacement.rename(app)
            exchanged = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", exchange_before_open)
    with pytest.raises(RepairError) as captured:
        repair_git._harden_candidate_tree(root, index, worktree_modes)

    assert exchanged is True
    assert captured.value.code is RepairErrorCode.MATERIALIZATION_FAILED
    assert captured.value.__context__ is None


def test_nested_linked_worktree_with_source_alternates_is_self_contained(
    tmp_path: Path,
) -> None:
    original, head = _repository(tmp_path / "original")
    shared = tmp_path / "shared"
    subprocess.run(
        (_GIT, "clone", "--quiet", "--shared", original, shared),
        check=True,
        capture_output=True,
    )
    linked = tmp_path / "linked"
    _git(shared, "worktree", "add", "--quiet", "--detach", str(linked), head)
    nested = linked / "untracked-directory"
    nested.mkdir()
    (nested / "dirty.txt").write_text("ignored\n", encoding="utf-8")
    source = _capture_repository(RepositoryInput(nested), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )

    candidate = _materialize_candidate(
        source,
        _GIT,
        tmp_path / "linked-candidate",
        (parsed,),
    )

    assert source.root == linked.resolve()
    assert source.git_dir != source.common_dir
    assert (source.common_dir / "objects" / "info" / "alternates").is_file()
    assert not (candidate.git_dir / "objects" / "info" / "alternates").exists()
    original.rename(tmp_path / "original-moved")
    assert _git(candidate.root, "cat-file", "-e", candidate.commit_oid) == b""


def test_git_tree_order_is_canonicalized_and_commit_is_reproducible(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)
    (root / "foo.bar").write_text("dot = 1\n", encoding="utf-8")
    (root / "foo").mkdir()
    (root / "foo" / "item.py").write_text("item = 1\n", encoding="utf-8")
    head = _commit(root, "tree order")
    source = _capture_repository(RepositoryInput(root / "foo"), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/foo.bar
+++ b/foo.bar
@@ -1 +1 @@
-dot = 1
+dot = 2
--- a/foo/item.py
+++ b/foo/item.py
@@ -1 +1 @@
-item = 1
+item = 2
""",
        ("foo.bar", "foo/item.py"),
    )

    first = _materialize_candidate(source, _GIT, tmp_path / "first", (parsed,))
    second = _materialize_candidate(source, _GIT, tmp_path / "second", (parsed,))

    assert tuple(entry.path for entry in source.entries) == tuple(
        sorted((entry.path for entry in source.entries), key=str.encode)
    )
    assert first.changed_paths == ("foo.bar", "foo/item.py")
    assert first.canonical_diff == second.canonical_diff
    assert first.tree_oid == second.tree_oid
    assert first.commit_oid == second.commit_oid


def test_missing_exact_head_blob_never_falls_back_to_lazy_fetch(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    entry = next(item for item in source.entries if item.path == "app.py")
    loose_object = source.common_dir / "objects" / entry.oid[:2] / entry.oid[2:]
    assert loose_object.is_file()
    loose_object.rename(tmp_path / "missing-object")
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )

    with pytest.raises(RepairError) as captured:
        _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))

    assert captured.value.code is RepairErrorCode.MISSING_OBJECT
    assert captured.value.stage is RepairStage.MATERIALIZATION


def test_head_file_and_capture_fail_closed_boundaries(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)
    (root / "link").symlink_to("app.py")
    head = _commit(root, "symlink")
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    app_oid = next(entry.oid for entry in source.entries if entry.path == "app.py")

    with pytest.raises(RepairError) as invalid_path:
        _read_head_file(source, _GIT, "../app.py")
    assert invalid_path.value.code is RepairErrorCode.INVALID_PATH
    with pytest.raises(ValueError):
        _read_head_file(source, _GIT, "app.py", maximum_bytes=0)
    with pytest.raises(RepairError) as oversized:
        _read_head_file(source, _GIT, "app.py", maximum_bytes=1)
    assert oversized.value.code is RepairErrorCode.RESOURCE_LIMIT
    with pytest.raises(RepairError) as nonordinary:
        _read_head_file(source, _GIT, "link")
    assert nonordinary.value.code is RepairErrorCode.INVALID_PATH
    with pytest.raises(RepairError) as noncommit:
        _capture_repository(RepositoryInput(root), _GIT, head_oid=app_oid)
    assert noncommit.value.code is RepairErrorCode.MISSING_OBJECT
    with pytest.raises(TypeError):
        _capture_repository(object(), _GIT, head_oid=head)  # type: ignore[arg-type]


def test_materialization_input_disk_and_identity_guards(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )

    with pytest.raises(ValueError):
        _materialize_candidate(source, _GIT, Path("relative"), (parsed,))
    with pytest.raises(ValueError):
        _materialize_candidate(source, _GIT, tmp_path / "empty", ())
    with pytest.raises(TypeError):
        _materialize_candidate(source, _GIT, tmp_path / "wrong", (object(),))  # type: ignore[arg-type]
    with pytest.raises(RepairError) as overlap:
        _materialize_candidate(source, _GIT, root / "private", (parsed,))
    assert overlap.value.code is RepairErrorCode.MATERIALIZATION_FAILED
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(RepairError) as occupied:
        _materialize_candidate(source, _GIT, existing, (parsed,))
    assert occupied.value.code is RepairErrorCode.MATERIALIZATION_FAILED
    no_space = replace(_GitLimits(), minimum_free_bytes=2**63)
    with pytest.raises(RepairError) as disk:
        _materialize_candidate(
            source,
            _GIT,
            tmp_path / "no-space",
            (parsed,),
            _limits=no_space,
        )
    assert disk.value.code is RepairErrorCode.RESOURCE_LIMIT
    stale = replace(source, root_inode=source.root_inode + 1)
    with pytest.raises(RepairError) as identity:
        _materialize_candidate(stale, _GIT, tmp_path / "stale", (parsed,))
    assert identity.value.code is RepairErrorCode.IDENTITY_MISMATCH


def test_blob_byte_and_final_change_limits_are_enforced(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    with pytest.raises(RepairError) as blob:
        _capture_repository(
            RepositoryInput(root),
            _GIT,
            head_oid=head,
            _limits=replace(_GitLimits(), max_blob_bytes=1),
        )
    assert blob.value.code is RepairErrorCode.RESOURCE_LIMIT
    with pytest.raises(RepairError) as total:
        _capture_repository(
            RepositoryInput(root),
            _GIT,
            head_oid=head,
            _limits=replace(_GitLimits(), max_head_blob_bytes=1),
        )
    assert total.value.code is RepairErrorCode.RESOURCE_LIMIT

    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    with pytest.raises(RepairError) as changes:
        _materialize_candidate(
            source,
            _GIT,
            tmp_path / "too-many-lines",
            (parsed,),
            _limits=replace(_GitLimits(), max_changed_lines=1),
        )
    assert changes.value.code is RepairErrorCode.RESOURCE_LIMIT


def test_publication_failure_leaves_ref_absent(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    source = _capture_repository(RepositoryInput(root), _GIT, head_oid=head)
    parsed = _patch(
        """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
""",
        ("app.py",),
    )
    candidate = _materialize_candidate(source, _GIT, tmp_path / "candidate", (parsed,))
    refs = source.common_dir / "refs"
    objects = source.common_dir / "objects"
    refs.chmod(0o500)
    objects.chmod(0o500)
    try:
        with pytest.raises(RepairError) as captured:
            _publish_repair_ref(source, candidate, _GIT, "c" * 64)
        assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
        assert _read_repair_ref(source, _GIT, "c" * 64) is None
    finally:
        refs.chmod(0o700)
        objects.chmod(0o700)


def _script(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def test_git_process_adapter_uses_clear_environment_and_bounded_io(tmp_path: Path) -> None:
    inspect_script = _script(
        tmp_path / "inspect",
        "import os, sys\n"
        "payload = sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(payload + b'\\0' + os.environ['HOME'].encode())\n",
    )
    result = repair_git._invoke_git(
        inspect_script,
        None,
        (),
        stage=RepairStage.INPUT,
        input_bytes=b"private-input",
    )
    assert result.returncode == 0
    assert result.stdout == b"private-input\0/nonexistent"

    created = tmp_path / "created-by-git-adapter"
    umask_script = _script(
        tmp_path / "umask",
        "from pathlib import Path\nPath(__import__('sys').argv[-1]).write_text('private')\n",
    )
    repair_git._invoke_git(
        umask_script,
        None,
        (str(created),),
        stage=RepairStage.INPUT,
    )
    assert stat_mode(created) == 0o600

    output_script = _script(tmp_path / "output", "import sys\nsys.stdout.write('x' * 1024)\n")
    with pytest.raises(RepairError) as output:
        repair_git._invoke_git(
            output_script,
            None,
            (),
            stage=RepairStage.INPUT,
            stdout_limit=16,
        )
    assert output.value.code is RepairErrorCode.RESOURCE_LIMIT

    timeout_script = _script(tmp_path / "timeout", "import time\ntime.sleep(1)\n")
    with pytest.raises(RepairError) as timeout:
        repair_git._invoke_git(
            timeout_script,
            None,
            (),
            stage=RepairStage.INPUT,
            timeout_seconds=0.01,
        )
    assert timeout.value.code is RepairErrorCode.GIT_FAILED


def test_git_process_adapter_inherits_only_explicit_open_descriptors(tmp_path: Path) -> None:
    inspect_fd = _script(
        tmp_path / "inspect-fd",
        "import os, sys\n"
        "try:\n"
        "    os.fstat(int(sys.argv[-1]))\n"
        "except OSError:\n"
        "    raise SystemExit(3)\n",
    )
    descriptor = os.open(tmp_path / "inherited.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        inherited = repair_git._invoke_git(
            inspect_fd,
            None,
            (str(descriptor),),
            stage=RepairStage.INPUT,
            inherited_fds=(descriptor,),
        )
        ordinary = repair_git._invoke_git(
            inspect_fd,
            None,
            (str(descriptor),),
            stage=RepairStage.INPUT,
        )
    finally:
        os.close(descriptor)

    assert inherited.returncode == 0
    assert ordinary.returncode == 3


def test_git_process_adapter_deadline_stops_descendant_held_pipes_and_descriptor(
    tmp_path: Path,
) -> None:
    child_pid = tmp_path / "child.pid"
    descriptor = os.open(
        tmp_path / "inherited.lock",
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    child_program = f"import os,time;os.fstat({descriptor});time.sleep(10)"
    leader = _script(
        tmp_path / "leader",
        "import pathlib, subprocess, sys\n"
        f"child = subprocess.Popen((sys.executable, '-c', {child_program!r}), close_fds=False)\n"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')\n",
    )

    started = time.monotonic()
    try:
        with pytest.raises(RepairError) as captured:
            repair_git._invoke_git(
                leader,
                None,
                (),
                stage=RepairStage.APPLICATION,
                timeout_seconds=0.2,
                inherited_fds=(descriptor,),
            )
        elapsed = time.monotonic() - started
    finally:
        os.close(descriptor)
        if child_pid.is_file():
            with suppress(ProcessLookupError):
                os.kill(int(child_pid.read_text(encoding="ascii")), signal.SIGKILL)

    assert captured.value.code is RepairErrorCode.GIT_FAILED
    assert elapsed < 0.75


def test_git_process_adapter_rejects_a_descendant_holding_only_an_inherited_lock(
    tmp_path: Path,
) -> None:
    child_pid = tmp_path / "child.pid"
    lock_path = tmp_path / "inherited.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    child_program = f"import os,time;os.close(1);os.close(2);os.fstat({descriptor});time.sleep(10)"
    leader = _script(
        tmp_path / "leader-no-pipes",
        "import pathlib, subprocess, sys\n"
        f"child = subprocess.Popen((sys.executable, '-c', {child_program!r}), close_fds=False)\n"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')\n",
    )
    descriptor_open = True

    started = time.monotonic()
    try:
        with pytest.raises(RepairError) as captured:
            repair_git._invoke_git(
                leader,
                None,
                (),
                stage=RepairStage.APPLICATION,
                timeout_seconds=0.2,
                inherited_fds=(descriptor,),
            )
        elapsed = time.monotonic() - started
        os.close(descriptor)
        descriptor_open = False
        probe = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe)
    finally:
        if descriptor_open:
            os.close(descriptor)
        if child_pid.is_file():
            with suppress(ProcessLookupError):
                os.kill(int(child_pid.read_text(encoding="ascii")), signal.SIGKILL)

    assert captured.value.code is RepairErrorCode.GIT_FAILED
    assert elapsed < 0.75


def test_git_process_and_private_helper_validation(tmp_path: Path) -> None:
    with pytest.raises(RepairError) as unavailable:
        repair_git._invoke_git(
            tmp_path / "missing-git",
            None,
            (),
            stage=RepairStage.INPUT,
        )
    assert unavailable.value.code is RepairErrorCode.GIT_UNAVAILABLE
    with pytest.raises(RepairError) as start_failed:
        repair_git._invoke_git(tmp_path, None, (), stage=RepairStage.INPUT)
    assert start_failed.value.code is RepairErrorCode.GIT_FAILED
    with pytest.raises(ValueError):
        repair_git._invoke_git(_GIT, None, (), stage=RepairStage.INPUT, stdout_limit=0)
    with pytest.raises(TypeError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage=RepairStage.INPUT,
            input_bytes="not bytes",  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage=RepairStage.INPUT,
            inherited_fds=[3],  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage=RepairStage.INPUT,
            inherited_fds=(True,),
        )
    with pytest.raises(ValueError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage=RepairStage.INPUT,
            inherited_fds=(2,),
        )
    closed_descriptor = os.open(tmp_path / "closed.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
    os.close(closed_descriptor)
    with pytest.raises(ValueError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage=RepairStage.INPUT,
            inherited_fds=(closed_descriptor,),
        )
    writable_directory = tmp_path / "writable"
    writable_directory.mkdir(mode=0o770)
    writable_fd = os.open(writable_directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError):
            repair_git._invoke_git(
                _GIT,
                Path("/proc/self/fd") / str(writable_fd),
                ("status",),
                stage=RepairStage.INPUT,
            )
    finally:
        os.close(writable_fd)
    with pytest.raises(TypeError):
        repair_git._git_environment({"KEY": 1})  # type: ignore[dict-item]
    with pytest.raises(ValueError):
        repair_git._repair_ref("A" * 64)
    with pytest.raises(ValueError):
        repair_git._require_limits(replace(_GitLimits(), max_blob_bytes=0))
    with pytest.raises(TypeError):
        repair_git._require_limits(object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mode", "kind", "size", "code"),
    [
        ("100664", "blob", b"1", RepairErrorCode.MATERIALIZATION_FAILED),
        ("040000", "tree", b"1", RepairErrorCode.GIT_FAILED),
        ("100644", "blob", b"-", RepairErrorCode.MISSING_OBJECT),
    ],
)
def test_tree_entry_parser_rejects_unsupported_records(
    mode: str,
    kind: str,
    size: bytes,
    code: RepairErrorCode,
) -> None:
    with pytest.raises(RepairError) as captured:
        repair_git._parse_tree_entry(mode, kind, size, RepairStage.INPUT)
    assert captured.value.code is code


@pytest.mark.parametrize("output", [b"", b"value", b"\n", b"a\nb\n", b"a\0\n"])
def test_single_ascii_line_parser_is_fail_closed(output: bytes) -> None:
    with pytest.raises(RepairError) as captured:
        repair_git._read_ascii_line(output, RepairStage.INPUT)
    assert captured.value.code is RepairErrorCode.GIT_FAILED


@pytest.mark.parametrize("output", [b"", b"diff without lf", b"\0\n", b"\xff\n"])
def test_canonical_diff_rejects_malformed_git_output(
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
) -> None:
    def fake_run_required(*args: object, **kwargs: object) -> repair_git._GitResult:
        return repair_git._GitResult(0, output, b"")

    monkeypatch.setattr(repair_git, "_run_required", fake_run_required)
    with pytest.raises(RepairError) as captured:
        repair_git._canonical_diff(_GIT, Path("/"), "a" * 40, {})
    assert captured.value.code is RepairErrorCode.MATERIALIZATION_FAILED


@pytest.mark.parametrize(
    ("output", "code"),
    [
        (b"not-nul-terminated", RepairErrorCode.MATERIALIZATION_FAILED),
        (b"bad\0", RepairErrorCode.MATERIALIZATION_FAILED),
        (b"1\t1\t\xff\0", RepairErrorCode.MATERIALIZATION_FAILED),
        (b"1\t1\t../bad\0", RepairErrorCode.MATERIALIZATION_FAILED),
        (b"1\t1\ta.py\01\t1\ta.py\0", RepairErrorCode.MATERIALIZATION_FAILED),
        (b"", RepairErrorCode.PATCH_INVALID),
        (b"0\t0\ta.py\0", RepairErrorCode.PATCH_INVALID),
    ],
)
def test_numstat_rejects_malformed_or_empty_git_output(
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
    code: RepairErrorCode,
) -> None:
    def fake_run_required(*args: object, **kwargs: object) -> repair_git._GitResult:
        return repair_git._GitResult(0, output, b"")

    monkeypatch.setattr(repair_git, "_run_required", fake_run_required)
    with pytest.raises(RepairError) as captured:
        repair_git._read_numstat(_GIT, Path("/"), "a" * 40, {}, _GitLimits())
    assert captured.value.code is code


@pytest.mark.parametrize(
    ("tree_output", "code"),
    [
        (b"not-nul-terminated", RepairErrorCode.GIT_FAILED),
        (b"bad\0", RepairErrorCode.GIT_FAILED),
        (
            b"100644 blob " + b"b" * 40 + b" 1\t\xff\0",
            RepairErrorCode.INVALID_PATH,
        ),
        (
            b"100644 blob " + b"b" * 40 + b" 1\t../bad\0",
            RepairErrorCode.INVALID_PATH,
        ),
        (
            b"100644 blob " + b"b" * 40 + b" -\tapp.py\0",
            RepairErrorCode.MISSING_OBJECT,
        ),
    ],
)
def test_head_traversal_rejects_malformed_git_records(
    monkeypatch: pytest.MonkeyPatch,
    tree_output: bytes,
    code: RepairErrorCode,
) -> None:
    responses = iter((b"1" * 40 + b"\n", tree_output))

    def fake_run_required(*args: object, **kwargs: object) -> repair_git._GitResult:
        return repair_git._GitResult(0, next(responses), b"")

    monkeypatch.setattr(repair_git, "_run_required", fake_run_required)
    with pytest.raises(RepairError) as captured:
        repair_git._read_head_entries(
            _GIT,
            Path("/"),
            "sha1",
            "a" * 40,
            stage=RepairStage.INPUT,
            limits=_GitLimits(),
        )
    assert captured.value.code is code


def test_low_level_helpers_reject_invalid_types_paths_and_commands(tmp_path: Path) -> None:
    with pytest.raises(RepairError):
        repair_git._read_ascii_line(b"\xff\n", RepairStage.INPUT)
    with pytest.raises(RepairError):
        repair_git._require_oid("0" * 40, "sha1", RepairStage.INPUT)
    with pytest.raises(TypeError):
        repair_git._require_repository_identity(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        repair_git._require_git_executable(Path("git"))
    with pytest.raises(TypeError):
        repair_git._resolved_directory(object(), RepairStage.INPUT)  # type: ignore[arg-type]
    with pytest.raises(RepairError):
        repair_git._resolved_directory(tmp_path / "missing", RepairStage.INPUT)
    regular_file = tmp_path / "file"
    regular_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RepairError):
        repair_git._directory_stat(regular_file, RepairStage.INPUT)

    failing = _script(tmp_path / "failing", "raise SystemExit(3)\n")
    with pytest.raises(RepairError) as command:
        repair_git._run_required(
            failing,
            None,
            (),
            stage=RepairStage.INPUT,
            failure_code=RepairErrorCode.GIT_FAILED,
        )
    assert command.value.code is RepairErrorCode.GIT_FAILED
    with pytest.raises(TypeError):
        repair_git._invoke_git(
            _GIT,
            None,
            (),
            stage="input",  # type: ignore[arg-type]
        )
