"""Focused tests for descriptor-safe repair session removal."""

from __future__ import annotations

import os
import secrets
import shutil
from pathlib import Path

import pytest

import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
from repoguard._repair_store import (
    _create_session_store,
    _initialize_runtime_root,
    _locked_session,
    _remove_session_store,
    _session_path_guard,
    _SessionRemovalOutcome,
)
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairManager,
    RepairManagerConfig,
    RepairSnapshot,
    RepairStage,
    RepairState,
)

_SESSION_ID = "a" * 64
_OTHER_SESSION_ID = "b" * 64
_REQUEST_SHA256 = "c" * 64


class _SimulatedCrash(BaseException):
    pass


def _snapshot(session_id: str = _SESSION_ID) -> RepairSnapshot:
    return RepairSnapshot(
        1,
        session_id,
        RepairState.CREATED,
        _REQUEST_SHA256,
        1,
        1,
        1,
        ("src/app.py",),
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )


def _config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        Path("/bin/true"),
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def _initialized_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepairManagerConfig:
    repository = tmp_path / "repository"
    common = repository / ".git"
    repository.mkdir(mode=0o700)
    common.mkdir(mode=0o700)
    config = _config(tmp_path / "runtime")
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    _initialize_runtime_root(config, repository_root=repository, common_dir=common)
    return config


def _create(config: RepairManagerConfig, session_id: str = _SESSION_ID) -> Path:
    _create_session_store(
        config,
        session_id,
        request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
        snapshot=_snapshot(session_id),
    )
    return config.runtime_root / "sessions" / session_id


def _initialized_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairManager]:
    config = _initialized_runtime(tmp_path, monkeypatch)
    root_fd = os.open(config.runtime_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        identity = store_module._runtime_root_identity(root_fd)
    finally:
        os.close(root_fd)
    monkeypatch.setattr(workflow_module, "_initialize_manager", lambda *_: identity)
    manager = RepairManager(RepositoryInput(tmp_path / "repository"), config)
    return config, manager


@pytest.mark.parametrize("maintenance", ["recover", "cleanup"])
def test_maintenance_removes_crash_staging_after_final_state_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    maintenance: str,
) -> None:
    config, manager = _initialized_manager(tmp_path, monkeypatch)
    real_write_atomic = store_module._write_atomic

    def crash_after_write(directory_fd: int, name: str, value: bytes) -> None:
        real_write_atomic(directory_fd, name, value)
        if name == "state.json":
            raise _SimulatedCrash

    monkeypatch.setattr(store_module, "_write_atomic", crash_after_write)
    with pytest.raises(_SimulatedCrash):
        _create_session_store(
            config,
            _SESSION_ID,
            request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
            snapshot=_snapshot(),
            runtime_root_identity=manager._runtime_root_identity,
        )
    monkeypatch.setattr(store_module, "_write_atomic", real_write_atomic)

    sessions = config.runtime_root / "sessions"
    staging = tuple(sessions.glob(f".{_SESSION_ID}.tmp-*"))
    assert len(staging) == 1
    assert (staging[0] / "state.json").is_file()
    report = manager.recover() if maintenance == "recover" else manager.cleanup()

    assert report.removed_session_ids == (_SESSION_ID,)
    assert report.failed_session_ids == ()
    assert not staging[0].exists()
    repeated = manager.recover() if maintenance == "recover" else manager.cleanup()
    assert repeated.removed_session_ids == ()
    assert repeated.failed_session_ids == ()


@pytest.mark.parametrize("maintenance", ["recover", "cleanup"])
def test_maintenance_removes_exact_staging_without_session_lock_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    maintenance: str,
) -> None:
    config, manager = _initialized_manager(tmp_path, monkeypatch)
    sessions = config.runtime_root / "sessions"
    staging = sessions / f".{_SESSION_ID}.tmp-{'1' * 16}"
    staging.mkdir(mode=0o700)
    private = staging / "private"
    private.mkdir(mode=0o700)
    request = private / "request.json"
    request.write_bytes(b"private")
    request.chmod(0o400)
    sessions_inode = sessions.stat().st_ino
    fsynced_inodes: list[int] = []
    real_fsync = store_module._fsync

    def record_fsync(descriptor: int) -> None:
        fsynced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(store_module, "_fsync", record_fsync)
    report = manager.recover() if maintenance == "recover" else manager.cleanup()

    assert report.removed_session_ids == (_SESSION_ID,)
    assert report.failed_session_ids == ()
    assert not staging.exists()
    assert sessions_inode in fsynced_inodes
    repeated = manager.recover() if maintenance == "recover" else manager.cleanup()
    assert repeated.removed_session_ids == ()
    assert repeated.failed_session_ids == ()


@pytest.mark.parametrize(
    "unsafe_kind",
    ["symlink", "mode", "foreign_owner", "hardlink", "cross_mount"],
)
def test_maintenance_refuses_unsafe_exact_staging_and_ignores_other_temps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    config, manager = _initialized_manager(tmp_path, monkeypatch)
    sessions = config.runtime_root / "sessions"
    staging_name = f".{_SESSION_ID}.tmp-{'1' * 16}"
    staging = sessions / staging_name
    outside = tmp_path / "outside-staging"
    outside.mkdir(mode=0o700)
    outside_sentinel = outside / "sentinel"
    outside_sentinel.write_bytes(b"retain")
    outside_sentinel.chmod(0o600)

    if unsafe_kind == "symlink":
        staging.symlink_to(outside, target_is_directory=True)
    else:
        staging.mkdir(mode=0o700)
        retained = staging / "a-retained"
        retained.write_bytes(b"retain")
        retained.chmod(0o600)
        if unsafe_kind == "mode":
            staging.chmod(0o755)
        elif unsafe_kind == "foreign_owner":
            staging_inode = staging.stat().st_ino
            real_validate = store_module._validate_removal_metadata

            def simulate_foreign_owner(
                metadata: os.stat_result,
                *,
                directory: bool,
            ) -> None:
                if metadata.st_ino == staging_inode:
                    fields = list(metadata)
                    fields[4] = metadata.st_uid + 1
                    metadata = os.stat_result(fields)
                real_validate(metadata, directory=directory)

            monkeypatch.setattr(
                store_module,
                "_validate_removal_metadata",
                simulate_foreign_owner,
            )
        elif unsafe_kind == "hardlink":
            linked = staging / "z-linked"
            linked.write_bytes(b"linked")
            linked.chmod(0o600)
            os.link(linked, tmp_path / "outside-hardlink")
        else:
            staging_inode = staging.stat().st_ino
            real_mount_id = store_module._descriptor_mount_id

            def simulate_cross_mount(descriptor: int) -> int:
                mount_id = real_mount_id(descriptor)
                if os.fstat(descriptor).st_ino == staging_inode:
                    return mount_id + 1
                return mount_id

            monkeypatch.setattr(
                store_module,
                "_descriptor_mount_id",
                simulate_cross_mount,
            )

    nonmatching = sessions / f".{_OTHER_SESSION_ID}.tmp-not-exact"
    nonmatching.mkdir(mode=0o700)
    nonmatching_sentinel = nonmatching / "sentinel"
    nonmatching_sentinel.write_bytes(b"retain")
    nonmatching_sentinel.chmod(0o600)

    report = manager.cleanup()

    assert report.removed_session_ids == ()
    assert report.failed_session_ids == (_SESSION_ID,)
    assert staging.is_symlink() if unsafe_kind == "symlink" else staging.is_dir()
    if unsafe_kind != "symlink":
        assert (staging / "a-retained").read_bytes() == b"retain"
    assert outside_sentinel.read_bytes() == b"retain"
    assert nonmatching_sentinel.read_bytes() == b"retain"


def test_failed_creation_does_not_remove_preexisting_exact_staging_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    staging = config.runtime_root / "sessions" / f".{_SESSION_ID}.tmp-{'1' * 16}"
    staging.mkdir(mode=0o700)
    sentinel = staging / "sentinel"
    sentinel.write_bytes(b"preexisting")
    sentinel.chmod(0o600)
    monkeypatch.setattr(secrets, "token_hex", lambda _: "1" * 16)

    with pytest.raises(RepairError) as captured:
        _create_session_store(
            config,
            _SESSION_ID,
            request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
            snapshot=_snapshot(),
        )

    assert captured.value.code is RepairErrorCode.PERSISTENCE_FAILED
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.session_id == _SESSION_ID
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert sentinel.read_bytes() == b"preexisting"


def test_remove_session_store_recurses_and_fsyncs_sessions_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    nested = session / "private" / "nested"
    nested.mkdir(mode=0o700)
    payload = nested / "payload.bin"
    payload.write_bytes(b"private")
    payload.chmod(0o400)
    sessions_inode = session.parent.stat().st_ino
    fsynced_inodes: list[int] = []
    real_fsync = store_module._fsync

    def observe_fsync(descriptor: int) -> None:
        fsynced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(store_module, "_fsync", observe_fsync)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REMOVED
    assert not session.exists()
    assert sessions_inode in fsynced_inodes


def test_remove_session_store_is_idempotent_and_fsyncs_confirmed_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REMOVED

    sessions = config.runtime_root / "sessions"
    sessions_inode = sessions.stat().st_ino
    fsynced_inodes: list[int] = []
    real_fsync = store_module._fsync

    def observe_fsync(descriptor: int) -> None:
        fsynced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(store_module, "_fsync", observe_fsync)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.ABSENT
    assert fsynced_inodes == [sessions_inode]


@pytest.mark.parametrize(
    "session_id",
    ["", "a" * 63, "A" * 64, "g" * 64, "../" + "a" * 61],
)
def test_remove_session_store_rejects_noncanonical_ids_before_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_id: str,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)

    with pytest.raises(ValueError, match="session_id is invalid"):
        _remove_session_store(config, session_id)

    assert session.is_dir()


def test_remove_session_store_refuses_nested_symlink_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    target = tmp_path / "outside"
    target.mkdir(mode=0o700)
    sentinel = target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    link = session / "private" / "outside-link"
    link.symlink_to(target, target_is_directory=True)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert session.is_dir()
    assert link.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert (session / "events" / "0000000000000000.json").is_file()


def test_private_cleanup_preflights_the_entire_tree_before_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    private = session / "private"
    retained = private / "retained.bin"
    retained.write_bytes(b"private")
    retained.chmod(0o400)
    target = tmp_path / "outside-private"
    target.mkdir(mode=0o700)
    sentinel = target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    link = private / "outside-link"
    link.symlink_to(target, target_is_directory=True)

    with _locked_session(config, _SESSION_ID) as storage:
        assert storage.cleanup_private() is False

    assert retained.read_bytes() == b"private"
    assert link.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_private_cleanup_refuses_a_replacement_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    private = session / "private"
    displaced = session / "private-displaced"

    with _locked_session(config, _SESSION_ID) as storage:
        private.rename(displaced)
        private.mkdir(mode=0o700)
        replacement_payload = private / "unrelated.bin"
        replacement_payload.write_bytes(b"retain replacement")
        replacement_payload.chmod(0o600)

        assert storage.cleanup_private() is False

    assert replacement_payload.read_bytes() == b"retain replacement"
    assert (displaced / "request.json").is_file()


def test_private_cleanup_refuses_mode_and_mount_identity_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    private = session / "private"

    with _locked_session(config, _SESSION_ID) as storage:
        private.chmod(0o755)
        assert storage.cleanup_private() is False
    assert (private / "request.json").is_file()

    private.chmod(0o700)
    calls = 0

    def changed_mount(_: int) -> int:
        nonlocal calls
        calls += 1
        return calls

    monkeypatch.setattr(store_module, "_descriptor_mount_id", changed_mount)
    with _locked_session(config, _SESSION_ID) as storage:
        assert storage.cleanup_private() is False
    assert (private / "request.json").is_file()


def test_private_cleanup_reports_descriptor_close_failure_after_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    real_close = os.close

    with _locked_session(config, _SESSION_ID) as storage:
        private_fd = storage._private_fd
        assert private_fd is not None
        failed = False

        def fail_private_close(descriptor: int) -> None:
            nonlocal failed
            real_close(descriptor)
            if descriptor == private_fd and not failed:
                failed = True
                raise OSError("simulated private descriptor close failure")

        monkeypatch.setattr(os, "close", fail_private_close)
        assert storage.cleanup_private() is False
        assert storage._private_fd is None
        assert storage.cleanup_private() is True

    assert failed is True
    assert not (session / "private").exists()


def test_private_cleanup_uses_the_already_pinned_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)

    def reject_reopen(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("private cleanup must not reopen the private directory")

    monkeypatch.setattr(store_module, "_open_removal_directory", reject_reopen)
    with _locked_session(config, _SESSION_ID) as storage:
        assert storage.cleanup_private() is True

    assert not (session / "private").exists()


def test_remove_session_store_refuses_symlink_at_canonical_session_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    target = tmp_path / "outside-session"
    target.mkdir(mode=0o700)
    sentinel = target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    link = config.runtime_root / "sessions" / _SESSION_ID
    link.symlink_to(target, target_is_directory=True)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert link.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_remove_session_store_refuses_simulated_foreign_owner_before_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    event = session / "events" / "0000000000000000.json"
    event_inode = event.stat().st_ino
    real_fstat = os.fstat

    def foreign_event_owner(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if metadata.st_ino != event_inode:
            return metadata
        values = list(metadata)
        values[4] = metadata.st_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", foreign_event_owner)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert session.is_dir()
    assert event.is_file()
    assert (session / "private" / "request.json").is_file()


def test_remove_session_store_refuses_unsafe_mode_and_hardlink_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    state = session / "state.json"
    state.chmod(0o644)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert session.is_dir()

    state.chmod(0o600)
    event = session / "events" / "0000000000000000.json"
    outside_link = tmp_path / "event-hardlink"
    os.link(event, outside_link)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert session.is_dir()
    assert outside_link.read_bytes() == event.read_bytes()


def test_remove_session_store_returns_failed_for_io_error_without_escaping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    real_unlink = os.unlink

    def fail_event_unlink(
        path: str | bytes,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if path == "0000000000000000.json":
            raise OSError("simulated unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", fail_event_unlink)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.FAILED
    assert session.is_dir()
    assert (session / "events" / "0000000000000000.json").is_file()


def test_remove_session_store_keeps_other_canonical_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    removed = _create(config)
    retained = _create(config, _OTHER_SESSION_ID)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REMOVED
    assert not removed.exists()
    assert retained.is_dir()
    assert (retained / "private" / "request.json").is_file()


def test_remove_session_store_reports_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)

    def fail_fsync(_: int) -> None:
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(store_module, "_fsync", fail_fsync)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.FAILED
    assert not session.exists()


def test_remove_session_store_refuses_an_active_session_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)

    with _locked_session(config, _SESSION_ID):
        monkeypatch.setattr(store_module, "_acquire_flock", lambda *_: False)
        outcome = _remove_session_store(config, _SESSION_ID)

    assert outcome is _SessionRemovalOutcome.FAILED
    assert session.is_dir()
    assert (session / "events" / "0000000000000000.json").is_file()


def test_locked_session_revalidates_its_name_after_waiting_for_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    displaced = session.with_name("displaced-session")

    def displace_before_acquire(*_: object) -> bool:
        session.rename(displaced)
        return True

    monkeypatch.setattr(store_module, "_acquire_flock", displace_before_acquire)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION_ID):
        pytest.fail("an unlinked session must never become usable")

    assert captured.value.code is RepairErrorCode.SESSION_NOT_FOUND
    assert displaced.is_dir()


def test_remove_session_store_refuses_cross_mount_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    nested = session / "private" / "mounted"
    nested.mkdir(mode=0o700)
    payload = nested / "payload.bin"
    payload.write_bytes(b"retain")
    payload.chmod(0o400)
    nested_inode = nested.stat().st_ino
    real_mount_id = store_module._descriptor_mount_id

    def simulated_mount_id(descriptor: int) -> int:
        mount_id = real_mount_id(descriptor)
        if os.fstat(descriptor).st_ino == nested_inode:
            return mount_id + 1
        return mount_id

    monkeypatch.setattr(store_module, "_descriptor_mount_id", simulated_mount_id)

    assert _remove_session_store(config, _SESSION_ID) is _SessionRemovalOutcome.REFUSED
    assert session.is_dir()
    assert payload.read_bytes() == b"retain"


def test_session_path_guard_rechecks_runtime_root_after_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    original_open = store_module._open_runtime_root

    def replace_after_open(
        current_config: RepairManagerConfig,
        identity: tuple[int, int] | None,
    ) -> int:
        descriptor = original_open(current_config, identity)
        displaced = current_config.runtime_root.with_name("runtime-displaced")
        current_config.runtime_root.rename(displaced)
        current_config.runtime_root.mkdir(mode=0o700)
        return descriptor

    monkeypatch.setattr(store_module, "_open_runtime_root", replace_after_open)
    with pytest.raises(RepairError) as captured, _session_path_guard(config, _SESSION_ID):
        pytest.fail("a replaced runtime root must not become usable")
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def test_session_path_guard_rejects_bound_file_replacement_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    request = session / "private" / "request.json"

    with _session_path_guard(config, _SESSION_ID) as runtime:
        bindings = runtime.capture_paths(((request, False),))
        request.unlink()
        request.write_text(
            '{"request_sha256":"' + _REQUEST_SHA256 + '","schema_version":1}',
            encoding="utf-8",
        )
        request.chmod(0o400)
        with pytest.raises(RepairError) as captured:
            runtime.revalidate_paths(bindings)

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def test_session_path_guard_keeps_private_and_candidate_writes_on_pinned_inodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    session = _create(config)
    private = session / "private"
    displaced_private = session / "private-displaced"
    replacement_private = session / "private-replacement"

    with _session_path_guard(config, _SESSION_ID) as runtime:
        private_io = runtime.io_path()
        private.rename(displaced_private)
        shutil.copytree(displaced_private, private)
        (private_io / "guard-secret.bin").write_bytes(b"pinned-private")
        (private_io / "guard-secret.bin").chmod(0o600)
        private.rename(replacement_private)
        displaced_private.rename(private)

        repository_binding = runtime.create_directory("repository")
        repository_io = runtime.io_path(repository_binding)
        repository = private / "repository"
        displaced_repository = private / "repository-displaced"
        replacement_repository = private / "repository-replacement"
        repository.rename(displaced_repository)
        repository.mkdir(mode=0o700)
        (repository_io / "candidate-secret.bin").write_bytes(b"pinned-repository")
        (repository_io / "candidate-secret.bin").chmod(0o600)
        repository.rename(replacement_repository)
        displaced_repository.rename(repository)

    assert (private / "guard-secret.bin").read_bytes() == b"pinned-private"
    assert not (replacement_private / "guard-secret.bin").exists()
    assert (private / "repository" / "candidate-secret.bin").read_bytes() == (b"pinned-repository")
    assert not (replacement_repository / "candidate-secret.bin").exists()
