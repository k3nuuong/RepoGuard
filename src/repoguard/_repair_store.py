"""Durable, hash-linked local storage for safe repair sessions."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from repoguard._repair_models import (
    _can_transition,
    _canonical_bytes,
    _domain_digest,
    _repair_snapshot_from_dict,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairManagerConfig,
    RepairSnapshot,
    RepairStage,
    RepairState,
    repair_application_to_dict,
    repair_approval_to_dict,
    repair_candidate_to_dict,
    repair_decision_to_dict,
    repair_snapshot_to_dict,
    repair_validation_to_dict,
)

type _RuntimeRootIdentity = tuple[int, int]

_EVENT_NAME_LENGTH = 21
_MAX_RECORD_BYTES = 4 * 1_048_576
_TERMINAL_STATES = frozenset(
    {
        RepairState.APPLIED,
        RepairState.REJECTED,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }
)
_EVENT_STATE_PAIRS: dict[str, frozenset[tuple[RepairState, RepairState]]] = {
    "generating": frozenset({(RepairState.CREATED, RepairState.GENERATING)}),
    "candidate": frozenset({(RepairState.GENERATING, RepairState.GENERATING)}),
    "validating": frozenset({(RepairState.GENERATING, RepairState.VALIDATING)}),
    "validation_intent": frozenset({(RepairState.VALIDATING, RepairState.VALIDATING)}),
    "validation_intent_abandoned": frozenset({(RepairState.VALIDATING, RepairState.VALIDATING)}),
    "validation_run": frozenset(
        {
            (RepairState.VALIDATING, RepairState.VALIDATING),
            (RepairState.CANCELLED, RepairState.CANCELLED),
            (RepairState.EXPIRED, RepairState.EXPIRED),
            (RepairState.FAILED, RepairState.FAILED),
        }
    ),
    "validation_result": frozenset({(RepairState.VALIDATING, RepairState.VALIDATING)}),
    "validated": frozenset({(RepairState.VALIDATING, RepairState.VALIDATED)}),
    "approved": frozenset({(RepairState.VALIDATED, RepairState.APPROVED)}),
    "applying": frozenset({(RepairState.APPROVED, RepairState.APPLYING)}),
    "applied": frozenset({(RepairState.APPLYING, RepairState.APPLIED)}),
    "rejected": frozenset(
        {
            (RepairState.VALIDATED, RepairState.REJECTED),
            (RepairState.APPROVED, RepairState.REJECTED),
        }
    ),
    "cancelled": frozenset(
        {
            (RepairState.CREATED, RepairState.CANCELLED),
            (RepairState.GENERATING, RepairState.CANCELLED),
            (RepairState.VALIDATING, RepairState.CANCELLED),
            (RepairState.VALIDATED, RepairState.CANCELLED),
            (RepairState.APPROVED, RepairState.CANCELLED),
        }
    ),
    "expired": frozenset(
        {
            (RepairState.CREATED, RepairState.EXPIRED),
            (RepairState.GENERATING, RepairState.EXPIRED),
            (RepairState.VALIDATING, RepairState.EXPIRED),
            (RepairState.VALIDATED, RepairState.EXPIRED),
            (RepairState.APPROVED, RepairState.EXPIRED),
        }
    ),
    "failed": frozenset(
        {
            (RepairState.GENERATING, RepairState.FAILED),
            (RepairState.VALIDATING, RepairState.FAILED),
        }
    ),
    "application_conflict": frozenset({(RepairState.APPLYING, RepairState.APPROVED)}),
    "recovered": frozenset({(RepairState.APPLYING, RepairState.APPROVED)}),
    "cleanup_complete": frozenset((state, state) for state in _TERMINAL_STATES),
    "cleanup_pending": frozenset((state, state) for state in _TERMINAL_STATES),
}
_EVENT_KINDS = frozenset({"created", *_EVENT_STATE_PAIRS})
_SNAPSHOT_IDENTITY_FIELDS = (
    "schema_version",
    "session_id",
    "request_sha256",
    "created_at_us",
    "target_count",
    "allowed_paths",
)
_SNAPSHOT_MUTABLE_FIELDS = (
    "candidate",
    "validation",
    "approval",
    "application",
    "decision",
    "failure",
    "cleanup_pending",
)
_EVENT_SNAPSHOT_CHANGES: dict[str, frozenset[str]] = {
    "generating": frozenset(),
    "candidate": frozenset({"candidate"}),
    "validating": frozenset(),
    "validation_intent": frozenset(),
    "validation_intent_abandoned": frozenset(),
    "validation_run": frozenset(),
    "validation_result": frozenset({"validation"}),
    "validated": frozenset(),
    "approved": frozenset({"approval"}),
    "applying": frozenset(),
    "applied": frozenset({"application", "cleanup_pending"}),
    "rejected": frozenset({"decision", "cleanup_pending"}),
    "cancelled": frozenset({"decision", "cleanup_pending"}),
    "expired": frozenset({"decision", "cleanup_pending"}),
    "failed": frozenset({"failure", "cleanup_pending"}),
    "application_conflict": frozenset(),
    "recovered": frozenset(),
    "cleanup_complete": frozenset({"cleanup_pending"}),
}
_LEASE_CARRY_STATES = frozenset(
    {
        RepairState.VALIDATING,
        RepairState.CANCELLED,
        RepairState.EXPIRED,
        RepairState.FAILED,
    }
)
_EVENT_NAME_PATTERN = re.compile(r"^[0-9]{16}\.json$")
_EVENT_TEMP_PATTERN = re.compile(r"^\.(?P<event>[0-9]{16}\.json)\.tmp-[0-9a-f]{32}$")
_STAGING_NAME_PATTERN = re.compile(r"^\.(?P<session_id>[0-9a-f]{64})\.tmp-[0-9a-f]{16}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VALIDATION_LABELS = frozenset(
    {
        "com.repoguard.component",
        "com.repoguard.session",
        "com.repoguard.candidate",
        "com.repoguard.run-token-sha256",
    }
)
_VALIDATION_COMPONENT = "safe-repair-validation"
_REMOVABLE_FILE_MODES = frozenset({0o400, 0o500, 0o600})


class _SessionRemovalOutcome(StrEnum):
    REMOVED = "removed"
    ABSENT = "absent"
    REFUSED = "refused"
    FAILED = "failed"


class _UnsafeRemoval(RuntimeError):
    """Internal marker for metadata that must never be removed."""


@dataclass(frozen=True, slots=True)
class _ValidationRunLease:
    container_id: str | None
    container_name: str
    labels: tuple[tuple[str, str], ...]
    session_id: str
    candidate_id: str
    run_token_sha256: str

    def __post_init__(self) -> None:
        if self.container_id is not None and (
            type(self.container_id) is not str
            or _SHA256_PATTERN.fullmatch(self.container_id) is None
        ):
            raise ValueError("validation run container identity is invalid")
        for value in (self.session_id, self.candidate_id, self.run_token_sha256):
            if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError("validation run digest identity is invalid")
        if (
            type(self.container_name) is not str
            or _CONTAINER_NAME_PATTERN.fullmatch(self.container_name) is None
        ):
            raise ValueError("validation run container name is invalid")
        if (
            type(self.labels) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or any(type(part) is not str for part in item)
                for item in self.labels
            )
            or tuple(sorted(self.labels)) != self.labels
            or len({name for name, _ in self.labels}) != len(self.labels)
        ):
            raise ValueError("validation run labels are invalid")
        labels = dict(self.labels)
        if set(labels) != _VALIDATION_LABELS or labels != {
            "com.repoguard.component": _VALIDATION_COMPONENT,
            "com.repoguard.session": self.session_id,
            "com.repoguard.candidate": self.candidate_id,
            "com.repoguard.run-token-sha256": self.run_token_sha256,
        }:
            raise ValueError("validation run labels do not match")


@dataclass(frozen=True, slots=True)
class _LoadedState:
    snapshot: RepairSnapshot
    event_sequence: int
    event_sha256: str
    event_timestamp_us: int
    preview_sha256: str | None
    validation_run: _ValidationRunLease | None


@dataclass(frozen=True, slots=True)
class _RuntimePathBinding:
    relative_parts: tuple[str, ...]
    directory: bool
    signatures: tuple[tuple[int, ...], ...]
    descriptor: int


class _SessionPathGuard:
    __slots__ = (
        "_bound_fds",
        "_config",
        "_named_path",
        "_private_fd",
        "_root_fd",
        "_runtime_root_identity",
        "_session_fd",
        "_sessions_fd",
        "session_id",
    )

    def __init__(
        self,
        config: RepairManagerConfig,
        session_id: str,
        runtime_root_identity: _RuntimeRootIdentity | None,
        root_fd: int,
        sessions_fd: int,
        session_fd: int,
        private_fd: int,
    ) -> None:
        self._config = config
        self.session_id = session_id
        self._runtime_root_identity = runtime_root_identity
        self._root_fd = root_fd
        self._sessions_fd = sessions_fd
        self._session_fd = session_fd
        self._private_fd = private_fd
        self._bound_fds: list[int] = []
        self._named_path = config.runtime_root / "sessions" / session_id / "private"

    def revalidate(self) -> None:
        failed = False
        try:
            _revalidate_runtime_root(
                self._config,
                self._root_fd,
                self._runtime_root_identity,
            )
            _require_named_fd_entry(
                self._root_fd,
                "sessions",
                self._sessions_fd,
                directory=True,
                mode=0o700,
            )
            _require_named_fd_entry(
                self._sessions_fd,
                self.session_id,
                self._session_fd,
                directory=True,
                mode=0o700,
            )
            _require_named_fd_entry(
                self._session_fd,
                "private",
                self._private_fd,
                directory=True,
                mode=0o700,
            )
        except OSError:
            failed = True
        if failed:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )

    def private_identity(self) -> _RuntimeRootIdentity:
        self.revalidate()
        metadata = os.fstat(self._private_fd)
        return metadata.st_dev, metadata.st_ino

    def create_directory(self, name: str) -> _RuntimePathBinding:
        if type(name) is not str or name not in {"repository", "candidate-input"}:
            raise ValueError("runtime directory name is invalid")
        self.revalidate()
        failed = False
        binding: _RuntimePathBinding | None = None
        try:
            os.mkdir(name, 0o700, dir_fd=self._private_fd)
            binding = _capture_runtime_path_binding(
                self._private_fd,
                (name,),
                directory=True,
            )
        except (OSError, RuntimeError, ValueError):
            failed = True
        if failed or binding is None:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )
        self._bound_fds.append(binding.descriptor)
        self.revalidate_paths((binding,))
        return binding

    def io_path(self, binding: _RuntimePathBinding | None = None) -> Path:
        if binding is None:
            self.revalidate()
            descriptor = self._private_fd
        else:
            if (
                type(binding) is not _RuntimePathBinding
                or binding.descriptor not in self._bound_fds
            ):
                raise TypeError("runtime path binding must be owned by this guard")
            self.revalidate_paths((binding,))
            descriptor = binding.descriptor
        path = Path("/proc/self/fd") / str(descriptor)
        failed = False
        try:
            _require_runtime_path_metadata(
                os.fstat(descriptor),
                path.stat(),
                directory=True if binding is None else binding.directory,
            )
        except OSError:
            failed = True
        if failed:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )
        return path

    def capture_paths(
        self,
        paths: tuple[tuple[Path, bool], ...],
    ) -> tuple[_RuntimePathBinding, ...]:
        if type(paths) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or not isinstance(item[0], Path)
            or type(item[1]) is not bool
            for item in paths
        ):
            raise TypeError("runtime paths must be exact path/type pairs")
        io_path = self.io_path()
        failed = False
        bindings: list[_RuntimePathBinding] = []
        try:
            for path, directory in paths:
                bindings.append(
                    _capture_runtime_path_binding(
                        self._private_fd,
                        _runtime_relative_parts(self._named_path, io_path, path),
                        directory=directory,
                    )
                )
        except (OSError, RuntimeError, ValueError):
            failed = True
        if failed:
            for binding in bindings:
                with suppress(OSError):
                    os.close(binding.descriptor)
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )
        self._bound_fds.extend(binding.descriptor for binding in bindings)
        result = tuple(bindings)
        self.revalidate_paths(result)
        return result

    def revalidate_paths(self, bindings: tuple[_RuntimePathBinding, ...]) -> None:
        if type(bindings) is not tuple or any(
            type(binding) is not _RuntimePathBinding for binding in bindings
        ):
            raise TypeError("runtime path bindings must be an exact tuple")
        self.revalidate()
        failed = False
        current: list[_RuntimePathBinding] = []
        try:
            for binding in bindings:
                if binding.descriptor not in self._bound_fds:
                    raise ValueError("runtime path binding is not owned by this guard")
                current.append(
                    _capture_runtime_path_binding(
                        self._private_fd,
                        binding.relative_parts,
                        directory=binding.directory,
                    )
                )
                if (
                    _runtime_binding_identity(current[-1]) != _runtime_binding_identity(binding)
                    or _runtime_path_signature(os.fstat(binding.descriptor))
                    != binding.signatures[-1]
                ):
                    failed = True
        except (OSError, RuntimeError, ValueError):
            failed = True
        finally:
            for observed in current:
                try:
                    os.close(observed.descriptor)
                except OSError:
                    failed = True
        if failed:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )
        self.revalidate()

    def named_path(self, binding: _RuntimePathBinding) -> Path:
        if type(binding) is not _RuntimePathBinding:
            raise TypeError("runtime path binding must be exact")
        self.revalidate_paths((binding,))
        return self._named_path.joinpath(*binding.relative_parts)

    def require_same_target(
        self,
        binding: _RuntimePathBinding,
        path: Path,
        *,
        directory: bool,
    ) -> None:
        if (
            type(binding) is not _RuntimePathBinding
            or binding.descriptor not in self._bound_fds
            or not isinstance(path, Path)
            or not path.is_absolute()
            or type(directory) is not bool
            or binding.directory is not directory
        ):
            raise TypeError("runtime target comparison is invalid")
        self.revalidate_paths((binding,))
        failed = False
        try:
            _require_runtime_path_metadata(
                os.fstat(binding.descriptor),
                path.stat(),
                directory=directory,
            )
        except OSError:
            failed = True
        if failed:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )

    def close(self) -> bool:
        closed = True
        for descriptor in (
            *reversed(self._bound_fds),
            self._private_fd,
            self._session_fd,
            self._sessions_fd,
            self._root_fd,
        ):
            try:
                os.close(descriptor)
            except OSError:
                closed = False
        return closed


class _SessionStore:
    __slots__ = ("_config", "_events_fd", "_lock_fd", "_private_fd", "_session_fd", "session_id")

    def __init__(
        self,
        config: RepairManagerConfig,
        session_id: str,
        session_fd: int,
        events_fd: int,
        private_fd: int | None,
        lock_fd: int,
    ) -> None:
        self._config = config
        self.session_id = session_id
        self._session_fd = session_fd
        self._events_fd = events_fd
        self._private_fd = private_fd
        self._lock_fd = lock_fd

    def close(self) -> None:
        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
        if self._private_fd is not None:
            os.close(self._private_fd)
        os.close(self._events_fd)
        os.close(self._session_fd)

    def publication_lock_fd(self) -> int:
        try:
            os.fstat(self._lock_fd)
        except OSError:
            raise ValueError("session lock descriptor is closed") from None
        return self._lock_fd

    def private_identity(self) -> _RuntimeRootIdentity | None:
        if self._private_fd is None:
            return None
        metadata = os.fstat(self._private_fd)
        return metadata.st_dev, metadata.st_ino

    def load(self) -> _LoadedState:
        invalid_chain = False
        try:
            loaded = _load_event_chain(self._events_fd, self.session_id)
        except RepairError:
            raise
        except (OSError, TypeError, ValueError):
            invalid_chain = True
            loaded = None
        if invalid_chain or loaded is None:
            _raise_corrupt(self.session_id)
        cached = _read_cache(self._session_fd)
        if cached != _cache_mapping(loaded):
            _write_atomic(self._session_fd, "state.json", _canonical_bytes(_cache_mapping(loaded)))
        return loaded

    def append(
        self,
        kind: str,
        snapshot: RepairSnapshot,
        *,
        validation_run: _ValidationRunLease | None = None,
        clear_validation_run: bool = False,
    ) -> _LoadedState:
        if type(kind) is not str or kind not in _EVENT_KINDS:
            raise ValueError("event kind is invalid")
        if type(snapshot) is not RepairSnapshot or snapshot.session_id != self.session_id:
            raise ValueError("event snapshot is invalid")
        if type(clear_validation_run) is not bool or (
            validation_run is not None and clear_validation_run
        ):
            raise ValueError("validation run update is invalid")
        current = self.load()
        next_validation_run = current.validation_run
        if validation_run is not None:
            if (
                type(validation_run) is not _ValidationRunLease
                or kind not in {"validation_intent", "validation_run"}
                or (kind == "validation_intent" and snapshot.state is not RepairState.VALIDATING)
                or (kind == "validation_run" and snapshot.state not in _LEASE_CARRY_STATES)
            ):
                raise ValueError("validation run registration is invalid")
            next_validation_run = validation_run
        elif kind in {"validation_intent", "validation_run"}:
            raise ValueError("validation run event requires a lease")
        elif clear_validation_run:
            if current.validation_run is None:
                raise ValueError("validation run is not registered")
            next_validation_run = None
        if snapshot.created_at_us != current.snapshot.created_at_us or (
            snapshot.updated_at_us < current.snapshot.updated_at_us
        ):
            raise ValueError("event timestamps are invalid")
        if not _event_state_pair_is_valid(kind, current.snapshot.state, snapshot.state):
            _raise_store_error(
                RepairErrorCode.INVALID_STATE,
                RepairStage.PERSISTENCE,
                current.snapshot.state,
                self.session_id,
            )
        if not _validation_run_update_is_valid(
            kind,
            current.snapshot,
            snapshot,
            current.validation_run,
            next_validation_run,
        ):
            raise ValueError("validation run update is invalid")
        next_preview_sha256 = current.preview_sha256
        if kind == "candidate" and next_preview_sha256 is None:
            try:
                preview = _read_canonical_mapping(
                    self._session_fd,
                    "preview.json",
                    _MAX_RECORD_BYTES,
                    immutable=True,
                )
            except (OSError, TypeError, ValueError):
                raise ValueError("candidate preview is invalid") from None
            next_preview_sha256 = _domain_digest("preview", preview)
        if not _candidate_preview_update_is_valid(
            kind,
            current.snapshot,
            snapshot,
            current.preview_sha256,
            next_preview_sha256,
        ):
            raise ValueError("candidate preview update is invalid")
        if not _snapshot_update_is_valid(kind, current.snapshot, snapshot):
            raise ValueError("event snapshot update is invalid")
        if not _snapshot_record_digests_are_valid(snapshot):
            raise ValueError("event snapshot record digest is invalid")
        sequence = current.event_sequence + 1
        timestamp_us = snapshot.updated_at_us
        event = _event_mapping(
            sequence,
            current.event_sha256,
            kind,
            timestamp_us,
            snapshot,
            next_preview_sha256,
            next_validation_run,
        )
        digest = _domain_digest("event", event)
        _write_event_immutable(self._events_fd, _event_name(sequence), _canonical_bytes(event))
        loaded = _LoadedState(
            snapshot,
            sequence,
            digest,
            timestamp_us,
            next_preview_sha256,
            next_validation_run,
        )
        _write_atomic(self._session_fd, "state.json", _canonical_bytes(_cache_mapping(loaded)))
        return loaded

    def write_private_json(self, name: str, value: Mapping[str, object]) -> None:
        private_fd = self._require_private_fd()
        _validate_payload_name(name)
        _write_immutable(private_fd, name, _canonical_bytes(value))

    def read_private_json(self, name: str) -> dict[str, object]:
        private_fd = self._require_private_fd()
        _validate_payload_name(name)
        return _read_canonical_mapping(private_fd, name, _MAX_RECORD_BYTES, immutable=True)

    def write_private_bytes(self, name: str, value: bytes) -> None:
        private_fd = self._require_private_fd()
        _validate_payload_name(name)
        if type(value) is not bytes or len(value) > _MAX_RECORD_BYTES:
            raise ValueError("private payload is invalid")
        _write_immutable(private_fd, name, value)

    def read_private_bytes(self, name: str, maximum: int = _MAX_RECORD_BYTES) -> bytes:
        private_fd = self._require_private_fd()
        _validate_payload_name(name)
        return _read_file(private_fd, name, maximum, immutable=True)

    def write_preview(self, value: Mapping[str, object]) -> None:
        _write_immutable(self._session_fd, "preview.json", _canonical_bytes(value))

    def read_preview(self) -> dict[str, object]:
        value = _read_canonical_mapping(
            self._session_fd,
            "preview.json",
            _MAX_RECORD_BYTES,
            immutable=True,
        )
        expected = self.load().preview_sha256
        if expected is None or _domain_digest("preview", value) != expected:
            _raise_corrupt(self.session_id)
        return value

    def cleanup_private(self) -> bool:
        if self._private_fd is None:
            try:
                os.stat("private", dir_fd=self._session_fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            except OSError:
                return False
            return False
        private_fd = self._private_fd
        try:
            metadata = os.stat("private", dir_fd=self._session_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            return False
        removed = False
        try:
            mount_id = _descriptor_mount_id(self._session_fd)
            _validate_removal_metadata(metadata, directory=True)
            _require_named_removal_entry(
                self._session_fd,
                "private",
                os.fstat(private_fd),
                directory=True,
            )
            _require_removal_mount(private_fd, mount_id)
            _verify_removal_tree(private_fd, mount_id)
            _remove_tree_contents(private_fd, mount_id)
            if os.listdir(private_fd):
                raise _UnsafeRemoval("private payload changed during removal")
            _require_named_removal_entry(
                self._session_fd,
                "private",
                os.fstat(private_fd),
                directory=True,
            )
            os.rmdir("private", dir_fd=self._session_fd)
            _fsync(self._session_fd)
            self._private_fd = None
            os.close(private_fd)
            removed = True
        except (_UnsafeRemoval, OSError):
            pass
        return removed

    def _require_private_fd(self) -> int:
        if self._private_fd is None:
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                self.session_id,
            )
        return self._private_fd


def _initialize_runtime_root(
    config: RepairManagerConfig,
    *,
    repository_root: Path,
    common_dir: Path,
) -> _RuntimeRootIdentity:
    _validate_host_inputs(config)
    _require_no_symlink_ancestors(config.runtime_root)
    root_fd: int | None = None
    runtime_root_identity: _RuntimeRootIdentity | None = None
    invalid = False
    try:
        with suppress(FileExistsError):
            config.runtime_root.mkdir(mode=0o700)
        _validate_owned_directory(config.runtime_root)
        _require_disjoint(config.runtime_root, repository_root)
        _require_disjoint(config.runtime_root, common_dir)
        root_fd = _open_directory(config.runtime_root)
        _probe_filesystem(root_fd)
        try:
            os.mkdir("sessions", 0o700, dir_fd=root_fd)
            _fsync(root_fd)
        except FileExistsError:
            pass
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        try:
            _validate_fd(sessions_fd, directory=True, mode=0o700)
        finally:
            os.close(sessions_fd)
        _ensure_lock_file(root_fd, "manager.lock")
        runtime_root_identity = _runtime_root_identity(root_fd)
    except RepairError:
        raise
    except OSError:
        invalid = True
    finally:
        if root_fd is not None:
            os.close(root_fd)
    if invalid or runtime_root_identity is None:
        _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)
    return runtime_root_identity


def _create_session_store(
    config: RepairManagerConfig,
    session_id: str,
    *,
    request: Mapping[str, object],
    snapshot: RepairSnapshot,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
) -> None:
    _validate_session_id(session_id)
    if snapshot.session_id != session_id or snapshot.state is not RepairState.CREATED:
        raise ValueError("initial snapshot is invalid")
    root_fd: int | None = None
    sessions_fd: int | None = None
    mount_id: int | None = None
    staging = f".{session_id}.tmp-{secrets.token_hex(8)}"
    staging_created = False
    failed = False
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        mount_id = _descriptor_mount_id(root_fd)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        _require_removal_mount(sessions_fd, mount_id)
        os.mkdir(staging, 0o700, dir_fd=sessions_fd)
        staging_created = True
        staging_fd = os.open(
            staging,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=sessions_fd,
        )
        try:
            os.mkdir("events", 0o700, dir_fd=staging_fd)
            os.mkdir("private", 0o700, dir_fd=staging_fd)
            events_fd = os.open(
                "events",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=staging_fd,
            )
            private_fd = os.open(
                "private",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=staging_fd,
            )
            try:
                _write_immutable(private_fd, "request.json", _canonical_bytes(request))
                _ensure_lock_file(staging_fd, "session.lock")
                event = _event_mapping(
                    0,
                    "0" * 64,
                    "created",
                    snapshot.updated_at_us,
                    snapshot,
                    None,
                    None,
                )
                event_digest = _domain_digest("event", event)
                _write_event_immutable(events_fd, _event_name(0), _canonical_bytes(event))
                loaded = _LoadedState(
                    snapshot,
                    0,
                    event_digest,
                    snapshot.updated_at_us,
                    None,
                    None,
                )
                _write_atomic(staging_fd, "state.json", _canonical_bytes(_cache_mapping(loaded)))
                _fsync(events_fd)
                _fsync(private_fd)
                _fsync(staging_fd)
            finally:
                os.close(private_fd)
                os.close(events_fd)
        finally:
            os.close(staging_fd)
        os.rename(staging, session_id, src_dir_fd=sessions_fd, dst_dir_fd=sessions_fd)
        _fsync(sessions_fd)
    except (OSError, _UnsafeRemoval):
        if staging_created and sessions_fd is not None and mount_id is not None:
            _remove_staging_store(sessions_fd, staging, mount_id)
        failed = True
    finally:
        if sessions_fd is not None:
            os.close(sessions_fd)
        if root_fd is not None:
            os.close(root_fd)
    if failed:
        _raise_store_error(
            RepairErrorCode.PERSISTENCE_FAILED,
            RepairStage.PERSISTENCE,
            None,
            session_id,
        )


@contextmanager
def _locked_session(
    config: RepairManagerConfig,
    session_id: str,
    *,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
    private_identity: _RuntimeRootIdentity | None = None,
) -> Iterator[_SessionStore]:
    _validate_session_id(session_id)
    _validate_runtime_root_identity(private_identity)
    root_fd: int | None = None
    session_fd: int | None = None
    events_fd: int | None = None
    private_fd: int | None = None
    lock_fd: int | None = None
    failure: tuple[RepairErrorCode, RepairStage] | None = None
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        try:
            _validate_fd(sessions_fd, directory=True, mode=0o700)
            session_fd = os.open(
                session_id,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=sessions_fd,
            )
        finally:
            os.close(sessions_fd)
        _validate_fd(session_fd, directory=True, mode=0o700)
        events_fd = os.open(
            "events",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=session_fd,
        )
        _validate_fd(events_fd, directory=True, mode=0o700)
        try:
            private_fd = os.open(
                "private",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=session_fd,
            )
            _validate_fd(private_fd, directory=True, mode=0o700)
            _require_expected_fd_identity(private_fd, private_identity)
        except FileNotFoundError:
            if private_identity is not None:
                raise OSError("repair private directory identity changed") from None
            private_fd = None
        lock_fd = os.open("session.lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=session_fd)
        _validate_fd(lock_fd, directory=False, mode=0o600)
        if not _acquire_flock(lock_fd, config.lock_timeout_seconds):
            _raise_store_error(
                RepairErrorCode.SESSION_LOCKED,
                RepairStage.SESSION,
                None,
                session_id,
            )
        _revalidate_locked_session(
            config,
            runtime_root_identity,
            root_fd,
            session_id,
            session_fd,
            private_fd,
            private_identity,
            lock_fd,
        )
        os.close(root_fd)
        root_fd = None
        store = _SessionStore(
            config,
            session_id,
            session_fd,
            events_fd,
            private_fd,
            lock_fd,
        )
        session_fd = events_fd = private_fd = lock_fd = None
        try:
            yield store
        finally:
            store.close()
    except FileNotFoundError:
        failure = (RepairErrorCode.SESSION_NOT_FOUND, RepairStage.SESSION)
    except OSError:
        failure = (RepairErrorCode.SESSION_CORRUPT, RepairStage.PERSISTENCE)
    finally:
        for descriptor in (lock_fd, private_fd, events_fd, session_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)
    if failure is not None:
        _raise_store_error(failure[0], failure[1], None, session_id)


def _revalidate_locked_session(
    config: RepairManagerConfig,
    runtime_root_identity: _RuntimeRootIdentity | None,
    root_fd: int,
    session_id: str,
    session_fd: int,
    private_fd: int | None,
    private_identity: _RuntimeRootIdentity | None,
    lock_fd: int,
) -> None:
    _revalidate_runtime_root(config, root_fd, runtime_root_identity)
    sessions_fd = os.open(
        "sessions",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=root_fd,
    )
    try:
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        _require_named_fd_entry(
            sessions_fd,
            session_id,
            session_fd,
            directory=True,
            mode=0o700,
        )
        _require_named_fd_entry(
            session_fd,
            "session.lock",
            lock_fd,
            directory=False,
            mode=0o600,
        )
        if private_fd is not None:
            _require_named_fd_entry(
                session_fd,
                "private",
                private_fd,
                directory=True,
                mode=0o700,
            )
            _require_expected_fd_identity(private_fd, private_identity)
        elif private_identity is not None:
            raise OSError("repair private directory identity changed")
    finally:
        os.close(sessions_fd)


def _require_named_fd_entry(
    parent_fd: int,
    name: str,
    descriptor: int,
    *,
    directory: bool,
    mode: int,
) -> None:
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(named.st_mode)
        or named.st_uid != os.geteuid()
        or stat.S_IMODE(named.st_mode) != mode
        or (not directory and named.st_nlink != 1)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise OSError("locked repair session changed")


@contextmanager
def _manager_lock(
    config: RepairManagerConfig,
    *,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
) -> Iterator[int]:
    root_fd, lock_fd = _acquire_manager_lock(config, runtime_root_identity)
    body_failed = False
    try:
        yield root_fd
    except BaseException:
        body_failed = True
        raise
    finally:
        released = _release_manager_lock(root_fd, lock_fd, unlock=True)
        if not released and not body_failed:
            _raise_store_error(
                RepairErrorCode.PERSISTENCE_FAILED,
                RepairStage.PERSISTENCE,
                None,
                None,
            )


def _acquire_manager_lock(
    config: RepairManagerConfig,
    runtime_root_identity: _RuntimeRootIdentity | None,
) -> tuple[int, int]:
    root_fd: int | None = None
    lock_fd: int | None = None
    acquired = False
    native_failure = False
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        lock_fd = os.open("manager.lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=root_fd)
        _validate_fd(lock_fd, directory=False, mode=0o600)
        if not _acquire_flock(lock_fd, config.lock_timeout_seconds):
            _raise_store_error(RepairErrorCode.SESSION_LOCKED, RepairStage.SESSION, None, None)
        acquired = True
        _revalidate_manager_lock(config, runtime_root_identity, root_fd, lock_fd)
    except OSError:
        native_failure = True
    except BaseException:
        _release_manager_lock(root_fd, lock_fd, unlock=acquired)
        raise
    if native_failure:
        _release_manager_lock(root_fd, lock_fd, unlock=acquired)
        _raise_store_error(
            RepairErrorCode.PERSISTENCE_FAILED,
            RepairStage.PERSISTENCE,
            None,
            None,
        )
    if root_fd is None or lock_fd is None:
        raise AssertionError("manager lock descriptors are missing")
    return root_fd, lock_fd


def _release_manager_lock(
    root_fd: int | None,
    lock_fd: int | None,
    *,
    unlock: bool,
) -> bool:
    released = True
    if lock_fd is not None and unlock:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            released = False
    for descriptor in (lock_fd, root_fd):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                released = False
    return released


def _revalidate_manager_lock(
    config: RepairManagerConfig,
    runtime_root_identity: _RuntimeRootIdentity | None,
    root_fd: int,
    lock_fd: int,
) -> None:
    _revalidate_runtime_root(config, root_fd, runtime_root_identity)
    _require_named_fd_entry(
        root_fd,
        "manager.lock",
        lock_fd,
        directory=False,
        mode=0o600,
    )


def _list_session_ids(
    config: RepairManagerConfig,
    *,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
) -> tuple[str, ...]:
    root_fd: int | None = None
    sessions_fd: int | None = None
    result: tuple[str, ...] = ()
    failed = False
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        result = tuple(sorted(name for name in os.listdir(sessions_fd) if _is_session_id(name)))
    except OSError:
        failed = True
    finally:
        for descriptor in (sessions_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
    if failed:
        _raise_store_error(
            RepairErrorCode.PERSISTENCE_FAILED,
            RepairStage.PERSISTENCE,
            None,
            None,
        )
    return result


def _cleanup_staging_stores(
    runtime_root_fd: int,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    sessions_fd: int | None = None
    removed: list[str] = []
    failed_ids: list[str] = []
    access_failed = False
    try:
        _validate_fd(runtime_root_fd, directory=True, mode=0o700)
        mount_id = _descriptor_mount_id(runtime_root_fd)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=runtime_root_fd,
        )
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        _require_removal_mount(sessions_fd, mount_id)
        for name in sorted(os.listdir(sessions_fd)):
            match = _STAGING_NAME_PATTERN.fullmatch(name)
            if match is None:
                continue
            session_id = match.group("session_id")
            outcome = _remove_staging_store(sessions_fd, name, mount_id)
            if outcome in {
                _SessionRemovalOutcome.REMOVED,
                _SessionRemovalOutcome.ABSENT,
            }:
                removed.append(session_id)
            else:
                failed_ids.append(session_id)
    except (OSError, _UnsafeRemoval):
        access_failed = True
    finally:
        if sessions_fd is not None:
            try:
                os.close(sessions_fd)
            except OSError:
                access_failed = True
    if access_failed:
        _raise_store_error(
            RepairErrorCode.PERSISTENCE_FAILED,
            RepairStage.PERSISTENCE,
            None,
            None,
        )
    return tuple(sorted(set(removed))), tuple(sorted(set(failed_ids)))


def _remove_staging_store(
    sessions_fd: int,
    name: str,
    mount_id: int,
) -> _SessionRemovalOutcome:
    if type(name) is not str or _STAGING_NAME_PATTERN.fullmatch(name) is None:
        raise ValueError("staging session name is invalid")
    staging_fd: int | None = None
    outcome = _SessionRemovalOutcome.FAILED
    try:
        try:
            staging_metadata = os.stat(
                name,
                dir_fd=sessions_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _fsync(sessions_fd)
            return _SessionRemovalOutcome.ABSENT
        _validate_removal_metadata(staging_metadata, directory=True)
        staging_fd = _open_removal_directory(
            sessions_fd,
            name,
            staging_metadata,
            mount_id,
        )
        opened_metadata = os.fstat(staging_fd)
        _verify_removal_tree(staging_fd, mount_id)
        _remove_tree_contents(staging_fd, mount_id)
        if os.listdir(staging_fd):
            raise _UnsafeRemoval("staging session changed during removal")
        _require_named_removal_entry(
            sessions_fd,
            name,
            opened_metadata,
            directory=True,
        )
        os.rmdir(name, dir_fd=sessions_fd)
        _fsync(sessions_fd)
        outcome = _SessionRemovalOutcome.REMOVED
    except _UnsafeRemoval:
        outcome = _SessionRemovalOutcome.REFUSED
    except OSError:
        outcome = _SessionRemovalOutcome.FAILED
    finally:
        if staging_fd is not None:
            try:
                os.close(staging_fd)
            except OSError:
                outcome = _SessionRemovalOutcome.FAILED
    return outcome


def _remove_session_store(
    config: RepairManagerConfig,
    session_id: str,
    *,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
) -> _SessionRemovalOutcome:
    """Remove one canonical session without following or trusting runtime paths."""
    _validate_session_id(session_id)
    root_fd: int | None = None
    sessions_fd: int | None = None
    session_fd: int | None = None
    lock_fd: int | None = None
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        mount_id = _descriptor_mount_id(root_fd)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        _require_removal_mount(sessions_fd, mount_id)
        try:
            session_metadata = os.stat(
                session_id,
                dir_fd=sessions_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _fsync(sessions_fd)
            return _SessionRemovalOutcome.ABSENT
        _validate_removal_metadata(session_metadata, directory=True)
        session_fd = os.open(
            session_id,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=sessions_fd,
        )
        opened_metadata = os.fstat(session_fd)
        _validate_removal_metadata(opened_metadata, directory=True)
        _require_same_removal_entry(session_metadata, opened_metadata)
        _require_removal_mount(session_fd, mount_id)
        lock_fd = os.open(
            "session.lock",
            os.O_RDWR | os.O_NOFOLLOW,
            dir_fd=session_fd,
        )
        _validate_fd(lock_fd, directory=False, mode=0o600)
        _require_removal_mount(lock_fd, mount_id)
        if not _acquire_flock(lock_fd, config.lock_timeout_seconds):
            return _SessionRemovalOutcome.FAILED
        _require_named_removal_entry(
            sessions_fd,
            session_id,
            opened_metadata,
            directory=True,
        )
        _require_named_removal_entry(
            session_fd,
            "session.lock",
            os.fstat(lock_fd),
            directory=False,
        )

        # A complete pass prevents known corruption from causing a partial deletion.
        _verify_removal_tree(session_fd, mount_id)
        _remove_tree_contents(session_fd, mount_id)
        if os.listdir(session_fd):
            raise _UnsafeRemoval("session changed during removal")
        _require_named_removal_entry(
            sessions_fd,
            session_id,
            opened_metadata,
            directory=True,
        )
        os.rmdir(session_id, dir_fd=sessions_fd)
        _fsync(sessions_fd)
        return _SessionRemovalOutcome.REMOVED
    except _UnsafeRemoval:
        return _SessionRemovalOutcome.REFUSED
    except OSError:
        return _SessionRemovalOutcome.FAILED
    finally:
        if lock_fd is not None:
            with suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        for descriptor in (lock_fd, session_fd, sessions_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


@contextmanager
def _session_path_guard(
    config: RepairManagerConfig,
    session_id: str,
    *,
    runtime_root_identity: _RuntimeRootIdentity | None = None,
    private_identity: _RuntimeRootIdentity | None = None,
) -> Iterator[_SessionPathGuard]:
    _validate_session_id(session_id)
    _validate_runtime_root_identity(private_identity)
    root_fd: int | None = None
    sessions_fd: int | None = None
    session_fd: int | None = None
    private_fd: int | None = None
    failed = False
    try:
        root_fd = _open_runtime_root(config, runtime_root_identity)
        sessions_fd = os.open(
            "sessions",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        _validate_fd(sessions_fd, directory=True, mode=0o700)
        session_fd = os.open(
            session_id,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=sessions_fd,
        )
        _validate_fd(session_fd, directory=True, mode=0o700)
        private_fd = os.open(
            "private",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=session_fd,
        )
        _validate_fd(private_fd, directory=True, mode=0o700)
        _require_expected_fd_identity(private_fd, private_identity)
    except OSError:
        failed = True
    if failed or root_fd is None or sessions_fd is None or session_fd is None or private_fd is None:
        for descriptor in (private_fd, session_fd, sessions_fd, root_fd):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
        _raise_store_error(
            RepairErrorCode.SESSION_CORRUPT,
            RepairStage.PERSISTENCE,
            None,
            session_id,
        )
    guard = _SessionPathGuard(
        config,
        session_id,
        runtime_root_identity,
        root_fd,
        sessions_fd,
        session_fd,
        private_fd,
    )
    try:
        guard.revalidate()
    except BaseException:
        guard.close()
        raise
    body_failed = False
    try:
        yield guard
    except BaseException:
        body_failed = True
        raise
    finally:
        revalidation_failed = False
        if not body_failed:
            try:
                guard.revalidate()
            except RepairError:
                revalidation_failed = True
        close_failed = not guard.close()
        if not body_failed and (revalidation_failed or close_failed):
            _raise_store_error(
                RepairErrorCode.SESSION_CORRUPT,
                RepairStage.PERSISTENCE,
                None,
                session_id,
            )


def _capture_runtime_path_binding(
    private_fd: int,
    relative_parts: tuple[str, ...],
    *,
    directory: bool,
) -> _RuntimePathBinding:
    if (
        type(relative_parts) is not tuple
        or not relative_parts
        or any(type(part) is not str for part in relative_parts)
        or any(part in {"", ".", ".."} or "/" in part for part in relative_parts)
        or type(directory) is not bool
    ):
        raise ValueError("runtime path binding is invalid")
    current_fd = private_fd
    opened: list[int] = []
    signatures: list[tuple[int, ...]] = []
    close_failed = False
    retained_fd = -1
    try:
        for index, component in enumerate(relative_parts):
            expected_directory = index < len(relative_parts) - 1 or directory
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            flags |= os.O_DIRECTORY if expected_directory else os.O_NONBLOCK
            descriptor = os.open(component, flags, dir_fd=current_fd)
            opened.append(descriptor)
            after = os.fstat(descriptor)
            _require_runtime_path_metadata(
                before,
                after,
                directory=expected_directory,
            )
            signatures.append(_runtime_path_signature(after))
            current_fd = descriptor
        retained_fd = opened.pop()
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                close_failed = True
    if close_failed or retained_fd < 0:
        if retained_fd >= 0:
            with suppress(OSError):
                os.close(retained_fd)
        raise OSError("repair runtime path descriptor close failed")
    return _RuntimePathBinding(
        relative_parts,
        directory,
        tuple(signatures),
        retained_fd,
    )


def _runtime_binding_identity(
    binding: _RuntimePathBinding,
) -> tuple[tuple[str, ...], bool, tuple[tuple[int, ...], ...]]:
    return binding.relative_parts, binding.directory, binding.signatures


def _runtime_relative_parts(
    named_session_path: Path,
    io_session_path: Path,
    path: Path,
) -> tuple[str, ...]:
    if (
        not isinstance(named_session_path, Path)
        or not named_session_path.is_absolute()
        or not isinstance(io_session_path, Path)
        or not io_session_path.is_absolute()
        or not isinstance(path, Path)
        or not path.is_absolute()
    ):
        raise ValueError("runtime path binding is invalid")
    relative: Path | None = None
    for root in (named_session_path, io_session_path):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        break
    if (
        relative is None
        or not relative.parts
        or any(part in {"", ".", ".."} or "/" in part for part in relative.parts)
    ):
        raise ValueError("runtime path binding is outside the session")
    return relative.parts


def _require_runtime_path_metadata(
    before: os.stat_result,
    after: os.stat_result,
    *,
    directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    allowed_modes = {0o700} if directory else _REMOVABLE_FILE_MODES
    if (
        not expected_type(before.st_mode)
        or not expected_type(after.st_mode)
        or before.st_uid != os.geteuid()
        or after.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) not in allowed_modes
        or stat.S_IMODE(after.st_mode) not in allowed_modes
        or (not directory and (before.st_nlink != 1 or after.st_nlink != 1))
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise OSError("unsafe repair runtime path")


def _runtime_path_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _verify_removal_tree(directory_fd: int, mount_id: int) -> None:
    for name in sorted(os.listdir(directory_fd)):
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            _validate_removal_metadata(metadata, directory=True)
            child_fd = _open_removal_directory(directory_fd, name, metadata, mount_id)
            try:
                _verify_removal_tree(child_fd, mount_id)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            _validate_removal_metadata(metadata, directory=False)
            descriptor = _open_removal_file(directory_fd, name, metadata, mount_id)
            os.close(descriptor)
        else:
            raise _UnsafeRemoval("unsupported session entry")


def _remove_tree_contents(directory_fd: int, mount_id: int) -> None:
    for name in sorted(os.listdir(directory_fd)):
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            _validate_removal_metadata(metadata, directory=True)
            child_fd = _open_removal_directory(directory_fd, name, metadata, mount_id)
            try:
                _remove_tree_contents(child_fd, mount_id)
                if os.listdir(child_fd):
                    raise _UnsafeRemoval("directory changed during removal")
                _require_named_removal_entry(
                    directory_fd,
                    name,
                    os.fstat(child_fd),
                    directory=True,
                )
                os.rmdir(name, dir_fd=directory_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            _validate_removal_metadata(metadata, directory=False)
            descriptor = _open_removal_file(directory_fd, name, metadata, mount_id)
            try:
                _require_named_removal_entry(
                    directory_fd,
                    name,
                    os.fstat(descriptor),
                    directory=False,
                )
                os.unlink(name, dir_fd=directory_fd)
            finally:
                os.close(descriptor)
        else:
            raise _UnsafeRemoval("unsupported session entry")


def _open_removal_directory(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    mount_id: int,
) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        _validate_removal_metadata(metadata, directory=True)
        _require_same_removal_entry(expected, metadata)
        _require_removal_mount(descriptor, mount_id)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_removal_file(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    mount_id: int,
) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        _validate_removal_metadata(metadata, directory=False)
        _require_same_removal_entry(expected, metadata)
        _require_removal_mount(descriptor, mount_id)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_named_removal_entry(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    *,
    directory: bool,
) -> None:
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_removal_metadata(metadata, directory=directory)
    _require_same_removal_entry(expected, metadata)


def _validate_removal_metadata(metadata: os.stat_result, *, directory: bool) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_modes = frozenset({0o700}) if directory else _REMOVABLE_FILE_MODES
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) not in expected_modes
        or (not directory and metadata.st_nlink != 1)
    ):
        raise _UnsafeRemoval("unsafe session entry metadata")


def _require_same_removal_entry(first: os.stat_result, second: os.stat_result) -> None:
    if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
        raise _UnsafeRemoval("session entry changed during removal")


def _descriptor_mount_id(descriptor: int) -> int:
    fdinfo: int | None = None
    try:
        fdinfo = os.open(
            f"/proc/self/fdinfo/{descriptor}",
            os.O_RDONLY | os.O_NOFOLLOW,
        )
        payload = os.read(fdinfo, 8_193)
    except OSError as error:
        raise _UnsafeRemoval("mount identity is unavailable") from error
    finally:
        if fdinfo is not None:
            os.close(fdinfo)
    if len(payload) > 8_192:
        raise _UnsafeRemoval("mount identity record is oversized")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise _UnsafeRemoval("mount identity record is invalid") from error
    values = [
        line.partition(":")[2].strip() for line in lines if line.partition(":")[0] == "mnt_id"
    ]
    if len(values) != 1 or not values[0].isdecimal():
        raise _UnsafeRemoval("mount identity record is invalid")
    return int(values[0])


def _require_removal_mount(descriptor: int, expected_mount_id: int) -> None:
    if _descriptor_mount_id(descriptor) != expected_mount_id:
        raise _UnsafeRemoval("cross-mount session entry")


def _load_event_chain(events_fd: int, session_id: str) -> _LoadedState:
    _cleanup_stale_event_temps(events_fd)
    names = sorted(os.listdir(events_fd))
    if not names:
        _raise_corrupt(session_id)
    previous_digest = "0" * 64
    previous_snapshot: RepairSnapshot | None = None
    previous_preview_sha256: str | None = None
    previous_validation_run: _ValidationRunLease | None = None
    loaded: _LoadedState | None = None
    for sequence, name in enumerate(names):
        if name != _event_name(sequence):
            _raise_corrupt(session_id)
        mapping = _read_canonical_mapping(events_fd, name, _MAX_RECORD_BYTES, immutable=True)
        event = _validate_event_mapping(mapping, sequence, previous_digest, session_id)
        snapshot = _repair_snapshot_from_dict(event["snapshot"])
        if not _snapshot_record_digests_are_valid(snapshot):
            _raise_corrupt(session_id)
        preview_sha256 = _optional_sha256(event["preview_sha256"])
        validation_run = _optional_validation_run_lease_from_dict(event["validation_run"])
        if snapshot.session_id != session_id or snapshot.state.value != event["state"]:
            _raise_corrupt(session_id)
        kind_value = event["kind"]
        if type(kind_value) is not str:
            _raise_corrupt(session_id)
        kind = kind_value
        if previous_snapshot is None:
            if (
                sequence != 0
                or snapshot.state is not RepairState.CREATED
                or kind != "created"
                or preview_sha256 is not None
                or validation_run is not None
            ):
                _raise_corrupt(session_id)
        else:
            if not _event_state_pair_is_valid(
                kind,
                previous_snapshot.state,
                snapshot.state,
            ):
                _raise_corrupt(session_id)
            if snapshot.created_at_us != previous_snapshot.created_at_us or (
                snapshot.updated_at_us < previous_snapshot.updated_at_us
            ):
                _raise_corrupt(session_id)
            if not _validation_run_update_is_valid(
                kind,
                previous_snapshot,
                snapshot,
                previous_validation_run,
                validation_run,
            ):
                _raise_corrupt(session_id)
            if not _candidate_preview_update_is_valid(
                kind,
                previous_snapshot,
                snapshot,
                previous_preview_sha256,
                preview_sha256,
            ):
                _raise_corrupt(session_id)
            if not _snapshot_update_is_valid(kind, previous_snapshot, snapshot):
                _raise_corrupt(session_id)
        timestamp_us = event["timestamp_us"]
        if type(timestamp_us) is not int or timestamp_us != snapshot.updated_at_us:
            _raise_corrupt(session_id)
        digest = _domain_digest("event", mapping)
        loaded = _LoadedState(
            snapshot,
            sequence,
            digest,
            timestamp_us,
            preview_sha256,
            validation_run,
        )
        previous_digest = digest
        previous_snapshot = snapshot
        previous_preview_sha256 = preview_sha256
        previous_validation_run = validation_run
    if loaded is None:
        _raise_corrupt(session_id)
    return loaded


def _event_state_pair_is_valid(
    kind: str,
    previous: RepairState,
    current: RepairState,
) -> bool:
    pairs = _EVENT_STATE_PAIRS.get(kind)
    return (
        pairs is not None
        and (previous, current) in pairs
        and _can_transition_or_same(
            previous,
            current,
        )
    )


def _can_transition_or_same(previous: RepairState, current: RepairState) -> bool:
    return previous is current or _can_transition(previous, current)


def _snapshot_update_is_valid(
    kind: str,
    previous: RepairSnapshot,
    current: RepairSnapshot,
) -> bool:
    if any(getattr(previous, name) != getattr(current, name) for name in _SNAPSHOT_IDENTITY_FIELDS):
        return False
    changes = frozenset(
        name
        for name in _SNAPSHOT_MUTABLE_FIELDS
        if getattr(previous, name) != getattr(current, name)
    )
    if kind == "cleanup_pending":
        return changes <= {"cleanup_pending"} and current.cleanup_pending
    expected = _EVENT_SNAPSHOT_CHANGES.get(kind)
    if changes != expected:
        return False
    if kind == "candidate":
        return previous.candidate is None and current.candidate is not None
    if kind == "validation_result":
        return previous.validation is None and current.validation is not None
    if kind == "approved":
        return previous.approval is None and current.approval is not None
    if kind == "applied":
        return (
            previous.application is None
            and current.application is not None
            and current.cleanup_pending
        )
    if kind in {"rejected", "cancelled", "expired"}:
        return (
            previous.decision is None and current.decision is not None and current.cleanup_pending
        )
    if kind == "failed":
        return previous.failure is None and current.failure is not None and current.cleanup_pending
    if kind == "cleanup_complete":
        return previous.cleanup_pending and not current.cleanup_pending
    return True


def _snapshot_record_digests_are_valid(snapshot: RepairSnapshot) -> bool:
    candidate = snapshot.candidate
    if candidate is not None:
        candidate_mapping = repair_candidate_to_dict(candidate)
        candidate_id = candidate_mapping.pop("candidate_id")
        for name in (
            "changed_paths",
            "changed_line_count",
            "provider_attempt_count",
            "input_tokens",
            "output_tokens",
        ):
            del candidate_mapping[name]
        if candidate_id != _domain_digest("candidate", candidate_mapping):
            return False

    validation = snapshot.validation
    if validation is not None:
        validation_mapping = repair_validation_to_dict(validation)
        validation_sha256 = validation_mapping.pop("validation_sha256")
        if validation_sha256 != _domain_digest("validation", validation_mapping):
            return False

    approval = snapshot.approval
    if approval is not None:
        approval_mapping = repair_approval_to_dict(approval)
        approval_sha256 = approval_mapping.pop("approval_sha256")
        if approval_sha256 != _domain_digest("approval", approval_mapping):
            return False

    application = snapshot.application
    if application is not None:
        application_mapping = repair_application_to_dict(application)
        application_sha256 = application_mapping.pop("application_sha256")
        if application_sha256 != _domain_digest("application", application_mapping):
            return False

    decision = snapshot.decision
    if decision is not None:
        decision_mapping = repair_decision_to_dict(decision)
        decision_sha256 = decision_mapping.pop("decision_sha256")
        if decision_sha256 != _domain_digest("decision", decision_mapping):
            return False
    return True


def _validation_run_update_is_valid(
    kind: str,
    previous_snapshot: RepairSnapshot,
    snapshot: RepairSnapshot,
    previous: _ValidationRunLease | None,
    current: _ValidationRunLease | None,
) -> bool:
    if previous is not None and not _validation_run_matches_snapshot(previous, previous_snapshot):
        return False
    if current is not None and not _validation_run_matches_snapshot(current, snapshot):
        return False
    if kind == "validation_intent":
        return (
            previous is None
            and current is not None
            and current.container_id is None
            and snapshot.validation is None
        )
    if kind == "validation_run":
        return (
            previous is not None
            and previous.container_id is None
            and current is not None
            and current.container_id is not None
            and _same_validation_intent(previous, current)
            and snapshot.validation is None
        )
    if kind == "validation_intent_abandoned":
        return (
            previous is not None
            and previous.container_id is None
            and current is None
            and snapshot.state is RepairState.VALIDATING
            and snapshot.validation is None
        )
    if kind == "validation_result":
        return (
            previous is not None
            and previous.container_id is not None
            and current == previous
            and snapshot.validation is not None
        )
    if previous is None:
        return current is None
    if current == previous:
        return kind != "cleanup_complete" and snapshot.state in _LEASE_CARRY_STATES
    if current is not None:
        return False
    return kind in {"validated", "failed", "cleanup_pending", "cleanup_complete"}


def _same_validation_intent(
    previous: _ValidationRunLease,
    current: _ValidationRunLease,
) -> bool:
    return (
        previous.container_name == current.container_name
        and previous.labels == current.labels
        and previous.session_id == current.session_id
        and previous.candidate_id == current.candidate_id
        and previous.run_token_sha256 == current.run_token_sha256
    )


def _validation_run_matches_snapshot(
    lease: _ValidationRunLease,
    snapshot: RepairSnapshot,
) -> bool:
    candidate = snapshot.candidate
    return (
        lease.session_id == snapshot.session_id
        and candidate is not None
        and lease.candidate_id == candidate.candidate_id
    )


def _candidate_preview_update_is_valid(
    kind: str,
    previous_snapshot: RepairSnapshot,
    snapshot: RepairSnapshot,
    previous_preview_sha256: str | None,
    preview_sha256: str | None,
) -> bool:
    previous_candidate = previous_snapshot.candidate
    candidate = snapshot.candidate
    if kind == "candidate":
        return (
            previous_candidate is None
            and candidate is not None
            and previous_preview_sha256 is None
            and preview_sha256 is not None
        )
    return (
        candidate == previous_candidate
        and preview_sha256 == previous_preview_sha256
        and ((candidate is None) == (preview_sha256 is None))
    )


def _validate_event_mapping(
    mapping: dict[str, object],
    sequence: int,
    previous_digest: str,
    session_id: str,
) -> dict[str, object]:
    expected = {
        "schema_version",
        "sequence",
        "previous_sha256",
        "kind",
        "state",
        "timestamp_us",
        "snapshot",
        "preview_sha256",
        "validation_run",
    }
    if set(mapping) != expected:
        _raise_corrupt(session_id)
    if (
        type(mapping["schema_version"]) is not int
        or mapping["schema_version"] != 1
        or type(mapping["sequence"]) is not int
        or mapping["sequence"] != sequence
    ):
        _raise_corrupt(session_id)
    if mapping["previous_sha256"] != previous_digest:
        _raise_corrupt(session_id)
    if type(mapping["kind"]) is not str or mapping["kind"] not in _EVENT_KINDS:
        _raise_corrupt(session_id)
    if type(mapping["state"]) is not str or type(mapping["timestamp_us"]) is not int:
        _raise_corrupt(session_id)
    if type(mapping["snapshot"]) is not dict:
        _raise_corrupt(session_id)
    preview_sha256 = mapping["preview_sha256"]
    if preview_sha256 is not None and (
        type(preview_sha256) is not str or _SHA256_PATTERN.fullmatch(preview_sha256) is None
    ):
        _raise_corrupt(session_id)
    return mapping


def _event_mapping(
    sequence: int,
    previous_sha256: str,
    kind: str,
    timestamp_us: int,
    snapshot: RepairSnapshot,
    preview_sha256: str | None,
    validation_run: _ValidationRunLease | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "sequence": sequence,
        "previous_sha256": previous_sha256,
        "kind": kind,
        "state": snapshot.state.value,
        "timestamp_us": timestamp_us,
        "snapshot": repair_snapshot_to_dict(snapshot),
        "preview_sha256": preview_sha256,
        "validation_run": (
            None if validation_run is None else _validation_run_lease_to_dict(validation_run)
        ),
    }


def _cache_mapping(loaded: _LoadedState) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_sequence": loaded.event_sequence,
        "event_sha256": loaded.event_sha256,
        "preview_sha256": loaded.preview_sha256,
        "snapshot": repair_snapshot_to_dict(loaded.snapshot),
        "validation_run": (
            None
            if loaded.validation_run is None
            else _validation_run_lease_to_dict(loaded.validation_run)
        ),
    }


def _optional_sha256(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("optional SHA-256 is invalid")
    return value


def _validation_run_lease_to_dict(value: _ValidationRunLease) -> dict[str, object]:
    if type(value) is not _ValidationRunLease:
        raise TypeError("value must be an exact _ValidationRunLease")
    return {
        "container_id": value.container_id,
        "container_name": value.container_name,
        "labels": [[name, item] for name, item in value.labels],
        "session_id": value.session_id,
        "candidate_id": value.candidate_id,
        "run_token_sha256": value.run_token_sha256,
    }


def _optional_validation_run_lease_from_dict(
    value: object,
) -> _ValidationRunLease | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {
        "container_id",
        "container_name",
        "labels",
        "session_id",
        "candidate_id",
        "run_token_sha256",
    }:
        raise ValueError("validation run mapping is invalid")
    labels_value = value["labels"]
    if type(labels_value) is not list:
        raise ValueError("validation run labels are invalid")
    labels: list[tuple[str, str]] = []
    for item in labels_value:
        if (
            type(item) is not list
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
        ):
            raise ValueError("validation run labels are invalid")
        labels.append((item[0], item[1]))
    scalar_names = ("container_name", "session_id", "candidate_id", "run_token_sha256")
    if any(type(value[name]) is not str for name in scalar_names):
        raise ValueError("validation run identity is invalid")
    container_id = value["container_id"]
    if container_id is not None and type(container_id) is not str:
        raise ValueError("validation run container identity is invalid")
    return _ValidationRunLease(
        container_id,
        value["container_name"],
        tuple(labels),
        value["session_id"],
        value["candidate_id"],
        value["run_token_sha256"],
    )


def _read_cache(session_fd: int) -> dict[str, object] | None:
    try:
        return _read_canonical_mapping(session_fd, "state.json", _MAX_RECORD_BYTES, immutable=False)
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return None


def _read_canonical_mapping(
    directory_fd: int,
    name: str,
    maximum: int,
    *,
    immutable: bool,
) -> dict[str, object]:
    raw = _read_file(directory_fd, name, maximum, immutable=immutable)
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("record JSON is invalid") from None
    if type(value) is not dict or _canonical_bytes(value) != raw:
        raise ValueError("record JSON is not canonical")
    return value


def _read_file(directory_fd: int, name: str, maximum: int, *, immutable: bool) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        expected_mode = 0o400 if immutable else 0o600
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise ValueError("record metadata is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum:
            raise ValueError("record is too large")
        return value
    finally:
        os.close(descriptor)


def _cleanup_stale_event_temps(events_fd: int) -> None:
    removed = False
    for name in sorted(os.listdir(events_fd)):
        match = _EVENT_TEMP_PATTERN.fullmatch(name)
        if match is None:
            continue
        metadata = os.stat(name, dir_fd=events_fd, follow_symlinks=False)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or mode not in {0o400, 0o600}
            or metadata.st_nlink not in {1, 2}
        ):
            raise OSError("unsafe temporary event record")
        linked_final: str | None = None
        if metadata.st_nlink == 2:
            linked_final = match.group("event")
            final = os.stat(
                linked_final,
                dir_fd=events_fd,
                follow_symlinks=False,
            )
            if (
                mode != 0o400
                or not stat.S_ISREG(final.st_mode)
                or final.st_uid != os.geteuid()
                or stat.S_IMODE(final.st_mode) != 0o400
                or final.st_nlink != 2
                or (metadata.st_dev, metadata.st_ino) != (final.st_dev, final.st_ino)
            ):
                raise OSError("unsafe linked temporary event record")
        os.unlink(name, dir_fd=events_fd)
        if linked_final is not None:
            final = os.stat(linked_final, dir_fd=events_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(final.st_mode)
                or final.st_uid != os.geteuid()
                or stat.S_IMODE(final.st_mode) != 0o400
                or final.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino) != (final.st_dev, final.st_ino)
            ):
                raise OSError("recovered event record metadata is invalid")
        removed = True
    if removed:
        _fsync(events_fd)


def _write_event_immutable(directory_fd: int, name: str, value: bytes) -> None:
    if (
        type(name) is not str
        or _EVENT_NAME_PATTERN.fullmatch(name) is None
        or type(value) is not bytes
        or len(value) > _MAX_RECORD_BYTES
    ):
        raise ValueError("event record is invalid")
    temporary = f".{name}.tmp-{secrets.token_hex(16)}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, value)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        named_metadata = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o400
            or temporary_metadata.st_nlink != 1
            or (temporary_metadata.st_dev, temporary_metadata.st_ino)
            != (named_metadata.st_dev, named_metadata.st_ino)
        ):
            raise OSError("temporary event record changed")
        os.link(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        final_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_metadata.st_mode) != 0o400
            or final_metadata.st_nlink != 2
            or (temporary_metadata.st_dev, temporary_metadata.st_ino)
            != (final_metadata.st_dev, final_metadata.st_ino)
        ):
            raise OSError("published event record changed")
        os.unlink(temporary, dir_fd=directory_fd)
        final_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_metadata.st_mode) != 0o400
            or final_metadata.st_nlink != 1
            or (temporary_metadata.st_dev, temporary_metadata.st_ino)
            != (final_metadata.st_dev, final_metadata.st_ino)
        ):
            raise OSError("published event record metadata is invalid")
        _fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)


def _write_immutable(directory_fd: int, name: str, value: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync(directory_fd)


def _write_atomic(directory_fd: int, name: str, value: bytes) -> None:
    temporary = f".{name}.tmp-{secrets.token_hex(8)}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, value)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        _fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("short record write")
        offset += written


def _validate_host_inputs(config: RepairManagerConfig) -> None:
    for path in (config.git_executable, config.docker_executable):
        metadata: os.stat_result | None = None
        with suppress(OSError):
            metadata = path.lstat()
        if (
            metadata is None
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or not os.access(path, os.X_OK)
        ):
            _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)
    socket_metadata: os.stat_result | None = None
    with suppress(OSError):
        socket_metadata = config.rootless_socket.lstat()
    if (
        socket_metadata is None
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != os.geteuid()
    ):
        _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)


def _require_no_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            metadata = None
        if metadata is None:
            _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)
        if stat.S_ISLNK(metadata.st_mode):
            _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)


def _validate_owned_directory(path: Path) -> None:
    metadata: os.stat_result | None = None
    with suppress(OSError):
        metadata = path.lstat()
    if (
        metadata is None
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)


def _require_disjoint(runtime_root: Path, protected: Path) -> None:
    runtime = os.path.normpath(str(runtime_root))
    other = os.path.normpath(str(protected))
    try:
        common = os.path.commonpath((runtime, other))
    except ValueError:
        return
    if common in {runtime, other}:
        _raise_store_error(RepairErrorCode.INVALID_CONFIG, RepairStage.INPUT, None, None)


def _runtime_root_identity(descriptor: int) -> _RuntimeRootIdentity:
    _validate_fd(descriptor, directory=True, mode=0o700)
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def _require_expected_fd_identity(
    descriptor: int,
    expected_identity: _RuntimeRootIdentity | None,
) -> None:
    if expected_identity is None:
        return
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino) != expected_identity:
        raise OSError("repair runtime path identity changed")


def _validate_runtime_root_identity(value: _RuntimeRootIdentity | None) -> None:
    if value is None:
        return
    if (
        type(value) is not tuple
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise ValueError("runtime root identity is invalid")


def _open_runtime_root(
    config: RepairManagerConfig,
    expected_identity: _RuntimeRootIdentity | None,
) -> int:
    _validate_runtime_root_identity(expected_identity)
    _require_no_symlink_ancestors(config.runtime_root)
    descriptor = _open_directory(config.runtime_root)
    try:
        if (
            expected_identity is not None
            and _runtime_root_identity(descriptor) != expected_identity
        ):
            raise OSError("repair runtime root identity changed")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _revalidate_runtime_root(
    config: RepairManagerConfig,
    descriptor: int,
    expected_identity: _RuntimeRootIdentity | None,
) -> None:
    opened_identity = _runtime_root_identity(descriptor)
    canonical_fd = _open_runtime_root(config, expected_identity)
    try:
        if opened_identity != _runtime_root_identity(canonical_fd):
            raise OSError("locked repair runtime root changed")
    finally:
        os.close(canonical_fd)


def _open_directory(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    _validate_fd(descriptor, directory=True, mode=0o700)
    return descriptor


def _validate_fd(descriptor: int, *, directory: bool, mode: int) -> None:
    metadata = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or (not directory and metadata.st_nlink != 1)
    ):
        raise OSError("unsafe repair storage metadata")


def _probe_filesystem(root_fd: int) -> None:
    token = secrets.token_hex(8)
    first = f".probe-{token}-a"
    second = f".probe-{token}-b"
    descriptor = os.open(
        first,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=root_fd,
    )
    other: int | None = None
    try:
        _write_all(descriptor, b"repoguard-m5-probe")
        os.fsync(descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        other = os.open(first, os.O_RDWR | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise OSError("flock probe did not contend")
        os.replace(first, second, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        _fsync(root_fd)
        os.unlink(second, dir_fd=root_fd)
        _fsync(root_fd)
    finally:
        if other is not None:
            os.close(other)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        for name in (first, second):
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=root_fd)


def _ensure_lock_file(directory_fd: int, name: str) -> None:
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError:
        descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        _validate_fd(descriptor, directory=False, mode=0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync(directory_fd)


def _acquire_flock(descriptor: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def _event_name(sequence: int) -> str:
    return f"{sequence:016d}.json"


def _validate_payload_name(name: str) -> None:
    if (
        type(name) is not str
        or not name
        or len(name.encode("utf-8")) > 128
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        or name.startswith(".")
    ):
        raise ValueError("private payload name is invalid")


def _validate_session_id(value: str) -> None:
    if not _is_session_id(value):
        raise ValueError("session_id is invalid")


def _is_session_id(value: str) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate or invalid JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _fsync(descriptor: int) -> None:
    os.fsync(descriptor)


def _raise_corrupt(session_id: str) -> NoReturn:
    _raise_store_error(
        RepairErrorCode.SESSION_CORRUPT,
        RepairStage.PERSISTENCE,
        None,
        session_id,
    )


def _raise_store_error(
    code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    raise RepairError(code, stage, state, session_id) from None
