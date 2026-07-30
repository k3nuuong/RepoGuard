"""Focused tests for durable repair storage and workflow state."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
from repoguard._repair_git import _PublicationOutcome, _PublicationResult
from repoguard._repair_models import _domain_digest
from repoguard._repair_store import (
    _create_session_store,
    _initialize_runtime_root,
    _list_session_ids,
    _locked_session,
    _ValidationRunLease,
)
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApplication,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairDecision,
    RepairError,
    RepairErrorCode,
    RepairFailure,
    RepairManager,
    RepairManagerConfig,
    RepairPreview,
    RepairPromptIdentity,
    RepairSession,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairValidation,
    ValidationCommandResult,
    read_repair_preview,
    read_repair_snapshot,
    repair_application_to_dict,
    repair_candidate_to_dict,
    repair_decision_to_dict,
    repair_preview_to_dict,
    repair_snapshot_to_dict,
    repair_validation_to_dict,
)

_SESSION = "a" * 64
_REQUEST = "b" * 64
_OID = "1" * 40


def _created_snapshot() -> RepairSnapshot:
    return RepairSnapshot(
        1,
        _SESSION,
        RepairState.CREATED,
        _REQUEST,
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


def _initialized_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RepairManagerConfig:
    repository = tmp_path / "repository"
    common = repository / ".git"
    repository.mkdir(mode=0o700)
    common.mkdir(mode=0o700)
    config = _config(tmp_path / "runtime")

    def ignore_host_inputs(_: RepairManagerConfig) -> None:
        return None

    monkeypatch.setattr(store_module, "_validate_host_inputs", ignore_host_inputs)
    _initialize_runtime_root(config, repository_root=repository, common_dir=common)
    return config


def _create(config: RepairManagerConfig) -> None:
    _create_session_store(
        config,
        _SESSION,
        request={"schema_version": 1, "request_sha256": _REQUEST},
        snapshot=_created_snapshot(),
    )


def _candidate() -> RepairCandidate:
    prompt = RepairPromptIdentity("agent_repair", 1, "1" * 64, "2" * 64, "3" * 64)
    context = RepairContextSummary(
        RepairContextOutcome.NOT_REQUESTED,
        None,
        None,
        0,
        0,
        0,
        None,
        None,
    )
    candidate = RepairCandidate(
        1,
        "0" * 64,
        _REQUEST,
        prompt,
        context,
        "4" * 64,
        _OID,
        _OID,
        ("src/app.py",),
        2,
        0,
        0,
        0,
    )
    payload = repair_candidate_to_dict(candidate)
    del payload["candidate_id"]
    for name in (
        "changed_paths",
        "changed_line_count",
        "provider_attempt_count",
        "input_tokens",
        "output_tokens",
    ):
        del payload[name]
    return replace(candidate, candidate_id=_domain_digest("candidate", payload))


_CANDIDATE = _candidate().candidate_id


def _validation() -> RepairValidation:
    result = ValidationCommandResult(
        0,
        0,
        None,
        False,
        10,
        "5" * 64,
        0,
        False,
        "6" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        "0" * 64,
        _CANDIDATE,
        "7" * 64,
        "8" * 64,
        f"sha256:{'9' * 64}",
        3,
        4,
        True,
        None,
        (result,),
        1,
        False,
        0,
        2,
        2,
        True,
    )
    payload = repair_validation_to_dict(validation)
    del payload["validation_sha256"]
    return replace(validation, validation_sha256=_domain_digest("validation", payload))


_VALIDATION = _validation().validation_sha256


def _decision(
    state: RepairState,
    subject: str,
    reason: str,
    candidate_id: str | None,
    decided_at_us: int,
) -> RepairDecision:
    decision = RepairDecision(
        1,
        "0" * 64,
        state,
        subject,
        reason,
        candidate_id,
        decided_at_us,
    )
    payload = repair_decision_to_dict(decision)
    del payload["decision_sha256"]
    return replace(decision, decision_sha256=_domain_digest("decision", payload))


def _application(*, approval_sha256: str, applied_at_us: int) -> RepairApplication:
    application = RepairApplication(
        1,
        "0" * 64,
        approval_sha256,
        f"refs/repoguard/repairs/{_CANDIDATE}",
        _OID,
        applied_at_us,
    )
    payload = repair_application_to_dict(application)
    del payload["application_sha256"]
    return replace(application, application_sha256=_domain_digest("application", payload))


def _preview() -> RepairPreview:
    return RepairPreview(
        1,
        _SESSION,
        RepairState.GENERATING,
        _CANDIDATE,
        None,
        ("src/app.py",),
        "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
        REPAIR_APPROVAL_CONFIRMATION,
    )


def _manager_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairManager, RepairSession]:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)

    root_fd = os.open(config.runtime_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        runtime_root_identity = store_module._runtime_root_identity(root_fd)
    finally:
        os.close(root_fd)

    monkeypatch.setattr(
        workflow_module,
        "_initialize_manager",
        lambda *_: runtime_root_identity,
    )
    manager = RepairManager(RepositoryInput(tmp_path / "repository"), config)
    return config, manager, manager.open_session(_SESSION)


def _validated_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairSession]:
    config, _, session = _manager_session(tmp_path, monkeypatch)
    repository = config.runtime_root / "sessions" / _SESSION / "private" / "repository"
    repository.mkdir(mode=0o700)
    candidate = _candidate()
    validation = _validation()
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    checkpoint = replace(generating, updated_at_us=3, candidate=candidate)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        tuple(
            sorted(
                (
                    ("com.repoguard.component", "safe-repair-validation"),
                    ("com.repoguard.session", _SESSION),
                    ("com.repoguard.candidate", _CANDIDATE),
                    ("com.repoguard.run-token-sha256", "f" * 64),
                )
            )
        ),
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )
    registered = replace(validating, updated_at_us=5)
    validation_result = replace(registered, updated_at_us=6, validation=validation)
    validated = replace(
        validation_result,
        state=RepairState.VALIDATED,
        updated_at_us=7,
    )
    preview = _preview()
    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(preview))
        storage.append("candidate", checkpoint)
        storage.append("validating", validating)
        storage.append(
            "validation_intent",
            registered,
            validation_run=replace(lease, container_id=None),
        )
        storage.append("validation_run", registered, validation_run=lease)
        storage.append("validation_result", validation_result)
        storage.append("validated", validated, clear_validation_run=True)
    return config, session


def _durable_tree(root: Path) -> tuple[tuple[object, ...], ...]:
    records: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*"))):
        metadata = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        records.append(
            (
                str(path.relative_to(root)),
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                content,
            )
        )
    return tuple(records)


def test_public_readers_never_initialize_or_repair_session_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _validated_session(tmp_path, monkeypatch)
    repository = RepositoryInput(tmp_path / "repository")
    monkeypatch.setattr(
        workflow_module,
        "_resolve_repository_layout",
        lambda *_: SimpleNamespace(
            root=repository.path,
            common_dir=repository.path / ".git",
        ),
    )
    cache = config.runtime_root / "sessions" / _SESSION / "state.json"
    cache.write_bytes(b"not canonical state")
    cache.chmod(0o600)
    before = _durable_tree(config.runtime_root)

    snapshot = read_repair_snapshot(repository, config, _SESSION)
    preview = read_repair_preview(repository, config, _SESSION)

    assert snapshot.state is RepairState.VALIDATED
    assert preview.state is RepairState.VALIDATED
    assert preview.candidate_id == _CANDIDATE
    assert cache.read_bytes() == b"not canonical state"
    assert _durable_tree(config.runtime_root) == before


def test_public_reader_missing_runtime_is_read_only_session_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = tmp_path / "repository"
    common_dir = repository_root / ".git"
    common_dir.mkdir(mode=0o700, parents=True)
    repository = RepositoryInput(repository_root)
    config = _config(tmp_path / "absent-runtime")
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _config: None)
    monkeypatch.setattr(
        workflow_module,
        "_resolve_repository_layout",
        lambda *_: SimpleNamespace(root=repository_root, common_dir=common_dir),
    )

    with pytest.raises(RepairError) as raised:
        read_repair_snapshot(repository, config, _SESSION)

    assert raised.value.code is RepairErrorCode.SESSION_NOT_FOUND
    assert raised.value.stage is RepairStage.SESSION
    assert not config.runtime_root.exists()


def test_runtime_and_session_creation_are_atomic_and_permissioned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)

    runtime = config.runtime_root
    session = runtime / "sessions" / _SESSION
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
    assert stat.S_IMODE(session.stat().st_mode) == 0o700
    assert stat.S_IMODE((session / "events").stat().st_mode) == 0o700
    assert stat.S_IMODE((session / "private").stat().st_mode) == 0o700
    assert stat.S_IMODE((runtime / "manager.lock").stat().st_mode) == 0o600
    assert stat.S_IMODE((session / "session.lock").stat().st_mode) == 0o600
    assert stat.S_IMODE((session / "state.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((session / "events" / "0000000000000000.json").stat().st_mode) == 0o400
    assert stat.S_IMODE((session / "private" / "request.json").stat().st_mode) == 0o400
    assert _list_session_ids(config) == (_SESSION,)
    assert not any(path.name.startswith(f".{_SESSION}.tmp-") for path in session.parent.iterdir())

    with _locked_session(config, _SESSION) as storage:
        loaded = storage.load()
        assert loaded.snapshot == _created_snapshot()
        assert loaded.event_sequence == 0
        assert storage.read_private_json("request.json")["request_sha256"] == _REQUEST


def test_event_append_links_state_and_rejects_invalid_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    invalid_created = replace(
        generating,
        state=RepairState.CREATED,
        updated_at_us=2,
    )

    with _locked_session(config, _SESSION) as storage:
        mismatched_kind = replace(
            _created_snapshot(), state=RepairState.GENERATING, updated_at_us=2
        )
        with pytest.raises(RepairError) as captured:
            storage.append("applied", mismatched_kind)
        assert captured.value.code is RepairErrorCode.INVALID_STATE
        appended = storage.append("generating", generating)
        assert appended.event_sequence == 1
        assert storage.load().snapshot.state is RepairState.GENERATING
        with pytest.raises(RepairError) as captured:
            storage.append("created", invalid_created)
        assert captured.value.code is RepairErrorCode.INVALID_STATE
        assert storage.load().event_sequence == 1

    events = config.runtime_root / "sessions" / _SESSION / "events"
    first = json.loads((events / "0000000000000000.json").read_text(encoding="utf-8"))
    second = json.loads((events / "0000000000000001.json").read_text(encoding="utf-8"))
    assert first["previous_sha256"] == "0" * 64
    assert second["previous_sha256"] != "0" * 64
    assert second["snapshot"] == repair_snapshot_to_dict(generating)


def test_candidate_event_authoritatively_binds_and_verifies_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    preview_value = repair_preview_to_dict(_preview())
    expected = _domain_digest("preview", preview_value)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)

    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        skipped_checkpoint = replace(checkpoint, state=RepairState.VALIDATING)
        with pytest.raises(ValueError, match="candidate preview update is invalid"):
            storage.append("validating", skipped_checkpoint)
        with pytest.raises(ValueError, match="candidate preview is invalid"):
            storage.append("candidate", checkpoint)
        assert storage.load().event_sequence == 1
        storage.write_preview(preview_value)
        candidate_event = storage.append("candidate", checkpoint)
        inherited = storage.append("validating", validating)
        assert candidate_event.preview_sha256 == expected
        assert inherited.preview_sha256 == expected
        assert storage.read_preview() == preview_value

    session = config.runtime_root / "sessions" / _SESSION
    candidate_mapping = json.loads((session / "events" / "0000000000000002.json").read_bytes())
    cache = json.loads((session / "state.json").read_bytes())
    assert candidate_mapping["preview_sha256"] == expected
    assert cache["preview_sha256"] == expected

    preview_path = session / "preview.json"
    changed = dict(preview_value)
    changed["canonical_diff"] = f"{changed['canonical_diff']}+unbound\n"
    preview_path.chmod(0o600)
    preview_path.write_bytes(
        json.dumps(
            changed,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    preview_path.chmod(0o400)

    with _locked_session(config, _SESSION) as storage, pytest.raises(RepairError) as captured:
        storage.read_preview()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def test_event_append_rejects_forged_inner_digest_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    forged = replace(_candidate(), diff_sha256="f" * 64)
    checkpoint = replace(generating, candidate=forged, updated_at_us=3)

    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(_preview()))
        before = storage.load()
        with pytest.raises(ValueError, match="event snapshot record digest"):
            storage.append("candidate", checkpoint)
        after = storage.load()

    assert after == before
    events = config.runtime_root / "sessions" / _SESSION / "events"
    assert tuple(path.name for path in sorted(events.iterdir())) == (
        "0000000000000000.json",
        "0000000000000001.json",
    )


def test_event_append_rejects_unexpected_snapshot_field_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    created = _created_snapshot()
    generating = replace(created, state=RepairState.GENERATING, updated_at_us=2)
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION),
                ("com.repoguard.candidate", _CANDIDATE),
                ("com.repoguard.run-token-sha256", "f" * 64),
            )
        )
    )
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        labels,
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )

    with _locked_session(config, _SESSION) as storage:
        with pytest.raises(ValueError, match="event snapshot update"):
            storage.append("generating", replace(generating, target_count=2))
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(_preview()))
        with pytest.raises(ValueError, match="event snapshot update"):
            storage.append("candidate", replace(checkpoint, validation=_validation()))
        storage.append("candidate", checkpoint)
        with pytest.raises(ValueError, match="candidate preview update"):
            storage.append("candidate", replace(checkpoint, updated_at_us=4))
        storage.append("validating", validating)
        registered = replace(validating, updated_at_us=5)
        storage.append(
            "validation_intent",
            registered,
            validation_run=replace(lease, container_id=None),
        )
        storage.append("validation_run", registered, validation_run=lease)
        result = replace(registered, updated_at_us=6, validation=_validation())
        storage.append("validation_result", result)
        replaced_result = replace(
            result,
            state=RepairState.VALIDATED,
            updated_at_us=7,
            validation=replace(_validation(), validation_sha256="f" * 64),
        )
        with pytest.raises(ValueError, match="event snapshot update"):
            storage.append("validated", replaced_result, clear_validation_run=True)
        loaded = storage.load()

    assert loaded.snapshot == result
    assert loaded.validation_run == lease


def test_event_publication_recovers_stale_temps_without_a_sequence_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    partial = events / f".0000000000000001.json.tmp-{'1' * 32}"
    partial.write_bytes(b'{"schema_version":')
    partial.chmod(0o600)

    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    with _locked_session(config, _SESSION) as storage:
        assert storage.load().event_sequence == 0
        assert not partial.exists()
        assert storage.append("generating", generating).event_sequence == 1

    final = events / "0000000000000001.json"
    linked_temp = events / f".0000000000000001.json.tmp-{'2' * 32}"
    os.link(final, linked_temp)
    assert final.stat().st_nlink == 2

    with _locked_session(config, _SESSION) as storage:
        loaded = storage.load()

    assert loaded.event_sequence == 1
    assert loaded.snapshot == generating
    assert not linked_temp.exists()
    assert final.stat().st_nlink == 1
    assert tuple(path.name for path in sorted(events.iterdir())) == (
        "0000000000000000.json",
        "0000000000000001.json",
    )


def test_event_publication_never_exposes_a_short_write_or_overwrites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    first = events / "0000000000000000.json"
    original = first.read_bytes()
    events_fd = os.open(events, os.O_RDONLY | os.O_DIRECTORY)
    real_write_all = store_module._write_all

    def interrupt_write(descriptor: int, value: bytes) -> None:
        assert os.write(descriptor, value[:8]) == 8
        raise OSError("simulated interrupted event write")

    try:
        monkeypatch.setattr(store_module, "_write_all", interrupt_write)
        with pytest.raises(OSError, match="simulated interrupted event write"):
            store_module._write_event_immutable(
                events_fd,
                "0000000000000001.json",
                b"complete-event-record",
            )
        assert not (events / "0000000000000001.json").exists()
        assert tuple(events.iterdir()) == (first,)

        monkeypatch.setattr(store_module, "_write_all", real_write_all)
        with pytest.raises(FileExistsError):
            store_module._write_event_immutable(
                events_fd,
                "0000000000000000.json",
                b"replacement",
            )
    finally:
        os.close(events_fd)

    assert first.read_bytes() == original
    assert stat.S_IMODE(first.stat().st_mode) == 0o400
    assert first.stat().st_nlink == 1
    assert tuple(events.iterdir()) == (first,)


def test_validation_run_lease_is_hash_linked_inherited_and_explicitly_cleared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION),
                ("com.repoguard.candidate", _CANDIDATE),
                ("com.repoguard.run-token-sha256", "f" * 64),
            )
        )
    )
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        labels,
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )

    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(_preview()))
        storage.append("candidate", checkpoint)
        storage.append("validating", validating)
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_run",
                replace(validating, updated_at_us=5),
                validation_run=lease,
            )
        intent = storage.append(
            "validation_intent",
            replace(validating, updated_at_us=5),
            validation_run=replace(lease, container_id=None),
        )
        assert intent.validation_run == replace(lease, container_id=None)
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_result",
                replace(validating, updated_at_us=6, validation=_validation()),
            )
        registered = storage.append(
            "validation_run",
            replace(validating, updated_at_us=5),
            validation_run=lease,
        )
        assert registered.validation_run == lease
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_intent_abandoned",
                replace(validating, updated_at_us=6),
            )
        checkpointed = storage.append(
            "validation_result",
            replace(validating, updated_at_us=6, validation=_validation()),
        )
        assert checkpointed.validation_run == lease
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_result",
                replace(checkpointed.snapshot, updated_at_us=7),
                clear_validation_run=True,
            )
        cleared = storage.append(
            "validated",
            replace(
                checkpointed.snapshot,
                state=RepairState.VALIDATED,
                updated_at_us=7,
            ),
            clear_validation_run=True,
        )
        assert cleared.validation_run is None

    cache = json.loads((config.runtime_root / "sessions" / _SESSION / "state.json").read_bytes())
    assert cache["validation_run"] is None


def test_unbound_validation_intent_can_only_be_abandoned_before_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(_created_snapshot(), state=RepairState.GENERATING, updated_at_us=2)
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION),
                ("com.repoguard.candidate", _CANDIDATE),
                ("com.repoguard.run-token-sha256", "f" * 64),
            )
        )
    )
    intent = _ValidationRunLease(
        None,
        "repoguard-m5-validation",
        labels,
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )
    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(_preview()))
        storage.append("candidate", checkpoint)
        storage.append("validating", validating)
        storage.append(
            "validation_intent",
            replace(validating, updated_at_us=5),
            validation_run=intent,
        )
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_intent_abandoned",
                replace(validating, updated_at_us=6),
            )
        abandoned = storage.append(
            "validation_intent_abandoned",
            replace(validating, updated_at_us=6),
            clear_validation_run=True,
        )
        assert abandoned.validation_run is None
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "validation_intent_abandoned",
                replace(validating, updated_at_us=7),
            )

    events = config.runtime_root / "sessions" / _SESSION / "events"
    assert [json.loads(path.read_bytes())["kind"] for path in sorted(events.iterdir())][-2:] == [
        "validation_intent",
        "validation_intent_abandoned",
    ]


@pytest.mark.parametrize(
    "tamper",
    [
        "kind_state",
        "lease_clear",
        "preview_drop",
        "candidate_skip",
        "candidate_payload",
        "request_shape",
        "intent_result_skip",
        "intent_abandon_noop",
    ],
)
def test_event_loader_rejects_semantic_kind_and_lease_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        tuple(
            sorted(
                (
                    ("com.repoguard.component", "safe-repair-validation"),
                    ("com.repoguard.session", _SESSION),
                    ("com.repoguard.candidate", _CANDIDATE),
                    ("com.repoguard.run-token-sha256", "f" * 64),
                )
            )
        ),
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )
    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        if tamper != "kind_state":
            storage.write_preview(repair_preview_to_dict(_preview()))
            storage.append("candidate", checkpoint)
        if tamper in {"lease_clear", "intent_result_skip", "intent_abandon_noop"}:
            storage.append("validating", validating)
            storage.append(
                "validation_intent",
                replace(validating, updated_at_us=5),
                validation_run=replace(lease, container_id=None),
            )
            storage.append(
                "validation_run",
                replace(validating, updated_at_us=5),
                validation_run=lease,
            )
        if tamper == "lease_clear":
            storage.append(
                "validation_result",
                replace(validating, updated_at_us=6, validation=_validation()),
            )

    sequence = {
        "kind_state": 1,
        "lease_clear": 5,
        "preview_drop": 2,
        "candidate_skip": 2,
        "candidate_payload": 2,
        "request_shape": 2,
        "intent_result_skip": 5,
        "intent_abandon_noop": 5,
    }[tamper]
    event = config.runtime_root / "sessions" / _SESSION / "events" / f"{sequence:016d}.json"
    mapping = json.loads(event.read_bytes())
    if tamper == "kind_state":
        mapping["kind"] = "applied"
    elif tamper == "lease_clear":
        mapping["validation_run"] = None
    elif tamper == "preview_drop":
        mapping["preview_sha256"] = None
    elif tamper == "candidate_skip":
        mapping["kind"] = "validating"
        mapping["state"] = RepairState.VALIDATING.value
        mapping["snapshot"]["state"] = RepairState.VALIDATING.value
        mapping["preview_sha256"] = None
    elif tamper == "candidate_payload":
        mapping["snapshot"] = repair_snapshot_to_dict(replace(checkpoint, validation=_validation()))
    elif tamper == "intent_result_skip":
        mapping["kind"] = "validation_result"
        mapping["snapshot"] = repair_snapshot_to_dict(
            replace(validating, updated_at_us=5, validation=_validation())
        )
        mapping["validation_run"]["container_id"] = None
    elif tamper == "intent_abandon_noop":
        mapping["kind"] = "validation_intent_abandoned"
        mapping["validation_run"]["container_id"] = None
    else:
        mapping["snapshot"] = repair_snapshot_to_dict(replace(checkpoint, target_count=2))
    event.chmod(0o600)
    event.write_bytes(
        json.dumps(
            mapping,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    event.chmod(0o400)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION) as storage:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


@pytest.mark.parametrize(
    ("record", "field", "replacement"),
    [
        ("candidate", "diff_sha256", "f" * 64),
        ("validation", "policy_sha256", "f" * 64),
        ("approval", "subject", "different reviewer"),
        ("application", "applied_at_us", 999),
        ("decision", "reason", "changed reason"),
    ],
)
def test_event_loader_rejects_embedded_record_digest_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record: str,
    field: str,
    replacement: object,
) -> None:
    if record in {"candidate", "validation"}:
        config, _, _ = _manager_session(tmp_path, monkeypatch)
        candidate = _candidate()
        generating = replace(
            _created_snapshot(),
            state=RepairState.GENERATING,
            updated_at_us=2,
        )
        checkpoint = replace(generating, updated_at_us=3, candidate=candidate)
        with _locked_session(
            config,
            _SESSION,
        ) as storage:
            storage.append("generating", generating)
            storage.write_preview(repair_preview_to_dict(_preview()))
            storage.append("candidate", checkpoint)
            if record == "validation":
                validating = replace(
                    checkpoint,
                    state=RepairState.VALIDATING,
                    updated_at_us=4,
                )
                registered = replace(validating, updated_at_us=5)
                labels = tuple(
                    sorted(
                        (
                            ("com.repoguard.component", "safe-repair-validation"),
                            ("com.repoguard.session", _SESSION),
                            ("com.repoguard.candidate", _CANDIDATE),
                            ("com.repoguard.run-token-sha256", "f" * 64),
                        )
                    )
                )
                lease = _ValidationRunLease(
                    "0" * 64,
                    "repoguard-m5-validation",
                    labels,
                    _SESSION,
                    _CANDIDATE,
                    "f" * 64,
                )
                storage.append("validating", validating)
                storage.append(
                    "validation_intent",
                    registered,
                    validation_run=replace(lease, container_id=None),
                )
                storage.append("validation_run", registered, validation_run=lease)
                storage.append(
                    "validation_result",
                    replace(registered, updated_at_us=6, validation=_validation()),
                )
    elif record == "approval":
        config, _, _ = _approved_session(tmp_path, monkeypatch)
    elif record == "application":
        config, _, _ = _approved_session(tmp_path, monkeypatch)
        with _locked_session(config, _SESSION) as storage:
            approved = storage.load().snapshot
            assert approved.approval is not None
            applying = replace(
                approved,
                state=RepairState.APPLYING,
                updated_at_us=approved.updated_at_us + 1,
            )
            applying = storage.append("applying", applying).snapshot
            applied_at_us = applying.updated_at_us + 1
            applied = replace(
                applying,
                state=RepairState.APPLIED,
                updated_at_us=applied_at_us,
                application=_application(
                    approval_sha256=approved.approval.approval_sha256,
                    applied_at_us=applied_at_us,
                ),
                cleanup_pending=True,
            )
            storage.append("applied", applied)
    else:
        config, _, _ = _manager_session(tmp_path, monkeypatch)
        cancelled = replace(
            _created_snapshot(),
            state=RepairState.CANCELLED,
            updated_at_us=2,
            decision=_decision(
                RepairState.CANCELLED,
                "local subject",
                "stop",
                None,
                2,
            ),
            cleanup_pending=True,
        )
        with _locked_session(config, _SESSION) as storage:
            storage.append("cancelled", cancelled)

    events = config.runtime_root / "sessions" / _SESSION / "events"
    event = sorted(events.iterdir())[-1]
    mapping = cast(dict[str, object], json.loads(event.read_bytes()))
    snapshot_mapping = cast(dict[str, object], mapping["snapshot"])
    record_mapping = cast(dict[str, object], snapshot_mapping[record])
    record_mapping[field] = replacement
    event.chmod(0o600)
    event.write_bytes(
        json.dumps(
            mapping,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    event.chmod(0o400)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION) as storage:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.session_id == _SESSION
    assert captured.value.retryable is False
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", True),
        ("schema_version", 1.0),
        ("sequence", False),
        ("sequence", 0.0),
    ],
)
def test_event_loader_requires_exact_integer_header_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: object,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    event = config.runtime_root / "sessions" / _SESSION / "events" / "0000000000000000.json"
    mapping = json.loads(event.read_bytes())
    mapping[field] = replacement
    event.chmod(0o600)
    event.write_bytes(
        json.dumps(
            mapping,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    event.chmod(0o400)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION) as storage:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def test_validation_run_lease_tampering_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    generating = replace(
        _created_snapshot(),
        state=RepairState.GENERATING,
        updated_at_us=2,
    )
    checkpoint = replace(generating, candidate=_candidate(), updated_at_us=3)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        tuple(
            sorted(
                (
                    ("com.repoguard.component", "safe-repair-validation"),
                    ("com.repoguard.session", _SESSION),
                    ("com.repoguard.candidate", _CANDIDATE),
                    ("com.repoguard.run-token-sha256", "f" * 64),
                )
            )
        ),
        _SESSION,
        _CANDIDATE,
        "f" * 64,
    )
    with _locked_session(config, _SESSION) as storage:
        storage.append("generating", generating)
        storage.write_preview(repair_preview_to_dict(_preview()))
        storage.append("candidate", checkpoint)
        storage.append("validating", validating)
        storage.append(
            "validation_intent",
            replace(validating, updated_at_us=5),
            validation_run=replace(lease, container_id=None),
        )

    event = config.runtime_root / "sessions" / _SESSION / "events" / "0000000000000004.json"
    mapping = json.loads(event.read_bytes())
    mapping["validation_run"]["run_token_sha256"] = "e" * 64
    event.chmod(0o600)
    event.write_text(
        json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    event.chmod(0o400)
    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION) as storage:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def test_disposable_state_cache_is_rebuilt_from_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    cache = config.runtime_root / "sessions" / _SESSION / "state.json"
    cache.write_text('{"unsafe":true}\n', encoding="utf-8")
    cache.chmod(0o600)

    with _locked_session(config, _SESSION) as storage:
        assert storage.load().snapshot == _created_snapshot()

    rebuilt = cache.read_bytes()
    assert not rebuilt.endswith(b"\n")
    assert json.loads(rebuilt)["snapshot"] == repair_snapshot_to_dict(_created_snapshot())


@pytest.mark.parametrize("tamper", ["mode", "gap", "content"])
def test_authoritative_event_tampering_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    event_dir = config.runtime_root / "sessions" / _SESSION / "events"
    event = event_dir / "0000000000000000.json"
    if tamper == "mode":
        event.chmod(0o600)
    elif tamper == "gap":
        event.rename(event_dir / "0000000000000001.json")
    else:
        event.chmod(0o600)
        event.write_text('{"schema_version":1}\n', encoding="utf-8")
        event.chmod(0o400)

    with _locked_session(config, _SESSION) as storage, pytest.raises(RepairError) as captured:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_session_lock_timeout_is_retryable_and_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    before = tuple(events.iterdir())
    monkeypatch.setattr(store_module, "_acquire_flock", lambda _fd, _timeout: False)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION):
        pass
    assert captured.value.code is RepairErrorCode.SESSION_LOCKED
    assert captured.value.retryable is True
    assert tuple(events.iterdir()) == before


def test_publication_child_lock_survives_abrupt_parent_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    worker_code = (
        "import os, subprocess, sys\n"
        "from pathlib import Path\n"
        "from repoguard._repair_store import _locked_session\n"
        "from repoguard.repair import RepairManagerConfig\n"
        "config = RepairManagerConfig("
        "Path(sys.argv[1]), Path('/bin/true'), Path('/bin/true'), "
        "Path('/run/repoguard-test.sock'))\n"
        "with _locked_session(config, sys.argv[2]) as storage:\n"
        "    child = subprocess.Popen("
        "[sys.executable, '-c', 'import time; time.sleep(1.0)'], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True, "
        "pass_fds=(storage.publication_lock_fd(),))\n"
        "    os.write(1, f'{child.pid}\\n'.encode('ascii'))\n"
        "    os._exit(0)\n"
    )
    worker = subprocess.Popen(
        (sys.executable, "-c", worker_code, str(config.runtime_root), _SESSION),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    assert worker.stdout is not None
    child_pid = worker.stdout.readline().decode("ascii").strip()
    assert child_pid.isdecimal()
    assert worker.wait(timeout=2.0) == 0

    def acquire_once(descriptor: int, _timeout: float) -> bool:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    monkeypatch.setattr(store_module, "_acquire_flock", acquire_once)
    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION):
        pass
    assert captured.value.code is RepairErrorCode.SESSION_LOCKED

    deadline = time.monotonic() + 3.0
    while True:
        try:
            with _locked_session(config, _SESSION) as storage:
                assert storage.load().snapshot.state is RepairState.CREATED
            break
        except RepairError as error:
            assert error.code is RepairErrorCode.SESSION_LOCKED
            if time.monotonic() >= deadline:
                pytest.fail(f"publication child {child_pid} did not release the session lock")
            time.sleep(0.05)


@pytest.mark.parametrize("replacement", ["runtime_root", "manager_lock"])
def test_manager_lock_waiter_rejects_renamed_canonical_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    runtime = config.runtime_root
    entered = False

    def replace_before_acquire(_descriptor: int, _timeout: float) -> bool:
        if replacement == "runtime_root":
            runtime.rename(tmp_path / "displaced-runtime")
            runtime.mkdir(mode=0o700)
            (runtime / "manager.lock").touch(mode=0o600)
        else:
            manager_lock = runtime / "manager.lock"
            manager_lock.rename(runtime / "displaced-manager.lock")
            manager_lock.touch(mode=0o600)
        return True

    monkeypatch.setattr(store_module, "_acquire_flock", replace_before_acquire)

    with pytest.raises(RepairError) as captured, store_module._manager_lock(config):
        entered = True

    assert entered is False
    assert captured.value.code is RepairErrorCode.PERSISTENCE_FAILED
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.state is None
    assert captured.value.session_id is None
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_manager_lock_propagates_body_exception_by_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    body_error = OSError("body sentinel")
    real_release = store_module._release_manager_lock

    def release_but_report_failure(
        root_fd: int | None,
        lock_fd: int | None,
        *,
        unlock: bool,
    ) -> bool:
        assert real_release(root_fd, lock_fd, unlock=unlock) is True
        return False

    monkeypatch.setattr(store_module, "_release_manager_lock", release_but_report_failure)

    with pytest.raises(OSError) as captured, store_module._manager_lock(config):
        raise body_error

    assert captured.value is body_error


def test_manager_lock_maps_release_failure_only_after_successful_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    entered = False
    real_release = store_module._release_manager_lock

    def release_but_report_failure(
        root_fd: int | None,
        lock_fd: int | None,
        *,
        unlock: bool,
    ) -> bool:
        assert real_release(root_fd, lock_fd, unlock=unlock) is True
        return False

    monkeypatch.setattr(store_module, "_release_manager_lock", release_but_report_failure)

    with pytest.raises(RepairError) as captured, store_module._manager_lock(config):
        entered = True

    assert entered is True
    assert captured.value.code is RepairErrorCode.PERSISTENCE_FAILED
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.state is None
    assert captured.value.session_id is None
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("operation", ["recover", "cleanup"])
def test_public_maintenance_maps_native_session_inventory_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    _, manager, _ = _manager_session(tmp_path, monkeypatch)
    monkeypatch.setattr(workflow_module, "_cleanup_staging_stores", lambda _: ((), ()))

    def fail_listdir(_: object) -> list[str]:
        raise OSError("simulated session inventory failure")

    monkeypatch.setattr(os, "listdir", fail_listdir)
    with pytest.raises(RepairError) as captured:
        if operation == "recover":
            manager.recover()
        else:
            manager.cleanup()

    assert captured.value.code is RepairErrorCode.PERSISTENCE_FAILED
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.state is None
    assert captured.value.session_id is None
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("operation", ["snapshot", "recover", "cleanup"])
def test_manager_bound_operations_reject_replacement_runtime_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    config, manager, session = _manager_session(tmp_path, monkeypatch)
    displaced = tmp_path / "displaced-runtime"
    config.runtime_root.rename(displaced)
    shutil.copytree(displaced, config.runtime_root)

    with pytest.raises(RepairError) as captured:
        if operation == "snapshot":
            session.snapshot()
        elif operation == "recover":
            manager.recover()
        else:
            manager.cleanup()

    expected = (
        RepairErrorCode.SESSION_CORRUPT
        if operation == "snapshot"
        else RepairErrorCode.PERSISTENCE_FAILED
    )
    assert captured.value.code is expected
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_manager_bound_session_rejects_symlinked_ancestor_to_same_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager_parent = tmp_path / "manager-parent"
    manager_parent.mkdir(mode=0o700)
    _, _, session = _manager_session(manager_parent, monkeypatch)
    displaced_parent = tmp_path / "displaced-manager-parent"
    manager_parent.rename(displaced_parent)
    manager_parent.symlink_to(displaced_parent, target_is_directory=True)

    with pytest.raises(RepairError) as captured:
        session.snapshot()

    assert captured.value.code is RepairErrorCode.INVALID_CONFIG
    assert captured.value.stage is RepairStage.INPUT
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_locked_session_rejects_rehoming_during_flock_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, session = _manager_session(tmp_path, monkeypatch)
    displaced = tmp_path / "displaced-runtime"

    def rehome_before_acquire(_descriptor: int, _timeout: float) -> bool:
        config.runtime_root.rename(displaced)
        config.runtime_root.mkdir(mode=0o700)
        replacement_sessions = config.runtime_root / "sessions"
        replacement_sessions.mkdir(mode=0o700)
        (config.runtime_root / "manager.lock").touch(mode=0o600)
        (displaced / "sessions" / _SESSION).rename(replacement_sessions / _SESSION)
        return True

    monkeypatch.setattr(store_module, "_acquire_flock", rehome_before_acquire)

    with pytest.raises(RepairError) as captured:
        session.snapshot()

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.session_id == _SESSION
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_terminal_private_cleanup_keeps_safe_event_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    _create(config)
    cancelled = replace(
        _created_snapshot(),
        state=RepairState.CANCELLED,
        updated_at_us=2,
        decision=_decision(
            RepairState.CANCELLED,
            "local subject",
            "",
            None,
            2,
        ),
        cleanup_pending=True,
    )
    cleaned = replace(cancelled, updated_at_us=3, cleanup_pending=False)

    with _locked_session(config, _SESSION) as storage:
        storage.append("cancelled", cancelled)
        assert storage.cleanup_private() is True
        storage.append("cleanup_complete", cleaned)
        assert storage.load().snapshot == cleaned

    session = config.runtime_root / "sessions" / _SESSION
    assert not (session / "private").exists()
    assert len(tuple((session / "events").iterdir())) == 3


def test_missing_session_and_unsafe_runtime_paths_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_runtime(tmp_path, monkeypatch)
    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION):
        pass
    assert captured.value.code is RepairErrorCode.SESSION_NOT_FOUND

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "runtime-link"
    link.symlink_to(target, target_is_directory=True)
    unsafe = _config(link)
    with pytest.raises(RepairError) as captured:
        _initialize_runtime_root(
            unsafe,
            repository_root=tmp_path / "repo-2",
            common_dir=tmp_path / "repo-2" / ".git",
        )
    assert captured.value.code is RepairErrorCode.INVALID_CONFIG


def test_runtime_root_must_be_disjoint_from_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    config = _config(repository / "runtime")

    def ignore_host_inputs(_: RepairManagerConfig) -> None:
        return None

    monkeypatch.setattr(store_module, "_validate_host_inputs", ignore_host_inputs)
    with pytest.raises(RepairError) as captured:
        _initialize_runtime_root(
            config,
            repository_root=repository,
            common_dir=repository / ".git",
        )
    assert captured.value.code is RepairErrorCode.INVALID_CONFIG


def test_public_approval_cas_preview_and_terminal_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session = _validated_session(tmp_path, monkeypatch)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    before_mismatch = len(tuple(events.iterdir()))

    with pytest.raises(RepairError) as captured:
        session.approve(
            subject="local reviewer",
            expected_candidate_id="0" * 64,
            expected_validation_sha256=_VALIDATION,
            confirmation=REPAIR_APPROVAL_CONFIRMATION,
        )
    assert captured.value.code is RepairErrorCode.APPROVAL_MISMATCH
    assert len(tuple(events.iterdir())) == before_mismatch

    approved = session.approve(
        subject="local reviewer",
        expected_candidate_id=_CANDIDATE,
        expected_validation_sha256=_VALIDATION,
        confirmation=REPAIR_APPROVAL_CONFIRMATION,
    )
    assert approved.state is RepairState.APPROVED
    assert approved.approval is not None
    assert approved.approval.candidate_id == _CANDIDATE
    assert session.snapshot() == approved

    preview = session.preview()
    assert preview.state is RepairState.APPROVED
    assert preview.validation_sha256 == _VALIDATION
    assert preview.canonical_diff.endswith("+new\n")

    rejected = session.reject(
        subject="local reviewer",
        reason="candidate is not wanted",
        expected_candidate_id=_CANDIDATE,
    )
    assert rejected.state is RepairState.REJECTED
    assert rejected.cleanup_pending is False
    assert rejected.decision is not None
    assert rejected.decision.candidate_id == _CANDIDATE
    session_dir = config.runtime_root / "sessions" / _SESSION
    assert not (session_dir / "private").exists()
    assert session.preview().state is RepairState.REJECTED

    with pytest.raises(RepairError) as captured:
        session.cancel(subject="late caller")
    assert captured.value.code is RepairErrorCode.INVALID_STATE
    assert session.snapshot() == rejected


@pytest.mark.parametrize(
    ("operation", "state", "terminal_code"),
    [
        ("cancel", RepairState.CANCELLED, RepairErrorCode.CANCELLED),
        ("expire", RepairState.EXPIRED, RepairErrorCode.EXPIRED),
    ],
)
def test_cancel_and_expire_are_absorbing_and_cleanup_private_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    state: RepairState,
    terminal_code: RepairErrorCode,
) -> None:
    config, _, session = _manager_session(tmp_path, monkeypatch)
    terminal = session.cancel(subject="local caller") if operation == "cancel" else session.expire()
    assert terminal.state is state
    assert terminal.cleanup_pending is False
    assert terminal.decision is not None
    assert not (config.runtime_root / "sessions" / _SESSION / "private").exists()

    with pytest.raises(RepairError) as captured:
        session.cancel(subject="late caller")
    assert captured.value.code is terminal_code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    ("subject", "reason"),
    [("", ""), ("local caller", "\x00"), ("x" * 257, "")],
)
def test_invalid_cancel_declaration_is_detached_and_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subject: str,
    reason: str,
) -> None:
    config, _, session = _manager_session(tmp_path, monkeypatch)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    before = len(tuple(events.iterdir()))

    with pytest.raises(RepairError) as captured:
        session.cancel(subject=subject, reason=reason)
    assert captured.value.code is RepairErrorCode.INVALID_DECISION
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert len(tuple(events.iterdir())) == before
    assert session.snapshot().state is RepairState.CREATED


def test_preview_requires_a_persisted_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, session = _manager_session(tmp_path, monkeypatch)
    with pytest.raises(RepairError) as captured:
        session.preview()
    assert captured.value.code is RepairErrorCode.INVALID_STATE


def _approved_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairSession, str]:
    config, session = _validated_session(tmp_path, monkeypatch)
    approved = session.approve(
        subject="local reviewer",
        expected_candidate_id=_CANDIDATE,
        expected_validation_sha256=_VALIDATION,
        confirmation=REPAIR_APPROVAL_CONFIRMATION,
    )
    assert approved.approval is not None
    return config, session, approved.approval.approval_sha256


@pytest.mark.parametrize("kind", ["cancelled", "failed"])
def test_applying_terminal_events_require_authoritative_ref_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    config, _session, _ = _approved_session(tmp_path, monkeypatch)
    with _locked_session(config, _SESSION) as storage:
        approved = storage.load().snapshot
        applying = replace(
            approved,
            state=RepairState.APPLYING,
            updated_at_us=approved.updated_at_us + 1,
        )
        applying = storage.append("applying", applying).snapshot
        terminal_at_us = applying.updated_at_us + 1
        if kind == "cancelled":
            invalid = replace(
                applying,
                state=RepairState.CANCELLED,
                updated_at_us=terminal_at_us,
                decision=_decision(
                    RepairState.CANCELLED,
                    "local subject",
                    "stop",
                    _CANDIDATE,
                    terminal_at_us,
                ),
                cleanup_pending=True,
            )
        else:
            invalid = replace(
                applying,
                state=RepairState.FAILED,
                updated_at_us=terminal_at_us,
                failure=RepairFailure(
                    1,
                    RepairErrorCode.INVALID_WORKFLOW,
                    RepairStage.APPLICATION,
                    False,
                    terminal_at_us,
                ),
                cleanup_pending=True,
            )
        with pytest.raises(RepairError) as captured:
            storage.append(kind, invalid)
        assert captured.value.code is RepairErrorCode.INVALID_STATE
        restored = replace(
            applying,
            state=RepairState.APPROVED,
            updated_at_us=terminal_at_us,
        )
        recovered = storage.append("recovered", restored)

    event = (
        config.runtime_root
        / "sessions"
        / _SESSION
        / "events"
        / f"{recovered.event_sequence:016d}.json"
    )
    mapping = json.loads(event.read_bytes())
    mapping["kind"] = kind
    mapping["state"] = invalid.state.value
    mapping["snapshot"] = repair_snapshot_to_dict(invalid)
    event.chmod(0o600)
    event.write_bytes(
        json.dumps(
            mapping,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    event.chmod(0o400)

    with pytest.raises(RepairError) as captured, _locked_session(config, _SESSION) as storage:
        storage.load()
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT


def _patch_application_inputs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    read_back: str | None = _OID,
) -> None:
    monkeypatch.setattr(workflow_module, "_load_request", lambda *_: object())
    monkeypatch.setattr(workflow_module, "_capture_frozen_source", lambda *_, **__: object())
    monkeypatch.setattr(workflow_module, "_read_candidate_diff", lambda *_: "diff\n")
    monkeypatch.setattr(workflow_module, "_open_materialized_candidate", lambda *_a, **_k: object())
    monkeypatch.setattr(
        workflow_module,
        "_read_repair_ref",
        lambda *_args, **_kwargs: read_back,
    )


def test_application_cas_success_and_terminal_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, approval_sha256 = _approved_session(tmp_path, monkeypatch)
    events = config.runtime_root / "sessions" / _SESSION / "events"
    before_mismatch = len(tuple(events.iterdir()))
    with pytest.raises(RepairError) as captured:
        session.apply(expected_approval_sha256="0" * 64)
    assert captured.value.code is RepairErrorCode.APPROVAL_MISMATCH
    assert len(tuple(events.iterdir())) == before_mismatch

    _patch_application_inputs(monkeypatch)
    repair_ref = f"refs/repoguard/repairs/{_CANDIDATE}"

    def publish(
        _source: object,
        _candidate_value: object,
        _git_executable: object,
        _candidate_id: object,
        *,
        inherited_lock_fd: int | None = None,
    ) -> _PublicationResult:
        assert type(inherited_lock_fd) is int
        os.fstat(inherited_lock_fd)
        competing_fd = os.open(
            config.runtime_root / "sessions" / _SESSION / "session.lock",
            os.O_RDWR | os.O_NOFOLLOW,
        )
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(competing_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(competing_fd)
        return _PublicationResult(_PublicationOutcome.PUBLISHED, repair_ref, _OID)

    monkeypatch.setattr(workflow_module, "_publish_repair_ref", publish)
    applied = session.apply(expected_approval_sha256=approval_sha256)
    assert applied.state is RepairState.APPLIED
    assert applied.application is not None
    assert applied.application.approval_sha256 == approval_sha256
    assert applied.application.ref == repair_ref
    assert applied.application.commit_oid == _OID
    assert applied.cleanup_pending is False
    assert not (config.runtime_root / "sessions" / _SESSION / "private").exists()


@pytest.mark.parametrize(
    "code",
    [RepairErrorCode.REF_CONFLICT, RepairErrorCode.PUBLICATION_FAILED],
)
def test_application_failure_restores_approved_and_retains_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: RepairErrorCode,
) -> None:
    config, session, approval_sha256 = _approved_session(tmp_path, monkeypatch)
    read_back = "f" * len(_OID) if code is RepairErrorCode.REF_CONFLICT else None
    _patch_application_inputs(monkeypatch, read_back=read_back)

    def fail_publication(*_: object, **__: object) -> _PublicationResult:
        raise RepairError(code, RepairStage.APPLICATION)

    monkeypatch.setattr(workflow_module, "_publish_repair_ref", fail_publication)
    with pytest.raises(RepairError) as captured:
        session.apply(expected_approval_sha256=approval_sha256)
    assert captured.value.code is code
    assert captured.value.state is RepairState.APPROVED
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    restored = session.snapshot()
    assert restored.state is RepairState.APPROVED
    assert restored.approval is not None
    assert restored.approval.approval_sha256 == approval_sha256
    assert (config.runtime_root / "sessions" / _SESSION / "private").is_dir()


def test_application_error_after_successful_publication_converges_to_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, approval_sha256 = _approved_session(tmp_path, monkeypatch)
    _patch_application_inputs(monkeypatch)

    def fail_after_publication(*_: object, **__: object) -> _PublicationResult:
        raise RepairError(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)

    monkeypatch.setattr(workflow_module, "_publish_repair_ref", fail_after_publication)
    applied = session.apply(expected_approval_sha256=approval_sha256)

    assert applied.state is RepairState.APPLIED
    assert applied.application is not None
    assert applied.application.commit_oid == _OID
    assert not (config.runtime_root / "sessions" / _SESSION / "private").exists()


def test_application_uncertain_readback_keeps_applying_and_private_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, approval_sha256 = _approved_session(tmp_path, monkeypatch)
    _patch_application_inputs(monkeypatch)

    def fail_publication(*_: object, **__: object) -> _PublicationResult:
        raise RepairError(RepairErrorCode.PUBLICATION_FAILED, RepairStage.APPLICATION)

    def fail_readback(*_: object, **__: object) -> str | None:
        raise RepairError(RepairErrorCode.GIT_FAILED, RepairStage.APPLICATION)

    monkeypatch.setattr(workflow_module, "_publish_repair_ref", fail_publication)
    monkeypatch.setattr(workflow_module, "_read_repair_ref", fail_readback)
    with pytest.raises(RepairError) as captured:
        session.apply(expected_approval_sha256=approval_sha256)

    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert captured.value.state is RepairState.APPLYING
    assert captured.value.__context__ is None
    assert session.snapshot().state is RepairState.APPLYING
    assert (config.runtime_root / "sessions" / _SESSION / "private").is_dir()


@pytest.mark.parametrize(
    ("operation", "terminal_state"),
    [("cancel", RepairState.CANCELLED), ("expire", RepairState.EXPIRED)],
)
@pytest.mark.parametrize(
    ("read_back", "reconciled_state", "expected_error"),
    [
        (None, None, None),
        (_OID, RepairState.APPLIED, None),
        ("f" * len(_OID), RepairState.APPROVED, RepairErrorCode.REF_CONFLICT),
    ],
)
def test_applying_decisions_reconcile_authoritative_ref_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    terminal_state: RepairState,
    read_back: str | None,
    reconciled_state: RepairState | None,
    expected_error: RepairErrorCode | None,
) -> None:
    config, session, _ = _approved_session(tmp_path, monkeypatch)
    _patch_application_inputs(monkeypatch, read_back=read_back)
    with _locked_session(config, _SESSION) as storage:
        approved = storage.load().snapshot
        applying = replace(
            approved,
            state=RepairState.APPLYING,
            updated_at_us=approved.updated_at_us + 1,
        )
        storage.append("applying", applying)

    def decide() -> RepairSnapshot:
        if operation == "cancel":
            return session.cancel(subject="local caller", reason="stop")
        return session.expire()

    expected_state = terminal_state if reconciled_state is None else reconciled_state
    if expected_error is None:
        result = decide()
        assert result.state is expected_state
    else:
        with pytest.raises(RepairError) as captured:
            decide()
        assert captured.value.code is expected_error
        assert captured.value.state is expected_state
        assert captured.value.__context__ is None
    assert session.snapshot().state is expected_state
