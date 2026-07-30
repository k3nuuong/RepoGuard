"""Focused tests for read-only publication of applied M5 Git objects."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import repoguard._repair_git as git_module
import repoguard._repair_store as store_module
from repoguard._repair_models import _domain_digest
from repoguard._repair_store import (
    _create_session_store,
    _locked_session,
    _ValidationRunLease,
)
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApplication,
    RepairApproval,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairError,
    RepairErrorCode,
    RepairManager,
    RepairManagerConfig,
    RepairPreview,
    RepairPromptIdentity,
    RepairPublicationBlob,
    RepairPublicationEntry,
    RepairPublicationManifest,
    RepairSession,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairValidation,
    ValidationCommandResult,
    repair_application_to_dict,
    repair_approval_to_dict,
    repair_candidate_to_dict,
    repair_preview_to_dict,
    repair_publication_entry_to_dict,
    repair_publication_entry_to_json,
    repair_publication_manifest_to_dict,
    repair_publication_manifest_to_json,
    repair_validation_to_dict,
)

_GIT = Path(shutil.which("git") or "/usr/bin/git").resolve()
_SESSION_ID = "a" * 64
_REQUEST_SHA256 = "b" * 64
_CHANGED_PATHS = ("src/app.py", "src/run.sh")


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "RepoGuard",
        "GIT_AUTHOR_EMAIL": "repoguard@localhost",
        "GIT_AUTHOR_DATE": "@0 +0000",
        "GIT_COMMITTER_NAME": "RepoGuard",
        "GIT_COMMITTER_EMAIL": "repoguard@localhost",
        "GIT_COMMITTER_DATE": "@0 +0000",
    }
    return subprocess.run(
        (str(_GIT), "-C", str(root), *arguments),
        input=input_bytes,
        capture_output=True,
        check=True,
        env=environment,
    ).stdout


def _build_repository(
    tmp_path: Path,
    *,
    object_format: str = "sha1",
) -> tuple[Path, str, str, str, dict[str, bytes]]:
    root = tmp_path / "repository"
    root.mkdir(mode=0o700, parents=True)
    init_arguments: tuple[str, ...] = ("init", "-q")
    if object_format == "sha256":
        init_arguments = (*init_arguments, "--object-format=sha256")
    _git(root, *init_arguments)
    _git(root, "config", "user.name", "RepoGuard test")
    _git(root, "config", "user.email", "repoguard@example.invalid")
    source = root / "src"
    source.mkdir()
    app = source / "app.py"
    runner = source / "run.sh"
    app.write_bytes(b"old\n")
    runner.write_bytes(b"#!/bin/sh\nexit 0\n")
    runner.chmod(0o755)
    _git(root, "add", "--", "src/app.py", "src/run.sh")
    _git(root, "commit", "-q", "-m", "base")
    parent_oid = _git(root, "rev-parse", "HEAD").decode("ascii").strip()

    content = {
        "src/app.py": b"new\n",
        "src/run.sh": b"#!/bin/sh\nprintf ok\n",
    }
    app.write_bytes(content["src/app.py"])
    runner.write_bytes(content["src/run.sh"])
    runner.chmod(0o755)
    _git(root, "add", "--", "src/app.py", "src/run.sh")
    tree_oid = _git(root, "write-tree").decode("ascii").strip()
    commit_oid = (
        _git(
            root,
            "commit-tree",
            tree_oid,
            "-p",
            parent_oid,
            input_bytes=b"RepoGuard safe repair candidate\n",
        )
        .decode("ascii")
        .strip()
    )
    _git(root, "reset", "-q", "--hard", parent_oid)
    return root, parent_oid, tree_oid, commit_oid, content


def _candidate(tree_oid: str, commit_oid: str, changed_paths: tuple[str, ...]) -> RepairCandidate:
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
        _REQUEST_SHA256,
        prompt,
        context,
        "4" * 64,
        tree_oid,
        commit_oid,
        changed_paths,
        4,
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


def _validation(candidate_id: str) -> RepairValidation:
    command = ValidationCommandResult(
        0,
        0,
        None,
        False,
        1,
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
        candidate_id,
        "7" * 64,
        "8" * 64,
        f"sha256:{'9' * 64}",
        1,
        2,
        True,
        None,
        (command,),
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


def _approval(candidate_id: str, validation_sha256: str) -> RepairApproval:
    approval = RepairApproval(
        1,
        "0" * 64,
        candidate_id,
        validation_sha256,
        "local reviewer",
        REPAIR_APPROVAL_CONFIRMATION,
        8,
    )
    payload = repair_approval_to_dict(approval)
    del payload["approval_sha256"]
    return replace(approval, approval_sha256=_domain_digest("approval", payload))


def _application(candidate: RepairCandidate, approval_sha256: str) -> RepairApplication:
    application = RepairApplication(
        1,
        "0" * 64,
        approval_sha256,
        f"refs/repoguard/repairs/{candidate.candidate_id}",
        candidate.commit_oid,
        10,
    )
    payload = repair_application_to_dict(application)
    del payload["application_sha256"]
    return replace(application, application_sha256=_domain_digest("application", payload))


def _created_snapshot(allowed_paths: tuple[str, ...]) -> RepairSnapshot:
    return RepairSnapshot(
        1,
        _SESSION_ID,
        RepairState.CREATED,
        _REQUEST_SHA256,
        1,
        1,
        1,
        allowed_paths,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
    )


def _config(tmp_path: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        tmp_path / "runtime",
        _GIT,
        Path("/bin/true"),
        Path("/run/repoguard-publication-test.sock"),
    )


def _manager(
    root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepairManager:
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    return RepairManager(RepositoryInput(root), _config(tmp_path))


def _create_store(manager: RepairManager, allowed_paths: tuple[str, ...]) -> None:
    _create_session_store(
        manager._config,
        _SESSION_ID,
        request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
        snapshot=_created_snapshot(allowed_paths),
        runtime_root_identity=manager._runtime_root_identity,
    )


def _append_applied(manager: RepairManager, candidate: RepairCandidate) -> RepairSnapshot:
    validation = _validation(candidate.candidate_id)
    approval = _approval(candidate.candidate_id, validation.validation_sha256)
    application = _application(candidate, approval.approval_sha256)
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION_ID),
                ("com.repoguard.candidate", candidate.candidate_id),
                ("com.repoguard.run-token-sha256", "f" * 64),
            )
        )
    )
    lease = _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-validation",
        labels,
        _SESSION_ID,
        candidate.candidate_id,
        "f" * 64,
    )
    with _locked_session(
        manager._config,
        _SESSION_ID,
        runtime_root_identity=manager._runtime_root_identity,
    ) as storage:
        created = storage.load().snapshot
        generating = storage.append(
            "generating",
            replace(created, state=RepairState.GENERATING, updated_at_us=2),
        ).snapshot
        preview = RepairPreview(
            1,
            _SESSION_ID,
            RepairState.GENERATING,
            candidate.candidate_id,
            None,
            candidate.changed_paths,
            "diff --git a/src/app.py b/src/app.py\n",
            REPAIR_APPROVAL_CONFIRMATION,
        )
        storage.write_preview(repair_preview_to_dict(preview))
        checkpoint = storage.append(
            "candidate",
            replace(generating, candidate=candidate, updated_at_us=3),
        ).snapshot
        validating = storage.append(
            "validating",
            replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4),
        ).snapshot
        registered = replace(validating, updated_at_us=5)
        storage.append(
            "validation_intent",
            registered,
            validation_run=replace(lease, container_id=None),
        )
        storage.append("validation_run", registered, validation_run=lease)
        validation_result = storage.append(
            "validation_result",
            replace(registered, validation=validation, updated_at_us=6),
        ).snapshot
        validated = storage.append(
            "validated",
            replace(validation_result, state=RepairState.VALIDATED, updated_at_us=7),
            clear_validation_run=True,
        ).snapshot
        approved = storage.append(
            "approved",
            replace(
                validated,
                state=RepairState.APPROVED,
                approval=approval,
                updated_at_us=8,
            ),
        ).snapshot
        applying = storage.append(
            "applying",
            replace(approved, state=RepairState.APPLYING, updated_at_us=9),
        ).snapshot
        applied = storage.append(
            "applied",
            replace(
                applying,
                state=RepairState.APPLIED,
                application=application,
                updated_at_us=10,
                cleanup_pending=True,
            ),
        ).snapshot
        assert storage.cleanup_private()
        return storage.append(
            "cleanup_complete",
            replace(applied, updated_at_us=11, cleanup_pending=False),
        ).snapshot


def _applied_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    recorded_paths: tuple[str, ...] = _CHANGED_PATHS,
    object_format: str = "sha1",
) -> tuple[RepairManager, RepairSession, RepairSnapshot, str, dict[str, bytes]]:
    root, parent_oid, tree_oid, commit_oid, content = _build_repository(
        tmp_path,
        object_format=object_format,
    )
    manager = _manager(root, tmp_path, monkeypatch)
    candidate = _candidate(tree_oid, commit_oid, recorded_paths)
    _create_store(manager, recorded_paths)
    applied = _append_applied(manager, candidate)
    _git(
        root,
        "update-ref",
        f"refs/repoguard/repairs/{candidate.candidate_id}",
        candidate.commit_oid,
    )
    assert applied.application is not None
    return manager, manager.open_session(_SESSION_ID), applied, parent_oid, content


def _assert_detached(error: RepairError) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    traceback = error.__traceback__
    while traceback is not None:
        assert "/src/repoguard/_repair_" not in traceback.tb_frame.f_code.co_filename
        traceback = traceback.tb_next


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_applied_publication_manifest_and_blobs_survive_terminal_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    object_format: str,
) -> None:
    manager, session, applied, parent_oid, expected_content = _applied_session(
        tmp_path,
        monkeypatch,
        object_format=object_format,
    )
    assert applied.application is not None
    assert not (manager._config.runtime_root / "sessions" / _SESSION_ID / "private").exists()

    manifest = session.publication_manifest(
        expected_application_sha256=applied.application.application_sha256
    )

    assert manifest.schema_version == 1
    assert manifest.session_id == _SESSION_ID
    assert manifest.object_format == object_format
    assert manifest.application_sha256 == applied.application.application_sha256
    assert manifest.parent_oid == parent_oid
    assert applied.candidate is not None
    assert manifest.tree_oid == applied.candidate.tree_oid
    assert manifest.commit_oid == applied.application.commit_oid
    assert tuple(entry.path for entry in manifest.entries) == _CHANGED_PATHS
    assert tuple(entry.mode for entry in manifest.entries) == ("100644", "100755")
    assert manifest.total_blob_bytes == sum(len(value) for value in expected_content.values())
    mapping = repair_publication_manifest_to_dict(manifest)
    encoded = repair_publication_manifest_to_json(manifest)
    assert encoded == json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    assert not encoded.endswith("\n")
    assert str(manager._repository.path) not in encoded
    assert all(value.decode("utf-8") not in encoded for value in expected_content.values())

    for entry in manifest.entries:
        blob = session.publication_blob(manifest=manifest, entry=entry)
        assert type(blob) is RepairPublicationBlob
        assert blob.schema_version == 1
        assert blob.manifest_sha256 == manifest.manifest_sha256
        assert blob.entry == entry
        assert blob.content == expected_content[entry.path]
        assert expected_content[entry.path].decode("utf-8") not in repr(blob)
        assert repair_publication_entry_to_json(entry) == json.dumps(
            repair_publication_entry_to_dict(entry),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    with pytest.raises(FrozenInstanceError):
        manifest.ref = "refs/heads/other"  # type: ignore[misc]


def test_publication_requires_applied_state_and_exact_application_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, _, _, _ = _build_repository(tmp_path)
    manager = _manager(root, tmp_path, monkeypatch)
    _create_store(manager, _CHANGED_PATHS)
    session = manager.open_session(_SESSION_ID)
    with pytest.raises(RepairError) as captured:
        session.publication_manifest(expected_application_sha256="0" * 64)
    assert captured.value.code is RepairErrorCode.INVALID_STATE
    assert captured.value.stage is RepairStage.APPLICATION
    assert captured.value.state is RepairState.CREATED
    _assert_detached(captured.value)

    manager, session, applied, _, _ = _applied_session(
        tmp_path / "second",
        monkeypatch,
    )
    assert applied.application is not None
    with pytest.raises(RepairError) as captured:
        session.publication_manifest(expected_application_sha256="0" * 64)
    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert captured.value.state is RepairState.APPLIED
    assert not (manager._config.runtime_root / "sessions" / _SESSION_ID / "private").exists()
    _assert_detached(captured.value)


def test_publication_rejects_authoritative_event_and_ref_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, session, applied, parent_oid, _ = _applied_session(tmp_path, monkeypatch)
    assert applied.application is not None
    root = manager._repository.path
    _git(root, "update-ref", applied.application.ref, parent_oid)
    with pytest.raises(RepairError) as captured:
        session.publication_manifest(
            expected_application_sha256=applied.application.application_sha256
        )
    assert captured.value.code is RepairErrorCode.REF_CONFLICT
    _assert_detached(captured.value)

    events = manager._config.runtime_root / "sessions" / _SESSION_ID / "events"
    terminal_event = sorted(events.iterdir())[-1]
    mapping = json.loads(terminal_event.read_bytes())
    mapping["snapshot"]["application"]["application_sha256"] = "f" * 64
    terminal_event.chmod(0o600)
    terminal_event.write_bytes(
        json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    terminal_event.chmod(0o400)
    with pytest.raises(RepairError) as captured:
        session.publication_manifest(
            expected_application_sha256=applied.application.application_sha256
        )
    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    _assert_detached(captured.value)


def test_blob_revalidates_complete_manifest_and_exact_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, session, applied, _, _ = _applied_session(tmp_path, monkeypatch)
    assert applied.application is not None
    manifest = session.publication_manifest(
        expected_application_sha256=applied.application.application_sha256
    )
    entry = manifest.entries[0]
    tampered_entry = replace(entry, size=entry.size + 1)
    tampered_entries = (tampered_entry, *manifest.entries[1:])
    tampered_manifest = replace(
        manifest,
        entries=tampered_entries,
        total_blob_bytes=manifest.total_blob_bytes + 1,
    )

    with pytest.raises(RepairError) as captured:
        session.publication_blob(manifest=tampered_manifest, entry=tampered_entry)
    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert captured.value.state is RepairState.APPLIED
    _assert_detached(captured.value)


def test_blob_independently_rejects_git_object_hash_mismatch_without_leaking_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, session, applied, _, _ = _applied_session(tmp_path, monkeypatch)
    assert applied.application is not None
    manifest = session.publication_manifest(
        expected_application_sha256=applied.application.application_sha256
    )
    entry = manifest.entries[0]
    original = git_module._run_required

    def corrupt_blob(
        git_executable: Path,
        root: Path | None,
        arguments: Sequence[str],
        *,
        stage: RepairStage,
        failure_code: RepairErrorCode,
        input_bytes: bytes | None = None,
        extra_environment: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
        stdout_limit: int = 2 * 1_024 * 1_024,
        stderr_limit: int = 2 * 1_024 * 1_024,
    ) -> git_module._GitResult:
        result = original(
            git_executable,
            root,
            arguments,
            stage=stage,
            failure_code=failure_code,
            input_bytes=input_bytes,
            extra_environment=extra_environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
        if tuple(arguments) == ("cat-file", "blob", entry.blob_oid):
            return replace(result, stdout=b"!" * entry.size)
        return result

    monkeypatch.setattr(git_module, "_run_required", corrupt_blob)
    with pytest.raises(RepairError) as captured:
        session.publication_blob(manifest=manifest, entry=entry)
    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    assert entry.path not in str(captured.value)
    assert (b"!" * entry.size).decode("ascii") not in str(captured.value)
    _assert_detached(captured.value)


def test_manifest_rejects_recorded_changed_paths_that_do_not_match_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, session, applied, _, _ = _applied_session(
        tmp_path,
        monkeypatch,
        recorded_paths=("src/app.py",),
    )
    assert applied.application is not None
    with pytest.raises(RepairError) as captured:
        session.publication_manifest(
            expected_application_sha256=applied.application.application_sha256
        )
    assert captured.value.code is RepairErrorCode.PUBLICATION_FAILED
    _assert_detached(captured.value)


def test_publication_records_enforce_exact_schema_and_never_serialize_blob_content() -> None:
    entry = RepairPublicationEntry(1, "src/app.py", "100644", "1" * 40, 4)
    manifest = RepairPublicationManifest(
        1,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        "5" * 64,
        "6" * 64,
        "sha1",
        f"refs/repoguard/repairs/{'6' * 64}",
        "7" * 40,
        "8" * 40,
        "9" * 40,
        (entry,),
        4,
    )
    blob = RepairPublicationBlob(1, manifest.manifest_sha256, entry, b"data")
    assert "data" not in repr(blob)
    assert "content" not in repair_publication_manifest_to_json(manifest)
    with pytest.raises(TypeError):
        repair_publication_entry_to_dict(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RepairPublicationEntry(1, "src/app.py", "120000", "1" * 40, 4)
    with pytest.raises(ValueError):
        replace(manifest, entries=(replace(entry, path="/absolute"),))
