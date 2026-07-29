"""Focused recovery and retention tests for safe repair maintenance."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import NoReturn, cast

import pytest

import repoguard._repair_sandbox as sandbox_module
import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
from repoguard._repair_models import _domain_digest
from repoguard._repair_sandbox import _SandboxRunIdentity
from repoguard._repair_store import (
    _create_session_store,
    _initialize_runtime_root,
    _locked_session,
    _SessionStore,
    _ValidationRunLease,
)
from repoguard.evidence import (
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApproval,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairError,
    RepairErrorCode,
    RepairFailure,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairMaintenanceReport,
    RepairManager,
    RepairManagerConfig,
    RepairPromptIdentity,
    RepairSession,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairTarget,
    RepairValidation,
    ValidationCommand,
    ValidationCommandResult,
    ValidationPolicy,
    repair_approval_to_dict,
    repair_candidate_to_dict,
    repair_validation_to_dict,
    validation_policy_to_dict,
)
from repoguard.review import RuleId, review_evidence

_REQUEST = "b" * 64
_OID = "1" * 40
_FOREIGN_OID = "2" * 40
_RUN_TOKEN = "3" * 64
_CONTAINER = "4" * 64
_RETENTION_US = 30 * 24 * 60 * 60 * 1_000_000
_REAL_GIT = Path("/usr/bin/git")
_IMAGE = f"sha256:{'1' * 64}"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        Path("/bin/true"),
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def _manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairManager]:
    repository = tmp_path / "repository"
    common = repository / ".git"
    repository.mkdir(mode=0o700)
    common.mkdir(mode=0o700)
    config = _config(tmp_path / "runtime")
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    _initialize_runtime_root(config, repository_root=repository, common_dir=common)
    monkeypatch.setattr(workflow_module, "_initialize_manager", lambda *_: None)
    return config, RepairManager(RepositoryInput(repository), config)


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return (
        subprocess.run(
            (_REAL_GIT, "-C", root, *arguments),
            check=True,
            capture_output=True,
            env=environment,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Repair Recovery Test",
        "-c",
        "user.email=repair-recovery@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _checkpoint_recovery_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairManager, RepairSession]:
    repository = tmp_path / "checkpoint-repository"
    repository.mkdir()
    _git(repository, "init", "--quiet", "-b", "main")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    source_directory = repository / "src"
    source_directory.mkdir()
    (source_directory / "app.py").write_text("value = 1\n", encoding="utf-8")
    base_oid = _commit(repository, "base")
    (repository / "secret.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    head_oid = _commit(repository, "add repair target")
    bundle = collect_evidence(
        RepositoryInput(repository),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    target_index = next(
        index
        for index, finding in enumerate(review.findings)
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL
    )
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = RepairManagerConfig(
        tmp_path / "checkpoint-runtime",
        _REAL_GIT,
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )
    manager = RepairManager(RepositoryInput(repository), config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(target_index, 0),),
        allowed_paths=("secret.pem",),
        generation=RepairGenerationPolicy(
            RepairGenerationMode.DETERMINISTIC,
            None,
            None,
        ),
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
    )
    return config, manager, session


def _created(session_id: str, *, timestamp_us: int = 1) -> RepairSnapshot:
    return RepairSnapshot(
        1,
        session_id,
        RepairState.CREATED,
        _REQUEST,
        timestamp_us,
        timestamp_us,
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


def _create(config: RepairManagerConfig, session_id: str, *, timestamp_us: int = 1) -> None:
    _create_session_store(
        config,
        session_id,
        request={"schema_version": 1, "request_sha256": _REQUEST},
        snapshot=_created(session_id, timestamp_us=timestamp_us),
    )


def _candidate() -> RepairCandidate:
    candidate = RepairCandidate(
        1,
        "0" * 64,
        _REQUEST,
        RepairPromptIdentity("agent_repair", 1, "5" * 64, "6" * 64, "7" * 64),
        RepairContextSummary(
            RepairContextOutcome.NOT_REQUESTED,
            None,
            None,
            0,
            0,
            0,
            None,
            None,
        ),
        "8" * 64,
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
    command = ValidationCommandResult(
        0,
        0,
        None,
        False,
        10,
        "9" * 64,
        0,
        False,
        "a" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        "0" * 64,
        _CANDIDATE,
        "b" * 64,
        "c" * 64,
        f"sha256:{'d' * 64}",
        3,
        4,
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


_VALIDATION = _validation().validation_sha256


def _approval(*, approved_at_us: int) -> RepairApproval:
    approval = RepairApproval(
        1,
        "0" * 64,
        _CANDIDATE,
        _VALIDATION,
        "local reviewer",
        REPAIR_APPROVAL_CONFIRMATION,
        approved_at_us,
    )
    payload = repair_approval_to_dict(approval)
    del payload["approval_sha256"]
    return replace(approval, approval_sha256=_domain_digest("approval", payload))


def _lease(session_id: str) -> _ValidationRunLease:
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", session_id),
                ("com.repoguard.candidate", _CANDIDATE),
                ("com.repoguard.run-token-sha256", _RUN_TOKEN),
            )
        )
    )
    return _ValidationRunLease(
        _CONTAINER,
        "repoguard-m5-validation-recovery",
        labels,
        session_id,
        _CANDIDATE,
        _RUN_TOKEN,
    )


def _append_generating(
    config: RepairManagerConfig,
    session_id: str,
    *,
    candidate: bool,
    timestamp_us: int = 2,
) -> RepairSnapshot:
    with _locked_session(config, session_id) as storage:
        created = storage.load().snapshot
        generating = replace(
            created,
            state=RepairState.GENERATING,
            updated_at_us=timestamp_us,
        )
        generating = storage.append("generating", generating).snapshot
        if not candidate:
            return generating
        checkpoint = replace(
            generating,
            candidate=_candidate(),
            updated_at_us=timestamp_us + 1,
        )
        storage.write_preview({"schema_version": 1})
        return storage.append("candidate", checkpoint).snapshot


def _append_validating_with_lease(
    config: RepairManagerConfig,
    session_id: str,
) -> _ValidationRunLease:
    checkpoint = _append_generating(config, session_id, candidate=True)
    lease = _lease(session_id)
    with _locked_session(config, session_id) as storage:
        validating = replace(
            checkpoint,
            state=RepairState.VALIDATING,
            updated_at_us=checkpoint.updated_at_us + 1,
        )
        validating = storage.append("validating", validating).snapshot
        storage.append(
            "validation_intent",
            replace(validating, updated_at_us=validating.updated_at_us + 1),
            validation_run=replace(lease, container_id=None),
        )
        storage.append(
            "validation_run",
            replace(validating, updated_at_us=validating.updated_at_us + 1),
            validation_run=lease,
        )
    return lease


def _append_applying(config: RepairManagerConfig, session_id: str) -> RepairSnapshot:
    checkpoint = _append_generating(config, session_id, candidate=True)
    repository = config.runtime_root / "sessions" / session_id / "private" / "repository"
    repository.mkdir(mode=0o700)
    validation = _validation()
    lease = _lease(session_id)
    with _locked_session(config, session_id) as storage:
        validating = replace(
            checkpoint,
            state=RepairState.VALIDATING,
            updated_at_us=checkpoint.updated_at_us + 1,
        )
        validating = storage.append("validating", validating).snapshot
        registered = replace(validating, updated_at_us=validating.updated_at_us + 1)
        storage.append(
            "validation_intent",
            registered,
            validation_run=replace(lease, container_id=None),
        )
        storage.append("validation_run", registered, validation_run=lease)
        validation_result = replace(
            registered,
            updated_at_us=registered.updated_at_us + 1,
            validation=validation,
        )
        storage.append("validation_result", validation_result)
        validated = replace(
            validation_result,
            state=RepairState.VALIDATED,
            updated_at_us=validation_result.updated_at_us + 1,
        )
        validated = storage.append(
            "validated",
            validated,
            clear_validation_run=True,
        ).snapshot
        approval = _approval(approved_at_us=validated.updated_at_us + 1)
        approved = replace(
            validated,
            state=RepairState.APPROVED,
            updated_at_us=validated.updated_at_us + 1,
            approval=approval,
        )
        approved = storage.append("approved", approved).snapshot
        applying = replace(
            approved,
            state=RepairState.APPLYING,
            updated_at_us=approved.updated_at_us + 1,
        )
        return storage.append("applying", applying).snapshot


def _append_failed(
    config: RepairManagerConfig,
    session_id: str,
    *,
    terminal_at_us: int,
    cleanup_pending: bool,
    cleanup_at_us: int | None = None,
) -> RepairSnapshot:
    generating = _append_generating(
        config,
        session_id,
        candidate=False,
        timestamp_us=terminal_at_us - 1,
    )
    failure = RepairFailure(
        1,
        RepairErrorCode.RECOVERY_FAILED,
        RepairStage.RECOVERY,
        False,
        terminal_at_us,
    )
    with _locked_session(config, session_id) as storage:
        failed = replace(
            generating,
            state=RepairState.FAILED,
            updated_at_us=terminal_at_us,
            failure=failure,
            cleanup_pending=cleanup_pending,
        )
        failed = storage.append("failed", failed).snapshot
        if cleanup_at_us is None:
            return failed
        assert storage.cleanup_private()
        cleaned = replace(
            failed,
            updated_at_us=cleanup_at_us,
            cleanup_pending=False,
        )
        return storage.append("cleanup_complete", cleaned).snapshot


def _event_kinds(config: RepairManagerConfig, session_id: str) -> tuple[str, ...]:
    events = config.runtime_root / "sessions" / session_id / "events"
    return tuple(
        cast(str, json.loads(path.read_bytes())["kind"]) for path in sorted(events.iterdir())
    )


def _freeze_time(monkeypatch: pytest.MonkeyPatch, now_us: int) -> None:
    monkeypatch.setattr(workflow_module, "_utc_now_us", lambda: now_us)


def _assert_sorted_report(report: RepairMaintenanceReport) -> None:
    assert report.schema_version == 1
    assert report.started_at_us <= report.finished_at_us
    for values in (
        report.recovered_session_ids,
        report.cleaned_session_ids,
        report.removed_session_ids,
        report.cleanup_pending_session_ids,
        report.failed_session_ids,
    ):
        assert values == tuple(sorted(set(values), key=lambda item: item.encode("utf-8")))


def test_recover_generating_without_candidate_fails_and_cleans_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "1" * 64
    _create(config, session_id)
    _append_generating(config, session_id, candidate=False)
    monkeypatch.setattr(
        workflow_module,
        "_generate_candidate",
        lambda *_args, **_kwargs: pytest.fail("recovery must never call a provider/generator"),
    )

    report = manager.recover()

    snapshot = manager.open_session(session_id).snapshot()
    assert snapshot.state is RepairState.FAILED
    assert snapshot.failure is not None
    assert snapshot.failure.code is RepairErrorCode.RECOVERY_FAILED
    assert snapshot.failure.stage is RepairStage.RECOVERY
    assert snapshot.cleanup_pending is False
    assert not (config.runtime_root / "sessions" / session_id / "private").exists()
    assert report.recovered_session_ids == (session_id,)
    assert report.failed_session_ids == ()
    assert _event_kinds(config, session_id)[-2:] == ("failed", "cleanup_complete")

    repeated = manager.recover()
    assert repeated.recovered_session_ids == ()
    assert repeated.cleaned_session_ids == ()
    assert repeated.failed_session_ids == ()


def test_recover_complete_candidate_checkpoint_validates_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager, session = _checkpoint_recovery_session(tmp_path, monkeypatch)
    assets = sandbox_module._load_sandbox_assets()

    class _SimulatedProcessLoss(BaseException):
        pass

    def interrupt_after_checkpoint(
        _config_value: RepairManagerConfig,
        _policy: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> NoReturn:
        mount_identity_check()
        assert probe_path.read_bytes() == assets.probe
        assert seccomp_path.read_bytes() == assets.seccomp_json
        raise _SimulatedProcessLoss

    monkeypatch.setattr(
        workflow_module,
        "_prepare_sandbox",
        interrupt_after_checkpoint,
    )
    with pytest.raises(_SimulatedProcessLoss):
        session.propose()

    checkpoint = session.snapshot()
    assert checkpoint.state is RepairState.GENERATING
    assert checkpoint.candidate is not None
    assert checkpoint.validation is None
    private_root = config.runtime_root / "sessions" / checkpoint.session_id / "private"
    assert (private_root / "repository" / ".git" / "repoguard-index").is_file()
    assert (private_root / "candidate-input").is_dir()
    assert (private_root / "candidate.diff").is_file()
    assert (private_root / "private-key.patch").is_file()
    assert (private_root / "runner.py").read_bytes() == assets.runner
    assert (private_root / "probe.py").read_bytes() == assets.probe
    assert (private_root / "seccomp-v1.json").read_bytes() == assets.seccomp_json
    assert _event_kinds(config, checkpoint.session_id) == (
        "created",
        "generating",
        "candidate",
    )

    def unexpected_generation(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("recovery must not call a provider or candidate generator")

    monkeypatch.setattr(workflow_module, "_generate_candidate", unexpected_generation)
    monkeypatch.setattr(
        workflow_module,
        "_invoke_repair_provider",
        unexpected_generation,
    )
    capabilities = sandbox_module._SandboxCapabilities(
        client_version="29.6.1",
        server_version="29.6.1",
        api_version="1.55",
        architecture="x86_64",
        cgroup_version="2",
        security_options=("name=rootless", "name=seccomp,profile=builtin"),
        image_id=_IMAGE,
        sandbox_manifest_sha256=assets.sandbox_manifest_sha256,
    )
    validation_calls: list[str] = []

    def prepare(
        _config_value: RepairManagerConfig,
        policy: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> sandbox_module._SandboxCapabilities:
        mount_identity_check()
        assert policy.image_id == _IMAGE
        assert probe_path.read_bytes() == assets.probe
        assert seccomp_path.read_bytes() == assets.seccomp_json
        mount_identity_check()
        return capabilities

    def run(
        _config_value: RepairManagerConfig,
        policy: ValidationPolicy,
        _capabilities: sandbox_module._SandboxCapabilities,
        **arguments: object,
    ) -> sandbox_module._SandboxValidationOutcome:
        recovered_session_id = cast(str, arguments["session_id"])
        candidate_id = cast(str, arguments["candidate_id"])
        validation_calls.append(candidate_id)
        assert recovered_session_id == checkpoint.session_id
        assert checkpoint.candidate is not None
        assert candidate_id == checkpoint.candidate.candidate_id
        assert arguments["candidate_root"] == private_root / "candidate-input"
        assert arguments["git_dir"] == private_root / "repository" / ".git"
        assert arguments["index_file"] == private_root / "repository" / ".git" / "repoguard-index"
        assert arguments["runner_path"] == private_root / "runner.py"
        assert arguments["seccomp_path"] == private_root / "seccomp-v1.json"
        assert arguments["expected_tree_oid"] == checkpoint.candidate.tree_oid
        tracked_inputs = cast(
            tuple[sandbox_module._TrackedInput, ...],
            arguments["tracked_inputs"],
        )
        mount_identity_check = cast(Callable[[], None], arguments["mount_identity_check"])
        mount_identity_check()
        assert tracked_inputs
        assert any(item.path == "src/app.py" for item in tracked_inputs)
        assert all(len(item.sha256) == 64 for item in tracked_inputs)
        run_token_sha256 = "d" * 64
        intent = sandbox_module._SandboxRunIntent(
            container_name="repoguard-m5-recovery-checkpoint-test",
            labels=(
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", recovered_session_id),
                ("com.repoguard.candidate", candidate_id),
                ("com.repoguard.run-token-sha256", run_token_sha256),
            ),
            session_id=recovered_session_id,
            candidate_id=candidate_id,
            run_token_sha256=run_token_sha256,
        )
        identity = sandbox_module._SandboxRunIdentity(
            container_id="c" * 64,
            container_name=intent.container_name,
            labels=intent.labels,
            session_id=recovered_session_id,
            candidate_id=candidate_id,
            run_token_sha256=run_token_sha256,
        )
        register_intent = cast(
            Callable[[sandbox_module._SandboxRunIntent], bool],
            arguments["register_intent"],
        )
        register_run = cast(
            Callable[[sandbox_module._SandboxRunIdentity], bool],
            arguments["register_run"],
        )
        before_remove = cast(
            Callable[[sandbox_module._SandboxValidationOutcome], None],
            arguments["before_remove"],
        )
        assert register_intent(intent) is True
        assert register_run(identity) is True
        command_result = ValidationCommandResult(
            0,
            0,
            None,
            False,
            1_000,
            _EMPTY_SHA256,
            0,
            False,
            _EMPTY_SHA256,
            0,
            False,
        )
        report = sandbox_module._SandboxReport(
            success=True,
            failure_kind=None,
            started_at_us=100,
            finished_at_us=200,
            command_results=(command_result,),
            peak_memory_bytes=4_096,
            oom_killed=False,
            residual_process_count=0,
            workspace_entry_count=len(tracked_inputs),
            workspace_inode_count=len(tracked_inputs),
            tracked_tree_clean=True,
        )
        outcome = sandbox_module._SandboxValidationOutcome(
            recovered_session_id,
            candidate_id,
            _domain_digest("policy", validation_policy_to_dict(policy)),
            capabilities.sandbox_manifest_sha256,
            capabilities.image_id,
            report,
            identity,
            False,
        )
        before_remove(outcome)
        return outcome

    monkeypatch.setattr(workflow_module, "_prepare_sandbox", prepare)
    monkeypatch.setattr(workflow_module, "_run_sandbox_validation", run)

    first = manager.recover()

    recovered = session.snapshot()
    assert recovered.state is RepairState.VALIDATED
    assert recovered.validation is not None
    assert recovered.validation.success is True
    assert validation_calls == [checkpoint.candidate.candidate_id]
    assert first.recovered_session_ids == (checkpoint.session_id,)
    assert first.failed_session_ids == ()
    assert _event_kinds(config, checkpoint.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "validation_run",
        "validation_result",
        "validated",
    )

    repeated = manager.recover()

    assert session.snapshot() == recovered
    assert validation_calls == [checkpoint.candidate.candidate_id]
    assert repeated.recovered_session_ids == ()
    assert repeated.failed_session_ids == ()


def test_recover_validating_exact_lease_stops_removes_and_never_revalidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "2" * 64
    _create(config, session_id)
    expected_lease = _append_validating_with_lease(config, session_id)
    calls: list[tuple[str, _SandboxRunIdentity]] = []

    def stop(_config: RepairManagerConfig, identity: _SandboxRunIdentity) -> bool:
        calls.append(("stop", identity))
        return True

    def remove(_config: RepairManagerConfig, identity: _SandboxRunIdentity) -> bool:
        calls.append(("remove", identity))
        return True

    monkeypatch.setattr(workflow_module, "_stop_exact_container", stop)
    monkeypatch.setattr(workflow_module, "_remove_exact_container", remove)
    monkeypatch.setattr(
        workflow_module,
        "_run_sandbox_validation",
        lambda *_args, **_kwargs: pytest.fail("recovery must never repeat validation"),
    )

    report = manager.recover()

    assert tuple(name for name, _ in calls) == ("stop", "remove")
    for _, identity in calls:
        assert identity.container_id == expected_lease.container_id
        assert identity.labels == expected_lease.labels
        assert identity.run_token_sha256 == expected_lease.run_token_sha256
    with _locked_session(config, session_id) as storage:
        loaded = storage.load()
    assert loaded.snapshot.state is RepairState.FAILED
    assert loaded.snapshot.failure is not None
    assert loaded.snapshot.failure.code is RepairErrorCode.RECOVERY_FAILED
    assert loaded.snapshot.cleanup_pending is False
    assert loaded.validation_run is None
    assert report.recovered_session_ids == (session_id,)
    assert report.failed_session_ids == ()


def test_recovery_never_clears_an_unbound_pre_create_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "9" * 64
    _create(config, session_id)
    checkpoint = _append_generating(config, session_id, candidate=True)
    intent = replace(_lease(session_id), container_id=None)
    with _locked_session(config, session_id) as storage:
        validating = storage.append(
            "validating",
            replace(
                checkpoint,
                state=RepairState.VALIDATING,
                updated_at_us=checkpoint.updated_at_us + 1,
            ),
        ).snapshot
        storage.append(
            "validation_intent",
            replace(validating, updated_at_us=validating.updated_at_us + 1),
            validation_run=intent,
        )

    def unexpected_container_action(*_args: object, **_kwargs: object) -> bool:
        pytest.fail("an unbound intent must not be managed as an exact container")

    monkeypatch.setattr(workflow_module, "_stop_exact_container", unexpected_container_action)
    monkeypatch.setattr(workflow_module, "_remove_exact_container", unexpected_container_action)

    recovered = manager.recover()
    snapshot = manager.open_session(session_id).snapshot()

    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is True
    assert recovered.recovered_session_ids == (session_id,)
    assert recovered.cleaned_session_ids == ()
    assert recovered.cleanup_pending_session_ids == (session_id,)
    with _locked_session(config, session_id) as storage:
        assert storage.load().validation_run == intent
    assert _event_kinds(config, session_id)[-2:] == ("validation_intent", "failed")

    cleanup = manager.cleanup()
    assert cleanup.cleaned_session_ids == ()
    assert cleanup.removed_session_ids == ()
    assert cleanup.cleanup_pending_session_ids == (session_id,)
    with _locked_session(config, session_id) as storage:
        assert storage.load().validation_run == intent


@pytest.mark.parametrize(
    ("read_back", "expected_state", "terminal", "final_kind"),
    [
        (_OID, RepairState.APPLIED, True, "cleanup_complete"),
        (None, RepairState.APPROVED, False, "recovered"),
        (_FOREIGN_OID, RepairState.APPROVED, False, "application_conflict"),
    ],
)
def test_recover_applying_converges_from_authoritative_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    read_back: str | None,
    expected_state: RepairState,
    terminal: bool,
    final_kind: str,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "3" * 64
    _create(config, session_id)
    _append_applying(config, session_id)
    monkeypatch.setattr(
        workflow_module,
        "_open_application_candidate",
        lambda *_args: (object(), object()),
    )
    monkeypatch.setattr(
        workflow_module,
        "_read_repair_ref",
        lambda *_args, **_kwargs: read_back,
    )

    report = manager.recover()

    snapshot = manager.open_session(session_id).snapshot()
    assert snapshot.state is expected_state
    assert report.recovered_session_ids == (session_id,)
    assert report.failed_session_ids == ()
    assert final_kind in _event_kinds(config, session_id)
    if terminal:
        assert snapshot.application is not None
        assert snapshot.application.commit_oid == _OID
        assert snapshot.cleanup_pending is False
        assert not (config.runtime_root / "sessions" / session_id / "private").exists()
    else:
        assert snapshot.application is None
        assert (config.runtime_root / "sessions" / session_id / "private").is_dir()


def test_recover_applying_read_error_remains_uncertain_and_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "4" * 64
    _create(config, session_id)
    before = _append_applying(config, session_id)
    monkeypatch.setattr(
        workflow_module,
        "_open_application_candidate",
        lambda *_args: (object(), object()),
    )

    def fail_read(*_args: object, **_kwargs: object) -> str | None:
        raise RepairError(RepairErrorCode.GIT_FAILED, RepairStage.APPLICATION)

    monkeypatch.setattr(workflow_module, "_read_repair_ref", fail_read)

    report = manager.recover()

    assert manager.open_session(session_id).snapshot() == before
    assert report.recovered_session_ids == ()
    assert report.failed_session_ids == (session_id,)
    assert _event_kinds(config, session_id)[-1] == "applying"


def test_cleanup_retries_terminal_private_payload_and_reports_pending_then_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "5" * 64
    terminal_at_us = 10_000_000
    _create(config, session_id, timestamp_us=terminal_at_us - 2)
    _append_failed(
        config,
        session_id,
        terminal_at_us=terminal_at_us,
        cleanup_pending=True,
    )
    _freeze_time(monkeypatch, terminal_at_us + 1)
    original_cleanup = _SessionStore.cleanup_private
    monkeypatch.setattr(_SessionStore, "cleanup_private", lambda _: False)

    pending = manager.cleanup()

    assert pending.cleanup_pending_session_ids == (session_id,)
    assert pending.cleaned_session_ids == ()
    assert manager.open_session(session_id).snapshot().cleanup_pending is True
    assert (config.runtime_root / "sessions" / session_id / "private").is_dir()

    monkeypatch.setattr(_SessionStore, "cleanup_private", original_cleanup)
    cleaned = manager.cleanup()

    snapshot = manager.open_session(session_id).snapshot()
    assert cleaned.cleaned_session_ids == (session_id,)
    assert cleaned.cleanup_pending_session_ids == ()
    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is False
    assert not (config.runtime_root / "sessions" / session_id / "private").exists()


def test_cleanup_retention_boundary_is_exactly_thirty_days(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "6" * 64
    terminal_at_us = 20_000_000
    _create(config, session_id, timestamp_us=terminal_at_us - 2)
    _append_failed(
        config,
        session_id,
        terminal_at_us=terminal_at_us,
        cleanup_pending=True,
        cleanup_at_us=terminal_at_us + 1,
    )
    session_path = config.runtime_root / "sessions" / session_id

    _freeze_time(monkeypatch, terminal_at_us + _RETENTION_US - 1)
    before_boundary = manager.cleanup()
    assert before_boundary.removed_session_ids == ()
    assert session_path.is_dir()

    _freeze_time(monkeypatch, terminal_at_us + _RETENTION_US)
    at_boundary = manager.cleanup()
    assert at_boundary.removed_session_ids == (session_id,)
    assert not session_path.exists()


def test_cleanup_timestamp_does_not_extend_terminal_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_id = "7" * 64
    terminal_at_us = 30_000_000
    cleanup_at_us = terminal_at_us + _RETENTION_US - 1
    _create(config, session_id, timestamp_us=terminal_at_us - 2)
    _append_failed(
        config,
        session_id,
        terminal_at_us=terminal_at_us,
        cleanup_pending=True,
        cleanup_at_us=cleanup_at_us,
    )
    _freeze_time(monkeypatch, terminal_at_us + _RETENTION_US)

    report = manager.cleanup()

    assert report.removed_session_ids == (session_id,)
    assert not (config.runtime_root / "sessions" / session_id).exists()


def test_recovery_reports_are_sorted_and_repeated_pass_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    session_ids = ("f" * 64, "8" * 64, "a" * 64)
    for session_id in session_ids:
        _create(config, session_id)
        _append_generating(config, session_id, candidate=False)

    first = manager.recover()
    second = manager.recover()

    _assert_sorted_report(first)
    _assert_sorted_report(second)
    assert first.recovered_session_ids == tuple(sorted(session_ids))
    assert second.recovered_session_ids == ()
    assert second.cleaned_session_ids == ()
    assert second.removed_session_ids == ()
    assert second.cleanup_pending_session_ids == ()
    assert second.failed_session_ids == ()


@pytest.mark.parametrize("operation", ["recover", "cleanup"])
def test_maintenance_reports_corrupt_and_locked_sessions_without_mutating_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    config, manager = _manager(tmp_path, monkeypatch)
    corrupt_id = "b" * 64
    locked_id = "c" * 64
    for session_id in (corrupt_id, locked_id):
        _create(config, session_id)
        _append_generating(config, session_id, candidate=False)

    corrupt_event = (
        config.runtime_root / "sessions" / corrupt_id / "events" / "0000000000000001.json"
    )
    corrupt_event.chmod(0o600)
    corrupt_event.write_bytes(b"{}")
    corrupt_event.chmod(0o400)
    original_acquire = store_module._acquire_flock

    def selective_lock(descriptor: int, timeout_seconds: float) -> bool:
        target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        if target.name == "session.lock" and target.parent.name == locked_id:
            return False
        return original_acquire(descriptor, timeout_seconds)

    monkeypatch.setattr(store_module, "_acquire_flock", selective_lock)
    maintain = cast(Callable[[], RepairMaintenanceReport], getattr(manager, operation))

    report = maintain()

    _assert_sorted_report(report)
    assert report.recovered_session_ids == ()
    assert report.cleaned_session_ids == ()
    assert report.removed_session_ids == ()
    assert report.failed_session_ids == (corrupt_id, locked_id)
    assert (config.runtime_root / "sessions" / corrupt_id).is_dir()
    assert (config.runtime_root / "sessions" / locked_id).is_dir()
