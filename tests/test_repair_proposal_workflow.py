"""End-to-end proposal workflow tests with a fenced fake sandbox."""

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
from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence
from repoguard.providers import OpenAIProvider
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairMaintenanceReport,
    RepairManager,
    RepairManagerConfig,
    RepairProviderKind,
    RepairSession,
    RepairStage,
    RepairState,
    RepairTarget,
    ValidationCommand,
    ValidationCommandResult,
    ValidationFailureKind,
    ValidationPolicy,
    validation_policy_to_dict,
)
from repoguard.review import RuleId, review_evidence

_GIT = Path("/usr/bin/git")
_IMAGE = f"sha256:{'1' * 64}"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


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
            (_GIT, "-C", root, *arguments),
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
        "user.name=Repair Test",
        "-c",
        "user.email=repair@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _repository(tmp_path: Path, *, provider: bool) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--quiet", "-b", "main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    if provider:
        (root / "conflict.py").write_text(
            "<<<<<<< HEAD\nleft = 1\n=======\nright = 2\n>>>>>>> branch\n",
            encoding="utf-8",
        )
    else:
        (root / "secret.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
    head_oid = _commit(root, "add repair target")
    return root, base_oid, head_oid


def _config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        _GIT,
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def _proposal_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider: bool = False,
) -> tuple[RepairManagerConfig, RepairSession, OpenAIProvider | None]:
    root, base_oid, head_oid = _repository(tmp_path, provider=provider)
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    if provider:
        target_index = next(
            index
            for index, finding in enumerate(review.findings)
            if finding.rule_id is RuleId.MERGE_CONFLICT_MARKER
        )
        allowed_paths = ("conflict.py",)
        generation = RepairGenerationPolicy(
            RepairGenerationMode.PROVIDER,
            RepairProviderKind.OPENAI,
            "gpt-fixed",
        )
        provider_value = object.__new__(OpenAIProvider)
    else:
        target_index = next(
            index
            for index, finding in enumerate(review.findings)
            if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL
        )
        allowed_paths = ("secret.pem",)
        generation = RepairGenerationPolicy(
            RepairGenerationMode.DETERMINISTIC,
            None,
            None,
        )
        provider_value = None
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = _config(tmp_path / "runtime")
    manager = RepairManager(RepositoryInput(root), config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(target_index, 0),),
        allowed_paths=allowed_paths,
        generation=generation,
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
    )
    return config, session, provider_value


def _event_kinds(config: RepairManagerConfig, session_id: str) -> tuple[str, ...]:
    events = config.runtime_root / "sessions" / session_id / "events"
    return tuple(
        cast(str, json.loads(path.read_bytes())["kind"]) for path in sorted(events.iterdir())
    )


def _install_fake_sandbox(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure_kind: ValidationFailureKind | None = None,
    late_action: Callable[[], None] | None = None,
    before_register_action: Callable[[], None] | None = None,
    rejected_runs: list[sandbox_module._SandboxRunIdentity] | None = None,
    release_rejected_intent: bool = True,
    fail_after_intent: bool = False,
) -> None:
    assets = sandbox_module._load_sandbox_assets()
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

    def prepare(
        _config_value: RepairManagerConfig,
        _policy: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> sandbox_module._SandboxCapabilities:
        mount_identity_check()
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
        session_id = cast(str, arguments["session_id"])
        candidate_id = cast(str, arguments["candidate_id"])
        register_intent = cast(
            Callable[[sandbox_module._SandboxRunIntent], bool],
            arguments["register_intent"],
        )
        register_run = cast(
            Callable[[sandbox_module._SandboxRunIdentity], bool],
            arguments["register_run"],
        )
        release_intent = cast(
            Callable[[sandbox_module._SandboxRunIntent], bool],
            arguments["release_intent"],
        )
        release_run = cast(
            Callable[[sandbox_module._SandboxRunIdentity], bool],
            arguments["release_run"],
        )
        before_remove = cast(
            Callable[[sandbox_module._SandboxValidationOutcome], None],
            arguments["before_remove"],
        )
        mount_identity_check = cast(Callable[[], None], arguments["mount_identity_check"])
        mount_identity_check()
        run_token_sha256 = "d" * 64
        identity = sandbox_module._SandboxRunIdentity(
            container_id="c" * 64,
            container_name="repoguard-m5-proposal-test",
            labels=(
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", session_id),
                ("com.repoguard.candidate", candidate_id),
                ("com.repoguard.run-token-sha256", run_token_sha256),
            ),
            session_id=session_id,
            candidate_id=candidate_id,
            run_token_sha256=run_token_sha256,
        )
        intent = sandbox_module._SandboxRunIntent(
            container_name=identity.container_name,
            labels=identity.labels,
            session_id=identity.session_id,
            candidate_id=identity.candidate_id,
            run_token_sha256=identity.run_token_sha256,
        )
        assert register_intent(intent) is True
        if fail_after_intent:
            assert release_intent(intent) is True
            raise RepairError(RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX)
        if before_register_action is not None:
            before_register_action()
        if register_run(identity) is not True:
            if release_rejected_intent:
                assert release_run(identity) is True
            if rejected_runs is not None:
                rejected_runs.append(identity)
            raise sandbox_module._SandboxRunRejected
        success = failure_kind is None
        result = ValidationCommandResult(
            0,
            0 if success else 1,
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
            success=success,
            failure_kind=failure_kind,
            started_at_us=100,
            finished_at_us=200,
            command_results=(result,),
            peak_memory_bytes=4_096,
            oom_killed=False,
            residual_process_count=0,
            workspace_entry_count=2,
            workspace_inode_count=2,
            tracked_tree_clean=True,
        )
        checkpoint = sandbox_module._SandboxValidationOutcome(
            session_id,
            candidate_id,
            _domain_digest("policy", validation_policy_to_dict(policy)),
            capabilities.sandbox_manifest_sha256,
            capabilities.image_id,
            report,
            identity,
            True,
        )
        if late_action is not None:
            late_action()
        before_remove(checkpoint)
        return replace(checkpoint, cleanup_pending=False)

    monkeypatch.setattr(workflow_module, "_prepare_sandbox", prepare)
    monkeypatch.setattr(workflow_module, "_run_sandbox_validation", run)


def test_fake_sandbox_success_reaches_validated_in_fenced_event_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    _install_fake_sandbox(monkeypatch)

    snapshot = session.propose()

    assert snapshot.state is RepairState.VALIDATED
    assert snapshot.validation is not None
    assert snapshot.validation.success is True
    assert snapshot.failure is None
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "validation_run",
        "validation_result",
        "validated",
    )


def test_authenticated_validation_failure_returns_failed_and_cleans_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    _install_fake_sandbox(
        monkeypatch,
        failure_kind=ValidationFailureKind.COMMAND_EXIT_NONZERO,
    )

    snapshot = session.propose()

    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is False
    assert snapshot.validation is not None
    assert snapshot.validation.success is False
    assert snapshot.validation.failure_kind is ValidationFailureKind.COMMAND_EXIT_NONZERO
    assert snapshot.failure is not None
    assert snapshot.failure.code is RepairErrorCode.VALIDATION_FAILED
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "validation_run",
        "validation_result",
        "failed",
        "cleanup_complete",
    )


@pytest.mark.parametrize(
    ("boundary", "code", "stage"),
    [
        ("provider", RepairErrorCode.PROVIDER_UNAVAILABLE, RepairStage.PROVIDER),
        ("git", RepairErrorCode.GIT_FAILED, RepairStage.MATERIALIZATION),
        ("sandbox", RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX),
    ],
)
def test_infrastructure_error_persists_failed_before_reraising(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    code: RepairErrorCode,
    stage: RepairStage,
) -> None:
    config, session, provider = _proposal_session(
        tmp_path,
        monkeypatch,
        provider=boundary == "provider",
    )

    def fail(*_arguments: object, **_keywords: object) -> NoReturn:
        raise RepairError(code, stage)

    target = {
        "provider": "_invoke_repair_provider",
        "git": "_export_candidate_projection",
        "sandbox": "_prepare_sandbox",
    }[boundary]
    monkeypatch.setattr(workflow_module, target, fail)

    with pytest.raises(RepairError) as captured:
        session.propose(provider=provider)

    assert captured.value.code is code
    assert captured.value.stage is stage
    assert captured.value.state is RepairState.FAILED
    snapshot = session.snapshot()
    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is False
    assert snapshot.failure is not None
    assert snapshot.failure.code is code
    assert snapshot.failure.stage is stage
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    kinds = _event_kinds(config, snapshot.session_id)
    assert kinds[-2:] == ("failed", "cleanup_complete")
    assert "validation_result" not in kinds
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_pre_create_infrastructure_failure_releases_intent_before_failing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    _install_fake_sandbox(monkeypatch, fail_after_intent=True)

    with pytest.raises(RepairError) as captured:
        session.propose()

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    snapshot = session.snapshot()
    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is False
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    assert _event_kinds(config, snapshot.session_id)[-4:] == (
        "validation_intent",
        "validation_intent_abandoned",
        "failed",
        "cleanup_complete",
    )


@pytest.mark.parametrize(
    ("operation", "expected_state", "terminal_kind"),
    [
        ("cancel", RepairState.CANCELLED, "cancelled"),
        ("expire", RepairState.EXPIRED, "expired"),
    ],
)
def test_late_validation_result_is_discarded_after_terminal_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    expected_state: RepairState,
    terminal_kind: str,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    container_actions: list[tuple[str, sandbox_module._SandboxRunIdentity]] = []

    def stop_exact_container(
        config_value: RepairManagerConfig,
        identity: sandbox_module._SandboxRunIdentity,
    ) -> bool:
        assert config_value is config
        container_actions.append(("stop", identity))
        return True

    def remove_exact_container(
        config_value: RepairManagerConfig,
        identity: sandbox_module._SandboxRunIdentity,
    ) -> bool:
        assert config_value is config
        container_actions.append(("remove", identity))
        return True

    monkeypatch.setattr(workflow_module, "_stop_exact_container", stop_exact_container)
    monkeypatch.setattr(workflow_module, "_remove_exact_container", remove_exact_container)

    def terminate() -> None:
        if operation == "cancel":
            session.cancel(subject="local reviewer", reason="superseded")
        else:
            session.expire()

    _install_fake_sandbox(monkeypatch, late_action=terminate)

    snapshot = session.propose()

    assert snapshot.state is expected_state
    assert snapshot.cleanup_pending is False
    assert snapshot.validation is None
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    assert tuple(action for action, _ in container_actions) == ("stop", "remove")
    stop_identity = container_actions[0][1]
    assert stop_identity == container_actions[1][1]
    assert stop_identity.session_id == snapshot.session_id
    assert snapshot.candidate is not None
    assert stop_identity.candidate_id == snapshot.candidate.candidate_id
    with store_module._locked_session(config, snapshot.session_id) as storage:
        assert storage.load().validation_run is None
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "validation_run",
        terminal_kind,
        "cleanup_complete",
    )


@pytest.mark.parametrize(
    ("operation", "expected_state", "terminal_kind"),
    [
        ("cancel", RepairState.CANCELLED, "cancelled"),
        ("expire", RepairState.EXPIRED, "expired"),
    ],
)
def test_terminal_decision_before_validation_registration_is_convergent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    expected_state: RepairState,
    terminal_kind: str,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    rejected_runs: list[sandbox_module._SandboxRunIdentity] = []

    def terminate() -> None:
        if operation == "cancel":
            session.cancel(subject="local reviewer", reason="superseded")
        else:
            session.expire()

    _install_fake_sandbox(
        monkeypatch,
        before_register_action=terminate,
        rejected_runs=rejected_runs,
    )

    snapshot = session.propose()

    assert snapshot.state is expected_state
    assert snapshot.cleanup_pending is False
    assert snapshot.validation is None
    assert len(rejected_runs) == 1
    assert rejected_runs[0].session_id == snapshot.session_id
    assert snapshot.candidate is not None
    assert rejected_runs[0].candidate_id == snapshot.candidate.candidate_id
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    with store_module._locked_session(config, snapshot.session_id) as storage:
        assert storage.load().validation_run is None
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        terminal_kind,
        "validation_run",
        "cleanup_complete",
    )


def test_pre_bind_terminal_remove_failure_retains_bound_identity_and_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)

    def terminate() -> None:
        session.cancel(subject="local reviewer", reason="superseded")

    _install_fake_sandbox(
        monkeypatch,
        before_register_action=terminate,
        release_rejected_intent=False,
    )

    snapshot = session.propose()

    assert snapshot.state is RepairState.CANCELLED
    assert snapshot.cleanup_pending is True
    assert (config.runtime_root / "sessions" / snapshot.session_id / "private").is_dir()
    with store_module._locked_session(config, snapshot.session_id) as storage:
        loaded = storage.load()
    assert loaded.validation_run is not None
    assert loaded.validation_run.container_id == "c" * 64
    assert _event_kinds(config, snapshot.session_id)[-3:] == (
        "validation_intent",
        "cancelled",
        "validation_run",
    )


def test_recovery_failure_before_validation_registration_is_convergent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    recovery_reports: list[RepairMaintenanceReport] = []
    rejected_runs: list[sandbox_module._SandboxRunIdentity] = []

    def recover_before_registration() -> None:
        recovery_reports.append(session._manager.recover())

    _install_fake_sandbox(
        monkeypatch,
        before_register_action=recover_before_registration,
        rejected_runs=rejected_runs,
    )

    snapshot = session.propose()

    assert snapshot.state is RepairState.FAILED
    assert snapshot.cleanup_pending is False
    assert snapshot.failure is not None
    assert snapshot.failure.code is RepairErrorCode.RECOVERY_FAILED
    assert recovery_reports[0].recovered_session_ids == (snapshot.session_id,)
    assert recovery_reports[0].cleanup_pending_session_ids == (snapshot.session_id,)
    assert len(rejected_runs) == 1
    assert rejected_runs[0].container_id == "c" * 64
    assert not (config.runtime_root / "sessions" / snapshot.session_id / "private").exists()
    with store_module._locked_session(config, snapshot.session_id) as storage:
        assert storage.load().validation_run is None
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "failed",
        "validation_run",
        "cleanup_complete",
    )


@pytest.mark.parametrize(
    ("operation", "expected_state", "terminal_kind"),
    [
        ("cancel", RepairState.CANCELLED, "cancelled"),
        ("expire", RepairState.EXPIRED, "expired"),
    ],
)
def test_terminal_validation_container_cleanup_failure_retains_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    expected_state: RepairState,
    terminal_kind: str,
) -> None:
    config, session, _ = _proposal_session(tmp_path, monkeypatch)
    container_actions: list[tuple[str, sandbox_module._SandboxRunIdentity]] = []

    def fail_container_action(
        config_value: RepairManagerConfig,
        identity: sandbox_module._SandboxRunIdentity,
        *,
        action: str,
    ) -> bool:
        assert config_value is config
        container_actions.append((action, identity))
        return False

    monkeypatch.setattr(
        workflow_module,
        "_stop_exact_container",
        lambda config_value, identity: fail_container_action(
            config_value,
            identity,
            action="stop",
        ),
    )
    monkeypatch.setattr(
        workflow_module,
        "_remove_exact_container",
        lambda config_value, identity: fail_container_action(
            config_value,
            identity,
            action="remove",
        ),
    )

    def terminate() -> None:
        if operation == "cancel":
            session.cancel(subject="local reviewer", reason="superseded")
        else:
            session.expire()

    _install_fake_sandbox(monkeypatch, late_action=terminate)

    snapshot = session.propose()

    assert snapshot.state is expected_state
    assert snapshot.cleanup_pending is True
    assert snapshot.validation is None
    assert (config.runtime_root / "sessions" / snapshot.session_id / "private").is_dir()
    assert tuple(action for action, _ in container_actions) == ("stop", "remove")
    stop_identity = container_actions[0][1]
    assert stop_identity == container_actions[1][1]
    with store_module._locked_session(config, snapshot.session_id) as storage:
        loaded = storage.load()
    assert loaded.snapshot == snapshot
    assert loaded.validation_run is not None
    assert loaded.validation_run.container_id == stop_identity.container_id
    assert loaded.validation_run.run_token_sha256 == stop_identity.run_token_sha256
    assert _event_kinds(config, snapshot.session_id) == (
        "created",
        "generating",
        "candidate",
        "validating",
        "validation_intent",
        "validation_run",
        terminal_kind,
    )
