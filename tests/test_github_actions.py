"""Static and local contract tests for the three M6 composite Actions."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import re
import stat
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

import repoguard.github_transport as github_transport

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW_ACTION = _ROOT / "action.yml"
_REPAIR_ACTION = _ROOT / "actions" / "repair" / "action.yml"
_PUBLISH_ACTION = _ROOT / "actions" / "publish" / "action.yml"
_DRIVER_PATH = _ROOT / "scripts" / "m6_action.py"
_WORKFLOW_ROOT = _ROOT / ".github" / "workflows"
_UPLOAD_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
_DOWNLOAD_SHA = "d3f86a106a0bac45b974a628896c90dbdf5c8093"
_BASE_SHA = "1" * 40
_HEAD_SHA = "2" * 40
_EVIDENCE_SHA256 = "3" * 64
_DETERMINISTIC_SHA256 = "4" * 64
_REVIEW_SHA256 = "5" * 64
_CHECK_CONFIRMATION = "I approve publishing this exact RepoGuard review as a GitHub Check Run."
_PUBLISHER_LABELS = ["Linux", "X64", "repoguard-publisher", "self-hosted"]


@pytest.fixture(scope="module")
def driver() -> Any:
    spec = importlib.util.spec_from_file_location("repoguard_m6_action", _DRIVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _action(path: Path) -> dict[str, Any]:
    decoded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert type(decoded) is dict
    return cast(dict[str, Any], decoded)


def _steps(action: dict[str, Any]) -> list[dict[str, Any]]:
    runs = action["runs"]
    assert type(runs) is dict and runs["using"] == "composite"
    steps = runs["steps"]
    assert type(steps) is list
    return cast(list[dict[str, Any]], steps)


def _step(action: dict[str, Any], step_id: str) -> dict[str, Any]:
    matches = [step for step in _steps(action) if step.get("id") == step_id]
    assert len(matches) == 1
    return matches[0]


def test_action_input_output_contracts_are_exact() -> None:
    review = _action(_REVIEW_ACTION)
    repair = _action(_REPAIR_ACTION)
    publish = _action(_PUBLISH_ACTION)

    assert set(review["inputs"]) == {
        "repository-path",
        "pr-number",
        "base-sha",
        "head-sha",
        "mode",
        "provider",
        "model",
        "cache-dir",
        "device",
        "fail-on",
    }
    assert set(review["outputs"]) == {
        "result-path",
        "result-sha256",
        "evidence-path",
        "evidence-sha256",
        "review-path",
        "review-sha256",
        "proposal-path",
        "proposal-sha256",
        "artifact-id",
        "artifact-digest",
        "finding-count",
        "highest-severity",
        "conclusion",
    }
    assert review["inputs"]["repository-path"]["default"] == "."
    assert review["inputs"]["mode"]["default"] == "deterministic"
    assert review["inputs"]["provider"]["default"] == "none"
    assert review["inputs"]["model"]["default"] == ""
    assert review["inputs"]["cache-dir"]["default"] == ""
    assert review["inputs"]["device"]["default"] == "cpu"
    assert review["inputs"]["fail-on"]["default"] == "high"

    assert set(repair["inputs"]) == {
        "pr-number",
        "base-sha",
        "head-sha",
        "repair-profile",
        "target-ids",
        "allowed-paths",
    }
    assert set(repair["outputs"]) == {
        "proposal-path",
        "proposal-sha256",
        "artifact-id",
        "artifact-digest",
        "candidate-id",
        "validation-sha256",
        "commit-oid",
        "state",
    }
    assert set(publish["inputs"]) == {
        "kind",
        "proposal-sha256",
        "source-run-id",
        "source-run-attempt",
        "artifact-id",
        "artifact-digest",
        "confirmation",
    }
    assert set(publish["outputs"]) == {
        "approval-sha256",
        "result-sha256",
        "state",
    }


def test_external_actions_are_full_sha_pinned_and_minimal() -> None:
    observed: list[str] = []
    for path in (_REVIEW_ACTION, _REPAIR_ACTION, _PUBLISH_ACTION):
        for step in _steps(_action(path)):
            uses = step.get("uses")
            if uses is None:
                continue
            assert type(uses) is str
            assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", uses)
            observed.append(uses)

    assert observed.count(f"actions/upload-artifact@{_UPLOAD_SHA}") == 2
    assert observed.count(f"actions/download-artifact@{_DOWNLOAD_SHA}") == 1
    assert len(observed) == 3


def test_repository_workflows_pin_actions_and_never_execute_pr_controlled_ci() -> None:
    workflow_paths = sorted(
        (*_WORKFLOW_ROOT.glob("*.yml"), *_WORKFLOW_ROOT.glob("*.yaml")),
        key=lambda path: path.name,
    )
    assert workflow_paths
    for path in workflow_paths:
        raw = path.read_text(encoding="utf-8")
        assert "pull_request_target" not in raw
        decoded = _action(path)
        jobs = decoded.get("jobs")
        assert type(jobs) is dict
        for job in jobs.values():
            assert type(job) is dict
            steps = job.get("steps", ())
            assert type(steps) is list
            for step in steps:
                assert type(step) is dict
                uses = step.get("uses")
                if uses is not None:
                    assert type(uses) is str
                    assert re.fullmatch(
                        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}",
                        uses,
                    )
                    if uses.startswith("actions/checkout@"):
                        configuration = step.get("with")
                        assert type(configuration) is dict
                        assert configuration.get("persist-credentials") is False
                run = step.get("run")
                if run is not None:
                    assert type(run) is str
                    assert "${{ github.event.pull_request" not in run

    ci_raw = (_WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    assert "\n  pull_request:" not in ci_raw


def test_shell_never_interpolates_github_expressions_or_pr_text() -> None:
    forbidden = (
        "pull_request_target",
        "github.event.pull_request.body",
        "github.event.pull_request.title",
        "github.event.pull_request.head.ref",
        "secrets.",
        "sudo ",
        "--privileged",
        "/var/run/docker.sock",
        "actions/cache",
        "pip install",
        "git checkout",
        "git fetch",
    )
    for path in (_REVIEW_ACTION, _REPAIR_ACTION, _PUBLISH_ACTION):
        raw = path.read_text(encoding="utf-8")
        for value in forbidden:
            assert value not in raw
        for step in _steps(_action(path)):
            run = step.get("run")
            if run is None:
                continue
            assert type(run) is str
            assert "${{" not in run
            assert "github." not in run
            assert "inputs." not in run
            assert re.search(r"(^|[;&|]\s*)eval(?:\s|$)", run) is None
            assert "m6_action.py" in run or '"$REPOGUARD_ACTION_DRIVER"' in run
            assert step["shell"] == "bash"


def test_proposal_upload_is_single_file_one_day_and_ids_are_not_faked() -> None:
    for action_path in (_REVIEW_ACTION, _REPAIR_ACTION):
        action = _action(action_path)
        upload = _step(action, "upload")
        configuration = upload["with"]
        assert configuration == {
            "name": "repoguard-proposal-v1-${{ steps.prepare.outputs.proposal-sha256 }}",
            "path": "${{ steps.prepare.outputs.proposal-path }}",
            "if-no-files-found": "error",
            "retention-days": "1",
            "compression-level": "0",
            "overwrite": "false",
            "include-hidden-files": "false",
        }
        assert (
            action["outputs"]["artifact-id"]["value"] == "${{ steps.upload.outputs.artifact-id }}"
        )
        assert (
            action["outputs"]["artifact-digest"]["value"]
            == "${{ steps.upload.outputs.artifact-digest }}"
        )
        prepare_environment = _step(action, "prepare")["env"]
        assert "REPOGUARD_ARTIFACT_ID" not in prepare_environment
        assert "REPOGUARD_ARTIFACT_DIGEST" not in prepare_environment
    assert (
        _step(_action(_REVIEW_ACTION), "upload")["if"]
        == "${{ steps.prepare.outputs.github-write-supported == 'true' }}"
    )
    assert "if" not in _step(_action(_REPAIR_ACTION), "upload")


def test_publish_readback_precedes_exact_artifact_download() -> None:
    publish = _action(_PUBLISH_ACTION)
    steps = _steps(publish)
    assert [step.get("id") for step in steps] == ["runner", "preflight", "download", "publish"]
    download = _step(publish, "download")
    assert download["with"] == {
        "artifact-ids": "${{ inputs.artifact-id }}",
        "path": "${{ steps.preflight.outputs.download-path }}",
        "merge-multiple": "true",
        "github-token": "${{ env.REPOGUARD_GITHUB_TOKEN }}",
        "repository": "${{ github.repository }}",
        "run-id": "${{ inputs.source-run-id }}",
    }
    preflight_source = inspect.getsource(
        cast(Any, driver_placeholder())._publish_preflight  # pragma: no cover
    )
    assert preflight_source.index("_verify_artifact_metadata") < preflight_source.index(
        "_new_private_directory"
    )


def driver_placeholder() -> ModuleType:
    """Load the fixed driver for one source-order assertion."""
    spec = importlib.util.spec_from_file_location("repoguard_m6_action_source", _DRIVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_self_hosted_actions_authenticate_fixed_python_and_runner_labels() -> None:
    for path in (_REPAIR_ACTION, _PUBLISH_ACTION):
        action = _action(path)
        runner = _step(action, "runner")
        assert runner["run"].startswith("exec /usr/bin/python3 -I ")
        assert '"${GITHUB_ACTION_PATH}/../../scripts/m6_action.py"' in runner["run"]
        assert "REPOGUARD_ACTION_SOURCE_ROOT" not in runner["run"]
        assert runner["env"]["REPOGUARD_PYTHON"] == "${{ env.REPOGUARD_PYTHON }}"
        assert (
            runner["env"]["REPOGUARD_ACTION_SOURCE_ROOT"]
            == "${{ env.REPOGUARD_ACTION_SOURCE_ROOT }}"
        )
        assert runner["env"]["REPOGUARD_RUNNER_LABELS"] == "${{ env.REPOGUARD_RUNNER_LABELS }}"
        for step in _steps(action):
            if step.get("id") not in {"prepare", "preflight", "publish"}:
                continue
            run = step["run"]
            assert run.startswith('exec "$REPOGUARD_PYTHON" -I ')
            assert run.split()[-2] == '"$REPOGUARD_ACTION_DRIVER"'
            assert "GITHUB_ACTION_PATH" not in run
            assert step["env"]["REPOGUARD_PYTHON"] == "${{ steps.runner.outputs.python-path }}"
            assert (
                step["env"]["REPOGUARD_ACTION_DRIVER"] == "${{ steps.runner.outputs.driver-path }}"
            )
            assert (
                step["env"]["REPOGUARD_ACTION_SOURCE_ROOT"]
                == "${{ env.REPOGUARD_ACTION_SOURCE_ROOT }}"
            )
            assert step["env"]["REPOGUARD_RUNNER_LABELS"] == "${{ env.REPOGUARD_RUNNER_LABELS }}"


def test_driver_uses_only_isolated_public_cli_and_public_transport() -> None:
    raw = _DRIVER_PATH.read_text(encoding="utf-8")
    assert "repoguard._repair_" not in raw
    assert "_github_store" not in raw
    assert "shell=True" not in raw
    assert "os.system" not in raw
    assert "subprocess.run" not in raw
    assert '(sys.executable, "-I", "-m", "repoguard", *arguments)' in raw
    assert "from repoguard.github_transport import GitHubMethod, GitHubTransport" in raw


@pytest.mark.parametrize(
    "raw",
    (
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b' {"a":1}',
        b'{"a":1}\n',
        b"\xef\xbb\xbf{}",
    ),
)
def test_driver_rejects_noncanonical_json(driver: Any, raw: bytes) -> None:
    with pytest.raises(driver._ActionFailure):
        driver._parse_canonical(raw, maximum=64)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("action_repository", "other/repoguard"),
        ("action_ref", "b" * 40),
    ),
)
def test_driver_binds_action_repository_and_sha_to_profile(
    driver: Any,
    field: str,
    value: str,
) -> None:
    context = {
        "action_repository": "owner/repoguard",
        "action_ref": "a" * 40,
    }
    context[field] = value
    profile = {
        "github_actions": {
            "action_repository": "owner/repoguard",
            "action_sha": "a" * 40,
            "publisher": None,
        }
    }

    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_action_source(context, profile)

    assert raised.value.code == "untrusted_action_source"
    assert raised.value.status == 5


def test_canonical_arrays_are_sorted_unique_and_bounded(driver: Any) -> None:
    assert driver._canonical_string_array(
        '["a","b"]',
        minimum=1,
        maximum=2,
        item_validator=lambda value: value,
    ) == ("a", "b")
    for raw in ('["b","a"]', '["a","a"]', '["a", "b"]', "[]"):
        with pytest.raises(driver._ActionFailure):
            driver._canonical_string_array(
                raw,
                minimum=1,
                maximum=2,
                item_validator=lambda value: value,
            )


def test_publication_input_gate_binds_actor_attempt_and_exact_confirmation(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "REPOGUARD_KIND": "check",
        "REPOGUARD_PROPOSAL_SHA256": "a" * 64,
        "REPOGUARD_SOURCE_RUN_ID": "41",
        "REPOGUARD_SOURCE_RUN_ATTEMPT": "1",
        "REPOGUARD_ARTIFACT_ID": "51",
        "REPOGUARD_ARTIFACT_DIGEST": "b" * 64,
        "REPOGUARD_CONFIRMATION": _CHECK_CONFIRMATION,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    context = {
        "run_attempt": 1,
        "run_id": 99,
        "actor": "maintainer",
        "triggering_actor": "maintainer",
    }
    result = driver._publication_inputs(context)
    assert result["source_run_id"] == 41
    assert result["source_run_attempt"] == 1
    assert result["artifact_id"] == 51

    monkeypatch.setenv("REPOGUARD_CONFIRMATION", f"{_CHECK_CONFIRMATION} ")
    with pytest.raises(driver._ActionFailure) as raised:
        driver._publication_inputs(context)
    assert raised.value.status == 5

    monkeypatch.setenv("REPOGUARD_CONFIRMATION", _CHECK_CONFIRMATION)
    with pytest.raises(driver._ActionFailure) as raised:
        driver._publication_inputs({**context, "triggering_actor": "rerunner"})
    assert raised.value.status == 5
    monkeypatch.setenv("REPOGUARD_SOURCE_RUN_ATTEMPT", "2")
    with pytest.raises(driver._ActionFailure) as raised:
        driver._publication_inputs(context)
    assert raised.value.status == 5


def test_publisher_python_capability_is_owner_only_regular_and_external(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    python_path = trusted / "python3"
    python_path.write_bytes(b"fixed frozen python")
    python_path.chmod(0o500)
    monkeypatch.setenv("REPOGUARD_PYTHON", str(python_path))
    monkeypatch.setattr(driver, "_validate_owner_only_parents", lambda _path: None)

    assert driver._publisher_python_path(workspace, expected=python_path) == python_path

    python_path.chmod(0o520)
    with pytest.raises(driver._ActionFailure):
        driver._publisher_python_path(workspace, expected=python_path)
    python_path.chmod(0o500)
    link = trusted / "python-link"
    link.symlink_to(python_path)
    monkeypatch.setenv("REPOGUARD_PYTHON", str(link))
    with pytest.raises(driver._ActionFailure):
        driver._publisher_python_path(workspace, expected=python_path)


@pytest.mark.parametrize("mutation", ("writable", "hardlink", "symlink", "special"))
def test_publisher_package_tree_is_protected_before_product_import(
    driver: Any,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = tmp_path / "package"
    package.mkdir(mode=0o700)
    package.chmod(0o700)
    module = package / "product.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    module.chmod(0o600)
    if mutation == "writable":
        module.chmod(0o666)
    elif mutation == "hardlink":
        (tmp_path / "hardlink.py").hardlink_to(module)
    elif mutation == "symlink":
        (package / "linked.py").symlink_to(module)
    else:
        os.mkfifo(package / "pipe", mode=0o600)

    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_package_tree(package)

    assert raised.value.code == "invalid_runner"
    assert raised.value.status == 8


def test_bootstrap_driver_must_byte_match_fixed_local_driver(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    action_path = bundle / "actions" / "repair"
    action_path.mkdir(mode=0o700, parents=True)
    bundle_scripts = bundle / "scripts"
    bundle_scripts.mkdir(mode=0o700)
    pinned = bundle_scripts / "m6_action.py"
    pinned.write_bytes(_DRIVER_PATH.read_bytes())
    pinned.chmod(0o600)
    source = tmp_path / "source"
    source_scripts = source / "scripts"
    source_scripts.mkdir(mode=0o700, parents=True)
    source.chmod(0o700)
    source_scripts.chmod(0o700)
    local = source_scripts / "m6_action.py"
    local.write_bytes(pinned.read_bytes())
    local.chmod(0o600)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    monkeypatch.setenv("GITHUB_ACTION_PATH", str(action_path))
    monkeypatch.setenv("REPOGUARD_ACTION_SOURCE_ROOT", str(source))
    monkeypatch.setattr(driver, "__file__", str(pinned))

    assert (
        driver._publisher_driver_path(
            workspace,
            source_root=source,
            bootstrap=True,
        )
        == local
    )

    local.write_bytes(b"# changed\n")
    local.chmod(0o600)
    with pytest.raises(driver._ActionFailure) as raised:
        driver._publisher_driver_path(
            workspace,
            source_root=source,
            bootstrap=True,
        )
    assert raised.value.code == "invalid_runner"


def test_publisher_runner_requires_exact_labels_os_arch_and_first_attempt(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("RUNNER_ARCH", "X64")
    monkeypatch.setenv(
        "REPOGUARD_RUNNER_LABELS",
        '["Linux","X64","repoguard-publisher","self-hosted"]',
    )
    frozen_python = tmp_path / "python3"
    fixed_driver = tmp_path / "m6_action.py"
    runtime = {
        "python_executable": frozen_python,
        "runtime_root": tmp_path / "runtime",
        "package_root": tmp_path / "runtime" / "package",
        "source_root": tmp_path / "source",
    }
    monkeypatch.setattr(driver, "_publisher_runtime_profile", lambda _profile: runtime)
    monkeypatch.setattr(
        driver,
        "_publisher_python_path",
        lambda _workspace, *, expected: expected,
    )
    monkeypatch.setattr(
        driver,
        "_publisher_driver_path",
        lambda _workspace, *, source_root, bootstrap: fixed_driver,
    )
    profile = {"runner_labels": list(_PUBLISHER_LABELS)}
    context = {"run_attempt": 1, "workspace": tmp_path}

    assert driver._validate_publisher_runner(
        profile,
        context,
        require_current_python=False,
    ) == (frozen_python, fixed_driver)

    monkeypatch.setenv(
        "REPOGUARD_RUNNER_LABELS",
        '["Linux","X64","self-hosted"]',
    )
    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_publisher_runner(
            profile,
            context,
            require_current_python=False,
        )
    assert raised.value.status == 8
    monkeypatch.setenv(
        "REPOGUARD_RUNNER_LABELS",
        '["Linux","X64","repoguard-publisher","self-hosted"]',
    )
    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_publisher_runner(
            profile,
            {**context, "run_attempt": 2},
            require_current_python=False,
        )
    assert raised.value.status == 8


def test_action_profile_reader_rejects_torn_same_inode(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile_path = tmp_path / "profile.json"
    profile: dict[str, object] = {key: None for key in driver._PROFILE_KEYS}
    profile["schema_version"] = 1
    _write_canonical(driver, profile_path, profile)
    raw = profile_path.read_bytes()
    original_read = os.read
    mutated = False

    def rewrite_while_reading(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if not mutated:
            mutated = True
            profile_path.write_bytes(raw)
            profile_path.chmod(0o600)
        return chunk

    monkeypatch.setattr(os, "read", rewrite_while_reading)

    with pytest.raises(driver._ActionFailure) as raised:
        driver._load_profile(profile_path)

    assert raised.value.code == "invalid_profile"


def test_runner_preflight_requires_github_actions_context(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    with pytest.raises(driver._ActionFailure) as raised:
        driver._runner_preflight()

    assert raised.value.code == "invalid_context"
    assert raised.value.status == 5


def test_authenticated_profile_summary_must_repeat_exact_runner_labels(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[tuple[str, ...]] = []

    def fake_cli(
        arguments: tuple[str, ...],
        *,
        expected_operation: str,
    ) -> tuple[dict[str, object], int]:
        observed.append(arguments)
        assert expected_operation == "profile.validate"
        return {
            "schema_version": 1,
            "operation": "profile.validate",
            "ok": True,
            "result": {"runner_labels": list(_PUBLISHER_LABELS)},
            "error": None,
        }, 0

    monkeypatch.setattr(driver, "_run_cli", fake_cli)
    context = {
        "profile_path": tmp_path / "profile.json",
        "repository_alias": "example",
    }

    driver._validate_profile_summary(context)

    assert observed == [
        (
            "--profile",
            str(tmp_path / "profile.json"),
            "--repository",
            "example",
            "profile",
            "validate",
        )
    ]


def test_cli_environment_keeps_only_named_repoguard_credentials(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REPOGUARD_OPENAI_API_KEY", "allowed")
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "allowed-github")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient")
    monkeypatch.setenv("GITHUB_TOKEN", "ambient-github")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "ambient-runtime")
    monkeypatch.setenv("SOME_API_KEY", "ambient-other")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
    monkeypatch.setenv("DATABASE_PASSWORD", "ambient-password")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")

    environment = driver._cli_environment()

    assert environment["REPOGUARD_OPENAI_API_KEY"] == "allowed"
    assert environment["REPOGUARD_GITHUB_TOKEN"] == "allowed-github"
    for name in (
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "SOME_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_PASSWORD",
        "PYTHONPATH",
    ):
        assert name not in environment
    assert environment == {
        "GITHUB_ACTIONS": "true",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "REPOGUARD_OPENAI_API_KEY": "allowed",
        "REPOGUARD_GITHUB_TOKEN": "allowed-github",
    }


def _proposal(
    driver: Any,
    *,
    kind: str = "check",
    payload: dict[str, Any] | None = None,
    profile_name: str = "deterministic",
) -> tuple[dict[str, Any], str]:
    identity = {
        "schema_version": 1,
        "kind": kind,
        "repository_id": 123,
        "repository_full_name": "owner/repository",
        "pull_request_number": 7,
        "base_ref": _BASE_SHA,
        "base_oid": _BASE_SHA,
        "head_oid": _HEAD_SHA,
        "origin": "action",
        "profile_name": profile_name,
        "created_at_us": 1_000_000,
        "expires_at_us": 86_401_000_000,
        "payload": {} if payload is None else payload,
    }
    digest = hashlib.sha256(
        b"repoguard.m6.github_proposal.v1\0" + driver._canonical_bytes(identity)
    ).hexdigest()
    return {"proposal_sha256": digest, **identity}, digest


def _proposal_context(tmp_path: Path) -> dict[str, Any]:
    return {
        "repository_id": 123,
        "repository_full_name": "owner/repository",
        "profile_path": tmp_path / "profile.json",
    }


def test_proposal_digest_cas_and_private_key_rejection(
    driver: Any,
    tmp_path: Path,
) -> None:
    proposal, digest = _proposal(driver)
    assert (
        driver._validate_proposal(
            proposal,
            expected_sha256=digest,
            kind="check",
            context=_proposal_context(tmp_path),
            pr_number=7,
            base_sha=_BASE_SHA,
            head_sha=_HEAD_SHA,
            profile_name="deterministic",
        )
        == proposal
    )

    changed = dict(proposal)
    changed["head_oid"] = "9" * 40
    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_proposal(
            changed,
            expected_sha256=digest,
            kind="check",
            context=_proposal_context(tmp_path),
            pr_number=7,
            base_sha=_BASE_SHA,
            head_sha=_HEAD_SHA,
            profile_name="deterministic",
        )
    assert raised.value.status == 7

    private, private_digest = _proposal(driver, payload={"session_id": "s" * 64})
    with pytest.raises(driver._ActionFailure) as raised:
        driver._validate_proposal(
            private,
            expected_sha256=private_digest,
            kind="check",
            context=_proposal_context(tmp_path),
            pr_number=7,
            base_sha=_BASE_SHA,
            head_sha=_HEAD_SHA,
            profile_name="deterministic",
        )
    assert raised.value.code == "private_artifact_data"


def test_downloaded_artifact_is_exactly_one_regular_canonical_proposal(
    driver: Any,
    tmp_path: Path,
) -> None:
    proposal, digest = _proposal(driver)
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    proposal_path = artifact / "proposal.json"
    proposal_path.write_bytes(driver._canonical_bytes(proposal))

    loaded = driver._load_downloaded_proposal(
        artifact,
        proposal_sha256=digest,
        kind="check",
        context=_proposal_context(tmp_path),
    )
    assert loaded == proposal

    (artifact / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(driver._ActionFailure):
        driver._load_downloaded_proposal(
            artifact,
            proposal_sha256=digest,
            kind="check",
            context=_proposal_context(tmp_path),
        )


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_downloaded_proposal_rejects_links(
    driver: Any,
    tmp_path: Path,
    link_kind: str,
) -> None:
    proposal, digest = _proposal(driver)
    source = tmp_path / "source.json"
    source.write_bytes(driver._canonical_bytes(proposal))
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    target = artifact / "proposal.json"
    if link_kind == "symlink":
        target.symlink_to(source)
    else:
        target.hardlink_to(source)

    with pytest.raises(driver._ActionFailure):
        driver._load_downloaded_proposal(
            artifact,
            proposal_sha256=digest,
            kind="check",
            context=_proposal_context(tmp_path),
        )


def test_check_import_file_is_hardened_and_rejects_hardlinks(
    driver: Any,
    tmp_path: Path,
) -> None:
    proposal, _digest = _proposal(driver)
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_bytes(driver._canonical_bytes(proposal))
    proposal_path.chmod(0o644)

    driver._harden_check_proposal_file(proposal_path)

    assert stat.S_IMODE(proposal_path.stat().st_mode) == 0o600
    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(proposal_path)
    with pytest.raises(driver._ActionFailure) as raised:
        driver._harden_check_proposal_file(proposal_path)
    assert raised.value.code == "invalid_artifact"


def test_step_summary_escapes_markup_and_disables_mentions(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    summary_path = tmp_path / "summary"
    summary_path.touch(mode=0o600)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setenv("REPOGUARD_HOST_PROFILE", str(tmp_path / "profile.json"))
    result = {
        "conclusion": "success",
        "finding_count": 1,
        "highest_severity": "high",
        "findings": [
            {
                "severity": "high",
                "title": "<unsafe> @reviewers",
                "message": "Do not ping @maintainer & keep <tags> literal.",
            }
        ],
    }

    driver._write_step_summary(result, github_write_supported=False)

    raw = summary_path.read_text(encoding="utf-8")
    assert "<unsafe>" not in raw
    assert "&lt;unsafe&gt;" in raw
    assert "@reviewers" not in raw
    assert "@&#8203;reviewers" in raw
    assert "@maintainer" not in raw
    assert "read-only fork; no proposal created" in raw


def test_artifact_metadata_readback_binds_digest_source_run_and_attempt(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    class FakeTransport:
        def __init__(self, token: str) -> None:
            assert token == "explicit-token"

        def request(self, method: object, target: str) -> SimpleNamespace:
            assert method is github_transport.GitHubMethod.GET
            observed.append(target)
            if "/artifacts/" in target:
                return SimpleNamespace(
                    status=200,
                    body={
                        "id": 51,
                        "name": f"repoguard-proposal-v1-{'a' * 64}",
                        "expired": False,
                        "digest": f"sha256:{'b' * 64}",
                        "size_in_bytes": 1_024,
                        "workflow_run": {"id": 41, "repository_id": 123},
                    },
                )
            return SimpleNamespace(
                status=200,
                body={
                    "id": 41,
                    "run_attempt": 1,
                    "status": "completed",
                    "conclusion": "failure",
                    "event": "pull_request",
                    "repository": {"id": 123, "full_name": "owner/repository"},
                },
            )

    monkeypatch.setattr(github_transport, "GitHubTransport", FakeTransport)
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "explicit-token")
    publication = {
        "kind": "check",
        "proposal_sha256": "a" * 64,
        "source_run_id": 41,
        "source_run_attempt": 1,
        "artifact_id": 51,
        "artifact_digest": "b" * 64,
    }
    context = {
        "repository_id": 123,
        "repository_full_name": "owner/repository",
    }

    driver._verify_artifact_metadata(context, publication)

    assert observed == [
        "/repos/owner/repository/actions/artifacts/51",
        "/repos/owner/repository/actions/runs/41",
    ]
    publication["artifact_digest"] = "c" * 64
    with pytest.raises(driver._ActionFailure) as raised:
        driver._verify_artifact_metadata(context, publication)
    assert raised.value.status == 7


def test_artifact_metadata_rejects_a_source_run_that_was_rerun(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeTransport:
        def __init__(self, token: str) -> None:
            assert token == "explicit-token"

        def request(self, method: object, target: str) -> SimpleNamespace:
            assert method is github_transport.GitHubMethod.GET
            if "/artifacts/" in target:
                return SimpleNamespace(
                    status=200,
                    body={
                        "id": 51,
                        "name": f"repoguard-proposal-v1-{'a' * 64}",
                        "expired": False,
                        "digest": f"sha256:{'b' * 64}",
                        "size_in_bytes": 1_024,
                        "workflow_run": {"id": 41, "repository_id": 123},
                    },
                )
            return SimpleNamespace(
                status=200,
                body={
                    "id": 41,
                    "run_attempt": 2,
                    "status": "completed",
                    "conclusion": "success",
                    "event": "pull_request",
                    "repository": {"id": 123, "full_name": "owner/repository"},
                },
            )

    monkeypatch.setattr(github_transport, "GitHubTransport", FakeTransport)
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "explicit-token")

    with pytest.raises(driver._ActionFailure) as raised:
        driver._verify_artifact_metadata(
            {
                "repository_id": 123,
                "repository_full_name": "owner/repository",
            },
            {
                "kind": "check",
                "proposal_sha256": "a" * 64,
                "source_run_id": 41,
                "source_run_attempt": 1,
                "artifact_id": 51,
                "artifact_digest": "b" * 64,
            },
        )

    assert raised.value.code == "source_run_mismatch"
    assert raised.value.status == 7


@pytest.mark.parametrize(
    ("provider", "openai", "anthropic", "github", "accepted"),
    (
        ("none", "", "", "github-token", True),
        ("none", "", "", "", False),
        ("none", "unexpected", "", "github-token", False),
        ("openai", "openai-token", "", "github-token", True),
        ("openai", "", "", "github-token", False),
        ("anthropic", "", "anthropic-token", "github-token", True),
        ("anthropic", "unexpected", "anthropic-token", "github-token", False),
    ),
)
def test_review_and_repair_require_github_token_and_only_selected_provider_secret(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    openai: str,
    anthropic: str,
    github: str,
    accepted: bool,
) -> None:
    monkeypatch.setenv("REPOGUARD_OPENAI_API_KEY", openai)
    monkeypatch.setenv("REPOGUARD_ANTHROPIC_API_KEY", anthropic)
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", github)

    if accepted:
        driver._validate_review_secrets(provider)
    else:
        with pytest.raises(driver._ActionFailure) as raised:
            driver._validate_review_secrets(provider)
        assert raised.value.status == 5


def _write_canonical(driver: Any, path: Path, value: object) -> None:
    path.write_bytes(driver._canonical_bytes(value))
    path.chmod(0o600)


@pytest.mark.parametrize("same_repository", (True, False))
def test_review_driver_materializes_path_free_records_and_fork_is_read_only(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    same_repository: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "number": 7,
                "pull_request": {
                    "base": {
                        "sha": _BASE_SHA,
                        "repo": {"id": 123, "full_name": "owner/repository"},
                    },
                    "head": {
                        "sha": _HEAD_SHA,
                        "repo": (
                            {"id": 123, "full_name": "owner/repository"}
                            if same_repository
                            else {"id": 456, "full_name": "contributor/fork"}
                        ),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    profile_path = tmp_path / "profile.json"
    profile = {
        "schema_version": 1,
        "repositories": [
            {
                "alias": "example",
                "path": str(workspace),
                "github_repository_id": 123,
                "github_full_name": "owner/repository",
            }
        ],
        "git_executable": "/usr/bin/git",
        "docker_executable": "/usr/bin/docker",
        "rootless_socket": "/run/user/1000/docker.sock",
        "product_state_root": str(tmp_path / "product-state"),
        "repair_state_root": str(tmp_path / "repair-state"),
        "runner_labels": [],
        "m4_caches": [],
        "review_profiles": [
            {
                "name": "deterministic",
                "mode": "deterministic",
                "provider": "none",
                "model": None,
                "cache": None,
                "device": "cpu",
                "fail_on": "high",
            }
        ],
        "repair_profiles": [],
        "github_actions": {
            "action_repository": "actions/repoguard",
            "action_sha": "a" * 40,
            "publisher": None,
        },
        "mcp": {"publish_check": False, "publish_repair": False},
    }
    _write_canonical(driver, profile_path, profile)
    github_output = tmp_path / "github-output"
    github_output.touch(mode=0o600)
    github_summary = tmp_path / "github-summary"
    github_summary.touch(mode=0o600)
    product = {
        "schema_version": 1,
        "repository_alias": "example",
        "object_format": "sha1",
        "base_ref": _BASE_SHA,
        "head_ref": _HEAD_SHA,
        "base_oid": _BASE_SHA,
        "head_oid": _HEAD_SHA,
        "merge_base_oid": _BASE_SHA,
        "review_profile": "deterministic",
        "provider": None,
        "model": None,
        "evidence_sha256": _EVIDENCE_SHA256,
        "deterministic_review_sha256": _DETERMINISTIC_SHA256,
        "review_sha256": _REVIEW_SHA256,
        "findings": [],
        "finding_count": 0,
        "highest_severity": None,
        "conclusion": "success",
    }
    proposal, proposal_sha256 = _proposal(driver, payload={"review_result": product})
    result: dict[str, Any] = {
        **product,
        "policy_passed": True,
        "github_pr": 7,
        "github_write_supported": same_repository,
    }
    if same_repository:
        result.update({"proposal": proposal, "proposal_sha256": proposal_sha256})
    observed_arguments: list[tuple[str, ...]] = []

    def fake_cli(
        arguments: tuple[str, ...],
        *,
        expected_operation: str,
    ) -> tuple[dict[str, object], int]:
        observed_arguments.append(arguments)
        assert expected_operation == "review.run"
        return {
            "schema_version": 1,
            "operation": "review.run",
            "ok": True,
            "result": result,
            "error": None,
        }, 0

    monkeypatch.setattr(driver, "_run_cli", fake_cli)
    environment = {
        "GITHUB_ACTIONS": "true",
        "REPOGUARD_ACTION_REF": "a" * 40,
        "REPOGUARD_ACTION_REPOSITORY": "actions/repoguard",
        "REPOGUARD_ACTOR": "maintainer",
        "REPOGUARD_BASE_SHA": _BASE_SHA,
        "REPOGUARD_CACHE_DIR": "",
        "REPOGUARD_DEFAULT_BRANCH": "main",
        "REPOGUARD_DEVICE": "cpu",
        "REPOGUARD_EVENT_NAME": "pull_request",
        "REPOGUARD_EVENT_PATH": str(event_path),
        "REPOGUARD_FAIL_ON": "high",
        "REPOGUARD_HEAD_SHA": _HEAD_SHA,
        "REPOGUARD_HOST_PROFILE": str(profile_path),
        "REPOGUARD_MODE": "deterministic",
        "REPOGUARD_MODEL": "",
        "REPOGUARD_OPENAI_API_KEY": "",
        "REPOGUARD_ANTHROPIC_API_KEY": "",
        "REPOGUARD_GITHUB_TOKEN": "read-only-github-token",
        "REPOGUARD_PR_NUMBER": "7",
        "REPOGUARD_PROVIDER": "none",
        "REPOGUARD_REF": "refs/pull/7/merge",
        "REPOGUARD_REPOSITORY_ALIAS": "example",
        "REPOGUARD_REPOSITORY_FULL_NAME": "owner/repository",
        "REPOGUARD_REPOSITORY_ID": "123",
        "REPOGUARD_REPOSITORY_PATH": ".",
        "REPOGUARD_RUN_ATTEMPT": "1",
        "REPOGUARD_RUN_ID": "88",
        "REPOGUARD_TRIGGERING_ACTOR": "maintainer",
        "REPOGUARD_WORKSPACE": str(workspace),
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "ImageOS": "ubuntu24",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(github_output),
        "GITHUB_STEP_SUMMARY": str(github_summary),
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    driver._review()

    outputs = dict(
        line.split("=", 1) for line in github_output.read_text(encoding="utf-8").splitlines()
    )
    assert "artifact-id" not in outputs
    assert "artifact-digest" not in outputs
    assert outputs["github-write-supported"] == str(same_repository).lower()
    assert outputs["result-sha256"] == _REVIEW_SHA256
    assert outputs["evidence-sha256"] == _EVIDENCE_SHA256
    assert outputs["review-sha256"] == _DETERMINISTIC_SHA256
    if same_repository:
        assert outputs["proposal-sha256"] == proposal_sha256
        proposal_path = Path(outputs["proposal-path"])
        assert proposal_path.name == "proposal.json"
        assert tuple(proposal_path.parent.iterdir()) == (proposal_path,)
        assert proposal_path.read_bytes() == driver._canonical_bytes(proposal)
        assert not proposal_path.read_bytes().endswith(b"\n")
        assert stat.S_IMODE(proposal_path.stat().st_mode) == 0o600
    else:
        assert outputs["proposal-path"] == ""
        assert outputs["proposal-sha256"] == ""
    result_raw = Path(outputs["result-path"]).read_bytes()
    assert str(workspace).encode() not in result_raw
    assert str(profile_path).encode() not in result_raw
    summary = github_summary.read_text(encoding="utf-8")
    assert "# RepoGuard review" in summary
    assert (
        "proposal prepared" in summary
        if same_repository
        else "read-only fork; no proposal created" in summary
    )
    assert "--github-pr" in observed_arguments[0]
    assert "7" in observed_arguments[0]


def test_repair_driver_accepts_exact_proposal_and_snapshot_shape(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate_id = "6" * 64
    validation_sha256 = "7" * 64
    commit_oid = "8" * 40
    proposal, proposal_sha256 = _proposal(
        driver,
        kind="repair",
        profile_name="fix",
        payload={
            "candidate_id": candidate_id,
            "validation_sha256": validation_sha256,
            "commit_oid": commit_oid,
        },
    )
    result = {
        "snapshot": {
            "state": "validated",
            "candidate": {
                "candidate_id": candidate_id,
                "commit_oid": commit_oid,
            },
            "validation": {"validation_sha256": validation_sha256},
        },
        "validation_success": True,
        "github_write_supported": True,
        "proposal": proposal,
        "proposal_sha256": proposal_sha256,
    }
    context = {
        "profile_path": tmp_path / "profile.json",
        "repository_alias": "example",
        "repository_id": 123,
        "repository_full_name": "owner/repository",
        "workspace": tmp_path / "workspace",
        "run_attempt": 1,
        "actor": "reviewer",
    }
    observed_arguments: list[tuple[str, ...]] = []

    monkeypatch.setattr(driver, "_common_context", lambda: dict(context))
    monkeypatch.setattr(driver, "_validate_action_source", lambda _context, _profile: None)
    monkeypatch.setattr(driver, "_load_profile", lambda _path: {"repair_profiles": []})
    monkeypatch.setattr(driver, "_validate_publisher_runner", lambda _profile, _context: None)
    monkeypatch.setattr(driver, "_load_event", lambda: {})
    monkeypatch.setattr(driver, "_validate_dispatch_event", lambda _event, _context: None)
    monkeypatch.setattr(driver, "_profile_repository", lambda _profile, _alias: {})
    monkeypatch.setattr(
        driver,
        "_validate_repository_context",
        lambda _repository, _context: None,
    )
    monkeypatch.setattr(driver, "_profile_sensitive_paths", lambda _profile: ())
    monkeypatch.setattr(driver, "_validate_rootless_profile", lambda _profile: None)
    monkeypatch.setattr(driver, "_select_repair_profile", lambda _profile, _name: {})
    monkeypatch.setattr(driver, "_validate_repair_secrets", lambda _profile: None)

    def fake_cli(
        arguments: tuple[str, ...],
        *,
        expected_operation: str,
    ) -> tuple[dict[str, object], int]:
        observed_arguments.append(arguments)
        assert expected_operation == "repair.prepare"
        return {
            "schema_version": 1,
            "operation": "repair.prepare",
            "ok": True,
            "result": result,
            "error": None,
        }, 0

    monkeypatch.setattr(driver, "_run_cli", fake_cli)
    github_output = tmp_path / "github-output"
    github_output.touch(mode=0o600)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    for key, value in {
        "GITHUB_OUTPUT": str(github_output),
        "RUNNER_TEMP": str(runner_temp),
        "REPOGUARD_PR_NUMBER": "7",
        "REPOGUARD_BASE_SHA": _BASE_SHA,
        "REPOGUARD_HEAD_SHA": _HEAD_SHA,
        "REPOGUARD_REPAIR_PROFILE": "fix",
        "REPOGUARD_TARGET_IDS": f'["{"9" * 64}"]',
        "REPOGUARD_ALLOWED_PATHS": '["src/a.py"]',
    }.items():
        monkeypatch.setenv(key, value)

    driver._repair()

    outputs = dict(
        line.split("=", 1) for line in github_output.read_text(encoding="utf-8").splitlines()
    )
    assert outputs["proposal-sha256"] == proposal_sha256
    assert outputs["candidate-id"] == candidate_id
    assert outputs["validation-sha256"] == validation_sha256
    assert outputs["commit-oid"] == commit_oid
    assert outputs["state"] == "validated"
    proposal_path = Path(outputs["proposal-path"])
    assert proposal_path.read_bytes() == driver._canonical_bytes(proposal)
    assert "--github-pr" in observed_arguments[0]


@pytest.mark.parametrize(
    ("kind", "expected_operation", "expected_state"),
    (
        ("check", "github.publish_check", "check_published"),
        ("repair", "github.publish_repair", "repair_published"),
    ),
)
def test_publish_driver_accepts_exact_three_field_result_shape(
    driver: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
    expected_operation: str,
    expected_state: str,
) -> None:
    proposal_sha256 = "a" * 64
    download_path = tmp_path / "download"
    download_path.mkdir()
    proposal_path = download_path / "proposal.json"
    proposal_path.write_text("{}", encoding="utf-8")
    context = {
        "profile_path": tmp_path / "profile.json",
        "repository_alias": "example",
        "repository_id": 123,
        "repository_full_name": "owner/repository",
        "workspace": tmp_path / "workspace",
        "run_attempt": 1,
        "actor": "reviewer",
    }
    publication = {
        "kind": kind,
        "proposal_sha256": proposal_sha256,
        "confirmation": (
            _CHECK_CONFIRMATION
            if kind == "check"
            else (
                "I approve publishing this exact RepoGuard repair commit to its dedicated "
                "branch and draft pull request."
            )
        ),
    }
    observed_environment: list[dict[str, str] | None] = []
    observed_outputs: list[dict[str, str]] = []
    hardened: list[Path] = []

    monkeypatch.setattr(driver, "_common_context", lambda: dict(context))
    monkeypatch.setattr(driver, "_validate_action_source", lambda _context, _profile: None)
    monkeypatch.setattr(driver, "_load_profile", lambda _path: {})
    monkeypatch.setattr(driver, "_validate_publisher_runner", lambda _profile, _context: None)
    monkeypatch.setattr(driver, "_profile_repository", lambda _profile, _alias: {})
    monkeypatch.setattr(
        driver,
        "_validate_repository_context",
        lambda _repository, _context: None,
    )
    monkeypatch.setattr(driver, "_profile_sensitive_paths", lambda _profile: ())
    monkeypatch.setattr(driver, "_load_event", lambda: {})
    monkeypatch.setattr(driver, "_validate_dispatch_event", lambda _event, _context: None)
    monkeypatch.setattr(driver, "_publication_inputs", lambda _context: publication)
    monkeypatch.setattr(driver, "_validate_publish_secrets", lambda: None)
    monkeypatch.setattr(
        driver,
        "_verify_artifact_metadata",
        lambda _context, _publication: None,
    )
    monkeypatch.setattr(
        driver,
        "_load_downloaded_proposal",
        lambda *_args, **_kwargs: {"origin": "action"},
    )
    monkeypatch.setattr(driver, "_harden_check_proposal_file", hardened.append)
    monkeypatch.setattr(
        driver, "_write_outputs", lambda values: observed_outputs.append(dict(values))
    )

    def fake_cli(
        arguments: tuple[str, ...],
        *,
        expected_operation: str,
        extra_environment: dict[str, str] | None = None,
    ) -> tuple[dict[str, object], int]:
        assert expected_operation == expected_operation_name
        assert "--proposal-sha256" in arguments
        observed_environment.append(extra_environment)
        return {
            "schema_version": 1,
            "operation": expected_operation_name,
            "ok": True,
            "result": {
                "approval_sha256": "b" * 64,
                "result_sha256": "c" * 64,
                "state": expected_state,
            },
            "error": None,
        }, 0

    expected_operation_name = expected_operation
    monkeypatch.setattr(driver, "_run_cli", fake_cli)
    monkeypatch.setenv("REPOGUARD_DOWNLOAD_PATH", str(download_path))

    driver._publish()

    assert observed_outputs == [
        {
            "approval-sha256": "b" * 64,
            "result-sha256": "c" * 64,
            "state": expected_state,
        }
    ]
    if kind == "check":
        assert hardened == [proposal_path]
        assert observed_environment == [
            {
                "REPOGUARD_ACTION_ACTOR": "reviewer",
                "REPOGUARD_ACTION_PROPOSAL_PATH": str(proposal_path),
            }
        ]
    else:
        assert hardened == []
        assert observed_environment == [{"REPOGUARD_ACTION_ACTOR": "reviewer"}]
