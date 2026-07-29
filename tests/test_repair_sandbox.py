"""Focused fake-transport tests for the M5 rootless Docker boundary."""

from __future__ import annotations

import ast
import copy
import hashlib
import hmac
import json
import os
import platform
import runpy
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import replace
from importlib.resources.abc import Traversable
from pathlib import Path
from types import FunctionType
from typing import Protocol, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import repoguard._repair_sandbox as sandbox
from repoguard._repair_models import _canonical_bytes, _domain_digest
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairManagerConfig,
    RepairStage,
    ValidationCommand,
    ValidationFailureKind,
    ValidationPolicy,
    validation_policy_to_dict,
)

_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64
_IMAGE = "sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846"
_UNLOCKED_IMAGE = f"sha256:{_HEX_A}"
_KEY = bytes.fromhex("11" * 32)
_NONCE = bytes.fromhex("22" * 32)
_RUN_TOKEN = bytes.fromhex("33" * 32)
_PROPERTY_SETTINGS = settings(database=None, derandomize=True, max_examples=100)
_DEFAULT_BIND_MOUNTS = (("/tmp/runner.py", "/opt/repoguard/runner.py"),)


class _RunnerStreamResult(Protocol):
    timed_out: bool


class _ExceptSandboxErrorVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.lines: list[int] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Raise)
                and isinstance(child.exc, ast.Call)
                and isinstance(child.exc.func, ast.Name)
                and child.exc.func.id == "_sandbox_error"
            ):
                self.lines.append(child.lineno)
        self.generic_visit(node)


def _assert_detached_sandbox_error(error: RepairError) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__


def _config(tmp_path: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root=(tmp_path / "runtime").resolve(),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/docker"),
        rootless_socket=(tmp_path / "docker.sock").resolve(),
    )


def _policy() -> ValidationPolicy:
    return ValidationPolicy(
        image_id=_IMAGE,
        commands=(
            ValidationCommand(
                argv=("/usr/local/bin/python3.12", "-m", "pytest", "-q"),
            ),
        ),
    )


def _secrets() -> sandbox._SandboxSecrets:
    return sandbox._SandboxSecrets(
        nonce=_NONCE,
        hmac_key=_KEY,
        run_token=_RUN_TOKEN,
        run_token_sha256=_domain_digest("run-token", {"run_token": _RUN_TOKEN.hex()}),
    )


def _docker_documents(*, rootless: bool = True, image_id: str = _IMAGE) -> tuple[bytes, ...]:
    security = ["name=seccomp,profile=builtin", "name=cgroupns"]
    if rootless:
        security.append("name=rootless")
    version = {
        "Client": {
            "Version": "29.6.1",
            "Os": "linux",
            "Arch": "amd64",
        },
        "Server": {
            "Version": "29.6.1",
            "ApiVersion": "1.55",
            "Os": "linux",
            "Arch": "amd64",
        },
    }
    info = {
        "OSType": "linux",
        "Architecture": "x86_64",
        "CgroupVersion": "2",
        "SecurityOptions": security,
        "MemoryLimit": True,
        "SwapLimit": True,
        "CpuCfsQuota": True,
        "PidsLimit": True,
    }
    image = {
        "Id": image_id,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Env": ["PATH=/image/default"]},
    }
    return tuple(
        json.dumps(value, separators=(",", ":")).encode() + b"\n"
        for value in (version, info, image)
    )


def _report_mapping(
    *,
    success: bool = True,
    failure_kind: str | None = None,
    command_results: list[dict[str, object]] | None = None,
    **overrides: object,
) -> dict[str, object]:
    if command_results is None:
        command_results = [
            {
                "command_index": 0,
                "exit_code": 0,
                "signal": None,
                "timed_out": False,
                "duration_us": 10,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stdout_bytes": 0,
                "stdout_truncated": False,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_bytes": 0,
                "stderr_truncated": False,
            }
        ]
    value: dict[str, object] = {
        "schema_version": 1,
        "nonce": _NONCE.hex(),
        "success": success,
        "failure_kind": failure_kind,
        "started_at_us": 100,
        "finished_at_us": 200,
        "command_results": command_results,
        "peak_memory_bytes": 1024,
        "oom_killed": False,
        "residual_process_count": 0,
        "workspace_entry_count": 5,
        "workspace_inode_count": 5,
        "tracked_tree_clean": True,
    }
    value.update(overrides)
    return value


def _authenticated_frame(mapping: dict[str, object]) -> bytes:
    payload = _canonical_bytes(mapping)
    authentication = hmac.new(
        _KEY,
        sandbox._REPORT_HMAC_DOMAIN + _NONCE + payload,
        hashlib.sha256,
    ).digest()
    return (
        sandbox._FRAME_HEADER.pack(sandbox._REPORT_MAGIC, len(payload)) + payload + authentication
    )


def _probe_frame() -> bytes:
    return _authenticated_frame(
        {
            "schema_version": 1,
            "nonce": _NONCE.hex(),
            "success": True,
            "checks": list(sandbox._PROBE_CHECKS),
        }
    )


def _asset_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    assets = sandbox._load_sandbox_assets()
    runner = tmp_path / "runner.py"
    probe = tmp_path / "probe.py"
    seccomp = tmp_path / "seccomp-v1.json"
    runner.write_bytes(assets.runner)
    probe.write_bytes(assets.probe)
    seccomp.write_bytes(assets.seccomp_json)
    return runner, probe, seccomp


class _TextPath:
    def __init__(self, text: str) -> None:
        self._text = text

    def read_text(self, *, encoding: str) -> str:
        assert encoding == "ascii"
        return self._text


def _capabilities() -> sandbox._SandboxCapabilities:
    return sandbox._SandboxCapabilities(
        client_version="29.6.1",
        server_version="29.6.1",
        api_version="1.55",
        architecture="x86_64",
        cgroup_version="2",
        security_options=("name=rootless", "name=seccomp,profile=builtin"),
        image_id=_IMAGE,
        sandbox_manifest_sha256=sandbox._load_sandbox_assets().sandbox_manifest_sha256,
    )


def _run_identity(
    *,
    container_id: str = _HEX_C,
    container_name: str = "repoguard-m5-test",
    session_id: str = _HEX_A,
    candidate_id: str = _HEX_B,
    run_token_sha256: str | None = None,
    labels: tuple[tuple[str, str], ...] | None = None,
) -> sandbox._SandboxRunIdentity:
    token_sha256 = _secrets().run_token_sha256 if run_token_sha256 is None else run_token_sha256
    expected_labels = (
        (sandbox._COMPONENT_LABEL, sandbox._COMPONENT_VALUE),
        (sandbox._SESSION_LABEL, session_id),
        (sandbox._CANDIDATE_LABEL, candidate_id),
        (sandbox._RUN_TOKEN_LABEL, token_sha256),
    )
    return sandbox._SandboxRunIdentity(
        container_id=container_id,
        container_name=container_name,
        labels=expected_labels if labels is None else labels,
        session_id=session_id,
        candidate_id=candidate_id,
        run_token_sha256=token_sha256,
    )


def _candidate_inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, tuple[sandbox._TrackedInput, ...], str]:
    candidate = tmp_path / "candidate-input"
    candidate.mkdir()
    content = b"print('validated')\n"
    (candidate / "example.py").write_bytes(content)
    git_dir = tmp_path / "isolated.git"
    git_dir.mkdir()
    index_file = git_dir / "repoguard-index"
    index_content = b"isolated-index"
    index_file.write_bytes(index_content)
    tracked = (
        sandbox._TrackedInput(
            path="example.py",
            sha256=hashlib.sha256(content).hexdigest(),
            executable=False,
        ),
    )
    return candidate, git_dir, index_file, tracked, hashlib.sha256(index_content).hexdigest()


class _FakeDockerProcess:
    def __init__(
        self,
        start_stdout: bytes,
        *,
        start_returncode: int = 0,
        start_timed_out: bool = False,
        start_output_limit: bool = False,
        start_stderr: bytes = b"",
        oom_killed: bool = False,
        remove_returncode: int = 0,
        create_stdout: bytes | None = None,
        create_timed_out: bool = False,
        late_list_visibility: bool = False,
    ) -> None:
        self.start_stdout = start_stdout
        self.start_returncode = start_returncode
        self.start_timed_out = start_timed_out
        self.start_output_limit = start_output_limit
        self.start_stderr = start_stderr
        self.oom_killed = oom_killed
        self.remove_returncode = remove_returncode
        self.create_stdout = _HEX_C.encode() + b"\n" if create_stdout is None else create_stdout
        self.create_timed_out = create_timed_out
        self.late_list_visibility = late_list_visibility
        self.calls: list[tuple[tuple[str, ...], bytes, float, int]] = []
        self.events: list[str] = []
        self.container_name = ""
        self.labels: dict[str, str] = {}
        self.create_arguments: tuple[str, ...] = ()
        self.state = "absent"
        self.exit_code = 0

    def __call__(
        self,
        argv: tuple[str, ...],
        stdin: bytes,
        timeout_seconds: float,
        stream_limit: int,
    ) -> sandbox._BoundedProcessResult:
        self.calls.append((argv, stdin, timeout_seconds, stream_limit))
        command = argv[3:]
        if command[0] == "create":
            self.events.append("create")
            self.create_arguments = command
            self.container_name = command[command.index("--name") + 1]
            self.labels = {}
            for index, value in enumerate(command):
                if value == "--label":
                    key, label_value = command[index + 1].split("=", 1)
                    self.labels[key] = label_value
            if self.create_timed_out:
                self.state = "absent"
                return self._result(stdout=self.create_stdout, timed_out=True)
            self.state = "created"
            return self._result(stdout=self.create_stdout)
        if command[:2] == ("container", "inspect"):
            self.events.append("inspect")
            if self.state == "absent":
                return self._result(returncode=1)
            return self._result(stdout=self._inspect_document())
        if command[:2] == ("container", "ls"):
            self.events.append("list")
            if self.late_list_visibility and self.state == "absent":
                self.state = "created"
            stdout = b"" if self.state == "absent" else _HEX_C.encode() + b"\n"
            return self._result(stdout=stdout)
        if command[0] == "start":
            self.events.append("start")
            self.state = "exited"
            if self.start_timed_out:
                self.exit_code = 137
            else:
                self.exit_code = max(0, self.start_returncode)
            return self._result(
                returncode=self.start_returncode,
                stdout=self.start_stdout,
                stderr=self.start_stderr,
                timed_out=self.start_timed_out,
                output_limit=self.start_output_limit,
            )
        if command[:2] == ("container", "stop"):
            self.events.append("stop")
            self.state = "exited"
            self.exit_code = 143
            return self._result()
        if command[:2] == ("container", "kill"):
            self.events.append("kill")
            self.state = "exited"
            self.exit_code = 137
            return self._result()
        if command[:2] == ("container", "wait"):
            self.events.append("wait")
            return self._result(stdout=f"{self.exit_code}\n".encode())
        if command[:2] == ("container", "rm"):
            self.events.append("remove")
            if self.remove_returncode == 0:
                self.state = "absent"
            return self._result(
                returncode=self.remove_returncode,
                stdout=_HEX_C.encode() + b"\n",
            )
        raise AssertionError(f"unexpected Docker argv: {argv!r}")

    def _inspect_document(self) -> bytes:
        status = "created" if self.state == "created" else "exited"
        policy = _policy()
        command = self.create_arguments
        image_index = command.index(_IMAGE) if command else -1
        environment = (
            [command[index + 1] for index, item in enumerate(command) if item == "--env"]
            if command
            else [f"{key}={value}" for key, value in sandbox._CONTAINER_ENVIRONMENT]
        )
        tmpfs_values = (
            [command[index + 1] for index, item in enumerate(command) if item == "--tmpfs"]
            if command
            else [
                sandbox._tmpfs_spec(
                    "/workspace",
                    size=policy.workspace_bytes,
                    inodes=policy.workspace_inodes,
                ),
                sandbox._tmpfs_spec("/tmp", size=policy.tmp_bytes, inodes=policy.tmp_inodes),
                sandbox._tmpfs_spec(
                    "/home/repoguard",
                    size=policy.home_bytes,
                    inodes=policy.home_inodes,
                ),
                sandbox._tmpfs_spec(
                    "/run",
                    size=policy.run_bytes,
                    inodes=policy.run_inodes,
                ),
            ]
        )
        tmpfs = dict(value.split(":", 1) for value in tmpfs_values)
        mount_values = (
            [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
            if command
            else ["type=bind,source=/tmp/runner.py,destination=/opt/repoguard/runner.py,readonly"]
        )
        mounts: list[dict[str, object]] = []
        for mount_value in mount_values:
            fields: dict[str, str] = {}
            read_only = False
            for item in mount_value.split(","):
                if item == "readonly":
                    read_only = True
                    continue
                key, field_value = item.split("=", 1)
                fields[key] = field_value
            mounts.append(
                {
                    "Type": fields["type"],
                    "Source": fields["source"],
                    "Destination": fields["destination"],
                    "Mode": "",
                    "RW": not read_only,
                    "Propagation": "rprivate",
                }
            )
        configured_command = (
            list(command[image_index + 1 :])
            if command
            else ["-I", "-S", "-E", "-B", "/opt/repoguard/runner.py"]
        )
        value = {
            "Id": _HEX_C,
            "Image": _IMAGE,
            "Config": {
                "Image": _IMAGE,
                "Labels": self.labels,
                "Hostname": "repoguard",
                "User": "0:0",
                "WorkingDir": "/",
                "Entrypoint": ["/usr/local/bin/python3.12"],
                "Cmd": configured_command,
                "Env": environment,
                "Volumes": None,
            },
            "HostConfig": {
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": [
                    "no-new-privileges=true",
                    'seccomp={"defaultAction":"SCMP_ACT_ERRNO"}',
                ],
                "NetworkMode": "none",
                "IpcMode": "private",
                "PidMode": "",
                "CgroupnsMode": "private",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "AutoRemove": False,
                "OomKillDisable": False,
                "Memory": policy.memory_bytes,
                "MemorySwap": policy.memory_bytes,
                "NanoCpus": policy.nano_cpus,
                "PidsLimit": policy.pids_limit,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Tmpfs": tmpfs,
            },
            "Mounts": mounts,
            "State": {
                "Running": False,
                "Status": status,
                "ExitCode": self.exit_code,
                "OOMKilled": self.oom_killed,
                "Pid": 0,
                "Error": "",
                "StartedAt": "" if status == "created" else "2026-07-29T00:00:00Z",
                "FinishedAt": "" if status == "created" else "2026-07-29T00:00:01Z",
            },
        }
        return json.dumps(value, separators=(",", ":")).encode() + b"\n"

    @staticmethod
    def _result(
        *,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        timed_out: bool = False,
        output_limit: bool = False,
    ) -> sandbox._BoundedProcessResult:
        return sandbox._BoundedProcessResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_limit=output_limit,
        )


def _validate_with_fake(
    tmp_path: Path,
    process: _FakeDockerProcess,
    *,
    register_intent: sandbox._IntentRegistrar | None = None,
    register_run: sandbox._RunRegistrar | None = None,
    release_intent: sandbox._IntentReleaser | None = None,
    release_run: sandbox._RunReleaser | None = None,
    before_remove: sandbox._OutcomeFence | None = None,
    mount_identity_check: sandbox._MountIdentityCheck | None = None,
) -> sandbox._SandboxValidationOutcome:
    runner, _, seccomp = _asset_files(tmp_path)
    candidate, git_dir, index_file, tracked, index_sha256 = _candidate_inputs(tmp_path)
    return sandbox._run_sandbox_validation(
        _config(tmp_path),
        _policy(),
        _capabilities(),
        session_id=_HEX_A,
        candidate_id=_HEX_B,
        candidate_root=candidate,
        git_dir=git_dir,
        index_file=index_file,
        runner_path=runner,
        seccomp_path=seccomp,
        tracked_inputs=tracked,
        git_index_sha256=index_sha256,
        expected_tree_oid="d" * 40,
        register_intent=_accept_intent if register_intent is None else register_intent,
        register_run=_accept_run if register_run is None else register_run,
        release_intent=_release_intent if release_intent is None else release_intent,
        release_run=_release_run if release_run is None else release_run,
        before_remove=_ignore_outcome if before_remove is None else before_remove,
        process_invoke=process,
        secrets_value=_secrets(),
        mount_identity_check=mount_identity_check,
    )


def _accept_intent(_: sandbox._SandboxRunIntent) -> bool:
    return True


def _accept_run(_: sandbox._SandboxRunIdentity) -> bool:
    return True


def _release_intent(_: sandbox._SandboxRunIntent) -> bool:
    return True


def _release_run(_: sandbox._SandboxRunIdentity) -> bool:
    return True


def _ignore_outcome(_: sandbox._SandboxValidationOutcome) -> None:
    return None


def test_packaged_manifest_binds_exact_assets_and_seccomp_policy() -> None:
    assets = sandbox._load_sandbox_assets()

    assert len(assets.syscall_allowlist) == 258
    assert assets.syscall_allowlist == tuple(sorted(set(assets.syscall_allowlist)))
    assert {"clone", "ioctl", "socket", "socketpair"} <= set(assets.syscall_allowlist)
    assert not sandbox._FORBIDDEN_ALLOWED_SYSCALLS.intersection(assets.syscall_allowlist)
    assert len(assets.runner) > 1_000
    assert len(assets.probe) > 1_000
    assert sandbox._validate_seccomp(assets.seccomp_json) == assets.syscall_allowlist
    assert "python312" in sandbox._PROBE_CHECKS
    assert b"sys.version_info[:2] == (3, 12)" in assets.probe


def test_packaged_runner_binds_read_only_index_to_expected_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(tmp_path),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    subprocess.run(
        ("/usr/bin/git", "init", "--quiet", "-b", "main", str(repository)),
        check=True,
        capture_output=True,
        env=environment,
    )
    (repository / "tracked.txt").write_text("fixed\n", encoding="utf-8")
    subprocess.run(
        ("/usr/bin/git", "-C", str(repository), "add", "--", "tracked.txt"),
        check=True,
        capture_output=True,
        env=environment,
    )
    tree_oid = (
        subprocess.run(
            ("/usr/bin/git", "-C", str(repository), "write-tree"),
            check=True,
            capture_output=True,
            env=environment,
        )
        .stdout.decode("ascii")
        .strip()
    )
    runner_path = Path(sandbox.__file__).parent / "repair_assets" / "runner.py"
    namespace = runpy.run_path(str(runner_path))
    matcher = cast(FunctionType, namespace["_git_index_matches_tree"])
    matcher.__globals__["_GIT_DIRECTORY"] = repository / ".git"
    matcher.__globals__["_GIT_INDEX"] = repository / ".git" / "index"
    matcher.__globals__["_WORKSPACE"] = repository

    assert matcher(tree_oid) is True
    assert matcher("0" * len(tree_oid)) is False


def test_packaged_runner_command_timeout_closes_descendant_held_pipes(tmp_path: Path) -> None:
    runner_path = Path(sandbox.__file__).parent / "repair_assets" / "runner.py"
    namespace = runpy.run_path(str(runner_path))
    run_command = cast(FunctionType, namespace["_run_command"])
    command_factory = cast(Callable[..., object], namespace["_Command"])
    run_command.__globals__["_remove_residual_processes"] = lambda: 0
    child = "import time; time.sleep(10)"
    child_pid = tmp_path / "child.pid"
    leader = (
        "import pathlib, subprocess, sys; "
        f"child = subprocess.Popen((sys.executable, '-c', {child!r}), start_new_session=True); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')"
    )
    command = command_factory(argv=(sys.executable, "-c", leader), cwd=str(tmp_path))

    started = time.monotonic()
    try:
        result = cast(
            _RunnerStreamResult,
            run_command(command, timeout_seconds=0.2, stream_limit=1_024),
        )
        elapsed = time.monotonic() - started
        holder_created = child_pid.is_file()
    finally:
        if child_pid.is_file():
            with suppress(ProcessLookupError):
                os.kill(int(child_pid.read_text(encoding="ascii")), signal.SIGKILL)

    assert holder_created is True
    assert result.timed_out is True
    assert elapsed < 0.75


def test_packaged_runner_waits_for_process_exit_after_command_streams_close(tmp_path: Path) -> None:
    runner_path = Path(sandbox.__file__).parent / "repair_assets" / "runner.py"
    namespace = runpy.run_path(str(runner_path))
    run_command = cast(FunctionType, namespace["_run_command"])
    command_factory = cast(Callable[..., object], namespace["_Command"])
    run_command.__globals__["_remove_residual_processes"] = lambda: 0
    program = (
        "import os, signal, sys, time; "
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
        "os.close(1); os.close(2); time.sleep(2)"
    )
    command = command_factory(argv=(sys.executable, "-c", program), cwd=str(tmp_path))

    started = time.monotonic()
    result = cast(
        _RunnerStreamResult,
        run_command(command, timeout_seconds=0.1, stream_limit=1_024),
    )
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed >= 0.08


def test_private_sandbox_record_invariants_fail_closed() -> None:
    report = sandbox._parse_report_frame(
        _authenticated_frame(_report_mapping()),
        expected_nonce=_NONCE,
        hmac_key=_KEY,
        expected_command_count=1,
    )
    identity = _run_identity()
    policy_sha256 = _domain_digest("policy", validation_policy_to_dict(_policy()))
    manifest_sha256 = _capabilities().sandbox_manifest_sha256

    with pytest.raises(TypeError):
        sandbox._DockerOutput(cast(int, True), b"", b"")
    with pytest.raises(TypeError):
        sandbox._DockerOutput(0, cast(bytes, ""), b"")
    with pytest.raises(TypeError):
        sandbox._TrackedInput("example.py", _HEX_A, cast(bool, 1))
    with pytest.raises(ValueError):
        sandbox._SandboxSecrets(b"short", _KEY, _RUN_TOKEN, _HEX_A)
    with pytest.raises(ValueError):
        sandbox._SandboxSecrets(_NONCE, _KEY, _RUN_TOKEN, _HEX_A)
    with pytest.raises(ValueError):
        _run_identity(container_id="short")
    with pytest.raises(ValueError):
        _run_identity(container_name="")
    with pytest.raises(ValueError):
        _run_identity(labels=((sandbox._COMPONENT_LABEL, sandbox._COMPONENT_VALUE),))
    with pytest.raises(ValueError):
        sandbox._SandboxValidationOutcome(
            _HEX_A,
            _HEX_B,
            policy_sha256,
            manifest_sha256,
            "sha256:not-an-image",
            report,
            identity,
            False,
        )
    with pytest.raises(TypeError):
        sandbox._SandboxValidationOutcome(
            _HEX_A,
            _HEX_B,
            policy_sha256,
            manifest_sha256,
            _IMAGE,
            cast(sandbox._SandboxReport, object()),
            identity,
            False,
        )
    with pytest.raises(TypeError):
        sandbox._SandboxValidationOutcome(
            _HEX_A,
            _HEX_B,
            policy_sha256,
            manifest_sha256,
            _IMAGE,
            report,
            cast(sandbox._SandboxRunIdentity, object()),
            False,
        )
    with pytest.raises(ValueError):
        sandbox._SandboxValidationOutcome(
            _HEX_C,
            _HEX_B,
            policy_sha256,
            manifest_sha256,
            _IMAGE,
            report,
            identity,
            False,
        )
    with pytest.raises(TypeError):
        sandbox._SandboxValidationOutcome(
            _HEX_A,
            _HEX_B,
            policy_sha256,
            manifest_sha256,
            _IMAGE,
            report,
            identity,
            cast(bool, 0),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "client_os",
        "client_arch",
        "info_os",
        "info_arch",
        "cgroup",
        "security_type",
        "resource_control",
        "swap_control",
        "image_platform",
        "image_environment",
        "image_volumes",
        "malformed",
    ],
)
def test_capability_documents_reject_unsupported_or_malformed_daemon_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    values = [json.loads(raw) for raw in _docker_documents()]
    if mutation == "client_os":
        values[0]["Client"]["Os"] = "windows"
    elif mutation == "client_arch":
        values[0]["Server"]["Arch"] = "arm64"
    elif mutation == "info_os":
        values[1]["OSType"] = "windows"
    elif mutation == "info_arch":
        values[1]["Architecture"] = "arm64"
    elif mutation == "cgroup":
        values[1]["CgroupVersion"] = "1"
    elif mutation == "security_type":
        values[1]["SecurityOptions"] = "name=rootless"
    elif mutation == "resource_control":
        values[1]["PidsLimit"] = False
    elif mutation == "swap_control":
        values[1]["SwapLimit"] = False
    elif mutation == "image_platform":
        values[2]["Architecture"] = "arm64"
    elif mutation == "image_environment":
        values[2]["Config"]["Env"].append("LD_PRELOAD=/tmp/injected.so")
    elif mutation == "image_volumes":
        values[2]["Config"]["Volumes"] = {"/unsafe": {}}
    documents = [json.dumps(value, separators=(",", ":")).encode() + b"\n" for value in values]
    if mutation == "malformed":
        documents[0] = b"{"
    outputs = iter(documents)
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def invoke(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        return sandbox._DockerOutput(0, next(outputs), b"")

    with pytest.raises(RepairError) as captured:
        sandbox._inspect_sandbox_capabilities(_config(tmp_path), _policy(), invoke=invoke)

    expected_code = (
        RepairErrorCode.IMAGE_MISMATCH
        if mutation in {"image_platform", "image_environment", "image_volumes"}
        else RepairErrorCode.SANDBOX_UNAVAILABLE
    )
    assert captured.value.code is expected_code


@pytest.mark.parametrize(
    "mutation",
    [
        "environment",
        "cap_drop",
        "security_opt",
        "network",
        "ipc",
        "pid",
        "read_only",
        "privileged",
        "memory",
        "memory_swap",
        "nano_cpus",
        "pids",
        "tmpfs",
        "mount_type",
        "mount_source",
        "mount_destination",
        "mount_rw",
        "mount_propagation",
        "mount_missing",
        "mount_duplicate",
        "mount_extra",
    ],
)
def test_created_container_effective_configuration_is_fail_closed(mutation: str) -> None:
    identity = _run_identity()
    process = _FakeDockerProcess(b"")
    process.state = "created"
    process.labels = dict(identity.labels)
    document = cast(dict[str, object], json.loads(process._inspect_document()))
    config = cast(dict[str, object], document["Config"])
    host_config = cast(dict[str, object], document["HostConfig"])
    mounts = cast(list[dict[str, object]], document["Mounts"])
    if mutation == "environment":
        cast(list[str], config["Env"]).append("LD_PRELOAD=/tmp/injected.so")
    elif mutation == "cap_drop":
        host_config["CapDrop"] = []
    elif mutation == "security_opt":
        host_config["SecurityOpt"] = ["seccomp=unconfined"]
    elif mutation == "network":
        host_config["NetworkMode"] = "bridge"
    elif mutation == "ipc":
        host_config["IpcMode"] = "host"
    elif mutation == "pid":
        host_config["PidMode"] = "host"
    elif mutation == "read_only":
        host_config["ReadonlyRootfs"] = False
    elif mutation == "privileged":
        host_config["Privileged"] = True
    elif mutation == "memory":
        host_config["Memory"] = _policy().memory_bytes - 1
    elif mutation == "memory_swap":
        host_config["MemorySwap"] = -1
    elif mutation == "nano_cpus":
        host_config["NanoCpus"] = _policy().nano_cpus - 1
    elif mutation == "pids":
        host_config["PidsLimit"] = _policy().pids_limit - 1
    elif mutation == "tmpfs":
        tmpfs = cast(dict[str, str], host_config["Tmpfs"])
        tmpfs["/workspace"] = tmpfs["/workspace"].replace("nosuid,", "")
    elif mutation == "mount_type":
        mounts[0]["Type"] = "volume"
    elif mutation == "mount_source":
        mounts[0]["Source"] = "/tmp/other.py"
    elif mutation == "mount_destination":
        mounts[0]["Destination"] = "/opt/repoguard/other.py"
    elif mutation == "mount_rw":
        mounts[0]["RW"] = True
    elif mutation == "mount_propagation":
        mounts[0]["Propagation"] = "rshared"
    elif mutation == "mount_missing":
        mounts.clear()
    elif mutation == "mount_duplicate":
        mounts.append(copy.deepcopy(mounts[0]))
    else:
        mounts.append(
            {
                "Type": "bind",
                "Source": "/tmp/extra",
                "Destination": "/input/extra",
                "Mode": "",
                "RW": False,
                "Propagation": "rprivate",
            }
        )

    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._corroborate_created_container(
            json.dumps(document, separators=(",", ":")).encode(),
            expected_container_id=_HEX_C,
            expected_labels=identity.labels,
            expected_policy=_policy(),
            expected_command=("-I", "-S", "-E", "-B", "/opt/repoguard/runner.py"),
            expected_bind_mounts=_DEFAULT_BIND_MOUNTS,
        )


@pytest.mark.parametrize(
    ("failed_call", "expected_code"),
    [
        (0, RepairErrorCode.SANDBOX_UNAVAILABLE),
        (1, RepairErrorCode.SANDBOX_UNAVAILABLE),
        (2, RepairErrorCode.IMAGE_UNAVAILABLE),
    ],
)
def test_capability_command_failures_have_stable_error_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_call: int,
    expected_code: RepairErrorCode,
) -> None:
    documents = _docker_documents()
    call_index = 0
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def invoke(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        nonlocal call_index
        index = call_index
        call_index += 1
        return sandbox._DockerOutput(
            1 if index == failed_call else 0,
            documents[index],
            b"",
        )

    with pytest.raises(RepairError) as captured:
        sandbox._inspect_sandbox_capabilities(_config(tmp_path), _policy(), invoke=invoke)

    assert captured.value.code is expected_code


@pytest.mark.parametrize(
    "mutation",
    [
        "keys",
        "default",
        "architecture",
        "syscalls_type",
        "entry_type",
        "names",
        "duplicate",
        "forbidden",
        "clone_rule",
        "socket_rule",
    ],
)
def test_seccomp_policy_mutations_fail_closed(mutation: str) -> None:
    value = copy.deepcopy(json.loads(sandbox._load_sandbox_assets().seccomp_json))
    if mutation == "keys":
        del value["defaultErrnoRet"]
    elif mutation == "default":
        value["defaultAction"] = "SCMP_ACT_ALLOW"
    elif mutation == "architecture":
        value["archMap"] = []
    elif mutation == "syscalls_type":
        value["syscalls"] = {}
    elif mutation == "entry_type":
        value["syscalls"].append("invalid")
    elif mutation == "names":
        value["syscalls"].append({"names": [], "action": "SCMP_ACT_ALLOW", "args": []})
    elif mutation == "duplicate":
        value["syscalls"].append({"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": []})
    elif mutation == "forbidden":
        value["syscalls"].append({"names": ["bpf"], "action": "SCMP_ACT_ALLOW", "args": []})
    elif mutation == "clone_rule":
        entry = next(item for item in value["syscalls"] if item["names"] == ["clone"])
        entry["args"] = []
    else:
        value["syscalls"] = [item for item in value["syscalls"] if item["names"] != ["socketpair"]]

    with pytest.raises(RepairError) as captured:
        sandbox._validate_seccomp(_canonical_bytes(value))

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "architecture",
        "allowlist",
        "resource_digest",
        "manifest_type",
        "manifest_digest",
    ],
)
def test_packaged_manifest_mutations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    assets = sandbox._load_sandbox_assets()
    asset_root = Path(sandbox.__file__).parent / "repair_assets"
    manifest_path = asset_root / "manifest.json"
    image_lock_path = asset_root / "validation_image_v1" / "image-lock.json"
    manifest = json.loads(manifest_path.read_bytes())
    if mutation == "schema":
        manifest["schema_version"] = 2
    elif mutation == "architecture":
        manifest["architecture"] = "linux-arm64"
    elif mutation == "allowlist":
        manifest["syscall_allowlist"] = manifest["syscall_allowlist"][:-1]
    elif mutation == "resource_digest":
        manifest["runner_sha256"] = _HEX_A
    elif mutation == "manifest_type":
        manifest["sandbox_manifest_sha256"] = 1
    else:
        manifest["sandbox_manifest_sha256"] = _HEX_A
    resources = iter(
        (
            assets.runner,
            assets.probe,
            assets.seccomp_json,
            _canonical_bytes(manifest),
            image_lock_path.read_bytes(),
        )
    )
    monkeypatch.setattr(sandbox, "_read_asset", lambda _: next(resources))

    with pytest.raises(RepairError) as captured:
        sandbox._load_sandbox_assets()

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE


def test_packaged_probe_checks_initial_environment_before_clearing() -> None:
    probe_path = Path(sandbox.__file__).parent / "repair_assets" / "probe.py"
    namespace = runpy.run_path(str(probe_path))
    run_checks_raw = namespace["_run_checks"]
    run_checks = cast(
        Callable[[dict[str, object], dict[str, str]], tuple[str, ...]],
        run_checks_raw,
    )
    globals_map = cast(dict[str, object], cast(FunctionType, run_checks_raw).__globals__)
    fixed_environment = cast(dict[str, str], namespace["_FIXED_ENVIRONMENT"])
    docker_initial_environment = {**fixed_environment, "HOSTNAME": "repoguard"}

    class _Libc:
        @staticmethod
        def prctl(*_arguments: object) -> int:
            return 0

    replacements: dict[str, object] = {
        "_libc": lambda: _Libc(),
        "_root_is_read_only": lambda: True,
        "_tmpfs_limits_match": lambda _: True,
        "_cgroup_limits_match": lambda _: True,
        "_network_is_denied": lambda: True,
        "_unix_socket_works": lambda: True,
        "_forbidden_syscalls_are_denied": lambda _: True,
        "_clone3_is_enosys": lambda _: True,
        "_process_security_matches": lambda: True,
    }
    originals = {name: globals_map[name] for name in replacements}
    original_environment = dict(os.environ)
    try:
        globals_map.update(replacements)
        os.environ.clear()
        os.environ.update(fixed_environment)
        exact = run_checks({}, docker_initial_environment)
        missing_hostname = run_checks({}, dict(fixed_environment))
        unexpected = run_checks(
            {},
            {**docker_initial_environment, "LD_PRELOAD": "/tmp/injected.so"},
        )
        os.environ["HOSTNAME"] = "repoguard"
        uncleared = run_checks({}, docker_initial_environment)
    finally:
        globals_map.update(originals)
        os.environ.clear()
        os.environ.update(original_environment)

    assert "environment_clear" in exact
    assert "environment_clear" not in missing_hostname
    assert "environment_clear" not in unexpected
    assert "environment_clear" not in uncleared


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("CapEff", "0000000000000001"),
        ("NoNewPrivs", "0"),
        ("Seccomp", "0"),
        ("Seccomp_filters", "0"),
    ],
)
def test_packaged_probe_rejects_weak_process_security(field: str, value: str) -> None:
    probe_path = Path(sandbox.__file__).parent / "repair_assets" / "probe.py"
    namespace = runpy.run_path(str(probe_path))
    check_raw = namespace["_process_security_matches"]
    check = cast(Callable[[], bool], check_raw)
    globals_map = cast(dict[str, object], cast(FunctionType, check_raw).__globals__)
    status = {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
        "Seccomp_filters": "1",
    }
    status[field] = value
    original_path = globals_map["Path"]
    globals_map["Path"] = lambda _: _TextPath(
        "".join(f"{name}:\t{item}\n" for name, item in status.items())
    )
    try:
        assert check() is False
    finally:
        globals_map["Path"] = original_path


def test_packaged_probe_binds_swap_and_tmpfs_mount_security(tmp_path: Path) -> None:
    probe_path = Path(sandbox.__file__).parent / "repair_assets" / "probe.py"
    namespace = runpy.run_path(str(probe_path))
    cgroup_raw = namespace["_cgroup_limits_match"]
    cgroup_check = cast(Callable[[dict[str, object]], bool], cgroup_raw)
    cgroup_globals = cast(dict[str, object], cast(FunctionType, cgroup_raw).__globals__)
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    (cgroup_root / "memory.max").write_text("1024\n", encoding="ascii")
    (cgroup_root / "memory.swap.max").write_text("0\n", encoding="ascii")
    (cgroup_root / "pids.max").write_text("8\n", encoding="ascii")
    (cgroup_root / "cpu.max").write_text("200000 100000\n", encoding="ascii")
    original_cgroup_root = cgroup_globals["_cgroup_root"]
    cgroup_globals["_cgroup_root"] = lambda: cgroup_root
    resources: dict[str, object] = {
        "memory_bytes": 1024,
        "pids_limit": 8,
        "nano_cpus": 2_000_000_000,
    }
    try:
        assert cgroup_check(resources)
        (cgroup_root / "memory.swap.max").write_text("1\n", encoding="ascii")
        assert not cgroup_check(resources)
    finally:
        cgroup_globals["_cgroup_root"] = original_cgroup_root

    mount_raw = namespace["_tmpfs_mount_is_secure"]
    mount_check = cast(Callable[[str], bool], mount_raw)
    mount_globals = cast(dict[str, object], cast(FunctionType, mount_raw).__globals__)
    original_path = mount_globals["Path"]
    mount_line = (
        "10 9 0:1 / /workspace rw,nosuid,nodev - tmpfs tmpfs rw,size=1024,nr_inodes=8,mode=700\n"
    )
    try:
        mount_globals["Path"] = lambda _: _TextPath(mount_line)
        assert mount_check("/workspace")
        mount_globals["Path"] = lambda _: _TextPath(mount_line.replace("nodev ", ""))
        assert not mount_check("/workspace")
    finally:
        mount_globals["Path"] = original_path


def test_fake_capability_probe_uses_only_local_read_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    outputs = iter(_docker_documents())
    calls: list[tuple[str, ...]] = []

    def invoke(
        received_config: RepairManagerConfig,
        arguments: tuple[str, ...],
        timeout: float,
    ) -> sandbox._DockerOutput:
        assert received_config is config
        assert timeout == 10.0
        calls.append(arguments)
        return sandbox._DockerOutput(0, next(outputs), b"")

    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)
    capabilities = sandbox._inspect_sandbox_capabilities(config, _policy(), invoke=invoke)

    assert capabilities.server_version == "29.6.1"
    assert capabilities.api_version == "1.55"
    assert capabilities.image_id == _IMAGE
    assert calls == [
        ("version", "--format", "{{json .}}"),
        ("info", "--format", "{{json .}}"),
        ("image", "inspect", "--format", "{{json .}}", _IMAGE),
    ]
    assert all("pull" not in call and "run" not in call for call in calls)


def test_capability_probe_rejects_nonlocked_image_before_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(_docker_documents())
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def invoke(
        _: RepairManagerConfig,
        arguments: tuple[str, ...],
        __: float,
    ) -> sandbox._DockerOutput:
        calls.append(arguments)
        return sandbox._DockerOutput(0, next(outputs), b"")

    with pytest.raises(RepairError) as captured:
        sandbox._inspect_sandbox_capabilities(
            _config(tmp_path),
            replace(_policy(), image_id=_UNLOCKED_IMAGE),
            invoke=invoke,
        )

    assert captured.value.code is RepairErrorCode.IMAGE_MISMATCH
    assert calls == []


@pytest.mark.parametrize(
    ("documents", "expected_code"),
    [
        (_docker_documents(rootless=False), RepairErrorCode.SANDBOX_UNAVAILABLE),
        (_docker_documents(image_id=f"sha256:{_HEX_B}"), RepairErrorCode.IMAGE_MISMATCH),
    ],
)
def test_capability_probe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    documents: tuple[bytes, ...],
    expected_code: RepairErrorCode,
) -> None:
    outputs = iter(documents)
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def invoke(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        return sandbox._DockerOutput(0, next(outputs), b"")

    with pytest.raises(RepairError) as captured:
        sandbox._inspect_sandbox_capabilities(_config(tmp_path), _policy(), invoke=invoke)

    assert captured.value.code is expected_code
    assert captured.value.stage is RepairStage.SANDBOX
    assert str(captured.value) in {
        "repair sandbox is unavailable",
        "repair validation image does not match",
    }


def test_prepare_sandbox_runs_packaged_probe_and_removes_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, probe, seccomp = _asset_files(tmp_path)
    documents = iter(_docker_documents())
    process = _FakeDockerProcess(_probe_frame())
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def inspect_capability(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        return sandbox._DockerOutput(0, next(documents), b"")

    capabilities = sandbox._prepare_sandbox(
        _config(tmp_path),
        _policy(),
        probe_path=probe,
        seccomp_path=seccomp,
        capability_invoke=inspect_capability,
        process_invoke=process,
        secrets_value=_secrets(),
    )

    assert capabilities.image_id == _IMAGE
    assert process.events == ["create", "inspect", "start", "inspect", "wait", "remove"]
    create_argv, _, _, _ = process.calls[0]
    assert "--pull=never" in create_argv
    assert "--network=none" in create_argv
    start_call = process.calls[2]
    assert start_call[1].startswith(sandbox._BOOTSTRAP_MAGIC)
    assert start_call[2] == 30.0


@pytest.mark.parametrize(
    ("start_stdout", "remove_returncode"),
    [
        (b"invalid-probe-report", 0),
        (_probe_frame(), 1),
    ],
)
def test_prepare_sandbox_fails_closed_and_attempts_probe_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    start_stdout: bytes,
    remove_returncode: int,
) -> None:
    _, probe, seccomp = _asset_files(tmp_path)
    documents = iter(_docker_documents())
    process = _FakeDockerProcess(
        start_stdout,
        remove_returncode=remove_returncode,
    )
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def inspect_capability(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        return sandbox._DockerOutput(0, next(documents), b"")

    with pytest.raises(RepairError) as captured:
        sandbox._prepare_sandbox(
            _config(tmp_path),
            _policy(),
            probe_path=probe,
            seccomp_path=seccomp,
            capability_invoke=inspect_capability,
            process_invoke=process,
            secrets_value=_secrets(),
        )

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert process.events[-1] == "remove"


def test_probe_rechecks_mount_identity_after_container_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, probe, seccomp = _asset_files(tmp_path)
    documents = iter(_docker_documents())
    process = _FakeDockerProcess(_probe_frame())
    monkeypatch.setattr(sandbox, "_require_owned_socket", lambda _: None)

    def inspect_capability(
        _: RepairManagerConfig,
        __: tuple[str, ...],
        ___: float,
    ) -> sandbox._DockerOutput:
        return sandbox._DockerOutput(0, next(documents), b"")

    checks = 0

    def replace_mount_after_create() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise RepairError(RepairErrorCode.SESSION_CORRUPT, RepairStage.PERSISTENCE)

    with pytest.raises(RepairError) as captured:
        sandbox._prepare_sandbox(
            _config(tmp_path),
            _policy(),
            probe_path=probe,
            seccomp_path=seccomp,
            capability_invoke=inspect_capability,
            process_invoke=process,
            secrets_value=_secrets(),
            mount_identity_check=replace_mount_after_create,
        )

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert process.events == ["create", "remove"]


def test_validation_rechecks_mount_identity_before_and_after_create(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    observed_events: list[tuple[str, ...]] = []

    def check_mounts() -> None:
        observed_events.append(tuple(process.events))

    _validate_with_fake(
        tmp_path,
        process,
        mount_identity_check=check_mounts,
    )

    assert observed_events[:5] == [
        (),
        (),
        ("create",),
        ("create", "inspect"),
        ("create", "inspect"),
    ]


def test_validation_mount_replacement_after_create_removes_container(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    checks = 0

    def replace_mount_after_create() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise RepairError(RepairErrorCode.SESSION_CORRUPT, RepairStage.PERSISTENCE)

    with pytest.raises(RepairError) as captured:
        _validate_with_fake(
            tmp_path,
            process,
            mount_identity_check=replace_mount_after_create,
        )

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert process.events == ["create", "remove"]


def test_post_create_mount_failure_persists_id_before_failed_removal(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(
        _authenticated_frame(_report_mapping()),
        remove_returncode=1,
    )
    checks = 0
    registered: list[sandbox._SandboxRunIdentity] = []

    def replace_mount_after_create() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise RepairError(RepairErrorCode.SESSION_CORRUPT, RepairStage.PERSISTENCE)

    def register_run(identity: sandbox._SandboxRunIdentity) -> bool:
        registered.append(identity)
        return True

    with pytest.raises(RepairError) as captured:
        _validate_with_fake(
            tmp_path,
            process,
            register_run=register_run,
            mount_identity_check=replace_mount_after_create,
        )

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert registered[0].container_id == _HEX_C
    assert process.events == ["create", "remove"]


def test_validation_lifecycle_fences_identity_and_result_before_removal(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    observed_identity: list[sandbox._SandboxRunIdentity] = []
    observed_outcome: list[sandbox._SandboxValidationOutcome] = []

    def register(identity: sandbox._SandboxRunIdentity) -> bool:
        process.events.append("register")
        observed_identity.append(identity)
        return True

    def persist(outcome: sandbox._SandboxValidationOutcome) -> None:
        process.events.append("persist")
        observed_outcome.append(outcome)

    outcome = _validate_with_fake(
        tmp_path,
        process,
        register_run=register,
        before_remove=persist,
    )

    assert process.events == [
        "create",
        "register",
        "inspect",
        "start",
        "inspect",
        "wait",
        "persist",
        "remove",
    ]
    assert outcome.report.success
    assert outcome.policy_sha256 == _domain_digest(
        "policy",
        validation_policy_to_dict(_policy()),
    )
    assert outcome.sandbox_manifest_sha256 == _capabilities().sandbox_manifest_sha256
    assert outcome.image_id == _IMAGE
    assert not outcome.cleanup_pending
    assert observed_identity == [outcome.run_identity]
    assert observed_outcome[0].report == outcome.report
    assert observed_outcome[0].run_identity == outcome.run_identity
    assert observed_outcome[0].cleanup_pending is True
    assert all(not hasattr(outcome.report, name) for name in ("stdout", "stderr", "hmac_key"))
    start_argv, bootstrap, timeout, limit = process.calls[2]
    assert start_argv[-1] == _HEX_C
    assert bootstrap.startswith(sandbox._BOOTSTRAP_MAGIC)
    assert timeout == 900.0
    assert limit == sandbox._MAX_REPORT_FRAME_BYTES


@pytest.mark.parametrize(
    "failure_kind",
    [
        ValidationFailureKind.COMMAND_TIMEOUT,
        ValidationFailureKind.COMMAND_SIGNAL,
        ValidationFailureKind.OUTPUT_LIMIT,
        ValidationFailureKind.RESOURCE_LIMIT,
        ValidationFailureKind.RESIDUAL_PROCESS,
        ValidationFailureKind.TRACKED_TREE_CHANGED,
    ],
)
def test_authenticated_validation_failures_preserve_safe_result_mapping(
    tmp_path: Path,
    failure_kind: ValidationFailureKind,
) -> None:
    mapping = _report_mapping(success=False, failure_kind=failure_kind.value)
    command_results = cast(list[dict[str, object]], mapping["command_results"])
    oom_killed = False
    if failure_kind is ValidationFailureKind.COMMAND_TIMEOUT:
        mapping["command_results"] = []
    elif failure_kind is ValidationFailureKind.COMMAND_SIGNAL:
        command_results[0]["exit_code"] = None
        command_results[0]["signal"] = 9
    elif failure_kind is ValidationFailureKind.OUTPUT_LIMIT:
        command_results[0]["stdout_bytes"] = _policy().stream_output_bytes + 1
        command_results[0]["stdout_truncated"] = True
    elif failure_kind is ValidationFailureKind.RESOURCE_LIMIT:
        mapping["oom_killed"] = True
        oom_killed = True
    elif failure_kind is ValidationFailureKind.RESIDUAL_PROCESS:
        mapping["residual_process_count"] = 1
    else:
        mapping["tracked_tree_clean"] = False
    process = _FakeDockerProcess(
        _authenticated_frame(mapping),
        oom_killed=oom_killed,
    )

    outcome = _validate_with_fake(tmp_path, process)

    assert not outcome.report.success
    assert outcome.report.failure_kind is failure_kind
    assert not outcome.cleanup_pending


@pytest.mark.parametrize(
    (
        "start_returncode",
        "start_timed_out",
        "start_output_limit",
        "expected_failure",
        "expected_watchdog",
    ),
    [
        (0, False, False, ValidationFailureKind.SANDBOX_REPORT_INVALID, False),
        (70, False, False, ValidationFailureKind.SANDBOX_RUNTIME_FAILED, False),
        (0, True, False, ValidationFailureKind.COMMAND_TIMEOUT, True),
        (0, False, True, ValidationFailureKind.SANDBOX_REPORT_INVALID, True),
    ],
)
def test_unreported_or_host_watchdog_failures_are_content_free(
    tmp_path: Path,
    start_returncode: int,
    start_timed_out: bool,
    start_output_limit: bool,
    expected_failure: ValidationFailureKind,
    expected_watchdog: bool,
) -> None:
    process = _FakeDockerProcess(
        b"not-an-authenticated-frame",
        start_returncode=start_returncode,
        start_timed_out=start_timed_out,
        start_output_limit=start_output_limit,
    )

    outcome = _validate_with_fake(tmp_path, process)

    assert not outcome.report.success
    assert outcome.report.failure_kind is expected_failure
    assert outcome.report.command_results == ()
    assert outcome.report.peak_memory_bytes == 0
    assert ("stop" in process.events and "kill" in process.events) is expected_watchdog
    assert process.events[-1] == "remove"


@pytest.mark.parametrize("failure_point", ["start", "terminal_inspect"])
def test_docker_infrastructure_errors_propagate_after_exact_cleanup(
    tmp_path: Path,
    failure_point: str,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))

    def fail_docker_boundary(
        argv: tuple[str, ...],
        stdin: bytes,
        timeout_seconds: float,
        stream_limit: int,
    ) -> sandbox._BoundedProcessResult:
        command = argv[3:]
        if failure_point == "start" and command[0] == "start":
            raise RepairError(RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX)
        if (
            failure_point == "terminal_inspect"
            and command[:2] == ("container", "inspect")
            and process.state == "exited"
        ):
            raise RepairError(RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX)
        return process(argv, stdin, timeout_seconds, stream_limit)

    runner, _, seccomp = _asset_files(tmp_path)
    candidate, git_dir, index_file, tracked, index_sha256 = _candidate_inputs(tmp_path)
    with pytest.raises(RepairError) as captured:
        sandbox._run_sandbox_validation(
            _config(tmp_path),
            _policy(),
            _capabilities(),
            session_id=_HEX_A,
            candidate_id=_HEX_B,
            candidate_root=candidate,
            git_dir=git_dir,
            index_file=index_file,
            runner_path=runner,
            seccomp_path=seccomp,
            tracked_inputs=tracked,
            git_index_sha256=index_sha256,
            expected_tree_oid="d" * 40,
            register_intent=_accept_intent,
            register_run=_accept_run,
            release_intent=_release_intent,
            release_run=_release_run,
            before_remove=_ignore_outcome,
            process_invoke=fail_docker_boundary,
            secrets_value=_secrets(),
        )

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert process.events[-1] == "remove"


def test_validation_reports_cleanup_pending_after_exact_remove_failure(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(
        _authenticated_frame(_report_mapping()),
        remove_returncode=1,
    )

    outcome = _validate_with_fake(tmp_path, process)

    assert outcome.report.success
    assert outcome.cleanup_pending
    assert process.events[-1] == "remove"


def test_validation_intent_is_registered_before_docker_create_and_id_binding(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    observed_intents: list[sandbox._SandboxRunIntent] = []

    def register_intent(intent: sandbox._SandboxRunIntent) -> bool:
        assert process.events == []
        observed_intents.append(intent)
        return True

    def register_run(identity: sandbox._SandboxRunIdentity) -> bool:
        assert process.events == ["create"]
        assert observed_intents == [
            sandbox._SandboxRunIntent(
                identity.container_name,
                identity.labels,
                identity.session_id,
                identity.candidate_id,
                identity.run_token_sha256,
            )
        ]
        return True

    outcome = _validate_with_fake(
        tmp_path,
        process,
        register_intent=register_intent,
        register_run=register_run,
    )

    assert outcome.run_identity.container_id == _HEX_C
    assert observed_intents[0].run_token_sha256 == outcome.run_identity.run_token_sha256


def test_rejected_validation_intent_never_calls_docker(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))

    with pytest.raises(sandbox._SandboxRunRejected):
        _validate_with_fake(
            tmp_path,
            process,
            register_intent=lambda _: False,
        )

    assert process.events == []


def test_unparseable_create_id_is_removed_by_exact_intent_before_release(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(
        _authenticated_frame(_report_mapping()),
        create_stdout=b"not-a-container-id\n",
    )
    released: list[sandbox._SandboxRunIntent] = []

    def release_intent(intent: sandbox._SandboxRunIntent) -> bool:
        released.append(intent)
        return True

    with pytest.raises(RepairError) as captured:
        _validate_with_fake(
            tmp_path,
            process,
            release_intent=release_intent,
        )

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert process.events == ["create", "inspect", "remove"]
    assert len(released) == 1
    assert released[0].container_name == process.container_name


def test_timed_out_create_with_empty_immediate_lookup_retains_intent(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(
        _authenticated_frame(_report_mapping()),
        create_stdout=b"",
        create_timed_out=True,
    )
    released: list[sandbox._SandboxRunIntent] = []

    def release_intent(intent: sandbox._SandboxRunIntent) -> bool:
        released.append(intent)
        return True

    with pytest.raises(RepairError) as captured:
        _validate_with_fake(
            tmp_path,
            process,
            release_intent=release_intent,
        )

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert process.events == ["create", "inspect", "list"]
    assert released == []


def test_timed_out_create_removes_exact_container_that_appears_during_lookup(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(
        _authenticated_frame(_report_mapping()),
        create_stdout=b"",
        create_timed_out=True,
        late_list_visibility=True,
    )
    released: list[sandbox._SandboxRunIntent] = []

    def release_intent(intent: sandbox._SandboxRunIntent) -> bool:
        released.append(intent)
        return True

    with pytest.raises(RepairError) as captured:
        _validate_with_fake(
            tmp_path,
            process,
            release_intent=release_intent,
        )

    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert process.events == ["create", "inspect", "list", "inspect", "remove"]
    assert len(released) == 1
    assert released[0].container_name == process.container_name


def test_rejected_run_fence_never_starts_and_still_removes_exact_container(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    released: list[sandbox._SandboxRunIdentity] = []

    def release_run(identity: sandbox._SandboxRunIdentity) -> bool:
        released.append(identity)
        return True

    with pytest.raises(sandbox._SandboxRunRejected):
        _validate_with_fake(
            tmp_path,
            process,
            register_run=lambda _: False,
            release_run=release_run,
        )

    assert process.events == ["create", "remove"]
    assert len(released) == 1
    assert released[0].container_id == _HEX_C
    assert released[0].container_name == process.container_name


def test_exact_cleanup_is_idempotent_for_absent_container_and_rejects_label_drift(
    tmp_path: Path,
) -> None:
    process = _FakeDockerProcess(_authenticated_frame(_report_mapping()))
    outcome = _validate_with_fake(tmp_path, process)

    assert sandbox._remove_exact_container(
        _config(tmp_path),
        outcome.run_identity,
        process_invoke=process,
    )
    assert process.events[-2:] == ["inspect", "list"]

    process.state = "exited"
    process.labels[sandbox._RUN_TOKEN_LABEL] = _HEX_A
    assert not sandbox._remove_exact_container(
        _config(tmp_path),
        outcome.run_identity,
        process_invoke=process,
    )
    assert process.events[-1] == "inspect"

    process.labels = dict(outcome.run_identity.labels)
    assert sandbox._stop_exact_container(
        _config(tmp_path),
        outcome.run_identity,
        process_invoke=process,
    )
    assert process.events[-3:] == ["inspect", "stop", "kill"]


def test_bounded_process_drains_exact_stdin_stdout_and_stderr() -> None:
    result = sandbox._run_bounded_process(
        (
            sys.executable,
            "-I",
            "-c",
            (
                "import sys;"
                "data=sys.stdin.buffer.read();"
                "sys.stdout.buffer.write(data.upper());"
                "sys.stderr.buffer.write(b'fixed-stderr')"
            ),
        ),
        environment={"PATH": "/usr/bin:/bin"},
        stdin=b"bounded input",
        timeout_seconds=2.0,
        stream_limit=1_024,
    )

    assert result.returncode == 0
    assert result.stdout == b"BOUNDED INPUT"
    assert result.stderr == b"fixed-stderr"
    assert not result.timed_out
    assert not result.output_limit


def test_bounded_process_enforces_output_and_time_limits() -> None:
    output_limited = sandbox._run_bounded_process(
        (sys.executable, "-I", "-c", "import sys;sys.stdout.buffer.write(b'x'*4096)"),
        environment={"PATH": "/usr/bin:/bin"},
        stdin=b"",
        timeout_seconds=2.0,
        stream_limit=32,
    )
    timed_out = sandbox._run_bounded_process(
        (sys.executable, "-I", "-c", "import time;time.sleep(5)"),
        environment={"PATH": "/usr/bin:/bin"},
        stdin=b"",
        timeout_seconds=0.05,
        stream_limit=32,
    )

    assert output_limited.stdout == b"x" * 32
    assert output_limited.output_limit
    assert timed_out.timed_out


def test_bounded_process_rejects_invalid_input_and_unavailable_executable() -> None:
    with pytest.raises(TypeError):
        sandbox._run_bounded_process(
            (),
            environment={},
            stdin=b"",
            timeout_seconds=1.0,
            stream_limit=1,
        )
    with pytest.raises(RepairError) as captured:
        sandbox._run_bounded_process(
            ("/definitely/not/a/repoguard-executable",),
            environment={},
            stdin=b"",
            timeout_seconds=1.0,
            stream_limit=1,
        )
    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    _assert_detached_sandbox_error(captured.value)


def test_exception_handlers_never_raise_public_sandbox_errors_directly() -> None:
    source = Path(sandbox.__file__).read_text(encoding="utf-8")
    visitor = _ExceptSandboxErrorVisitor()
    visitor.visit(ast.parse(source))
    assert visitor.lines == []


def test_docker_wrapper_uses_fixed_prefix_and_maps_transport_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_argv: list[tuple[str, ...]] = []
    results = iter(
        (
            sandbox._BoundedProcessResult(0, b"document", b"", False, False),
            sandbox._BoundedProcessResult(-15, b"", b"", True, False),
        )
    )

    def run(
        argv: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        stdin: bytes,
        timeout_seconds: float,
        stream_limit: int,
    ) -> sandbox._BoundedProcessResult:
        assert environment == sandbox._HOST_DOCKER_ENVIRONMENT
        assert stdin == b""
        assert timeout_seconds == 1.0
        assert stream_limit == sandbox._MAX_DOCKER_OUTPUT_BYTES
        observed_argv.append(argv)
        return next(results)

    monkeypatch.setattr(sandbox, "_run_bounded_process", run)
    output = sandbox._invoke_docker(_config(tmp_path), ("info",), 1.0)
    with pytest.raises(RepairError) as captured:
        sandbox._invoke_docker(_config(tmp_path), ("info",), 1.0)

    assert output == sandbox._DockerOutput(0, b"document", b"")
    assert observed_argv[0][:4] == (
        "/usr/bin/docker",
        "--host",
        f"unix://{_config(tmp_path).rootless_socket}",
        "info",
    )
    assert captured.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE


def test_low_level_parsers_and_filesystem_guards_fail_closed(tmp_path: Path) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"content")
    directory = tmp_path / "directory"
    directory.mkdir()

    for raw in (
        b"",
        b"\xff",
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
    ):
        with pytest.raises(ValueError):
            sandbox._parse_json_object(raw, 128)
    with pytest.raises(ValueError):
        sandbox._parse_canonical_object(b'{"a": 1}')
    with pytest.raises(ValueError):
        sandbox._parse_wait_exit_code(cast(bytes, "0"))
    with pytest.raises(ValueError):
        sandbox._parse_wait_exit_code(b"0\n1\n")
    with pytest.raises(TypeError):
        sandbox._resource_digest("", b"value")
    with pytest.raises(ValueError):
        sandbox._require_mount_path(Path("relative"), expected_directory=False)
    with pytest.raises(ValueError):
        sandbox._require_mount_path(tmp_path / "missing", expected_directory=False)
    with pytest.raises(ValueError):
        sandbox._require_mount_path(directory, expected_directory=False)
    with pytest.raises(ValueError):
        sandbox._require_labels(())
    with pytest.raises(ValueError):
        sandbox._require_labels((("duplicate", "a"), ("duplicate", "b")))
    with pytest.raises(ValueError):
        sandbox._require_tracked_inputs(
            (
                sandbox._TrackedInput("b.py", _HEX_A, False),
                sandbox._TrackedInput("a.py", _HEX_B, False),
            )
        )
    with pytest.raises(TypeError):
        sandbox._require_tracked_inputs(cast(tuple[sandbox._TrackedInput, ...], (object(),)))
    with pytest.raises(TypeError):
        sandbox._regular_file_digest(regular, maximum_bytes=cast(int, True))
    with pytest.raises(ValueError):
        sandbox._regular_file_digest(tmp_path / "missing")
    with pytest.raises(ValueError):
        sandbox._regular_file_digest(directory)
    with pytest.raises(ValueError):
        sandbox._regular_file_digest(regular, maximum_bytes=1)
    with pytest.raises(RepairError):
        sandbox._require_exact_asset_path(regular, b"different")
    with pytest.raises(ValueError):
        sandbox._require_exact_file_digest(regular, _HEX_A)

    projection = tmp_path / "projection"
    projection.mkdir()
    (projection / ".git").mkdir()
    with pytest.raises(ValueError):
        sandbox._require_candidate_projection(projection)


def test_remaining_platform_protocol_and_helper_guards_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _run_identity()
    process = _FakeDockerProcess(b"")
    process.state = "created"
    process.labels = dict(identity.labels)
    created_document = process._inspect_document()

    with pytest.raises(TypeError):
        sandbox._inspect_sandbox_capabilities(
            cast(RepairManagerConfig, object()),
            _policy(),
        )
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(RepairError) as unsupported_os:
        sandbox._inspect_sandbox_capabilities(_config(tmp_path), _policy())
    assert unsupported_os.value.code is RepairErrorCode.UNSUPPORTED_PLATFORM
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    with pytest.raises(RepairError) as unsupported_arch:
        sandbox._inspect_sandbox_capabilities(_config(tmp_path), _policy())
    assert unsupported_arch.value.code is RepairErrorCode.UNSUPPORTED_PLATFORM

    generated = sandbox._new_sandbox_secrets()
    assert len(generated.nonce) == len(generated.hmac_key) == len(generated.run_token) == 32
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_report_frame(
            _authenticated_frame(_report_mapping()),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
            expected_command_count=0,
        )
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_probe_frame(
            _probe_frame(),
            expected_nonce=b"short",
            hmac_key=_KEY,
        )
    invalid_probe = {
        "schema_version": 1,
        "nonce": _NONCE.hex(),
        "success": True,
        "checks": list(sandbox._PROBE_CHECKS),
        "extra": True,
    }
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_probe_frame(
            _authenticated_frame(invalid_probe),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
        )
    with pytest.raises(TypeError):
        sandbox._corroborate_container_result(
            cast(sandbox._SandboxReport, object()),
            b"{}",
            b"0\n",
            expected_container_id=_HEX_C,
            expected_labels=identity.labels,
        )
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._corroborate_created_container(
            created_document,
            expected_container_id=_HEX_C,
            expected_labels=identity.labels,
            expected_policy=ValidationPolicy(
                image_id=f"sha256:{_HEX_B}",
                commands=_policy().commands,
            ),
            expected_command=("-I", "-S", "-E", "-B", "/opt/repoguard/runner.py"),
            expected_bind_mounts=_DEFAULT_BIND_MOUNTS,
        )
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_container_state(
            created_document,
            expected_container_id="short",
            expected_labels=identity.labels,
        )
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_container_state(
            created_document,
            expected_container_id=_HEX_B,
            expected_labels=identity.labels,
        )
    with pytest.raises(TypeError):
        sandbox._invoke_docker(
            _config(tmp_path),
            cast(tuple[str, ...], ["info"]),
            1.0,
        )
    with pytest.raises(TypeError):
        sandbox._validate_report_against_policy(
            cast(sandbox._SandboxReport, object()),
            _policy(),
        )
    with pytest.raises(RepairError) as missing_socket:
        sandbox._require_owned_socket(tmp_path / "missing.sock")
    _assert_detached_sandbox_error(missing_socket.value)
    regular = tmp_path / "not-a-socket"
    regular.write_bytes(b"")
    with pytest.raises(RepairError):
        sandbox._require_owned_socket(regular)
    with pytest.raises(ValueError):
        sandbox._mapping_field({"field": "not-a-mapping"}, "field")
    for helper, value in (
        (sandbox._exact_string, 1),
        (sandbox._exact_bool, 1),
        (sandbox._exact_nonnegative_int, -1),
        (sandbox._exact_sha256, 1),
    ):
        with pytest.raises(ValueError):
            helper(value)
    with pytest.raises(ValueError):
        sandbox._require_sha256("invalid")

    class EmptyResource:
        def read_bytes(self) -> bytes:
            return b""

    class BrokenResource:
        def read_bytes(self) -> bytes:
            raise OSError

    with pytest.raises(RepairError):
        sandbox._read_asset(cast(Traversable, EmptyResource()))
    with pytest.raises(RepairError) as broken_asset:
        sandbox._read_asset(cast(Traversable, BrokenResource()))
    _assert_detached_sandbox_error(broken_asset.value)


def test_invocation_guards_reject_partial_mounts_and_non_authoritative_index(
    tmp_path: Path,
) -> None:
    runner, _, seccomp = _asset_files(tmp_path)
    candidate, git_dir, index_file, tracked, index_sha256 = _candidate_inputs(tmp_path)
    wrong_index = git_dir / "index"
    wrong_index.write_bytes(index_file.read_bytes())

    with pytest.raises(ValueError):
        sandbox._container_create_arguments(
            _policy(),
            container_name="repoguard-test",
            labels=((sandbox._COMPONENT_LABEL, sandbox._COMPONENT_VALUE),),
            script_host_path=runner,
            seccomp_path=seccomp,
            candidate_root=candidate,
            git_dir=None,
            git_index_file=None,
            script_path="/opt/repoguard/runner.py",
        )
    with pytest.raises(ValueError):
        sandbox._build_validation_invocation(
            _config(tmp_path),
            _policy(),
            session_id=_HEX_A,
            candidate_id=_HEX_B,
            candidate_root=candidate,
            git_dir=git_dir,
            index_file=wrong_index,
            runner_path=runner,
            seccomp_path=seccomp,
            tracked_inputs=tracked,
            git_index_sha256=index_sha256,
            expected_tree_oid="d" * 40,
            secrets_value=_secrets(),
        )
    with pytest.raises(ValueError):
        sandbox._build_validation_invocation(
            _config(tmp_path),
            _policy(),
            session_id=_HEX_A,
            candidate_id=_HEX_B,
            candidate_root=candidate,
            git_dir=git_dir,
            index_file=index_file,
            runner_path=runner,
            seccomp_path=seccomp,
            tracked_inputs=tracked,
            git_index_sha256=index_sha256,
            expected_tree_oid="invalid",
            secrets_value=_secrets(),
        )


def test_validation_invocation_fixes_all_security_and_resource_flags(tmp_path: Path) -> None:
    candidate = tmp_path / 'candidate,with"quote'
    git_dir = tmp_path / "git"
    candidate.mkdir()
    git_dir.mkdir()
    index_file = git_dir / "repoguard-index"
    index_file.write_bytes(b"index")
    runner = tmp_path / "runner.py"
    runner.write_text("pass\n", encoding="utf-8")
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}\n", encoding="utf-8")
    invocation = sandbox._build_validation_invocation(
        _config(tmp_path),
        _policy(),
        session_id=_HEX_B,
        candidate_id=_HEX_C,
        candidate_root=candidate,
        git_dir=git_dir,
        index_file=index_file,
        runner_path=runner,
        seccomp_path=seccomp,
        tracked_inputs=(),
        git_index_sha256=_HEX_A,
        expected_tree_oid="d" * 40,
        secrets_value=_secrets(),
    )

    create = invocation.create_argv
    assert create[:5] == (
        "/usr/bin/docker",
        "--host",
        f"unix://{_config(tmp_path).rootless_socket}",
        "create",
        "--pull=never",
    )
    for required in (
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--network=none",
        "--ipc=private",
        "--read-only",
        "--memory=2147483648",
        "--memory-swap=2147483648",
        "--cpus=2.000000000",
        "--pids-limit=128",
        "--restart=no",
        "--no-healthcheck",
        "--interactive",
        "--entrypoint=/usr/local/bin/python3.12",
    ):
        assert required in create
    assert "--pid=private" not in create
    assert create[-6:] == (
        _IMAGE,
        "-I",
        "-S",
        "-E",
        "-B",
        "/opt/repoguard/runner.py",
    )
    assert any(
        '"source=' in argument and 'candidate,with""quote' in argument for argument in create
    )
    assert any(
        "source=" in argument
        and "repoguard-index" in argument
        and "destination=/input/git/index" in argument
        for argument in create
    )
    assert all("http_proxy" not in argument.lower() for argument in create)
    assert invocation.start_argv[-4:] == (
        "start",
        "--attach",
        "--interactive",
        invocation.container_name,
    )
    assert invocation.remove_argv[-4:] == (
        "rm",
        "--force",
        "--volumes",
        invocation.container_name,
    )
    assert _RUN_TOKEN.hex().encode() not in invocation.bootstrap
    assert _KEY.hex().encode() in invocation.bootstrap


@pytest.mark.parametrize(
    ("nano_cpus", "expected"),
    [
        (1, "0.000000001"),
        (999_999_999, "0.999999999"),
        (1_000_000_000, "1.000000000"),
        (2_000_000_000, "2.000000000"),
    ],
)
def test_nano_cpu_policy_uses_docker_create_cpus_syntax(
    nano_cpus: int,
    expected: str,
) -> None:
    assert sandbox._nano_cpus_to_cpus(nano_cpus) == expected


@pytest.mark.parametrize("value", [0, -1, True, 1.0])
def test_nano_cpu_formatter_rejects_invalid_values(value: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        sandbox._nano_cpus_to_cpus(cast(int, value))


def test_probe_invocation_has_no_repository_mount(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text("pass\n", encoding="utf-8")
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text("{}\n", encoding="utf-8")

    invocation = sandbox._build_probe_invocation(
        _config(tmp_path),
        _policy(),
        probe_path=probe,
        seccomp_path=seccomp,
        secrets_value=_secrets(),
    )

    assert "/input/repository" not in " ".join(invocation.create_argv)
    assert "/input/git" not in " ".join(invocation.create_argv)
    assert invocation.create_argv[-1] == "/opt/repoguard/probe.py"
    assert dict(invocation.labels)[sandbox._COMPONENT_LABEL] == sandbox._PROBE_COMPONENT_VALUE


def test_authenticated_report_round_trips_without_raw_output() -> None:
    report = sandbox._parse_report_frame(
        _authenticated_frame(_report_mapping()),
        expected_nonce=_NONCE,
        hmac_key=_KEY,
        expected_command_count=1,
    )

    assert report.success
    assert report.failure_kind is None
    assert report.command_results[0].stdout_sha256 == hashlib.sha256(b"").hexdigest()
    assert not hasattr(report.command_results[0], "stdout")
    assert not hasattr(report.command_results[0], "stderr")


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "nonce",
        "timestamp",
        "results_type",
        "success_semantics",
        "failure_semantics",
    ],
)
def test_authenticated_report_rejects_invalid_inner_semantics(mutation: str) -> None:
    mapping = _report_mapping()
    if mutation == "schema":
        mapping["schema_version"] = 2
    elif mutation == "nonce":
        mapping["nonce"] = _HEX_A
    elif mutation == "timestamp":
        mapping["finished_at_us"] = 99
    elif mutation == "results_type":
        mapping["command_results"] = {}
    elif mutation == "success_semantics":
        mapping["tracked_tree_clean"] = False
    else:
        mapping["success"] = False
        mapping["failure_kind"] = None

    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_report_frame(
            _authenticated_frame(mapping),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
            expected_command_count=1,
        )


@pytest.mark.parametrize(
    "mapping",
    [
        {
            "schema_version": 2,
            "nonce": _NONCE.hex(),
            "success": True,
            "checks": list(sandbox._PROBE_CHECKS),
        },
        {
            "schema_version": 1,
            "nonce": _HEX_A,
            "success": True,
            "checks": list(sandbox._PROBE_CHECKS),
        },
        {
            "schema_version": 1,
            "nonce": _NONCE.hex(),
            "success": True,
            "checks": "not-a-list",
        },
        {
            "schema_version": 1,
            "nonce": _NONCE.hex(),
            "success": True,
            "checks": list(reversed(sandbox._PROBE_CHECKS)),
        },
    ],
)
def test_authenticated_probe_rejects_invalid_inner_semantics(
    mapping: dict[str, object],
) -> None:
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_probe_frame(
            _authenticated_frame(mapping),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
        )


@_PROPERTY_SETTINGS
@given(index=st.integers(min_value=0, max_value=4_096))
def test_every_single_byte_frame_tamper_is_rejected(index: int) -> None:
    valid = _authenticated_frame(_report_mapping())
    position = index % len(valid)
    tampered = bytearray(valid)
    tampered[position] ^= 1

    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_report_frame(
            bytes(tampered),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
            expected_command_count=1,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value + b"\n",
        lambda value: b"prefix" + value,
        lambda value: value[:-1],
    ],
)
def test_report_rejects_prefix_suffix_and_truncation(
    mutate: Callable[[bytes], bytes],
) -> None:
    frame = _authenticated_frame(_report_mapping())

    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_report_frame(
            mutate(frame),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
            expected_command_count=1,
        )


def test_authenticated_failure_requires_matching_safe_evidence() -> None:
    result = cast(
        list[dict[str, object]],
        _report_mapping()["command_results"],
    )
    result[0]["exit_code"] = 3
    report = sandbox._parse_report_frame(
        _authenticated_frame(
            _report_mapping(
                success=False,
                failure_kind="command_exit_nonzero",
                command_results=result,
            )
        ),
        expected_nonce=_NONCE,
        hmac_key=_KEY,
        expected_command_count=1,
    )
    assert report.failure_kind is ValidationFailureKind.COMMAND_EXIT_NONZERO

    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._parse_report_frame(
            _authenticated_frame(
                _report_mapping(success=False, failure_kind="command_exit_nonzero")
            ),
            expected_nonce=_NONCE,
            hmac_key=_KEY,
            expected_command_count=1,
        )


def test_probe_frame_and_container_readback_are_strict() -> None:
    probe_frame = _authenticated_frame(
        {
            "schema_version": 1,
            "nonce": _NONCE.hex(),
            "success": True,
            "checks": list(sandbox._PROBE_CHECKS),
        }
    )
    assert sandbox._parse_probe_frame(
        probe_frame,
        expected_nonce=_NONCE,
        hmac_key=_KEY,
    ).success

    report = sandbox._parse_report_frame(
        _authenticated_frame(_report_mapping()),
        expected_nonce=_NONCE,
        hmac_key=_KEY,
        expected_command_count=1,
    )
    labels = (
        (sandbox._COMPONENT_LABEL, sandbox._COMPONENT_VALUE),
        (sandbox._SESSION_LABEL, _HEX_B),
    )
    inspect = {
        "Id": _HEX_C,
        "Config": {"Labels": dict(labels)},
        "State": {
            "Running": False,
            "Status": "exited",
            "ExitCode": 0,
            "OOMKilled": False,
            "Pid": 0,
            "Error": "",
            "StartedAt": "2026-07-29T00:00:00Z",
            "FinishedAt": "2026-07-29T00:00:01Z",
        },
    }
    sandbox._corroborate_container_result(
        report,
        json.dumps(inspect).encode(),
        b"0\n",
        expected_container_id=_HEX_C,
        expected_labels=labels,
    )

    inspect["State"]["ExitCode"] = 1  # type: ignore[index]
    with pytest.raises(sandbox._SandboxProtocolError):
        sandbox._corroborate_container_result(
            report,
            json.dumps(inspect).encode(),
            b"0\n",
            expected_container_id=_HEX_C,
            expected_labels=labels,
        )
