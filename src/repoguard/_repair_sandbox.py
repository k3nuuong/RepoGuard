"""Rootless Docker capability, invocation, and authenticated report boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import BinaryIO, Never, cast

from repoguard._repair_models import _canonical_bytes, _domain_digest
from repoguard._repair_paths import _path_sort_key, _validate_repository_path
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairManagerConfig,
    RepairStage,
    ValidationCommandResult,
    ValidationFailureKind,
    ValidationPolicy,
    validation_policy_to_dict,
)

_ASSET_DIRECTORY = ("repair_assets",)
_RUNNER_RESOURCE = "runner.py"
_PROBE_RESOURCE = "probe.py"
_SECCOMP_RESOURCE = "seccomp-v1.json"
_MANIFEST_RESOURCE = "manifest.json"
_IMAGE_LOCK_DIRECTORY = "validation_image_v1"
_IMAGE_LOCK_RESOURCE = "image-lock.json"

_BOOTSTRAP_MAGIC = b"RGB1"
_REPORT_MAGIC = b"RGR1"
_FRAME_HEADER = struct.Struct(">4sQ")
_HMAC_BYTES = 32
_SECRET_BYTES = 32
_MAX_BOOTSTRAP_BYTES = 8 * 1_048_576
_MAX_REPORT_BYTES = 262_144
_MAX_DOCKER_OUTPUT_BYTES = 1_048_576
_MAX_ASSET_BYTES = 524_288
_DOCKER_TIMEOUT_SECONDS = 10.0
_PROBE_TIMEOUT_SECONDS = 30.0
_MAX_REPORT_FRAME_BYTES = _FRAME_HEADER.size + _MAX_REPORT_BYTES + _HMAC_BYTES
_REPORT_HMAC_DOMAIN = b"repoguard.m5.sandbox-report.v1\x00"
_RESOURCE_DOMAIN_PREFIX = "repoguard.m5.sandbox-resource"

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CONTAINER_ID_PATTERN = _SHA256_PATTERN
_SUPPORTED_ARCHITECTURES = frozenset({"amd64", "x86_64"})

_COMPONENT_LABEL = "com.repoguard.component"
_SESSION_LABEL = "com.repoguard.session"
_CANDIDATE_LABEL = "com.repoguard.candidate"
_RUN_TOKEN_LABEL = "com.repoguard.run-token-sha256"
_COMPONENT_VALUE = "safe-repair-validation"
_PROBE_COMPONENT_VALUE = "safe-repair-probe"
_PROBE_CHECKS = (
    "cgroup_limits",
    "clone3_enosys",
    "environment_clear",
    "network_denied",
    "nondumpable",
    "pid1",
    "process_security",
    "python312",
    "root_read_only",
    "seccomp_denied",
    "tmpfs_limits",
    "uid0",
    "unix_socket",
)

_CONTAINER_ENVIRONMENT: tuple[tuple[str, str], ...] = (
    ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("TZ", "UTC"),
    ("HOME", "/home/repoguard"),
    ("TMPDIR", "/tmp"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("UV_NO_CONFIG", "1"),
    ("UV_NO_PROGRESS", "1"),
    ("UV_OFFLINE", "1"),
    ("UV_PYTHON_DOWNLOADS", "never"),
    ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
    ("PIP_NO_INDEX", "1"),
    ("PIP_NO_INPUT", "1"),
)

_HOST_DOCKER_ENVIRONMENT: dict[str, str] = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
}

_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "architecture",
        "seccomp_sha256",
        "runner_sha256",
        "probe_sha256",
        "syscall_allowlist",
        "sandbox_manifest_sha256",
    }
)
_IMAGE_LOCK_KEYS = frozenset(
    {
        "base_config_digest",
        "base_index_digest",
        "base_manifest_digest",
        "base_reference",
        "dockerfile_sha256",
        "git_path",
        "git_version",
        "image_config_digest",
        "image_id",
        "image_tag",
        "platform",
        "python_path",
        "python_version",
        "schema_version",
        "source_date_epoch",
        "upstream_revision",
    }
)
_SECCOMP_KEYS = frozenset({"defaultAction", "defaultErrnoRet", "archMap", "syscalls"})
_FORBIDDEN_ALLOWED_SYSCALLS = frozenset(
    {
        "bpf",
        "chroot",
        "fanotify_init",
        "fanotify_mark",
        "init_module",
        "io_pgetevents",
        "io_setup",
        "io_submit",
        "io_uring_enter",
        "io_uring_register",
        "io_uring_setup",
        "ioperm",
        "iopl",
        "kcmp",
        "kexec_file_load",
        "kexec_load",
        "keyctl",
        "lookup_dcookie",
        "mount",
        "move_mount",
        "name_to_handle_at",
        "open_by_handle_at",
        "open_tree",
        "perf_event_open",
        "personality",
        "pivot_root",
        "process_vm_readv",
        "process_vm_writev",
        "ptrace",
        "reboot",
        "request_key",
        "setns",
        "syslog",
        "umount",
        "umount2",
        "unshare",
        "userfaultfd",
    }
)


class _SandboxProtocolError(ValueError):
    """Content-free marker for an unauthenticated or malformed sandbox result."""

    failure_kind = ValidationFailureKind.SANDBOX_REPORT_INVALID

    def __init__(self) -> None:
        super().__init__("sandbox report is invalid")


class _SandboxRunRejected(RuntimeError):
    """Content-free signal that the workflow rejected a newly created run identity."""

    def __init__(self) -> None:
        super().__init__("sandbox run was rejected")


class _ContainerCreateFailure(RuntimeError):
    """Internal create outcome retaining only cleanup-authority metadata."""

    __slots__ = ("absence_is_authoritative", "container_id")

    def __init__(
        self,
        container_id: str | None,
        *,
        absence_is_authoritative: bool,
    ) -> None:
        super().__init__("sandbox container creation failed")
        self.container_id = container_id
        self.absence_is_authoritative = absence_is_authoritative


@dataclass(frozen=True, slots=True)
class _DockerOutput:
    returncode: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if type(self.returncode) is not int:
            raise TypeError("returncode must be an exact integer")
        if type(self.stdout) is not bytes or type(self.stderr) is not bytes:
            raise TypeError("Docker output must be exact bytes")


@dataclass(frozen=True, slots=True)
class _SandboxAssets:
    runner: bytes
    probe: bytes
    seccomp_json: bytes
    sandbox_manifest_sha256: str
    syscall_allowlist: tuple[str, ...]
    locked_image_id: str


@dataclass(frozen=True, slots=True)
class _SandboxCapabilities:
    client_version: str
    server_version: str
    api_version: str
    architecture: str
    cgroup_version: str
    security_options: tuple[str, ...]
    image_id: str
    sandbox_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _TrackedInput:
    path: str
    sha256: str
    executable: bool

    def __post_init__(self) -> None:
        _validate_repository_path(self.path)
        _require_sha256(self.sha256)
        if type(self.executable) is not bool:
            raise TypeError("executable must be an exact bool")


@dataclass(frozen=True, slots=True)
class _SandboxSecrets:
    nonce: bytes
    hmac_key: bytes
    run_token: bytes
    run_token_sha256: str

    def __post_init__(self) -> None:
        for value in (self.nonce, self.hmac_key, self.run_token):
            if type(value) is not bytes or len(value) != _SECRET_BYTES:
                raise ValueError("sandbox secrets must be exact 256-bit values")
        _require_sha256(self.run_token_sha256)
        expected = _domain_digest("run-token", {"run_token": self.run_token.hex()})
        if not hmac.compare_digest(self.run_token_sha256, expected):
            raise ValueError("run-token digest does not match")


@dataclass(frozen=True, slots=True)
class _SandboxInvocation:
    container_name: str
    labels: tuple[tuple[str, str], ...]
    bind_mounts: tuple[tuple[str, str], ...]
    create_argv: tuple[str, ...]
    start_argv: tuple[str, ...]
    inspect_argv: tuple[str, ...]
    wait_argv: tuple[str, ...]
    stop_argv: tuple[str, ...]
    kill_argv: tuple[str, ...]
    remove_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    bootstrap: bytes
    nonce: bytes
    hmac_key: bytes
    run_token_sha256: str


@dataclass(frozen=True, slots=True)
class _SandboxRunIntent:
    container_name: str
    labels: tuple[tuple[str, str], ...]
    session_id: str
    candidate_id: str
    run_token_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.container_name) is not str
            or not self.container_name
            or len(self.container_name.encode("utf-8")) > 128
        ):
            raise ValueError("container_name is invalid")
        _require_labels(self.labels)
        _require_sha256(self.session_id)
        _require_sha256(self.candidate_id)
        _require_sha256(self.run_token_sha256)
        expected = {
            _COMPONENT_LABEL: _COMPONENT_VALUE,
            _SESSION_LABEL: self.session_id,
            _CANDIDATE_LABEL: self.candidate_id,
            _RUN_TOKEN_LABEL: self.run_token_sha256,
        }
        if dict(self.labels) != expected:
            raise ValueError("run intent labels are invalid")


@dataclass(frozen=True, slots=True)
class _SandboxRunIdentity:
    container_id: str
    container_name: str
    labels: tuple[tuple[str, str], ...]
    session_id: str
    candidate_id: str
    run_token_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.container_id) is not str
            or _CONTAINER_ID_PATTERN.fullmatch(self.container_id) is None
        ):
            raise ValueError("container_id is invalid")
        if (
            type(self.container_name) is not str
            or not self.container_name
            or len(self.container_name.encode("utf-8")) > 128
        ):
            raise ValueError("container_name is invalid")
        _require_labels(self.labels)
        _require_sha256(self.session_id)
        _require_sha256(self.candidate_id)
        _require_sha256(self.run_token_sha256)
        expected = {
            _COMPONENT_LABEL: _COMPONENT_VALUE,
            _SESSION_LABEL: self.session_id,
            _CANDIDATE_LABEL: self.candidate_id,
            _RUN_TOKEN_LABEL: self.run_token_sha256,
        }
        if dict(self.labels) != expected:
            raise ValueError("run identity labels are invalid")


@dataclass(frozen=True, slots=True)
class _SandboxReport:
    success: bool
    failure_kind: ValidationFailureKind | None
    started_at_us: int
    finished_at_us: int
    command_results: tuple[ValidationCommandResult, ...]
    peak_memory_bytes: int
    oom_killed: bool
    residual_process_count: int
    workspace_entry_count: int
    workspace_inode_count: int
    tracked_tree_clean: bool


@dataclass(frozen=True, slots=True)
class _SandboxValidationOutcome:
    session_id: str
    candidate_id: str
    policy_sha256: str
    sandbox_manifest_sha256: str
    image_id: str
    report: _SandboxReport
    run_identity: _SandboxRunIdentity
    cleanup_pending: bool

    def __post_init__(self) -> None:
        _require_sha256(self.session_id)
        _require_sha256(self.candidate_id)
        _require_sha256(self.policy_sha256)
        _require_sha256(self.sandbox_manifest_sha256)
        if type(self.image_id) is not str or _IMAGE_ID_PATTERN.fullmatch(self.image_id) is None:
            raise ValueError("image_id is invalid")
        if type(self.report) is not _SandboxReport:
            raise TypeError("report must be an exact _SandboxReport")
        if type(self.run_identity) is not _SandboxRunIdentity:
            raise TypeError("run_identity must be an exact _SandboxRunIdentity")
        if (
            self.run_identity.session_id != self.session_id
            or self.run_identity.candidate_id != self.candidate_id
        ):
            raise ValueError("run identity does not match validation outcome")
        if type(self.cleanup_pending) is not bool:
            raise TypeError("cleanup_pending must be an exact bool")


@dataclass(frozen=True, slots=True)
class _ProbeReport:
    success: bool
    checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ContainerState:
    container_id: str
    labels: tuple[tuple[str, str], ...]
    status: str
    running: bool
    exit_code: int
    oom_killed: bool
    pid: int
    error: str
    started_at: str
    finished_at: str


_DockerInvoker = Callable[[RepairManagerConfig, tuple[str, ...], float], _DockerOutput]


def _load_sandbox_assets() -> _SandboxAssets:
    root = files("repoguard")
    for component in _ASSET_DIRECTORY:
        root = root.joinpath(component)
    runner = _read_asset(root.joinpath(_RUNNER_RESOURCE))
    probe = _read_asset(root.joinpath(_PROBE_RESOURCE))
    seccomp_json = _read_asset(root.joinpath(_SECCOMP_RESOURCE))
    manifest_raw = _read_asset(root.joinpath(_MANIFEST_RESOURCE))
    image_lock_raw = _read_asset(
        root.joinpath(_IMAGE_LOCK_DIRECTORY).joinpath(_IMAGE_LOCK_RESOURCE)
    )

    manifest = _parse_packaged_canonical_object(manifest_raw)
    if frozenset(manifest) != _MANIFEST_KEYS or manifest.get("schema_version") != 1:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if manifest.get("architecture") != "linux-x86_64":
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)

    allowlist = _validate_seccomp(seccomp_json)
    manifest_allowlist = manifest.get("syscall_allowlist")
    if (
        type(manifest_allowlist) is not list
        or any(type(item) is not str for item in manifest_allowlist)
        or tuple(cast(list[str], manifest_allowlist)) != allowlist
    ):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)

    expected_resource_digests = {
        "seccomp_sha256": _resource_digest("seccomp", seccomp_json),
        "runner_sha256": _resource_digest("runner", runner),
        "probe_sha256": _resource_digest("probe", probe),
    }
    for name, expected in expected_resource_digests.items():
        actual = manifest.get(name)
        if type(actual) is not str or not hmac.compare_digest(actual, expected):
            raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)

    manifest_digest = manifest.get("sandbox_manifest_sha256")
    if type(manifest_digest) is not str:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    core = dict(manifest)
    del core["sandbox_manifest_sha256"]
    expected_manifest_digest = _domain_digest("sandbox-manifest", core)
    if not hmac.compare_digest(manifest_digest, expected_manifest_digest):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    image_lock = _parse_packaged_canonical_object(image_lock_raw)
    locked_image_id = image_lock.get("image_id")
    image_config_digest = image_lock.get("image_config_digest")
    if (
        frozenset(image_lock) != _IMAGE_LOCK_KEYS
        or image_lock.get("schema_version") != 1
        or image_lock.get("platform") != "linux/amd64"
        or image_lock.get("source_date_epoch") != 0
        or type(locked_image_id) is not str
        or _IMAGE_ID_PATTERN.fullmatch(locked_image_id) is None
        or type(image_config_digest) is not str
        or _IMAGE_ID_PATTERN.fullmatch(image_config_digest) is None
    ):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return _SandboxAssets(
        runner=runner,
        probe=probe,
        seccomp_json=seccomp_json,
        sandbox_manifest_sha256=manifest_digest,
        syscall_allowlist=allowlist,
        locked_image_id=locked_image_id,
    )


def _inspect_sandbox_capabilities(
    config: RepairManagerConfig,
    policy: ValidationPolicy,
    *,
    invoke: _DockerInvoker | None = None,
) -> _SandboxCapabilities:
    if type(config) is not RepairManagerConfig or type(policy) is not ValidationPolicy:
        raise TypeError("sandbox capability inputs must use exact public record types")
    if os.name != "posix" or platform.system() != "Linux":
        raise _sandbox_error(RepairErrorCode.UNSUPPORTED_PLATFORM)
    if platform.machine().lower() not in _SUPPORTED_ARCHITECTURES:
        raise _sandbox_error(RepairErrorCode.UNSUPPORTED_PLATFORM)
    _require_owned_socket(config.rootless_socket)
    assets = _load_sandbox_assets()
    if not hmac.compare_digest(policy.image_id, assets.locked_image_id):
        raise _sandbox_error(RepairErrorCode.IMAGE_MISMATCH)
    docker_invoke = _invoke_docker if invoke is None else invoke

    version_output = docker_invoke(
        config,
        ("version", "--format", "{{json .}}"),
        _DOCKER_TIMEOUT_SECONDS,
    )
    if version_output.returncode != 0:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    info_output = docker_invoke(
        config,
        ("info", "--format", "{{json .}}"),
        _DOCKER_TIMEOUT_SECONDS,
    )
    if info_output.returncode != 0:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    image_output = docker_invoke(
        config,
        ("image", "inspect", "--format", "{{json .}}", policy.image_id),
        _DOCKER_TIMEOUT_SECONDS,
    )
    if image_output.returncode != 0:
        raise _sandbox_error(RepairErrorCode.IMAGE_UNAVAILABLE)

    invalid_capabilities = False
    try:
        version = _parse_json_object(version_output.stdout, _MAX_DOCKER_OUTPUT_BYTES)
        info = _parse_json_object(info_output.stdout, _MAX_DOCKER_OUTPUT_BYTES)
        image = _parse_json_object(image_output.stdout, _MAX_DOCKER_OUTPUT_BYTES)
        client = _mapping_field(version, "Client")
        server = _mapping_field(version, "Server")
        client_version = _string_field(client, "Version")
        server_version = _string_field(server, "Version")
        api_version = _string_field(server, "ApiVersion")
        if _string_field(client, "Os") != "linux" or _string_field(server, "Os") != "linux":
            raise ValueError
        if (
            _string_field(client, "Arch") not in _SUPPORTED_ARCHITECTURES
            or _string_field(server, "Arch") not in _SUPPORTED_ARCHITECTURES
        ):
            raise ValueError
        if _string_field(info, "OSType") != "linux":
            raise ValueError
        architecture = _string_field(info, "Architecture")
        if architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError
        if _string_field(info, "CgroupVersion") != "2":
            raise ValueError
        security_raw = info.get("SecurityOptions")
        if type(security_raw) is not list or any(type(item) is not str for item in security_raw):
            raise ValueError
        security_options = tuple(cast(list[str], security_raw))
        if "name=rootless" not in security_options or not any(
            item.startswith("name=seccomp") for item in security_options
        ):
            raise ValueError
        for capability in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"):
            if info.get(capability) is not True:
                raise ValueError
        image_id = _string_field(image, "Id")
        if image_id != policy.image_id:
            raise _sandbox_error(RepairErrorCode.IMAGE_MISMATCH)
        if (
            _string_field(image, "Os") != "linux"
            or _string_field(image, "Architecture") not in _SUPPORTED_ARCHITECTURES
        ):
            raise _sandbox_error(RepairErrorCode.IMAGE_MISMATCH)
        image_config = _mapping_field(image, "Config")
        if (
            not _image_environment_is_safe(image_config.get("Env"))
            or image_config.get("Volumes") is not None
        ):
            raise _sandbox_error(RepairErrorCode.IMAGE_MISMATCH)
    except RepairError:
        raise
    except (KeyError, TypeError, ValueError):
        invalid_capabilities = True
    if invalid_capabilities:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)

    return _SandboxCapabilities(
        client_version=client_version,
        server_version=server_version,
        api_version=api_version,
        architecture=architecture,
        cgroup_version="2",
        security_options=security_options,
        image_id=image_id,
        sandbox_manifest_sha256=assets.sandbox_manifest_sha256,
    )


def _new_sandbox_secrets() -> _SandboxSecrets:
    nonce = secrets.token_bytes(_SECRET_BYTES)
    hmac_key = secrets.token_bytes(_SECRET_BYTES)
    run_token = secrets.token_bytes(_SECRET_BYTES)
    return _SandboxSecrets(
        nonce=nonce,
        hmac_key=hmac_key,
        run_token=run_token,
        run_token_sha256=_domain_digest("run-token", {"run_token": run_token.hex()}),
    )


def _build_validation_invocation(
    config: RepairManagerConfig,
    policy: ValidationPolicy,
    *,
    session_id: str,
    candidate_id: str,
    candidate_root: Path,
    git_dir: Path,
    index_file: Path,
    runner_path: Path,
    seccomp_path: Path,
    tracked_inputs: tuple[_TrackedInput, ...],
    git_index_sha256: str,
    expected_tree_oid: str,
    secrets_value: _SandboxSecrets | None = None,
) -> _SandboxInvocation:
    if type(config) is not RepairManagerConfig or type(policy) is not ValidationPolicy:
        raise TypeError("sandbox invocation inputs must use exact public record types")
    _require_sha256(session_id)
    _require_sha256(candidate_id)
    _require_sha256(git_index_sha256)
    if type(expected_tree_oid) is not str or _OID_PATTERN.fullmatch(expected_tree_oid) is None:
        raise ValueError("expected_tree_oid is invalid")
    _require_tracked_inputs(tracked_inputs)
    for path, expected_directory in (
        (candidate_root, True),
        (git_dir, True),
        (index_file, False),
        (runner_path, False),
        (seccomp_path, False),
    ):
        _require_mount_path(path, expected_directory=expected_directory)
    if index_file != git_dir / "repoguard-index":
        raise ValueError("index_file must be the isolated repoguard-index")
    sandbox_secrets = _new_sandbox_secrets() if secrets_value is None else secrets_value
    if type(sandbox_secrets) is not _SandboxSecrets:
        raise TypeError("secrets_value must be an exact _SandboxSecrets or None")

    labels = (
        (_COMPONENT_LABEL, _COMPONENT_VALUE),
        (_SESSION_LABEL, session_id),
        (_CANDIDATE_LABEL, candidate_id),
        (_RUN_TOKEN_LABEL, sandbox_secrets.run_token_sha256),
    )
    container_name = (
        f"repoguard-m5-{session_id[:12]}-{candidate_id[:12]}-"
        f"{sandbox_secrets.run_token_sha256[:12]}"
    )
    bootstrap_mapping: dict[str, object] = {
        "schema_version": 1,
        "nonce": sandbox_secrets.nonce.hex(),
        "hmac_key": sandbox_secrets.hmac_key.hex(),
        "policy": validation_policy_to_dict(policy),
        "tracked_inputs": [
            {
                "path": item.path,
                "sha256": item.sha256,
                "executable": item.executable,
            }
            for item in tracked_inputs
        ],
        "git_index_sha256": git_index_sha256,
        "expected_tree_oid": expected_tree_oid,
    }
    bootstrap = _encode_bootstrap_frame(bootstrap_mapping)

    prefix = _docker_prefix(config)
    create_arguments = _container_create_arguments(
        policy,
        container_name=container_name,
        labels=labels,
        script_host_path=runner_path,
        seccomp_path=seccomp_path,
        candidate_root=candidate_root,
        git_dir=git_dir,
        git_index_file=index_file,
        script_path="/opt/repoguard/runner.py",
    )
    return _SandboxInvocation(
        container_name=container_name,
        labels=labels,
        bind_mounts=(
            (str(runner_path), "/opt/repoguard/runner.py"),
            (str(candidate_root), "/input/repository"),
            (str(git_dir), "/input/git/repository"),
            (str(index_file), "/input/git/index"),
        ),
        create_argv=(*prefix, "create", *create_arguments),
        start_argv=(*prefix, "start", "--attach", "--interactive", container_name),
        inspect_argv=(
            *prefix,
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            container_name,
        ),
        wait_argv=(*prefix, "container", "wait", container_name),
        stop_argv=(*prefix, "container", "stop", "--time", "2", container_name),
        kill_argv=(*prefix, "container", "kill", "--signal", "KILL", container_name),
        remove_argv=(*prefix, "container", "rm", "--force", "--volumes", container_name),
        environment=tuple(_HOST_DOCKER_ENVIRONMENT.items()),
        bootstrap=bootstrap,
        nonce=sandbox_secrets.nonce,
        hmac_key=sandbox_secrets.hmac_key,
        run_token_sha256=sandbox_secrets.run_token_sha256,
    )


def _build_probe_invocation(
    config: RepairManagerConfig,
    policy: ValidationPolicy,
    *,
    probe_path: Path,
    seccomp_path: Path,
    secrets_value: _SandboxSecrets | None = None,
) -> _SandboxInvocation:
    if type(config) is not RepairManagerConfig or type(policy) is not ValidationPolicy:
        raise TypeError("sandbox invocation inputs must use exact public record types")
    _require_mount_path(probe_path, expected_directory=False)
    _require_mount_path(seccomp_path, expected_directory=False)
    sandbox_secrets = _new_sandbox_secrets() if secrets_value is None else secrets_value
    if type(sandbox_secrets) is not _SandboxSecrets:
        raise TypeError("secrets_value must be an exact _SandboxSecrets or None")
    labels = (
        (_COMPONENT_LABEL, _PROBE_COMPONENT_VALUE),
        (_RUN_TOKEN_LABEL, sandbox_secrets.run_token_sha256),
    )
    container_name = f"repoguard-m5-probe-{sandbox_secrets.run_token_sha256[:20]}"
    resource_names = (
        "memory_bytes",
        "nano_cpus",
        "pids_limit",
        "workspace_bytes",
        "workspace_inodes",
        "tmp_bytes",
        "tmp_inodes",
        "home_bytes",
        "home_inodes",
        "run_bytes",
        "run_inodes",
    )
    bootstrap = _encode_bootstrap_frame(
        {
            "schema_version": 1,
            "nonce": sandbox_secrets.nonce.hex(),
            "hmac_key": sandbox_secrets.hmac_key.hex(),
            "resources": {name: getattr(policy, name) for name in resource_names},
        }
    )
    prefix = _docker_prefix(config)
    create_arguments = _container_create_arguments(
        policy,
        container_name=container_name,
        labels=labels,
        script_host_path=probe_path,
        seccomp_path=seccomp_path,
        candidate_root=None,
        git_dir=None,
        git_index_file=None,
        script_path="/opt/repoguard/probe.py",
    )
    return _SandboxInvocation(
        container_name=container_name,
        labels=labels,
        bind_mounts=((str(probe_path), "/opt/repoguard/probe.py"),),
        create_argv=(*prefix, "create", *create_arguments),
        start_argv=(*prefix, "start", "--attach", "--interactive", container_name),
        inspect_argv=(
            *prefix,
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            container_name,
        ),
        wait_argv=(*prefix, "container", "wait", container_name),
        stop_argv=(*prefix, "container", "stop", "--time", "2", container_name),
        kill_argv=(*prefix, "container", "kill", "--signal", "KILL", container_name),
        remove_argv=(*prefix, "container", "rm", "--force", "--volumes", container_name),
        environment=tuple(_HOST_DOCKER_ENVIRONMENT.items()),
        bootstrap=bootstrap,
        nonce=sandbox_secrets.nonce,
        hmac_key=sandbox_secrets.hmac_key,
        run_token_sha256=sandbox_secrets.run_token_sha256,
    )


def _parse_report_frame(
    frame: bytes,
    *,
    expected_nonce: bytes,
    hmac_key: bytes,
    expected_command_count: int,
) -> _SandboxReport:
    if (
        type(frame) is not bytes
        or type(expected_nonce) is not bytes
        or type(hmac_key) is not bytes
        or len(expected_nonce) != _SECRET_BYTES
        or len(hmac_key) != _SECRET_BYTES
        or type(expected_command_count) is not int
        or not 1 <= expected_command_count <= 8
    ):
        raise _SandboxProtocolError
    payload = _decode_authenticated_frame(frame, expected_nonce=expected_nonce, hmac_key=hmac_key)
    try:
        mapping = _parse_canonical_object(payload)
        expected_keys = {
            "schema_version",
            "nonce",
            "success",
            "failure_kind",
            "started_at_us",
            "finished_at_us",
            "command_results",
            "peak_memory_bytes",
            "oom_killed",
            "residual_process_count",
            "workspace_entry_count",
            "workspace_inode_count",
            "tracked_tree_clean",
        }
        if set(mapping) != expected_keys or mapping["schema_version"] != 1:
            raise ValueError
        nonce_text = mapping["nonce"]
        if type(nonce_text) is not str or not hmac.compare_digest(nonce_text, expected_nonce.hex()):
            raise ValueError
        success = _bool_field(mapping, "success")
        failure_raw = mapping["failure_kind"]
        failure_kind = (
            None if failure_raw is None else ValidationFailureKind(_exact_string(failure_raw))
        )
        started_at_us = _nonnegative_int_field(mapping, "started_at_us")
        finished_at_us = _nonnegative_int_field(mapping, "finished_at_us")
        if finished_at_us < started_at_us:
            raise ValueError
        raw_results = mapping["command_results"]
        if type(raw_results) is not list or len(raw_results) > expected_command_count:
            raise ValueError
        command_results = tuple(
            _command_result_from_mapping(item, index)
            for index, item in enumerate(cast(list[object], raw_results))
        )
        peak_memory_bytes = _nonnegative_int_field(mapping, "peak_memory_bytes")
        oom_killed = _bool_field(mapping, "oom_killed")
        residual_process_count = _nonnegative_int_field(mapping, "residual_process_count")
        workspace_entry_count = _nonnegative_int_field(mapping, "workspace_entry_count")
        workspace_inode_count = _nonnegative_int_field(mapping, "workspace_inode_count")
        tracked_tree_clean = _bool_field(mapping, "tracked_tree_clean")
        report = _SandboxReport(
            success=success,
            failure_kind=failure_kind,
            started_at_us=started_at_us,
            finished_at_us=finished_at_us,
            command_results=command_results,
            peak_memory_bytes=peak_memory_bytes,
            oom_killed=oom_killed,
            residual_process_count=residual_process_count,
            workspace_entry_count=workspace_entry_count,
            workspace_inode_count=workspace_inode_count,
            tracked_tree_clean=tracked_tree_clean,
        )
        _validate_report_semantics(report, expected_command_count)
        return report
    except (KeyError, TypeError, ValueError):
        raise _SandboxProtocolError from None


def _parse_probe_frame(
    frame: bytes,
    *,
    expected_nonce: bytes,
    hmac_key: bytes,
) -> _ProbeReport:
    if (
        type(frame) is not bytes
        or type(expected_nonce) is not bytes
        or type(hmac_key) is not bytes
        or len(expected_nonce) != _SECRET_BYTES
        or len(hmac_key) != _SECRET_BYTES
    ):
        raise _SandboxProtocolError
    payload = _decode_authenticated_frame(frame, expected_nonce=expected_nonce, hmac_key=hmac_key)
    try:
        mapping = _parse_canonical_object(payload)
        if set(mapping) != {"schema_version", "nonce", "success", "checks"}:
            raise ValueError
        if mapping["schema_version"] != 1:
            raise ValueError
        nonce_text = _exact_string(mapping["nonce"])
        if not hmac.compare_digest(nonce_text, expected_nonce.hex()):
            raise ValueError
        success = _exact_bool(mapping["success"])
        checks_raw = mapping["checks"]
        if type(checks_raw) is not list or any(type(item) is not str for item in checks_raw):
            raise ValueError
        checks = tuple(cast(list[str], checks_raw))
        if checks != tuple(sorted(set(checks))) or success is not (checks == _PROBE_CHECKS):
            raise ValueError
        return _ProbeReport(success=success, checks=checks)
    except (KeyError, TypeError, ValueError):
        raise _SandboxProtocolError from None


def _corroborate_container_result(
    report: _SandboxReport,
    inspect_output: bytes,
    wait_output: bytes,
    *,
    expected_container_id: str,
    expected_labels: tuple[tuple[str, str], ...],
) -> None:
    if type(report) is not _SandboxReport:
        raise TypeError("report must be an exact _SandboxReport")
    state = _parse_terminal_container_state(
        inspect_output,
        wait_output,
        expected_container_id=expected_container_id,
        expected_labels=expected_labels,
    )
    if state.exit_code != 0 or state.oom_killed is not report.oom_killed:
        raise _SandboxProtocolError


def _corroborate_created_container(
    inspect_output: bytes,
    *,
    expected_container_id: str,
    expected_labels: tuple[tuple[str, str], ...],
    expected_policy: ValidationPolicy,
    expected_command: tuple[str, ...],
    expected_bind_mounts: tuple[tuple[str, str], ...],
) -> None:
    if (
        type(expected_policy) is not ValidationPolicy
        or type(expected_command) is not tuple
        or not _expected_bind_mounts_are_valid(expected_bind_mounts)
    ):
        raise TypeError("created-container expectations are invalid")
    state, inspect = _parse_container_state(
        inspect_output,
        expected_container_id=expected_container_id,
        expected_labels=expected_labels,
    )
    try:
        config = _mapping_field(inspect, "Config")
        if (
            _string_field(inspect, "Image") != expected_policy.image_id
            or _string_field(config, "Image") != expected_policy.image_id
            or _string_field(config, "Hostname") != "repoguard"
            or _string_field(config, "User") != "0:0"
            or _string_field(config, "WorkingDir") != "/"
            or _exact_string_tuple(config.get("Entrypoint")) != ("/usr/local/bin/python3.12",)
            or _exact_string_tuple(config.get("Cmd")) != expected_command
            or _environment_from_entries(config.get("Env")) != dict(_CONTAINER_ENVIRONMENT)
            or config.get("Volumes") is not None
            or not _created_bind_mounts_match(inspect.get("Mounts"), expected_bind_mounts)
            or state.running
            or state.status != "created"
            or state.pid != 0
            or state.error != ""
            or not _created_host_config_matches(
                _mapping_field(inspect, "HostConfig"),
                expected_policy,
            )
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise _SandboxProtocolError from None


def _expected_bind_mounts_are_valid(value: object) -> bool:
    return (
        type(value) is tuple
        and bool(value)
        and all(
            type(item) is tuple
            and len(item) == 2
            and type(item[0]) is str
            and type(item[1]) is str
            and item[0].startswith("/")
            and item[1].startswith("/")
            for item in value
        )
        and len(value) == len(set(cast(tuple[tuple[str, str], ...], value)))
    )


def _created_bind_mounts_match(
    value: object,
    expected: tuple[tuple[str, str], ...],
) -> bool:
    if type(value) is not list or len(value) != len(expected):
        return False
    observed: list[tuple[str, str]] = []
    try:
        for raw_mount in cast(list[object], value):
            if type(raw_mount) is not dict:
                return False
            mount = cast(dict[str, object], raw_mount)
            if (
                _string_field(mount, "Type") != "bind"
                or _bool_field(mount, "RW")
                or _string_field(mount, "Propagation") != "rprivate"
            ):
                return False
            observed.append(
                (
                    _string_field(mount, "Source"),
                    _string_field(mount, "Destination"),
                )
            )
    except (KeyError, TypeError, ValueError):
        return False
    return len(observed) == len(set(observed)) and set(observed) == set(expected)


def _image_environment_is_safe(value: object) -> bool:
    try:
        environment = _environment_from_entries(value)
    except ValueError:
        return False
    return environment.keys() <= dict(_CONTAINER_ENVIRONMENT).keys()


def _environment_from_entries(value: object) -> dict[str, str]:
    entries = _exact_string_tuple(value)
    environment: dict[str, str] = {}
    for entry in entries:
        key, separator, item_value = entry.partition("=")
        if separator != "=" or not key or key in environment:
            raise ValueError
        environment[key] = item_value
    return environment


def _exact_string_tuple(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError
    return tuple(cast(list[str], value))


def _created_host_config_matches(
    host_config: dict[str, object],
    policy: ValidationPolicy,
) -> bool:
    try:
        cap_drop = _exact_string_tuple(host_config.get("CapDrop"))
        cap_add_raw = host_config.get("CapAdd")
        cap_add = () if cap_add_raw is None else _exact_string_tuple(cap_add_raw)
        security_options = _exact_string_tuple(host_config.get("SecurityOpt"))
        restart = _mapping_field(host_config, "RestartPolicy")
        return (
            cap_drop == ("ALL",)
            and not cap_add
            and len(security_options) == 2
            and "no-new-privileges=true" in security_options
            and len(
                tuple(
                    option
                    for option in security_options
                    if option.startswith("seccomp=") and option != "seccomp=unconfined"
                )
            )
            == 1
            and _string_field(host_config, "NetworkMode") == "none"
            and _string_field(host_config, "IpcMode") == "private"
            and _string_field(host_config, "PidMode") in {"", "private"}
            and _string_field(host_config, "CgroupnsMode") in {"", "private"}
            and _bool_field(host_config, "ReadonlyRootfs")
            and not _bool_field(host_config, "Privileged")
            and not _bool_field(host_config, "AutoRemove")
            and not _bool_field(host_config, "OomKillDisable")
            and _nonnegative_int_field(host_config, "Memory") == policy.memory_bytes
            and _nonnegative_int_field(host_config, "MemorySwap") == policy.memory_bytes
            and _nonnegative_int_field(host_config, "NanoCpus") == policy.nano_cpus
            and _nonnegative_int_field(host_config, "PidsLimit") == policy.pids_limit
            and _string_field(restart, "Name") == "no"
            and _nonnegative_int_field(restart, "MaximumRetryCount") == 0
            and _tmpfs_configuration_matches(host_config.get("Tmpfs"), policy)
        )
    except (KeyError, TypeError, ValueError):
        return False


def _tmpfs_configuration_matches(value: object, policy: ValidationPolicy) -> bool:
    if type(value) is not dict:
        return False
    tmpfs = cast(dict[object, object], value)
    expected = {
        "/workspace": (policy.workspace_bytes, policy.workspace_inodes),
        "/tmp": (policy.tmp_bytes, policy.tmp_inodes),
        "/home/repoguard": (policy.home_bytes, policy.home_inodes),
        "/run": (policy.run_bytes, policy.run_inodes),
    }
    if set(tmpfs) != set(expected):
        return False
    for path, (size, inodes) in expected.items():
        options = tmpfs.get(path)
        if type(options) is not str:
            return False
        parts = options.split(",")
        if len(parts) != len(set(parts)) or set(parts) != {
            "rw",
            "nosuid",
            "nodev",
            f"size={size}",
            f"nr_inodes={inodes}",
            "mode=0700",
        }:
            return False
    return True


def _parse_terminal_container_state(
    inspect_output: bytes,
    wait_output: bytes,
    *,
    expected_container_id: str,
    expected_labels: tuple[tuple[str, str], ...],
) -> _ContainerState:
    state, _ = _parse_container_state(
        inspect_output,
        expected_container_id=expected_container_id,
        expected_labels=expected_labels,
    )
    try:
        wait_exit_code = _parse_wait_exit_code(wait_output)
        if (
            state.running
            or state.status != "exited"
            or state.pid != 0
            or state.error != ""
            or not state.started_at
            or not state.finished_at
            or wait_exit_code != state.exit_code
        ):
            raise ValueError
        return state
    except (TypeError, ValueError):
        raise _SandboxProtocolError from None


def _parse_container_state(
    inspect_output: bytes,
    *,
    expected_container_id: str,
    expected_labels: tuple[tuple[str, str], ...],
) -> tuple[_ContainerState, dict[str, object]]:
    if (
        type(expected_container_id) is not str
        or _CONTAINER_ID_PATTERN.fullmatch(expected_container_id) is None
    ):
        raise _SandboxProtocolError
    _require_labels(expected_labels)
    try:
        inspect = _parse_json_object(inspect_output, _MAX_DOCKER_OUTPUT_BYTES)
        if _string_field(inspect, "Id") != expected_container_id:
            raise ValueError
        config = _mapping_field(inspect, "Config")
        labels_raw = config.get("Labels")
        if type(labels_raw) is not dict:
            raise ValueError
        labels = cast(dict[object, object], labels_raw)
        for key, value in expected_labels:
            if labels.get(key) != value:
                raise ValueError
        state = _mapping_field(inspect, "State")
        return (
            _ContainerState(
                container_id=expected_container_id,
                labels=expected_labels,
                status=_string_field(state, "Status"),
                running=_bool_field(state, "Running"),
                exit_code=_nonnegative_int_field(state, "ExitCode"),
                oom_killed=_bool_field(state, "OOMKilled"),
                pid=_nonnegative_int_field(state, "Pid"),
                error=_string_field(state, "Error"),
                started_at=_string_field(state, "StartedAt"),
                finished_at=_string_field(state, "FinishedAt"),
            ),
            inspect,
        )
    except (KeyError, TypeError, ValueError):
        raise _SandboxProtocolError from None


def _parse_wait_exit_code(value: bytes) -> int:
    if type(value) is not bytes:
        raise ValueError
    raw = value[:-1] if value.endswith(b"\n") else value
    if not raw or b"\n" in raw or not raw.isdigit():
        raise ValueError
    return int(raw)


def _encode_bootstrap_frame(mapping: Mapping[str, object]) -> bytes:
    payload = _canonical_bytes(mapping)
    if not payload or len(payload) > _MAX_BOOTSTRAP_BYTES:
        raise ValueError("sandbox bootstrap exceeds its bound")
    return _FRAME_HEADER.pack(_BOOTSTRAP_MAGIC, len(payload)) + payload


def _resource_digest(name: str, content: bytes) -> str:
    if type(name) is not str or not name or type(content) is not bytes:
        raise TypeError("sandbox resource digest input is invalid")
    domain = f"{_RESOURCE_DOMAIN_PREFIX}.{name}.v1".encode("ascii")
    return hashlib.sha256(domain + b"\x00" + content).hexdigest()


def _validate_seccomp(raw: bytes) -> tuple[str, ...]:
    invalid_seccomp = False
    validated_allowlist: tuple[str, ...] | None = None
    try:
        seccomp = _parse_canonical_object(raw)
        if frozenset(seccomp) != _SECCOMP_KEYS:
            raise ValueError
        if seccomp["defaultAction"] != "SCMP_ACT_ERRNO" or seccomp["defaultErrnoRet"] != 1:
            raise ValueError
        if seccomp["archMap"] != [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []}]:
            raise ValueError
        syscall_entries = seccomp["syscalls"]
        if type(syscall_entries) is not list:
            raise ValueError
        allowed: list[str] = []
        clone_rule = False
        clone3_rule = False
        ioctl_rule = False
        socket_rules: set[str] = set()
        for raw_entry in cast(list[object], syscall_entries):
            if type(raw_entry) is not dict:
                raise ValueError
            entry = cast(dict[object, object], raw_entry)
            names = entry.get("names")
            action = entry.get("action")
            args = entry.get("args", [])
            if (
                type(names) is not list
                or not names
                or any(type(name) is not str for name in names)
                or tuple(cast(list[str], names)) != tuple(sorted(cast(list[str], names)))
                or type(args) is not list
            ):
                raise ValueError
            name_tuple = tuple(cast(list[str], names))
            if action == "SCMP_ACT_ALLOW":
                allowed.extend(name_tuple)
            if name_tuple == ("clone",):
                clone_rule = (
                    args
                    == [
                        {
                            "index": 0,
                            "value": 2_114_060_416,
                            "valueTwo": 0,
                            "op": "SCMP_CMP_MASKED_EQ",
                        }
                    ]
                    and action == "SCMP_ACT_ALLOW"
                )
            elif name_tuple == ("clone3",):
                clone3_rule = (
                    action == "SCMP_ACT_ERRNO" and entry.get("errnoRet") == 38 and args == []
                )
            elif name_tuple == ("ioctl",):
                ioctl_rule = (
                    args == [{"index": 1, "value": 21_522, "op": "SCMP_CMP_NE"}]
                    and action == "SCMP_ACT_ALLOW"
                )
            elif (
                name_tuple in {("socket",), ("socketpair",)}
                and args == [{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]
                and action == "SCMP_ACT_ALLOW"
            ):
                socket_rules.add(name_tuple[0])
        allowlist = tuple(sorted(allowed))
        if len(allowlist) != len(set(allowlist)):
            raise ValueError
        if _FORBIDDEN_ALLOWED_SYSCALLS.intersection(allowlist):
            raise ValueError
        if not clone_rule or not clone3_rule or not ioctl_rule:
            raise ValueError
        if socket_rules != {"socket", "socketpair"}:
            raise ValueError
        validated_allowlist = allowlist
    except (KeyError, TypeError, ValueError):
        invalid_seccomp = True
    if invalid_seccomp or validated_allowlist is None:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return validated_allowlist


def _container_create_arguments(
    policy: ValidationPolicy,
    *,
    container_name: str,
    labels: tuple[tuple[str, str], ...],
    script_host_path: Path,
    seccomp_path: Path,
    candidate_root: Path | None,
    git_dir: Path | None,
    git_index_file: Path | None,
    script_path: str,
) -> tuple[str, ...]:
    arguments: list[str] = [
        "--pull=never",
        "--name",
        container_name,
        "--hostname",
        "repoguard",
        "--user",
        "0:0",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        f"--security-opt=seccomp={seccomp_path}",
        "--network=none",
        "--ipc=private",
        "--read-only",
        f"--memory={policy.memory_bytes}",
        f"--memory-swap={policy.memory_bytes}",
        f"--cpus={_nano_cpus_to_cpus(policy.nano_cpus)}",
        f"--pids-limit={policy.pids_limit}",
        "--oom-kill-disable=false",
        "--restart=no",
        "--no-healthcheck",
        "--interactive",
        "--workdir=/",
    ]
    for key, value in labels:
        arguments.extend(("--label", f"{key}={value}"))
    for key, value in _CONTAINER_ENVIRONMENT:
        arguments.extend(("--env", f"{key}={value}"))
    arguments.extend(
        (
            "--mount",
            _bind_mount(script_host_path, script_path),
        )
    )
    if candidate_root is not None and git_dir is not None and git_index_file is not None:
        arguments.extend(
            (
                "--mount",
                _bind_mount(candidate_root, "/input/repository"),
                "--mount",
                _bind_mount(git_dir, "/input/git/repository"),
                "--mount",
                _bind_mount(git_index_file, "/input/git/index"),
            )
        )
    elif candidate_root is not None or git_dir is not None or git_index_file is not None:
        raise ValueError("candidate, Git, and index mounts must be supplied together")
    arguments.extend(
        (
            "--tmpfs",
            _tmpfs_spec(
                "/workspace",
                size=policy.workspace_bytes,
                inodes=policy.workspace_inodes,
            ),
            "--tmpfs",
            _tmpfs_spec("/tmp", size=policy.tmp_bytes, inodes=policy.tmp_inodes),
            "--tmpfs",
            _tmpfs_spec(
                "/home/repoguard",
                size=policy.home_bytes,
                inodes=policy.home_inodes,
            ),
            "--tmpfs",
            _tmpfs_spec("/run", size=policy.run_bytes, inodes=policy.run_inodes),
            "--entrypoint=/usr/local/bin/python3.12",
            policy.image_id,
            "-I",
            "-S",
            "-E",
            "-B",
            script_path,
        )
    )
    return tuple(arguments)


def _bind_mount(source: Path, destination: str) -> str:
    source_field = _csv_field(f"source={source}")
    return f"type=bind,{source_field},destination={destination},readonly"


def _csv_field(value: str) -> str:
    if any(character in value for character in ',"\r\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def _tmpfs_spec(destination: str, *, size: int, inodes: int) -> str:
    return f"{destination}:rw,nosuid,nodev,size={size},nr_inodes={inodes},mode=0700"


def _nano_cpus_to_cpus(value: int) -> str:
    if type(value) is not int or value <= 0:
        raise ValueError("nano CPU limit must be a positive integer")
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _docker_prefix(config: RepairManagerConfig) -> tuple[str, ...]:
    endpoint = f"unix://{config.rootless_socket}"
    return (str(config.docker_executable), "--host", endpoint)


def _invoke_docker(
    config: RepairManagerConfig,
    arguments: tuple[str, ...],
    timeout_seconds: float,
) -> _DockerOutput:
    if type(config) is not RepairManagerConfig or type(arguments) is not tuple:
        raise TypeError("Docker invocation input is invalid")
    result = _run_bounded_process(
        (*_docker_prefix(config), *arguments),
        environment=_HOST_DOCKER_ENVIRONMENT,
        stdin=b"",
        timeout_seconds=timeout_seconds,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
    )
    if result.timed_out or result.output_limit:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return _DockerOutput(result.returncode, result.stdout, result.stderr)


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limit: bool


def _run_bounded_process(
    argv: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    stdin: bytes,
    timeout_seconds: float,
    stream_limit: int,
) -> _BoundedProcessResult:
    if (
        type(argv) is not tuple
        or not argv
        or any(type(argument) is not str for argument in argv)
        or type(stdin) is not bytes
        or type(timeout_seconds) is not float
        or timeout_seconds <= 0
        or type(stream_limit) is not int
        or stream_limit <= 0
    ):
        raise TypeError("bounded process input is invalid")
    process: subprocess.Popen[bytes] | None = None
    process_start_failed = False
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=dict(environment),
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError):
        process_start_failed = True
    if process_start_failed or process is None:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)

    selector = selectors.DefaultSelector()
    input_offset = 0
    stdout = bytearray()
    stderr = bytearray()
    output_limit = False
    timed_out = False
    deadline = time.monotonic() + timeout_seconds
    streams: dict[int, tuple[str, BinaryIO]] = {}
    process_failed = False
    returncode = 0
    try:
        for name, stream, event_mask in (
            ("stdin", process.stdin, selectors.EVENT_WRITE),
            ("stdout", process.stdout, selectors.EVENT_READ),
            ("stderr", process.stderr, selectors.EVENT_READ),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event_mask, name)
            streams[stream.fileno()] = (name, cast(BinaryIO, stream))
        if not stdin:
            selector.unregister(process.stdin)
            process.stdin.close()

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process(process)
                remaining = 0.05
            selected_events = selector.select(min(max(remaining, 0.0), 0.05))
            for key, _ in selected_events:
                name = cast(str, key.data)
                stream = cast(BinaryIO, key.fileobj)
                descriptor = stream.fileno()
                if name == "stdin":
                    try:
                        written = os.write(descriptor, stdin[input_offset : input_offset + 65_536])
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(stdin)
                    input_offset += written
                    if input_offset >= len(stdin):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(descriptor, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                target = stdout if name == "stdout" else stderr
                available = max(0, stream_limit - len(target))
                target.extend(chunk[:available])
                if len(chunk) > available:
                    output_limit = True
                    _terminate_process(process)
            if process.poll() is not None and not selected_events:
                for descriptor, (_, stream) in tuple(streams.items()):
                    if stream.closed:
                        streams.pop(descriptor, None)
        if process.poll() is None:
            _terminate_process(process)
        returncode = process.wait(timeout=1.0)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        _terminate_process(process)
        process_failed = True
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    if process_failed:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        timed_out=timed_out,
        output_limit=output_limit,
    )


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=0.2)
    except (OSError, subprocess.TimeoutExpired):
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1.0)


_DockerProcessInvoker = Callable[
    [tuple[str, ...], bytes, float, int],
    _BoundedProcessResult,
]
_IntentRegistrar = Callable[[_SandboxRunIntent], bool]
_IntentReleaser = Callable[[_SandboxRunIntent], bool]
_RunRegistrar = Callable[[_SandboxRunIdentity], bool]
_RunReleaser = Callable[[_SandboxRunIdentity], bool]
_OutcomeFence = Callable[[_SandboxValidationOutcome], None]
_MountIdentityCheck = Callable[[], None]


def _prepare_sandbox(
    config: RepairManagerConfig,
    policy: ValidationPolicy,
    *,
    probe_path: Path,
    seccomp_path: Path,
    capability_invoke: _DockerInvoker | None = None,
    process_invoke: _DockerProcessInvoker | None = None,
    secrets_value: _SandboxSecrets | None = None,
    mount_identity_check: _MountIdentityCheck | None = None,
) -> _SandboxCapabilities:
    """Inspect the rootless daemon/image and execute the authenticated packaged probe."""
    if mount_identity_check is not None and not callable(mount_identity_check):
        raise TypeError("mount_identity_check must be callable or None")
    capabilities = _inspect_sandbox_capabilities(
        config,
        policy,
        invoke=capability_invoke,
    )
    assets = _load_sandbox_assets()
    if (
        capabilities.image_id != policy.image_id
        or capabilities.sandbox_manifest_sha256 != assets.sandbox_manifest_sha256
    ):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if mount_identity_check is not None:
        mount_identity_check()
    _require_exact_asset_path(probe_path, assets.probe)
    _require_exact_asset_path(seccomp_path, assets.seccomp_json)
    invocation = _build_probe_invocation(
        config,
        policy,
        probe_path=probe_path,
        seccomp_path=seccomp_path,
        secrets_value=secrets_value,
    )
    docker_process = _invoke_docker_process if process_invoke is None else process_invoke
    _execute_probe_invocation(
        invocation,
        policy,
        docker_process,
        mount_identity_check=mount_identity_check,
    )
    return capabilities


def _run_sandbox_validation(
    config: RepairManagerConfig,
    policy: ValidationPolicy,
    capabilities: _SandboxCapabilities,
    *,
    session_id: str,
    candidate_id: str,
    candidate_root: Path,
    git_dir: Path,
    index_file: Path,
    runner_path: Path,
    seccomp_path: Path,
    tracked_inputs: tuple[_TrackedInput, ...],
    git_index_sha256: str,
    expected_tree_oid: str,
    register_intent: _IntentRegistrar,
    register_run: _RunRegistrar,
    release_intent: _IntentReleaser,
    release_run: _RunReleaser,
    before_remove: _OutcomeFence,
    process_invoke: _DockerProcessInvoker | None = None,
    secrets_value: _SandboxSecrets | None = None,
    mount_identity_check: _MountIdentityCheck | None = None,
) -> _SandboxValidationOutcome:
    """Execute one fenced candidate validation and return only raw-output-free state."""
    if (
        type(config) is not RepairManagerConfig
        or type(policy) is not ValidationPolicy
        or type(capabilities) is not _SandboxCapabilities
        or not callable(register_intent)
        or not callable(register_run)
        or not callable(release_intent)
        or not callable(release_run)
        or not callable(before_remove)
        or (mount_identity_check is not None and not callable(mount_identity_check))
    ):
        raise TypeError("sandbox validation inputs must use exact record types")
    assets = _load_sandbox_assets()
    if (
        capabilities.image_id != policy.image_id
        or capabilities.sandbox_manifest_sha256 != assets.sandbox_manifest_sha256
    ):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if mount_identity_check is not None:
        mount_identity_check()
    _require_exact_asset_path(runner_path, assets.runner)
    _require_exact_asset_path(seccomp_path, assets.seccomp_json)
    _require_candidate_projection(candidate_root)
    if index_file != git_dir / "repoguard-index":
        raise ValueError("index_file must be the isolated repoguard-index")
    _require_exact_file_digest(index_file, git_index_sha256)
    invocation = _build_validation_invocation(
        config,
        policy,
        session_id=session_id,
        candidate_id=candidate_id,
        candidate_root=candidate_root,
        git_dir=git_dir,
        index_file=index_file,
        runner_path=runner_path,
        seccomp_path=seccomp_path,
        tracked_inputs=tracked_inputs,
        git_index_sha256=git_index_sha256,
        expected_tree_oid=expected_tree_oid,
        secrets_value=secrets_value,
    )
    intent = _SandboxRunIntent(
        container_name=invocation.container_name,
        labels=invocation.labels,
        session_id=session_id,
        candidate_id=candidate_id,
        run_token_sha256=invocation.run_token_sha256,
    )
    if register_intent(intent) is not True:
        raise _SandboxRunRejected
    docker_process = _invoke_docker_process if process_invoke is None else process_invoke
    return _execute_validation_invocation(
        invocation,
        policy,
        capabilities,
        session_id=session_id,
        candidate_id=candidate_id,
        intent=intent,
        register_run=register_run,
        release_intent=release_intent,
        release_run=release_run,
        before_remove=before_remove,
        process_invoke=docker_process,
        mount_identity_check=mount_identity_check,
    )


def _stop_exact_container(
    config: RepairManagerConfig,
    identity: _SandboxRunIdentity,
    *,
    process_invoke: _DockerProcessInvoker | None = None,
) -> bool:
    """Stop and kill only a container whose immutable ID and fencing labels still match."""
    if type(config) is not RepairManagerConfig or type(identity) is not _SandboxRunIdentity:
        raise TypeError("exact-container stop inputs must use exact record types")
    docker_process = _invoke_docker_process if process_invoke is None else process_invoke
    inspect = _call_docker_process(
        (
            *_docker_prefix(config),
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            identity.container_id,
        ),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=docker_process,
    )
    if not _docker_command_succeeded(inspect):
        return _exact_container_is_absent(config, identity, docker_process)
    try:
        _parse_container_state(
            inspect.stdout,
            expected_container_id=identity.container_id,
            expected_labels=identity.labels,
        )
    except _SandboxProtocolError:
        return False
    stop = _call_docker_process(
        (
            *_docker_prefix(config),
            "container",
            "stop",
            "--time",
            "2",
            identity.container_id,
        ),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=docker_process,
    )
    kill = _call_docker_process(
        (
            *_docker_prefix(config),
            "container",
            "kill",
            "--signal",
            "KILL",
            identity.container_id,
        ),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=docker_process,
    )
    return _docker_command_succeeded(stop) or _docker_command_succeeded(kill)


def _remove_exact_container(
    config: RepairManagerConfig,
    identity: _SandboxRunIdentity,
    *,
    process_invoke: _DockerProcessInvoker | None = None,
) -> bool:
    """Remove only a container whose immutable ID and fencing labels still match."""
    if type(config) is not RepairManagerConfig or type(identity) is not _SandboxRunIdentity:
        raise TypeError("exact-container removal inputs must use exact record types")
    docker_process = _invoke_docker_process if process_invoke is None else process_invoke
    inspect = _call_docker_process(
        (
            *_docker_prefix(config),
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            identity.container_id,
        ),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=docker_process,
    )
    if not _docker_command_succeeded(inspect):
        return _exact_container_is_absent(config, identity, docker_process)
    try:
        _parse_container_state(
            inspect.stdout,
            expected_container_id=identity.container_id,
            expected_labels=identity.labels,
        )
    except _SandboxProtocolError:
        return False
    remove = _call_docker_process(
        (
            *_docker_prefix(config),
            "container",
            "rm",
            "--force",
            "--volumes",
            identity.container_id,
        ),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=docker_process,
    )
    return _docker_command_succeeded(remove)


def _exact_container_is_absent(
    config: RepairManagerConfig,
    identity: _SandboxRunIdentity,
    process_invoke: _DockerProcessInvoker,
) -> bool:
    try:
        listed = _call_docker_process(
            (
                *_docker_prefix(config),
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"id={identity.container_id}",
                "--format",
                "{{.ID}}",
            ),
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        return False
    if not _docker_command_succeeded(listed):
        return False
    return listed.stdout in {b"", b"\n"}


def _execute_probe_invocation(
    invocation: _SandboxInvocation,
    policy: ValidationPolicy,
    process_invoke: _DockerProcessInvoker,
    *,
    mount_identity_check: _MountIdentityCheck | None,
) -> None:
    container_id: str | None = None
    remove_succeeded = True
    protocol_failed = False
    try:
        container_id = _create_and_corroborate_container(
            invocation,
            policy,
            process_invoke,
            mount_identity_check=mount_identity_check,
        )
        start = _call_docker_process(
            _target_container(invocation.start_argv, invocation.container_name, container_id),
            stdin=invocation.bootstrap,
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            stream_limit=_MAX_REPORT_FRAME_BYTES,
            process_invoke=process_invoke,
        )
        if not _docker_command_succeeded(start):
            _stop_invocation_container(invocation, container_id, process_invoke)
            raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
        inspect, wait = _read_terminal_container(
            invocation,
            container_id,
            process_invoke,
        )
        report = _parse_probe_frame(
            start.stdout,
            expected_nonce=invocation.nonce,
            hmac_key=invocation.hmac_key,
        )
        if not report.success:
            raise _SandboxProtocolError
        state = _parse_terminal_container_state(
            inspect,
            wait,
            expected_container_id=container_id,
            expected_labels=invocation.labels,
        )
        if state.exit_code != 0 or state.oom_killed:
            raise _SandboxProtocolError
    except _SandboxProtocolError:
        protocol_failed = True
    finally:
        if container_id is not None:
            remove_succeeded = _remove_invocation_container(
                invocation,
                container_id,
                process_invoke,
            )
    if protocol_failed or not remove_succeeded:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)


def _execute_validation_invocation(
    invocation: _SandboxInvocation,
    policy: ValidationPolicy,
    capabilities: _SandboxCapabilities,
    *,
    session_id: str,
    candidate_id: str,
    intent: _SandboxRunIntent,
    register_run: _RunRegistrar,
    release_intent: _IntentReleaser,
    release_run: _RunReleaser,
    before_remove: _OutcomeFence,
    process_invoke: _DockerProcessInvoker,
    mount_identity_check: _MountIdentityCheck | None,
) -> _SandboxValidationOutcome:
    container_id: str | None = None
    identity: _SandboxRunIdentity | None = None
    run_registered = False
    container_create_failed = False
    try:
        if mount_identity_check is not None:
            mount_identity_check()
        container_id = _create_container_id(invocation, process_invoke)
        identity = _SandboxRunIdentity(
            container_id=container_id,
            container_name=invocation.container_name,
            labels=invocation.labels,
            session_id=session_id,
            candidate_id=candidate_id,
            run_token_sha256=invocation.run_token_sha256,
        )
        if register_run(identity) is not True:
            raise _SandboxRunRejected
        run_registered = True
        if mount_identity_check is not None:
            mount_identity_check()
        inspect = _inspect_created_container(invocation, container_id, process_invoke)
        if mount_identity_check is not None:
            mount_identity_check()
        _corroborate_created_container(
            inspect,
            expected_container_id=container_id,
            expected_labels=invocation.labels,
            expected_policy=policy,
            expected_command=invocation.create_argv[-5:],
            expected_bind_mounts=invocation.bind_mounts,
        )
        if mount_identity_check is not None:
            mount_identity_check()
        report = _execute_validation_start(
            invocation,
            policy,
            container_id,
            process_invoke,
        )
        outcome = _SandboxValidationOutcome(
            session_id=session_id,
            candidate_id=candidate_id,
            policy_sha256=_domain_digest("policy", validation_policy_to_dict(policy)),
            sandbox_manifest_sha256=capabilities.sandbox_manifest_sha256,
            image_id=capabilities.image_id,
            report=report,
            run_identity=identity,
            cleanup_pending=True,
        )
        before_remove(outcome)
    except _ContainerCreateFailure as failure:
        removed = False
        if failure.container_id is not None:
            identity = _SandboxRunIdentity(
                container_id=failure.container_id,
                container_name=invocation.container_name,
                labels=invocation.labels,
                session_id=session_id,
                candidate_id=candidate_id,
                run_token_sha256=invocation.run_token_sha256,
            )
            accepted = register_run(identity) is True
            removed = _remove_invocation_container(
                invocation,
                failure.container_id,
                process_invoke,
            )
            if not accepted and removed and not release_run(identity):
                release_intent(intent)
        else:
            removed = _remove_or_confirm_unbound_invocation(
                invocation,
                process_invoke,
                allow_absent=failure.absence_is_authoritative,
            )
            if removed:
                release_intent(intent)
        container_create_failed = True
    except BaseException:
        removed = False
        if container_id is not None:
            removed = _remove_invocation_container(invocation, container_id, process_invoke)
        else:
            removed = _remove_or_confirm_unbound_invocation(
                invocation,
                process_invoke,
                allow_absent=False,
            )
        if not run_registered and removed and (identity is None or not release_run(identity)):
            release_intent(intent)
        raise
    if container_create_failed or container_id is None:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    removed = _remove_invocation_container(invocation, container_id, process_invoke)
    return _SandboxValidationOutcome(
        session_id=outcome.session_id,
        candidate_id=outcome.candidate_id,
        policy_sha256=outcome.policy_sha256,
        sandbox_manifest_sha256=outcome.sandbox_manifest_sha256,
        image_id=outcome.image_id,
        report=outcome.report,
        run_identity=outcome.run_identity,
        cleanup_pending=not removed,
    )


def _execute_validation_start(
    invocation: _SandboxInvocation,
    policy: ValidationPolicy,
    container_id: str,
    process_invoke: _DockerProcessInvoker,
) -> _SandboxReport:
    started_at_us = time.time_ns() // 1_000
    authenticated = False
    try:
        start = _call_docker_process(
            _target_container(invocation.start_argv, invocation.container_name, container_id),
            stdin=invocation.bootstrap,
            timeout_seconds=float(policy.total_timeout_seconds),
            stream_limit=_MAX_REPORT_FRAME_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        _stop_invocation_container(invocation, container_id, process_invoke)
        raise
    else:
        if start.timed_out:
            _stop_invocation_container(invocation, container_id, process_invoke)
            report = _failed_sandbox_report(
                ValidationFailureKind.COMMAND_TIMEOUT,
                started_at_us,
            )
        elif start.output_limit or start.stderr:
            _stop_invocation_container(invocation, container_id, process_invoke)
            report = _failed_sandbox_report(
                ValidationFailureKind.SANDBOX_REPORT_INVALID,
                started_at_us,
            )
        elif start.returncode != 0:
            report = _failed_sandbox_report(
                ValidationFailureKind.SANDBOX_RUNTIME_FAILED,
                started_at_us,
            )
        else:
            try:
                report = _parse_report_frame(
                    start.stdout,
                    expected_nonce=invocation.nonce,
                    hmac_key=invocation.hmac_key,
                    expected_command_count=len(policy.commands),
                )
                _validate_report_against_policy(report, policy)
                authenticated = True
            except _SandboxProtocolError:
                report = _failed_sandbox_report(
                    ValidationFailureKind.SANDBOX_REPORT_INVALID,
                    started_at_us,
                )

    try:
        inspect, wait = _read_terminal_container(
            invocation,
            container_id,
            process_invoke,
        )
        state = _parse_terminal_container_state(
            inspect,
            wait,
            expected_container_id=container_id,
            expected_labels=invocation.labels,
        )
        if authenticated:
            _corroborate_container_result(
                report,
                inspect,
                wait,
                expected_container_id=container_id,
                expected_labels=invocation.labels,
            )
        elif state.oom_killed:
            report = _failed_sandbox_report(
                ValidationFailureKind.RESOURCE_LIMIT,
                started_at_us,
                oom_killed=True,
            )
    except RepairError:
        raise
    except _SandboxProtocolError:
        report = _failed_sandbox_report(
            ValidationFailureKind.SANDBOX_REPORT_INVALID,
            started_at_us,
        )
    return report


def _create_and_corroborate_container(
    invocation: _SandboxInvocation,
    policy: ValidationPolicy,
    process_invoke: _DockerProcessInvoker,
    *,
    mount_identity_check: _MountIdentityCheck | None,
) -> str:
    container_id: str | None = None
    creation_failed = False
    identity_error: RepairError | None = None
    try:
        if mount_identity_check is not None:
            mount_identity_check()
        container_id = _create_container_id(invocation, process_invoke)
        if mount_identity_check is not None:
            mount_identity_check()
        inspect = _inspect_created_container(invocation, container_id, process_invoke)
        if mount_identity_check is not None:
            mount_identity_check()
        _corroborate_created_container(
            inspect,
            expected_container_id=container_id,
            expected_labels=invocation.labels,
            expected_policy=policy,
            expected_command=invocation.create_argv[-5:],
            expected_bind_mounts=invocation.bind_mounts,
        )
        if mount_identity_check is not None:
            mount_identity_check()
    except _ContainerCreateFailure as failure:
        if failure.container_id is not None:
            _remove_invocation_container(invocation, failure.container_id, process_invoke)
        else:
            _remove_or_confirm_unbound_invocation(
                invocation,
                process_invoke,
                allow_absent=failure.absence_is_authoritative,
            )
        creation_failed = True
    except RepairError as error:
        if container_id is not None:
            _remove_invocation_container(invocation, container_id, process_invoke)
        identity_error = error
    except _SandboxProtocolError:
        if container_id is not None:
            _remove_invocation_container(invocation, container_id, process_invoke)
        creation_failed = True
    if identity_error is not None:
        raise identity_error
    if creation_failed:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    assert container_id is not None
    return container_id


def _create_container_id(
    invocation: _SandboxInvocation,
    process_invoke: _DockerProcessInvoker,
) -> str:
    try:
        create = _call_docker_process(
            invocation.create_argv,
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        raise _ContainerCreateFailure(None, absence_is_authoritative=False) from None

    container_id: str | None = None
    if create.returncode == 0:
        with suppress(ValueError):
            container_id = _parse_container_id(create.stdout)
    if not _docker_command_succeeded(create):
        raise _ContainerCreateFailure(
            container_id,
            absence_is_authoritative=(
                create.returncode >= 0 and not create.timed_out and not create.output_limit
            ),
        )
    if container_id is None:
        raise _ContainerCreateFailure(None, absence_is_authoritative=False)
    return container_id


def _inspect_created_container(
    invocation: _SandboxInvocation,
    container_id: str,
    process_invoke: _DockerProcessInvoker,
) -> bytes:
    inspect = _call_docker_process(
        _target_container(invocation.inspect_argv, invocation.container_name, container_id),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=process_invoke,
    )
    if not _docker_command_succeeded(inspect):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return inspect.stdout


def _read_terminal_container(
    invocation: _SandboxInvocation,
    container_id: str,
    process_invoke: _DockerProcessInvoker,
) -> tuple[bytes, bytes]:
    inspect = _call_docker_process(
        _target_container(invocation.inspect_argv, invocation.container_name, container_id),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=process_invoke,
    )
    wait = _call_docker_process(
        _target_container(invocation.wait_argv, invocation.container_name, container_id),
        stdin=b"",
        timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
        stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
        process_invoke=process_invoke,
    )
    if not _docker_command_succeeded(inspect) or not _docker_command_succeeded(wait):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return inspect.stdout, wait.stdout


def _stop_invocation_container(
    invocation: _SandboxInvocation,
    container_id: str,
    process_invoke: _DockerProcessInvoker,
) -> None:
    for argv in (invocation.stop_argv, invocation.kill_argv):
        with suppress(RepairError):
            _call_docker_process(
                _target_container(argv, invocation.container_name, container_id),
                stdin=b"",
                timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
                stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
                process_invoke=process_invoke,
            )


def _remove_invocation_container(
    invocation: _SandboxInvocation,
    container_id: str,
    process_invoke: _DockerProcessInvoker,
) -> bool:
    try:
        result = _call_docker_process(
            _target_container(invocation.remove_argv, invocation.container_name, container_id),
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        return False
    return _docker_command_succeeded(result)


def _remove_or_confirm_unbound_invocation(
    invocation: _SandboxInvocation,
    process_invoke: _DockerProcessInvoker,
    *,
    allow_absent: bool,
) -> bool:
    if type(allow_absent) is not bool:
        raise TypeError("allow_absent must be an exact bool")
    try:
        inspect = _call_docker_process(
            invocation.inspect_argv,
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        return False
    if _docker_command_succeeded(inspect):
        try:
            mapping = _parse_json_object(inspect.stdout, _MAX_DOCKER_OUTPUT_BYTES)
            container_id = _string_field(mapping, "Id")
            _parse_container_state(
                inspect.stdout,
                expected_container_id=container_id,
                expected_labels=invocation.labels,
            )
        except (KeyError, TypeError, ValueError, _SandboxProtocolError):
            return False
        return _remove_invocation_container(invocation, container_id, process_invoke)
    if (
        len(invocation.remove_argv) < 5
        or invocation.remove_argv[-5:-1] != ("container", "rm", "--force", "--volumes")
        or invocation.remove_argv[-1] != invocation.container_name
    ):
        return False
    prefix = invocation.remove_argv[:-5]
    try:
        listed = _call_docker_process(
            (
                *prefix,
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{re.escape(invocation.container_name)}$",
                "--format",
                "{{.ID}}",
            ),
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
    except RepairError:
        return False
    if not _docker_command_succeeded(listed):
        return False
    if listed.stdout in {b"", b"\n"}:
        return allow_absent
    try:
        container_id = _parse_container_id(listed.stdout)
        exact_inspect = _call_docker_process(
            _target_container(invocation.inspect_argv, invocation.container_name, container_id),
            stdin=b"",
            timeout_seconds=_DOCKER_TIMEOUT_SECONDS,
            stream_limit=_MAX_DOCKER_OUTPUT_BYTES,
            process_invoke=process_invoke,
        )
        if not _docker_command_succeeded(exact_inspect):
            return False
        _parse_container_state(
            exact_inspect.stdout,
            expected_container_id=container_id,
            expected_labels=invocation.labels,
        )
    except (RepairError, ValueError, _SandboxProtocolError):
        return False
    return _remove_invocation_container(invocation, container_id, process_invoke)


def _invoke_docker_process(
    argv: tuple[str, ...],
    stdin: bytes,
    timeout_seconds: float,
    stream_limit: int,
) -> _BoundedProcessResult:
    return _run_bounded_process(
        argv,
        environment=_HOST_DOCKER_ENVIRONMENT,
        stdin=stdin,
        timeout_seconds=timeout_seconds,
        stream_limit=stream_limit,
    )


def _call_docker_process(
    argv: tuple[str, ...],
    *,
    stdin: bytes,
    timeout_seconds: float,
    stream_limit: int,
    process_invoke: _DockerProcessInvoker,
) -> _BoundedProcessResult:
    invocation_failed = False
    result: _BoundedProcessResult | None = None
    try:
        result = process_invoke(argv, stdin, timeout_seconds, stream_limit)
    except RepairError:
        raise
    except (OSError, TypeError, ValueError):
        invocation_failed = True
    if invocation_failed or result is None:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if type(result) is not _BoundedProcessResult:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return result


def _docker_command_succeeded(result: _BoundedProcessResult) -> bool:
    return (
        result.returncode == 0
        and not result.timed_out
        and not result.output_limit
        and not result.stderr
    )


def _target_container(
    argv: tuple[str, ...],
    container_name: str,
    container_id: str,
) -> tuple[str, ...]:
    if (
        type(argv) is not tuple
        or not argv
        or argv[-1] != container_name
        or _CONTAINER_ID_PATTERN.fullmatch(container_id) is None
    ):
        raise ValueError("container command target is invalid")
    return (*argv[:-1], container_id)


def _parse_container_id(value: bytes) -> str:
    if type(value) is not bytes:
        raise ValueError
    raw = value[:-1] if value.endswith(b"\n") else value
    if len(raw) != 64 or b"\n" in raw:
        raise ValueError
    try:
        container_id = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError from None
    if _CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        raise ValueError
    return container_id


def _failed_sandbox_report(
    failure_kind: ValidationFailureKind,
    started_at_us: int,
    *,
    oom_killed: bool = False,
) -> _SandboxReport:
    finished_at_us = max(started_at_us, time.time_ns() // 1_000)
    return _SandboxReport(
        success=False,
        failure_kind=failure_kind,
        started_at_us=started_at_us,
        finished_at_us=finished_at_us,
        command_results=(),
        peak_memory_bytes=0,
        oom_killed=oom_killed,
        residual_process_count=0,
        workspace_entry_count=0,
        workspace_inode_count=0,
        tracked_tree_clean=False,
    )


def _validate_report_against_policy(
    report: _SandboxReport,
    policy: ValidationPolicy,
) -> None:
    if type(report) is not _SandboxReport or type(policy) is not ValidationPolicy:
        raise TypeError("sandbox report policy inputs must use exact record types")
    for result in report.command_results:
        if (result.stdout_bytes > policy.stream_output_bytes and not result.stdout_truncated) or (
            result.stderr_bytes > policy.stream_output_bytes and not result.stderr_truncated
        ):
            raise _SandboxProtocolError
    if report.success and (
        report.peak_memory_bytes > policy.memory_bytes
        or report.workspace_entry_count > policy.workspace_entries
        or report.workspace_inode_count > policy.workspace_inodes
    ):
        raise _SandboxProtocolError


def _require_exact_asset_path(path: Path, expected: bytes) -> None:
    _require_mount_path(path, expected_directory=False)
    invalid_asset = False
    size = 0
    digest = b""
    try:
        size, digest = _regular_file_digest(path, maximum_bytes=len(expected))
    except ValueError:
        invalid_asset = True
    if invalid_asset:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if size != len(expected) or not hmac.compare_digest(digest, hashlib.sha256(expected).digest()):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)


def _require_candidate_projection(path: Path) -> None:
    _require_mount_path(path, expected_directory=True)
    try:
        path.joinpath(".git").lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise ValueError("candidate projection is unavailable") from None
    raise ValueError("candidate projection must not contain .git")


def _require_exact_file_digest(path: Path, expected_sha256: str) -> None:
    _require_sha256(expected_sha256)
    _require_mount_path(path, expected_directory=False)
    try:
        _, digest = _regular_file_digest(path)
    except ValueError:
        raise ValueError("sandbox input file is unavailable") from None
    if not hmac.compare_digest(digest.hex(), expected_sha256):
        raise ValueError("sandbox input digest does not match")


def _regular_file_digest(
    path: Path,
    *,
    maximum_bytes: int | None = None,
) -> tuple[int, bytes]:
    if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes < 0):
        raise TypeError("maximum_bytes must be a non-negative exact integer or None")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("file is unavailable") from None
    digest = hashlib.sha256()
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise ValueError("file has an invalid type")
        if maximum_bytes is not None and status.st_size > maximum_bytes:
            raise ValueError("file exceeds its bound")
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            digest.update(chunk)
    except OSError:
        raise ValueError("file is unavailable") from None
    finally:
        os.close(descriptor)
    return status.st_size, digest.digest()


def _decode_authenticated_frame(
    frame: bytes,
    *,
    expected_nonce: bytes,
    hmac_key: bytes,
) -> bytes:
    minimum = _FRAME_HEADER.size + 2 + _HMAC_BYTES
    if len(frame) < minimum:
        raise _SandboxProtocolError
    try:
        magic, payload_length = _FRAME_HEADER.unpack(frame[: _FRAME_HEADER.size])
    except struct.error:
        raise _SandboxProtocolError from None
    if magic != _REPORT_MAGIC or not 2 <= payload_length <= _MAX_REPORT_BYTES:
        raise _SandboxProtocolError
    expected_length = _FRAME_HEADER.size + payload_length + _HMAC_BYTES
    if len(frame) != expected_length:
        raise _SandboxProtocolError
    payload_end = _FRAME_HEADER.size + payload_length
    payload = frame[_FRAME_HEADER.size : payload_end]
    supplied_mac = frame[payload_end:]
    expected_mac = hmac.new(
        hmac_key,
        _REPORT_HMAC_DOMAIN + expected_nonce + payload,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise _SandboxProtocolError
    return payload


def _command_result_from_mapping(value: object, expected_index: int) -> ValidationCommandResult:
    if type(value) is not dict:
        raise ValueError
    mapping = cast(dict[object, object], value)
    expected_keys = {
        "command_index",
        "exit_code",
        "signal",
        "timed_out",
        "duration_us",
        "stdout_sha256",
        "stdout_bytes",
        "stdout_truncated",
        "stderr_sha256",
        "stderr_bytes",
        "stderr_truncated",
    }
    if set(mapping) != expected_keys or mapping["command_index"] != expected_index:
        raise ValueError
    exit_code = _optional_nonnegative_int(mapping["exit_code"])
    signal_value = _optional_nonnegative_int(mapping["signal"])
    return ValidationCommandResult(
        command_index=expected_index,
        exit_code=exit_code,
        signal=signal_value,
        timed_out=_exact_bool(mapping["timed_out"]),
        duration_us=_exact_nonnegative_int(mapping["duration_us"]),
        stdout_sha256=_exact_sha256(mapping["stdout_sha256"]),
        stdout_bytes=_exact_nonnegative_int(mapping["stdout_bytes"]),
        stdout_truncated=_exact_bool(mapping["stdout_truncated"]),
        stderr_sha256=_exact_sha256(mapping["stderr_sha256"]),
        stderr_bytes=_exact_nonnegative_int(mapping["stderr_bytes"]),
        stderr_truncated=_exact_bool(mapping["stderr_truncated"]),
    )


def _validate_report_semantics(report: _SandboxReport, expected_command_count: int) -> None:
    if report.success:
        if (
            report.failure_kind is not None
            or len(report.command_results) != expected_command_count
            or report.oom_killed
            or report.residual_process_count != 0
            or not report.tracked_tree_clean
            or any(
                result.exit_code != 0
                or result.signal is not None
                or result.timed_out
                or result.stdout_truncated
                or result.stderr_truncated
                for result in report.command_results
            )
        ):
            raise ValueError
        return
    if report.failure_kind is None:
        raise ValueError
    evidence = {
        ValidationFailureKind.COMMAND_EXIT_NONZERO: any(
            result.exit_code not in (None, 0) for result in report.command_results
        ),
        ValidationFailureKind.COMMAND_TIMEOUT: any(
            result.timed_out for result in report.command_results
        )
        or len(report.command_results) < expected_command_count,
        ValidationFailureKind.COMMAND_SIGNAL: any(
            result.signal is not None for result in report.command_results
        ),
        ValidationFailureKind.OUTPUT_LIMIT: any(
            result.stdout_truncated or result.stderr_truncated for result in report.command_results
        ),
        ValidationFailureKind.RESOURCE_LIMIT: True,
        ValidationFailureKind.RESIDUAL_PROCESS: report.residual_process_count > 0,
        ValidationFailureKind.TRACKED_TREE_CHANGED: not report.tracked_tree_clean,
        ValidationFailureKind.SANDBOX_REPORT_INVALID: False,
        ValidationFailureKind.SANDBOX_RUNTIME_FAILED: True,
    }
    if not evidence[report.failure_kind]:
        raise ValueError


def _require_tracked_inputs(value: tuple[_TrackedInput, ...]) -> None:
    if type(value) is not tuple or len(value) > 20_000:
        raise ValueError("tracked_inputs must be a bounded exact tuple")
    if any(type(item) is not _TrackedInput for item in value):
        raise TypeError("tracked_inputs must contain exact _TrackedInput values")
    paths = tuple(item.path for item in value)
    if paths != tuple(sorted(paths, key=_path_sort_key)) or len(paths) != len(set(paths)):
        raise ValueError("tracked_inputs must be uniquely sorted by UTF-8 path bytes")


def _require_labels(value: tuple[tuple[str, str], ...]) -> None:
    if (
        type(value) is not tuple
        or not value
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or not item[0]
            or not item[1]
            for item in value
        )
    ):
        raise ValueError("container labels are invalid")
    keys = tuple(item[0] for item in value)
    if len(keys) != len(set(keys)):
        raise ValueError("container labels must be unique")


def _require_mount_path(path: Path, *, expected_directory: bool) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("sandbox mount paths must be absolute pathlib.Path values")
    try:
        status = path.lstat()
    except OSError:
        raise ValueError("sandbox mount path is unavailable") from None
    expected = stat.S_ISDIR(status.st_mode) if expected_directory else stat.S_ISREG(status.st_mode)
    if not expected or stat.S_ISLNK(status.st_mode):
        raise ValueError("sandbox mount path has an invalid type")


def _require_owned_socket(path: Path) -> None:
    unavailable = False
    status: os.stat_result | None = None
    try:
        status = path.lstat()
    except OSError:
        unavailable = True
    if unavailable or status is None:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if (
        not stat.S_ISSOCK(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid != os.geteuid()
    ):
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)


def _read_asset(resource: Traversable) -> bytes:
    unavailable = False
    content = b""
    try:
        content = resource.read_bytes()
    except (AttributeError, OSError):
        unavailable = True
    if unavailable:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    if type(content) is not bytes or not content or len(content) > _MAX_ASSET_BYTES:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return content


def _parse_canonical_object(raw: bytes) -> dict[str, object]:
    mapping = _parse_json_object(raw, _MAX_ASSET_BYTES)
    if _canonical_bytes(mapping) != raw:
        raise ValueError("JSON is not canonical")
    return mapping


def _parse_packaged_canonical_object(raw: bytes) -> dict[str, object]:
    invalid = False
    mapping: dict[str, object] = {}
    try:
        mapping = _parse_canonical_object(raw)
    except (TypeError, ValueError):
        invalid = True
    if invalid:
        raise _sandbox_error(RepairErrorCode.SANDBOX_UNAVAILABLE)
    return mapping


def _parse_json_object(raw: bytes, maximum: int) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise ValueError("JSON bytes are invalid")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("JSON bytes are invalid") from None
    if type(value) is not dict:
        raise ValueError("JSON value must be an object")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(_: str) -> Never:
    raise ValueError("non-finite JSON number")


def _mapping_field(value: Mapping[str, object], name: str) -> dict[str, object]:
    field = value[name]
    if type(field) is not dict:
        raise ValueError
    return cast(dict[str, object], field)


def _string_field(value: Mapping[str, object], name: str) -> str:
    return _exact_string(value[name])


def _bool_field(value: Mapping[str, object], name: str) -> bool:
    return _exact_bool(value[name])


def _nonnegative_int_field(value: Mapping[str, object], name: str) -> int:
    return _exact_nonnegative_int(value[name])


def _exact_string(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    value.encode("utf-8")
    return value


def _exact_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError
    return value


def _exact_nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError
    return value


def _optional_nonnegative_int(value: object) -> int | None:
    return None if value is None else _exact_nonnegative_int(value)


def _exact_sha256(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    _require_sha256(value)
    return value


def _require_sha256(value: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("SHA-256 value is invalid")


def _sandbox_error(code: RepairErrorCode) -> RepairError:
    return RepairError(code, RepairStage.SANDBOX)
