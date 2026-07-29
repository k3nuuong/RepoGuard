"""Standalone PID-1 validation runner for the M5 rootless Docker sandbox."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Never, cast

_BOOTSTRAP_MAGIC = b"RGB1"
_REPORT_MAGIC = b"RGR1"
_FRAME_HEADER = struct.Struct(">4sQ")
_REPORT_HMAC_DOMAIN = b"repoguard.m5.sandbox-report.v1\x00"
_MAX_BOOTSTRAP_BYTES = 8 * 1_048_576
_SECRET_BYTES = 32
_READ_CHUNK = 65_536
_TERM_GRACE_SECONDS = 0.25
_PIPE_DRAIN_SECONDS = 0.25
_WORKSPACE = Path("/workspace/repository")
_INPUT = Path("/input/repository")
_GIT_DIRECTORY = Path("/input/git/repository")
_GIT_INDEX = Path("/input/git/index")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

_FIXED_ENVIRONMENT: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HOME": "/home/repoguard",
    "TMPDIR": "/tmp",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "UV_NO_CONFIG": "1",
    "UV_NO_PROGRESS": "1",
    "UV_OFFLINE": "1",
    "UV_PYTHON_DOWNLOADS": "never",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INDEX": "1",
    "PIP_NO_INPUT": "1",
}

_FAILURE_KINDS = frozenset(
    {
        "command_exit_nonzero",
        "command_timeout",
        "command_signal",
        "output_limit",
        "resource_limit",
        "residual_process",
        "tracked_tree_changed",
        "sandbox_runtime_failed",
    }
)
_POLICY_KEYS = frozenset(
    {
        "image_id",
        "commands",
        "command_timeout_seconds",
        "total_timeout_seconds",
        "memory_bytes",
        "nano_cpus",
        "pids_limit",
        "stream_output_bytes",
        "workspace_bytes",
        "workspace_inodes",
        "workspace_entries",
        "tmp_bytes",
        "tmp_inodes",
        "home_bytes",
        "home_inodes",
        "run_bytes",
        "run_inodes",
    }
)


class _RunnerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _Command:
    argv: tuple[str, ...]
    cwd: str


@dataclass(frozen=True, slots=True)
class _Policy:
    commands: tuple[_Command, ...]
    command_timeout_seconds: int
    total_timeout_seconds: int
    stream_output_bytes: int
    workspace_inodes: int
    workspace_entries: int


@dataclass(frozen=True, slots=True)
class _TrackedFile:
    path: str
    sha256: str
    executable: bool


@dataclass(frozen=True, slots=True)
class _Bootstrap:
    nonce: bytes
    hmac_key: bytes
    policy: _Policy
    tracked_inputs: tuple[_TrackedFile, ...]
    git_index_sha256: str
    expected_tree_oid: str


@dataclass(frozen=True, slots=True)
class _CommandResult:
    command_index: int
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_us: int
    stdout_sha256: str
    stdout_bytes: int
    stdout_truncated: bool
    stderr_sha256: str
    stderr_bytes: int
    stderr_truncated: bool


@dataclass(frozen=True, slots=True)
class _Report:
    success: bool
    failure_kind: str | None
    started_at_us: int
    finished_at_us: int
    command_results: tuple[_CommandResult, ...]
    peak_memory_bytes: int
    oom_killed: bool
    residual_process_count: int
    workspace_entry_count: int
    workspace_inode_count: int
    tracked_tree_clean: bool


@dataclass(frozen=True, slots=True)
class _StreamResult:
    returncode: int
    duration_us: int
    timed_out: bool
    stdout_sha256: str
    stdout_bytes: int
    stdout_truncated: bool
    stderr_sha256: str
    stderr_bytes: int
    stderr_truncated: bool


def main() -> int:
    _silence_stderr()
    os.environ.clear()
    os.environ.update(_FIXED_ENVIRONMENT)
    if (
        os.getpid() != 1
        or os.geteuid() != 0
        or platform.system() != "Linux"
        or platform.machine().lower() not in {"amd64", "x86_64"}
    ):
        return 70
    try:
        _set_process_security()
        bootstrap = _read_bootstrap()
    except (OSError, ValueError, _RunnerError):
        return 70

    started_at_us = _now_us()
    try:
        report = _execute(bootstrap, started_at_us)
    except BaseException:
        report = _Report(
            success=False,
            failure_kind="sandbox_runtime_failed",
            started_at_us=started_at_us,
            finished_at_us=_now_us(),
            command_results=(),
            peak_memory_bytes=0,
            oom_killed=False,
            residual_process_count=0,
            workspace_entry_count=0,
            workspace_inode_count=0,
            tracked_tree_clean=False,
        )
    try:
        frame = _encode_report(report, bootstrap.nonce, bootstrap.hmac_key)
        _write_all(1, frame)
    except (OSError, ValueError):
        return 70
    return 0


def _execute(bootstrap: _Bootstrap, started_at_us: int) -> _Report:
    _copy_candidate(bootstrap.tracked_inputs, bootstrap.git_index_sha256)
    initial_oom_count = _read_oom_kill_count()
    deadline = time.monotonic() + bootstrap.policy.total_timeout_seconds
    results: list[_CommandResult] = []
    failure_kind: str | None = None
    residual_count = 0

    for index, command in enumerate(bootstrap.policy.commands):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure_kind = "command_timeout"
            break
        stream_result = _run_command(
            command,
            timeout_seconds=min(
                float(bootstrap.policy.command_timeout_seconds),
                remaining,
            ),
            stream_limit=bootstrap.policy.stream_output_bytes,
        )
        command_result = _to_command_result(index, stream_result)
        results.append(command_result)
        residual = _remove_residual_processes()
        residual_count += residual
        if residual:
            failure_kind = "residual_process"
            break
        entry_count, inode_count = _workspace_counts(_WORKSPACE)
        if (
            entry_count > bootstrap.policy.workspace_entries
            or inode_count > bootstrap.policy.workspace_inodes
        ):
            failure_kind = "resource_limit"
            break
        failure_kind = _command_failure_kind(command_result)
        if failure_kind is not None:
            break

    tracked_tree_clean = _tracked_tree_is_clean(bootstrap)
    entry_count, inode_count = _workspace_counts(_WORKSPACE)
    oom_count = _read_oom_kill_count()
    oom_killed = oom_count > initial_oom_count
    peak_memory_bytes = _read_memory_peak()
    if failure_kind is None:
        if oom_killed or (
            entry_count > bootstrap.policy.workspace_entries
            or inode_count > bootstrap.policy.workspace_inodes
        ):
            failure_kind = "resource_limit"
        elif not tracked_tree_clean:
            failure_kind = "tracked_tree_changed"
        elif len(results) != len(bootstrap.policy.commands):
            failure_kind = "command_timeout"

    return _Report(
        success=failure_kind is None,
        failure_kind=failure_kind,
        started_at_us=started_at_us,
        finished_at_us=_now_us(),
        command_results=tuple(results),
        peak_memory_bytes=peak_memory_bytes,
        oom_killed=oom_killed,
        residual_process_count=residual_count,
        workspace_entry_count=entry_count,
        workspace_inode_count=inode_count,
        tracked_tree_clean=tracked_tree_clean,
    )


def _read_bootstrap() -> _Bootstrap:
    header = _read_exact(0, _FRAME_HEADER.size)
    try:
        magic, size = _FRAME_HEADER.unpack(header)
    except struct.error:
        raise _RunnerError from None
    if magic != _BOOTSTRAP_MAGIC or not 2 <= size <= _MAX_BOOTSTRAP_BYTES:
        raise _RunnerError
    payload = _read_exact(0, size)
    if os.read(0, 1):
        raise _RunnerError
    mapping = _parse_canonical_object(payload)
    if (
        set(mapping)
        != {
            "schema_version",
            "nonce",
            "hmac_key",
            "policy",
            "tracked_inputs",
            "git_index_sha256",
            "expected_tree_oid",
        }
        or mapping["schema_version"] != 1
    ):
        raise _RunnerError
    nonce = _hex_secret(mapping["nonce"])
    hmac_key = _hex_secret(mapping["hmac_key"])
    policy = _parse_policy(mapping["policy"])
    tracked_inputs = _parse_tracked_files(mapping["tracked_inputs"])
    git_index_sha256 = _sha256_value(mapping["git_index_sha256"])
    expected_tree_oid = _string(mapping["expected_tree_oid"])
    if _OID_PATTERN.fullmatch(expected_tree_oid) is None:
        raise _RunnerError
    return _Bootstrap(
        nonce=nonce,
        hmac_key=hmac_key,
        policy=policy,
        tracked_inputs=tracked_inputs,
        git_index_sha256=git_index_sha256,
        expected_tree_oid=expected_tree_oid,
    )


def _parse_policy(value: object) -> _Policy:
    mapping = _mapping(value)
    if frozenset(mapping) != _POLICY_KEYS:
        raise _RunnerError
    raw_commands = mapping["commands"]
    if type(raw_commands) is not list or not 1 <= len(raw_commands) <= 8:
        raise _RunnerError
    commands: list[_Command] = []
    for raw_command in cast(list[object], raw_commands):
        command = _mapping(raw_command)
        if set(command) != {"argv", "cwd"}:
            raise _RunnerError
        raw_argv = command["argv"]
        if (
            type(raw_argv) is not list
            or not 1 <= len(raw_argv) <= 64
            or any(type(argument) is not str for argument in raw_argv)
        ):
            raise _RunnerError
        argv = tuple(cast(list[str], raw_argv))
        for argument in argv:
            _validate_text(argument, maximum=4_096)
        if not argv[0].startswith("/"):
            raise _RunnerError
        cwd = _string(command["cwd"])
        _validate_container_path(argv[0])
        _validate_container_path(cwd)
        if cwd != "/workspace" and not cwd.startswith("/workspace/"):
            raise _RunnerError
        commands.append(_Command(argv=argv, cwd=cwd))
    ceilings = {
        "command_timeout_seconds": 300,
        "total_timeout_seconds": 900,
        "memory_bytes": 2_147_483_648,
        "nano_cpus": 2_000_000_000,
        "pids_limit": 128,
        "stream_output_bytes": 1_048_576,
        "workspace_bytes": 1_073_741_824,
        "workspace_inodes": 65_536,
        "workspace_entries": 50_000,
        "tmp_bytes": 268_435_456,
        "tmp_inodes": 16_384,
        "home_bytes": 67_108_864,
        "home_inodes": 4_096,
        "run_bytes": 16_777_216,
        "run_inodes": 1_024,
    }
    validated = {
        name: _bounded_int(mapping[name], maximum=maximum) for name, maximum in ceilings.items()
    }
    if validated["total_timeout_seconds"] < validated["command_timeout_seconds"]:
        raise _RunnerError
    image_id = mapping["image_id"]
    if (
        type(image_id) is not str
        or not image_id.startswith("sha256:")
        or _SHA256_PATTERN.fullmatch(image_id.removeprefix("sha256:")) is None
    ):
        raise _RunnerError
    return _Policy(
        commands=tuple(commands),
        command_timeout_seconds=validated["command_timeout_seconds"],
        total_timeout_seconds=validated["total_timeout_seconds"],
        stream_output_bytes=validated["stream_output_bytes"],
        workspace_inodes=validated["workspace_inodes"],
        workspace_entries=validated["workspace_entries"],
    )


def _parse_tracked_files(value: object) -> tuple[_TrackedFile, ...]:
    if type(value) is not list or len(value) > 20_000:
        raise _RunnerError
    tracked: list[_TrackedFile] = []
    for raw_item in cast(list[object], value):
        item = _mapping(raw_item)
        if set(item) != {"path", "sha256", "executable"}:
            raise _RunnerError
        path = _string(item["path"])
        _validate_repository_path(path)
        executable = item["executable"]
        if type(executable) is not bool:
            raise _RunnerError
        tracked.append(
            _TrackedFile(
                path=path,
                sha256=_sha256_value(item["sha256"]),
                executable=executable,
            )
        )
    paths = tuple(item.path for item in tracked)
    if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
        raise _RunnerError
    if len(paths) != len(set(paths)):
        raise _RunnerError
    return tuple(tracked)


def _copy_candidate(
    tracked_files: tuple[_TrackedFile, ...],
    expected_git_index_sha256: str,
) -> None:
    try:
        if _WORKSPACE.exists():
            raise _RunnerError
        _WORKSPACE.mkdir(mode=0o700, parents=True)
        expected_paths = {item.path for item in tracked_files}
        observed_paths = _regular_tree_paths(_INPUT)
        if observed_paths != expected_paths:
            raise _RunnerError
        for tracked in tracked_files:
            source_fd = _open_regular_beneath(_INPUT, tracked.path)
            source_status = os.fstat(source_fd)
            if bool(source_status.st_mode & 0o111) is not tracked.executable:
                os.close(source_fd)
                raise _RunnerError
            destination = _WORKSPACE.joinpath(*tracked.path.split("/"))
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            destination_fd = os.open(destination, flags, 0o700 if tracked.executable else 0o600)
            digest = hashlib.sha256()
            try:
                while True:
                    chunk = os.read(source_fd, _READ_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    _write_all(destination_fd, chunk)
                os.fsync(destination_fd)
                os.fchmod(destination_fd, 0o700 if tracked.executable else 0o600)
            finally:
                os.close(source_fd)
                os.close(destination_fd)
            if not hmac.compare_digest(digest.hexdigest(), tracked.sha256):
                raise _RunnerError
        if not hmac.compare_digest(
            _sha256_file(_GIT_INDEX),
            expected_git_index_sha256,
        ):
            raise _RunnerError
    except OSError:
        raise _RunnerError from None


def _run_command(
    command: _Command,
    *,
    timeout_seconds: float,
    stream_limit: int,
) -> _StreamResult:
    started_ns = time.monotonic_ns()
    cwd = Path(command.cwd)
    if not cwd.is_dir():
        raise _RunnerError
    try:
        process = subprocess.Popen(
            command.argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=command.cwd,
            env=dict(_FIXED_ENVIRONMENT),
            shell=False,
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, ValueError):
        raise _RunnerError from None
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise _RunnerError

    stdout_hash = hashlib.sha256()
    stderr_hash = hashlib.sha256()
    stdout_bytes = 0
    stderr_bytes = 0
    stdout_truncated = False
    stderr_truncated = False
    timed_out = False
    terminated = False
    drain_deadline: float | None = None
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline and not timed_out:
                timed_out = True
                _terminate_command_processes(process)
                terminated = True
                drain_deadline = time.monotonic() + _PIPE_DRAIN_SECONDS
            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                break
            wait_seconds = 0.05
            if drain_deadline is not None:
                wait_seconds = min(wait_seconds, max(0.0, drain_deadline - time.monotonic()))
            if not selector.get_map():
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=wait_seconds)
                continue
            events = selector.select(wait_seconds)
            for key, _ in events:
                stream = cast(BinaryIO, key.fileobj)
                try:
                    chunk = os.read(stream.fileno(), _READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if key.data == "stdout":
                    stdout_hash.update(chunk)
                    stdout_bytes += len(chunk)
                    if stdout_bytes > stream_limit and not stdout_truncated:
                        stdout_truncated = True
                        if not terminated:
                            _terminate_command_processes(process)
                            terminated = True
                            drain_deadline = time.monotonic() + _PIPE_DRAIN_SECONDS
                else:
                    stderr_hash.update(chunk)
                    stderr_bytes += len(chunk)
                    if stderr_bytes > stream_limit and not stderr_truncated:
                        stderr_truncated = True
                        if not terminated:
                            _terminate_command_processes(process)
                            terminated = True
                            drain_deadline = time.monotonic() + _PIPE_DRAIN_SECONDS
            if process.poll() is not None and not events:
                continue
        if process.poll() is None:
            _terminate_command_processes(process)
        returncode = process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        _terminate_command_processes(process)
        raise _RunnerError from None
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    return _StreamResult(
        returncode=returncode,
        duration_us=(time.monotonic_ns() - started_ns) // 1_000,
        timed_out=timed_out,
        stdout_sha256=stdout_hash.hexdigest(),
        stdout_bytes=stdout_bytes,
        stdout_truncated=stdout_truncated,
        stderr_sha256=stderr_hash.hexdigest(),
        stderr_bytes=stderr_bytes,
        stderr_truncated=stderr_truncated,
    )


def _to_command_result(index: int, value: _StreamResult) -> _CommandResult:
    exit_code = value.returncode if value.returncode >= 0 else None
    signal_value = -value.returncode if value.returncode < 0 else None
    return _CommandResult(
        command_index=index,
        exit_code=exit_code,
        signal=signal_value,
        timed_out=value.timed_out,
        duration_us=value.duration_us,
        stdout_sha256=value.stdout_sha256,
        stdout_bytes=value.stdout_bytes,
        stdout_truncated=value.stdout_truncated,
        stderr_sha256=value.stderr_sha256,
        stderr_bytes=value.stderr_bytes,
        stderr_truncated=value.stderr_truncated,
    )


def _command_failure_kind(result: _CommandResult) -> str | None:
    if result.timed_out:
        return "command_timeout"
    if result.stdout_truncated or result.stderr_truncated:
        return "output_limit"
    if result.signal is not None:
        return "command_signal"
    if result.exit_code != 0:
        return "command_exit_nonzero"
    return None


def _tracked_tree_is_clean(bootstrap: _Bootstrap) -> bool:
    try:
        if not hmac.compare_digest(_sha256_file(_GIT_INDEX), bootstrap.git_index_sha256):
            return False
        if not _git_index_matches_tree(bootstrap.expected_tree_oid):
            return False
        for tracked in bootstrap.tracked_inputs:
            descriptor = _open_regular_beneath(_WORKSPACE, tracked.path)
            digest = hashlib.sha256()
            try:
                status = os.fstat(descriptor)
                executable = bool(status.st_mode & 0o111)
                if executable is not tracked.executable:
                    return False
                while True:
                    chunk = os.read(descriptor, _READ_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(descriptor)
            if not hmac.compare_digest(digest.hexdigest(), tracked.sha256):
                return False
        return True
    except (OSError, _RunnerError):
        return False


def _git_index_matches_tree(expected_tree_oid: str) -> bool:
    environment = dict(_FIXED_ENVIRONMENT)
    environment.update(
        {
            "GIT_DIR": str(_GIT_DIRECTORY),
            "GIT_INDEX_FILE": str(_GIT_INDEX),
            "GIT_WORK_TREE": str(_WORKSPACE),
        }
    )
    try:
        result = subprocess.run(
            (
                "/usr/bin/git",
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "protocol.allow=never",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.attributesFile=/dev/null",
                "diff-index",
                "--cached",
                "--quiet",
                "--no-ext-diff",
                "--ignore-submodules=all",
                expected_tree_oid,
                "--",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env=environment,
            shell=False,
            timeout=10.0,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False
    return result.returncode == 0


def _regular_tree_paths(root: Path) -> set[str]:
    result: set[str] = set()
    root_status = root.lstat()
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise _RunnerError
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in tuple(directories):
            child = directory_path / name
            status = child.lstat()
            if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
                raise _RunnerError
        for name in files:
            child = directory_path / name
            status = child.lstat()
            if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
                raise _RunnerError
            result.add(child.relative_to(root).as_posix())
    return result


def _open_regular_beneath(root: Path, relative: str) -> int:
    components = relative.split("/")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in components[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        result = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        status = os.fstat(result)
        if not stat.S_ISREG(status.st_mode):
            os.close(result)
            raise _RunnerError
        return result
    finally:
        os.close(descriptor)


def _workspace_counts(root: Path) -> tuple[int, int]:
    entries = 0
    inodes: set[tuple[int, int]] = set()
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in (*directories, *files):
            status = (directory_path / name).lstat()
            entries += 1
            inodes.add((status.st_dev, status.st_ino))
    return entries, len(inodes)


def _remove_residual_processes() -> int:
    residual = _container_process_ids()
    for process_id in residual:
        with suppress(ProcessLookupError):
            os.kill(process_id, signal.SIGKILL)
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        _reap_children()
        if not _container_process_ids():
            break
        time.sleep(0.01)
    return len(residual)


def _container_process_ids() -> tuple[int, ...]:
    process_ids: list[int] = []
    try:
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                process_id = int(entry.name)
                if process_id != 1:
                    process_ids.append(process_id)
    except OSError:
        raise _RunnerError from None
    return tuple(sorted(process_ids))


def _reap_children() -> None:
    while True:
        try:
            process_id, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if process_id == 0:
            return


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    process.poll()
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + _TERM_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _terminate_command_processes(process: subprocess.Popen[bytes]) -> None:
    _kill_process_group(process)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_TERM_GRACE_SECONDS)
    _remove_residual_processes()


def _cgroup_root() -> Path:
    try:
        content = Path("/proc/self/cgroup").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise _RunnerError from None
    lines = content.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise _RunnerError
    relative = lines[0][4:]
    return Path("/sys/fs/cgroup") / relative


def _read_memory_peak() -> int:
    return _read_nonnegative_file(_cgroup_root() / "memory.peak")


def _read_oom_kill_count() -> int:
    try:
        lines = (_cgroup_root() / "memory.events").read_text(encoding="ascii").splitlines()
        values = dict(line.split(" ", 1) for line in lines)
        return _nonnegative_decimal(values["oom_kill"])
    except (KeyError, OSError, UnicodeError, ValueError):
        raise _RunnerError from None


def _read_nonnegative_file(path: Path) -> int:
    try:
        return _nonnegative_decimal(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        raise _RunnerError from None


def _encode_report(report: _Report, nonce: bytes, hmac_key: bytes) -> bytes:
    if report.failure_kind is not None and report.failure_kind not in _FAILURE_KINDS:
        raise ValueError
    mapping: dict[str, object] = {
        "schema_version": 1,
        "nonce": nonce.hex(),
        "success": report.success,
        "failure_kind": report.failure_kind,
        "started_at_us": report.started_at_us,
        "finished_at_us": report.finished_at_us,
        "command_results": [_command_result_mapping(item) for item in report.command_results],
        "peak_memory_bytes": report.peak_memory_bytes,
        "oom_killed": report.oom_killed,
        "residual_process_count": report.residual_process_count,
        "workspace_entry_count": report.workspace_entry_count,
        "workspace_inode_count": report.workspace_inode_count,
        "tracked_tree_clean": report.tracked_tree_clean,
    }
    payload = _canonical_bytes(mapping)
    authentication = hmac.new(
        hmac_key,
        _REPORT_HMAC_DOMAIN + nonce + payload,
        hashlib.sha256,
    ).digest()
    return _FRAME_HEADER.pack(_REPORT_MAGIC, len(payload)) + payload + authentication


def _command_result_mapping(value: _CommandResult) -> dict[str, object]:
    return {
        "command_index": value.command_index,
        "exit_code": value.exit_code,
        "signal": value.signal,
        "timed_out": value.timed_out,
        "duration_us": value.duration_us,
        "stdout_sha256": value.stdout_sha256,
        "stdout_bytes": value.stdout_bytes,
        "stdout_truncated": value.stdout_truncated,
        "stderr_sha256": value.stderr_sha256,
        "stderr_bytes": value.stderr_bytes,
        "stderr_truncated": value.stderr_truncated,
    }


def _set_process_security() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(4, 0, 0, 0, 0) != 0:
        raise _RunnerError
    if prctl(36, 1, 0, 0, 0) != 0:
        raise _RunnerError


def _silence_stderr() -> None:
    try:
        descriptor = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(descriptor, 2)
        finally:
            os.close(descriptor)
    except OSError:
        pass


def _read_exact(descriptor: int, count: int) -> bytes:
    value = bytearray()
    while len(value) < count:
        chunk = os.read(descriptor, count - len(value))
        if not chunk:
            raise _RunnerError
        value.extend(chunk)
    return bytes(value)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        offset += written


def _sha256_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise _RunnerError
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _parse_canonical_object(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _RunnerError from None
    if type(value) is not dict:
        raise _RunnerError
    mapping = cast(dict[str, object], value)
    if _canonical_bytes(mapping) != raw:
        raise _RunnerError
    return mapping


def _canonical_bytes(value: dict[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _RunnerError from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_: str) -> Never:
    raise ValueError


def _mapping(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise _RunnerError
    return cast(dict[str, object], value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise _RunnerError
    _validate_text(value, maximum=4_096)
    return value


def _hex_secret(value: object) -> bytes:
    text = _string(value)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise _RunnerError
    return bytes.fromhex(text)


def _sha256_value(value: object) -> str:
    text = _string(value)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise _RunnerError
    return text


def _bounded_int(value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise _RunnerError
    return value


def _nonnegative_decimal(value: str) -> int:
    if not value.isdecimal():
        raise ValueError
    result = int(value)
    if result < 0:
        raise ValueError
    return result


def _validate_text(value: str, *, maximum: int) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise _RunnerError from None
    if (
        not encoded
        or len(encoded) > maximum
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise _RunnerError


def _validate_repository_path(value: str) -> None:
    _validate_text(value, maximum=1_024)
    if value.startswith("/") or "\\" in value or value != value.strip(" "):
        raise _RunnerError
    components = value.split("/")
    if any(
        not component
        or component in {".", ".."}
        or component.casefold() == ".git"
        or len(component.encode("utf-8")) > 255
        for component in components
    ):
        raise _RunnerError


def _validate_container_path(value: str) -> None:
    _validate_text(value, maximum=1_024)
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(component in {"", ".", ".."} for component in path.parts[1:])
    ):
        raise _RunnerError


def _now_us() -> int:
    return time.time_ns() // 1_000


if __name__ == "__main__":
    raise SystemExit(main())
