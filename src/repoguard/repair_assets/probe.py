"""Standalone capability probe for the M5 rootless Docker sandbox."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import platform
import socket
import struct
import sys
from contextlib import suppress
from pathlib import Path
from typing import Never, cast

_BOOTSTRAP_MAGIC = b"RGB1"
_REPORT_MAGIC = b"RGR1"
_FRAME_HEADER = struct.Struct(">4sQ")
_REPORT_HMAC_DOMAIN = b"repoguard.m5.sandbox-report.v1\x00"
_MAX_BOOTSTRAP_BYTES = 262_144
_SHA256_HEX_LENGTH = 64

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
_DOCKER_INITIAL_ENVIRONMENT = {**_FIXED_ENVIRONMENT, "HOSTNAME": "repoguard"}

_CHECK_NAMES = (
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


class _ProbeError(RuntimeError):
    pass


def main() -> int:
    _silence_stderr()
    initial_environment = dict(os.environ)
    os.environ.clear()
    os.environ.update(_FIXED_ENVIRONMENT)
    try:
        nonce, hmac_key, resources = _read_bootstrap()
        checks = _run_checks(resources, initial_environment)
        payload = _canonical_bytes(
            {
                "schema_version": 1,
                "nonce": nonce.hex(),
                "success": checks == _CHECK_NAMES,
                "checks": list(checks),
            }
        )
        authentication = hmac.new(
            hmac_key,
            _REPORT_HMAC_DOMAIN + nonce + payload,
            hashlib.sha256,
        ).digest()
        frame = _FRAME_HEADER.pack(_REPORT_MAGIC, len(payload)) + payload + authentication
        _write_all(1, frame)
        return 0
    except BaseException:
        return 70


def _read_bootstrap() -> tuple[bytes, bytes, dict[str, object]]:
    header = _read_exact(0, _FRAME_HEADER.size)
    try:
        magic, size = _FRAME_HEADER.unpack(header)
    except struct.error:
        raise _ProbeError from None
    if magic != _BOOTSTRAP_MAGIC or not 2 <= size <= _MAX_BOOTSTRAP_BYTES:
        raise _ProbeError
    payload = _read_exact(0, size)
    if os.read(0, 1):
        raise _ProbeError
    mapping = _parse_canonical_object(payload)
    if set(mapping) != {"schema_version", "nonce", "hmac_key", "resources"}:
        raise _ProbeError
    if mapping["schema_version"] != 1:
        raise _ProbeError
    nonce = _secret(mapping["nonce"])
    hmac_key = _secret(mapping["hmac_key"])
    resources = _mapping(mapping["resources"])
    if set(resources) != {
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
    }:
        raise _ProbeError
    if any(type(value) is not int or value <= 0 for value in resources.values()):
        raise _ProbeError
    return nonce, hmac_key, resources


def _run_checks(
    resources: dict[str, object],
    initial_environment: dict[str, str],
) -> tuple[str, ...]:
    completed: list[str] = []
    if os.getpid() == 1:
        completed.append("pid1")
    if os.geteuid() == 0:
        completed.append("uid0")
    if sys.version_info[:2] == (3, 12):
        completed.append("python312")
    if platform.system() != "Linux" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise _ProbeError

    libc = _libc()
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise _ProbeError
    completed.append("nondumpable")

    if (
        initial_environment == _DOCKER_INITIAL_ENVIRONMENT
        and dict(os.environ) == _FIXED_ENVIRONMENT
    ):
        completed.append("environment_clear")
    if _process_security_matches():
        completed.append("process_security")
    if _root_is_read_only():
        completed.append("root_read_only")
    if _tmpfs_limits_match(resources):
        completed.append("tmpfs_limits")
    if _cgroup_limits_match(resources):
        completed.append("cgroup_limits")
    if _network_is_denied():
        completed.append("network_denied")
    if _unix_socket_works():
        completed.append("unix_socket")
    if _forbidden_syscalls_are_denied(libc):
        completed.append("seccomp_denied")
    if _clone3_is_enosys(libc):
        completed.append("clone3_enosys")
    return tuple(sorted(completed))


def _root_is_read_only() -> bool:
    path = Path("/repoguard-capability-probe")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        return error.errno in {errno.EROFS, errno.EACCES, errno.EPERM}
    os.close(descriptor)
    with suppress(OSError):
        path.unlink()
    return False


def _tmpfs_limits_match(resources: dict[str, object]) -> bool:
    values = (
        ("/workspace", "workspace_bytes", "workspace_inodes"),
        ("/tmp", "tmp_bytes", "tmp_inodes"),
        ("/home/repoguard", "home_bytes", "home_inodes"),
        ("/run", "run_bytes", "run_inodes"),
    )
    try:
        for path, size_name, inode_name in values:
            status = os.statvfs(path)
            configured_size = cast(int, resources[size_name])
            configured_inodes = cast(int, resources[inode_name])
            total_size = status.f_blocks * status.f_frsize
            if (
                total_size <= 0
                or total_size > configured_size
                or status.f_files <= 0
                or status.f_files > configured_inodes
                or not _tmpfs_mount_is_secure(path)
            ):
                return False
        return True
    except OSError:
        return False


def _cgroup_limits_match(resources: dict[str, object]) -> bool:
    try:
        root = _cgroup_root()
        memory = _decimal_file(root / "memory.max")
        memory_swap = _decimal_file(root / "memory.swap.max")
        pids = _decimal_file(root / "pids.max")
        cpu_parts = (root / "cpu.max").read_text(encoding="ascii").strip().split(" ")
        if len(cpu_parts) != 2:
            return False
        quota = int(cpu_parts[0])
        period = int(cpu_parts[1])
        expected_nano_cpus = cast(int, resources["nano_cpus"])
        return (
            memory == resources["memory_bytes"]
            and memory_swap == 0
            and pids == resources["pids_limit"]
            and quota > 0
            and period > 0
            and quota * 1_000_000_000 == expected_nano_cpus * period
        )
    except (OSError, UnicodeError, ValueError):
        return False


def _process_security_matches() -> bool:
    try:
        fields: dict[str, str] = {}
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            name, separator, value = line.partition(":")
            if separator:
                fields[name] = value.strip()
        capability_names = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        return (
            all(int(fields[name], 16) == 0 for name in capability_names)
            and fields["NoNewPrivs"] == "1"
            and fields["Seccomp"] == "2"
            and int(fields["Seccomp_filters"]) >= 1
        )
    except (KeyError, OSError, UnicodeError, ValueError):
        return False


def _tmpfs_mount_is_secure(path: str) -> bool:
    try:
        for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
            before, separator, after = line.partition(" - ")
            if not separator:
                return False
            fields = before.split(" ")
            filesystem = after.split(" ")
            if len(fields) < 6 or len(filesystem) < 3:
                return False
            if fields[4] != path:
                continue
            options = set(fields[5].split(",")) | set(filesystem[2].split(","))
            return (
                filesystem[0] == "tmpfs"
                and {"rw", "nosuid", "nodev"} <= options
                and bool({"mode=700", "mode=0700"} & options)
            )
        return False
    except (OSError, UnicodeError):
        return False


def _network_is_denied() -> bool:
    try:
        internet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        return error.errno == errno.EPERM
    internet_socket.close()
    return False


def _unix_socket_works() -> bool:
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        left.sendall(b"x")
        valid = right.recv(1) == b"x"
        left.close()
        right.close()
        return valid
    except OSError:
        return False


def _forbidden_syscalls_are_denied(libc: ctypes.CDLL) -> bool:
    # x86_64 syscall numbers: unshare, bpf, io_uring_setup, personality, ioctl.
    attempts = (
        (272, (0,)),
        (321, (0, 0, 0)),
        (425, (1, 0)),
        (135, (0,)),
        (16, (-1, 0x5412, 0)),
    )
    for syscall_number, arguments in attempts:
        ctypes.set_errno(0)
        result = libc.syscall(syscall_number, *arguments)
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            return False
    return True


def _clone3_is_enosys(libc: ctypes.CDLL) -> bool:
    ctypes.set_errno(0)
    result = libc.syscall(435, 0, 0)
    return result == -1 and ctypes.get_errno() == errno.ENOSYS


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    libc.syscall.restype = ctypes.c_long
    return libc


def _cgroup_root() -> Path:
    lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise _ProbeError
    return Path("/sys/fs/cgroup") / lines[0][4:]


def _decimal_file(path: Path) -> int:
    value = path.read_text(encoding="ascii").strip()
    if not value.isdecimal():
        raise ValueError
    return int(value)


def _parse_canonical_object(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _ProbeError from None
    if type(value) is not dict:
        raise _ProbeError
    mapping = cast(dict[str, object], value)
    if _canonical_bytes(mapping) != raw:
        raise _ProbeError
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
        raise _ProbeError from None


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
        raise _ProbeError
    return cast(dict[str, object], value)


def _secret(value: object) -> bytes:
    if type(value) is not str or len(value) != _SHA256_HEX_LENGTH:
        raise _ProbeError
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise _ProbeError from None
    if len(result) != 32 or result.hex() != value:
        raise _ProbeError
    return result


def _read_exact(descriptor: int, count: int) -> bytes:
    value = bytearray()
    while len(value) < count:
        chunk = os.read(descriptor, count - len(value))
        if not chunk:
            raise _ProbeError
        value.extend(chunk)
    return bytes(value)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise _ProbeError
        offset += written


def _silence_stderr() -> None:
    try:
        descriptor = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(descriptor, 2)
        finally:
            os.close(descriptor)
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
