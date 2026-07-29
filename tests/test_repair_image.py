"""Repository-owned validation image definition and maintenance tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path
from typing import Never, cast

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_ASSET_ROOT = _PROJECT_ROOT / "src" / "repoguard" / "repair_assets" / "validation_image_v1"
_DOCKERFILE = _ASSET_ROOT / "Dockerfile"
_LOCK = _ASSET_ROOT / "image-lock.json"
_DOCKERIGNORE = _ASSET_ROOT / "Dockerfile.dockerignore"
_SCRIPT = _PROJECT_ROOT / "scripts" / "manage-repair-image.sh"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOCK_KEYS = {
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
_BASE_NAME = "docker.io/library/python:3.12.13-bookworm"
_BASE_CONFIG = "sha256:3a8bac27170e870e5499f2c0ea9d997a3a0d78a6b2c84dd5ddca56895a29bee4"
_BASE_INDEX = "sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a"
_BASE_MANIFEST = "sha256:058149828b8d4a90425f5ae6d255ee1fcfe73bf7d749635d824f4e033460d83c"
_IMAGE_CONFIG = "sha256:102ecfd6432e305a8dbbaecd6ede090a93259dde2c6356e04f55c1ba3bf38be3"
_UPSTREAM_REVISION = "3362634339580d3232e65a66dd5a36c47ae7ff14"
_BUILDER_NAME = "repoguard-repair-validation-v1"
_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_OCI_CONFIG = "application/vnd.oci.image.config.v1+json"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Never:
    raise ValueError("non-finite JSON number")


def _load_lock() -> tuple[bytes, dict[str, object]]:
    raw = _LOCK.read_bytes()
    value = json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    assert type(value) is dict
    return raw, cast(dict[str, object], value)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _supported_daemon_info() -> dict[str, object]:
    return {
        "ID": "repoguard-rootless-daemon",
        "OSType": "linux",
        "Architecture": "x86_64",
        "CgroupVersion": "2",
        "SecurityOptions": [
            "name=seccomp,profile=builtin",
            "name=rootless",
        ],
        "MemoryLimit": True,
        "SwapLimit": True,
        "CpuCfsQuota": True,
        "PidsLimit": True,
    }


def _context_inspect(socket_path: Path) -> dict[str, object]:
    return {
        "Name": _BUILDER_NAME,
        "Metadata": {"Description": "RepoGuard repair validation image v1"},
        "Endpoints": {
            "docker": {
                "Host": f"unix://{socket_path}",
                "SkipTLSVerify": False,
            }
        },
        "TLSMaterial": {},
        "Storage": {},
    }


def _builder_list() -> str:
    return json.dumps(
        {
            "Current": True,
            "Driver": "docker",
            "Dynamic": False,
            "Name": _BUILDER_NAME,
            "Nodes": [
                {
                    "Endpoint": _BUILDER_NAME,
                    "Name": _BUILDER_NAME,
                    "Platforms": ["linux/amd64"],
                    "Status": "running",
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _base_index() -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "mediaType": _OCI_INDEX,
        "manifests": [
            {
                "mediaType": _OCI_MANIFEST,
                "digest": _BASE_MANIFEST,
                "size": 2325,
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }


def _base_manifest() -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "mediaType": _OCI_MANIFEST,
        "config": {
            "mediaType": _OCI_CONFIG,
            "digest": _BASE_CONFIG,
            "size": 7401,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": f"sha256:{'1' * 64}",
                "size": 1,
            }
        ],
    }


def _build_metadata() -> dict[str, object]:
    _, lock = _load_lock()
    image_id = cast(str, lock["image_id"])
    image_tag = cast(str, lock["image_tag"])
    return {
        "containerimage.config.digest": _IMAGE_CONFIG,
        "containerimage.descriptor": {
            "mediaType": _OCI_MANIFEST,
            "digest": image_id,
            "size": 483,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        "containerimage.digest": image_id,
        "image.name": f"docker.io/{image_tag}",
    }


def _image_inspect(created: str) -> dict[str, object]:
    _, lock = _load_lock()
    image_tag = cast(str, lock["image_tag"])
    image_id = cast(str, lock["image_id"])
    base_reference = cast(str, lock["base_reference"])
    base_manifest = cast(str, lock["base_manifest_digest"])
    base_config = cast(str, lock["base_config_digest"])
    revision = cast(str, lock["upstream_revision"])
    config_digest = cast(str, lock["image_config_digest"])
    return {
        "Id": image_id,
        "Os": "linux",
        "Architecture": "amd64",
        "RepoTags": [image_tag],
        "Created": created,
        "Config": {
            "Labels": {
                "com.repoguard.validation-image.schema": "1",
                "com.repoguard.validation-image.base.config": base_config,
                "com.repoguard.validation-image.upstream.revision": revision,
                "org.opencontainers.image.base.digest": base_manifest,
                "org.opencontainers.image.base.name": base_reference.partition("@")[0],
                "org.opencontainers.image.title": "RepoGuard repair validation",
                "org.opencontainers.image.version": "python3.12.13-bookworm-v1",
            },
            "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
            "Cmd": None,
            "Entrypoint": None,
            "Healthcheck": None,
            "Shell": None,
            "Volumes": None,
            "User": "",
            "WorkingDir": "/",
        },
        "Descriptor": {
            "digest": image_id,
            "annotations": {"config.digest": config_digest},
        },
    }


def _fake_maintenance_environment(tmp_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_docker = bin_dir / "docker"
    fake_docker.write_text(
        """#!/bin/sh
if [ -n "${REPOGUARD_TEST_DOCKER_LOG:-}" ]; then
    printf 'DOCKER_HOST=%s DOCKER_CONTEXT=%s BUILDX_BUILDER=%s BUILDKIT_HOST=%s ' \
        "${DOCKER_HOST-unset}" \
        "${DOCKER_CONTEXT-unset}" \
        "${BUILDX_BUILDER-unset}" \
        "${BUILDKIT_HOST-unset}" >> "$REPOGUARD_TEST_DOCKER_LOG"
    printf 'BUILDX_CONFIG=%s DOCKER_CONFIG=%s ARGS=' \
        "${BUILDX_CONFIG-unset}" \
        "${DOCKER_CONFIG-unset}" >> "$REPOGUARD_TEST_DOCKER_LOG"
    printf 'DOCKER_TLS_VERIFY=%s DOCKER_CERT_PATH=%s ' \
        "${DOCKER_TLS_VERIFY-unset}" \
        "${DOCKER_CERT_PATH-unset}" >> "$REPOGUARD_TEST_DOCKER_LOG"
    printf '[%s]' "$@" >> "$REPOGUARD_TEST_DOCKER_LOG"
    printf '\\n' >> "$REPOGUARD_TEST_DOCKER_LOG"
fi
if [ "$1" = "context" ] && [ "$2" = "create" ]; then
    exit 0
fi
if [ "$1" = "context" ] && [ "$2" = "inspect" ]; then
    printf '%s\\n' "$REPOGUARD_TEST_CONTEXT_INSPECT"
    exit 0
fi
if [ "$3" = "info" ]; then
    printf '%s\\n' "$REPOGUARD_TEST_DOCKER_INFO"
    exit 0
fi
if [ "$3" = "image" ]; then
    printf '%s\\n' "$REPOGUARD_TEST_IMAGE_INSPECT"
    exit 0
fi
if [ "$3" = "run" ]; then
    case "$*" in
        *--entrypoint=/usr/local/bin/python3.12*)
            printf '3.12.13\\n'
            ;;
        *--entrypoint=/usr/bin/git*)
            printf 'git version 2.39.5\\n'
            ;;
        *)
            exit 78
            ;;
    esac
    exit 0
fi
if [ "$3" = "buildx" ] && [ "$4" = "inspect" ]; then
    exit 0
fi
if [ "$3" = "buildx" ] && [ "$4" = "ls" ]; then
    printf '%s\\n' "$REPOGUARD_TEST_BUILDER_LIST"
    exit 0
fi
if [ "$3" = "buildx" ] && [ "$4" = "imagetools" ]; then
    case "$*" in
        *"$REPOGUARD_TEST_BASE_INDEX_DIGEST"*)
            printf '%s\\n' "$REPOGUARD_TEST_BASE_INDEX"
            ;;
        *)
            printf '%s\\n' "$REPOGUARD_TEST_BASE_MANIFEST"
            ;;
    esac
    exit 0
fi
if [ "$3" = "buildx" ] && [ "$4" = "build" ]; then
    previous=
    for argument in "$@"; do
        if [ "$previous" = "--iidfile" ]; then
            printf '%s' "$REPOGUARD_TEST_BUILD_IID" > "$argument"
        fi
        if [ "$previous" = "--metadata-file" ]; then
            printf '%s' "$REPOGUARD_TEST_BUILD_METADATA" > "$argument"
        fi
        previous="$argument"
    done
    exit 0
fi
exit 77
""",
        encoding="ascii",
    )
    fake_docker.chmod(0o700)
    return {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "REPOGUARD_TEST_BASE_INDEX": json.dumps(_base_index()),
        "REPOGUARD_TEST_BASE_INDEX_DIGEST": _BASE_INDEX,
        "REPOGUARD_TEST_BASE_MANIFEST": json.dumps(_base_manifest()),
        "REPOGUARD_TEST_BUILDER_LIST": _builder_list(),
        "REPOGUARD_TEST_BUILD_IID": _IMAGE_CONFIG,
        "REPOGUARD_TEST_BUILD_METADATA": json.dumps(_build_metadata()),
        "REPOGUARD_TEST_CONTEXT_INSPECT": json.dumps(_context_inspect(tmp_path / "docker.sock")),
        "REPOGUARD_TEST_DOCKER_LOG": str(tmp_path / "docker.log"),
    }


def _run_maintenance(
    tmp_path: Path,
    action: str,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    docker_socket = tmp_path / "docker.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(docker_socket))
        return subprocess.run(
            (str(_SCRIPT), action, str(docker_socket)),
            cwd=_PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )


def test_validation_image_lock_is_canonical_and_complete() -> None:
    raw, lock = _load_lock()

    assert raw == _canonical_json(lock)
    assert set(lock) == _LOCK_KEYS
    assert lock["schema_version"] == 1
    assert type(lock["schema_version"]) is int
    assert lock["source_date_epoch"] == 0
    assert type(lock["source_date_epoch"]) is int
    assert lock["base_config_digest"] == _BASE_CONFIG
    assert lock["base_index_digest"] == _BASE_INDEX
    assert lock["base_manifest_digest"] == _BASE_MANIFEST
    assert lock["base_reference"] == f"{_BASE_NAME}@{_BASE_MANIFEST}"
    assert lock["platform"] == "linux/amd64"
    assert lock["image_tag"] == "repoguard/repair-validation:python3.12.13-bookworm-v1"
    assert lock["python_path"] == "/usr/local/bin/python3.12"
    assert lock["python_version"] == "3.12.13"
    assert lock["git_path"] == "/usr/bin/git"
    assert lock["git_version"] == "2.39.5"
    assert lock["image_config_digest"] == _IMAGE_CONFIG
    assert lock["upstream_revision"] == _UPSTREAM_REVISION
    assert type(lock["image_id"]) is str
    assert _DIGEST.fullmatch(lock["image_id"]) is not None
    assert lock["image_id"] != f"sha256:{'0' * 64}"


def test_validation_image_dockerfile_has_one_pinned_source_and_clean_final_config() -> None:
    raw, lock = _load_lock()
    dockerfile_bytes = _DOCKERFILE.read_bytes()
    dockerfile = dockerfile_bytes.decode("ascii")
    lines = dockerfile.splitlines()
    instructions = tuple(
        line.split(maxsplit=1)[0].upper()
        for line in lines
        if line and not line.startswith((" ", "#"))
    )

    assert raw
    assert b"\r" not in dockerfile_bytes
    assert hashlib.sha256(dockerfile_bytes).hexdigest() == lock["dockerfile_sha256"]
    assert lines[0] == f"FROM {_BASE_NAME}@{_BASE_MANIFEST} AS upstream"
    assert lines[2] == "FROM scratch"
    assert lines[3] == "COPY --from=upstream / /"
    assert lines[4] == "ENV PATH=/usr/local/bin:/usr/bin:/bin"
    assert instructions == ("FROM", "FROM", "COPY", "ENV", "LABEL")
    assert _DOCKERIGNORE.read_text(encoding="ascii") == "*\n!Dockerfile\n"
    assert f'com.repoguard.validation-image.base.config="{_BASE_CONFIG}"' in dockerfile
    assert f'com.repoguard.validation-image.upstream.revision="{_UPSTREAM_REVISION}"' in dockerfile
    assert f'org.opencontainers.image.base.digest="{_BASE_MANIFEST}"' in dockerfile
    assert f'org.opencontainers.image.base.name="{_BASE_NAME}"' in dockerfile
    for forbidden in (
        "ADD",
        "ARG",
        "CMD",
        "ENTRYPOINT",
        "EXPOSE",
        "HEALTHCHECK",
        "RUN",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    ):
        assert forbidden not in instructions


def test_validation_image_maintenance_script_is_local_only_after_build() -> None:
    script = _SCRIPT.read_text(encoding="ascii")
    mode = stat.S_IMODE(_SCRIPT.stat().st_mode)
    syntax = subprocess.run(
        ("bash", "-n", str(_SCRIPT)),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    usage = subprocess.run(
        (str(_SCRIPT),),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert mode == 0o755
    assert syntax.returncode == 0, syntax.stderr
    assert usage.returncode == 2
    assert "build|verify" in usage.stderr
    assert "--pull=never" in script
    assert "--network=none" in script
    assert "--no-cache" in script
    assert "SOURCE_DATE_EPOCH=$source_date_epoch" in script
    assert '--builder "$builder_name"' in script
    assert '--iidfile "$iid_file"' in script
    assert '--metadata-file "$metadata_file"' in script
    assert "-u BUILDX_BUILDER" in script
    assert "-u DOCKER_CONTEXT" in script
    assert '"DOCKER_CONFIG=$docker_config"' in script
    assert "docker push" not in script


def test_validation_image_maintenance_script_requires_rootless_daemon(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    environment = _fake_maintenance_environment(tmp_path)
    docker_socket = tmp_path / "docker.sock"
    supported = _supported_daemon_info()
    invalid_documents: tuple[object, ...] = (
        [],
        {**supported, "OSType": "windows"},
        {**supported, "Architecture": "arm64"},
        {**supported, "CgroupVersion": "1"},
        {**supported, "SecurityOptions": ["name=seccomp,profile=builtin"]},
        {**supported, "SecurityOptions": ["name=rootless"]},
        {**supported, "SecurityOptions": ["name=rootless", 1]},
        {**supported, "MemoryLimit": False},
    )

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(docker_socket))
        for daemon_info in invalid_documents:
            rejected = subprocess.run(
                (str(_SCRIPT), "verify", str(docker_socket)),
                cwd=_PROJECT_ROOT,
                env={
                    **environment,
                    "REPOGUARD_TEST_DOCKER_INFO": json.dumps(daemon_info),
                },
                check=False,
                capture_output=True,
                text=True,
            )
            assert rejected.returncode == 2
            assert rejected.stderr == (
                "Docker daemon is not a supported rootless Linux amd64 daemon\n"
            )

        malformed = subprocess.run(
            (str(_SCRIPT), "verify", str(docker_socket)),
            cwd=_PROJECT_ROOT,
            env={
                **environment,
                "REPOGUARD_TEST_DOCKER_INFO": "{",
            },
            check=False,
            capture_output=True,
            text=True,
        )

    assert malformed.returncode == 2
    assert malformed.stderr == ("Docker daemon is not a supported rootless Linux amd64 daemon\n")


def test_validation_image_maintenance_script_requires_exact_epoch(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    environment = {
        **_fake_maintenance_environment(tmp_path),
        "REPOGUARD_TEST_DOCKER_INFO": json.dumps(_supported_daemon_info()),
    }
    docker_socket = tmp_path / "docker.sock"

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(docker_socket))
        for created in (
            "1970-01-01T00:00:00.999Z",
            "1970-01-01T00:00:00Z-attacker",
        ):
            rejected = subprocess.run(
                (str(_SCRIPT), "verify", str(docker_socket)),
                cwd=_PROJECT_ROOT,
                env={
                    **environment,
                    "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(_image_inspect(created)),
                },
                check=False,
                capture_output=True,
                text=True,
            )
            assert rejected.returncode == 1
            assert "local validation image creation time is not reproducible" in rejected.stderr

        accepted = subprocess.run(
            (str(_SCRIPT), "verify", str(docker_socket)),
            cwd=_PROJECT_ROOT,
            env={
                **environment,
                "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(
                    _image_inspect("1970-01-01T00:00:00Z"),
                ),
            },
            check=False,
            capture_output=True,
            text=True,
        )

    assert accepted.returncode == 0, accepted.stderr
    assert "verified_image_id=sha256:" in accepted.stdout


def test_validation_image_build_uses_the_repository_rootless_builder(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    ambient_config = tmp_path / "attacker-docker-config"
    environment = {
        **_fake_maintenance_environment(tmp_path),
        "BUILDKIT_HOST": "tcp://attacker-buildkit.invalid:1234",
        "BUILDX_BUILDER": "attacker-builder",
        "BUILDX_CONFIG": str(tmp_path / "attacker-buildx-config"),
        "DOCKER_CERT_PATH": str(tmp_path / "attacker-certificates"),
        "DOCKER_CONFIG": str(ambient_config),
        "DOCKER_CONTEXT": "attacker-context",
        "DOCKER_HOST": "tcp://attacker-docker.invalid:2375",
        "DOCKER_TLS_VERIFY": "1",
        "REPOGUARD_TEST_DOCKER_INFO": json.dumps(_supported_daemon_info()),
        "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(_image_inspect("1970-01-01T00:00:00Z")),
    }

    built = _run_maintenance(tmp_path, "build", environment)

    assert built.returncode == 0, built.stderr
    assert "actual_image_id=sha256:" in built.stdout
    assert f"actual_config_digest={_IMAGE_CONFIG}" in built.stdout
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    for forbidden in (
        "attacker-builder",
        "attacker-buildkit",
        "attacker-buildx-config",
        "attacker-certificates",
        "attacker-context",
        "attacker-docker",
        str(ambient_config),
    ):
        assert forbidden not in log
    assert f"[--docker][host=unix://{tmp_path / 'docker.sock'}]" in log
    assert f"[--builder][{_BUILDER_NAME}]" in log
    assert "[--iidfile]" in log
    assert "[--metadata-file]" in log
    assert "[--network=none]" in log
    assert "[push]" not in log
    assert all(
        "DOCKER_HOST=unset" in line
        and "DOCKER_CONTEXT=unset" in line
        and "BUILDX_BUILDER=unset" in line
        and "BUILDKIT_HOST=unset" in line
        and "BUILDX_CONFIG=unset" in line
        and "DOCKER_TLS_VERIFY=unset" in line
        and "DOCKER_CERT_PATH=unset" in line
        for line in log.splitlines()
    )


def test_validation_image_build_rejects_a_mismatched_builder(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    builder = cast(dict[str, object], json.loads(_builder_list()))
    nodes = cast(list[dict[str, object]], builder["Nodes"])
    nodes[0]["Endpoint"] = "attacker-context"
    environment = {
        **_fake_maintenance_environment(tmp_path),
        "REPOGUARD_TEST_BUILDER_LIST": json.dumps(builder),
        "REPOGUARD_TEST_DOCKER_INFO": json.dumps(_supported_daemon_info()),
        "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(_image_inspect("1970-01-01T00:00:00Z")),
    }

    rejected = _run_maintenance(tmp_path, "build", environment)

    assert rejected.returncode == 2
    assert "Buildx builder does not match the rootless daemon" in rejected.stderr
    assert "[buildx][build]" not in (tmp_path / "docker.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("failure", ["index", "manifest", "metadata"])
def test_validation_image_build_rejects_broken_identity_chains(
    tmp_path: Path,
    socket_enabled: None,
    failure: str,
) -> None:
    assert socket_enabled is None
    base_index = _base_index()
    base_manifest = _base_manifest()
    metadata = _build_metadata()
    if failure == "index":
        manifests = cast(list[dict[str, object]], base_index["manifests"])
        manifests[0]["digest"] = f"sha256:{'2' * 64}"
    elif failure == "manifest":
        config = cast(dict[str, object], base_manifest["config"])
        config["digest"] = f"sha256:{'3' * 64}"
    else:
        metadata["containerimage.digest"] = f"sha256:{'4' * 64}"
    environment = {
        **_fake_maintenance_environment(tmp_path),
        "REPOGUARD_TEST_BASE_INDEX": json.dumps(base_index),
        "REPOGUARD_TEST_BASE_MANIFEST": json.dumps(base_manifest),
        "REPOGUARD_TEST_BUILD_METADATA": json.dumps(metadata),
        "REPOGUARD_TEST_DOCKER_INFO": json.dumps(_supported_daemon_info()),
        "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(_image_inspect("1970-01-01T00:00:00Z")),
    }

    rejected = _run_maintenance(tmp_path, "build", environment)

    assert rejected.returncode == 3
    if failure == "metadata":
        assert "build result does not match the image lock" in rejected.stderr
    else:
        assert "base image descriptor chain is invalid" in rejected.stderr


def test_validation_image_verify_requires_the_local_descriptor(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    image = _image_inspect("1970-01-01T00:00:00Z")
    del image["Descriptor"]
    environment = {
        **_fake_maintenance_environment(tmp_path),
        "REPOGUARD_TEST_DOCKER_INFO": json.dumps(_supported_daemon_info()),
        "REPOGUARD_TEST_IMAGE_INSPECT": json.dumps(image),
    }

    rejected = _run_maintenance(tmp_path, "verify", environment)

    assert rejected.returncode == 1
    assert "local validation image descriptor is inconsistent" in rejected.stderr
