#!/usr/bin/env bash
set -euo pipefail

umask 077

usage() {
    printf 'usage: %s build|verify [rootless-docker-socket]\n' "$0" >&2
    exit 2
}

if (( $# < 1 || $# > 2 )); then
    usage
fi

action="$1"
if [[ "$action" != "build" && "$action" != "verify" ]]; then
    usage
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
asset_root="$repo_root/src/repoguard/repair_assets/validation_image_v1"
dockerfile="$asset_root/Dockerfile"
lock_file="$asset_root/image-lock.json"
socket="${2:-/run/user/$(id -u)/docker.sock}"
builder_name="repoguard-repair-validation-v1"

docker_executable="$(command -v docker)"
python_executable="$(command -v python3.12)"
flock_executable="$(command -v flock)"

exec {maintenance_lock_fd}<"$lock_file"
if ! "$flock_executable" -w 5 "$maintenance_lock_fd"; then
    printf 'validation image maintenance is already running\n' >&2
    exit 2
fi

if [[ "$socket" != /* || -L "$socket" || ! -S "$socket" ]]; then
    printf 'rootless Docker socket is invalid\n' >&2
    exit 2
fi
if [[ "$(stat -Lc '%u' -- "$socket")" != "$(id -u)" ]]; then
    printf 'rootless Docker socket owner does not match the effective user\n' >&2
    exit 2
fi
docker_endpoint="unix://$socket"

docker_config="$(mktemp -d "${TMPDIR:-/tmp}/repoguard-repair-image.XXXXXXXX")"
chmod 0700 "$docker_config"
cleanup() {
    rm -rf -- "$docker_config"
}
trap cleanup EXIT

docker_cli=(
    env
    -u DOCKER_HOST
    -u DOCKER_CONTEXT
    -u BUILDX_BUILDER
    -u BUILDKIT_HOST
    -u BUILDX_CONFIG
    -u DOCKER_TLS_VERIFY
    -u DOCKER_CERT_PATH
    "DOCKER_CONFIG=$docker_config"
    "$docker_executable"
)

if ! daemon_info="$(
    "${docker_cli[@]}" --host "$docker_endpoint" info --format '{{json .}}' 2>/dev/null
)"; then
    printf 'Docker daemon is not a supported rootless Linux amd64 daemon\n' >&2
    exit 2
fi
if ! "$python_executable" - "$daemon_info" <<'PY'
from __future__ import annotations

import json
import sys
from typing import Never


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError


try:
    info = json.loads(
        sys.argv[1],
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (TypeError, ValueError):
    raise SystemExit(1) from None
if type(info) is not dict:
    raise SystemExit(1)
security_options = info.get("SecurityOptions")
if (
    info.get("OSType") != "linux"
    or info.get("Architecture") not in {"amd64", "x86_64"}
    or info.get("CgroupVersion") != "2"
    or type(security_options) is not list
    or any(type(item) is not str for item in security_options)
    or "name=rootless" not in security_options
    or not any(item.startswith("name=seccomp") for item in security_options)
    or any(
        info.get(capability) is not True
        for capability in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
    )
):
    raise SystemExit(1)
PY
then
    printf 'Docker daemon is not a supported rootless Linux amd64 daemon\n' >&2
    exit 2
fi

if ! "${docker_cli[@]}" context create \
    "$builder_name" \
    --description "RepoGuard repair validation image v1" \
    --docker "host=$docker_endpoint" >/dev/null
then
    printf 'repository Docker context could not be created\n' >&2
    exit 2
fi
if ! context_info="$(
    "${docker_cli[@]}" context inspect "$builder_name" --format '{{json .}}'
)" || ! context_daemon_info="$(
    "${docker_cli[@]}" --context "$builder_name" info --format '{{json .}}' 2>/dev/null
)"; then
    printf 'repository Docker context could not be inspected\n' >&2
    exit 2
fi
if ! "$python_executable" - \
    "$context_info" \
    "$daemon_info" \
    "$context_daemon_info" \
    "$builder_name" \
    "$docker_endpoint" <<'PY'
from __future__ import annotations

import json
import sys
from typing import Never


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError


def load(raw: str) -> object:
    return json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


try:
    context = load(sys.argv[1])
    direct_info = load(sys.argv[2])
    context_info = load(sys.argv[3])
except (TypeError, ValueError):
    raise SystemExit(1) from None
builder_name, docker_endpoint = sys.argv[4:]
if type(context) is not dict or type(direct_info) is not dict or type(context_info) is not dict:
    raise SystemExit(1)
endpoints = context.get("Endpoints")
docker = endpoints.get("docker") if type(endpoints) is dict else None
if (
    context.get("Name") != builder_name
    or type(docker) is not dict
    or docker.get("Host") != docker_endpoint
    or docker.get("SkipTLSVerify") is not False
    or context.get("TLSMaterial") != {}
    or type(direct_info.get("ID")) is not str
    or not direct_info["ID"]
    or context_info.get("ID") != direct_info["ID"]
):
    raise SystemExit(1)
PY
then
    printf 'repository Docker context does not match the rootless daemon\n' >&2
    exit 2
fi

lock_values=()
mapfile -d '' -t lock_values < <(
    "$python_executable" - "$lock_file" "$dockerfile" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Never

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCK_KEYS = {
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


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate image-lock key")
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError("non-finite image-lock value")


lock_path = Path(sys.argv[1])
dockerfile_path = Path(sys.argv[2])
raw = lock_path.read_bytes()
try:
    value = json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit("image lock is invalid") from error
if type(value) is not dict or set(value) != LOCK_KEYS:
    raise SystemExit("image lock schema is invalid")
lock = value
canonical = json.dumps(
    lock,
    allow_nan=False,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
).encode("utf-8")
if raw != canonical:
    raise SystemExit("image lock is not canonical JSON")
if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
    raise SystemExit("image lock schema version is invalid")
if type(lock["source_date_epoch"]) is not int or lock["source_date_epoch"] != 0:
    raise SystemExit("image build epoch is invalid")
for key in LOCK_KEYS - {"schema_version", "source_date_epoch"}:
    if type(lock[key]) is not str:
        raise SystemExit(f"image lock field {key} is invalid")
for key in (
    "base_config_digest",
    "base_index_digest",
    "base_manifest_digest",
    "image_config_digest",
    "image_id",
):
    if DIGEST.fullmatch(lock[key]) is None:
        raise SystemExit(f"image lock digest {key} is invalid")
if re.fullmatch(r"[0-9a-f]{64}", lock["dockerfile_sha256"]) is None:
    raise SystemExit("Dockerfile digest is invalid")
if lock["base_reference"] != (
    "docker.io/library/python:3.12.13-bookworm@" + lock["base_manifest_digest"]
):
    raise SystemExit("base image reference is invalid")
if lock["platform"] != "linux/amd64":
    raise SystemExit("image platform is invalid")
if lock["image_tag"] != "repoguard/repair-validation:python3.12.13-bookworm-v1":
    raise SystemExit("local image tag is invalid")
if lock["python_path"] != "/usr/local/bin/python3.12" or lock["python_version"] != "3.12.13":
    raise SystemExit("Python identity is invalid")
if lock["git_path"] != "/usr/bin/git" or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", lock["git_version"]) is None:
    raise SystemExit("Git identity is invalid")
if re.fullmatch(r"[0-9a-f]{40}", lock["upstream_revision"]) is None:
    raise SystemExit("upstream revision is invalid")
try:
    dockerfile_digest = hashlib.sha256(dockerfile_path.read_bytes()).hexdigest()
except OSError as error:
    raise SystemExit("Dockerfile is unavailable") from error
if dockerfile_digest != lock["dockerfile_sha256"]:
    raise SystemExit("Dockerfile does not match image lock")

for key in (
    "base_reference",
    "base_index_digest",
    "base_config_digest",
    "base_manifest_digest",
    "upstream_revision",
    "image_tag",
    "image_id",
    "image_config_digest",
    "platform",
    "python_path",
    "python_version",
    "git_path",
    "git_version",
    "source_date_epoch",
):
    sys.stdout.write(f"{lock[key]}\0")
PY
)

if (( ${#lock_values[@]} != 14 )); then
    printf 'image lock could not be loaded\n' >&2
    exit 2
fi

base_reference="${lock_values[0]}"
base_index_digest="${lock_values[1]}"
base_config_digest="${lock_values[2]}"
base_manifest_digest="${lock_values[3]}"
upstream_revision="${lock_values[4]}"
image_tag="${lock_values[5]}"
expected_image_id="${lock_values[6]}"
image_config_digest="${lock_values[7]}"
platform="${lock_values[8]}"
python_path="${lock_values[9]}"
python_version="${lock_values[10]}"
git_path="${lock_values[11]}"
git_version="${lock_values[12]}"
source_date_epoch="${lock_values[13]}"

# This revision is a recipe annotation. The locked manifest and config digests are authoritative.

verify_image() {
    local inspect_json
    local python_output
    local git_output

    inspect_json="$(
        "${docker_cli[@]}" --context "$builder_name" image inspect \
            --format '{{json .}}' "$image_tag"
    )"
    "$python_executable" - \
        "$inspect_json" \
        "$expected_image_id" \
        "$image_tag" \
        "$base_reference" \
        "$base_manifest_digest" \
        "$base_config_digest" \
        "$upstream_revision" \
        "$image_config_digest" <<'PY'
from __future__ import annotations

import json
import sys

image = json.loads(sys.argv[1])
expected_id, image_tag, base_reference, base_digest, base_config, revision, config_digest = (
    sys.argv[2:]
)
if type(image) is not dict:
    raise SystemExit("local validation image inspect result is invalid")
if image.get("Id") != expected_id:
    raise SystemExit("local validation image ID does not match the lock")
if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
    raise SystemExit("local validation image platform does not match the lock")
if image_tag not in image.get("RepoTags", []):
    raise SystemExit("local validation image tag is missing")
if image.get("Created") != "1970-01-01T00:00:00Z":
    raise SystemExit("local validation image creation time is not reproducible")
config = image.get("Config")
if type(config) is not dict:
    raise SystemExit("local validation image configuration is invalid")
expected_labels = {
    "com.repoguard.validation-image.schema": "1",
    "com.repoguard.validation-image.base.config": base_config,
    "com.repoguard.validation-image.upstream.revision": revision,
    "org.opencontainers.image.base.digest": base_digest,
    "org.opencontainers.image.base.name": base_reference.partition("@")[0],
    "org.opencontainers.image.title": "RepoGuard repair validation",
    "org.opencontainers.image.version": "python3.12.13-bookworm-v1",
}
if config.get("Labels") != expected_labels:
    raise SystemExit("local validation image labels do not match the lock")
if config.get("Env") != ["PATH=/usr/local/bin:/usr/bin:/bin"]:
    raise SystemExit("local validation image environment is not minimal")
for key in ("Cmd", "Entrypoint", "Healthcheck", "Shell", "Volumes"):
    if config.get(key) is not None:
        raise SystemExit(f"local validation image {key} must be empty")
if config.get("User", "") != "":
    raise SystemExit("local validation image User must be empty")
if config.get("WorkingDir") != "/":
    raise SystemExit("local validation image WorkingDir must be root")
descriptor = image.get("Descriptor")
if type(descriptor) is not dict or descriptor.get("digest") != expected_id:
    raise SystemExit("local validation image descriptor is inconsistent")
annotations = descriptor.get("annotations")
if type(annotations) is not dict or annotations.get("config.digest") != config_digest:
    raise SystemExit("local validation image config digest does not match the lock")
PY

    common_run=(
        "${docker_cli[@]}"
        --context "$builder_name"
        run
        --rm
        --pull=never
        --network=none
        --read-only
        --user=0:0
        --cap-drop=ALL
        --security-opt=no-new-privileges=true
        --pids-limit=16
        --memory=134217728
        --memory-swap=134217728
    )
    python_output="$(
        "${common_run[@]}" --entrypoint="$python_path" "$expected_image_id" \
            -I -S -E -B -c \
            'import sys; print(".".join(str(item) for item in sys.version_info[:3]))'
    )"
    if [[ "$python_output" != "$python_version" ]]; then
        printf 'local validation image Python version does not match the lock\n' >&2
        exit 1
    fi
    git_output="$(
        "${common_run[@]}" --entrypoint="$git_path" "$expected_image_id" --version
    )"
    if [[ "$git_output" != "git version $git_version" ]]; then
        printf 'local validation image Git version does not match the lock\n' >&2
        exit 1
    fi
    printf 'verified_image_id=%s\n' "$expected_image_id"
    printf 'python_version=%s\n' "$python_version"
    printf 'git_version=%s\n' "$git_version"
}

if [[ "$action" == "build" ]]; then
    if ! "${docker_cli[@]}" --context "$builder_name" buildx inspect \
        "$builder_name" --bootstrap >/dev/null
    then
        printf 'repository Buildx builder could not be bootstrapped\n' >&2
        exit 2
    fi
    if ! builder_list="$(
        "${docker_cli[@]}" --context "$builder_name" buildx ls --format '{{json .}}'
    )"; then
        printf 'repository Buildx builder could not be inspected\n' >&2
        exit 2
    fi
    if ! "$python_executable" - "$builder_list" "$builder_name" <<'PY'
from __future__ import annotations

import json
import sys
from typing import Never


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError


rows: list[object] = []
try:
    for line in sys.argv[1].splitlines():
        if line:
            rows.append(
                json.loads(
                    line,
                    object_pairs_hook=unique_object,
                    parse_constant=reject_constant,
                )
            )
except (TypeError, ValueError):
    raise SystemExit(1) from None
builder_name = sys.argv[2]
matches = [row for row in rows if type(row) is dict and row.get("Name") == builder_name]
if not matches:
    raise SystemExit(1)
canonical = {
    json.dumps(row, allow_nan=False, separators=(",", ":"), sort_keys=True) for row in matches
}
if len(canonical) != 1:
    raise SystemExit(1)
builder = matches[0]
nodes = builder.get("Nodes")
node = nodes[0] if type(nodes) is list and len(nodes) == 1 else None
platforms = node.get("Platforms") if type(node) is dict else None
if (
    builder.get("Driver") != "docker"
    or builder.get("Dynamic") is not False
    or builder.get("Err") not in (None, "")
    or type(node) is not dict
    or node.get("Name") != builder_name
    or node.get("Endpoint") != builder_name
    or node.get("Status") != "running"
    or type(platforms) is not list
    or "linux/amd64" not in platforms
):
    raise SystemExit(1)
PY
    then
        printf 'repository Buildx builder does not match the rootless daemon\n' >&2
        exit 2
    fi

    base_name="${base_reference%@*}"
    if ! base_index_json="$(
        "${docker_cli[@]}" --context "$builder_name" buildx imagetools inspect \
            --builder "$builder_name" \
            --raw \
            "$base_name@$base_index_digest"
    )" || ! base_manifest_json="$(
        "${docker_cli[@]}" --context "$builder_name" buildx imagetools inspect \
            --builder "$builder_name" \
            --raw \
            "$base_reference"
    )"; then
        printf 'locked base image descriptors could not be inspected\n' >&2
        exit 3
    fi
    if ! "$python_executable" - \
        "$base_index_json" \
        "$base_manifest_json" \
        "$base_manifest_digest" \
        "$base_config_digest" <<'PY'
from __future__ import annotations

import json
import sys
from typing import Never


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError


def load(raw: str) -> object:
    return json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


try:
    index = load(sys.argv[1])
    manifest = load(sys.argv[2])
except (TypeError, ValueError):
    raise SystemExit(1) from None
expected_manifest, expected_config = sys.argv[3:]
if type(index) is not dict or type(manifest) is not dict:
    raise SystemExit(1)
descriptors = index.get("manifests")
matching: list[object] = []
if type(descriptors) is list:
    for descriptor in descriptors:
        platform = descriptor.get("platform") if type(descriptor) is dict else None
        if (
            type(platform) is dict
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
            and platform.get("variant") in (None, "")
        ):
            matching.append(descriptor)
config = manifest.get("config")
layers = manifest.get("layers")
if (
    index.get("schemaVersion") != 2
    or index.get("mediaType") != "application/vnd.oci.image.index.v1+json"
    or len(matching) != 1
    or matching[0].get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
    or matching[0].get("digest") != expected_manifest
    or manifest.get("schemaVersion") != 2
    or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
    or type(config) is not dict
    or config.get("mediaType") != "application/vnd.oci.image.config.v1+json"
    or config.get("digest") != expected_config
    or type(layers) is not list
    or not layers
):
    raise SystemExit(1)
PY
    then
        printf 'locked base image descriptor chain is invalid\n' >&2
        exit 3
    fi

    iid_file="$docker_config/build.iid"
    metadata_file="$docker_config/build-metadata.json"
    "${docker_cli[@]}" --context "$builder_name" buildx build \
        --builder "$builder_name" \
        --load \
        --platform "$platform" \
        --pull \
        --no-cache \
        --network=none \
        --provenance=false \
        --sbom=false \
        --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
        --iidfile "$iid_file" \
        --metadata-file "$metadata_file" \
        --tag "$image_tag" \
        "$asset_root"
    if ! "$python_executable" - \
        "$iid_file" \
        "$metadata_file" \
        "$expected_image_id" \
        "$image_config_digest" \
        "$image_tag" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Never


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    raise ValueError


iid_path = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])
expected_image, expected_config, image_tag = sys.argv[3:]
try:
    iid = iid_path.read_bytes()
    metadata = json.loads(
        metadata_path.read_bytes(),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (OSError, TypeError, UnicodeError, ValueError):
    raise SystemExit(1) from None
descriptor = metadata.get("containerimage.descriptor") if type(metadata) is dict else None
platform = descriptor.get("platform") if type(descriptor) is dict else None
if (
    iid != expected_config.encode("ascii")
    or type(metadata) is not dict
    or metadata.get("containerimage.digest") != expected_image
    or metadata.get("containerimage.config.digest") != expected_config
    or metadata.get("image.name") != f"docker.io/{image_tag}"
    or type(descriptor) is not dict
    or descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
    or descriptor.get("digest") != expected_image
    or type(descriptor.get("size")) is not int
    or descriptor["size"] <= 0
    or platform != {"architecture": "amd64", "os": "linux"}
):
    raise SystemExit(1)
PY
    then
        printf 'repository build result does not match the image lock\n' >&2
        exit 3
    fi
    printf 'actual_image_id=%s\n' "$expected_image_id"
    printf 'actual_config_digest=%s\n' "$image_config_digest"
    printf 'expected_image_id=%s\n' "$expected_image_id"
fi

verify_image
