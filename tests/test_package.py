"""Tests for installed package metadata."""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import zipfile
from importlib.metadata import requires, version
from importlib.resources import files
from pathlib import Path
from typing import Never, cast

import pytest

import repoguard

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REPAIR_MODULE_FILES = (
    "_repair_git.py",
    "_repair_input.py",
    "_repair_models.py",
    "_repair_patch.py",
    "_repair_paths.py",
    "_repair_prompt.py",
    "_repair_retrieval.py",
    "_repair_sandbox.py",
    "_repair_secrets.py",
    "_repair_store.py",
    "_repair_workflow.py",
)
_M5_RESOURCE_FILES = (
    "prompts/agent_repair/v1/system.md",
    "prompts/agent_repair/v1/response-schema.json",
    "repair_assets/runner.py",
    "repair_assets/probe.py",
    "repair_assets/seccomp-v1.json",
    "repair_assets/manifest.json",
    "repair_assets/validation_image_v1/Dockerfile",
    "repair_assets/validation_image_v1/Dockerfile.dockerignore",
    "repair_assets/validation_image_v1/image-lock.json",
    "evaluation_data/m5_safe_repair.json",
)
_CANONICAL_M5_JSON_FILES = (
    "repair_assets/seccomp-v1.json",
    "repair_assets/manifest.json",
    "repair_assets/validation_image_v1/image-lock.json",
    "evaluation_data/m5_safe_repair.json",
)
_M5_PACKAGE_FILES = ("repair.py", *_REPAIR_MODULE_FILES, *_M5_RESOURCE_FILES)
_M5_SDIST_FILES = ("scripts/manage-repair-image.sh",)
_SDIST_ROOT = "repoguard-0.1.0"


@pytest.fixture(scope="module")
def built_distributions(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    uv_executable = shutil.which("uv")
    assert uv_executable is not None
    output = tmp_path_factory.mktemp("m5-distributions")
    result = subprocess.run(
        (
            uv_executable,
            "build",
            "--offline",
            "--no-python-downloads",
            "--python",
            "3.12",
            "--out-dir",
            str(output),
        ),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = tuple(output.glob("*.whl"))
    sdists = tuple(output.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    return wheels[0], sdists[0]


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> Never:
    raise ValueError("non-finite JSON number")


def _parse_json(raw: bytes) -> object:
    return json.loads(
        raw,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_package_version_matches_distribution_metadata() -> None:
    assert repoguard.__version__ == version("repoguard")


def test_runtime_metadata_constrains_the_direct_onnx_runtime_import() -> None:
    dependencies = requires("repoguard")

    assert dependencies is not None
    assert "onnxruntime-gpu<1.28" in dependencies


def test_py_typed_marker_is_packaged() -> None:
    assert files("repoguard").joinpath("py.typed").is_file()


def test_git_metadata_facades_are_packaged() -> None:
    package = files("repoguard")
    for object_format in ("sha1", "sha256"):
        facade = package.joinpath("_git_facades", object_format)
        assert facade.joinpath("HEAD").is_file()
        assert facade.joinpath("config").is_file()
        assert facade.joinpath("objects").is_dir()
        assert facade.joinpath("refs").is_dir()


def test_m4_model_prompt_and_evaluation_resources_are_packaged() -> None:
    package = files("repoguard")
    resources = (
        package.joinpath("models", "bge_small_en_v1_5", "manifest.json"),
        package.joinpath("prompts", "agent_review", "v2", "system.md"),
        package.joinpath("prompts", "agent_review", "v2", "response-schema.json"),
        package.joinpath("evaluation_data", "m4_retrieval.json"),
    )

    assert all(resource.is_file() for resource in resources)
    manifest = json.loads(resources[0].read_text(encoding="utf-8"))
    evaluation = json.loads(resources[3].read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert evaluation["schema_version"] == 1
    assert len(evaluation["cases"]) == 60


def test_m5_resources_are_importlib_readable_and_canonical() -> None:
    package = files("repoguard")
    contents: dict[str, bytes] = {}
    for relative_path in _M5_RESOURCE_FILES:
        resource = package.joinpath(*relative_path.split("/"))
        assert resource.is_file(), relative_path
        contents[relative_path] = resource.read_bytes()
        assert contents[relative_path], relative_path

    assert contents["prompts/agent_repair/v1/system.md"].decode("utf-8")
    response_schema = _parse_json(contents["prompts/agent_repair/v1/response-schema.json"])
    response_mapping = cast(dict[str, object], response_schema)
    assert response_mapping["type"] == "object"
    assert response_mapping["additionalProperties"] is False

    for relative_path in _CANONICAL_M5_JSON_FILES:
        raw = contents[relative_path]
        assert not raw.endswith(b"\n"), relative_path
        assert raw == _canonical_json_bytes(_parse_json(raw)), relative_path

    manifest = cast(
        dict[str, object],
        _parse_json(contents["repair_assets/manifest.json"]),
    )
    evaluation = cast(
        dict[str, object],
        _parse_json(contents["evaluation_data/m5_safe_repair.json"]),
    )
    assert manifest["schema_version"] == 1
    assert evaluation["schema_version"] == 1
    cases = evaluation["cases"]
    assert type(cases) is list
    assert len(cases) == 30


def test_m5_repair_surface_is_in_wheel_and_sdist(
    built_distributions: tuple[Path, Path],
) -> None:
    wheel_path, sdist_path = built_distributions
    source_package = _PROJECT_ROOT / "src" / "repoguard"
    source_modules = tuple(path.name for path in sorted(source_package.glob("_repair_*.py")))
    assert source_modules == _REPAIR_MODULE_FILES

    expected_wheel = {f"repoguard/{relative_path}" for relative_path in _M5_PACKAGE_FILES}
    expected_sdist = {
        f"{_SDIST_ROOT}/src/repoguard/{relative_path}" for relative_path in _M5_PACKAGE_FILES
    }
    expected_sdist.update(f"{_SDIST_ROOT}/{relative_path}" for relative_path in _M5_SDIST_FILES)
    resource_contents = {
        relative_path: (files("repoguard").joinpath(*relative_path.split("/")).read_bytes())
        for relative_path in _M5_RESOURCE_FILES
    }

    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_members = set(wheel.namelist())
        assert expected_wheel <= wheel_members
        assert not any(name.endswith((".pyc", ".pyo")) for name in wheel_members)
        for relative_path, expected in resource_contents.items():
            assert wheel.read(f"repoguard/{relative_path}") == expected

    with tarfile.open(sdist_path, mode="r:gz") as sdist:
        sdist_members = set(sdist.getnames())
        assert expected_sdist <= sdist_members
        assert not any(name.endswith((".pyc", ".pyo")) for name in sdist_members)
        for relative_path, expected in resource_contents.items():
            member = sdist.getmember(f"{_SDIST_ROOT}/src/repoguard/{relative_path}")
            extracted = sdist.extractfile(member)
            assert extracted is not None
            assert extracted.read() == expected
        for relative_path in _M5_SDIST_FILES:
            member = sdist.getmember(f"{_SDIST_ROOT}/{relative_path}")
            extracted = sdist.extractfile(member)
            assert extracted is not None
            assert extracted.read() == (_PROJECT_ROOT / relative_path).read_bytes()
            assert member.mode == 0o755
