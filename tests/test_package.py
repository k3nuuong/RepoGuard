"""Tests for installed package metadata."""

import json
from importlib.metadata import requires, version
from importlib.resources import files

import repoguard


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
