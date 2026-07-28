"""Tests for installed package metadata."""

from importlib.metadata import version
from importlib.resources import files

import repoguard


def test_package_version_matches_distribution_metadata() -> None:
    assert repoguard.__version__ == version("repoguard")


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
