"""Tests for installed package metadata."""

from importlib.metadata import version
from importlib.resources import files

import repoguard


def test_package_version_matches_distribution_metadata() -> None:
    assert repoguard.__version__ == version("repoguard")


def test_py_typed_marker_is_packaged() -> None:
    assert files("repoguard").joinpath("py.typed").is_file()
