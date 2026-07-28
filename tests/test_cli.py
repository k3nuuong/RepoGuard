"""Tests for the minimal module command."""

import subprocess
import sys

import pytest

from repoguard import __version__
from repoguard.__main__ import main


def test_main_without_arguments() -> None:
    assert main([]) == 0


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"repoguard {__version__}\n"


def test_module_version_command() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "repoguard", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == f"repoguard {__version__}\n"
    assert completed.stderr == ""
