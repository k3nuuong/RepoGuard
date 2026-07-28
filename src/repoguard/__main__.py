"""Module entry point for RepoGuard."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from repoguard import __version__


def main(argv: Sequence[str] | None = None) -> int:
    """Run the minimal RepoGuard command-line interface."""
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="RepoGuard project command-line interface.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
