"""Strict path validation shared by all repair boundaries."""

from __future__ import annotations

import unicodedata
from pathlib import PurePosixPath


def _validate_repository_path(value: str, name: str = "path") -> str:
    encoded = _require_utf8(value, name)
    if not encoded or len(encoded) > 1_024 or value.startswith("/") or "\\" in value:
        raise ValueError(f"{name} is not a safe repository path")
    if value != value.strip(" "):
        raise ValueError(f"{name} has leading or trailing space")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} contains a control character")
    components = value.split("/")
    if any(
        not component
        or component in {".", ".."}
        or component.casefold() == ".git"
        or len(component.encode("utf-8")) > 255
        for component in components
    ):
        raise ValueError(f"{name} contains an unsafe component")
    return value


def _validate_container_path(value: str, name: str = "path") -> str:
    encoded = _require_utf8(value, name)
    if not encoded or len(encoded) > 1_024:
        raise ValueError(f"{name} is outside its allowed byte size")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} contains a control character")
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) != value:
        raise ValueError(f"{name} must be a canonical absolute POSIX path")
    if any(
        component in {"", ".", ".."} or len(component.encode("utf-8")) > 255
        for component in path.parts[1:]
    ):
        raise ValueError(f"{name} contains an unsafe component")
    return value


def _canonical_repository_paths(
    value: tuple[str, ...],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> tuple[str, ...]:
    if type(value) is not tuple or not minimum <= len(value) <= maximum:
        raise ValueError(f"{name} must be an exact tuple within its allowed size")
    for index, path in enumerate(value):
        _validate_repository_path(path, f"{name}[{index}]")
    canonical = tuple(sorted(value, key=_path_sort_key))
    if canonical != value or len(set(value)) != len(value):
        raise ValueError(f"{name} must be unique and sorted by UTF-8 bytes")
    return value


def _path_sort_key(value: str) -> bytes:
    return value.encode("utf-8")


def _require_utf8(value: str, name: str) -> bytes:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be valid UTF-8") from error
