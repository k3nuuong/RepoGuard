"""Strict canonical JSON primitives shared by product interfaces."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import cast

type JSONScalar = bool | int | float | str | None
type JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class CanonicalJSONError(ValueError):
    """A content-free strict canonical JSON failure."""


def canonical_json_bytes(value: object, *, max_depth: int = 64) -> bytes:
    """Return exact canonical UTF-8 JSON bytes without a trailing newline."""
    _validate_json_value(value, depth=0, max_depth=max_depth)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJSONError("canonical JSON value is invalid") from error
    return encoded


def canonical_json_text(value: object, *, max_depth: int = 64) -> str:
    """Return exact canonical JSON text without a trailing newline."""
    return canonical_json_bytes(value, max_depth=max_depth).decode("utf-8")


def parse_canonical_json(
    raw: bytes,
    *,
    max_bytes: int,
    max_depth: int = 64,
) -> JSONValue:
    """Parse bytes only when their complete spelling is canonical JSON."""
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise CanonicalJSONError("canonical JSON bytes are invalid")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJSONError("canonical JSON bytes are invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalJSONError("canonical JSON bytes are invalid") from error

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalJSONError("canonical JSON object has duplicate keys")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise CanonicalJSONError("canonical JSON number is invalid")

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise CanonicalJSONError("canonical JSON bytes are invalid") from error
    _validate_json_value(decoded, depth=0, max_depth=max_depth)
    if canonical_json_bytes(decoded, max_depth=max_depth) != raw:
        raise CanonicalJSONError("JSON bytes are not canonical")
    return cast(JSONValue, decoded)


def domain_sha256(domain: str, value: object) -> str:
    """Hash canonical JSON with one explicit ASCII/NUL-separated domain."""
    if type(domain) is not str or not domain or "\0" in domain or not domain.isascii():
        raise ValueError("digest domain must be non-empty ASCII without NUL")
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_json_bytes(value)).hexdigest()


def require_exact_keys(
    mapping: Mapping[str, object],
    expected: Sequence[str],
    *,
    name: str,
) -> None:
    """Reject missing and unknown mapping fields without echoing their names."""
    if type(mapping) is not dict or set(mapping) != set(expected):
        raise ValueError(f"{name} fields are invalid")


def _validate_json_value(value: object, *, depth: int, max_depth: int) -> None:
    if type(max_depth) is not int or max_depth < 1 or depth > max_depth:
        raise CanonicalJSONError("canonical JSON nesting is invalid")
    if value is None or type(value) in (bool, int, str):
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise CanonicalJSONError("canonical JSON string is invalid") from error
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalJSONError("canonical JSON number is invalid")
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalJSONError("canonical JSON object key is invalid")
            _validate_json_value(key, depth=depth + 1, max_depth=max_depth)
            _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
        return
    raise CanonicalJSONError("canonical JSON value is invalid")
