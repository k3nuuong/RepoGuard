"""Bounded, secret-safe transport for the fixed GitHub.com REST API."""

from __future__ import annotations

import json
import math
import re
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from http.client import HTTPSConnection
from typing import Protocol, cast, runtime_checkable
from urllib.parse import unquote_to_bytes, urlsplit

from repoguard._canonical import CanonicalJSONError, canonical_json_bytes

__all__ = [
    "GITHUB_API_VERSION",
    "GITHUB_REQUEST_MAX_BYTES",
    "GITHUB_RESPONSE_MAX_BYTES",
    "GitHubJSONScalar",
    "GitHubJSONValue",
    "GitHubMethod",
    "GitHubTransport",
    "GitHubTransportError",
    "GitHubTransportErrorCode",
    "GitHubTransportResponse",
    "GitHubTransportSender",
    "GitHubWireRequest",
    "GitHubWireResponse",
]

type GitHubJSONScalar = bool | int | float | str | None
type GitHubJSONValue = GitHubJSONScalar | list["GitHubJSONValue"] | dict[str, "GitHubJSONValue"]

GITHUB_API_VERSION = "2022-11-28"
GITHUB_REQUEST_MAX_BYTES = 24 * 1024 * 1024
GITHUB_RESPONSE_MAX_BYTES = 4 * 1024 * 1024

_GITHUB_API_SCHEME = "https"
_GITHUB_API_HOST = "api.github.com"
_GITHUB_API_PORT = 443
_GITHUB_ACCEPT = "application/vnd.github+json"
_GITHUB_USER_AGENT = "RepoGuard/0.1.0"
_CONNECT_TIMEOUT_SECONDS = 5.0
_READ_TIMEOUT_SECONDS = 15.0
_TOTAL_TIMEOUT_SECONDS = 30.0
_MAX_TARGET_BYTES = 4_096
_MAX_RESPONSE_HEADERS = 100
_MAX_RESPONSE_HEADER_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_COLLECTION_ITEMS = 1_000
_MAX_JSON_TOTAL_ITEMS = 10_000
_READ_CHUNK_BYTES = 64 * 1024
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_monotonic = time.monotonic


class GitHubMethod(StrEnum):
    """HTTP methods needed by the M6 read and publication workflows."""

    GET = "GET"
    POST = "POST"
    PATCH = "PATCH"


class GitHubTransportErrorCode(StrEnum):
    """Stable failure categories independent of response content."""

    INVALID_REQUEST = "invalid_request"
    REQUEST_LIMIT_EXCEEDED = "request_limit_exceeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    REDIRECT_FORBIDDEN = "redirect_forbidden"
    UNEXPECTED_STATUS = "unexpected_status"
    RESPONSE_LIMIT_EXCEEDED = "response_limit_exceeded"
    MALFORMED_RESPONSE = "malformed_response"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"


_ERROR_MESSAGES = {
    GitHubTransportErrorCode.INVALID_REQUEST: "GitHub API request is invalid.",
    GitHubTransportErrorCode.REQUEST_LIMIT_EXCEEDED: (
        "GitHub API request exceeds the fixed resource limit."
    ),
    GitHubTransportErrorCode.AUTHENTICATION_FAILED: "GitHub authentication failed.",
    GitHubTransportErrorCode.FORBIDDEN: "GitHub denied the request.",
    GitHubTransportErrorCode.NOT_FOUND: "GitHub resource was not found.",
    GitHubTransportErrorCode.CONFLICT: "GitHub reported a state conflict.",
    GitHubTransportErrorCode.VALIDATION_FAILED: "GitHub rejected the request.",
    GitHubTransportErrorCode.RATE_LIMITED: "GitHub rate limit was exceeded.",
    GitHubTransportErrorCode.SERVER_ERROR: "GitHub service is unavailable.",
    GitHubTransportErrorCode.REDIRECT_FORBIDDEN: "GitHub API redirect was refused.",
    GitHubTransportErrorCode.UNEXPECTED_STATUS: "GitHub returned an unexpected status.",
    GitHubTransportErrorCode.RESPONSE_LIMIT_EXCEEDED: (
        "GitHub API response exceeds the fixed resource limit."
    ),
    GitHubTransportErrorCode.MALFORMED_RESPONSE: "GitHub returned a malformed response.",
    GitHubTransportErrorCode.TIMEOUT: "GitHub API request timed out.",
    GitHubTransportErrorCode.NETWORK_ERROR: "GitHub API network request failed.",
}


class GitHubTransportError(RuntimeError):
    """Detached transport failure with safe retry and read-back guidance."""

    __slots__ = ("ambiguous", "code", "retryable", "status")

    code: GitHubTransportErrorCode
    status: int | None
    retryable: bool
    ambiguous: bool

    def __init__(
        self,
        code: GitHubTransportErrorCode,
        *,
        status: int | None,
        retryable: bool,
        ambiguous: bool,
    ) -> None:
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code
        self.status = status
        self.retryable = retryable
        self.ambiguous = ambiguous


@dataclass(frozen=True, slots=True)
class GitHubTransportResponse:
    """One bounded parsed JSON response from GitHub.com."""

    status: int
    body: GitHubJSONValue = field(repr=False)


@dataclass(frozen=True, slots=True)
class GitHubWireRequest:
    """Exact low-level request supplied to the sender test seam."""

    method: GitHubMethod
    scheme: str
    host: str
    port: int
    target: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes | None = field(repr=False)
    connect_timeout_seconds: float
    read_timeout_seconds: float
    total_timeout_seconds: float
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class GitHubWireResponse:
    """Raw bounded response returned by a low-level sender."""

    status: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


@runtime_checkable
class GitHubTransportSender(Protocol):
    """Send exactly one prepared GitHub.com request without retry or redirect."""

    def send(self, request: GitHubWireRequest) -> GitHubWireResponse:
        """Return one raw response or raise a transport exception."""
        ...


class GitHubTransport:
    """Synchronous fixed-host GitHub REST transport with no ambient discovery."""

    __slots__ = ("_sender", "_token")

    def __init__(
        self,
        token: str,
        *,
        sender: GitHubTransportSender | None = None,
    ) -> None:
        if (
            type(token) is not str
            or not 1 <= len(token) <= 1_024
            or any(not 0x21 <= ord(character) <= 0x7E for character in token)
        ):
            raise ValueError("GitHub token is invalid")
        if sender is not None and not isinstance(sender, GitHubTransportSender):
            raise TypeError("sender must implement GitHubTransportSender")
        self._token = token
        self._sender = _StdlibGitHubSender() if sender is None else sender

    def request(
        self,
        method: GitHubMethod,
        path: str,
        body: dict[str, GitHubJSONValue] | None = None,
    ) -> GitHubTransportResponse:
        """Send one bounded request to ``https://api.github.com``.

        ``path`` must be an ASCII absolute API path, optionally with a query.
        The caller supplies a JSON object rather than encoded bytes. Mutating
        failures marked ``ambiguous`` require an explicit read-back before any
        higher-level retry; this method never retries on its own.
        """
        prepared = self._prepare_request(method, path, body)
        response: GitHubWireResponse | None = None
        failure_code: GitHubTransportErrorCode | None = None
        try:
            response = self._sender.send(prepared)
        except TimeoutError:
            failure_code = GitHubTransportErrorCode.TIMEOUT
        except Exception:
            failure_code = GitHubTransportErrorCode.NETWORK_ERROR
        if failure_code is not None:
            raise _transport_error(
                failure_code,
                status=None,
                retryable=True,
                ambiguous=_is_write(method),
            )
        if type(response) is not GitHubWireResponse:
            raise _transport_error(
                GitHubTransportErrorCode.MALFORMED_RESPONSE,
                status=None,
                retryable=False,
                ambiguous=_is_write(method),
            )
        return _parse_response(method, response)

    def _prepare_request(
        self,
        method: GitHubMethod,
        path: str,
        body: dict[str, GitHubJSONValue] | None,
    ) -> GitHubWireRequest:
        if not isinstance(method, GitHubMethod) or not _valid_target(path):
            raise _transport_error(
                GitHubTransportErrorCode.INVALID_REQUEST,
                status=None,
                retryable=False,
                ambiguous=False,
            )
        if method is GitHubMethod.GET and body is not None:
            raise _transport_error(
                GitHubTransportErrorCode.INVALID_REQUEST,
                status=None,
                retryable=False,
                ambiguous=False,
            )
        encoded_body = _encode_request_body(body)
        headers = [
            ("Accept", _GITHUB_ACCEPT),
            ("Authorization", f"Bearer {self._token}"),
            ("Connection", "close"),
            ("Host", _GITHUB_API_HOST),
            ("User-Agent", _GITHUB_USER_AGENT),
            ("X-GitHub-Api-Version", GITHUB_API_VERSION),
        ]
        if encoded_body is not None:
            headers.extend(
                (
                    ("Content-Length", str(len(encoded_body))),
                    ("Content-Type", "application/json"),
                )
            )
        return GitHubWireRequest(
            method=method,
            scheme=_GITHUB_API_SCHEME,
            host=_GITHUB_API_HOST,
            port=_GITHUB_API_PORT,
            target=path,
            headers=tuple(headers),
            body=encoded_body,
            connect_timeout_seconds=_CONNECT_TIMEOUT_SECONDS,
            read_timeout_seconds=_READ_TIMEOUT_SECONDS,
            total_timeout_seconds=_TOTAL_TIMEOUT_SECONDS,
            max_response_bytes=GITHUB_RESPONSE_MAX_BYTES,
        )


class _StdlibGitHubSender:
    """Direct TLS sender that never consults proxy settings or follows redirects."""

    __slots__ = ()

    def send(self, request: GitHubWireRequest) -> GitHubWireResponse:
        deadline = _monotonic() + request.total_timeout_seconds
        context = _build_tls_context()
        connection = HTTPSConnection(
            request.host,
            request.port,
            timeout=min(request.connect_timeout_seconds, _remaining(deadline)),
            context=context,
        )
        try:
            connection.connect()
            _set_socket_timeout(connection, deadline, request.read_timeout_seconds)
            connection.putrequest(
                request.method.value,
                request.target,
                skip_host=True,
                skip_accept_encoding=True,
            )
            for name, value in request.headers:
                connection.putheader(name, value)
            connection.endheaders(request.body)
            _set_socket_timeout(connection, deadline, request.read_timeout_seconds)
            response = connection.getresponse()
            headers = tuple(response.getheaders())
            content = bytearray()
            while len(content) <= request.max_response_bytes:
                _set_socket_timeout(connection, deadline, request.read_timeout_seconds)
                amount = min(
                    _READ_CHUNK_BYTES,
                    request.max_response_bytes + 1 - len(content),
                )
                chunk = response.read(amount)
                if not chunk:
                    break
                content.extend(chunk)
            return GitHubWireResponse(
                status=response.status,
                headers=headers,
                body=bytes(content),
            )
        finally:
            with suppress(Exception):
                connection.close()


def _build_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context


def _valid_target(target: object) -> bool:
    if type(target) is not str or not target:
        return False
    try:
        raw = target.encode("ascii")
    except UnicodeEncodeError:
        return False
    if (
        len(raw) > _MAX_TARGET_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in raw)
        or "\\" in target
        or not _valid_percent_escapes(target)
    ):
        return False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.startswith("//")
        or "//" in parsed.path
    ):
        return False
    for segment in parsed.path.split("/")[1:]:
        decoded = unquote_to_bytes(segment)
        if decoded in (b".", b"..") or any(
            byte in (0x00, 0x0A, 0x0D, 0x2F, 0x5C) for byte in decoded
        ):
            return False
    return True


def _valid_percent_escapes(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX_DIGITS
            or value[index + 2] not in _HEX_DIGITS
        ):
            return False
        index += 3
    return True


def _encode_request_body(
    body: dict[str, GitHubJSONValue] | None,
) -> bytes | None:
    if body is None:
        return None
    if type(body) is not dict:
        raise _transport_error(
            GitHubTransportErrorCode.INVALID_REQUEST,
            status=None,
            retryable=False,
            ambiguous=False,
        )
    invalid = False
    encoded = b""
    try:
        _validate_json_limits(body)
        encoded = canonical_json_bytes(body, max_depth=_MAX_JSON_DEPTH)
    except (CanonicalJSONError, RecursionError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise _transport_error(
            GitHubTransportErrorCode.INVALID_REQUEST,
            status=None,
            retryable=False,
            ambiguous=False,
        )
    if len(encoded) > GITHUB_REQUEST_MAX_BYTES:
        raise _transport_error(
            GitHubTransportErrorCode.REQUEST_LIMIT_EXCEEDED,
            status=None,
            retryable=False,
            ambiguous=False,
        )
    return encoded


def _parse_response(
    method: GitHubMethod,
    response: GitHubWireResponse,
) -> GitHubTransportResponse:
    write_ambiguous = _is_write(method)
    if (
        type(response.status) is not int
        or not 100 <= response.status <= 599
        or type(response.body) is not bytes
    ):
        raise _transport_error(
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            status=None,
            retryable=False,
            ambiguous=write_ambiguous,
        )
    status_error = _status_error(method, response.status)
    if status_error is not None:
        raise status_error
    if len(response.body) > GITHUB_RESPONSE_MAX_BYTES:
        raise _transport_error(
            GitHubTransportErrorCode.RESPONSE_LIMIT_EXCEEDED,
            status=response.status,
            retryable=False,
            ambiguous=write_ambiguous,
        )
    if not _valid_headers(response.headers):
        raise _transport_error(
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            status=response.status,
            retryable=False,
            ambiguous=write_ambiguous,
        )
    if not response.body:
        if response.status in (204, 205):
            return GitHubTransportResponse(status=response.status, body=None)
        raise _transport_error(
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            status=response.status,
            retryable=False,
            ambiguous=write_ambiguous,
        )
    malformed = False
    decoded: object = None

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError

    try:
        text = response.body.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError
        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
        _validate_json_limits(decoded)
        canonical_json_bytes(decoded, max_depth=_MAX_JSON_DEPTH)
    except (
        CanonicalJSONError,
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ):
        malformed = True
    if malformed:
        raise _transport_error(
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            status=response.status,
            retryable=False,
            ambiguous=write_ambiguous,
        )
    return GitHubTransportResponse(
        status=response.status,
        body=cast(GitHubJSONValue, decoded),
    )


def _valid_headers(headers: object) -> bool:
    if type(headers) is not tuple or len(headers) > _MAX_RESPONSE_HEADERS:
        return False
    total = 0
    for item in headers:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or _HEADER_NAME_PATTERN.fullmatch(item[0]) is None
            or any(character in item[1] for character in ("\0", "\r", "\n"))
        ):
            return False
        try:
            total += len(item[0].encode("ascii")) + len(item[1].encode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            return False
        if total > _MAX_RESPONSE_HEADER_BYTES:
            return False
    return True


def _validate_json_limits(value: object) -> None:
    total_items = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError
        if type(current) is dict:
            if len(current) > _MAX_JSON_COLLECTION_ITEMS:
                raise ValueError
            total_items += len(current)
            stack.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            if len(current) > _MAX_JSON_COLLECTION_ITEMS:
                raise ValueError
            total_items += len(current)
            stack.extend((item, depth + 1) for item in current)
        elif current is None or type(current) in (bool, int, str):
            pass
        elif type(current) is float:
            if not math.isfinite(current):
                raise ValueError
        else:
            raise ValueError
        if total_items > _MAX_JSON_TOTAL_ITEMS:
            raise ValueError


def _status_error(
    method: GitHubMethod,
    status: int,
) -> GitHubTransportError | None:
    if 200 <= status <= 299:
        return None
    ambiguous = _is_write(method)
    if status == 401:
        return _transport_error(
            GitHubTransportErrorCode.AUTHENTICATION_FAILED,
            status=status,
            retryable=False,
            ambiguous=False,
        )
    if status == 403:
        return _transport_error(
            GitHubTransportErrorCode.FORBIDDEN,
            status=status,
            retryable=False,
            ambiguous=False,
        )
    if status == 404:
        return _transport_error(
            GitHubTransportErrorCode.NOT_FOUND,
            status=status,
            retryable=False,
            ambiguous=False,
        )
    if status == 408:
        return _transport_error(
            GitHubTransportErrorCode.TIMEOUT,
            status=status,
            retryable=True,
            ambiguous=ambiguous,
        )
    if status == 409:
        return _transport_error(
            GitHubTransportErrorCode.CONFLICT,
            status=status,
            retryable=False,
            ambiguous=False,
        )
    if status == 422:
        return _transport_error(
            GitHubTransportErrorCode.VALIDATION_FAILED,
            status=status,
            retryable=False,
            ambiguous=False,
        )
    if status == 429:
        return _transport_error(
            GitHubTransportErrorCode.RATE_LIMITED,
            status=status,
            retryable=True,
            ambiguous=False,
        )
    if 500 <= status <= 599:
        return _transport_error(
            GitHubTransportErrorCode.SERVER_ERROR,
            status=status,
            retryable=True,
            ambiguous=ambiguous,
        )
    if 300 <= status <= 399:
        return _transport_error(
            GitHubTransportErrorCode.REDIRECT_FORBIDDEN,
            status=status,
            retryable=False,
            ambiguous=ambiguous,
        )
    return _transport_error(
        GitHubTransportErrorCode.UNEXPECTED_STATUS,
        status=status,
        retryable=False,
        ambiguous=False,
    )


def _is_write(method: GitHubMethod) -> bool:
    return method in (GitHubMethod.POST, GitHubMethod.PATCH)


def _transport_error(
    code: GitHubTransportErrorCode,
    *,
    status: int | None,
    retryable: bool,
    ambiguous: bool,
) -> GitHubTransportError:
    return GitHubTransportError(
        code,
        status=status,
        retryable=retryable,
        ambiguous=ambiguous,
    )


def _remaining(deadline: float) -> float:
    remaining = deadline - _monotonic()
    if remaining <= 0.0:
        raise TimeoutError
    return remaining


def _set_socket_timeout(
    connection: HTTPSConnection,
    deadline: float,
    read_timeout_seconds: float,
) -> None:
    sock = connection.sock
    if sock is None:
        raise OSError
    sock.settimeout(min(read_timeout_seconds, _remaining(deadline)))
