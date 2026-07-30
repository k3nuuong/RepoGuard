"""Security and behavior specifications for the fixed GitHub.com transport."""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from pytest import MonkeyPatch

import repoguard.github_transport as transport_impl
from repoguard.github_transport import (
    GITHUB_API_VERSION,
    GITHUB_RESPONSE_MAX_BYTES,
    GitHubJSONValue,
    GitHubMethod,
    GitHubTransport,
    GitHubTransportError,
    GitHubTransportErrorCode,
    GitHubTransportResponse,
    GitHubWireRequest,
    GitHubWireResponse,
)

_TOKEN = "github_pat_EXPLICIT_TOKEN"
_OK = GitHubWireResponse(
    status=200,
    headers=(("Content-Type", "application/json; charset=utf-8"),),
    body=b'{"ok":true}',
)


class _FakeSender:
    def __init__(
        self,
        response: GitHubWireResponse = _OK,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.response = response
        self.failure = failure
        self.requests: list[GitHubWireRequest] = []

    def send(self, request: GitHubWireRequest) -> GitHubWireResponse:
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        return self.response


def _assert_error(
    raised: pytest.ExceptionInfo[GitHubTransportError],
    code: GitHubTransportErrorCode,
    *,
    status: int | None,
    retryable: bool,
    ambiguous: bool,
) -> None:
    error = raised.value
    assert error.code is code
    assert error.status == status
    assert error.retryable is retryable
    assert error.ambiguous is ambiguous
    assert error.__cause__ is None
    assert error.__context__ is None


def test_public_error_codes_and_methods_are_closed_and_exact() -> None:
    assert [method.value for method in GitHubMethod] == ["GET", "POST", "PATCH"]
    assert [code.value for code in GitHubTransportErrorCode] == [
        "invalid_request",
        "request_limit_exceeded",
        "authentication_failed",
        "forbidden",
        "not_found",
        "conflict",
        "validation_failed",
        "rate_limited",
        "server_error",
        "redirect_forbidden",
        "unexpected_status",
        "response_limit_exceeded",
        "malformed_response",
        "timeout",
        "network_error",
    ]
    assert GITHUB_API_VERSION == "2022-11-28"


@pytest.mark.parametrize(
    "token",
    [
        "",
        " ",
        "token with space",
        "token\nheader",
        "tøken",
        "x" * 1_025,
        cast(str, b"bytes"),
    ],
)
def test_token_must_be_explicit_bounded_visible_ascii(token: str) -> None:
    with pytest.raises(ValueError, match=r"^GitHub token is invalid$"):
        GitHubTransport(token, sender=_FakeSender())


def test_request_is_fixed_host_canonical_and_has_fixed_headers_and_timeouts(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "AMBIENT_TOKEN")
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "AMBIENT_REPOGUARD_TOKEN")
    monkeypatch.setenv("HTTPS_PROXY", "https://AMBIENT_PROXY.invalid")
    sender = _FakeSender(
        GitHubWireResponse(
            status=201,
            headers=(("content-type", "application/json"),),
            body=b'{ "z": 1, "a": [true, null] }\n',
        )
    )

    result = GitHubTransport(_TOKEN, sender=sender).request(
        GitHubMethod.POST,
        "/repos/owner/repo/git/refs?trace=caller%2Fvalue",
        {"z": "é", "a": [True, None]},
    )

    assert result == GitHubTransportResponse(
        status=201,
        body={"a": [True, None], "z": 1},
    )
    assert len(sender.requests) == 1
    request = sender.requests[0]
    assert request.method is GitHubMethod.POST
    assert request.scheme == "https"
    assert request.host == "api.github.com"
    assert request.port == 443
    assert request.target == "/repos/owner/repo/git/refs?trace=caller%2Fvalue"
    assert request.body == b'{"a":[true,null],"z":"\xc3\xa9"}'
    assert request.connect_timeout_seconds == 5.0
    assert request.read_timeout_seconds == 15.0
    assert request.total_timeout_seconds == 30.0
    assert request.max_response_bytes == GITHUB_RESPONSE_MAX_BYTES
    headers = dict(request.headers)
    assert headers == {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {_TOKEN}",
        "Connection": "close",
        "Content-Length": str(len(request.body)),
        "Content-Type": "application/json",
        "Host": "api.github.com",
        "User-Agent": "RepoGuard/0.1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    rendered = repr(request)
    assert _TOKEN not in rendered
    assert "trace=" not in rendered
    assert "é" not in rendered
    assert "AMBIENT" not in repr(result)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "repos/owner/repo",
        "https://api.github.com/repos/owner/repo",
        "//attacker.invalid/repos/owner/repo",
        "//[",
        "/repos//owner",
        "/repos/./owner",
        "/repos/%2e%2e/owner",
        "/repos/owner/a%2Fb",
        "/repos/owner/%2e%2e%2fuser",
        "/repos/owner\\repo",
        "/repos/owner repo",
        "/repos/ownér/repo",
        "/repos/owner/repo#fragment",
        "/repos/owner/repo?bad=%XX",
        "/repos/owner/repo\r\nX-Injected:value",
        "/" + ("x" * 4_096),
    ],
)
def test_invalid_path_fails_before_sender(path: str) -> None:
    sender = _FakeSender()
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(GitHubMethod.GET, path)
    _assert_error(
        raised,
        GitHubTransportErrorCode.INVALID_REQUEST,
        status=None,
        retryable=False,
        ambiguous=False,
    )
    assert sender.requests == []


def test_literal_ref_segments_and_bounded_query_are_valid_targets() -> None:
    sender = _FakeSender()
    result = GitHubTransport(_TOKEN, sender=sender).request(
        GitHubMethod.GET,
        "/repos/owner/repo/git/ref/heads/repair?state=open&per_page=100",
    )
    assert result.body == {"ok": True}
    assert len(sender.requests) == 1
    assert sender.requests[0].body is None
    assert "Content-Type" not in dict(sender.requests[0].headers)


def test_unknown_method_and_get_body_fail_before_sender() -> None:
    sender = _FakeSender()
    client = GitHubTransport(_TOKEN, sender=sender)
    with pytest.raises(GitHubTransportError) as invalid_method:
        client.request(cast(GitHubMethod, "PUT"), "/user")
    with pytest.raises(GitHubTransportError) as get_body:
        client.request(GitHubMethod.GET, "/user", {"value": 1})
    for raised in (invalid_method, get_body):
        _assert_error(
            raised,
            GitHubTransportErrorCode.INVALID_REQUEST,
            status=None,
            retryable=False,
            ambiguous=False,
        )
    assert sender.requests == []


def test_sender_must_implement_the_explicit_low_level_seam() -> None:
    with pytest.raises(TypeError, match=r"^sender must implement GitHubTransportSender$"):
        GitHubTransport(_TOKEN, sender=cast(transport_impl.GitHubTransportSender, object()))


@pytest.mark.parametrize(
    "body",
    [
        cast(dict[str, object], []),
        {"value": float("nan")},
        {"value": object()},
        cast(dict[str, object], {1: "bad-key"}),
        {"items": list(range(1_001))},
    ],
)
def test_invalid_or_overcount_request_json_fails_atomically(
    body: dict[str, object],
) -> None:
    sender = _FakeSender()
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(
            GitHubMethod.POST,
            "/repos/owner/repo/git/refs",
            cast(dict[str, transport_impl.GitHubJSONValue], body),
        )
    _assert_error(
        raised,
        GitHubTransportErrorCode.INVALID_REQUEST,
        status=None,
        retryable=False,
        ambiguous=False,
    )
    assert sender.requests == []


def test_request_depth_total_count_and_byte_limits_are_atomic(
    monkeypatch: MonkeyPatch,
) -> None:
    sender = _FakeSender()
    client = GitHubTransport(_TOKEN, sender=sender)
    deep: object = "leaf"
    for _ in range(33):
        deep = {"child": deep}
    too_many_total = {str(index): list(range(1_000)) for index in range(11)}

    for body, code in (
        ({"deep": deep}, GitHubTransportErrorCode.INVALID_REQUEST),
        (too_many_total, GitHubTransportErrorCode.INVALID_REQUEST),
    ):
        with pytest.raises(GitHubTransportError) as raised:
            client.request(
                GitHubMethod.POST,
                "/repos/owner/repo/git/refs",
                cast(dict[str, transport_impl.GitHubJSONValue], body),
            )
        assert raised.value.code is code

    monkeypatch.setattr(transport_impl, "GITHUB_REQUEST_MAX_BYTES", 16)
    with pytest.raises(GitHubTransportError) as oversized:
        client.request(
            GitHubMethod.POST,
            "/repos/owner/repo/git/refs",
            {"value": "x" * 16},
        )
    _assert_error(
        oversized,
        GitHubTransportErrorCode.REQUEST_LIMIT_EXCEEDED,
        status=None,
        retryable=False,
        ambiguous=False,
    )
    assert sender.requests == []


def test_request_byte_and_per_list_limits_have_exact_boundaries(
    monkeypatch: MonkeyPatch,
) -> None:
    sender = _FakeSender()
    client = GitHubTransport(_TOKEN, sender=sender)
    body: dict[str, GitHubJSONValue] = {
        "items": list(range(1_000)),
    }
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    monkeypatch.setattr(transport_impl, "GITHUB_REQUEST_MAX_BYTES", len(encoded))

    result = client.request(
        GitHubMethod.POST,
        "/repos/owner/repo/git/refs",
        body,
    )

    assert result.body == {"ok": True}
    assert len(sender.requests) == 1
    assert sender.requests[0].body == encoded

    monkeypatch.setattr(transport_impl, "GITHUB_REQUEST_MAX_BYTES", len(encoded) - 1)
    with pytest.raises(GitHubTransportError) as raised:
        client.request(
            GitHubMethod.POST,
            "/repos/owner/repo/git/refs",
            body,
        )
    assert raised.value.code is GitHubTransportErrorCode.REQUEST_LIMIT_EXCEEDED
    assert len(sender.requests) == 1


@pytest.mark.parametrize(
    ("method", "status", "code", "retryable", "ambiguous"),
    [
        (GitHubMethod.GET, 401, GitHubTransportErrorCode.AUTHENTICATION_FAILED, False, False),
        (GitHubMethod.GET, 403, GitHubTransportErrorCode.FORBIDDEN, False, False),
        (GitHubMethod.GET, 404, GitHubTransportErrorCode.NOT_FOUND, False, False),
        (GitHubMethod.GET, 408, GitHubTransportErrorCode.TIMEOUT, True, False),
        (GitHubMethod.POST, 408, GitHubTransportErrorCode.TIMEOUT, True, True),
        (GitHubMethod.GET, 409, GitHubTransportErrorCode.CONFLICT, False, False),
        (GitHubMethod.GET, 422, GitHubTransportErrorCode.VALIDATION_FAILED, False, False),
        (GitHubMethod.GET, 429, GitHubTransportErrorCode.RATE_LIMITED, True, False),
        (GitHubMethod.GET, 500, GitHubTransportErrorCode.SERVER_ERROR, True, False),
        (GitHubMethod.PATCH, 599, GitHubTransportErrorCode.SERVER_ERROR, True, True),
        (GitHubMethod.GET, 301, GitHubTransportErrorCode.REDIRECT_FORBIDDEN, False, False),
        (GitHubMethod.POST, 307, GitHubTransportErrorCode.REDIRECT_FORBIDDEN, False, True),
        (GitHubMethod.GET, 400, GitHubTransportErrorCode.UNEXPECTED_STATUS, False, False),
    ],
)
def test_http_statuses_have_stable_content_independent_classification(
    method: GitHubMethod,
    status: int,
    code: GitHubTransportErrorCode,
    retryable: bool,
    ambiguous: bool,
) -> None:
    sender = _FakeSender(
        GitHubWireResponse(
            status=status,
            headers=(("Location", "https://ATTACKER.invalid/SECRET"),),
            body=b'{"message":"SECRET_RESPONSE_BODY"}',
        )
    )
    body: dict[str, GitHubJSONValue] | None = (
        None if method is GitHubMethod.GET else {"value": "SECRET_REQUEST_BODY"}
    )

    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(method, "/user?query=SECRET_QUERY", body)

    _assert_error(
        raised,
        code,
        status=status,
        retryable=retryable,
        ambiguous=ambiguous,
    )
    assert len(sender.requests) == 1
    rendered = f"{raised.value!s} {raised.value!r} {vars(raised.value)}"
    assert "SECRET" not in rendered
    assert _TOKEN not in rendered


@pytest.mark.parametrize(
    ("method", "failure", "code", "ambiguous"),
    [
        (GitHubMethod.GET, TimeoutError("SECRET_TIMEOUT"), GitHubTransportErrorCode.TIMEOUT, False),
        (GitHubMethod.POST, TimeoutError("SECRET_TIMEOUT"), GitHubTransportErrorCode.TIMEOUT, True),
        (
            GitHubMethod.GET,
            OSError("SECRET_NETWORK"),
            GitHubTransportErrorCode.NETWORK_ERROR,
            False,
        ),
        (
            GitHubMethod.PATCH,
            OSError("SECRET_NETWORK"),
            GitHubTransportErrorCode.NETWORK_ERROR,
            True,
        ),
    ],
)
def test_network_failures_are_detached_single_attempt_and_write_ambiguous(
    method: GitHubMethod,
    failure: Exception,
    code: GitHubTransportErrorCode,
    ambiguous: bool,
) -> None:
    sender = _FakeSender(failure=failure)
    body: dict[str, GitHubJSONValue] | None = (
        None if method is GitHubMethod.GET else {"secret": "SECRET_BODY"}
    )

    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(
            method,
            "/repos/owner/repo?query=SECRET_QUERY",
            body,
        )

    _assert_error(
        raised,
        code,
        status=None,
        retryable=True,
        ambiguous=ambiguous,
    )
    assert len(sender.requests) == 1
    rendered = f"{raised.value!s} {raised.value!r} {vars(raised.value)}"
    assert "SECRET" not in rendered
    assert _TOKEN not in rendered


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"duplicate":1,"duplicate":2}',
        b'{"number":NaN}',
        b'{"number":1e400}',
        (b"[" * 34) + b"null" + (b"]" * 34),
        b"[" + b",".join(b"0" for _ in range(1_001)) + b"]",
    ],
)
def test_malformed_response_json_is_content_free_failure(body: bytes) -> None:
    sender = _FakeSender(GitHubWireResponse(status=200, headers=(), body=body))
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(GitHubMethod.GET, "/user")
    _assert_error(
        raised,
        GitHubTransportErrorCode.MALFORMED_RESPONSE,
        status=200,
        retryable=False,
        ambiguous=False,
    )


@pytest.mark.parametrize(
    ("method", "ambiguous"),
    [
        (GitHubMethod.GET, False),
        (GitHubMethod.POST, True),
        (GitHubMethod.PATCH, True),
    ],
)
def test_malformed_success_is_ambiguous_only_after_a_write(
    method: GitHubMethod,
    ambiguous: bool,
) -> None:
    sender = _FakeSender(
        GitHubWireResponse(
            status=201,
            headers=(),
            body=b'{"truncated":',
        )
    )
    body: dict[str, GitHubJSONValue] | None = None if method is GitHubMethod.GET else {}
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=sender).request(method, "/user", body)
    _assert_error(
        raised,
        GitHubTransportErrorCode.MALFORMED_RESPONSE,
        status=201,
        retryable=False,
        ambiguous=ambiguous,
    )
    assert len(sender.requests) == 1


def test_response_collection_total_bytes_headers_and_status_are_bounded(
    monkeypatch: MonkeyPatch,
) -> None:
    too_many_total = {str(index): list(range(1_000)) for index in range(11)}
    total_body = json.dumps(too_many_total, separators=(",", ":")).encode()
    cases: list[tuple[GitHubWireResponse, GitHubTransportErrorCode, int | None]] = [
        (
            GitHubWireResponse(status=200, headers=(), body=total_body),
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            200,
        ),
        (
            GitHubWireResponse(
                status=200,
                headers=tuple(("X-Test", "ok") for _ in range(101)),
                body=b"{}",
            ),
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            200,
        ),
        (
            GitHubWireResponse(
                status=cast(int, True),
                headers=(),
                body=b"{}",
            ),
            GitHubTransportErrorCode.MALFORMED_RESPONSE,
            None,
        ),
    ]
    for response, code, status in cases:
        with pytest.raises(GitHubTransportError) as raised:
            GitHubTransport(_TOKEN, sender=_FakeSender(response)).request(
                GitHubMethod.GET,
                "/user",
            )
        assert raised.value.code is code
        assert raised.value.status == status

    monkeypatch.setattr(transport_impl, "GITHUB_RESPONSE_MAX_BYTES", 16)
    oversized = GitHubWireResponse(
        status=200,
        headers=(),
        body=b'"' + (b"x" * 16) + b'"',
    )
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN, sender=_FakeSender(oversized)).request(
            GitHubMethod.GET,
            "/user",
        )
    assert raised.value.code is GitHubTransportErrorCode.RESPONSE_LIMIT_EXCEEDED
    assert raised.value.status == 200


def test_oversized_success_write_is_ambiguous_but_classifiable_http_error_is_not(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_impl, "GITHUB_RESPONSE_MAX_BYTES", 16)
    oversized = b'"' + (b"x" * 16) + b'"'
    cases = [
        (
            201,
            GitHubTransportErrorCode.RESPONSE_LIMIT_EXCEEDED,
            False,
            True,
        ),
        (
            422,
            GitHubTransportErrorCode.VALIDATION_FAILED,
            False,
            False,
        ),
        (
            500,
            GitHubTransportErrorCode.SERVER_ERROR,
            True,
            True,
        ),
    ]
    for status, code, retryable, ambiguous in cases:
        sender = _FakeSender(
            GitHubWireResponse(
                status=status,
                headers=(),
                body=oversized,
            )
        )
        with pytest.raises(GitHubTransportError) as raised:
            GitHubTransport(_TOKEN, sender=sender).request(
                GitHubMethod.POST,
                "/repos/owner/repo/git/refs",
                {},
            )
        _assert_error(
            raised,
            code,
            status=status,
            retryable=retryable,
            ambiguous=ambiguous,
        )
        assert len(sender.requests) == 1


def test_no_content_is_supported_but_empty_json_response_is_malformed() -> None:
    for status in (204, 205):
        result = GitHubTransport(
            _TOKEN,
            sender=_FakeSender(GitHubWireResponse(status=status, headers=(), body=b"")),
        ).request(GitHubMethod.GET, "/user")
        assert result == GitHubTransportResponse(status=status, body=None)
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(
            _TOKEN,
            sender=_FakeSender(GitHubWireResponse(status=200, headers=(), body=b"")),
        ).request(GitHubMethod.GET, "/user")
    assert raised.value.code is GitHubTransportErrorCode.MALFORMED_RESPONSE


def test_response_byte_limit_has_an_exact_boundary(monkeypatch: MonkeyPatch) -> None:
    body = b'{ "ok": true }\n'
    monkeypatch.setattr(transport_impl, "GITHUB_RESPONSE_MAX_BYTES", len(body))
    result = GitHubTransport(
        _TOKEN,
        sender=_FakeSender(GitHubWireResponse(status=200, headers=(), body=body)),
    ).request(GitHubMethod.GET, "/user")
    assert result.body == {"ok": True}

    monkeypatch.setattr(transport_impl, "GITHUB_RESPONSE_MAX_BYTES", len(body) - 1)
    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(
            _TOKEN,
            sender=_FakeSender(GitHubWireResponse(status=200, headers=(), body=body)),
        ).request(GitHubMethod.GET, "/user")
    assert raised.value.code is GitHubTransportErrorCode.RESPONSE_LIMIT_EXCEEDED


class _FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class _FakeHTTPResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self._body = body
        self._offset = 0
        self.read_amounts: list[int] = []

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json")]

    def read(self, amount: int = -1) -> bytes:
        self.read_amounts.append(amount)
        if self._offset == len(self._body):
            return b""
        end = len(self._body) if amount < 0 else min(len(self._body), self._offset + amount)
        chunk = self._body[self._offset : end]
        self._offset = end
        return chunk


class _FakeHTTPSConnection:
    def __init__(self, response: _FakeHTTPResponse) -> None:
        self.sock = _FakeSocket()
        self.response = response
        self.connected = False
        self.closed = False
        self.putrequest_calls: list[tuple[str, str, bool, bool]] = []
        self.headers: list[tuple[str, str]] = []
        self.sent_body: bytes | None = None

    def connect(self) -> None:
        self.connected = True

    def putrequest(
        self,
        method: str,
        target: str,
        *,
        skip_host: bool,
        skip_accept_encoding: bool,
    ) -> None:
        self.putrequest_calls.append((method, target, skip_host, skip_accept_encoding))

    def putheader(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def endheaders(self, body: bytes | None) -> None:
        self.sent_body = body

    def getresponse(self) -> _FakeHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def test_stdlib_sender_uses_direct_tls_and_ignores_proxy_and_ambient_auth(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://SECRET_PROXY.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "https://SECRET_PROXY.invalid")
    monkeypatch.setenv("ALL_PROXY", "socks5://SECRET_PROXY.invalid")
    monkeypatch.setenv("GITHUB_TOKEN", "SECRET_AMBIENT_TOKEN")
    keylog = tmp_path / "ambient-tls-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    response = _FakeHTTPResponse(b'{"login":"octocat"}')
    connection = _FakeHTTPSConnection(response)
    factory_calls: list[tuple[str, int, float, ssl.SSLContext]] = []

    def factory(
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _FakeHTTPSConnection:
        factory_calls.append((host, port, timeout, context))
        return connection

    monkeypatch.setattr(
        transport_impl,
        "HTTPSConnection",
        cast(Callable[..., object], factory),
    )

    result = GitHubTransport(_TOKEN).request(GitHubMethod.GET, "/user?view=exact")

    assert result.body == {"login": "octocat"}
    assert len(factory_calls) == 1
    host, port, timeout, context = factory_calls[0]
    assert host == "api.github.com"
    assert port == 443
    assert 0.0 < timeout <= 5.0
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.keylog_filename is None
    assert not keylog.exists()
    assert connection.connected is True
    assert connection.closed is True
    assert connection.putrequest_calls == [("GET", "/user?view=exact", True, True)]
    assert dict(connection.headers)["Authorization"] == f"Bearer {_TOKEN}"
    assert "SECRET" not in repr(connection.headers)
    assert connection.sent_body is None
    assert connection.sock.timeouts
    assert all(0.0 < value <= 15.0 for value in connection.sock.timeouts)
    assert response.read_amounts


def test_stdlib_sender_enforces_total_deadline_without_retry(
    monkeypatch: MonkeyPatch,
) -> None:
    response = _FakeHTTPResponse(b'{"ok":true}')
    connection = _FakeHTTPSConnection(response)
    factory_calls = 0

    def factory(
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _FakeHTTPSConnection:
        nonlocal factory_calls
        del host, port, timeout, context
        factory_calls += 1
        return connection

    moments = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(transport_impl, "HTTPSConnection", cast(Callable[..., object], factory))
    monkeypatch.setattr(transport_impl, "_monotonic", lambda: next(moments))

    with pytest.raises(GitHubTransportError) as raised:
        GitHubTransport(_TOKEN).request(
            GitHubMethod.POST,
            "/repos/owner/repo/git/refs",
            {},
        )

    _assert_error(
        raised,
        GitHubTransportErrorCode.TIMEOUT,
        status=None,
        retryable=True,
        ambiguous=True,
    )
    assert factory_calls == 1
    assert connection.connected is True
    assert connection.putrequest_calls == []
    assert connection.closed is True
