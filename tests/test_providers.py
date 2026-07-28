"""Focused tests for the synchronous M3 provider boundary."""

from __future__ import annotations

import io
import logging
import socket
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from typing import Any, cast

import anthropic
import anthropic._client as anthropic_client
import httpx
import openai
import pytest
from pytest import MonkeyPatch
from pytest_socket import SocketBlockedError

import repoguard.providers as providers_impl
from repoguard.providers import (
    AnthropicProvider,
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    MessageRole,
    OpenAIProvider,
    ProviderError,
    ProviderErrorCode,
    TokenUsage,
)

API_KEY = "provider-secret-key"
SYSTEM_PROMPT_MARKER = "SYSTEM-PROMPT-MUST-NOT-BE-LOGGED"
USER_PROMPT_MARKER = "USER-PROMPT-MUST-NOT-BE-LOGGED"


class _FakeResource:
    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class _FakeClient:
    def __init__(self, resource_name: str, resource: _FakeResource) -> None:
        setattr(self, resource_name, resource)


class _ClientFactory:
    def __init__(self, resource_name: str, resource: _FakeResource) -> None:
        self.resource_name = resource_name
        self.resource = resource
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> _FakeClient:
        self.calls.append(kwargs)
        return _FakeClient(self.resource_name, self.resource)


def _request(
    *,
    system: str = "trusted system",
    user: str = '{"untrusted":"data"}',
) -> LLMRequest:
    return LLMRequest(
        model="provider-model",
        messages=(
            LLMMessage(MessageRole.SYSTEM, system),
            LLMMessage(MessageRole.USER, user),
        ),
        max_output_tokens=4096,
        timeout_seconds=12.5,
    )


def _openai_output(
    text: str = '{"schema_version":1,"findings":[]}',
    *,
    usage: object = None,
    status: str = "completed",
) -> SimpleNamespace:
    block = SimpleNamespace(type="output_text", text=text)
    message = SimpleNamespace(type="message", content=[block])
    return SimpleNamespace(output=[message], usage=usage, status=status)


def _anthropic_output(
    text: str = '{"schema_version":1,"findings":[]}',
    *,
    usage: object = None,
    stop_reason: str = "end_turn",
) -> SimpleNamespace:
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=usage,
        stop_reason=stop_reason,
    )


def _install_openai(
    monkeypatch: MonkeyPatch,
    *,
    result: object = None,
    error: Exception | None = None,
) -> tuple[_ClientFactory, _FakeResource]:
    resource = _FakeResource(result=result, error=error)
    factory = _ClientFactory("responses", resource)
    monkeypatch.setattr(openai, "OpenAI", factory)
    return factory, resource


def _install_anthropic(
    monkeypatch: MonkeyPatch,
    *,
    result: object = None,
    error: Exception | None = None,
) -> tuple[_ClientFactory, _FakeResource]:
    resource = _FakeResource(result=result, error=error)
    factory = _ClientFactory("messages", resource)
    monkeypatch.setattr(providers_impl, "_ExplicitAnthropicClient", factory)
    return factory, resource


def _http_response(status_code: int) -> httpx.Response:
    request = httpx.Request("POST", "https://provider.invalid")
    return httpx.Response(status_code, request=request)


def test_public_enums_are_fixed() -> None:
    assert {member.value for member in MessageRole} == {"system", "user"}
    assert {member.value for member in ProviderErrorCode} == {
        "authentication_failed",
        "rate_limited",
        "timeout",
        "unavailable",
        "request_failed",
        "refused",
        "invalid_response",
    }


def test_automated_suite_blocks_real_network_sockets() -> None:
    with (
        pytest.warns(UserWarning, match="tried to use socket"),
        pytest.raises(SocketBlockedError),
    ):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_public_models_are_frozen_slotted_and_validate_the_contract() -> None:
    message = LLMMessage(MessageRole.SYSTEM, "content")
    request = _request()
    usage = TokenUsage(input_tokens=1, output_tokens=2, total_tokens=3)
    response = LLMResponse(output_text="{}", usage=usage)

    assert TokenUsage() == TokenUsage(None, None, None)
    assert LLMResponse(output_text="{}").usage is None
    assert (
        LLMRequest(
            model="model",
            messages=(
                LLMMessage(MessageRole.SYSTEM, "system"),
                LLMMessage(MessageRole.USER, "user"),
            ),
            max_output_tokens=1,
            timeout_seconds=1,
        ).timeout_seconds
        == 1.0
    )

    for model, field_name in (
        (message, "content"),
        (request, "model"),
        (usage, "input_tokens"),
        (response, "output_text"),
    ):
        assert not hasattr(model, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(model, field_name, "changed")

    with pytest.raises(ValueError, match="system message followed by one user"):
        LLMRequest(
            model="model",
            messages=(
                LLMMessage(MessageRole.USER, "wrong"),
                LLMMessage(MessageRole.SYSTEM, "order"),
            ),
            max_output_tokens=1,
            timeout_seconds=1.0,
        )
    with pytest.raises(ValueError, match="non-negative"):
        TokenUsage(input_tokens=-1, output_tokens=None, total_tokens=None)


def test_public_models_reject_invalid_runtime_shapes_and_bounds() -> None:
    messages = (
        LLMMessage(MessageRole.SYSTEM, "system"),
        LLMMessage(MessageRole.USER, "user"),
    )

    with pytest.raises(ValueError, match="MessageRole"):
        LLMMessage(cast(MessageRole, "system"), "content")
    with pytest.raises(ValueError, match="content must be a string"):
        LLMMessage(MessageRole.SYSTEM, cast(str, None))
    with pytest.raises(ValueError, match="model must be a non-empty string"):
        LLMRequest("", messages, 1, 1.0)
    with pytest.raises(ValueError, match="exact two-item tuple"):
        LLMRequest("model", cast(tuple[LLMMessage, ...], list(messages)), 1, 1.0)
    with pytest.raises(ValueError, match="positive integer"):
        LLMRequest("model", messages, cast(int, True), 1.0)
    with pytest.raises(ValueError, match="positive finite number"):
        LLMRequest("model", messages, 1, float("inf"))
    with pytest.raises(ValueError, match="output_text must be a string"):
        LLMResponse(cast(str, None))
    with pytest.raises(ValueError, match="usage must be TokenUsage"):
        LLMResponse("{}", cast(TokenUsage, object()))


@pytest.mark.parametrize("api_key", ["", " ", "\t", cast(str, None), cast(str, 42)])
@pytest.mark.parametrize("provider_type", [OpenAIProvider, AnthropicProvider])
def test_provider_constructors_require_an_explicit_nonempty_api_key(
    provider_type: type[OpenAIProvider] | type[AnthropicProvider],
    api_key: str,
) -> None:
    with pytest.raises(ValueError, match="api_key must be a non-empty string") as raised:
        provider_type(api_key)
    assert API_KEY not in str(raised.value)


def test_openai_uses_fixed_endpoint_disabled_retries_and_responses_shape(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "environment-key-must-be-ignored")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://environment.invalid")
    usage = SimpleNamespace(input_tokens=11, output_tokens=7, total_tokens=18)
    factory, resource = _install_openai(
        monkeypatch,
        result=_openai_output("openai result", usage=usage),
    )

    provider = OpenAIProvider(API_KEY)
    response = provider.complete(_request())

    assert provider.name == "openai"
    assert isinstance(provider, LLMProvider)
    assert factory.calls == [
        {
            "api_key": API_KEY,
            "admin_api_key": "",
            "organization": "",
            "project": "",
            "webhook_secret": "",
            "base_url": "https://api.openai.com/v1",
            "max_retries": 0,
            "default_headers": {},
        }
    ]
    assert resource.calls == [
        {
            "model": "provider-model",
            "instructions": "trusted system",
            "input": '{"untrusted":"data"}',
            "max_output_tokens": 4096,
            "store": False,
            "stream": False,
            "timeout": 12.5,
        }
    ]
    assert response == LLMResponse(
        output_text="openai result",
        usage=TokenUsage(input_tokens=11, output_tokens=7, total_tokens=18),
    )
    assert API_KEY not in repr(provider)


def test_anthropic_uses_fixed_endpoint_disabled_retries_and_messages_shape(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "environment-key-must-be-ignored")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://environment.invalid")
    usage = SimpleNamespace(input_tokens=13, output_tokens=5)
    factory, resource = _install_anthropic(
        monkeypatch,
        result=_anthropic_output("anthropic result", usage=usage),
    )

    provider = AnthropicProvider(API_KEY)
    response = provider.complete(_request())

    assert provider.name == "anthropic"
    assert isinstance(provider, LLMProvider)
    assert factory.calls == [
        {
            "api_key": API_KEY,
            "webhook_key": "",
            "base_url": "https://api.anthropic.com",
            "max_retries": 0,
            "default_headers": {},
        }
    ]
    assert resource.calls == [
        {
            "model": "provider-model",
            "system": "trusted system",
            "messages": [{"role": "user", "content": '{"untrusted":"data"}'}],
            "max_tokens": 4096,
            "stream": False,
            "timeout": 12.5,
        }
    ]
    assert response == LLMResponse(
        output_text="anthropic result",
        usage=TokenUsage(input_tokens=13, output_tokens=5, total_tokens=None),
    )
    assert API_KEY not in repr(provider)


def test_openai_ignores_all_sdk_header_and_identity_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "environment-admin-key")
    monkeypatch.setenv("OPENAI_ORG_ID", "environment-organization")
    monkeypatch.setenv("OPENAI_PROJECT_ID", "environment-project")
    monkeypatch.setenv("OPENAI_WEBHOOK_SECRET", "environment-webhook-secret")
    monkeypatch.setenv(
        "OPENAI_CUSTOM_HEADERS",
        "\n".join(
            (
                "Authorization: Bearer environment-credential",
                "X-Environment-Only: injected",
                "OpenAI-Organization: environment-header-organization",
            )
        ),
    )
    requests: list[httpx.Request] = []
    clients: list[openai.OpenAI] = []
    client_type = openai.OpenAI

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            401,
            request=request,
            json={
                "error": {
                    "message": "denied",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": "invalid_api_key",
                }
            },
        )

    def client_factory(**kwargs: object) -> openai.OpenAI:
        client = client_type(
            **cast(dict[str, Any], kwargs),
            http_client=httpx.Client(
                transport=httpx.MockTransport(handle),
                trust_env=False,
            ),
        )
        clients.append(client)
        return client

    monkeypatch.setattr(openai, "OpenAI", client_factory)
    try:
        provider = OpenAIProvider(API_KEY)
        with pytest.raises(ProviderError) as exc_info:
            provider.complete(_request())
    finally:
        for client in clients:
            client.close()

    assert exc_info.value.code is ProviderErrorCode.AUTHENTICATION_FAILED
    assert len(requests) == 1
    headers = requests[0].headers
    assert headers["authorization"] == f"Bearer {API_KEY}"
    assert "openai-organization" not in headers
    assert "openai-project" not in headers
    assert "x-environment-only" not in headers
    assert "environment" not in str(headers).lower()


def test_anthropic_ignores_all_sdk_header_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_WEBHOOK_SIGNING_KEY", "environment-webhook-secret")
    monkeypatch.setenv(
        "ANTHROPIC_CUSTOM_HEADERS",
        "\n".join(
            (
                "X-Api-Key: environment-credential",
                "Authorization: Bearer environment-credential",
                "X-Environment-Only: injected",
            )
        ),
    )
    requests: list[httpx.Request] = []
    clients: list[anthropic.Anthropic] = []
    client_type = providers_impl._ExplicitAnthropicClient

    def fail_on_credential_discovery() -> bool:
        raise AssertionError("explicit Anthropic configuration must not inspect config files")

    monkeypatch.setattr(
        anthropic_client,
        "_has_auto_discoverable_credentials",
        fail_on_credential_discovery,
    )

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            401,
            request=request,
            json={
                "type": "error",
                "error": {
                    "type": "authentication_error",
                    "message": "denied",
                },
            },
        )

    def client_factory(**kwargs: object) -> anthropic.Anthropic:
        client = client_type(
            **cast(dict[str, Any], kwargs),
            http_client=httpx.Client(
                transport=httpx.MockTransport(handle),
                trust_env=False,
            ),
        )
        clients.append(client)
        return client

    monkeypatch.setattr(providers_impl, "_ExplicitAnthropicClient", client_factory)
    try:
        provider = AnthropicProvider(API_KEY)
        with pytest.raises(ProviderError) as exc_info:
            provider.complete(_request())
    finally:
        for client in clients:
            client.close()

    assert exc_info.value.code is ProviderErrorCode.AUTHENTICATION_FAILED
    assert len(requests) == 1
    headers = requests[0].headers
    assert headers["x-api-key"] == API_KEY
    assert "authorization" not in headers
    assert "x-environment-only" not in headers
    assert "environment" not in str(headers).lower()


def test_openai_sdk_debug_logging_redacts_prompt_without_changing_logger(
    monkeypatch: MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    clients: list[openai.OpenAI] = []
    client_type = openai.OpenAI

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            400,
            request=request,
            json={
                "error": {
                    "message": "denied",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": "invalid_prompt",
                }
            },
        )

    def client_factory(**kwargs: object) -> openai.OpenAI:
        client = client_type(
            **cast(dict[str, Any], kwargs),
            http_client=httpx.Client(
                transport=httpx.MockTransport(handle),
                trust_env=False,
            ),
        )
        clients.append(client)
        return client

    monkeypatch.setattr(openai, "OpenAI", client_factory)
    logger = logging.getLogger("openai._base_client")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        state_before = (
            logger.level,
            tuple(logger.handlers),
            tuple(logger.filters),
            logger.propagate,
            logger.disabled,
        )
        provider = OpenAIProvider(API_KEY)
        with pytest.raises(ProviderError):
            provider.complete(
                _request(
                    system=SYSTEM_PROMPT_MARKER,
                    user=USER_PROMPT_MARKER,
                )
            )
        state_after = (
            logger.level,
            tuple(logger.handlers),
            tuple(logger.filters),
            logger.propagate,
            logger.disabled,
        )
    finally:
        for client in clients:
            client.close()
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    captured = stream.getvalue()
    assert SYSTEM_PROMPT_MARKER not in captured
    assert USER_PROMPT_MARKER not in captured
    assert "[REDACTED_REPOGUARD_PROMPT]" in captured
    assert state_after == state_before
    assert len(requests) == 1
    assert SYSTEM_PROMPT_MARKER.encode() in requests[0].content
    assert USER_PROMPT_MARKER.encode() in requests[0].content


def test_anthropic_sdk_debug_logging_redacts_prompt_without_changing_logger(
    monkeypatch: MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    clients: list[anthropic.Anthropic] = []
    client_type = providers_impl._ExplicitAnthropicClient

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            400,
            request=request,
            json={
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "denied",
                },
            },
        )

    def client_factory(**kwargs: object) -> anthropic.Anthropic:
        client = client_type(
            **cast(dict[str, Any], kwargs),
            http_client=httpx.Client(
                transport=httpx.MockTransport(handle),
                trust_env=False,
            ),
        )
        clients.append(client)
        return client

    monkeypatch.setattr(providers_impl, "_ExplicitAnthropicClient", client_factory)
    logger = logging.getLogger("anthropic._base_client")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        state_before = (
            logger.level,
            tuple(logger.handlers),
            tuple(logger.filters),
            logger.propagate,
            logger.disabled,
        )
        provider = AnthropicProvider(API_KEY)
        with pytest.raises(ProviderError):
            provider.complete(
                _request(
                    system=SYSTEM_PROMPT_MARKER,
                    user=USER_PROMPT_MARKER,
                )
            )
        state_after = (
            logger.level,
            tuple(logger.handlers),
            tuple(logger.filters),
            logger.propagate,
            logger.disabled,
        )
    finally:
        for client in clients:
            client.close()
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    captured = stream.getvalue()
    assert SYSTEM_PROMPT_MARKER not in captured
    assert USER_PROMPT_MARKER not in captured
    assert "[REDACTED_REPOGUARD_PROMPT]" in captured
    assert state_after == state_before
    assert len(requests) == 1
    assert SYSTEM_PROMPT_MARKER.encode() in requests[0].content
    assert USER_PROMPT_MARKER.encode() in requests[0].content


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (
            openai.AuthenticationError(
                "unsafe authentication body",
                response=_http_response(401),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.AUTHENTICATION_FAILED,
        ),
        (
            openai.PermissionDeniedError(
                "unsafe permission body",
                response=_http_response(403),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.AUTHENTICATION_FAILED,
        ),
        (
            openai.RateLimitError(
                "unsafe rate body",
                response=_http_response(429),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.RATE_LIMITED,
        ),
        (
            openai.APITimeoutError(httpx.Request("POST", "https://provider.invalid")),
            ProviderErrorCode.TIMEOUT,
        ),
        (
            openai.APIConnectionError(
                message=f"unsafe connection {API_KEY}",
                request=httpx.Request("POST", "https://provider.invalid"),
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            openai.InternalServerError(
                f"unsafe server {API_KEY}",
                response=_http_response(500),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            openai.APIStatusError(
                f"unsafe timeout status {API_KEY}",
                response=_http_response(408),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.TIMEOUT,
        ),
        (
            openai.ConflictError(
                f"unsafe conflict status {API_KEY}",
                response=_http_response(409),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            openai.BadRequestError(
                f"unsafe request {API_KEY}",
                response=_http_response(400),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.REQUEST_FAILED,
        ),
        (
            openai.ContentFilterFinishReasonError(),
            ProviderErrorCode.REFUSED,
        ),
    ],
)
def test_openai_maps_known_sdk_errors_without_leaking_or_chaining(
    monkeypatch: MonkeyPatch,
    error: Exception,
    expected_code: ProviderErrorCode,
) -> None:
    _install_openai(monkeypatch, error=error)
    provider = OpenAIProvider(API_KEY)

    with pytest.raises(ProviderError) as raised:
        provider.complete(_request())

    assert raised.value.code is expected_code
    assert API_KEY not in str(raised.value)
    assert API_KEY not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (
            anthropic.AuthenticationError(
                "unsafe authentication body",
                response=_http_response(401),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.AUTHENTICATION_FAILED,
        ),
        (
            anthropic.PermissionDeniedError(
                "unsafe permission body",
                response=_http_response(403),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.AUTHENTICATION_FAILED,
        ),
        (
            anthropic.RateLimitError(
                "unsafe rate body",
                response=_http_response(429),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.RATE_LIMITED,
        ),
        (
            anthropic.APITimeoutError(httpx.Request("POST", "https://provider.invalid")),
            ProviderErrorCode.TIMEOUT,
        ),
        (
            anthropic.APIConnectionError(
                message=f"unsafe connection {API_KEY}",
                request=httpx.Request("POST", "https://provider.invalid"),
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            anthropic.InternalServerError(
                f"unsafe server {API_KEY}",
                response=_http_response(500),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            anthropic.APIStatusError(
                f"unsafe timeout status {API_KEY}",
                response=_http_response(408),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.TIMEOUT,
        ),
        (
            anthropic.ConflictError(
                f"unsafe conflict status {API_KEY}",
                response=_http_response(409),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.UNAVAILABLE,
        ),
        (
            anthropic.BadRequestError(
                f"unsafe request {API_KEY}",
                response=_http_response(400),
                body={"api_key": API_KEY},
            ),
            ProviderErrorCode.REQUEST_FAILED,
        ),
    ],
)
def test_anthropic_maps_known_sdk_errors_without_leaking_or_chaining(
    monkeypatch: MonkeyPatch,
    error: Exception,
    expected_code: ProviderErrorCode,
) -> None:
    _install_anthropic(monkeypatch, error=error)
    provider = AnthropicProvider(API_KEY)

    with pytest.raises(ProviderError) as raised:
        provider.complete(_request())

    assert raised.value.code is expected_code
    assert API_KEY not in str(raised.value)
    assert API_KEY not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_provider_refusals_and_invalid_response_shapes_are_stable(
    monkeypatch: MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="refusal", refusal="not allowed")],
            )
        ],
        usage=None,
        status="completed",
    )
    _install_openai(monkeypatch, result=refusal)
    with pytest.raises(ProviderError) as openai_refusal:
        OpenAIProvider(API_KEY).complete(_request())
    assert openai_refusal.value.code is ProviderErrorCode.REFUSED

    _install_anthropic(
        monkeypatch,
        result=_anthropic_output(stop_reason="refusal"),
    )
    with pytest.raises(ProviderError) as anthropic_refusal:
        AnthropicProvider(API_KEY).complete(_request())
    assert anthropic_refusal.value.code is ProviderErrorCode.REFUSED

    _install_openai(monkeypatch, result=SimpleNamespace(output=None, usage=None))
    with pytest.raises(ProviderError) as invalid_openai:
        OpenAIProvider(API_KEY).complete(_request())
    assert invalid_openai.value.code is ProviderErrorCode.INVALID_RESPONSE

    invalid_usage = SimpleNamespace(input_tokens=-1, output_tokens=0)
    _install_anthropic(
        monkeypatch,
        result=_anthropic_output(usage=invalid_usage),
    )
    with pytest.raises(ProviderError) as invalid_anthropic:
        AnthropicProvider(API_KEY).complete(_request())
    assert invalid_anthropic.value.code is ProviderErrorCode.INVALID_RESPONSE


def test_incomplete_provider_generations_are_invalid_responses(
    monkeypatch: MonkeyPatch,
) -> None:
    _install_openai(
        monkeypatch,
        result=_openai_output(status="incomplete"),
    )
    with pytest.raises(ProviderError) as incomplete_openai:
        OpenAIProvider(API_KEY).complete(_request())
    assert incomplete_openai.value.code is ProviderErrorCode.INVALID_RESPONSE

    _install_anthropic(
        monkeypatch,
        result=_anthropic_output(stop_reason="max_tokens"),
    )
    with pytest.raises(ProviderError) as incomplete_anthropic:
        AnthropicProvider(API_KEY).complete(_request())
    assert incomplete_anthropic.value.code is ProviderErrorCode.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("status", "error_code", "incomplete_reason", "expected_code"),
    [
        ("failed", "server_error", None, ProviderErrorCode.UNAVAILABLE),
        ("failed", "rate_limit_exceeded", None, ProviderErrorCode.RATE_LIMITED),
        ("failed", "invalid_prompt", None, ProviderErrorCode.REQUEST_FAILED),
        ("incomplete", None, "content_filter", ProviderErrorCode.REFUSED),
        ("incomplete", None, "max_output_tokens", ProviderErrorCode.INVALID_RESPONSE),
    ],
)
def test_openai_maps_native_response_failures(
    monkeypatch: MonkeyPatch,
    status: str,
    error_code: str | None,
    incomplete_reason: str | None,
    expected_code: ProviderErrorCode,
) -> None:
    response = _openai_output(status=status)
    response.error = (
        None
        if error_code is None
        else SimpleNamespace(code=error_code, message=f"unsafe {API_KEY}")
    )
    response.incomplete_details = (
        None if incomplete_reason is None else SimpleNamespace(reason=incomplete_reason)
    )
    _install_openai(monkeypatch, result=response)

    with pytest.raises(ProviderError) as raised:
        OpenAIProvider(API_KEY).complete(_request())

    assert raised.value.code is expected_code
    assert API_KEY not in str(raised.value)
    assert API_KEY not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize("provider_name", ["openai", "anthropic"])
def test_unexpected_adapter_exceptions_remain_for_the_outer_workflow(
    monkeypatch: MonkeyPatch,
    provider_name: str,
) -> None:
    unexpected = RuntimeError(f"outer workflow must sanitize {API_KEY}")
    if provider_name == "openai":
        _install_openai(monkeypatch, error=unexpected)
        provider: LLMProvider = OpenAIProvider(API_KEY)
    else:
        _install_anthropic(monkeypatch, error=unexpected)
        provider = AnthropicProvider(API_KEY)

    with pytest.raises(RuntimeError) as raised:
        provider.complete(_request())
    assert raised.value is unexpected
