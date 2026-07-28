"""Typed synchronous interfaces for RepoGuard LLM providers."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

import anthropic
import openai

__all__ = [
    "AnthropicProvider",
    "LLMMessage",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "MessageRole",
    "OpenAIProvider",
    "ProviderError",
    "ProviderErrorCode",
    "TokenUsage",
]

_OPENAI_BASE_URL = "https://api.openai.com/v1"
_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
_OPENAI_REQUEST_ERROR_CODES = frozenset(
    {
        "data_residency_mismatch",
        "empty_image_file",
        "failed_to_download_image",
        "image_file_not_found",
        "image_file_too_large",
        "image_parse_error",
        "image_too_large",
        "image_too_small",
        "invalid_base64_image",
        "invalid_image",
        "invalid_image_format",
        "invalid_image_mode",
        "invalid_image_url",
        "invalid_prompt",
        "unsupported_image_media_type",
    }
)
_OPENAI_REFUSAL_ERROR_CODES = frozenset(
    {
        "bio_policy",
        "image_content_policy_violation",
    }
)


class _ExplicitAnthropicClient(anthropic.Anthropic):
    """Official client subtype with base-client credential discovery disabled."""


class _RedactedPromptText(str):
    """String that preserves wire content while redacting SDK request-option logs."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'[REDACTED_REPOGUARD_PROMPT]'"


class MessageRole(StrEnum):
    """Role of one trusted provider request message."""

    SYSTEM = "system"
    USER = "user"


class ProviderErrorCode(StrEnum):
    """Stable category for a provider adapter failure."""

    AUTHENTICATION_FAILED = "authentication_failed"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    REQUEST_FAILED = "request_failed"
    REFUSED = "refused"
    INVALID_RESPONSE = "invalid_response"


_ERROR_MESSAGES = {
    ProviderErrorCode.AUTHENTICATION_FAILED: "Provider authentication failed.",
    ProviderErrorCode.RATE_LIMITED: "Provider rate limit exceeded.",
    ProviderErrorCode.TIMEOUT: "Provider request timed out.",
    ProviderErrorCode.UNAVAILABLE: "Provider service is unavailable.",
    ProviderErrorCode.REQUEST_FAILED: "Provider request failed.",
    ProviderErrorCode.REFUSED: "Provider refused the request.",
    ProviderErrorCode.INVALID_RESPONSE: "Provider returned an invalid response.",
}


class ProviderError(RuntimeError):
    """Secret-safe provider failure with a stable machine-readable code."""

    code: ProviderErrorCode

    def __init__(self, code: ProviderErrorCode) -> None:
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code


@dataclass(frozen=True, slots=True)
class LLMMessage:
    """One message supplied to a provider."""

    role: MessageRole
    content: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, MessageRole):
            msg = "role must be a MessageRole"
            raise ValueError(msg)
        if type(self.content) is not str:
            msg = "content must be a string"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """One bounded synchronous provider request."""

    model: str
    messages: tuple[LLMMessage, ...]
    max_output_tokens: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if type(self.model) is not str or not self.model:
            msg = "model must be a non-empty string"
            raise ValueError(msg)
        if type(self.messages) is not tuple or len(self.messages) != 2:
            msg = "messages must be an exact two-item tuple"
            raise ValueError(msg)
        if (
            self.messages[0].role is not MessageRole.SYSTEM
            or self.messages[1].role is not MessageRole.USER
        ):
            msg = "messages must contain one system message followed by one user message"
            raise ValueError(msg)
        if type(self.max_output_tokens) is not int or self.max_output_tokens <= 0:
            msg = "max_output_tokens must be a positive integer"
            raise ValueError(msg)
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            msg = "timeout_seconds must be a positive finite number"
            raise ValueError(msg)
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Provider-reported token counts without local estimation."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        for value in (self.input_tokens, self.output_tokens, self.total_tokens):
            if value is not None and (type(value) is not int or value < 0):
                msg = "token usage values must be non-negative integers or None"
                raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Provider text and optional provider-reported token usage."""

    output_text: str
    usage: TokenUsage | None = None

    def __post_init__(self) -> None:
        if type(self.output_text) is not str:
            msg = "output_text must be a string"
            raise ValueError(msg)
        if self.usage is not None and not isinstance(self.usage, TokenUsage):
            msg = "usage must be TokenUsage or None"
            raise ValueError(msg)


@runtime_checkable
class LLMProvider(Protocol):
    """Synchronous provider boundary used by the controlled review workflow."""

    @property
    def name(self) -> str:
        """Return the stable non-empty provider name."""
        ...

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Return one complete response or raise ProviderError."""
        ...


class OpenAIProvider:
    """Official OpenAI Responses API adapter."""

    __slots__ = ("_client",)

    def __init__(self, api_key: str) -> None:
        _validate_api_key(api_key)
        client = openai.OpenAI(
            api_key=api_key,
            admin_api_key="",
            organization="",
            project="",
            webhook_secret="",
            base_url=_OPENAI_BASE_URL,
            max_retries=0,
            default_headers={},
        )
        client._custom_headers = {}
        client.admin_api_key = None
        client.organization = None
        client.project = None
        client.webhook_secret = None
        self._client = client

    @property
    def name(self) -> str:
        """Return the stable provider name."""
        return "openai"

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Complete one non-streaming request through the Responses API."""
        failure: ProviderErrorCode | None = None
        response: object = None
        try:
            response = self._client.responses.create(
                model=request.model,
                instructions=_RedactedPromptText(request.messages[0].content),
                input=_RedactedPromptText(request.messages[1].content),
                max_output_tokens=request.max_output_tokens,
                store=False,
                stream=False,
                timeout=request.timeout_seconds,
            )
        except openai.AuthenticationError:
            failure = ProviderErrorCode.AUTHENTICATION_FAILED
        except openai.PermissionDeniedError:
            failure = ProviderErrorCode.AUTHENTICATION_FAILED
        except openai.RateLimitError:
            failure = ProviderErrorCode.RATE_LIMITED
        except openai.APITimeoutError:
            failure = ProviderErrorCode.TIMEOUT
        except openai.APIConnectionError:
            failure = ProviderErrorCode.UNAVAILABLE
        except openai.APIResponseValidationError:
            failure = ProviderErrorCode.INVALID_RESPONSE
        except openai.ContentFilterFinishReasonError:
            failure = ProviderErrorCode.REFUSED
        except openai.APIStatusError as error:
            failure = _status_error_code(error.status_code)
        except openai.APIError:
            failure = ProviderErrorCode.REQUEST_FAILED

        if failure is not None:
            raise ProviderError(failure) from None

        return _openai_response(response)


class AnthropicProvider:
    """Official Anthropic Messages API adapter."""

    __slots__ = ("_client",)

    def __init__(self, api_key: str) -> None:
        _validate_api_key(api_key)
        client = _ExplicitAnthropicClient(
            api_key=api_key,
            webhook_key="",
            base_url=_ANTHROPIC_BASE_URL,
            max_retries=0,
            default_headers={},
        )
        client._custom_headers = {}
        client.webhook_key = None
        self._client = client

    @property
    def name(self) -> str:
        """Return the stable provider name."""
        return "anthropic"

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Complete one non-streaming request through the Messages API."""
        failure: ProviderErrorCode | None = None
        response: object = None
        try:
            response = self._client.messages.create(
                model=request.model,
                system=_RedactedPromptText(request.messages[0].content),
                messages=[
                    {
                        "role": "user",
                        "content": _RedactedPromptText(request.messages[1].content),
                    }
                ],
                max_tokens=request.max_output_tokens,
                stream=False,
                timeout=request.timeout_seconds,
            )
        except anthropic.AuthenticationError:
            failure = ProviderErrorCode.AUTHENTICATION_FAILED
        except anthropic.PermissionDeniedError:
            failure = ProviderErrorCode.AUTHENTICATION_FAILED
        except anthropic.RateLimitError:
            failure = ProviderErrorCode.RATE_LIMITED
        except anthropic.APITimeoutError:
            failure = ProviderErrorCode.TIMEOUT
        except anthropic.APIConnectionError:
            failure = ProviderErrorCode.UNAVAILABLE
        except anthropic.APIResponseValidationError:
            failure = ProviderErrorCode.INVALID_RESPONSE
        except anthropic.APIStatusError as error:
            failure = _status_error_code(error.status_code)
        except anthropic.APIError:
            failure = ProviderErrorCode.REQUEST_FAILED

        if failure is not None:
            raise ProviderError(failure) from None

        return _anthropic_response(response)


def _validate_api_key(api_key: object) -> None:
    if type(api_key) is not str or not api_key.strip():
        msg = "api_key must be a non-empty string"
        raise ValueError(msg)


def _status_error_code(status_code: int) -> ProviderErrorCode:
    if status_code == 408:
        return ProviderErrorCode.TIMEOUT
    if status_code == 409 or status_code >= 500:
        return ProviderErrorCode.UNAVAILABLE
    return ProviderErrorCode.REQUEST_FAILED


def _openai_response(response: object) -> LLMResponse:
    status = getattr(response, "status", None)
    if status != "completed":
        raise ProviderError(_openai_response_error_code(response, status)) from None
    output = getattr(response, "output", None)
    if type(output) is not list:
        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None

    text_parts: list[str] = []
    for item in output:
        item_type = getattr(item, "type", None)
        if item_type != "message":
            continue
        content = getattr(item, "content", None)
        if type(content) is not list:
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type == "refusal":
                raise ProviderError(ProviderErrorCode.REFUSED) from None
            if block_type != "output_text":
                raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
            text = getattr(block, "text", None)
            if type(text) is not str:
                raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
            text_parts.append(text)

    return LLMResponse(
        output_text="".join(text_parts),
        usage=_openai_usage(getattr(response, "usage", None)),
    )


def _openai_response_error_code(
    response: object,
    status: object,
) -> ProviderErrorCode:
    if status == "failed":
        error = getattr(response, "error", None)
        code = getattr(error, "code", None)
        if type(code) is not str:
            return ProviderErrorCode.INVALID_RESPONSE
        if code == "server_error":
            return ProviderErrorCode.UNAVAILABLE
        if code == "rate_limit_exceeded":
            return ProviderErrorCode.RATE_LIMITED
        if code == "vector_store_timeout":
            return ProviderErrorCode.TIMEOUT
        if code in _OPENAI_REFUSAL_ERROR_CODES:
            return ProviderErrorCode.REFUSED
        if code in _OPENAI_REQUEST_ERROR_CODES:
            return ProviderErrorCode.REQUEST_FAILED
        return ProviderErrorCode.INVALID_RESPONSE

    if status == "incomplete":
        details = getattr(response, "incomplete_details", None)
        if getattr(details, "reason", None) == "content_filter":
            return ProviderErrorCode.REFUSED

    return ProviderErrorCode.INVALID_RESPONSE


def _openai_usage(usage: object) -> TokenUsage | None:
    if usage is None:
        return None
    return _token_usage(
        getattr(usage, "input_tokens", None),
        getattr(usage, "output_tokens", None),
        getattr(usage, "total_tokens", None),
    )


def _anthropic_response(response: object) -> LLMResponse:
    stop_reason = getattr(response, "stop_reason", None)
    if stop_reason == "refusal":
        raise ProviderError(ProviderErrorCode.REFUSED) from None
    if stop_reason not in {"end_turn", "stop_sequence"}:
        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None

    content = getattr(response, "content", None)
    if type(content) is not list:
        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None

    text_parts: list[str] = []
    for block in content:
        if getattr(block, "type", None) != "text":
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
        text = getattr(block, "text", None)
        if type(text) is not str:
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
        text_parts.append(text)

    return LLMResponse(
        output_text="".join(text_parts),
        usage=_anthropic_usage(getattr(response, "usage", None)),
    )


def _anthropic_usage(usage: object) -> TokenUsage | None:
    if usage is None:
        return None
    return _token_usage(
        getattr(usage, "input_tokens", None),
        getattr(usage, "output_tokens", None),
        None,
    )


def _token_usage(
    input_tokens: object,
    output_tokens: object,
    total_tokens: object,
) -> TokenUsage:
    return TokenUsage(
        input_tokens=_usage_value(input_tokens),
        output_tokens=_usage_value(output_tokens),
        total_tokens=_usage_value(total_tokens),
    )


def _usage_value(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE) from None
    return value
