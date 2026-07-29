"""Trusted repair prompt resources and bounded built-in provider execution."""

from __future__ import annotations

import hashlib
import json
import time
import unicodedata
from dataclasses import dataclass
from importlib.resources import files
from typing import NoReturn

from repoguard._repair_models import _canonical_bytes
from repoguard._repair_paths import _validate_repository_path
from repoguard.providers import (
    AnthropicProvider,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    MessageRole,
    OpenAIProvider,
    ProviderError,
    ProviderErrorCode,
    TokenUsage,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairPromptIdentity,
    RepairProviderKind,
    RepairStage,
    RepairState,
)

_PROMPT_DIRECTORY = ("prompts", "agent_repair", "v1")
_SYSTEM_RESOURCE = "system.md"
_SCHEMA_RESOURCE = "response-schema.json"
_MAX_PROVIDER_ATTEMPTS = 3
_BACKOFF_SECONDS = {2: 0.5, 3: 1.0}
_RETRYABLE_PROVIDER_ERRORS = frozenset(
    {
        ProviderErrorCode.RATE_LIMITED,
        ProviderErrorCode.TIMEOUT,
        ProviderErrorCode.UNAVAILABLE,
    }
)
_PROVIDER_ERROR_MAP = {
    ProviderErrorCode.AUTHENTICATION_FAILED: RepairErrorCode.PROVIDER_AUTHENTICATION,
    ProviderErrorCode.RATE_LIMITED: RepairErrorCode.PROVIDER_RATE_LIMITED,
    ProviderErrorCode.TIMEOUT: RepairErrorCode.PROVIDER_TIMEOUT,
    ProviderErrorCode.UNAVAILABLE: RepairErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorCode.REQUEST_FAILED: RepairErrorCode.PROVIDER_BAD_REQUEST,
    ProviderErrorCode.REFUSED: RepairErrorCode.PROVIDER_PERMISSION,
    ProviderErrorCode.INVALID_RESPONSE: RepairErrorCode.PROVIDER_INVALID_RESPONSE,
}

_monotonic = time.monotonic
_sleep = time.sleep


@dataclass(frozen=True, slots=True)
class _RepairPromptFinding:
    rule_id: str
    category: str
    severity: str
    title: str
    remediation: str
    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class _RepairPromptFile:
    path: str
    present: bool
    content: str | None


@dataclass(frozen=True, slots=True)
class _RepairPromptHit:
    path: str
    oid: str
    start_line: int
    end_line: int
    content: str
    definitions: tuple[str, ...]
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RenderedRepairPrompt:
    messages: tuple[LLMMessage, ...]
    identity: RepairPromptIdentity
    byte_count: int


@dataclass(frozen=True, slots=True)
class _RepairProviderResult:
    response_text: str
    patch: str
    attempt_count: int
    input_tokens: int
    output_tokens: int


def _repair_prompt_identity() -> RepairPromptIdentity:
    system_bytes, schema_bytes = _read_prompt_resources()
    combined = b"repoguard.agent_repair.v1\0" + system_bytes + b"\0" + schema_bytes
    return RepairPromptIdentity(
        "agent_repair",
        1,
        hashlib.sha256(system_bytes).hexdigest(),
        hashlib.sha256(schema_bytes).hexdigest(),
        hashlib.sha256(combined).hexdigest(),
    )


def _render_repair_prompt(
    *,
    object_format: str,
    head_oid: str,
    findings: tuple[_RepairPromptFinding, ...],
    allowed_files: tuple[_RepairPromptFile, ...],
    context_hits: tuple[_RepairPromptHit, ...],
    policy: RepairGenerationPolicy,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> _RenderedRepairPrompt:
    if (
        type(policy) is not RepairGenerationPolicy
        or type(findings) is not tuple
        or not findings
        or len(findings) > 16
        or any(type(finding) is not _RepairPromptFinding for finding in findings)
        or any(not _valid_prompt_finding(finding) for finding in findings)
        or type(allowed_files) is not tuple
        or not allowed_files
        or len(allowed_files) > 32
        or any(type(item) is not _RepairPromptFile for item in allowed_files)
        or type(context_hits) is not tuple
        or len(context_hits) > policy.max_context_hits
        or any(type(hit) is not _RepairPromptHit for hit in context_hits)
        or any(not _valid_prompt_hit(hit) for hit in context_hits)
    ):
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROMPT, state, session_id)
    expected_oid_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    if (
        expected_oid_length == 0
        or type(head_oid) is not str
        or len(head_oid) != expected_oid_length
        or any(character not in "0123456789abcdef" for character in head_oid)
    ):
        _raise_repair(RepairErrorCode.IDENTITY_MISMATCH, RepairStage.PROMPT, state, session_id)

    file_mappings: list[dict[str, object]] = []
    previous_path: bytes | None = None
    for item in allowed_files:
        if not _valid_repository_path(item.path):
            _raise_repair(RepairErrorCode.INVALID_PATH, RepairStage.PROMPT, state, session_id)
        invalid_encoding = False
        try:
            path_bytes = item.path.encode("utf-8")
            content_bytes = None if item.content is None else item.content.encode("utf-8")
        except UnicodeEncodeError:
            invalid_encoding = True
            path_bytes = b""
            content_bytes = None
        if invalid_encoding:
            _raise_repair(RepairErrorCode.INVALID_PATH, RepairStage.PROMPT, state, session_id)
        if previous_path is not None and path_bytes <= previous_path:
            _raise_repair(RepairErrorCode.INVALID_PATH, RepairStage.PROMPT, state, session_id)
        previous_path = path_bytes
        if (
            type(item.present) is not bool
            or item.present != (item.content is not None)
            or (content_bytes is not None and len(content_bytes) > policy.max_file_bytes)
        ):
            _raise_repair(RepairErrorCode.RESOURCE_LIMIT, RepairStage.PROMPT, state, session_id)
        file_mappings.append({"path": item.path, "present": item.present, "content": item.content})

    system_bytes, schema_bytes = _read_prompt_resources()
    invalid_resource = False
    try:
        system_text = system_bytes.decode("utf-8")
        schema_text = schema_bytes.decode("utf-8")
        schema_value = json.loads(schema_text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        invalid_resource = True
        system_text = schema_text = ""
        schema_value = None
    if invalid_resource or type(schema_value) is not dict:
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROMPT, state, session_id)

    user_value: dict[str, object] = {
        "schema_version": 1,
        "repository": {"object_format": object_format, "head_oid": head_oid},
        "selected_findings": [_finding_mapping(finding) for finding in findings],
        "allowed_files": file_mappings,
        "context_hits": [_hit_mapping(hit) for hit in context_hits],
    }
    invalid_user = False
    try:
        user_text = _canonical_bytes(user_value).decode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        invalid_user = True
        user_text = ""
    if invalid_user:
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROMPT, state, session_id)
    trusted_text = f"{system_text}\nResponse schema:\n{schema_text}"
    messages = (
        LLMMessage(MessageRole.SYSTEM, trusted_text),
        LLMMessage(MessageRole.USER, user_text),
    )
    byte_count = sum(len(message.content.encode("utf-8")) for message in messages)
    if byte_count > policy.max_prompt_bytes:
        _raise_repair(RepairErrorCode.RESOURCE_LIMIT, RepairStage.PROMPT, state, session_id)
    return _RenderedRepairPrompt(messages, _repair_prompt_identity(), byte_count)


def _validate_provider_capability(
    policy: RepairGenerationPolicy,
    provider: OpenAIProvider | AnthropicProvider | None,
    *,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> None:
    if type(policy) is not RepairGenerationPolicy:
        _raise_repair(RepairErrorCode.INVALID_CONFIG, RepairStage.PROVIDER, state, session_id)
    if policy.mode is RepairGenerationMode.DETERMINISTIC:
        if provider is not None:
            _raise_repair(
                RepairErrorCode.PROVIDER_MISMATCH,
                RepairStage.PROVIDER,
                state,
                session_id,
            )
        return
    if provider is None:
        _raise_repair(RepairErrorCode.PROVIDER_REQUIRED, RepairStage.PROVIDER, state, session_id)
    expected_type: type[OpenAIProvider] | type[AnthropicProvider]
    expected_kind: RepairProviderKind
    if policy.provider_kind is RepairProviderKind.OPENAI:
        expected_type = OpenAIProvider
        expected_kind = RepairProviderKind.OPENAI
    else:
        expected_type = AnthropicProvider
        expected_kind = RepairProviderKind.ANTHROPIC
    if type(provider) is not expected_type or provider.name != expected_kind.value:
        _raise_repair(
            RepairErrorCode.PROVIDER_MISMATCH,
            RepairStage.PROVIDER,
            state,
            session_id,
        )


def _invoke_repair_provider(
    provider: OpenAIProvider | AnthropicProvider,
    rendered: _RenderedRepairPrompt,
    policy: RepairGenerationPolicy,
    *,
    deadline: float | None = None,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> _RepairProviderResult:
    _validate_provider_capability(policy, provider, state=state, session_id=session_id)
    if type(rendered) is not _RenderedRepairPrompt or policy.model is None:
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROVIDER, state, session_id)
    if deadline is None:
        deadline = _monotonic() + policy.total_timeout_seconds
    elif type(deadline) is not float:
        _raise_repair(RepairErrorCode.INVALID_CONFIG, RepairStage.PROVIDER, state, session_id)
    for attempt in range(1, _MAX_PROVIDER_ATTEMPTS + 1):
        if attempt > 1:
            delay = _BACKOFF_SECONDS[attempt]
            if _monotonic() + delay >= deadline:
                _raise_repair(
                    RepairErrorCode.PROVIDER_TIMEOUT,
                    RepairStage.PROVIDER,
                    state,
                    session_id,
                )
            _sleep(delay)
        remaining = deadline - _monotonic()
        if remaining <= 0:
            _raise_repair(
                RepairErrorCode.PROVIDER_TIMEOUT,
                RepairStage.PROVIDER,
                state,
                session_id,
            )
        request = LLMRequest(
            policy.model,
            rendered.messages,
            policy.max_output_tokens,
            min(policy.attempt_timeout_seconds, remaining),
        )
        provider_error: ProviderErrorCode | None = None
        response: LLMResponse | None = None
        unknown_failure = False
        try:
            response = provider.complete(request)
        except ProviderError as error:
            provider_error = error.code if type(error.code) is ProviderErrorCode else None
            unknown_failure = provider_error is None
        except Exception:
            unknown_failure = True
        if unknown_failure:
            _raise_repair(RepairErrorCode.PROVIDER_FAILED, RepairStage.PROVIDER, state, session_id)
        if provider_error is not None:
            if provider_error in _RETRYABLE_PROVIDER_ERRORS and attempt < _MAX_PROVIDER_ATTEMPTS:
                continue
            _raise_repair(
                _PROVIDER_ERROR_MAP[provider_error],
                RepairStage.PROVIDER,
                state,
                session_id,
            )
        if _monotonic() >= deadline:
            _raise_repair(
                RepairErrorCode.PROVIDER_TIMEOUT,
                RepairStage.PROVIDER,
                state,
                session_id,
            )
        return _parse_repair_response(
            response,
            attempt_count=attempt,
            maximum_bytes=policy.max_response_bytes,
            state=state,
            session_id=session_id,
        )
    _raise_repair(RepairErrorCode.PROVIDER_FAILED, RepairStage.PROVIDER, state, session_id)


def _parse_repair_response(
    response: LLMResponse | None,
    *,
    attempt_count: int,
    maximum_bytes: int,
    state: RepairState | None = None,
    session_id: str | None = None,
) -> _RepairProviderResult:
    invalid = False
    text = ""
    usage: TokenUsage | None = None
    mapping: object = None
    if type(response) is not LLMResponse:
        invalid = True
    else:
        text = response.output_text
        usage = response.usage
        if type(text) is not str or (usage is not None and type(usage) is not TokenUsage):
            invalid = True
    if not invalid:
        try:
            encoded = text.encode("utf-8")
            if len(encoded) > maximum_bytes or text != text.strip():
                invalid = True
            else:
                mapping = json.loads(
                    text,
                    object_pairs_hook=_reject_duplicate_pairs,
                    parse_constant=_reject_constant,
                )
        except (UnicodeEncodeError, json.JSONDecodeError, ValueError):
            invalid = True
    patch = ""
    if not invalid:
        if (
            type(mapping) is not dict
            or set(mapping) != {"schema_version", "patch"}
            or type(mapping["schema_version"]) is not int
            or mapping["schema_version"] != 1
            or type(mapping["patch"]) is not str
        ):
            invalid = True
        else:
            patch = mapping["patch"]
            try:
                patch.encode("utf-8")
            except UnicodeEncodeError:
                invalid = True
    if invalid:
        _raise_repair(
            RepairErrorCode.MODEL_RESPONSE_INVALID,
            RepairStage.PROVIDER,
            state,
            session_id,
        )
    input_tokens = 0 if usage is None or usage.input_tokens is None else usage.input_tokens
    output_tokens = 0 if usage is None or usage.output_tokens is None else usage.output_tokens
    return _RepairProviderResult(text, patch, attempt_count, input_tokens, output_tokens)


def _read_prompt_resources() -> tuple[bytes, bytes]:
    root = files("repoguard")
    for part in _PROMPT_DIRECTORY:
        root = root.joinpath(part)
    unavailable = False
    result: tuple[bytes, bytes] | None = None
    try:
        result = (
            root.joinpath(_SYSTEM_RESOURCE).read_bytes(),
            root.joinpath(_SCHEMA_RESOURCE).read_bytes(),
        )
    except (FileNotFoundError, OSError):
        unavailable = True
    if unavailable or result is None:
        _raise_repair(RepairErrorCode.INVALID_WORKFLOW, RepairStage.PROMPT, None, None)
    return result


def _finding_mapping(value: _RepairPromptFinding) -> dict[str, object]:
    return {
        "rule_id": value.rule_id,
        "category": value.category,
        "severity": value.severity,
        "title": value.title,
        "remediation": value.remediation,
        "reference": {
            "path": value.path,
            "side": "new",
            "start_line": value.start_line,
            "end_line": value.end_line,
        },
    }


def _hit_mapping(value: _RepairPromptHit) -> dict[str, object]:
    return {
        "path": value.path,
        "oid": value.oid,
        "start_line": value.start_line,
        "end_line": value.end_line,
        "content": value.content,
        "definitions": list(value.definitions),
        "references": list(value.references),
    }


def _valid_prompt_finding(value: _RepairPromptFinding) -> bool:
    return (
        _valid_text(value.rule_id, minimum=1, maximum=128)
        and _valid_text(value.category, minimum=1, maximum=64)
        and _valid_text(value.severity, minimum=1, maximum=64)
        and _valid_text(value.title, minimum=1, maximum=120)
        and _valid_text(value.remediation, minimum=1, maximum=1_000)
        and _valid_repository_path(value.path)
        and type(value.start_line) is int
        and type(value.end_line) is int
        and 1 <= value.start_line <= value.end_line
    )


def _valid_prompt_hit(value: _RepairPromptHit) -> bool:
    return (
        _valid_repository_path(value.path)
        and _valid_oid(value.oid)
        and type(value.start_line) is int
        and type(value.end_line) is int
        and 1 <= value.start_line <= value.end_line
        and _valid_text(value.content, minimum=1, maximum=1_048_576, allow_controls=True)
        and type(value.definitions) is tuple
        and type(value.references) is tuple
        and all(_valid_text(item, minimum=1, maximum=512) for item in value.definitions)
        and all(_valid_text(item, minimum=1, maximum=512) for item in value.references)
    )


def _valid_repository_path(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        _validate_repository_path(value)
    except (TypeError, ValueError):
        return False
    return True


def _valid_oid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_text(
    value: object,
    *,
    minimum: int,
    maximum: int,
    allow_controls: bool = False,
) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if not minimum <= len(encoded) <= maximum:
        return False
    return allow_controls or not any(
        unicodedata.category(character).startswith("C") for character in value
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("response object keys are invalid")
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("response constants are invalid")


def _raise_repair(
    code: RepairErrorCode,
    stage: RepairStage,
    state: RepairState | None,
    session_id: str | None,
) -> NoReturn:
    error = RepairError(code, stage, state, session_id)
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    raise error from None
