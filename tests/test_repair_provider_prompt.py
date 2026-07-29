"""Focused tests for repair prompt isolation and provider execution."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest

import repoguard._repair_prompt as prompt_module
from repoguard._repair_prompt import (
    _invoke_repair_provider,
    _parse_repair_response,
    _render_repair_prompt,
    _repair_prompt_identity,
    _RepairPromptFile,
    _RepairPromptFinding,
    _RepairPromptHit,
    _validate_provider_capability,
)
from repoguard.providers import (
    LLMRequest,
    LLMResponse,
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
    RepairProviderKind,
)

_HEAD = "1" * 40
_PATCH = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "gpt-fixed",
    )


def _finding() -> _RepairPromptFinding:
    return _RepairPromptFinding(
        "merge_conflict_marker",
        "correctness",
        "high",
        "Resolve conflict marker",
        "Keep the intended branch and remove the marker",
        "src/app.py",
        1,
        3,
    )


def _files() -> tuple[_RepairPromptFile, ...]:
    return (
        _RepairPromptFile("src/app.py", True, "<<<<<<< HEAD\nold\n=======\nnew\n>>>>>>> branch\n"),
        _RepairPromptFile("src/new.py", False, None),
    )


def _hit() -> _RepairPromptHit:
    return _RepairPromptHit(
        "src/helper.py",
        "2" * 40,
        5,
        7,
        "def helper():\n    return '[REDACTED_PRIVATE_KEY_MATERIAL]'\n",
        ("helper",),
        ("helper",),
    )


def _rendered() -> prompt_module._RenderedRepairPrompt:
    return _render_repair_prompt(
        object_format="sha1",
        head_oid=_HEAD,
        findings=(_finding(),),
        allowed_files=_files(),
        context_hits=(_hit(),),
        policy=_policy(),
    )


def _provider() -> OpenAIProvider:
    return object.__new__(OpenAIProvider)


def test_prompt_identity_and_payload_are_exact_bounded_and_content_only() -> None:
    rendered = _rendered()
    assert rendered.identity == _repair_prompt_identity()
    assert rendered.identity.name == "agent_repair"
    assert rendered.identity.version == 1
    assert rendered.byte_count == sum(
        len(message.content.encode("utf-8")) for message in rendered.messages
    )
    assert "additionalProperties" in rendered.messages[0].content

    payload = json.loads(rendered.messages[1].content)
    assert set(payload) == {
        "schema_version",
        "repository",
        "selected_findings",
        "allowed_files",
        "context_hits",
    }
    assert payload["repository"] == {"object_format": "sha1", "head_oid": _HEAD}
    assert payload["allowed_files"][1] == {
        "path": "src/new.py",
        "present": False,
        "content": None,
    }
    assert payload["selected_findings"][0]["reference"]["side"] == "new"
    assert payload["context_hits"][0]["content"].count("[REDACTED_") == 1
    encoded = rendered.messages[1].content
    assert "/tmp/" not in encoded
    assert "merge_base" not in encoded
    assert "old_hunks" not in encoded
    assert "PRIVATE KEY-----" not in encoded


def test_prompt_rejects_file_and_total_budget_without_truncation() -> None:
    with pytest.raises(RepairError) as captured:
        _render_repair_prompt(
            object_format="sha1",
            head_oid=_HEAD,
            findings=(_finding(),),
            allowed_files=_files(),
            context_hits=(),
            policy=replace(_policy(), max_file_bytes=4),
        )
    assert captured.value.code is RepairErrorCode.RESOURCE_LIMIT

    with pytest.raises(RepairError) as captured:
        _render_repair_prompt(
            object_format="sha1",
            head_oid=_HEAD,
            findings=(_finding(),),
            allowed_files=_files(),
            context_hits=(),
            policy=replace(_policy(), max_prompt_bytes=100),
        )
    assert captured.value.code is RepairErrorCode.RESOURCE_LIMIT


@pytest.mark.parametrize(
    "text",
    [
        f' {{"schema_version":1,"patch":{json.dumps(_PATCH)}}}',
        '{"schema_version":1,"schema_version":1,"patch":""}',
        '{"schema_version":true,"patch":""}',
        '{"schema_version":1,"patch":"","extra":0}',
        '{"schema_version":1,"patch":null}',
        '{"schema_version":1,"patch":"","number":NaN}',
    ],
)
def test_response_parser_rejects_noncanonical_or_nonexact_json(text: str) -> None:
    with pytest.raises(RepairError) as captured:
        _parse_repair_response(
            LLMResponse(text),
            attempt_count=1,
            maximum_bytes=524_288,
        )
    assert captured.value.code is RepairErrorCode.MODEL_RESPONSE_INVALID
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_response_parser_preserves_patch_and_exact_usage() -> None:
    text = json.dumps(
        {"schema_version": 1, "patch": _PATCH},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    result = _parse_repair_response(
        LLMResponse(text, TokenUsage(11, 7, 18)),
        attempt_count=2,
        maximum_bytes=len(text.encode("utf-8")),
    )
    assert result.response_text == text
    assert result.patch == _PATCH
    assert result.attempt_count == 2
    assert (result.input_tokens, result.output_tokens) == (11, 7)

    with pytest.raises(RepairError) as captured:
        _parse_repair_response(
            LLMResponse(text),
            attempt_count=1,
            maximum_bytes=len(text.encode("utf-8")) - 1,
        )
    assert captured.value.code is RepairErrorCode.MODEL_RESPONSE_INVALID


def test_exact_builtin_provider_retries_only_transient_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[LLMRequest] = []
    delays: list[float] = []
    text = json.dumps({"patch": _PATCH, "schema_version": 1}, separators=(",", ":"))

    def complete(_: OpenAIProvider, request: LLMRequest) -> LLMResponse:
        calls.append(request)
        if len(calls) < 3:
            raise ProviderError(ProviderErrorCode.RATE_LIMITED)
        return LLMResponse(text, TokenUsage(3, 4, 7))

    monkeypatch.setattr(OpenAIProvider, "complete", complete)
    monkeypatch.setattr(prompt_module, "_sleep", delays.append)
    monkeypatch.setattr(prompt_module, "_monotonic", lambda: 10.0)
    result = _invoke_repair_provider(_provider(), _rendered(), _policy())

    assert len(calls) == 3
    assert delays == [0.5, 1.0]
    assert all(request.model == "gpt-fixed" for request in calls)
    assert all(request.max_output_tokens == 16_384 for request in calls)
    assert all(request.timeout_seconds == 30.0 for request in calls)
    assert result.attempt_count == 3
    assert result.patch == _PATCH


def test_total_deadline_prevents_backoff_from_starting_another_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    delays: list[float] = []
    monotonic_values = iter((0.0, 0.0, 94.6))

    def complete(_: OpenAIProvider, __: LLMRequest) -> LLMResponse:
        nonlocal calls
        calls += 1
        raise ProviderError(ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(OpenAIProvider, "complete", complete)
    monkeypatch.setattr(prompt_module, "_sleep", delays.append)
    monkeypatch.setattr(prompt_module, "_monotonic", lambda: next(monotonic_values))
    with pytest.raises(RepairError) as captured:
        _invoke_repair_provider(_provider(), _rendered(), _policy())
    assert captured.value.code is RepairErrorCode.PROVIDER_TIMEOUT
    assert calls == 1
    assert delays == []


def test_shared_generation_deadline_includes_elapsed_retrieval_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def complete(_: OpenAIProvider, __: LLMRequest) -> LLMResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("expired shared deadline reached provider")

    monkeypatch.setattr(OpenAIProvider, "complete", complete)
    monkeypatch.setattr(prompt_module, "_monotonic", lambda: 10.0)
    with pytest.raises(RepairError) as captured:
        _invoke_repair_provider(
            _provider(),
            _rendered(),
            _policy(),
            deadline=9.0,
        )
    assert captured.value.code is RepairErrorCode.PROVIDER_TIMEOUT
    assert calls == 0


@pytest.mark.parametrize(
    ("provider_code", "repair_code"),
    [
        (ProviderErrorCode.AUTHENTICATION_FAILED, RepairErrorCode.PROVIDER_AUTHENTICATION),
        (ProviderErrorCode.REQUEST_FAILED, RepairErrorCode.PROVIDER_BAD_REQUEST),
        (ProviderErrorCode.REFUSED, RepairErrorCode.PROVIDER_PERMISSION),
        (ProviderErrorCode.INVALID_RESPONSE, RepairErrorCode.PROVIDER_INVALID_RESPONSE),
    ],
)
def test_nonretryable_provider_errors_are_detached_and_atomic(
    monkeypatch: pytest.MonkeyPatch,
    provider_code: ProviderErrorCode,
    repair_code: RepairErrorCode,
) -> None:
    call_count = 0

    def complete(_: OpenAIProvider, __: LLMRequest) -> LLMResponse:
        nonlocal call_count
        call_count += 1
        raise ProviderError(provider_code)

    monkeypatch.setattr(OpenAIProvider, "complete", complete)
    with pytest.raises(RepairError) as captured:
        _invoke_repair_provider(_provider(), _rendered(), _policy())
    assert captured.value.code is repair_code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert call_count == 1


def test_provider_capability_rejects_missing_mismatched_and_subclass_instances() -> None:
    with pytest.raises(RepairError) as captured:
        _validate_provider_capability(_policy(), None)
    assert captured.value.code is RepairErrorCode.PROVIDER_REQUIRED

    deterministic = RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)
    with pytest.raises(RepairError) as captured:
        _validate_provider_capability(deterministic, _provider())
    assert captured.value.code is RepairErrorCode.PROVIDER_MISMATCH

    class DerivedOpenAIProvider(OpenAIProvider):
        pass

    derived = cast(OpenAIProvider, object.__new__(DerivedOpenAIProvider))
    with pytest.raises(RepairError) as captured:
        _validate_provider_capability(_policy(), derived)
    assert captured.value.code is RepairErrorCode.PROVIDER_MISMATCH
