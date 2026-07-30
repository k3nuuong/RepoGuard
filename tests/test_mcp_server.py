"""Focused MCP 2.0 protocol tests for the product adapter."""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import anyio
import pytest
from mcp import Client, MCPError, StdioServerParameters, stdio_client
from mcp.client.context import ClientRequestContext
from mcp.server import MCPServer
from mcp.types import (
    CallToolResult,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitRequestParams,
    ElicitResult,
    InputRequiredResult,
    TextContent,
)

import repoguard.mcp_server as mcp_server_module
from repoguard.host_profile import (
    HostMCPWriters,
    HostProfile,
    HostRepository,
    ProductProviderKind,
    ProductReviewMode,
    ProductReviewProfile,
)
from repoguard.mcp_server import create_mcp_server, serve_mcp_stdio
from repoguard.product import (
    PRODUCT_ENVELOPE_MAX_BYTES,
    PRODUCT_RESULT_MAX_BYTES,
    ProductEnvelope,
    ProductOperation,
    product_envelope_from_json,
    product_envelope_to_dict,
    product_envelope_to_json,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

_SESSION_ID = "1" * 64
_CANDIDATE_ID = "2" * 64
_VALIDATION_SHA256 = "3" * 64
_PROPOSAL_SHA256 = "5" * 64
_LOCAL_CONFIRMATION = (
    "I approve this exact RepoGuard candidate and validation result for ref-only application."
)
_CHECK_CONFIRMATION = "I approve publishing this exact RepoGuard review as a GitHub Check Run."
_STDIO_SERVER_CODE = textwrap.dedent(
    r"""
    import json
    import os
    import time
    from pathlib import Path

    from repoguard.host_profile import (
        HostMCPWriters,
        HostProfile,
        HostRepository,
        ProductProviderKind,
        ProductReviewMode,
        ProductReviewProfile,
    )
    from repoguard.mcp_server import serve_mcp_stdio
    from repoguard.product import (
        ProductEnvelope,
        ProductOperation,
        product_envelope_to_json,
    )
    from repoguard.retrieval import EmbeddingDevice
    from repoguard.review import FindingSeverity

    CANDIDATE_ID = "2" * 64
    VALIDATION_SHA256 = "3" * 64

    class Product:
        def review_run(
            self,
            *,
            repository,
            base_ref,
            head_ref,
            review_profile,
            github_pr=None,
        ):
            result = {
                "repository": repository,
                "base_ref": base_ref,
                "head_ref": head_ref,
                "review_profile": review_profile,
                "github_pr": github_pr,
            }
            target_size = os.environ.get("M6_MCP_TEST_REVIEW_RESULT_BYTES")
            if target_size is None:
                return ProductEnvelope(
                    schema_version=1,
                    operation=ProductOperation.REVIEW_RUN,
                    ok=True,
                    result=result,
                    error=None,
                )
            result["payload"] = ""
            payload_size = int(target_size) - len(
                json.dumps(
                    result,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            )
            result["payload"] = "x" * payload_size
            return ProductEnvelope(
                schema_version=1,
                operation=ProductOperation.REVIEW_RUN,
                ok=True,
                result=result,
                error=None,
            )

        def repair_status(self, *, repository, session_id):
            time.sleep(float(os.environ.get("M6_MCP_TEST_STATUS_DELAY", "0")))
            return ProductEnvelope(
                schema_version=1,
                operation=ProductOperation.REPAIR_STATUS,
                ok=True,
                result={
                    "snapshot": {
                        "schema_version": 1,
                        "session_id": session_id,
                        "state": "validated",
                        "candidate": {"candidate_id": CANDIDATE_ID},
                        "validation": {
                            "candidate_id": CANDIDATE_ID,
                            "validation_sha256": VALIDATION_SHA256,
                            "success": True,
                        },
                        "approval": None,
                        "application": None,
                        "decision": None,
                        "failure": None,
                        "cleanup_pending": False,
                    }
                },
                error=None,
            )

        def repair_approve_and_apply_local(
            self,
            *,
            repository,
            session_id,
            candidate_id,
            validation_sha256,
            confirmation,
        ):
            Path(os.environ["M6_MCP_TEST_MARKER"]).write_text(
                "applied",
                encoding="utf-8",
            )
            return ProductEnvelope(
                schema_version=1,
                operation=ProductOperation.REPAIR_APPLY_LOCAL,
                ok=True,
                result={
                    "repository": repository,
                    "session_id": session_id,
                    "candidate_id": candidate_id,
                    "validation_sha256": validation_sha256,
                    "confirmation": confirmation,
                },
                error=None,
            )

    profile = HostProfile(
        schema_version=1,
        repositories=(
            HostRepository(
                alias="repo",
                path=Path("/host/repo"),
                github_repository_id=123,
                github_full_name="owner/repo",
            ),
        ),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/docker"),
        rootless_socket=Path("/run/user/1000/docker.sock"),
        product_state_root=Path("/state/product"),
        repair_state_root=Path("/state/repair"),
        runner_labels=(),
        m4_caches=(),
        review_profiles=(
            ProductReviewProfile(
                name="deterministic",
                mode=ProductReviewMode.DETERMINISTIC,
                provider=ProductProviderKind.NONE,
                model=None,
                cache=None,
                device=EmbeddingDevice.CPU,
                fail_on=FindingSeverity.HIGH,
            ),
        ),
        repair_profiles=(),
        github_actions=None,
        mcp=HostMCPWriters(False, False),
    )
    serve_mcp_stdio(profile, orchestrator=Product())
    """
)


def _profile(*, publish_check: bool = False, publish_repair: bool = False) -> HostProfile:
    return HostProfile(
        schema_version=1,
        repositories=(
            HostRepository(
                alias="repo",
                path=Path("/host/repo"),
                github_repository_id=123,
                github_full_name="owner/repo",
            ),
        ),
        git_executable=Path("/usr/bin/git"),
        docker_executable=Path("/usr/bin/docker"),
        rootless_socket=Path("/run/user/1000/docker.sock"),
        product_state_root=Path("/state/product"),
        repair_state_root=Path("/state/repair"),
        runner_labels=(),
        m4_caches=(),
        review_profiles=(
            ProductReviewProfile(
                name="deterministic",
                mode=ProductReviewMode.DETERMINISTIC,
                provider=ProductProviderKind.NONE,
                model=None,
                cache=None,
                device=EmbeddingDevice.CPU,
                fail_on=FindingSeverity.HIGH,
            ),
        ),
        repair_profiles=(),
        github_actions=None,
        mcp=HostMCPWriters(
            publish_check=publish_check,
            publish_repair=publish_repair,
        ),
    )


def _success(operation: ProductOperation, **result: object) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=True,
        result=result,
        error=None,
    )


class _FakeProduct:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.review_envelope: ProductEnvelope | None = None
        self.review_exception: Exception | None = None
        self.repair_state = "validated"
        self.repair_candidate_id = _CANDIDATE_ID
        self.repair_validation_sha256 = _VALIDATION_SHA256
        self.status_read_count = 0

    def review_run(
        self,
        *,
        repository: str,
        base_ref: str,
        head_ref: str,
        review_profile: str,
        github_pr: int | None = None,
    ) -> ProductEnvelope:
        arguments: dict[str, object] = {
            "repository": repository,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "review_profile": review_profile,
            "github_pr": github_pr,
        }
        self.calls.append(("review_run", arguments))
        if self.review_exception is not None:
            raise self.review_exception
        if self.review_envelope is not None:
            return self.review_envelope
        return _success(ProductOperation.REVIEW_RUN, arguments=arguments)

    def repair_prepare(
        self,
        *,
        repository: str,
        base_ref: str,
        head_ref: str,
        repair_profile: str,
        target_ids: tuple[str, ...],
        allowed_paths: tuple[str, ...],
        github_pr: int | None = None,
    ) -> ProductEnvelope:
        arguments: dict[str, object] = {
            "repository": repository,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "repair_profile": repair_profile,
            "target_ids": list(target_ids),
            "allowed_paths": list(allowed_paths),
            "github_pr": github_pr,
        }
        self.calls.append(("repair_prepare", arguments))
        return _success(ProductOperation.REPAIR_PREPARE, arguments=arguments)

    def repair_status(self, *, repository: str, session_id: str) -> ProductEnvelope:
        self.calls.append(("repair_status", {"repository": repository, "session_id": session_id}))
        self.status_read_count += 1
        return _success(
            ProductOperation.REPAIR_STATUS,
            snapshot={
                "schema_version": 1,
                "session_id": session_id,
                "state": self.repair_state,
                "candidate": {"candidate_id": self.repair_candidate_id},
                "validation": {
                    "candidate_id": self.repair_candidate_id,
                    "validation_sha256": self.repair_validation_sha256,
                    "success": True,
                },
                "approval": None,
                "application": None,
                "decision": None,
                "failure": None,
                "cleanup_pending": False,
            },
        )

    def repair_preview(self, *, repository: str, session_id: str) -> ProductEnvelope:
        self.calls.append(("repair_preview", {"repository": repository, "session_id": session_id}))
        return _success(ProductOperation.REPAIR_PREVIEW, preview={"session_id": session_id})

    def repair_approve_and_apply_local(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        validation_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        self.calls.append(
            (
                "repair_approve_and_apply_local",
                {
                    "repository": repository,
                    "session_id": session_id,
                    "candidate_id": candidate_id,
                    "validation_sha256": validation_sha256,
                    "confirmation": confirmation,
                },
            )
        )
        return _success(ProductOperation.REPAIR_APPLY_LOCAL, state="applied")

    def repair_reject(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        reason: str,
    ) -> ProductEnvelope:
        self.calls.append(
            (
                "repair_reject",
                {
                    "repository": repository,
                    "session_id": session_id,
                    "candidate_id": candidate_id,
                    "reason": reason,
                },
            )
        )
        return _success(ProductOperation.REPAIR_REJECT, state="rejected")

    def repair_cancel(
        self,
        *,
        repository: str,
        session_id: str,
        reason: str = "",
    ) -> ProductEnvelope:
        self.calls.append(
            (
                "repair_cancel",
                {"repository": repository, "session_id": session_id, "reason": reason},
            )
        )
        return _success(ProductOperation.REPAIR_CANCEL, state="cancelled")

    def github_publish_check(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        self.calls.append(
            (
                "github_publish_check",
                {
                    "repository": repository,
                    "proposal_sha256": proposal_sha256,
                    "confirmation": confirmation,
                },
            )
        )
        return _success(ProductOperation.GITHUB_PUBLISH_CHECK, state="published")

    def github_publish_repair(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope:
        self.calls.append(
            (
                "github_publish_repair",
                {
                    "repository": repository,
                    "proposal_sha256": proposal_sha256,
                    "confirmation": confirmation,
                },
            )
        )
        return _success(ProductOperation.GITHUB_PUBLISH_REPAIR, state="published")


def _tool_arguments() -> dict[str, str]:
    return {
        "repository": "repo",
        "session_id": _SESSION_ID,
        "candidate_id": _CANDIDATE_ID,
        "validation_sha256": _VALIDATION_SHA256,
    }


def _stdio_parameters(
    marker: Path,
    *,
    status_delay: float = 0.0,
    review_result_bytes: int | None = None,
) -> StdioServerParameters:
    environment = {
        "M6_MCP_TEST_MARKER": str(marker),
        "M6_MCP_TEST_STATUS_DELAY": str(status_delay),
    }
    if review_result_bytes is not None:
        environment["M6_MCP_TEST_REVIEW_RESULT_BYTES"] = str(review_result_bytes)
    return StdioServerParameters(
        command=sys.executable,
        args=["-c", _STDIO_SERVER_CODE],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
    )


def _review_envelope_with_result_size(size: int) -> ProductEnvelope:
    empty_result = {"payload": ""}
    empty_size = len(
        json.dumps(
            empty_result,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    if size < empty_size:
        raise ValueError("requested test result is too small")
    envelope = _success(
        ProductOperation.REVIEW_RUN,
        payload="x" * (size - empty_size),
    )
    if size <= PRODUCT_RESULT_MAX_BYTES:
        rendered = product_envelope_to_json(envelope)
        assert len(rendered.encode("utf-8")) <= PRODUCT_ENVELOPE_MAX_BYTES
    else:
        with pytest.raises(ValueError, match="result limit exceeded"):
            product_envelope_to_json(envelope)
    return envelope


def _assert_safe_completion_failure(result: CallToolResult, *, code: str) -> None:
    assert result.is_error
    assert isinstance(result.content[0], TextContent)
    rendered = result.content[0].text
    assert len(rendered.encode("utf-8")) < PRODUCT_ENVELOPE_MAX_BYTES
    assert "SECRET" not in rendered
    assert result.structured_content == {
        "schema_version": 1,
        "operation": "review.run",
        "ok": False,
        "result": None,
        "error": {
            "domain": "mcp",
            "code": code,
            "message": "MCP operation failed",
            "retryable": False,
            "stage": "internal",
            "state": None,
            "session_id": None,
            "proposal_sha256": None,
            "attempt_count": 0,
        },
    }
    assert (
        product_envelope_to_dict(product_envelope_from_json(rendered.encode("utf-8")))
        == result.structured_content
    )


def test_fixed_tool_list_and_canonical_structured_result(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def scenario() -> None:
        tools = await server.list_tools()
        assert [tool.name for tool in tools] == [
            "review_run",
            "repair_prepare",
            "repair_status",
            "repair_preview",
            "repair_apply_local",
            "repair_reject",
            "repair_cancel",
        ]
        apply_tool = next(tool for tool in tools if tool.name == "repair_apply_local")
        properties = cast(dict[str, object], apply_tool.input_schema["properties"])
        assert set(properties) == {
            "repository",
            "session_id",
            "candidate_id",
            "validation_sha256",
        }
        assert set(cast(list[str], apply_tool.input_schema["required"])) == set(properties)
        assert "approval_sha256" not in apply_tool.input_schema
        result = await server.call_tool(
            "review_run",
            {
                "repository": "repo",
                "base_ref": "main",
                "head_ref": "feature",
                "review_profile": "deterministic",
            },
        )
        assert isinstance(result, CallToolResult)
        assert not result.is_error
        expected = _success(
            ProductOperation.REVIEW_RUN,
            arguments={
                "repository": "repo",
                "base_ref": "main",
                "head_ref": "feature",
                "review_profile": "deterministic",
                "github_pr": None,
            },
        )
        assert result.structured_content == product_envelope_to_dict(expected)
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == product_envelope_to_json(expected)

    anyio.run(scenario)


def test_mcp_completion_accepts_exact_four_mib_boundary(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    product.review_envelope = _review_envelope_with_result_size(PRODUCT_RESULT_MAX_BYTES)
    expected_wire_size = len(product_envelope_to_json(product.review_envelope).encode("utf-8"))
    server = create_mcp_server(_profile(), orchestrator=product)

    async def scenario() -> None:
        result = await server.call_tool(
            "review_run",
            {
                "repository": "repo",
                "base_ref": "main",
                "head_ref": "feature",
                "review_profile": "deterministic",
            },
        )
        assert isinstance(result, CallToolResult)
        assert not result.is_error
        assert isinstance(result.content[0], TextContent)
        assert len(result.content[0].text.encode("utf-8")) == expected_wire_size
        assert expected_wire_size > PRODUCT_RESULT_MAX_BYTES

    anyio.run(scenario)


def test_mcp_completion_replaces_over_limit_result_with_safe_envelope(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    product.review_envelope = _review_envelope_with_result_size(PRODUCT_RESULT_MAX_BYTES + 1)
    server = create_mcp_server(_profile(), orchestrator=product)

    async def scenario() -> None:
        result = await server.call_tool(
            "review_run",
            {
                "repository": "repo",
                "base_ref": "main",
                "head_ref": "feature",
                "review_profile": "deterministic",
            },
        )
        assert isinstance(result, CallToolResult)
        _assert_safe_completion_failure(result, code="resource_limit")

    anyio.run(scenario)


def test_mcp_completion_and_tool_errors_never_leak_internal_text(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)

    async def call(product: _FakeProduct) -> CallToolResult:
        server = create_mcp_server(_profile(), orchestrator=product)
        async with Client(server) as client:
            return await client.call_tool(
                "review_run",
                {
                    "repository": "repo",
                    "base_ref": "main",
                    "head_ref": "feature",
                    "review_profile": "deterministic",
                },
            )

    async def scenario() -> None:
        payload: dict[str, object] = {}
        invalid = _FakeProduct()
        invalid.review_envelope = _success(ProductOperation.REVIEW_RUN, payload=payload)
        payload["invalid"] = float("nan")
        _assert_safe_completion_failure(await call(invalid), code="internal")

        raising = _FakeProduct()
        raising.review_exception = RuntimeError("SECRET-TOOL-ERROR")
        _assert_safe_completion_failure(await call(raising), code="internal")

        def tool_error(
            _operation: ProductOperation,
            _call: object,
        ) -> CallToolResult:
            raise RuntimeError("SECRET-MIDDLEWARE-TOOL-ERROR")

        monkeypatch.setattr(mcp_server_module, "_complete_call", tool_error)
        _assert_safe_completion_failure(await call(_FakeProduct()), code="internal")

    anyio.run(scenario)


@pytest.mark.parametrize(
    ("publish_check", "publish_repair", "token", "expected"),
    [
        (True, True, None, set()),
        (True, True, "   ", set()),
        (False, False, "token", set()),
        (True, False, "token", {"github_publish_check"}),
        (False, True, "token", {"github_publish_repair"}),
    ],
)
def test_github_writers_require_profile_switch_and_token(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
    publish_check: bool,
    publish_repair: bool,
    token: str | None,
    expected: set[str],
) -> None:
    assert socket_enabled is None
    if token is None:
        monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    else:
        monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", token)
    server = create_mcp_server(
        _profile(publish_check=publish_check, publish_repair=publish_repair),
        orchestrator=_FakeProduct(),
    )

    async def scenario() -> None:
        names = {tool.name for tool in await server.list_tools()}
        assert names & {"github_publish_check", "github_publish_repair"} == expected

    anyio.run(scenario)


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "repository": "repo",
            "base_ref": "main",
            "head_ref": "feature",
            "review_profile": "deterministic",
            "unknown": "rejected",
        },
        {
            "repository": "r" * 65,
            "base_ref": "main",
            "head_ref": "feature",
            "review_profile": "deterministic",
        },
        {
            "repository": "repo",
            "base_ref": "main",
            "review_profile": "deterministic",
        },
    ],
)
def test_invalid_tool_arguments_return_canonical_envelope_without_calling_product(
    arguments: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("review_run", arguments)
        assert result.is_error
        assert isinstance(result.content[0], TextContent)
        structured = cast(dict[str, object], result.structured_content)
        error = cast(dict[str, object], structured["error"])
        assert error["code"] == "invalid_request"
        assert error["stage"] == "input"
        assert (
            product_envelope_to_dict(
                product_envelope_from_json(result.content[0].text.encode("utf-8"))
            )
            == structured
        )

    anyio.run(scenario)
    assert product.calls == []


@pytest.mark.parametrize(
    ("target_ids", "allowed_paths"),
    [
        (["a" * 64, "0" * 64], ["src/example.py"]),
        (["a" * 64], ["/src/example.py"]),
        (["a" * 64], ["src/../example.py"]),
        (["a" * 64], [".git/config"]),
        (["a" * 64], ["a" * 1_025]),
        (["a" * 64], ["tests/example.py", "src/example.py"]),
    ],
)
def test_repair_prepare_rejects_noncanonical_targets_and_paths_before_product_call(
    target_ids: list[str],
    allowed_paths: list[str],
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)
    arguments = {
        "repository": "repo",
        "base_ref": "main",
        "head_ref": "feature",
        "repair_profile": "safe",
        "target_ids": target_ids,
        "allowed_paths": allowed_paths,
    }

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("repair_prepare", arguments)
        assert result.is_error
        error = cast(dict[str, object], result.structured_content)["error"]
        assert cast(dict[str, object], error)["code"] == "invalid_request"

    anyio.run(scenario)
    assert product.calls == []


@pytest.mark.parametrize("action", ["decline", "cancel"])
def test_local_apply_refusal_and_cancel_are_zero_write(
    action: Literal["decline", "cancel"],
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        return ElicitResult(action=action)

    async def scenario() -> None:
        async with Client(server, elicitation_callback=answer) as client:
            result = await client.call_tool("repair_apply_local", _tool_arguments())
        assert result.is_error
        assert cast(dict[str, object], result.structured_content)["error"] == {
            "domain": "mcp",
            "code": "approval_required",
            "message": "MCP operation failed",
            "retryable": False,
            "stage": "approval",
            "state": None,
            "session_id": _SESSION_ID,
            "proposal_sha256": None,
            "attempt_count": 0,
        }

    anyio.run(scenario)
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


def test_local_apply_requires_exact_multiround_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def unused_answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("manual input-required flow must not call the callback")

    async def scenario() -> None:
        async with Client(server, elicitation_callback=unused_answer) as client:
            first = await client.session.call_tool(
                "repair_apply_local",
                _tool_arguments(),
                allow_input_required=True,
            )
            assert isinstance(first, InputRequiredResult)
            assert first.input_requests is not None
            request = first.input_requests["confirmation"]
            assert isinstance(request, ElicitRequest)
            assert isinstance(request.params, ElicitRequestFormParams)
            assert _CANDIDATE_ID in request.params.message
            assert _VALIDATION_SHA256 in request.params.message
            assert first.request_state is not None
            mismatch = await client.session.call_tool(
                "repair_apply_local",
                _tool_arguments(),
                input_responses={
                    "confirmation": ElicitResult(
                        action="accept",
                        content={"confirmation": "not the displayed confirmation"},
                    )
                },
                request_state=first.request_state,
                allow_input_required=True,
            )
        assert isinstance(mismatch, CallToolResult)
        assert mismatch.is_error
        error = cast(dict[str, object], mismatch.structured_content)["error"]
        assert cast(dict[str, object], error)["code"] == "invalid_confirmation"

    anyio.run(scenario)
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


def test_local_apply_acceptance_writes_once(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context
        assert isinstance(params, ElicitRequestFormParams)
        return ElicitResult(
            action="accept",
            content={"confirmation": _LOCAL_CONFIRMATION},
        )

    async def scenario() -> None:
        async with Client(server, elicitation_callback=answer) as client:
            result = await client.call_tool("repair_apply_local", _tool_arguments())
        assert not result.is_error

    anyio.run(scenario)
    apply_calls = [
        arguments for name, arguments in product.calls if name == "repair_approve_and_apply_local"
    ]
    assert apply_calls == [
        {
            "repository": "repo",
            "session_id": _SESSION_ID,
            "candidate_id": _CANDIDATE_ID,
            "validation_sha256": _VALIDATION_SHA256,
            "confirmation": _LOCAL_CONFIRMATION,
        }
    ]


def test_unsupported_elicitation_is_zero_write(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("repair_apply_local", _tool_arguments())
        assert result.is_error
        error = cast(dict[str, object], result.structured_content)["error"]
        assert cast(dict[str, object], error)["code"] == "elicitation_unavailable"

    anyio.run(scenario)
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


@pytest.mark.parametrize(
    ("state", "candidate_id", "validation_sha256"),
    [
        ("approved", _CANDIDATE_ID, _VALIDATION_SHA256),
        ("validated", "6" * 64, _VALIDATION_SHA256),
        ("validated", _CANDIDATE_ID, "7" * 64),
    ],
)
def test_local_apply_requires_exact_validated_cas_before_elicitation(
    state: str,
    candidate_id: str,
    validation_sha256: str,
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    product.repair_state = state
    product.repair_candidate_id = candidate_id
    product.repair_validation_sha256 = validation_sha256
    server = create_mcp_server(_profile(), orchestrator=product)

    async def answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("CAS mismatch must fail before elicitation")

    async def scenario() -> None:
        async with Client(server, elicitation_callback=answer) as client:
            result = await client.call_tool("repair_apply_local", _tool_arguments())
        assert result.is_error
        error = cast(dict[str, object], result.structured_content)["error"]
        assert cast(dict[str, object], error)["code"] == "cas_conflict"

    anyio.run(scenario)
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


def test_local_apply_concurrent_drift_between_rounds_is_zero_write(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def unused_answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("manual input-required flow must not call the callback")

    async def scenario() -> None:
        async with Client(server, elicitation_callback=unused_answer) as client:
            first = await client.session.call_tool(
                "repair_apply_local",
                _tool_arguments(),
                allow_input_required=True,
            )
            assert isinstance(first, InputRequiredResult)
            product.repair_state = "approved"
            assert first.request_state is not None
            drifted = await client.session.call_tool(
                "repair_apply_local",
                _tool_arguments(),
                input_responses={
                    "confirmation": ElicitResult(
                        action="accept",
                        content={"confirmation": _LOCAL_CONFIRMATION},
                    )
                },
                request_state=first.request_state,
                allow_input_required=True,
            )
        assert isinstance(drifted, CallToolResult)
        assert drifted.is_error
        error = cast(dict[str, object], drifted.structured_content)["error"]
        assert cast(dict[str, object], error)["code"] == "cas_conflict"

    anyio.run(scenario)
    assert product.status_read_count == 2
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


def test_local_apply_rejects_forged_request_state_without_write(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    product = _FakeProduct()
    server = create_mcp_server(_profile(), orchestrator=product)

    async def unused_answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("manual input-required flow must not call the callback")

    async def scenario() -> None:
        async with Client(server, elicitation_callback=unused_answer) as client:
            first = await client.session.call_tool(
                "repair_apply_local",
                _tool_arguments(),
                allow_input_required=True,
            )
            assert isinstance(first, InputRequiredResult)
            assert first.request_state is not None
            forged_state = first.request_state[:-1] + (
                "A" if first.request_state[-1] != "A" else "B"
            )
            with pytest.raises(MCPError, match="Invalid or expired requestState"):
                await client.session.call_tool(
                    "repair_apply_local",
                    _tool_arguments(),
                    input_responses={
                        "confirmation": ElicitResult(
                            action="accept",
                            content={"confirmation": _LOCAL_CONFIRMATION},
                        )
                    },
                    request_state=forged_state,
                    allow_input_required=True,
                )

    anyio.run(scenario)
    assert product.status_read_count == 1
    assert not any(name == "repair_approve_and_apply_local" for name, _arguments in product.calls)


def test_github_writer_confirmation_and_disconnect_are_zero_write(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "token")
    profile = replace(_profile(), mcp=HostMCPWriters(True, False))
    product = _FakeProduct()
    server = create_mcp_server(profile, orchestrator=product)

    async def unused_answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("manual input-required flow must not call the callback")

    async def scenario() -> None:
        async with Client(server, elicitation_callback=unused_answer) as client:
            first = await client.session.call_tool(
                "github_publish_check",
                {"repository": "repo", "proposal_sha256": _PROPOSAL_SHA256},
                allow_input_required=True,
            )
            assert isinstance(first, InputRequiredResult)
            assert first.input_requests is not None
            request = first.input_requests["confirmation"]
            assert isinstance(request, ElicitRequest)
            assert isinstance(request.params, ElicitRequestFormParams)
            assert _PROPOSAL_SHA256 in request.params.message
            assert _CHECK_CONFIRMATION in request.params.message

    anyio.run(scenario)
    assert not any(name == "github_publish_check" for name, _arguments in product.calls)


def test_github_writer_passes_only_the_exact_elicited_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "token")
    product = _FakeProduct()
    server = create_mcp_server(
        _profile(publish_check=True),
        orchestrator=product,
    )

    async def answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context
        assert isinstance(params, ElicitRequestFormParams)
        return ElicitResult(
            action="accept",
            content={"confirmation": _CHECK_CONFIRMATION},
        )

    async def scenario() -> None:
        async with Client(server, elicitation_callback=answer) as client:
            result = await client.call_tool(
                "github_publish_check",
                {"repository": "repo", "proposal_sha256": _PROPOSAL_SHA256},
            )
        assert not result.is_error

    anyio.run(scenario)
    publish_calls = [
        arguments for name, arguments in product.calls if name == "github_publish_check"
    ]
    assert publish_calls == [
        {
            "repository": "repo",
            "proposal_sha256": _PROPOSAL_SHA256,
            "confirmation": _CHECK_CONFIRMATION,
        }
    ]


def test_real_stdio_initialize_list_concurrent_calls_and_restart(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    marker = tmp_path / "unexpected-write"

    async def one_connection(index: int) -> None:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with Client(
                stdio_client(_stdio_parameters(marker), errlog=stderr),
                mode="legacy",
                read_timeout_seconds=5,
            ) as client:
                assert client.protocol_version == "2025-11-25"
                assert client.server_info is not None
                assert client.server_info.name == "repoguard_mcp"
                listing = await client.list_tools()
                assert [tool.name for tool in listing.tools] == [
                    "review_run",
                    "repair_prepare",
                    "repair_status",
                    "repair_preview",
                    "repair_apply_local",
                    "repair_reject",
                    "repair_cancel",
                ]
                results: dict[str, CallToolResult] = {}

                async def call_review(name: str) -> None:
                    results[name] = await client.call_tool(
                        "review_run",
                        {
                            "repository": "repo",
                            "base_ref": f"base-{index}-{name}",
                            "head_ref": f"head-{index}-{name}",
                            "review_profile": "deterministic",
                        },
                    )

                async with anyio.create_task_group() as task_group:
                    task_group.start_soon(call_review, "first")
                    task_group.start_soon(call_review, "second")
                assert set(results) == {"first", "second"}
                assert all(not result.is_error for result in results.values())
            stderr.seek(0)
            assert stderr.read() == ""

    async def scenario() -> None:
        await one_connection(1)
        await one_connection(2)

    anyio.run(scenario)
    assert not marker.exists()


def test_real_stdio_over_limit_completion_is_one_safe_protocol_result(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    marker = tmp_path / "unexpected-write"

    async def scenario() -> None:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with Client(
                stdio_client(
                    _stdio_parameters(
                        marker,
                        review_result_bytes=PRODUCT_RESULT_MAX_BYTES + 1,
                    ),
                    errlog=stderr,
                ),
                mode="legacy",
                read_timeout_seconds=5,
            ) as client:
                result = await client.call_tool(
                    "review_run",
                    {
                        "repository": "repo",
                        "base_ref": "main",
                        "head_ref": "feature",
                        "review_profile": "deterministic",
                    },
                )
                _assert_safe_completion_failure(result, code="resource_limit")
            stderr.seek(0)
            assert stderr.read() == ""

    anyio.run(scenario)
    assert not marker.exists()


def test_real_stdio_input_required_eof_is_zero_write_and_next_server_recovers(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    marker = tmp_path / "apply-marker"

    async def unused_answer(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        raise AssertionError("manual input-required flow must not dispatch elicitation")

    async def accept(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context
        assert isinstance(params, ElicitRequestFormParams)
        return ElicitResult(
            action="accept",
            content={"confirmation": _LOCAL_CONFIRMATION},
        )

    async def scenario() -> None:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with Client(
                stdio_client(_stdio_parameters(marker), errlog=stderr),
                mode="auto",
                elicitation_callback=unused_answer,
                read_timeout_seconds=5,
            ) as client:
                assert client.protocol_version == "2026-07-28"
                pending = await client.session.call_tool(
                    "repair_apply_local",
                    _tool_arguments(),
                    allow_input_required=True,
                )
                assert isinstance(pending, InputRequiredResult)
                assert pending.request_state is not None
            stderr.seek(0)
            assert stderr.read() == ""
        assert not marker.exists()

        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with Client(
                stdio_client(_stdio_parameters(marker), errlog=stderr),
                mode="auto",
                elicitation_callback=accept,
                read_timeout_seconds=5,
            ) as client:
                result = await client.call_tool("repair_apply_local", _tool_arguments())
                assert not result.is_error
            stderr.seek(0)
            assert stderr.read() == ""

    anyio.run(scenario)
    assert marker.read_text(encoding="utf-8") == "applied"


def test_real_stdio_cancelled_pending_apply_is_zero_write_and_server_recovers(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    marker = tmp_path / "apply-marker"

    async def accept(
        context: ClientRequestContext,
        params: ElicitRequestParams,
    ) -> ElicitResult:
        del context, params
        return ElicitResult(
            action="accept",
            content={"confirmation": _LOCAL_CONFIRMATION},
        )

    async def scenario() -> None:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
            async with Client(
                stdio_client(
                    _stdio_parameters(marker, status_delay=0.5),
                    errlog=stderr,
                ),
                mode="auto",
                elicitation_callback=accept,
                read_timeout_seconds=5,
            ) as client:
                with anyio.move_on_after(0.05) as cancel_scope:
                    await client.call_tool("repair_apply_local", _tool_arguments())
                assert cancel_scope.cancel_called
                listing = await client.list_tools(cache_mode="bypass")
                assert any(tool.name == "repair_status" for tool in listing.tools)
            stderr.seek(0)
            assert stderr.read() == ""

    anyio.run(scenario)
    assert not marker.exists()


def test_public_server_runner_selects_stdio_only(monkeypatch: pytest.MonkeyPatch) -> None:
    transports: list[str] = []

    def run(server: MCPServer[object], transport: str = "stdio", **_kwargs: object) -> None:
        assert server.name == "repoguard_mcp"
        transports.append(transport)

    monkeypatch.setattr(MCPServer, "run", run)
    serve_mcp_stdio(_profile(), orchestrator=_FakeProduct())

    assert transports == ["stdio"]
