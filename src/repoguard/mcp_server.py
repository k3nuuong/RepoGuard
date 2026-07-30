"""Bounded stdio MCP adapter for the public RepoGuard product facade."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Protocol, cast

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.types import (
    LATEST_PROTOCOL_VERSION,
    CallToolResult,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
    TextContent,
    ToolAnnotations,
)
from pydantic import Field
from pydantic_core import ValidationError

from repoguard import __version__
from repoguard.host_profile import HostProfile
from repoguard.product import (
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductInterface,
    ProductOperation,
    ProductOrchestrator,
    ProductStage,
    product_envelope_to_dict,
    product_envelope_to_json,
    product_error_message,
)
from repoguard.repair import REPAIR_APPROVAL_CONFIRMATION

__all__ = ["create_mcp_server", "serve_mcp_stdio"]

_GITHUB_CHECK_CONFIRMATION = (
    "I approve publishing this exact RepoGuard review as a GitHub Check Run."
)
_GITHUB_REPAIR_CONFIRMATION = (
    "I approve publishing this exact RepoGuard repair commit to its dedicated branch and "
    "draft pull request."
)
_CONFIRMATION_KEY = "confirmation"
_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOOL_OPERATIONS = {
    "review_run": ProductOperation.REVIEW_RUN,
    "repair_prepare": ProductOperation.REPAIR_PREPARE,
    "repair_status": ProductOperation.REPAIR_STATUS,
    "repair_preview": ProductOperation.REPAIR_PREVIEW,
    "repair_apply_local": ProductOperation.REPAIR_APPLY_LOCAL,
    "repair_reject": ProductOperation.REPAIR_REJECT,
    "repair_cancel": ProductOperation.REPAIR_CANCEL,
    "github_publish_check": ProductOperation.GITHUB_PUBLISH_CHECK,
    "github_publish_repair": ProductOperation.GITHUB_PUBLISH_REPAIR,
}
_TOOL_ARGUMENTS = {
    "review_run": frozenset({"repository", "base_ref", "head_ref", "review_profile", "github_pr"}),
    "repair_prepare": frozenset(
        {
            "repository",
            "base_ref",
            "head_ref",
            "repair_profile",
            "target_ids",
            "allowed_paths",
            "github_pr",
        }
    ),
    "repair_status": frozenset({"repository", "session_id"}),
    "repair_preview": frozenset({"repository", "session_id"}),
    "repair_apply_local": frozenset(
        {"repository", "session_id", "candidate_id", "validation_sha256"}
    ),
    "repair_reject": frozenset({"repository", "session_id", "candidate_id", "reason"}),
    "repair_cancel": frozenset({"repository", "session_id", "reason"}),
    "github_publish_check": frozenset({"repository", "proposal_sha256"}),
    "github_publish_repair": frozenset({"repository", "proposal_sha256"}),
}
_TOOL_REQUIRED_ARGUMENTS = {
    "review_run": frozenset({"repository", "base_ref", "head_ref", "review_profile"}),
    "repair_prepare": frozenset(
        {
            "repository",
            "base_ref",
            "head_ref",
            "repair_profile",
            "target_ids",
            "allowed_paths",
        }
    ),
    "repair_status": frozenset({"repository", "session_id"}),
    "repair_preview": frozenset({"repository", "session_id"}),
    "repair_apply_local": frozenset(
        {"repository", "session_id", "candidate_id", "validation_sha256"}
    ),
    "repair_reject": frozenset({"repository", "session_id", "candidate_id", "reason"}),
    "repair_cancel": frozenset({"repository", "session_id"}),
    "github_publish_check": frozenset({"repository", "proposal_sha256"}),
    "github_publish_repair": frozenset({"repository", "proposal_sha256"}),
}

_RepositoryAlias = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description="Exact repository alias from the startup host profile.",
    ),
]
_GitRef = Annotated[
    str,
    Field(
        min_length=1,
        max_length=4_096,
        pattern=r"^[^\x00\r\n]+$",
        description="Git revision resolved inside the selected repository.",
    ),
]
_ProfileName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description="Exact named policy from the startup host profile.",
    ),
]
_Sha256 = Annotated[
    str,
    Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="Lowercase hexadecimal SHA-256 identity.",
    ),
]
_RepositoryPath = Annotated[
    str,
    Field(
        min_length=1,
        max_length=1_024,
        pattern=r"^[^/\\\x00\r\n](?:[^\\\x00\r\n]*[^/\\\x00\r\n])?$",
        description="Canonical repository-relative path from the repair allowlist.",
    ),
]
_TargetIds = Annotated[
    list[_Sha256],
    Field(
        min_length=1,
        max_length=16,
        description="Sorted unique deterministic repair target IDs.",
    ),
]
_AllowedPaths = Annotated[
    list[_RepositoryPath],
    Field(
        min_length=1,
        max_length=32,
        description="Sorted unique repository-relative paths allowed for repair.",
    ),
]
_GithubPullRequest = Annotated[
    int,
    Field(ge=1, le=2_147_483_647, description="GitHub pull request number."),
]
_Reason = Annotated[
    str,
    Field(max_length=4_096, description="Bounded reason recorded with the local decision."),
]


class _ProductFacade(Protocol):
    """Public product operations consumed by the MCP adapter."""

    def review_run(
        self,
        *,
        repository: str,
        base_ref: str,
        head_ref: str,
        review_profile: str,
        github_pr: int | None = None,
    ) -> ProductEnvelope: ...

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
    ) -> ProductEnvelope: ...

    def repair_status(self, *, repository: str, session_id: str) -> ProductEnvelope: ...

    def repair_preview(self, *, repository: str, session_id: str) -> ProductEnvelope: ...

    def repair_approve_and_apply_local(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        validation_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope: ...

    def repair_reject(
        self,
        *,
        repository: str,
        session_id: str,
        candidate_id: str,
        reason: str,
    ) -> ProductEnvelope: ...

    def repair_cancel(
        self,
        *,
        repository: str,
        session_id: str,
        reason: str = "",
    ) -> ProductEnvelope: ...

    def github_publish_check(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope: ...

    def github_publish_repair(
        self,
        *,
        repository: str,
        proposal_sha256: str,
        confirmation: str,
    ) -> ProductEnvelope: ...


def create_mcp_server(
    profile: HostProfile,
    *,
    orchestrator: _ProductFacade | None = None,
) -> MCPServer[object]:
    """Create the fixed RepoGuard MCP server for one validated startup profile."""
    if type(profile) is not HostProfile:
        raise TypeError("profile must be an exact HostProfile")
    product = (
        cast(
            _ProductFacade,
            ProductOrchestrator(profile, interface=ProductInterface.MCP),
        )
        if orchestrator is None
        else orchestrator
    )
    server: MCPServer[object] = MCPServer(
        "repoguard_mcp",
        title="RepoGuard",
        description="Bounded review and repair product operations.",
        version=__version__,
        middleware=[_canonical_tool_results],
    )

    @server.tool(
        name="review_run",
        description="Run one bounded review for exact refs in a configured repository.",
        annotations=_annotations(
            read_only=True, destructive=False, idempotent=True, open_world=True
        ),
        structured_output=False,
    )
    def review_run(
        repository: _RepositoryAlias,
        base_ref: _GitRef,
        head_ref: _GitRef,
        review_profile: _ProfileName,
        github_pr: _GithubPullRequest | None = None,
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REVIEW_RUN,
            lambda: product.review_run(
                repository=repository,
                base_ref=base_ref,
                head_ref=head_ref,
                review_profile=review_profile,
                github_pr=github_pr,
            ),
        )

    @server.tool(
        name="repair_prepare",
        description="Prepare, validate, and preview one bounded local repair session.",
        annotations=_annotations(
            read_only=False,
            destructive=False,
            idempotent=False,
            open_world=True,
        ),
        structured_output=False,
    )
    def repair_prepare(
        repository: _RepositoryAlias,
        base_ref: _GitRef,
        head_ref: _GitRef,
        repair_profile: _ProfileName,
        target_ids: _TargetIds,
        allowed_paths: _AllowedPaths,
        github_pr: _GithubPullRequest | None = None,
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REPAIR_PREPARE,
            lambda: product.repair_prepare(
                repository=repository,
                base_ref=base_ref,
                head_ref=head_ref,
                repair_profile=repair_profile,
                target_ids=tuple(target_ids),
                allowed_paths=tuple(allowed_paths),
                github_pr=github_pr,
            ),
        )

    @server.tool(
        name="repair_status",
        description="Read the content-free durable status of one local repair session.",
        annotations=_annotations(
            read_only=True,
            destructive=False,
            idempotent=True,
            open_world=False,
        ),
        structured_output=False,
    )
    def repair_status(
        repository: _RepositoryAlias,
        session_id: _Sha256,
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REPAIR_STATUS,
            lambda: product.repair_status(repository=repository, session_id=session_id),
        )

    @server.tool(
        name="repair_preview",
        description="Read the secret-redacted preview of one local repair session.",
        annotations=_annotations(
            read_only=True,
            destructive=False,
            idempotent=True,
            open_world=False,
        ),
        structured_output=False,
    )
    def repair_preview(
        repository: _RepositoryAlias,
        session_id: _Sha256,
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REPAIR_PREVIEW,
            lambda: product.repair_preview(repository=repository, session_id=session_id),
        )

    @server.tool(
        name="repair_apply_local",
        description=(
            "Confirm, approve, and apply one exact VALIDATED candidate and validation "
            "to its dedicated local ref."
        ),
        annotations=_annotations(
            read_only=False,
            destructive=True,
            idempotent=False,
            open_world=False,
        ),
        structured_output=False,
    )
    def repair_apply_local(
        repository: _RepositoryAlias,
        session_id: _Sha256,
        candidate_id: _Sha256,
        validation_sha256: _Sha256,
        ctx: Context[object, object],
    ) -> CallToolResult | InputRequiredResult:
        try:
            status = product.repair_status(repository=repository, session_id=session_id)
        except Exception:
            return _completion_failure_result(
                ProductOperation.REPAIR_APPLY_LOCAL,
                code="internal",
            )
        if type(status) is not ProductEnvelope:
            return _completion_failure_result(
                ProductOperation.REPAIR_APPLY_LOCAL,
                code="internal",
            )
        if not status.ok:
            return _complete(
                _failure_for_operation(status, ProductOperation.REPAIR_APPLY_LOCAL),
                operation=ProductOperation.REPAIR_APPLY_LOCAL,
            )
        if not _is_exact_validated_session(
            status,
            session_id=session_id,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
        ):
            return _complete(
                _failure(
                    ProductOperation.REPAIR_APPLY_LOCAL,
                    code="cas_conflict",
                    session_id=session_id,
                ),
                operation=ProductOperation.REPAIR_APPLY_LOCAL,
            )
        unavailable = _elicitation_unavailable(
            ctx,
            ProductOperation.REPAIR_APPLY_LOCAL,
            session_id=session_id,
        )
        if unavailable is not None:
            return unavailable
        expected_state = _local_apply_state(
            repository=repository,
            session_id=session_id,
            candidate_id=candidate_id,
            validation_sha256=validation_sha256,
        )
        prompt = (
            "Approve and apply this exact local RepoGuard repair to its dedicated ref?\n"
            f"candidate_id: {candidate_id}\n"
            f"validation_sha256: {validation_sha256}\n"
            f"Exact confirmation: {REPAIR_APPROVAL_CONFIRMATION}"
        )
        confirmation = _confirmed_or_request(
            ctx,
            operation=ProductOperation.REPAIR_APPLY_LOCAL,
            expected_state=expected_state,
            expected_confirmation=REPAIR_APPROVAL_CONFIRMATION,
            prompt=prompt,
            session_id=session_id,
        )
        if not isinstance(confirmation, str):
            return confirmation
        return _complete_call(
            ProductOperation.REPAIR_APPLY_LOCAL,
            lambda: product.repair_approve_and_apply_local(
                repository=repository,
                session_id=session_id,
                candidate_id=candidate_id,
                validation_sha256=validation_sha256,
                confirmation=confirmation,
            ),
        )

    @server.tool(
        name="repair_reject",
        description="Reject one exact local repair candidate.",
        annotations=_annotations(
            read_only=False,
            destructive=True,
            idempotent=False,
            open_world=False,
        ),
        structured_output=False,
    )
    def repair_reject(
        repository: _RepositoryAlias,
        session_id: _Sha256,
        candidate_id: _Sha256,
        reason: _Reason,
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REPAIR_REJECT,
            lambda: product.repair_reject(
                repository=repository,
                session_id=session_id,
                candidate_id=candidate_id,
                reason=reason,
            ),
        )

    @server.tool(
        name="repair_cancel",
        description="Cancel one nonterminal local repair session.",
        annotations=_annotations(
            read_only=False,
            destructive=True,
            idempotent=False,
            open_world=False,
        ),
        structured_output=False,
    )
    def repair_cancel(
        repository: _RepositoryAlias,
        session_id: _Sha256,
        reason: _Reason = "",
    ) -> CallToolResult:
        return _complete_call(
            ProductOperation.REPAIR_CANCEL,
            lambda: product.repair_cancel(
                repository=repository,
                session_id=session_id,
                reason=reason,
            ),
        )

    token = os.environ.get("REPOGUARD_GITHUB_TOKEN")
    github_token_present = token is not None and bool(token.strip())
    token = ""
    if profile.mcp.publish_check and github_token_present:
        _register_github_writer(
            server,
            product=product,
            operation=ProductOperation.GITHUB_PUBLISH_CHECK,
            confirmation=_GITHUB_CHECK_CONFIRMATION,
        )
    if profile.mcp.publish_repair and github_token_present:
        _register_github_writer(
            server,
            product=product,
            operation=ProductOperation.GITHUB_PUBLISH_REPAIR,
            confirmation=_GITHUB_REPAIR_CONFIRMATION,
        )
    return server


def serve_mcp_stdio(
    profile: HostProfile,
    *,
    orchestrator: _ProductFacade | None = None,
) -> None:
    """Run the fixed RepoGuard MCP server over stdio and no other transport."""
    create_mcp_server(profile, orchestrator=orchestrator).run(transport="stdio")


def _register_github_writer(
    server: MCPServer[object],
    *,
    product: _ProductFacade,
    operation: ProductOperation,
    confirmation: str,
) -> None:
    name = (
        "github_publish_check"
        if operation is ProductOperation.GITHUB_PUBLISH_CHECK
        else "github_publish_repair"
    )
    noun = "GitHub Check Run" if operation is ProductOperation.GITHUB_PUBLISH_CHECK else "repair PR"

    def github_writer(
        repository: _RepositoryAlias,
        proposal_sha256: _Sha256,
        ctx: Context[object, object],
    ) -> CallToolResult | InputRequiredResult:
        unavailable = _elicitation_unavailable(ctx, operation, proposal_sha256=proposal_sha256)
        if unavailable is not None:
            return unavailable
        expected_state = f"repoguard.m6.mcp.{operation.value}.v1:{repository}:{proposal_sha256}"
        prompt = (
            f"Approve publishing this exact RepoGuard proposal as a {noun}?\n"
            f"proposal_sha256: {proposal_sha256}\n"
            f"Exact confirmation: {confirmation}"
        )
        confirmed = _confirmed_or_request(
            ctx,
            operation=operation,
            expected_state=expected_state,
            expected_confirmation=confirmation,
            prompt=prompt,
            proposal_sha256=proposal_sha256,
        )
        if not isinstance(confirmed, str):
            return confirmed

        def publish() -> ProductEnvelope:
            if operation is ProductOperation.GITHUB_PUBLISH_CHECK:
                return product.github_publish_check(
                    repository=repository,
                    proposal_sha256=proposal_sha256,
                    confirmation=confirmed,
                )
            return product.github_publish_repair(
                repository=repository,
                proposal_sha256=proposal_sha256,
                confirmation=confirmed,
            )

        return _complete_call(operation, publish)

    server.add_tool(
        github_writer,
        name=name,
        description=f"Publish one exact approved RepoGuard proposal as a {noun}.",
        annotations=_annotations(
            read_only=False,
            destructive=False,
            idempotent=True,
            open_world=True,
        ),
        structured_output=False,
    )


def _annotations(
    *,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
) -> ToolAnnotations:
    return ToolAnnotations(
        read_only_hint=read_only,
        destructive_hint=destructive,
        idempotent_hint=idempotent,
        open_world_hint=open_world,
    )


def _complete_call(
    operation: ProductOperation,
    call: Callable[[], ProductEnvelope],
) -> CallToolResult:
    try:
        envelope = call()
    except Exception:
        return _completion_failure_result(operation, code="internal")
    return _complete(envelope, operation=operation)


def _complete(
    envelope: ProductEnvelope,
    *,
    operation: ProductOperation,
) -> CallToolResult:
    try:
        if type(envelope) is not ProductEnvelope or envelope.operation is not operation:
            raise ValueError("product completion operation is invalid")
        rendered = product_envelope_to_json(envelope)
        structured = product_envelope_to_dict(envelope)
    except ValueError as error:
        code = (
            "resource_limit"
            if str(error) == "product envelope result limit exceeded"
            else "internal"
        )
        return _completion_failure_result(operation, code=code)
    except Exception:
        return _completion_failure_result(operation, code="internal")
    return CallToolResult(
        content=[TextContent(type="text", text=rendered)],
        structured_content=structured,
        is_error=not envelope.ok,
    )


def _completion_failure_result(
    operation: ProductOperation,
    *,
    code: str,
) -> CallToolResult:
    envelope = _failure(
        operation,
        code=code,
        stage=ProductStage.INTERNAL,
    )
    rendered = product_envelope_to_json(envelope)
    structured = product_envelope_to_dict(envelope)
    return CallToolResult(
        content=[TextContent(type="text", text=rendered)],
        structured_content=structured,
        is_error=True,
    )


def _failure(
    operation: ProductOperation,
    *,
    code: str,
    stage: ProductStage = ProductStage.APPROVAL,
    session_id: str | None = None,
    proposal_sha256: str | None = None,
) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=False,
        result=None,
        error=ProductErrorRecord(
            domain=ProductErrorDomain.MCP,
            code=code,
            message=product_error_message(ProductErrorDomain.MCP),
            retryable=False,
            stage=stage,
            state=None,
            session_id=session_id,
            proposal_sha256=proposal_sha256,
            attempt_count=0,
        ),
    )


def _elicitation_unavailable(
    ctx: Context[object, object],
    operation: ProductOperation,
    *,
    session_id: str | None = None,
    proposal_sha256: str | None = None,
) -> CallToolResult | None:
    capabilities = ctx.client_capabilities
    elicitation = None if capabilities is None else capabilities.elicitation
    if (
        ctx.protocol_version != LATEST_PROTOCOL_VERSION
        or elicitation is None
        or elicitation.form is None
    ):
        return _complete(
            _failure(
                operation,
                code="elicitation_unavailable",
                session_id=session_id,
                proposal_sha256=proposal_sha256,
            ),
            operation=operation,
        )
    return None


def _confirmed_or_request(
    ctx: Context[object, object],
    *,
    operation: ProductOperation,
    expected_state: str,
    expected_confirmation: str,
    prompt: str,
    session_id: str | None = None,
    proposal_sha256: str | None = None,
) -> str | CallToolResult | InputRequiredResult:
    responses = ctx.input_responses
    if responses is None:
        return InputRequiredResult(
            input_requests={
                _CONFIRMATION_KEY: ElicitRequest(
                    params=ElicitRequestFormParams(
                        message=prompt,
                        requested_schema={
                            "type": "object",
                            "properties": {
                                _CONFIRMATION_KEY: {
                                    "type": "string",
                                    "enum": [expected_confirmation],
                                    "description": "Exact approval text displayed above.",
                                }
                            },
                            "required": [_CONFIRMATION_KEY],
                            "additionalProperties": False,
                        },
                    )
                )
            },
            request_state=expected_state,
        )
    if ctx.request_state != expected_state:
        return _complete(
            _failure(
                operation,
                code="invalid_confirmation",
                session_id=session_id,
                proposal_sha256=proposal_sha256,
            ),
            operation=operation,
        )
    answer = responses.get(_CONFIRMATION_KEY)
    if not isinstance(answer, ElicitResult) or answer.action != "accept":
        return _complete(
            _failure(
                operation,
                code="approval_required",
                session_id=session_id,
                proposal_sha256=proposal_sha256,
            ),
            operation=operation,
        )
    content = answer.content
    if (
        type(content) is not dict
        or set(content) != {_CONFIRMATION_KEY}
        or type(content.get(_CONFIRMATION_KEY)) is not str
        or content[_CONFIRMATION_KEY] != expected_confirmation
    ):
        return _complete(
            _failure(
                operation,
                code="invalid_confirmation",
                session_id=session_id,
                proposal_sha256=proposal_sha256,
            ),
            operation=operation,
        )
    return expected_confirmation


def _is_exact_validated_session(
    status: ProductEnvelope,
    *,
    session_id: str,
    candidate_id: str,
    validation_sha256: str,
) -> bool:
    if status.operation is not ProductOperation.REPAIR_STATUS:
        return False
    result = status.result
    if result is None or type(result.get("snapshot")) is not dict:
        return False
    snapshot = cast(dict[str, object], result["snapshot"])
    if (
        snapshot.get("schema_version") != 1
        or snapshot.get("session_id") != session_id
        or snapshot.get("state") != "validated"
        or snapshot.get("approval") is not None
        or snapshot.get("application") is not None
        or snapshot.get("decision") is not None
        or snapshot.get("failure") is not None
        or snapshot.get("cleanup_pending") is not False
    ):
        return False
    candidate = snapshot.get("candidate")
    validation = snapshot.get("validation")
    if type(candidate) is not dict or type(validation) is not dict:
        return False
    candidate_mapping = cast(dict[str, object], candidate)
    validation_mapping = cast(dict[str, object], validation)
    return (
        candidate_mapping.get("candidate_id") == candidate_id
        and validation_mapping.get("candidate_id") == candidate_id
        and validation_mapping.get("validation_sha256") == validation_sha256
        and validation_mapping.get("success") is True
    )


def _local_apply_state(
    *,
    repository: str,
    session_id: str,
    candidate_id: str,
    validation_sha256: str,
) -> str:
    return (
        "repoguard.m6.mcp.repair_apply_local.v1:"
        f"{repository}:{session_id}:{candidate_id}:{validation_sha256}"
    )


def _failure_for_operation(
    envelope: ProductEnvelope,
    operation: ProductOperation,
) -> ProductEnvelope:
    if envelope.ok or envelope.error is None:
        raise ValueError("envelope must be a failed product operation")
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=False,
        result=None,
        error=envelope.error,
    )


def _tool_arguments_are_valid(name: str, arguments: object) -> bool:
    if type(arguments) is not dict:
        return False
    keys = set(arguments)
    if not _TOOL_REQUIRED_ARGUMENTS[name].issubset(keys) or not keys.issubset(
        _TOOL_ARGUMENTS[name]
    ):
        return False
    for field in ("repository",):
        if field in arguments and not _matches_alias(arguments[field]):
            return False
    for field in ("review_profile", "repair_profile"):
        if field in arguments and not _matches_alias(arguments[field]):
            return False
    for field in ("base_ref", "head_ref"):
        if field in arguments and not _matches_git_ref(arguments[field]):
            return False
    for field in (
        "session_id",
        "candidate_id",
        "validation_sha256",
        "proposal_sha256",
    ):
        if field in arguments and not _matches_sha256(arguments[field]):
            return False
    github_pr = arguments.get("github_pr")
    if github_pr is not None and (
        type(github_pr) is not int or not 1 <= github_pr <= 2_147_483_647
    ):
        return False
    if "target_ids" in arguments:
        target_ids = arguments["target_ids"]
        if not (
            type(target_ids) is list
            and 1 <= len(target_ids) <= 16
            and all(_matches_sha256(value) for value in target_ids)
            and _is_sorted_unique(target_ids)
        ):
            return False
    if "allowed_paths" in arguments:
        allowed_paths = arguments["allowed_paths"]
        if not (
            type(allowed_paths) is list
            and 1 <= len(allowed_paths) <= 32
            and all(_matches_repository_path(value) for value in allowed_paths)
            and _is_sorted_unique(allowed_paths)
        ):
            return False
    if "reason" in arguments:
        reason = arguments["reason"]
        if type(reason) is not str or len(reason) > 4_096:
            return False
    return True


def _matches_alias(value: object) -> bool:
    return type(value) is str and _ALIAS_PATTERN.fullmatch(value) is not None


def _matches_git_ref(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 4_096
        and not any(character in value for character in "\x00\r\n")
    )


def _matches_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _matches_repository_path(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if (
        not encoded
        or len(encoded) > 1_024
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(character in value for character in "\x00\r\n")
    ):
        return False
    parts = value.split("/")
    return all(
        part and part.casefold() not in {".", "..", ".git"} and len(part.encode("utf-8")) <= 255
        for part in parts
    )


def _is_sorted_unique(values: list[object]) -> bool:
    if any(type(value) is not str for value in values):
        return False
    strings = cast(list[str], values)
    return len(strings) == len(set(strings)) and strings == sorted(
        strings,
        key=lambda value: value.encode("utf-8"),
    )


async def _canonical_tool_results(
    ctx: ServerRequestContext[Any, Any],
    call_next: CallNext,
) -> HandlerResult:
    """Keep all recognized tool failures in the schema-1 product envelope."""
    request = _known_tool_request(ctx)
    if request is None:
        return await call_next(ctx)
    name, arguments = request
    operation = _TOOL_OPERATIONS[name]
    if not _tool_arguments_are_valid(name, arguments):
        return _invalid_request_result(operation, arguments)
    try:
        result = await call_next(ctx)
    except ValidationError:
        return _invalid_request_result(operation, arguments)
    except Exception:
        return _completion_failure_result(operation, code="internal")
    if isinstance(result, CallToolResult) and result.is_error and result.structured_content is None:
        return _completion_failure_result(operation, code="internal")
    if (
        type(result) is dict
        and result.get("isError") is True
        and result.get("structuredContent") is None
    ):
        return _completion_failure_result(operation, code="internal")
    return result


def _known_tool_request(
    ctx: ServerRequestContext[Any, Any],
) -> tuple[str, object] | None:
    if ctx.method != "tools/call" or not isinstance(ctx.params, Mapping):
        return None
    name = ctx.params.get("name")
    if type(name) is not str or name not in _TOOL_OPERATIONS:
        return None
    return name, ctx.params.get("arguments")


def _invalid_request_result(
    operation: ProductOperation,
    arguments: object,
) -> CallToolResult:
    session_id = _argument_sha256(arguments, "session_id")
    proposal_sha256 = _argument_sha256(arguments, "proposal_sha256")
    return _complete(
        _failure(
            operation,
            code="invalid_request",
            stage=ProductStage.INPUT,
            session_id=session_id,
            proposal_sha256=proposal_sha256,
        ),
        operation=operation,
    )


def _argument_sha256(arguments: object, name: str) -> str | None:
    if type(arguments) is not dict:
        return None
    value = arguments.get(name)
    if type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None:
        return value
    return None
