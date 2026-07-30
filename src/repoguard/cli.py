"""Command-line adapter for RepoGuard product operations."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn, cast

from repoguard import __version__
from repoguard.host_profile import load_host_profile
from repoguard.product import (
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductExitCode,
    ProductInterface,
    ProductOperation,
    ProductOrchestrator,
    ProductStage,
    product_envelope_to_json,
    product_error_message,
    product_exit_code,
    profile_validate,
)

__all__ = ["main"]


class _ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and run one RepoGuard product command."""
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return 0

    parser = _build_parser()
    namespace = parser.parse_args(arguments)
    operation = cast(ProductOperation, namespace.operation)
    if operation is ProductOperation.MCP_SERVE:
        return _serve_mcp(namespace)
    try:
        envelope = _dispatch(namespace)
        rendered = product_envelope_to_json(envelope)
    except Exception:
        envelope = _failure(
            operation,
            domain=ProductErrorDomain.INTERNAL,
            code="internal",
            stage=ProductStage.INTERNAL,
        )
        rendered = product_envelope_to_json(envelope)
    sys.stdout.write(f"{rendered}\n")
    return int(product_exit_code(envelope))


def _build_parser() -> _ArgumentParser:
    parser = _ArgumentParser(
        prog="repoguard",
        description="RepoGuard product command-line interface.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--profile",
        required=True,
        type=_absolute_path,
        metavar="ABS_PATH",
        help="owner-only host profile",
    )
    parser.add_argument(
        "--repository",
        required=True,
        metavar="ALIAS",
        help="repository alias from the host profile",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    _add_profile_commands(commands)
    _add_review_commands(commands)
    _add_repair_commands(commands)
    _add_github_commands(commands)
    _add_mcp_commands(commands)
    return parser


def _add_profile_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    profile = commands.add_parser("profile", help="host profile operations")
    subcommands = profile.add_subparsers(dest="profile_command", required=True)
    validate = subcommands.add_parser("validate", help="validate the host profile")
    _set_operation(validate, ProductOperation.PROFILE_VALIDATE)


def _add_review_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    review = commands.add_parser("review", help="review operations")
    subcommands = review.add_subparsers(dest="review_command", required=True)
    run = subcommands.add_parser("run", help="run a bounded review")
    run.add_argument("--base-ref", required=True, metavar="REF")
    run.add_argument("--head-ref", required=True, metavar="REF")
    run.add_argument("--review-profile", required=True, metavar="NAME")
    run.add_argument("--github-pr", type=_positive_integer, metavar="N")
    _set_operation(run, ProductOperation.REVIEW_RUN)


def _add_repair_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    repair = commands.add_parser("repair", help="local repair operations")
    subcommands = repair.add_subparsers(dest="repair_command", required=True)

    prepare = subcommands.add_parser("prepare", help="prepare and validate a repair")
    prepare.add_argument("--base-ref", required=True, metavar="REF")
    prepare.add_argument("--head-ref", required=True, metavar="REF")
    prepare.add_argument("--repair-profile", required=True, metavar="NAME")
    prepare.add_argument("--target", required=True, nargs="+", metavar="ID")
    prepare.add_argument("--allow-path", required=True, nargs="+", metavar="PATH")
    prepare.add_argument("--github-pr", type=_positive_integer, metavar="N")
    _set_operation(prepare, ProductOperation.REPAIR_PREPARE)

    status = subcommands.add_parser("status", help="read repair status")
    _add_session_id(status)
    _set_operation(status, ProductOperation.REPAIR_STATUS)

    preview = subcommands.add_parser("preview", help="read a redacted repair preview")
    _add_session_id(preview)
    _set_operation(preview, ProductOperation.REPAIR_PREVIEW)

    approve = subcommands.add_parser("approve-local", help="approve a local repair")
    _add_session_id(approve)
    approve.add_argument("--candidate-id", required=True, metavar="ID")
    approve.add_argument("--validation-sha256", required=True, metavar="ID")
    approve.add_argument("--confirmation", required=True, metavar="TEXT")
    _set_operation(approve, ProductOperation.REPAIR_APPROVE_LOCAL)

    apply = subcommands.add_parser("apply-local", help="apply a local repair")
    _add_session_id(apply)
    apply.add_argument("--approval-sha256", required=True, metavar="ID")
    _set_operation(apply, ProductOperation.REPAIR_APPLY_LOCAL)

    reject = subcommands.add_parser("reject", help="reject a local repair")
    _add_session_id(reject)
    reject.add_argument("--candidate-id", required=True, metavar="ID")
    reject.add_argument("--reason", required=True, metavar="TEXT")
    _set_operation(reject, ProductOperation.REPAIR_REJECT)

    cancel = subcommands.add_parser("cancel", help="cancel a local repair")
    _add_session_id(cancel)
    cancel.add_argument("--reason", default="", metavar="TEXT")
    _set_operation(cancel, ProductOperation.REPAIR_CANCEL)

    expire = subcommands.add_parser("expire", help="expire a local repair")
    _add_session_id(expire)
    _set_operation(expire, ProductOperation.REPAIR_EXPIRE)

    recover = subcommands.add_parser("recover", help="recover interrupted repairs")
    _set_operation(recover, ProductOperation.REPAIR_RECOVER)

    cleanup = subcommands.add_parser("cleanup", help="clean terminal repair data")
    _set_operation(cleanup, ProductOperation.REPAIR_CLEANUP)


def _add_github_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    github = commands.add_parser("github", help="approved GitHub publication operations")
    subcommands = github.add_subparsers(dest="github_command", required=True)

    publication = subcommands.add_parser("publication", help="publication state operations")
    publication_commands = publication.add_subparsers(
        dest="github_publication_command",
        required=True,
    )
    status = publication_commands.add_parser("status", help="read publication status")
    _add_proposal_sha256(status)
    _set_operation(status, ProductOperation.GITHUB_PUBLICATION_STATUS)
    recover = publication_commands.add_parser("recover", help="recover a publication")
    _add_proposal_sha256(recover)
    _set_operation(recover, ProductOperation.GITHUB_PUBLICATION_RECOVER)

    publish_check = subcommands.add_parser("publish-check", help="publish an approved Check Run")
    _add_publication_approval(publish_check)
    _set_operation(publish_check, ProductOperation.GITHUB_PUBLISH_CHECK)

    publish_repair = subcommands.add_parser(
        "publish-repair",
        help="publish an approved repair branch and draft pull request",
    )
    _add_publication_approval(publish_repair)
    _set_operation(publish_repair, ProductOperation.GITHUB_PUBLISH_REPAIR)


def _add_mcp_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    mcp = commands.add_parser("mcp", help="MCP server operations")
    subcommands = mcp.add_subparsers(dest="mcp_command", required=True)
    serve = subcommands.add_parser("serve", help="serve MCP over stdio")
    _set_operation(serve, ProductOperation.MCP_SERVE)


def _set_operation(parser: argparse.ArgumentParser, operation: ProductOperation) -> None:
    parser.set_defaults(operation=operation)


def _add_session_id(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-id", required=True, metavar="ID")


def _add_proposal_sha256(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proposal-sha256", required=True, metavar="ID")


def _add_publication_approval(parser: argparse.ArgumentParser) -> None:
    _add_proposal_sha256(parser)
    parser.add_argument("--confirmation", required=True, metavar="TEXT")


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("profile must be an absolute path")
    return path


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("value must be a positive integer") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _dispatch(namespace: argparse.Namespace) -> ProductEnvelope:
    operation = cast(ProductOperation, namespace.operation)
    profile_path = cast(Path, namespace.profile)
    repository = cast(str, namespace.repository)
    if operation is ProductOperation.PROFILE_VALIDATE:
        return profile_validate(profile_path)

    try:
        profile = load_host_profile(profile_path)
    except ValueError:
        return _failure(
            operation,
            domain=ProductErrorDomain.PROFILE,
            code="invalid_profile",
            stage=ProductStage.PROFILE,
        )
    try:
        profile.repository(repository)
    except ValueError:
        return _failure(
            operation,
            domain=ProductErrorDomain.CLI,
            code="invalid_repository",
            stage=ProductStage.INPUT,
        )
    interface = (
        ProductInterface.ACTION
        if os.environ.get("GITHUB_ACTIONS") == "true"
        else ProductInterface.CLI
    )
    orchestrator = ProductOrchestrator(profile, interface=interface)

    if operation is ProductOperation.REVIEW_RUN:
        return orchestrator.review_run(
            repository=repository,
            base_ref=cast(str, namespace.base_ref),
            head_ref=cast(str, namespace.head_ref),
            review_profile=cast(str, namespace.review_profile),
            github_pr=cast(int | None, namespace.github_pr),
        )
    if operation is ProductOperation.REPAIR_PREPARE:
        return orchestrator.repair_prepare(
            repository=repository,
            base_ref=cast(str, namespace.base_ref),
            head_ref=cast(str, namespace.head_ref),
            repair_profile=cast(str, namespace.repair_profile),
            target_ids=tuple(cast(list[str], namespace.target)),
            allowed_paths=tuple(cast(list[str], namespace.allow_path)),
            github_pr=cast(int | None, namespace.github_pr),
        )
    if operation is ProductOperation.REPAIR_STATUS:
        return orchestrator.repair_status(
            repository=repository,
            session_id=cast(str, namespace.session_id),
        )
    if operation is ProductOperation.REPAIR_PREVIEW:
        return orchestrator.repair_preview(
            repository=repository,
            session_id=cast(str, namespace.session_id),
        )
    if operation is ProductOperation.REPAIR_APPROVE_LOCAL:
        return orchestrator.repair_approve_local(
            repository=repository,
            session_id=cast(str, namespace.session_id),
            candidate_id=cast(str, namespace.candidate_id),
            validation_sha256=cast(str, namespace.validation_sha256),
            confirmation=cast(str, namespace.confirmation),
        )
    if operation is ProductOperation.REPAIR_APPLY_LOCAL:
        return orchestrator.repair_apply_local(
            repository=repository,
            session_id=cast(str, namespace.session_id),
            approval_sha256=cast(str, namespace.approval_sha256),
        )
    if operation is ProductOperation.REPAIR_REJECT:
        return orchestrator.repair_reject(
            repository=repository,
            session_id=cast(str, namespace.session_id),
            candidate_id=cast(str, namespace.candidate_id),
            reason=cast(str, namespace.reason),
        )
    if operation is ProductOperation.REPAIR_CANCEL:
        return orchestrator.repair_cancel(
            repository=repository,
            session_id=cast(str, namespace.session_id),
            reason=cast(str, namespace.reason),
        )
    if operation is ProductOperation.REPAIR_EXPIRE:
        return orchestrator.repair_expire(
            repository=repository,
            session_id=cast(str, namespace.session_id),
        )
    if operation is ProductOperation.REPAIR_RECOVER:
        return orchestrator.repair_recover(repository=repository)
    if operation is ProductOperation.REPAIR_CLEANUP:
        return orchestrator.repair_cleanup(repository=repository)
    if operation is ProductOperation.GITHUB_PUBLICATION_STATUS:
        return orchestrator.github_publication_status(
            repository=repository,
            proposal_sha256=cast(str, namespace.proposal_sha256),
        )
    if operation is ProductOperation.GITHUB_PUBLICATION_RECOVER:
        return orchestrator.github_publication_recover(
            repository=repository,
            proposal_sha256=cast(str, namespace.proposal_sha256),
        )
    if operation is ProductOperation.GITHUB_PUBLISH_CHECK:
        return orchestrator.github_publish_check(
            repository=repository,
            proposal_sha256=cast(str, namespace.proposal_sha256),
            confirmation=cast(str, namespace.confirmation),
        )
    if operation is ProductOperation.GITHUB_PUBLISH_REPAIR:
        return orchestrator.github_publish_repair(
            repository=repository,
            proposal_sha256=cast(str, namespace.proposal_sha256),
            confirmation=cast(str, namespace.confirmation),
        )
    return _unreachable_operation(operation)


def _serve_mcp(namespace: argparse.Namespace) -> int:
    operation = ProductOperation.MCP_SERVE
    profile_path = cast(Path, namespace.profile)
    repository = cast(str, namespace.repository)
    try:
        profile = load_host_profile(profile_path)
    except ValueError:
        return _write_failure(
            _failure(
                operation,
                domain=ProductErrorDomain.PROFILE,
                code="invalid_profile",
                stage=ProductStage.PROFILE,
            )
        )
    try:
        profile.repository(repository)
    except ValueError:
        return _write_failure(
            _failure(
                operation,
                domain=ProductErrorDomain.CLI,
                code="invalid_repository",
                stage=ProductStage.INPUT,
            )
        )
    try:
        from repoguard.mcp_server import serve_mcp_stdio

        serve_mcp_stdio(profile)
    except Exception:
        # Once the server is invoked, stdout belongs exclusively to MCP JSON-RPC.
        # A CLI envelope here would corrupt a partially established stdio session.
        return int(ProductExitCode.INTERNAL)
    return 0


def _write_failure(envelope: ProductEnvelope) -> int:
    sys.stdout.write(f"{product_envelope_to_json(envelope)}\n")
    return int(product_exit_code(envelope))


def _failure(
    operation: ProductOperation,
    *,
    domain: ProductErrorDomain,
    code: str,
    stage: ProductStage,
) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=False,
        result=None,
        error=ProductErrorRecord(
            domain=domain,
            code=code,
            message=product_error_message(domain),
            retryable=False,
            stage=stage,
            state=None,
            session_id=None,
            proposal_sha256=None,
            attempt_count=0,
        ),
    )


def _unreachable_operation(operation: ProductOperation) -> NoReturn:
    raise AssertionError(f"unhandled product operation: {operation.value}")
