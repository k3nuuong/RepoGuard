"""Focused tests for the M6 product command-line adapter."""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import repoguard.cli as cli
from repoguard.host_profile import HostProfile
from repoguard.product import (
    ProductEnvelope,
    ProductErrorDomain,
    ProductErrorRecord,
    ProductInterface,
    ProductOperation,
    ProductStage,
    product_envelope_from_json,
    product_envelope_to_json,
    product_error_message,
)

_PROFILE = "/outside/repoguard-profile.json"
_SHA_A = "a" * 64
_SHA_B = "b" * 64
_GLOBAL = ("--profile", _PROFILE, "--repository", "example")

_COMMANDS = (
    (ProductOperation.PROFILE_VALIDATE, ("profile", "validate")),
    (
        ProductOperation.REVIEW_RUN,
        (
            "review",
            "run",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "deterministic",
            "--github-pr",
            "7",
        ),
    ),
    (
        ProductOperation.REPAIR_PREPARE,
        (
            "repair",
            "prepare",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--repair-profile",
            "default",
            "--target",
            _SHA_A,
            _SHA_B,
            "--allow-path",
            "src/a.py",
            "src/b.py",
            "--github-pr",
            "9",
        ),
    ),
    (ProductOperation.REPAIR_STATUS, ("repair", "status", "--session-id", _SHA_A)),
    (ProductOperation.REPAIR_PREVIEW, ("repair", "preview", "--session-id", _SHA_A)),
    (
        ProductOperation.REPAIR_APPROVE_LOCAL,
        (
            "repair",
            "approve-local",
            "--session-id",
            _SHA_A,
            "--candidate-id",
            _SHA_B,
            "--validation-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
    ),
    (
        ProductOperation.REPAIR_APPLY_LOCAL,
        (
            "repair",
            "apply-local",
            "--session-id",
            _SHA_A,
            "--approval-sha256",
            _SHA_B,
        ),
    ),
    (
        ProductOperation.REPAIR_REJECT,
        (
            "repair",
            "reject",
            "--session-id",
            _SHA_A,
            "--candidate-id",
            _SHA_B,
            "--reason",
            "not approved",
        ),
    ),
    (ProductOperation.REPAIR_CANCEL, ("repair", "cancel", "--session-id", _SHA_A)),
    (ProductOperation.REPAIR_EXPIRE, ("repair", "expire", "--session-id", _SHA_A)),
    (ProductOperation.REPAIR_RECOVER, ("repair", "recover")),
    (ProductOperation.REPAIR_CLEANUP, ("repair", "cleanup")),
    (
        ProductOperation.GITHUB_PUBLICATION_STATUS,
        ("github", "publication", "status", "--proposal-sha256", _SHA_A),
    ),
    (
        ProductOperation.GITHUB_PUBLICATION_RECOVER,
        ("github", "publication", "recover", "--proposal-sha256", _SHA_A),
    ),
    (
        ProductOperation.GITHUB_PUBLISH_CHECK,
        (
            "github",
            "publish-check",
            "--proposal-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
    ),
    (
        ProductOperation.GITHUB_PUBLISH_REPAIR,
        (
            "github",
            "publish-repair",
            "--proposal-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
    ),
    (ProductOperation.MCP_SERVE, ("mcp", "serve")),
)


class _HostProfileStub:
    def repository(self, alias: str) -> object:
        if alias != "example":
            raise ValueError("unknown alias")
        return object()


def _host_profile_stub() -> HostProfile:
    return cast(HostProfile, _HostProfileStub())


def _success(
    operation: ProductOperation,
    result: dict[str, object] | None = None,
) -> ProductEnvelope:
    return ProductEnvelope(
        schema_version=1,
        operation=operation,
        ok=True,
        result={} if result is None else result,
        error=None,
    )


def _failure(
    operation: ProductOperation,
    domain: ProductErrorDomain,
    code: str,
    *,
    retryable: bool = False,
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
            retryable=retryable,
            stage=ProductStage.INPUT,
            state=None,
            session_id=None,
            proposal_sha256=None,
            attempt_count=0,
        ),
    )


def _decode_stdout(stdout: str) -> ProductEnvelope:
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1
    return product_envelope_from_json(stdout[:-1].encode("utf-8"))


def test_command_matrix_covers_every_product_operation() -> None:
    assert {operation for operation, _ in _COMMANDS} == set(ProductOperation)


@pytest.mark.parametrize(("operation", "arguments"), _COMMANDS[:-1])
def test_fixed_command_tree_emits_one_canonical_envelope(
    operation: ProductOperation,
    arguments: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: list[ProductOperation] = []

    def dispatch(namespace: argparse.Namespace) -> ProductEnvelope:
        parsed_operation = cast(ProductOperation, namespace.operation)
        observed.append(parsed_operation)
        return _success(parsed_operation)

    monkeypatch.setattr(cli, "_dispatch", dispatch)

    assert cli.main((*_GLOBAL, *arguments)) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert _decode_stdout(captured.out) == _success(operation)
    assert captured.out == f"{product_envelope_to_json(_success(operation))}\n"
    assert observed == [operation]


def test_no_arguments_preserves_silent_compatibility(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(()) == 0
    assert capsys.readouterr() == ("", "")


def test_help_does_not_require_profile_or_repository(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(("--help",))

    assert exit_info.value.code == 0
    captured = capsys.readouterr()
    assert "{profile,review,repair,github,mcp}" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    "arguments",
    (
        ("--repository", "example", "profile", "validate"),
        ("--profile", _PROFILE, "profile", "validate"),
        ("--profile", "relative.json", "--repository", "example", "profile", "validate"),
        (*_GLOBAL, "unknown"),
        (
            *_GLOBAL,
            "review",
            "run",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "default",
            "--github-pr",
            "0",
        ),
        (
            *_GLOBAL,
            "review",
            "run",
            "--base-r",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "default",
        ),
        (*_GLOBAL, "repair", "status"),
    ),
)
def test_argparse_errors_are_exit_two_and_stderr_only(
    arguments: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(arguments)

    assert exit_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("usage: repoguard")


@pytest.mark.parametrize(
    ("envelope", "expected_exit"),
    (
        (_success(ProductOperation.REVIEW_RUN), 0),
        (_success(ProductOperation.REVIEW_RUN, {"policy_passed": False}), 6),
        (_failure(ProductOperation.REVIEW_RUN, ProductErrorDomain.CLI, "invalid_request"), 3),
        (_failure(ProductOperation.REVIEW_RUN, ProductErrorDomain.REVIEW, "invalid_evidence"), 4),
        (
            _failure(
                ProductOperation.REVIEW_RUN,
                ProductErrorDomain.PROVIDER,
                "authentication_failed",
            ),
            5,
        ),
        (_failure(ProductOperation.REVIEW_RUN, ProductErrorDomain.REPAIR, "stale"), 7),
        (
            _failure(
                ProductOperation.REVIEW_RUN,
                ProductErrorDomain.MCP,
                "capability_unavailable",
            ),
            8,
        ),
        (_failure(ProductOperation.REVIEW_RUN, ProductErrorDomain.INTERNAL, "internal"), 70),
        (
            _failure(
                ProductOperation.REVIEW_RUN,
                ProductErrorDomain.PROVIDER,
                "provider_timeout",
                retryable=True,
            ),
            75,
        ),
    ),
)
def test_parsed_commands_use_fixed_exit_mapping(
    envelope: ProductEnvelope,
    expected_exit: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_dispatch", lambda _: envelope)

    exit_code = cli.main(
        (
            *_GLOBAL,
            "review",
            "run",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "default",
        )
    )

    assert exit_code == expected_exit
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == f"{product_envelope_to_json(envelope)}\n"


def test_unexpected_dispatch_failure_is_redacted_internal_envelope(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_: object) -> ProductEnvelope:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(cli, "_dispatch", fail)

    exit_code = cli.main(
        (
            *_GLOBAL,
            "review",
            "run",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "default",
        )
    )

    assert exit_code == 70
    captured = capsys.readouterr()
    assert "secret detail" not in f"{captured.out}{captured.err}"
    envelope = _decode_stdout(captured.out)
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.INTERNAL


def test_profile_validation_routes_to_public_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: list[Path] = []
    expected = _success(ProductOperation.PROFILE_VALIDATE)

    def validate(path: Path) -> ProductEnvelope:
        observed.append(path)
        return expected

    monkeypatch.setattr(cli, "profile_validate", validate)

    assert cli.main((*_GLOBAL, "profile", "validate")) == 0
    assert observed == [Path(_PROFILE)]
    assert _decode_stdout(capsys.readouterr().out) == expected


_ORCHESTRATOR_COMMANDS = (
    (
        ProductOperation.REVIEW_RUN,
        "review_run",
        (
            "review",
            "run",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--review-profile",
            "default",
            "--github-pr",
            "3",
        ),
        {
            "repository": "example",
            "base_ref": "base",
            "head_ref": "head",
            "review_profile": "default",
            "github_pr": 3,
        },
    ),
    (
        ProductOperation.REPAIR_PREPARE,
        "repair_prepare",
        (
            "repair",
            "prepare",
            "--base-ref",
            "base",
            "--head-ref",
            "head",
            "--repair-profile",
            "default",
            "--target",
            _SHA_A,
            "--allow-path",
            "src/a.py",
        ),
        {
            "repository": "example",
            "base_ref": "base",
            "head_ref": "head",
            "repair_profile": "default",
            "target_ids": (_SHA_A,),
            "allowed_paths": ("src/a.py",),
            "github_pr": None,
        },
    ),
    (
        ProductOperation.REPAIR_STATUS,
        "repair_status",
        ("repair", "status", "--session-id", _SHA_A),
        {"repository": "example", "session_id": _SHA_A},
    ),
    (
        ProductOperation.REPAIR_PREVIEW,
        "repair_preview",
        ("repair", "preview", "--session-id", _SHA_A),
        {"repository": "example", "session_id": _SHA_A},
    ),
    (
        ProductOperation.REPAIR_APPROVE_LOCAL,
        "repair_approve_local",
        (
            "repair",
            "approve-local",
            "--session-id",
            _SHA_A,
            "--candidate-id",
            _SHA_B,
            "--validation-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
        {
            "repository": "example",
            "session_id": _SHA_A,
            "candidate_id": _SHA_B,
            "validation_sha256": _SHA_A,
            "confirmation": "confirmation",
        },
    ),
    (
        ProductOperation.REPAIR_APPLY_LOCAL,
        "repair_apply_local",
        (
            "repair",
            "apply-local",
            "--session-id",
            _SHA_A,
            "--approval-sha256",
            _SHA_B,
        ),
        {"repository": "example", "session_id": _SHA_A, "approval_sha256": _SHA_B},
    ),
    (
        ProductOperation.REPAIR_REJECT,
        "repair_reject",
        (
            "repair",
            "reject",
            "--session-id",
            _SHA_A,
            "--candidate-id",
            _SHA_B,
            "--reason",
            "reason",
        ),
        {
            "repository": "example",
            "session_id": _SHA_A,
            "candidate_id": _SHA_B,
            "reason": "reason",
        },
    ),
    (
        ProductOperation.REPAIR_CANCEL,
        "repair_cancel",
        ("repair", "cancel", "--session-id", _SHA_A),
        {"repository": "example", "session_id": _SHA_A, "reason": ""},
    ),
    (
        ProductOperation.REPAIR_EXPIRE,
        "repair_expire",
        ("repair", "expire", "--session-id", _SHA_A),
        {"repository": "example", "session_id": _SHA_A},
    ),
    (
        ProductOperation.REPAIR_RECOVER,
        "repair_recover",
        ("repair", "recover"),
        {"repository": "example"},
    ),
    (
        ProductOperation.REPAIR_CLEANUP,
        "repair_cleanup",
        ("repair", "cleanup"),
        {"repository": "example"},
    ),
    (
        ProductOperation.GITHUB_PUBLICATION_STATUS,
        "github_publication_status",
        ("github", "publication", "status", "--proposal-sha256", _SHA_A),
        {"repository": "example", "proposal_sha256": _SHA_A},
    ),
    (
        ProductOperation.GITHUB_PUBLICATION_RECOVER,
        "github_publication_recover",
        ("github", "publication", "recover", "--proposal-sha256", _SHA_A),
        {"repository": "example", "proposal_sha256": _SHA_A},
    ),
    (
        ProductOperation.GITHUB_PUBLISH_CHECK,
        "github_publish_check",
        (
            "github",
            "publish-check",
            "--proposal-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
        {
            "repository": "example",
            "proposal_sha256": _SHA_A,
            "confirmation": "confirmation",
        },
    ),
    (
        ProductOperation.GITHUB_PUBLISH_REPAIR,
        "github_publish_repair",
        (
            "github",
            "publish-repair",
            "--proposal-sha256",
            _SHA_A,
            "--confirmation",
            "confirmation",
        ),
        {
            "repository": "example",
            "proposal_sha256": _SHA_A,
            "confirmation": "confirmation",
        },
    ),
)


@pytest.mark.parametrize(
    ("operation", "method_name", "arguments", "expected_arguments"),
    _ORCHESTRATOR_COMMANDS,
)
def test_supported_commands_route_only_through_product_orchestrator(
    operation: ProductOperation,
    method_name: str,
    arguments: tuple[str, ...],
    expected_arguments: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _host_profile_stub()
    calls: list[tuple[str, dict[str, object]]] = []

    def load(_: Path) -> HostProfile:
        return profile

    class Orchestrator:
        def __init__(
            self,
            loaded_profile: HostProfile,
            *,
            interface: ProductInterface,
        ) -> None:
            assert loaded_profile is profile
            assert interface is ProductInterface.CLI

        def __getattr__(self, name: str) -> Callable[..., ProductEnvelope]:
            def invoke(**kwargs: object) -> ProductEnvelope:
                calls.append((name, kwargs))
                return _success(operation)

            return invoke

    monkeypatch.setattr(cli, "load_host_profile", load)
    monkeypatch.setattr(cli, "ProductOrchestrator", Orchestrator)

    assert cli.main((*_GLOBAL, *arguments)) == 0
    assert calls == [(method_name, expected_arguments)]
    assert _decode_stdout(capsys.readouterr().out) == _success(operation)


def test_github_actions_runtime_records_action_interface_provenance(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _host_profile_stub()
    observed: list[ProductInterface] = []

    class Orchestrator:
        def __init__(
            self,
            loaded_profile: HostProfile,
            *,
            interface: ProductInterface,
        ) -> None:
            assert loaded_profile is profile
            observed.append(interface)

        def review_run(self, **_arguments: object) -> ProductEnvelope:
            return _success(ProductOperation.REVIEW_RUN)

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(cli, "load_host_profile", lambda _: profile)
    monkeypatch.setattr(cli, "ProductOrchestrator", Orchestrator)

    arguments = (
        "review",
        "run",
        "--base-ref",
        "base",
        "--head-ref",
        "head",
        "--review-profile",
        "deterministic",
    )
    assert cli.main((*_GLOBAL, *arguments)) == 0
    assert observed == [ProductInterface.ACTION]
    assert _decode_stdout(capsys.readouterr().out).ok


def test_mcp_serve_hands_stdio_to_official_server_without_cli_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _host_profile_stub()
    observed: list[object] = []

    monkeypatch.setattr(cli, "load_host_profile", lambda _: profile)
    monkeypatch.setattr(
        "repoguard.mcp_server.serve_mcp_stdio",
        lambda loaded: observed.append(loaded),
    )

    assert cli.main((*_GLOBAL, "mcp", "serve")) == 0
    captured = capsys.readouterr()
    assert observed == [profile]
    assert captured.out == ""
    assert captured.err == ""


def test_mcp_runtime_failure_never_writes_a_cli_envelope_to_stdio(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "load_host_profile", lambda _: _host_profile_stub())

    def fail_after_stdio_ownership(_: object) -> None:
        raise RuntimeError("private MCP failure")

    monkeypatch.setattr(
        "repoguard.mcp_server.serve_mcp_stdio",
        fail_after_stdio_ownership,
    )

    assert cli.main((*_GLOBAL, "mcp", "serve")) == 70
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_unknown_repository_is_rejected_before_operation_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "load_host_profile", lambda _: _host_profile_stub())

    exit_code = cli.main(("--profile", _PROFILE, "--repository", "unknown", "mcp", "serve"))

    assert exit_code == 3
    envelope = _decode_stdout(capsys.readouterr().out)
    assert envelope.operation is ProductOperation.MCP_SERVE
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.CLI
    assert envelope.error.code == "invalid_repository"


def test_invalid_profile_is_a_request_envelope_in_subprocess() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "repoguard",
            "--profile",
            "/definitely/missing/repoguard-profile.json",
            "--repository",
            "example",
            "profile",
            "validate",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 3
    assert completed.stderr == ""
    envelope = _decode_stdout(completed.stdout)
    assert envelope.operation is ProductOperation.PROFILE_VALIDATE
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.PROFILE
    assert envelope.error.code == "invalid_profile"


def test_cli_has_no_private_repoguard_imports() -> None:
    source = Path(cli.__file__).read_text(encoding="utf-8")
    imported_modules = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_names = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }

    assert not {module for module in imported_modules if module.startswith("repoguard._")}
    assert not {name for name in imported_names if name.startswith("_repair_")}
