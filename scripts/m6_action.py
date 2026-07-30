#!/usr/bin/env python3
"""Fixed GitHub composite-action adapter for the public RepoGuard CLI."""

from __future__ import annotations

import hashlib
import hmac
import html
import importlib.util
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, cast

_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_MAX_PRODUCT_ENVELOPE_BYTES = _MAX_CANONICAL_BYTES + 4 * 1024
_MAX_PROFILE_BYTES = 1024 * 1024
_MAX_EVENT_BYTES = 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_ACTION_DRIVER_BYTES = 512 * 1024
_MAX_PACKAGE_TREE_ENTRIES = 10_000
_MAX_PACKAGE_TREE_DEPTH = 64
_CLI_TIMEOUT_SECONDS = 30 * 60
_PROPOSAL_DOMAIN = b"repoguard.m6.github_proposal.v1\0"
_CHECK_CONFIRMATION = "I approve publishing this exact RepoGuard review as a GitHub Check Run."
_REPAIR_CONFIRMATION = (
    "I approve publishing this exact RepoGuard repair commit to its dedicated branch and "
    "draft pull request."
)
_PUBLISHER_LABELS = ("Linux", "X64", "repoguard-publisher", "self-hosted")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^[1-9][0-9]{0,19}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FULL_NAME = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_PRODUCT_REVIEW_KEYS = (
    "schema_version",
    "repository_alias",
    "object_format",
    "base_ref",
    "head_ref",
    "base_oid",
    "head_oid",
    "merge_base_oid",
    "review_profile",
    "provider",
    "model",
    "evidence_sha256",
    "deterministic_review_sha256",
    "review_sha256",
    "findings",
    "finding_count",
    "highest_severity",
    "conclusion",
)
_PROPOSAL_KEYS = (
    "schema_version",
    "proposal_sha256",
    "kind",
    "repository_id",
    "repository_full_name",
    "pull_request_number",
    "base_ref",
    "base_oid",
    "head_oid",
    "origin",
    "profile_name",
    "created_at_us",
    "expires_at_us",
    "payload",
)
_SECRET_NAMES = (
    "REPOGUARD_OPENAI_API_KEY",
    "REPOGUARD_ANTHROPIC_API_KEY",
    "REPOGUARD_GITHUB_TOKEN",
)
_PROFILE_KEYS = {
    "schema_version",
    "repositories",
    "git_executable",
    "docker_executable",
    "rootless_socket",
    "product_state_root",
    "repair_state_root",
    "runner_labels",
    "m4_caches",
    "review_profiles",
    "repair_profiles",
    "github_actions",
    "mcp",
}
_GITHUB_ACTION_KEYS = {"action_repository", "action_sha", "publisher"}
_PUBLISHER_RUNTIME_KEYS = {
    "python_executable",
    "runtime_root",
    "package_root",
    "source_root",
}


class _ActionFailure(Exception):
    """Content-free action failure with one stable process status."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one fixed action adapter operation without echoing untrusted data."""
    argv = tuple(sys.argv[1:] if arguments is None else arguments)
    try:
        if argv == ("review",):
            _review()
        elif argv == ("review-conclusion",):
            _review_conclusion()
        elif argv == ("runner-preflight",):
            _runner_preflight()
        elif argv == ("repair",):
            _repair()
        elif argv == ("publish-preflight",):
            _publish_preflight()
        elif argv == ("publish",):
            _publish()
        else:
            raise _ActionFailure("invalid_command", 2)
    except _ActionFailure as error:
        sys.stderr.write(f"RepoGuard Action failed: {error.code}.\n")
        return error.status
    except BaseException:
        sys.stderr.write("RepoGuard Action failed: internal.\n")
        return 70
    return 0


def _review() -> None:
    context = _common_context()
    _validate_review_runner()
    if context["run_attempt"] != 1:
        raise _ActionFailure("invalid_run_attempt", 5)
    profile = _load_profile(context["profile_path"])
    _validate_action_source(context, profile)
    event = _load_event()
    repository = _profile_repository(profile, context["repository_alias"])
    _validate_repository_context(repository, context)
    context["sensitive_paths"] = _profile_sensitive_paths(profile)

    pr_number = _positive_int(_required_env("REPOGUARD_PR_NUMBER"), maximum=2_147_483_647)
    base_sha = _sha1(_required_env("REPOGUARD_BASE_SHA"))
    head_sha = _sha1(_required_env("REPOGUARD_HEAD_SHA"))
    _review_repository_path(repository, context["workspace"])
    if profile.get("runner_labels") != []:
        raise _ActionFailure("invalid_runner", 8)
    mode = _enum_env("REPOGUARD_MODE", {"deterministic", "agent", "retrieval"})
    provider = _enum_env("REPOGUARD_PROVIDER", {"none", "openai", "anthropic"})
    model = _optional_env("REPOGUARD_MODEL", maximum=256)
    cache_dir = _optional_env("REPOGUARD_CACHE_DIR", maximum=4_096)
    device = _enum_env("REPOGUARD_DEVICE", {"auto", "cpu", "cuda"})
    fail_on = _enum_env(
        "REPOGUARD_FAIL_ON",
        {"info", "low", "medium", "high", "critical"},
    )
    review_profile = _select_review_profile(
        profile,
        mode=mode,
        provider=provider,
        model=model,
        cache_dir=cache_dir,
        device=device,
        fail_on=fail_on,
    )
    same_repository = _validate_review_event(
        event,
        context=context,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        mode=mode,
        provider=provider,
        model=model,
        cache_dir=cache_dir,
        device=device,
    )
    _validate_review_secrets(provider)

    envelope, status = _run_cli(
        (
            "--profile",
            str(context["profile_path"]),
            "--repository",
            context["repository_alias"],
            "review",
            "run",
            "--base-ref",
            base_sha,
            "--head-ref",
            head_sha,
            "--review-profile",
            review_profile,
            "--github-pr",
            str(pr_number),
        ),
        expected_operation="review.run",
    )
    if status not in (0, 6) or envelope["ok"] is not True:
        raise _ActionFailure("review_failed", status if status in _known_statuses() else 70)
    result = _exact_mapping(envelope["result"])
    product_result = _product_review_result(result)
    github_write_supported = result.get("github_write_supported")
    if type(github_write_supported) is not bool or (
        same_repository is not None and github_write_supported is not same_repository
    ):
        raise _ActionFailure("proposal_mismatch", 7)

    output_root = _new_private_directory("repoguard-review-")
    result_path = output_root / "result.json"
    evidence_path = output_root / "evidence.json"
    review_path = output_root / "review.json"
    _write_private_file(result_path, _canonical_bytes(product_result))
    _write_private_file(evidence_path, _canonical_bytes(_evidence_projection(product_result)))
    _write_private_file(review_path, _canonical_bytes(_review_projection(product_result)))
    proposal_path = ""
    proposal_sha256 = ""
    if github_write_supported:
        proposal, proposal_sha256 = _proposal_from_result(
            result,
            kind="check",
            context=context,
            pr_number=pr_number,
            base_sha=base_sha,
            head_sha=head_sha,
            profile_name=review_profile,
        )
        if proposal["payload"].get("review_result") != product_result:
            raise _ActionFailure("proposal_mismatch", 7)
        proposal_root = _new_private_directory("repoguard-proposal-")
        materialized_proposal = proposal_root / "proposal.json"
        _write_private_file(materialized_proposal, _canonical_bytes(proposal))
        proposal_path = str(materialized_proposal)
    elif "proposal" in result or "proposal_sha256" in result:
        raise _ActionFailure("proposal_mismatch", 7)
    _write_step_summary(product_result, github_write_supported=github_write_supported)

    finding_count = _exact_int(product_result["finding_count"])
    highest = product_result["highest_severity"]
    if highest is not None and (
        type(highest) is not str or highest not in {"info", "low", "medium", "high", "critical"}
    ):
        raise _ActionFailure("invalid_result", 70)
    conclusion = product_result["conclusion"]
    if type(conclusion) is not str or conclusion not in {"success", "neutral", "failure"}:
        raise _ActionFailure("invalid_result", 70)
    if (status == 6) != (conclusion == "failure"):
        raise _ActionFailure("invalid_exit_status", 70)
    _write_outputs(
        {
            "result-path": str(result_path),
            "result-sha256": _sha256(_exact_str(product_result["review_sha256"])),
            "evidence-path": str(evidence_path),
            "evidence-sha256": _sha256(_exact_str(product_result["evidence_sha256"])),
            "review-path": str(review_path),
            "review-sha256": _sha256(_exact_str(product_result["deterministic_review_sha256"])),
            "proposal-path": proposal_path,
            "proposal-sha256": proposal_sha256,
            "finding-count": str(finding_count),
            "highest-severity": "" if highest is None else highest,
            "conclusion": conclusion,
            "github-write-supported": "true" if github_write_supported else "false",
        }
    )


def _review_conclusion() -> None:
    conclusion = _required_env("REPOGUARD_REVIEW_CONCLUSION", maximum=16)
    if conclusion not in {"success", "neutral", "failure"}:
        raise _ActionFailure("invalid_conclusion", 70)
    if conclusion == "failure":
        raise _ActionFailure("policy_failed", 6)


def _repair() -> None:
    context = _common_context()
    profile = _load_profile(context["profile_path"])
    _validate_action_source(context, profile)
    _validate_publisher_runner(profile, context)
    event = _load_event()
    _validate_dispatch_event(event, context)
    repository = _profile_repository(profile, context["repository_alias"])
    _validate_repository_context(repository, context)
    context["sensitive_paths"] = _profile_sensitive_paths(profile)
    _validate_rootless_profile(profile)

    pr_number = _positive_int(_required_env("REPOGUARD_PR_NUMBER"), maximum=2_147_483_647)
    base_sha = _sha1(_required_env("REPOGUARD_BASE_SHA"))
    head_sha = _sha1(_required_env("REPOGUARD_HEAD_SHA"))
    repair_profile = _name(_required_env("REPOGUARD_REPAIR_PROFILE"))
    targets = _canonical_string_array(
        _required_env("REPOGUARD_TARGET_IDS", maximum=4_096),
        minimum=1,
        maximum=16,
        item_validator=_sha256,
    )
    allowed_paths = _canonical_string_array(
        _required_env("REPOGUARD_ALLOWED_PATHS", maximum=16_384),
        minimum=1,
        maximum=32,
        item_validator=_repository_path,
    )
    selected_repair = _select_repair_profile(profile, repair_profile)
    _validate_repair_secrets(selected_repair)

    cli_arguments = [
        "--profile",
        str(context["profile_path"]),
        "--repository",
        context["repository_alias"],
        "repair",
        "prepare",
        "--base-ref",
        base_sha,
        "--head-ref",
        head_sha,
        "--repair-profile",
        repair_profile,
        "--target",
        *targets,
        "--allow-path",
        *allowed_paths,
        "--github-pr",
        str(pr_number),
    ]
    envelope, status = _run_cli(cli_arguments, expected_operation="repair.prepare")
    if status != 0 or envelope["ok"] is not True:
        raise _ActionFailure("repair_failed", status if status in _known_statuses() else 70)
    result = _exact_mapping(envelope["result"])
    proposal, proposal_sha256 = _proposal_from_result(
        result,
        kind="repair",
        context=context,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        profile_name=repair_profile,
    )
    snapshot = _exact_mapping(result.get("snapshot"))
    if snapshot.get("state") != "validated" or result.get("validation_success") is not True:
        raise _ActionFailure("validation_failed", 6)
    candidate = _exact_mapping(snapshot.get("candidate"))
    validation = _exact_mapping(snapshot.get("validation"))
    candidate_id = _sha256(_exact_str(candidate.get("candidate_id")))
    validation_sha256 = _sha256(_exact_str(validation.get("validation_sha256")))
    commit_oid = _sha1(_exact_str(candidate.get("commit_oid")))
    payload = _exact_mapping(proposal["payload"])
    if (
        payload.get("candidate_id") != candidate_id
        or payload.get("validation_sha256") != validation_sha256
        or payload.get("commit_oid") != commit_oid
    ):
        raise _ActionFailure("proposal_mismatch", 7)

    proposal_root = _new_private_directory("repoguard-proposal-")
    proposal_path = proposal_root / "proposal.json"
    _write_private_file(proposal_path, _canonical_bytes(proposal))
    _write_outputs(
        {
            "proposal-path": str(proposal_path),
            "proposal-sha256": proposal_sha256,
            "candidate-id": candidate_id,
            "validation-sha256": validation_sha256,
            "commit-oid": commit_oid,
            "state": "validated",
        }
    )


def _runner_preflight() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise _ActionFailure("invalid_context", 5)
    profile_path = Path(_required_env("REPOGUARD_HOST_PROFILE", maximum=4_096))
    workspace = Path(_required_env("REPOGUARD_WORKSPACE", maximum=4_096))
    if not profile_path.is_absolute() or not workspace.is_absolute():
        raise _ActionFailure("invalid_context", 3)
    context = {
        "action_ref": _required_env("REPOGUARD_ACTION_REF", maximum=64),
        "action_repository": _required_env(
            "REPOGUARD_ACTION_REPOSITORY",
            maximum=256,
        ),
        "run_attempt": _positive_int(
            _required_env("REPOGUARD_RUN_ATTEMPT"),
            maximum=1_000,
        ),
        "workspace": workspace,
    }
    profile = _load_profile(profile_path)
    _validate_action_source(context, profile)
    python_path, driver_path = _validate_publisher_runner(
        profile,
        context,
        require_current_python=False,
    )
    _write_outputs(
        {
            "python-path": str(python_path),
            "driver-path": str(driver_path),
        }
    )


def _publish_preflight() -> None:
    context = _common_context()
    profile = _load_profile(context["profile_path"])
    _validate_action_source(context, profile)
    _validate_publisher_runner(profile, context)
    repository = _profile_repository(profile, context["repository_alias"])
    _validate_repository_context(repository, context)
    event = _load_event()
    _validate_dispatch_event(event, context)
    publication = _publication_inputs(context)
    _validate_publish_secrets()
    _validate_profile_summary(context)
    _verify_artifact_metadata(context, publication)
    download_path = _new_private_directory("repoguard-download-")
    _write_outputs({"download-path": str(download_path)})


def _publish() -> None:
    context = _common_context()
    profile = _load_profile(context["profile_path"])
    _validate_action_source(context, profile)
    _validate_publisher_runner(profile, context)
    repository = _profile_repository(profile, context["repository_alias"])
    _validate_repository_context(repository, context)
    context["sensitive_paths"] = _profile_sensitive_paths(profile)
    event = _load_event()
    _validate_dispatch_event(event, context)
    publication = _publication_inputs(context)
    _validate_publish_secrets()
    _verify_artifact_metadata(context, publication)

    download_path = Path(_required_env("REPOGUARD_DOWNLOAD_PATH", maximum=4_096))
    proposal = _load_downloaded_proposal(
        download_path,
        proposal_sha256=publication["proposal_sha256"],
        kind=publication["kind"],
        context=context,
    )
    if proposal["origin"] != "action":
        raise _ActionFailure("proposal_mismatch", 7)
    proposal_path = download_path / "proposal.json"
    extra_environment = {"REPOGUARD_ACTION_ACTOR": context["actor"]}
    if publication["kind"] == "check":
        _harden_check_proposal_file(proposal_path)
        extra_environment["REPOGUARD_ACTION_PROPOSAL_PATH"] = str(proposal_path)

    operation = (
        ("github", "publish-check")
        if publication["kind"] == "check"
        else ("github", "publish-repair")
    )
    envelope, status = _run_cli(
        (
            "--profile",
            str(context["profile_path"]),
            "--repository",
            context["repository_alias"],
            *operation,
            "--proposal-sha256",
            publication["proposal_sha256"],
            "--confirmation",
            publication["confirmation"],
        ),
        expected_operation=(
            "github.publish_check" if publication["kind"] == "check" else "github.publish_repair"
        ),
        extra_environment=extra_environment,
    )
    if status != 0 or envelope["ok"] is not True:
        raise _ActionFailure("publication_failed", status if status in _known_statuses() else 70)
    result = _exact_mapping(envelope["result"])
    approval_sha256 = _sha256(_exact_str(result.get("approval_sha256")))
    result_sha256 = _sha256(_exact_str(result.get("result_sha256")))
    state = _exact_str(result.get("state"))
    expected_state = "check_published" if publication["kind"] == "check" else "repair_published"
    if state != expected_state:
        raise _ActionFailure("publication_state_mismatch", 7)
    _write_outputs(
        {
            "approval-sha256": approval_sha256,
            "result-sha256": result_sha256,
            "state": state,
        }
    )


def _common_context() -> dict[str, Any]:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise _ActionFailure("invalid_context", 5)
    profile_path = Path(_required_env("REPOGUARD_HOST_PROFILE", maximum=4_096))
    if not profile_path.is_absolute():
        raise _ActionFailure("invalid_profile", 3)
    repository_alias = _name(_required_env("REPOGUARD_REPOSITORY_ALIAS"))
    repository_id = _positive_int(
        _required_env("REPOGUARD_REPOSITORY_ID"),
        maximum=2**63 - 1,
    )
    repository_full_name = _full_name(_required_env("REPOGUARD_REPOSITORY_FULL_NAME"))
    workspace = Path(_required_env("REPOGUARD_WORKSPACE", maximum=4_096))
    if not workspace.is_absolute():
        raise _ActionFailure("invalid_context", 3)
    return {
        "profile_path": profile_path,
        "repository_alias": repository_alias,
        "repository_id": repository_id,
        "repository_full_name": repository_full_name,
        "workspace": workspace,
        "event_name": _required_env("REPOGUARD_EVENT_NAME", maximum=64),
        "ref": _required_env("REPOGUARD_REF", maximum=512),
        "default_branch": _required_env("REPOGUARD_DEFAULT_BRANCH", maximum=255),
        "run_id": _positive_int(_required_env("REPOGUARD_RUN_ID"), maximum=2**63 - 1),
        "run_attempt": _positive_int(
            _required_env("REPOGUARD_RUN_ATTEMPT"),
            maximum=1_000,
        ),
        "actor": _required_env("REPOGUARD_ACTOR", maximum=64),
        "triggering_actor": _required_env("REPOGUARD_TRIGGERING_ACTOR", maximum=64),
        "action_ref": _required_env("REPOGUARD_ACTION_REF", maximum=64),
        "action_repository": _required_env(
            "REPOGUARD_ACTION_REPOSITORY",
            maximum=256,
        ),
    }


def _validate_action_source(
    context: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    actions = _github_actions_profile(profile)
    action_ref = _sha1(_exact_str(context["action_ref"]))
    action_repository = _full_name(_exact_str(context["action_repository"]))
    if (
        actions.get("action_repository") != action_repository
        or actions.get("action_sha") != action_ref
    ):
        raise _ActionFailure("untrusted_action_source", 5)


def _validate_review_runner() -> None:
    if (
        os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Linux"
        or os.environ.get("RUNNER_ARCH") != "X64"
        or os.environ.get("ImageOS") != "ubuntu24"  # noqa: SIM112
    ):
        raise _ActionFailure("invalid_runner", 8)


def _validate_publisher_runner(
    profile: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    require_current_python: bool = True,
) -> tuple[Path, Path]:
    if (
        os.environ.get("RUNNER_ENVIRONMENT") != "self-hosted"
        or os.environ.get("RUNNER_OS") != "Linux"
        or os.environ.get("RUNNER_ARCH") != "X64"
        or context["run_attempt"] != 1
        or os.geteuid() == 0
    ):
        raise _ActionFailure("invalid_runner", 8)
    try:
        labels = _canonical_string_array(
            _required_env("REPOGUARD_RUNNER_LABELS", maximum=512),
            minimum=len(_PUBLISHER_LABELS),
            maximum=len(_PUBLISHER_LABELS),
            item_validator=lambda value: _bounded_text(value, maximum=64),
        )
    except _ActionFailure:
        raise _ActionFailure("invalid_runner", 8) from None
    if tuple(labels) != _PUBLISHER_LABELS:
        raise _ActionFailure("invalid_runner", 8)
    profile_labels = profile.get("runner_labels")
    if type(profile_labels) is not list or tuple(profile_labels) != _PUBLISHER_LABELS:
        raise _ActionFailure("invalid_runner", 8)
    publisher = _publisher_runtime_profile(profile)
    workspace = Path(context["workspace"])
    python_path = _publisher_python_path(
        workspace,
        expected=publisher["python_executable"],
    )
    driver_path = _publisher_driver_path(
        workspace,
        source_root=publisher["source_root"],
        bootstrap=not require_current_python,
    )
    if require_current_python:
        try:
            if (
                not Path(sys.executable).samefile(python_path)
                or sys.version_info[:2] != (3, 12)
                or sys.flags.isolated != 1
            ):
                raise _ActionFailure("invalid_runner", 8)
        except OSError:
            raise _ActionFailure("invalid_runner", 8) from None
        _validate_installed_package(publisher["package_root"])
    return python_path, driver_path


def _publisher_python_path(workspace: Path, *, expected: Path) -> Path:
    python_path = Path(_required_env("REPOGUARD_PYTHON", maximum=4_096))
    if (
        not python_path.is_absolute()
        or Path(os.path.normpath(str(python_path))) != python_path
        or python_path != expected
        or python_path == Path("/usr/bin/python3")
    ):
        raise _ActionFailure("invalid_runner", 8)
    if not workspace.is_absolute() or Path(os.path.normpath(str(workspace))) != workspace:
        raise _ActionFailure("invalid_runner", 8) from None
    if _paths_overlap_lexically(python_path, workspace):
        raise _ActionFailure("invalid_runner", 8)
    _validate_owner_only_parents(python_path)
    try:
        descriptor = _open_absolute_descriptor(python_path, directory=False)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, _ActionFailure):
        raise _ActionFailure("invalid_runner", 8) from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise _ActionFailure("invalid_runner", 8)
    return python_path


def _publisher_driver_path(
    workspace: Path,
    *,
    source_root: Path,
    bootstrap: bool,
) -> Path:
    supplied_root = Path(_required_env("REPOGUARD_ACTION_SOURCE_ROOT", maximum=4_096))
    if (
        not supplied_root.is_absolute()
        or Path(os.path.normpath(str(supplied_root))) != supplied_root
        or supplied_root != source_root
        or _paths_overlap_lexically(source_root, workspace)
    ):
        raise _ActionFailure("invalid_runner", 8)
    _validate_protected_directory(source_root)
    driver_path = source_root / "scripts" / "m6_action.py"
    _validate_owner_only_parents(driver_path)
    try:
        descriptor = _open_absolute_descriptor(driver_path, directory=False)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current_driver = Path(__file__).resolve(strict=True)
        if not bootstrap and not current_driver.samefile(driver_path):
            raise _ActionFailure("invalid_runner", 8)
    except (OSError, _ActionFailure):
        raise _ActionFailure("invalid_runner", 8) from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise _ActionFailure("invalid_runner", 8)
    pinned_driver = _pinned_action_driver()
    try:
        if bootstrap and not current_driver.samefile(pinned_driver):
            raise _ActionFailure("invalid_runner", 8)
        pinned_bytes = _read_regular_file(
            pinned_driver,
            maximum=_MAX_ACTION_DRIVER_BYTES,
            require_single_link=True,
        )
        local_bytes = _read_regular_file(
            driver_path,
            maximum=_MAX_ACTION_DRIVER_BYTES,
            require_single_link=True,
        )
    except (OSError, _ActionFailure):
        raise _ActionFailure("invalid_runner", 8) from None
    if not hmac.compare_digest(
        hashlib.sha256(pinned_bytes).digest(),
        hashlib.sha256(local_bytes).digest(),
    ):
        raise _ActionFailure("invalid_runner", 8)
    return driver_path


def _pinned_action_driver() -> Path:
    action_path = Path(_required_env("GITHUB_ACTION_PATH", maximum=4_096))
    if (
        not action_path.is_absolute()
        or Path(os.path.normpath(str(action_path))) != action_path
        or len(action_path.parents) < 2
    ):
        raise _ActionFailure("invalid_runner", 8)
    driver_path = action_path.parents[1] / "scripts" / "m6_action.py"
    try:
        descriptor = _open_absolute_descriptor(driver_path, directory=False)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise _ActionFailure("invalid_runner", 8) from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > _MAX_ACTION_DRIVER_BYTES
    ):
        raise _ActionFailure("invalid_runner", 8)
    return driver_path


def _validate_installed_package(expected: Path) -> None:
    try:
        specification = importlib.util.find_spec("repoguard")
        if specification is None or specification.origin is None:
            raise _ActionFailure("invalid_runner", 8)
        package_root = Path(specification.origin).parent
        locations = specification.submodule_search_locations
        if (
            Path(specification.origin).name != "__init__.py"
            or locations is None
            or len(locations) != 1
            or not package_root.samefile(expected)
            or not Path(next(iter(locations))).samefile(expected)
        ):
            raise _ActionFailure("invalid_runner", 8)
        _validate_package_tree(expected)
    except (ImportError, OSError, ValueError):
        raise _ActionFailure("invalid_runner", 8) from None


def _github_actions_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    actions = _exact_mapping(profile.get("github_actions"))
    if set(actions) != _GITHUB_ACTION_KEYS:
        raise _ActionFailure("invalid_profile", 3)
    _full_name(_exact_str(actions.get("action_repository")))
    _sha1(_exact_str(actions.get("action_sha")))
    publisher = actions.get("publisher")
    if publisher is not None and type(publisher) is not dict:
        raise _ActionFailure("invalid_profile", 3)
    return actions


def _publisher_runtime_profile(profile: Mapping[str, Any]) -> dict[str, Path]:
    actions = _github_actions_profile(profile)
    publisher = _exact_mapping(actions.get("publisher"))
    if set(publisher) != _PUBLISHER_RUNTIME_KEYS:
        raise _ActionFailure("invalid_profile", 3)
    paths = {
        key: _absolute_normalized_path(_exact_str(publisher.get(key)))
        for key in _PUBLISHER_RUNTIME_KEYS
    }
    runtime_root = paths["runtime_root"]
    package_root = paths["package_root"]
    source_root = paths["source_root"]
    python_path = paths["python_executable"]
    if (
        runtime_root == package_root
        or runtime_root not in package_root.parents
        or runtime_root not in python_path.parents
        or _paths_overlap_lexically(runtime_root, source_root)
    ):
        raise _ActionFailure("invalid_profile", 3)
    _validate_protected_directory(runtime_root)
    _validate_protected_directory(package_root)
    _validate_package_tree(package_root)
    _validate_protected_directory(source_root)
    return paths


def _absolute_normalized_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        raise _ActionFailure("invalid_profile", 3)
    return path


def _validate_owner_only_parents(path: Path) -> None:
    try:
        descriptor = _open_absolute_descriptor(
            path.parent,
            directory=True,
            protected_parents=True,
        )
        os.close(descriptor)
    except OSError:
        raise _ActionFailure("invalid_runner", 8) from None


def _validate_protected_directory(path: Path) -> None:
    try:
        descriptor = _open_absolute_descriptor(
            path,
            directory=True,
            protected_parents=True,
        )
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise _ActionFailure("invalid_runner", 8) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _ActionFailure("invalid_runner", 8)


def _validate_package_tree(path: Path) -> None:
    try:
        descriptor = _open_absolute_descriptor(
            path,
            directory=True,
            protected_parents=True,
        )
        try:
            entries = [0]
            _validate_package_directory(
                descriptor,
                entries=entries,
                depth=0,
            )
        finally:
            os.close(descriptor)
    except _ActionFailure:
        raise
    except (OSError, UnicodeError):
        raise _ActionFailure("invalid_runner", 8) from None


def _validate_package_directory(
    descriptor: int,
    *,
    entries: list[int],
    depth: int,
) -> None:
    if depth > _MAX_PACKAGE_TREE_DEPTH:
        raise _ActionFailure("invalid_runner", 8)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
    ):
        raise _ActionFailure("invalid_runner", 8)
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    for entry in os.listdir(descriptor):
        encoded = entry.encode("utf-8")
        if (
            not encoded
            or len(encoded) > 255
            or entry in {"", ".", ".."}
            or "/" in entry
            or "\x00" in entry
        ):
            raise _ActionFailure("invalid_runner", 8)
        entries[0] += 1
        if entries[0] > _MAX_PACKAGE_TREE_ENTRIES:
            raise _ActionFailure("invalid_runner", 8)
        value = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(value.st_mode):
            child = os.open(entry, directory_flags, dir_fd=descriptor)
            try:
                if _namespace_identity(os.fstat(child)) != _namespace_identity(value):
                    raise _ActionFailure("invalid_runner", 8)
                _validate_package_directory(
                    child,
                    entries=entries,
                    depth=depth + 1,
                )
                current = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
                if _namespace_identity(current) != _namespace_identity(value):
                    raise _ActionFailure("invalid_runner", 8)
            finally:
                os.close(child)
        elif stat.S_ISREG(value.st_mode):
            child = os.open(entry, file_flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    _namespace_identity(opened) != _namespace_identity(value)
                    or opened.st_uid not in {0, os.geteuid()}
                    or opened.st_nlink != 1
                    or opened.st_mode & 0o022
                ):
                    raise _ActionFailure("invalid_runner", 8)
            finally:
                os.close(child)
        else:
            raise _ActionFailure("invalid_runner", 8)


def _validate_profile_summary(context: Mapping[str, Any]) -> None:
    envelope, status = _run_cli(
        (
            "--profile",
            str(context["profile_path"]),
            "--repository",
            context["repository_alias"],
            "profile",
            "validate",
        ),
        expected_operation="profile.validate",
    )
    if status != 0 or envelope["ok"] is not True:
        raise _ActionFailure("invalid_profile", 3)
    result = _exact_mapping(envelope["result"])
    labels = result.get("runner_labels")
    if type(labels) is not list or tuple(labels) != _PUBLISHER_LABELS:
        raise _ActionFailure("invalid_runner", 8)


def _validate_rootless_profile(profile: Mapping[str, Any]) -> None:
    socket = profile.get("rootless_socket")
    if type(socket) is not str:
        raise _ActionFailure("invalid_profile", 3)
    expected_prefix = f"/run/user/{os.geteuid()}/"
    if not socket.startswith(expected_prefix) or socket == "/var/run/docker.sock":
        raise _ActionFailure("invalid_runner", 8)
    docker_host = os.environ.get("DOCKER_HOST", "")
    if docker_host not in ("", f"unix://{socket}"):
        raise _ActionFailure("invalid_runner", 8)


def _load_profile(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise _ActionFailure("invalid_profile", 3)
    try:
        descriptor = _open_absolute_descriptor(
            path,
            directory=False,
            protected_parents=True,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_size < 1
                or metadata.st_size > _MAX_PROFILE_BYTES
            ):
                raise _ActionFailure("invalid_profile", 3)
            expected = _metadata_identity(metadata)
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    raise _ActionFailure("invalid_profile", 3)
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1) or _metadata_identity(os.fstat(descriptor)) != expected:
                raise _ActionFailure("invalid_profile", 3)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
        repeated = _open_absolute_descriptor(
            path,
            directory=False,
            protected_parents=True,
        )
        try:
            repeated_metadata = os.fstat(repeated)
        finally:
            os.close(repeated)
    except _ActionFailure:
        raise
    except OSError:
        raise _ActionFailure("invalid_profile", 3) from None
    if (
        not raw
        or len(raw) != metadata.st_size
        or len(raw) > _MAX_PROFILE_BYTES
        or _metadata_identity(metadata) != _metadata_identity(repeated_metadata)
    ):
        raise _ActionFailure("invalid_profile", 3)
    profile = _exact_mapping(_parse_canonical(raw, maximum=_MAX_PROFILE_BYTES))
    if profile.get("schema_version") != 1 or set(profile) != _PROFILE_KEYS:
        raise _ActionFailure("invalid_profile", 3)
    return profile


def _profile_repository(profile: Mapping[str, Any], alias: str) -> dict[str, Any]:
    repositories = profile.get("repositories")
    if type(repositories) is not list:
        raise _ActionFailure("invalid_profile", 3)
    matches = [
        _exact_mapping(repository)
        for repository in repositories
        if type(repository) is dict and repository.get("alias") == alias
    ]
    if len(matches) != 1:
        raise _ActionFailure("invalid_profile", 3)
    return matches[0]


def _profile_sensitive_paths(profile: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in (
        "git_executable",
        "docker_executable",
        "rootless_socket",
        "product_state_root",
        "repair_state_root",
    ):
        value = profile.get(key)
        if type(value) is str and value.startswith("/"):
            values.append(value)
    for collection_name in ("repositories", "m4_caches"):
        collection = profile.get(collection_name)
        if type(collection) is not list:
            continue
        for item in collection:
            if type(item) is dict:
                value = item.get("path")
                if type(value) is str and value.startswith("/"):
                    values.append(value)
    actions = profile.get("github_actions")
    if type(actions) is dict:
        publisher = actions.get("publisher")
        if type(publisher) is dict:
            for key in _PUBLISHER_RUNTIME_KEYS:
                value = publisher.get(key)
                if type(value) is str and value.startswith("/"):
                    values.append(value)
    return tuple(sorted(set(values), key=lambda value: value.encode("utf-8")))


def _validate_repository_context(
    repository: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    if (
        repository.get("github_repository_id") != context["repository_id"]
        or repository.get("github_full_name") != context["repository_full_name"]
    ):
        raise _ActionFailure("repository_mismatch", 7)


def _review_repository_path(
    repository: Mapping[str, Any],
    workspace: Path,
) -> Path:
    raw = _required_env("REPOGUARD_REPOSITORY_PATH", maximum=4_096)
    requested = Path(raw)
    if not requested.is_absolute():
        requested = workspace / requested
    try:
        requested = requested.resolve(strict=True)
        profile_path = Path(_exact_str(repository.get("path"))).resolve(strict=True)
        workspace_resolved = workspace.resolve(strict=True)
    except OSError:
        raise _ActionFailure("invalid_repository", 3) from None
    if requested != profile_path or (
        requested != workspace_resolved and workspace_resolved not in requested.parents
    ):
        raise _ActionFailure("repository_mismatch", 7)
    return requested


def _select_review_profile(
    profile: Mapping[str, Any],
    *,
    mode: str,
    provider: str,
    model: str,
    cache_dir: str,
    device: str,
    fail_on: str,
) -> str:
    if mode == "deterministic":
        if provider != "none" or model or cache_dir:
            raise _ActionFailure("invalid_review_policy", 3)
        cache_name: str | None = None
    elif mode == "agent":
        if provider == "none" or not model or cache_dir:
            raise _ActionFailure("invalid_review_policy", 3)
        cache_name = None
    else:
        if provider == "none" or not model or not cache_dir:
            raise _ActionFailure("invalid_review_policy", 3)
        cache_path = Path(cache_dir)
        if not cache_path.is_absolute():
            raise _ActionFailure("invalid_review_policy", 3)
        caches = profile.get("m4_caches")
        if type(caches) is not list:
            raise _ActionFailure("invalid_profile", 3)
        matching_caches = [
            _exact_mapping(cache)
            for cache in caches
            if type(cache) is dict
            and cache.get("path") == cache_dir
            and cache.get("device") == device
        ]
        if len(matching_caches) != 1:
            raise _ActionFailure("invalid_review_policy", 3)
        cache_name = _name(_exact_str(matching_caches[0].get("name")))
    profiles = profile.get("review_profiles")
    if type(profiles) is not list:
        raise _ActionFailure("invalid_profile", 3)
    matches = [
        _exact_mapping(item)
        for item in profiles
        if type(item) is dict
        and item.get("mode") == mode
        and item.get("provider") == provider
        and item.get("model") == (model if model else None)
        and item.get("cache") == cache_name
        and item.get("device") == device
        and item.get("fail_on") == fail_on
    ]
    if len(matches) != 1:
        raise _ActionFailure("invalid_review_policy", 3)
    return _name(_exact_str(matches[0].get("name")))


def _select_repair_profile(
    profile: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    profiles = profile.get("repair_profiles")
    if type(profiles) is not list:
        raise _ActionFailure("invalid_profile", 3)
    matches = [
        _exact_mapping(item) for item in profiles if type(item) is dict and item.get("name") == name
    ]
    if len(matches) != 1:
        raise _ActionFailure("invalid_repair_policy", 3)
    return matches[0]


def _validate_review_event(
    event: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
    pr_number: int,
    base_sha: str,
    head_sha: str,
    mode: str,
    provider: str,
    model: str,
    cache_dir: str,
    device: str,
) -> bool | None:
    event_name = context["event_name"]
    if event_name == "pull_request":
        if mode != "deterministic" or provider != "none" or model or cache_dir or device != "cpu":
            raise _ActionFailure("untrusted_review_mode", 5)
        pull_request = _exact_mapping(event.get("pull_request"))
        base = _exact_mapping(pull_request.get("base"))
        head = _exact_mapping(pull_request.get("head"))
        if (
            event.get("number") != pr_number
            or base.get("sha") != base_sha
            or head.get("sha") != head_sha
        ):
            raise _ActionFailure("stale_pull_request", 7)
        base_repository = _exact_mapping(base.get("repo"))
        head_repository = _exact_mapping(head.get("repo"))
        if (
            base_repository.get("id") != context["repository_id"]
            or base_repository.get("full_name") != context["repository_full_name"]
        ):
            raise _ActionFailure("repository_mismatch", 7)
        return bool(
            head_repository.get("id") == context["repository_id"]
            and head_repository.get("full_name") == context["repository_full_name"]
        )
    if event_name == "workflow_dispatch":
        _validate_dispatch_event(event, context)
        return None
    raise _ActionFailure("invalid_event", 5)


def _validate_dispatch_event(
    event: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    if context["event_name"] != "workflow_dispatch":
        raise _ActionFailure("invalid_event", 5)
    repository = _exact_mapping(event.get("repository"))
    default_branch = _bounded_text(
        _exact_str(repository.get("default_branch")),
        maximum=255,
    )
    if (
        default_branch != context["default_branch"]
        or context["ref"] != f"refs/heads/{default_branch}"
        or repository.get("id") != context["repository_id"]
        or repository.get("full_name") != context["repository_full_name"]
    ):
        raise _ActionFailure("untrusted_dispatch", 5)


def _validate_review_secrets(provider: str) -> None:
    openai = os.environ.get("REPOGUARD_OPENAI_API_KEY", "")
    anthropic = os.environ.get("REPOGUARD_ANTHROPIC_API_KEY", "")
    github = os.environ.get("REPOGUARD_GITHUB_TOKEN", "")
    valid = (
        (provider == "none" and not openai and not anthropic)
        or (provider == "openai" and bool(openai) and not anthropic)
        or (provider == "anthropic" and bool(anthropic) and not openai)
    )
    if not valid or not github:
        raise _ActionFailure("invalid_credentials", 5)


def _validate_repair_secrets(repair_profile: Mapping[str, Any]) -> None:
    generation = _exact_mapping(repair_profile.get("generation"))
    provider = generation.get("provider_kind")
    if provider is None:
        selected = "none"
    elif type(provider) is str and provider in {"openai", "anthropic"}:
        selected = provider
    else:
        raise _ActionFailure("invalid_repair_policy", 3)
    _validate_review_secrets(selected)


def _validate_publish_secrets() -> None:
    if (
        os.environ.get("REPOGUARD_OPENAI_API_KEY", "")
        or os.environ.get("REPOGUARD_ANTHROPIC_API_KEY", "")
        or not os.environ.get("REPOGUARD_GITHUB_TOKEN", "")
    ):
        raise _ActionFailure("invalid_credentials", 5)


def _publication_inputs(context: Mapping[str, Any]) -> dict[str, Any]:
    if context["run_attempt"] != 1 or context["actor"] != context["triggering_actor"]:
        raise _ActionFailure("invalid_approval_context", 5)
    kind = _enum_env("REPOGUARD_KIND", {"check", "repair"})
    proposal_sha256 = _sha256(_required_env("REPOGUARD_PROPOSAL_SHA256"))
    source_run_id = _positive_int(
        _required_env("REPOGUARD_SOURCE_RUN_ID"),
        maximum=2**63 - 1,
    )
    source_run_attempt = _positive_int(
        _required_env("REPOGUARD_SOURCE_RUN_ATTEMPT"),
        maximum=1_000,
    )
    artifact_id = _positive_int(
        _required_env("REPOGUARD_ARTIFACT_ID"),
        maximum=2**63 - 1,
    )
    artifact_digest = _sha256(_required_env("REPOGUARD_ARTIFACT_DIGEST"))
    confirmation = _required_env("REPOGUARD_CONFIRMATION", maximum=256)
    expected_confirmation = _CHECK_CONFIRMATION if kind == "check" else _REPAIR_CONFIRMATION
    if (
        confirmation != expected_confirmation
        or source_run_id == context["run_id"]
        or source_run_attempt != 1
    ):
        raise _ActionFailure("invalid_approval_context", 5)
    return {
        "kind": kind,
        "proposal_sha256": proposal_sha256,
        "source_run_id": source_run_id,
        "source_run_attempt": source_run_attempt,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "confirmation": confirmation,
    }


def _verify_artifact_metadata(
    context: Mapping[str, Any],
    publication: Mapping[str, Any],
) -> None:
    try:
        from repoguard.github_transport import GitHubMethod, GitHubTransport

        transport = GitHubTransport(os.environ["REPOGUARD_GITHUB_TOKEN"])
        repository = context["repository_full_name"]
        artifact_response = transport.request(
            GitHubMethod.GET,
            f"/repos/{repository}/actions/artifacts/{publication['artifact_id']}",
        )
        run_response = transport.request(
            GitHubMethod.GET,
            f"/repos/{repository}/actions/runs/{publication['source_run_id']}",
        )
    except BaseException:
        raise _ActionFailure("artifact_metadata_unavailable", 75) from None
    artifact = _exact_mapping(artifact_response.body)
    workflow_run = _exact_mapping(artifact.get("workflow_run"))
    if (
        artifact_response.status != 200
        or artifact.get("id") != publication["artifact_id"]
        or artifact.get("name") != f"repoguard-proposal-v1-{publication['proposal_sha256']}"
        or artifact.get("expired") is not False
        or artifact.get("digest") != f"sha256:{publication['artifact_digest']}"
        or type(artifact.get("size_in_bytes")) is not int
        or not 0 < artifact["size_in_bytes"] <= _MAX_ARTIFACT_BYTES
        or workflow_run.get("id") != publication["source_run_id"]
        or workflow_run.get("repository_id") != context["repository_id"]
    ):
        raise _ActionFailure("artifact_mismatch", 7)
    run = _exact_mapping(run_response.body)
    repository = _exact_mapping(run.get("repository"))
    if (
        run_response.status != 200
        or run.get("id") != publication["source_run_id"]
        or run.get("run_attempt") != publication["source_run_attempt"]
        or run.get("status") != "completed"
        or repository.get("id") != context["repository_id"]
        or repository.get("full_name") != context["repository_full_name"]
        or (
            publication["kind"] == "repair"
            and (run.get("event") != "workflow_dispatch" or run.get("conclusion") != "success")
        )
        or (
            publication["kind"] == "check"
            and run.get("event") not in {"pull_request", "workflow_dispatch"}
        )
    ):
        raise _ActionFailure("source_run_mismatch", 7)


def _load_downloaded_proposal(
    directory: Path,
    *,
    proposal_sha256: str,
    kind: str,
    context: Mapping[str, Any],
) -> dict[str, Any]:
    if not directory.is_absolute():
        raise _ActionFailure("invalid_artifact", 3)
    try:
        entries = tuple(directory.iterdir())
    except OSError:
        raise _ActionFailure("invalid_artifact", 3) from None
    if len(entries) != 1 or entries[0].name != "proposal.json":
        raise _ActionFailure("invalid_artifact", 3)
    raw = _read_regular_file(
        entries[0],
        maximum=_MAX_CANONICAL_BYTES,
        require_single_link=True,
    )
    proposal = _validate_proposal(
        _exact_mapping(_parse_canonical(raw, maximum=_MAX_CANONICAL_BYTES)),
        expected_sha256=proposal_sha256,
        kind=kind,
        context=context,
        pr_number=None,
        base_sha=None,
        head_sha=None,
        profile_name=None,
    )
    return proposal


def _harden_check_proposal_file(path: Path) -> None:
    flags = os.O_RDWR | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= _MAX_CANONICAL_BYTES
            ):
                raise _ActionFailure("invalid_artifact", 3)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            hardened = os.fstat(descriptor)
            if stat.S_IMODE(hardened.st_mode) != 0o600:
                raise _ActionFailure("invalid_artifact", 3)
        finally:
            os.close(descriptor)
    except _ActionFailure:
        raise
    except OSError:
        raise _ActionFailure("invalid_artifact", 3) from None


def _proposal_from_result(
    result: Mapping[str, Any],
    *,
    kind: str,
    context: Mapping[str, Any],
    pr_number: int,
    base_sha: str,
    head_sha: str,
    profile_name: str,
) -> tuple[dict[str, Any], str]:
    proposal_sha256 = _sha256(_exact_str(result.get("proposal_sha256")))
    proposal = _validate_proposal(
        _exact_mapping(result.get("proposal")),
        expected_sha256=proposal_sha256,
        kind=kind,
        context=context,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        profile_name=profile_name,
    )
    return proposal, proposal_sha256


def _validate_proposal(
    proposal: dict[str, Any],
    *,
    expected_sha256: str,
    kind: str,
    context: Mapping[str, Any],
    pr_number: int | None,
    base_sha: str | None,
    head_sha: str | None,
    profile_name: str | None,
) -> dict[str, Any]:
    if set(proposal) != set(_PROPOSAL_KEYS):
        raise _ActionFailure("invalid_proposal", 3)
    identity = {key: proposal[key] for key in _PROPOSAL_KEYS if key != "proposal_sha256"}
    digest = hashlib.sha256(_PROPOSAL_DOMAIN + _canonical_bytes(identity)).hexdigest()
    if (
        proposal.get("schema_version") != 1
        or proposal.get("proposal_sha256") != expected_sha256
        or digest != expected_sha256
        or proposal.get("kind") != kind
        or proposal.get("repository_id") != context["repository_id"]
        or proposal.get("repository_full_name") != context["repository_full_name"]
        or proposal.get("origin") != "action"
        or type(proposal.get("created_at_us")) is not int
        or type(proposal.get("expires_at_us")) is not int
        or proposal["expires_at_us"] != proposal["created_at_us"] + 86_400_000_000
        or type(proposal.get("payload")) is not dict
    ):
        raise _ActionFailure("proposal_mismatch", 7)
    if pr_number is not None and proposal.get("pull_request_number") != pr_number:
        raise _ActionFailure("proposal_mismatch", 7)
    if base_sha is not None and proposal.get("base_oid") != base_sha:
        raise _ActionFailure("proposal_mismatch", 7)
    if head_sha is not None and proposal.get("head_oid") != head_sha:
        raise _ActionFailure("proposal_mismatch", 7)
    if profile_name is not None and proposal.get("profile_name") != profile_name:
        raise _ActionFailure("proposal_mismatch", 7)
    _reject_private_proposal_data(proposal, context)
    return proposal


def _reject_private_proposal_data(
    proposal: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    forbidden_keys = {
        "session_id",
        "evidence_bundle",
        "provider_prompt",
        "provider_response",
        "validation_logs",
        "git_pack",
        "runtime_files",
    }

    def walk(value: Any) -> None:
        if type(value) is dict:
            if forbidden_keys.intersection(value):
                raise _ActionFailure("private_artifact_data", 70)
            for item in value.values():
                walk(item)
        elif type(value) is list:
            for item in value:
                walk(item)

    walk(proposal)
    raw = _canonical_bytes(proposal)
    sensitive = {
        str(context["profile_path"]),
        *cast(tuple[str, ...], context.get("sensitive_paths", ())),
        *(os.environ.get(name, "") for name in _SECRET_NAMES),
    }
    if any(value and value.encode("utf-8") in raw for value in sensitive):
        raise _ActionFailure("private_artifact_data", 70)


def _product_review_result(result: Mapping[str, Any]) -> dict[str, Any]:
    try:
        product = {key: result[key] for key in _PRODUCT_REVIEW_KEYS}
    except KeyError:
        raise _ActionFailure("invalid_result", 70) from None
    if (
        product["schema_version"] != 1
        or set(product) != set(_PRODUCT_REVIEW_KEYS)
        or type(product["findings"]) is not list
        or type(product["finding_count"]) is not int
        or product["finding_count"] != len(product["findings"])
    ):
        raise _ActionFailure("invalid_result", 70)
    for key in ("evidence_sha256", "deterministic_review_sha256", "review_sha256"):
        _sha256(_exact_str(product[key]))
    return product


def _evidence_projection(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "repository_alias": result["repository_alias"],
        "object_format": result["object_format"],
        "base_ref": result["base_ref"],
        "head_ref": result["head_ref"],
        "base_oid": result["base_oid"],
        "head_oid": result["head_oid"],
        "merge_base_oid": result["merge_base_oid"],
        "evidence_sha256": result["evidence_sha256"],
    }


def _review_projection(result: Mapping[str, Any]) -> dict[str, Any]:
    findings = result["findings"]
    assert type(findings) is list
    return {
        "schema_version": 1,
        "repository_alias": result["repository_alias"],
        "object_format": result["object_format"],
        "base_ref": result["base_ref"],
        "head_ref": result["head_ref"],
        "base_oid": result["base_oid"],
        "head_oid": result["head_oid"],
        "merge_base_oid": result["merge_base_oid"],
        "deterministic_review_sha256": result["deterministic_review_sha256"],
        "findings": [
            finding
            for finding in findings
            if type(finding) is dict and finding.get("source") == "deterministic"
        ],
    }


def _run_cli(
    arguments: Sequence[str],
    *,
    expected_operation: str,
    extra_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], int]:
    command = (sys.executable, "-I", "-m", "repoguard", *arguments)
    environment = _cli_environment()
    if extra_environment is not None:
        for name, value in extra_environment.items():
            if (
                type(name) is not str
                or not re.fullmatch(r"REPOGUARD_ACTION_[A-Z_]{1,64}", name)
                or type(value) is not str
                or any(character in value for character in "\0\r\n")
            ):
                raise _ActionFailure("invalid_product_environment", 70)
            environment[name] = value
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd="/",
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
            try:
                status = process.wait(timeout=_CLI_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                raise _ActionFailure("product_timeout", 75) from None
        except _ActionFailure:
            raise
        except (OSError, subprocess.SubprocessError):
            raise _ActionFailure("product_unavailable", 8) from None
        stdout_size = stdout_file.tell()
        stderr_size = stderr_file.tell()
        if (
            stdout_size < 2
            or stdout_size > _MAX_PRODUCT_ENVELOPE_BYTES + 1
            or stderr_size != 0
            or stderr_size > _MAX_STDERR_BYTES
        ):
            raise _ActionFailure("invalid_product_output", 70)
        stdout_file.seek(0)
        raw = stdout_file.read()
    if not raw.endswith(b"\n") or b"\n" in raw[:-1]:
        raise _ActionFailure("invalid_product_output", 70)
    envelope = _exact_mapping(_parse_canonical(raw[:-1], maximum=_MAX_PRODUCT_ENVELOPE_BYTES))
    if (
        set(envelope) != {"schema_version", "operation", "ok", "result", "error"}
        or envelope.get("schema_version") != 1
        or envelope.get("operation") != expected_operation
        or type(envelope.get("ok")) is not bool
        or (
            envelope["ok"] is True
            and (type(envelope.get("result")) is not dict or envelope.get("error") is not None)
        )
        or (
            envelope["ok"] is False
            and (envelope.get("result") is not None or type(envelope.get("error")) is not dict)
        )
    ):
        raise _ActionFailure("invalid_product_output", 70)
    if envelope["result"] is not None and (
        len(_canonical_bytes(envelope["result"])) > _MAX_CANONICAL_BYTES
    ):
        raise _ActionFailure("invalid_product_output", 70)
    if status not in _known_statuses():
        raise _ActionFailure("invalid_exit_status", 70)
    return envelope, status


def _cli_environment() -> dict[str, str]:
    environment = {
        "GITHUB_ACTIONS": "true",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
    }
    for name in _SECRET_NAMES:
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    return environment


def _load_event() -> dict[str, Any]:
    path = Path(_required_env("REPOGUARD_EVENT_PATH", maximum=4_096))
    if not path.is_absolute():
        raise _ActionFailure("invalid_event", 3)
    raw = _read_regular_file(path, maximum=_MAX_EVENT_BYTES, require_single_link=True)
    return _exact_mapping(_parse_json(raw, maximum=_MAX_EVENT_BYTES, canonical=False))


def _new_private_directory(prefix: str) -> Path:
    runner_temp = Path(_required_env("RUNNER_TEMP", maximum=4_096))
    if not runner_temp.is_absolute():
        raise _ActionFailure("invalid_runner", 8)
    try:
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=runner_temp))
        os.chmod(path, 0o700)
    except OSError:
        raise _ActionFailure("output_unavailable", 70) from None
    return path


def _write_private_file(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        raise _ActionFailure("output_unavailable", 70) from None


def _write_outputs(values: Mapping[str, str]) -> None:
    output_path = Path(_required_env("GITHUB_OUTPUT", maximum=4_096))
    if not output_path.is_absolute():
        raise _ActionFailure("output_unavailable", 70)
    lines: list[str] = []
    for key, value in values.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", key) or any(
            character in value for character in "\r\n\0"
        ):
            raise _ActionFailure("invalid_output", 70)
        lines.append(f"{key}={value}\n")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output_path, flags)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.writelines(lines)
            output.flush()
    except OSError:
        raise _ActionFailure("output_unavailable", 70) from None


def _write_step_summary(
    result: Mapping[str, Any],
    *,
    github_write_supported: bool,
) -> None:
    summary_path = Path(_required_env("GITHUB_STEP_SUMMARY", maximum=4_096))
    if not summary_path.is_absolute():
        raise _ActionFailure("output_unavailable", 70)
    conclusion = _summary_inline(_exact_str(result["conclusion"]))
    finding_count = _exact_int(result["finding_count"])
    highest = result["highest_severity"]
    lines = [
        "# RepoGuard review\n\n",
        f"- Conclusion: **{conclusion}**\n",
        f"- Findings: **{finding_count}**\n",
        (
            "- GitHub publication: **proposal prepared**\n\n"
            if github_write_supported
            else "- GitHub publication: **read-only fork; no proposal created**\n\n"
        ),
    ]
    if highest is not None:
        lines.insert(2, f"- Highest severity: **{_summary_inline(_exact_str(highest))}**\n")
    findings = result["findings"]
    if type(findings) is not list:
        raise _ActionFailure("invalid_result", 70)
    for finding in findings:
        mapping = _exact_mapping(finding)
        severity = _summary_inline(_exact_str(mapping.get("severity")))
        title = _summary_inline(_exact_str(mapping.get("title")))
        message = _summary_block(_exact_str(mapping.get("message")))
        section = f"## {severity}: {title}\n\n<pre>{message}</pre>\n\n"
        if len("".join((*lines, section)).encode("utf-8")) > 60 * 1024:
            lines.append("_Additional findings omitted from the step summary._\n")
            break
        lines.append(section)
    raw = "".join(lines).encode("utf-8")
    sensitive = {
        *(os.environ.get(name, "") for name in _SECRET_NAMES),
        os.environ.get("REPOGUARD_HOST_PROFILE", ""),
    }
    if any(value and value.encode("utf-8") in raw for value in sensitive):
        raise _ActionFailure("private_summary_data", 70)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(summary_path, flags)
        with os.fdopen(descriptor, "ab", closefd=True) as output:
            output.write(raw)
            output.flush()
    except OSError:
        raise _ActionFailure("output_unavailable", 70) from None


def _summary_inline(value: str) -> str:
    normalized = " ".join(value.split())
    return html.escape(normalized, quote=True).replace("@", "@&#8203;")


def _summary_block(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return html.escape(normalized, quote=True).replace("@", "@&#8203;")


def _open_absolute_descriptor(
    path: Path,
    *,
    directory: bool,
    protected_parents: bool = False,
) -> int:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path or len(path.parts) < 2:
        raise OSError("path is not an absolute normalized capability")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = (
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open("/", directory_flags)
    try:
        for index, part in enumerate(path.parts[1:]):
            final = index == len(path.parts) - 2
            flags = directory_flags if (not final or directory) else file_flags
            opened = os.open(part, flags, dir_fd=descriptor)
            metadata = os.fstat(opened)
            if not final or directory:
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(opened)
                    raise OSError("path component is not a directory")
                if protected_parents and (
                    metadata.st_uid not in {0, os.geteuid()}
                    or (
                        metadata.st_mode & 0o022
                        and not (
                            metadata.st_uid == 0
                            and metadata.st_mode & stat.S_ISVTX
                            and metadata.st_mode & 0o002
                        )
                    )
                ):
                    os.close(opened)
                    raise OSError("path component is not protected")
            os.close(descriptor)
            descriptor = opened
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _namespace_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_namespace_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _paths_overlap_lexically(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
    except ValueError:
        pass
    else:
        return True
    try:
        second.relative_to(first)
    except ValueError:
        return False
    return True


def _read_regular_file(
    path: Path,
    *,
    maximum: int,
    require_single_link: bool,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size < 1
                or metadata.st_size > maximum
                or (require_single_link and metadata.st_nlink != 1)
            ):
                raise _ActionFailure("invalid_file", 3)
            raw = source.read(maximum + 1)
    except _ActionFailure:
        raise
    except OSError:
        raise _ActionFailure("invalid_file", 3) from None
    if not raw or len(raw) > maximum:
        raise _ActionFailure("invalid_file", 3)
    return raw


def _canonical_string_array(
    value: str,
    *,
    minimum: int,
    maximum: int,
    item_validator: Any,
) -> tuple[str, ...]:
    raw = value.encode("utf-8")
    decoded = _parse_canonical(raw, maximum=len(raw))
    if type(decoded) is not list or not minimum <= len(decoded) <= maximum:
        raise _ActionFailure("invalid_array", 3)
    result = tuple(item_validator(_exact_str(item)) for item in decoded)
    if tuple(sorted(set(result), key=lambda item: item.encode("utf-8"))) != result:
        raise _ActionFailure("invalid_array", 3)
    return result


def _parse_canonical(raw: bytes, *, maximum: int) -> Any:
    value = _parse_json(raw, maximum=maximum, canonical=True)
    if _canonical_bytes(value) != raw:
        raise _ActionFailure("invalid_json", 3)
    return value


def _parse_json(raw: bytes, *, maximum: int, canonical: bool) -> Any:
    if not raw or len(raw) > maximum or raw.startswith(b"\xef\xbb\xbf"):
        raise _ActionFailure("invalid_json", 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _ActionFailure("invalid_json", 3) from None

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _ActionFailure("invalid_json", 3)
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise _ActionFailure("invalid_json", 3)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except _ActionFailure:
        raise
    except (json.JSONDecodeError, RecursionError):
        raise _ActionFailure("invalid_json", 3) from None
    _validate_json_value(value, depth=0)
    if canonical and _canonical_bytes(value) != raw:
        raise _ActionFailure("invalid_json", 3)
    return value


def _canonical_bytes(value: Any) -> bytes:
    _validate_json_value(value, depth=0)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _ActionFailure("invalid_json", 3) from None


def _validate_json_value(value: Any, *, depth: int) -> None:
    if depth > 64:
        raise _ActionFailure("invalid_json", 3)
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise _ActionFailure("invalid_json", 3) from None
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise _ActionFailure("invalid_json", 3)
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise _ActionFailure("invalid_json", 3)
            _validate_json_value(key, depth=depth + 1)
            _validate_json_value(item, depth=depth + 1)
        return
    raise _ActionFailure("invalid_json", 3)


def _required_env(name: str, *, maximum: int = 16_384) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise _ActionFailure("missing_input", 3)
    return _bounded_text(value, maximum=maximum)


def _optional_env(name: str, *, maximum: int) -> str:
    value = os.environ.get(name, "")
    if value == "":
        return ""
    return _bounded_text(value, maximum=maximum)


def _bounded_text(value: str, *, maximum: int) -> str:
    if type(value) is not str:
        raise _ActionFailure("invalid_input", 3)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise _ActionFailure("invalid_input", 3) from None
    if not encoded or len(encoded) > maximum or any(character in value for character in "\0\r\n"):
        raise _ActionFailure("invalid_input", 3)
    return value


def _enum_env(name: str, accepted: set[str]) -> str:
    value = _required_env(name, maximum=64)
    if value not in accepted:
        raise _ActionFailure("invalid_input", 3)
    return value


def _positive_int(value: str, *, maximum: int) -> int:
    if _DECIMAL.fullmatch(value) is None:
        raise _ActionFailure("invalid_input", 3)
    result = int(value)
    if result > maximum:
        raise _ActionFailure("invalid_input", 3)
    return result


def _sha1(value: str) -> str:
    if _SHA1.fullmatch(value) is None:
        raise _ActionFailure("invalid_input", 3)
    return value


def _sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise _ActionFailure("invalid_input", 3)
    return value


def _name(value: str) -> str:
    if _NAME.fullmatch(value) is None or ".." in value:
        raise _ActionFailure("invalid_input", 3)
    return value


def _full_name(value: str) -> str:
    if _FULL_NAME.fullmatch(value) is None or ".." in value:
        raise _ActionFailure("invalid_input", 3)
    return value


def _repository_path(value: str) -> str:
    _bounded_text(value, maximum=4_096)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
        or "\\" in value
    ):
        raise _ActionFailure("invalid_input", 3)
    return value


def _exact_mapping(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise _ActionFailure("invalid_input", 3)
    return value


def _exact_str(value: Any) -> str:
    if type(value) is not str:
        raise _ActionFailure("invalid_input", 3)
    return value


def _exact_int(value: Any) -> int:
    if type(value) is not int:
        raise _ActionFailure("invalid_input", 3)
    return value


def _known_statuses() -> frozenset[int]:
    return frozenset({0, 2, 3, 4, 5, 6, 7, 8, 70, 75})


if __name__ == "__main__":
    raise SystemExit(main())
