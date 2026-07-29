"""Cross-cutting fail-closed safety matrix for persisted repair requests."""

from __future__ import annotations

import copy
import os
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from repoguard._repair_input import (
    _clone_context_identity,
    _clone_evidence,
    _clone_generation,
    _clone_prompt,
    _clone_review,
    _clone_validation,
    _freeze_repair_request,
    _FrozenRepairRequest,
    _repair_request_from_dict,
    _repair_request_to_dict,
    _RepairRepositoryIdentity,
)
from repoguard._repair_prompt import _repair_prompt_identity
from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    PullRequestInput,
    RepositoryInput,
    collect_evidence,
)
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairProviderKind,
    RepairTarget,
    ValidationCommand,
    ValidationPolicy,
)
from repoguard.review import ReviewResult, RuleId, review_evidence

_GIT = Path("/usr/bin/git")
_IMAGE = f"sha256:{'1' * 64}"

type _PathToken = str | int
type _Mutation = tuple[str, tuple[_PathToken, ...], object]


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return (
        subprocess.run(
            (_GIT, "-C", root, *arguments),
            check=True,
            capture_output=True,
            env=environment,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Repair Matrix",
        "-c",
        "user.email=repair-matrix@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def frozen_request(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, object]]:
    root = tmp_path_factory.mktemp("repair-safety-repository")
    _git(root, "init", "--quiet", "-b", "main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    (root / "secret.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    head_oid = _commit(root, "add private key")
    repository = RepositoryInput(root)
    evidence = collect_evidence(
        repository,
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(evidence)
    target_index = next(
        index
        for index, finding in enumerate(review.findings)
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL
    )
    request = _freeze_repair_request(
        repository,
        _RepairRepositoryIdentity(root.resolve(), (root / ".git").resolve(), "sha1", head_oid),
        evidence,
        review,
        targets=(RepairTarget(target_index, 0),),
        allowed_paths=("secret.pem",),
        generation=RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None),
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
        prompt=_repair_prompt_identity(),
    )
    assert _repair_request_to_dict(_repair_request_from_dict(request)) == request
    yield request


_MUTATIONS: tuple[_Mutation, ...] = (
    ("top-schema", ("schema_version",), 2),
    ("request-digest", ("request_sha256",), "A" * 64),
    ("repository-root-relative", ("repository", "worktree_root"), "relative"),
    ("repository-common-relative", ("repository", "common_dir"), "relative"),
    ("repository-format", ("repository", "object_format"), "sha512"),
    ("repository-head", ("repository", "head_oid"), "A" * 40),
    ("evidence-schema", ("evidence", "schema_version"), 2),
    ("evidence-root", ("evidence", "repository", "root"), "/different"),
    ("evidence-format", ("evidence", "repository", "object_format"), "sha256"),
    ("evidence-head", ("evidence", "revisions", "head_oid"), "2" * 40),
    ("evidence-base", ("evidence", "revisions", "base_oid"), "z" * 40),
    ("evidence-merge-base", ("evidence", "revisions", "merge_base_oid"), "z" * 40),
    ("change-type", ("evidence", "changes", 0, "change_type"), "invalid"),
    ("rename-similarity", ("evidence", "changes", 0, "rename_similarity"), True),
    ("new-path", ("evidence", "changes", 0, "new", "path"), "/secret.pem"),
    ("new-mode", ("evidence", "changes", 0, "new", "mode"), "10064"),
    ("new-oid", ("evidence", "changes", 0, "new", "oid"), "z" * 40),
    ("new-content-kind", ("evidence", "changes", 0, "new", "content_kind"), "invalid"),
    ("hunk-old-start", ("evidence", "changes", 0, "hunks", 0, "old_start"), -1),
    ("hunk-old-count", ("evidence", "changes", 0, "hunks", 0, "old_count"), -1),
    ("hunk-new-count", ("evidence", "changes", 0, "hunks", 0, "new_count"), 999),
    ("line-kind", ("evidence", "changes", 0, "hunks", 0, "lines", 0, "kind"), "bad"),
    (
        "line-old-number",
        ("evidence", "changes", 0, "hunks", 0, "lines", 0, "old_line_number"),
        True,
    ),
    (
        "line-new-number",
        ("evidence", "changes", 0, "hunks", 0, "lines", 0, "new_line_number"),
        -1,
    ),
    (
        "line-content-utf8",
        ("evidence", "changes", 0, "hunks", 0, "lines", 0, "content"),
        "\ud800",
    ),
    (
        "line-trailing-newline",
        ("evidence", "changes", 0, "hunks", 0, "lines", 0, "has_trailing_newline"),
        1,
    ),
    ("review-schema", ("review", "schema_version"), 2),
    ("review-root", ("review", "repository", "root"), "/different"),
    ("review-head", ("review", "revisions", "head_oid"), "2" * 40),
    ("finding-rule", ("review", "findings", 0, "rule_id"), "invalid"),
    ("finding-category", ("review", "findings", 0, "category"), "invalid"),
    ("finding-severity", ("review", "findings", 0, "severity"), "invalid"),
    ("finding-title-empty", ("review", "findings", 0, "title"), ""),
    ("finding-title-control", ("review", "findings", 0, "title"), "bad\x00title"),
    ("finding-message", ("review", "findings", 0, "message"), ""),
    ("finding-remediation", ("review", "findings", 0, "remediation"), ""),
    ("reference-path", ("review", "findings", 0, "references", 0, "path"), "../secret"),
    ("reference-side", ("review", "findings", 0, "references", 0, "side"), "invalid"),
    ("reference-oid", ("review", "findings", 0, "references", 0, "oid"), "2" * 40),
    ("reference-start", ("review", "findings", 0, "references", 0, "start_line"), 0),
    ("reference-end", ("review", "findings", 0, "references", 0, "end_line"), 0),
    ("target-finding", ("targets", 0, "finding_index"), 999),
    ("target-reference", ("targets", 0, "reference_index"), 999),
    ("allowed-path", ("allowed_paths", 0), ".git/config"),
    ("allowed-path-binding", ("allowed_paths", 0), "README.md"),
    ("generation-mode", ("generation", "mode"), "provider"),
    ("generation-provider", ("generation", "provider_kind"), "invalid"),
    ("generation-query-limit", ("generation", "max_queries"), 0),
    ("validation-image", ("validation", "image_id"), "sha256:invalid"),
    ("validation-argv", ("validation", "commands", 0, "argv", 0), "python"),
    ("validation-cwd", ("validation", "commands", 0, "cwd"), "relative"),
    ("prompt-name", ("prompt", "resource_name"), "agent_review"),
    ("prompt-schema", ("prompt", "schema_version"), 2),
    ("prompt-digest", ("prompt", "system_sha256"), "A" * 64),
    ("retrieval-policy", ("retrieval_policy", "algorithm"), "different"),
    ("patch-policy", ("patch_policy", "allow_deletions"), True),
    ("commit-policy", ("commit_policy", "message"), "different"),
)


@pytest.mark.parametrize(("name", "path", "replacement"), _MUTATIONS, ids=lambda value: str(value))
def test_persisted_request_tampering_fails_closed(
    frozen_request: dict[str, object],
    name: str,
    path: tuple[_PathToken, ...],
    replacement: object,
) -> None:
    del name
    mutated = copy.deepcopy(frozen_request)
    _replace_path(mutated, path, replacement)

    with pytest.raises((TypeError, ValueError)):
        _repair_request_from_dict(mutated)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("targets", []),
        ("targets", {}),
        ("allowed_paths", []),
        ("allowed_paths", {}),
        ("context_identity", {}),
        ("retrieval_policy", []),
        ("patch_policy", []),
        ("commit_policy", []),
    ),
)
def test_persisted_request_structural_substitution_fails_closed(
    frozen_request: dict[str, object],
    field: str,
    value: object,
) -> None:
    mutated = copy.deepcopy(frozen_request)
    mutated[field] = value

    with pytest.raises((TypeError, ValueError)):
        _repair_request_from_dict(mutated)


@pytest.mark.parametrize("operation", ("missing", "extra"))
def test_persisted_request_requires_exact_top_level_schema(
    frozen_request: dict[str, object],
    operation: str,
) -> None:
    mutated = copy.deepcopy(frozen_request)
    if operation == "missing":
        del mutated["commit_policy"]
    else:
        mutated["unexpected"] = True

    with pytest.raises((TypeError, ValueError)):
        _repair_request_from_dict(mutated)


def test_frozen_request_digest_and_exact_type_are_rechecked(
    frozen_request: dict[str, object],
) -> None:
    decoded = _repair_request_from_dict(copy.deepcopy(frozen_request))
    assert _repair_request_to_dict(decoded) == frozen_request

    invalid_serializer = cast(Callable[[object], dict[str, object]], _repair_request_to_dict)
    with pytest.raises(TypeError, match="exact _FrozenRepairRequest"):
        invalid_serializer(frozen_request)

    object.__setattr__(decoded, "request_sha256", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        _repair_request_to_dict(decoded)


_RECORD_MUTATIONS = (
    "repository-head",
    "evidence-schema",
    "evidence-repository-type",
    "evidence-changes-list",
    "evidence-root-relative",
    "evidence-root-utf8",
    "evidence-format",
    "evidence-revisions-type",
    "evidence-ref-empty",
    "evidence-oid",
    "change-type",
    "change-hunks-list",
    "change-rename-similarity",
    "change-sides",
    "change-duplicate-version",
    "change-renamed-same-path",
    "change-binary-hunks",
    "change-duplicate-hunk-coordinates",
    "version-symlink-kind",
    "hunk-lines-list",
    "hunk-duplicate-new-line",
    "review-schema",
    "review-repository-type",
    "review-findings-list",
    "finding-type",
    "finding-references-list",
    "finding-no-references",
    "finding-duplicate-references",
    "reference-partial-range",
    "reference-outside-hunk",
    "review-duplicate-findings",
    "targets-list",
    "target-type",
    "target-duplicate",
    "deterministic-nonprivate",
    "provider-private",
    "mixed-private-only",
    "generation-record",
    "validation-record",
    "prompt-record",
)


@pytest.mark.parametrize("mutation", _RECORD_MUTATIONS)
def test_mutated_exact_records_are_rejected_by_public_freeze(
    frozen_request: dict[str, object],
    mutation: str,
) -> None:
    request = _repair_request_from_dict(copy.deepcopy(frozen_request))
    expected = _mutate_exact_request(request, mutation)

    with pytest.raises(RepairError) as captured:
        _freeze_repair_request(
            RepositoryInput(request.repository.worktree_root),
            request.repository,
            request.evidence,
            request.review,
            targets=request.targets,
            allowed_paths=request.allowed_paths,
            generation=request.generation,
            validation=request.validation,
            prompt=request.prompt,
            context_identity=request.context_identity,
        )

    assert captured.value.code is expected
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_clone_boundaries_reject_nonexact_records(
    frozen_request: dict[str, object],
) -> None:
    request = _repair_request_from_dict(copy.deepcopy(frozen_request))
    calls: tuple[tuple[Callable[[object], object], RepairErrorCode], ...] = (
        (cast(Callable[[object], object], _clone_evidence), RepairErrorCode.INVALID_EVIDENCE),
        (cast(Callable[[object], object], _clone_generation), RepairErrorCode.INVALID_CONFIG),
        (cast(Callable[[object], object], _clone_validation), RepairErrorCode.INVALID_CONFIG),
        (cast(Callable[[object], object], _clone_prompt), RepairErrorCode.INVALID_CONFIG),
        (cast(Callable[[object], object], _clone_context_identity), RepairErrorCode.INVALID_CONFIG),
    )
    for clone, expected in calls:
        with pytest.raises(RepairError) as captured:
            clone(object())
        assert captured.value.code is expected
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    with pytest.raises(RepairError) as captured:
        _clone_review(cast(ReviewResult, object()), request.evidence)
    assert captured.value.code is RepairErrorCode.INVALID_REVIEW
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def _mutate_exact_request(
    request: _FrozenRepairRequest,
    mutation: str,
) -> RepairErrorCode:
    evidence = request.evidence
    review = request.review
    change = evidence.changes[0]
    assert change.new is not None
    hunk = change.hunks[0]
    line = hunk.lines[0]
    finding = review.findings[0]
    reference = finding.references[0]
    if mutation == "repository-head":
        object.__setattr__(request.repository, "head_oid", "z" * 40)
        return RepairErrorCode.INVALID_CONFIG
    if mutation == "evidence-schema":
        object.__setattr__(evidence, "schema_version", 2)
        return RepairErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA
    if mutation == "evidence-repository-type":
        object.__setattr__(evidence, "repository", object())
    elif mutation == "evidence-changes-list":
        object.__setattr__(evidence, "changes", list(evidence.changes))
    elif mutation == "evidence-root-relative":
        object.__setattr__(evidence.repository, "root", Path("relative"))
    elif mutation == "evidence-root-utf8":
        object.__setattr__(evidence.repository, "root", Path("/tmp/\ud800"))
    elif mutation == "evidence-format":
        object.__setattr__(evidence.repository, "object_format", "sha512")
    elif mutation == "evidence-revisions-type":
        object.__setattr__(evidence, "revisions", object())
    elif mutation == "evidence-ref-empty":
        object.__setattr__(evidence.revisions, "base_ref", "")
    elif mutation == "evidence-oid":
        object.__setattr__(evidence.revisions, "base_oid", "z" * 40)
    elif mutation == "change-type":
        object.__setattr__(change, "change_type", "invalid")
    elif mutation == "change-hunks-list":
        object.__setattr__(change, "hunks", list(change.hunks))
    elif mutation == "change-rename-similarity":
        object.__setattr__(change, "rename_similarity", 0)
    elif mutation == "change-sides":
        object.__setattr__(change, "old", change.new)
    elif mutation == "change-duplicate-version":
        object.__setattr__(evidence, "changes", (change, change))
    elif mutation == "change-renamed-same-path":
        object.__setattr__(change, "change_type", ChangeType.RENAMED)
        object.__setattr__(change, "rename_similarity", 100)
        object.__setattr__(change, "old", change.new)
    elif mutation == "change-binary-hunks":
        object.__setattr__(change.new, "content_kind", ContentKind.BINARY)
    elif mutation == "change-duplicate-hunk-coordinates":
        empty = DiffHunkEvidence(hunk.old_start, 0, hunk.new_start, 0, ())
        object.__setattr__(change, "hunks", (empty, empty))
    elif mutation == "version-symlink-kind":
        object.__setattr__(change.new, "mode", "120000")
    elif mutation == "hunk-lines-list":
        object.__setattr__(hunk, "lines", list(hunk.lines))
    elif mutation == "hunk-duplicate-new-line":
        duplicate = replace(hunk, old_count=0, new_count=1, lines=(line,))
        object.__setattr__(change, "hunks", (hunk, duplicate))
    elif mutation == "review-schema":
        object.__setattr__(review, "schema_version", 2)
        return RepairErrorCode.UNSUPPORTED_REVIEW_SCHEMA
    elif mutation == "review-repository-type":
        object.__setattr__(review, "repository", object())
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "review-findings-list":
        object.__setattr__(review, "findings", list(review.findings))
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "finding-type":
        object.__setattr__(review, "findings", (object(),))
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "finding-references-list":
        object.__setattr__(finding, "references", list(finding.references))
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "finding-no-references":
        object.__setattr__(finding, "references", ())
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "finding-duplicate-references":
        object.__setattr__(finding, "references", (reference, reference))
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "reference-partial-range":
        object.__setattr__(reference, "end_line", None)
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "reference-outside-hunk":
        object.__setattr__(reference, "start_line", 999)
        object.__setattr__(reference, "end_line", 999)
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "review-duplicate-findings":
        object.__setattr__(review, "findings", (finding, finding))
        return RepairErrorCode.INVALID_REVIEW
    elif mutation == "targets-list":
        object.__setattr__(request, "targets", list(request.targets))
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "target-type":
        object.__setattr__(request, "targets", (object(),))
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "target-duplicate":
        object.__setattr__(request, "targets", (request.targets[0], request.targets[0]))
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "deterministic-nonprivate":
        object.__setattr__(finding, "rule_id", RuleId.MERGE_CONFLICT_MARKER)
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "provider-private":
        object.__setattr__(
            request,
            "generation",
            RepairGenerationPolicy(
                RepairGenerationMode.PROVIDER,
                RepairProviderKind.OPENAI,
                "gpt-fixed",
            ),
        )
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "mixed-private-only":
        object.__setattr__(
            request,
            "generation",
            RepairGenerationPolicy(
                RepairGenerationMode.MIXED,
                RepairProviderKind.OPENAI,
                "gpt-fixed",
            ),
        )
        return RepairErrorCode.INVALID_TARGETS
    elif mutation == "generation-record":
        object.__setattr__(request.generation, "max_queries", 0)
        return RepairErrorCode.INVALID_CONFIG
    elif mutation == "validation-record":
        object.__setattr__(request.validation, "image_id", "invalid")
        return RepairErrorCode.INVALID_CONFIG
    elif mutation == "prompt-record":
        object.__setattr__(request.prompt, "system_sha256", "invalid")
        return RepairErrorCode.INVALID_CONFIG
    else:
        raise AssertionError(f"unknown exact-record mutation: {mutation}")
    return RepairErrorCode.INVALID_EVIDENCE


def _replace_path(
    root: dict[str, object],
    path: tuple[_PathToken, ...],
    replacement: object,
) -> None:
    current: object = root
    for token in path[:-1]:
        if isinstance(token, str):
            current = cast(dict[str, object], current)[token]
        else:
            assert isinstance(token, int)
            current = cast(list[object], current)[token]
    final = path[-1]
    if isinstance(final, str):
        cast(dict[str, object], current)[final] = replacement
    else:
        assert isinstance(final, int)
        cast(list[object], current)[final] = replacement
