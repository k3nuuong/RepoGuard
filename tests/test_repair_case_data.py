"""Strict deterministic runner for the packaged M5 safe-repair safety cases."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Never, cast

import pytest

import repoguard._repair_retrieval as repair_retrieval
import repoguard._repair_sandbox as sandbox
import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
import repoguard._retrieval as retrieval_core
from repoguard._repair_git import (
    _capture_repository,
    _materialize_candidate,
    _MaterializedCandidate,
    _PublicationOutcome,
    _PublicationResult,
    _publish_repair_ref,
    _repair_ref,
    _RepositoryIdentity,
)
from repoguard._repair_models import _can_transition, _domain_digest
from repoguard._repair_patch import _parse_wire_patch
from repoguard._repair_prompt import (
    _invoke_repair_provider,
    _render_repair_prompt,
    _RepairPromptFile,
    _RepairPromptFinding,
)
from repoguard._repair_secrets import (
    _prepare_private_key_plan,
    _RepairFileContent,
    _SelectedPrivateKeyRange,
    _validate_final_changed_files,
)
from repoguard._repair_workflow import _ApplicationRefOutcome
from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence
from repoguard.providers import LLMRequest, LLMResponse, OpenAIProvider, TokenUsage
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairContextOutcome,
    RepairContextSummary,
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairManager,
    RepairManagerConfig,
    RepairProviderKind,
    RepairSession,
    RepairState,
    RepairTarget,
    ValidationCommand,
    ValidationCommandResult,
    ValidationFailureKind,
    ValidationPolicy,
    validation_policy_to_dict,
)
from repoguard.retrieval import (
    ContextIndex,
    ContextQuery,
    EmbeddingDevice,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalError,
    RetrievalErrorCode,
    RetrievalResult,
    RetrievalStage,
)
from repoguard.review import RuleId, review_evidence

_CASE_NAMES = (
    "success-existing",
    "success-new",
    "success-multi-file",
    "success-private-only",
    "success-mixed",
    "success-context",
    "success-context-degraded",
    "success-dirty-linked-alternates",
    "success-sha256",
    "success-idempotent-apply",
    "reject-cr",
    "reject-nul",
    "reject-extended-header",
    "reject-delete-rename-mode",
    "reject-path-traversal",
    "reject-git-component",
    "reject-patch-byte-limit",
    "reject-path-line-limit",
    "reject-unselected-private-key",
    "reject-added-private-key",
    "adversarial-rootful",
    "adversarial-seccomp",
    "adversarial-timeout-output-resource",
    "adversarial-residual-process",
    "adversarial-tracked-mutation",
    "adversarial-forged-report",
    "adversarial-stale-approval",
    "adversarial-foreign-ref",
    "adversarial-cancel-late-result",
    "adversarial-crash-recovery",
)
_EXPECTED_DRIVER_VARIANTS = {
    "success-existing": ("patch_accept", "modified"),
    "success-new": ("patch_accept", "new_file"),
    "success-multi-file": ("patch_accept", "multi_file"),
    "success-private-only": ("private_plan", "deterministic"),
    "success-mixed": ("private_plan", "mixed_provider"),
    "success-context": ("context_summary", "used"),
    "success-context-degraded": ("context_summary", "degraded"),
    "success-dirty-linked-alternates": ("workflow_contract", "dirty_linked_alternates"),
    "success-sha256": ("workflow_contract", "sha256"),
    "success-idempotent-apply": ("workflow_contract", "idempotent_apply"),
    "reject-cr": ("patch_reject", "cr"),
    "reject-nul": ("patch_reject", "nul"),
    "reject-extended-header": ("patch_reject", "extended_header"),
    "reject-delete-rename-mode": ("patch_reject", "delete_rename_mode"),
    "reject-path-traversal": ("patch_reject", "path_traversal"),
    "reject-git-component": ("patch_reject", "git_component"),
    "reject-patch-byte-limit": ("patch_reject", "byte_limit"),
    "reject-path-line-limit": ("patch_reject", "path_line_limit"),
    "reject-unselected-private-key": ("secret_reject", "unselected"),
    "reject-added-private-key": ("secret_reject", "added"),
    "adversarial-rootful": ("sandbox_capability", "rootful"),
    "adversarial-seccomp": ("seccomp_policy", "forbidden_syscall"),
    "adversarial-timeout-output-resource": (
        "validation_failure",
        "timeout_output_resource",
    ),
    "adversarial-residual-process": ("validation_failure", "residual_process"),
    "adversarial-tracked-mutation": ("validation_failure", "tracked_mutation"),
    "adversarial-forged-report": ("validation_failure", "forged_report"),
    "adversarial-stale-approval": ("workflow_contract", "stale_approval"),
    "adversarial-foreign-ref": ("workflow_contract", "foreign_ref"),
    "adversarial-cancel-late-result": ("workflow_contract", "cancel_late_result"),
    "adversarial-crash-recovery": ("workflow_contract", "crash_recovery"),
}
_SESSION_ID = "a" * 64
_CANDIDATE_ID = "b" * 64
_IMAGE_ID = "sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_GIT = Path("/usr/bin/git")
_CONTEXT_MODEL = "BAAI/bge-small-en-v1.5"
_CONTEXT_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"
_MODIFIED_PATCH = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
_NEW_PATCH = "--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+new\n"
_MULTI_PATCH = _MODIFIED_PATCH + _NEW_PATCH
_APP_PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"


class _Category(StrEnum):
    SUCCESS = "success"
    REJECTION = "rejection"
    ADVERSARIAL = "adversarial"


class _RefOutcome(StrEnum):
    PUBLISHED = "published"
    ALREADY_PRESENT = "already_present"
    NOT_ATTEMPTED = "not_attempted"
    FOREIGN = "foreign"
    EXPECTED = "expected"


@dataclass(frozen=True, slots=True)
class _ExpectedOutcome:
    session_state: RepairState
    error_code: RepairErrorCode | None
    ref_outcome: _RefOutcome
    validation_failure_kinds: tuple[ValidationFailureKind, ...]


@dataclass(frozen=True, slots=True)
class _Case:
    name: str
    category: _Category
    driver: str
    variant: str
    expected: _ExpectedOutcome


@dataclass(frozen=True, slots=True)
class _Dataset:
    schema_version: int
    cases: tuple[_Case, ...]


@dataclass(frozen=True, slots=True)
class _RunContext:
    tmp_path: Path
    monkeypatch: pytest.MonkeyPatch


@dataclass(frozen=True, slots=True)
class _GitFixture:
    root: Path
    head_oid: str
    source: _RepositoryIdentity
    candidate: _MaterializedCandidate


@dataclass(frozen=True, slots=True)
class _WorkflowFixture:
    root: Path
    head_oid: str
    manager: RepairManager
    session: RepairSession


@dataclass(frozen=True, slots=True)
class _ProviderWorkflowFixture:
    workflow: _WorkflowFixture
    provider: OpenAIProvider
    context_index: ContextIndex | None


class _FakeIndexState:
    def __init__(self, identity: IndexIdentity) -> None:
        self._identity = identity
        self._closed = False

    @property
    def identity(self) -> IndexIdentity:
        return self._identity

    @property
    def statistics(self) -> IndexStatistics:
        return IndexStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True


class _PublicationCrash(BaseException):
    pass


_APPLIED_PUBLISHED = _ExpectedOutcome(
    RepairState.APPLIED,
    None,
    _RefOutcome.PUBLISHED,
    (),
)
_FAILED_PATCH_INVALID = _ExpectedOutcome(
    RepairState.FAILED,
    RepairErrorCode.PATCH_INVALID,
    _RefOutcome.NOT_ATTEMPTED,
    (),
)
_EXPECTED_OUTCOMES = {
    **{name: _APPLIED_PUBLISHED for name in _CASE_NAMES[:9]},
    "success-idempotent-apply": _ExpectedOutcome(
        RepairState.APPLIED,
        None,
        _RefOutcome.ALREADY_PRESENT,
        (),
    ),
    **{name: _FAILED_PATCH_INVALID for name in _CASE_NAMES[10:16]},
    "reject-patch-byte-limit": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.PATCH_LIMIT,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "reject-path-line-limit": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.PATCH_LIMIT,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "reject-unselected-private-key": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.INVALID_TARGETS,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "reject-added-private-key": _FAILED_PATCH_INVALID,
    "adversarial-rootful": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.SANDBOX_UNAVAILABLE,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "adversarial-seccomp": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.SANDBOX_UNAVAILABLE,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "adversarial-timeout-output-resource": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.VALIDATION_FAILED,
        _RefOutcome.NOT_ATTEMPTED,
        (
            ValidationFailureKind.COMMAND_TIMEOUT,
            ValidationFailureKind.OUTPUT_LIMIT,
            ValidationFailureKind.RESOURCE_LIMIT,
        ),
    ),
    "adversarial-residual-process": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.VALIDATION_FAILED,
        _RefOutcome.NOT_ATTEMPTED,
        (ValidationFailureKind.RESIDUAL_PROCESS,),
    ),
    "adversarial-tracked-mutation": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.VALIDATION_FAILED,
        _RefOutcome.NOT_ATTEMPTED,
        (ValidationFailureKind.TRACKED_TREE_CHANGED,),
    ),
    "adversarial-forged-report": _ExpectedOutcome(
        RepairState.FAILED,
        RepairErrorCode.VALIDATION_FAILED,
        _RefOutcome.NOT_ATTEMPTED,
        (ValidationFailureKind.SANDBOX_REPORT_INVALID,),
    ),
    "adversarial-stale-approval": _ExpectedOutcome(
        RepairState.VALIDATED,
        RepairErrorCode.APPROVAL_MISMATCH,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "adversarial-foreign-ref": _ExpectedOutcome(
        RepairState.APPROVED,
        RepairErrorCode.REF_CONFLICT,
        _RefOutcome.FOREIGN,
        (),
    ),
    "adversarial-cancel-late-result": _ExpectedOutcome(
        RepairState.CANCELLED,
        None,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    ),
    "adversarial-crash-recovery": _ExpectedOutcome(
        RepairState.APPLIED,
        None,
        _RefOutcome.EXPECTED,
        (),
    ),
}


def _resource_bytes() -> bytes:
    return (
        resources.files("repoguard").joinpath("evaluation_data", "m5_safe_repair.json").read_bytes()
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Never:
    raise ValueError("non-finite JSON number")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _exact_mapping(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("expected an exact object")
    mapping = cast(dict[str, object], value)
    if set(mapping) != keys:
        raise ValueError("object keys do not match schema")
    return mapping


def _exact_string(value: object) -> str:
    if type(value) is not str:
        raise ValueError("expected an exact string")
    return value


def _enum_value[EnumType: StrEnum](enum_type: type[EnumType], value: object) -> EnumType:
    try:
        return enum_type(_exact_string(value))
    except ValueError:
        raise ValueError("unknown enum value") from None


def _optional_error_code(value: object) -> RepairErrorCode | None:
    if value is None:
        return None
    return _enum_value(RepairErrorCode, value)


def _failure_kinds(value: object) -> tuple[ValidationFailureKind, ...]:
    if type(value) is not list:
        raise ValueError("validation_failure_kinds must be an exact array")
    raw = cast(list[object], value)
    result = tuple(_enum_value(ValidationFailureKind, item) for item in raw)
    if len(set(result)) != len(result):
        raise ValueError("validation failure kinds must be unique")
    return result


def _decode_dataset(raw: bytes) -> _Dataset:
    if type(raw) is not bytes or not raw or raw.endswith(b"\n"):
        raise ValueError("dataset bytes are not canonical")
    try:
        parsed: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("dataset JSON is invalid") from None
    if raw != _canonical_bytes(parsed):
        raise ValueError("dataset JSON is not canonical")
    root = _exact_mapping(parsed, {"schema_version", "cases"})
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("dataset schema version is unsupported")
    raw_cases = root["cases"]
    if type(raw_cases) is not list or len(raw_cases) != 30:
        raise ValueError("dataset must contain exactly 30 cases")

    cases: list[_Case] = []
    for raw_case in cast(list[object], raw_cases):
        case_mapping = _exact_mapping(
            raw_case,
            {"name", "category", "driver", "variant", "expected"},
        )
        expected_mapping = _exact_mapping(
            case_mapping["expected"],
            {
                "session_state",
                "error_code",
                "ref_outcome",
                "validation_failure_kinds",
            },
        )
        cases.append(
            _Case(
                _exact_string(case_mapping["name"]),
                _enum_value(_Category, case_mapping["category"]),
                _exact_string(case_mapping["driver"]),
                _exact_string(case_mapping["variant"]),
                _ExpectedOutcome(
                    _enum_value(RepairState, expected_mapping["session_state"]),
                    _optional_error_code(expected_mapping["error_code"]),
                    _enum_value(_RefOutcome, expected_mapping["ref_outcome"]),
                    _failure_kinds(expected_mapping["validation_failure_kinds"]),
                ),
            )
        )

    names = tuple(case.name for case in cases)
    if names != _CASE_NAMES or len(set(names)) != 30:
        raise ValueError("dataset case names or order changed")
    for index, case in enumerate(cases):
        expected_category = (
            _Category.SUCCESS
            if index < 10
            else _Category.REJECTION
            if index < 20
            else _Category.ADVERSARIAL
        )
        if case.category is not expected_category:
            raise ValueError("dataset category order changed")
        if (case.driver, case.variant) != _EXPECTED_DRIVER_VARIANTS[case.name]:
            raise ValueError("dataset driver mapping changed")
        if case.expected != _EXPECTED_OUTCOMES[case.name]:
            raise ValueError("dataset expected outcome changed")
    return _Dataset(1, tuple(cases))


def _generation_policy(
    mode: RepairGenerationMode = RepairGenerationMode.DETERMINISTIC,
) -> RepairGenerationPolicy:
    if mode is RepairGenerationMode.DETERMINISTIC:
        return RepairGenerationPolicy(mode, None, None)
    return RepairGenerationPolicy(mode, RepairProviderKind.OPENAI, "gpt-fixed")


def _validation_policy() -> ValidationPolicy:
    return ValidationPolicy(
        _IMAGE_ID,
        (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
    )


def _git_environment(home: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        (_GIT, "-C", root, *arguments),
        check=True,
        capture_output=True,
        env=_git_environment(root),
    ).stdout


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Case Runner",
        "-c",
        "user.email=case-runner@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _initialize_git_repository(root: Path, *, object_format: str = "sha1") -> str:
    root.mkdir(parents=True)
    _git(root, "init", "--quiet", f"--object-format={object_format}", "-b", "main")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    return _commit(root, "base")


def _git_fixture(context: _RunContext, variant: str) -> _GitFixture:
    case_root = context.tmp_path / f"git-{variant}"
    case_root.mkdir(mode=0o700)
    if variant == "dirty_linked_alternates":
        original = case_root / "original"
        head_oid = _initialize_git_repository(original)
        shared = case_root / "shared"
        subprocess.run(
            (_GIT, "clone", "--quiet", "--shared", original, shared),
            check=True,
            capture_output=True,
            env=_git_environment(case_root),
        )
        linked = case_root / "linked"
        _git(shared, "worktree", "add", "--quiet", "--detach", str(linked), head_oid)
        (linked / "app.py").write_text("dirty worktree\n", encoding="utf-8")
        nested = linked / "untracked"
        nested.mkdir()
        (nested / "ignored.txt").write_text("untracked\n", encoding="utf-8")
        repository = RepositoryInput(nested)
        root = linked
    else:
        object_format = "sha256" if variant == "sha256" else "sha1"
        root = case_root / "source"
        head_oid = _initialize_git_repository(root, object_format=object_format)
        repository = RepositoryInput(root)

    source = _capture_repository(repository, _GIT, head_oid=head_oid)
    parsed = _parse_wire_patch(
        _APP_PATCH,
        allowed_paths=("app.py",),
        policy=_generation_policy(),
    )
    candidate = _materialize_candidate(
        source,
        _GIT,
        case_root / "candidate",
        (parsed,),
    )
    assert candidate.changed_paths == ("app.py",)
    assert candidate.changed_line_count == 2
    assert (candidate.root / "app.py").read_text(encoding="utf-8") == "value = 2\n"
    return _GitFixture(root, head_oid, source, candidate)


def _workflow_fixture(context: _RunContext, variant: str) -> _WorkflowFixture:
    case_root = context.tmp_path / f"workflow-{variant}"
    repository: RepositoryInput
    if variant == "dirty_linked_alternates":
        original = case_root / "original"
        original.mkdir(parents=True)
        _git(original, "init", "--quiet", "-b", "main")
        (original / "README.md").write_text("base\n", encoding="utf-8")
        base_oid = _commit(original, "base")
        (original / "secret.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        head_oid = _commit(original, "add private material")
        shared = case_root / "shared"
        subprocess.run(
            (_GIT, "clone", "--quiet", "--shared", original, shared),
            check=True,
            capture_output=True,
            env=_git_environment(case_root),
        )
        linked = case_root / "linked"
        _git(shared, "worktree", "add", "--quiet", "--detach", str(linked), head_oid)
        (linked / "README.md").write_text("dirty worktree\n", encoding="utf-8")
        (linked / "untracked").mkdir()
        (linked / "untracked" / "ignored.txt").write_text("untracked\n", encoding="utf-8")
        root = linked
        repository = RepositoryInput(linked / "untracked")
    else:
        object_format = "sha256" if variant == "sha256" else "sha1"
        root = case_root / "source"
        root.mkdir(parents=True)
        _git(root, "init", "--quiet", f"--object-format={object_format}", "-b", "main")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        base_oid = _commit(root, "base")
        (root / "secret.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        head_oid = _commit(root, "add private material")
        repository = RepositoryInput(root)
    bundle = collect_evidence(
        repository,
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    target_index = next(
        index
        for index, finding in enumerate(review.findings)
        if finding.rule_id is RuleId.PRIVATE_KEY_MATERIAL
    )
    context.monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = RepairManagerConfig(
        case_root / "runtime",
        _GIT,
        Path("/bin/true"),
        case_root / "docker.sock",
    )
    manager = RepairManager(repository, config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(target_index, 0),),
        allowed_paths=("secret.pem",),
        generation=_generation_policy(),
        validation=_validation_policy(),
    )
    return _WorkflowFixture(root, head_oid, manager, session)


def _provider_workflow_fixture(
    context: _RunContext,
    variant: str,
    *,
    patch: str,
    allowed_paths: tuple[str, ...],
    generation: RepairGenerationPolicy | None = None,
    include_private: bool = False,
    context_outcome: RepairContextOutcome | None = None,
) -> _ProviderWorkflowFixture:
    case_root = context.tmp_path / f"provider-workflow-{variant}"
    root = case_root / "source"
    (root / "src").mkdir(parents=True)
    _git(root, "init", "--quiet", "-b", "main")
    (root / "src" / "app.py").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    (root / "src" / "app.py").write_text(
        "old\n<<<<<<< HEAD\nleft\n=======\nright\n>>>>>>> branch\n",
        encoding="utf-8",
    )
    if include_private:
        (root / "secret.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
    head_oid = _commit(root, "selected repair findings")
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    selected_rules = {RuleId.MERGE_CONFLICT_MARKER}
    if include_private:
        selected_rules.add(RuleId.PRIVATE_KEY_MATERIAL)
    targets = tuple(
        RepairTarget(index, 0)
        for index, finding in enumerate(review.findings)
        if finding.rule_id in selected_rules
    )
    assert len(targets) == len(selected_rules)

    context_index: ContextIndex | None = None
    if context_outcome is not None:
        identity = IndexIdentity(
            root.resolve(),
            "sha1",
            head_oid,
            (RetrievalChannel.TEXT,),
            "3" * 64,
            _CONTEXT_MODEL,
            _CONTEXT_MODEL_REVISION,
            "4" * 64,
            384,
            EmbeddingDevice.CPU,
        )
        context_index = ContextIndex(_FakeIndexState(identity))
        context.monkeypatch.setattr(workflow_module, "_validate_live_index", lambda *_: None)
        if context_outcome is RepairContextOutcome.USED:
            context.monkeypatch.setattr(repair_retrieval, "_validate_live_index", lambda *_: None)

            def retrieve(
                _: ContextIndex,
                queries: tuple[ContextQuery, ...],
                *,
                deadline: float,
            ) -> RetrievalResult:
                assert type(deadline) is float
                query_texts = tuple(query.text for query in queries)
                query_sha256 = retrieval_core._validated_query_digest(query_texts)
                return RetrievalResult(identity, query_sha256, 0, 0, 0, ())

            context.monkeypatch.setattr(retrieval_core, "_retrieve_context_queries", retrieve)
        else:

            def fail_retrieval(*_: object) -> None:
                raise RetrievalError(
                    RetrievalErrorCode.BACKEND_FAILED,
                    RetrievalStage.VALIDATE,
                )

            context.monkeypatch.setattr(
                repair_retrieval,
                "_validate_live_index",
                fail_retrieval,
            )

    policy = _generation_policy(RepairGenerationMode.PROVIDER) if generation is None else generation
    context.monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = RepairManagerConfig(
        case_root / "runtime",
        _GIT,
        Path("/bin/true"),
        case_root / "docker.sock",
    )
    manager = RepairManager(RepositoryInput(root), config)
    session = manager.create_session(
        bundle,
        review,
        targets=targets,
        allowed_paths=allowed_paths,
        generation=policy,
        validation=_validation_policy(),
        context_index=context_index,
    )
    response_text = json.dumps(
        {"patch": patch, "schema_version": 1},
        separators=(",", ":"),
        sort_keys=True,
    )

    def complete(_: OpenAIProvider, request: LLMRequest) -> LLMResponse:
        assert request.model == "gpt-fixed"
        return LLMResponse(response_text, TokenUsage(4, 3, 7))

    context.monkeypatch.setattr(OpenAIProvider, "complete", complete)
    return _ProviderWorkflowFixture(
        _WorkflowFixture(root, head_oid, manager, session),
        object.__new__(OpenAIProvider),
        context_index,
    )


def _install_case_sandbox(
    context: _RunContext,
    *,
    late_action: Callable[[], None] | None = None,
    configured_report: sandbox._SandboxReport | None = None,
) -> None:
    assets = sandbox._load_sandbox_assets()
    capabilities = sandbox._SandboxCapabilities(
        "29.6.1",
        "29.6.1",
        "1.55",
        "x86_64",
        "2",
        ("name=rootless", "name=seccomp,profile=builtin"),
        _IMAGE_ID,
        assets.sandbox_manifest_sha256,
    )

    def prepare(
        _: RepairManagerConfig,
        __: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> sandbox._SandboxCapabilities:
        mount_identity_check()
        assert probe_path.read_bytes() == assets.probe
        assert seccomp_path.read_bytes() == assets.seccomp_json
        mount_identity_check()
        return capabilities

    def run(
        _: RepairManagerConfig,
        policy: ValidationPolicy,
        __: sandbox._SandboxCapabilities,
        **arguments: object,
    ) -> sandbox._SandboxValidationOutcome:
        session_id = cast(str, arguments["session_id"])
        candidate_id = cast(str, arguments["candidate_id"])
        register_intent = cast(
            Callable[[sandbox._SandboxRunIntent], bool],
            arguments["register_intent"],
        )
        register_run = cast(
            Callable[[sandbox._SandboxRunIdentity], bool],
            arguments["register_run"],
        )
        before_remove = cast(
            Callable[[sandbox._SandboxValidationOutcome], None],
            arguments["before_remove"],
        )
        mount_identity_check = cast(Callable[[], None], arguments["mount_identity_check"])
        mount_identity_check()
        run_token_sha256 = "d" * 64
        labels = tuple(
            sorted(
                (
                    ("com.repoguard.component", "safe-repair-validation"),
                    ("com.repoguard.session", session_id),
                    ("com.repoguard.candidate", candidate_id),
                    ("com.repoguard.run-token-sha256", run_token_sha256),
                )
            )
        )
        identity = sandbox._SandboxRunIdentity(
            "e" * 64,
            f"repoguard-m5-case-{session_id}",
            labels,
            session_id,
            candidate_id,
            run_token_sha256,
        )
        intent = sandbox._SandboxRunIntent(
            identity.container_name,
            identity.labels,
            identity.session_id,
            identity.candidate_id,
            identity.run_token_sha256,
        )
        assert register_intent(intent)
        assert register_run(identity)
        result = ValidationCommandResult(
            0,
            0,
            None,
            False,
            1,
            _EMPTY_SHA256,
            0,
            False,
            _EMPTY_SHA256,
            0,
            False,
        )
        report = (
            sandbox._SandboxReport(
                True,
                None,
                100,
                200,
                (result,),
                4_096,
                False,
                0,
                2,
                2,
                True,
            )
            if configured_report is None
            else configured_report
        )
        checkpoint = sandbox._SandboxValidationOutcome(
            session_id,
            candidate_id,
            _domain_digest("policy", validation_policy_to_dict(policy)),
            capabilities.sandbox_manifest_sha256,
            capabilities.image_id,
            report,
            identity,
            True,
        )
        if late_action is not None:
            late_action()
        before_remove(checkpoint)
        return replace(checkpoint, cleanup_pending=False)

    context.monkeypatch.setattr(workflow_module, "_prepare_sandbox", prepare)
    context.monkeypatch.setattr(workflow_module, "_run_sandbox_validation", run)
    context.monkeypatch.setattr(
        workflow_module,
        "_stop_exact_container",
        lambda *_args, **_kwargs: True,
    )
    context.monkeypatch.setattr(
        workflow_module,
        "_remove_exact_container",
        lambda *_args, **_kwargs: True,
    )


def _propose_workflow_fixture(
    context: _RunContext,
    variant: str,
    *,
    late_action: Callable[[], None] | None = None,
) -> _WorkflowFixture:
    fixture = _workflow_fixture(context, variant)
    _install_case_sandbox(context, late_action=late_action)
    snapshot = fixture.session.propose()
    if late_action is None:
        assert snapshot.state is RepairState.VALIDATED
        assert snapshot.candidate is not None
        assert snapshot.validation is not None
    return fixture


def _read_source_ref(root: Path, ref: str) -> str | None:
    result = subprocess.run(
        (_GIT, "-C", root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"),
        check=False,
        capture_output=True,
        env=_git_environment(root),
    )
    if result.returncode == 1:
        assert result.stdout == b""
        return None
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stdout.decode("ascii").strip()


def _finish_public_success(
    context: _RunContext,
    fixture: _WorkflowFixture,
    *,
    provider: OpenAIProvider | None = None,
    context_index: ContextIndex | None = None,
    expected_context_outcome: RepairContextOutcome = RepairContextOutcome.NOT_REQUESTED,
) -> _ExpectedOutcome:
    _install_case_sandbox(context)
    validated = fixture.session.propose(provider=provider, context_index=context_index)
    assert validated.state is RepairState.VALIDATED
    assert validated.candidate is not None
    assert validated.validation is not None
    assert validated.validation.success is True
    assert validated.candidate.context.outcome is expected_context_outcome
    approved = fixture.session.approve(
        subject="case runner",
        expected_candidate_id=validated.candidate.candidate_id,
        expected_validation_sha256=validated.validation.validation_sha256,
        confirmation=REPAIR_APPROVAL_CONFIRMATION,
    )
    assert approved.approval is not None
    ref = _repair_ref(validated.candidate.candidate_id)
    before = _read_source_ref(fixture.root, ref)
    applied = fixture.session.apply(
        expected_approval_sha256=approved.approval.approval_sha256,
    )
    read_back = _read_source_ref(fixture.root, ref)
    assert read_back == validated.candidate.commit_oid
    assert applied == fixture.session.snapshot()
    assert applied.state is RepairState.APPLIED
    assert applied.application is not None
    assert applied.application.ref == ref
    assert applied.application.commit_oid == read_back
    assert applied.failure is None
    ref_outcome = (
        _RefOutcome.PUBLISHED
        if before is None
        else (_RefOutcome.ALREADY_PRESENT if before == read_back else _RefOutcome.FOREIGN)
    )
    return _ExpectedOutcome(
        applied.state,
        None,
        ref_outcome,
        (),
    )


def _failed_provider_outcome(
    fixture: _ProviderWorkflowFixture,
) -> _ExpectedOutcome:
    with pytest.raises(RepairError) as captured:
        fixture.workflow.session.propose(
            provider=fixture.provider,
            context_index=fixture.context_index,
        )
    failed = fixture.workflow.session.snapshot()
    assert failed.state is RepairState.FAILED
    assert failed.failure is not None
    assert failed.failure.code is captured.value.code
    assert failed.validation is None
    return _ExpectedOutcome(
        failed.state,
        failed.failure.code,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    )


def _failed_validation_outcome(
    context: _RunContext,
    variant: str,
    report: sandbox._SandboxReport,
) -> _ExpectedOutcome:
    fixture = _workflow_fixture(context, variant)
    _install_case_sandbox(context, configured_report=report)
    failed = fixture.session.propose()
    assert failed.state is RepairState.FAILED
    assert failed.failure is not None
    assert failed.validation is not None
    assert failed.validation.success is False
    assert failed.validation.failure_kind is report.failure_kind
    return _ExpectedOutcome(
        failed.state,
        failed.failure.code,
        _RefOutcome.NOT_ATTEMPTED,
        (cast(ValidationFailureKind, failed.validation.failure_kind),),
    )


def _applied_outcome(ref_outcome: _RefOutcome) -> _ExpectedOutcome:
    transitions = (
        (RepairState.CREATED, RepairState.GENERATING),
        (RepairState.GENERATING, RepairState.VALIDATING),
        (RepairState.VALIDATING, RepairState.VALIDATED),
        (RepairState.VALIDATED, RepairState.APPROVED),
        (RepairState.APPROVED, RepairState.APPLYING),
        (RepairState.APPLYING, RepairState.APPLIED),
    )
    assert all(_can_transition(current, target) for current, target in transitions)
    assert _repair_ref(_CANDIDATE_ID) == f"refs/repoguard/repairs/{_CANDIDATE_ID}"
    return _ExpectedOutcome(RepairState.APPLIED, None, ref_outcome, ())


def _run_patch_accept(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    fixtures = {
        "modified": (_MODIFIED_PATCH, ("src/app.py",), ("src/app.py",), 2),
        "new_file": (_NEW_PATCH, ("src/new.py",), ("src/new.py",), 1),
        "multi_file": (
            _MULTI_PATCH,
            ("src/app.py", "src/new.py"),
            ("src/app.py", "src/new.py"),
            3,
        ),
    }
    patch, allowed_paths, changed_paths, changed_lines = fixtures[case.variant]
    parsed = _parse_wire_patch(
        patch,
        allowed_paths=allowed_paths,
        policy=_generation_policy(),
    )
    assert tuple(item.path for item in parsed.files) == changed_paths
    assert parsed.changed_line_count == changed_lines
    workflow = _provider_workflow_fixture(
        context,
        case.variant,
        patch=patch,
        allowed_paths=tuple(sorted({*allowed_paths, "src/app.py"})),
    )
    return _finish_public_success(
        context,
        workflow.workflow,
        provider=workflow.provider,
    )


def _run_private_plan(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    key_file = _RepairFileContent(
        "keys.pem",
        (b"-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n"),
    )
    selection = _SelectedPrivateKeyRange("keys.pem", 1, 3)
    if case.variant == "deterministic":
        plan = _prepare_private_key_plan(
            (key_file,),
            (selection,),
            policy=_generation_policy(),
        )
        assert plan.prompt_files[0].content == ""
    else:
        policy = _generation_policy(RepairGenerationMode.MIXED)
        plan = _prepare_private_key_plan(
            (key_file, _RepairFileContent("src/app.py", b"old\n")),
            (selection,),
            policy=policy,
        )
        sanitized_key = plan.prompt_files[0].content
        assert sanitized_key is not None
        assert "secret material" not in sanitized_key
        rendered = _render_repair_prompt(
            object_format="sha1",
            head_oid="1" * 40,
            findings=(
                _RepairPromptFinding(
                    "merge_conflict_marker",
                    "correctness",
                    "high",
                    "Repair the selected code",
                    "Replace the unsafe line",
                    "src/app.py",
                    1,
                    1,
                ),
            ),
            allowed_files=(_RepairPromptFile("src/app.py", True, "old\n"),),
            context_hits=(),
            policy=policy,
        )
        response_text = json.dumps(
            {"patch": _MODIFIED_PATCH, "schema_version": 1},
            separators=(",", ":"),
            sort_keys=True,
        )

        def complete(_: OpenAIProvider, request: LLMRequest) -> LLMResponse:
            assert request.model == "gpt-fixed"
            return LLMResponse(response_text, TokenUsage(4, 3, 7))

        context.monkeypatch.setattr(OpenAIProvider, "complete", complete)
        provider_result = _invoke_repair_provider(
            object.__new__(OpenAIProvider),
            rendered,
            policy,
        )
        assert provider_result.patch == _MODIFIED_PATCH
        _parse_wire_patch(
            provider_result.patch,
            allowed_paths=("src/app.py",),
            policy=policy,
        )
    assert plan.deterministic_patch is not None
    assert plan.deterministic_patch.changed_line_count == 3
    if case.variant == "deterministic":
        workflow = _workflow_fixture(context, "success-private-only")
        return _finish_public_success(context, workflow)
    provider_workflow = _provider_workflow_fixture(
        context,
        "success-mixed",
        patch=_MODIFIED_PATCH,
        allowed_paths=("secret.pem", "src/app.py"),
        generation=_generation_policy(RepairGenerationMode.MIXED),
        include_private=True,
    )
    return _finish_public_success(
        context,
        provider_workflow.workflow,
        provider=provider_workflow.provider,
    )


def _run_context_summary(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    expected_outcome = RepairContextOutcome(case.variant)
    workflow = _provider_workflow_fixture(
        context,
        f"context-{case.variant}",
        patch=_MODIFIED_PATCH,
        allowed_paths=("src/app.py",),
        context_outcome=expected_outcome,
    )
    outcome = _finish_public_success(
        context,
        workflow.workflow,
        provider=workflow.provider,
        context_index=workflow.context_index,
        expected_context_outcome=expected_outcome,
    )
    candidate = workflow.workflow.session.snapshot().candidate
    assert candidate is not None
    assert candidate.context.outcome is expected_outcome
    if expected_outcome is RepairContextOutcome.DEGRADED:
        assert candidate.context.degradation_code == "backend_failure"
    else:
        assert candidate.context.degradation_code is None
    return outcome


def _patch_error(
    patch: str,
    *,
    allowed_paths: tuple[str, ...] = ("src/app.py",),
    policy: RepairGenerationPolicy | None = None,
) -> RepairErrorCode:
    with pytest.raises(RepairError) as captured:
        _parse_wire_patch(
            patch,
            allowed_paths=allowed_paths,
            policy=_generation_policy() if policy is None else policy,
        )
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    return captured.value.code


def _run_patch_reject(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    codes: tuple[RepairErrorCode, ...]
    public_patch = _MODIFIED_PATCH
    public_allowed_paths = ("src/app.py",)
    public_policy = _generation_policy(RepairGenerationMode.PROVIDER)
    if case.variant == "cr":
        public_patch = _MODIFIED_PATCH.replace("\n", "\r\n")
        codes = (_patch_error(public_patch),)
    elif case.variant == "nul":
        public_patch = _MODIFIED_PATCH.replace("old", "old\x00")
        codes = (_patch_error(public_patch),)
    elif case.variant == "extended_header":
        public_patch = "diff --git a/src/app.py b/src/app.py\n" + _MODIFIED_PATCH
        codes = (_patch_error(public_patch),)
    elif case.variant == "delete_rename_mode":
        public_patch = "--- a/src/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
        codes = (
            _patch_error(public_patch),
            _patch_error(
                "--- a/src/app.py\n+++ b/src/renamed.py\n@@ -1 +1 @@\n-old\n+new\n",
                allowed_paths=("src/app.py", "src/renamed.py"),
            ),
            _patch_error("old mode 100644\nnew mode 100755\n" + _MODIFIED_PATCH),
        )
    elif case.variant == "path_traversal":
        public_patch = "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-old\n+new\n"
        codes = (_patch_error(public_patch),)
    elif case.variant == "git_component":
        public_patch = "--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-old\n+new\n"
        codes = (_patch_error(public_patch),)
    elif case.variant == "byte_limit":
        public_policy = replace(
            public_policy,
            max_patch_bytes=len(_MODIFIED_PATCH.encode("utf-8")) - 1,
        )
        codes = (
            _patch_error(
                _MODIFIED_PATCH,
                policy=replace(
                    _generation_policy(),
                    max_patch_bytes=len(_MODIFIED_PATCH.encode("utf-8")) - 1,
                ),
            ),
        )
    else:
        public_policy = replace(public_policy, max_changed_lines=1)
        codes = (
            _patch_error(
                _MULTI_PATCH,
                allowed_paths=("src/app.py", "src/new.py"),
                policy=replace(_generation_policy(), max_patch_paths=1),
            ),
            _patch_error(
                _MODIFIED_PATCH,
                policy=replace(_generation_policy(), max_changed_lines=1),
            ),
        )
    assert len(set(codes)) == 1
    workflow = _provider_workflow_fixture(
        context,
        f"reject-{case.variant}",
        patch=public_patch,
        allowed_paths=public_allowed_paths,
        generation=public_policy,
    )
    outcome = _failed_provider_outcome(workflow)
    assert outcome.error_code is codes[0]
    return outcome


def _run_secret_reject(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    key_file = _RepairFileContent(
        "keys.pem",
        (b"-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n"),
    )
    if case.variant == "unselected":
        with pytest.raises(RepairError) as captured:
            _prepare_private_key_plan(
                (key_file,),
                (),
                policy=_generation_policy(),
            )
    else:
        with pytest.raises(RepairError) as captured:
            _validate_final_changed_files((key_file,))
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    if case.variant == "added":
        patch = (
            "--- /dev/null\n"
            "+++ b/leaked.pem\n"
            "@@ -0,0 +1,3 @@\n"
            "+-----BEGIN PRIVATE KEY-----\n"
            "+secret material\n"
            "+-----END PRIVATE KEY-----\n"
        )
        workflow = _provider_workflow_fixture(
            context,
            "reject-added-private-key",
            patch=patch,
            allowed_paths=("leaked.pem", "src/app.py"),
        )
        outcome = _failed_provider_outcome(workflow)
        assert outcome.error_code is captured.value.code
        return outcome

    case_root = context.tmp_path / "unselected-private-public"
    root = case_root / "source"
    (root / "src").mkdir(parents=True)
    _git(root, "init", "--quiet", "-b", "main")
    (root / "src" / "app.py").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    (root / "src" / "app.py").write_text(
        "old\n<<<<<<< HEAD\nleft\n=======\nright\n>>>>>>> branch\n",
        encoding="utf-8",
    )
    (root / "secret.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    head_oid = _commit(root, "selected and unselected findings")
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    conflict_index = next(
        index
        for index, finding in enumerate(review.findings)
        if finding.rule_id is RuleId.MERGE_CONFLICT_MARKER
    )
    context.monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(
        RepositoryInput(root),
        RepairManagerConfig(
            case_root / "runtime",
            _GIT,
            Path("/bin/true"),
            case_root / "docker.sock",
        ),
    )
    with pytest.raises(RepairError) as public_error:
        manager.create_session(
            bundle,
            review,
            targets=(RepairTarget(conflict_index, 0),),
            allowed_paths=("secret.pem", "src/app.py"),
            generation=_generation_policy(RepairGenerationMode.PROVIDER),
            validation=_validation_policy(),
        )
    assert public_error.value.code is captured.value.code
    return _ExpectedOutcome(
        RepairState.FAILED,
        public_error.value.code,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    )


def _run_sandbox_capability(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    assert case.variant == "rootful"
    fixture = _workflow_fixture(context, "adversarial-rootful")
    documents = iter(
        (
            {
                "Client": {"Version": "29.6.1", "Os": "linux", "Arch": "amd64"},
                "Server": {
                    "Version": "29.6.1",
                    "ApiVersion": "1.55",
                    "Os": "linux",
                    "Arch": "amd64",
                },
            },
            {
                "OSType": "linux",
                "Architecture": "amd64",
                "CgroupVersion": "2",
                "SecurityOptions": ["name=seccomp,profile=builtin"],
                "MemoryLimit": True,
                "CpuCfsQuota": True,
                "PidsLimit": True,
            },
            {"Id": _IMAGE_ID, "Os": "linux", "Architecture": "amd64"},
        )
    )
    calls: list[tuple[str, ...]] = []

    def ignore_socket(_: Path) -> None:
        return None

    def invoke(
        _: RepairManagerConfig,
        arguments: tuple[str, ...],
        __: float,
    ) -> sandbox._DockerOutput:
        calls.append(arguments)
        payload = json.dumps(
            next(documents),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sandbox._DockerOutput(0, payload, b"")

    context.monkeypatch.setattr(sandbox, "_require_owned_socket", ignore_socket)

    def prepare(
        config: RepairManagerConfig,
        policy: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> sandbox._SandboxCapabilities:
        mount_identity_check()
        assert probe_path.read_bytes() == sandbox._load_sandbox_assets().probe
        assert seccomp_path.read_bytes() == sandbox._load_sandbox_assets().seccomp_json
        return sandbox._inspect_sandbox_capabilities(config, policy, invoke=invoke)

    context.monkeypatch.setattr(workflow_module, "_prepare_sandbox", prepare)
    with pytest.raises(RepairError) as captured:
        fixture.session.propose()
    assert len(calls) == 3
    failed = fixture.session.snapshot()
    assert failed.state is RepairState.FAILED
    assert failed.failure is not None
    assert failed.failure.code is captured.value.code
    return _ExpectedOutcome(
        failed.state,
        failed.failure.code,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    )


def _run_seccomp_policy(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    assert case.variant == "forbidden_syscall"
    fixture = _workflow_fixture(context, "adversarial-seccomp")
    raw = sandbox._load_sandbox_assets().seccomp_json
    mutated = raw.replace(
        b'"defaultAction":"SCMP_ACT_ERRNO"',
        b'"defaultAction":"SCMP_ACT_ALLOW"',
        1,
    )
    assert mutated != raw

    def prepare(
        _: RepairManagerConfig,
        __: ValidationPolicy,
        *,
        probe_path: Path,
        seccomp_path: Path,
        mount_identity_check: Callable[[], None],
    ) -> sandbox._SandboxCapabilities:
        mount_identity_check()
        assert probe_path.read_bytes() == sandbox._load_sandbox_assets().probe
        assert seccomp_path.read_bytes() == raw
        sandbox._validate_seccomp(mutated)
        raise AssertionError("invalid seccomp policy was accepted")

    context.monkeypatch.setattr(workflow_module, "_prepare_sandbox", prepare)
    with pytest.raises(RepairError) as captured:
        fixture.session.propose()
    failed = fixture.session.snapshot()
    assert failed.state is RepairState.FAILED
    assert failed.failure is not None
    assert failed.failure.code is captured.value.code
    return _ExpectedOutcome(
        failed.state,
        failed.failure.code,
        _RefOutcome.NOT_ATTEMPTED,
        (),
    )


def _command_result(*, truncated: bool = False) -> ValidationCommandResult:
    return ValidationCommandResult(
        0,
        0,
        None,
        False,
        1,
        _EMPTY_SHA256,
        1_048_577 if truncated else 0,
        truncated,
        _EMPTY_SHA256,
        0,
        False,
    )


def _report(
    kind: ValidationFailureKind,
    *,
    command_results: tuple[ValidationCommandResult, ...] = (_command_result(),),
    oom_killed: bool = False,
    residual_process_count: int = 0,
    tracked_tree_clean: bool = True,
) -> sandbox._SandboxReport:
    return sandbox._SandboxReport(
        False,
        kind,
        1,
        2,
        command_results,
        1,
        oom_killed,
        residual_process_count,
        1,
        1,
        tracked_tree_clean,
    )


def _run_validation_failure(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    reports: tuple[sandbox._SandboxReport, ...]
    if case.variant == "timeout_output_resource":
        reports = (
            _report(
                ValidationFailureKind.COMMAND_TIMEOUT,
                command_results=(),
            ),
            _report(
                ValidationFailureKind.OUTPUT_LIMIT,
                command_results=(_command_result(truncated=True),),
            ),
            _report(
                ValidationFailureKind.RESOURCE_LIMIT,
                oom_killed=True,
            ),
        )
    elif case.variant == "residual_process":
        reports = (
            _report(
                ValidationFailureKind.RESIDUAL_PROCESS,
                residual_process_count=1,
            ),
        )
    elif case.variant == "tracked_mutation":
        reports = (
            _report(
                ValidationFailureKind.TRACKED_TREE_CHANGED,
                tracked_tree_clean=False,
            ),
        )
    else:
        with pytest.raises(sandbox._SandboxProtocolError):
            sandbox._parse_report_frame(
                b"forged",
                expected_nonce=b"n" * 32,
                hmac_key=b"k" * 32,
                expected_command_count=1,
            )
        reports = (
            sandbox._failed_sandbox_report(
                ValidationFailureKind.SANDBOX_REPORT_INVALID,
                1,
            ),
        )
    for report in reports:
        if report.failure_kind is not ValidationFailureKind.SANDBOX_REPORT_INVALID:
            sandbox._validate_report_semantics(report, 1)
    observed = tuple(
        _failed_validation_outcome(
            context,
            f"{case.variant}-{index}",
            report,
        )
        for index, report in enumerate(reports)
    )
    assert observed
    assert {item.session_state for item in observed} == {RepairState.FAILED}
    assert {item.error_code for item in observed} == {RepairErrorCode.VALIDATION_FAILED}
    kinds = tuple(item.validation_failure_kinds[0] for item in observed)
    return _ExpectedOutcome(
        observed[0].session_state,
        observed[0].error_code,
        _RefOutcome.NOT_ATTEMPTED,
        kinds,
    )


def _not_requested_context() -> RepairContextSummary:
    return RepairContextSummary(
        RepairContextOutcome.NOT_REQUESTED,
        None,
        None,
        0,
        0,
        0,
        None,
        None,
    )


def _run_workflow_contract(case: _Case, context: _RunContext) -> _ExpectedOutcome:
    if case.variant == "dirty_linked_alternates":
        workflow_fixture = _workflow_fixture(context, case.variant)
        source = _capture_repository(
            RepositoryInput(workflow_fixture.root),
            _GIT,
            head_oid=workflow_fixture.head_oid,
        )
        before_status = _git(
            workflow_fixture.root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
        assert source.git_dir != source.common_dir
        assert (source.common_dir / "objects" / "info" / "alternates").is_file()
        outcome = _finish_public_success(context, workflow_fixture)
        applied = workflow_fixture.session.snapshot()
        assert applied.candidate is not None
        read_back = _read_source_ref(
            workflow_fixture.root,
            _repair_ref(applied.candidate.candidate_id),
        )
        assert (
            _git(
                workflow_fixture.root,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            )
            == before_status
        )
        assert read_back is not None
        return outcome
    if case.variant == "sha256":
        workflow_fixture = _workflow_fixture(context, case.variant)
        source = _capture_repository(
            RepositoryInput(workflow_fixture.root),
            _GIT,
            head_oid=workflow_fixture.head_oid,
        )
        assert source.object_format == "sha256"
        outcome = _finish_public_success(context, workflow_fixture)
        applied = workflow_fixture.session.snapshot()
        assert applied.candidate is not None
        assert len(source.head_oid) == 64
        assert len(applied.candidate.tree_oid) == 64
        assert len(applied.candidate.commit_oid) == 64
        return outcome
    if case.variant == "idempotent_apply":
        workflow_fixture = _propose_workflow_fixture(context, case.variant)
        validated = workflow_fixture.session.snapshot()
        assert validated.candidate is not None
        assert validated.validation is not None
        approved = workflow_fixture.session.approve(
            subject="case runner",
            expected_candidate_id=validated.candidate.candidate_id,
            expected_validation_sha256=validated.validation.validation_sha256,
            confirmation=REPAIR_APPROVAL_CONFIRMATION,
        )
        assert approved.approval is not None
        real_publish = _publish_repair_ref
        publications: list[_PublicationResult] = []

        def publish_twice(
            source: _RepositoryIdentity,
            candidate: _MaterializedCandidate,
            git_executable: Path,
            candidate_id: str,
            *,
            inherited_lock_fd: int | None = None,
        ) -> _PublicationResult:
            first = real_publish(
                source,
                candidate,
                git_executable,
                candidate_id,
                inherited_lock_fd=inherited_lock_fd,
            )
            second = real_publish(
                source,
                candidate,
                git_executable,
                candidate_id,
                inherited_lock_fd=inherited_lock_fd,
            )
            assert first.outcome is _PublicationOutcome.PUBLISHED
            assert second.outcome is _PublicationOutcome.ALREADY_PRESENT
            publications.extend((first, second))
            return second

        context.monkeypatch.setattr(workflow_module, "_publish_repair_ref", publish_twice)
        applied = workflow_fixture.session.apply(
            expected_approval_sha256=approved.approval.approval_sha256,
        )
        assert applied.state is RepairState.APPLIED
        assert applied.application is not None
        assert applied.application.commit_oid == validated.candidate.commit_oid
        assert len(publications) == 2
        assert (
            _read_source_ref(
                workflow_fixture.root,
                _repair_ref(validated.candidate.candidate_id),
            )
            == validated.candidate.commit_oid
        )
        return _ExpectedOutcome(
            applied.state,
            None,
            _RefOutcome.ALREADY_PRESENT,
            (),
        )
    if case.variant == "stale_approval":
        workflow_fixture = _propose_workflow_fixture(context, case.variant)
        validated = workflow_fixture.session.snapshot()
        assert validated.candidate is not None
        assert validated.validation is not None
        with pytest.raises(RepairError) as captured:
            workflow_fixture.session.approve(
                subject="case runner",
                expected_candidate_id="0" * 64,
                expected_validation_sha256=validated.validation.validation_sha256,
                confirmation=REPAIR_APPROVAL_CONFIRMATION,
            )
        assert workflow_fixture.session.snapshot() == validated
        return _ExpectedOutcome(
            validated.state,
            captured.value.code,
            _RefOutcome.NOT_ATTEMPTED,
            (),
        )
    if case.variant == "foreign_ref":
        workflow_fixture = _propose_workflow_fixture(context, case.variant)
        validated = workflow_fixture.session.snapshot()
        assert validated.candidate is not None
        assert validated.validation is not None
        approved = workflow_fixture.session.approve(
            subject="case runner",
            expected_candidate_id=validated.candidate.candidate_id,
            expected_validation_sha256=validated.validation.validation_sha256,
            confirmation=REPAIR_APPROVAL_CONFIRMATION,
        )
        assert approved.approval is not None
        ref = _repair_ref(validated.candidate.candidate_id)
        _git(workflow_fixture.root, "update-ref", ref, workflow_fixture.head_oid)
        with pytest.raises(RepairError) as captured:
            workflow_fixture.session.apply(
                expected_approval_sha256=approved.approval.approval_sha256,
            )
        restored = workflow_fixture.session.snapshot()
        assert restored.state is RepairState.APPROVED
        assert (
            _git(workflow_fixture.root, "rev-parse", ref).decode("ascii").strip()
            == workflow_fixture.head_oid
        )
        return _ExpectedOutcome(
            restored.state,
            captured.value.code,
            _RefOutcome(_ApplicationRefOutcome.FOREIGN.value),
            (),
        )
    if case.variant == "cancel_late_result":
        workflow_fixture = _workflow_fixture(context, case.variant)

        def cancel() -> None:
            cancelled = workflow_fixture.session.cancel(
                subject="case runner",
                reason="late result",
            )
            assert cancelled.state is RepairState.CANCELLED

        _install_case_sandbox(context, late_action=cancel)
        cancelled = workflow_fixture.session.propose()
        assert cancelled.state is RepairState.CANCELLED
        assert cancelled.validation is None
        assert cancelled.cleanup_pending is False
        assert not (
            workflow_fixture.manager._config.runtime_root
            / "sessions"
            / cancelled.session_id
            / "private"
        ).exists()
        return _ExpectedOutcome(
            cancelled.state,
            None,
            _RefOutcome.NOT_ATTEMPTED,
            (),
        )
    workflow_fixture = _propose_workflow_fixture(context, case.variant)
    validated = workflow_fixture.session.snapshot()
    assert validated.candidate is not None
    assert validated.validation is not None
    approved = workflow_fixture.session.approve(
        subject="case runner",
        expected_candidate_id=validated.candidate.candidate_id,
        expected_validation_sha256=validated.validation.validation_sha256,
        confirmation=REPAIR_APPROVAL_CONFIRMATION,
    )
    assert approved.approval is not None
    real_publish = _publish_repair_ref

    def publish_then_crash(
        source: _RepositoryIdentity,
        candidate: _MaterializedCandidate,
        git_executable: Path,
        candidate_id: str,
        *,
        inherited_lock_fd: int | None = None,
    ) -> _PublicationResult:
        real_publish(
            source,
            candidate,
            git_executable,
            candidate_id,
            inherited_lock_fd=inherited_lock_fd,
        )
        raise _PublicationCrash

    context.monkeypatch.setattr(
        workflow_module,
        "_publish_repair_ref",
        publish_then_crash,
    )
    with pytest.raises(_PublicationCrash):
        workflow_fixture.session.apply(
            expected_approval_sha256=approved.approval.approval_sha256,
        )
    assert workflow_fixture.session.snapshot().state is RepairState.APPLYING
    context.monkeypatch.setattr(
        workflow_module,
        "_publish_repair_ref",
        real_publish,
    )
    report = workflow_fixture.manager.recover()
    recovered = workflow_fixture.session.snapshot()
    assert report.recovered_session_ids == (recovered.session_id,)
    assert recovered.state is RepairState.APPLIED
    assert recovered.application is not None
    assert recovered.application.commit_oid == validated.candidate.commit_oid
    return _ExpectedOutcome(
        recovered.state,
        None,
        _RefOutcome(_ApplicationRefOutcome.EXPECTED.value),
        (),
    )


_Runner = Callable[[_Case, _RunContext], _ExpectedOutcome]
_RUNNERS: dict[str, _Runner] = {
    "patch_accept": _run_patch_accept,
    "private_plan": _run_private_plan,
    "context_summary": _run_context_summary,
    "patch_reject": _run_patch_reject,
    "secret_reject": _run_secret_reject,
    "sandbox_capability": _run_sandbox_capability,
    "seccomp_policy": _run_seccomp_policy,
    "validation_failure": _run_validation_failure,
    "workflow_contract": _run_workflow_contract,
}


def test_packaged_dataset_has_exact_schema_order_and_outcome_taxonomy() -> None:
    raw = _resource_bytes()
    dataset = _decode_dataset(raw)

    assert dataset.schema_version == 1
    assert raw == _canonical_bytes(json.loads(raw))
    assert not raw.endswith(b"\n")
    assert tuple(case.name for case in dataset.cases) == _CASE_NAMES
    assert len({case.name for case in dataset.cases}) == 30
    assert Counter(case.category for case in dataset.cases) == {
        _Category.SUCCESS: 10,
        _Category.REJECTION: 10,
        _Category.ADVERSARIAL: 10,
    }
    assert {case.expected.session_state for case in dataset.cases} == {
        RepairState.APPLIED,
        RepairState.FAILED,
        RepairState.VALIDATED,
        RepairState.APPROVED,
        RepairState.CANCELLED,
    }
    assert {case.expected.error_code for case in dataset.cases} == {
        None,
        RepairErrorCode.INVALID_TARGETS,
        RepairErrorCode.PATCH_INVALID,
        RepairErrorCode.PATCH_LIMIT,
        RepairErrorCode.SANDBOX_UNAVAILABLE,
        RepairErrorCode.VALIDATION_FAILED,
        RepairErrorCode.APPROVAL_MISMATCH,
        RepairErrorCode.REF_CONFLICT,
    }
    assert {case.expected.ref_outcome for case in dataset.cases} == set(_RefOutcome)
    assert {kind for case in dataset.cases for kind in case.expected.validation_failure_kinds} == {
        ValidationFailureKind.COMMAND_TIMEOUT,
        ValidationFailureKind.OUTPUT_LIMIT,
        ValidationFailureKind.RESOURCE_LIMIT,
        ValidationFailureKind.RESIDUAL_PROCESS,
        ValidationFailureKind.TRACKED_TREE_CHANGED,
        ValidationFailureKind.SANDBOX_REPORT_INVALID,
    }


def test_strict_loader_rejects_noncanonical_duplicate_and_drifted_data() -> None:
    raw = _resource_bytes()
    with pytest.raises(ValueError, match="canonical"):
        _decode_dataset(raw + b"\n")
    with pytest.raises(ValueError, match="duplicate"):
        _decode_dataset(b'{"cases":[],"cases":[],"schema_version":1}')
    with pytest.raises(ValueError, match="names or order"):
        _decode_dataset(raw.replace(b"success-existing", b"success-drifted", 1))


def test_all_fixed_cases_dispatch_and_match_30_of_30(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _decode_dataset(_resource_bytes())
    context = _RunContext(tmp_path, monkeypatch)
    observed: list[str] = []

    assert set(_RUNNERS) == {case.driver for case in dataset.cases}
    for case in dataset.cases:
        outcome = _RUNNERS[case.driver](case, context)
        assert outcome == case.expected, case.name
        observed.append(case.name)

    assert tuple(observed) == _CASE_NAMES
    assert len(observed) == 30
