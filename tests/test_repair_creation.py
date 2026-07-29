"""Focused integration tests for manager binding and session creation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import repoguard._repair_store as store_module
from repoguard._repair_input import _repair_request_from_dict
from repoguard._repair_models import _domain_digest
from repoguard._repair_store import _locked_session, _session_path_guard
from repoguard._repair_workflow import _generate_candidate
from repoguard.evidence import PullRequestInput, RepositoryInput, collect_evidence
from repoguard.providers import LLMResponse, OpenAIProvider, TokenUsage
from repoguard.repair import (
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairManager,
    RepairManagerConfig,
    RepairProviderKind,
    RepairSession,
    RepairStage,
    RepairState,
    RepairTarget,
    ValidationCommand,
    ValidationPolicy,
    repair_context_summary_to_dict,
    repair_prompt_identity_to_dict,
)
from repoguard.review import RuleId, review_evidence

_GIT = Path("/usr/bin/git")
_IMAGE = f"sha256:{'1' * 64}"


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
    root_parts = root.parts
    pass_fds = (
        (int(root_parts[4]),)
        if len(root_parts) == 5
        and root_parts[:4] == ("/", "proc", "self", "fd")
        and root_parts[4].isdecimal()
        else ()
    )
    return (
        subprocess.run(
            (_GIT, "-C", root, *arguments),
            check=True,
            capture_output=True,
            env=environment,
            pass_fds=pass_fds,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Repair Test",
        "-c",
        "user.email=repair@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--quiet", "-b", "main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    (root / "secret.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    head_oid = _commit(root, "add private material")
    return root, base_oid, head_oid


def _provider_repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "provider-repository"
    root.mkdir()
    _git(root, "init", "--quiet", "-b", "main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    (root / "conflict.py").write_text(
        "<<<<<<< HEAD\nleft = 1\n=======\nright = 2\n>>>>>>> branch\n",
        encoding="utf-8",
    )
    head_oid = _commit(root, "add conflict")
    return root, base_oid, head_oid


def _config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        _GIT,
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def test_create_session_freezes_nested_repository_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, base_oid, head_oid = _repository(tmp_path)
    nested = root / "nested"
    nested.mkdir()
    bundle = collect_evidence(
        RepositoryInput(nested),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    assert len(review.findings) == 1
    assert review.findings[0].rule_id is RuleId.PRIVATE_KEY_MATERIAL

    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = _config(tmp_path / "runtime")
    manager = RepairManager(RepositoryInput(nested), config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(0, 0),),
        allowed_paths=("secret.pem",),
        generation=RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None),
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
    )

    snapshot = session.snapshot()
    assert snapshot.state is RepairState.CREATED
    assert len(snapshot.session_id) == 64
    assert set(snapshot.session_id) <= set("0123456789abcdef")
    assert snapshot.target_count == 1
    assert snapshot.allowed_paths == ("secret.pem",)
    session_root = config.runtime_root / "sessions" / snapshot.session_id
    request_path = session_root / "private" / "request.json"
    assert stat.S_IMODE(request_path.stat().st_mode) == 0o400
    request = _repair_request_from_dict(json.loads(request_path.read_bytes()))
    assert request.repository.worktree_root == root.resolve()
    assert request.repository.head_oid == head_oid
    assert request.request_sha256 == snapshot.request_sha256
    assert manager.open_session(snapshot.session_id).snapshot() == snapshot


def test_create_session_rejects_evidence_for_stale_current_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, base_oid, head_oid = _repository(tmp_path)
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(RepositoryInput(root), _config(tmp_path / "runtime"))

    (root / "after.txt").write_text("advanced\n", encoding="utf-8")
    _commit(root, "advance HEAD after evidence")

    with pytest.raises(RepairError) as captured:
        manager.create_session(
            bundle,
            review,
            targets=(RepairTarget(0, 0),),
            allowed_paths=("secret.pem",),
            generation=RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None),
            validation=ValidationPolicy(
                _IMAGE,
                (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
            ),
        )
    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert tuple((tmp_path / "runtime" / "sessions").iterdir()) == ()


def test_public_manager_error_has_no_private_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, _ = _repository(tmp_path)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(RepositoryInput(root), _config(tmp_path / "runtime"))

    with pytest.raises(RepairError) as captured:
        manager.open_session("d" * 64)

    frames = traceback.extract_tb(captured.value.__traceback__)
    assert all("/src/repoguard/_repair_" not in frame.filename for frame in frames)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_invalid_session_id_maps_to_detached_public_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, _ = _repository(tmp_path)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(RepositoryInput(root), _config(tmp_path / "runtime"))

    with pytest.raises(RepairError) as captured:
        manager.open_session("bad")

    assert captured.value.code is RepairErrorCode.SESSION_NOT_FOUND
    assert captured.value.stage is RepairStage.SESSION
    assert captured.value.state is None
    assert captured.value.session_id is None
    frames = traceback.extract_tb(captured.value.__traceback__)
    assert all("/src/repoguard/_repair_" not in frame.filename for frame in frames)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_public_session_error_has_no_private_traceback_or_operation_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, _ = _repository(tmp_path)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(RepositoryInput(root), _config(tmp_path / "runtime"))
    session = RepairSession(manager, "e" * 64)

    with pytest.raises(RepairError) as captured:
        session.snapshot()

    current = captured.value.__traceback__
    saw_unwrap = False
    while current is not None:
        assert "/src/repoguard/_repair_" not in current.tb_frame.f_code.co_filename
        assert current.tb_frame.f_code.co_name != "_public_call"
        saw_unwrap |= current.tb_frame.f_code.co_name == "_unwrap_public_outcome"
        current = current.tb_next
    assert saw_unwrap
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def _reachable_values(root: object) -> tuple[object, ...]:
    pending = [root]
    seen: set[int] = set()
    reachable: list[object] = []
    while pending:
        value = pending.pop()
        identity = id(value)
        if identity in seen:
            continue
        seen.add(identity)
        reachable.append(value)
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            pending.extend(value)
        else:
            namespace = getattr(value, "__dict__", None)
            if isinstance(namespace, dict):
                pending.extend(namespace.values())
            for value_type in type(value).__mro__:
                slots = value_type.__dict__.get("__slots__", ())
                if isinstance(slots, str):
                    slots = (slots,)
                for slot in slots:
                    if slot not in {"__dict__", "__weakref__"} and hasattr(value, slot):
                        pending.append(getattr(value, slot))
    return tuple(reachable)


def test_public_propose_error_traceback_cannot_reach_provider_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, _ = _repository(tmp_path)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    manager = RepairManager(RepositoryInput(root), _config(tmp_path / "runtime"))
    session = RepairSession(manager, "f" * 64)
    api_key = "repoguard-traceback-regression-secret"
    provider = object.__new__(OpenAIProvider)
    object.__setattr__(provider, "_client", {"api_key": api_key})

    def fail_proposal(*_: object, **__: object) -> None:
        raise RepairError(
            RepairErrorCode.PROVIDER_AUTHENTICATION,
            RepairStage.PROVIDER,
            RepairState.GENERATING,
            "f" * 64,
        )

    monkeypatch.setattr("repoguard._repair_workflow._propose", fail_proposal)

    with pytest.raises(RepairError) as captured:
        session.propose(provider=provider)

    current = captured.value.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_filename.endswith("/src/repoguard/repair.py"):
            reachable = _reachable_values(current.tb_frame.f_locals)
            assert all(value is not provider for value in reachable)
            assert all(value != api_key for value in reachable if isinstance(value, str))
        current = current.tb_next
    assert captured.value.code is RepairErrorCode.PROVIDER_AUTHENTICATION
    assert captured.value.stage is RepairStage.PROVIDER
    assert captured.value.state is RepairState.GENERATING
    assert captured.value.session_id == "f" * 64
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("operation", ["create_session", "recover", "cleanup"])
def test_public_manager_operations_map_native_manager_lock_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    root, base_oid, head_oid = _repository(tmp_path)
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = _config(tmp_path / "runtime")
    manager = RepairManager(RepositoryInput(root), config)

    def fail_runtime_open(*_: object) -> int:
        raise OSError("simulated manager runtime open failure")

    monkeypatch.setattr(store_module, "_open_runtime_root", fail_runtime_open)

    with pytest.raises(RepairError) as captured:
        if operation == "create_session":
            manager.create_session(
                bundle,
                review,
                targets=(RepairTarget(0, 0),),
                allowed_paths=("secret.pem",),
                generation=RepairGenerationPolicy(
                    RepairGenerationMode.DETERMINISTIC,
                    None,
                    None,
                ),
                validation=ValidationPolicy(
                    _IMAGE,
                    (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
                ),
            )
        elif operation == "recover":
            manager.recover()
        else:
            manager.cleanup()

    assert captured.value.code is RepairErrorCode.PERSISTENCE_FAILED
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.state is None
    assert captured.value.session_id is None
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_deterministic_generation_builds_fixed_secret_safe_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, base_oid, head_oid = _repository(tmp_path)
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = _config(tmp_path / "runtime")
    manager = RepairManager(RepositoryInput(root), config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(0, 0),),
        allowed_paths=("secret.pem",),
        generation=RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None),
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
    )
    (root / "later.txt").write_text("ref moved after creation\n", encoding="utf-8")
    _commit(root, "move ref after repair request freeze")
    created = session.snapshot()
    with _locked_session(config, created.session_id) as storage:
        request = _repair_request_from_dict(storage.read_private_json("request.json"))
        generating = replace(
            created,
            state=RepairState.GENERATING,
            updated_at_us=created.updated_at_us + 1,
        )
        generating = storage.append("generating", generating).snapshot

    with _session_path_guard(
        config,
        created.session_id,
        runtime_root_identity=manager._runtime_root_identity,
    ) as runtime:
        generated = _generate_candidate(
            session,
            request,
            generating,
            runtime=runtime,
            provider=None,
            context_index=None,
        )
        candidate_parent = _git(
            generated.materialized.root,
            "rev-parse",
            f"{generated.record.commit_oid}^",
        )
        candidate_secret = _git(
            generated.materialized.root,
            "show",
            f"{generated.record.commit_oid}:secret.pem",
        )

    assert generated.record.changed_paths == ("secret.pem",)
    assert generated.record.provider_attempt_count == 0
    assert generated.record.input_tokens == 0
    assert generated.record.output_tokens == 0
    assert generated.prompt_bytes is None
    assert generated.response_bytes is None
    assert generated.provider_patch_bytes is None
    assert generated.deterministic_patch_bytes is not None
    assert generated.materialized.commit_oid == generated.record.commit_oid
    assert generated.materialized.tree_oid == generated.record.tree_oid
    assert candidate_parent == head_oid
    assert candidate_secret == ""
    assert "private material" not in generated.preview.canonical_diff
    assert "-----BEGIN PRIVATE KEY-----" not in generated.preview.canonical_diff
    assert "[REDACTED_PRIVATE_KEY_MATERIAL]" in generated.preview.canonical_diff
    expected_candidate = _domain_digest(
        "candidate",
        {
            "schema_version": 1,
            "request_sha256": request.request_sha256,
            "prompt": repair_prompt_identity_to_dict(request.prompt),
            "context": repair_context_summary_to_dict(generated.record.context),
            "diff_sha256": generated.record.diff_sha256,
            "tree_oid": generated.record.tree_oid,
            "commit_oid": generated.record.commit_oid,
        },
    )
    assert generated.record.candidate_id == expected_candidate


def test_provider_generation_renders_and_applies_exact_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, base_oid, head_oid = _provider_repository(tmp_path)
    bundle = collect_evidence(
        RepositoryInput(root),
        PullRequestInput(base_ref=base_oid, head_ref=head_oid),
    )
    review = review_evidence(bundle)
    target_index = next(
        index
        for index, finding in enumerate(review.findings)
        if finding.rule_id is RuleId.MERGE_CONFLICT_MARKER
    )
    patch = (
        "--- a/conflict.py\n"
        "+++ b/conflict.py\n"
        "@@ -1,5 +1 @@\n"
        "-<<<<<<< HEAD\n"
        "-left = 1\n"
        "-=======\n"
        "-right = 2\n"
        "->>>>>>> branch\n"
        "+result = 1\n"
    )
    response_text = json.dumps(
        {"patch": patch, "schema_version": 1},
        separators=(",", ":"),
        sort_keys=True,
    )
    calls = 0

    def complete(_: OpenAIProvider, __: object) -> LLMResponse:
        nonlocal calls
        calls += 1
        return LLMResponse(response_text, TokenUsage(13, 5, 18))

    monkeypatch.setattr(OpenAIProvider, "complete", complete)
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    config = _config(tmp_path / "provider-runtime")
    manager = RepairManager(RepositoryInput(root), config)
    session = manager.create_session(
        bundle,
        review,
        targets=(RepairTarget(target_index, 0),),
        allowed_paths=("conflict.py",),
        generation=RepairGenerationPolicy(
            RepairGenerationMode.PROVIDER,
            RepairProviderKind.OPENAI,
            "gpt-fixed",
        ),
        validation=ValidationPolicy(
            _IMAGE,
            (ValidationCommand(("/usr/local/bin/python3.12", "-c", "pass")),),
        ),
    )
    created = session.snapshot()
    with _locked_session(config, created.session_id) as storage:
        request = _repair_request_from_dict(storage.read_private_json("request.json"))
        generating = storage.append(
            "generating",
            replace(
                created,
                state=RepairState.GENERATING,
                updated_at_us=created.updated_at_us + 1,
            ),
        ).snapshot

    with _session_path_guard(
        config,
        created.session_id,
        runtime_root_identity=manager._runtime_root_identity,
    ) as runtime:
        generated = _generate_candidate(
            session,
            request,
            generating,
            runtime=runtime,
            provider=object.__new__(OpenAIProvider),
            context_index=None,
        )
        candidate_content = _git(
            generated.materialized.root,
            "show",
            f"{generated.record.commit_oid}:conflict.py",
        )

    assert calls == 1
    assert (generated.record.provider_attempt_count, generated.record.input_tokens) == (1, 13)
    assert generated.record.output_tokens == 5
    assert generated.prompt_bytes is not None
    assert str(root).encode() not in generated.prompt_bytes
    assert generated.response_bytes == response_text.encode()
    assert generated.provider_patch_bytes == patch.encode()
    assert generated.deterministic_patch_bytes is None
    assert candidate_content == "result = 1"
