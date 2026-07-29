"""Adversarial safety matrix for repair workflow, storage, and retrieval."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import repoguard._repair_retrieval as retrieval_module
import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
import repoguard._retrieval as native_retrieval
from repoguard._repair_models import _canonical_bytes, _domain_digest
from repoguard._repair_retrieval import _retrieve_repair_context
from repoguard._repair_store import (
    _create_session_store,
    _initialize_runtime_root,
    _locked_session,
    _SessionStore,
    _ValidationRunLease,
)
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairCandidate,
    RepairContextOutcome,
    RepairContextSummary,
    RepairError,
    RepairErrorCode,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairManager,
    RepairManagerConfig,
    RepairPromptIdentity,
    RepairProviderKind,
    RepairSession,
    RepairSnapshot,
    RepairStage,
    RepairState,
    repair_candidate_to_dict,
)
from repoguard.retrieval import (
    ChunkProvenance,
    ContextChunk,
    ContextIndex,
    ContextQuery,
    EmbeddingDevice,
    IndexIdentity,
    IndexStatistics,
    RetrievalChannel,
    RetrievalHit,
    RetrievalResult,
)

_SESSION_ID = "a" * 64
_OTHER_SESSION_ID = "b" * 64
_REQUEST_SHA256 = "c" * 64
_HEAD_OID = "1" * 40
_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"


class _IndexState:
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


class _ExplodingIndexState:
    @property
    def identity(self) -> IndexIdentity:
        raise RuntimeError("native identity failure")

    @property
    def statistics(self) -> IndexStatistics:
        return IndexStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0)

    @property
    def closed(self) -> bool:
        return False

    def close(self) -> None:
        return None


class _PrivateBytesReader:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def read_private_bytes(self, _: str, maximum: int = 4 * 1_048_576) -> bytes:
        assert maximum > 0
        return self._value


def _identity(*, head_oid: str = _HEAD_OID) -> IndexIdentity:
    return IndexIdentity(
        Path("/repository"),
        "sha1",
        head_oid,
        (RetrievalChannel.TEXT,),
        "2" * 64,
        _MODEL,
        _MODEL_REVISION,
        "3" * 64,
        384,
        EmbeddingDevice.CPU,
    )


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        provider_kind=RepairProviderKind.OPENAI,
        model="repair-model",
    )


def _retrieval_hit() -> RetrievalHit:
    provenance = ChunkProvenance(
        "4" * 64,
        "src/context.py",
        "5" * 40,
        0,
        12,
        1,
        1,
    )
    chunk = ContextChunk(
        provenance,
        "def safe():\n",
        (),
        ("safe",),
        (),
    )
    return RetrievalHit(
        chunk,
        (RetrievalChannel.TEXT,),
        1,
        None,
        None,
        1,
        1_000_000,
    )


def _snapshot(
    *,
    session_id: str = _SESSION_ID,
    state: RepairState = RepairState.CREATED,
    updated_at_us: int = 1,
    candidate: RepairCandidate | None = None,
) -> RepairSnapshot:
    return RepairSnapshot(
        1,
        session_id,
        state,
        _REQUEST_SHA256,
        1,
        updated_at_us,
        1,
        ("src/app.py",),
        candidate,
        None,
        None,
        None,
        None,
        None,
        False,
    )


def _candidate() -> RepairCandidate:
    candidate = RepairCandidate(
        1,
        "0" * 64,
        _REQUEST_SHA256,
        RepairPromptIdentity("agent_repair", 1, "6" * 64, "7" * 64, "8" * 64),
        RepairContextSummary(
            RepairContextOutcome.NOT_REQUESTED,
            None,
            None,
            0,
            0,
            0,
            None,
            None,
        ),
        "9" * 64,
        _HEAD_OID,
        _HEAD_OID,
        ("src/app.py",),
        1,
        0,
        0,
        0,
    )
    payload = repair_candidate_to_dict(candidate)
    del payload["candidate_id"]
    for name in (
        "changed_paths",
        "changed_line_count",
        "provider_attempt_count",
        "input_tokens",
        "output_tokens",
    ):
        del payload[name]
    return replace(candidate, candidate_id=_domain_digest("candidate", payload))


_CANDIDATE_ID = _candidate().candidate_id


def _config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        Path("/bin/true"),
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def _initialized_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, Path]:
    repository = tmp_path / "repository"
    common = repository / ".git"
    repository.mkdir(mode=0o700)
    common.mkdir(mode=0o700)
    config = _config(tmp_path / "runtime")
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    _initialize_runtime_root(config, repository_root=repository, common_dir=common)
    return config, repository


def _create_store(config: RepairManagerConfig, session_id: str = _SESSION_ID) -> None:
    _create_session_store(
        config,
        session_id,
        request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
        snapshot=_snapshot(session_id=session_id),
    )


def _session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RepairManagerConfig, RepairSnapshot, RepairSession]:
    config, repository = _initialized_runtime(tmp_path, monkeypatch)
    _create_store(config)
    monkeypatch.setattr(workflow_module, "_initialize_manager", lambda *_: None)
    manager = RepairManager(RepositoryInput(repository), config)
    session = manager.open_session(_SESSION_ID)
    return config, session.snapshot(), session


def _assert_repair_error(
    operation: Callable[[], object],
    *,
    code: RepairErrorCode,
    stage: RepairStage,
) -> RepairError:
    with pytest.raises(RepairError) as captured:
        operation()
    error = captured.value
    assert error.code is code
    assert error.stage is stage
    assert error.__cause__ is None
    assert error.__context__ is None
    return error


def test_retrieval_projects_exact_hits_and_binds_safe_hit_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_IndexState(identity))
    query = ContextQuery("safe context")
    hit = _retrieval_hit()
    backend_result = RetrievalResult(
        identity,
        hashlib.sha256(query.text.encode("utf-8")).hexdigest(),
        1,
        1,
        0,
        (hit,),
    )
    monkeypatch.setattr(retrieval_module, "_validate_live_index", lambda *_: None)
    monkeypatch.setattr(
        native_retrieval,
        "_retrieve_context_queries",
        lambda *_args, **_kwargs: backend_result,
    )

    result = _retrieve_repair_context(
        expected_identity=identity,
        index=index,
        queries=(query,),
        policy=_policy(),
        deadline=1.0,
        state=RepairState.GENERATING,
        session_id=_SESSION_ID,
    )

    assert result.summary.outcome is RepairContextOutcome.USED
    assert result.summary.query_count == 1
    assert result.summary.candidate_count == 1
    assert result.summary.selected_hit_count == 1
    assert result.summary.hit_identity_sha256 is not None
    assert len(result.summary.hit_identity_sha256) == 64
    assert result.hits[0].path == "src/context.py"
    assert result.hits[0].content == "def safe():\n"
    assert result.hits[0].definitions == ("safe",)


def test_retrieval_empty_query_set_is_explicit_used_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_IndexState(identity))
    monkeypatch.setattr(retrieval_module, "_validate_live_index", lambda *_: None)
    monkeypatch.setattr(
        native_retrieval,
        "_retrieve_context_queries",
        lambda *_args, **_kwargs: pytest.fail("empty queries must not call retrieval"),
    )

    result = _retrieve_repair_context(
        expected_identity=identity,
        index=index,
        queries=(),
        policy=_policy(),
        deadline=1.0,
    )

    assert result.summary.outcome is RepairContextOutcome.USED
    assert result.summary.query_count == 0
    assert result.summary.candidate_count == 0
    assert result.summary.selected_hit_count == 0
    assert result.summary.hit_identity_sha256 is not None
    assert result.hits == ()


def test_retrieval_refuses_missing_or_unrequested_live_capability() -> None:
    identity = _identity()
    index = ContextIndex(_IndexState(identity))

    _assert_repair_error(
        lambda: _retrieve_repair_context(
            expected_identity=None,
            index=index,
            queries=(),
            policy=_policy(),
            deadline=1.0,
        ),
        code=RepairErrorCode.IDENTITY_MISMATCH,
        stage=RepairStage.RETRIEVAL,
    )
    _assert_repair_error(
        lambda: _retrieve_repair_context(
            expected_identity=identity,
            index=None,
            queries=(),
            policy=_policy(),
            deadline=1.0,
        ),
        code=RepairErrorCode.IDENTITY_MISMATCH,
        stage=RepairStage.RETRIEVAL,
    )


def test_retrieval_refuses_result_from_another_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_IndexState(identity))
    mismatched = RetrievalResult(
        _identity(head_oid="2" * 40),
        hashlib.sha256(b"query").hexdigest(),
        0,
        0,
        0,
        (),
    )
    monkeypatch.setattr(retrieval_module, "_validate_live_index", lambda *_: None)
    monkeypatch.setattr(
        native_retrieval,
        "_retrieve_context_queries",
        lambda *_args, **_kwargs: mismatched,
    )

    _assert_repair_error(
        lambda: _retrieve_repair_context(
            expected_identity=identity,
            index=index,
            queries=(ContextQuery("query"),),
            policy=_policy(),
            deadline=1.0,
            state=RepairState.GENERATING,
            session_id=_SESSION_ID,
        ),
        code=RepairErrorCode.IDENTITY_MISMATCH,
        stage=RepairStage.RETRIEVAL,
    )


@pytest.mark.parametrize(
    "corruption",
    [
        "extra_key",
        "schema",
        "previous",
        "unknown_kind",
        "state_type",
        "snapshot_type",
        "state_mismatch",
        "timestamp_mismatch",
        "initial_kind",
    ],
)
def test_event_mapping_corruption_always_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    config, _ = _initialized_runtime(tmp_path, monkeypatch)
    _create_store(config)
    event_path = config.runtime_root / "sessions" / _SESSION_ID / "events" / "0000000000000000.json"
    value = json.loads(event_path.read_bytes())
    assert type(value) is dict
    event = cast(dict[str, object], value)
    if corruption == "extra_key":
        event["extra"] = True
    elif corruption == "schema":
        event["schema_version"] = 2
    elif corruption == "previous":
        event["previous_sha256"] = "f" * 64
    elif corruption == "unknown_kind":
        event["kind"] = "unknown"
    elif corruption == "state_type":
        event["state"] = 1
    elif corruption == "snapshot_type":
        event["snapshot"] = "invalid"
    elif corruption == "state_mismatch":
        event["state"] = RepairState.GENERATING.value
    elif corruption == "timestamp_mismatch":
        event["timestamp_us"] = 2
    else:
        assert corruption == "initial_kind"
        event["kind"] = "candidate"
    event_path.chmod(0o600)
    event_path.write_bytes(_canonical_bytes(event))
    event_path.chmod(0o400)

    with (
        pytest.raises(RepairError) as captured,
        _locked_session(
            config,
            _SESSION_ID,
        ) as storage,
    ):
        storage.load()

    assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
    assert captured.value.stage is RepairStage.PERSISTENCE
    assert captured.value.session_id == _SESSION_ID


def test_store_append_rejects_invalid_control_updates_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _initialized_runtime(tmp_path, monkeypatch)
    _create_store(config)
    created = _snapshot()
    other = _snapshot(session_id=_OTHER_SESSION_ID)

    with _locked_session(config, _SESSION_ID) as storage:
        with pytest.raises(ValueError, match="event kind"):
            storage.append("unknown", created)
        with pytest.raises(ValueError, match="event snapshot"):
            storage.append("candidate", other)
        with pytest.raises(ValueError, match="event timestamps"):
            storage.append(
                "candidate",
                replace(created, created_at_us=2, updated_at_us=2),
            )
        with pytest.raises(ValueError, match="requires a lease"):
            storage.append("validation_run", created)
        with pytest.raises(ValueError, match="not registered"):
            storage.append("candidate", created, clear_validation_run=True)
        assert storage.load().event_sequence == 0


def test_validation_run_lease_rejects_unbound_container_metadata() -> None:
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION_ID),
                ("com.repoguard.candidate", _CANDIDATE_ID),
                ("com.repoguard.run-token-sha256", "e" * 64),
            )
        )
    )
    with pytest.raises(ValueError, match="container identity"):
        _ValidationRunLease(
            "bad", "repoguard-validation", labels, _SESSION_ID, _CANDIDATE_ID, "e" * 64
        )
    with pytest.raises(ValueError, match="container name"):
        _ValidationRunLease(
            "f" * 64,
            "bad/name",
            labels,
            _SESSION_ID,
            _CANDIDATE_ID,
            "e" * 64,
        )
    with pytest.raises(ValueError, match="labels are invalid"):
        _ValidationRunLease(
            "f" * 64,
            "repoguard-validation",
            tuple(reversed(labels)),
            _SESSION_ID,
            _CANDIDATE_ID,
            "e" * 64,
        )
    with pytest.raises(ValueError, match="labels do not match"):
        _ValidationRunLease(
            "f" * 64,
            "repoguard-validation",
            tuple(
                (name, "0" * 64) if name == "com.repoguard.candidate" else (name, value)
                for name, value in labels
            ),
            _SESSION_ID,
            _CANDIDATE_ID,
            "e" * 64,
        )


def test_private_cleanup_refuses_top_level_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _initialized_runtime(tmp_path, monkeypatch)
    _create_store(config)
    session_root = config.runtime_root / "sessions" / _SESSION_ID
    outside = tmp_path / "outside-private"
    outside.mkdir(mode=0o700)
    sentinel = outside / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")

    with _locked_session(config, _SESSION_ID) as storage:
        private = session_root / "private"
        retained = session_root / "private-retained"
        private.rename(retained)
        private.symlink_to(outside, target_is_directory=True)
        assert storage.cleanup_private() is False

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert (session_root / "private").is_symlink()
    assert (session_root / "private-retained" / "request.json").is_file()


def test_corrupt_request_fails_before_generation_state_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, session = _session(tmp_path, monkeypatch)

    error = _assert_repair_error(
        lambda: session.propose(),
        code=RepairErrorCode.SESSION_CORRUPT,
        stage=RepairStage.PERSISTENCE,
    )

    assert error.state is RepairState.CREATED
    assert session.snapshot().state is RepairState.CREATED
    events = config.runtime_root / "sessions" / _SESSION_ID / "events"
    assert len(tuple(events.iterdir())) == 1


def test_created_session_rejects_approval_application_and_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, session = _session(tmp_path, monkeypatch)

    for operation, stage in (
        (
            lambda: session.approve(
                subject="local reviewer",
                expected_candidate_id=_CANDIDATE_ID,
                expected_validation_sha256="e" * 64,
                confirmation=REPAIR_APPROVAL_CONFIRMATION,
            ),
            RepairStage.APPROVAL,
        ),
        (
            lambda: session.apply(expected_approval_sha256="f" * 64),
            RepairStage.APPLICATION,
        ),
        (
            lambda: session.reject(
                subject="local reviewer",
                reason="not accepted",
                expected_candidate_id=_CANDIDATE_ID,
            ),
            RepairStage.APPROVAL,
        ),
    ):
        error = _assert_repair_error(
            operation,
            code=RepairErrorCode.INVALID_STATE,
            stage=stage,
        )
        assert error.state is RepairState.CREATED
    assert session.snapshot().state is RepairState.CREATED


def test_corrupt_preview_record_is_never_returned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, session = _session(tmp_path, monkeypatch)
    candidate = _candidate()
    with _locked_session(config, _SESSION_ID) as storage:
        generating = replace(
            storage.load().snapshot,
            state=RepairState.GENERATING,
            updated_at_us=2,
        )
        generating = storage.append("generating", generating).snapshot
        checkpoint = replace(generating, updated_at_us=3, candidate=candidate)
        storage.write_preview({"schema_version": 1})
        storage.append("candidate", checkpoint)

    error = _assert_repair_error(
        session.preview,
        code=RepairErrorCode.SESSION_CORRUPT,
        stage=RepairStage.PERSISTENCE,
    )

    assert error.state is RepairState.GENERATING


def test_context_identity_capture_maps_unknown_backend_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = ContextIndex(_ExplodingIndexState())
    error = _assert_repair_error(
        lambda: workflow_module._capture_context_identity(index),
        code=RepairErrorCode.IDENTITY_MISMATCH,
        stage=RepairStage.RETRIEVAL,
    )
    assert error.state is None


@pytest.mark.parametrize("payload", [b"", b"\xff", b"not the committed diff\n"])
def test_candidate_diff_corruption_is_content_free_error(payload: bytes) -> None:
    storage = cast(_SessionStore, _PrivateBytesReader(payload))

    error = _assert_repair_error(
        lambda: workflow_module._read_candidate_diff(
            storage,
            _snapshot(state=RepairState.GENERATING, candidate=_candidate()),
        ),
        code=RepairErrorCode.SESSION_CORRUPT,
        stage=RepairStage.PERSISTENCE,
    )

    assert error.state is RepairState.GENERATING
    if payload:
        assert payload not in str(error).encode("utf-8")


def test_candidate_diff_accepts_only_the_candidate_digest() -> None:
    payload = b"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n"
    candidate = replace(
        _candidate(),
        diff_sha256=hashlib.sha256(payload).hexdigest(),
    )
    storage = cast(_SessionStore, _PrivateBytesReader(payload))

    assert workflow_module._read_candidate_diff(
        storage,
        _snapshot(state=RepairState.GENERATING, candidate=candidate),
    ) == payload.decode("utf-8")


def test_file_digest_rejects_relative_and_missing_paths(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="digest path"):
        workflow_module._sha256_file(Path("relative"))

    _assert_repair_error(
        lambda: workflow_module._sha256_file(tmp_path / "missing"),
        code=RepairErrorCode.SANDBOX_UNAVAILABLE,
        stage=RepairStage.SANDBOX,
    )


def test_host_input_validation_maps_native_path_failures(
    tmp_path: Path,
) -> None:
    missing = _config(tmp_path / "runtime")
    _assert_repair_error(
        lambda: store_module._validate_host_inputs(missing),
        code=RepairErrorCode.INVALID_CONFIG,
        stage=RepairStage.INPUT,
    )

    executable_directory = tmp_path / "not-an-executable"
    executable_directory.mkdir()
    invalid_executable = RepairManagerConfig(
        tmp_path / "runtime-2",
        executable_directory,
        Path("/bin/true"),
        tmp_path / "missing.sock",
    )
    _assert_repair_error(
        lambda: store_module._validate_host_inputs(invalid_executable),
        code=RepairErrorCode.INVALID_CONFIG,
        stage=RepairStage.INPUT,
    )
