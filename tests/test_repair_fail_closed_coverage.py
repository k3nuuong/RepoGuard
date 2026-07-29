"""Focused fail-closed coverage for M5 retrieval, persistence, and workflow boundaries."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import repoguard._repair_retrieval as retrieval_module
import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
import repoguard._retrieval as retrieval_core
from repoguard._repair_models import _domain_digest
from repoguard._repair_retrieval import (
    _context_index_identity_sha256,
    _retrieve_repair_context,
    _validate_live_index,
)
from repoguard._repair_store import (
    _create_session_store,
    _initialize_runtime_root,
    _locked_session,
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
    RepairFailure,
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairManager,
    RepairManagerConfig,
    RepairPromptIdentity,
    RepairProviderKind,
    RepairSnapshot,
    RepairStage,
    RepairState,
    RepairValidation,
    ValidationCommandResult,
    repair_candidate_to_dict,
    repair_validation_to_dict,
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
    RetrievalError,
    RetrievalErrorCode,
    RetrievalHit,
    RetrievalResult,
    RetrievalStage,
)

_SESSION_ID = "1" * 64
_OTHER_SESSION_ID = "2" * 64
_REQUEST_SHA256 = "3" * 64
_RUN_TOKEN_SHA256 = "5" * 64
_CONTAINER_ID = "6" * 64
_HEAD_OID = "7" * 40
_BLOB_OID = "8" * 40
_MODEL = "BAAI/bge-small-en-v1.5"
_MODEL_REVISION = "52398278842ec682c6f32300af41344b1c0b0bb2"


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(
        RepairGenerationMode.PROVIDER,
        RepairProviderKind.OPENAI,
        "repair-model",
    )


def _identity(*, config_sha256: str = "9" * 64) -> IndexIdentity:
    return IndexIdentity(
        Path("/repository"),
        "sha1",
        _HEAD_OID,
        (RetrievalChannel.TEXT,),
        config_sha256,
        _MODEL,
        _MODEL_REVISION,
        "a" * 64,
        384,
        EmbeddingDevice.CPU,
    )


def _statistics() -> IndexStatistics:
    return IndexStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0)


class _FakeIndexState:
    def __init__(self, identity: IndexIdentity) -> None:
        self._identity = identity
        self._closed = False

    @property
    def identity(self) -> IndexIdentity:
        return self._identity

    @property
    def statistics(self) -> IndexStatistics:
        return _statistics()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True


class _AttestedConfig:
    def __init__(self, channels: tuple[RetrievalChannel, ...]) -> None:
        self.channels = channels


class _AttestedIndexState:
    def __init__(self, identity: IndexIdentity) -> None:
        self._lock = threading.Lock()
        self.identity = identity
        self.statistics = _statistics()
        self._provider = object()
        self._config = _AttestedConfig(identity.channels)


class _ExplodingIndexState(_FakeIndexState):
    @property
    def identity(self) -> IndexIdentity:
        raise RuntimeError("native identity failure")


def _retrieval_hit() -> RetrievalHit:
    content = "def helper(value: int) -> int:\n    return value + 1\n"
    provenance = ChunkProvenance(
        "b" * 64,
        "src/helper.py",
        _BLOB_OID,
        0,
        len(content.encode("utf-8")),
        10,
        11,
    )
    chunk = ContextChunk(
        provenance,
        content,
        (),
        ("helper",),
        ("value",),
    )
    return RetrievalHit(
        chunk,
        (RetrievalChannel.TEXT,),
        1,
        None,
        None,
        1,
        61,
    )


def test_retrieval_projects_exact_hits_and_binds_empty_query_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))
    hit = _retrieval_hit()
    query = ContextQuery("helper usage")
    result = RetrievalResult(
        identity,
        retrieval_core._validated_query_digest((query.text,)),
        2,
        1,
        1,
        (hit,),
    )
    calls: list[tuple[ContextQuery, ...]] = []

    def accept_live_index(
        _index: ContextIndex,
        _expected: IndexIdentity,
        _deadline: float,
    ) -> None:
        return None

    def retrieve(
        _index: ContextIndex,
        queries: tuple[ContextQuery, ...],
        *,
        deadline: float,
    ) -> RetrievalResult:
        assert deadline == 10.0
        calls.append(queries)
        return result

    monkeypatch.setattr(retrieval_module, "_validate_live_index", accept_live_index)
    monkeypatch.setattr(retrieval_core, "_retrieve_context_queries", retrieve)

    projected = _retrieve_repair_context(
        expected_identity=identity,
        index=index,
        queries=(query,),
        policy=_policy(),
        deadline=10.0,
    )

    assert projected.summary.outcome is RepairContextOutcome.USED
    assert projected.summary.index_identity_sha256 == _context_index_identity_sha256(identity)
    assert projected.summary.query_count == 1
    assert projected.summary.candidate_count == 2
    assert projected.summary.selected_hit_count == 1
    assert projected.summary.hit_identity_sha256 is not None
    assert projected.summary.degradation_code is None
    assert len(projected.hits) == 1
    assert projected.hits[0].path == "src/helper.py"
    assert projected.hits[0].oid == _BLOB_OID
    assert projected.hits[0].content == hit.chunk.content
    assert projected.hits[0].definitions == ("helper",)
    assert projected.hits[0].references == ("value",)
    assert calls == [(query,)]

    empty = _retrieve_repair_context(
        expected_identity=identity,
        index=index,
        queries=(),
        policy=_policy(),
        deadline=10.0,
    )

    assert empty.summary.outcome is RepairContextOutcome.USED
    assert empty.summary.query_count == 0
    assert empty.summary.candidate_count == 0
    assert empty.summary.selected_hit_count == 0
    assert empty.summary.hit_identity_sha256 is not None
    assert empty.hits == ()
    assert calls == [(query,)]


def test_retrieval_rejects_result_from_a_different_exact_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _identity()
    index = ContextIndex(_FakeIndexState(expected))
    foreign = _identity(config_sha256="d" * 64)
    result = RetrievalResult(foreign, "e" * 64, 0, 0, 0, ())

    monkeypatch.setattr(retrieval_module, "_validate_live_index", lambda *_: None)
    monkeypatch.setattr(
        retrieval_core,
        "_retrieve_context_queries",
        lambda *_args, **_kwargs: result,
    )

    with pytest.raises(RepairError) as captured:
        _retrieve_repair_context(
            expected_identity=expected,
            index=index,
            queries=(ContextQuery("query"),),
            policy=_policy(),
            deadline=10.0,
            state=RepairState.GENERATING,
            session_id=_SESSION_ID,
        )

    assert captured.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert captured.value.stage is RepairStage.RETRIEVAL
    assert captured.value.state is RepairState.GENERATING
    assert captured.value.session_id == _SESSION_ID
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    ("retrieval_code", "repair_code"),
    [
        (RetrievalErrorCode.GIT_UNAVAILABLE, RepairErrorCode.GIT_UNAVAILABLE),
        (RetrievalErrorCode.READ_FAILED, RepairErrorCode.GIT_FAILED),
        (RetrievalErrorCode.MISSING_OBJECT, RepairErrorCode.MISSING_OBJECT),
        (RetrievalErrorCode.QUERY_LIMIT_EXCEEDED, RepairErrorCode.RESOURCE_LIMIT),
    ],
)
def test_non_degradable_retrieval_failures_map_to_stable_repair_errors(
    monkeypatch: pytest.MonkeyPatch,
    retrieval_code: RetrievalErrorCode,
    repair_code: RepairErrorCode,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))

    def fail(
        _index: ContextIndex,
        _expected: IndexIdentity,
        _deadline: float,
    ) -> None:
        raise RetrievalError(retrieval_code, RetrievalStage.QUERY_TEXT)

    monkeypatch.setattr(retrieval_module, "_validate_live_index", fail)

    with pytest.raises(RepairError) as captured:
        _retrieve_repair_context(
            expected_identity=identity,
            index=index,
            queries=(ContextQuery("query"),),
            policy=_policy(),
            deadline=10.0,
        )

    assert captured.value.code is repair_code
    assert captured.value.stage is RepairStage.RETRIEVAL
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_live_index_attestation_enforces_deadline_and_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))
    state = _AttestedIndexState(identity)
    monkeypatch.setattr(retrieval_core, "_validated_state", lambda _: state)
    monkeypatch.setattr(
        retrieval_core,
        "_validate_initialized_provider",
        lambda _: ("fixed-provider", EmbeddingDevice.CPU),
    )
    monkeypatch.setattr(
        retrieval_core,
        "_model_identity",
        lambda _: (_MODEL, _MODEL_REVISION, "a" * 64, 384),
    )
    monkeypatch.setattr(retrieval_core, "_config_sha256", lambda _: "9" * 64)

    _validate_live_index(index, identity, retrieval_module._monotonic() + 1.0)

    with pytest.raises(ValueError, match="live context index identity is invalid"):
        _validate_live_index(
            index,
            _identity(config_sha256="d" * 64),
            retrieval_module._monotonic() + 1.0,
        )

    with pytest.raises(RetrievalError) as captured:
        _validate_live_index(index, identity, retrieval_module._monotonic())
    assert captured.value.code is RetrievalErrorCode.DEADLINE_EXCEEDED
    assert captured.value.stage is RetrievalStage.VALIDATE


def _store_config(runtime_root: Path) -> RepairManagerConfig:
    return RepairManagerConfig(
        runtime_root,
        Path("/bin/true"),
        Path("/bin/true"),
        Path("/run/repoguard-test.sock"),
    )


def _snapshot(session_id: str = _SESSION_ID) -> RepairSnapshot:
    return RepairSnapshot(
        1,
        session_id,
        RepairState.CREATED,
        _REQUEST_SHA256,
        1,
        1,
        1,
        ("src/app.py",),
        None,
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
        RepairPromptIdentity(
            "agent_repair",
            1,
            "0" * 64,
            "1" * 64,
            "2" * 64,
        ),
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
        "d" * 64,
        "f" * 40,
        "0" * 40,
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


def _validation() -> RepairValidation:
    command = ValidationCommandResult(
        0,
        0,
        None,
        False,
        10,
        "1" * 64,
        0,
        False,
        "2" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        "0" * 64,
        _CANDIDATE_ID,
        "3" * 64,
        "4" * 64,
        f"sha256:{'5' * 64}",
        3,
        4,
        True,
        None,
        (command,),
        1,
        False,
        0,
        2,
        2,
        True,
    )
    payload = repair_validation_to_dict(validation)
    del payload["validation_sha256"]
    return replace(validation, validation_sha256=_domain_digest("validation", payload))


_VALIDATION_SHA256 = _validation().validation_sha256


def _validated_snapshot() -> RepairSnapshot:
    return RepairSnapshot(
        1,
        _SESSION_ID,
        RepairState.VALIDATED,
        _REQUEST_SHA256,
        1,
        2,
        1,
        ("src/app.py",),
        _candidate(),
        _validation(),
        None,
        None,
        None,
        None,
        False,
    )


def _initialized_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepairManagerConfig:
    repository = tmp_path / "repository"
    common = repository / ".git"
    repository.mkdir(mode=0o700)
    common.mkdir(mode=0o700)
    config = _store_config(tmp_path / "runtime")
    monkeypatch.setattr(store_module, "_validate_host_inputs", lambda _: None)
    _initialize_runtime_root(config, repository_root=repository, common_dir=common)
    return config


def _manager_for_store(
    config: RepairManagerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepairManager:
    repository = tmp_path / "manager-repository"
    repository.mkdir(mode=0o700)
    monkeypatch.setattr(workflow_module, "_initialize_manager", lambda *_: None)
    return RepairManager(RepositoryInput(repository), config)


def _create_store(
    config: RepairManagerConfig,
    session_id: str = _SESSION_ID,
) -> Path:
    _create_session_store(
        config,
        session_id,
        request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
        snapshot=_snapshot(session_id),
    )
    return config.runtime_root / "sessions" / session_id


def _lease() -> _ValidationRunLease:
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION_ID),
                ("com.repoguard.candidate", _CANDIDATE_ID),
                ("com.repoguard.run-token-sha256", _RUN_TOKEN_SHA256),
            )
        )
    )
    return _ValidationRunLease(
        _CONTAINER_ID,
        "repoguard-m5-fail-closed-test",
        labels,
        _SESSION_ID,
        _CANDIDATE_ID,
        _RUN_TOKEN_SHA256,
    )


@pytest.mark.parametrize(
    "corruption",
    ["digest", "name", "label_order", "label_identity"],
)
def test_validation_lease_rejects_ambiguous_container_identity(corruption: str) -> None:
    lease = _lease()
    with pytest.raises(ValueError):
        if corruption == "digest":
            replace(lease, container_id="not-a-digest")
        elif corruption == "name":
            replace(lease, container_name="-invalid")
        elif corruption == "label_order":
            replace(lease, labels=tuple(reversed(lease.labels)))
        else:
            labels = tuple(
                sorted(
                    (
                        ("com.repoguard.component", "foreign-component"),
                        ("com.repoguard.session", _SESSION_ID),
                        ("com.repoguard.candidate", _CANDIDATE_ID),
                        ("com.repoguard.run-token-sha256", _RUN_TOKEN_SHA256),
                    )
                )
            )
            replace(lease, labels=labels)


def test_event_store_rejects_invalid_mutations_without_extending_the_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    session_path = _create_store(config)

    with _locked_session(config, _SESSION_ID) as storage:
        created = storage.load()
        with pytest.raises(ValueError, match="event kind is invalid"):
            storage.append("unknown", created.snapshot)
        with pytest.raises(ValueError, match="event snapshot is invalid"):
            storage.append("candidate", replace(created.snapshot, session_id=_OTHER_SESSION_ID))
        with pytest.raises(ValueError, match="validation run update is invalid"):
            storage.append(
                "candidate",
                created.snapshot,
                validation_run=_lease(),
                clear_validation_run=True,
            )
        with pytest.raises(ValueError, match="private payload name is invalid"):
            storage.write_private_bytes("../outside", b"secret")
        storage.write_private_json("metadata.json", {"schema_version": 1})
        assert storage.read_private_json("metadata.json") == {"schema_version": 1}
        with pytest.raises(ValueError, match="private payload is invalid"):
            storage.write_private_bytes("oversized.bin", b"x" * 4_194_305)

        generating = replace(
            created.snapshot,
            state=RepairState.GENERATING,
            updated_at_us=2,
        )
        generating = storage.append("generating", generating).snapshot
        with pytest.raises(ValueError, match="validation run registration is invalid"):
            storage.append("validation_run", generating, validation_run=_lease())
        with pytest.raises(ValueError, match="validation run event requires a lease"):
            storage.append("validation_run", generating)
        with pytest.raises(ValueError, match="validation run is not registered"):
            storage.append("candidate", generating, clear_validation_run=True)
        with pytest.raises(ValueError, match="event timestamps are invalid"):
            storage.append("candidate", replace(generating, updated_at_us=1))

        after = storage.load()

    assert after.event_sequence == 1
    assert after.snapshot == generating
    assert tuple(path.name for path in sorted((session_path / "events").iterdir())) == (
        "0000000000000000.json",
        "0000000000000001.json",
    )
    assert not (session_path.parent / "outside").exists()


def test_private_cleanup_refuses_a_replaced_non_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    session_path = _create_store(config)
    private_path = session_path / "private"
    retained_path = session_path / "retained-private"

    with _locked_session(config, _SESSION_ID) as storage:
        private_path.rename(retained_path)
        private_path.write_bytes(b"attacker-controlled replacement")
        assert storage.cleanup_private() is False

    assert private_path.read_bytes() == b"attacker-controlled replacement"
    assert (retained_path / "request.json").is_file()


def test_exact_container_cleanup_requires_remove_even_when_stop_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    manager = _manager_for_store(config, tmp_path, monkeypatch)
    lease = _lease()
    calls: list[str] = []

    def fail_stop(*_args: object) -> bool:
        calls.append("stop")
        raise RepairError(RepairErrorCode.SANDBOX_UNAVAILABLE, RepairStage.SANDBOX)

    def remove(*_args: object) -> bool:
        calls.append("remove")
        return True

    monkeypatch.setattr(workflow_module, "_stop_exact_container", fail_stop)
    monkeypatch.setattr(workflow_module, "_remove_exact_container", remove)

    assert workflow_module._remove_validation_container(manager, lease) is True
    assert calls == ["stop", "remove"]

    def fail_remove(*_args: object) -> bool:
        calls.append("remove-failed")
        raise OSError("container remove failed")

    monkeypatch.setattr(workflow_module, "_remove_exact_container", fail_remove)
    assert workflow_module._remove_validation_container(manager, lease) is False
    assert calls[-2:] == ["stop", "remove-failed"]


def test_terminal_cleanup_failure_persists_pending_and_retains_validation_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    manager = _manager_for_store(config, tmp_path, monkeypatch)
    session_path = _create_store(config)
    lease = _lease()
    monkeypatch.setattr(
        workflow_module,
        "_remove_validation_container",
        lambda *_: False,
    )

    with _locked_session(config, _SESSION_ID) as storage:
        created = storage.load().snapshot
        generating = storage.append(
            "generating",
            replace(
                created,
                state=RepairState.GENERATING,
                updated_at_us=2,
            ),
        ).snapshot
        storage.write_preview({"schema_version": 1})
        checkpoint = storage.append(
            "candidate",
            replace(
                generating,
                candidate=_candidate(),
                updated_at_us=3,
            ),
        ).snapshot
        validating = storage.append(
            "validating",
            replace(
                checkpoint,
                state=RepairState.VALIDATING,
                updated_at_us=4,
            ),
        ).snapshot
        storage.append(
            "validation_intent",
            replace(validating, updated_at_us=5),
            validation_run=replace(lease, container_id=None),
        )
        registered = storage.append(
            "validation_run",
            replace(validating, updated_at_us=5),
            validation_run=lease,
        ).snapshot
        failure = RepairFailure(
            1,
            RepairErrorCode.CLEANUP_FAILED,
            RepairStage.CLEANUP,
            False,
            6,
        )
        failed = storage.append(
            "failed",
            replace(
                registered,
                state=RepairState.FAILED,
                updated_at_us=6,
                failure=failure,
                cleanup_pending=True,
            ),
        ).snapshot

        pending, cleaned = workflow_module._retry_terminal_cleanup(
            manager,
            storage,
            failed,
            lease,
        )
        loaded = storage.load()

    assert cleaned is False
    assert pending.state is RepairState.FAILED
    assert pending.cleanup_pending is True
    assert loaded.snapshot == pending
    assert loaded.validation_run == lease
    assert workflow_module._terminal_timestamp_us(pending) == 6
    assert (session_path / "private").is_dir()


def test_store_rebuilds_untrusted_cache_but_rejects_noncanonical_event_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    session_path = _create_store(config)
    state_path = session_path / "state.json"
    state_path.write_bytes(b'{"event_sequence":0}\n')

    with _locked_session(config, _SESSION_ID) as storage:
        loaded = storage.load()

    rebuilt = state_path.read_bytes()
    assert loaded.snapshot == _snapshot()
    assert json.loads(rebuilt)["event_sha256"] == loaded.event_sha256
    assert rebuilt == json.dumps(
        json.loads(rebuilt),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    event_path = session_path / "events" / "0000000000000000.json"
    event_path.chmod(0o600)
    event_path.write_bytes(b'{"schema_version":NaN}')
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


@pytest.mark.parametrize(
    "corruption",
    [
        "kind",
        "state_type",
        "snapshot_type",
        "snapshot_session",
        "lease_keys",
        "lease_labels_type",
        "lease_label_item",
        "lease_scalar",
    ],
)
def test_canonical_event_tampering_is_never_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    session_path = _create_store(config)
    event_path = session_path / "events" / "0000000000000000.json"
    mapping = cast(dict[str, object], json.loads(event_path.read_bytes()))
    lease_mapping: dict[str, object] = {
        "container_id": _CONTAINER_ID,
        "container_name": "repoguard-m5-fail-closed-test",
        "labels": [
            ["com.repoguard.candidate", _CANDIDATE_ID],
            ["com.repoguard.component", "safe-repair-validation"],
            ["com.repoguard.run-token-sha256", _RUN_TOKEN_SHA256],
            ["com.repoguard.session", _SESSION_ID],
        ],
        "session_id": _SESSION_ID,
        "candidate_id": _CANDIDATE_ID,
        "run_token_sha256": _RUN_TOKEN_SHA256,
    }
    if corruption == "kind":
        mapping["kind"] = "untrusted"
    elif corruption == "state_type":
        mapping["state"] = 1
    elif corruption == "snapshot_type":
        mapping["snapshot"] = []
    elif corruption == "snapshot_session":
        snapshot_mapping = cast(dict[str, object], mapping["snapshot"])
        snapshot_mapping["session_id"] = _OTHER_SESSION_ID
    elif corruption == "lease_keys":
        mapping["validation_run"] = {}
    elif corruption == "lease_labels_type":
        lease_mapping["labels"] = {}
        mapping["validation_run"] = lease_mapping
    elif corruption == "lease_label_item":
        lease_mapping["labels"] = [["only-one"]]
        mapping["validation_run"] = lease_mapping
    else:
        lease_mapping["container_id"] = 1
        mapping["validation_run"] = lease_mapping
    event_path.chmod(0o600)
    event_path.write_bytes(
        json.dumps(
            mapping,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
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
    assert event_path.is_file()


def test_workflow_rejects_invalid_frozen_request_and_empty_candidate_diff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _initialized_store(tmp_path, monkeypatch)
    _create_store(config)

    with _locked_session(config, _SESSION_ID) as storage:
        snapshot = storage.load().snapshot
        with pytest.raises(RepairError) as request_error:
            workflow_module._load_request(storage, snapshot)
        storage.write_private_bytes("candidate.diff", b"")
        with pytest.raises(RepairError) as diff_error:
            workflow_module._read_candidate_diff(storage, snapshot)

    for captured in (request_error, diff_error):
        assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
        assert captured.value.stage is RepairStage.PERSISTENCE
        assert captured.value.state is RepairState.CREATED
        assert captured.value.session_id == _SESSION_ID
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    _create_store(config, _OTHER_SESSION_ID)
    with _locked_session(config, _OTHER_SESSION_ID) as storage:
        other_snapshot = storage.load().snapshot
        storage.write_private_bytes("candidate.diff", b"\xff")
        with pytest.raises(RepairError) as encoding_error:
            workflow_module._read_candidate_diff(storage, other_snapshot)
    assert encoding_error.value.code is RepairErrorCode.SESSION_CORRUPT
    assert encoding_error.value.stage is RepairStage.PERSISTENCE
    assert encoding_error.value.session_id == _OTHER_SESSION_ID
    assert encoding_error.value.__cause__ is None
    assert encoding_error.value.__context__ is None


def test_approval_and_application_records_reject_invalid_identity_fields() -> None:
    validated = _validated_snapshot()

    with pytest.raises(RepairError) as approval_error:
        workflow_module._build_approval(
            validated,
            subject="\x00",
            confirmation=REPAIR_APPROVAL_CONFIRMATION,
            approved_at_us=3,
        )
    assert approval_error.value.code is RepairErrorCode.INVALID_DECISION
    assert approval_error.value.stage is RepairStage.APPROVAL
    assert approval_error.value.state is RepairState.VALIDATED

    with pytest.raises(RepairError) as missing_approval:
        workflow_module._build_application(
            validated,
            ref=f"refs/repoguard/repairs/{_CANDIDATE_ID}",
            commit_oid="0" * 40,
            applied_at_us=3,
        )
    assert missing_approval.value.code is RepairErrorCode.SESSION_CORRUPT
    assert missing_approval.value.stage is RepairStage.PERSISTENCE

    approval = workflow_module._build_approval(
        validated,
        subject="local reviewer",
        confirmation=REPAIR_APPROVAL_CONFIRMATION,
        approved_at_us=3,
    )
    approved = replace(
        validated,
        state=RepairState.APPROVED,
        updated_at_us=3,
        approval=approval,
    )
    with pytest.raises(RepairError) as application_error:
        workflow_module._build_application(
            approved,
            ref="refs/heads/main",
            commit_oid="0" * 40,
            applied_at_us=4,
        )
    assert application_error.value.code is RepairErrorCode.INVALID_WORKFLOW
    assert application_error.value.stage is RepairStage.APPLICATION
    assert application_error.value.state is RepairState.APPROVED
    assert application_error.value.__cause__ is None
    assert application_error.value.__context__ is None


def test_host_input_validation_requires_regular_executables_and_owned_unix_socket(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    git = tmp_path / "git"
    docker = tmp_path / "docker"
    for executable in (git, docker):
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
    socket_path = tmp_path / "docker.sock"
    rootless_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        rootless_socket.bind(str(socket_path))
        config = RepairManagerConfig(tmp_path / "runtime", git, docker, socket_path)
        store_module._validate_host_inputs(config)

        git_link = tmp_path / "git-link"
        git_link.symlink_to(git)
        with pytest.raises(RepairError) as symlink_error:
            store_module._validate_host_inputs(replace(config, git_executable=git_link))

        regular_socket = tmp_path / "not-a-socket"
        regular_socket.write_bytes(b"")
        with pytest.raises(RepairError) as socket_error:
            store_module._validate_host_inputs(
                replace(config, rootless_socket=regular_socket),
            )

        with pytest.raises(RepairError) as missing_error:
            store_module._validate_host_inputs(
                replace(config, docker_executable=tmp_path / "missing-docker"),
            )
        with pytest.raises(RepairError) as missing_socket_error:
            store_module._validate_host_inputs(
                replace(config, rootless_socket=tmp_path / "missing.sock"),
            )
    finally:
        rootless_socket.close()

    for captured in (symlink_error, socket_error):
        assert captured.value.code is RepairErrorCode.INVALID_CONFIG
        assert captured.value.stage is RepairStage.INPUT
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    assert missing_error.value.code is RepairErrorCode.INVALID_CONFIG
    assert missing_error.value.stage is RepairStage.INPUT
    assert missing_error.value.__cause__ is None
    assert missing_error.value.__context__ is None
    assert missing_socket_error.value.code is RepairErrorCode.INVALID_CONFIG
    assert missing_socket_error.value.stage is RepairStage.INPUT
    assert missing_socket_error.value.__cause__ is None
    assert missing_socket_error.value.__context__ is None


def test_context_capability_capture_and_sandbox_digest_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    index = ContextIndex(_FakeIndexState(identity))

    def accept_live_index(
        _index: ContextIndex,
        _expected: IndexIdentity,
        _deadline: float,
    ) -> None:
        return None

    monkeypatch.setattr(workflow_module, "_validate_live_index", accept_live_index)
    assert workflow_module._capture_context_identity(index) == identity

    with pytest.raises(RepairError) as type_error:
        workflow_module._capture_context_identity(cast(ContextIndex, object()))
    assert type_error.value.code is RepairErrorCode.IDENTITY_MISMATCH
    with pytest.raises(RepairError) as native_error:
        workflow_module._capture_context_identity(
            ContextIndex(_ExplodingIndexState(identity)),
        )
    assert native_error.value.code is RepairErrorCode.IDENTITY_MISMATCH

    def reject_live_index(
        _index: ContextIndex,
        _expected: IndexIdentity,
        _deadline: float,
    ) -> None:
        raise RetrievalError(RetrievalErrorCode.INDEX_CLOSED, RetrievalStage.VALIDATE)

    monkeypatch.setattr(workflow_module, "_validate_live_index", reject_live_index)
    with pytest.raises(RepairError) as identity_error:
        workflow_module._capture_context_identity(index)
    assert identity_error.value.code is RepairErrorCode.IDENTITY_MISMATCH
    assert identity_error.value.stage is RepairStage.RETRIEVAL

    artifact = tmp_path / "runner.py"
    artifact.write_bytes(b"fixed packaged runner")
    assert (
        workflow_module._sha256_file(artifact)
        == hashlib.sha256(b"fixed packaged runner").hexdigest()
    )

    with pytest.raises(TypeError, match="digest path is invalid"):
        workflow_module._sha256_file(Path("relative-runner.py"))
    with pytest.raises(RepairError) as digest_error:
        workflow_module._sha256_file(tmp_path / "missing-runner.py")
    assert digest_error.value.code is RepairErrorCode.SANDBOX_UNAVAILABLE
    assert digest_error.value.stage is RepairStage.SANDBOX
    assert digest_error.value.__cause__ is None
    assert digest_error.value.__context__ is None
