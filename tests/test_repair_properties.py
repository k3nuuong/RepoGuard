"""Deterministic properties for safe-repair pure functions."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import repoguard._repair_store as store_module
import repoguard._repair_workflow as workflow_module
from repoguard._repair_git import _parse_packed_repair_ref, _scan_packed_repair_ref
from repoguard._repair_models import (
    _can_transition,
    _canonical_bytes,
    _domain_digest,
    _is_terminal,
    _repair_snapshot_from_dict,
    _repair_target_from_dict,
)
from repoguard._repair_patch import _parse_wire_patch
from repoguard._repair_paths import _validate_repository_path
from repoguard._repair_store import (
    _create_session_store,
    _locked_session,
    _ValidationRunLease,
)
from repoguard._repair_workflow import _ApplicationRefOutcome
from repoguard.evidence import RepositoryInput
from repoguard.repair import (
    REPAIR_APPROVAL_CONFIRMATION,
    RepairApproval,
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
    RepairSnapshot,
    RepairState,
    RepairTarget,
    RepairValidation,
    ValidationCommandResult,
    repair_approval_to_dict,
    repair_candidate_to_dict,
    repair_snapshot_to_dict,
    repair_snapshot_to_json,
    repair_target_to_dict,
    repair_target_to_json,
    repair_validation_to_dict,
)

_PROPERTY_SETTINGS = settings(
    database=None,
    deadline=None,
    derandomize=True,
    max_examples=100,
)

_DIGEST_KINDS = (
    "request",
    "prompt",
    "context",
    "candidate",
    "validation",
    "approval",
    "application",
    "decision",
    "event",
    "preview",
    "policy",
    "sandbox-manifest",
    "run-token",
)

_TRANSITION_ORACLE = {
    (RepairState.CREATED, RepairState.GENERATING),
    (RepairState.CREATED, RepairState.CANCELLED),
    (RepairState.CREATED, RepairState.EXPIRED),
    (RepairState.GENERATING, RepairState.VALIDATING),
    (RepairState.GENERATING, RepairState.CANCELLED),
    (RepairState.GENERATING, RepairState.EXPIRED),
    (RepairState.GENERATING, RepairState.FAILED),
    (RepairState.VALIDATING, RepairState.VALIDATED),
    (RepairState.VALIDATING, RepairState.CANCELLED),
    (RepairState.VALIDATING, RepairState.EXPIRED),
    (RepairState.VALIDATING, RepairState.FAILED),
    (RepairState.VALIDATED, RepairState.APPROVED),
    (RepairState.VALIDATED, RepairState.REJECTED),
    (RepairState.VALIDATED, RepairState.CANCELLED),
    (RepairState.VALIDATED, RepairState.EXPIRED),
    (RepairState.APPROVED, RepairState.APPLYING),
    (RepairState.APPROVED, RepairState.REJECTED),
    (RepairState.APPROVED, RepairState.CANCELLED),
    (RepairState.APPROVED, RepairState.EXPIRED),
    (RepairState.APPLYING, RepairState.APPLIED),
    (RepairState.APPLYING, RepairState.APPROVED),
    (RepairState.APPLYING, RepairState.CANCELLED),
    (RepairState.APPLYING, RepairState.FAILED),
}

_TERMINAL = (
    RepairState.APPLIED,
    RepairState.REJECTED,
    RepairState.CANCELLED,
    RepairState.EXPIRED,
    RepairState.FAILED,
)

_SAFE_COMPONENT = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Lt", "Lo", "Nd")),
    min_size=1,
    max_size=24,
)
_SAFE_PATH = st.lists(_SAFE_COMPONENT, min_size=1, max_size=4).map("/".join)
_SAFE_LINE = st.text(
    alphabet=st.characters(
        blacklist_characters="\r\n\x00",
        blacklist_categories=("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"),
    ),
    max_size=40,
)

_SESSION_ID = "a" * 64
_REQUEST_SHA256 = "b" * 64
_OID = "1" * 40
_PROPERTY_CANDIDATE_ID = "c" * 64
_PROPERTY_REPAIR_REF = f"refs/repoguard/repairs/{_PROPERTY_CANDIDATE_ID}"


@_PROPERTY_SETTINGS
@given(
    finding_index=st.integers(min_value=0, max_value=1_000_000),
    reference_index=st.integers(min_value=0, max_value=1_000_000),
)
def test_serializer_is_deterministic_and_json_roundtrips(
    finding_index: int,
    reference_index: int,
) -> None:
    target = RepairTarget(finding_index, reference_index)
    encoded = repair_target_to_json(target)
    assert encoded == repair_target_to_json(target)
    assert json.loads(encoded) == repair_target_to_dict(target)
    assert _repair_target_from_dict(json.loads(encoded)) == target
    assert encoded.encode("utf-8").decode("utf-8") == encoded
    assert not encoded.endswith("\n")


@_PROPERTY_SETTINGS
@given(
    state=st.sampled_from(
        (
            RepairState.GENERATING,
            RepairState.VALIDATING,
            RepairState.VALIDATED,
            RepairState.APPROVED,
        )
    ),
    target_count=st.integers(min_value=1, max_value=16),
    updated_at_us=st.integers(min_value=2, max_value=2**63 - 1),
    path=_SAFE_PATH,
)
@example(
    state=RepairState.APPROVED,
    target_count=16,
    updated_at_us=2**63 - 1,
    path="源代码/repair file.py",
)
def test_nested_snapshot_serializer_and_digests_roundtrip(
    state: RepairState,
    target_count: int,
    updated_at_us: int,
    path: str,
) -> None:
    candidate = _property_candidate()
    validation = (
        _property_validation() if state in {RepairState.VALIDATED, RepairState.APPROVED} else None
    )
    approval = (
        _property_approval(approved_at_us=updated_at_us) if state is RepairState.APPROVED else None
    )
    snapshot = RepairSnapshot(
        1,
        _SESSION_ID,
        state,
        _REQUEST_SHA256,
        1,
        updated_at_us,
        target_count,
        (path,),
        candidate,
        validation,
        approval,
        None,
        None,
        None,
        False,
    )

    encoded = repair_snapshot_to_json(snapshot)
    mapping = json.loads(encoded)
    decoded = _repair_snapshot_from_dict(mapping)
    assert encoded == repair_snapshot_to_json(snapshot)
    assert mapping == repair_snapshot_to_dict(snapshot)
    assert decoded == snapshot
    assert encoded.encode("utf-8").decode("utf-8") == encoded
    assert not encoded.endswith("\n")

    assert decoded.candidate is not None
    candidate_payload = repair_candidate_to_dict(decoded.candidate)
    candidate_id = candidate_payload.pop("candidate_id")
    for name in (
        "changed_paths",
        "changed_line_count",
        "provider_attempt_count",
        "input_tokens",
        "output_tokens",
    ):
        del candidate_payload[name]
    assert candidate_id == _domain_digest("candidate", candidate_payload)
    if decoded.validation is not None:
        validation_payload = repair_validation_to_dict(decoded.validation)
        validation_sha256 = validation_payload.pop("validation_sha256")
        assert validation_sha256 == _domain_digest("validation", validation_payload)
    if decoded.approval is not None:
        approval_payload = repair_approval_to_dict(decoded.approval)
        approval_sha256 = approval_payload.pop("approval_sha256")
        assert approval_sha256 == _domain_digest("approval", approval_payload)


@_PROPERTY_SETTINGS
@given(
    value=st.dictionaries(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
        st.one_of(st.integers(), st.booleans(), st.none(), st.text(max_size=24)),
        max_size=8,
    ),
    pair=st.sampled_from(
        tuple(
            (left, right)
            for index, left in enumerate(_DIGEST_KINDS)
            for right in _DIGEST_KINDS[index + 1 :]
        )
    ),
)
def test_digest_domains_are_deterministic_and_separate(
    value: dict[str, object],
    pair: tuple[str, str],
) -> None:
    left, right = pair
    expected = hashlib.sha256(
        f"repoguard.m5.{left}.v1".encode("ascii") + b"\x00" + _canonical_bytes(value)
    ).hexdigest()
    actual = _domain_digest(left, value)
    assert actual == expected
    assert actual == _domain_digest(left, value)
    assert actual != _domain_digest(right, value)


@_PROPERTY_SETTINGS
@given(
    object_format=st.sampled_from(("sha1", "sha256")),
    unrelated_ids=st.lists(
        st.integers(min_value=0, max_value=2**32 - 1),
        max_size=16,
        unique=True,
    ),
    target_seed=st.one_of(st.none(), st.integers(min_value=0, max_value=2**64 - 1)),
    include_unicode=st.booleans(),
    separator=st.sampled_from((b" ", b"\t", b"\r")),
    chunk_size=st.integers(min_value=1, max_value=128),
)
@example(
    object_format="sha256",
    unrelated_ids=[0, 1, 2],
    target_seed=2**64 - 1,
    include_unicode=True,
    separator=b"\r",
    chunk_size=1,
)
def test_packed_repair_ref_parser_selects_only_the_optional_exact_target(
    object_format: str,
    unrelated_ids: list[int],
    target_seed: int | None,
    include_unicode: bool,
    separator: bytes,
    chunk_size: int,
) -> None:
    oid_length = 40 if object_format == "sha1" else 64

    def oid(label: str) -> str:
        return hashlib.sha256(label.encode("utf-8")).hexdigest()[:oid_length]

    records: list[tuple[bytes, str, str | None]] = []
    for index, identifier in enumerate(unrelated_ids):
        prefix = "属性-" if include_unicode and index == 0 else "property-"
        ref = f"refs/tags/{prefix}{identifier:08x}".encode()
        peeled = oid(f"peeled:{object_format}:{identifier}") if identifier % 2 == 0 else None
        records.append((ref, oid(f"object:{object_format}:{identifier}"), peeled))

    expected: str | None = None
    if target_seed is not None:
        expected = oid(f"target:{object_format}:{target_seed}")
        records.append((_PROPERTY_REPAIR_REF.encode("ascii"), expected, None))
    records.sort(key=lambda record: record[0])

    lines = [b"# pack-refs with: peeled fully-peeled sorted"]
    for ref, object_oid, peeled_oid in records:
        lines.append(object_oid.encode("ascii") + separator + ref)
        if peeled_oid is not None:
            lines.append(b"^" + peeled_oid.encode("ascii"))
    payload = b"\n".join(lines) + b"\n"
    chunks = tuple(
        payload[index : index + chunk_size] for index in range(0, len(payload), chunk_size)
    )

    assert _parse_packed_repair_ref(payload, _PROPERTY_REPAIR_REF, object_format) == expected
    assert _parse_packed_repair_ref(payload, _PROPERTY_REPAIR_REF, object_format) == expected
    assert _scan_packed_repair_ref(chunks, _PROPERTY_REPAIR_REF, object_format) == (
        expected,
        len(payload),
    )


@_PROPERTY_SETTINGS
@given(
    object_format=st.sampled_from(("sha1", "sha256")),
    mutation=st.sampled_from(
        (
            "arbitrary-comment",
            "blank-line",
            "duplicate-header",
            "duplicate-peeled",
            "invalid-separator",
            "malformed-unrelated",
            "missing-final-lf",
            "orphan-peeled",
        )
    ),
    chunk_size=st.integers(min_value=1, max_value=128),
)
@example(object_format="sha256", mutation="missing-final-lf", chunk_size=1)
def test_packed_ref_parser_rejects_invalid_complete_stream_across_chunk_boundaries(
    object_format: str,
    mutation: str,
    chunk_size: int,
) -> None:
    oid_length = 40 if object_format == "sha1" else 64
    oid = b"1" * oid_length
    target = _PROPERTY_REPAIR_REF.encode("ascii")
    direct = oid + b" " + target + b"\n"
    peeled = b"^" + oid + b"\n"
    header = b"# pack-refs with: peeled fully-peeled sorted\n"
    payload = {
        "arbitrary-comment": b"# local comment\n" + direct,
        "blank-line": b"\n" + direct,
        "duplicate-header": header + header + direct,
        "duplicate-peeled": direct + peeled + peeled,
        "invalid-separator": oid + b"\v" + target + b"\n",
        "malformed-unrelated": b"not-a-record\n" + direct,
        "missing-final-lf": direct[:-1],
        "orphan-peeled": peeled + direct,
    }[mutation]
    chunks = tuple(
        payload[index : index + chunk_size] for index in range(0, len(payload), chunk_size)
    )

    with pytest.raises(ValueError, match="packed"):
        _scan_packed_repair_ref(chunks, _PROPERTY_REPAIR_REF, object_format)


@_PROPERTY_SETTINGS
@given(path=_SAFE_PATH)
@example(path="src/Unicode file.py")
@example(path="源代码/修复.py")
def test_valid_repository_paths_preserve_exact_spelling(path: str) -> None:
    assert _validate_repository_path(path) == path
    assert _validate_repository_path(_validate_repository_path(path)) == path


@_PROPERTY_SETTINGS
@given(
    path=_SAFE_PATH,
    mutation=st.sampled_from(
        (
            "absolute",
            "backslash",
            "control",
            "dot",
            "dotdot",
            "git",
            "leading-space",
            "trailing-space",
        )
    ),
)
def test_generated_unsafe_repository_paths_are_rejected(path: str, mutation: str) -> None:
    unsafe = {
        "absolute": f"/{path}",
        "backslash": path.replace("/", "\\", 1) if "/" in path else f"bad\\{path}",
        "control": f"{path}\x00",
        "dot": f"./{path}",
        "dotdot": f"../{path}",
        "git": f".git/{path}",
        "leading-space": f" {path}",
        "trailing-space": f"{path} ",
    }[mutation]

    with pytest.raises(ValueError, match="path"):
        _validate_repository_path(unsafe)


@_PROPERTY_SETTINGS
@given(seed=st.integers(min_value=0, max_value=2**32 - 1))
@example(seed=2**32 - 1)
def test_repository_path_and_component_byte_limits_are_inclusive(
    seed: int,
) -> None:
    unit = "界" if seed % 2 else f"{seed:08x}"
    unit_bytes = len(unit.encode("utf-8"))

    def component(byte_length: int) -> str:
        repetitions, remainder = divmod(byte_length, unit_bytes)
        return (unit * repetitions) + ("a" * remainder)

    exact_path = "/".join(
        (
            component(255),
            component(255),
            component(255),
            component(254),
            component(1),
        )
    )
    one_past_path = f"{exact_path}a"
    assert len(exact_path.encode("utf-8")) == 1_024
    assert _validate_repository_path(exact_path) == exact_path
    assert len(one_past_path.encode("utf-8")) == 1_025
    with pytest.raises(ValueError, match="path"):
        _validate_repository_path(one_past_path)

    exact_component = component(255)
    one_past_component = component(256)
    assert _validate_repository_path(exact_component) == exact_component
    with pytest.raises(ValueError, match="component"):
        _validate_repository_path(one_past_component)


@_PROPERTY_SETTINGS
@given(
    path=_SAFE_PATH,
    old=st.one_of(_SAFE_LINE, st.just(""), st.just("私钥")),
    new=st.one_of(_SAFE_LINE, st.just(""), st.just("修复")),
    line_number=st.integers(min_value=1, max_value=1_000_000),
)
def test_minimal_patch_parser_preserves_lines_and_counts(
    path: str,
    old: str,
    new: str,
    line_number: int,
) -> None:
    patch = f"--- a/{path}\n+++ b/{path}\n@@ -{line_number} +{line_number} @@\n-{old}\n+{new}\n"
    parsed = _parse_wire_patch(patch, allowed_paths=(path,), policy=_policy())
    assert parsed.source == patch
    assert parsed.files[0].path == path
    assert parsed.files[0].hunks[0].lines[0].content == old
    assert parsed.files[0].hunks[0].lines[1].content == new
    assert parsed.changed_line_count == 2


@_PROPERTY_SETTINGS
@given(
    path=_SAFE_PATH,
    mutation=st.sampled_from(
        (
            "binary",
            "carriage-return",
            "delete",
            "extended-header",
            "mode",
            "nul",
            "rename",
        )
    ),
)
def test_generated_unsafe_wire_patches_are_rejected(path: str, mutation: str) -> None:
    valid = f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"
    unsafe = {
        "binary": f"Binary files a/{path} and b/{path} differ\n",
        "carriage-return": valid.replace("\n", "\r\n", 1),
        "delete": f"--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
        "extended-header": f"diff --git a/{path} b/{path}\n{valid}",
        "mode": f"old mode 100644\nnew mode 100755\n{valid}",
        "nul": valid.replace("+new", "+new\x00"),
        "rename": f"rename from {path}\nrename to renamed.py\n{valid}",
    }[mutation]

    with pytest.raises(RepairError) as captured:
        _parse_wire_patch(unsafe, allowed_paths=(path,), policy=_policy())

    assert captured.value.code is RepairErrorCode.PATCH_INVALID
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@_PROPERTY_SETTINGS
@given(changed_pairs=st.integers(min_value=1, max_value=100))
@example(changed_pairs=1)
@example(changed_pairs=100)
def test_patch_byte_and_changed_line_limits_are_inclusive(changed_pairs: int) -> None:
    deletions = "".join(f"-old-{index}\n" for index in range(changed_pairs))
    additions = "".join(f"+new-{index}\n" for index in range(changed_pairs))
    patch = (
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        f"@@ -1,{changed_pairs} +1,{changed_pairs} @@\n"
        f"{deletions}{additions}"
    )
    changed_lines = changed_pairs * 2
    exact = replace(
        _policy(),
        max_changed_lines=changed_lines,
        max_patch_bytes=len(patch.encode("utf-8")),
    )
    assert (
        _parse_wire_patch(
            patch,
            allowed_paths=("src/app.py",),
            policy=exact,
        ).changed_line_count
        == changed_lines
    )

    with pytest.raises(RepairError) as captured:
        _parse_wire_patch(
            patch,
            allowed_paths=("src/app.py",),
            policy=replace(exact, max_patch_bytes=exact.max_patch_bytes - 1),
        )
    assert captured.value.code is RepairErrorCode.PATCH_LIMIT

    with pytest.raises(RepairError) as captured:
        _parse_wire_patch(
            patch,
            allowed_paths=("src/app.py",),
            policy=replace(exact, max_changed_lines=changed_lines - 1),
        )
    assert captured.value.code is RepairErrorCode.PATCH_LIMIT


@_PROPERTY_SETTINGS
@given(
    path_count=st.integers(min_value=2, max_value=32),
    nonce=st.integers(min_value=0, max_value=2**32 - 1),
)
@example(path_count=2, nonce=0)
@example(path_count=32, nonce=2**32 - 1)
def test_patch_path_count_limit_is_inclusive(path_count: int, nonce: int) -> None:
    paths = tuple(f"src/case-{nonce:08x}-file-{index:02d}.py" for index in range(path_count))
    patch = "".join(f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n" for path in paths)
    exact = replace(_policy(), max_patch_paths=path_count)
    parsed = _parse_wire_patch(patch, allowed_paths=paths, policy=exact)
    assert tuple(file.path for file in parsed.files) == paths

    with pytest.raises(RepairError) as captured:
        _parse_wire_patch(
            patch,
            allowed_paths=paths,
            policy=replace(exact, max_patch_paths=path_count - 1),
        )
    assert captured.value.code is RepairErrorCode.PATCH_LIMIT


@_PROPERTY_SETTINGS
@given(current=st.sampled_from(tuple(RepairState)), target=st.sampled_from(tuple(RepairState)))
def test_state_transitions_match_the_complete_oracle(
    current: RepairState,
    target: RepairState,
) -> None:
    assert _can_transition(current, target) is ((current, target) in _TRANSITION_ORACLE)


def test_all_121_state_transition_pairs_match_the_explicit_oracle() -> None:
    evaluated: set[tuple[RepairState, RepairState]] = set()
    for current in RepairState:
        for target in RepairState:
            pair = (current, target)
            evaluated.add(pair)
            assert _can_transition(current, target) is (pair in _TRANSITION_ORACLE)
    assert len(evaluated) == 121


@_PROPERTY_SETTINGS
@given(
    terminal=st.sampled_from(_TERMINAL),
    targets=st.lists(
        st.sampled_from(tuple(RepairState)),
        min_size=1,
        max_size=8,
    ).map(tuple),
)
@example(terminal=RepairState.APPLIED, targets=tuple(RepairState))
@example(terminal=RepairState.REJECTED, targets=tuple(RepairState))
@example(terminal=RepairState.CANCELLED, targets=tuple(RepairState))
@example(terminal=RepairState.EXPIRED, targets=tuple(RepairState))
@example(terminal=RepairState.FAILED, targets=tuple(RepairState))
def test_terminal_states_absorb_every_mutation(
    terminal: RepairState,
    targets: tuple[RepairState, ...],
) -> None:
    assert _is_terminal(terminal)
    assert all(not _can_transition(terminal, target) for target in targets)


@_PROPERTY_SETTINGS
@given(
    update_count=st.integers(min_value=0, max_value=7),
    fault=st.sampled_from(("none", "temporary", "gap", "tamper", "reorder")),
    nonce=st.integers(min_value=0, max_value=2**64 - 1),
)
def test_event_recovery_accepts_only_a_complete_linked_prefix(
    update_count: int,
    fault: str,
    nonce: int,
) -> None:
    with tempfile.TemporaryDirectory(prefix="repoguard-m5-property-") as temporary:
        runtime_root = Path(temporary) / "runtime"
        runtime_root.mkdir(mode=0o700)
        (runtime_root / "sessions").mkdir(mode=0o700)
        config = RepairManagerConfig(
            runtime_root,
            Path("/usr/bin/true"),
            Path("/usr/bin/true"),
            Path("/run/user/1000/docker.sock"),
        )
        initial = _property_snapshot()
        _create_session_store(
            config,
            _SESSION_ID,
            request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
            snapshot=initial,
        )
        latest = replace(initial, state=RepairState.GENERATING, updated_at_us=2)
        candidate = _property_candidate()
        validation = _property_validation()
        lease = _property_lease()
        with _locked_session(config, _SESSION_ID) as storage:
            storage.append("generating", latest)
            if update_count >= 1:
                storage.write_preview({"schema_version": 1})
                latest = replace(latest, updated_at_us=3, candidate=candidate)
                storage.append("candidate", latest)
            if update_count >= 2:
                latest = replace(latest, state=RepairState.VALIDATING, updated_at_us=4)
                storage.append("validating", latest)
            if update_count >= 3:
                latest = replace(latest, updated_at_us=5)
                storage.append(
                    "validation_intent",
                    latest,
                    validation_run=replace(lease, container_id=None),
                )
            if update_count >= 4:
                storage.append("validation_run", latest, validation_run=lease)
            if update_count >= 5:
                latest = replace(latest, updated_at_us=6, validation=validation)
                storage.append("validation_result", latest)
            if update_count >= 6:
                latest = replace(latest, state=RepairState.VALIDATED, updated_at_us=7)
                storage.append("validated", latest, clear_validation_run=True)
            if update_count >= 7:
                latest = replace(
                    latest,
                    state=RepairState.APPROVED,
                    updated_at_us=8,
                    approval=_property_approval(approved_at_us=8),
                )
                storage.append("approved", latest)

        session = runtime_root / "sessions" / _SESSION_ID
        events = session / "events"
        event_names = sorted(events.iterdir())
        if fault == "temporary":
            temporary_cache = session / f".state.json.tmp-{nonce:016x}"
            temporary_cache.write_bytes(b"uncommitted")
            temporary_cache.chmod(0o600)
        elif fault == "gap":
            event_names[-1].rename(events / f"{len(event_names):016d}.json")
        elif fault == "tamper":
            last = event_names[-1]
            mapping = json.loads(last.read_text(encoding="utf-8"))
            mapping["previous_sha256"] = f"{nonce:064x}"[-64:]
            last.chmod(0o600)
            last.write_text(
                json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                encoding="utf-8",
            )
            last.chmod(0o400)
        elif fault == "reorder":
            first, second = event_names[:2]
            first_bytes = first.read_bytes()
            second_bytes = second.read_bytes()
            first.chmod(0o600)
            second.chmod(0o600)
            first.write_bytes(second_bytes)
            second.write_bytes(first_bytes)
            first.chmod(0o400)
            second.chmod(0o400)

        if fault in {"none", "temporary"}:
            with _locked_session(config, _SESSION_ID) as storage:
                recovered = storage.load()
            assert recovered.snapshot == latest
            assert recovered.event_sequence == update_count + 1
        else:
            with (
                pytest.raises(RepairError) as captured,
                _locked_session(config, _SESSION_ID) as storage,
            ):
                storage.load()
            assert captured.value.code is RepairErrorCode.SESSION_CORRUPT
            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None


@_PROPERTY_SETTINGS
@given(
    prior_outcomes=st.lists(
        st.sampled_from(
            (
                _ApplicationRefOutcome.ABSENT,
                _ApplicationRefOutcome.FOREIGN,
            )
        ),
        max_size=6,
    )
)
@example(prior_outcomes=[])
@example(
    prior_outcomes=[
        _ApplicationRefOutcome.FOREIGN,
        _ApplicationRefOutcome.ABSENT,
    ]
)
def test_public_application_cas_is_idempotent_under_readback_schedules(
    prior_outcomes: list[_ApplicationRefOutcome],
) -> None:
    with tempfile.TemporaryDirectory(prefix="repoguard-m5-cas-property-") as temporary:
        temporary_root = Path(temporary)
        runtime_root = temporary_root / "runtime"
        runtime_root.mkdir(mode=0o700)
        (runtime_root / "sessions").mkdir(mode=0o700)
        repository = temporary_root / "repository"
        repository.mkdir(mode=0o700)
        config = RepairManagerConfig(
            runtime_root,
            Path("/usr/bin/true"),
            Path("/usr/bin/true"),
            Path("/run/user/1000/docker.sock"),
        )
        approved = _property_approved_snapshot(config)
        assert approved.state is RepairState.APPROVED
        private_repository = runtime_root / "sessions" / _SESSION_ID / "private" / "repository"
        private_repository.mkdir(mode=0o700)
        root_fd = os.open(
            runtime_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            runtime_root_identity = store_module._runtime_root_identity(root_fd)
        finally:
            os.close(root_fd)

        schedule = (*prior_outcomes, _ApplicationRefOutcome.EXPECTED)
        publications: list[object] = []
        observations: list[_ApplicationRefOutcome] = []

        def publish(*args: object, **kwargs: object) -> object:
            publications.append((args, kwargs))
            return object()

        def observe(*_: object, **__: object) -> _ApplicationRefOutcome:
            outcome = schedule[len(observations)]
            observations.append(outcome)
            return outcome

        events = runtime_root / "sessions" / _SESSION_ID / "events"

        def event_fingerprint() -> tuple[tuple[str, bytes], ...]:
            return tuple((path.name, path.read_bytes()) for path in sorted(events.iterdir()))

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                workflow_module,
                "_initialize_manager",
                lambda *_: runtime_root_identity,
            )
            monkeypatch.setattr(
                workflow_module,
                "_open_application_candidate",
                lambda *_: (object(), object()),
            )
            monkeypatch.setattr(workflow_module, "_publish_repair_ref", publish)
            monkeypatch.setattr(workflow_module, "_read_application_ref_outcome", observe)

            manager = RepairManager(RepositoryInput(repository), config)
            session = manager.open_session(_SESSION_ID)
            approval = approved.approval
            assert approval is not None
            approval_sha256 = approval.approval_sha256

            before_mismatch = session.snapshot()
            mismatch_events = event_fingerprint()
            with pytest.raises(RepairError) as captured:
                session.apply(expected_approval_sha256="f" * 64)
            assert captured.value.code is RepairErrorCode.APPROVAL_MISMATCH
            assert session.snapshot() == before_mismatch
            assert event_fingerprint() == mismatch_events
            assert publications == []
            assert observations == []

            for expected_outcome in prior_outcomes:
                expected_error = (
                    RepairErrorCode.PUBLICATION_FAILED
                    if expected_outcome is _ApplicationRefOutcome.ABSENT
                    else RepairErrorCode.REF_CONFLICT
                )
                with pytest.raises(RepairError) as captured:
                    session.apply(expected_approval_sha256=approval_sha256)
                assert captured.value.code is expected_error
                assert session.snapshot().state is RepairState.APPROVED

            applied = session.apply(expected_approval_sha256=approval_sha256)
            assert applied.state is RepairState.APPLIED
            assert applied.application is not None
            assert applied.application.approval_sha256 == approval_sha256
            assert applied.application.commit_oid == _OID
            assert observations == list(schedule)
            assert len(publications) == len(schedule)

            terminal_events = event_fingerprint()
            terminal_publication_count = len(publications)
            terminal_observations = tuple(observations)
            with pytest.raises(RepairError) as captured:
                session.apply(expected_approval_sha256=approval_sha256)
            assert captured.value.code is RepairErrorCode.INVALID_STATE
            assert session.snapshot() == applied
            assert event_fingerprint() == terminal_events
            assert len(publications) == terminal_publication_count
            assert tuple(observations) == terminal_observations
            assert not (runtime_root / "sessions" / _SESSION_ID / "private").exists()


def _policy() -> RepairGenerationPolicy:
    return RepairGenerationPolicy(RepairGenerationMode.DETERMINISTIC, None, None)


def _property_snapshot() -> RepairSnapshot:
    return RepairSnapshot(
        1,
        _SESSION_ID,
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


def _property_candidate() -> RepairCandidate:
    candidate = RepairCandidate(
        1,
        "0" * 64,
        _REQUEST_SHA256,
        RepairPromptIdentity("agent_repair", 1, "1" * 64, "2" * 64, "3" * 64),
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
        "4" * 64,
        _OID,
        _OID,
        ("src/app.py",),
        2,
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


_CANDIDATE_ID = _property_candidate().candidate_id


def _property_validation() -> RepairValidation:
    command = ValidationCommandResult(
        0,
        0,
        None,
        False,
        10,
        "5" * 64,
        0,
        False,
        "6" * 64,
        0,
        False,
    )
    validation = RepairValidation(
        1,
        "0" * 64,
        _CANDIDATE_ID,
        "7" * 64,
        "8" * 64,
        f"sha256:{'9' * 64}",
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


_VALIDATION_SHA256 = _property_validation().validation_sha256


def _property_approval(*, approved_at_us: int) -> RepairApproval:
    approval = RepairApproval(
        1,
        "0" * 64,
        _CANDIDATE_ID,
        _VALIDATION_SHA256,
        "local reviewer",
        REPAIR_APPROVAL_CONFIRMATION,
        approved_at_us,
    )
    payload = repair_approval_to_dict(approval)
    del payload["approval_sha256"]
    return replace(approval, approval_sha256=_domain_digest("approval", payload))


def _property_lease() -> _ValidationRunLease:
    labels = tuple(
        sorted(
            (
                ("com.repoguard.component", "safe-repair-validation"),
                ("com.repoguard.session", _SESSION_ID),
                ("com.repoguard.candidate", _CANDIDATE_ID),
                ("com.repoguard.run-token-sha256", "f" * 64),
            )
        )
    )
    return _ValidationRunLease(
        "0" * 64,
        "repoguard-m5-property",
        labels,
        _SESSION_ID,
        _CANDIDATE_ID,
        "f" * 64,
    )


def _property_approved_snapshot(config: RepairManagerConfig) -> RepairSnapshot:
    created = _property_snapshot()
    _create_session_store(
        config,
        _SESSION_ID,
        request={"schema_version": 1, "request_sha256": _REQUEST_SHA256},
        snapshot=created,
    )
    candidate = _property_candidate()
    validation = _property_validation()
    approval = _property_approval(approved_at_us=8)
    lease = _property_lease()
    generating = replace(created, state=RepairState.GENERATING, updated_at_us=2)
    checkpoint = replace(generating, updated_at_us=3, candidate=candidate)
    validating = replace(checkpoint, state=RepairState.VALIDATING, updated_at_us=4)
    registered = replace(validating, updated_at_us=5)
    validation_result = replace(registered, updated_at_us=6, validation=validation)
    validated = replace(
        validation_result,
        state=RepairState.VALIDATED,
        updated_at_us=7,
    )
    approved = replace(
        validated,
        state=RepairState.APPROVED,
        updated_at_us=8,
        approval=approval,
    )
    with _locked_session(config, _SESSION_ID) as storage:
        storage.append("generating", generating)
        storage.write_preview({"schema_version": 1})
        storage.append("candidate", checkpoint)
        storage.append("validating", validating)
        storage.append(
            "validation_intent",
            registered,
            validation_run=replace(lease, container_id=None),
        )
        storage.append("validation_run", registered, validation_run=lease)
        storage.append("validation_result", validation_result)
        storage.append("validated", validated, clear_validation_run=True)
        storage.append("approved", approved)
    return approved
