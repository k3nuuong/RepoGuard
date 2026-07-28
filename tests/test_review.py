"""Tests for the public deterministic review contract and fixed M2 rules."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import cast

import pytest

import repoguard._review as review_implementation
from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    FileChangeEvidence,
    FileVersion,
    RepositoryEvidence,
    RevisionEvidence,
)
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    FindingCategory,
    FindingSeverity,
    ReviewError,
    ReviewErrorCode,
    ReviewResult,
    RuleId,
    review_evidence,
    review_to_dict,
    review_to_json,
)

OID_A = "a" * 40
OID_B = "b" * 40
OID_C = "c" * 40
OID_256_A = "a" * 64
OID_256_B = "b" * 64
OID_256_C = "c" * 64

PRIVATE_KEY_LABELS = (
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)


class _FirstTraversalOnly(tuple[object, ...]):
    traversals = 0

    def __iter__(self) -> Iterator[object]:
        self.traversals += 1
        if self.traversals == 1:
            return super().__iter__()
        return iter(())


def _bundle(
    *changes: FileChangeEvidence,
    repository: RepositoryEvidence | None = None,
    revisions: RevisionEvidence | None = None,
) -> EvidenceBundle:
    return EvidenceBundle(
        repository=repository or RepositoryEvidence(root=Path("/work/repo"), object_format="sha1"),
        revisions=revisions
        or RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid=OID_A,
            head_oid=OID_B,
            merge_base_oid=OID_C,
        ),
        changes=changes,
    )


def _version(
    path: str,
    *,
    mode: str = "100644",
    oid: str = OID_B,
    content_kind: ContentKind = ContentKind.TEXT,
) -> FileVersion:
    return FileVersion(path=path, mode=mode, oid=oid, content_kind=content_kind)


def _addition(number: int, content: str) -> DiffLineEvidence:
    return DiffLineEvidence(
        kind=DiffLineKind.ADDITION,
        old_line_number=None,
        new_line_number=number,
        content=content,
        has_trailing_newline=True,
    )


def _text_change(
    path: str,
    additions: Sequence[tuple[int, str]],
    *,
    extra_lines: Sequence[DiffLineEvidence] = (),
    oid: str = OID_B,
) -> FileChangeEvidence:
    lines = tuple(_addition(number, content) for number, content in additions)
    lines += tuple(extra_lines)
    return FileChangeEvidence(
        change_type=ChangeType.ADDED,
        rename_similarity=None,
        old=None,
        new=_version(path, oid=oid),
        hunks=(
            DiffHunkEvidence(
                old_start=0,
                old_count=0,
                new_start=min((number for number, _ in additions), default=0),
                new_count=len(additions),
                lines=lines,
            ),
        ),
    )


def _metadata_change(
    path: str,
    *,
    new_mode: str = "100644",
    new_oid: str = OID_B,
    new_kind: ContentKind = ContentKind.TEXT,
    old_mode: str | None = None,
    old_oid: str = OID_A,
    old_kind: ContentKind = ContentKind.TEXT,
    change_type: ChangeType = ChangeType.MODIFIED,
) -> FileChangeEvidence:
    old = (
        None
        if old_mode is None
        else _version(path, mode=old_mode, oid=old_oid, content_kind=old_kind)
    )
    return FileChangeEvidence(
        change_type=change_type,
        rename_similarity=100 if change_type is ChangeType.RENAMED else None,
        old=old,
        new=_version(path, mode=new_mode, oid=new_oid, content_kind=new_kind),
        hunks=(),
    )


def _reference(
    path: str,
    *,
    oid: str = OID_B,
    start_line: int | None = None,
    end_line: int | None = None,
) -> EvidenceReference:
    return EvidenceReference(
        path=path,
        side=EvidenceSide.NEW,
        oid=oid,
        start_line=start_line,
        end_line=end_line,
    )


def _expected_finding(
    rule_id: RuleId,
    category: FindingCategory,
    severity: FindingSeverity,
    title: str,
    message: str,
    remediation: str,
    reference: EvidenceReference,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        message=message,
        remediation=remediation,
        references=(reference,),
    )


def test_public_enum_values_are_fixed() -> None:
    assert {member.value for member in RuleId} == {
        "private_key_material",
        "merge_conflict_marker",
        "executable_bit_added",
        "symlink_changed",
        "submodule_changed",
        "binary_content_changed",
    }
    assert {member.value for member in FindingCategory} == {
        "security",
        "correctness",
        "reviewability",
        "supply_chain",
    }
    assert {member.value for member in FindingSeverity} == {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }
    assert {member.value for member in EvidenceSide} == {"old", "new"}
    assert {member.value for member in ReviewErrorCode} == {
        "unsupported_evidence_schema",
        "invalid_evidence",
        "rule_execution_failed",
    }


def test_empty_review_retains_identity_and_serializes_exact_schema() -> None:
    bundle = _bundle()

    result = review_evidence(bundle)

    assert result.repository is bundle.repository
    assert result.revisions is bundle.revisions
    assert result.findings == ()
    assert review_to_dict(result) == {
        "schema_version": 1,
        "repository": {"root": "/work/repo", "object_format": "sha1"},
        "revisions": {
            "base_ref": "main",
            "head_ref": "feature",
            "base_oid": OID_A,
            "head_oid": OID_B,
            "merge_base_oid": OID_C,
        },
        "findings": [],
    }


def test_mixed_bundle_returns_exact_deduplicated_severity_ordered_findings() -> None:
    private_key = _text_change(
        "secrets/key.pem",
        (
            (10, "prefix -----BEGIN PRIVATE KEY-----"),
            (11, "sensitive-body-not-for-output"),
            (12, "-----END PRIVATE KEY----- suffix"),
        ),
    )
    conflict = _text_change(
        "conflict.txt",
        ((20, "<<<<<<< HEAD"), (21, "======="), (22, ">>>>>>> feature")),
    )
    symlink = _metadata_change(
        "link",
        old_mode="100644",
        old_oid=OID_B,
        old_kind=ContentKind.TEXT,
        new_mode="120000",
        new_kind=ContentKind.SYMLINK,
        change_type=ChangeType.TYPE_CHANGED,
    )
    submodule = _metadata_change(
        "vendor/module",
        new_mode="160000",
        new_kind=ContentKind.SUBMODULE,
    )
    executable = _metadata_change(
        "script.sh",
        old_mode="100644",
        new_mode="100755",
    )
    binary = _metadata_change(
        "image.bin",
        old_mode="100644",
        old_kind=ContentKind.BINARY,
        new_kind=ContentKind.BINARY,
    )
    bundle = _bundle(
        binary,
        executable,
        submodule,
        private_key,
        symlink,
        conflict,
        private_key,
    )

    result = review_evidence(bundle)

    assert result.findings == (
        _expected_finding(
            RuleId.PRIVATE_KEY_MATERIAL,
            FindingCategory.SECURITY,
            FindingSeverity.HIGH,
            "Private key material added",
            "Added lines contain a paired private-key block.",
            "Remove the private key, rotate any exposed credential, and load the replacement "
            "from an approved secret store.",
            _reference("secrets/key.pem", start_line=10, end_line=12),
        ),
        _expected_finding(
            RuleId.MERGE_CONFLICT_MARKER,
            FindingCategory.CORRECTNESS,
            FindingSeverity.MEDIUM,
            "Unresolved merge conflict added",
            "Added lines contain a complete unresolved merge-conflict block.",
            "Resolve the conflict, remove the conflict markers, and verify the intended "
            "combined content.",
            _reference("conflict.txt", start_line=20, end_line=22),
        ),
        _expected_finding(
            RuleId.SYMLINK_CHANGED,
            FindingCategory.SECURITY,
            FindingSeverity.MEDIUM,
            "Symbolic link introduced or changed",
            "The head version introduces a symbolic link or changes its target object.",
            "Verify that the link target is intentional and cannot escape or redirect access "
            "outside the expected repository path.",
            _reference("link"),
        ),
        _expected_finding(
            RuleId.SUBMODULE_CHANGED,
            FindingCategory.SUPPLY_CHAIN,
            FindingSeverity.MEDIUM,
            "Submodule pointer introduced or changed",
            "The head version introduces a submodule or changes its referenced commit.",
            "Verify the submodule source and review the referenced commit before accepting the "
            "change.",
            _reference("vendor/module"),
        ),
        _expected_finding(
            RuleId.EXECUTABLE_BIT_ADDED,
            FindingCategory.SECURITY,
            FindingSeverity.LOW,
            "Executable permission introduced",
            "The head version introduces executable permission for this file.",
            "Confirm that executable permission is required; otherwise restore a non-executable "
            "regular-file mode.",
            _reference("script.sh"),
        ),
        _expected_finding(
            RuleId.BINARY_CONTENT_CHANGED,
            FindingCategory.REVIEWABILITY,
            FindingSeverity.INFO,
            "Opaque binary content introduced or changed",
            "The head version introduces binary content or changes its object ID, so text review "
            "evidence is unavailable.",
            "Verify the binary's provenance and inspect it with an appropriate trusted tool.",
            _reference("image.bin"),
        ),
    )
    assert "sensitive-body-not-for-output" not in review_to_json(result)


def test_review_serialization_is_canonical_utf8_and_has_no_trailing_newline() -> None:
    bundle = _bundle(
        _text_change(
            "unicodé\n:(glob)*.pem",
            ((1, "-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----"),),
        )
    )
    result = review_evidence(bundle)

    first = review_to_json(result)
    second = review_to_json(result)

    assert first == second
    assert json.loads(first) == review_to_dict(result)
    assert first.startswith('{"findings":')
    assert "unicodé" in first
    assert not first.endswith("\n")
    first.encode("utf-8")
    assert list(review_to_dict(result)) == [
        "schema_version",
        "repository",
        "revisions",
        "findings",
    ]
    assert review_to_dict(result)["findings"] == [
        {
            "rule_id": "private_key_material",
            "category": "security",
            "severity": "high",
            "title": "Private key material added",
            "message": "Added lines contain a paired private-key block.",
            "remediation": "Remove the private key, rotate any exposed credential, and load the "
            "replacement from an approved secret store.",
            "references": [
                {
                    "path": "unicodé\n:(glob)*.pem",
                    "side": "new",
                    "oid": OID_B,
                    "start_line": 1,
                    "end_line": 1,
                }
            ],
        }
    ]


def test_public_models_are_frozen_slotted_and_require_supported_shapes() -> None:
    result = review_evidence(
        _bundle(
            _text_change(
                "key.pem",
                ((1, "-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----"),),
            )
        )
    )
    finding = result.findings[0]
    reference = finding.references[0]

    with pytest.raises(FrozenInstanceError):
        reference.path = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.schema_version = 2  # type: ignore[misc]
    assert not hasattr(reference, "__dict__")
    assert not hasattr(finding, "__dict__")
    assert not hasattr(result, "__dict__")

    with pytest.raises(ValueError, match="schema_version must be 1"):
        ReviewResult(
            repository=result.repository,
            revisions=result.revisions,
            findings=(),
            schema_version=2,
        )
    with pytest.raises(ValueError, match="schema_version must be 1"):
        ReviewResult(
            repository=result.repository,
            revisions=result.revisions,
            findings=(),
            schema_version=cast(int, True),
        )
    with pytest.raises(ValueError, match="references"):
        Finding(
            rule_id=RuleId.PRIVATE_KEY_MATERIAL,
            category=FindingCategory.SECURITY,
            severity=FindingSeverity.HIGH,
            title="Private key material added",
            message="Added lines contain a paired private-key block.",
            remediation="Remove it.",
            references=(),
        )


@pytest.mark.parametrize("label", PRIVATE_KEY_LABELS)
def test_private_key_rule_supports_every_exact_label_and_embedded_markers(label: str) -> None:
    result = review_evidence(
        _bundle(
            _text_change(
                "key.txt",
                (
                    (7, f'prefix "-----BEGIN {label}-----"'),
                    (9, f'"-----END {label}-----" suffix'),
                ),
            )
        )
    )

    assert [(finding.rule_id, finding.references[0]) for finding in result.findings] == [
        (RuleId.PRIVATE_KEY_MATERIAL, _reference("key.txt", start_line=7, end_line=9))
    ]


def test_private_key_rule_supports_same_line_and_multiple_blocks_in_line_order() -> None:
    change = _text_change(
        "keys.txt",
        (
            (12, "-----END RSA PRIVATE KEY-----"),
            (3, "-----BEGIN PRIVATE KEY----- body -----END PRIVATE KEY-----"),
            (10, "-----BEGIN RSA PRIVATE KEY-----"),
        ),
    )

    result = review_evidence(_bundle(change))

    assert [finding.references[0] for finding in result.findings] == [
        _reference("keys.txt", start_line=3, end_line=3),
        _reference("keys.txt", start_line=10, end_line=12),
    ]


def test_private_key_rule_pairs_same_label_markers_fifo() -> None:
    change = _text_change(
        "keys.txt",
        (
            (1, "-----BEGIN PRIVATE KEY-----"),
            (2, "-----BEGIN PRIVATE KEY-----"),
            (3, "-----END PRIVATE KEY-----"),
            (4, "-----END PRIVATE KEY-----"),
        ),
    )

    result = review_evidence(_bundle(change))

    assert [finding.references[0] for finding in result.findings] == [
        _reference("keys.txt", start_line=1, end_line=3),
        _reference("keys.txt", start_line=2, end_line=4),
    ]


@pytest.mark.parametrize(
    "additions",
    [
        ((1, "-----BEGIN PRIVATE KEY-----"),),
        ((1, "-----END PRIVATE KEY-----"),),
        (
            (1, "-----BEGIN RSA PRIVATE KEY-----"),
            (2, "-----END EC PRIVATE KEY-----"),
        ),
        (
            (1, "-----begin PRIVATE KEY-----"),
            (2, "-----end PRIVATE KEY-----"),
        ),
    ],
)
def test_private_key_rule_rejects_unpaired_mismatched_or_wrong_case_markers(
    additions: Sequence[tuple[int, str]],
) -> None:
    assert review_evidence(_bundle(_text_change("key.txt", additions))).findings == ()


def test_private_key_rule_ignores_deletion_and_context_lines() -> None:
    non_additions = (
        DiffLineEvidence(
            kind=DiffLineKind.DELETION,
            old_line_number=1,
            new_line_number=None,
            content="-----BEGIN PRIVATE KEY-----",
            has_trailing_newline=True,
        ),
        DiffLineEvidence(
            kind=DiffLineKind.CONTEXT,
            old_line_number=2,
            new_line_number=2,
            content="-----END PRIVATE KEY-----",
            has_trailing_newline=True,
        ),
    )

    assert (
        review_evidence(_bundle(_text_change("key.txt", (), extra_lines=non_additions))).findings
        == ()
    )


@pytest.mark.parametrize("marker_size", [7, 11])
def test_conflict_rule_supports_default_and_longer_equal_sized_markers(
    marker_size: int,
) -> None:
    result = review_evidence(
        _bundle(
            _text_change(
                "conflict.txt",
                (
                    (4, "<" * marker_size + " HEAD"),
                    (6, "=" * marker_size),
                    (8, ">" * marker_size + " feature"),
                ),
            )
        )
    )

    assert [(finding.rule_id, finding.references[0]) for finding in result.findings] == [
        (RuleId.MERGE_CONFLICT_MARKER, _reference("conflict.txt", start_line=4, end_line=8))
    ]


def test_conflict_rule_treats_terminal_carriage_returns_as_crlf_line_endings() -> None:
    result = review_evidence(
        _bundle(
            _text_change(
                "conflict.txt",
                (
                    (4, "<<<<<<< HEAD\r"),
                    (6, "=======\r"),
                    (8, ">>>>>>> feature\r"),
                ),
            )
        )
    )

    assert [(finding.rule_id, finding.references[0]) for finding in result.findings] == [
        (RuleId.MERGE_CONFLICT_MARKER, _reference("conflict.txt", start_line=4, end_line=8))
    ]


def test_conflict_rule_preserves_unterminated_carriage_return_as_content() -> None:
    change = _text_change(
        "conflict.txt",
        ((4, "<<<<<<< HEAD"), (6, "=======\r"), (8, ">>>>>>> feature")),
    )
    hunk = change.hunks[0]
    lines = (
        hunk.lines[0],
        replace(hunk.lines[1], has_trailing_newline=False),
        hunk.lines[2],
    )
    change = replace(change, hunks=(replace(hunk, lines=lines),))

    assert review_evidence(_bundle(change)).findings == ()


def test_conflict_rule_supports_multiple_blocks_and_normalizes_addition_order() -> None:
    change = _text_change(
        "conflict.txt",
        (
            (14, ">>>>>>>> branch"),
            (2, "<<<<<<<"),
            (12, "========"),
            (4, "======="),
            (10, "<<<<<<<< other"),
            (6, ">>>>>>>"),
        ),
    )

    result = review_evidence(_bundle(change))

    assert [finding.references[0] for finding in result.findings] == [
        _reference("conflict.txt", start_line=2, end_line=6),
        _reference("conflict.txt", start_line=10, end_line=14),
    ]


def test_conflict_rule_pairs_same_length_markers_fifo() -> None:
    change = _text_change(
        "conflict.txt",
        (
            (1, "<<<<<<< first"),
            (2, "<<<<<<< second"),
            (3, "======="),
            (4, "======="),
            (5, ">>>>>>> first"),
            (6, ">>>>>>> second"),
        ),
    )

    result = review_evidence(_bundle(change))

    assert [finding.references[0] for finding in result.findings] == [
        _reference("conflict.txt", start_line=1, end_line=5),
        _reference("conflict.txt", start_line=2, end_line=6),
    ]


@pytest.mark.parametrize(
    "additions",
    [
        ((1, " <<<<<<< HEAD"), (2, "======="), (3, ">>>>>>> branch")),
        ((1, "<<<<<<< "), (2, "======="), (3, ">>>>>>> branch")),
        ((1, "<<<<<<< HEAD"), (2, "======="), (3, ">>>>>>> ")),
        ((1, "<<<<<<< HEAD"), (2, "=======")),
        ((1, "<<<<<<< HEAD"), (2, "========"), (3, ">>>>>>> branch")),
        ((1, "======="), (2, "<<<<<<< HEAD"), (3, ">>>>>>> branch")),
        ((1, "<<<<<<<\tHEAD"), (2, "======="), (3, ">>>>>>> branch")),
        ((1, "<<<<<<< HEAD"), (2, "======= label"), (3, ">>>>>>> branch")),
    ],
)
def test_conflict_rule_rejects_indented_incomplete_mismatched_or_out_of_order_blocks(
    additions: Sequence[tuple[int, str]],
) -> None:
    assert review_evidence(_bundle(_text_change("conflict.txt", additions))).findings == ()


def test_conflict_rule_ignores_deletion_and_context_lines() -> None:
    non_additions = (
        DiffLineEvidence(
            kind=DiffLineKind.DELETION,
            old_line_number=1,
            new_line_number=None,
            content="<<<<<<< HEAD",
            has_trailing_newline=True,
        ),
        DiffLineEvidence(
            kind=DiffLineKind.CONTEXT,
            old_line_number=2,
            new_line_number=2,
            content="=======",
            has_trailing_newline=True,
        ),
        DiffLineEvidence(
            kind=DiffLineKind.DELETION,
            old_line_number=3,
            new_line_number=None,
            content=">>>>>>> branch",
            has_trailing_newline=True,
        ),
    )

    assert (
        review_evidence(
            _bundle(_text_change("conflict.txt", (), extra_lines=non_additions))
        ).findings
        == ()
    )


def test_executable_rule_reports_new_and_newly_executable_files() -> None:
    result = review_evidence(
        _bundle(
            _metadata_change("added.sh", new_mode="100755"),
            _metadata_change("changed.sh", old_mode="100644", new_mode="100755"),
        )
    )

    assert [(finding.rule_id, finding.references[0]) for finding in result.findings] == [
        (RuleId.EXECUTABLE_BIT_ADDED, _reference("added.sh")),
        (RuleId.EXECUTABLE_BIT_ADDED, _reference("changed.sh")),
    ]


@pytest.mark.parametrize(
    ("content_kind", "mode", "rule_id"),
    [
        (ContentKind.SYMLINK, "120000", RuleId.SYMLINK_CHANGED),
        (ContentKind.SUBMODULE, "160000", RuleId.SUBMODULE_CHANGED),
        (ContentKind.BINARY, "100644", RuleId.BINARY_CONTENT_CHANGED),
    ],
)
@pytest.mark.parametrize("transition", ["added", "oid_changed", "type_changed"])
def test_special_content_rules_report_additions_oid_changes_and_type_changes(
    content_kind: ContentKind,
    mode: str,
    rule_id: RuleId,
    transition: str,
) -> None:
    old_mode: str | None = None
    old_oid = OID_A
    old_kind = ContentKind.TEXT
    if transition == "oid_changed":
        old_mode = mode
        old_kind = content_kind
    elif transition == "type_changed":
        old_mode = "100644"
        old_oid = OID_B

    result = review_evidence(
        _bundle(
            _metadata_change(
                "entry",
                old_mode=old_mode,
                old_oid=old_oid,
                old_kind=old_kind,
                new_mode=mode,
                new_kind=content_kind,
                change_type=(
                    ChangeType.TYPE_CHANGED if transition == "type_changed" else ChangeType.MODIFIED
                ),
            )
        )
    )

    assert [(finding.rule_id, finding.references[0]) for finding in result.findings] == [
        (rule_id, _reference("entry"))
    ]


@pytest.mark.parametrize(
    ("content_kind", "mode"),
    [
        (ContentKind.TEXT, "100755"),
        (ContentKind.SYMLINK, "120000"),
        (ContentKind.SUBMODULE, "160000"),
        (ContentKind.BINARY, "100644"),
    ],
)
def test_metadata_rules_ignore_deletions_and_unchanged_pure_renames(
    content_kind: ContentKind,
    mode: str,
) -> None:
    unchanged_rename = _metadata_change(
        "new-name",
        old_mode=mode,
        old_oid=OID_B,
        old_kind=content_kind,
        new_mode=mode,
        new_kind=content_kind,
        change_type=ChangeType.RENAMED,
    )
    unchanged_rename = replace(
        unchanged_rename,
        old=_version("old-name", mode=mode, oid=OID_B, content_kind=content_kind),
    )
    deletion = FileChangeEvidence(
        change_type=ChangeType.DELETED,
        rename_similarity=None,
        old=_version("deleted", mode=mode, oid=OID_A, content_kind=content_kind),
        new=None,
        hunks=(),
    )

    assert review_evidence(_bundle(deletion, unchanged_rename)).findings == ()


def test_other_content_with_no_hunks_is_a_successful_empty_review() -> None:
    change = _metadata_change(
        "opaque-entry",
        new_kind=ContentKind.OTHER,
        change_type=ChangeType.ADDED,
    )

    assert review_evidence(_bundle(change)).findings == ()


def test_executable_binary_change_produces_both_applicable_findings() -> None:
    result = review_evidence(
        _bundle(
            _metadata_change(
                "tool.bin",
                new_mode="100755",
                new_kind=ContentKind.BINARY,
            )
        )
    )

    assert [finding.rule_id for finding in result.findings] == [
        RuleId.EXECUTABLE_BIT_ADDED,
        RuleId.BINARY_CONTENT_CHANGED,
    ]


def test_valid_sha256_evidence_and_special_utf8_path_are_supported() -> None:
    repository = RepositoryEvidence(root=Path("/work/répo"), object_format="sha256")
    revisions = RevisionEvidence(
        base_ref="refs/heads/main",
        head_ref="feature/ü",
        base_oid=OID_256_A,
        head_oid=OID_256_B,
        merge_base_oid=OID_256_C,
    )
    change = _text_change(
        "unicodé\n:(glob)*.pem",
        ((1, "-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----"),),
        oid=OID_256_B,
    )

    result = review_evidence(_bundle(change, repository=repository, revisions=revisions))

    assert result.findings[0].references == (
        _reference(
            "unicodé\n:(glob)*.pem",
            oid=OID_256_B,
            start_line=1,
            end_line=1,
        ),
    )


def test_unsupported_schema_has_stable_error_code() -> None:
    bundle = _bundle()
    object.__setattr__(bundle, "schema_version", 2)

    with pytest.raises(ReviewError) as error_info:
        review_evidence(bundle)

    assert error_info.value.code is ReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA


def _invalid_collection_shapes() -> list[EvidenceBundle]:
    change = _text_change(
        "key.pem",
        ((1, "-----BEGIN PRIVATE KEY-----"), (2, "-----END PRIVATE KEY-----")),
    )
    hunk = change.hunks[0]
    return [
        replace(
            _bundle(change),
            changes=cast(tuple[FileChangeEvidence, ...], iter((change,))),
        ),
        replace(
            _bundle(change),
            changes=cast(tuple[FileChangeEvidence, ...], None),
        ),
        _bundle(
            replace(
                change,
                hunks=cast(tuple[DiffHunkEvidence, ...], iter(change.hunks)),
            )
        ),
        _bundle(
            replace(
                change,
                hunks=cast(tuple[DiffHunkEvidence, ...], None),
            )
        ),
        _bundle(
            replace(
                change,
                hunks=(
                    replace(
                        hunk,
                        lines=cast(
                            tuple[DiffLineEvidence, ...],
                            iter(hunk.lines),
                        ),
                    ),
                ),
            )
        ),
        _bundle(
            replace(
                change,
                hunks=(
                    replace(
                        hunk,
                        lines=cast(tuple[DiffLineEvidence, ...], None),
                    ),
                ),
            )
        ),
        replace(
            _bundle(change),
            changes=cast(
                tuple[FileChangeEvidence, ...],
                _FirstTraversalOnly((change,)),
            ),
        ),
        _bundle(
            replace(
                change,
                hunks=cast(
                    tuple[DiffHunkEvidence, ...],
                    _FirstTraversalOnly(change.hunks),
                ),
            )
        ),
        _bundle(
            replace(
                change,
                hunks=(
                    replace(
                        hunk,
                        lines=cast(
                            tuple[DiffLineEvidence, ...],
                            _FirstTraversalOnly(hunk.lines),
                        ),
                    ),
                ),
            )
        ),
    ]


def _invalid_bundles() -> list[EvidenceBundle]:
    valid = _bundle()
    invalid_addition = _addition(1, "content")
    return [
        replace(valid, repository=replace(valid.repository, root=Path("relative"))),
        replace(valid, repository=replace(valid.repository, root=Path("/work/\udcff"))),
        replace(valid, repository=replace(valid.repository, object_format="sha512")),
        replace(
            valid,
            repository=replace(valid.repository, object_format=cast(str, [])),
        ),
        replace(valid, revisions=replace(valid.revisions, base_ref="\udcff")),
        replace(valid, revisions=replace(valid.revisions, base_oid=OID_A.upper())),
        _bundle(_text_change("", ((1, "content"),))),
        _bundle(_text_change("\udcff", ((1, "content"),))),
        _bundle(_text_change("path", ((1, "content"),), oid="b" * 39)),
        _bundle(
            FileChangeEvidence(
                change_type=ChangeType.DELETED,
                rename_similarity=None,
                old=_version("old"),
                new=None,
                hunks=(
                    DiffHunkEvidence(
                        old_start=0,
                        old_count=0,
                        new_start=1,
                        new_count=1,
                        lines=(invalid_addition,),
                    ),
                ),
            )
        ),
        _bundle(
            _text_change(
                "path",
                (),
                extra_lines=(replace(invalid_addition, old_line_number=1),),
            )
        ),
        _bundle(_text_change("path", ((0, "content"),))),
        _bundle(
            _text_change(
                "path",
                (),
                extra_lines=(replace(invalid_addition, new_line_number=False),),
            )
        ),
        _bundle(_text_change("path", ((1, "first"), (1, "second")))),
        *_invalid_collection_shapes(),
    ]


@pytest.mark.parametrize("bundle", _invalid_bundles())
def test_invalid_evidence_has_stable_error_code_without_source_leakage(
    bundle: EvidenceBundle,
) -> None:
    with pytest.raises(ReviewError) as error_info:
        review_evidence(bundle)

    assert error_info.value.code is ReviewErrorCode.INVALID_EVIDENCE
    assert "content" not in str(error_info.value)


def test_non_bundle_input_is_rejected_as_invalid_evidence() -> None:
    with pytest.raises(ReviewError) as error_info:
        review_evidence(cast(EvidenceBundle, object()))

    assert error_info.value.code is ReviewErrorCode.INVALID_EVIDENCE


def test_unexpected_rule_failure_is_atomic_stable_and_does_not_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(
        _text_change(
            "key.pem",
            ((1, "-----BEGIN PRIVATE KEY-----"), (2, "-----END PRIVATE KEY-----")),
        )
    )

    def fail_rule(_bundle: EvidenceBundle) -> tuple[Finding, ...]:
        raise RuntimeError("sensitive-internal-detail")

    monkeypatch.setattr(
        review_implementation,
        "_RULES",
        (
            (
                RuleId.PRIVATE_KEY_MATERIAL,
                review_implementation._private_key_findings,
            ),
            (RuleId.MERGE_CONFLICT_MARKER, fail_rule),
        ),
    )

    with pytest.raises(ReviewError) as error_info:
        review_evidence(bundle)

    assert error_info.value.code is ReviewErrorCode.RULE_EXECUTION_FAILED
    assert str(error_info.value) == "review rule failed: merge_conflict_marker"
    assert "sensitive-internal-detail" not in str(error_info.value)
    assert "PRIVATE KEY" not in str(error_info.value)
