"""Tests for the public read-only evidence contract."""

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from repoguard.evidence import (
    ChangeType,
    ContentKind,
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    EvidenceCollectionError,
    EvidenceErrorCode,
    FileChangeEvidence,
    FileVersion,
    RepositoryEvidence,
    RevisionEvidence,
    evidence_to_dict,
    evidence_to_json,
)

OID_A = "a" * 40
OID_B = "b" * 40
OID_C = "c" * 40


def _sample_bundle(*, path: str = "src/example.py") -> EvidenceBundle:
    old = FileVersion(
        path=path,
        mode="100644",
        oid=OID_A,
        content_kind=ContentKind.TEXT,
    )
    new = FileVersion(
        path=path,
        mode="100755",
        oid=OID_B,
        content_kind=ContentKind.TEXT,
    )
    hunk = DiffHunkEvidence(
        old_start=1,
        old_count=1,
        new_start=1,
        new_count=1,
        lines=(
            DiffLineEvidence(
                kind=DiffLineKind.DELETION,
                old_line_number=1,
                new_line_number=None,
                content="old",
                has_trailing_newline=True,
            ),
            DiffLineEvidence(
                kind=DiffLineKind.ADDITION,
                old_line_number=None,
                new_line_number=1,
                content="new",
                has_trailing_newline=False,
            ),
        ),
    )
    return EvidenceBundle(
        repository=RepositoryEvidence(root=Path("/work/repo"), object_format="sha1"),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid=OID_A,
            head_oid=OID_B,
            merge_base_oid=OID_C,
        ),
        changes=(
            FileChangeEvidence(
                change_type=ChangeType.MODIFIED,
                rename_similarity=None,
                old=old,
                new=new,
                hunks=(hunk,),
            ),
        ),
    )


def test_evidence_serializes_to_the_versioned_public_schema() -> None:
    bundle = _sample_bundle()

    mapping = evidence_to_dict(bundle)

    assert mapping == {
        "schema_version": 1,
        "repository": {"root": "/work/repo", "object_format": "sha1"},
        "revisions": {
            "base_ref": "main",
            "head_ref": "feature",
            "base_oid": OID_A,
            "head_oid": OID_B,
            "merge_base_oid": OID_C,
        },
        "changes": [
            {
                "change_type": "modified",
                "rename_similarity": None,
                "old": {
                    "path": "src/example.py",
                    "mode": "100644",
                    "oid": OID_A,
                    "content_kind": "text",
                },
                "new": {
                    "path": "src/example.py",
                    "mode": "100755",
                    "oid": OID_B,
                    "content_kind": "text",
                },
                "hunks": [
                    {
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 1,
                        "lines": [
                            {
                                "kind": "deletion",
                                "old_line_number": 1,
                                "new_line_number": None,
                                "content": "old",
                                "has_trailing_newline": True,
                            },
                            {
                                "kind": "addition",
                                "old_line_number": None,
                                "new_line_number": 1,
                                "content": "new",
                                "has_trailing_newline": False,
                            },
                        ],
                    }
                ],
            }
        ],
    }


def test_json_is_canonical_and_has_no_trailing_newline() -> None:
    bundle = _sample_bundle()

    first = evidence_to_json(bundle)
    second = evidence_to_json(bundle)

    assert first == second
    assert first.startswith('{"changes":')
    assert not first.endswith("\n")
    assert json.loads(first) == evidence_to_dict(bundle)


def test_evidence_models_are_frozen_and_schema_is_fixed() -> None:
    bundle = _sample_bundle()

    with pytest.raises(FrozenInstanceError):
        bundle.schema_version = 2  # type: ignore[misc]

    with pytest.raises(ValueError, match="schema_version must be 1"):
        EvidenceBundle(
            repository=bundle.repository,
            revisions=bundle.revisions,
            changes=(),
            schema_version=2,
        )


def test_non_utf8_path_fails_with_stable_error_code() -> None:
    bundle = _sample_bundle(path="\udcff")

    with pytest.raises(EvidenceCollectionError) as error_info:
        evidence_to_json(bundle)

    assert error_info.value.code is EvidenceErrorCode.UNSUPPORTED_PATH_ENCODING
