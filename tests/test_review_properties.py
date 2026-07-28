"""Deterministic properties for M2 review evaluation and serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from hypothesis import example, given, settings
from hypothesis import strategies as st

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
from repoguard.review import review_evidence, review_to_dict, review_to_json

OID_A = "a" * 40
OID_B = "b" * 40
OID_C = "c" * 40
PROPERTY_SETTINGS = settings(database=None, derandomize=True, max_examples=100)
SURROGATE_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
UTF8_CHARACTER = st.characters(
    exclude_categories=SURROGATE_CATEGORIES,
    exclude_characters="\x00\n",
)
GIT_PATH = st.text(UTF8_CHARACTER, min_size=1, max_size=24)
LOGICAL_LINE = st.text(UTF8_CHARACTER, max_size=32)
NON_ADDITION = st.tuples(
    st.sampled_from((DiffLineKind.DELETION, DiffLineKind.CONTEXT)),
    LOGICAL_LINE,
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
    additions: tuple[tuple[int, str], ...],
    *,
    extra_lines: tuple[DiffLineEvidence, ...] = (),
) -> FileChangeEvidence:
    lines = tuple(_addition(number, content) for number, content in additions) + extra_lines
    return FileChangeEvidence(
        change_type=ChangeType.ADDED,
        rename_similarity=None,
        old=None,
        new=_version(path),
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
    mode: str,
    content_kind: ContentKind,
) -> FileChangeEvidence:
    return FileChangeEvidence(
        change_type=ChangeType.ADDED,
        rename_similarity=None,
        old=None,
        new=_version(path, mode=mode, content_kind=content_kind),
        hunks=(),
    )


def _bundle(changes: tuple[FileChangeEvidence, ...]) -> EvidenceBundle:
    return EvidenceBundle(
        repository=RepositoryEvidence(root=Path("/work/repo"), object_format="sha1"),
        revisions=RevisionEvidence(
            base_ref="main",
            head_ref="feature",
            base_oid=OID_A,
            head_oid=OID_B,
            merge_base_oid=OID_C,
        ),
        changes=changes,
    )


def _all_rule_changes() -> tuple[FileChangeEvidence, ...]:
    return (
        _text_change(
            "secrets/key.pem",
            (
                (1, "-----BEGIN PRIVATE KEY-----"),
                (2, "body"),
                (3, "-----END PRIVATE KEY-----"),
            ),
        ),
        _text_change(
            "conflict.txt",
            ((1, "<<<<<<< HEAD"), (2, "======="), (3, ">>>>>>> feature")),
        ),
        _metadata_change("script.sh", mode="100755", content_kind=ContentKind.TEXT),
        _metadata_change("link", mode="120000", content_kind=ContentKind.SYMLINK),
        _metadata_change(
            "vendor/module",
            mode="160000",
            content_kind=ContentKind.SUBMODULE,
        ),
        _metadata_change("image.bin", mode="100644", content_kind=ContentKind.BINARY),
    )


@PROPERTY_SETTINGS
@example(path="unicodé\tname.pem", marker_size=7)
@given(path=GIT_PATH, marker_size=st.integers(min_value=7, max_value=16))
def test_repeated_review_and_json_are_byte_stable(path: str, marker_size: int) -> None:
    bundle = _bundle(
        (
            _text_change(
                f"key/{path}",
                ((2, "-----BEGIN PRIVATE KEY-----"), (4, "-----END PRIVATE KEY-----")),
            ),
            _text_change(
                f"conflict/{path}",
                (
                    (2, "<" * marker_size + " HEAD"),
                    (4, "=" * marker_size),
                    (6, ">" * marker_size + " feature"),
                ),
            ),
        )
    )

    first = review_evidence(bundle)
    second = review_evidence(bundle)

    assert first == second
    assert review_to_json(first) == review_to_json(second)


@PROPERTY_SETTINGS
@example(order=[0, 1, 2, 3, 4, 5])
@example(order=[5, 4, 3, 2, 1, 0])
@given(order=st.permutations(tuple(range(6))))
def test_review_is_invariant_under_change_permutations(order: list[int]) -> None:
    changes = _all_rule_changes()
    original = review_evidence(_bundle(changes))
    permuted = review_evidence(_bundle(tuple(changes[index] for index in order)))

    assert permuted == original
    assert review_to_json(permuted) == review_to_json(original)


@PROPERTY_SETTINGS
@example(
    generated_lines=[
        (DiffLineKind.DELETION, "-----BEGIN PRIVATE KEY-----"),
        (DiffLineKind.CONTEXT, "-----END PRIVATE KEY-----"),
        (DiffLineKind.DELETION, "<<<<<<< HEAD"),
        (DiffLineKind.CONTEXT, "======="),
        (DiffLineKind.DELETION, ">>>>>>> feature"),
    ]
)
@given(generated_lines=st.lists(NON_ADDITION, max_size=12))
def test_deletion_and_context_content_cannot_change_findings(
    generated_lines: list[tuple[DiffLineKind, str]],
) -> None:
    additions = (
        (10, "-----BEGIN PRIVATE KEY-----"),
        (11, "-----END PRIVATE KEY-----"),
        (20, "<<<<<<< HEAD"),
        (21, "======="),
        (22, ">>>>>>> feature"),
    )
    extra_lines = tuple(
        DiffLineEvidence(
            kind=kind,
            old_line_number=index + 1,
            new_line_number=index + 1 if kind is DiffLineKind.CONTEXT else None,
            content=content,
            has_trailing_newline=index % 2 == 0,
        )
        for index, (kind, content) in enumerate(generated_lines)
    )
    baseline = review_evidence(_bundle((_text_change("mixed.txt", additions),)))
    augmented = review_evidence(
        _bundle((_text_change("mixed.txt", additions, extra_lines=extra_lines),))
    )

    assert augmented == baseline
    assert review_to_json(augmented) == review_to_json(baseline)


@PROPERTY_SETTINGS
@example(path="特殊/secret.pem", nonce=0)
@given(path=GIT_PATH, nonce=st.integers(min_value=0, max_value=2**128 - 1))
def test_json_matches_mapping_and_never_copies_generated_secret_body(
    path: str,
    nonce: int,
) -> None:
    secret_body = f"SENSITIVE_BODY_{nonce:032x}_DO_NOT_COPY"
    result = review_evidence(
        _bundle(
            (
                _text_change(
                    f"ü/{path}",
                    (
                        (1, "-----BEGIN PRIVATE KEY-----"),
                        (2, secret_body),
                        (3, "-----END PRIVATE KEY-----"),
                    ),
                ),
            )
        )
    )

    serialized = review_to_json(result)

    assert json.loads(serialized) == review_to_dict(result)
    assert secret_body not in serialized
    assert not serialized.endswith("\n")
    serialized.encode("utf-8")
