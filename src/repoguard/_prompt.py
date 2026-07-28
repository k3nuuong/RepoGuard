"""Trusted prompt resources and canonical untrusted-data projection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files

from repoguard.agent import PromptIdentity
from repoguard.evidence import (
    DiffHunkEvidence,
    DiffLineEvidence,
    DiffLineKind,
    EvidenceBundle,
    FileChangeEvidence,
    FileVersion,
)
from repoguard.providers import LLMMessage, MessageRole
from repoguard.review import (
    EvidenceReference,
    EvidenceSide,
    Finding,
    ReviewResult,
    RuleId,
)

_PROMPT_DIRECTORY = ("prompts", "agent_review", "v1")
_SYSTEM_RESOURCE = "system.md"
_SCHEMA_RESOURCE = "response-schema.json"
_REDACTION_SENTINEL = "[REDACTED_PRIVATE_KEY_MATERIAL]"


@dataclass(frozen=True, slots=True)
class _ReferenceTarget:
    path: str
    side: EvidenceSide
    oid: str
    hunk_line_numbers: tuple[frozenset[int], ...]


@dataclass(frozen=True, slots=True)
class _RenderedPrompt:
    messages: tuple[LLMMessage, ...]
    identity: PromptIdentity
    byte_count: int
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget]


def _render_review_prompt(
    bundle: EvidenceBundle,
    review: ReviewResult,
) -> _RenderedPrompt:
    system_bytes, schema_bytes = _read_prompt_resources()
    system_text = system_bytes.decode("utf-8")
    schema_text = schema_bytes.decode("utf-8")
    trusted_content = f"{system_text}\nResponse schema:\n{schema_text}"

    redactions = _private_key_redactions(review.findings)
    changes = [_change_to_prompt_dict(change, redactions) for change in bundle.changes]
    changes.sort(key=_canonical_mapping_bytes)

    user_data: dict[str, object] = {
        "schema_version": 1,
        "repository": {"object_format": bundle.repository.object_format},
        "revisions": {
            "base_oid": bundle.revisions.base_oid,
            "head_oid": bundle.revisions.head_oid,
            "merge_base_oid": bundle.revisions.merge_base_oid,
        },
        "deterministic_findings": [
            _deterministic_finding_to_dict(finding) for finding in review.findings
        ],
        "changes": changes,
    }
    user_content = json.dumps(
        user_data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    messages = (
        LLMMessage(role=MessageRole.SYSTEM, content=trusted_content),
        LLMMessage(role=MessageRole.USER, content=user_content),
    )
    digest = hashlib.sha256(system_bytes + b"\0" + schema_bytes).hexdigest()
    return _RenderedPrompt(
        messages=messages,
        identity=PromptIdentity(name="agent_review", version="v1", sha256=digest),
        byte_count=sum(len(message.content.encode("utf-8")) for message in messages),
        targets=_reference_targets(bundle),
    )


def _read_prompt_resources() -> tuple[bytes, bytes]:
    root = files("repoguard")
    for part in _PROMPT_DIRECTORY:
        root = root.joinpath(part)
    return (
        root.joinpath(_SYSTEM_RESOURCE).read_bytes(),
        root.joinpath(_SCHEMA_RESOURCE).read_bytes(),
    )


def _private_key_redactions(
    findings: tuple[Finding, ...],
) -> dict[tuple[str, str], tuple[tuple[int, int], ...]]:
    pending: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for finding in findings:
        if finding.rule_id is not RuleId.PRIVATE_KEY_MATERIAL:
            continue
        for reference in finding.references:
            if (
                reference.side is EvidenceSide.NEW
                and reference.start_line is not None
                and reference.end_line is not None
            ):
                key = (reference.path, reference.oid)
                pending.setdefault(key, []).append(
                    (reference.start_line, reference.end_line),
                )
    return {key: tuple(sorted(ranges)) for key, ranges in pending.items()}


def _change_to_prompt_dict(
    change: FileChangeEvidence,
    redactions: dict[tuple[str, str], tuple[tuple[int, int], ...]],
) -> dict[str, object]:
    return {
        "change_type": change.change_type.value,
        "rename_similarity": change.rename_similarity,
        "old": None if change.old is None else _version_to_dict(change.old),
        "new": None if change.new is None else _version_to_dict(change.new),
        "hunks": [
            _hunk_to_dict(hunk, new=change.new, redactions=redactions) for hunk in change.hunks
        ],
    }


def _version_to_dict(version: FileVersion) -> dict[str, object]:
    return {
        "path": version.path,
        "mode": version.mode,
        "oid": version.oid,
        "content_kind": version.content_kind.value,
    }


def _hunk_to_dict(
    hunk: DiffHunkEvidence,
    *,
    new: FileVersion | None,
    redactions: dict[tuple[str, str], tuple[tuple[int, int], ...]],
) -> dict[str, object]:
    return {
        "old_start": hunk.old_start,
        "old_count": hunk.old_count,
        "new_start": hunk.new_start,
        "new_count": hunk.new_count,
        "lines": [_line_to_dict(line, new=new, redactions=redactions) for line in hunk.lines],
    }


def _line_to_dict(
    line: DiffLineEvidence,
    *,
    new: FileVersion | None,
    redactions: dict[tuple[str, str], tuple[tuple[int, int], ...]],
) -> dict[str, object]:
    content = line.content
    if (
        new is not None
        and line.kind is DiffLineKind.ADDITION
        and line.new_line_number is not None
        and _is_redacted(new, line.new_line_number, redactions)
    ):
        content = _REDACTION_SENTINEL
    return {
        "kind": line.kind.value,
        "old_line_number": line.old_line_number,
        "new_line_number": line.new_line_number,
        "content": content,
        "has_trailing_newline": line.has_trailing_newline,
    }


def _is_redacted(
    version: FileVersion,
    line_number: int,
    redactions: dict[tuple[str, str], tuple[tuple[int, int], ...]],
) -> bool:
    return any(
        start <= line_number <= end
        for start, end in redactions.get((version.path, version.oid), ())
    )


def _deterministic_finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "references": [_reference_to_dict(reference) for reference in finding.references],
    }


def _reference_to_dict(reference: EvidenceReference) -> dict[str, object]:
    return {
        "path": reference.path,
        "side": reference.side.value,
        "oid": reference.oid,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
    }


def _canonical_mapping_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reference_targets(
    bundle: EvidenceBundle,
) -> dict[tuple[str, EvidenceSide], _ReferenceTarget]:
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget] = {}
    for change in bundle.changes:
        if change.old is not None:
            _add_reference_target(
                targets,
                version=change.old,
                side=EvidenceSide.OLD,
                hunks=change.hunks,
            )
        if change.new is not None:
            _add_reference_target(
                targets,
                version=change.new,
                side=EvidenceSide.NEW,
                hunks=change.hunks,
            )
    return targets


def _add_reference_target(
    targets: dict[tuple[str, EvidenceSide], _ReferenceTarget],
    *,
    version: FileVersion,
    side: EvidenceSide,
    hunks: tuple[DiffHunkEvidence, ...],
) -> None:
    key = (version.path, side)
    if key in targets:
        msg = "evidence contains duplicate path and side targets"
        raise ValueError(msg)
    targets[key] = _ReferenceTarget(
        path=version.path,
        side=side,
        oid=version.oid,
        hunk_line_numbers=tuple(_hunk_line_numbers(hunk, side) for hunk in hunks),
    )


def _hunk_line_numbers(
    hunk: DiffHunkEvidence,
    side: EvidenceSide,
) -> frozenset[int]:
    numbers: set[int] = set()
    for line in hunk.lines:
        number = line.old_line_number if side is EvidenceSide.OLD else line.new_line_number
        if number is not None:
            numbers.add(number)
    return frozenset(numbers)
