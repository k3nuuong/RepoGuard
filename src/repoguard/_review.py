"""Pure implementation of deterministic review rules."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Never

from repoguard.evidence import (
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
)

type _Addition = tuple[int, str]
type _RuleEvaluator = Callable[[EvidenceBundle], tuple[Finding, ...]]
type _ReferenceSortKey = tuple[bytes, str, str, int, int]
type _FindingSortKey = tuple[
    int,
    bytes,
    int,
    int,
    str,
    tuple[_ReferenceSortKey, ...],
]

_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_LOWERCASE_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_PRIVATE_KEY_LABELS = (
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)
_PRIVATE_KEY_MARKER_PATTERN = re.compile(
    r"-----(BEGIN|END) (" + "|".join(re.escape(label) for label in _PRIVATE_KEY_LABELS) + r")-----"
)
_CONFLICT_START_PATTERN = re.compile(r"^(<{7,})(?:$| .+)")
_CONFLICT_SEPARATOR_PATTERN = re.compile(r"^(=+)$")
_CONFLICT_END_PATTERN = re.compile(r"^(>{7,})(?:$| .+)")
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def _review_evidence(bundle: EvidenceBundle) -> ReviewResult:
    _validate_bundle(bundle)
    findings: list[Finding] = []
    for rule_id, evaluator in _RULES:
        try:
            findings.extend(evaluator(bundle))
        except Exception as error:
            msg = f"review rule failed: {rule_id.value}"
            raise ReviewError(ReviewErrorCode.RULE_EXECUTION_FAILED, msg) from error

    return ReviewResult(
        repository=bundle.repository,
        revisions=bundle.revisions,
        findings=_canonicalize_findings(findings),
    )


def _validate_bundle(bundle: EvidenceBundle) -> None:
    if not isinstance(bundle, EvidenceBundle):
        _raise_invalid("review evidence must be an EvidenceBundle")
    if type(bundle.schema_version) is not int or bundle.schema_version != 1:
        raise ReviewError(
            ReviewErrorCode.UNSUPPORTED_EVIDENCE_SCHEMA,
            "evidence schema_version must be 1",
        )
    if not isinstance(bundle.repository, RepositoryEvidence):
        _raise_invalid("repository evidence is invalid")
    if not isinstance(bundle.revisions, RevisionEvidence):
        _raise_invalid("revision evidence is invalid")
    if type(bundle.changes) is not tuple:
        _raise_invalid("file changes must be a tuple")

    root = bundle.repository.root
    if not isinstance(root, Path) or not root.is_absolute():
        _raise_invalid("repository root must be an absolute path")
    _require_utf8(str(root), "repository root must be valid UTF-8")

    object_format = bundle.repository.object_format
    if not isinstance(object_format, str):
        _raise_invalid("repository object format must be sha1 or sha256")
    oid_length = _OID_LENGTHS.get(object_format)
    if oid_length is None:
        _raise_invalid("repository object format must be sha1 or sha256")

    revisions = bundle.revisions
    _require_utf8(revisions.base_ref, "requested refs must be valid UTF-8")
    _require_utf8(revisions.head_ref, "requested refs must be valid UTF-8")
    for oid in (revisions.base_oid, revisions.head_oid, revisions.merge_base_oid):
        _validate_oid(oid, oid_length, "revision OIDs must match the object format")

    for change in bundle.changes:
        _validate_change(change, oid_length)


def _validate_change(change: FileChangeEvidence, oid_length: int) -> None:
    if not isinstance(change, FileChangeEvidence):
        _raise_invalid("file change evidence is invalid")
    if type(change.hunks) is not tuple:
        _raise_invalid("diff hunks must be a tuple")

    if change.new is not None:
        if not isinstance(change.new, FileVersion):
            _raise_invalid("new-side file evidence is invalid")
        if not change.new.path:
            _raise_invalid("new-side paths must be non-empty")
        _require_utf8(change.new.path, "new-side paths must be valid UTF-8")
        _validate_oid(change.new.oid, oid_length, "new-side OIDs must match the object format")

    new_line_numbers: set[int] = set()
    for hunk in change.hunks:
        if not isinstance(hunk, DiffHunkEvidence):
            _raise_invalid("diff hunk evidence is invalid")
        if type(hunk.lines) is not tuple:
            _raise_invalid("diff lines must be a tuple")
        for line in hunk.lines:
            if not isinstance(line, DiffLineEvidence):
                _raise_invalid("diff line evidence is invalid")
            if line.kind is not DiffLineKind.ADDITION:
                continue
            if change.new is None:
                _raise_invalid("addition lines require a new file side")
            if line.old_line_number is not None:
                _raise_invalid("addition lines must not have an old line number")
            number = line.new_line_number
            if type(number) is not int or number <= 0 or number in new_line_numbers:
                _raise_invalid(
                    "addition lines must have unique positive new line numbers per change"
                )
            new_line_numbers.add(number)


def _require_utf8(value: object, message: str) -> None:
    if not isinstance(value, str):
        _raise_invalid(message)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReviewError(ReviewErrorCode.INVALID_EVIDENCE, message) from error


def _validate_oid(oid: object, length: int, message: str) -> None:
    if (
        not isinstance(oid, str)
        or len(oid) != length
        or _LOWERCASE_HEX_PATTERN.fullmatch(oid) is None
    ):
        _raise_invalid(message)


def _raise_invalid(message: str) -> Never:
    raise ReviewError(ReviewErrorCode.INVALID_EVIDENCE, message)


def _private_key_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for change in bundle.changes:
        if change.new is None:
            continue
        unmatched_begins: dict[str, deque[int]] = defaultdict(deque)
        for line_number, content in _addition_lines(change):
            for match in _PRIVATE_KEY_MARKER_PATTERN.finditer(content):
                marker_kind, label = match.groups()
                if marker_kind == "BEGIN":
                    unmatched_begins[label].append(line_number)
                    continue
                starts = unmatched_begins[label]
                if starts:
                    start_line = starts.popleft()
                    findings.append(
                        _text_finding(
                            change.new,
                            rule_id=RuleId.PRIVATE_KEY_MATERIAL,
                            category=FindingCategory.SECURITY,
                            severity=FindingSeverity.HIGH,
                            title="Private key material added",
                            message="Added lines contain a paired private-key block.",
                            remediation=(
                                "Remove the private key, rotate any exposed credential, and load "
                                "the replacement from an approved secret store."
                            ),
                            start_line=start_line,
                            end_line=line_number,
                        )
                    )
    return tuple(findings)


def _merge_conflict_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for change in bundle.changes:
        if change.new is None:
            continue
        starts_by_length: dict[int, deque[int]] = defaultdict(deque)
        blocks_by_length: dict[int, deque[int]] = defaultdict(deque)
        for line_number, content in _addition_lines(change):
            start_match = _CONFLICT_START_PATTERN.fullmatch(content)
            if start_match is not None:
                starts_by_length[len(start_match.group(1))].append(line_number)
                continue

            separator_match = _CONFLICT_SEPARATOR_PATTERN.fullmatch(content)
            if separator_match is not None:
                marker_length = len(separator_match.group(1))
                starts = starts_by_length[marker_length]
                if starts:
                    blocks_by_length[marker_length].append(starts.popleft())
                continue

            end_match = _CONFLICT_END_PATTERN.fullmatch(content)
            if end_match is None:
                continue
            blocks = blocks_by_length[len(end_match.group(1))]
            if not blocks:
                continue
            start_line = blocks.popleft()
            findings.append(
                _text_finding(
                    change.new,
                    rule_id=RuleId.MERGE_CONFLICT_MARKER,
                    category=FindingCategory.CORRECTNESS,
                    severity=FindingSeverity.MEDIUM,
                    title="Unresolved merge conflict added",
                    message="Added lines contain a complete unresolved merge-conflict block.",
                    remediation=(
                        "Resolve the conflict, remove the conflict markers, and verify the "
                        "intended "
                        "combined content."
                    ),
                    start_line=start_line,
                    end_line=line_number,
                )
            )
    return tuple(findings)


def _executable_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for change in bundle.changes:
        new = change.new
        if new is None or new.mode != "100755":
            continue
        if change.old is not None and change.old.mode == "100755":
            continue
        findings.append(
            _file_finding(
                new,
                rule_id=RuleId.EXECUTABLE_BIT_ADDED,
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.LOW,
                title="Executable permission introduced",
                message="The head version introduces executable permission for this file.",
                remediation=(
                    "Confirm that executable permission is required; otherwise restore a "
                    "non-executable regular-file mode."
                ),
            )
        )
    return tuple(findings)


def _symlink_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    return _content_kind_findings(
        bundle,
        content_kind=ContentKind.SYMLINK,
        rule_id=RuleId.SYMLINK_CHANGED,
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.MEDIUM,
        title="Symbolic link introduced or changed",
        message="The head version introduces a symbolic link or changes its target object.",
        remediation=(
            "Verify that the link target is intentional and cannot escape or redirect access "
            "outside the expected repository path."
        ),
    )


def _submodule_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    return _content_kind_findings(
        bundle,
        content_kind=ContentKind.SUBMODULE,
        rule_id=RuleId.SUBMODULE_CHANGED,
        category=FindingCategory.SUPPLY_CHAIN,
        severity=FindingSeverity.MEDIUM,
        title="Submodule pointer introduced or changed",
        message="The head version introduces a submodule or changes its referenced commit.",
        remediation=(
            "Verify the submodule source and review the referenced commit before accepting the "
            "change."
        ),
    )


def _binary_findings(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    return _content_kind_findings(
        bundle,
        content_kind=ContentKind.BINARY,
        rule_id=RuleId.BINARY_CONTENT_CHANGED,
        category=FindingCategory.REVIEWABILITY,
        severity=FindingSeverity.INFO,
        title="Opaque binary content introduced or changed",
        message=(
            "The head version introduces binary content or changes its object ID, so text review "
            "evidence is unavailable."
        ),
        remediation=(
            "Verify the binary's provenance and inspect it with an appropriate trusted tool."
        ),
    )


def _content_kind_findings(
    bundle: EvidenceBundle,
    *,
    content_kind: ContentKind,
    rule_id: RuleId,
    category: FindingCategory,
    severity: FindingSeverity,
    title: str,
    message: str,
    remediation: str,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for change in bundle.changes:
        new = change.new
        if new is None or new.content_kind is not content_kind:
            continue
        old = change.old
        if old is not None and old.content_kind is content_kind and old.oid == new.oid:
            continue
        findings.append(
            _file_finding(
                new,
                rule_id=rule_id,
                category=category,
                severity=severity,
                title=title,
                message=message,
                remediation=remediation,
            )
        )
    return tuple(findings)


def _addition_lines(change: FileChangeEvidence) -> tuple[_Addition, ...]:
    additions = [
        (line.new_line_number, _logical_line_content(line))
        for hunk in change.hunks
        for line in hunk.lines
        if line.kind is DiffLineKind.ADDITION and line.new_line_number is not None
    ]
    return tuple(sorted(additions))


def _logical_line_content(line: DiffLineEvidence) -> str:
    # M1 removes LF from patch lines but preserves the CR in a CRLF terminator.
    if line.has_trailing_newline:
        return line.content.removesuffix("\r")
    return line.content


def _text_finding(
    version: FileVersion,
    *,
    rule_id: RuleId,
    category: FindingCategory,
    severity: FindingSeverity,
    title: str,
    message: str,
    remediation: str,
    start_line: int,
    end_line: int,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        message=message,
        remediation=remediation,
        references=(
            EvidenceReference(
                path=version.path,
                side=EvidenceSide.NEW,
                oid=version.oid,
                start_line=start_line,
                end_line=end_line,
            ),
        ),
    )


def _file_finding(
    version: FileVersion,
    *,
    rule_id: RuleId,
    category: FindingCategory,
    severity: FindingSeverity,
    title: str,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        message=message,
        remediation=remediation,
        references=(
            EvidenceReference(
                path=version.path,
                side=EvidenceSide.NEW,
                oid=version.oid,
                start_line=None,
                end_line=None,
            ),
        ),
    )


def _canonicalize_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    unique: dict[tuple[RuleId, tuple[EvidenceReference, ...]], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.references), finding)
    return tuple(sorted(unique.values(), key=_finding_sort_key))


def _finding_sort_key(finding: Finding) -> _FindingSortKey:
    first_reference = finding.references[0]
    return (
        _SEVERITY_RANK[finding.severity],
        first_reference.path.encode("utf-8"),
        _line_sort_value(first_reference.start_line),
        _line_sort_value(first_reference.end_line),
        finding.rule_id.value,
        tuple(_reference_sort_key(reference) for reference in finding.references),
    )


def _reference_sort_key(reference: EvidenceReference) -> _ReferenceSortKey:
    return (
        reference.path.encode("utf-8"),
        reference.side.value,
        reference.oid,
        _line_sort_value(reference.start_line),
        _line_sort_value(reference.end_line),
    )


def _line_sort_value(line: int | None) -> int:
    return 0 if line is None else line


_RULES: tuple[tuple[RuleId, _RuleEvaluator], ...] = (
    (RuleId.PRIVATE_KEY_MATERIAL, _private_key_findings),
    (RuleId.MERGE_CONFLICT_MARKER, _merge_conflict_findings),
    (RuleId.EXECUTABLE_BIT_ADDED, _executable_findings),
    (RuleId.SYMLINK_CHANGED, _symlink_findings),
    (RuleId.SUBMODULE_CHANGED, _submodule_findings),
    (RuleId.BINARY_CONTENT_CHANGED, _binary_findings),
)
