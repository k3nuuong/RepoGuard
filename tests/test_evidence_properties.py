"""Property specifications for Git parsing and canonical evidence JSON."""

import json
import os
import subprocess
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from repoguard._git import (
    _invoke_git,
    _invoke_no_index_diff,
    _parse_hunks,
    _parse_merge_bases,
    _parse_raw_changes,
    _read_patch,
    _resolve_merge_base,
    _run_required,
)
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
EMPTY_BUNDLE = EvidenceBundle(
    repository=RepositoryEvidence(root=Path("/repo"), object_format="sha1"),
    revisions=RevisionEvidence(
        base_ref="main",
        head_ref="main",
        base_oid=OID_A,
        head_oid=OID_A,
        merge_base_oid=OID_A,
    ),
    changes=(),
)
PROPERTY_SETTINGS = settings(
    database=None,
    derandomize=True,
    max_examples=100,
)
SURROGATE_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
UTF8_CHARACTER = st.characters(
    exclude_categories=SURROGATE_CATEGORIES,
    exclude_characters="\x00",
)
GIT_PATH = st.text(UTF8_CHARACTER, min_size=1, max_size=24)
LINE_CHARACTER = st.characters(
    exclude_categories=SURROGATE_CATEGORIES,
    exclude_characters="\x00\n",
)
LOGICAL_LINE = st.text(LINE_CHARACTER, max_size=24)

FILE_VERSION = st.builds(
    FileVersion,
    path=GIT_PATH,
    mode=st.sampled_from(("100644", "100755", "120000", "160000")),
    oid=st.sampled_from((OID_A, OID_B)),
    content_kind=st.sampled_from(tuple(ContentKind)),
)
DIFF_LINE = st.builds(
    DiffLineEvidence,
    kind=st.sampled_from(tuple(DiffLineKind)),
    old_line_number=st.one_of(st.none(), st.integers(min_value=0, max_value=100)),
    new_line_number=st.one_of(st.none(), st.integers(min_value=0, max_value=100)),
    content=st.text(UTF8_CHARACTER, max_size=24),
    has_trailing_newline=st.booleans(),
)
DIFF_HUNK = st.builds(
    DiffHunkEvidence,
    old_start=st.integers(min_value=0, max_value=100),
    old_count=st.integers(min_value=0, max_value=10),
    new_start=st.integers(min_value=0, max_value=100),
    new_count=st.integers(min_value=0, max_value=10),
    lines=st.lists(DIFF_LINE, max_size=8).map(tuple),
)
FILE_CHANGE = st.builds(
    FileChangeEvidence,
    change_type=st.sampled_from(tuple(ChangeType)),
    rename_similarity=st.one_of(st.none(), st.integers(min_value=0, max_value=100)),
    old=st.one_of(st.none(), FILE_VERSION),
    new=st.one_of(st.none(), FILE_VERSION),
    hunks=st.lists(DIFF_HUNK, max_size=4).map(tuple),
)
BUNDLE = st.builds(
    EvidenceBundle,
    repository=st.builds(
        RepositoryEvidence,
        root=GIT_PATH.map(lambda path: Path("/repo") / path),
        object_format=st.sampled_from(("sha1", "sha256")),
    ),
    revisions=st.builds(
        RevisionEvidence,
        base_ref=GIT_PATH,
        head_ref=GIT_PATH,
        base_oid=st.sampled_from((OID_A, OID_B)),
        head_oid=st.sampled_from((OID_B, OID_C)),
        merge_base_oid=st.sampled_from((OID_A, OID_C)),
    ),
    changes=st.lists(FILE_CHANGE, max_size=5).map(tuple),
)

NON_EMPTY_LINES = st.lists(LOGICAL_LINE, min_size=1, max_size=5)
LINE_PAIRS: SearchStrategy[tuple[list[str], list[str]]] = st.one_of(
    st.tuples(NON_EMPTY_LINES, st.lists(LOGICAL_LINE, max_size=5)),
    st.tuples(st.just([]), NON_EMPTY_LINES),
)


@PROPERTY_SETTINGS
@example(bundle=EMPTY_BUNDLE)
@given(bundle=BUNDLE)
def test_canonical_json_matches_mapping_for_generated_bundles(
    bundle: EvidenceBundle,
) -> None:
    first = evidence_to_json(bundle)
    second = evidence_to_json(bundle)
    decoded: object = json.loads(first)

    assert first == second
    assert decoded == evidence_to_dict(bundle)
    assert not first.endswith("\n")
    first.encode("utf-8")


@PROPERTY_SETTINGS
@example(path="name\nwith\ttabs.txt")
@given(path=GIT_PATH)
def test_nul_delimited_raw_path_round_trips(path: str) -> None:
    header = f":100644 100644 {OID_A} {OID_B} M".encode()
    raw = header + b"\0" + path.encode() + b"\0"

    changes = _parse_raw_changes(raw, 40)

    assert len(changes) == 1
    assert changes[0].old_path == path
    assert changes[0].new_path == path
    assert changes[0].old_oid == OID_A
    assert changes[0].new_oid == OID_B


@PROPERTY_SETTINGS
@example(line_pair=([""], []))
@example(line_pair=([], [""]))
@given(line_pair=LINE_PAIRS)
def test_hunk_parser_preserves_content_and_line_coordinates(
    line_pair: tuple[list[str], list[str]],
) -> None:
    old_lines, new_lines = line_pair
    old_start = 1 if old_lines else 0
    new_start = 1 if new_lines else 0
    header = f"@@ -{old_start},{len(old_lines)} +{new_start},{len(new_lines)} @@\n"
    body = "".join(f"-{line}\n" for line in old_lines)
    body += "".join(f"+{line}\n" for line in new_lines)

    hunks = _parse_hunks((header + body).encode())

    assert len(hunks) == 1
    assert hunks[0].old_count == len(old_lines)
    assert hunks[0].new_count == len(new_lines)
    assert [line.content for line in hunks[0].lines] == old_lines + new_lines
    assert [
        line.old_line_number for line in hunks[0].lines if line.kind is DiffLineKind.DELETION
    ] == list(range(old_start, old_start + len(old_lines)))
    assert [
        line.new_line_number for line in hunks[0].lines if line.kind is DiffLineKind.ADDITION
    ] == list(range(new_start, new_start + len(new_lines)))


def test_hunk_parser_records_missing_final_newlines() -> None:
    patch = b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"

    hunk = _parse_hunks(patch)[0]

    assert [line.has_trailing_newline for line in hunk.lines] == [False, False]


def test_hunk_parser_rejects_count_mismatch() -> None:
    with pytest.raises(EvidenceCollectionError, match="line counts"):
        _parse_hunks(b"@@ -1,2 +1 @@\n-old\n+new\n")


@pytest.mark.parametrize(
    "raw",
    [
        b"not NUL terminated",
        b"not-a-header\0",
        b":100644 100644 too-few-fields\0path\0",
        f":badmode 100644 {OID_A} {OID_B} M".encode() + b"\0path\0",
        f":100644 100644 {OID_A} {OID_B} X".encode() + b"\0path\0",
        f":000000 100644 {OID_A} {OID_B} A".encode() + b"\0path\0",
        f":100644 100644 {OID_A} {OID_B} A".encode() + b"\0path\0",
        f":000000 000000 {'0' * 40} {'0' * 40} M".encode() + b"\0path\0",
    ],
)
def test_raw_diff_parser_rejects_malformed_records(raw: bytes) -> None:
    with pytest.raises(EvidenceCollectionError) as error_info:
        _parse_raw_changes(raw, 40)

    assert error_info.value.code is EvidenceErrorCode.MALFORMED_GIT_OUTPUT


def test_raw_diff_parser_rejects_non_utf8_paths() -> None:
    raw = f":100644 100644 {OID_A} {OID_B} M".encode() + b"\0\xff\0"

    with pytest.raises(EvidenceCollectionError) as error_info:
        _parse_raw_changes(raw, 40)

    assert error_info.value.code is EvidenceErrorCode.UNSUPPORTED_PATH_ENCODING


def test_merge_base_parser_and_resolver_reject_ambiguous_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = f"{OID_A}\n{OID_B}\n".encode()
    assert _parse_merge_bases(output, 40) == (OID_A, OID_B)

    def fake_invoke(
        root: Path,
        args: Sequence[str],
        *,
        attribute_source: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del root, attribute_source
        return subprocess.CompletedProcess(args, 0, stdout=output, stderr=b"")

    monkeypatch.setattr("repoguard._git._invoke_git", fake_invoke)
    with pytest.raises(EvidenceCollectionError) as error_info:
        _resolve_merge_base(tmp_path, OID_A, OID_B, 40)

    assert error_info.value.code is EvidenceErrorCode.AMBIGUOUS_MERGE_BASE


def test_git_nonzero_exit_uses_the_stable_command_error() -> None:
    with pytest.raises(EvidenceCollectionError) as error_info:
        _run_required(Path.cwd(), ("cat-file", "blob", "0" * 40))

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED


def test_patch_pipe_failure_uses_the_stable_command_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_to_create_pipe() -> tuple[int, int]:
        raise OSError("pipe unavailable")

    monkeypatch.setattr("repoguard._git.os.pipe", fail_to_create_pipe)

    with pytest.raises(EvidenceCollectionError) as error_info:
        _read_patch(b"old\n", b"new\n")

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED


def test_no_index_access_failure_is_not_treated_as_a_content_diff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_to_access_inputs(
        old_file_descriptor: int,
        new_file_descriptor: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del old_file_descriptor, new_file_descriptor
        return subprocess.CompletedProcess(
            ("git", "diff", "--no-index"),
            1,
            stdout=b"",
            stderr=b"error: Could not access '/dev/fd/3'\n",
        )

    monkeypatch.setattr("repoguard._git._invoke_no_index_diff", fail_to_access_inputs)

    with pytest.raises(EvidenceCollectionError) as error_info:
        _read_patch(b"old\n", b"new\n")

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED


@pytest.mark.parametrize("failing_start", [1, 2])
def test_patch_thread_start_failure_closes_all_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    failing_start: int,
) -> None:
    real_start = threading.Thread.start
    start_count = 0

    def controlled_start(thread: threading.Thread) -> None:
        nonlocal start_count
        start_count += 1
        if start_count == failing_start:
            raise RuntimeError("thread unavailable")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", controlled_start)
    descriptors_before = set(os.listdir("/proc/self/fd"))

    with pytest.raises(EvidenceCollectionError) as error_info:
        _read_patch(b"old\n", b"new\n")

    assert error_info.value.code is EvidenceErrorCode.GIT_COMMAND_FAILED
    assert set(os.listdir("/proc/self/fd")) == descriptors_before


def test_git_invocation_disables_lazy_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed_environment: dict[str, str] = {}

    def fake_run(
        command: Sequence[str],
        *,
        check: bool,
        capture_output: bool,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        assert not check
        assert capture_output
        observed_environment.update(env)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    monkeypatch.setattr(subprocess, "run", fake_run)

    _invoke_git(tmp_path, ("rev-parse", "HEAD"))

    assert observed_environment["GIT_NO_LAZY_FETCH"] == "1"


def test_no_index_diff_uses_packaged_metadata_facade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_environment: dict[str, str] = {}

    def fake_run(
        command: Sequence[str],
        *,
        check: bool,
        capture_output: bool,
        cwd: str,
        env: Mapping[str, str],
        pass_fds: Sequence[int],
    ) -> subprocess.CompletedProcess[bytes]:
        assert not check
        assert capture_output
        assert cwd == os.path.abspath(os.sep)
        assert tuple(pass_fds) == (10, 11)
        observed_environment.update(env)
        return subprocess.CompletedProcess(command, 1, stdout=b"patch", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    _invoke_no_index_diff(10, 11)

    facade = Path(observed_environment["GIT_DIR"])
    assert facade.name == "sha1"
    assert facade.joinpath("HEAD").is_file()
    assert facade.joinpath("config").is_file()
