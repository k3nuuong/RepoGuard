"""Security and schema tests for the owner-only M6 host profile."""

import json
import os
import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from repoguard.host_profile import (
    HostGitHubActions,
    HostMCPWriters,
    HostProfile,
    HostPublisherRuntime,
    HostRepository,
    M4CacheProfile,
    ProductProviderKind,
    ProductRepairProfile,
    ProductReviewMode,
    ProductReviewProfile,
    host_profile_to_dict,
    host_profile_to_json,
    load_host_profile,
)
from repoguard.repair import (
    RepairGenerationMode,
    RepairGenerationPolicy,
    ValidationCommand,
    ValidationPolicy,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

_IMAGE_ID = "sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846"


def _mkdir_private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _profile(tmp_path: Path, socket_path: Path) -> HostProfile:
    repository = tmp_path / "repository"
    repository.mkdir()
    product_state = _mkdir_private(tmp_path / "product-state")
    repair_state = _mkdir_private(tmp_path / "repair-state")
    git = _executable(tmp_path / "git")
    docker = _executable(tmp_path / "docker")
    runtime = _mkdir_private(tmp_path / "publisher-runtime")
    package = _mkdir_private(runtime / "packages")
    package_init = package / "__init__.py"
    package_init.write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    package_init.chmod(0o600)
    package_module = package / "product.py"
    package_module.write_text("VALUE = 1\n", encoding="utf-8")
    package_module.chmod(0o600)
    python = _executable(runtime / "python")
    source = _mkdir_private(tmp_path / "publisher-source")
    scripts = _mkdir_private(source / "scripts")
    action_driver = scripts / "m6_action.py"
    action_driver.write_text("raise SystemExit(0)\n", encoding="utf-8")
    action_driver.chmod(0o600)
    review = ProductReviewProfile(
        name="deterministic",
        mode=ProductReviewMode.DETERMINISTIC,
        provider=ProductProviderKind.NONE,
        model=None,
        cache=None,
        device=EmbeddingDevice.CPU,
        fail_on=FindingSeverity.HIGH,
    )
    repair = ProductRepairProfile(
        name="safe",
        review_profile="deterministic",
        generation=RepairGenerationPolicy(
            mode=RepairGenerationMode.DETERMINISTIC,
            provider_kind=None,
            model=None,
        ),
        validation=ValidationPolicy(
            image_id=_IMAGE_ID,
            commands=(ValidationCommand(argv=("/usr/bin/python3", "-m", "pytest")),),
        ),
        allowed_path_prefixes=("src",),
    )
    return HostProfile(
        schema_version=1,
        repositories=(
            HostRepository(
                alias="repository",
                path=repository,
                github_repository_id=123456,
                github_full_name="owner/repository",
            ),
        ),
        git_executable=git,
        docker_executable=docker,
        rootless_socket=socket_path,
        product_state_root=product_state,
        repair_state_root=repair_state,
        runner_labels=("Linux", "X64", "repoguard-publisher", "self-hosted"),
        m4_caches=(),
        review_profiles=(review,),
        repair_profiles=(repair,),
        github_actions=HostGitHubActions(
            action_repository="owner/repoguard",
            action_sha="a" * 40,
            publisher=HostPublisherRuntime(
                python_executable=python,
                runtime_root=runtime,
                package_root=package,
                source_root=source,
            ),
        ),
        mcp=HostMCPWriters(publish_check=False, publish_repair=False),
    )


def _write_profile(path: Path, profile: HostProfile, *, mode: int = 0o600) -> None:
    path.write_text(host_profile_to_json(profile), encoding="utf-8")
    path.chmod(mode)


@pytest.fixture
def profile_fixture(
    tmp_path: Path,
    socket_enabled: None,
) -> tuple[HostProfile, Path, socket.socket]:
    assert socket_enabled is None
    socket_path = tmp_path / "docker.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    profile = _profile(tmp_path, socket_path)
    profile_path = tmp_path / "profile.json"
    _write_profile(profile_path, profile)
    return profile, profile_path, server


def test_load_owner_only_canonical_profile(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    try:
        loaded = load_host_profile(path)
    finally:
        server.close()

    assert loaded == profile
    assert loaded.repository("repository").path == profile.repositories[0].path
    assert loaded.review_profile("deterministic") == profile.review_profiles[0]
    assert loaded.repair_profile("safe") == profile.repair_profiles[0]
    assert host_profile_to_json(loaded) == path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("mode", "link_kind"),
    [
        (0o644, "plain"),
        (0o600, "hardlink"),
        (0o600, "symlink"),
    ],
)
def test_profile_file_must_be_owner_only_single_link_and_not_symlink(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
    mode: int,
    link_kind: str,
) -> None:
    _profile_value, path, server = profile_fixture
    candidate = path
    if link_kind == "hardlink":
        candidate = tmp_path / "profile-hardlink.json"
        os.link(path, candidate)
    elif link_kind == "symlink":
        candidate = tmp_path / "profile-symlink.json"
        candidate.symlink_to(path)
    else:
        path.chmod(mode)
    try:
        with pytest.raises(ValueError, match="host profile is invalid") as error_info:
            load_host_profile(candidate)
        assert str(candidate) not in str(error_info.value)
    finally:
        server.close()


def test_profile_rejects_world_writable_ancestor(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
) -> None:
    profile, _path, server = profile_fixture
    untrusted = tmp_path / "untrusted"
    untrusted.mkdir(mode=0o700)
    protected = _mkdir_private(untrusted / "protected")
    path = protected / "profile.json"
    _write_profile(path, profile)
    untrusted.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_rejects_namespace_swap_during_read(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, path, server = profile_fixture
    original_open = os.open
    profile_opens = 0

    def swap_before_reopen(
        candidate: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal profile_opens
        if candidate == path.name and dir_fd is not None:
            profile_opens += 1
            if profile_opens == 2:
                displaced = path.with_name("profile-displaced.json")
                path.rename(displaced)
                _write_profile(path, profile)
        return original_open(candidate, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_before_reopen)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_rejects_torn_same_inode_read(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _profile_value, path, server = profile_fixture
    raw = path.read_bytes()
    original_read = os.read
    mutated = False

    def rewrite_while_reading(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if not mutated:
            mutated = True
            path.write_bytes(raw)
            path.chmod(0o600)
        return chunk

    monkeypatch.setattr(os, "read", rewrite_while_reading)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


@pytest.mark.parametrize("suffix", ["\n", " "])
def test_profile_rejects_noncanonical_trailing_bytes(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    suffix: str,
) -> None:
    _profile_value, path, server = profile_fixture
    path.write_text(path.read_text(encoding="utf-8") + suffix, encoding="utf-8")
    path.chmod(0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_rejects_duplicate_and_unknown_fields(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    duplicate = host_profile_to_json(profile).replace(
        '"schema_version":1',
        '"schema_version":1,"schema_version":1',
    )
    path.write_text(duplicate, encoding="utf-8")
    path.chmod(0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
        mapping = host_profile_to_dict(profile)
        mapping["secret"] = "forbidden"
        path.write_text(
            json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        path.chmod(0o600)
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "actions-missing",
        "unknown",
        "publisher-missing",
        "publisher-unknown",
    ],
)
def test_profile_requires_exact_github_actions_schema(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    mutation: str,
) -> None:
    profile, path, server = profile_fixture
    mapping = host_profile_to_dict(profile)
    if mutation == "missing":
        del mapping["github_actions"]
    else:
        actions = mapping["github_actions"]
        assert isinstance(actions, dict)
        if mutation == "actions-missing":
            del actions["action_sha"]
        elif mutation == "unknown":
            actions["unexpected"] = None
        else:
            publisher = actions["publisher"]
            assert isinstance(publisher, dict)
            if mutation == "publisher-missing":
                del publisher["package_root"]
            else:
                publisher["unexpected"] = None
    path.write_text(
        json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_must_be_outside_reviewed_repository(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, _path, server = profile_fixture
    path = profile.repositories[0].path / "profile.json"
    _write_profile(path, profile)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_state_roots_are_exact_owner_only_directories(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    profile.product_state_root.chmod(0o755)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


@pytest.mark.parametrize("capability", ["git", "docker", "socket"])
def test_executable_and_socket_capabilities_must_be_outside_reviewed_repository(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    capability: str,
) -> None:
    profile, path, server = profile_fixture
    repository = profile.repositories[0].path
    replacement = repository / capability
    if capability == "socket":
        server.close()
        replacement_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement_server.bind(str(replacement))
        changed = replace(profile, rootless_socket=replacement)
    else:
        replacement_server = None
        _executable(replacement)
        changed = (
            replace(profile, git_executable=replacement)
            if capability == "git"
            else replace(profile, docker_executable=replacement)
        )
    _write_profile(path, changed)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        if replacement_server is not None:
            replacement_server.close()
        else:
            server.close()


@pytest.mark.parametrize("mode", [0o720, 0o702, 0o777])
def test_executables_must_not_be_group_or_world_writable(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    mode: int,
) -> None:
    profile, path, server = profile_fixture
    profile.git_executable.chmod(mode)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_protected_capability_rejects_world_writable_ancestor(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
) -> None:
    profile, path, server = profile_fixture
    untrusted = tmp_path / "untrusted-capability"
    untrusted.mkdir(mode=0o700)
    replacement = _executable(untrusted / "git")
    untrusted.chmod(0o777)
    _write_profile(path, replace(profile, git_executable=replacement))
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_m4_cache_must_not_overlap_state_roots(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    mapping = host_profile_to_dict(profile)
    mapping["m4_caches"] = [
        {
            "name": "offline",
            "path": str(profile.repair_state_root),
            "device": "cpu",
        }
    ]
    path.write_text(
        json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_rejects_unknown_repository_path_as_alias(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    _profile_value, path, server = profile_fixture
    try:
        loaded = load_host_profile(path)
    finally:
        server.close()

    with pytest.raises(ValueError, match="repository alias"):
        loaded.repository("/tmp/arbitrary-repository")
    with pytest.raises(ValueError, match="unknown"):
        loaded.repository("another")


def test_profile_rejects_policy_above_existing_m5_ceiling(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    mapping = host_profile_to_dict(profile)
    repair_profiles = mapping["repair_profiles"]
    assert isinstance(repair_profiles, list)
    repair_mapping = repair_profiles[0]
    assert isinstance(repair_mapping, dict)
    generation = repair_mapping["generation"]
    assert isinstance(generation, dict)
    generation["max_patch_paths"] = 33
    path.write_text(
        json.dumps(mapping, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_profile_requires_sorted_unique_names_and_prefixes() -> None:
    review_a = ProductReviewProfile(
        name="a",
        mode=ProductReviewMode.DETERMINISTIC,
        provider=ProductProviderKind.NONE,
        model=None,
        cache=None,
        device=EmbeddingDevice.CPU,
        fail_on=FindingSeverity.HIGH,
    )
    with pytest.raises(ValueError, match="allowed path prefixes must be sorted"):
        ProductRepairProfile(
            name="repair",
            review_profile="a",
            generation=RepairGenerationPolicy(
                mode=RepairGenerationMode.DETERMINISTIC,
                provider_kind=None,
                model=None,
            ),
            validation=ValidationPolicy(
                image_id=_IMAGE_ID,
                commands=(ValidationCommand(argv=("/usr/bin/true",)),),
            ),
            allowed_path_prefixes=("tests", "src"),
        )
    with pytest.raises(ValueError, match="deterministic review profile"):
        replace(review_a, provider=ProductProviderKind.OPENAI, model="model")


@pytest.mark.parametrize(
    "runner_labels",
    [
        ("Linux", "X64", "self-hosted"),
        ("Linux", "X64", "linux", "self-hosted"),
        ("X64", "Linux", "repoguard-publisher", "self-hosted"),
        ("Linux", "X64", "repoguard m6", "self-hosted"),
    ],
)
def test_profile_requires_fixed_unique_self_hosted_runner_labels(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    runner_labels: tuple[str, ...],
) -> None:
    profile, _path, server = profile_fixture
    try:
        with pytest.raises(ValueError, match="runner label"):
            replace(profile, runner_labels=runner_labels)
    finally:
        server.close()


def test_review_only_profile_may_declare_no_self_hosted_runner_capability(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    assert profile.github_actions is not None
    try:
        hosted_actions = replace(profile.github_actions, publisher=None)
        hosted = replace(
            profile,
            runner_labels=(),
            github_actions=hosted_actions,
        )
        assert hosted.runner_labels == ()
        assert hosted.github_actions == hosted_actions
        _write_profile(path, hosted)
        assert load_host_profile(path) == hosted
    finally:
        server.close()


def test_non_action_profile_serializes_explicit_null_capability(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, _path, server = profile_fixture
    try:
        non_action = replace(profile, runner_labels=(), github_actions=None)
        assert host_profile_to_dict(non_action)["github_actions"] is None
    finally:
        server.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action_repository", "owner"),
        ("action_repository", "owner/../repo"),
        ("action_sha", "A" * 40),
        ("action_sha", "a" * 39),
    ],
)
def test_github_actions_requires_exact_repository_and_lowercase_sha(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValueError, match="GitHub Action"):
        HostGitHubActions(
            action_repository=value if field == "action_repository" else "owner/repoguard",
            action_sha=value if field == "action_sha" else "a" * 40,
            publisher=None,
        )


def test_runner_labels_and_publisher_runtime_are_declared_together(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, _path, server = profile_fixture
    assert profile.github_actions is not None
    try:
        with pytest.raises(ValueError, match="declared together"):
            replace(profile, runner_labels=())
        with pytest.raises(ValueError, match="declared together"):
            replace(
                profile,
                github_actions=replace(profile.github_actions, publisher=None),
            )
    finally:
        server.close()


@pytest.mark.parametrize("layout", ["python-outside", "package-outside", "source-overlap"])
def test_publisher_runtime_requires_isolated_normalized_layout(
    tmp_path: Path,
    layout: str,
) -> None:
    runtime = tmp_path / "runtime"
    package = runtime / "packages"
    python = runtime / "python"
    source = tmp_path / "source"
    if layout == "python-outside":
        python = tmp_path / "python"
    elif layout == "package-outside":
        package = tmp_path / "packages"
    else:
        source = runtime / "source"
    with pytest.raises(ValueError, match="publisher"):
        HostPublisherRuntime(
            python_executable=python,
            runtime_root=runtime,
            package_root=package,
            source_root=source,
        )


@pytest.mark.parametrize(
    ("capability", "mutation"),
    [
        ("python", "non-executable"),
        ("python", "group-writable"),
        ("python", "hardlink"),
        ("runtime", "group-writable"),
        ("package", "world-writable"),
        ("source", "symlink"),
        ("driver", "hardlink"),
        ("driver", "world-writable"),
    ],
)
def test_publisher_runtime_requires_fixed_protected_filesystem_capabilities(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
    capability: str,
    mutation: str,
) -> None:
    profile, path, server = profile_fixture
    assert profile.github_actions is not None
    publisher = profile.github_actions.publisher
    assert publisher is not None
    target = {
        "python": publisher.python_executable,
        "runtime": publisher.runtime_root,
        "package": publisher.package_root,
        "source": publisher.source_root,
        "driver": publisher.source_root / "scripts" / "m6_action.py",
    }[capability]
    if mutation == "non-executable":
        target.chmod(0o600)
    elif mutation == "group-writable":
        target.chmod(0o720)
    elif mutation == "world-writable":
        target.chmod(0o702)
    elif mutation == "hardlink":
        os.link(target, tmp_path / f"{capability}-hardlink")
    else:
        replacement = tmp_path / "source-link"
        replacement.symlink_to(target, target_is_directory=True)
        profile = replace(
            profile,
            github_actions=replace(
                profile.github_actions,
                publisher=replace(publisher, source_root=replacement),
            ),
        )
        _write_profile(path, profile)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


@pytest.mark.parametrize("mutation", ["writable-file", "hardlink", "symlink", "special"])
def test_publisher_package_tree_is_recursively_protected(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
    mutation: str,
) -> None:
    profile, path, server = profile_fixture
    assert profile.github_actions is not None
    publisher = profile.github_actions.publisher
    assert publisher is not None
    target = publisher.package_root / "product.py"
    if mutation == "writable-file":
        target.chmod(0o666)
    elif mutation == "hardlink":
        os.link(target, tmp_path / "package-hardlink.py")
    elif mutation == "symlink":
        (publisher.package_root / "linked.py").symlink_to(target)
    else:
        os.mkfifo(publisher.package_root / "pipe", mode=0o600)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_host_profile_validation_does_not_leak_descriptors(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
) -> None:
    profile, path, server = profile_fixture
    assert profile.github_actions is not None
    publisher = profile.github_actions.publisher
    assert publisher is not None
    (publisher.package_root / "product.py").chmod(0o666)
    descriptor_root = Path("/proc/self/fd")
    before = len(tuple(descriptor_root.iterdir()))
    try:
        for _ in range(50):
            with pytest.raises(ValueError, match="host profile is invalid"):
                load_host_profile(path)
        assert len(tuple(descriptor_root.iterdir())) == before
    finally:
        server.close()


@pytest.mark.parametrize("overlap", ["repository", "product-state", "cache"])
def test_publisher_roots_must_not_overlap_reviewed_or_mutable_roots(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
    overlap: str,
) -> None:
    profile, path, server = profile_fixture
    assert profile.github_actions is not None
    publisher = profile.github_actions.publisher
    assert publisher is not None
    changed = profile
    if overlap == "repository":
        source = profile.repositories[0].path / "publisher-source"
    elif overlap == "product-state":
        source = profile.product_state_root / "publisher-source"
    else:
        cache = _mkdir_private(tmp_path / "cache")
        changed = replace(
            profile,
            m4_caches=(M4CacheProfile(name="offline", path=cache, device=EmbeddingDevice.CPU),),
        )
        source = cache / "publisher-source"
    _mkdir_private(source)
    scripts = _mkdir_private(source / "scripts")
    driver = scripts / "m6_action.py"
    driver.write_text("raise SystemExit(0)\n", encoding="utf-8")
    driver.chmod(0o600)
    changed = replace(
        changed,
        github_actions=replace(
            profile.github_actions,
            publisher=replace(publisher, source_root=source),
        ),
    )
    _write_profile(path, changed)
    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


def test_mutable_state_must_not_overlap_external_git_common_directory(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
) -> None:
    profile, path, server = profile_fixture
    repository = profile.repositories[0].path
    common_directory = tmp_path / "shared.git"
    git = shutil.which("git")
    assert git is not None
    subprocess.run(
        (
            git,
            "init",
            "--quiet",
            f"--separate-git-dir={common_directory}",
            str(repository),
        ),
        check=True,
        capture_output=True,
    )
    common_directory.chmod(0o700)
    product_state = _mkdir_private(common_directory / "product-state")
    changed = replace(
        profile,
        git_executable=Path(git),
        product_state_root=product_state,
    )
    _write_profile(path, changed)

    try:
        with pytest.raises(ValueError, match="host profile is invalid"):
            load_host_profile(path)
    finally:
        server.close()


@pytest.mark.parametrize("duplicate", ["github_id", "github_name", "path"])
def test_profile_rejects_overlapping_repository_identity_mappings(
    profile_fixture: tuple[HostProfile, Path, socket.socket],
    tmp_path: Path,
    duplicate: str,
) -> None:
    profile, _path, server = profile_fixture
    first = profile.repositories[0]
    second_path = tmp_path / "repository-two"
    second_path.mkdir()
    second = HostRepository(
        alias="repository-two",
        path=first.path if duplicate == "path" else second_path,
        github_repository_id=(first.github_repository_id if duplicate == "github_id" else 654321),
        github_full_name=(
            first.github_full_name.upper() if duplicate == "github_name" else "owner/repository-two"
        ),
    )
    try:
        with pytest.raises(ValueError, match="repository"):
            replace(profile, repositories=(first, second))
    finally:
        server.close()
