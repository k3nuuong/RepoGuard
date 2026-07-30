"""Strict owner-only host profile for RepoGuard product interfaces."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

from repoguard._canonical import (
    JSONValue,
    canonical_json_text,
    parse_canonical_json,
    require_exact_keys,
)
from repoguard.repair import (
    RepairGenerationMode,
    RepairGenerationPolicy,
    RepairProviderKind,
    ValidationCommand,
    ValidationPolicy,
    repair_generation_policy_to_dict,
    validation_policy_to_dict,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

__all__ = [
    "HOST_PROFILE_MAX_BYTES",
    "HostGitHubActions",
    "HostMCPWriters",
    "HostProfile",
    "HostPublisherRuntime",
    "HostRepository",
    "M4CacheProfile",
    "ProductProviderKind",
    "ProductRepairProfile",
    "ProductReviewMode",
    "ProductReviewProfile",
    "host_profile_to_dict",
    "host_profile_to_json",
    "load_host_profile",
]

HOST_PROFILE_MAX_BYTES = 1024 * 1024
_MAX_PACKAGE_TREE_ENTRIES = 10_000
_MAX_PACKAGE_TREE_DEPTH = 64
_MAX_GIT_PATH_BYTES = 4_096
_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_GITHUB_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_REQUIRED_RUNNER_LABELS = frozenset(("Linux", "X64", "self-hosted"))
_GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ProductReviewMode(StrEnum):
    """Review capability selected by a named host policy."""

    DETERMINISTIC = "deterministic"
    AGENT = "agent"
    RETRIEVAL = "retrieval"


class ProductProviderKind(StrEnum):
    """Provider selection for review policies."""

    NONE = "none"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


@dataclass(frozen=True, slots=True)
class HostRepository:
    """One fixed local repository alias and GitHub identity."""

    alias: str
    path: Path
    github_repository_id: int
    github_full_name: str

    def __post_init__(self) -> None:
        _require_alias(self.alias, "repository alias")
        _require_absolute_path(self.path, "repository path")
        if type(self.github_repository_id) is not int or self.github_repository_id <= 0:
            raise ValueError("GitHub repository ID is invalid")
        if (
            type(self.github_full_name) is not str
            or _GITHUB_NAME_PATTERN.fullmatch(self.github_full_name) is None
            or ".." in self.github_full_name
        ):
            raise ValueError("GitHub full name is invalid")


@dataclass(frozen=True, slots=True)
class M4CacheProfile:
    """One fixed offline M4 model cache capability."""

    name: str
    path: Path
    device: EmbeddingDevice

    def __post_init__(self) -> None:
        _require_alias(self.name, "cache name")
        _require_absolute_path(self.path, "cache path")
        if type(self.device) is not EmbeddingDevice:
            raise ValueError("cache device is invalid")


@dataclass(frozen=True, slots=True)
class ProductReviewProfile:
    """One named deterministic, Agent, or retrieval review policy."""

    name: str
    mode: ProductReviewMode
    provider: ProductProviderKind
    model: str | None
    cache: str | None
    device: EmbeddingDevice
    fail_on: FindingSeverity

    def __post_init__(self) -> None:
        _require_alias(self.name, "review profile name")
        if type(self.mode) is not ProductReviewMode:
            raise ValueError("review mode is invalid")
        if type(self.provider) is not ProductProviderKind:
            raise ValueError("review provider is invalid")
        if type(self.device) is not EmbeddingDevice:
            raise ValueError("review device is invalid")
        if type(self.fail_on) is not FindingSeverity:
            raise ValueError("review fail_on is invalid")
        if self.mode is ProductReviewMode.DETERMINISTIC:
            if self.provider is not ProductProviderKind.NONE or any(
                value is not None for value in (self.model, self.cache)
            ):
                raise ValueError("deterministic review profile is invalid")
        else:
            if self.provider is ProductProviderKind.NONE or self.model is None:
                raise ValueError("model review profile requires provider and model")
            _require_text(self.model, "review model", max_bytes=256)
            if self.mode is ProductReviewMode.AGENT and self.cache is not None:
                raise ValueError("Agent review profile cannot name a cache")
            if self.mode is ProductReviewMode.RETRIEVAL:
                _require_alias(self.cache, "review cache")


@dataclass(frozen=True, slots=True)
class ProductRepairProfile:
    """One named M5 generation/validation policy with path-prefix authority."""

    name: str
    review_profile: str
    generation: RepairGenerationPolicy
    validation: ValidationPolicy
    allowed_path_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_alias(self.name, "repair profile name")
        _require_alias(self.review_profile, "repair review profile")
        if type(self.generation) is not RepairGenerationPolicy:
            raise ValueError("repair generation policy is invalid")
        if type(self.validation) is not ValidationPolicy:
            raise ValueError("repair validation policy is invalid")
        if type(self.allowed_path_prefixes) is not tuple or not self.allowed_path_prefixes:
            raise ValueError("allowed path prefixes are invalid")
        for prefix in self.allowed_path_prefixes:
            _require_repository_path(prefix, "allowed path prefix")
        _require_sorted_unique(self.allowed_path_prefixes, "allowed path prefixes")


@dataclass(frozen=True, slots=True)
class HostMCPWriters:
    """Explicit MCP registration switches for GitHub writers."""

    publish_check: bool
    publish_repair: bool

    def __post_init__(self) -> None:
        if type(self.publish_check) is not bool or type(self.publish_repair) is not bool:
            raise ValueError("MCP writer flags are invalid")


@dataclass(frozen=True, slots=True)
class HostPublisherRuntime:
    """Fixed self-hosted publisher source and Python runtime capability."""

    python_executable: Path
    runtime_root: Path
    package_root: Path
    source_root: Path

    def __post_init__(self) -> None:
        for name in (
            "python_executable",
            "runtime_root",
            "package_root",
            "source_root",
        ):
            _require_absolute_path(getattr(self, name), name)
        if not _is_within(self.python_executable, self.runtime_root):
            raise ValueError("publisher Python executable is outside runtime root")
        if self.package_root == self.runtime_root or not _is_within(
            self.package_root,
            self.runtime_root,
        ):
            raise ValueError("publisher package root is outside runtime root")
        if _paths_overlap(self.source_root, self.runtime_root):
            raise ValueError("publisher source and runtime roots overlap")


@dataclass(frozen=True, slots=True)
class HostGitHubActions:
    """Pinned GitHub Action identity and optional publisher runtime."""

    action_repository: str
    action_sha: str
    publisher: HostPublisherRuntime | None

    def __post_init__(self) -> None:
        if (
            type(self.action_repository) is not str
            or _GITHUB_NAME_PATTERN.fullmatch(self.action_repository) is None
            or ".." in self.action_repository
        ):
            raise ValueError("GitHub Action repository is invalid")
        if type(self.action_sha) is not str or _GIT_SHA_PATTERN.fullmatch(self.action_sha) is None:
            raise ValueError("GitHub Action SHA is invalid")
        if self.publisher is not None and type(self.publisher) is not HostPublisherRuntime:
            raise ValueError("GitHub Action publisher is invalid")


@dataclass(frozen=True, slots=True)
class HostProfile:
    """Schema-1 host capabilities selected by all product interfaces."""

    schema_version: int
    repositories: tuple[HostRepository, ...]
    git_executable: Path
    docker_executable: Path
    rootless_socket: Path
    product_state_root: Path
    repair_state_root: Path
    runner_labels: tuple[str, ...]
    m4_caches: tuple[M4CacheProfile, ...]
    review_profiles: tuple[ProductReviewProfile, ...]
    repair_profiles: tuple[ProductRepairProfile, ...]
    github_actions: HostGitHubActions | None
    mcp: HostMCPWriters

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        _require_typed_tuple(self.repositories, HostRepository, "repositories", minimum=1)
        if type(self.runner_labels) is not tuple:
            raise ValueError("runner labels are invalid")
        if self.runner_labels:
            if len(self.runner_labels) < 4:
                raise ValueError("runner labels are invalid")
            for label in self.runner_labels:
                _require_alias(label, "runner label")
            _require_sorted_unique(self.runner_labels, "runner labels")
            if len({label.casefold() for label in self.runner_labels}) != len(self.runner_labels):
                raise ValueError("runner labels must be unique")
            if not _REQUIRED_RUNNER_LABELS.issubset(self.runner_labels):
                raise ValueError("runner labels are invalid")
        if self.github_actions is not None and type(self.github_actions) is not HostGitHubActions:
            raise ValueError("GitHub Actions profile is invalid")
        publisher = None if self.github_actions is None else self.github_actions.publisher
        if bool(self.runner_labels) != (publisher is not None):
            raise ValueError("runner labels and publisher runtime must be declared together")
        _require_typed_tuple(self.m4_caches, M4CacheProfile, "M4 caches")
        _require_typed_tuple(
            self.review_profiles,
            ProductReviewProfile,
            "review profiles",
            minimum=1,
        )
        _require_typed_tuple(self.repair_profiles, ProductRepairProfile, "repair profiles")
        for name in (
            "git_executable",
            "docker_executable",
            "rootless_socket",
            "product_state_root",
            "repair_state_root",
        ):
            _require_absolute_path(getattr(self, name), name)
        if type(self.mcp) is not HostMCPWriters:
            raise ValueError("MCP writer profile is invalid")
        _require_named_order(self.repositories, "alias", "repositories")
        if len({repository.github_repository_id for repository in self.repositories}) != len(
            self.repositories
        ):
            raise ValueError("repository GitHub IDs must be unique")
        if len({repository.github_full_name.casefold() for repository in self.repositories}) != len(
            self.repositories
        ):
            raise ValueError("repository GitHub names must be unique")
        for index, first in enumerate(self.repositories):
            for second in self.repositories[index + 1 :]:
                if _paths_overlap(first.path, second.path):
                    raise ValueError("repository paths overlap")
        _require_named_order(self.m4_caches, "name", "M4 caches")
        _require_named_order(self.review_profiles, "name", "review profiles")
        _require_named_order(self.repair_profiles, "name", "repair profiles")
        cache_names = {cache.name for cache in self.m4_caches}
        review_names = {review.name for review in self.review_profiles}
        for review in self.review_profiles:
            if review.cache is not None and review.cache not in cache_names:
                raise ValueError("review profile cache is invalid")
        for repair in self.repair_profiles:
            if repair.review_profile not in review_names:
                raise ValueError("repair profile review policy is invalid")

    def repository(self, alias: str) -> HostRepository:
        """Resolve one exact repository alias without accepting a path."""
        _require_alias(alias, "repository alias")
        for repository in self.repositories:
            if repository.alias == alias:
                return repository
        raise ValueError("repository alias is unknown")

    def review_profile(self, name: str) -> ProductReviewProfile:
        """Resolve one exact named review profile."""
        _require_alias(name, "review profile name")
        for profile in self.review_profiles:
            if profile.name == name:
                return profile
        raise ValueError("review profile is unknown")

    def repair_profile(self, name: str) -> ProductRepairProfile:
        """Resolve one exact named repair profile."""
        _require_alias(name, "repair profile name")
        for profile in self.repair_profiles:
            if profile.name == name:
                return profile
        raise ValueError("repair profile is unknown")


def load_host_profile(path: Path) -> HostProfile:
    """Load and validate one canonical owner-only profile without following links."""
    try:
        _require_absolute_path(path, "profile path")
        raw = _read_owner_only_file(path)
        decoded = parse_canonical_json(raw, max_bytes=HOST_PROFILE_MAX_BYTES)
        if type(decoded) is not dict:
            raise ValueError("host profile must be an object")
        profile = _profile_from_mapping(decoded)
        _validate_host_capabilities(profile, profile_path=path)
        return profile
    except (KeyError, OSError, TypeError, ValueError):
        raise ValueError("host profile is invalid") from None


def host_profile_to_dict(profile: HostProfile) -> dict[str, object]:
    """Return the exact schema-1 host profile mapping."""
    if type(profile) is not HostProfile:
        raise TypeError("profile must be an exact HostProfile")
    return {
        "schema_version": profile.schema_version,
        "repositories": [
            {
                "alias": repository.alias,
                "path": str(repository.path),
                "github_repository_id": repository.github_repository_id,
                "github_full_name": repository.github_full_name,
            }
            for repository in profile.repositories
        ],
        "git_executable": str(profile.git_executable),
        "docker_executable": str(profile.docker_executable),
        "rootless_socket": str(profile.rootless_socket),
        "product_state_root": str(profile.product_state_root),
        "repair_state_root": str(profile.repair_state_root),
        "runner_labels": list(profile.runner_labels),
        "m4_caches": [
            {"name": cache.name, "path": str(cache.path), "device": cache.device.value}
            for cache in profile.m4_caches
        ],
        "review_profiles": [
            {
                "name": review.name,
                "mode": review.mode.value,
                "provider": review.provider.value,
                "model": review.model,
                "cache": review.cache,
                "device": review.device.value,
                "fail_on": review.fail_on.value,
            }
            for review in profile.review_profiles
        ],
        "repair_profiles": [
            {
                "name": repair.name,
                "review_profile": repair.review_profile,
                "generation": repair_generation_policy_to_dict(repair.generation),
                "validation": validation_policy_to_dict(repair.validation),
                "allowed_path_prefixes": list(repair.allowed_path_prefixes),
            }
            for repair in profile.repair_profiles
        ],
        "github_actions": (
            None
            if profile.github_actions is None
            else {
                "action_repository": profile.github_actions.action_repository,
                "action_sha": profile.github_actions.action_sha,
                "publisher": (
                    None
                    if profile.github_actions.publisher is None
                    else {
                        "python_executable": str(
                            profile.github_actions.publisher.python_executable
                        ),
                        "runtime_root": str(profile.github_actions.publisher.runtime_root),
                        "package_root": str(profile.github_actions.publisher.package_root),
                        "source_root": str(profile.github_actions.publisher.source_root),
                    }
                ),
            }
        ),
        "mcp": {
            "publish_check": profile.mcp.publish_check,
            "publish_repair": profile.mcp.publish_repair,
        },
    }


def host_profile_to_json(profile: HostProfile) -> str:
    """Serialize a host profile as canonical UTF-8 JSON without a newline."""
    return canonical_json_text(host_profile_to_dict(profile))


def _profile_from_mapping(mapping: dict[str, JSONValue]) -> HostProfile:
    require_exact_keys(
        mapping,
        (
            "schema_version",
            "repositories",
            "git_executable",
            "docker_executable",
            "rootless_socket",
            "product_state_root",
            "repair_state_root",
            "runner_labels",
            "m4_caches",
            "review_profiles",
            "repair_profiles",
            "github_actions",
            "mcp",
        ),
        name="host profile",
    )
    return HostProfile(
        schema_version=_as_int(mapping["schema_version"]),
        repositories=tuple(
            _repository_from_mapping(item) for item in _as_object_list(mapping["repositories"])
        ),
        git_executable=Path(_as_str(mapping["git_executable"])),
        docker_executable=Path(_as_str(mapping["docker_executable"])),
        rootless_socket=Path(_as_str(mapping["rootless_socket"])),
        product_state_root=Path(_as_str(mapping["product_state_root"])),
        repair_state_root=Path(_as_str(mapping["repair_state_root"])),
        runner_labels=tuple(_as_string_list(mapping["runner_labels"])),
        m4_caches=tuple(
            _cache_from_mapping(item) for item in _as_object_list(mapping["m4_caches"])
        ),
        review_profiles=tuple(
            _review_profile_from_mapping(item)
            for item in _as_object_list(mapping["review_profiles"])
        ),
        repair_profiles=tuple(
            _repair_profile_from_mapping(item)
            for item in _as_object_list(mapping["repair_profiles"])
        ),
        github_actions=_github_actions_from_value(mapping["github_actions"]),
        mcp=_mcp_from_mapping(_as_object(mapping["mcp"])),
    )


def _repository_from_mapping(mapping: dict[str, JSONValue]) -> HostRepository:
    require_exact_keys(
        mapping,
        ("alias", "path", "github_repository_id", "github_full_name"),
        name="host repository",
    )
    return HostRepository(
        alias=_as_str(mapping["alias"]),
        path=Path(_as_str(mapping["path"])),
        github_repository_id=_as_int(mapping["github_repository_id"]),
        github_full_name=_as_str(mapping["github_full_name"]),
    )


def _cache_from_mapping(mapping: dict[str, JSONValue]) -> M4CacheProfile:
    require_exact_keys(mapping, ("name", "path", "device"), name="M4 cache")
    return M4CacheProfile(
        name=_as_str(mapping["name"]),
        path=Path(_as_str(mapping["path"])),
        device=EmbeddingDevice(_as_str(mapping["device"])),
    )


def _review_profile_from_mapping(mapping: dict[str, JSONValue]) -> ProductReviewProfile:
    require_exact_keys(
        mapping,
        ("name", "mode", "provider", "model", "cache", "device", "fail_on"),
        name="review profile",
    )
    return ProductReviewProfile(
        name=_as_str(mapping["name"]),
        mode=ProductReviewMode(_as_str(mapping["mode"])),
        provider=ProductProviderKind(_as_str(mapping["provider"])),
        model=_as_optional_str(mapping["model"]),
        cache=_as_optional_str(mapping["cache"]),
        device=EmbeddingDevice(_as_str(mapping["device"])),
        fail_on=FindingSeverity(_as_str(mapping["fail_on"])),
    )


def _repair_profile_from_mapping(mapping: dict[str, JSONValue]) -> ProductRepairProfile:
    require_exact_keys(
        mapping,
        ("name", "review_profile", "generation", "validation", "allowed_path_prefixes"),
        name="repair profile",
    )
    prefixes = _as_string_list(mapping["allowed_path_prefixes"])
    return ProductRepairProfile(
        name=_as_str(mapping["name"]),
        review_profile=_as_str(mapping["review_profile"]),
        generation=_generation_from_mapping(_as_object(mapping["generation"])),
        validation=_validation_from_mapping(_as_object(mapping["validation"])),
        allowed_path_prefixes=tuple(prefixes),
    )


def _mcp_from_mapping(mapping: dict[str, JSONValue]) -> HostMCPWriters:
    require_exact_keys(mapping, ("publish_check", "publish_repair"), name="MCP writers")
    return HostMCPWriters(
        publish_check=_as_bool(mapping["publish_check"]),
        publish_repair=_as_bool(mapping["publish_repair"]),
    )


def _github_actions_from_value(value: JSONValue) -> HostGitHubActions | None:
    if value is None:
        return None
    mapping = _as_object(value)
    require_exact_keys(
        mapping,
        ("action_repository", "action_sha", "publisher"),
        name="GitHub Actions",
    )
    publisher_value = mapping["publisher"]
    publisher = (
        None
        if publisher_value is None
        else _publisher_runtime_from_mapping(_as_object(publisher_value))
    )
    return HostGitHubActions(
        action_repository=_as_str(mapping["action_repository"]),
        action_sha=_as_str(mapping["action_sha"]),
        publisher=publisher,
    )


def _publisher_runtime_from_mapping(
    mapping: dict[str, JSONValue],
) -> HostPublisherRuntime:
    require_exact_keys(
        mapping,
        ("python_executable", "runtime_root", "package_root", "source_root"),
        name="publisher runtime",
    )
    return HostPublisherRuntime(
        python_executable=Path(_as_str(mapping["python_executable"])),
        runtime_root=Path(_as_str(mapping["runtime_root"])),
        package_root=Path(_as_str(mapping["package_root"])),
        source_root=Path(_as_str(mapping["source_root"])),
    )


def _generation_from_mapping(mapping: dict[str, JSONValue]) -> RepairGenerationPolicy:
    require_exact_keys(
        mapping,
        (
            "mode",
            "provider_kind",
            "model",
            "max_file_bytes",
            "max_prompt_bytes",
            "max_response_bytes",
            "max_output_tokens",
            "max_queries",
            "max_query_bytes",
            "max_context_hits",
            "max_patch_bytes",
            "max_patch_paths",
            "max_changed_lines",
            "attempt_timeout_seconds",
            "total_timeout_seconds",
        ),
        name="repair generation policy",
    )
    provider_value = _as_optional_str(mapping["provider_kind"])
    return RepairGenerationPolicy(
        mode=RepairGenerationMode(_as_str(mapping["mode"])),
        provider_kind=None if provider_value is None else RepairProviderKind(provider_value),
        model=_as_optional_str(mapping["model"]),
        max_file_bytes=_as_int(mapping["max_file_bytes"]),
        max_prompt_bytes=_as_int(mapping["max_prompt_bytes"]),
        max_response_bytes=_as_int(mapping["max_response_bytes"]),
        max_output_tokens=_as_int(mapping["max_output_tokens"]),
        max_queries=_as_int(mapping["max_queries"]),
        max_query_bytes=_as_int(mapping["max_query_bytes"]),
        max_context_hits=_as_int(mapping["max_context_hits"]),
        max_patch_bytes=_as_int(mapping["max_patch_bytes"]),
        max_patch_paths=_as_int(mapping["max_patch_paths"]),
        max_changed_lines=_as_int(mapping["max_changed_lines"]),
        attempt_timeout_seconds=_as_float(mapping["attempt_timeout_seconds"]),
        total_timeout_seconds=_as_float(mapping["total_timeout_seconds"]),
    )


def _validation_from_mapping(mapping: dict[str, JSONValue]) -> ValidationPolicy:
    fields = (
        "image_id",
        "commands",
        "command_timeout_seconds",
        "total_timeout_seconds",
        "memory_bytes",
        "nano_cpus",
        "pids_limit",
        "stream_output_bytes",
        "workspace_bytes",
        "workspace_inodes",
        "workspace_entries",
        "tmp_bytes",
        "tmp_inodes",
        "home_bytes",
        "home_inodes",
        "run_bytes",
        "run_inodes",
    )
    require_exact_keys(mapping, fields, name="validation policy")
    commands = tuple(
        _validation_command_from_mapping(item) for item in _as_object_list(mapping["commands"])
    )
    return ValidationPolicy(
        image_id=_as_str(mapping["image_id"]),
        commands=commands,
        command_timeout_seconds=_as_int(mapping["command_timeout_seconds"]),
        total_timeout_seconds=_as_int(mapping["total_timeout_seconds"]),
        memory_bytes=_as_int(mapping["memory_bytes"]),
        nano_cpus=_as_int(mapping["nano_cpus"]),
        pids_limit=_as_int(mapping["pids_limit"]),
        stream_output_bytes=_as_int(mapping["stream_output_bytes"]),
        workspace_bytes=_as_int(mapping["workspace_bytes"]),
        workspace_inodes=_as_int(mapping["workspace_inodes"]),
        workspace_entries=_as_int(mapping["workspace_entries"]),
        tmp_bytes=_as_int(mapping["tmp_bytes"]),
        tmp_inodes=_as_int(mapping["tmp_inodes"]),
        home_bytes=_as_int(mapping["home_bytes"]),
        home_inodes=_as_int(mapping["home_inodes"]),
        run_bytes=_as_int(mapping["run_bytes"]),
        run_inodes=_as_int(mapping["run_inodes"]),
    )


def _validation_command_from_mapping(mapping: dict[str, JSONValue]) -> ValidationCommand:
    require_exact_keys(mapping, ("argv", "cwd"), name="validation command")
    return ValidationCommand(
        argv=tuple(_as_string_list(mapping["argv"])),
        cwd=_as_str(mapping["cwd"]),
    )


def _validate_host_capabilities(profile: HostProfile, *, profile_path: Path) -> None:
    _require_regular_executable(profile.git_executable, "git executable")
    _require_regular_executable(profile.docker_executable, "docker executable")
    _require_owned_socket(profile.rootless_socket)
    _require_owned_directory(profile.product_state_root, "product state root", mode=0o700)
    _require_owned_directory(profile.repair_state_root, "repair state root", mode=0o700)
    if _paths_overlap(profile.product_state_root, profile.repair_state_root):
        raise ValueError("state roots overlap")
    for cache in profile.m4_caches:
        _require_owned_directory(cache.path, "M4 cache", mode=0o700)
    mutable_roots = (
        profile.product_state_root,
        profile.repair_state_root,
        *(cache.path for cache in profile.m4_caches),
    )
    for index, first in enumerate(mutable_roots):
        for second in mutable_roots[index + 1 :]:
            if _paths_overlap(first, second):
                raise ValueError("mutable host capabilities overlap")
    publisher = None if profile.github_actions is None else profile.github_actions.publisher
    publisher_roots: tuple[Path, ...] = ()
    if publisher is not None:
        _require_regular_executable(
            publisher.python_executable,
            "publisher Python executable",
        )
        _require_protected_directory(publisher.runtime_root, "publisher runtime root")
        _require_protected_directory(publisher.package_root, "publisher package root")
        _require_protected_tree(publisher.package_root, "publisher package root")
        _require_protected_directory(publisher.source_root, "publisher source root")
        _require_protected_regular_file(
            publisher.source_root / "scripts" / "m6_action.py",
            "publisher Action driver",
        )
        publisher_roots = (publisher.runtime_root, publisher.package_root, publisher.source_root)
        for root in publisher_roots:
            for mutable_root in mutable_roots:
                if _paths_overlap(root, mutable_root):
                    raise ValueError("publisher and mutable host capabilities overlap")
    for repository in profile.repositories:
        _require_existing_directory(repository.path, "repository path")
        if _is_within(profile_path, repository.path):
            raise ValueError("profile is inside a reviewed repository")
        git_common_directory = _git_common_directory(
            repository.path,
            git_executable=profile.git_executable,
        )
        for protected in (
            profile.git_executable,
            profile.docker_executable,
            profile.rootless_socket,
            *mutable_roots,
            *publisher_roots,
        ):
            if _paths_overlap(protected, repository.path) or (
                git_common_directory is not None and _paths_overlap(protected, git_common_directory)
            ):
                raise ValueError("host capability overlaps a reviewed repository")


def _git_common_directory(
    repository: Path,
    *,
    git_executable: Path,
) -> Path | None:
    try:
        marker = os.stat(repository / ".git", follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not (stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode)):
        raise ValueError("repository Git metadata is invalid")
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            (
                str(git_executable),
                "-C",
                str(repository),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            cwd="/",
            env=environment,
            close_fds=True,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("repository Git metadata is invalid") from None
    raw = completed.stdout
    if (
        completed.returncode != 0
        or not 2 <= len(raw) <= _MAX_GIT_PATH_BYTES + 1
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or len(completed.stderr) > _MAX_GIT_PATH_BYTES
    ):
        raise ValueError("repository Git metadata is invalid")
    try:
        rendered = raw[:-1].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("repository Git metadata is invalid") from None
    _require_text(rendered, "Git common directory", max_bytes=_MAX_GIT_PATH_BYTES)
    common_directory = Path(rendered)
    _require_absolute_path(common_directory, "Git common directory")
    try:
        resolved = common_directory.resolve(strict=True)
        value = resolved.stat()
    except OSError:
        raise ValueError("repository Git metadata is invalid") from None
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError("repository Git metadata is invalid")
    return resolved


def _read_owner_only_file(path: Path) -> bytes:
    parent_fd: int | None = None
    descriptor: int | None = None
    repeated_parent_fd: int | None = None
    repeated_descriptor: int | None = None
    try:
        parent_fd, name = _open_trusted_parent(path)
        descriptor = _open_named_file(parent_fd, name)
        opened = os.fstat(descriptor)
        _require_profile_metadata(opened)
        opened_identity = _metadata_identity(opened)
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ValueError("profile file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("profile file exceeds its bound")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if _metadata_identity(after) != opened_identity:
            raise ValueError("profile file changed during read")
        repeated_parent_fd, repeated_name = _open_trusted_parent(path)
        repeated_descriptor = _open_named_file(repeated_parent_fd, repeated_name)
        repeated = os.fstat(repeated_descriptor)
        _require_profile_metadata(repeated)
        if _metadata_identity(repeated) != opened_identity:
            raise ValueError("profile file identity changed")
        return raw
    finally:
        for opened_fd in (
            repeated_descriptor,
            repeated_parent_fd,
            descriptor,
            parent_fd,
        ):
            if opened_fd is not None:
                os.close(opened_fd)


def _require_regular_executable(path: Path, name: str) -> None:
    descriptor = _open_absolute_file(path)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_uid not in {0, os.geteuid()}
            or value.st_mode & 0o111 == 0
            or value.st_mode & 0o022 != 0
        ):
            raise ValueError(f"{name} capability is invalid")
    finally:
        os.close(descriptor)


def _require_owned_socket(path: Path) -> None:
    value = _stat_absolute_path(path)
    if not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 1:
        raise ValueError("rootless socket capability is invalid")


def _require_existing_directory(path: Path, name: str) -> None:
    descriptor = _open_absolute_directory(path, protected=False)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{name} capability is invalid")
    finally:
        os.close(descriptor)


def _require_owned_directory(path: Path, name: str, *, mode: int) -> None:
    descriptor = _open_absolute_directory(path)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != mode
        ):
            raise ValueError(f"{name} capability is invalid")
    finally:
        os.close(descriptor)


def _require_protected_directory(path: Path, name: str) -> None:
    descriptor = _open_absolute_directory(path)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700
        ):
            raise ValueError(f"{name} capability is invalid")
    finally:
        os.close(descriptor)


def _require_protected_regular_file(path: Path, name: str) -> None:
    descriptor = _open_absolute_file(path)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_uid != os.geteuid()
            or value.st_mode & 0o022 != 0
        ):
            raise ValueError(f"{name} capability is invalid")
    finally:
        os.close(descriptor)


def _require_protected_tree(path: Path, name: str) -> None:
    descriptor = _open_absolute_directory(path)
    entries = [0]
    try:
        _validate_tree_directory(descriptor, name, entries=entries, depth=0)
    finally:
        os.close(descriptor)


def _validate_tree_directory(
    descriptor: int,
    name: str,
    *,
    entries: list[int],
    depth: int,
) -> None:
    if depth > _MAX_PACKAGE_TREE_DEPTH:
        raise ValueError(f"{name} capability is invalid")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022 != 0
    ):
        raise ValueError(f"{name} capability is invalid")
    for entry in os.listdir(descriptor):
        try:
            encoded = entry.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(f"{name} capability is invalid") from None
        if (
            not encoded
            or len(encoded) > 255
            or entry in {".", ".."}
            or "/" in entry
            or "\x00" in entry
        ):
            raise ValueError(f"{name} capability is invalid")
        entries[0] += 1
        if entries[0] > _MAX_PACKAGE_TREE_ENTRIES:
            raise ValueError(f"{name} capability is invalid")
        value = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(value.st_mode):
            child = os.open(entry, _directory_open_flags(), dir_fd=descriptor)
            try:
                if _metadata_namespace_identity(os.fstat(child)) != (
                    _metadata_namespace_identity(value)
                ):
                    raise ValueError(f"{name} capability is invalid")
                _validate_tree_directory(
                    child,
                    name,
                    entries=entries,
                    depth=depth + 1,
                )
                current = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
                if _metadata_namespace_identity(current) != _metadata_namespace_identity(value):
                    raise ValueError(f"{name} capability is invalid")
            finally:
                os.close(child)
        elif stat.S_ISREG(value.st_mode):
            child = os.open(entry, _file_open_flags(), dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    _metadata_namespace_identity(opened) != _metadata_namespace_identity(value)
                    or opened.st_uid not in {0, os.geteuid()}
                    or opened.st_nlink != 1
                    or opened.st_mode & 0o022 != 0
                ):
                    raise ValueError(f"{name} capability is invalid")
            finally:
                os.close(child)
        else:
            raise ValueError(f"{name} capability is invalid")


def _open_absolute_file(path: Path) -> int:
    parent_fd, name = _open_trusted_parent(path)
    try:
        descriptor = _open_named_file(parent_fd, name)
    finally:
        os.close(parent_fd)
    return descriptor


def _open_absolute_directory(path: Path, *, protected: bool = True) -> int:
    parent_fd, name = _open_trusted_parent(path)
    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        if protected:
            _require_trusted_directory_metadata(os.fstat(descriptor))
    except BaseException:
        os.close(parent_fd)
        raise
    os.close(parent_fd)
    return descriptor


def _stat_absolute_path(path: Path) -> os.stat_result:
    parent_fd, name = _open_trusted_parent(path)
    try:
        first = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    repeated_parent_fd, repeated_name = _open_trusted_parent(path)
    try:
        repeated = os.stat(repeated_name, dir_fd=repeated_parent_fd, follow_symlinks=False)
    finally:
        os.close(repeated_parent_fd)
    if _metadata_identity(first) != _metadata_identity(repeated):
        raise ValueError("host capability identity changed")
    return first


def _open_trusted_parent(path: Path) -> tuple[int, str]:
    if not path.is_absolute() or len(path.parts) < 2 or path.name in {"", ".", ".."}:
        raise ValueError("host path is invalid")
    descriptor = os.open("/", _directory_open_flags())
    try:
        _require_trusted_directory_metadata(os.fstat(descriptor), allow_root_sticky=True)
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise ValueError("host path is invalid")
            opened = os.open(
                component,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            try:
                _require_trusted_directory_metadata(
                    os.fstat(opened),
                    allow_root_sticky=True,
                )
            except BaseException:
                os.close(opened)
                raise
            os.close(descriptor)
            descriptor = opened
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def _require_trusted_directory_metadata(
    metadata: os.stat_result,
    *,
    allow_root_sticky: bool = False,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError("host path ancestor is invalid")
    if metadata.st_mode & 0o022 and not (
        allow_root_sticky
        and metadata.st_uid == 0
        and metadata.st_mode & stat.S_ISVTX
        and metadata.st_mode & 0o002
    ):
        raise ValueError("host path ancestor is writable")


def _open_named_file(parent_fd: int, name: str) -> int:
    return os.open(name, _file_open_flags(), dir_fd=parent_fd)


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


def _file_open_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _require_profile_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= HOST_PROFILE_MAX_BYTES
    ):
        raise ValueError("profile file capability is invalid")


def _metadata_namespace_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_metadata_namespace_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_absolute_path(path: object, name: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{name} must be an absolute pathlib.Path")
    rendered = str(path)
    _require_text(rendered, name, max_bytes=4_096)
    if Path(os.path.normpath(rendered)) != path:
        raise ValueError(f"{name} is not normalized")


def _paths_overlap(first: Path, second: Path) -> bool:
    return _is_within(first, second) or _is_within(second, first)


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_named_order(values: tuple[object, ...], field: str, name: str) -> None:
    names = tuple(cast(str, getattr(value, field)) for value in values)
    _require_sorted_unique(names, name)


def _require_sorted_unique(values: tuple[str, ...], name: str) -> None:
    if tuple(sorted(values, key=lambda value: value.encode("utf-8"))) != values:
        raise ValueError(f"{name} must be sorted")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")


def _require_typed_tuple(
    values: object,
    expected: type[object],
    name: str,
    *,
    minimum: int = 0,
) -> None:
    if type(values) is not tuple or len(values) < minimum:
        raise ValueError(f"{name} are invalid")
    if any(type(value) is not expected for value in values):
        raise ValueError(f"{name} are invalid")


def _require_alias(value: object, name: str) -> None:
    if type(value) is not str or _ALIAS_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _require_text(value: object, name: str, *, max_bytes: int) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{name} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} is invalid") from error
    if len(encoded) > max_bytes or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} is invalid")


def _require_repository_path(value: object, name: str) -> None:
    _require_text(value, name, max_bytes=1_024)
    rendered = cast(str, value)
    if rendered.startswith("/") or rendered.endswith("/") or "\\" in rendered:
        raise ValueError(f"{name} is invalid")
    parts = rendered.split("/")
    if any(
        not part
        or part in (".", "..")
        or part.casefold() == ".git"
        or len(part.encode("utf-8")) > 255
        for part in parts
    ):
        raise ValueError(f"{name} is invalid")


def _as_object(value: JSONValue) -> dict[str, JSONValue]:
    if type(value) is not dict:
        raise ValueError("profile value must be an object")
    return value


def _as_object_list(value: JSONValue) -> list[dict[str, JSONValue]]:
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise ValueError("profile value must be an object array")
    return cast(list[dict[str, JSONValue]], value)


def _as_string_list(value: JSONValue) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError("profile value must be a string array")
    return cast(list[str], value)


def _as_str(value: JSONValue) -> str:
    if type(value) is not str:
        raise ValueError("profile value must be a string")
    return value


def _as_optional_str(value: JSONValue) -> str | None:
    if value is None:
        return None
    return _as_str(value)


def _as_int(value: JSONValue) -> int:
    if type(value) is not int:
        raise ValueError("profile value must be an integer")
    return value


def _as_float(value: JSONValue) -> float:
    if type(value) is not float:
        raise ValueError("profile value must be a float")
    return value


def _as_bool(value: JSONValue) -> bool:
    if type(value) is not bool:
        raise ValueError("profile value must be a boolean")
    return value
