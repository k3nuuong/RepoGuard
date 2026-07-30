"""Integration tests for the shared M6 product orchestrator."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from repoguard.github_publication import GitHubSourcePullRequest
from repoguard.host_profile import (
    HostMCPWriters,
    HostProfile,
    HostRepository,
    ProductProviderKind,
    ProductRepairProfile,
    ProductReviewMode,
    ProductReviewProfile,
)
from repoguard.product import (
    ProductErrorDomain,
    ProductExitCode,
    ProductOrchestrator,
    ProductStage,
    product_envelope_to_json,
    product_exit_code,
)
from repoguard.repair import (
    RepairGenerationMode,
    RepairGenerationPolicy,
    ValidationCommand,
    ValidationPolicy,
)
from repoguard.retrieval import EmbeddingDevice
from repoguard.review import FindingSeverity

_GIT = Path(shutil.which("git") or "/usr/bin/git").resolve()


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "HOME": str(root.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return (
        subprocess.run(
            (str(_GIT), "-C", str(root), *arguments),
            check=True,
            capture_output=True,
            env=environment,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=RepoGuard Tests",
        "-c",
        "user.email=repoguard@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir(mode=0o700)
    _git(root, "init", "-q", "-b", "main")
    source = root / "src" / "example.py"
    source.parent.mkdir()
    source.write_text("print('base')\n", encoding="utf-8")
    base_oid = _commit(root, "base")
    source.write_text("<<<<<<< HEAD\nprint('unsafe')\n=======\n>>>>>>> topic\n", encoding="utf-8")
    head_oid = _commit(root, "head")
    return root, base_oid, head_oid


def _profile(tmp_path: Path, repository: Path) -> HostProfile:
    product_state = tmp_path / "product-state"
    repair_state = tmp_path / "repair-state"
    product_state.mkdir(mode=0o700)
    repair_state.mkdir(mode=0o700)
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
        git_executable=_GIT,
        docker_executable=Path("/bin/true"),
        rootless_socket=tmp_path / "docker.sock",
        product_state_root=product_state,
        repair_state_root=repair_state,
        runner_labels=(),
        m4_caches=(),
        review_profiles=(
            ProductReviewProfile(
                name="agent",
                mode=ProductReviewMode.AGENT,
                provider=ProductProviderKind.OPENAI,
                model="gpt-test",
                cache=None,
                device=EmbeddingDevice.CPU,
                fail_on=FindingSeverity.HIGH,
            ),
            ProductReviewProfile(
                name="deterministic",
                mode=ProductReviewMode.DETERMINISTIC,
                provider=ProductProviderKind.NONE,
                model=None,
                cache=None,
                device=EmbeddingDevice.CPU,
                fail_on=FindingSeverity.MEDIUM,
            ),
        ),
        repair_profiles=(
            ProductRepairProfile(
                name="safe",
                review_profile="deterministic",
                generation=RepairGenerationPolicy(
                    mode=RepairGenerationMode.DETERMINISTIC,
                    provider_kind=None,
                    model=None,
                ),
                validation=ValidationPolicy(
                    image_id=(
                        "sha256:2b86e77e08a658d8a0438c75a19e66648de69fea4f27be6cb081d7369fcb0846"
                    ),
                    commands=(ValidationCommand(argv=("/usr/bin/true",)),),
                ),
                allowed_path_prefixes=("src",),
            ),
        ),
        github_actions=None,
        mcp=HostMCPWriters(publish_check=False, publish_repair=False),
    )


def _source_pull_request(
    *,
    base_oid: str,
    head_oid: str,
    same_repository: bool = True,
) -> GitHubSourcePullRequest:
    return GitHubSourcePullRequest(
        repository_id=123456,
        repository_full_name="owner/repository",
        repository_is_fork=False,
        pull_request_number=7,
        base_ref="main",
        base_oid=base_oid,
        head_oid=head_oid,
        base_repository_id=123456,
        base_repository_full_name="owner/repository",
        head_repository_id=123456 if same_repository else 654321,
        head_repository_full_name=(
            "owner/repository" if same_repository else "contributor/repository"
        ),
        same_repository=same_repository,
    )


def _fake_source_service(
    source: GitHubSourcePullRequest,
    *,
    expected_same_repository: bool,
) -> object:
    class Service:
        def read_source_pull_request(
            self,
            *,
            repository_id: int,
            repository_full_name: str,
            pull_request_number: int,
            require_same_repository: bool,
        ) -> GitHubSourcePullRequest:
            assert repository_id == 123456
            assert repository_full_name == "owner/repository"
            assert pull_request_number == 7
            assert require_same_repository is expected_same_repository
            return source

    return Service()


def test_deterministic_review_is_bounded_path_free_and_policy_aware(tmp_path: Path) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="deterministic",
    )

    assert envelope.ok
    assert envelope.result is not None
    assert envelope.result["repository_alias"] == "repository"
    assert envelope.result["base_oid"] == base_oid
    assert envelope.result["head_oid"] == head_oid
    assert envelope.result["finding_count"] == 1
    assert envelope.result["highest_severity"] == "medium"
    assert envelope.result["conclusion"] == "failure"
    assert envelope.result["policy_passed"] is False
    serialized = product_envelope_to_json(envelope)
    assert str(repository) not in serialized
    assert product_exit_code(envelope) is ProductExitCode.POLICY_OR_VALIDATION


def test_same_repository_review_records_exact_check_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    profile = _profile(tmp_path, repository)
    source = _source_pull_request(base_oid=base_oid, head_oid=head_oid)
    service = _fake_source_service(source, expected_same_repository=False)
    monkeypatch.setattr("repoguard._product._publication_service", lambda *_a, **_k: service)
    monkeypatch.setattr("repoguard._product._wall_clock_us", lambda: 1_800_000_000_000_000)
    orchestrator = ProductOrchestrator(profile)

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="deterministic",
        github_pr=7,
    )

    assert envelope.ok
    assert envelope.result is not None
    assert envelope.result["github_write_supported"] is True
    proposal = envelope.result["proposal"]
    assert isinstance(proposal, dict)
    assert proposal["proposal_sha256"] == envelope.result["proposal_sha256"]
    assert proposal["origin"] == "cli"
    assert proposal["base_ref"] == "main"
    status = orchestrator.github_publication_status(
        repository="repository",
        proposal_sha256=str(envelope.result["proposal_sha256"]),
    )
    assert status.ok
    assert status.result is not None
    assert status.result["state"] == "proposed"
    assert status.result["proposal"] == proposal
    assert str(repository) not in product_envelope_to_json(envelope)


def test_fork_review_is_read_only_and_has_no_publishable_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    source = _source_pull_request(
        base_oid=base_oid,
        head_oid=head_oid,
        same_repository=False,
    )
    service = _fake_source_service(source, expected_same_repository=False)
    monkeypatch.setattr("repoguard._product._publication_service", lambda *_a, **_k: service)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="deterministic",
        github_pr=7,
    )

    assert envelope.ok
    assert envelope.result is not None
    assert envelope.result["github_write_supported"] is False
    assert "proposal" not in envelope.result
    assert "proposal_sha256" not in envelope.result


def test_github_review_requires_only_explicit_github_token_before_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    monkeypatch.delenv("REPOGUARD_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        "repoguard._product.collect_evidence",
        lambda *_a, **_k: pytest.fail("evidence must not run before GitHub authentication"),
    )
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="deterministic",
        github_pr=7,
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.GITHUB
    assert envelope.error.code == "authentication_failed"
    assert envelope.error.stage is ProductStage.TRANSPORT
    assert product_exit_code(envelope) is ProductExitCode.AUTH_OR_APPROVAL


def test_github_source_oid_drift_is_a_stale_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    source = _source_pull_request(base_oid=base_oid, head_oid="f" * 40)
    service = _fake_source_service(source, expected_same_repository=False)
    monkeypatch.setattr("repoguard._product._publication_service", lambda *_a, **_k: service)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="deterministic",
        github_pr=7,
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.GITHUB
    assert envelope.error.code == "pull_request_stale"
    assert envelope.error.stage is ProductStage.PROPOSAL
    assert product_exit_code(envelope) is ProductExitCode.STALE_OR_CONFLICT


@pytest.mark.parametrize(
    ("repository_alias", "review_profile", "expected_code"),
    [
        ("unknown", "deterministic", "invalid_repository"),
        ("repository", "unknown", "invalid_review_profile"),
    ],
)
def test_unknown_profile_selection_is_a_stable_request_error(
    tmp_path: Path,
    repository_alias: str,
    review_profile: str,
    expected_code: str,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository=repository_alias,
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile=review_profile,
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.CLI
    assert envelope.error.code == expected_code
    assert envelope.error.stage is ProductStage.INPUT
    assert product_exit_code(envelope) is ProductExitCode.PROFILE_OR_REQUEST


def test_invalid_ref_is_detached_as_an_evidence_error(tmp_path: Path) -> None:
    repository, _base_oid, head_oid = _repository(tmp_path)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref="refs/heads/missing",
        head_ref=head_oid,
        review_profile="deterministic",
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.EVIDENCE
    assert envelope.error.code == "invalid_base_ref"
    assert envelope.error.stage is ProductStage.EVIDENCE
    assert str(repository) not in product_envelope_to_json(envelope)


def test_model_review_requires_only_the_named_product_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))
    monkeypatch.delenv("REPOGUARD_OPENAI_API_KEY", raising=False)

    envelope = orchestrator.review_run(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        review_profile="agent",
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.domain is ProductErrorDomain.PROVIDER
    assert envelope.error.code == "authentication_failed"
    assert envelope.error.stage is ProductStage.PROVIDER
    assert product_exit_code(envelope) is ProductExitCode.AUTH_OR_APPROVAL


@pytest.mark.parametrize(
    "allowed_path",
    [
        "/src/example.py",
        "src/../example.py",
        "src/",
        "src/" + ("x" * 1_025),
    ],
)
def test_repair_paths_fail_before_expensive_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allowed_path: str,
) -> None:
    repository, base_oid, head_oid = _repository(tmp_path)
    orchestrator = ProductOrchestrator(_profile(tmp_path, repository))

    def forbidden_collection(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("evidence must not run for an invalid product path")

    monkeypatch.setattr("repoguard._product.collect_evidence", forbidden_collection)

    envelope = orchestrator.repair_prepare(
        repository="repository",
        base_ref=base_oid,
        head_ref=head_oid,
        repair_profile="safe",
        target_ids=("a" * 64,),
        allowed_paths=(allowed_path,),
    )

    assert not envelope.ok
    assert envelope.error is not None
    assert envelope.error.code == "invalid_request"
    assert envelope.error.stage is ProductStage.INPUT
