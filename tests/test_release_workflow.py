"""Invariants of .github/workflows/release.yml (plan 8.3.2, design §11.5).

Pinned here so a later edit that widens the release path fails CI: the trigger, per-job
permissions, the `release` environment around everything that can publish, the verify gate,
SHA-pinned actions and no expressions in shell."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SIGNERS = ROOT / ".github" / "allowed_signers"

# Permissions that can publish or sign, and so need the protected environment.
PUBLISHING = {"id-token", "packages", "attestations"}


def _load() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text())
    # PyYAML reads the bare key `on` as True.
    data["on"] = data.pop(True, data.get("on"))
    return data


@pytest.fixture(scope="module")
def wf() -> dict[str, Any]:
    return _load()


@pytest.fixture(scope="module")
def jobs(wf: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return wf["jobs"]


def _steps(jobs: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    return [(name, step) for name, job in jobs.items() for step in job.get("steps", [])]


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def test_runs_only_on_v_tags(wf: dict[str, Any]) -> None:
    assert wf["on"] == {"push": {"tags": ["v*"]}}


def test_no_default_permissions(wf: dict[str, Any]) -> None:
    assert wf["permissions"] == {}


def test_every_job_states_its_permissions(jobs: dict[str, dict[str, Any]]) -> None:
    for name, job in jobs.items():
        assert isinstance(job.get("permissions"), dict), name
        assert all(v in ("read", "write") for v in job["permissions"].values()), name


def test_publishing_permissions_only_in_release_environment(
    jobs: dict[str, dict[str, Any]],
) -> None:
    for name, job in jobs.items():
        writes = {k for k, v in job["permissions"].items() if v == "write"}
        if writes & PUBLISHING:
            assert job.get("environment") == "release", name


def test_contents_write_only_for_the_github_release(jobs: dict[str, dict[str, Any]]) -> None:
    writers = [n for n, j in jobs.items() if j["permissions"].get("contents") == "write"]
    assert writers == ["github-release"]


def test_every_job_waits_for_verify(jobs: dict[str, dict[str, Any]]) -> None:
    def reaches(name: str) -> bool:
        return any(n == "verify" or reaches(n) for n in _needs(jobs[name]))

    for name in jobs:
        if name != "verify":
            assert reaches(name), name


def test_publish_happens_after_image_tests(jobs: dict[str, dict[str, Any]]) -> None:
    assert "image-test" in _needs(jobs["pypi"])
    assert {"image-test", "pypi"} <= set(_needs(jobs["github-release"]))


def test_actions_pinned_by_sha(jobs: dict[str, dict[str, Any]]) -> None:
    for name, step in _steps(jobs):
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), (name, step)


def test_no_expressions_in_shell(jobs: dict[str, dict[str, Any]]) -> None:
    """Values reach `run:` through `env:` only, so none is spliced into a script."""
    for name, step in _steps(jobs):
        if "run" in step:
            assert "${{" not in step["run"], (name, step.get("name"))


def test_no_secrets_but_the_job_token(jobs: dict[str, dict[str, Any]]) -> None:
    text = WORKFLOW.read_text()
    assert set(re.findall(r"secrets\.(\w+)", text)) <= {"GITHUB_TOKEN"}
    for name, job in jobs.items():
        assert "secrets" not in job, name


def test_checkouts_drop_credentials(jobs: dict[str, dict[str, Any]]) -> None:
    for name, step in _steps(jobs):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, name


def test_verify_runs_the_script(jobs: dict[str, dict[str, Any]]) -> None:
    runs = " ".join(s.get("run", "") for s in jobs["verify"]["steps"])
    assert "python3 -I scripts/release-verify.py" in runs
    assert "--fetch" in runs
    assert '--sha "$GITHUB_SHA"' in runs


def test_build_jobs_check_out_the_tagged_commit(jobs: dict[str, dict[str, Any]]) -> None:
    for name, step in _steps(jobs):
        if step.get("uses", "").startswith("actions/checkout@") and name != "verify":
            assert step["with"].get("ref") == "${{ github.sha }}", name


def test_allowed_signers_file() -> None:
    lines = [ln for ln in SIGNERS.read_text().splitlines() if ln and not ln.startswith("#")]
    assert lines
    for line in lines:
        principal, options, keytype, key = line.split(" ", 3)
        assert principal.endswith("@users.noreply.github.com")
        assert options == 'namespaces="git"'
        assert keytype == "ssh-ed25519"
        assert re.fullmatch(r"[A-Za-z0-9+/]+=*", key)
