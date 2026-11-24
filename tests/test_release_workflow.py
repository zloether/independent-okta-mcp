"""Invariants of .github/workflows/release.yml (plans 8.3.2, 8.4.1; design §11.5).

Pinned here so a later edit that widens the release path fails CI: the trigger, per-job
permissions, the `release` environment around everything that can publish, the verify gate,
SHA-pinned actions and no expressions in shell; and that the image ships as one index of
`linux/amd64` and `linux/arm64`, each built and tested on its own native runner."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
SIGNERS = ROOT / ".github" / "allowed_signers"

# Permissions that can publish or sign, and so need the protected environment.
PUBLISHING = {"id-token", "packages", "attestations"}

# The image's platforms, each on a GitHub-hosted runner of that architecture (not QEMU).
PLATFORMS = {
    "linux/amd64": ("ubuntu-latest", "x86_64"),
    "linux/arm64": ("ubuntu-24.04-arm", "aarch64"),
}


def _load(path: Path = WORKFLOW) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
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


def test_image_pushed_only_once_everything_is_built(jobs: dict[str, dict[str, Any]]) -> None:
    """A pushed tag spends the version: nothing is pushed until the dists and both platforms
    are built."""
    assert {"build", "image-build"} <= set(_needs(jobs["image"]))


def test_layouts_outlive_the_approval_wait(jobs: dict[str, dict[str, Any]]) -> None:
    # `image` waits for a human; a short retention could expire the layouts before approval.
    (upload,) = _uses(jobs["image-build"], "actions/upload-artifact")
    assert "retention-days" not in upload["with"]


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


@pytest.mark.parametrize(
    "path", [WORKFLOW, ROOT / "docs" / "releasing.md", ROOT / "docs" / "runbook.md"]
)
def test_attestation_verify_pins_release_workflow_and_tag(path: Path) -> None:
    """`--repo` alone accepts an attestation from any workflow on any branch of the repo,
    and anyone with write access can run one (8.3.1 access review)."""
    text = path.read_text().replace("\\\n", " ")
    commands = re.findall(r"gh attestation verify [^\n`]+", text)
    assert commands, path
    repo = r"(\$GITHUB_REPOSITORY|\$REPO|zloether/independent-okta-mcp)"
    # $GITHUB_REF is the pushed tag only inside the workflow; on an operator's machine it is unset.
    ref = r"(refs/tags/v|\$GITHUB_REF\b)" if path == WORKFLOW else r"refs/tags/v"
    for cmd in commands:
        assert re.search(rf'--signer-workflow "?{repo}/\.github/workflows/release\.yml\b', cmd), cmd
        assert re.search(rf'--source-ref "?{ref}', cmd), cmd
        assert "--deny-self-hosted-runners" in cmd, cmd


def test_image_attestation_verified_while_logged_in(jobs: dict[str, dict[str, Any]]) -> None:
    """`gh attestation verify oci://` reads the image from GHCR with Docker's credentials, and
    a new package is private until the maintainer makes it public after the first run."""
    steps = jobs["image-test"]["steps"]

    def at(command: str) -> list[int]:
        return [i for i, s in enumerate(steps) if command in s.get("run", "")]

    login, verify, logout = (
        at("docker login ghcr.io"),
        at("gh attestation verify"),
        at("docker logout ghcr.io"),
    )
    assert len(login) == len(verify) == len(logout) == 1, (login, verify, logout)
    assert login[0] < verify[0] < logout[0]
    assert steps[logout[0]].get("if") == "always()"


def _matrix(job: dict[str, Any]) -> list[dict[str, str]]:
    return job["strategy"]["matrix"]["include"]


def _uses(job: dict[str, Any], action: str) -> list[dict[str, Any]]:
    return [s for s in job["steps"] if s.get("uses", "").startswith(f"{action}@")]


def _runs(job: dict[str, Any]) -> str:
    return "\n".join(s.get("run", "") for s in job["steps"])


def test_no_emulation(jobs: dict[str, dict[str, Any]]) -> None:
    """An emulated arm64 build isn't the runtime that ships (8.4.1): every platform builds on
    its own native runner."""
    text = WORKFLOW.read_text()
    assert "setup-qemu-action" not in text
    assert "binfmt" not in text


def test_image_built_per_platform_on_native_runners(jobs: dict[str, dict[str, Any]]) -> None:
    job = jobs["image-build"]
    legs = {leg["platform"]: leg["runner"] for leg in _matrix(job)}
    assert legs == {p: runner for p, (runner, _) in PLATFORMS.items()}
    assert job["runs-on"] == "${{ matrix.runner }}"
    (build,) = _uses(job, "docker/build-push-action")
    assert build["with"]["platforms"] == "${{ matrix.platform }}"
    # SBOM and BuildKit provenance per platform; `imagetools create` carries them into the index.
    assert build["with"]["sbom"] is True
    assert build["with"]["provenance"] == "mode=max"


def test_image_build_cannot_publish(jobs: dict[str, dict[str, Any]]) -> None:
    """Builds run before approval, so they get no write permission and push nothing: only the
    approved `image` job pushes."""
    job = jobs["image-build"]
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job
    (build,) = _uses(job, "docker/build-push-action")
    assert build["with"]["push"] is False
    assert build["with"]["outputs"].startswith("type=oci,")
    assert "docker login" not in _runs(job)
    (upload,) = _uses(job, "actions/upload-artifact")
    assert upload["with"]["name"] == "${{ matrix.artifact }}"
    assert {leg["artifact"] for leg in _matrix(job)} == {
        "image-" + p.replace("/", "-") for p in PLATFORMS
    }


def test_index_holds_both_platforms(jobs: dict[str, dict[str, Any]]) -> None:
    job = jobs["image"]
    assert "image-build" in _needs(job)
    assert job.get("environment") == "release"
    (download,) = _uses(job, "actions/download-artifact")
    assert download["with"]["pattern"] == "image-linux-*"
    run = _runs(job)
    # Each layout checked against its platform before the push, the index after it.
    per_layout = r'test "$got" = "[\"$platform\"]"'
    both = """test "$got" = '["linux/amd64","linux/arm64"]'"""
    assert "for platform in linux/amd64 linux/arm64; do" in run
    assert run.index(per_layout) < run.index("imagetools create") < run.index(both)
    assert run.index(both) < run.index('echo "digest=')


def test_attestation_covers_the_index_digest(jobs: dict[str, dict[str, Any]]) -> None:
    """The index digest (from `imagetools create`) is what's attested, what `image-test` pulls
    and what the release notes print."""
    job = jobs["image"]
    (push,) = [s for s in job["steps"] if s.get("id") == "push"]
    assert "imagetools create" in push["run"]
    assert '."containerimage.descriptor".digest' in push["run"]
    assert job["outputs"]["digest"] == "${{ steps.push.outputs.digest }}"
    (attest,) = _uses(job, "actions/attest-build-provenance")
    assert attest["with"]["subject-digest"] == "${{ steps.push.outputs.digest }}"
    assert attest["with"]["push-to-registry"] is True
    steps = job["steps"]
    assert steps.index(push) < steps.index(attest)
    digest_ref = "${{ needs.image.outputs.digest }}"
    assert digest_ref in jobs["image-test"]["env"]["IMAGE"]
    (notes,) = [s for s in jobs["github-release"]["steps"] if s.get("name") == "Create the release"]
    assert digest_ref in notes["env"]["IMAGE"]


def test_image_tested_natively_on_each_platform(jobs: dict[str, dict[str, Any]]) -> None:
    """An untested arm64 image doesn't ship: the same checks, `tests/container/` and Trivy on
    every leg, each checking that it runs its own architecture."""
    job = jobs["image-test"]
    legs = {leg["runner"]: leg["machine"] for leg in _matrix(job)}
    assert legs == dict(PLATFORMS.values())
    assert job["runs-on"] == "${{ matrix.runner }}"
    assert job["strategy"].get("fail-fast") is False
    run = _runs(job)
    assert 'docker pull "$IMAGE"' in run
    assert "platform.machine()" in run and '"$MACHINE"' in run
    assert "gh attestation verify" in run
    assert "uv run pytest tests/container" in run
    assert "aquasec/trivy" in run and "--exit-code 1" in run
    # Both legs must pass before anything is published to PyPI or the release is made.
    assert "image-test" in _needs(jobs["pypi"])


def test_ci_builds_and_tests_the_image_on_each_platform() -> None:
    job = _load(CI)["jobs"]["container"]
    legs = {leg["runner"]: leg["machine"] for leg in _matrix(job)}
    assert legs == dict(PLATFORMS.values())
    assert job["runs-on"] == "${{ matrix.runner }}"
    # The `main` ruleset requires `container`: the amd64 leg keeps that check name.
    assert job["name"] == "${{ matrix.name }}"
    names = {leg["runner"]: leg["name"] for leg in _matrix(job)}
    assert names["ubuntu-latest"] == "container"
    run = _runs(job)
    assert "docker build -t okta-mcp:ci ." in run
    assert "platform.machine()" in run
    assert "uv run pytest tests/container" in run
    assert "aquasec/trivy" in run


def test_allowed_signers_file() -> None:
    lines = [ln for ln in SIGNERS.read_text().splitlines() if ln and not ln.startswith("#")]
    assert lines
    for line in lines:
        principal, options, keytype, key = line.split(" ", 3)
        assert principal.endswith("@users.noreply.github.com")
        assert options == 'namespaces="git"'
        assert keytype == "ssh-ed25519"
        assert re.fullmatch(r"[A-Za-z0-9+/]+=*", key)
