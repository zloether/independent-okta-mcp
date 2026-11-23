"""The Dockerfile's `BASE_IMAGE` argument and build inputs (design §11.2), read statically: no
Docker needed.

The build-time check is the Dockerfile's own `RUN` command, run here with `sh`, so a change to it
is tested as written. CI's `container` job also builds with the argument.
"""

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

DOCKERFILE = (Path(__file__).parents[2] / "Dockerfile").read_text()
FROM = re.findall(r"^FROM (\S+)(?: AS (\S+))?$", DOCKERFILE, re.MULTILINE)
DIGEST = "sha256:" + "0" * 64


def _check() -> str:
    """The build stage's first `RUN`, continuation lines joined."""
    build = DOCKERFILE.split("FROM ${BASE_IMAGE} AS build\n", 1)[1]
    match = re.search(r"^RUN ((?:.*\\\n)*.*)$", build, re.MULTILINE)
    assert match is not None
    return match.group(1).replace("\\\n", "")


def test_both_python_stages_use_the_one_argument() -> None:
    assert re.search(r"^ARG BASE_IMAGE=python-base$", DOCKERFILE, re.MULTILINE)
    stages = {name: image for image, name in FROM}
    # The default stage is the pinned upstream image; build and runtime both come from the arg,
    # so they can't diverge (the venv's interpreter is a symlink into the base).
    assert re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", stages["python-base"])
    assert stages["build"] == "${BASE_IMAGE}"
    assert FROM[-1] == ("${BASE_IMAGE}", "")
    assert [image for image, _ in FROM].count("${BASE_IMAGE}") == 2


def test_the_check_runs_first_in_the_build_stage() -> None:
    build = DOCKERFILE.split("FROM ${BASE_IMAGE} AS build\n", 1)[1]
    lines = build.splitlines()
    assert lines[0] == "ARG BASE_IMAGE"
    first_run = next(line for line in lines if line.startswith("RUN "))
    assert "BASE_IMAGE" in first_run


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("python-base", True),
        (f"python:3.12-slim@{DIGEST}", True),
        (f"registry.example.com:5000/team/python:3.12@{DIGEST}", True),
        (f"registry.example.com/python@{DIGEST}", True),
        ("python:3.12-slim", False),
        ("registry.example.com/python:latest", False),
        ("uv", False),  # the other stage
        ("python-base-x", False),
        (f"python@{DIGEST[:-1]}", False),  # 63 hex
        (f"python@{DIGEST.upper()}", False),
        (f"python@{DIGEST} extra", False),
        (f"@{DIGEST}", False),
        ("", False),
        # grep -x matches per line: a second, valid line must not carry the value
        (f"python:3.12-slim\nx@{DIGEST}", False),
        (f"x@{DIGEST}\n", False),
        ("python-base\tx", False),
    ],
)
def test_build_check_accepts_only_the_default_or_a_digest(value: str, accepted: bool) -> None:
    sh = shutil.which("sh")
    assert sh is not None
    run = subprocess.run(
        [sh, "-c", _check()],
        env={"BASE_IMAGE": value, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (run.returncode == 0) is accepted
    assert ("must be pinned by digest" in run.stderr) is not accepted


def test_license_files_reach_the_project_build() -> None:
    # `uv sync` builds the project, and uv_build fails if a `license-files` entry is missing
    # (pyproject.toml): each must be in the build context and copied before that sync.
    root = Path(__file__).parents[2]
    files = tomllib.loads((root / "pyproject.toml").read_text())["project"]["license-files"]
    allowed = (root / ".dockerignore").read_text().splitlines()
    build = DOCKERFILE.split("FROM ${BASE_IMAGE} AS build\n", 1)[1]
    before_sync = build.split("RUN uv sync --frozen --no-dev --no-editable", 1)[0]
    copied = {
        name
        for line in re.findall(r"^COPY (?!--)(.+) \./$", before_sync, re.MULTILINE)
        for name in line.split()
    }
    for name in files:
        assert f"!{name}" in allowed, name
        assert name in copied, name
