"""docker/compose.example.yaml brought up as written, with the image under test (plan 7.2).

`tests/test_compose_example.py` checks the file statically; this checks that Docker accepts it
and that the running container gets what it asks for. The only change to the example is an
override that swaps in `OKTA_MCP_IMAGE` and sets an egress proxy that doesn't exist, so
nothing leaves the runner (the placeholder org and issuer are real-looking hostnames).
Skipped when `OKTA_MCP_IMAGE` is unset, like the image tests.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

IMAGE = os.environ.get("OKTA_MCP_IMAGE", "")
DOCKER = Path(__file__).parents[2] / "docker"
PROJECT = "okta-mcp-compose-test"
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")

pytestmark = pytest.mark.skipif(
    not IMAGE, reason="set OKTA_MCP_IMAGE to a built image to run container tests"
)


def _compose(
    project_dir: Path, *args: str, check: bool = True, timeout: float = 90
) -> subprocess.CompletedProcess[str]:
    files = ["-f", str(DOCKER / "compose.example.yaml"), "-f", str(project_dir / "override.yaml")]
    return subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            PROJECT,
            *files,
            "--project-directory",
            str(project_dir),
            *args,
        ],
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def _get(path: str) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        return opener.open(f"http://127.0.0.1:8080{path}", timeout=2).status
    except urllib.error.HTTPError as e:
        return e.code


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The files the example expects next to it (policy, secrets), readable by uid 10001 as its
    header says, and the test override."""
    d = tmp_path_factory.mktemp("compose")
    (d / "secrets").mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    files = {
        "policy.yaml": (DOCKER / "policy.example.yaml").read_bytes(),
        "secrets/okta_private_key.pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "secrets/cursor_key": b"Y3Vyc29yLWtleS1mb3ItY29udGFpbmVyLXRlc3RzLW9ubHkh\n",
    }
    for name, content in files.items():
        (d / name).write_bytes(content)
        (d / name).chmod(0o444)
    env = "".join(f"      {v}: http://proxy.example.com:3128\n" for v in PROXY_VARS)
    (d / "override.yaml").write_text(
        f"services:\n  okta-mcp:\n    image: {IMAGE}\n    environment:\n{env}"
    )
    return d


@pytest.fixture(scope="module")
def stack(project: Path) -> Iterator[dict[str, Any]]:
    """`up --wait`: the image's HEALTHCHECK must report healthy."""
    d = project
    up = _compose(d, "up", "--detach", "--no-build", "--wait", "--wait-timeout", "45", check=False)
    try:
        cid = _compose(d, "ps", "--quiet", "okta-mcp").stdout.strip()
        assert up.returncode == 0, up.stderr + _compose(d, "logs", check=False).stdout
        yield json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]
    finally:
        _compose(d, "down", "--volumes", check=False)


def test_runs_with_the_hardening_it_asks_for(stack: dict[str, Any]) -> None:
    host = stack["HostConfig"]
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert not host.get("CapAdd")
    assert host["Privileged"] is False
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert stack["Config"]["User"] == "10001:10001"
    assert stack["State"]["Health"]["Status"] == "healthy"


def test_every_mount_is_read_only(stack: dict[str, Any]) -> None:
    mounts = {m["Destination"]: m for m in stack["Mounts"]}
    assert set(mounts) == {
        "/etc/okta-mcp/policy.yaml",
        "/run/secrets/cursor_key",
        "/run/secrets/okta_private_key",
    }
    for m in mounts.values():
        assert m["RW"] is False, m


def test_port_published_on_loopback_only(stack: dict[str, Any]) -> None:
    bindings = stack["HostConfig"]["PortBindings"]
    assert bindings == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}


def test_serves_health_through_the_published_port(stack: dict[str, Any]) -> None:
    deadline = time.monotonic() + 10
    while _get("/healthz") != 200 and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _get("/healthz") == 200
    # The placeholder issuer is behind a proxy that doesn't exist: not ready (§11.3).
    assert _get("/readyz") == 503


def _check(project: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    """`okta-mcp --check` the way the runbook runs it (§4.2): a one-off container of the same
    service, so the same variables, mounts and user, with no published port."""
    return _compose(
        project, "run", "--rm", "--pull", "never", *extra, "okta-mcp", "--check", check=False
    )


def _candidate(project: Path, text: str) -> tuple[str, ...]:
    """The runbook's candidate-policy mount: beside the live one, picked by MCP_POLICY_FILE."""
    path = project / "policy.new.yaml"
    path.write_text(text)
    path.chmod(0o444)
    return (
        "--volume",
        f"{path}:/etc/okta-mcp/policy.new.yaml:ro",
        "--env",
        "MCP_POLICY_FILE=/etc/okta-mcp/policy.new.yaml",
    )


def test_check_passes_with_the_example(project: Path) -> None:
    result = _check(project)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0] == "okta-mcp: check passed"


def test_check_fails_a_bad_candidate_policy(project: Path) -> None:
    result = _check(project, *_candidate(project, "version: 2\nroles: {}\n"))
    assert result.returncode == 2
    lines = result.stderr.splitlines()
    assert "okta-mcp: check failed" in lines
    assert any(line.strip().startswith("policy.new.yaml: ") for line in lines)


def test_check_passes_a_good_candidate_policy(project: Path) -> None:
    good = (DOCKER / "policy.example.yaml").read_text()
    result = _check(project, *_candidate(project, good))
    assert result.returncode == 0, result.stderr
