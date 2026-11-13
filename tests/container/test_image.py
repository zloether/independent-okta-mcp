"""Container image checks (plan 7.1, design §11.2, §11.4), run against a built image:

    docker build -t okta-mcp:test .
    OKTA_MCP_IMAGE=okta-mcp:test uv run pytest tests/container

Skipped when `OKTA_MCP_IMAGE` is unset, so the default `uv run pytest` needs no Docker. CI's
`container` job sets it.
"""

import json
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

IMAGE = os.environ.get("OKTA_MCP_IMAGE", "")
POLICY = Path(__file__).parents[2] / "docker" / "policy.example.yaml"
UID = "10001"

pytestmark = pytest.mark.skipif(
    not IMAGE, reason="set OKTA_MCP_IMAGE to a built image to run container tests"
)
"""Only the variable decides: with it set and no docker, every test fails rather than skips."""

HARDENED = [
    "--read-only",
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
]
"""How compose runs it (plan 7.2), plus no network at all: startup must not need the issuer
or the org (§11.3)."""

ENV = {
    "MCP_PUBLIC_URL": "https://mcp.example.com/mcp",
    "MCP_ISSUER": "https://example.okta.com/oauth2/aus1example000000000",
    "MCP_ALLOWED_CLIENT_IDS": "0oa1client0000000000",
    "MCP_POLICY_FILE": "/run/secrets/policy.yaml",
    "MCP_CURSOR_KEY_FILE": "/run/secrets/cursor_key",
    "OKTA_ORG_URL": "https://example.okta.com",
    "OKTA_CLIENT_ID": "0oa1service000000000",
    "OKTA_PRIVATE_KEY_FILE": "/run/secrets/okta.pem",
    "OKTA_SCOPES": "okta.users.read okta.groups.read",
}

FETCH = """
import sys, urllib.error, urllib.request
req = urllib.request.Request("http://127.0.0.1:8080" + sys.argv[1], method=sys.argv[2])
try:
    r = urllib.request.urlopen(req, timeout=2)
except urllib.error.HTTPError as e:
    r = e
print(r.status, r.headers.get("Retry-After") or "-")
"""
"""Run inside the container (`--network=none` leaves nothing reachable from outside)."""

SCAN = r"""
import json, os, re, stat
PEM = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40}")
OURS = ("/app", "/app/.venv/lib/python3.12/site-packages/okta_mcp")
found = {"secrets": [], "setid": [], "dirs": []}
for root, dirs, files in os.walk("/", onerror=lambda e: None):
    if root in ("/proc", "/sys", "/dev"):
        dirs[:] = []
        continue
    for d in dirs:
        if root in OURS and d in ("tests", "docs", ".git", ".claude", "src", "scripts", "spikes"):
            found["dirs"].append(os.path.join(root, d))
    for f in files:
        p = os.path.join(root, f)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            found["setid"].append(p)
        if st.st_size > 1 << 20 or not os.access(p, os.R_OK):
            continue
        with open(p, "rb") as fh:
            if PEM.search(fh.read()):
                found["secrets"].append(p)
print(json.dumps(found))
"""
"""Walks the image as the server's user: what it can read is what a compromise could. A key is
a PEM header followed by a body (`cryptography` holds the bare header as a constant); the
repo's own trees are looked for at the top of `/app` and in the installed package, since
third-party packages may ship their own `tests/`."""


def _docker(
    *args: str, check: bool = True, timeout: float = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def _python(*code: str, extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
    return _docker("run", "--rm", *HARDENED, *extra, "--entrypoint", "python", IMAGE, "-c", *code)


def _inspect() -> dict[str, Any]:
    return json.loads(_docker("image", "inspect", IMAGE).stdout)[0]["Config"]


def test_runs_as_non_root_in_production_mode() -> None:
    config = _inspect()
    assert config["User"] == f"{UID}:{UID}"
    env = dict(e.split("=", 1) for e in config["Env"])
    assert env["MCP_ENV"] == "production"
    assert env["MCP_HOST"] == "0.0.0.0"  # noqa: S104 (the image binds all interfaces, §11.3)
    assert env["MCP_PORT"] == "8080"
    assert config["Entrypoint"] == ["okta-mcp"]
    assert config["Healthcheck"]["Test"][0] == "CMD"
    ids = _docker("run", "--rm", *HARDENED, "--entrypoint", "id", IMAGE).stdout
    assert ids.startswith(f"uid={UID}(mcp) gid={UID}(mcp) ")


def test_image_holds_no_keys_sources_or_setid_files() -> None:
    found = json.loads(_python(SCAN).stdout)
    assert found == {"secrets": [], "setid": [], "dirs": []}
    assert _docker("run", "--rm", "--entrypoint", "ls", IMAGE, "-A", "/app").stdout.split() == [
        ".venv"
    ]


def test_package_is_installed_not_editable_and_ships_its_data() -> None:
    code = (
        "import okta_mcp, pathlib; p = pathlib.Path(okta_mcp.__file__).parent; "
        "print(p); print(sorted(x.name for x in (p / 'data').iterdir()))"
    )
    where, data = _python(code).stdout.splitlines()
    assert where == "/app/.venv/lib/python3.12/site-packages/okta_mcp"
    assert data == "['registry', 'resources', 'scrub.yaml', 'specs']"


def test_no_pip_and_nothing_writable() -> None:
    pip = _docker("run", "--rm", "--entrypoint", "python", IMAGE, "-m", "pip", check=False)
    assert pip.returncode != 0
    assert "No module named pip" in pip.stderr
    # Without --read-only too: the server's user can't change the installed code.
    touch = _docker(
        "run", "--rm", "--entrypoint", "touch", IMAGE, "/app/.venv/bin/okta-mcp", check=False
    )
    assert touch.returncode != 0


def test_version_and_startup_failure() -> None:
    assert (
        _docker("run", "--rm", *HARDENED, IMAGE, "--version").stdout.strip().startswith("okta-mcp ")
    )
    bad = _docker("run", "--rm", *HARDENED, IMAGE, check=False)
    assert bad.returncode == 2
    assert "okta-mcp: cannot start" in bad.stderr
    assert "MCP_POLICY_FILE: required" in bad.stderr


@pytest.fixture
def secrets(tmp_path: Path) -> list[str]:
    """Bind mounts for the policy, a throwaway service key and a cursor key, readable by the
    image's user (files only; the mount points are created by Docker)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    files = {
        "policy.yaml": POLICY.read_bytes(),
        "okta.pem": pem,
        "cursor_key": b"Y3Vyc29yLWtleS1mb3ItY29udGFpbmVyLXRlc3RzLW9ubHkh\n",
    }
    mounts: list[str] = []
    for name, content in files.items():
        path = tmp_path / name
        path.write_bytes(content)
        path.chmod(0o644)
        mounts.append(f"--mount=type=bind,src={path},dst=/run/secrets/{name},readonly")
    return mounts


@pytest.fixture
def server(secrets: list[str]) -> Iterator[str]:
    env = [f"--env={k}={v}" for k, v in ENV.items()]
    cid = _docker("run", "--detach", *HARDENED, *secrets, *env, IMAGE).stdout.strip()
    try:
        yield cid
    finally:
        _docker("rm", "--force", cid, check=False)


def test_production_image_refuses_dev_mode_and_ssws(secrets: list[str]) -> None:
    env = [f"--env={k}={v}" for k, v in ENV.items()]
    dev = _docker(
        "run", "--rm", *HARDENED, *secrets, *env, "--env=MCP_DEV_MODE=1",
        "--env=MCP_DEV_PRINCIPAL_FILE=/run/secrets/policy.yaml", "--env=OKTA_API_TOKEN=x",
        IMAGE, "--stdio", check=False,
    )  # fmt: skip
    assert dev.returncode == 2
    assert "MCP_DEV_MODE: refused when MCP_ENV=production" in dev.stderr
    assert "OKTA_API_TOKEN: refused when MCP_ENV=production" in dev.stderr


def _fetch(cid: str, path: str, method: str = "GET") -> str:
    out = _docker("exec", cid, "python", "-c", FETCH, path, method, check=False)
    return out.stdout.strip() if out.returncode == 0 else f"error: {out.stderr.strip()[-200:]}"


def _wait(predicate: Any, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.5)
    return False


def test_serves_health_on_a_read_only_fs_with_no_network(server: str) -> None:
    assert _wait(lambda: _fetch(server, "/healthz") == "200 -", 30), _docker("logs", server).stderr
    # No route to the issuer: not ready, and /mcp is 503 with Retry-After (§11.3), not 401.
    assert _fetch(server, "/readyz") == "503 -"
    status, retry = _fetch(server, "/mcp", "POST").split()
    assert status == "503"
    assert retry != "-"

    def healthy() -> bool:
        state = _docker("inspect", "--format", "{{.State.Health.Status}}", server).stdout
        return state.strip() == "healthy"

    assert _wait(healthy, 30)


def test_stops_promptly_on_sigterm(server: str) -> None:
    assert _wait(lambda: _fetch(server, "/healthz") == "200 -", 30)
    start = time.monotonic()
    _docker("stop", "--time=10", server)
    assert time.monotonic() - start < 8  # exited on SIGTERM, not killed at the timeout
    state = json.loads(_docker("inspect", "--format", "{{json .State}}", server).stdout)
    assert state["ExitCode"] == 0
    logs = _docker("logs", server)
    assert "Traceback" not in logs.stdout + logs.stderr
