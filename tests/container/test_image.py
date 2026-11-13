"""Container image checks (plan 7.1, design §11.2, §11.4), run against a built image:

    docker build -t okta-mcp:test .
    OKTA_MCP_IMAGE=okta-mcp:test uv run pytest tests/container

Skipped when `OKTA_MCP_IMAGE` is unset, so the default `uv run pytest` needs no Docker. CI's
`container` job sets it.
"""

import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Iterator
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
    r = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2)
except urllib.error.HTTPError as e:
    r = e
print(r.status, r.headers.get("Retry-After") or "-")
"""
"""Run inside the container (`--network=none` leaves nothing reachable from outside). No proxy,
like the image's HEALTHCHECK."""

SCAN = r"""
import json, os, re, stat, sys
PEM = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n(?:[A-Za-z-]+: [^\n]*\n)*\r?\n?[A-Za-z0-9+/=]{40}"
)
JWK = re.compile(rb'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"')
KEY_EXTENSIONS = (".key", ".jwk", ".p12", ".pfx", ".der")
SCRATCH = ("/tmp", "/var/tmp", "/run/lock")
SITE = os.path.join(sys.prefix, "lib", "python%d.%d" % sys.version_info[:2], "site-packages")
OURS = ("/app", os.path.join(SITE, "okta_mcp"))
found = {"secrets": [], "setid": [], "dirs": [], "writable": []}
for root, dirs, files in os.walk("/", onerror=lambda e: None):
    if root in ("/proc", "/sys", "/dev"):
        dirs[:] = []
        continue
    in_app = root == "/app" or root.startswith("/app/")
    scratch = root in SCRATCH
    for d in dirs:
        if root in OURS and d in ("tests", "docs", ".git", ".claude", "src", "scripts", "spikes"):
            found["dirs"].append(os.path.join(root, d))
    if not scratch and os.access(root, os.W_OK):
        found["writable"].append(root)
    for f in files:
        p = os.path.join(root, f)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                found["setid"].append(p)
            if not scratch and os.access(p, os.W_OK):
                found["writable"].append(p)
            name = f.lower()
            if name.endswith(KEY_EXTENSIONS) or (in_app and name.endswith(".pem")):
                found["secrets"].append(p)
                continue
            if st.st_size > 1 << 20 or not os.access(p, os.R_OK):
                continue
            with open(p, "rb") as fh:
                body = fh.read()
        except OSError:
            continue
        if PEM.search(body) or (b'"kty"' in body and JWK.search(body)):
            found["secrets"].append(p)
print(json.dumps(found))
"""
"""Walks the image as the server's user: what it can read is what a compromise could, and
nothing it may write outside the sticky scratch directories (`/tmp`, `/var/tmp`, `/run/lock`):
not the code it imports, not `/etc` (a CA bundle it trusts), even without `--read-only`.

A key is: a file named like a private key anywhere (`.key .jwk .p12 .pfx .der`, since the
content patterns can't read PKCS#12, DER or every encrypted form); a `.pem` under `/app`
(elsewhere public certificates use that name); a PEM private-key header followed by a body
(optionally after `Proc-Type`/`DEK-Info` lines; `cryptography` holds the bare header as a
constant); or a JWK with a private `d`. The repo's own trees are looked for at the top of
`/app` and in the installed package, since third-party packages may ship their own `tests/`."""

PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")

ENV_ARGS = [f"--env={k}={v}" for k, v in ENV.items()]


def _docker(
    *args: str, check: bool = True, timeout: float = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def _python(*code: str, read_only: bool = True) -> subprocess.CompletedProcess[str]:
    flags = HARDENED if read_only else [f for f in HARDENED if f != "--read-only"]
    return _docker("run", "--rm", *flags, "--entrypoint", "python", IMAGE, "-c", *code)


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
    # Writable access is what the image grants, so not under --read-only: there every
    # access(W_OK) fails with EROFS and the check would pass whatever the ownership.
    found = json.loads(_python(SCAN, read_only=False).stdout)
    assert found == {"secrets": [], "setid": [], "dirs": [], "writable": []}
    assert _docker("run", "--rm", "--entrypoint", "ls", IMAGE, "-A", "/app").stdout.split() == [
        ".venv"
    ]


def test_package_is_installed_not_editable_and_ships_its_data() -> None:
    code = (
        "import okta_mcp, pathlib; p = pathlib.Path(okta_mcp.__file__).parent; "
        "print(p); print(sorted(x.name for x in (p / 'data').iterdir()))"
    )
    where, data = _python(code).stdout.splitlines()
    assert re.fullmatch(r"/app/\.venv/lib/python3\.\d+/site-packages/okta_mcp", where)
    assert data == "['registry', 'resources', 'scrub.yaml', 'specs']"


def test_no_pip() -> None:
    for module in ("pip", "ensurepip"):
        run = _docker("run", "--rm", "--entrypoint", "python", IMAGE, "-m", module, check=False)
        assert run.returncode != 0
        assert f"No module named {module}" in run.stderr


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
    """The server, with an egress proxy set as an operator would for the Okta calls: the
    HEALTHCHECK must not send its loopback probe there (the proxy host doesn't exist)."""
    proxy = [f"--env={name}=http://proxy.example.com:3128" for name in PROXY_VARS]
    args = ["run", "--detach", *HARDENED, *secrets, *ENV_ARGS, *proxy, IMAGE]
    cid = _docker(*args).stdout.strip()
    try:
        yield cid
    finally:
        _docker("rm", "--force", cid, check=False)


def test_production_image_refuses_dev_mode_and_ssws(secrets: list[str]) -> None:
    dev = _docker(
        "run", "--rm", *HARDENED, *secrets, *ENV_ARGS, "--env=MCP_DEV_MODE=1",
        "--env=MCP_DEV_PRINCIPAL_FILE=/run/secrets/policy.yaml", "--env=OKTA_API_TOKEN=x",
        IMAGE, "--stdio", check=False,
    )  # fmt: skip
    assert dev.returncode == 2
    assert "MCP_DEV_MODE: refused when MCP_ENV=production" in dev.stderr
    assert "OKTA_API_TOKEN: refused when MCP_ENV=production" in dev.stderr


def _fetch(cid: str, path: str, method: str = "GET") -> str:
    out = _docker("exec", cid, "python", "-c", FETCH, path, method, check=False)
    return out.stdout.strip() if out.returncode == 0 else f"error: {out.stderr.strip()[-200:]}"


def _wait(predicate: Callable[[], bool], timeout: float) -> bool:
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
