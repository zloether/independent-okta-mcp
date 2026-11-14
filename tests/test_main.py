"""The `okta-mcp` entrypoint (plan 4.1, design §8.6): which transport starts, and when it
refuses to."""

import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client, StdioServerParameters

from okta_mcp import __main__ as entry
from okta_mcp.__main__ import (
    CANNOT_START,
    CHECK_FAILED,
    CHECK_PASSED,
    HTTP_REFUSES_DEV_MODE,
    STARTUP_FAILED,
    STDIO_NEEDS_DEV_MODE,
    main,
)
from okta_mcp.audit import OTHERS_CAN_ACCESS, probe_sink
from okta_mcp.config import Config

PILOT = Path(__file__).parent / "policy" / "fixtures" / "pilot.yaml"
READERS = "00g1readers000000000"


def env(tmp_path: Path, *, dev: bool = True, **extra: str) -> dict[str, str]:
    principal = tmp_path / "principal.yaml"
    principal.write_text(f"uid: 00u1devuser000000000\nsub: dev@example.com\ngroups: [{READERS}]\n")
    values = {
        "MCP_POLICY_FILE": str(PILOT),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": "https://example.okta.com",
        "OKTA_SCOPES": "okta.groups.read",
    }
    if dev:
        values |= {
            "MCP_DEV_MODE": "1",
            "MCP_DEV_PRINCIPAL_FILE": str(principal),
            "OKTA_API_TOKEN": "test-ssws-token",
        }
    else:
        key = tmp_path / "key.pem"
        key.write_text("not read before the transport starts")
        values |= {
            "MCP_PUBLIC_URL": "https://mcp.example.com/mcp",
            "MCP_ISSUER": "https://example.okta.com/oauth2/aus1example0000000000",
            "MCP_ALLOWED_CLIENT_IDS": "0oa1client0000000000",
            "OKTA_CLIENT_ID": "0oa1service000000000",
            "OKTA_PRIVATE_KEY_FILE": str(key),
        }
    return values | extra


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in list(os.environ):
        if name.startswith(("MCP_", "OKTA_")):
            monkeypatch.delenv(name)
    # `main` would replace the root handlers pytest captures with.
    monkeypatch.setattr(entry, "configure_logging", lambda level: None)
    return monkeypatch


def set_env(monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> None:
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def failed(capsys: pytest.CaptureFixture[str], code: int, header: str = CANNOT_START) -> list[str]:
    assert code == STARTUP_FAILED
    out, err = capsys.readouterr()
    assert out == ""
    first, *rest = err.splitlines()
    assert first == header
    return [line.strip() for line in rest]


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    from okta_mcp import __version__

    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"okta-mcp {__version__}"


def test_config_errors_listed(capsys: pytest.CaptureFixture[str]) -> None:
    errors = failed(capsys, main([]))
    assert "MCP_POLICY_FILE: required" in errors
    assert "OKTA_ORG_URL: required" in errors


def test_http_refuses_dev_mode(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(clean_env, env(tmp_path))
    assert failed(capsys, main([])) == [HTTP_REFUSES_DEV_MODE]


def test_http_refuses_dev_mode_even_without_ssws(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    values = env(tmp_path, dev=False)
    values |= {"MCP_DEV_MODE": "true", "MCP_DEV_PRINCIPAL_FILE": str(tmp_path / "principal.yaml")}
    set_env(clean_env, values)
    assert failed(capsys, main([])) == [HTTP_REFUSES_DEV_MODE]


def test_http_serves_without_dev_mode(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    served: list[Config] = []

    async def serve(config: Config) -> None:
        served.append(config)

    clean_env.setattr(entry, "serve_http", serve)
    set_env(clean_env, env(tmp_path, dev=False))
    assert main([]) == 0
    (config,) = served
    assert not config.dev_mode


def test_http_startup_errors_are_listed(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real `serve_http`: the unreadable key fails before the port opens, as exit 2."""
    set_env(clean_env, env(tmp_path, dev=False))
    (line,) = failed(capsys, main([]))
    assert line.startswith("OKTA_PRIVATE_KEY_FILE:")


def test_stdio_needs_dev_mode(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(clean_env, env(tmp_path, dev=False))
    assert failed(capsys, main(["--stdio"])) == [STDIO_NEEDS_DEV_MODE]


def test_stdio_dev_mode_off_explicitly(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(clean_env, env(tmp_path, dev=False, MCP_DEV_MODE="0"))
    assert failed(capsys, main(["--stdio"])) == [STDIO_NEEDS_DEV_MODE]


def test_stdio_refused_in_production(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(clean_env, env(tmp_path, MCP_ENV="production"))
    errors = failed(capsys, main(["--stdio"]))
    assert "MCP_DEV_MODE: refused when MCP_ENV=production" in errors
    assert "OKTA_API_TOKEN: refused when MCP_ENV=production" in errors


def test_stdio_bad_principal_file(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(clean_env, env(tmp_path))
    (tmp_path / "principal.yaml").write_text("uid: someone\nsub: dev@example.com\ngroups: []\n")
    assert failed(capsys, main(["--stdio"])) == [
        "MCP_DEV_PRINCIPAL_FILE: principal.yaml: uid must be an Okta user ID "
        "(00u + 17 letters or digits)"
    ]


def test_stdio_bad_policy(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 2\nroles: {}\n")
    set_env(clean_env, env(tmp_path, MCP_POLICY_FILE=str(policy)))
    errors = failed(capsys, main(["--stdio"]))
    assert errors
    assert all(e.startswith("policy.yaml: ") for e in errors)


def test_stdio_ssws_token_never_printed(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 2\nroles: {}\n")
    set_env(clean_env, env(tmp_path, MCP_POLICY_FILE=str(policy)))
    main(["--stdio"])
    out, err = capsys.readouterr()
    assert "test-ssws-token" not in out + err


@pytest.mark.anyio
async def test_stdio_serves_the_dev_principal(tmp_path: Path) -> None:
    """The real console path: a subprocess on stdin/stdout. Nothing here calls Okta."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "okta_mcp", "--stdio"],
        env={"PATH": os.environ.get("PATH", ""), **env(tmp_path)},
        cwd=str(tmp_path),
    )
    async with Client(params) as client:
        tools = await client.list_tools()
        status = await client.call_tool("okta_status", {})
        resources = await client.list_resources()
    assert [t.name for t in tools.tools] == ["okta_groups", "okta_help", "okta_status"]
    assert status.structured_content["user"] == "dev@example.com"
    assert status.structured_content["roles"] == ["directory-reader"]
    assert "okta://guide/groups" in [r.uri for r in resources.resources]


# --- --check ------------------------------------------------------------------------------

WARNS = (
    "version: 1\nroles:\n  r:\n    groups: ['00g1readers000000000']\n"
    "    allow: {groups: ['*']}\n    include_sensitive: ['*']\n"
)


def write_key(path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def http_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    values = env(tmp_path, dev=False, **extra)
    write_key(Path(values["OKTA_PRIVATE_KEY_FILE"]))
    return values


@pytest.fixture
def no_serving(clean_env: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """`--check` must never reach a transport."""

    async def refuse(config: Config) -> None:
        raise AssertionError("--check served")

    clean_env.setattr(entry, "serve_http", refuse)
    clean_env.setattr(entry, "serve_stdio", refuse)
    return clean_env


def passed(capsys: pytest.CaptureFixture[str], code: int) -> list[str]:
    assert code == 0
    out, err = capsys.readouterr()
    assert err == ""
    first, *rest = out.splitlines()
    assert first == CHECK_PASSED
    return [line.strip() for line in rest]


def test_check_http_passes(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(no_serving, http_env(tmp_path))
    assert passed(capsys, main(["--check"])) == []


def test_check_prints_policy_warnings(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Warnings go to stdout once, not also to the log; they don't fail the check."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(WARNS)
    set_env(no_serving, http_env(tmp_path, MCP_POLICY_FILE=str(policy)))
    lines = passed(capsys, main(["--check"]))
    assert lines
    assert all(line.startswith("warning: policy: ") for line in lines)
    assert any("include_sensitive" in line for line in lines)


def test_check_bad_key(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The key is read, as serving reads it; this one isn't a PEM key."""
    set_env(no_serving, env(tmp_path, dev=False))
    (line,) = failed(capsys, main(["--check"]), CHECK_FAILED)
    assert line.startswith("OKTA_PRIVATE_KEY_FILE:")


def test_check_bad_policy(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 2\nroles: {}\n")
    set_env(no_serving, http_env(tmp_path, MCP_POLICY_FILE=str(policy)))
    errors = failed(capsys, main(["--check"]), CHECK_FAILED)
    assert errors
    assert all(e.startswith("policy.yaml: ") for e in errors)


def test_check_config_errors(
    no_serving: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert failed(capsys, main(["--check"]), CHECK_FAILED)


def test_check_http_refuses_dev_mode(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Checked for the transport that would serve: HTTP refuses dev mode, so does its check."""
    set_env(no_serving, env(tmp_path))
    assert failed(capsys, main(["--check"]), CHECK_FAILED) == [HTTP_REFUSES_DEV_MODE]


def test_check_stdio_needs_dev_mode(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(no_serving, http_env(tmp_path))
    assert failed(capsys, main(["--check", "--stdio"]), CHECK_FAILED) == [STDIO_NEEDS_DEV_MODE]


def test_check_stdio_passes(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(no_serving, env(tmp_path))
    assert main(["--check", "--stdio"]) == 0
    out, err = capsys.readouterr()
    assert "test-ssws-token" not in out + err
    assert out.splitlines() == [CHECK_PASSED]


def test_check_stdio_bad_principal_file(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_env(no_serving, env(tmp_path))
    (tmp_path / "principal.yaml").write_text("uid: someone\nsub: dev@example.com\ngroups: []\n")
    (line,) = failed(capsys, main(["--check", "--stdio"]), CHECK_FAILED)
    assert line.startswith("MCP_DEV_PRINCIPAL_FILE:")


def test_check_does_not_create_the_audit_file(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit = tmp_path / "audit.jsonl"
    set_env(no_serving, http_env(tmp_path, MCP_AUDIT_LOG=str(audit)))
    passed(capsys, main(["--check"]))
    assert not audit.exists()


def test_check_leaves_an_existing_audit_file_alone(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("earlier\n")
    audit.chmod(0o600)
    set_env(no_serving, http_env(tmp_path, MCP_AUDIT_LOG=str(audit)))
    assert passed(capsys, main(["--check"])) == []
    assert audit.read_text() == "earlier\n"


def test_check_warns_of_an_audit_file_others_can_read(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The warning startup would log, printed by the check instead."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text("")
    audit.chmod(0o644)
    set_env(no_serving, http_env(tmp_path, MCP_AUDIT_LOG=str(audit)))
    assert passed(capsys, main(["--check"])) == [f"warning: {OTHERS_CAN_ACCESS}"]


def test_check_audit_error_matches_startup(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory the server can't open: the check and startup give the same line."""
    set_env(clean_env, http_env(tmp_path, MCP_AUDIT_LOG=str(tmp_path)))
    checked = failed(capsys, main(["--check"]), CHECK_FAILED)
    started = failed(capsys, main([]))
    assert checked == started == ["MCP_AUDIT_LOG: cannot open the file (IsADirectoryError)"]


def test_check_audit_file_in_a_missing_directory(
    no_serving: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit = tmp_path / "missing" / "audit.jsonl"
    set_env(no_serving, http_env(tmp_path, MCP_AUDIT_LOG=str(audit)))
    assert failed(capsys, main(["--check"]), CHECK_FAILED) == [
        "MCP_AUDIT_LOG: cannot open the file (FileNotFoundError)"
    ]
    assert not audit.parent.exists()


@pytest.mark.parametrize("target", ["stdout", "stderr"])
def test_probe_sink_streams(target: str) -> None:
    assert probe_sink(target) is None


def test_probe_sink(tmp_path: Path) -> None:
    new = tmp_path / "new.jsonl"
    assert probe_sink(str(new)) is None
    assert not new.exists()
    with pytest.raises(IsADirectoryError):
        probe_sink(str(tmp_path))
    with pytest.raises(FileNotFoundError):
        probe_sink(str(tmp_path / "no" / "new.jsonl"))


def test_probe_sink_refuses_a_dangling_symlink(tmp_path: Path) -> None:
    link = tmp_path / "audit.jsonl"
    link.symlink_to(tmp_path / "elsewhere.jsonl")
    with pytest.raises(FileNotFoundError):
        probe_sink(str(link))
    assert not (tmp_path / "elsewhere.jsonl").exists()


def test_probe_sink_fifo_without_reader_does_not_block(tmp_path: Path) -> None:
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        probe_sink(str(fifo))


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anything")
def test_probe_sink_unwritable(tmp_path: Path) -> None:
    existing = tmp_path / "audit.jsonl"
    existing.write_text("")
    existing.chmod(0o400)
    with pytest.raises(PermissionError):
        probe_sink(str(existing))
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        with pytest.raises(PermissionError):
            probe_sink(str(locked / "new.jsonl"))
    finally:
        locked.chmod(0o700)
