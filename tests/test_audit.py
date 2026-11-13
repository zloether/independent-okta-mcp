"""The audit log (plan 6.1, design §12.3)."""

import io
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import Client

from okta_mcp.audit import (
    CUT,
    NAME_MAX,
    VALUE_MAX,
    AuditError,
    AuditLog,
    CallStats,
    collect,
    hash_key,
    open_sink,
    record_sent,
)
from okta_mcp.auth.principal import Principal
from okta_mcp.config import Config, ConfigError, load_config
from okta_mcp.exec.executor import Code, Failure, Success
from okta_mcp.exec.output import REDACTED, load_scrub
from okta_mcp.okta.client import new_http_client
from okta_mcp.policy.engine import Engine
from okta_mcp.policy.loader import load_policy
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec
from okta_mcp.server import build_runtime, mcp_server
from okta_mcp.tools import Text

PILOT = Path(__file__).parent / "policy" / "fixtures" / "pilot.yaml"
ORG = "https://example.okta.com"
READERS = "00g1readers000000000"
HELPDESK = "00g1helpdsk000000000"
NOBODY = "00g9nobody0000000000"
GROUP = "00g1emaKYZTWRYYRRTSK"
SECRET = "-".join(["okta", "group", "secret"])
"""A value only an Okta result holds: it must never reach the audit log."""
SSWS = "test-ssws-token"
CURSOR_KEY = "A" * 44


def caller(*groups: str) -> Principal:
    return Principal(
        uid="00u1devuser000000000",
        sub="dev@example.com",
        groups=frozenset(groups),
        client_id="0oa1client0000000000",
    )


@pytest.fixture(scope="module")
def loaded() -> tuple[SpecIndex, Registry]:
    spec = load_spec()
    return spec, load_registry(spec)


@pytest.fixture(autouse=True)
def load_once(loaded: tuple[SpecIndex, Registry], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("okta_mcp.server.load_spec", lambda: loaded[0])
    monkeypatch.setattr("okta_mcp.server.load_registry", lambda spec: loaded[1])


@pytest.fixture
def registry(loaded: tuple[SpecIndex, Registry]) -> Registry:
    return loaded[1]


@pytest.fixture
def engine(registry: Registry) -> Engine:
    policy = load_policy(PILOT, registry, load_scrub())
    return Engine(policy, registry, frozenset({"okta.groups.read", "okta.networkZones.read"}))


def audit(
    registry: Registry, engine: Engine, mode: str = "full", sink: Any = None
) -> tuple[AuditLog, io.StringIO]:
    out = sink if sink is not None else io.StringIO()
    log = AuditLog(
        out,
        registry=registry,
        engine=engine,
        args_mode=mode,  # pyright: ignore[reportArgumentType]
        key=hash_key(b"k" * 32),
        clock=iter([10.0, 10.25]).__next__,
        now=lambda: "2026-11-13T00:00:00.000Z",
    )
    return log, out


def line(
    log: AuditLog,
    out: io.StringIO,
    tool: object,
    arguments: object,
    outcome: object,
    principal: Principal | None = None,
    stats: CallStats | None = None,
) -> dict[str, Any]:
    log.record(
        request_id="r1",
        principal=principal or caller(READERS),
        tool=tool,
        arguments=arguments,
        outcome=outcome,
        started=log.start(),
        stats=stats or CallStats(),
    )
    (written,) = out.getvalue().splitlines()
    return json.loads(written)


LIST = '{"untrusted":true,"count":2,"items":[{"id":"a"},{"id":"b"}],"truncated":"max_items"}'


# --- fields ------------------------------------------------------------------------------


def test_call_fields(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    got = line(
        log,
        out,
        "okta_groups",
        {"command": "list", "args": {"q": "Staff"}, "select": "id", "limit": 2},
        Success(LIST),
        principal=caller(READERS, HELPDESK),
        stats=CallStats(okta_requests=2, status=200),
    )
    assert got == {
        "ts": "2026-11-13T00:00:00.000Z",
        "event": "tool_call",
        "request_id": "r1",
        "uid": "00u1devuser000000000",
        "sub": "dev@example.com",
        "client_id": "0oa1client0000000000",
        "roles": ["directory-reader", "helpdesk"],
        "tool": "okta_groups",
        "command": "list",
        "args": {"q": "Staff"},
        "options": {"select": "id", "limit": 2},
        "outcome": "ok",
        "bytes": len(LIST),
        "items": 2,
        "truncated": "max_items",
        "status": 200,
        "okta_requests": 2,
        "duration_ms": 250,
    }


def test_single_resource_and_failure(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    item = '{"untrusted":true,"item":{"id":"' + GROUP + '"}}'
    got = line(log, out, "okta_groups", {"command": "get", "args": {"group": GROUP}}, Success(item))
    assert (got["items"], got["truncated"], got["bytes"]) == (1, False, len(item))
    log, out = audit(registry, engine)
    failed = Failure(Code.NOT_FOUND, "no such group")
    got = line(
        log,
        out,
        "okta_groups",
        {"command": "get", "args": {"group": GROUP}},
        failed,
        stats=CallStats(1, 404),
    )
    assert (got["event"], got["outcome"], got["status"]) == ("tool_call", "not_found", 404)
    assert "items" not in got and "bytes" not in got and "reason" not in got


def test_bytes_and_bool_count(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    got = line(log, out, "okta_help", {"tool": "okta_groups", "command": "list"}, Text("é"))
    assert got["bytes"] == 2  # UTF-8 bytes, not characters
    log, out = audit(registry, engine)
    got = line(
        log, out, "okta_groups", {"command": "list"}, Success('{"untrusted":true,"count":true}')
    )
    assert got["items"] == 1


def test_help_status_and_cancelled(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    got = line(log, out, "okta_help", {"tool": "okta_groups", "command": "list"}, Text("help"))
    assert got["args"] == {"tool": "okta_groups", "command": "list"}
    assert (got["outcome"], got["bytes"]) == ("ok", 4)
    assert "items" not in got and "command" not in got
    log, out = audit(registry, engine)
    got = line(log, out, "okta_status", {}, Success('{"user":"dev@example.com"}'))
    assert "items" not in got and "args" not in got
    log, out = audit(registry, engine)
    got = line(log, out, "okta_groups", {"command": "list"}, None)
    assert got["outcome"] == "cancelled"


# --- denials -----------------------------------------------------------------------------

DENIED = Failure(Code.FORBIDDEN_BY_POLICY, "forbidden")


@pytest.mark.parametrize(
    ("tool", "arguments", "reason"),
    [
        ("okta_nope", {"command": "list"}, "unknown_tool"),
        ("okta_network_zones", {"command": "list"}, "tool_not_permitted"),
        ("okta_groups", {"command": "nope"}, "command_not_permitted"),
        ("okta_groups", {"command": "list", "args": {"expand": "stats"}}, "args_not_permitted"),
        ("okta_groups", {"command": ["list"]}, "command_not_permitted"),
        ("okta_help", {"tool": "okta_network_zones", "command": "list"}, "tool_not_permitted"),
        ("okta_help", {"tool": "okta_groups", "command": "nope"}, "command_not_permitted"),
        ("okta_help", {"tool": "okta_groups", "command": ["list"]}, "command_not_permitted"),
        ("okta_help", {"tool": "okta_nope", "command": "list"}, "unknown_tool"),
        (42, {}, "unknown_tool"),
    ],
)
def test_denials(
    registry: Registry, engine: Engine, tool: object, arguments: object, reason: str
) -> None:
    log, out = audit(registry, engine)
    got = line(log, out, tool, arguments, DENIED)
    assert (got["event"], got["outcome"], got["reason"]) == (
        "tool_denied",
        "forbidden_by_policy",
        reason,
    )


def test_denied_with_no_roles(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    got = line(log, out, "okta_groups", {"command": "list"}, DENIED, principal=caller(NOBODY))
    assert (got["roles"], got["reason"]) == ([], "tool_not_permitted")


# --- args --------------------------------------------------------------------------------


def test_caller_names_cut_and_unknown_args_not_named(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    long = "x" * 500
    got = line(log, out, "okta_" + long, {"command": long, "args": {"q": "a"}}, DENIED)
    assert got["tool"] == ("okta_" + long)[:NAME_MAX] + CUT
    assert "command" not in got and "args" not in got  # unknown tool: nothing of its args
    log, out = audit(registry, engine)
    got = line(log, out, "okta_groups", {"command": long, "args": {"q": "a"}}, DENIED)
    assert got["command"] == long[:NAME_MAX] + CUT
    assert "args" not in got  # unknown command: its args aren't ours to name
    log, out = audit(registry, engine)
    sent = {"command": "list", "args": {"q": "a", "Bearer " + SSWS: SSWS, "zz": 1}}
    got = line(log, out, "okta_groups", sent, Failure(Code.INVALID_ARGUMENTS, "unknown arg"))
    assert (got["args"], got["unknown_args"]) == ({"q": "a"}, 2)
    assert SSWS not in out.getvalue()


def test_cursor_never_logged(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    cursor = "v1." + "c" * 200
    got = line(log, out, "okta_groups", {"command": "list", "cursor": cursor}, Success(LIST))
    assert got["options"] == {"cursor": True}
    assert cursor not in out.getvalue()


def test_bad_option_types(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    sent = {"command": "list", "args": "x", "select": ["id"], "limit": {"a": 1}, "links": True}
    got = line(log, out, "okta_groups", sent, Failure(Code.INVALID_ARGUMENTS, "bad"))
    assert got["args"] == "invalid"
    assert got["options"] == {"select": "invalid", "limit": "invalid", "links": True}


def test_long_value_cut(registry: Registry, engine: Engine) -> None:
    log, out = audit(registry, engine)
    value = "Staff" * 1000
    got = line(log, out, "okta_groups", {"command": "list", "args": {"q": value}}, Success(LIST))
    assert got["args"]["q"] == json.dumps(value)[:VALUE_MAX] + CUT


def test_arg_named_by_a_scrub_rule_is_redacted(registry: Registry, engine: Engine) -> None:
    """No declared arg is named like a secret today; if one ever is, its value isn't logged.
    The names come from scrub.yaml's single-key paths."""
    log, out = audit(registry, engine)
    assert "client_secret" in log._redacted  # pyright: ignore[reportPrivateUsage]
    log._redacted = frozenset({"q"})  # pyright: ignore[reportPrivateUsage]
    sent = {"command": "list", "args": {"Q": SECRET, "search": 'type eq "OKTA_GROUP"'}}
    got = line(log, out, "okta_groups", sent, Failure(Code.INVALID_ARGUMENTS, "unknown arg"))
    assert got["unknown_args"] == 1  # `Q` isn't declared: arg names are case-sensitive
    log, out = audit(registry, engine)
    log._redacted = frozenset({"q"})  # pyright: ignore[reportPrivateUsage]
    sent = {"command": "list", "args": {"q": SECRET, "search": 'type eq "OKTA_GROUP"'}}
    got = line(log, out, "okta_groups", sent, Success(LIST))
    assert got["args"] == {"q": REDACTED, "search": 'type eq "OKTA_GROUP"'}
    assert SECRET not in out.getvalue()


def test_hash_mode(registry: Registry, engine: Engine) -> None:
    sent = {"command": "list", "args": {"q": "Staff", "search": 'profile.name eq "Staff"'}}
    log, out = audit(registry, engine, mode="hash")
    first = line(log, out, "okta_groups", sent, Success(LIST))
    log, out = audit(registry, engine, mode="hash")
    again = line(log, out, "okta_groups", sent, Success(LIST))
    assert "Staff" not in out.getvalue()
    assert first["args"] == again["args"]  # equal values match across lines
    assert first["args"]["q"] != first["args"]["search"]
    assert all(v.startswith("hmac:") and len(v) == 37 for v in first["args"].values())
    other = AuditLog(
        io.StringIO(),
        registry=registry,
        engine=engine,
        args_mode="hash",
        key=hash_key(b"j" * 32),
    )
    assert other._value("Staff") != log._value("Staff")  # pyright: ignore[reportPrivateUsage]


def test_hash_mode_hashes_caller_free_text(registry: Registry, engine: Engine) -> None:
    """Names that aren't ours, okta_help's target and `select` are free text a caller could
    put an email in; ours stay readable."""
    email = "jane.doe@example.com"
    log, out = audit(registry, engine, mode="hash")
    got = line(log, out, "okta_groups", {"command": email}, DENIED)
    assert got["tool"] == "okta_groups" and got["command"].startswith("hmac:")
    log, out = audit(registry, engine, mode="hash")
    as_arg = line(log, out, "okta_groups", {"command": "list", "args": {"q": email}}, DENIED)
    assert as_arg["args"]["q"] == got["command"]  # one value, one hash, wherever it was sent
    log, out = audit(registry, engine, mode="hash")
    got = line(log, out, email, {}, DENIED)
    assert got["tool"].startswith("hmac:")
    log, out = audit(registry, engine, mode="hash")
    got = line(log, out, "okta_help", {"tool": "okta_groups", "command": email}, DENIED)
    assert got["args"]["tool"] == "okta_groups" and got["args"]["command"].startswith("hmac:")
    log, out = audit(registry, engine, mode="hash")
    got = line(log, out, "okta_groups", {"command": "list", "select": email}, Success(LIST))
    assert got["command"] == "list" and got["options"]["select"].startswith("hmac:")
    log, out = audit(registry, engine, mode="hash")
    got = line(log, out, "okta_help", {"tool": "okta_groups", "command": "list"}, Text("h"))
    assert got["args"] == {"tool": "okta_groups", "command": "list"}


def test_hash_key_is_not_the_cursor_key() -> None:
    key = b"k" * 32
    assert hash_key(key) != key and len(hash_key(key)) == 32


# --- sinks -------------------------------------------------------------------------------


def test_write_failure_raises(registry: Registry, engine: Engine, tmp_path: Path) -> None:
    sink = (tmp_path / "audit.log").open("a")
    sink.close()
    log, _ = audit(registry, engine, sink=sink)
    with pytest.raises(AuditError):
        log.record(
            request_id="r1",
            principal=caller(READERS),
            tool="okta_status",
            arguments={},
            outcome=Success("{}"),
            started=log.start(),
            stats=CallStats(),
        )


def test_open_sink(tmp_path: Path) -> None:
    assert open_sink("stdout", stdio=False) is sys.stdout
    assert open_sink("stdout", stdio=True) is sys.stderr  # stdout is the stdio transport
    assert open_sink("stderr", stdio=False) is sys.stderr
    path = tmp_path / "audit.log"
    path.write_text("earlier\n")
    sink = open_sink(str(path), stdio=False)
    sink.write("next\n")
    assert path.read_text() == "earlier\nnext\n"  # appended, line-buffered
    created = tmp_path / "new.log"
    open_sink(str(created), stdio=False)
    assert created.stat().st_mode & 0o777 == 0o600  # owner-only: args are PII


def test_open_sink_warns_on_a_shared_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "audit.log"
    path.touch()
    path.chmod(0o600)
    open_sink(str(path), stdio=False)
    assert "readable or writable by others" not in caplog.text
    path.chmod(0o644)
    open_sink(str(path), stdio=False)
    assert "MCP_AUDIT_LOG: the file is readable or writable by others" in caplog.text


def test_collect_counts_only_inside() -> None:
    record_sent(200)  # outside a call: nothing to count, no error
    with collect() as stats:
        record_sent(429)
        record_sent(None)
        record_sent(200)
    record_sent(500)
    assert (stats.okta_requests, stats.status) == (3, 200)


# --- through the server ------------------------------------------------------------------


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    principal = tmp_path / "principal.yaml"
    principal.write_text("uid: 00u1devuser000000000\nsub: dev@example.com\ngroups: []\n")
    return {
        "MCP_DEV_MODE": "1",
        "MCP_DEV_PRINCIPAL_FILE": str(principal),
        "MCP_POLICY_FILE": str(PILOT),
        "MCP_CURSOR_KEY": CURSOR_KEY,
        "MCP_AUDIT_LOG": str(tmp_path / "audit.log"),
        "OKTA_ORG_URL": ORG,
        "OKTA_SCOPES": "okta.groups.read okta.networkZones.read",
        "OKTA_API_TOKEN": SSWS,
        **extra,
    }


def okta(request: httpx2.Request) -> httpx2.Response:
    if request.url.path == "/api/v1/groups":
        group = {"id": GROUP, "type": "OKTA_GROUP", "profile": {"name": SECRET}}
        return httpx2.Response(200, json=[group])
    return httpx2.Response(404, json={"errorSummary": SECRET})


@asynccontextmanager
async def running(config: Config, principal: Principal) -> AsyncIterator[Client]:
    async with new_http_client(httpx2.MockTransport(okta)) as http:
        runtime = build_runtime(config, http)
        async with Client(mcp_server(runtime, lambda: principal)) as client:
            yield client


def lines(tmp_path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]


@pytest.mark.anyio
async def test_server_writes_one_line_per_call(tmp_path: Path) -> None:
    config = load_config(env(tmp_path))
    async with running(config, caller(READERS)) as client:
        ok = await client.call_tool("okta_groups", {"command": "list", "args": {"q": "Sta"}})
        missing = await client.call_tool(
            "okta_groups", {"command": "get", "args": {"group": "00g" + "x" * 17}}
        )
        denied = await client.call_tool("okta_network_zones", {"command": "list"})
        await client.call_tool("okta_status", {})
        await client.list_tools()  # not a call: no line
    assert not ok.is_error and missing.is_error and denied.is_error
    first, second, third, fourth = lines(tmp_path)
    assert (first["outcome"], first["status"], first["okta_requests"], first["items"]) == (
        "ok",
        200,
        1,
        1,
    )
    assert first["args"] == {"q": "Sta"}
    error = missing.structured_content
    assert error is not None
    assert (second["outcome"], second["status"]) == (error["error"]["code"], 404)
    assert (third["event"], third["reason"], third["okta_requests"]) == (
        "tool_denied",
        "tool_not_permitted",
        0,
    )
    assert fourth["tool"] == "okta_status"
    # Each line carries the request ID the caller was given.
    assert second["request_id"] == error["error"]["request_id"]
    text = (tmp_path / "audit.log").read_text()
    assert SECRET not in text and SSWS not in text and CURSOR_KEY not in text


@pytest.mark.anyio
async def test_server_withholds_result_if_audit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(env(tmp_path))

    def broken(self: AuditLog, **_: object) -> None:
        raise AuditError("OSError")

    monkeypatch.setattr(AuditLog, "record", broken)
    async with running(config, caller(READERS)) as client:
        result = await client.call_tool("okta_groups", {"command": "list"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["error"]["code"] == "internal_error"
    assert SECRET not in json.dumps(result.structured_content)


@pytest.mark.anyio
async def test_server_withholds_result_if_building_the_line_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A bug in the audit code fails closed too, logged by type only."""
    config = load_config(env(tmp_path))

    def broken(self: AuditLog, **_: object) -> None:
        raise TypeError(SECRET)

    monkeypatch.setattr(AuditLog, "record", broken)
    async with running(config, caller(READERS)) as client:
        result = await client.call_tool("okta_groups", {"command": "list"})
    assert result.is_error
    assert result.structured_content is not None
    assert result.structured_content["error"]["code"] == "internal_error"
    assert "internal error in audit: TypeError" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.anyio
async def test_unopenable_audit_file_fails_startup(tmp_path: Path) -> None:
    config = load_config(env(tmp_path, MCP_AUDIT_LOG=str(tmp_path / "missing" / "audit.log")))
    async with new_http_client(httpx2.MockTransport(okta)) as http:
        with pytest.raises(ConfigError, match="MCP_AUDIT_LOG"):
            build_runtime(config, http)


@pytest.mark.parametrize("value", ["audit.log", "./audit.log", "-"])
def test_audit_log_must_be_a_stream_or_absolute_path(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="MCP_AUDIT_LOG"):
        load_config(env(tmp_path, MCP_AUDIT_LOG=value))
