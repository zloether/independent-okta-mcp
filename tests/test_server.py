"""Startup wiring and the MCP handlers (plan 4.1, design §4, §5.2, §5.5, §8.6)."""

import json
import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2
import mcp_types as types
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.shared.exceptions import MCPError

from okta_mcp.auth.principal import Principal
from okta_mcp.config import Config, load_config
from okta_mcp.exec.executor import FORBIDDEN, INTERNAL
from okta_mcp.logs import RequestIdFilter
from okta_mcp.okta.client import new_http_client
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.token import ClientCredentialsProvider, SSWSProvider
from okta_mcp.policy.loader import PolicyError
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec
from okta_mcp.server import (
    LIST_TTL_MS,
    RESOURCE_NOT_FOUND,
    Runtime,
    _tokens,  # pyright: ignore[reportPrivateUsage]
    build_runtime,
    mcp_server,
)

PILOT = Path(__file__).parent / "policy" / "fixtures" / "pilot.yaml"
ORG = "https://example.okta.com"
READERS = "00g1readers000000000"
HELPDESK = "00g1helpdsk000000000"
NOBODY = "00g9nobody0000000000"
GROUP = "00g1emaKYZTWRYYRRTSK"
MODES = ["2026-07-28", "legacy"]
REQUEST_ID = re.compile(r"[0-9a-f]{32}")
SECRET = "-".join(["okta", "said", "secret"])
"""Built at run time, so a logged traceback's source lines don't hold it."""


def caller(*groups: str) -> Principal:
    return Principal(uid="00u1devuser000000000", sub="dev@example.com", groups=frozenset(groups))


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    principal = tmp_path / "principal.yaml"
    principal.write_text("uid: 00u1devuser000000000\nsub: dev@example.com\ngroups: []\n")
    values = {
        "MCP_DEV_MODE": "1",
        "MCP_DEV_PRINCIPAL_FILE": str(principal),
        "MCP_POLICY_FILE": str(PILOT),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": ORG,
        "OKTA_SCOPES": "okta.groups.read okta.networkZones.read",
        "OKTA_API_TOKEN": "test-ssws-token",
    }
    return {**values, **extra}


class Okta:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.url.path == "/api/v1/groups":
            return httpx2.Response(
                200, json=[{"id": GROUP, "type": "OKTA_GROUP", "profile": {"name": "Staff"}}]
            )
        return httpx2.Response(404, json={"errorSummary": "Not found"})


def only_text(result: types.CallToolResult) -> str:
    (block,) = result.content
    assert isinstance(block, types.TextContent)
    return block.text


@asynccontextmanager
async def running(
    config: Config, principal: Principal, okta: Okta, mode: str = "2026-07-28"
) -> AsyncIterator[tuple[Client, Runtime]]:
    async with new_http_client(httpx2.MockTransport(okta)) as http:
        runtime = build_runtime(config, http)
        async with Client(mcp_server(runtime, lambda: principal), mode=mode) as client:
            yield client, runtime


@pytest.fixture(scope="module")
def loaded() -> tuple[SpecIndex, Registry]:
    spec = load_spec()
    return spec, load_registry(spec)


@pytest.fixture(autouse=True)
def load_once(loaded: tuple[SpecIndex, Registry], monkeypatch: pytest.MonkeyPatch) -> None:
    """The spec takes a second to load; every runtime here gets the same one."""
    monkeypatch.setattr("okta_mcp.server.load_spec", lambda: loaded[0])
    monkeypatch.setattr("okta_mcp.server.load_registry", lambda spec: loaded[1])


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return load_config(env(tmp_path))


# --- tools ------------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_tools_list_per_principal(config: Config, mode: str) -> None:
    async with running(config, caller(READERS), Okta(), mode) as (client, _):
        reader = await client.list_tools()
    async with running(config, caller(HELPDESK), Okta(), mode) as (client, _):
        helpdesk = await client.list_tools()
    async with running(config, caller(NOBODY), Okta(), mode) as (client, _):
        nobody = await client.list_tools()
    assert [t.name for t in reader.tools] == ["okta_groups", "okta_help", "okta_status"]
    assert [t.name for t in helpdesk.tools] == [
        "okta_groups",
        "okta_network_zones",
        "okta_help",
        "okta_status",
    ]
    assert [t.name for t in nobody.tools] == ["okta_status"]
    for tool in reader.tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
    if mode != "legacy":
        assert reader.cache_scope == "private"
        assert reader.ttl_ms == LIST_TTL_MS


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_call_returns_the_envelope_as_text_and_structured(config: Config, mode: str) -> None:
    okta = Okta()
    async with running(config, caller(READERS), okta, mode) as (client, _):
        result = await client.call_tool("okta_groups", {"command": "list"})
    assert result.is_error is False
    text = only_text(result)
    assert result.structured_content == json.loads(text)
    assert result.structured_content["rows"] == [[GROUP, "OKTA_GROUP", "Staff"]]
    (request,) = okta.requests
    assert request.method == "GET"
    assert request.headers["authorization"] == "SSWS test-ssws-token"


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_refusal_is_an_error_envelope_with_a_request_id(config: Config, mode: str) -> None:
    okta = Okta()
    async with running(config, caller(READERS), okta, mode) as (client, _):
        first = await client.call_tool("okta_network_zones", {"command": "list"})
        second = await client.call_tool("okta_network_zones", {"command": "list"})
    assert first.is_error is True
    error = json.loads(only_text(first))["error"]
    assert first.structured_content == {"error": error}
    assert error["code"] == "forbidden_by_policy"
    assert error["message"] == FORBIDDEN
    assert REQUEST_ID.fullmatch(error["request_id"])
    assert second.structured_content["error"]["request_id"] != error["request_id"]
    assert okta.requests == []


@pytest.mark.anyio
async def test_help_is_plain_text(config: Config) -> None:
    async with running(config, caller(READERS), Okta()) as (client, _):
        result = await client.call_tool("okta_help", {"tool": "okta_groups", "command": "list"})
    assert result.is_error is False
    assert result.structured_content is None
    assert only_text(result).startswith("okta_groups list")


@pytest.mark.anyio
async def test_status_names_the_dev_principal(config: Config) -> None:
    async with running(config, caller(READERS), Okta()) as (client, _):
        result = await client.call_tool("okta_status", {})
    assert result.structured_content["user"] == "dev@example.com"
    assert result.structured_content["roles"] == ["directory-reader"]


@pytest.mark.anyio
async def test_exception_message_never_reaches_the_caller(
    config: Config, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(*_: object) -> None:
        raise RuntimeError(SECRET)

    async with running(config, caller(READERS), Okta()) as (client, runtime):
        monkeypatch.setattr(runtime.tools, "call", boom)
        with caplog.at_level(logging.ERROR, logger="okta_mcp.server"):
            result = await client.call_tool("okta_groups", {"command": "list"})
    assert result.is_error is True
    error = result.structured_content["error"]
    assert error["code"] == "internal_error"
    assert error["message"] == INTERNAL
    assert SECRET not in only_text(result)
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


PROTOCOL_CALLS: dict[str, tuple[str, str, tuple[Any, ...]]] = {
    "list_tools": ("tools", "list_tools", ()),
    "list_resources": ("resources", "visible", ()),
    "read_resource": ("resources", "read", ("okta://guide/groups",)),
}


@pytest.mark.anyio
@pytest.mark.parametrize("method", list(PROTOCOL_CALLS))
async def test_exception_is_a_fixed_protocol_error(
    config: Config,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError(SECRET)

    part, attribute, args = PROTOCOL_CALLS[method]
    async with running(config, caller(READERS), Okta()) as (client, runtime):
        monkeypatch.setattr(getattr(runtime, part), attribute, boom)
        with caplog.at_level(logging.ERROR), pytest.raises(MCPError) as e:
            await getattr(client, method)(*args)
    assert (e.value.code, e.value.message) == (types.INTERNAL_ERROR, INTERNAL)
    assert REQUEST_ID.fullmatch(e.value.data["request_id"])
    assert SECRET not in str(e.value.data)
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("method", [*PROTOCOL_CALLS, "call_tool"])
async def test_principal_failure_is_a_fixed_protocol_error(
    config: Config, caplog: pytest.LogCaptureFixture, method: str, mode: str
) -> None:
    """What the principal source raises (4.2: the verifier's contextvar) never reaches the
    client as text, and never runs the request."""

    def no_principal() -> Principal:
        raise LookupError(SECRET)

    okta = Okta()
    if method == "call_tool":
        args: tuple[Any, ...] = ("okta_groups", {"command": "list"})
    else:
        args = PROTOCOL_CALLS[method][2]
    async with new_http_client(httpx2.MockTransport(okta)) as http:
        server = mcp_server(build_runtime(config, http), no_principal)
        async with Client(server, mode=mode) as client:
            with caplog.at_level(logging.ERROR), pytest.raises(MCPError) as e:
                await getattr(client, method)(*args)
    assert (e.value.code, e.value.message) == (types.INTERNAL_ERROR, INTERNAL)
    assert REQUEST_ID.fullmatch(e.value.data["request_id"])
    assert "LookupError" in caplog.text
    assert SECRET not in caplog.text
    assert okta.requests == []


@pytest.mark.anyio
async def test_a_handler_added_later_is_guarded(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    """The guard is middleware, so a handler registered without any wrapper is covered."""

    async def prompts(ctx: Any, params: Any) -> types.ListPromptsResult:
        raise RuntimeError(SECRET)

    async with new_http_client(httpx2.MockTransport(Okta())) as http:
        server = mcp_server(build_runtime(config, http), lambda: caller(READERS))
        server.add_request_handler("prompts/list", types.PaginatedRequestParams, prompts)
        async with Client(server) as client:
            with caplog.at_level(logging.ERROR), pytest.raises(MCPError) as e:
                await client.list_prompts()
    assert (e.value.code, e.value.message) == (types.INTERNAL_ERROR, INTERNAL)
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.anyio
async def test_guard_passes_validation_and_protocol_errors_through() -> None:
    """The SDK maps these to fixed texts itself (`Invalid request parameters`, our own
    `MCPError`s); turning them into internal errors would hide a client's bad params."""
    from pydantic import BaseModel, ValidationError

    from okta_mcp.server import _Guard  # pyright: ignore[reportPrivateUsage]

    class Params(BaseModel):
        uri: str

    with pytest.raises(ValidationError) as caught:
        Params.model_validate({"uri": 123})
    invalid = caught.value
    ctx: Any = type("Ctx", (), {"method": "resources/read", "request_id": 1})()
    for error in (invalid, MCPError(code=types.INVALID_PARAMS, message=RESOURCE_NOT_FOUND)):

        async def call_next(_: Any, error: Exception = error) -> None:
            raise error

        with pytest.raises(type(error)) as raised:
            await _Guard()(ctx, call_next)
        assert raised.value is error


@pytest.mark.anyio
async def test_request_id_tags_log_lines_of_the_call(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    records: list[logging.LogRecord] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Keep()
    handler.addFilter(RequestIdFilter())
    logger = logging.getLogger("okta_mcp.test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    async def logs(*_: object) -> None:
        logger.info("inside the call")
        raise RuntimeError("x")

    try:
        async with running(config, caller(READERS), Okta()) as (client, runtime):
            monkeypatch.setattr(runtime.tools, "call", logs)
            result = await client.call_tool("okta_groups", {"command": "list"})
            logger.info("after the call")
    finally:
        logger.removeHandler(handler)
    rid = result.structured_content["error"]["request_id"]
    assert [getattr(r, "request_id", None) for r in records] == [rid, "-"]


# --- resources ----------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_resources_per_principal(config: Config, mode: str) -> None:
    async with running(config, caller(READERS), Okta(), mode) as (client, _):
        listed = await client.list_resources()
        read = await client.read_resource("okta://guide/groups")
        with pytest.raises(MCPError) as hidden:
            await client.read_resource("okta://guide/network-zones")
        with pytest.raises(MCPError) as missing:
            await client.read_resource("okta://guide/nothing")
    assert [r.uri for r in listed.resources] == [
        "okta://reference/filters",
        "okta://reference/expression-language",
        "okta://guide/groups",
    ]
    assert all(r.mime_type == "text/markdown" for r in listed.resources)
    if mode != "legacy":
        assert listed.cache_scope == "private"
    (contents,) = read.contents
    assert isinstance(contents, types.TextResourceContents)
    assert contents.uri == "okta://guide/groups"
    assert contents.text.startswith("#")
    # A guide this caller can't see answers exactly as one that doesn't exist.
    assert (hidden.value.code, hidden.value.message) == (missing.value.code, RESOURCE_NOT_FOUND)
    assert REQUEST_ID.fullmatch(hidden.value.data["request_id"])
    assert hidden.value.data.keys() == missing.value.data.keys()


# --- startup ------------------------------------------------------------------------------


def write_key(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "key.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def service_app_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    values = env(tmp_path, OKTA_CLIENT_ID="0oa1service000000000", **extra)
    del values["OKTA_API_TOKEN"]
    values["OKTA_PRIVATE_KEY_FILE"] = str(write_key(tmp_path))
    return values


@pytest.mark.anyio
async def test_ssws_has_no_dpop(config: Config) -> None:
    async with new_http_client() as http:
        tokens, dpop = _tokens(config, http)
    assert isinstance(tokens, SSWSProvider)
    assert dpop is None


@pytest.mark.anyio
async def test_service_app_shares_one_dpop_key(tmp_path: Path) -> None:
    config = load_config(service_app_env(tmp_path))
    async with new_http_client() as http:
        tokens, dpop = _tokens(config, http)
    assert isinstance(tokens, ClientCredentialsProvider)
    assert isinstance(dpop, DPoP)
    assert tokens._dpop is dpop  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_service_app_without_dpop(tmp_path: Path) -> None:
    config = load_config(service_app_env(tmp_path, OKTA_DPOP="false"))
    async with new_http_client() as http:
        tokens, dpop = _tokens(config, http)
    assert isinstance(tokens, ClientCredentialsProvider)
    assert dpop is None
    assert tokens._dpop is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_policy_warnings_are_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\nroles:\n  r:\n    groups: ['00g1readers000000000']\n"
        "    allow: {groups: ['*']}\n    include_sensitive: ['*']\n"
    )
    config = load_config(env(tmp_path, MCP_POLICY_FILE=str(policy)))
    async with new_http_client() as http:
        with caplog.at_level(logging.WARNING, logger="okta_mcp.server"):
            build_runtime(config, http)
    assert "policy: " in caplog.text
    assert "include_sensitive" in caplog.text


@pytest.mark.anyio
async def test_invalid_policy_fails_startup(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nroles:\n  r:\n    groups: [mcp-okta-readers]\n")
    config = load_config(env(tmp_path, MCP_POLICY_FILE=str(policy)))
    async with new_http_client() as http:
        with pytest.raises(PolicyError):
            build_runtime(config, http)


def test_handlers_registered(config: Config) -> None:
    # Only what the server serves; nothing writes or subscribes.
    server = mcp_server(Any, lambda: caller())  # pyright: ignore[reportArgumentType]
    capabilities = server.get_capabilities()
    assert capabilities.tools is not None
    assert capabilities.resources is not None
    assert capabilities.resources.subscribe is False
    assert capabilities.prompts is None
    assert capabilities.completions is None
    # The guard only; no tracing.
    assert [type(m).__name__ for m in server.middleware] == ["_Guard"]
