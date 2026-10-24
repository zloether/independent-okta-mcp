"""Run: uv run pytest spikes/sdk"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from spike_server import build_app

URL = "https://example.com/mcp"
MODES = ["2026-07-28", "legacy"]


@asynccontextmanager
async def client_for(token: str | None, mode: str) -> AsyncIterator[Client]:
    app = build_app()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
        Client(streamable_http_client(URL, http_client=http), mode=mode) as client,
    ):
        yield client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_tools_list_differs_per_principal(mode: str) -> None:
    async with client_for("token-alice", mode) as c:
        alice = await c.list_tools()
        assert c.protocol_version == ("2025-11-25" if mode == "legacy" else mode)
    async with client_for("token-bob", mode) as c:
        bob = await c.list_tools()
    assert [t.name for t in alice.tools] == ["users_get"]
    assert [t.name for t in bob.tools] == ["groups_list"]
    assert alice.tools[0].annotations is not None
    assert alice.tools[0].annotations.read_only_hint is True
    if mode != "legacy":
        assert alice.cache_scope == "private"
        assert alice.ttl_ms == 60_000


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_call_tool_structured_content(mode: str) -> None:
    async with client_for("token-alice", mode) as c:
        ok = await c.call_tool("users_get", {"id": "00u1"})
        denied = await c.call_tool("groups_list", {})
    assert ok.structured_content == {"id": "00u1", "principal": "alice"}
    assert ok.content[0].type == "text"
    assert denied.is_error


@pytest.mark.anyio
async def test_missing_token_is_401() -> None:
    app = build_app()
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app)) as http,
    ):
        r = await http.post(URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert "resource_metadata" in r.headers["www-authenticate"]


@pytest.mark.anyio
async def test_stateless_issues_no_session_id() -> None:
    app = build_app()
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }
    headers = {
        "Authorization": "Bearer token-alice",
        "Accept": "application/json, text/event-stream",
    }
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
    ):
        r = await http.post(URL, json=init)
    assert r.status_code == 200
    assert "mcp-session-id" not in r.headers
