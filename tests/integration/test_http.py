"""Integration (plan 4.5, design §14 Integration and Protocol rows): the server as `serve_http`
wires it, with the real `JWTVerifier`, a mocked custom authorization server (metadata and a
local JWKS) and a mocked Okta org on one transport.

Only uvicorn is replaced: `uvicorn.Server.serve` is patched to run the app's lifespan and hand
the app to the test, which talks to it over `httpx2.ASGITransport`. Everything else is the
production path, background tasks included (`JWTVerifier.run`, `keep_fresh`), so readiness here
comes from a real JWKS fetch and a real service-token request.

`tests/test_app.py` covers the app with a stand-in verifier; `tests/auth/` the verifier and the
challenges on their own. These tests check that the parts agree when joined: the token a client
gets after following the 401 is the one that authenticates, its `groups` claim picks the tools,
and the policy refuses at call time without an Okta request.
"""

import json
import time
from pathlib import Path
from typing import Any

import httpx2
import mcp_types as types
import pytest
from _harness import (
    ANALYSTS,
    ANNOTATIONS,
    EXPIRED,
    FORGED_KEY,
    GROUP,
    HELPDESK,
    HOST,
    INIT,
    ISSUER,
    JSON_HEADERS,
    MODES,
    ORG,
    PRM_PATH_URL,
    PUBLIC,
    READERS,
    SCOPE,
    ZONE,
    Running,
    World,
    access_token,
    challenge_params,
    env,
    envelope,
    http_for,
    mcp_client,
    until_ready,
)
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from okta_mcp.app import NOT_READY
from okta_mcp.config import Config, load_config
from okta_mcp.server import LIST_TTL_MS

# --- 401 → discovery → token → call -----------------------------------------------------


@pytest.mark.anyio
async def test_a_client_follows_the_401_to_a_token_that_works(
    running: Running, config: Config, world: World
) -> None:
    """The path a client takes (design §8.1): 401 names the PRM URL and the scope; PRM names
    the issuer; a token that issuer signs (the key the verifier found through its metadata) is
    accepted."""
    async with running(config, world) as app, http_for(app) as http:
        refused = await http.post("/mcp", json=INIT, headers=JSON_HEADERS)
        assert refused.status_code == 401
        params = challenge_params(refused.headers["www-authenticate"])
        assert params == {
            "resource_metadata": PRM_PATH_URL,
            "scope": SCOPE,
        }  # no `error` without a token (RFC 6750 §3.1)

        prm = await http.get(params["resource_metadata"].removeprefix(HOST))
        assert prm.status_code == 200
        assert prm.json()["resource"] == PUBLIC
        assert prm.json()["scopes_supported"] == [SCOPE]
        (issuer,) = prm.json()["authorization_servers"]
        assert issuer == ISSUER
        root = await http.get("/.well-known/oauth-protected-resource")
        assert root.json() == prm.json()

        token = access_token(READERS)
        accepted = await http.post(
            "/mcp", json=INIT, headers={**JSON_HEADERS, "authorization": f"Bearer {token}"}
        )
    assert accepted.status_code == 200
    assert accepted.json()["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("overrides", "status", "error"),
    # Overrides, not tokens: a token minted at collection would age with the run.
    [
        ({"key": FORGED_KEY}, 401, "invalid_token"),
        ({"kid": "nope"}, 401, "invalid_token"),
        ({"aud": "https://other.example.com/mcp"}, 401, "invalid_token"),
        ({"iss": ORG}, 401, "invalid_token"),
        ({"cid": "0oa1otherclient00000"}, 401, "invalid_token"),
        ({"exp": EXPIRED}, 401, "invalid_token"),
        ({"scp": ["openid"]}, 403, "insufficient_scope"),
    ],
    ids=["forged", "unknown-kid", "wrong-aud", "wrong-iss", "other-client", "expired", "scope"],
)
async def test_tokens_the_verifier_refuses(
    running: Running,
    config: Config,
    world: World,
    overrides: dict[str, Any],
    status: int,
    error: str,
) -> None:
    if overrides.get("exp") is EXPIRED:
        overrides = {**overrides, "exp": int(time.time()) - 120}
    token = access_token(READERS, **overrides)
    async with (
        running(config, world) as app,
        http_for(app, authorization=f"Bearer {token}") as http,
    ):
        r = await http.post("/mcp", json=INIT, headers=JSON_HEADERS)
    assert r.status_code == status
    params = challenge_params(r.headers["www-authenticate"])
    assert params["error"] == error
    assert params["resource_metadata"] == PRM_PATH_URL
    assert params["scope"] == SCOPE
    assert world.okta_api() == []


@pytest.mark.anyio
async def test_mcp_is_503_until_the_issuer_answers(
    running: Running, config: Config, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cold JWKS is 503 for a valid token, never 401 (§11.3); once the background refresh
    gets the keys (after its first backoff, shortened here), the same token works."""
    monkeypatch.setattr("okta_mcp.auth.verifier.RETRY_MIN", 0.01)
    world.issuer_up = False
    token = access_token(READERS)
    async with (
        running(config, world, wait_ready=False) as app,
        http_for(app, authorization=f"Bearer {token}") as http,
    ):
        cold = await http.post("/mcp", json=INIT, headers=JSON_HEADERS)
        assert cold.status_code == 503
        assert cold.json() == {"error": NOT_READY}
        assert "retry-after" in cold.headers
        world.issuer_up = True
        await until_ready(app, seconds=10)
        warm = await http.post("/mcp", json=INIT, headers=JSON_HEADERS)
    assert warm.status_code == 200


# --- per principal ----------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_tools_list_follows_the_groups_claim(
    running: Running, config: Config, world: World, mode: str
) -> None:
    async with running(config, world) as app:
        async with mcp_client(app, access_token(READERS), mode) as client:
            reader = await client.list_tools()
        async with mcp_client(app, access_token(HELPDESK), mode) as client:
            helpdesk = await client.list_tools()
        async with mcp_client(app, access_token(), mode) as client:
            nobody = await client.list_tools()
    assert [t.name for t in reader.tools] == ["okta_groups", "okta_help", "okta_status"]
    assert [t.name for t in helpdesk.tools] == [
        "okta_groups",
        "okta_network_zones",
        "okta_help",
        "okta_status",
    ]
    assert [t.name for t in nobody.tools] == ["okta_status"]
    if mode != "legacy":  # 2025-11-25 results have neither field
        for listed in (reader, helpdesk, nobody):
            assert listed.cache_scope == "private"
            assert listed.ttl_ms == LIST_TTL_MS
    assert world.okta_api() == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("groups", "tool", "arguments"),
    [
        # No command in the tool for this caller.
        ((READERS,), "okta_network_zones", {"command": "list"}),
        # Allowed command, but a search attribute the role doesn't grant.
        (
            (READERS,),
            "okta_groups",
            {"command": "list", "args": {"search": 'profile.description eq "x"'}},
        ),
        # Explicit deny wins over the role's wildcard.
        ((ANALYSTS,), "okta_groups", {"command": "get-apps", "args": {"group": GROUP}}),
    ],
    ids=["tool", "search-attribute", "deny"],
)
async def test_call_time_denial_sends_nothing_to_okta(
    running: Running,
    config: Config,
    world: World,
    groups: tuple[str, ...],
    tool: str,
    arguments: dict[str, Any],
) -> None:
    async with (
        running(config, world) as app,
        mcp_client(app, access_token(*groups), "2026-07-28") as client,
    ):
        result = await client.call_tool(tool, arguments)
    assert result.is_error is True
    assert envelope(result)["error"]["code"] == "forbidden_by_policy"
    assert world.okta_api() == []


@pytest.mark.anyio
async def test_the_same_call_is_allowed_for_another_role(
    running: Running, config: Config, world: World
) -> None:
    async with (
        running(config, world) as app,
        mcp_client(app, access_token(HELPDESK), "2026-07-28") as client,
    ):
        zones = await client.call_tool("okta_network_zones", {"command": "list"})
        status = await client.call_tool("okta_status", {})
    assert zones.is_error is False
    assert envelope(zones)["rows"][0][0] == ZONE
    assert world.okta_api() == ["/api/v1/zones"]
    (block,) = status.content
    assert isinstance(block, types.TextContent)
    assert json.loads(block.text)["user"] == "user@example.com"


@pytest.mark.anyio
async def test_the_request_limiter_is_per_principal(
    running: Running, tmp_path: Path, world: World
) -> None:
    """One Okta request per minute per user: the reader's second call is refused without a
    request, and the help desk user (another `uid`) is unaffected. Plan 6.2 owns the limiter's
    full integration test; this checks the HTTP caller reaches it."""
    config = load_config(env(tmp_path, MCP_REQUESTS_PER_MINUTE="1"))
    async with running(config, world) as app:
        async with mcp_client(app, access_token(READERS), "2026-07-28") as client:
            first = await client.call_tool("okta_groups", {"command": "list"})
            second = await client.call_tool("okta_groups", {"command": "list"})
        other = access_token(HELPDESK, uid="00u1otheruser0000000", sub="other@example.com")
        async with mcp_client(app, other, "2026-07-28") as client:
            third = await client.call_tool("okta_groups", {"command": "list"})
    assert first.is_error is False
    assert envelope(second)["error"]["code"] == "rate_limited"
    assert third.is_error is False
    assert world.okta_api() == ["/api/v1/groups", "/api/v1/groups"]


# --- protocol smoke ---------------------------------------------------------------------


class Recorder(httpx2.AsyncBaseTransport):
    """The ASGI transport, recording each request's headers."""

    def __init__(self, app: Starlette) -> None:
        self.inner = httpx2.ASGITransport(app=app)
        self.headers: list[httpx2.Headers] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.headers.append(request.headers)
        return await self.inner.handle_async_request(request)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_protocol_smoke(running: Running, config: Config, world: World, mode: str) -> None:
    """Design §14 Protocol row: an SDK client over Streamable HTTP at both revisions gets the
    version it asked for, tool annotations, and `structuredContent` with a matching text block."""
    token = access_token(HELPDESK)
    async with running(config, world) as app:
        recorder = Recorder(app)
        async with (
            httpx2.AsyncClient(
                transport=recorder, base_url=HOST, headers={"authorization": f"Bearer {token}"}
            ) as http,
            Client(streamable_http_client(PUBLIC, http_client=http), mode=mode) as client,
        ):
            assert client.protocol_version == MODES[mode]
            tools = await client.list_tools()
            groups = await client.call_tool("okta_groups", {"command": "list"})
            help_text = await client.call_tool(
                "okta_help", {"tool": "okta_groups", "command": "list"}
            )
            resources = await client.list_resources()
    for tool in tools.tools:
        assert tool.annotations is not None
        assert tool.annotations.model_dump(by_alias=True, exclude_none=True) == ANNOTATIONS
    assert envelope(groups)["rows"] == [[GROUP, "OKTA_GROUP", "Staff"]]
    assert help_text.is_error is False
    (block,) = help_text.content
    assert isinstance(block, types.TextContent)
    assert "search" in block.text
    assert resources.resources
    # 2026-07-28 has no handshake (the client adopts the pinned version, so
    # `client.protocol_version` alone proves nothing): every request must carry the version.
    # 2025-11-25 sends it on every request after `initialize`, whose result negotiated it.
    sent = recorder.headers if mode != "legacy" else recorder.headers[1:]
    assert {h.get("mcp-protocol-version") for h in sent} == {MODES[mode]}
    assert all("mcp-session-id" not in h for h in recorder.headers)
