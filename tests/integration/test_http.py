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
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx2
import jwt
import mcp_types as types
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from okta_mcp.app import NOT_READY, serve_http
from okta_mcp.config import Config, load_config
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec
from okta_mcp.server import LIST_TTL_MS

PILOT = Path(__file__).parents[1] / "policy" / "fixtures" / "pilot.yaml"
ORG = "https://example.okta.com"
HOST = "https://mcp.example.com"
PUBLIC = HOST + "/mcp"
ISSUER = ORG + "/oauth2/aus1example000000000"
AS_METADATA = ISSUER + "/.well-known/oauth-authorization-server"
JWKS_URI = ISSUER + "/v1/keys"
PRM_PATH_URL = HOST + "/.well-known/oauth-protected-resource/mcp"
CLIENT = "0oa1client0000000000"
SCOPE = "okta-mcp"

READERS = "00g1readers000000000"
HELPDESK = "00g1helpdsk000000000"
ANALYSTS = "00g1secanalyst000000"
GROUP = "00g1emaKYZTWRYYRRTSK"
ZONE = "nzo1example000000000"

AS_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""The mock authorization server's signing key; its public half is the JWKS."""
FORGED_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SERVICE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

MODES = {"2026-07-28": "2026-07-28", "legacy": "2025-11-25"}
"""Client `mode` → the protocol version it must end up speaking (design §5.2)."""
ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


class World:
    """The mocked network: the custom AS (metadata, JWKS) and the Okta org (service token,
    groups, network zones), with every request recorded. `issuer_up` false refuses connections
    to the AS only."""

    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []
        self.issuer_up = True
        self.jwks: dict[str, Any] = {
            "keys": [
                {
                    **RSAAlgorithm.to_jwk(AS_KEY.public_key(), as_dict=True),
                    "kid": "as1",
                    "use": "sig",
                    "alg": "RS256",
                }
            ]
        }

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        url = str(request.url.copy_with(query=None))
        if url.startswith(ISSUER + "/"):
            if not self.issuer_up:
                raise httpx2.ConnectError("issuer down")
            if url == AS_METADATA:
                return httpx2.Response(
                    200,
                    json={
                        "issuer": ISSUER,
                        "jwks_uri": JWKS_URI,
                        "authorization_endpoint": ISSUER + "/v1/authorize",
                        "token_endpoint": ISSUER + "/v1/token",
                    },
                )
            if url == JWKS_URI:
                return httpx2.Response(200, json=self.jwks)
        if request.method == "POST" and url == ORG + "/oauth2/v1/token":
            return httpx2.Response(
                200, json={"access_token": "svc", "token_type": "Bearer", "expires_in": 3600}
            )
        if request.method == "GET" and url == ORG + "/api/v1/groups":
            return httpx2.Response(
                200, json=[{"id": GROUP, "type": "OKTA_GROUP", "profile": {"name": "Staff"}}]
            )
        if request.method == "GET" and url == ORG + "/api/v1/zones":
            return httpx2.Response(
                200, json=[{"id": ZONE, "type": "IP", "name": "Office", "status": "ACTIVE"}]
            )
        return httpx2.Response(404, json={"errorSummary": "Not found"})

    def okta_api(self) -> list[str]:
        """Paths of the Management API requests sent (not the token or the AS)."""
        return [r.url.path for r in self.requests if r.url.path.startswith("/api/")]


def access_token(
    *groups: str, key: rsa.RSAPrivateKey = AS_KEY, kid: str = "as1", **overrides: Any
) -> str:
    """An access token as the custom AS would issue it to `CLIENT` (Okta's claim names)."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": PUBLIC,
        "sub": "user@example.com",
        "uid": "00u1httpuser00000000",
        "cid": CLIENT,
        "scp": [SCOPE],
        "groups": list(groups),
        "iat": now - 5,
        "exp": now + 3600,
        **overrides,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    key = tmp_path / "service.pem"
    key.write_bytes(
        SERVICE_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    values = {
        "MCP_PUBLIC_URL": PUBLIC,
        "MCP_ISSUER": ISSUER,
        "MCP_ALLOWED_CLIENT_IDS": CLIENT,
        "MCP_ALLOWED_ORIGINS": "https://app.example.com",
        "MCP_POLICY_FILE": str(PILOT),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": ORG,
        "OKTA_SCOPES": "okta.groups.read okta.networkZones.read",
        "OKTA_CLIENT_ID": "0oa1service000000000",
        "OKTA_PRIVATE_KEY_FILE": str(key),
        "OKTA_DPOP": "false",
    }
    return {**values, **extra}


@pytest.fixture(scope="module")
def loaded() -> tuple[SpecIndex, Registry]:
    spec = load_spec()
    return spec, load_registry(spec)


@pytest.fixture(autouse=True)
def load_once(loaded: tuple[SpecIndex, Registry], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("okta_mcp.server.load_spec", lambda: loaded[0])
    monkeypatch.setattr("okta_mcp.server.load_registry", lambda spec: loaded[1])


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return load_config(env(tmp_path))


@pytest.fixture
def world() -> World:
    return World()


Running = Callable[..., Any]


@pytest.fixture
def running(monkeypatch: pytest.MonkeyPatch) -> Running:
    """`running(config, world)`: an async context manager that runs `serve_http` with uvicorn
    replaced, and yields the app it would have served."""

    @asynccontextmanager
    async def run(
        config: Config, world: World, *, wait_ready: bool = True
    ) -> AsyncIterator[Starlette]:
        apps: list[Starlette] = []
        started, stop = anyio.Event(), anyio.Event()

        async def serve(self: uvicorn.Server) -> None:
            app = self.config.app
            assert isinstance(app, Starlette)
            async with app.router.lifespan_context(app):
                apps.append(app)
                started.set()
                await stop.wait()

        monkeypatch.setattr(uvicorn.Server, "serve", serve)
        async with anyio.create_task_group() as tg:
            tg.start_soon(serve_http, config, httpx2.MockTransport(world))
            with anyio.fail_after(5):
                await started.wait()
            (app,) = apps
            if wait_ready:
                await until_ready(app)
            try:
                yield app
            finally:
                stop.set()

    return run


def http_for(app: Starlette, **headers: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=HOST, headers=headers
    )


async def until_ready(app: Starlette, seconds: float = 5) -> None:
    async with http_for(app) as http:
        with anyio.fail_after(seconds):
            while (await http.get("/readyz")).status_code != 200:
                await anyio.sleep(0.01)


@asynccontextmanager
async def mcp_client(app: Starlette, token: str, mode: str) -> AsyncIterator[Client]:
    async with (
        http_for(app, authorization=f"Bearer {token}") as http,
        Client(streamable_http_client(PUBLIC, http_client=http), mode=mode) as client,
    ):
        yield client


def envelope(result: types.CallToolResult) -> dict[str, Any]:
    """The tool result's structured content, checked against its text block (§5.2)."""
    assert result.structured_content is not None
    (block,) = result.content
    assert isinstance(block, types.TextContent)
    assert json.loads(block.text) == result.structured_content
    return result.structured_content


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
JSON_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def challenge_params(header: str) -> dict[str, str]:
    scheme, _, rest = header.partition(" ")
    assert scheme == "Bearer"
    params: dict[str, str] = {}
    for part in rest.split(", "):
        name, _, value = part.partition("=")
        params[name] = value.strip('"')
    return params


# --- 401 → discovery → token → call -----------------------------------------------------


@pytest.mark.anyio
async def test_a_client_follows_the_401_to_a_token_that_works(
    running: Running, config: Config, world: World
) -> None:
    """The path a client takes (design §8.1): 401 names the PRM URL and the scope; PRM names
    the issuer; the issuer's metadata is the mocked AS's; a token that AS signs is accepted."""
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

        # The client's own fetch of the AS metadata, on the same mocked AS the verifier uses.
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(world)) as outside:
            as_metadata = (await outside.get(AS_METADATA)).json()
        assert as_metadata["issuer"] == issuer

        token = access_token(READERS)
        accepted = await http.post(
            "/mcp", json=INIT, headers={**JSON_HEADERS, "authorization": f"Bearer {token}"}
        )
    assert accepted.status_code == 200
    assert accepted.json()["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("token", "status", "error"),
    [
        (access_token(READERS, key=FORGED_KEY), 401, "invalid_token"),
        (access_token(READERS, kid="nope"), 401, "invalid_token"),
        (access_token(READERS, aud="https://other.example.com/mcp"), 401, "invalid_token"),
        (access_token(READERS, iss=ORG), 401, "invalid_token"),
        (access_token(READERS, cid="0oa1otherclient00000"), 401, "invalid_token"),
        (access_token(READERS, exp=int(time.time()) - 120), 401, "invalid_token"),
        (access_token(READERS, scp=["openid"]), 403, "insufficient_scope"),
    ],
    ids=["forged", "unknown-kid", "wrong-aud", "wrong-iss", "other-client", "expired", "scope"],
)
async def test_tokens_the_verifier_refuses(
    running: Running, config: Config, world: World, token: str, status: int, error: str
) -> None:
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
    running: Running, config: Config, world: World
) -> None:
    """A cold JWKS is 503 for a valid token, never 401 (§11.3); once the background refresh
    gets the keys (after its first 1 s backoff), the same token works."""
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
    # Every request after the first names the negotiated version (the 2025-11-25 transport
    # rule; 2026-07-28 sends it on every request).
    versions = {h.get("mcp-protocol-version") for h in recorder.headers[1:]}
    assert versions == {MODES[mode]}
    assert all("mcp-session-id" not in h for h in recorder.headers)
