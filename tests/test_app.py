"""The HTTP app (plan 4.2, design §4, §5.2, §11.3, §11.4)."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2
import mcp_types as types
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from okta_mcp.app import ORIGIN_REFUSED, build_app, serve_http, uvicorn_config
from okta_mcp.auth.principal import Principal, VerifiedToken
from okta_mcp.config import Config, load_config
from okta_mcp.exec.executor import INTERNAL
from okta_mcp.okta.client import new_http_client
from okta_mcp.policy.loader import PolicyError
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec
from okta_mcp.server import LIST_TTL_MS, build_runtime

PILOT = Path(__file__).parent / "policy" / "fixtures" / "pilot.yaml"
ORG = "https://example.okta.com"
PUBLIC = "https://mcp.example.com/mcp"
ISSUER = "https://example.okta.com/oauth2/aus1example000000000"
ALLOWED = "https://app.example.com"
READERS = "00g1readers000000000"
HELPDESK = "00g1helpdsk000000000"
GROUP = "00g1emaKYZTWRYYRRTSK"
SCOPE = "okta-mcp"
MODES = ["2026-07-28", "legacy"]
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


def caller(*groups: str) -> Principal:
    return Principal(uid="00u1httpuser00000000", sub="user@example.com", groups=frozenset(groups))


def verified(principal: Principal, scopes: list[str] | None = None) -> VerifiedToken:
    return VerifiedToken(
        token="t",  # noqa: S106
        client_id="0oa1client0000000000",
        subject=principal.uid,
        scopes=[SCOPE] if scopes is None else scopes,
        principal=principal,
    )


class FakeVerifier:
    """Stands in for 4.3's verifier: a fixed token → result table."""

    def __init__(self, tokens: dict[str, AccessToken], ready: bool = True) -> None:
        self.tokens = tokens
        self.is_ready = ready
        self.calls = 0

    async def verify_token(self, token: str) -> AccessToken | None:
        self.calls += 1
        return self.tokens.get(token)

    def ready(self) -> bool:
        return self.is_ready


TOKENS: dict[str, AccessToken] = {
    "reader": verified(caller(READERS)),
    "helpdesk": verified(caller(HELPDESK)),
    "no-scope": verified(caller(READERS), scopes=["openid"]),
    # A token the SDK accepts but that isn't ours: the handlers must refuse to serve it.
    "foreign": AccessToken(token="f", client_id="0oa1client0000000000", scopes=[SCOPE]),  # noqa: S106
}


class Okta:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.url.path == "/oauth2/v1/token":
            return httpx2.Response(
                200, json={"access_token": "svc", "token_type": "Bearer", "expires_in": 3600}
            )
        if request.url.path == "/api/v1/groups":
            return httpx2.Response(
                200, json=[{"id": GROUP, "type": "OKTA_GROUP", "profile": {"name": "Staff"}}]
            )
        return httpx2.Response(404, json={"errorSummary": "Not found"})


def write_key(tmp_path: Path) -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

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


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    values = {
        "MCP_PUBLIC_URL": PUBLIC,
        "MCP_ISSUER": ISSUER,
        "MCP_ALLOWED_CLIENT_IDS": "0oa1client0000000000",
        "MCP_ALLOWED_ORIGINS": ALLOWED,
        "MCP_POLICY_FILE": str(PILOT),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": ORG,
        "OKTA_SCOPES": "okta.groups.read okta.networkZones.read",
        "OKTA_CLIENT_ID": "0oa1service000000000",
        "OKTA_PRIVATE_KEY_FILE": str(write_key(tmp_path)),
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


@asynccontextmanager
async def serving(
    config: Config, verifier: FakeVerifier | None = None, okta: Okta | None = None
) -> AsyncIterator[Starlette]:
    async with new_http_client(httpx2.MockTransport(okta or Okta())) as http:
        runtime = build_runtime(config, http)
        app = build_app(runtime, config, verifier or FakeVerifier(TOKENS))
        async with app.router.lifespan_context(app):
            yield app


def http_for(app: Starlette, **headers: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://mcp.example.com", headers=headers
    )


@asynccontextmanager
async def mcp_client(app: Starlette, token: str, mode: str) -> AsyncIterator[Client]:
    async with (
        http_for(app, authorization=f"Bearer {token}") as http,
        Client(streamable_http_client(PUBLIC, http_client=http), mode=mode) as client,
    ):
        yield client


# --- health -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_healthz_needs_no_token(config: Config) -> None:
    async with serving(config) as app, http_for(app) as http:
        r = await http.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("ready", "status", "body"), [(True, 200, "ready"), (False, 503, "not ready")]
)
async def test_readyz_follows_the_verifier(
    config: Config, ready: bool, status: int, body: str
) -> None:
    verifier = FakeVerifier(TOKENS, ready=ready)
    async with serving(config, verifier) as app, http_for(app) as http:
        r = await http.get("/readyz")
    assert r.status_code == status
    assert r.json() == {"status": body}
    assert verifier.calls == 0


@pytest.mark.anyio
async def test_health_with_the_bind_host_header(config: Config) -> None:
    """The container healthcheck calls `http://127.0.0.1:8080/healthz` (design §11.2)."""
    async with serving(config) as app:
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as h:
            assert (await h.get("/healthz")).status_code == 200


# --- Origin -----------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/mcp", "/healthz", "/readyz"])
@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example.com",
        "null",
        "https://app.example.com:443",  # not the canonical form a browser sends
        "HTTPS://APP.EXAMPLE.COM",
        "https://app.example.com/",
        "http://app.example.com",
    ],
)
async def test_disallowed_origin_is_refused_before_auth(
    config: Config, path: str, origin: str
) -> None:
    verifier = FakeVerifier(TOKENS)
    async with serving(config, verifier) as app, http_for(app, origin=origin) as http:
        r = await http.post(
            path, json=INIT, headers={**JSON_HEADERS, "authorization": "Bearer reader"}
        )
    assert r.status_code == 403
    assert r.text == ORIGIN_REFUSED
    assert verifier.calls == 0


@pytest.mark.anyio
async def test_two_origin_headers_are_refused(config: Config) -> None:
    async with serving(config) as app, http_for(app) as http:
        r = await http.get("/healthz", headers=[("origin", ALLOWED), ("origin", ALLOWED)])
    assert r.status_code == 403


@pytest.mark.anyio
@pytest.mark.parametrize("headers", [{}, {"origin": ALLOWED}])
async def test_allowed_or_missing_origin_passes(config: Config, headers: dict[str, str]) -> None:
    async with serving(config) as app, http_for(app, **headers) as http:
        r = await http.post(
            "/mcp", json=INIT, headers={**JSON_HEADERS, "authorization": "Bearer reader"}
        )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_no_allowed_origins_refuses_every_origin(tmp_path: Path) -> None:
    config = load_config(env(tmp_path, MCP_ALLOWED_ORIGINS=""))
    async with serving(config) as app, http_for(app, origin=ALLOWED) as http:
        assert (await http.get("/healthz")).status_code == 403


@pytest.mark.anyio
async def test_public_host_is_served_with_a_loopback_bind(config: Config) -> None:
    """The SDK turns its Host check on by itself for a loopback bind (the default `MCP_HOST`);
    with it, every request through the proxy would get 421."""
    assert config.host == "127.0.0.1"
    async with serving(config) as app, http_for(app) as http:
        r = await http.post(
            "/mcp",
            json=INIT,
            headers={**JSON_HEADERS, "authorization": "Bearer reader", "host": "mcp.example.com"},
        )
    assert r.status_code == 200


# --- auth -------------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", [None, "Bearer unknown", "Basic cmVhZGVyOg=="])
async def test_mcp_without_a_valid_token_is_401(config: Config, authorization: str | None) -> None:
    headers = dict(JSON_HEADERS)
    if authorization:
        headers["authorization"] = authorization
    async with serving(config) as app, http_for(app) as http:
        r = await http.post("/mcp", json=INIT, headers=headers)
    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" in challenge


@pytest.mark.anyio
async def test_token_without_the_required_scope_is_403(config: Config) -> None:
    async with serving(config) as app, http_for(app) as http:
        r = await http.post(
            "/mcp", json=INIT, headers={**JSON_HEADERS, "authorization": "Bearer no-scope"}
        )
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_a_token_that_is_not_ours_is_never_served(config: Config, mode: str) -> None:
    async with serving(config) as app, mcp_client(app, "foreign", mode) as client:
        with pytest.raises(MCPError) as caught:
            await client.list_tools()
    assert caught.value.error.message == INTERNAL


# --- MCP over HTTP ----------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_tools_list_per_principal_and_private(config: Config, mode: str) -> None:
    async with serving(config) as app:
        async with mcp_client(app, "reader", mode) as client:
            reader = await client.list_tools()
            resources = await client.list_resources()
        async with mcp_client(app, "helpdesk", mode) as client:
            helpdesk = await client.list_tools()
    assert [t.name for t in reader.tools] == ["okta_groups", "okta_help", "okta_status"]
    assert [t.name for t in helpdesk.tools] == [
        "okta_groups",
        "okta_network_zones",
        "okta_help",
        "okta_status",
    ]
    if mode != "legacy":
        for listed in (reader, helpdesk, resources):
            assert listed.cache_scope == "private"
            assert listed.ttl_ms == LIST_TTL_MS


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_call_over_http(config: Config, mode: str) -> None:
    okta = Okta()
    async with serving(config, okta=okta) as app, mcp_client(app, "reader", mode) as client:
        result = await client.call_tool("okta_groups", {"command": "list"})
        status = await client.call_tool("okta_status", {})
    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["rows"] == [[GROUP, "OKTA_GROUP", "Staff"]]
    (block,) = status.content
    assert isinstance(block, types.TextContent)
    # The token's principal, not some other caller's.
    assert json.loads(block.text)["user"] == "user@example.com"
    assert [r.method for r in okta.requests] == ["POST", "GET"]
    assert okta.requests[0].url.path == "/oauth2/v1/token"


@pytest.mark.anyio
async def test_stateless_issues_no_session_id(config: Config) -> None:
    async with serving(config) as app, http_for(app) as http:
        r = await http.post(
            "/mcp", json=INIT, headers={**JSON_HEADERS, "authorization": "Bearer reader"}
        )
    assert r.status_code == 200
    assert "mcp-session-id" not in r.headers


# --- construction and uvicorn -----------------------------------------------------------


@pytest.mark.anyio
async def test_build_app_refuses_dev_mode(tmp_path: Path) -> None:
    principal = tmp_path / "principal.yaml"
    principal.write_text("uid: 00u1devuser000000000\nsub: dev@example.com\ngroups: []\n")
    config = load_config(env(tmp_path, MCP_DEV_MODE="1", MCP_DEV_PRINCIPAL_FILE=str(principal)))
    async with new_http_client(httpx2.MockTransport(Okta())) as http:
        runtime = build_runtime(config, http)
        with pytest.raises(ValueError, match="stdio only"):
            build_app(runtime, config, FakeVerifier(TOKENS))


@pytest.mark.anyio
@pytest.mark.parametrize("trust", [False, True])
async def test_uvicorn_config(tmp_path: Path, trust: bool) -> None:
    config = load_config(
        env(tmp_path, MCP_TRUST_PROXY=str(trust).lower(), MCP_HOST="0.0.0.0", MCP_PORT="9090")  # noqa: S104
    )
    async with serving(config) as app:
        settings = uvicorn_config(config, app)
    assert (settings.host, settings.port) == ("0.0.0.0", 9090)  # noqa: S104
    assert settings.proxy_headers is trust
    if trust:
        assert settings.forwarded_allow_ips == "*"
    assert settings.log_config is None
    assert settings.access_log is False
    assert settings.server_header is False
    assert settings.lifespan == "on"


class RaisingVerifier(FakeVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        self.calls += 1
        raise RuntimeError("JWKS not loaded")


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
async def test_health_never_runs_the_verifier(config: Config, path: str) -> None:
    """The health routes sit outside the SDK's auth middleware, which would verify any bearer
    header and fail with the verifier."""
    verifier = RaisingVerifier(TOKENS)
    async with serving(config, verifier) as app, http_for(app) as http:
        r = await http.get(path, headers={"authorization": "Bearer reader"})
    assert r.status_code == 200
    assert verifier.calls == 0


@pytest.mark.anyio
async def test_prm_is_served_at_the_path_url(config: Config) -> None:
    async with serving(config) as app, http_for(app) as http:
        r = await http.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    assert r.json()["resource"] == PUBLIC


def test_verified_token_must_name_its_principal() -> None:
    p = Principal(uid="00u1httpuser00000000", sub="user@example.com", groups=frozenset())
    for subject in (None, "user@example.com", "00u1other0000000000"):
        with pytest.raises(ValueError, match="must match its principal"):
            VerifiedToken(token="t", client_id="0oa1", scopes=[], subject=subject, principal=p)  # noqa: S106
    bound = Principal(uid=p.uid, sub=p.sub, groups=frozenset(), client_id="0oa1client0000000000")
    with pytest.raises(ValueError, match="must match its principal"):
        VerifiedToken(token="t", client_id="0oa2", scopes=[], subject=p.uid, principal=bound)  # noqa: S106
    VerifiedToken(
        token="t",  # noqa: S106
        client_id="0oa1client0000000000",
        scopes=[],
        subject=p.uid,
        principal=bound,
    )


@pytest.mark.anyio
async def test_serve_http_loads_everything_before_serving(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    served: list[uvicorn.Config] = []

    async def serve(self: uvicorn.Server) -> None:
        served.append(self.config)

    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    await serve_http(config, FakeVerifier(TOKENS))
    (settings,) = served
    assert isinstance(settings.app, Starlette)
    assert settings.log_config is None


@pytest.mark.anyio
async def test_serve_http_startup_error_comes_before_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("roles: nope\n")
    config = load_config(env(tmp_path, MCP_POLICY_FILE=str(bad)))
    served: list[object] = []

    async def serve(self: uvicorn.Server) -> None:
        served.append(self)

    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    with pytest.raises(PolicyError):
        await serve_http(config, FakeVerifier(TOKENS))
    assert served == []
