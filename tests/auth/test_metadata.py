"""Protected Resource Metadata and bearer challenges (plan 4.4, design §8.1)."""

import httpx2
import pytest
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from okta_mcp.auth.metadata import (
    INVALID,
    MISSING,
    NO_SCOPE,
    PRM_PATH,
    RequireToken,
    metadata,
    metadata_url,
    prm_routes,
)

PUBLIC = "https://mcp.example.com/mcp"
ISSUER = "https://example.okta.com/oauth2/aus1example000000000"
SCOPE = "okta-mcp"
PRM_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
DOC = {
    "resource": PUBLIC,
    "authorization_servers": [ISSUER],
    "scopes_supported": [SCOPE],
    "bearer_methods_supported": ["header"],
}


class Verifier:
    def __init__(self) -> None:
        self.calls = 0

    async def verify_token(self, token: str) -> AccessToken | None:
        self.calls += 1
        scopes = {"good": [SCOPE, "openid"], "no-scope": ["openid"]}.get(token)
        if scopes is None:
            return None
        return AccessToken(token=token, client_id="0oa1client0000000000", scopes=scopes)


async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    await PlainTextResponse("served")(scope, receive, send)


def app(verifier: Verifier) -> Starlette:
    """`RequireToken` behind the SDK's backend, as `app.build_app` wires it (minus readiness),
    and the PRM routes outside the authentication middleware, as the outer app has them."""
    inner = Starlette(
        routes=[Route("/mcp", RequireToken(endpoint, scope=SCOPE, public_url=PUBLIC))],
        middleware=[Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier))],
    )
    return Starlette(routes=[*prm_routes(PUBLIC, ISSUER, SCOPE), Mount("", app=inner)])


def client(verifier: Verifier) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app(verifier)), base_url="https://mcp.example.com"
    )


# --- metadata ---------------------------------------------------------------------------


def test_metadata_url_inserts_the_well_known_segment() -> None:
    assert metadata_url(PUBLIC) == PRM_URL
    assert metadata_url("https://mcp.example.com:8443/mcp") == (
        "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp"
    )


def test_metadata_values_are_the_config_strings_unchanged() -> None:
    # An issuer with no path must not gain a trailing slash: clients compare it with the AS
    # metadata's `issuer` exactly.
    doc = metadata(PUBLIC, "https://example.okta.com", SCOPE)
    assert doc["authorization_servers"] == ["https://example.okta.com"]
    assert metadata(PUBLIC, ISSUER, SCOPE) == DOC


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/.well-known/oauth-protected-resource/mcp", PRM_PATH])
async def test_prm_at_both_urls_without_running_the_verifier(path: str) -> None:
    verifier = Verifier()
    async with client(verifier) as http:
        r = await http.get(path, headers={"authorization": "Bearer good"})
        head = await http.head(path)
        pre = await http.options(
            path,
            headers={"origin": "https://app.example.com", "access-control-request-method": "GET"},
        )
    assert r.status_code == 200
    assert r.json() == DOC
    assert r.headers["cache-control"] == "public, max-age=3600"
    assert head.status_code == 200
    assert pre.status_code == 200
    assert "GET" in pre.headers["access-control-allow-methods"]
    assert verifier.calls == 0


# --- challenges -------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", [None, "Basic cmVhZGVyOg==", "Token good", "Bearer"])
async def test_no_bearer_token_is_401_without_an_error_code(authorization: str | None) -> None:
    """RFC 6750 §3.1: no error code when the request has no bearer token; MCP: `scope` in the
    challenge, which clients use first when choosing what to ask for."""
    headers = {"authorization": authorization} if authorization else {}
    async with client(Verifier()) as http:
        r = await http.post("/mcp", headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{PRM_URL}", scope="{SCOPE}"'
    )
    assert r.json() == {"error_description": MISSING}


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", ["Bearer unknown", "bearer unknown", "Bearer  good"])
async def test_a_bad_bearer_token_is_401_invalid_token(authorization: str) -> None:
    async with client(Verifier()) as http:
        r = await http.post("/mcp", headers={"authorization": authorization})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == (
        f'Bearer error="invalid_token", error_description="{INVALID}", '
        f'resource_metadata="{PRM_URL}", scope="{SCOPE}"'
    )
    assert r.json() == {"error": "invalid_token", "error_description": INVALID}


@pytest.mark.anyio
async def test_a_token_without_the_scope_is_403_insufficient_scope() -> None:
    async with client(Verifier()) as http:
        r = await http.post("/mcp", headers={"authorization": "Bearer no-scope"})
    assert r.status_code == 403
    assert r.headers["www-authenticate"] == (
        f'Bearer error="insufficient_scope", error_description="{NO_SCOPE}", '
        f'resource_metadata="{PRM_URL}", scope="{SCOPE}"'
    )


@pytest.mark.anyio
@pytest.mark.parametrize("authorization", ["Bearer good", "bearer good", "BEARER good"])
async def test_a_good_token_is_served(authorization: str) -> None:
    async with client(Verifier()) as http:
        r = await http.post("/mcp?x=access_token", headers={"authorization": authorization})
    assert r.status_code == 200
    assert r.text == "served"


# --- header only ------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("query", "authorization"),
    [
        ("access_token=good", None),
        ("access_token=good", "Bearer good"),
        ("access_token=", "Bearer good"),
        ("a=1&access_token", "Bearer good"),
    ],
)
async def test_a_token_in_the_query_is_400(query: str, authorization: str | None) -> None:
    """MCP: tokens MUST NOT be in the query string. Refused even beside a good header."""
    headers = {"authorization": authorization} if authorization else {}
    async with client(Verifier()) as http:
        r = await http.post(f"/mcp?{query}", headers=headers)
    assert r.status_code == 400
    assert r.headers["www-authenticate"].startswith('Bearer error="invalid_request"')
    assert "good" not in r.text
    assert "good" not in r.headers["www-authenticate"]


@pytest.mark.anyio
async def test_two_authorization_headers_are_400() -> None:
    """The SDK's backend reads only the first; a second one (say, added by a proxy) must not
    leave which token was meant to chance."""
    async with client(Verifier()) as http:
        r = await http.post(
            "/mcp", headers=[("authorization", "Bearer good"), ("authorization", "Bearer x")]
        )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


@pytest.mark.anyio
async def test_a_token_in_the_body_never_authenticates() -> None:
    async with client(Verifier()) as http:
        r = await http.post(
            "/mcp",
            content="access_token=good",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_require_token_without_auth_scope_keys_is_401() -> None:
    """Without the SDK's middleware in front (a wiring bug), nothing is served."""
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b""}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    require = RequireToken(endpoint, scope=SCOPE, public_url=PUBLIC)
    await require(
        {"type": "http", "method": "POST", "path": "/mcp", "headers": [], "query_string": b""},
        receive,  # type: ignore[arg-type]
        send,  # type: ignore[arg-type]
    )
    assert sent[0]["status"] == 401
