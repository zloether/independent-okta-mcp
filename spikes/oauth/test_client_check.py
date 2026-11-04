"""Run: uv run pytest spikes/oauth"""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import jwt
import pytest
from client_check import build_app
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://example.okta.com/oauth2/aus1"
RESOURCE = "http://127.0.0.1:8000/mcp"
CID = "0oa1client"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True) | {"kid": "k1", "alg": "RS256"}
LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "whoami"}}


def okta(request: httpx2.Request) -> httpx2.Response:
    if request.url.path.endswith("/openid-configuration"):
        return httpx2.Response(200, json={"jwks_uri": f"{ISSUER}/v1/keys"})
    return httpx2.Response(200, json={"keys": [JWK]})


def token(**overrides: Any) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "iat": now,
        "exp": now + 600,
        "uid": "00u1user",
        "sub": "jane@example.com",
        "cid": CID,
        "scp": ["openid", "okta-mcp"],
        "groups": ["00g1group"],
    } | overrides
    return jwt.encode(
        {k: v for k, v in claims.items() if v is not None}, KEY, "RS256", headers={"kid": "k1"}
    )


@asynccontextmanager
async def http_for(
    client_ids: frozenset[str] = frozenset({CID}),
) -> AsyncIterator[httpx2.AsyncClient]:
    upstream = httpx2.AsyncClient(transport=httpx2.MockTransport(okta))
    app = build_app(ISSUER, RESOURCE, client_ids, upstream)
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
    }
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
            headers=headers,
        ) as http,
    ):
        yield http


def bearer(t: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_unauthenticated_gets_401_with_prm() -> None:
    async with http_for() as http:
        r = await http.post("/mcp", json=LIST)
    assert r.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp" in r.headers["www-authenticate"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "path", ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]
)
async def test_prm_at_both_urls(path: str) -> None:
    async with http_for() as http:
        r = await http.get(path)
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == RESOURCE
    assert body["authorization_servers"] == [ISSUER]
    assert body["scopes_supported"] == ["okta-mcp"]


@pytest.mark.anyio
async def test_valid_token_calls_whoami() -> None:
    async with http_for() as http:
        r = await http.post("/mcp", json=CALL, headers=bearer(token()))
    assert r.status_code == 200
    text = r.json()["result"]["content"][0]["text"]
    assert "00u1user" in text
    assert "00g1group" in text


@pytest.mark.anyio
@pytest.mark.parametrize(
    "bad",
    [
        {"aud": "https://other.example.com/mcp"},
        {"iss": "https://example.okta.com/oauth2/default"},
        {"exp": int(time.time()) - 600},
        {"uid": None},
        {"cid": "0oa1other"},
    ],
)
async def test_bad_claims_are_401(bad: dict[str, Any]) -> None:
    async with http_for() as http:
        r = await http.post("/mcp", json=LIST, headers=bearer(token(**bad)))
    assert r.status_code == 401


@pytest.mark.anyio
async def test_any_cid_when_no_allow_list() -> None:
    async with http_for(frozenset()) as http:
        r = await http.post("/mcp", json=LIST, headers=bearer(token(cid="0oa1other")))
    assert r.status_code == 200


@pytest.mark.anyio
async def test_missing_scope_is_403() -> None:
    async with http_for() as http:
        r = await http.post("/mcp", json=LIST, headers=bearer(token(scp=["openid"])))
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]


@pytest.mark.anyio
@pytest.mark.parametrize("alg", ["HS256", "none"])
async def test_non_rs256_rejected(alg: str) -> None:
    claims = jwt.decode(token(), options={"verify_signature": False})
    key = "x" * 32 if alg == "HS256" else None
    forged = jwt.encode(claims, key, alg, headers={"kid": "k1"})  # pyright: ignore[reportArgumentType]
    async with http_for() as http:
        r = await http.post("/mcp", json=LIST, headers=bearer(forged))
    assert r.status_code == 401
