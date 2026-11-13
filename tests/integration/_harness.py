"""The integration harness (plan 4.5): the server as `serve_http` wires it, with the real
`JWTVerifier`, a mocked custom authorization server (metadata and a local JWKS) and a mocked
Okta org on one transport. Fixtures are in `conftest.py`; tests in `test_http.py` (auth,
per-principal surface, protocol) and `test_limits.py` (limits and operational logs, plan 6.2).
"""

import json
import re
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx2
import jwt
import mcp_types as types
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

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

EXPIRED: Any = object()
"""Stands for an `exp` two minutes before the test runs."""

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


Running = Callable[..., Any]


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


CHALLENGE_PARAM = re.compile(r'([a-z_]+)="([^"\\]*)"(?:, |$)')


def challenge_params(header: str) -> dict[str, str]:
    """The auth-params of a `Bearer` challenge. The whole header must be `name="value"` pairs
    joined by `, ` with no quote or backslash in a value (what `RequireToken` promises), or
    the parse fails rather than skipping a malformed part."""
    scheme, _, rest = header.partition(" ")
    assert scheme == "Bearer"
    pairs = list(CHALLENGE_PARAM.finditer(rest))
    assert "".join(m.group(0) for m in pairs) == rest, header
    return {m.group(1): m.group(2) for m in pairs}
