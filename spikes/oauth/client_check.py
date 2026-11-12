"""Step 0.6 client OAuth check (V3, V10, V11 per client). Throwaway; deleted after 0.6 and 4.6.

A minimal MCP server that real clients sign in to through the spike's custom AS (Path A):
401 + Protected Resource Metadata at both URLs (design §8.1), real JWT validation against the
issuer's JWKS, and one tool, `whoami`, that returns the caller's own claims. Every request is
logged as one line (method, path, auth header present, status) so the run shows which
discovery URLs each client tries. Tokens are never logged.

  uv run python spikes/oauth/client_check.py --issuer https://<org>/oauth2/<as> \
      [--client-id 0oa…]...   # MCP endpoint: http://127.0.0.1:8000/mcp
"""

import argparse
import logging
import sys
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import httpx2
import jwt
import mcp_types as types
import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import create_protected_resource_routes
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.routing import Route

SCOPE = "okta-mcp"
log = logging.getLogger("client_check")

ASGIApp = Callable[
    [MutableMapping[str, Any], Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[None]]],
    Awaitable[None],
]


class OktaVerifier:
    """Signature, `iss`, `aud`, `exp`/`iat` and `cid`; the SDK checks the scope (403)."""

    def __init__(
        self, issuer: str, audience: str, client_ids: frozenset[str], http: httpx2.AsyncClient
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.client_ids = client_ids
        self.http = http
        self._jwks: jwt.PyJWKSet | None = None

    async def _keys(self) -> jwt.PyJWKSet:
        if self._jwks is None:
            meta = await self.http.get(f"{self.issuer}/.well-known/openid-configuration")
            jwks = await self.http.get(meta.raise_for_status().json()["jwks_uri"])
            self._jwks = jwt.PyJWKSet.from_dict(jwks.raise_for_status().json())
        return self._jwks

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            key = (await self._keys())[str(kid)]
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=60,
                options={"require": ["exp", "iat", "uid", "cid"]},
            )
        except (jwt.PyJWTError, KeyError) as e:
            log.info("token rejected: %s", type(e).__name__)
            return None
        if self.client_ids and claims["cid"] not in self.client_ids:
            log.info("token rejected: cid not allowed")
            return None
        scopes = claims.get("scp", [])
        return AccessToken(
            token=token,
            client_id=claims["cid"],
            scopes=scopes if isinstance(scopes, list) else [],
            expires_at=claims["exp"],
            subject=claims["uid"],
            claims=claims,
        )


async def list_tools(
    ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    tool = types.Tool(
        name="whoami",
        description="Your own token claims as this server sees them (read-only).",
        input_schema={"type": "object", "properties": {}},
        annotations=types.ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    return types.ListToolsResult(tools=[tool], ttl_ms=60_000, cache_scope="private")


async def call_tool(
    ctx: ServerRequestContext, params: types.CallToolRequestParams
) -> types.CallToolResult:
    token = get_access_token()
    if params.name != "whoami" or token is None or token.claims is None:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="unknown tool")], is_error=True
        )
    keep = ("uid", "sub", "cid", "scp", "groups", "aud", "exp")
    text = str({k: token.claims.get(k) for k in keep})
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


def access_log(app: ASGIApp) -> ASGIApp:
    async def wrapped(
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[Any]],
        send: Callable[[Any], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        has_auth = any(k == b"authorization" for k, _ in scope["headers"])

        async def logged_send(message: Any) -> None:
            if message["type"] == "http.response.start":
                log.info(
                    "%s %s auth=%s -> %s",
                    scope["method"],
                    scope["path"],
                    "yes" if has_auth else "no",
                    message["status"],
                )
            await send(message)

        await app(scope, receive, logged_send)

    return wrapped


def build_app(
    issuer: str, resource: str, client_ids: frozenset[str], http: httpx2.AsyncClient
) -> Starlette:
    server = Server(
        "okta-mcp-client-check", version="0.0.0", on_list_tools=list_tools, on_call_tool=call_tool
    )
    # The SDK serves PRM only at the path-inserted URL; design §8.1 also serves the root.
    prm = create_protected_resource_routes(
        AnyHttpUrl(resource), [AnyHttpUrl(issuer)], scopes_supported=[SCOPE]
    )[0]
    root_prm = Route(
        "/.well-known/oauth-protected-resource", prm.endpoint, methods=["GET", "OPTIONS"]
    )
    return server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        host="127.0.0.1",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(issuer),
            resource_server_url=AnyHttpUrl(resource),
            required_scopes=[SCOPE],
            validate_token_resource=False,  # Okta ignores `resource` (V9)
        ),
        token_verifier=OktaVerifier(issuer, resource, client_ids, http),
        custom_starlette_routes=[root_prm],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Step 0.6 client OAuth check server")
    parser.add_argument("--issuer", required=True, help="spike custom AS issuer URL")
    parser.add_argument("--port", type=int, default=8000, help="must match the AS audience")
    parser.add_argument(
        "--client-id", action="append", default=[], help="allowed cid (repeat); default: any"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stdout)
    resource = f"http://127.0.0.1:{args.port}/mcp"
    http = httpx2.AsyncClient(timeout=10)
    app = build_app(args.issuer.rstrip("/"), resource, frozenset(args.client_id), http)
    uvicorn.run(access_log(app), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
