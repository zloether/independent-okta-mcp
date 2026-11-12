"""Protected Resource Metadata and the bearer challenges (design §8.1, RFC 9728, RFC 6750).

What the SDK doesn't do, and why this module exists:

- **PRM at the root URL.** The SDK serves PRM only at the path-inserted URL
  (`/.well-known/oauth-protected-resource/mcp`); §8.1 also serves it at
  `/.well-known/oauth-protected-resource` for clients that only try the root. `prm_routes`
  serves both from one document, written from `Config` as is (it holds canonical URLs), so the
  `resource` and `authorization_servers` values are exactly `MCP_PUBLIC_URL` and `MCP_ISSUER`
  with no URL normalization in between. `app.build_app` puts these routes in the outer app,
  outside the SDK's authentication middleware, so fetching PRM never runs the verifier.
- **The challenges.** The SDK's `RequireAuthMiddleware` sends `error="invalid_token"` even
  when no token was sent (RFC 6750 §3.1: no error code then) and never sends `scope`, which
  the MCP spec (2025-11-25, "Scope Selection Strategy") says clients read first. `RequireToken`
  replaces it around the `/mcp` endpoint.
- **Header only.** The SDK's backend reads only the `Authorization` header, so a token
  anywhere else never authenticates. `RequireToken` also refuses, with 400
  `invalid_request`, a request that carries `access_token` in the query (the MCP spec: tokens
  MUST NOT be in the query string) or more than one `Authorization` header (RFC 6750 §2: one
  method per request; the backend would read only the first).

Every value in a challenge is fixed text or comes from `Config`, which keeps them free of
quotes, backslashes and control characters (`MCP_PUBLIC_URL` canonical, `MCP_REQUIRED_SCOPE`
an RFC 6749 scope-token). Nothing from the request is echoed.
"""

import json
from urllib.parse import parse_qsl, urlsplit

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from pydantic import AnyHttpUrl
from starlette.authentication import AuthCredentials
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

PRM_PATH = "/.well-known/oauth-protected-resource"
PRM_MAX_AGE = 3600

MISSING = "a bearer token is required"
INVALID = "the access token is not valid"
NO_SCOPE = "the access token lacks the required scope"
TWO_HEADERS = "send exactly one Authorization header"
IN_QUERY = "send the access token in the Authorization header, not the query"


def metadata_url(public_url: str) -> str:
    """The path-specific PRM URL for `public_url` (RFC 9728 §3.1), the one the challenges point
    at: the SDK's builder. `Config` holds `MCP_PUBLIC_URL` in the form `AnyHttpUrl` writes it,
    so the string is unchanged by the round trip."""
    return str(build_resource_metadata_url(AnyHttpUrl(public_url)))


def metadata(public_url: str, issuer: str, scope: str) -> dict[str, object]:
    """The PRM document (§8.1)."""
    return {
        "resource": public_url,
        "authorization_servers": [issuer],
        "scopes_supported": [scope],
        "bearer_methods_supported": ["header"],
    }


def prm_routes(public_url: str, issuer: str, scope: str) -> list[Route]:
    """GET (and HEAD, OPTIONS) routes for the PRM document at the path-specific and the root
    URL. Public and data-free; CORS as the SDK does it (any origin may read it), though
    `OriginGuard`, outside these, still refuses an `Origin` not in `MCP_ALLOWED_ORIGINS`."""
    body = metadata(public_url, issuer, scope)

    async def prm(request: Request) -> Response:
        return JSONResponse(body, headers={"Cache-Control": f"public, max-age={PRM_MAX_AGE}"})

    endpoint = cors_middleware(prm, ["GET", "OPTIONS"])
    paths = [urlsplit(metadata_url(public_url)).path, PRM_PATH]
    return [Route(path, endpoint=endpoint, methods=["GET", "OPTIONS"]) for path in paths]


def _quoted(**params: str) -> str:
    return ", ".join(f'{k}="{v}"' for k, v in params.items())


class RequireToken:
    """ASGI app in front of the `/mcp` endpoint, after the SDK's authentication middleware
    (which set `scope["user"]` and `scope["auth"]` from the verifier). In order:

    1. `access_token` in the query, or more than one `Authorization` header → 400
       `invalid_request`.
    2. Not authenticated → 401 with `resource_metadata` and `scope`; `error="invalid_token"`
       only when a bearer token was sent.
    3. Authenticated without `scope` → 403 `insufficient_scope`, with `scope` and
       `resource_metadata`.

    Anything else reaches `app`. Not a listed check here, by design: which tokens authenticate
    (the verifier's job, §8.5) and readiness (`app.ReadyGate`, outside this, answers 503
    first)."""

    def __init__(self, app: ASGIApp, *, scope: str, public_url: str) -> None:
        self.app = app
        self.scope = scope
        self.resource_metadata = metadata_url(public_url)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        auths = [v for k, v in headers if k.lower() == b"authorization"]
        query = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        if any(k == "access_token" for k, _ in query):
            await self._refuse(scope, receive, send, 400, "invalid_request", IN_QUERY)
            return
        if len(auths) > 1:
            await self._refuse(scope, receive, send, 400, "invalid_request", TWO_HEADERS)
            return
        if not isinstance(scope.get("user"), AuthenticatedUser):
            # The same test as the SDK's backend for "a bearer token was sent".
            if auths and auths[0][:7].lower() == b"bearer ":
                await self._refuse(scope, receive, send, 401, "invalid_token", INVALID)
            else:
                await self._refuse(scope, receive, send, 401, None, MISSING)
            return
        credentials = scope.get("auth")
        if not isinstance(credentials, AuthCredentials) or self.scope not in credentials.scopes:
            await self._refuse(scope, receive, send, 403, "insufficient_scope", NO_SCOPE)
            return
        await self.app(scope, receive, send)

    async def _refuse(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        status: int,
        error: str | None,
        description: str,
    ) -> None:
        params = {"error": error, "error_description": description} if error else {}
        challenge = "Bearer " + _quoted(
            **params, resource_metadata=self.resource_metadata, scope=self.scope
        )
        response = Response(
            json.dumps(params or {"error_description": description}),
            status_code=status,
            media_type="application/json",
            headers={"WWW-Authenticate": challenge},
        )
        await response(scope, receive, send)
