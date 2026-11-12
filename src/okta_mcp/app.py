"""The HTTP app: stateless Streamable HTTP at `/mcp`, `/healthz`, `/readyz` (design §4, §5.2,
§11.4).

`build_app` wraps the SDK's Streamable HTTP app around the same `mcp_server` stdio uses, with
the caller taken from the verified bearer token (`http_principal`). Authentication is never
optional here: `build_app` needs a `Verifier`, and the SDK's `RequireAuthMiddleware` answers
`/mcp` without a valid token with 401 before any handler runs. The verifier and its 401/403
details are steps 4.3 and 4.4.

`OriginGuard` is outermost and covers every route: a request whose
`Origin` header is not in `MCP_ALLOWED_ORIGINS` gets 403, and one without `Origin` (a
non-browser client) passes (§11.3, §12.1 DNS rebinding). The SDK's own Host/Origin check is
turned off: it is turned on automatically whenever the bind host is loopback, which is the
default `MCP_HOST`, and it would then refuse every `Host` but loopback, i.e. every request
through the TLS proxy.
"""

import logging
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol

import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from okta_mcp.auth.principal import Principal, VerifiedToken
from okta_mcp.config import MCP_PATH, Config
from okta_mcp.okta.client import new_http_client
from okta_mcp.server import Runtime, build_runtime, mcp_server

log = logging.getLogger(__name__)

ORIGIN_REFUSED = "Origin not allowed"


class Verifier(TokenVerifier, Protocol):
    """The SDK's bearer-token verifier, which returns a `VerifiedToken` for a valid token and
    `None` otherwise, plus whether it can verify at all yet (JWKS loaded, §11.3). 4.3 builds
    it."""

    def ready(self) -> bool: ...


def http_principal() -> Principal:
    """The caller of the current HTTP request, from the token the SDK's auth middleware put in
    the request context. Raises if there is none or it isn't ours, which `_Guard` answers with
    the fixed internal error: a handler never runs as nobody."""
    token = get_access_token()
    if not isinstance(token, VerifiedToken):
        raise RuntimeError("no verified token in the request context")
    return token.principal


class OriginGuard:
    """ASGI middleware: 403 for an `Origin` header not in `allowed` (canonical origins, as
    `Config` holds them), and for more than one `Origin` header. Compared as exact strings:
    browsers send the canonical serialization (lowercase scheme and host, no default port), so
    anything else is not a browser we allow. `null` (an opaque origin) is never allowed."""

    def __init__(self, app: ASGIApp, allowed: tuple[str, ...]) -> None:
        self.app = app
        self.allowed = frozenset(allowed)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            headers: list[tuple[bytes, bytes]] = scope["headers"]
            origins = [v for k, v in headers if k.lower() == b"origin"]
            if len(origins) > 1 or (origins and origins[0].decode("latin-1") not in self.allowed):
                # DEBUG: the requests are the sender's to repeat, and a log line each would
                # let them flood the logs.
                log.debug("refused a request with a disallowed Origin header")
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                    return
                response = PlainTextResponse(ORIGIN_REFUSED, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _health_routes(ready: Callable[[], bool]) -> list[Route]:
    """Unauthenticated and data-free (§11.4). `/readyz` asks `ready()`, which reads state
    (e.g. whether the JWKS is loaded) and never fetches."""

    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(request: Request) -> Response:
        if ready():
            return JSONResponse({"status": "ready"})
        return JSONResponse({"status": "not ready"}, status_code=503)

    return [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]


def _lifespan_of(inner: Starlette) -> Callable[[Starlette], AbstractAsyncContextManager[None]]:
    """The outer app's lifespan runs `inner`'s (the SDK's session manager): Starlette doesn't
    run a mounted app's lifespan."""

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncGenerator[None]:
        async with inner.router.lifespan_context(inner):
            yield

    return lifespan


def build_app(runtime: Runtime, config: Config, verifier: Verifier) -> Starlette:
    """The ASGI app for `runtime`. Refuses a dev-mode `Config` (dev mode is stdio only, §8.6)
    and one without the HTTP auth settings, which `Config` requires outside dev mode.

    Two layers: an outer app with `OriginGuard` and the health routes, and the SDK's app (its
    auth middleware, `/mcp` and PRM) mounted under it. The health routes are outside the SDK's
    `AuthenticationMiddleware`, which runs the verifier on any request with a bearer header,
    so a probe never verifies a token and stays 200 while the verifier can't."""
    if config.dev_mode:
        raise ValueError("dev mode is stdio only; the HTTP app always authenticates")
    if config.public_url is None or config.issuer is None:
        raise ValueError("Config without MCP_PUBLIC_URL or MCP_ISSUER")
    server = mcp_server(runtime, http_principal)
    mcp = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.issuer),
            resource_server_url=AnyHttpUrl(config.public_url),
            required_scopes=[config.required_scope],
            # Okta ignores RFC 8707 `resource` (V9); the verifier checks `aud` (§8.5).
            validate_token_resource=False,
        ),
        token_verifier=verifier,
    )
    return Starlette(
        routes=[*_health_routes(verifier.ready), Mount("", app=mcp)],
        middleware=[Middleware(OriginGuard, allowed=config.allowed_origins)],
        lifespan=_lifespan_of(mcp),
    )


def uvicorn_config(config: Config, app: Starlette) -> uvicorn.Config:
    """Uvicorn settings. `log_config=None` keeps `configure_logging` in charge (uvicorn would
    otherwise install its own handlers and log at INFO); no access log, no `Server` header.
    `X-Forwarded-*` is honored only with `MCP_TRUST_PROXY` (uvicorn's default trusts it from
    127.0.0.1); when on, from any peer, since the server is meant to be reachable only through
    the proxy (§11.4)."""
    return uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        lifespan="on",
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=config.trust_proxy,
        forwarded_allow_ips="*" if config.trust_proxy else None,
    )


async def serve_http(config: Config, verifier: Verifier) -> None:
    """Serve the HTTP app until stopped. Everything is loaded, and every startup error raised,
    before the port opens."""
    async with new_http_client() as http:
        runtime = build_runtime(config, http)
        app = build_app(runtime, config, verifier)
        log.info("serving %s on %s:%d", MCP_PATH, config.host, config.port)
        await uvicorn.Server(uvicorn_config(config, app)).serve()
