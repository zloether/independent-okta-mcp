"""The HTTP app: stateless Streamable HTTP at `/mcp`, `/healthz`, `/readyz` (design §4, §5.2,
§11.4).

`build_app` wraps the SDK's Streamable HTTP app around the same `mcp_server` stdio uses, with
the caller taken from the verified bearer token (`http_principal`). Authentication is never
optional here: `build_app` needs a `Verifier`, and the SDK's `RequireAuthMiddleware` answers
`/mcp` without a valid token with 401 before any handler runs. The verifier is
`okta_mcp.auth.verifier`; `serve_http` builds it and keeps its keys and the service token
fresh in the background.

`ReadyGate` wraps the SDK's `/mcp` endpoint and answers 503 + `Retry-After` while the verifier
isn't ready (JWKS not loaded), token or not, so a valid token never gets 401 for it.

`OriginGuard` is outermost and covers every route: a request whose
`Origin` header is not in `MCP_ALLOWED_ORIGINS` gets 403, and one without `Origin` (a
non-browser client) passes (§11.3, §12.1 DNS rebinding). The SDK's own Host/Origin check is
turned off: it is turned on automatically whenever the bind host is loopback, which is the
default `MCP_HOST`, and it would then refuse every `Host` but loopback, i.e. every request
through the TLS proxy.
"""

import logging
import math
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol

import anyio
import httpx2
import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
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
from okta_mcp.auth.verifier import JWTVerifier
from okta_mcp.config import MCP_PATH, Config
from okta_mcp.logs import log_internal
from okta_mcp.okta.client import new_http_client
from okta_mcp.okta.token import keep_fresh
from okta_mcp.server import Runtime, build_runtime, mcp_server

log = logging.getLogger(__name__)

ORIGIN_REFUSED = "Origin not allowed"
NOT_READY = "server not ready; retry shortly"
RETRY_AFTER = "5"


class Verifier(TokenVerifier, Protocol):
    """The SDK's bearer-token verifier, which returns a `VerifiedToken` for a valid token and
    `None` otherwise, plus whether it can verify at all yet (JWKS loaded, §11.3):
    `okta_mcp.auth.verifier.JWTVerifier`."""

    def ready(self) -> bool: ...


class _FailClosed:
    """The verifier as the SDK's auth middleware sees it: an exception means "not
    authenticated" (`None`), never a 500, and never Starlette's `AuthenticationError` path,
    which sends the error's text back as the 400 body. That middleware runs on every request
    with a bearer header, on every route it serves (PRM, and anything that falls through to the
    SDK app). Logged by type and frames only: the message could hold the token. A verifier that
    isn't ready yet returns `None` and `ReadyGate` (inside the auth middleware, in front of
    `RequireAuthMiddleware`) answers 503; a raise here is a verifier bug."""

    def __init__(self, inner: Verifier) -> None:
        self.inner = inner

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return await self.inner.verify_token(token)
        except Exception as e:
            log_internal(log, "token verification", e)
            return None


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


READY_LOG_EVERY = 60.0
"""At most one log line per this many seconds for a readiness check that raises: `/readyz`
and `/mcp` call it on every request, which senders control."""


def _ready_or_not(
    ready: Callable[[], bool], monotonic: Callable[[], float] = time.monotonic
) -> Callable[[], bool]:
    """`ready`, with an exception counted as not ready (logged by type and frames, at most once
    per `READY_LOG_EVERY`), so neither `ReadyGate` nor `/readyz` turns a broken check into a
    500."""
    last = -math.inf

    def checked() -> bool:
        nonlocal last
        try:
            return ready()
        except Exception as e:
            if (now := monotonic()) - last >= READY_LOG_EVERY:
                last = now
                log_internal(log, "readiness check", e)
            return False

    return checked


READY_KEY = "okta_mcp.ready"
"""ASGI scope key: whether the verifier was ready when the request arrived."""


class ReadySnapshot:
    """ASGI middleware, before the SDK's auth: records `ready()` once per request in the scope,
    for `ReadyGate`, so a request the verifier saw while not ready (and so answered `None`) is
    never let through to `RequireAuthMiddleware` as 401 because the keys loaded in between.
    Runs on every route (cheap: it reads state), since the route isn't known yet."""

    def __init__(self, app: ASGIApp, ready: Callable[[], bool]) -> None:
        self.app = app
        self.ready = ready

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope[READY_KEY] = self.ready()
        await self.app(scope, receive, send)


class ReadyGate:
    """ASGI app wrapped around the SDK's `/mcp` endpoint, outside its `RequireAuthMiddleware`:
    503 + `Retry-After` unless the verifier was ready both when the request arrived
    (`ReadySnapshot`, before the SDK's auth) and is still ready now (§11.3: JWKS loaded).
    Without it a verifier that can't verify would answer a valid token with 401
    `invalid_token`, and clients would throw the token away and sign in again in a loop. These
    two readings are the only ones (the verifier doesn't read readiness), so keys loading or
    expiring mid-request can only mean 503, never 401 for a valid token. Wrapping the
    endpoint, not matching paths, means the gate sees exactly the requests the endpoint
    serves. No snapshot (a wiring bug) is not ready."""

    def __init__(self, app: ASGIApp, ready: Callable[[], bool]) -> None:
        self.app = app
        self.ready = ready

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not (scope.get(READY_KEY) is True and self.ready()):
            response = JSONResponse(
                {"error": NOT_READY}, status_code=503, headers={"Retry-After": RETRY_AFTER}
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _gate_endpoint(app: Starlette, ready: Callable[[], bool]) -> None:
    """Put `ReadyGate` in front of the SDK's `/mcp` route, which must exist exactly once."""
    routes = [r for r in app.router.routes if isinstance(r, Route) and r.path == MCP_PATH]
    if len(routes) != 1:
        raise RuntimeError(f"expected one SDK route at {MCP_PATH}, found {len(routes)}")
    routes[0].app = ReadyGate(routes[0].app, ready)


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

    Two layers: an outer app (middleware `OriginGuard`, then `ReadySnapshot`; routes
    `/healthz`, `/readyz`) and the SDK's app (its auth middleware, `/mcp` and PRM) mounted under
    it, with `ReadyGate` around its `/mcp` endpoint. The order matters: Origin first, so a
    refused page learns nothing; the readiness snapshot before the SDK's auth and the gate
    before `RequireAuthMiddleware`, so a cold verifier means 503, not 401. `/readyz` also needs
    a service token (§11.4); `/mcp` doesn't wait for one, since a call fetches it. The health
    routes are outside the SDK's `AuthenticationMiddleware`, which runs the verifier on any
    request with a bearer header, so a GET or HEAD probe never verifies a token. Anything else
    falls through to the SDK app, where `_FailClosed` keeps a failing verifier from turning it
    into a 500."""
    if config.dev_mode:
        raise ValueError("dev mode is stdio only; the HTTP app always authenticates")
    if config.public_url is None or config.issuer is None:
        raise ValueError("Config without MCP_PUBLIC_URL or MCP_ISSUER")
    server = mcp_server(runtime, http_principal)
    can_verify = _ready_or_not(verifier.ready)
    has_token = _ready_or_not(runtime.tokens.ready)
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
        token_verifier=_FailClosed(verifier),
    )
    _gate_endpoint(mcp, can_verify)
    return Starlette(
        routes=[
            *_health_routes(lambda: can_verify() and has_token()),
            Mount("", app=mcp),
        ],
        middleware=[
            Middleware(OriginGuard, allowed=config.allowed_origins),
            Middleware(ReadySnapshot, ready=can_verify),
        ],
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


async def serve_http(config: Config, transport: httpx2.AsyncBaseTransport | None = None) -> None:
    """Serve the HTTP app until stopped. Everything is loaded, and every startup error raised,
    before the port opens; the issuer need not be reachable (§11.3): the verifier loads its
    keys in the background, and `/mcp` is 503 until it has. The service token is fetched in
    the background too, for `/readyz`. `transport` is for tests."""
    async with new_http_client(transport) as http:
        runtime = build_runtime(config, http)
        verifier = JWTVerifier(http, config)
        app = build_app(runtime, config, verifier)
        async with anyio.create_task_group() as tg:
            tg.start_soon(verifier.run)
            tg.start_soon(keep_fresh, runtime.tokens)
            log.info("serving %s on %s:%d", MCP_PATH, config.host, config.port)
            await uvicorn.Server(uvicorn_config(config, app)).serve()
            tg.cancel_scope.cancel()
