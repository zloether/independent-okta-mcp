"""The Okta Management API client (design §6.5).

GET only: `OktaClient.get` is the one way the server reads from Okta. Each call checks the URL
is on `OKTA_ORG_URL` before anything is sent, holds one of `MCP_OKTA_MAX_INFLIGHT` slots, attaches
the service token (and a fresh DPoP proof for a DPoP token), retries once for a `use_dpop_nonce`
error, and turns any non-2xx response, and a failure to get the service token, into an
`UpstreamError`. The provider logs a token failure's hint for the operator; callers get a fixed
message. Deadlines are the caller's (`anyio.fail_after`); cancelling one aborts the request in
flight and frees its slot.
"""

import logging
from collections.abc import Callable, Mapping

import anyio
import httpx2

from okta_mcp.okta.dpop import DPoP, use_dpop_nonce
from okta_mcp.okta.token import ServiceToken, TokenError, TokenProvider

log = logging.getLogger(__name__)

_SUMMARY_MAX = 500


class OriginError(Exception):
    """A URL that isn't on the Okta org; nothing was sent."""


class UpstreamError(Exception):
    """Okta answered with an error, or didn't answer (`status` None). The message is safe to
    return to the caller: 401/403 never carry Okta's text."""

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


def new_http_client(transport: httpx2.AsyncBaseTransport | None = None) -> httpx2.AsyncClient:
    """The one `AsyncClient` for Okta, shared with the token provider. TLS is verified against the
    system trust store, and redirects are never followed: a followed redirect would replay the
    client assertion or a token off the org."""
    return httpx2.AsyncClient(
        verify=True,
        follow_redirects=False,
        timeout=httpx2.Timeout(30, connect=10),
        transport=transport,
    )


def _origin(url: httpx2.URL) -> tuple[str, str, int | None, str]:
    return url.scheme, url.host, url.port, url.userinfo.decode()


class OktaClient:
    def __init__(
        self,
        http: httpx2.AsyncClient,
        *,
        org_url: str,
        tokens: TokenProvider,
        dpop: DPoP | None,
        max_inflight: int,
        on_request: Callable[[], None] | None = None,
    ) -> None:
        """`dpop` is the instance the token provider was given, so token and resource proofs
        share one key and nonce. `on_request` runs before every request sent to Okta, nonce
        retries included (the per-principal limiter's counter)."""
        self._http = http
        self._origin = _origin(httpx2.URL(org_url))
        self._tokens = tokens
        self._dpop = dpop
        self._slots = anyio.Semaphore(max_inflight)
        self._on_request = on_request

    async def get(self, url: str, params: Mapping[str, str] | None = None) -> httpx2.Response:
        """A 2xx response for `url` (absolute, on the org) with `params` merged into its query
        (a key in both takes the `params` value)."""
        try:
            target = httpx2.URL(url)
        except httpx2.InvalidURL:
            target = None
        if target is None or _origin(target) != self._origin:
            raise OriginError("URL is not on the Okta org")
        if params:
            target = target.copy_merge_params(params)
        async with self._slots:
            token, response = await self._send(target)
            if self._dpop is not None and self._dpop.needs_retry(response):
                token, response = await self._send(target)
                self._dpop.needs_retry(response)  # records a rotated nonce; no second retry
        if response.is_success:
            return response
        # Only a nonce challenge is known to be about the proof, not the token; any other 401
        # (`invalid_dpop_proof` included, as Okta's shape for an expired token is unconfirmed)
        # drops it.
        if response.status_code == 401 and not use_dpop_nonce(response):
            self._tokens.invalidate(token)
        raise self._error(response)

    async def _send(self, url: httpx2.URL) -> tuple[ServiceToken, httpx2.Response]:
        try:
            token = await self._tokens.token()
        except TokenError:
            token = None
        # Raised outside `except`: the TokenError's hint is for the operator log only.
        if token is None:
            raise UpstreamError(
                None, "Okta service credentials are unavailable; contact the MCP administrator"
            )
        request = self._http.build_request("GET", url)
        request.headers["Accept"] = "application/json"
        request.headers["Authorization"] = token.authorization
        if token.scheme == "DPoP":
            if self._dpop is None:
                raise RuntimeError("DPoP token but the Okta client has no DPoP key")
            request.headers["DPoP"] = self._dpop.proof("GET", str(request.url), token.value)
        if self._on_request is not None:
            self._on_request()
        try:
            return token, await self._http.send(request)
        except httpx2.HTTPError as e:
            reason = type(e).__name__
        # Raised outside `except`: the httpx error holds the request and its Authorization header.
        raise UpstreamError(None, f"Okta request failed: {reason}")

    def _error(self, response: httpx2.Response) -> UpstreamError:
        status = response.status_code
        if status in (401, 403):
            log.warning("Okta refused the service app's request: HTTP %d", status)
            return UpstreamError(
                status, f"Okta refused the request (HTTP {status}); contact the MCP administrator"
            )
        try:
            body = response.json()
        except (ValueError, UnicodeDecodeError):
            body = None
        match body:
            case {"errorSummary": str(summary)} if summary:
                return UpstreamError(
                    status, f"Okta returned HTTP {status}: {summary[:_SUMMARY_MAX]}"
                )
            case _:
                return UpstreamError(status, f"Okta returned HTTP {status}")
