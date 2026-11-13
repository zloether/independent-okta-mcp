"""The Okta Management API client (design §6.5).

GET only: `OktaClient.get` is the one way the server reads from Okta. Each call checks the URL
is on `OKTA_ORG_URL` before anything is sent, holds one of the principal's share of slots
(`ratelimit.InflightShare`) and then one of `MCP_OKTA_MAX_INFLIGHT` slots, attaches
the service token (and a fresh DPoP proof for a DPoP token), retries once for a `use_dpop_nonce`
error and once after a 429 (`ratelimit.retry_wait`; else `RateLimited`), and turns any other
non-2xx response, and a failure to get the service token, into an `UpstreamError`. The provider
logs a token failure's hint for the operator; callers get a fixed message. Deadlines are the
caller's (`anyio.fail_after`); cancelling one aborts the request in flight and frees its slot.
"""

import logging
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from typing import Any

import anyio
import httpx2

from okta_mcp.logs import event
from okta_mcp.okta.dpop import DPoP, use_dpop_nonce
from okta_mcp.okta.ratelimit import InflightShare, rate_limited, retry_wait
from okta_mcp.okta.token import ServiceToken, TokenError, TokenProvider

log = logging.getLogger(__name__)

_SUMMARY_MAX = 500
_FEATURE_OFF = "E0000015"


class OriginError(Exception):
    """A URL that isn't on the Okta org; nothing was sent."""


class UpstreamError(Exception):
    """Okta answered with an error, or didn't answer (`status` None). The message is safe to
    return to the caller: 401/403 never carry Okta's text."""

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


def json_body(response: httpx2.Response) -> Any:
    """The response's JSON, or `None` if it isn't JSON."""
    try:
        return response.json()
    except (ValueError, UnicodeDecodeError):
        return None


def _feature_off(response: httpx2.Response) -> bool:
    """Okta's "feature not enabled on the org" error (e.g. group owners), which says nothing
    about the token. A token challenge alongside it means the token was refused too."""
    if "WWW-Authenticate" in response.headers:
        return False
    match json_body(response):
        case {"errorCode": str(code)}:
            return code == _FEATURE_OFF
        case _:
            return False


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


def on_origin(url: httpx2.URL, origin: httpx2.URL) -> bool:
    """`url` has `origin`'s scheme, host and port, and no userinfo. The one origin check, used
    by the client before a token is attached, by `paginate` on next links, and by
    `exec.params.build_url` and `exec.cursor.resume_url` on the URLs they build (design §6.4,
    §6.5). httpx2 has already lower-cased the host and dropped a default port."""
    return (url.scheme, url.host, url.port) == (
        origin.scheme,
        origin.host,
        origin.port,
    ) and not url.userinfo


class OktaClient:
    def __init__(
        self,
        http: httpx2.AsyncClient,
        *,
        org_url: str,
        tokens: TokenProvider,
        dpop: DPoP | None,
        max_inflight: int,
        rate_limit_max_wait: float,
        on_request: Callable[[], None] | None = None,
        on_sent: Callable[[int | None], None] | None = None,
        share: InflightShare | None = None,
    ) -> None:
        """`dpop` is the instance the token provider was given, so token and resource proofs
        share one key and nonce. `on_request` (`RequestLimiter.charge`) runs once per request
        to Okta, nonce and 429 retries included: before the slot and the token are taken, and
        for a 429 retry before the wait. What it raises propagates. `on_sent`
        (`audit.record_sent`) runs once per request actually sent, with the response's status
        or None for a transport error or a cancellation: a request attempted, which may not
        have reached Okta. `share`, if given, is taken before a global slot, so a principal's
        waiting requests don't hold slots others could use."""
        self._http = http
        self._origin = httpx2.URL(org_url)
        self._tokens = tokens
        self._dpop = dpop
        self._slots = anyio.Semaphore(max_inflight)
        self._max_wait = rate_limit_max_wait
        self._on_request = on_request
        self._on_sent = on_sent
        self._share = share

    async def get(
        self, url: str, params: Mapping[str, str | list[str]] | None = None
    ) -> httpx2.Response:
        """A 2xx response for `url` (absolute, on the org) with `params` merged into its query
        (a key in both takes the `params` value; a list is sent as repeated keys)."""
        try:
            target = httpx2.URL(url)
        except httpx2.InvalidURL:
            target = None
        if target is None or not on_origin(target, self._origin):
            raise OriginError("URL is not on the Okta org")
        if params:
            target = target.copy_merge_params(params)
        self._charge()
        token, response = await self._attempt(target)
        if response.status_code == 429:
            wait = retry_wait(response, self._max_wait)
            self._charge()  # before the wait: a principal at its limit fails now, not after it
            log.warning(
                "Okta rate limit hit; retrying in %.1f s",
                wait,
                extra=event("okta_rate_limited", retry=True, wait_s=round(wait, 1)),
            )
            await anyio.sleep(wait)
            token, response = await self._attempt(target)
            if response.status_code == 429:
                log.warning(
                    "Okta rate limit hit again; giving up",
                    extra=event("okta_rate_limited", retry=False),
                )
                raise rate_limited(response)
        if response.is_success:
            return response
        # Only a nonce challenge (about the proof) and a disabled feature are known not to be
        # about the token; any other 401 (`invalid_dpop_proof` included, as Okta's shape for an
        # expired token is unconfirmed) drops it.
        if (
            response.status_code == 401
            and not use_dpop_nonce(response)
            and not _feature_off(response)
        ):
            self._tokens.invalidate(token)
        raise self._error(response)

    def _charge(self) -> None:
        if self._on_request is not None:
            self._on_request()

    def _sent(self, status: int | None) -> None:
        if self._on_sent is not None:
            self._on_sent(status)

    async def _attempt(self, url: httpx2.URL) -> tuple[ServiceToken, httpx2.Response]:
        """One request in one slot, with the nonce retry. The caller has charged the first
        request. The slot is free during a 429 wait."""
        async with self._share_slot(), self._slots:
            token, response = await self._send(url)
            if self._dpop is not None and self._dpop.needs_retry(response):
                log.debug("Okta asked for a DPoP nonce; retrying", extra=event("dpop_nonce_retry"))
                self._charge()
                token, response = await self._send(url)
                self._dpop.needs_retry(response)  # records a rotated nonce; no second retry
        return token, response

    def _share_slot(self) -> AbstractAsyncContextManager[None]:
        return nullcontext() if self._share is None else self._share.slot()

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
        try:
            response = await self._http.send(request)
        except httpx2.HTTPError as e:
            reason = type(e).__name__
        except BaseException:
            self._sent(None)  # cancelled in flight (the call's deadline): it was still sent
            raise
        else:
            self._sent(response.status_code)
            return token, response
        self._sent(None)
        # Raised outside `except`: the httpx error holds the request and its Authorization header.
        raise UpstreamError(None, f"Okta request failed: {reason}")

    def _error(self, response: httpx2.Response) -> UpstreamError:
        status = response.status_code
        if status in (401, 403) and _feature_off(response):
            log.warning("Okta refused the service app's request: HTTP %d %s", status, _FEATURE_OFF)
            return UpstreamError(
                status,
                f"Okta refused the request (HTTP {status}, {_FEATURE_OFF}): the org may not have "
                "the feature this command needs, or the service app's admin role doesn't cover "
                "it; contact the MCP administrator",
            )
        if status in (401, 403):
            log.warning("Okta refused the service app's request: HTTP %d", status)
            return UpstreamError(
                status, f"Okta refused the request (HTTP {status}); contact the MCP administrator"
            )
        match json_body(response):
            case {"errorSummary": str(summary)} if summary:
                return UpstreamError(
                    status, f"Okta returned HTTP {status}: {summary[:_SUMMARY_MAX]}"
                )
            case _:
                return UpstreamError(status, f"Okta returned HTTP {status}")
