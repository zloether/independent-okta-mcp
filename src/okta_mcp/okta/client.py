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
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from typing import Any

import anyio
import httpx2

from okta_mcp.logs import event
from okta_mcp.okta.dpop import DPoP, use_dpop_nonce
from okta_mcp.okta.ratelimit import (
    GiveUp,
    InflightShare,
    OktaRateLimited,
    RateLimited,
    rate_limited,
    retry_wait,
)
from okta_mcp.okta.token import ServiceToken, TokenError, TokenProvider

log = logging.getLogger(__name__)

_SUMMARY_MAX = 500
_FEATURE_OFF = "E0000015"
_ERROR_CODE = re.compile(r"E[0-9]{7}")
# A challenge's `error` codes and descriptions (RFC 6750 §3), shown like `errorSummary`.
_CHALLENGE_ERROR = re.compile(r'\berror\s*=\s*"?([A-Za-z0-9_]{1,64})')
_CHALLENGE_DESCRIPTION = re.compile(r'\berror_description\s*=\s*"([\x20\x21\x23-\x7e]{1,500})"')


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


def _error_code(response: httpx2.Response) -> str | None:
    """Okta's `errorCode` (`E` and seven ASCII digits), or None. A fixed Okta string, so it may
    be logged; anything else in that field is Okta data and isn't returned."""
    match json_body(response):
        case {"errorCode": str(code)} if _ERROR_CODE.fullmatch(code):
            return code
        case _:
            return None


def _feature_off(response: httpx2.Response) -> bool:
    """Okta's "feature not enabled on the org" error (e.g. group owners), which says nothing
    about the token. A token challenge alongside it means the token was refused too."""
    return "WWW-Authenticate" not in response.headers and _error_code(response) == _FEATURE_OFF


def _log_retry(wait: float) -> None:
    """`okta_rate_limited` for a 429 about to be retried (design §13)."""
    log.warning(
        "Okta rate limit hit; retrying in %.1f s",
        wait,
        extra=event("okta_rate_limited", retry=True, wait_s=round(wait, 1)),
    )


def _log_give_up(reason: GiveUp) -> None:
    """`okta_rate_limited` for a 429 not retried, or whose retry didn't succeed. Every 429
    ends in exactly one of these or a successful retry (`OktaClient.get`)."""
    log.warning(
        "Okta rate limit hit; gave up (%s)",
        reason,
        extra=event("okta_rate_limited", retry=False, reason=reason),
    )


class _NoCookies(DefaultCookiePolicy):
    """Stores and sends no cookie."""

    def set_ok(self, cookie: Cookie, request: object) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: object) -> bool:
        return False


def new_http_client(transport: httpx2.AsyncBaseTransport | None = None) -> httpx2.AsyncClient:
    """The one `AsyncClient` for Okta, shared with the token provider. TLS is verified against the
    system trust store, and redirects are never followed: a followed redirect would replay the
    client assertion or a token off the org. Cookies are refused: the client serves every
    principal, so a cookie Okta set on one caller's response would ride on everyone's requests
    and on the token POST. (A bare `CookieJar`: httpx2 copies a `Cookies` into its own jar.)"""
    return httpx2.AsyncClient(
        verify=True,
        follow_redirects=False,
        timeout=httpx2.Timeout(30, connect=10),
        transport=transport,
        cookies=CookieJar(policy=_NoCookies()),
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
            try:
                wait = retry_wait(response, self._max_wait)
            except OktaRateLimited as e:
                _log_give_up(e.reason)
                raise
            try:
                self._charge()  # before the wait: a principal at its limit fails now
            except RateLimited:
                _log_give_up("principal_limit")
                raise
            _log_retry(wait)
            # One outcome per retry, logged in one place. Anything that isn't an `Exception`
            # (a cancellation by the deadline or shutdown, or an interpreter exit) keeps the
            # default.
            outcome: GiveUp | None = "cancelled"
            try:
                await anyio.sleep(wait)
                token, response = await self._attempt(target)
                if response.status_code == 429:
                    outcome = "retry_failed"
                    raise rate_limited(response, "retry_failed")
                outcome = None if response.is_success else "retry_error"
            except RateLimited as e:
                if not isinstance(e, OktaRateLimited):  # Okta's own: `retry_failed`, set above
                    outcome = "principal_limit"  # the nonce retry's charge, inside `_attempt`
                raise
            except Exception:
                outcome = "retry_error"
                raise
            finally:
                if outcome is not None:
                    _log_give_up(outcome)
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
        if status in (401, 403):
            # The code tells a too-narrow admin role (E0000006) from a missing feature
            # (E0000015) for the operator; the caller's message names only the latter.
            code = _error_code(response)
            log.warning(
                "Okta refused the service app's request: HTTP %d %s",
                status,
                code or "(no errorCode)",
                extra=event("okta_refused", status=status, error_code=code),
            )
        if status in (401, 403) and _feature_off(response):
            return UpstreamError(
                status,
                f"Okta refused the request (HTTP {status}, {_FEATURE_OFF}): the org may not have "
                "the feature this command needs, or the service app's admin role doesn't cover "
                "it; contact the MCP administrator",
            )
        if status in (401, 403):
            return UpstreamError(
                status, f"Okta refused the request (HTTP {status}); contact the MCP administrator"
            )
        match json_body(response):
            case {"errorSummary": str(summary)} if summary:
                return UpstreamError(
                    status, f"Okta returned HTTP {status}: {summary[:_SUMMARY_MAX]}"
                )
            # OAuth-style, as for a DPoP proof Okta rejects (`invalid_dpop_proof`).
            case {"error": str(error), "error_description": str(description)} if description:
                summary = f"{error[:64]}: {description}"
                return UpstreamError(
                    status, f"Okta returned HTTP {status}: {summary[:_SUMMARY_MAX]}"
                )
            case _ if errors := _CHALLENGE_ERROR.findall(
                challenge := response.headers.get("WWW-Authenticate", "")
            ):
                descriptions = _CHALLENGE_DESCRIPTION.findall(challenge)
                summary = ", ".join(errors + descriptions)
                return UpstreamError(
                    status, f"Okta returned HTTP {status}: {summary[:_SUMMARY_MAX]}"
                )
            case _:
                return UpstreamError(status, f"Okta returned HTTP {status}")
