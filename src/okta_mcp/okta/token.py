"""Service-app credentials for the Okta Management API (design §6.5, §10).

A `TokenProvider` returns the `ServiceToken` whose `authorization` value goes in the
`Authorization` header; a `DPoP` scheme means each request also needs a proof. Two providers:

- `ClientCredentialsProvider`: client credentials with a `private_key_jwt` assertion at the org
  authorization server, with DPoP unless `OKTA_DPOP=false`. The token is cached in memory and
  fetched again under a lock when less than a minute remains, so concurrent callers share one
  request. After a failed request, callers get the same error for `FAILURE_BACKOFF` seconds
  without a new one, so an outage or a bad key costs one POST per backoff, not one per tool call
  (those aren't charged to the per-principal limiter). Its POST to the token endpoint is the
  only non-GET request the server sends to Okta, and it goes only to that fixed URL.
- `SSWSProvider`: `OKTA_API_TOKEN`, which `Config` accepts only in stdio dev mode (design §8.6).

`TokenError` messages hold the HTTP status, the OAuth error code and a hint, never tokens,
assertions, keys or response bodies.
"""

import logging
import math
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, cast

import anyio
import httpx2
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from okta_mcp.config import ConfigError
from okta_mcp.logs import event, log_internal
from okta_mcp.okta.dpop import DPoP

log = logging.getLogger(__name__)

_ASSERTION_LIFETIME = 300
_REFRESH_MARGIN = 60
FAILURE_BACKOFF = 5.0
"""Seconds after a failed token request during which the error is served without a new one.
`keep_fresh` asks again this long after a first failure, then doubles up to
`KEEP_FRESH_EVERY`."""
_ERROR_CODE = re.compile(r"[a-z_]{1,64}")
# For an error without an OAuth `error` code: Okta's API error code, else the shape of the
# reply (key names, media type), so a failure says where to look without showing the body.
# A code, not text: Okta's are `E` plus digits, but the token endpoint's were seen not to
# match `E\d{7}` (8.2.1 run 16), so any short token of code characters.
_OKTA_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_KEY_NAME = re.compile(r"[A-Za-z_]{1,32}")
_MEDIA_TYPE = re.compile(r"[a-z0-9.+-]{1,32}/[a-z0-9.+-]{1,64}")
_HINTS = {
    "invalid_client": "check OKTA_CLIENT_ID, OKTA_PRIVATE_KEY_FILE and OKTA_KEY_ID against the "
    "service app's public keys",
    "invalid_scope": "grant every OKTA_SCOPES entry to the service app",
}


class TokenError(Exception):
    pass


@dataclass(frozen=True)
class ServiceToken:
    value: str = field(repr=False)
    scheme: Literal["Bearer", "DPoP", "SSWS"]

    @property
    def authorization(self) -> str:
        return f"{self.scheme} {self.value}"


class TokenProvider(Protocol):
    async def token(self) -> ServiceToken: ...

    def invalidate(self, token: ServiceToken) -> None:
        """Okta answered 401 to `token`: stop serving it from the cache."""
        ...


KEEP_FRESH_EVERY = 30.0
"""Less than `_REFRESH_MARGIN`, so the cached token is renewed before it expires."""


class RefreshableTokens(TokenProvider, Protocol):
    def ready(self) -> bool:
        """A usable token is held now (for `/readyz`); reads state, never fetches."""
        ...


async def keep_fresh(
    provider: TokenProvider,
    every: float = KEEP_FRESH_EVERY,
    sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
) -> None:
    """Ask `provider` for a token every `every` seconds until cancelled, so `ready()` reflects
    a token obtained within the last refresh cycle without a probe ever fetching one (§11.4).
    Served from the cache while it is fresh; a failure is the provider's to log. After a
    failure the next ask comes after `FAILURE_BACKOFF`, doubling with each further failure up
    to `every`, so readiness returns soon after a short outage. Anything else (a bug) is
    logged and retried: this shares a task group with the server, so letting it out would stop
    the server rather than just leave it not ready."""
    backoff = 0.0  # 0 while the last ask succeeded
    while True:
        try:
            await provider.token()
        except TokenError:
            # Doubling from the backoff up to `every`: quick to notice Okta recovering, but a
            # bad key on an idle server costs `every`'s rate, not 12 POSTs a minute. A running
            # value, capped each time, so a long outage can't grow it without bound.
            backoff = min(every, backoff * 2 if backoff else FAILURE_BACKOFF)
        except Exception as e:
            log_internal(log, "service token refresh", e)
        else:
            backoff = 0.0
        await sleep(backoff or every)


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    """The service app's signing key from `OKTA_PRIVATE_KEY_FILE`; Okta needs RSA ≥ 2048 bits
    for RS256. The error names the file, never its contents."""
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        key = None
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ConfigError(
            [
                f"OKTA_PRIVATE_KEY_FILE: {path} is not an unencrypted PEM RSA private key "
                "of at least 2048 bits"
            ]
        )
    return key


class SSWSProvider:
    def __init__(self, api_token: SecretStr) -> None:
        self._token = ServiceToken(api_token.get_secret_value(), "SSWS")

    async def token(self) -> ServiceToken:
        return self._token

    def invalidate(self, token: ServiceToken) -> None:
        pass  # nothing to fetch again

    def ready(self) -> bool:
        return True


class ClientCredentialsProvider:
    def __init__(
        self,
        http: httpx2.AsyncClient,
        *,
        org_url: str,
        client_id: str,
        key: rsa.RSAPrivateKey,
        key_id: str | None,
        scopes: frozenset[str],
        dpop: DPoP | None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """`org_url` is `Config.okta_org_url` (canonical, no trailing slash). `clock` dates the
        assertion; `monotonic` times the cache, so a wall-clock step can't keep a stale token.
        Without `key_id` the assertion has no `kid` and Okta tries the app's keys."""
        self._http = http
        self._url = f"{org_url}/oauth2/v1/token"  # org authorization server
        self._client_id = client_id
        self._key = key
        self._headers = {"kid": key_id} if key_id else None
        self._scope = " ".join(sorted(scopes))
        self._dpop = dpop
        self._clock = clock
        self._monotonic = monotonic
        self._lock = anyio.Lock()
        self._token: ServiceToken | None = None
        self._expires_at = 0.0
        self._failures = 0
        self._error: str | None = None
        self._failed_at = -math.inf

    async def token(self) -> ServiceToken:
        """The cached token, or a new one. Callers queued behind a failed request, and callers
        within `FAILURE_BACKOFF` of one, don't send their own: they get the still-valid old
        token if there is one, else the same error."""
        if (token := self._cached()) is not None:
            return token
        failures = self._failures
        async with self._lock:
            if (token := self._cached()) is not None:
                return token
            if self._failures == failures and not self._backing_off():
                try:
                    token, self._expires_at = await self._fetch()
                except TokenError as e:
                    self._failures += 1
                    self._error = str(e)
                    self._failed_at = self._monotonic()
                    log.warning(
                        "service token request failed: %s",
                        e,
                        extra=event("service_token_failed", backoff_s=FAILURE_BACKOFF),
                    )
                else:
                    self._token = token
                    self._failed_at = -math.inf
                    return token
            if self._token is not None and self._monotonic() < self._expires_at:
                return self._token
            raise TokenError(self._error)

    def _backing_off(self) -> bool:
        return self._error is not None and self._monotonic() - self._failed_at < FAILURE_BACKOFF

    def invalidate(self, token: ServiceToken) -> None:
        """Covers a token Okta expired before our clock did (e.g. `time.monotonic` stopped
        while the host was suspended). A newer token isn't dropped for an older one's 401."""
        if token == self._token:
            self._token = None
            self._expires_at = 0.0

    def ready(self) -> bool:
        """A token is held and hasn't expired (§11.4: obtained within the last refresh cycle).
        Reads state; never fetches."""
        return self._token is not None and self._monotonic() < self._expires_at

    def _cached(self) -> ServiceToken | None:
        if self._monotonic() < self._expires_at - _REFRESH_MARGIN:
            return self._token
        return None

    async def _fetch(self) -> tuple[ServiceToken, float]:
        # Okta's clock for `expires_in` starts before the response arrives.
        start = self._monotonic()
        response = await self._post()
        if self._dpop is not None and self._dpop.needs_retry(response):
            response = await self._post()
            self._dpop.needs_retry(response)  # records a rotated nonce; no second retry
        token, expires_in = self._parse(response)
        log.info("service token issued (%s, expires in %d s)", token.scheme, expires_in)
        return token, start + expires_in

    def _assertion(self) -> str:
        now = int(self._clock())
        claims = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": self._url,
            "iat": now,
            "exp": now + _ASSERTION_LIFETIME,
            "jti": secrets.token_urlsafe(16),
        }
        return jwt.encode(claims, self._key, algorithm="RS256", headers=self._headers)

    async def _post(self) -> httpx2.Response:
        form = {
            "grant_type": "client_credentials",
            "scope": self._scope,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self._assertion(),
        }
        headers = {"Accept": "application/json"}
        if self._dpop is not None:
            headers["DPoP"] = self._dpop.proof("POST", self._url)
        try:
            return await self._http.post(self._url, data=form, headers=headers)
        except httpx2.HTTPError as e:
            reason = type(e).__name__
        # Raised outside `except`: the httpx error holds the request, whose body is the assertion.
        raise TokenError(f"token request failed: {reason}")

    def _parse(self, response: httpx2.Response) -> tuple[ServiceToken, int]:
        try:
            body = response.json()
        except (ValueError, UnicodeDecodeError):
            body = None
        if response.status_code != 200:
            raise TokenError(
                self._describe(response.status_code, body, response.headers.get("content-type", ""))
            )
        # A lifetime within the refresh margin could never be served from the cache.
        match body:
            case {
                "access_token": str(value),
                "token_type": str(scheme),
                "expires_in": int(ttl),
            } if value and not isinstance(ttl, bool) and ttl > _REFRESH_MARGIN:
                pass
            case _:
                raise TokenError("token response is malformed")
        expected = "DPoP" if self._dpop is not None else "Bearer"
        if scheme.lower() != expected.lower():
            hint = (
                ": turn on 'Require DPoP' for the service app, or set OKTA_DPOP=false"
                if expected == "DPoP"
                else ""
            )
            raise TokenError(f"Okta's token_type is not {expected}{hint}")
        return ServiceToken(value, expected), ttl

    def _describe(self, status: int, body: object, content_type: str = "") -> str:
        match body:
            # Okta sometimes puts the OAuth code in an API-style body's `errorCode` (seen live:
            # `invalid_client`, 8.2.1 run 17), so both get the same hints.
            case {"error": str(code)} | {"errorCode": str(code)} if _ERROR_CODE.fullmatch(code):
                pass
            case _:
                return f"token request failed: HTTP {status}" + _shape(body, content_type)
        hint = _HINTS.get(code)
        if code == "invalid_dpop_proof" and self._dpop is None:
            hint = "the service app requires DPoP: unset OKTA_DPOP or set it to true"
        return f"token request failed: HTTP {status} {code}" + (f" ({hint})" if hint else "")


def _shape(body: object, content_type: str) -> str:
    """What an error reply without an OAuth `error` code looked like: Okta's `errorCode`, or its
    JSON key names, or its media type. Only values matching a fixed pattern, never body text."""
    if isinstance(body, dict):
        fields = cast(dict[object, object], body)
        code = fields.get("errorCode")
        if isinstance(code, str) and _OKTA_ERROR_CODE.fullmatch(code):
            causes = fields.get("errorCauses")
            n = len(cast(list[object], causes)) if isinstance(causes, list) else 0
            return f" {code}" + (f" ({n} error causes)" if n else "")
        keys = sorted(k for k in fields if isinstance(k, str) and _KEY_NAME.fullmatch(k))[:8]
        return f" (JSON keys: {', '.join(keys)})" if keys else " (JSON, no usable keys)"
    if body is not None:
        return " (JSON, not an object)"
    media = content_type.split(";", 1)[0].strip().lower()
    return f" ({media}, not JSON)" if _MEDIA_TYPE.fullmatch(media) else " (not JSON)"
