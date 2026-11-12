"""The HTTP bearer-token verifier (design §8.5).

`JWTVerifier.verify_token` checks a user's access token from the dedicated Okta custom
authorization server and returns a `VerifiedToken` (the SDK's `AccessToken` plus our
`Principal`), or `None` for any token it doesn't accept. It never raises for a bad token:
`okta_mcp.app._FailClosed` logs a raise at ERROR, as a bug.

Checks, in order: size; header (`alg` RS256 or ES256, a `kid`, no `crit`/`b64`); a JWKS key
with that `kid` and the same algorithm; signature; `iss` exactly `MCP_ISSUER`; `aud` contains
`MCP_AUDIENCE`; `exp` (strict, as the SDK checks it too), `nbf`, `iat` with 60 s skew and
`iat` no older than `MCP_MAX_TOKEN_AGE`; `cid` (or `client_id`) in `MCP_ALLOWED_CLIENT_IDS`;
`uid` an Okta user ID; `sub` a string; `scp` (or `scope`) well formed. The required scope
itself is the SDK's check (`RequireAuthMiddleware`), so a token without it gets 403
`insufficient_scope`, not 401. The groups claim is an array of strings or counts as no groups.

Keys: discovered from the issuer's RFC 8414 metadata (`issuer` must match, `jwks_uri` on the
issuer's origin), refreshed in the background (`run`) every half TTL and held for one TTL
(1 h), so a warm cache outlives an issuer outage by at least 30 min. An unknown `kid` refetches
at most once per 60 s. `ready()` is true while keys are held and not past their TTL; until then
`okta_mcp.app.ReadyGate` answers `/mcp` with 503. Startup doesn't wait for the issuer.

Nothing here logs a token, a claim value or a response body; a rejection is logged at DEBUG
with a fixed reason.
"""

import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, cast

import anyio
import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from okta_mcp.auth.principal import Principal, VerifiedToken
from okta_mcp.config import Config
from okta_mcp.exec.resolve import USER_ID
from okta_mcp.logs import log_internal
from okta_mcp.okta.client import on_origin

log = logging.getLogger(__name__)

ALGORITHMS = frozenset({"RS256", "ES256"})
LEEWAY = 60
"""Clock skew allowed on `nbf`, `iat` and the token age (s); none on `exp` (see `_accept`)."""
JWKS_TTL = 3600.0
"""How long fetched keys are trusted without a successful refresh (s)."""
REFRESH_EVERY = JWKS_TTL / 2
UNKNOWN_KID_INTERVAL = 60.0
"""At most one refetch per this many seconds for a `kid` the cache doesn't have."""
RETRY_MIN, RETRY_MAX = 1.0, 60.0
"""Backoff between failed background fetches (s)."""
FETCH_TIMEOUT = 10.0
MAX_TOKEN_BYTES = 16 * 1024
"""Okta access tokens are a few KiB with a 100-group claim; anything far larger isn't one."""
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_KID = 256
MIN_RSA_BITS = 2048
_FORBIDDEN_HEADERS = frozenset({"crit", "b64"})


class _Rejected(Exception):
    """A token we don't accept; the message is a fixed reason, never token content."""


class _FetchError(Exception):
    """Metadata or JWKS unusable; the message is fixed text, a status, or an exception type."""


def _number(value: object) -> float | None:
    """A JWT NumericDate: a finite int or float, not a bool."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        f = float(value)
    except OverflowError:  # an int beyond float range
        return None
    return f if math.isfinite(f) else None


def _usable_key(jwk: object) -> tuple[str, jwt.PyJWK] | None:
    """`(kid, key)` for a signing key we can verify with, else `None`."""
    if not isinstance(jwk, dict):
        return None
    d = cast(dict[str, object], jwk)
    kid, use, kty = d.get("kid"), d.get("use", "sig"), d.get("kty")
    if not isinstance(kid, str) or not 0 < len(kid) <= MAX_KID or use != "sig":
        return None
    if kty not in ("RSA", "EC"):
        return None
    try:
        key = jwt.PyJWK(cast(dict[str, Any], d))
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return None
    if key.algorithm_name not in ALGORITHMS:
        return None
    raw = key.key
    if isinstance(raw, rsa.RSAPublicKey):
        if raw.key_size < MIN_RSA_BITS or key.algorithm_name != "RS256":
            return None
    elif isinstance(raw, ec.EllipticCurvePublicKey):
        if not isinstance(raw.curve, ec.SECP256R1) or key.algorithm_name != "ES256":
            return None
    else:  # a private key, or a type we don't verify with
        return None
    return kid, key


def parse_jwks(document: object) -> dict[str, jwt.PyJWK]:
    """The usable signing keys in a JWKS, by `kid`. A `kid` that appears twice is dropped
    (which key would be meant is ambiguous). Raises `_FetchError` if none is usable."""
    if not isinstance(document, dict):
        raise _FetchError("JWKS is not a JSON object")
    keys = cast(dict[str, object], document).get("keys")
    if not isinstance(keys, list):
        raise _FetchError("JWKS has no keys array")
    found: dict[str, jwt.PyJWK] = {}
    seen: set[str] = set()
    for jwk in cast(list[object], keys):
        if (usable := _usable_key(jwk)) is None:
            continue
        kid, key = usable
        if kid in seen:
            found.pop(kid, None)
            continue
        seen.add(kid)
        found[kid] = key
    if not found:
        raise _FetchError("JWKS has no usable RS256 or ES256 signing key")
    return found


class JWTVerifier:
    """The SDK `TokenVerifier` for HTTP (design §8.5), plus `ready()` and the background `run`
    that keeps its keys fresh. `clock` is wall time (token dates); `monotonic` times the key
    cache, so a wall-clock step can't keep stale keys."""

    def __init__(
        self,
        http: httpx2.AsyncClient,
        config: Config,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if config.issuer is None or config.audience is None or not config.allowed_client_ids:
            raise ValueError("Config without MCP_ISSUER, MCP_AUDIENCE or MCP_ALLOWED_CLIENT_IDS")
        self._http = http
        self._issuer = config.issuer
        self._audience = config.audience
        self._clients = frozenset(config.allowed_client_ids)  # `*` only ever alone (Config)
        self._groups_claim = config.groups_claim
        self._max_age = config.max_token_age
        self._clock = clock
        self._monotonic = monotonic
        self._metadata_url = self._issuer.rstrip("/") + "/.well-known/oauth-authorization-server"
        self._keys: dict[str, jwt.PyJWK] = {}
        self._keys_until = -math.inf
        self._last_fetch = -math.inf
        self._lock = anyio.Lock()

    # --- readiness and keys -----------------------------------------------------------------

    def ready(self) -> bool:
        """Keys loaded and within their TTL. Reads state; never fetches, never raises."""
        return bool(self._keys) and self._monotonic() < self._keys_until

    async def run(self, sleep: Callable[[float], Awaitable[None]] = anyio.sleep) -> None:
        """Load the keys, then keep them fresh, until cancelled. A failed fetch is retried with
        backoff; the old keys keep serving until their TTL runs out. An unexpected exception (a
        bug) is logged and retried the same way: it shares a task group with the server, so
        letting it out would stop the server rather than just leave it not ready."""
        delay = RETRY_MIN
        while True:
            try:
                ok = await self.refresh()
            except Exception as e:
                log_internal(log, "JWKS refresh", e)
                ok = False
            if ok:
                delay = RETRY_MIN
                await sleep(REFRESH_EVERY)
            else:
                await sleep(delay)
                delay = min(delay * 2, RETRY_MAX)

    async def refresh(self) -> bool:
        """Fetch metadata and JWKS once; on success replace the keys. Never raises (but
        cancellation propagates)."""
        async with self._lock:
            return await self._refresh_locked()

    async def _refresh_locked(self) -> bool:
        self._last_fetch = self._monotonic()
        try:
            with anyio.fail_after(FETCH_TIMEOUT):
                keys = await self._fetch_keys()
        except _FetchError as e:
            log.warning("JWKS fetch from the issuer failed: %s", e)
            return False
        except TimeoutError:
            log.warning("JWKS fetch from the issuer failed: timed out")
            return False
        except httpx2.HTTPError as e:
            # Not chained or formatted: the exception text can hold the URL and headers.
            log.warning("JWKS fetch from the issuer failed: %s", type(e).__name__)
            return False
        if not self._keys:
            log.info("JWKS loaded (%d keys)", len(keys))
        self._keys = keys
        self._keys_until = self._monotonic() + JWKS_TTL
        return True

    async def _get_json(self, url: str) -> object:
        """GET `url` as JSON, reading at most `MAX_DOCUMENT_BYTES` of the body."""
        body = bytearray()
        async with self._http.stream("GET", url, headers={"accept": "application/json"}) as r:
            if r.status_code != 200:
                raise _FetchError(f"HTTP {r.status_code}")
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise _FetchError("response too large")
        try:
            return json.loads(body)
        except (ValueError, RecursionError):
            raise _FetchError("response is not JSON") from None

    async def _fetch_keys(self) -> dict[str, jwt.PyJWK]:
        metadata = await self._get_json(self._metadata_url)
        if not isinstance(metadata, dict):
            raise _FetchError("metadata is not a JSON object")
        m = cast(dict[str, object], metadata)
        if m.get("issuer") != self._issuer:
            raise _FetchError("metadata issuer is not MCP_ISSUER")
        jwks_uri = m.get("jwks_uri")
        if not isinstance(jwks_uri, str) or any(
            c.isspace() or not c.isprintable() for c in jwks_uri
        ):
            raise _FetchError("metadata jwks_uri is malformed")
        try:
            url = httpx2.URL(jwks_uri)
        except (httpx2.InvalidURL, ValueError):
            raise _FetchError("metadata jwks_uri is malformed") from None
        # Same scheme, host and port as the issuer, no userinfo: keys come from the issuer,
        # nowhere else.
        if not on_origin(url, httpx2.URL(self._issuer)):
            raise _FetchError("metadata jwks_uri is not on the issuer's origin")
        return parse_jwks(await self._get_json(str(url)))

    async def _key(self, kid: str) -> jwt.PyJWK | None:
        if (key := self._keys.get(kid)) is not None:
            return key
        # Unknown kid: the issuer may have rotated. At most one refetch per interval, shared by
        # every request that asks within it.
        async with self._lock:
            if (key := self._keys.get(kid)) is not None:
                return key
            if self._monotonic() - self._last_fetch < UNKNOWN_KID_INTERVAL:
                return None
            await self._refresh_locked()
            return self._keys.get(kid)

    # --- verification -----------------------------------------------------------------------

    async def verify_token(self, token: str) -> VerifiedToken | None:
        if not self.ready():
            return None  # `ReadyGate` answers 503 before any handler; never 401 for this
        try:
            return await self._verify(token)
        except _Rejected as e:
            log.debug("bearer token rejected: %s", e)
            return None
        except jwt.PyJWTError as e:
            log.debug("bearer token rejected: %s", type(e).__name__)
            return None

    async def _verify(self, token: str) -> VerifiedToken:
        if len(token) > MAX_TOKEN_BYTES or not token.isascii():
            raise _Rejected("not a JWT of acceptable size")
        header = jwt.get_unverified_header(token)
        alg, kid = header.get("alg"), header.get("kid")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            raise _Rejected("alg not RS256 or ES256")
        if _FORBIDDEN_HEADERS & header.keys():
            raise _Rejected("crit or b64 header")
        if not isinstance(kid, str) or not 0 < len(kid) <= MAX_KID:
            raise _Rejected("no kid")
        key = await self._key(kid)
        if key is None:
            raise _Rejected("unknown kid")
        if key.algorithm_name != alg:
            raise _Rejected("alg does not match the key")
        # Signature only; every claim is checked below, against our own clock.
        claims: dict[str, object] = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_sub": False,
                "verify_jti": False,
            },
        )
        return self._accept(token, claims)

    def _accept(self, token: str, claims: Mapping[str, object]) -> VerifiedToken:
        if claims.get("iss") != self._issuer:
            raise _Rejected("iss")
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud
        if not isinstance(audiences, list):
            raise _Rejected("aud")
        auds = cast(list[object], audiences)
        if not all(isinstance(a, str) for a in auds) or self._audience not in auds:
            raise _Rejected("aud")

        now = self._clock()
        exp, iat = _number(claims.get("exp")), _number(claims.get("iat"))
        if exp is None or iat is None:
            raise _Rejected("exp or iat missing or not a number")
        # No skew on `exp`: the SDK checks `expires_at` against its own clock with none.
        if exp <= now:
            raise _Rejected("expired")
        if iat > now + LEEWAY:
            raise _Rejected("iat in the future")
        if now - iat > self._max_age + LEEWAY:
            raise _Rejected("older than MCP_MAX_TOKEN_AGE")
        if "nbf" in claims:
            nbf = _number(claims["nbf"])
            if nbf is None or nbf > now + LEEWAY:
                raise _Rejected("nbf")

        client_id = self._client_id(claims)
        uid = claims.get("uid")
        if not isinstance(uid, str) or not USER_ID.fullmatch(uid):
            raise _Rejected("uid missing or not an Okta user ID")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise _Rejected("sub")
        scopes = self._scopes(claims)

        principal = Principal(
            uid=uid,
            sub=sub,
            groups=self._groups(claims.get(self._groups_claim)),
            client_id=client_id,
            exp=int(exp),
        )
        return VerifiedToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(exp),
            subject=uid,
            claims={"iss": self._issuer},
            principal=principal,
        )

    def _client_id(self, claims: Mapping[str, object]) -> str:
        """Okta's `cid`, or RFC 9068 `client_id`; if both are present they must agree."""
        given = [claims[k] for k in ("cid", "client_id") if k in claims]
        if not given or any(not isinstance(c, str) or not c for c in given):
            raise _Rejected("cid missing or malformed")
        if len(set(cast(list[str], given))) != 1:
            raise _Rejected("cid and client_id disagree")
        client_id = cast(str, given[0])
        if "*" not in self._clients and client_id not in self._clients:
            raise _Rejected("cid not in MCP_ALLOWED_CLIENT_IDS")
        return client_id

    @staticmethod
    def _scopes(claims: Mapping[str, object]) -> list[str]:
        """Okta's `scp` (an array), or RFC 9068 `scope` (space-separated). Malformed is a
        rejection; absent is no scopes, which the SDK answers with 403."""
        scopes: set[str] = set()
        if "scp" in claims:
            scp = claims["scp"]
            if not isinstance(scp, list) or not all(
                isinstance(s, str) for s in cast(list[object], scp)
            ):
                raise _Rejected("scp")
            scopes.update(cast(list[str], scp))
        if "scope" in claims:
            scope = claims["scope"]
            if not isinstance(scope, str):
                raise _Rejected("scope")
            scopes.update(scope.split())
        return sorted(scopes)

    @staticmethod
    def _groups(value: object) -> frozenset[str]:
        """An array of strings; anything else is no groups (§8.5), which the policy maps to no
        role."""
        if isinstance(value, list) and all(isinstance(g, str) for g in cast(list[object], value)):
            return frozenset(cast(list[str], value))
        if value is not None:
            log.debug("groups claim is not an array of strings; treated as no groups")
        return frozenset()
