import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import anyio
import httpx2
import jwt
import pytest
from _fakes import FakeTokenProvider
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr

from okta_mcp.config import ConfigError
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.token import (
    FAILURE_BACKOFF,
    KEEP_FRESH_EVERY,
    ClientCredentialsProvider,
    ServiceToken,
    SSWSProvider,
    TokenError,
    TokenProvider,
    keep_fresh,
    load_private_key,
)

ORG = "https://example.okta.com"
TOKEN_URL = ORG + "/oauth2/v1/token"
ACCESS_TOKEN = "eyJ.access-token-value.sig"  # noqa: S105

Handler = Callable[[httpx2.Request], Awaitable[httpx2.Response]]


@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def ok(
    scheme: str = "DPoP", expires_in: Any = 3600, headers: dict[str, str] | None = None
) -> httpx2.Response:
    body = {"access_token": ACCESS_TOKEN, "token_type": scheme, "expires_in": expires_in}
    return httpx2.Response(200, json=body, headers=headers)


def nonce_error() -> httpx2.Response:
    return httpx2.Response(400, headers={"DPoP-Nonce": "n1"}, json={"error": "use_dpop_nonce"})


class Okta:
    """Records token requests and answers them from `responses` in order (last one repeats)."""

    def __init__(
        self,
        *responses: httpx2.Response | Exception,
        delay: float = 0,
        clock: Clock | None = None,
    ) -> None:
        """`delay` is real time; `clock` (the provider's monotonic clock) also moves `delay`."""
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []
        self.delay = delay
        self.clock = clock

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.clock is not None:
            self.clock.now += self.delay
        else:
            await anyio.sleep(self.delay)
        r = self.responses[min(len(self.requests), len(self.responses)) - 1]
        if isinstance(r, Exception):
            raise r
        return r

    def form(self, i: int = 0) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.requests[i].content.decode()).items()}

    def proof(self, i: int = 0) -> dict[str, Any]:
        proof = self.requests[i].headers["DPoP"]
        jwk = ECAlgorithm.from_jwk(json.dumps(jwt.get_unverified_header(proof)["jwk"]))
        return jwt.decode(proof, jwk, algorithms=["ES256"])  # pyright: ignore[reportArgumentType]


def provider(
    okta: Okta,
    key: rsa.RSAPrivateKey,
    *,
    dpop: bool = True,
    key_id: str | None = "kid-1",
    monotonic: Clock | None = None,
) -> ClientCredentialsProvider:
    return ClientCredentialsProvider(
        httpx2.AsyncClient(transport=httpx2.MockTransport(okta)),
        org_url=ORG,
        client_id="0oa1service",
        key=key,
        key_id=key_id,
        scopes=frozenset({"okta.users.read", "okta.groups.read"}),
        dpop=DPoP() if dpop else None,
        clock=lambda: 1_700_000_000.4,
        monotonic=monotonic or Clock(),
    )


@pytest.mark.anyio
async def test_assertion_and_form(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok())
    token = await provider(okta, key).token()
    assert token == ServiceToken(ACCESS_TOKEN, "DPoP")
    assert token.authorization == f"DPoP {ACCESS_TOKEN}"
    request = okta.requests[0]
    assert (request.method, str(request.url)) == ("POST", TOKEN_URL)
    form = okta.form()
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "okta.groups.read okta.users.read"
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assertion = form["client_assertion"]
    assert jwt.get_unverified_header(assertion) == {"alg": "RS256", "kid": "kid-1", "typ": "JWT"}
    claims = jwt.decode(
        assertion,
        key.public_key(),
        algorithms=["RS256"],
        audience=TOKEN_URL,
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["iss"] == claims["sub"] == "0oa1service"
    assert (claims["iat"], claims["exp"]) == (1_700_000_000, 1_700_000_300)
    assert len(claims["jti"]) >= 16


@pytest.mark.anyio
async def test_no_kid_without_key_id(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok())
    await provider(okta, key, key_id=None).token()
    assert "kid" not in jwt.get_unverified_header(okta.form()["client_assertion"])


@pytest.mark.anyio
async def test_dpop_proof_at_token_endpoint(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok())
    await provider(okta, key).token()
    claims = okta.proof()
    assert (claims["htm"], claims["htu"]) == ("POST", TOKEN_URL)
    assert "ath" not in claims
    assert "nonce" not in claims


@pytest.mark.anyio
async def test_nonce_retry(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(nonce_error(), ok())
    assert (await provider(okta, key).token()).scheme == "DPoP"
    assert len(okta.requests) == 2
    assert okta.proof(1)["nonce"] == "n1"
    assert okta.proof(0)["jti"] != okta.proof(1)["jti"]
    assert okta.form(0)["client_assertion"] != okta.form(1)["client_assertion"]


@pytest.mark.anyio
async def test_nonce_retry_only_once(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(nonce_error())
    with pytest.raises(TokenError, match="HTTP 400 use_dpop_nonce"):
        await provider(okta, key).token()
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_bearer_without_dpop(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok("Bearer"))
    token = await provider(okta, key, dpop=False).token()
    assert token.authorization == f"Bearer {ACCESS_TOKEN}"
    assert "DPoP" not in okta.requests[0].headers


@pytest.mark.anyio
async def test_no_nonce_retry_without_dpop(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(nonce_error(), ok("Bearer"))
    with pytest.raises(TokenError):
        await provider(okta, key, dpop=False).token()
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_bearer_token_refused_when_dpop_on(key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(TokenError, match=r"Require DPoP.*OKTA_DPOP=false"):
        await provider(Okta(ok("Bearer")), key).token()


@pytest.mark.anyio
async def test_dpop_token_refused_when_dpop_off(key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(TokenError, match=r"^Okta's token_type is not Bearer$"):
        await provider(Okta(ok("DPoP")), key, dpop=False).token()


@pytest.mark.anyio
async def test_token_type_case_insensitive(key: rsa.RSAPrivateKey) -> None:
    assert (await provider(Okta(ok("dpop")), key).token()).scheme == "DPoP"


@pytest.mark.anyio
async def test_cached_then_refreshed_under_a_minute(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(ok(expires_in=3600))
    p = provider(okta, key, monotonic=clock)
    await p.token()
    clock.now += 3600 - 61
    await p.token()
    assert len(okta.requests) == 1
    clock.now += 1
    await p.token()
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_ready_while_a_token_is_held(key: rsa.RSAPrivateKey) -> None:
    """`/readyz` (§11.4): reads state, never fetches."""
    clock = Clock()
    okta = Okta(ok(expires_in=3600), httpx2.Response(500))
    p = provider(okta, key, monotonic=clock)
    assert not p.ready()
    assert okta.requests == []
    token = await p.token()
    assert p.ready()
    clock.now += 3599
    assert p.ready()
    clock.now += 1
    assert not p.ready()
    p.invalidate(token)
    assert not p.ready()
    with pytest.raises(TokenError):
        await p.token()
    assert not p.ready()


@pytest.mark.anyio
async def test_keep_fresh_renews_before_expiry(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(ok(expires_in=3600), httpx2.Response(500), ok(expires_in=3600))
    p = provider(okta, key, monotonic=clock)
    ready: list[bool] = []

    async def sleep(seconds: float) -> None:
        assert seconds == KEEP_FRESH_EVERY
        ready.append(p.ready())
        clock.now += 3600 - 60  # into the refresh margin each time
        if len(ready) == 3:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await keep_fresh(p, sleep=sleep)
    # fetched; refetch failed (old token still valid for 60 s); fetched again
    assert ready == [True, True, True]
    assert len(okta.requests) == 3


@pytest.mark.anyio
async def test_keep_fresh_asks_again_after_the_backoff(key: rsa.RSAPrivateKey) -> None:
    """After a failure the background refresh comes back after the backoff, not a whole cycle,
    so readiness returns soon after Okta does even on an idle server."""
    clock = Clock()
    okta = Okta(httpx2.Response(503), ok(expires_in=3600))
    p = provider(okta, key, monotonic=clock)
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.now += seconds
        if len(slept) == 3:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await keep_fresh(p, sleep=sleep)
    assert slept == [FAILURE_BACKOFF, KEEP_FRESH_EVERY, KEEP_FRESH_EVERY]
    assert len(okta.requests) == 2
    assert p.ready()


@pytest.mark.anyio
async def test_keep_fresh_backs_off_on_repeated_failures(key: rsa.RSAPrivateKey) -> None:
    """A bad key on an idle server: the background asks double up to the normal cycle."""
    clock = Clock()
    okta = Okta(httpx2.Response(401, json={"error": "invalid_client"}))
    p = provider(okta, key, monotonic=clock)
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock.now += seconds
        if len(slept) == 6:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await keep_fresh(p, sleep=sleep)
    assert slept == [5, 10, 20, 30, 30, 30]
    assert len(okta.requests) == 6


@pytest.mark.anyio
async def test_keep_fresh_survives_a_long_outage_and_recovers() -> None:
    """2000 failures in a row (over 16 hours at 30 s) don't overflow the backoff or stop the
    loop, and one success puts it back on the normal cycle."""

    class Down(FakeTokenProvider):
        up = False

        async def token(self) -> ServiceToken:
            self.calls += 1
            if not self.up:
                raise TokenError("token request failed: HTTP 503")
            return ServiceToken("t", "Bearer")

    p = Down()
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)
        p.up = len(slept) >= 2000
        if len(slept) == 2002:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await keep_fresh(p, sleep=sleep)
    assert slept[:5] == [5, 10, 20, 30, 30]
    assert set(slept[3:2000]) == {KEEP_FRESH_EVERY}
    assert slept[2000:] == [KEEP_FRESH_EVERY, KEEP_FRESH_EVERY]
    assert p.calls == 2002


@pytest.mark.anyio
async def test_keep_fresh_survives_an_unexpected_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It shares a task group with the server: a bug must not stop the server."""

    class Broken(FakeTokenProvider):
        async def token(self) -> ServiceToken:
            self.calls += 1
            raise RuntimeError("bug")

    p = Broken()
    sleeps = 0

    async def sleep(seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 3:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await keep_fresh(p, sleep=sleep)
    assert p.calls == 3
    assert "internal error in service token refresh: RuntimeError" in caplog.text


@pytest.mark.anyio
async def test_ssws_is_always_ready() -> None:
    assert SSWSProvider(SecretStr("x")).ready()


@pytest.mark.anyio
async def test_invalidate_drops_only_that_token(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok(), httpx2.Response(200, json={**ok().json(), "access_token": "eyJ.newer"}))
    p = provider(okta, key)
    old = await p.token()
    p.invalidate(old)
    new = await p.token()
    assert len(okta.requests) == 2
    assert new.value == "eyJ.newer"
    p.invalidate(old)  # a late 401 for the old token
    assert await p.token() is new
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_invalidated_token_not_served_when_refresh_fails(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok(), httpx2.Response(500))
    p = provider(okta, key)
    p.invalidate(await p.token())
    with pytest.raises(TokenError, match="HTTP 500"):
        await p.token()


@pytest.mark.anyio
async def test_one_refresh_for_concurrent_callers(key: rsa.RSAPrivateKey) -> None:
    okta = Okta(ok(), delay=0.05)
    p = provider(okta, key)
    tokens: list[ServiceToken] = []

    async def call() -> None:
        tokens.append(await p.token())

    async with anyio.create_task_group() as tg:
        for _ in range(20):
            tg.start_soon(call)
    assert len(okta.requests) == 1
    assert tokens == [ServiceToken(ACCESS_TOKEN, "DPoP")] * 20


@pytest.mark.anyio
async def test_expiry_counts_from_request_start(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    start = clock.now
    okta = Okta(nonce_error(), ok(expires_in=3600), ok(), delay=25, clock=clock)
    p = provider(okta, key, monotonic=clock)
    await p.token()
    assert clock.now == start + 50
    clock.now = start + 3600 - 61
    await p.token()
    assert len(okta.requests) == 2
    clock.now = start + 3600 - 60
    await p.token()
    assert len(okta.requests) == 3


@pytest.mark.anyio
async def test_nonce_on_retry_response_is_kept(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(nonce_error(), ok(headers={"DPoP-Nonce": "n2"}), ok())
    p = provider(okta, key, monotonic=clock)
    await p.token()
    clock.now += 3600
    await p.token()
    assert okta.proof(2)["nonce"] == "n2"


@pytest.mark.anyio
async def test_queued_callers_share_a_failure(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(httpx2.Response(503), ok(), delay=0.05)
    p = provider(okta, key, monotonic=clock)
    errors: list[str] = []

    async def call() -> None:
        try:
            await p.token()
        except TokenError as e:
            errors.append(str(e))

    async with anyio.create_task_group() as tg:
        for _ in range(20):
            tg.start_soon(call)
    assert len(okta.requests) == 1
    assert errors == ["token request failed: HTTP 503"] * 20
    clock.now += FAILURE_BACKOFF
    assert (await p.token()).value == ACCESS_TOKEN
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_valid_token_served_when_refresh_fails(
    key: rsa.RSAPrivateKey, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    okta = Okta(ok(expires_in=3600), httpx2.Response(503))
    p = provider(okta, key, monotonic=clock)
    await p.token()
    clock.now += 3550
    assert (await p.token()).value == ACCESS_TOKEN
    assert len(okta.requests) == 2
    assert "service token request failed: token request failed: HTTP 503" in caplog.text
    clock.now += 50
    with pytest.raises(TokenError, match=r"HTTP 503$"):
        await p.token()


@pytest.mark.anyio
async def test_failure_is_not_cached(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(httpx2.Response(503), ok())
    p = provider(okta, key, monotonic=clock)
    with pytest.raises(TokenError, match=r"HTTP 503$"):
        await p.token()
    clock.now += FAILURE_BACKOFF
    assert (await p.token()).value == ACCESS_TOKEN


@pytest.mark.anyio
async def test_failure_backs_off(key: rsa.RSAPrivateKey) -> None:
    """Plan 6.2: during an outage or with a bad key, calls within the backoff get the stored
    error without a token request of their own; the first call after it sends one."""
    clock = Clock()
    okta = Okta(httpx2.Response(401, json={"error": "invalid_client"}), ok())
    p = provider(okta, key, monotonic=clock)
    for _ in range(5):
        with pytest.raises(TokenError, match=r"HTTP 401 invalid_client"):
            await p.token()
        clock.now += FAILURE_BACKOFF / 10
    assert len(okta.requests) == 1
    assert not p.ready()
    clock.now += FAILURE_BACKOFF
    assert (await p.token()).value == ACCESS_TOKEN
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_backoff_restarts_after_each_failure(key: rsa.RSAPrivateKey) -> None:
    clock = Clock()
    okta = Okta(httpx2.Response(503), httpx2.Response(502), ok())
    p = provider(okta, key, monotonic=clock)
    with pytest.raises(TokenError, match=r"HTTP 503$"):
        await p.token()
    clock.now += FAILURE_BACKOFF
    with pytest.raises(TokenError, match=r"HTTP 502$"):
        await p.token()
    clock.now += FAILURE_BACKOFF - 0.1
    with pytest.raises(TokenError, match=r"HTTP 502$"):
        await p.token()
    assert len(okta.requests) == 2
    clock.now += 0.1
    assert (await p.token()).value == ACCESS_TOKEN


@pytest.mark.anyio
async def test_backoff_still_serves_a_valid_token(key: rsa.RSAPrivateKey) -> None:
    """A refresh failure inside the margin doesn't stop the old token being served, and the
    backoff keeps each call in it from sending its own refresh."""
    clock = Clock()
    okta = Okta(ok(expires_in=3600), httpx2.Response(503))
    p = provider(okta, key, monotonic=clock)
    await p.token()
    clock.now += 3550
    for _ in range(3):
        assert (await p.token()).value == ACCESS_TOKEN
    assert len(okta.requests) == 2


def test_backoff_is_shorter_than_the_background_refresh() -> None:
    assert FAILURE_BACKOFF < KEEP_FRESH_EVERY


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "dpop", "message"),
    [
        (
            httpx2.Response(401, json={"error": "invalid_client", "error_description": "x"}),
            True,
            r"^token request failed: HTTP 401 invalid_client \(check OKTA_CLIENT_ID",
        ),
        (
            httpx2.Response(400, json={"error": "invalid_scope"}),
            True,
            r"HTTP 400 invalid_scope \(grant every OKTA_SCOPES",
        ),
        (
            httpx2.Response(400, json={"error": "invalid_dpop_proof"}),
            False,
            r"HTTP 400 invalid_dpop_proof \(the service app requires DPoP: unset OKTA_DPOP",
        ),
        (httpx2.Response(400, json={"error": "invalid_dpop_proof"}), True, r"proof$"),
        (httpx2.Response(400, json={"error": "Bad <script>"}), True, r"^[^<]*HTTP 400$"),
        (httpx2.Response(500, content=b"<html>"), True, r"HTTP 500$"),
        (httpx2.Response(200, content=b"not json"), True, "malformed"),
        (httpx2.Response(200, json={"access_token": "t", "token_type": "DPoP"}), True, "malformed"),
        (ok(expires_in=0), True, "malformed"),
        (ok(expires_in=60), True, "malformed"),
        (ok(expires_in=True), True, "malformed"),
        (ok("evil<b>"), True, r"^Okta's token_type is not DPoP[^<]*$"),
        (ok(expires_in="3600"), True, "malformed"),
        (httpx2.Response(200, json={**ok().json(), "access_token": ""}), True, "malformed"),
        (httpx2.ConnectError("boom"), True, r"^token request failed: ConnectError$"),
        (httpx2.ReadTimeout("slow"), True, r"ReadTimeout$"),
    ],
)
async def test_error_mapping(
    key: rsa.RSAPrivateKey, response: httpx2.Response | Exception, dpop: bool, message: str
) -> None:
    with pytest.raises(TokenError, match=message):
        await provider(Okta(response), key, dpop=dpop).token()


@pytest.mark.anyio
async def test_transport_error_drops_request_context(key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(TokenError) as e:
        await provider(Okta(httpx2.ConnectError("boom")), key).token()
    assert e.value.__cause__ is None
    assert e.value.__context__ is None


@pytest.mark.anyio
async def test_secrets_never_logged_or_shown(
    key: rsa.RSAPrivateKey, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    okta = Okta(nonce_error(), ok())
    p = provider(okta, key)
    token = await p.token()
    errors: list[str] = []
    for response in (httpx2.Response(401, json={"error": "invalid_client"}), ok("Bearer")):
        with pytest.raises(TokenError) as e:
            await provider(Okta(response), key).token()
        errors.append(str(e.value))
    secrets = [
        ACCESS_TOKEN,
        *(okta.form(i)["client_assertion"] for i in range(2)),
        *(r.headers["DPoP"] for r in okta.requests),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        str(key.private_numbers().d),
    ]
    shown = "\n".join([caplog.text, repr(token), repr(p), *errors])
    assert "service token issued (DPoP, expires in 3600 s)" in caplog.text
    for secret in secrets:
        assert secret not in shown


@pytest.mark.anyio
async def test_ssws() -> None:
    provider = SSWSProvider(SecretStr("00ssws-secret"))
    token = await provider.token()
    assert token.authorization == "SSWS 00ssws-secret"
    assert "00ssws-secret" not in repr(token)
    provider.invalidate(token)
    assert await provider.token() == token


@pytest.mark.anyio
async def test_fake_provider() -> None:
    fake: TokenProvider = FakeTokenProvider()
    assert (await fake.token()).authorization == "Bearer fake-token"


def _pem(key: Any, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def test_load_private_key(tmp_path: Path, key: rsa.RSAPrivateKey) -> None:
    path = tmp_path / "okta.pem"
    path.write_bytes(_pem(key))
    assert load_private_key(path).private_numbers() == key.private_numbers()


@pytest.mark.parametrize(
    "content",
    [
        lambda: _pem(ec.generate_private_key(ec.SECP256R1())),
        lambda: _pem(rsa.generate_private_key(public_exponent=65537, key_size=1024)),  # noqa: S505
        lambda: _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048), b"pw"),
        lambda: b"-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
        lambda: b"",
    ],
    ids=["ec", "rsa-1024", "encrypted", "garbage", "empty"],
)
def test_load_private_key_rejects(tmp_path: Path, content: Callable[[], bytes]) -> None:
    path = tmp_path / "okta.pem"
    data = content()
    path.write_bytes(data)
    with pytest.raises(ConfigError) as e:
        load_private_key(path)
    assert e.value.errors == [
        f"OKTA_PRIVATE_KEY_FILE: {path} is not an unencrypted PEM RSA private key "
        "of at least 2048 bits"
    ]
    assert e.value.__context__ is None


def test_load_private_key_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="OKTA_PRIVATE_KEY_FILE"):
        load_private_key(tmp_path / "missing.pem")
