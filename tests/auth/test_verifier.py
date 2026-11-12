"""The HTTP token verifier (plan 4.3, design §8.5), against a local signing key and a mocked
issuer."""

import json
import logging
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import anyio
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from jwt.utils import base64url_encode

from okta_mcp.auth import verifier as verifier_module
from okta_mcp.auth.principal import VerifiedToken
from okta_mcp.auth.verifier import (
    JWKS_TTL,
    LEEWAY,
    MAX_TOKEN_BYTES,
    REFRESH_EVERY,
    RETRY_MAX,
    RETRY_MIN,
    UNKNOWN_KID_INTERVAL,
    JWTVerifier,
    parse_jwks,
)
from okta_mcp.config import Config, load_config

ISSUER = "https://example.okta.com/oauth2/aus1example000000000"
METADATA = ISSUER + "/.well-known/oauth-authorization-server"
JWKS_URI = ISSUER + "/v1/keys"
AUDIENCE = "https://mcp.example.com/mcp"
CLIENT = "0oa1client0000000000"
UID = "00u1httpuser00000000"
GROUP = "00g1readers000000000"
NOW = 1_760_000_000.0

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
DROP: Any = object()
"""An override that removes the claim (or JWK member)."""


def _without_drops(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not DROP}


def rsa_jwk(key: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    jwk: dict[str, Any] = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return _without_drops({**jwk, "kid": kid, "use": "sig", "alg": "RS256", **extra})


def ec_jwk(key: ec.EllipticCurvePrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    jwk: dict[str, Any] = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return _without_drops({**jwk, "kid": kid, "use": "sig", **extra})


def claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user@example.com",
        "uid": UID,
        "cid": CLIENT,
        "scp": ["okta-mcp"],
        "groups": [GROUP],
        "iat": int(NOW) - 60,
        "exp": int(NOW) + 3600,
    }
    return _without_drops({**base, **overrides})


def sign(
    payload: dict[str, Any] | None = None,
    *,
    key: Any = RSA_KEY,
    alg: str = "RS256",
    kid: str | None = "k1",
    headers: dict[str, Any] | None = None,
) -> str:
    h = {**({"kid": kid} if kid is not None else {}), **(headers or {})}
    return jwt.encode(payload or claims(), key, algorithm=alg, headers=h)


class Issuer:
    """A mocked custom authorization server: metadata and JWKS, with request counts."""

    def __init__(self) -> None:
        self.keys: list[dict[str, Any]] = [rsa_jwk(RSA_KEY, "k1"), ec_jwk(EC_KEY, "e1")]
        self.metadata: Any = {"issuer": ISSUER, "jwks_uri": JWKS_URI}
        self.up = True
        self.jwks_status = 200
        self.raw_jwks: bytes | None = None
        self.metadata_hits = 0
        self.jwks_hits = 0
        self.other: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if not self.up:
            raise httpx2.ConnectError("issuer down")
        url = str(request.url)
        if url == METADATA:
            self.metadata_hits += 1
            return httpx2.Response(200, json=self.metadata)
        if url == JWKS_URI:
            self.jwks_hits += 1
            if self.raw_jwks is not None:
                return httpx2.Response(self.jwks_status, content=self.raw_jwks)
            return httpx2.Response(self.jwks_status, json={"keys": self.keys})
        self.other.append(url)
        return httpx2.Response(200, json={"keys": self.keys})  # would work, if asked


class Clock:
    def __init__(self) -> None:
        self.wall = NOW
        self.mono = 1000.0

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    key = tmp_path / "key.pem"
    key.write_bytes(
        RSA_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text("roles: {}\n")
    values = {
        "MCP_PUBLIC_URL": AUDIENCE,
        "MCP_ISSUER": ISSUER,
        "MCP_ALLOWED_CLIENT_IDS": CLIENT,
        "MCP_POLICY_FILE": str(policy),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": "https://example.okta.com",
        "OKTA_SCOPES": "okta.groups.read",
        "OKTA_CLIENT_ID": "0oa1service000000000",
        "OKTA_PRIVATE_KEY_FILE": str(key),
    }
    return {**values, **extra}


@pytest.fixture
def issuer() -> Issuer:
    return Issuer()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return load_config(env(tmp_path))


Make = Callable[..., JWTVerifier]


@pytest.fixture
async def make(issuer: Issuer, clock: Clock, config: Config) -> AsyncIterator[Make]:
    """Builds verifiers on the mocked issuer (or `handler`), closing their clients after."""
    clients: list[httpx2.AsyncClient] = []

    def build(
        cfg: Config | None = None, handler: Callable[[httpx2.Request], Any] | None = None
    ) -> JWTVerifier:
        transport = httpx2.MockTransport(handler or issuer)
        http = httpx2.AsyncClient(transport=transport, follow_redirects=False)
        clients.append(http)
        return JWTVerifier(
            http, cfg or config, clock=lambda: clock.wall, monotonic=lambda: clock.mono
        )

    yield build
    for http in clients:
        await http.aclose()


async def loaded(make: Make, cfg: Config | None = None) -> JWTVerifier:
    v = make(cfg)
    assert await v.refresh()
    assert v.ready()
    return v


# --- accepted ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_valid_rs256_token(make: Make) -> None:
    v = await loaded(make)
    token = sign()
    result = await v.verify_token(token)
    assert isinstance(result, VerifiedToken)
    p = result.principal
    assert (p.uid, p.sub, p.client_id, p.groups, p.exp) == (
        UID,
        "user@example.com",
        CLIENT,
        frozenset({GROUP}),
        int(NOW) + 3600,
    )
    assert result.subject == UID
    assert result.client_id == CLIENT
    assert result.scopes == ["okta-mcp"]
    assert result.expires_at == int(NOW) + 3600
    assert result.claims == {"iss": ISSUER}
    assert result.token == token


@pytest.mark.anyio
async def test_valid_es256_token(make: Make) -> None:
    v = await loaded(make)
    assert await v.verify_token(sign(key=EC_KEY, alg="ES256", kid="e1")) is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": [AUDIENCE, "api://other"]},
        {"scp": ["openid", "okta-mcp", "offline_access"]},
        {"scp": DROP, "scope": "openid okta-mcp"},
        {"cid": DROP, "client_id": CLIENT},
        {"cid": CLIENT, "client_id": CLIENT},
        {"nbf": int(NOW) + LEEWAY - 1},
        {"iat": int(NOW) + LEEWAY - 1},
        {"exp": int(NOW) + 1},
        {"iat": int(NOW) - 86400},
        {"exp": NOW + 10.5, "iat": NOW - 0.5},
    ],
)
async def test_accepted_variants(make: Make, overrides: dict[str, Any]) -> None:
    v = await loaded(make)
    assert await v.verify_token(sign(claims(**overrides))) is not None


@pytest.mark.anyio
async def test_missing_scope_is_not_a_rejection(make: Make) -> None:
    """The SDK answers a token without `MCP_REQUIRED_SCOPE` with 403 `insufficient_scope`
    (§8.1); a 401 here would send the client to sign in again for the same token."""
    v = await loaded(make)
    result = await v.verify_token(sign(claims(scp=["openid"])))
    assert result is not None
    assert result.scopes == ["openid"]
    result = await v.verify_token(sign(claims(scp=DROP)))
    assert result is not None
    assert result.scopes == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "groups",
    [DROP, GROUP, [GROUP, 5], {"id": GROUP}, None, [[GROUP]], True],
)
async def test_malformed_groups_are_no_groups(make: Make, groups: Any) -> None:
    v = await loaded(make)
    result = await v.verify_token(sign(claims(groups=groups)))
    assert result is not None
    assert result.principal.groups == frozenset()


@pytest.mark.anyio
async def test_groups_claim_name_is_configurable(make: Make, tmp_path: Path) -> None:
    cfg = load_config(env(tmp_path, MCP_GROUPS_CLAIM="mcp_groups"))
    v = await loaded(make, cfg)
    result = await v.verify_token(sign(claims(groups=DROP, mcp_groups=[GROUP])))
    assert result is not None
    assert result.principal.groups == frozenset({GROUP})
    result = await v.verify_token(sign(claims()))  # `groups` is not the configured claim
    assert result is not None
    assert result.principal.groups == frozenset()


@pytest.mark.anyio
async def test_any_client_when_star(make: Make, tmp_path: Path) -> None:
    cfg = load_config(env(tmp_path, MCP_ALLOWED_CLIENT_IDS="*"))
    v = await loaded(make, cfg)
    assert await v.verify_token(sign(claims(cid="0oa1whatever00000000"))) is not None


@pytest.mark.anyio
async def test_audience_defaults_to_public_url_and_is_configurable(
    make: Make, tmp_path: Path
) -> None:
    cfg = load_config(env(tmp_path, MCP_AUDIENCE="api://okta-mcp"))
    v = await loaded(make, cfg)
    assert await v.verify_token(sign(claims(aud="api://okta-mcp"))) is not None
    assert await v.verify_token(sign(claims())) is None


# --- rejected ---------------------------------------------------------------------------


async def rejected_for(v: JWTVerifier, token: str, caplog: pytest.LogCaptureFixture) -> str:
    """The logged reason `token` was refused for (each check is pinned, not just the outcome,
    since the alg checks back each other up)."""
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="okta_mcp"):
        assert await v.verify_token(token) is None
    (line,) = [r.getMessage() for r in caplog.records if "rejected" in r.getMessage()]
    return line.removeprefix("bearer token rejected: ")


@pytest.mark.anyio
async def test_forged_signature(make: Make) -> None:
    v = await loaded(make)
    assert await v.verify_token(sign(key=OTHER_RSA_KEY)) is None
    head, _, sig = sign().split(".")
    other = base64url_encode(json.dumps(claims(uid="00u1someoneelse00000")).encode())
    assert await v.verify_token(f"{head}.{other.decode()}.{sig}") is None


@pytest.mark.anyio
async def test_alg_none(make: Make, caplog: pytest.LogCaptureFixture) -> None:
    v = await loaded(make)
    token = jwt.encode(claims(), "", algorithm="none", headers={"kid": "k1"})
    assert await rejected_for(v, token, caplog) == "alg not RS256 or ES256"
    # And with the signature segment left on.
    head, body, _ = token.split(".")
    _, _, sig = sign().split(".")
    assert await rejected_for(v, f"{head}.{body}.{sig}", caplog) == "alg not RS256 or ES256"


@pytest.mark.anyio
async def test_hs256_with_the_public_key_as_secret(
    make: Make, caplog: pytest.LogCaptureFixture
) -> None:
    """Algorithm confusion: an HMAC over the issuer's public key, which anyone can fetch."""
    v = await loaded(make)
    public_pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib
    import hmac

    head = base64url_encode(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    body = base64url_encode(json.dumps(claims()).encode())
    mac = hmac.new(public_pem, head + b"." + body, hashlib.sha256).digest()
    token = b".".join([head, body, base64url_encode(mac)]).decode()
    assert await rejected_for(v, token, caplog) == "alg not RS256 or ES256"


@pytest.mark.anyio
async def test_other_rsa_algorithms_refused(make: Make, caplog: pytest.LogCaptureFixture) -> None:
    v = await loaded(make)
    for alg in ("RS384", "PS256"):
        assert await rejected_for(v, sign(alg=alg), caplog) == "alg not RS256 or ES256"


@pytest.mark.anyio
async def test_alg_must_match_the_keys(make: Make, caplog: pytest.LogCaptureFixture) -> None:
    """ES256 header naming the RSA key's kid (and the reverse)."""
    v = await loaded(make)
    mismatch = "alg does not match the key"
    assert await rejected_for(v, sign(key=EC_KEY, alg="ES256", kid="k1"), caplog) == mismatch
    assert await rejected_for(v, sign(kid="e1"), caplog) == mismatch


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    # PyJWT drops `b64: true` when encoding, and `b64: false` needs `crit` (RFC 7797).
    [{"crit": ["exp"]}, {"crit": []}, {"b64": False, "crit": ["b64"]}],
)
async def test_crit_and_b64_headers_refused(
    make: Make, caplog: pytest.LogCaptureFixture, headers: dict[str, Any]
) -> None:
    v = await loaded(make)
    # PyJWT refuses a `crit` it doesn't understand itself; ours is the backstop.
    assert await rejected_for(v, sign(headers=headers), caplog) in {
        "crit or b64 header",
        "InvalidTokenError",
    }


@pytest.mark.anyio
@pytest.mark.parametrize("kid", [None, "", "x" * 257])
async def test_kid_required(make: Make, issuer: Issuer, kid: str | None) -> None:
    v = await loaded(make)
    hits = issuer.jwks_hits
    token = sign(kid=kid)
    assert await v.verify_token(token) is None
    assert issuer.jwks_hits == hits  # no refetch for a token that can't name a key


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"iss": ISSUER + "/"}, "iss"),
        ({"iss": "https://example.okta.com/oauth2/default"}, "iss"),
        ({"iss": DROP}, "iss"),
        ({"aud": "https://mcp.example.com/mcp/"}, "aud"),
        ({"aud": "https://MCP.example.com/mcp"}, "aud"),
        ({"aud": [AUDIENCE, 5]}, "aud"),
        ({"aud": {"v": AUDIENCE}}, "aud"),
        ({"aud": DROP}, "aud"),
        ({"exp": int(NOW)}, "expired"),  # no skew on exp: the SDK has none
        ({"exp": 10**400}, "exp or iat"),
        ({"iat": -(10**400)}, "exp or iat"),
        ({"exp": DROP}, "exp or iat"),
        ({"exp": True}, "exp or iat"),
        ({"exp": "9999999999"}, "exp or iat"),
        ({"iat": DROP}, "exp or iat"),
        ({"iat": int(NOW) + LEEWAY + 1}, "iat in the future"),
        ({"iat": int(NOW) - 86400 - LEEWAY - 1}, "older than"),
        ({"nbf": int(NOW) + LEEWAY + 1}, "nbf"),
        ({"nbf": "0"}, "nbf"),
        ({"cid": "0oa1other00000000000"}, "cid not in"),
        ({"cid": DROP}, "cid missing"),
        ({"cid": ""}, "cid missing"),
        ({"cid": [CLIENT]}, "cid missing"),
        ({"client_id": "0oa1other00000000000"}, "cid and client_id disagree"),
        ({"uid": DROP}, "uid"),
        ({"uid": "00g1readers000000000"}, "uid"),
        ({"uid": "00u1httpuser00000000/../x"}, "uid"),
        ({"uid": 5}, "uid"),
        ({"sub": DROP}, "sub"),
        ({"sub": ""}, "sub"),
        ({"scp": "okta-mcp"}, "scp"),
        ({"scp": ["okta-mcp", 1]}, "scp"),
        ({"scope": ["okta-mcp"]}, "scope"),
    ],
)
async def test_rejected_claims(
    make: Make, caplog: pytest.LogCaptureFixture, overrides: dict[str, Any], reason: str
) -> None:
    v = await loaded(make)
    token = sign(claims(**overrides))
    with caplog.at_level(logging.DEBUG, logger="okta_mcp"):
        assert await v.verify_token(token) is None
    assert f"bearer token rejected: {reason}" in caplog.text
    assert token not in caplog.text


@pytest.mark.anyio
async def test_max_token_age_is_configurable(make: Make, tmp_path: Path) -> None:
    cfg = load_config(env(tmp_path, MCP_MAX_TOKEN_AGE="3600"))  # noqa: S106
    v = await loaded(make, cfg)
    assert await v.verify_token(sign(claims(iat=int(NOW) - 3600))) is not None
    assert await v.verify_token(sign(claims(iat=int(NOW) - 3600 - LEEWAY - 1))) is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-jwt",
        "a.b",
        "a.b.c",
        "....",
        "eyJhbGciOiJSUzI1NiJ9.e30.",
        "eyJ.eyJ.eyJ",
        "W10.e30.c2ln",  # header `[]`
        "bnVsbA.e30.c2ln",  # header `null`
        "é.é.é",
        "x" * (MAX_TOKEN_BYTES + 1),
    ],
)
async def test_garbage_is_none_and_never_raises(make: Make, token: str) -> None:
    v = await loaded(make)
    assert await v.verify_token(token) is None


@pytest.mark.anyio
async def test_garbage_payloads_never_raise(make: Make) -> None:
    """Validly signed, but the payload isn't a claims object."""
    v = await loaded(make)
    head = base64url_encode(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
    for payload in [b"[]", b"null", b"5", b'"x"', b"{", b"\xff"]:
        body = base64url_encode(payload)
        signing_input = head + b"." + body
        sig = RSAAlgorithm(RSAAlgorithm.SHA256).sign(signing_input, RSA_KEY)
        token = (signing_input + b"." + base64url_encode(sig)).decode()
        assert await v.verify_token(token) is None


@pytest.mark.anyio
async def test_oversized_token_refused_before_parsing(make: Make) -> None:
    v = await loaded(make)
    token = sign(claims(pad="x" * MAX_TOKEN_BYTES))
    assert await v.verify_token(token) is None


@pytest.mark.anyio
async def test_logs_never_hold_the_token_or_claims(
    make: Make, issuer: Issuer, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    v = await loaded(make)
    tokens = [sign(), sign(claims(cid="0oa1other00000000000")), sign(kid="nope")]
    with caplog.at_level(logging.DEBUG):
        for t in tokens:
            await v.verify_token(t)
        clock.advance(UNKNOWN_KID_INTERVAL)
        issuer.up = False
        await v.verify_token(tokens[2])
    for t in tokens:
        assert t not in caplog.text
    assert "user@example.com" not in caplog.text
    assert UID not in caplog.text


# --- keys: discovery, refetch, readiness --------------------------------------------------


@pytest.mark.anyio
async def test_unknown_kid_refetches_at_most_once_a_minute(
    make: Make, issuer: Issuer, clock: Clock
) -> None:
    v = await loaded(make)
    assert issuer.jwks_hits == 1
    issuer.keys.append(rsa_jwk(OTHER_RSA_KEY, "k2"))
    clock.advance(UNKNOWN_KID_INTERVAL)
    assert await v.verify_token(sign(key=OTHER_RSA_KEY, kid="k2")) is not None  # rotated in
    assert issuer.jwks_hits == 2
    for i in range(20):
        assert await v.verify_token(sign(kid=f"bogus{i}")) is None
    assert issuer.jwks_hits == 2  # within the interval: no refetch
    clock.advance(UNKNOWN_KID_INTERVAL - 1)
    assert await v.verify_token(sign(kid="bogus")) is None
    assert issuer.jwks_hits == 2
    clock.advance(1)
    assert await v.verify_token(sign(kid="bogus")) is None
    assert issuer.jwks_hits == 3


@pytest.mark.anyio
async def test_unknown_kid_right_after_load_does_not_refetch(make: Make, issuer: Issuer) -> None:
    v = await loaded(make)
    assert await v.verify_token(sign(kid="k9")) is None
    assert issuer.jwks_hits == 1


@pytest.mark.anyio
async def test_concurrent_unknown_kids_share_one_refetch(
    make: Make, issuer: Issuer, clock: Clock
) -> None:
    v = await loaded(make)
    clock.advance(UNKNOWN_KID_INTERVAL)
    results: list[object] = []

    async def one(i: int) -> None:
        results.append(await v.verify_token(sign(kid=f"new{i}")))

    async with anyio.create_task_group() as tg:
        for i in range(25):
            tg.start_soon(one, i)
    assert results == [None] * 25
    assert issuer.jwks_hits == 2


@pytest.mark.anyio
async def test_issuer_down_at_startup(make: Make, issuer: Issuer, clock: Clock) -> None:
    """Startup doesn't need the issuer: not ready, every token `None` without a fetch, until a
    refresh succeeds."""
    issuer.up = False
    v = make()
    assert not v.ready()
    assert await v.verify_token(sign()) is None
    assert issuer.metadata_hits == 0
    assert not await v.refresh()
    assert not v.ready()
    issuer.up = True
    clock.advance(1)
    assert await v.refresh()
    assert v.ready()
    assert await v.verify_token(sign()) is not None


@pytest.mark.anyio
async def test_warm_cache_serves_until_ttl(make: Make, issuer: Issuer, clock: Clock) -> None:
    v = await loaded(make)
    issuer.up = False
    clock.advance(REFRESH_EVERY)
    assert not await v.refresh()
    assert v.ready()
    assert await v.verify_token(sign()) is not None
    clock.advance(JWKS_TTL - REFRESH_EVERY - 1)
    assert v.ready()
    clock.advance(1)
    assert not v.ready()
    # Past the TTL it is the gate that refuses (503); the verifier itself still answers, so
    # that the gate's readings are the only readiness readings (`test_app`).
    assert await v.verify_token(sign(claims(exp=int(clock.wall) + 600))) is not None


@pytest.mark.anyio
async def test_a_wall_clock_step_does_not_extend_the_cache(make: Make, clock: Clock) -> None:
    v = await loaded(make)
    clock.mono += JWKS_TTL
    assert not v.ready()


@pytest.mark.anyio
async def test_refresh_replaces_keys(make: Make, issuer: Issuer, clock: Clock) -> None:
    """A key the issuer drops stops verifying at the next refresh."""
    v = await loaded(make)
    issuer.keys = [rsa_jwk(OTHER_RSA_KEY, "k2")]
    clock.advance(REFRESH_EVERY)
    assert await v.refresh()
    assert await v.verify_token(sign()) is None
    assert await v.verify_token(sign(key=OTHER_RSA_KEY, kid="k2")) is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "metadata",
    [
        {"issuer": ISSUER + "/", "jwks_uri": JWKS_URI},
        {"issuer": "https://evil.example.com", "jwks_uri": JWKS_URI},
        {"jwks_uri": JWKS_URI},
        {"issuer": ISSUER},
        {"issuer": ISSUER, "jwks_uri": "https://evil.example.com/keys"},
        {"issuer": ISSUER, "jwks_uri": "http://example.okta.com/oauth2/v1/keys"},
        {"issuer": ISSUER, "jwks_uri": "https://example.okta.com:8443/keys"},
        {"issuer": ISSUER, "jwks_uri": "https://user@example.okta.com/keys"},
        {"issuer": ISSUER, "jwks_uri": 5},
        [ISSUER],
        "x",
    ],
)
async def test_bad_metadata_loads_nothing(make: Make, issuer: Issuer, metadata: Any) -> None:
    issuer.metadata = metadata
    v = make()
    assert not await v.refresh()
    assert not v.ready()
    assert issuer.jwks_hits == 0
    assert issuer.other == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "raw"),
    [
        (500, None),
        (302, None),
        (200, b"not json"),
        (200, b'{"keys": "x"}'),
        (200, b"[]"),
        (200, json.dumps({"keys": [], "pad": "x" * 300_000}).encode()),
    ],
)
async def test_bad_jwks_responses(
    make: Make, issuer: Issuer, status: int, raw: bytes | None, caplog: pytest.LogCaptureFixture
) -> None:
    issuer.jwks_status = status
    issuer.raw_jwks = raw
    v = make()
    assert not await v.refresh()
    assert not v.ready()
    assert "JWKS fetch from the issuer failed" in caplog.text
    assert "pad" not in caplog.text


@pytest.mark.anyio
async def test_a_failed_refresh_keeps_the_old_keys(
    make: Make, issuer: Issuer, clock: Clock
) -> None:
    v = await loaded(make)
    issuer.keys = []
    clock.advance(10)
    assert not await v.refresh()
    assert await v.verify_token(sign()) is not None


def test_parse_jwks_keeps_only_usable_signing_keys() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    p384 = ec.generate_private_key(ec.SECP384R1())
    keys = parse_jwks(
        {
            "keys": [
                rsa_jwk(RSA_KEY, "good-rsa"),
                ec_jwk(EC_KEY, "good-ec"),
                rsa_jwk(RSA_KEY, "no-alg", alg=DROP),
                rsa_jwk(small, "small"),
                ec_jwk(p384, "p384"),
                rsa_jwk(RSA_KEY, "enc", use="enc"),
                rsa_jwk(RSA_KEY, "rs384", alg="RS384"),
                rsa_jwk(RSA_KEY, "dup"),
                rsa_jwk(OTHER_RSA_KEY, "dup"),
                {"kty": "oct", "k": "c2VjcmV0", "kid": "hmac"},
                {"kty": "RSA", "kid": "broken", "n": "x"},
                {"kid": "no-kty"},
                rsa_jwk(RSA_KEY, ""),
                "x",
            ]
        }
    )
    assert set(keys) == {"good-rsa", "good-ec", "no-alg"}


def test_parse_jwks_with_no_usable_key_is_an_error() -> None:
    with pytest.raises(verifier_module._FetchError):  # pyright: ignore[reportPrivateUsage]
        parse_jwks({"keys": [rsa_jwk(RSA_KEY, "enc", use="enc")]})


@pytest.mark.anyio
async def test_run_loads_then_refreshes_and_backs_off(make: Make, issuer: Issuer) -> None:
    sleeps: list[float] = []
    issuer.up = False

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 9:
            issuer.up = True
        if len(sleeps) == 11:
            raise anyio.get_cancelled_exc_class()

    v = make()
    with pytest.raises(anyio.get_cancelled_exc_class()):
        await v.run(sleep)
    assert sleeps == [
        RETRY_MIN,
        2.0,
        4.0,
        8.0,
        16.0,
        32.0,
        RETRY_MAX,
        RETRY_MAX,
        RETRY_MAX,
        REFRESH_EVERY,
        REFRESH_EVERY,
    ]
    assert v.ready()


def test_needs_the_http_auth_settings(tmp_path: Path) -> None:
    principal = tmp_path / "p.yaml"
    principal.write_text("uid: 00u1devuser000000000\nsub: d\ngroups: []\n")
    values = env(tmp_path)
    for name in ("MCP_PUBLIC_URL", "MCP_ISSUER", "MCP_ALLOWED_CLIENT_IDS"):
        del values[name]
    del values["OKTA_CLIENT_ID"], values["OKTA_PRIVATE_KEY_FILE"]
    values |= {
        "MCP_DEV_MODE": "1",
        "MCP_DEV_PRINCIPAL_FILE": str(principal),
        "OKTA_API_TOKEN": "x",
    }
    cfg = load_config(values)
    with pytest.raises(ValueError, match="MCP_ISSUER"):
        JWTVerifier(httpx2.AsyncClient(), cfg)  # raises before the client is used


# --- in the app -------------------------------------------------------------------------

PILOT = Path(__file__).parent.parent / "policy" / "fixtures" / "pilot.yaml"
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
JSON_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


@pytest.mark.anyio
async def test_in_the_app(issuer: Issuer, clock: Clock, tmp_path: Path) -> None:
    """The real verifier behind the SDK's auth: 503 until the keys load, then 200 for a valid
    token, 403 `insufficient_scope` without the scope, 401 for a bad one."""
    from okta_mcp.app import build_app
    from okta_mcp.server import build_runtime

    def transport(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/oauth2/v1/token":
            return httpx2.Response(
                200, json={"access_token": "svc", "token_type": "Bearer", "expires_in": 3600}
            )
        return issuer(request)

    cfg = load_config(env(tmp_path, MCP_POLICY_FILE=str(PILOT), OKTA_DPOP="false"))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as http:
        runtime = build_runtime(cfg, http)
        v = JWTVerifier(http, cfg, clock=lambda: clock.wall, monotonic=lambda: clock.mono)
        app = build_app(runtime, cfg, v)
        async with (
            app.router.lifespan_context(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="https://mcp.example.com"
            ) as client,
        ):

            async def post(token: str) -> httpx2.Response:
                headers = {**JSON_HEADERS, "authorization": f"Bearer {token}"}
                return await client.post("/mcp", json=INIT, headers=headers)

            # The SDK checks `exp` against the real clock too.
            clock.wall = time.time()
            now = {"iat": int(clock.wall) - 60, "exp": int(clock.wall) + 3600}
            cold = await post(sign(claims(**now)))
            assert await v.refresh()
            ok = await post(sign(claims(**now)))
            no_scope = await post(sign(claims(scp=["openid"], **now)))
            forged = await post(sign(key=OTHER_RSA_KEY))
            readyz = await client.get("/readyz")
            await runtime.tokens.token()
            readyz_warm = await client.get("/readyz")
    assert cold.status_code == 503
    assert ok.status_code == 200
    assert no_scope.status_code == 403
    assert 'error="insufficient_scope"' in no_scope.headers["www-authenticate"]
    assert forged.status_code == 401
    assert 'error="invalid_token"' in forged.headers["www-authenticate"]
    assert "resource_metadata=" in forged.headers["www-authenticate"]
    assert readyz.status_code == 503  # keys loaded, no service token yet
    assert readyz_warm.status_code == 200


# --- review regressions -----------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("alg", [["RS256"], {"a": 1}, 256, None, True])
async def test_unhashable_or_odd_alg_is_rejected_not_raised(
    make: Make, caplog: pytest.LogCaptureFixture, alg: Any
) -> None:
    v = await loaded(make)
    head = base64url_encode(json.dumps({"alg": alg, "kid": "k1"}).encode()).decode()
    assert await rejected_for(v, f"{head}.e30.c2ln", caplog) == "alg not RS256 or ES256"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "jwks_uri",
    [
        "https://example.okta.com:99999/keys",
        "https://[::1/keys",
        "https://example.okta.com:x/keys",
        "https://example.okta.com/ke ys",
        "",
    ],
)
async def test_malformed_jwks_uri_fails_the_fetch_without_raising(
    make: Make, issuer: Issuer, jwks_uri: str
) -> None:
    issuer.metadata = {"issuer": ISSUER, "jwks_uri": jwks_uri}
    v = make()
    assert not await v.refresh()
    assert issuer.other == []


@pytest.mark.anyio
async def test_jwks_uri_with_the_default_port_is_the_issuers_origin(
    make: Make, issuer: Issuer
) -> None:
    issuer.metadata = {"issuer": ISSUER, "jwks_uri": "https://EXAMPLE.okta.com:443/oauth2/v1/keys"}
    v = make()
    assert await v.refresh()
    assert issuer.other == ["https://example.okta.com/oauth2/v1/keys"]


@pytest.mark.anyio
async def test_an_endless_jwks_body_is_cut_off(make: Make, issuer: Issuer) -> None:
    """The size limit holds while reading, not after buffering the whole body."""
    sent = 0

    async def endless() -> AsyncIterator[bytes]:
        nonlocal sent
        while True:
            sent += 64 * 1024
            yield b" " * (64 * 1024)

    def handler(request: httpx2.Request) -> httpx2.Response:
        if str(request.url) == JWKS_URI:
            return httpx2.Response(200, content=endless())
        return issuer(request)

    v = make(handler=handler)
    assert not await v.refresh()
    assert sent <= 512 * 1024


@pytest.mark.anyio
async def test_run_survives_an_unexpected_exception(
    make: Make, issuer: Issuer, caplog: pytest.LogCaptureFixture
) -> None:
    """`run` shares a task group with the server: a bug in a fetch must not stop it."""
    calls = 0

    def flaky(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("bug")
        return issuer(request)

    v = make(handler=flaky)
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise anyio.get_cancelled_exc_class()

    with pytest.raises(anyio.get_cancelled_exc_class()):
        await v.run(sleep)
    assert sleeps == [RETRY_MIN, REFRESH_EVERY]
    assert v.ready()
    assert "internal error in JWKS refresh: RuntimeError" in caplog.text


@pytest.mark.anyio
async def test_unknown_kid_refetch_bug_is_none_not_a_raise(
    make: Make, issuer: Issuer, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """Any sender can reach the refetch with a new `kid`; a bug there must not escape."""
    broken = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        if broken:
            raise RuntimeError("bug")
        return issuer(request)

    v = make(handler=handler)
    assert await v.refresh()
    broken = True
    clock.advance(UNKNOWN_KID_INTERVAL)
    assert await v.verify_token(sign(kid="new")) is None
    assert "internal error in JWKS refresh: RuntimeError" in caplog.text
    assert await v.verify_token(sign()) is not None  # old keys still serve


@pytest.mark.anyio
@pytest.mark.parametrize("pad", [0, 300_000])
async def test_compressed_documents_are_decoded_and_capped(
    make: Make, issuer: Issuer, caplog: pytest.LogCaptureFixture, pad: int
) -> None:
    """Asked for uncompressed; a compressed answer is still taken (refusing it would leave
    `/mcp` at 503 behind a compressing proxy), and the cap counts decoded bytes."""
    import gzip

    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get("accept-encoding", ""))
        if str(request.url) == JWKS_URI:
            doc = {"keys": issuer.keys, "pad": " " * pad}
            body = gzip.compress(json.dumps(doc).encode())
            return httpx2.Response(200, content=body, headers={"content-encoding": "gzip"})
        return issuer(request)

    v = make(handler=handler)
    assert await v.refresh() is (pad == 0)
    assert seen == ["identity", "identity"]
    if pad:
        assert "JWKS fetch from the issuer failed: response too large" in caplog.text
