import base64
import hashlib
import json
from typing import Any

import anyio
import httpx2
import jwt
import pytest
from _fakes import FakeTokenProvider
from jwt.algorithms import ECAlgorithm

from okta_mcp.okta.client import OktaClient, OriginError, UpstreamError, new_http_client
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.token import ServiceToken, TokenError

ORG = "https://example.okta.com"
USERS = ORG + "/api/v1/users"
DPOP_TOKEN = ServiceToken("eyJ.dpop-bound.sig", "DPoP")


def nonce_401(nonce: str = "n1") -> httpx2.Response:
    return httpx2.Response(
        401,
        headers={"DPoP-Nonce": nonce, "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'},
    )


class Okta:
    """Records requests and answers them from `responses` in order (last one repeats)."""

    def __init__(self, *responses: httpx2.Response | Exception) -> None:
        self.responses = list(responses) or [httpx2.Response(200, json=[])]
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        r = self.responses[min(len(self.requests), len(self.responses)) - 1]
        if isinstance(r, Exception):
            raise r
        return r

    def proof(self, i: int = 0) -> dict[str, Any]:
        proof = self.requests[i].headers["DPoP"]
        jwk = ECAlgorithm.from_jwk(json.dumps(jwt.get_unverified_header(proof)["jwk"]))
        return jwt.decode(proof, jwk, algorithms=["ES256"])  # pyright: ignore[reportArgumentType]


def client(
    handler: Any,
    tokens: FakeTokenProvider | None = None,
    *,
    dpop: DPoP | None = None,
    max_inflight: int = 10,
    on_request: Any = None,
) -> OktaClient:
    return OktaClient(
        new_http_client(httpx2.MockTransport(handler)),
        org_url=ORG,
        tokens=tokens or FakeTokenProvider(),
        dpop=dpop,
        max_inflight=max_inflight,
        on_request=on_request,
    )


@pytest.mark.anyio
async def test_get_sends_token_and_params() -> None:
    okta = Okta(httpx2.Response(200, json=[{"id": "00u1"}]))
    response = await client(okta).get(USERS, {"limit": "200", "search": 'profile.login eq "a"'})
    assert response.json() == [{"id": "00u1"}]
    (request,) = okta.requests
    assert request.method == "GET"
    assert request.url.params["search"] == 'profile.login eq "a"'
    assert request.headers["Authorization"] == "Bearer fake-token"
    assert request.headers["Accept"] == "application/json"
    assert "DPoP" not in request.headers


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("params", "query"),
    [
        ({"limit": "2"}, "after=00u5&limit=2"),
        ({"after": "00u9"}, "after=00u9"),
        ({}, "after=00u5"),
        (None, "after=00u5"),
    ],
)
async def test_params_merged_into_url_query(params: dict[str, str] | None, query: str) -> None:
    okta = Okta()
    c = client(okta, FakeTokenProvider(DPOP_TOKEN), dpop=DPoP())
    await c.get(USERS + "?after=00u5", params)
    assert okta.requests[0].url.query.decode() == query
    assert okta.proof()["htu"] == USERS


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "https://example.okta.com/api/v1/users?after=x",
        "https://EXAMPLE.okta.com:443/api/v1/users",
    ],
)
async def test_org_urls_accepted(url: str) -> None:
    okta = Okta()
    await client(okta).get(url)
    assert len(okta.requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/api/v1/users",
        "https://example.okta.com.evil.example.com/api/v1/users",
        "http://example.okta.com/api/v1/users",
        "https://example.okta.com:8443/api/v1/users",
        "https://user@example.okta.com/api/v1/users",
        "https://example.okta.com@evil.example.com/api/v1/users",
        "//evil.example.com/api/v1/users",
        "/api/v1/users",
        "https://[::1/api",
        "",
    ],
)
async def test_non_origin_url_refused(url: str) -> None:
    okta = Okta()
    tokens = FakeTokenProvider()
    with pytest.raises(OriginError):
        await client(okta, tokens).get(url)
    assert okta.requests == []
    assert tokens.calls == 0


@pytest.mark.anyio
async def test_semaphore_caps_concurrency() -> None:
    inflight = peak = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await anyio.sleep(0.02)
        inflight -= 1
        return httpx2.Response(200, json=[])

    c = client(handler, max_inflight=3)
    async with anyio.create_task_group() as tg:
        for _ in range(10):
            tg.start_soon(c.get, USERS)
    assert peak == 3


@pytest.mark.anyio
async def test_dpop_proof_per_request() -> None:
    okta = Okta()
    c = client(okta, FakeTokenProvider(DPOP_TOKEN), dpop=DPoP())
    await c.get(USERS, {"limit": "2"})
    await c.get(USERS)
    first, second = okta.proof(0), okta.proof(1)
    assert okta.requests[0].headers["Authorization"] == "DPoP eyJ.dpop-bound.sig"
    assert first["htm"] == "GET"
    assert first["htu"] == USERS  # no query
    digest = hashlib.sha256(DPOP_TOKEN.value.encode()).digest()
    assert first["ath"] == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert first["jti"] != second["jti"]


@pytest.mark.anyio
async def test_nonce_retry_once() -> None:
    okta = Okta(nonce_401(), httpx2.Response(200, json=[]))
    tokens = FakeTokenProvider(DPOP_TOKEN)
    calls: list[None] = []
    c = client(okta, tokens, dpop=DPoP(), on_request=lambda: calls.append(None))
    await c.get(USERS)
    assert len(okta.requests) == len(calls) == 2
    assert "nonce" not in okta.proof(0)
    assert okta.proof(1)["nonce"] == "n1"
    assert okta.proof(0)["jti"] != okta.proof(1)["jti"]
    assert tokens.invalidated == []


@pytest.mark.anyio
async def test_nonce_retry_not_repeated() -> None:
    okta = Okta(nonce_401("n1"), nonce_401("n2"))
    dpop = DPoP()
    tokens = FakeTokenProvider(DPOP_TOKEN)
    with pytest.raises(UpstreamError) as e:
        await client(okta, tokens, dpop=dpop).get(USERS)
    assert e.value.status == 401
    assert len(okta.requests) == 2
    assert dpop.nonce == "n2"
    assert tokens.invalidated == []  # the proof failed, not the token


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("challenge", "invalidated"),
    [
        ('DPoP error="use_dpop_nonce"', False),  # no nonce, so no retry
        ("DPoP error=use_dpop_nonce", False),
        ('DPoP error="invalid_dpop_proof"', True),
        ('DPoP error="invalid_token"', True),
        ('DPoP error="invalid_token", DPoP error="use_dpop_nonce"', True),
        ('DPoP error="invalid_token", error_description="not error=use_dpop_nonce"', True),
        ("", True),
    ],
)
async def test_401_invalidates_unless_nonce_challenge(challenge: str, invalidated: bool) -> None:
    okta = Okta(httpx2.Response(401, headers={"WWW-Authenticate": challenge}))
    tokens = FakeTokenProvider(DPOP_TOKEN)
    with pytest.raises(UpstreamError):
        await client(okta, tokens, dpop=DPoP()).get(USERS)
    assert tokens.invalidated == ([DPOP_TOKEN] if invalidated else [])


class FailingTokenProvider(FakeTokenProvider):
    async def token(self) -> ServiceToken:
        raise TokenError("token request failed: HTTP 401 invalid_client (check OKTA_CLIENT_ID)")


@pytest.mark.anyio
async def test_token_failure_is_upstream_error_without_hint() -> None:
    okta = Okta()
    with pytest.raises(UpstreamError) as e:
        await client(okta, FailingTokenProvider()).get(USERS)
    assert e.value.status is None
    assert str(e.value) == (
        "Okta service credentials are unavailable; contact the MCP administrator"
    )
    assert e.value.__context__ is None
    assert okta.requests == []


@pytest.mark.anyio
async def test_dpop_token_without_key_not_sent() -> None:
    okta = Okta()
    with pytest.raises(RuntimeError, match="no DPoP key"):
        await client(okta, FakeTokenProvider(DPOP_TOKEN)).get(USERS)
    assert okta.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403])
async def test_401_403_sanitized(status: int) -> None:
    body = {"errorCode": "E0000006", "errorSummary": "You do not have permission: okta.apps.read"}
    tokens = FakeTokenProvider()
    with pytest.raises(UpstreamError) as e:
        await client(Okta(httpx2.Response(status, json=body)), tokens).get(USERS)
    assert e.value.status == status
    assert str(e.value) == (
        f"Okta refused the request (HTTP {status}); contact the MCP administrator"
    )
    assert tokens.invalidated == ([ServiceToken("fake-token", "Bearer")] if status == 401 else [])


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            httpx2.Response(404, json={"errorSummary": "Not found: Resource not found: x (User)"}),
            "Okta returned HTTP 404: Not found: Resource not found: x (User)",
        ),
        (
            httpx2.Response(400, json={"errorSummary": "x" * 600}),
            "Okta returned HTTP 400: " + "x" * 500,
        ),
        (httpx2.Response(500, text="<html>"), "Okta returned HTTP 500"),
        (httpx2.Response(502, json={"errorSummary": 5}), "Okta returned HTTP 502"),
        (httpx2.Response(429, json={"errorSummary": ""}), "Okta returned HTTP 429"),
    ],
)
async def test_error_mapping(response: httpx2.Response, message: str) -> None:
    with pytest.raises(UpstreamError) as e:
        await client(Okta(response)).get(USERS)
    assert (e.value.status, str(e.value)) == (response.status_code, message)


@pytest.mark.anyio
async def test_redirect_not_followed() -> None:
    okta = Okta(httpx2.Response(302, headers={"Location": "https://evil.example.com/steal"}))
    with pytest.raises(UpstreamError) as e:
        await client(okta, FakeTokenProvider(DPOP_TOKEN), dpop=DPoP()).get(USERS)
    assert e.value.status == 302
    assert len(okta.requests) == 1


def test_http_client_settings() -> None:
    http = new_http_client()
    assert http.follow_redirects is False
    assert (http.timeout.connect, http.timeout.read) == (10, 30)


@pytest.mark.anyio
async def test_transport_error_not_chained() -> None:
    okta = Okta(httpx2.ConnectError("boom"))
    with pytest.raises(UpstreamError) as e:
        await client(okta, FakeTokenProvider(DPOP_TOKEN), dpop=DPoP()).get(USERS)
    assert e.value.status is None
    assert str(e.value) == "Okta request failed: ConnectError"
    assert e.value.__cause__ is None
    assert e.value.__context__ is None


@pytest.mark.anyio
async def test_deadline_cancels_in_flight_request() -> None:
    cancelled = anyio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.params.get("hang"):
            try:
                await anyio.sleep_forever()
            finally:
                cancelled.set()
        return httpx2.Response(200, json=[])

    c = client(handler, max_inflight=1)
    with pytest.raises(TimeoutError), anyio.fail_after(0.05):
        await c.get(USERS, {"hang": "1"})
    assert cancelled.is_set()
    with anyio.fail_after(1):  # the slot was released
        await c.get(USERS)
