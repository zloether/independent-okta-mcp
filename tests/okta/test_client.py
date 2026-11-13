import base64
import hashlib
import json
import time
from collections.abc import Iterator
from email.utils import formatdate
from typing import Any

import anyio
import httpx2
import jwt
import pytest
from _fakes import FakeTokenProvider
from jwt.algorithms import ECAlgorithm

from okta_mcp.okta import ratelimit
from okta_mcp.okta.client import (
    OktaClient,
    OriginError,
    UpstreamError,
    new_http_client,
    on_origin,
)
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.ratelimit import (
    InflightShare,
    OktaRateLimited,
    RateLimited,
    RequestLimiter,
    share_of,
)
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
    on_sent: Any = None,
    share: InflightShare | None = None,
) -> OktaClient:
    return OktaClient(
        new_http_client(httpx2.MockTransport(handler)),
        org_url=ORG,
        tokens=tokens or FakeTokenProvider(),
        dpop=dpop,
        max_inflight=max_inflight,
        rate_limit_max_wait=10,
        on_request=on_request,
        on_sent=on_sent,
        share=share,
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
async def test_one_principal_gets_its_share_of_the_slots() -> None:
    """Plan 6.2: ten slow calls from one user hold at most half the slots; another user's
    request is sent while they wait, not after them."""
    inflight: dict[str, int] = {"00u1": 0, "00u2": 0}
    peak: dict[str, int] = {"00u1": 0, "00u2": 0}
    order: list[str] = []
    release = anyio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        uid = request.url.params["who"]
        order.append(uid)
        inflight[uid] += 1
        peak[uid] = max(peak[uid], inflight[uid])
        if uid == "00u1":
            await release.wait()
        inflight[uid] -= 1
        return httpx2.Response(200, json=[])

    c = client(handler, max_inflight=4, share=InflightShare(share_of(4)))

    async def call(uid: str) -> None:
        token = ratelimit.principal.set(uid)
        try:
            await c.get(USERS, {"who": uid})
        finally:
            ratelimit.principal.reset(token)

    async with anyio.create_task_group() as tg:
        for _ in range(10):
            tg.start_soon(call, "00u1")
        await anyio.wait_all_tasks_blocked()
        tg.start_soon(call, "00u2")
        await anyio.wait_all_tasks_blocked()
        assert order == ["00u1", "00u1", "00u2"]
        release.set()
    assert peak == {"00u1": 2, "00u2": 1}
    assert len(order) == 11


@pytest.mark.anyio
async def test_a_share_without_a_principal_sends_nothing() -> None:
    okta = Okta()
    c = client(okta, share=InflightShare(1))
    with pytest.raises(RuntimeError, match="principal"):
        await c.get(USERS)
    assert okta.requests == []


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


# Live shape (dev org, groups get-owners without the group-owners feature): no WWW-Authenticate.
FEATURE_OFF = {
    "errorCode": "E0000015",
    "errorSummary": "You do not have permission to access the feature you are requesting",
}


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403])
async def test_feature_not_enabled_keeps_token_and_says_so(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    tokens = FakeTokenProvider(DPOP_TOKEN)
    okta = Okta(httpx2.Response(status, json=FEATURE_OFF))
    with pytest.raises(UpstreamError) as e:
        await client(okta, tokens, dpop=DPoP()).get(USERS)
    assert e.value.status == status
    assert str(e.value) == (
        f"Okta refused the request (HTTP {status}, E0000015): the org may not have the feature "
        "this command needs, or the service app's admin role doesn't cover it; contact the MCP "
        "administrator"
    )
    assert tokens.invalidated == []
    assert f"HTTP {status} E0000015" in caplog.text


@pytest.mark.anyio
async def test_feature_not_enabled_after_nonce_retry_keeps_token() -> None:
    tokens = FakeTokenProvider(DPOP_TOKEN)
    okta = Okta(nonce_401(), httpx2.Response(401, json=FEATURE_OFF))
    with pytest.raises(UpstreamError, match="E0000015"):
        await client(okta, tokens, dpop=DPoP()).get(USERS)
    assert len(okta.requests) == 2
    assert tokens.invalidated == []


@pytest.mark.anyio
async def test_feature_off_with_token_challenge_gets_generic_403_message() -> None:
    headers = {"WWW-Authenticate": 'DPoP error="insufficient_scope"'}
    okta = Okta(httpx2.Response(403, headers=headers, json=FEATURE_OFF))
    with pytest.raises(UpstreamError) as e:
        await client(okta, FakeTokenProvider()).get(USERS)
    assert str(e.value) == "Okta refused the request (HTTP 403); contact the MCP administrator"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("headers", "body"),
    [
        ({"WWW-Authenticate": 'DPoP error="invalid_token"'}, FEATURE_OFF),  # the token, too
        ({}, {"errorCode": ["E0000015"]}),
        ({}, {"errorCode": "E0000011"}),
        ({}, None),
    ],
)
async def test_401_not_exactly_feature_off_still_invalidates(
    headers: dict[str, str], body: object
) -> None:
    tokens = FakeTokenProvider(DPOP_TOKEN)
    okta = Okta(httpx2.Response(401, headers=headers, json=body))
    with pytest.raises(UpstreamError) as e:
        await client(okta, tokens, dpop=DPoP()).get(USERS)
    assert "contact the MCP administrator" in str(e.value)
    assert tokens.invalidated == [DPOP_TOKEN]


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
        (httpx2.Response(502, json={"errorSummary": ""}), "Okta returned HTTP 502"),
        (httpx2.Response(503, json={"errorSummary": 5}), "Okta returned HTTP 503"),
    ],
)
async def test_error_mapping(response: httpx2.Response, message: str) -> None:
    with pytest.raises(UpstreamError) as e:
        await client(Okta(response)).get(USERS)
    assert (e.value.status, str(e.value)) == (response.status_code, message)


def rate_limited(wait: int = 0) -> httpx2.Response:
    sent = int(time.time())
    return httpx2.Response(
        429,
        headers={"Date": formatdate(sent, usegmt=True), "x-rate-limit-reset": str(sent + wait)},
        json={"errorSummary": "API call exceeded rate limit due to too many requests."},
    )


@pytest.fixture
def no_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.0)


@pytest.mark.anyio
@pytest.mark.usefixtures("no_jitter")
async def test_429_retried_once() -> None:
    okta = Okta(rate_limited(), httpx2.Response(200, json=[{"id": "00u1"}]))
    calls: list[None] = []
    tokens = FakeTokenProvider(DPOP_TOKEN)
    c = client(okta, tokens, dpop=DPoP(), on_request=lambda: calls.append(None))
    response = await c.get(USERS, {"limit": "2"})
    assert response.json() == [{"id": "00u1"}]
    assert len(okta.requests) == len(calls) == 2
    assert okta.requests[1].url == okta.requests[0].url
    assert okta.proof(0)["jti"] != okta.proof(1)["jti"]


@pytest.mark.anyio
@pytest.mark.usefixtures("no_jitter")
async def test_429_not_retried_twice(caplog: pytest.LogCaptureFixture) -> None:
    okta = Okta(rate_limited(), rate_limited(40))
    with pytest.raises(OktaRateLimited, match="try again in 40 s") as e:
        await client(okta).get(USERS)
    assert len(okta.requests) == 2
    assert e.value.reason == "retry_failed"
    logged = [getattr(r, "okta_mcp_event", None) for r in caplog.records]
    assert logged == [
        ("okta_rate_limited", {"retry": True, "wait_s": 0.0}),
        ("okta_rate_limited", {"retry": False, "reason": "retry_failed"}),
    ]


@pytest.mark.anyio
async def test_429_over_max_wait_not_retried(caplog: pytest.LogCaptureFixture) -> None:
    okta = Okta(rate_limited(30))
    with pytest.raises(RateLimited, match="try again in 30 s"):
        await client(okta).get(USERS)
    assert len(okta.requests) == 1
    logged = [getattr(r, "okta_mcp_event", None) for r in caplog.records]
    assert logged == [("okta_rate_limited", {"retry": False, "reason": "over_max_wait"})]


@pytest.mark.anyio
async def test_429_wait_past_deadline_not_retried() -> None:
    okta = Okta(rate_limited(5))
    with pytest.raises(RateLimited), anyio.fail_after(1):
        await client(okta).get(USERS)
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_429_wait_frees_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.2)
    done: list[str] = []

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return rate_limited() if request.url.params.get("first") else httpx2.Response(200)

    c = client(handler, max_inflight=1)

    async def get(name: str, params: dict[str, str]) -> None:
        await c.get(USERS, params)
        done.append(name)

    async with anyio.create_task_group() as tg:
        tg.start_soon(get, "limited", {"first": "1"})
        await anyio.sleep(0.05)
        with anyio.fail_after(0.1):
            await get("other", {})
        tg.cancel_scope.cancel()
    assert done == ["other"]


@pytest.fixture
def as_user() -> Iterator[None]:
    token = ratelimit.principal.set("00u1")
    yield
    ratelimit.principal.reset(token)


@pytest.mark.anyio
@pytest.mark.usefixtures("as_user")
async def test_limiter_rejects_before_slot_and_token() -> None:
    sent: list[httpx2.Request] = []

    async def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        await anyio.sleep_forever()
        raise AssertionError

    tokens = FakeTokenProvider()
    c = client(handler, tokens, max_inflight=1, on_request=RequestLimiter(1).charge)
    async with anyio.create_task_group() as tg:
        tg.start_soon(c.get, USERS)  # holds the only slot
        await anyio.sleep(0.02)
        with pytest.raises(RateLimited), anyio.fail_after(0.1):
            await c.get(USERS)
        tg.cancel_scope.cancel()
    assert len(sent) == tokens.calls == 1


@pytest.mark.anyio
@pytest.mark.usefixtures("as_user")
async def test_limiter_charges_429_retry_before_wait(caplog: pytest.LogCaptureFixture) -> None:
    okta = Okta(rate_limited(5))
    c = client(okta, on_request=RequestLimiter(1).charge)
    start = anyio.current_time()
    with pytest.raises(RateLimited, match="Too many Okta requests"):
        await c.get(USERS)
    assert anyio.current_time() - start < 1
    assert len(okta.requests) == 1
    logged = [getattr(r, "okta_mcp_event", None) for r in caplog.records]
    assert ("okta_rate_limited", {"retry": False, "reason": "principal_limit"}) in logged
    assert ("okta_rate_limited", {"retry": True, "wait_s": 5.0}) not in logged


@pytest.mark.anyio
@pytest.mark.usefixtures("no_jitter")
async def test_a_retry_cut_by_the_deadline_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Every 429 ends in one give-up event or a successful retry: a deadline hit during the
    retry logs `cancelled` after the `retry` line."""
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return rate_limited(1)
        await anyio.sleep_forever()
        raise AssertionError

    c = client(handler)
    with anyio.move_on_after(2.5):  # leaves retry_wait's headroom; the retry never answers
        await c.get(USERS)
    logged = [getattr(r, "okta_mcp_event", None) for r in caplog.records]
    assert logged == [
        ("okta_rate_limited", {"retry": True, "wait_s": 1.0}),
        ("okta_rate_limited", {"retry": False, "reason": "cancelled"}),
    ]
    assert calls == 2


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


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://example.okta.com/x", True),
        ("https://EXAMPLE.okta.com:443/x?y", True),
        ("http://example.okta.com/x", False),
        ("https://example.okta.com:8443/x", False),
        ("https://evil.example.com/x", False),
        ("https://u@example.okta.com/x", False),
        ("https://u:p@example.okta.com/x", False),
        ("https://:@example.okta.com/x", False),
    ],
)
def test_on_origin(url: str, ok: bool) -> None:
    # The one origin check behind the client, `paginate`, `build_url` and `resume_url`.
    assert on_origin(httpx2.URL(url), httpx2.URL("https://example.okta.com")) is ok


def test_empty_userinfo_is_dropped_by_the_parser() -> None:
    # S4: `https://@host` parses to no userinfo and is sent without the `@`, so it is the org
    # URL itself; `:@` keeps a userinfo and is refused.
    url = httpx2.URL("https://@example.okta.com/x")
    assert url.userinfo == b"" and str(url) == "https://example.okta.com/x"
    assert not on_origin(httpx2.URL("https://:@example.okta.com/x"), httpx2.URL(ORG))


@pytest.mark.anyio
@pytest.mark.usefixtures("no_jitter")
async def test_on_sent_sees_every_request_sent() -> None:
    """The audit log's `okta_requests` and `status` (6.1): retries count; a transport error
    has no status; a request the limiter refuses, or one without a token, isn't sent."""
    sent: list[int | None] = []
    okta = Okta(rate_limited(), nonce_401(), httpx2.Response(200, json=[]))
    tokens = FakeTokenProvider(DPOP_TOKEN)
    await client(okta, tokens, dpop=DPoP(), on_sent=sent.append).get(USERS)
    assert sent == [429, 401, 200]
    sent.clear()
    with pytest.raises(UpstreamError):
        await client(Okta(httpx2.ConnectError("boom")), on_sent=sent.append).get(USERS)
    assert sent == [None]
    sent.clear()

    def refuse() -> None:
        raise RateLimited("slow down")

    with pytest.raises(RateLimited):
        await client(Okta(), on_request=refuse, on_sent=sent.append).get(USERS)
    with pytest.raises(UpstreamError):
        await client(Okta(), FailingTokenProvider(), on_sent=sent.append).get(USERS)
    assert sent == []


@pytest.mark.anyio
async def test_on_sent_counts_a_request_cancelled_in_flight() -> None:
    sent: list[int | None] = []

    async def slow(request: httpx2.Request) -> httpx2.Response:
        await anyio.sleep(10)
        return httpx2.Response(200, json=[])

    with anyio.move_on_after(0.05):
        await client(slow, on_sent=sent.append).get(USERS)
    assert sent == [None]
