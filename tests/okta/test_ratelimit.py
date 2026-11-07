from collections.abc import Iterator
from email.utils import formatdate

import anyio
import httpx2
import pytest

from okta_mcp.okta import ratelimit
from okta_mcp.okta.ratelimit import RateLimited, RequestLimiter, retry_wait

SENT = 1_700_000_000


def response_429(headers: dict[str, str]) -> httpx2.Response:
    return httpx2.Response(429, headers=headers)


def at(sent: int, reset: int) -> httpx2.Response:
    return response_429({"Date": formatdate(sent, usegmt=True), "x-rate-limit-reset": str(reset)})


@pytest.fixture(autouse=True)
def no_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.0)


@pytest.mark.anyio
@pytest.mark.parametrize("skew", [0, 3600, -3600])
async def test_wait_from_date_header_ignores_local_clock(skew: int) -> None:
    assert retry_wait(at(SENT, SENT + 3), 10, now=lambda: SENT + skew) == 3


@pytest.mark.anyio
@pytest.mark.parametrize("date", [None, "not a date", ""])
async def test_wait_from_local_clock_without_valid_date(date: str | None) -> None:
    headers = {"x-rate-limit-reset": str(SENT + 4)}
    if date is not None:
        headers["Date"] = date
    assert retry_wait(response_429(headers), 10, now=lambda: SENT) == 4


@pytest.mark.anyio
async def test_reset_in_past_waits_only_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.5)
    assert retry_wait(at(SENT, SENT - 30), 10) == 0.5


@pytest.mark.anyio
async def test_jitter_added_after_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.5)
    assert retry_wait(at(SENT, SENT + 10), 10) == 10.5


def test_jitter_bounded() -> None:
    assert all(0 <= ratelimit._jitter() <= 1 for _ in range(100))  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_wait_over_cap_raises() -> None:
    with pytest.raises(RateLimited, match="try again in 11 s"):
        retry_wait(at(SENT, SENT + 11), 10)


@pytest.mark.anyio
async def test_zero_cap_retries_only_past_reset() -> None:
    assert retry_wait(at(SENT, SENT), 0) == 0
    with pytest.raises(RateLimited):
        retry_wait(at(SENT, SENT + 1), 0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [{}, {"x-rate-limit-reset": "soon"}, {"x-rate-limit-reset": ""}, {"Date": "x"}],
)
async def test_no_usable_reset_raises(headers: dict[str, str]) -> None:
    with pytest.raises(RateLimited, match="try again later"):
        retry_wait(response_429(headers), 10)


@pytest.mark.anyio
async def test_wait_past_deadline_raises() -> None:
    with anyio.fail_after(2):
        assert retry_wait(at(SENT, SENT + 1), 10) == 1
        with pytest.raises(RateLimited):
            retry_wait(at(SENT, SENT + 2), 10)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def as_user() -> Iterator[None]:
    token = ratelimit.principal.set("00u1")
    yield
    ratelimit.principal.reset(token)


@pytest.mark.usefixtures("as_user")
def test_limiter_window() -> None:
    clock = Clock()
    limiter = RequestLimiter(3, clock)
    for _ in range(3):
        limiter.charge()
        clock.t += 10
    with pytest.raises(RateLimited):
        limiter.charge()
    clock.t = 1060  # the first request leaves the window
    limiter.charge()
    with pytest.raises(RateLimited):
        limiter.charge()


@pytest.mark.usefixtures("as_user")
def test_limiter_rejection_not_counted() -> None:
    clock = Clock()
    limiter = RequestLimiter(1, clock)
    limiter.charge()
    for _ in range(5):
        clock.t += 10
        with pytest.raises(RateLimited):
            limiter.charge()
    clock.t = 1060
    limiter.charge()


def test_limiter_per_principal() -> None:
    limiter = RequestLimiter(1, Clock())
    for uid in ("00u1", "00u2"):
        token = ratelimit.principal.set(uid)
        try:
            limiter.charge()
            with pytest.raises(RateLimited):
                limiter.charge()
        finally:
            ratelimit.principal.reset(token)


def test_limiter_without_principal_fails() -> None:
    with pytest.raises(RuntimeError):
        RequestLimiter(1).charge()


def test_limiter_forgets_idle_principals() -> None:
    clock = Clock()
    limiter = RequestLimiter(5, clock)
    for uid in ("00u1", "00u2"):
        token = ratelimit.principal.set(uid)
        limiter.charge()
        ratelimit.principal.reset(token)
        clock.t += 30
    token = ratelimit.principal.set("00u3")
    limiter.charge()  # 60 s since the last sweep: 00u1 is idle, 00u2 isn't
    ratelimit.principal.reset(token)
    assert set(limiter._sent) == {"00u2", "00u3"}  # pyright: ignore[reportPrivateUsage]
