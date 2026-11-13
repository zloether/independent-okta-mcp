from collections.abc import Iterator
from email.utils import formatdate

import anyio
import httpx2
import pytest

from okta_mcp.okta import ratelimit
from okta_mcp.okta.ratelimit import (
    InflightShare,
    OktaRateLimited,
    RateLimited,
    RequestLimiter,
    rate_limited,
    retry_wait,
    share_of,
)

SENT = 1_700_000_000
real_jitter = ratelimit._jitter  # pyright: ignore[reportPrivateUsage]  # before no_jitter


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
    samples = [real_jitter() for _ in range(100)]
    assert all(0 <= s <= 1 for s in samples)
    assert len(set(samples)) > 1


@pytest.mark.anyio
async def test_wait_over_cap_raises() -> None:
    with pytest.raises(OktaRateLimited, match="try again in 11 s") as e:
        retry_wait(at(SENT, SENT + 11), 10)
    assert e.value.reason == "over_max_wait"


@pytest.mark.anyio
async def test_zero_cap_retries_only_past_reset() -> None:
    assert retry_wait(at(SENT, SENT), 0) == 0
    with pytest.raises(RateLimited):
        retry_wait(at(SENT, SENT + 1), 0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"x-rate-limit-reset": "soon"},
        {"x-rate-limit-reset": ""},
        {"x-rate-limit-reset": "1" + "0" * 400},
        {"Date": "x"},
    ],
)
async def test_no_usable_reset_raises(headers: dict[str, str]) -> None:
    with pytest.raises(OktaRateLimited, match="try again later") as e:
        retry_wait(response_429(headers), 10)
    assert e.value.reason == "no_reset"


@pytest.mark.anyio
async def test_wait_must_leave_headroom_before_deadline() -> None:
    with anyio.fail_after(3):
        assert retry_wait(at(SENT, SENT + 1), 10) == 1
        with pytest.raises(OktaRateLimited) as e:
            retry_wait(at(SENT, SENT + 2), 10)  # ends 1 s before the deadline: too close
    assert e.value.reason == "deadline"


@pytest.mark.anyio
async def test_message_wait_excludes_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.5)
    with pytest.raises(RateLimited, match="try again in 2 s"), anyio.fail_after(3):
        retry_wait(at(SENT, SENT + 2), 10)


def test_rate_limited_message() -> None:
    limited = rate_limited(at(SENT, SENT + 40), "over_max_wait")
    assert str(limited) == "Okta rate limit reached; try again in 40 s"
    assert limited.reason == "over_max_wait"
    assert (
        str(rate_limited(response_429({}), "no_reset"))
        == "Okta rate limit reached; try again later"
    )


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


# --- in-flight share ----------------------------------------------------------------------


@pytest.mark.parametrize(("total", "share"), [(1, 1), (2, 1), (3, 2), (10, 5), (11, 6)])
def test_share_is_half_rounded_up(total: int, share: int) -> None:
    assert share_of(total) == share


def test_share_must_be_positive() -> None:
    with pytest.raises(ValueError):
        InflightShare(0)


@pytest.mark.anyio
async def test_share_caps_one_principal_and_forgets_it() -> None:
    share = InflightShare(2)
    held = peak = 0
    release = anyio.Event()

    async def hold() -> None:
        nonlocal held, peak
        token = ratelimit.principal.set("00u1")
        try:
            async with share.slot():
                held += 1
                peak = max(peak, held)
                await release.wait()
                held -= 1
        finally:
            ratelimit.principal.reset(token)

    async with anyio.create_task_group() as tg:
        for _ in range(5):
            tg.start_soon(hold)
        await anyio.wait_all_tasks_blocked()
        assert held == 2
        assert set(share._held) == {"00u1"}  # pyright: ignore[reportPrivateUsage]
        release.set()
    assert peak == 2
    assert share._held == {}  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_share_is_released_when_a_waiter_is_cancelled() -> None:
    """The call deadline cancels a request still waiting for its share: the slot it waited
    for isn't leaked and the principal's entry goes once nothing holds it."""
    share = InflightShare(1)
    token = ratelimit.principal.set("00u1")
    try:
        async with share.slot():
            with anyio.move_on_after(0.01) as scope:
                async with share.slot():
                    pytest.fail("got a second slot")
            assert scope.cancelled_caught
        assert share._held == {}  # pyright: ignore[reportPrivateUsage]
        with anyio.fail_after(1):
            async with share.slot():
                pass
    finally:
        ratelimit.principal.reset(token)


@pytest.mark.anyio
async def test_share_without_principal_fails() -> None:
    with pytest.raises(RuntimeError):
        async with InflightShare(1).slot():
            pass


def share_waits(caplog: pytest.LogCaptureFixture) -> int:
    return sum(
        getattr(r, "okta_mcp_event", ("",))[0] == "inflight_share_wait" for r in caplog.records
    )


@pytest.mark.anyio
async def test_share_wait_is_logged_at_most_once_a_minute(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """How many requests wait is up to the caller: bursts inside a minute give one line;
    a minute later, still busy, another."""
    caplog.set_level("INFO", "okta_mcp")
    clock = Clock()
    share = InflightShare(1, clock)

    async def hold(release: anyio.Event) -> None:
        token = ratelimit.principal.set("00u1")
        try:
            async with share.slot():
                await release.wait()
        finally:
            ratelimit.principal.reset(token)

    async def burst() -> None:
        release = anyio.Event()
        async with anyio.create_task_group() as tg:
            for _ in range(6):
                tg.start_soon(hold, release)
            await anyio.wait_all_tasks_blocked()
            release.set()

    await burst()
    clock.t += 59
    await burst()
    assert share_waits(caplog) == 1
    clock.t += 1
    await burst()
    assert share_waits(caplog) == 2


@pytest.mark.anyio
async def test_share_wait_under_steady_load(caplog: pytest.LogCaptureFixture) -> None:
    """One request over the share, all the time: a new request arrives each time the waiter
    gets the slot. One line, then one more a minute later while it stays busy."""
    caplog.set_level("INFO", "okta_mcp")
    clock = Clock()
    share = InflightShare(1, clock)
    token = ratelimit.principal.set("00u1")
    try:
        releases = [anyio.Event() for _ in range(10)]

        async def hold(i: int) -> None:
            async with share.slot():
                await releases[i].wait()

        async with anyio.create_task_group() as tg:
            tg.start_soon(hold, 0)
            await anyio.wait_all_tasks_blocked()
            for i in range(1, 10):
                tg.start_soon(hold, i)  # waits behind i - 1
                await anyio.wait_all_tasks_blocked()
                releases[i - 1].set()
                await anyio.wait_all_tasks_blocked()
                clock.t += 10
            releases[9].set()
    finally:
        ratelimit.principal.reset(token)
    assert share_waits(caplog) == 2  # at t=0 and t=60
    assert share._held == {}  # pyright: ignore[reportPrivateUsage]
