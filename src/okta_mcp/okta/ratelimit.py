"""Okta rate limits and the per-principal request limiter (design §6.5).

On a 429 the client waits until Okta's `x-rate-limit-reset`, measured against the response's
`Date` header so a skewed local clock doesn't change it, plus jitter, and retries once. A wait
over `OKTA_RATE_LIMIT_MAX_WAIT`, or too close to the caller's deadline, is `RateLimited` at once.

`RequestLimiter.charge` is the client's `on_request` hook: every request to Okta, retries
included, counts against the principal in `principal` (`MCP_REQUESTS_PER_MINUTE` in any 60 s).
The client charges before it takes a slot or a token, and charges a 429 retry before the wait.

`InflightShare.slot` caps how many of the client's `MCP_OKTA_MAX_INFLIGHT` slots one principal
holds at once (half, rounded up): the per-minute limit counts requests, not time, so a few slow
System Log calls from one user could otherwise hold every slot. A request over its share waits
for one of its own to finish, under the caller's deadline, before it queues for a global slot.
"""

import logging
import math
import random
import time
from collections import deque
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime
from typing import Literal

import anyio
import httpx2

from okta_mcp.logs import event

log = logging.getLogger(__name__)

_JITTER_MAX = 1.0
_RETRY_HEADROOM = 1.0
"""Time the retry needs after the wait, so it isn't cut off by the deadline."""
_WINDOW = 60.0

principal: ContextVar[str | None] = ContextVar("okta_mcp_principal", default=None)
"""The calling user's `uid`, set per tool call; the limiter's key."""


GiveUp = Literal[
    "over_max_wait",
    "no_reset",
    "deadline",
    "principal_limit",
    "retry_failed",
    "retry_error",
    "cancelled",
]
"""Why an Okta 429 wasn't retried (`over_max_wait`, `no_reset`, `deadline`,
`principal_limit`), or how its retry ended without success: another 429 (`retry_failed`),
any other error (`retry_error`), or a cancellation (`cancelled`: the call's deadline, or
shutdown). The `okta_rate_limited` event's `reason`."""


class RateLimited(Exception):
    """Okta's rate limit outlasted the wait we allow, or the principal sent too many requests.
    The message is safe to return to the caller."""


class OktaRateLimited(RateLimited):
    """An Okta 429 that won't be retried; `reason` is for the client's log event."""

    def __init__(self, message: str, reason: GiveUp) -> None:
        super().__init__(message)
        self.reason: GiveUp = reason


def _jitter() -> float:
    return random.uniform(0, _JITTER_MAX)  # noqa: S311 - spreads retries, not a secret


def _sent_at(response: httpx2.Response, now: Callable[[], float]) -> float:
    try:
        sent = parsedate_to_datetime(response.headers["Date"])
    except (KeyError, ValueError):
        return now()
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=UTC)
    return sent.timestamp()


def _reset_wait(response: httpx2.Response, now: Callable[[], float]) -> float | None:
    """Seconds until Okta's reset, or None without a usable `x-rate-limit-reset`."""
    try:
        return max(0.0, int(response.headers["x-rate-limit-reset"]) - _sent_at(response, now))
    except (KeyError, ValueError, OverflowError):
        return None


def rate_limited(
    response: httpx2.Response, reason: GiveUp, now: Callable[[], float] = time.time
) -> OktaRateLimited:
    """The error for a 429 that won't be retried, with Okta's wait (no jitter) when known."""
    wait = _reset_wait(response, now)
    if wait is None:
        return OktaRateLimited("Okta rate limit reached; try again later", reason)
    return OktaRateLimited(f"Okta rate limit reached; try again in {math.ceil(wait)} s", reason)


def retry_wait(
    response: httpx2.Response, max_wait: float, now: Callable[[], float] = time.time
) -> float:
    """Seconds to sleep before retrying a 429 `response`, or `OktaRateLimited`
    if the wait is over `max_wait`, doesn't leave `_RETRY_HEADROOM` before the current
    deadline, or Okta sent no usable reset time. `now` is used only when the response has no
    valid `Date`. Call inside the caller's cancel scope. Logs nothing: the client logs every
    429 outcome."""
    wait = _reset_wait(response, now)
    reason: GiveUp
    if wait is None or wait > max_wait:
        reason = "no_reset" if wait is None else "over_max_wait"
    else:
        delay = wait + _jitter()
        if anyio.current_time() + delay + _RETRY_HEADROOM <= anyio.current_effective_deadline():
            return delay
        reason = "deadline"
    raise rate_limited(response, reason, now)


class RequestLimiter:
    """At most `per_minute` Okta requests per principal in any 60 s window."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self._limit = per_minute
        self._clock = clock
        self._sent: dict[str, deque[float]] = {}
        self._swept = clock()

    def charge(self) -> None:
        """Count one request for the current principal, or raise `RateLimited` (not counted).
        A request with no principal is a bug: fail rather than go unmetered."""
        uid = principal.get()
        if uid is None:
            raise RuntimeError("Okta request outside a principal's call")
        now = self._clock()
        if now - self._swept >= _WINDOW:
            self._sweep(now)
        sent = self._sent.setdefault(uid, deque())
        while sent and sent[0] <= now - _WINDOW:
            sent.popleft()
        if len(sent) >= self._limit:
            log.warning(
                "Per-principal Okta request limit reached",
                extra=event("limiter_rejected", limit_per_minute=self._limit),
            )
            raise RateLimited("Too many Okta requests; try again in a minute")
        sent.append(now)

    def _sweep(self, now: float) -> None:
        """Forget principals with no request in the window, so idle ones don't hold memory."""
        self._swept = now
        for uid in [u for u, sent in self._sent.items() if sent[-1] <= now - _WINDOW]:
            del self._sent[uid]


def share_of(max_inflight: int) -> int:
    """One principal's share of `max_inflight` slots: half, rounded up (all of 1)."""
    return (max_inflight + 1) // 2


SHARE_LOG_EVERY = 60.0
"""At most one `inflight_share_wait` line per principal per this many seconds."""


@dataclass
class _Share:
    semaphore: anyio.Semaphore
    users: int = 0
    """Requests holding or waiting for `semaphore`."""


class InflightShare:
    """At most `per_principal` requests in flight per principal. Semaphores exist only while a
    principal has a request holding or waiting for one, so idle principals hold no memory.
    `inflight_share_wait` is logged at most once per `SHARE_LOG_EVERY` per principal: how many
    wait is up to the caller, so a line per request (or per burst) would let one user flood
    the log, and a line per busy period would hide hours of saturation. The log times are kept
    apart from the semaphores, which go when a principal's queue drains, and pruned when a
    line is written."""

    def __init__(self, per_principal: int, clock: Callable[[], float] = time.monotonic) -> None:
        if per_principal < 1:
            raise ValueError("per_principal must be at least 1")
        self._limit = per_principal
        self._clock = clock
        self._held: dict[str, _Share] = {}
        self._logged: dict[str, float] = {}

    @asynccontextmanager
    async def slot(self) -> AsyncGenerator[None]:
        """Hold one of the current principal's slots. No principal is a bug, as in
        `RequestLimiter.charge`: fail rather than go unshared."""
        uid = principal.get()
        if uid is None:
            raise RuntimeError("Okta request outside a principal's call")
        share = self._held.get(uid)
        if share is None:
            share = self._held[uid] = _Share(anyio.Semaphore(self._limit))
        share.users += 1
        try:
            if share.semaphore.value == 0 and self._log_due(uid):
                log.info(
                    "Per-principal share of in-flight Okta requests in use; waiting",
                    extra=event("inflight_share_wait", share=self._limit),
                )
            async with share.semaphore:
                yield
        finally:
            share.users -= 1
            if share.users == 0:
                del self._held[uid]

    def _log_due(self, uid: str) -> bool:
        """Whether `uid`'s wait line is due, recording it if so. Pruned here, at most once a
        minute per principal, so the map holds only principals logged in the minute before the
        latest line."""
        now = self._clock()
        if now - self._logged.get(uid, -math.inf) < SHARE_LOG_EVERY:
            return False
        self._logged = {u: t for u, t in self._logged.items() if now - t < SHARE_LOG_EVERY}
        self._logged[uid] = now
        return True
