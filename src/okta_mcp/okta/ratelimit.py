"""Okta rate limits and the per-principal request limiter (design §6.5).

On a 429 the client waits until Okta's `x-rate-limit-reset`, measured against the response's
`Date` header so a skewed local clock doesn't change it, plus jitter, and retries once. A wait
over `OKTA_RATE_LIMIT_MAX_WAIT`, or past the caller's deadline, is `RateLimited` at once.

`RequestLimiter.charge` is the client's `on_request` hook: every request sent to Okta, retries
included, counts against the principal in `principal` (`MCP_REQUESTS_PER_MINUTE` in any 60 s).
"""

import logging
import math
import random
import time
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC
from email.utils import parsedate_to_datetime

import anyio
import httpx2

log = logging.getLogger(__name__)

_JITTER_MAX = 1.0
_WINDOW = 60.0

principal: ContextVar[str | None] = ContextVar("okta_mcp_principal", default=None)
"""The calling user's `uid`, set per tool call; the limiter's key."""


class RateLimited(Exception):
    """Okta's rate limit outlasted the wait we allow, or the principal sent too many requests.
    The message is safe to return to the caller."""


def _jitter() -> float:
    return random.uniform(0, _JITTER_MAX)  # noqa: S311 - spreads retries, not a secret


def _sent_at(response: httpx2.Response, now: Callable[[], float]) -> float:
    try:
        sent = parsedate_to_datetime(response.headers["Date"])
    except (KeyError, TypeError, ValueError):
        return now()
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=UTC)
    return sent.timestamp()


def retry_wait(
    response: httpx2.Response, max_wait: float, now: Callable[[], float] = time.time
) -> float:
    """Seconds to sleep before retrying a 429 `response`, or `RateLimited` if the wait is over
    `max_wait`, doesn't end before the current deadline, or Okta sent no usable reset time.
    `now` is used only when the response has no valid `Date`. Call inside the caller's
    cancel scope."""
    try:
        reset = int(response.headers["x-rate-limit-reset"])
    except (KeyError, ValueError):
        reset = None
    if reset is None:
        raise RateLimited("Okta rate limit reached; try again later")
    wait = max(0.0, reset - _sent_at(response, now))
    if wait > max_wait:
        raise RateLimited(f"Okta rate limit reached; try again in {math.ceil(wait)} s")
    wait += _jitter()
    if anyio.current_time() + wait >= anyio.current_effective_deadline():
        raise RateLimited(f"Okta rate limit reached; try again in {math.ceil(wait)} s")
    return wait


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
            log.warning("Per-principal Okta request limit reached")
            raise RateLimited("Too many Okta requests; try again in a minute")
        sent.append(now)

    def _sweep(self, now: float) -> None:
        """Forget principals with no request in the window, so idle ones don't hold memory."""
        self._swept = now
        for uid in [u for u, sent in self._sent.items() if sent[-1] <= now - _WINDOW]:
            del self._sent[uid]
