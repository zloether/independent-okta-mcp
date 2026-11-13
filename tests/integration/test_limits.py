"""Limits and operational logs through the HTTP server (plan 6.2, design §6.5, §13).

The same harness as `test_http.py` (real verifier, mocked AS and Okta on one transport, only
uvicorn replaced), with Okta answers that trip each limit, and the operational log captured
as the JSON lines `configure_logging` writes. Each test checks the caller's error and the event
an operator would count, joined on the request ID the caller was given.
"""

import io
import json
import logging
import time
from collections.abc import Callable, Iterator
from email.utils import formatdate
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from _harness import (
    ANALYSTS,
    GROUP,
    HELPDESK,
    INIT,
    JSON_HEADERS,
    ORG,
    READERS,
    Running,
    World,
    access_token,
    env,
    envelope,
    http_for,
    mcp_client,
)

from okta_mcp.config import load_config
from okta_mcp.logs import DependencyExceptionFilter, JsonFormatter, RequestIdFilter
from okta_mcp.okta import ratelimit
from okta_mcp.okta.token import FAILURE_BACKOFF

OTHER_UID = "00u1otheruser0000000"
Lines = Callable[[], list[dict[str, Any]]]


@pytest.fixture
def log_lines() -> Iterator[Lines]:
    """The operational log as `configure_logging` formats it, without replacing pytest's own
    handlers: `log_lines()` parses what has been written so far, one JSON object per line."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.addFilter(DependencyExceptionFilter())
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(JsonFormatter())
    ours = logging.getLogger("okta_mcp")
    saved = ours.level
    ours.addHandler(handler)
    ours.setLevel(logging.DEBUG)
    try:
        yield lambda: [json.loads(line) for line in buffer.getvalue().splitlines()]
    finally:
        ours.removeHandler(handler)
        ours.setLevel(saved)


@pytest.fixture(autouse=True)
def no_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_jitter", lambda: 0.0)


def events(lines: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [line for line in lines if line.get("event") == name]


def other_user(*groups: str) -> str:
    return access_token(*groups, uid=OTHER_UID, sub="other@example.com")


def rate_limit_429(reset_in: int) -> httpx2.Response:
    now = int(time.time())
    return httpx2.Response(
        429,
        headers={
            "Date": formatdate(now, usegmt=True),
            "x-rate-limit-reset": str(now + reset_in),
        },
        json={"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit"},
    )


# --- per-principal request limiter ----------------------------------------------------------


@pytest.mark.anyio
async def test_the_limiter_trips_and_is_logged(
    running: Running, tmp_path: Path, world: World, log_lines: Lines
) -> None:
    """Two Okta requests per minute per user: the third call is refused before anything is
    sent, its request ID is on the `limiter_rejected` line, and another user still gets in."""
    config = load_config(env(tmp_path, MCP_REQUESTS_PER_MINUTE="2"))
    async with (
        running(config, world) as app,
        mcp_client(app, access_token(READERS), "2026-07-28") as client,
    ):
        results = [await client.call_tool("okta_groups", {"command": "list"}) for _ in range(3)]
        async with mcp_client(app, other_user(READERS), "2026-07-28") as client:
            other = await client.call_tool("okta_groups", {"command": "list"})
    assert [r.is_error for r in results] == [False, False, True]
    error = envelope(results[2])["error"]
    assert error["code"] == "rate_limited"
    assert other.is_error is False
    assert world.okta_api() == ["/api/v1/groups"] * 3
    (rejected,) = events(log_lines(), "limiter_rejected")
    assert rejected["request_id"] == error["request_id"]
    assert rejected["limit_per_minute"] == 2
    assert rejected["level"] == "WARNING"
    # The principal isn't on operational lines; the audit log joins on the request ID.
    assert "00u1httpuser00000000" not in json.dumps(log_lines())


# --- Okta 429s ------------------------------------------------------------------------------


class Throttled(World):
    """Okta answering `/api/v1/groups` with the queued responses first, then the usual list."""

    def __init__(self, *responses: httpx2.Response) -> None:
        super().__init__()
        self.queued = list(responses)

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/v1/groups" and self.queued:
            self.requests.append(request)
            return self.queued.pop(0)
        return super().__call__(request)


@pytest.mark.anyio
async def test_a_short_okta_429_is_retried_and_logged(
    running: Running, tmp_path: Path, log_lines: Lines
) -> None:
    world = Throttled(rate_limit_429(reset_in=0))
    config = load_config(env(tmp_path))
    async with (
        running(config, world) as app,
        mcp_client(app, access_token(READERS), "2026-07-28") as client,
    ):
        result = await client.call_tool("okta_groups", {"command": "list"})
    assert result.is_error is False
    assert envelope(result)["rows"][0][0] == GROUP
    assert world.okta_api() == ["/api/v1/groups"] * 2
    (retried,) = events(log_lines(), "okta_rate_limited")
    assert retried["retry"] is True
    assert retried["request_id"] is not None


@pytest.mark.anyio
async def test_a_long_okta_429_is_rate_limited_and_logged(
    running: Running, tmp_path: Path, log_lines: Lines
) -> None:
    world = Throttled(rate_limit_429(reset_in=60))
    config = load_config(env(tmp_path, OKTA_RATE_LIMIT_MAX_WAIT="5"))
    async with (
        running(config, world) as app,
        mcp_client(app, access_token(READERS), "2026-07-28") as client,
    ):
        result = await client.call_tool("okta_groups", {"command": "list"})
    error = envelope(result)["error"]
    assert error["code"] == "rate_limited"
    assert world.okta_api() == ["/api/v1/groups"]
    (refused,) = events(log_lines(), "okta_rate_limited")
    assert (refused["retry"], refused["reason"]) == (False, "over_max_wait")
    assert refused["request_id"] == error["request_id"]


# --- per-principal share of the in-flight slots ---------------------------------------------


class Slow(World):
    """Network zones that answer only once `release` is set, counting those in flight."""

    def __init__(self) -> None:
        super().__init__()
        self.release = anyio.Event()
        self.zones_inflight = 0
        self.zones_peak = 0

    async def __call__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, request: httpx2.Request
    ) -> httpx2.Response:
        """Async: `httpx2.MockTransport` awaits a handler that returns an awaitable."""
        if request.url.path == "/api/v1/zones":
            self.zones_inflight += 1
            self.zones_peak = max(self.zones_peak, self.zones_inflight)
            try:
                await self.release.wait()
            finally:
                self.zones_inflight -= 1
        return super().__call__(request)


@pytest.mark.anyio
async def test_one_user_cannot_hold_every_slot(running: Running, tmp_path: Path) -> None:
    """Plan 6.2: with two slots, one user's slow calls hold one; another user's call is
    answered while they wait, not after them."""
    world = Slow()
    config = load_config(env(tmp_path, MCP_OKTA_MAX_INFLIGHT="2"))
    slow_done: list[bool] = []
    async with running(config, world) as app:

        async def slow_call() -> None:
            async with mcp_client(app, access_token(HELPDESK), "2026-07-28") as client:
                r = await client.call_tool("okta_network_zones", {"command": "list"})
                slow_done.append(r.is_error is False)

        async with anyio.create_task_group() as tg:
            for _ in range(3):
                tg.start_soon(slow_call)
            with anyio.fail_after(5):
                while world.zones_inflight == 0:
                    await anyio.sleep(0.01)
            async with mcp_client(app, other_user(READERS), "2026-07-28") as client:
                with anyio.fail_after(5):
                    other = await client.call_tool("okta_groups", {"command": "list"})
            assert other.is_error is False
            assert slow_done == []
            assert world.zones_inflight == 1
            world.release.set()
    assert slow_done == [True, True, True]
    assert world.zones_peak == 1


# --- service-token backoff ------------------------------------------------------------------


class BadKey(World):
    """The org's token endpoint refuses the service app's assertion."""

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/oauth2/v1/token":
            self.requests.append(request)
            return httpx2.Response(401, json={"error": "invalid_client"})
        return super().__call__(request)

    def token_posts(self) -> int:
        return sum(1 for r in self.requests if r.url.path == "/oauth2/v1/token")


async def until_mcp_serves(app: Any) -> None:
    """`/mcp` past `ReadyGate` (JWKS loaded); `/readyz` stays 503 with no service token."""
    async with http_for(app, authorization=f"Bearer {access_token(READERS)}") as http:
        with anyio.fail_after(5):
            while (await http.post("/mcp", json=INIT, headers=JSON_HEADERS)).status_code == 503:
                await anyio.sleep(0.01)


@pytest.mark.anyio
async def test_a_failed_service_token_is_not_requested_per_call(
    running: Running, tmp_path: Path, log_lines: Lines
) -> None:
    """Plan 6.2: with a bad key, the calls inside the backoff get the stored error without a
    token request each. The background refresh made the one request at startup."""
    world = BadKey()
    config = load_config(env(tmp_path))
    async with running(config, world, wait_ready=False) as app:
        await until_mcp_serves(app)
        async with mcp_client(app, access_token(READERS), "2026-07-28") as client:
            with anyio.fail_after(FAILURE_BACKOFF - 1):
                results = [
                    await client.call_tool("okta_groups", {"command": "list"}) for _ in range(5)
                ]
    assert all(envelope(r)["error"]["code"] == "upstream_error" for r in results)
    assert world.token_posts() == 1
    assert world.okta_api() == []
    (failed,) = events(log_lines(), "service_token_failed")
    assert failed["backoff_s"] == FAILURE_BACKOFF
    assert "invalid_client" in failed["msg"]


# --- truncation -----------------------------------------------------------------------------


class TwoGroups(World):
    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/v1/groups":
            self.requests.append(request)
            groups = [
                {"id": f"00g1group{i}00000000000", "type": "OKTA_GROUP", "profile": {"name": "g"}}
                for i in (1, 2)
            ]
            return httpx2.Response(200, json=groups)
        return super().__call__(request)


@pytest.mark.anyio
async def test_a_truncated_list_is_logged(
    running: Running, tmp_path: Path, log_lines: Lines
) -> None:
    config = load_config(env(tmp_path))
    async with (
        running(config, TwoGroups()) as app,
        mcp_client(app, access_token(ANALYSTS), "2026-07-28") as client,
    ):
        result = await client.call_tool("okta_groups", {"command": "list", "limit": 1})
    assert envelope(result)["truncated"] == "max_items"
    (cut,) = events(log_lines(), "result_truncated")
    assert (cut["reason"], cut["items"]) == ("max_items", 1)
    assert cut["request_id"] is not None


# --- the log itself -------------------------------------------------------------------------


@pytest.mark.anyio
async def test_no_line_carries_a_token_or_okta_data(
    running: Running, tmp_path: Path, log_lines: Lines
) -> None:
    """Across a run that trips the limiter and a 429, nothing Okta sent, and no token, is on
    an operational line (AGENTS.md "Never log")."""
    world = Throttled(rate_limit_429(reset_in=0))
    config = load_config(env(tmp_path, MCP_REQUESTS_PER_MINUTE="2"))
    bearer = access_token(READERS)
    async with running(config, world) as app, mcp_client(app, bearer, "2026-07-28") as client:
        for _ in range(2):
            await client.call_tool("okta_groups", {"command": "list"})
    text = json.dumps(log_lines())
    assert log_lines(), "expected some lines"
    for secret in (bearer, "svc", GROUP, "Staff", "API call exceeded rate limit", ORG + "/api"):
        assert secret not in text
