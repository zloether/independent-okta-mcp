"""Shared helpers for the live-org tests (plan 8.2.1); fixtures are in `conftest.py`.

A module of its own, as `tests/integration/_harness.py` is: test modules import these by name,
and `from conftest import ...` would find whichever `conftest` is first on the path.
"""

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY = Path(__file__).parents[2] / "docker" / "policy.example.yaml"
ADMIN_GROUP = "00g1abc2defGHI3jkL45"
"""`platform-admin` in the example policy: every command, sensitive ones too."""
PREFIX = os.environ.get("OKTA_LIVE_SEED_PREFIX", "okta-mcp-ci")
DOMAIN = os.environ.get("OKTA_LIVE_SEED_DOMAIN", "example.com")
PAGING_SIZE = int(os.environ.get("OKTA_LIVE_PAGING_SIZE", "25"))
RATE_WAIT = 61.0
"""Over the limiter's 60 s window: a call refused by `MCP_REQUESTS_PER_MINUTE` is retried once
after it."""


@dataclass(frozen=True)
class Answer:
    """What Okta answered a raw request: status, `errorCode`, and whether the body was a JSON
    list, an object or neither. Never the body."""

    status: int
    error_code: str | None
    kind: str


ANSWERS: dict[str, Answer] = {}
"""Raw path (with query) → the last answer to it, for requests sent through `okta`."""


@dataclass(frozen=True)
class Seeds:
    user_login: str
    user_id: str
    group_id: str
    paging_group_id: str
    rule_id: str
    app_id: str
    policy_id: str


@dataclass(frozen=True)
class Result:
    """One tool call, reduced to what a test may assert on. `body` is the parsed envelope; a
    test reads keys and counts from it and never puts a value in an assert message."""

    ok: bool
    code: str | None
    body: dict[str, Any]


class Refusals(logging.Handler):
    """Okta's error codes on 401/403, from the client's `okta_refused` warning: the executor's
    message never carries them (they're for the operator), and E0000006 is what check 2 is
    for."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.codes: list[str | None] = []

    def emit(self, record: logging.LogRecord) -> None:
        name, fields = getattr(record, "okta_mcp_event", (None, {}))  # okta_mcp.logs.event
        if name == "okta_refused":
            self.codes.append(fields.get("error_code"))


Call = Callable[..., Any]
"""The `call` fixture: `await call(domain, command, args, *, select, limit, cursor, principal)`."""


_TOKENS: list[str] = []


def remember_token(value: str) -> None:
    """Make `no_secrets` look for this service token from here on. Every provider built here
    fetches its first token at once and calls this, so no test runs with an unwatched one."""
    _TOKENS.append(value)
