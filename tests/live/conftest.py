"""Live-org tests (plan 8.2.1): what only Okta decides, against the CI org.

Collected only with `OKTA_LIVE=1`, so the default `uv run pytest` never reaches a network.
`live.yml` runs them; locally, with the CI service key at hand:

    OKTA_LIVE=1 OKTA_ORG_URL=https://<ci org> OKTA_CLIENT_ID=0oa… OKTA_KEY_ID=… \
    OKTA_SCOPES="okta.users.read …" OKTA_PRIVATE_KEY_FILE=/path/ci-service.pem \
    uv run pytest tests/live --tb=line -p no:cacheprovider

**Output hygiene.** pytest prints both sides of a failed `assert`, so these tests assert only on
derived values: status codes, error codes, key names, counts. Never on a result body. Messages
name commands and fields from the registry, never values from Okta. `no_secrets` fails a test
whose captured output holds the service token or a line of the private key.

Seed objects come from `okta-ci-org-terraform` in the infra repo, found by name from
`OKTA_LIVE_SEED_PREFIX` (default `okta-mcp-ci`) and `OKTA_LIVE_SEED_DOMAIN` (`example.com`).
Nothing here creates or changes anything in Okta (the client has only `get`), except
`test_signin.py`: its sign-ins fail on purpose, as the seeded test user, and lock that user
until the seeded policy unlocks it. It runs only with `OKTA_LIVE_SIGNIN_PASSWORD` set.
"""

import json
import logging
import os
import secrets
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from _live import (
    _TOKENS,
    ADMIN_GROUP,
    ANSWERS,
    DOMAIN,
    POLICY,
    PREFIX,
    RATE_WAIT,
    Answer,
    Call,
    Refusals,
    Result,
    Seeds,
    remember_token,
)

LIVE = os.environ.get("OKTA_LIVE") == "1"
if not LIVE:
    # Not imported either: the modules read live-only fixtures at import.
    collect_ignore_glob = ["test_*.py"]


def _env() -> dict[str, str]:
    missing = [
        v
        for v in ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_SCOPES", "OKTA_PRIVATE_KEY_FILE")
        if not os.environ.get(v)
    ]
    if missing:
        pytest.exit(f"OKTA_LIVE=1 needs {', '.join(missing)}", returncode=2)
    values = {
        "MCP_PUBLIC_URL": "https://mcp.example.com/mcp",
        # Never contacted: no HTTP app runs here, so nothing verifies a user token.
        "MCP_ISSUER": "https://issuer.example.com/oauth2/aus1example000000000",
        "MCP_ALLOWED_CLIENT_IDS": "0oa1client0000000000",
        "MCP_POLICY_FILE": str(POLICY),
        "MCP_CURSOR_KEY": secrets.token_urlsafe(32),
        "MCP_AUDIT_LOG": "stderr",
        "MCP_AUDIT_ARGS": "hash",
        "MCP_REQUESTS_PER_MINUTE": os.environ.get("MCP_REQUESTS_PER_MINUTE", "120"),
    }
    for name in (
        "OKTA_ORG_URL",
        "OKTA_CLIENT_ID",
        "OKTA_KEY_ID",
        "OKTA_SCOPES",
        "OKTA_PRIVATE_KEY_FILE",
        "OKTA_DPOP",
    ):
        if os.environ.get(name):
            values[name] = os.environ[name]
    return values


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def live_env() -> dict[str, str]:
    return _env()


@pytest.fixture(scope="session")
def config(live_env: dict[str, str]) -> Any:
    from okta_mcp.config import load_config

    return load_config(live_env)


@pytest.fixture(scope="session")
def refusals() -> Iterator[Refusals]:
    handler = Refusals()
    logger = logging.getLogger("okta_mcp")
    logger.addHandler(handler)
    yield handler
    logger.removeHandler(handler)


@pytest.fixture(scope="session")
async def runtime(config: Any, refusals: Refusals) -> AsyncIterator[Any]:
    from okta_mcp.okta.client import new_http_client
    from okta_mcp.server import build_runtime

    async with new_http_client() as http:
        built = build_runtime(config, http)
        remember_token((await built.tokens.token()).value)
        yield built


@pytest.fixture(scope="session")
def admin() -> Any:
    from okta_mcp.auth.principal import Principal

    return Principal(uid="00u1livecitests00000", sub="live-ci", groups=frozenset({ADMIN_GROUP}))


@pytest.fixture(scope="session")
def call(runtime: Any, admin: Any) -> Call:
    """`await call(domain, command, args, *, select=None, limit=None, principal=admin)`:
    one tool call through `Tools` and the executor, as the server makes it. A call the
    per-principal limiter refuses is retried once, after its window."""
    from okta_mcp.exec.executor import Failure, tool_name

    async def run(
        domain: str,
        command: str,
        args: dict[str, Any] | None = None,
        *,
        select: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        links: bool = False,
        principal: Any = None,
    ) -> Result:
        arguments: dict[str, Any] = {"command": command, "args": args or {}}
        if select is not None:
            arguments["select"] = select
        if limit is not None:
            arguments["limit"] = limit
        if cursor is not None:
            arguments["cursor"] = cursor
        if links:
            arguments["links"] = True
        who = principal or admin
        for attempt in (1, 2):
            outcome = await runtime.tools.call(who, tool_name(domain), arguments)
            if isinstance(outcome, Failure):
                if outcome.code.value == "rate_limited" and attempt == 1:
                    await anyio.sleep(RATE_WAIT)
                    continue
                return Result(False, outcome.code.value, {})
            return Result(True, None, json.loads(outcome.text))
        raise AssertionError("unreachable")

    return run


async def _one(call: Call, domain: str, command: str, args: dict[str, Any], key: str) -> str:
    """The `id` of the one seeded object a lookup names, or the test session stops: every live
    test depends on the seed data."""
    result = await call(domain, command, args, select="id," + key, limit=200)
    if not result.ok:
        pytest.exit(f"seed lookup {domain} {command} failed: {result.code}", returncode=2)
    rows = result.body.get("rows", [])
    # select "id,<key>": each row is [id, key value]; the name is compared, never printed.
    want = args.get("q") or args.get("search")
    ids = [r[0] for r in rows if len(r) == 2 and r[1] == want]
    if len(ids) != 1:
        pytest.exit(f"seed {domain} {command}: {len(ids)} matches, expected 1", returncode=2)
    return ids[0]


@pytest.fixture(scope="session")
async def seeds(call: Call) -> Seeds:
    login = f"{PREFIX}-known@{DOMAIN}"
    user = await call("users", "get", {"user": login}, select="id")
    if not user.ok:
        pytest.exit(f"seed user lookup failed: {user.code}", returncode=2)
    group = await _one(call, "groups", "list", {"q": f"{PREFIX}-known"}, "profile.name")
    paging = await _one(call, "groups", "list", {"q": f"{PREFIX}-paging"}, "profile.name")
    app = await _one(call, "apps", "list", {"q": f"{PREFIX}-bookmark"}, "label")
    rule = await _one(call, "groups", "list-rules", {"search": f"{PREFIX}-rule"}, "name")
    policies = await call("policies", "list", {"type": "PASSWORD"}, select="id,name", limit=200)
    if not policies.ok:
        pytest.exit(f"seed policy lookup failed: {policies.code}", returncode=2)
    named = [r[0] for r in policies.body.get("rows", []) if r[1] == f"{PREFIX}-password"]
    if len(named) != 1:
        pytest.exit(f"seed password policy: {len(named)} matches, expected 1", returncode=2)
    return Seeds(
        user_login=login,
        user_id=user.body["item"]["id"],
        group_id=group,
        paging_group_id=paging,
        rule_id=rule,
        app_id=app,
        policy_id=named[0],
    )


@pytest.fixture(autouse=True)
def no_secrets(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> Iterator[None]:
    """Fail a test whose captured output holds a line of the private key or the service token
    (plan 8.2.1: output hygiene). Checked after the test, on what pytest would print."""
    yield
    out, err = capsys.readouterr()
    text = out + err + "\n".join(r.getMessage() for r in caplog.records)
    for secret in _secrets():
        assert secret not in text, "a secret value appeared in the test's output"
    # Put both back for pytest's own report.
    sys.stdout.write(out)
    sys.stderr.write(err)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Iterator[None]:
    """`no_secrets` sees only a test's own capture; output from module and session fixtures
    (the service token's, the sign-in fixture's) lands in the report's "Captured … setup"
    sections, which `-rA` prints. Blank any section holding a secret, and fail the test."""
    outcome = yield
    report: pytest.TestReport = outcome.get_result()  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
    found = _secrets()
    if not found:
        return
    leaked = False
    sections: list[tuple[str, str]] = []
    for title, text in report.sections:
        if any(secret in text for secret in found):
            leaked = True
            text = "[removed: held a secret value]"
        sections.append((title, text))
    if leaked:
        report.sections = sections
        report.outcome = "failed"
        report.longrepr = "a secret value appeared in captured output"


def _secrets() -> list[str]:
    found: list[str] = []
    path = os.environ.get("OKTA_PRIVATE_KEY_FILE")
    if path and Path(path).is_file():
        lines = Path(path).read_text().splitlines()
        found += [ln for ln in lines if len(ln) >= 40 and not ln.startswith("-----")]
    return found + list(_TOKENS)


@pytest.fixture(scope="session")
def org_url(config: Any) -> str:
    return str(config.okta_org_url)


@pytest.fixture(scope="session")
async def okta(config: Any) -> AsyncIterator[tuple[Any, Any, list[httpx2.Request]]]:
    """A bare client and token provider, built the way `build_runtime` builds them, with every
    request recorded (and each response's status and Okta `errorCode` in `ANSWERS`): for the
    paging and routing checks, which send URLs the executor refuses or builds differently."""
    from okta_mcp.okta.client import OktaClient, new_http_client
    from okta_mcp.okta.dpop import DPoP
    from okta_mcp.okta.token import ClientCredentialsProvider, load_private_key

    sent: list[httpx2.Request] = []

    async def record(request: httpx2.Request) -> None:
        sent.append(request)

    async def answer(response: httpx2.Response) -> None:
        await response.aread()
        try:
            body = response.json()
        except (ValueError, UnicodeDecodeError):
            body = None
        code = body.get("errorCode") if isinstance(body, dict) else None  # pyright: ignore[reportUnknownMemberType]
        kind = "list" if isinstance(body, list) else "object" if isinstance(body, dict) else "-"
        ANSWERS[response.request.url.raw_path.decode()] = Answer(
            response.status_code, code if isinstance(code, str) else None, kind
        )

    async with new_http_client() as http:
        http.event_hooks["request"].append(record)
        http.event_hooks["response"].append(answer)
        dpop = DPoP() if config.okta_dpop else None
        provider = ClientCredentialsProvider(
            http,
            org_url=config.okta_org_url,
            client_id=config.okta_client_id,
            key=load_private_key(config.okta_private_key_file),
            key_id=config.okta_key_id,
            scopes=config.okta_scopes,
            dpop=dpop,
        )
        client = OktaClient(
            http,
            org_url=config.okta_org_url,
            tokens=provider,
            dpop=dpop,
            max_inflight=2,
            rate_limit_max_wait=config.okta_rate_limit_max_wait,
        )
        remember_token((await provider.token()).value)
        # No `on_request`: these requests aren't a principal's, so the limiter isn't charged.
        yield provider, client, sent
