"""Login-failure checks (plan 8.2.1, 9.1): cause known failures, then `diagnostics
login-failures` must name them.

Runs only when `OKTA_LIVE_SIGNIN_PASSWORD` is set (the `signin` job in `live.yml`). The sign-ins
(`_signin.py`) are the only code in `tests/live/` that changes anything in Okta: they leave
System Log events and lock the test user, which the seeded password policy unlocks by itself.
They use the test user's own password and the seeded apps' public client IDs, never the
service app.

Cases, in this order (the lockout last, since it blocks sign-in until the policy unlocks it):

1. Sign-in to an app the user isn't assigned to → `not_assigned`
2. Sign-in to an app whose authentication policy denies the user's group → `sign_on_policy_deny`
3. Right password, wrong TOTP code → `mfa_failed`
4. Wrong passwords up to the policy's lockout threshold → `invalid_credentials` and `locked_out`

Each case gets its own `since`/`until` window, in whole seconds that don't overlap, so one
case's events can't satisfy another. The System Log lags, so each check polls until its cause
shows up or `POLL_FOR` runs out. Asserts are on cause names, and for the lockout case on the
count of wrong passwords (at most the number sent: 9.1 pairs Okta's two events per attempt).

Seeds (infra repo Terraform, plus one manual step), by name from `OKTA_LIVE_SEED_PREFIX`:
user `<prefix>-signin@<domain>`, enrolled in Google Authenticator (by hand, once); OIDC apps
(Interaction Code grant, redirect URI `_signin.REDIRECT_URI`) `<prefix>-signin-mfa` (assigned;
password + TOTP), `<prefix>-signin-unassigned` (not assigned), `<prefix>-signin-deny`
(assigned; its authentication policy denies the user's group); password policy
`<prefix>-signin-password` for the user's group only, with lockout and auto-unlock.
"""

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import httpx2
import pytest
from _live import DOMAIN, PREFIX, Call, remember_token
from _signin import Outcome, Signin, message_keys

pytestmark = pytest.mark.anyio

PASSWORD = os.environ.get("OKTA_LIVE_SIGNIN_PASSWORD", "")
if not PASSWORD:
    pytest.skip(
        "OKTA_LIVE_SIGNIN_PASSWORD not set: sign-in checks not configured", allow_module_level=True
    )

LOGIN = f"{PREFIX}-signin@{DOMAIN}"
POLL_FOR = 300.0
POLL_EVERY = 20.0
MAX_LOCKOUT_ATTEMPTS = 10
"""A higher seeded threshold is refused: the case would send that many wrong passwords."""


@dataclass
class Case:
    since: str
    until: str
    outcomes: list[Outcome]
    sent: int
    """Wrong credentials this case sent: the most a cause it causes may count."""


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _next_second() -> datetime:
    """Wait for the next whole second and return it: a `since` no request of this case is
    before, and (after the previous case's `until`, truncated down) after all of that case's."""
    now = datetime.now(UTC)
    at = now.replace(microsecond=0) + timedelta(seconds=1)
    await anyio.sleep((at - now).total_seconds())
    return at


async def _client_id(call: Call, label: str) -> str:
    found = await call("apps", "list", {"q": label}, select="id,label", limit=200)
    ids = [r[0] for r in found.body.get("rows", []) if len(r) == 2 and r[1] == label]
    if not found.ok or len(ids) != 1:
        pytest.exit(f"seed app {label}: {len(ids)} matches ({found.code})", returncode=2)
    app = await call("apps", "get", {"app": ids[0]}, select="*")
    item: dict[str, Any] = app.body.get("item", {}) if app.ok else {}
    client = item.get("credentials", {}).get("oauthClient", {}).get("client_id")
    if not isinstance(client, str):
        pytest.exit(f"seed app {label}: no OIDC client ID ({app.code})", returncode=2)
    return client


async def _lockout_attempts(call: Call) -> int:
    """The seeded policy's lockout threshold, after checking it unlocks by itself: a case that
    locks the user for good would fail every later run until someone unlocks it."""
    listed = await call("policies", "list", {"type": "PASSWORD"}, select="id,name", limit=200)
    name = f"{PREFIX}-signin-password"
    ids = [r[0] for r in listed.body.get("rows", []) if len(r) == 2 and r[1] == name]
    if not listed.ok or len(ids) != 1:
        pytest.exit(f"seed policy {name}: {len(ids)} matches ({listed.code})", returncode=2)
    got = await call("policies", "get", {"policy": ids[0]}, select="*")
    lockout = got.body.get("item", {}).get("settings", {}).get("password", {}).get("lockout", {})
    attempts, unlock = lockout.get("maxAttempts"), lockout.get("autoUnlockMinutes")
    if not (isinstance(unlock, int) and unlock > 0):
        pytest.exit(f"seed policy {name}: no auto-unlock; refusing to lock the user", returncode=2)
    if not (isinstance(attempts, int) and 0 < attempts <= MAX_LOCKOUT_ATTEMPTS):
        pytest.exit(
            f"seed policy {name}: lockout threshold not 1 to {MAX_LOCKOUT_ATTEMPTS}", returncode=2
        )
    return attempts


@pytest.fixture(scope="module")
async def cases(call: Call) -> dict[str, Case]:
    remember_token(PASSWORD)
    user = await call("users", "get", {"user": LOGIN}, select="status")
    status = user.body.get("item", {}).get("status") if user.ok else None
    if status != "ACTIVE":
        # LOCKED_OUT: an earlier run's lockout case, still inside the policy's auto-unlock time.
        pytest.exit(f"sign-in test user is {status or user.code}, not ACTIVE", returncode=2)
    mfa = await _client_id(call, f"{PREFIX}-signin-mfa")
    unassigned = await _client_id(call, f"{PREFIX}-signin-unassigned")
    deny = await _client_id(call, f"{PREFIX}-signin-deny")
    attempts = await _lockout_attempts(call)

    out: dict[str, Case] = {}
    async with httpx2.AsyncClient(timeout=30) as http:
        signin = Signin(http, os.environ["OKTA_ORG_URL"], LOGIN, PASSWORD)

        async def case(
            name: str, sent: int, step: Callable[[], Awaitable[Outcome | list[Outcome]]]
        ) -> None:
            since = await _next_second()
            result = await step()
            outcomes = result if isinstance(result, list) else [result]
            # Then `until`, truncated down: past every request above, and not in the future.
            await anyio.sleep(2)
            out[name] = Case(_iso(since), _iso(datetime.now(UTC)), outcomes, sent)

        await case("not_assigned", 0, lambda: signin.attempt(unassigned))
        await case("sign_on_policy_deny", 0, lambda: signin.attempt(deny))
        await case("mfa_failed", 1, lambda: signin.wrong_totp(mfa))
        await case("locked_out", attempts, lambda: signin.wrong_passwords(mfa, attempts))
    return out


async def _causes(call: Call, case: Case, want: set[str]) -> dict[str, int]:
    """Poll `login-failures` over the case's window until every cause in `want` shows up."""
    counts: dict[str, int] = {}
    with anyio.move_on_after(POLL_FOR):
        while True:
            result = await call(
                "diagnostics",
                "login-failures",
                {"user": LOGIN, "since": case.since, "until": case.until},
            )
            assert result.ok, f"login-failures failed: {result.code}"
            causes = result.body.get("item", {}).get("causes", [])
            counts = {
                c["cause"]: c["count"]
                for c in causes
                if isinstance(c, dict) and isinstance(c.get("cause"), str)
            }
            if want <= counts.keys():
                break
            await anyio.sleep(POLL_EVERY)
    return counts


@pytest.mark.parametrize(
    ("name", "want"),
    [
        ("not_assigned", {"not_assigned"}),
        ("sign_on_policy_deny", {"sign_on_policy_deny"}),
        ("mfa_failed", {"mfa_failed"}),
        ("locked_out", {"locked_out", "invalid_credentials"}),
    ],
)
async def test_cause_named(call: Call, cases: dict[str, Case], name: str, want: set[str]) -> None:
    case = cases[name]
    counts = await _causes(call, case, want)
    # Cause names, counts and Okta's message keys: fixed strings, never event values.
    assert want <= counts.keys(), (
        f"{name}: causes {sorted(counts.items())}, IDX messages {message_keys(case.outcomes)}"
    )
    # One wrong password is one count, however many events Okta logs for it (9.1's pairing).
    if name == "locked_out":
        assert counts["invalid_credentials"] <= case.sent, (
            f"invalid_credentials {counts['invalid_credentials']} > {case.sent} sent"
        )
