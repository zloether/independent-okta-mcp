"""Check 5 (plan 8.2.1): the example policy's roles against the live org.

One allowed `tools/call` per role, and one the role is refused, through `Tools`, the engine and
the executor as the server wires them. Principals are built here, with each role's group IDs
from `docker/policy.example.yaml`: no user token is involved, since a real Okta sign-in can't
run unattended (8.2.1, decided 2026-11-14), and the token verifier is covered against a local
issuer by `tests/integration`. That a refused call sends nothing is `tests/exec`'s to show.
"""

from typing import Any

import pytest
import yaml
from _live import POLICY, Call, Seeds

from okta_mcp.auth.principal import Principal

pytestmark = pytest.mark.anyio

ROLES: dict[str, Any] = yaml.safe_load(POLICY.read_text())["roles"]


def _who(role: str) -> Principal:
    return Principal(
        uid=f"00u1live{role[:4]}0000000"[:20],
        sub=f"live-{role}",
        groups=frozenset(ROLES[role]["groups"]),
    )


def _allowed(seeds: Seeds) -> dict[str, tuple[str, str, dict[str, Any]]]:
    return {
        "helpdesk": ("users", "get-groups", {"user": seeds.user_login}),
        "directory-reader": ("groups", "get-members", {"group": seeds.group_id}),
        "security-analyst": ("policies", "list", {"type": "PASSWORD"}),
        "platform-admin": ("apps", "get-groups", {"app": seeds.app_id}),
    }


ALLOWED_ROLES = ("helpdesk", "directory-reader", "security-analyst", "platform-admin")
REFUSED = {
    "helpdesk": ("policies", "list", {"type": "PASSWORD"}),
    "directory-reader": ("apps", "list", {}),
    "security-analyst": ("users", "get-factors", {"user": "00u1example000000000"}),
}


def test_every_role_has_a_case() -> None:
    """A role added to the example policy needs its cases here (platform-admin is refused
    nothing)."""
    assert set(ALLOWED_ROLES) == set(ROLES), "a role without an allowed case"
    assert set(REFUSED) | {"platform-admin"} == set(ROLES), "a role without a refused case"


@pytest.mark.parametrize("role", sorted(ROLES))
async def test_allowed_call(role: str, call: Call, seeds: Seeds) -> None:
    domain, command, args = _allowed(seeds)[role]
    result = await call(domain, command, args, principal=_who(role))
    assert result.ok, f"{role}: {domain} {command} failed: {result.code}"


@pytest.mark.parametrize("role", sorted(REFUSED))
async def test_refused_call(role: str, call: Call) -> None:
    domain, command, args = REFUSED[role]
    result = await call(domain, command, args, principal=_who(role))
    assert result.code == "forbidden_by_policy", f"{role}: {domain} {command}: {result.code}"


async def test_login_failures(call: Call, seeds: Seeds) -> None:
    """The composite command, live: the seeded user is STAGED and never signs in, so the
    diagnosis has no failures, but every operation the handler uses must answer."""
    result = await call(
        "diagnostics", "login-failures", {"user": seeds.user_login}, principal=_who("helpdesk")
    )
    assert result.ok, f"login-failures failed: {result.code}"
    item = result.body.get("item", {})
    assert {"user", "window", "checks", "headline"} <= set(item), sorted(item)
    assert item["window"]["truncated"] is False
