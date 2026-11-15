"""`docker/policy.example.yaml` (step 5.7) against the full registry, and design §9.3's copy."""

import re
from pathlib import Path

import pytest
import yaml

from okta_mcp.auth.principal import Principal
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.loader import build_policy, load_policy
from okta_mcp.policy.model import Policy
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import load_spec

ROOT = Path(__file__).parents[2]
EXAMPLE = ROOT / "docker" / "policy.example.yaml"
DESIGN = ROOT / "docs" / "design" / "mcp-server.md"

HELPDESK, READERS = "00g1helpdsk000000000", "00g1readers000000000"
ANALYSTS, ADMINS = "00g1secanalyst000000", "00g1abc2defGHI3jkL45"
ADMIN_WARNING = (
    'roles.platform-admin.include_sensitive: "*" lets this role\'s wildcards match sensitive '
    "commands in every domain"
)


@pytest.fixture(scope="module")
def full() -> Registry:
    return load_registry(load_spec())


@pytest.fixture(scope="module")
def policy(full: Registry) -> Policy:
    return load_policy(EXAMPLE, full)


@pytest.fixture(scope="module")
def engine(policy: Policy, full: Registry) -> Engine:
    scopes = frozenset(
        s
        for d in full.domains.values()
        for c in d.commands.values()
        for scope_set in c.scope_sets
        for s in scope_set
    )
    return Engine(policy, full, scopes)


def _who(*groups: str) -> Principal:
    return Principal(uid="00u1example000000000", sub="user@example.com", groups=frozenset(groups))


def _design_block() -> str:
    section = DESIGN.read_text().split("### 9.3 Policy file", 1)[1]
    match = re.search(r"```yaml\n(.*?)```", section, re.DOTALL)
    assert match is not None
    return match.group(1)


def test_loads_against_the_full_registry_with_only_the_admin_warning(policy: Policy) -> None:
    assert policy.warnings == (ADMIN_WARNING,)
    assert set(policy.roles) == {
        "helpdesk",
        "directory-reader",
        "security-analyst",
        "platform-admin",
    }


def test_design_copy_compiles_to_the_same_roles(policy: Policy, full: Registry) -> None:
    design = build_policy(yaml.safe_load(_design_block()), full)
    assert design.roles == policy.roles
    assert design.warnings == policy.warnings


def test_platform_admin_holds_every_command(policy: Policy, full: Registry) -> None:
    every = {(d.name, c) for d in full.domains.values() for c in d.commands}
    assert policy.roles["platform-admin"].allow == every


def test_wildcards_reach_no_sensitive_command_unless_named(policy: Policy, full: Registry) -> None:
    sensitive = {
        (d.name, n)
        for d in full.domains.values()
        for n, c in d.commands.items()
        if c.sensitivity == "sensitive"
    }
    assert policy.roles["directory-reader"].allow & sensitive == set()
    assert policy.roles["helpdesk"].allow & sensitive == {
        ("users", "get-factors"),
        ("users", "get-enrollments"),
        ("diagnostics", "login-failures"),
    }
    # logs and sessions through include_sensitive, get-risk by name.
    assert policy.roles["security-analyst"].allow & sensitive == {
        ("logs", "list"),
        ("sessions", "get"),
        ("users", "get-risk"),
    }


@pytest.mark.parametrize(
    ("groups", "grant", "args", "verdict"),
    [
        # helpdesk searches users by login; the reader lists but can't search
        (
            [HELPDESK],
            ("users", "list"),
            {"search": 'profile.login eq "a@example.com"'},
            Verdict.ALLOWED,
        ),
        ([READERS], ("users", "list"), {}, Verdict.ALLOWED),
        ([READERS], ("users", "list"), {"search": 'status eq "ACTIVE"'}, Verdict.FORBIDDEN),
        ([HELPDESK], ("users", "get-factors"), {}, Verdict.ALLOWED),
        ([READERS], ("users", "get-factors"), {}, Verdict.FORBIDDEN),
        # deny wins across roles: an analyst who is also on the help desk loses get-factors
        ([HELPDESK, ANALYSTS], ("users", "get-factors"), {}, Verdict.FORBIDDEN),
        (
            [ANALYSTS],
            ("logs", "list"),
            {"filter": 'eventType eq "user.session.start"'},
            Verdict.ALLOWED,
        ),
        ([ANALYSTS], ("logs", "list"), {"filter": 'displayMessage eq "x"'}, Verdict.FORBIDDEN),
        # the analyst's attributes are System Log fields: no profile search on users
        (
            [ANALYSTS],
            ("users", "list"),
            {"search": 'profile.login eq "a@example.com"'},
            Verdict.FORBIDDEN,
        ),
        ([ANALYSTS], ("users", "get-factors"), {}, Verdict.FORBIDDEN),
        ([ADMINS], ("users", "list"), {"search": 'profile.department eq "IT"'}, Verdict.ALLOWED),
        ([], ("users", "list"), {}, Verdict.FORBIDDEN),
    ],
)
def test_roles_in_use(
    engine: Engine,
    groups: list[str],
    grant: tuple[str, str],
    args: dict[str, object],
    verdict: Verdict,
) -> None:
    assert engine.check(_who(*groups), *grant, args) == verdict
