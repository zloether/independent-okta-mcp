import copy
import dataclasses
import itertools
import random
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.loader import build_policy, load_policy
from okta_mcp.policy.model import Grant, Policy
from okta_mcp.registry.loader import Command, Domain, Registry
from okta_mcp.registry.model import ArgRule

PILOT = Path(__file__).parent / "fixtures" / "pilot.yaml"
READERS, HELPDESK = "00g1readers000000000", "00g1helpdsk000000000"
ANALYSTS, ADMINS = "00g1secanalyst000000", "00g1abc2defGHI3jkL45"
STRANGERS = "00g9nobody0000000000"
G1, G2, G3 = "00g1aaaaaaaaaaaaaaaa", "00g2bbbbbbbbbbbbbbbb", "00g3cccccccccccccccc"
GROUP = "00g1emaKYZTWRYYRRTSK"

GROUPS_NORMAL = {"list", "get", "get-members", "get-apps", "get-owners", "list-rules", "get-rule"}
GROUPS_SENSITIVE = {"list-roles", "get-role", "list-role-app-targets", "list-role-group-targets"}
ZONES = {("network-zones", "list"), ("network-zones", "get")}
ALL_SCOPES = frozenset({"okta.groups.read", "okta.roles.read", "okta.networkZones.read"})

ALLOWED, FORBIDDEN, UNAVAILABLE = Verdict.ALLOWED, Verdict.FORBIDDEN, Verdict.UNAVAILABLE


def _who(*groups: str) -> Principal:
    return Principal(uid="00u1example000000000", sub="user@example.com", groups=frozenset(groups))


def _groups(*names: str) -> set[Grant]:
    return {("groups", n) for n in names}


def _policy(registry: Registry, **roles: dict[str, Any]) -> Policy:
    return build_policy({"version": 1, "roles": copy.deepcopy(roles)}, registry)


def _engine(
    registry: Registry, scopes: frozenset[str] = ALL_SCOPES, **roles: dict[str, Any]
) -> Engine:
    return Engine(_policy(registry, **roles), registry, scopes)


def _all(registry: Registry) -> set[Grant]:
    return {(d.name, c) for d in registry.domains.values() for c in d.commands}


def _replace(registry: Registry, grant: Grant, **changes: Any) -> Registry:
    domain = registry.domains[grant[0]]
    command = dataclasses.replace(domain.commands[grant[1]], **changes)
    commands = MappingProxyType({**domain.commands, grant[1]: command})
    return Registry(
        MappingProxyType({**registry.domains, domain.name: Domain(domain.name, "x", commands)})
    )


@pytest.fixture(scope="module")
def engine(pilot: Registry) -> Engine:
    return Engine(load_policy(PILOT, pilot), pilot, ALL_SCOPES)


# --- the pilot policy, role by role --------------------------------------------------------


def test_assumed_scopes_are_what_the_pilot_registry_needs(pilot: Registry) -> None:
    needed = {s for d in pilot.domains.values() for c in d.commands.values() for s in c.scope_sets}
    assert needed == {
        frozenset({"okta.groups.read"}),
        frozenset({"okta.roles.read"}),
        frozenset({"okta.networkZones.read"}),
    }


@pytest.mark.parametrize(
    ("group", "role", "expected"),
    [
        (READERS, "directory-reader", _groups(*GROUPS_NORMAL)),
        (HELPDESK, "helpdesk", _groups(*GROUPS_NORMAL, "list-roles", "get-role") | ZONES),
        (
            ANALYSTS,
            "security-analyst",
            _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE) - _groups("get-apps") | ZONES,
        ),
        (ADMINS, "platform-admin", _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE) | ZONES),
    ],
)
def test_pilot_roles(engine: Engine, group: str, role: str, expected: set[Grant]) -> None:
    who = _who(group)
    assert engine.roles(who) == {role}
    assert engine.permitted(who) == expected


def test_every_permitted_command_is_callable_without_args_and_no_other(
    engine: Engine, pilot: Registry
) -> None:
    for group in (READERS, HELPDESK, ANALYSTS, ADMINS, STRANGERS):
        who = _who(group)
        for domain, command in _all(pilot):
            expected = ALLOWED if (domain, command) in engine.permitted(who) else FORBIDDEN
            assert engine.check(who, domain, command, {}) is expected


def test_helpdesk_and_readers_can_search(engine: Engine) -> None:
    # The 3.2 decision: `groups: ["*"]` used to list but not search.
    for group in (READERS, HELPDESK):
        who = _who(group)
        for arg in ("q", "filter", "search"):
            assert engine.check(who, "groups", "list", {arg: "x"}) is ALLOWED
        assert engine.check(who, "groups", "get-members", {"group": GROUP, "search": "x"}) is (
            ALLOWED
        )
        assert engine.check(who, "groups", "get-owners", {"group": GROUP, "filter": "x"}) is (
            ALLOWED
        )
        assert engine.check(who, "groups", "list-rules", {"search": "x"}) is ALLOWED
    assert engine.check(_who(HELPDESK), "network-zones", "list", {"filter": "x"}) is ALLOWED


def test_plain_wildcard_does_not_reach_a_raising_arg(engine: Engine) -> None:
    # `expand=stats` carries admin-role data; both roles reach `list` by wildcard only.
    for group in (READERS, HELPDESK):
        assert engine.check(_who(group), "groups", "list", {"expand": "stats"}) is FORBIDDEN
        assert (
            engine.check(_who(group), "groups", "list", {"search": "x", "expand": "stats"})
            is FORBIDDEN
        )


def test_wildcard_with_include_sensitive_reaches_a_raising_arg(engine: Engine) -> None:
    for group in (ANALYSTS, ADMINS):
        assert engine.check(_who(group), "groups", "list", {"expand": "stats"}) is ALLOWED


def test_args_without_a_rule_change_nothing(engine: Engine) -> None:
    who = _who(READERS)
    assert engine.check(who, "groups", "list", {"sort_by": "x", "sort_order": "asc"}) is ALLOWED
    assert engine.check(who, "groups", "get", {"group": GROUP}) is ALLOWED
    # `allowed_values` without an `arg_rule` (get-members `expand`).
    assert (
        engine.check(who, "groups", "get-members", {"group": GROUP, "expand": "group-rules"})
        is ALLOWED
    )


# --- roles from groups ---------------------------------------------------------------------


def test_no_groups_and_unknown_groups_hold_no_role(engine: Engine, pilot: Registry) -> None:
    for who in (_who(), _who(STRANGERS), _who("mcp-okta-admins"), _who(ADMINS.lower())):
        assert engine.roles(who) == frozenset()
        assert engine.permitted(who) == frozenset()
        for domain, command in _all(pilot):
            assert engine.check(who, domain, command, {}) is FORBIDDEN


def test_roles_union_and_unknown_groups_add_nothing(engine: Engine) -> None:
    who = _who(READERS, HELPDESK, STRANGERS)
    assert engine.roles(who) == {"directory-reader", "helpdesk"}
    assert engine.permitted(who) == engine.permitted(_who(HELPDESK))


def test_any_one_of_a_roles_groups_grants_it(registry: Registry) -> None:
    e = _engine(registry, r={"groups": [G1, G2], "allow": {"groups": ["get"]}})
    for who in (_who(G1), _who(G2), _who(G1, G2)):
        assert e.roles(who) == {"r"}
    assert e.roles(_who(G3)) == frozenset()


def test_one_group_in_two_roles_grants_both(registry: Registry) -> None:
    e = _engine(
        registry,
        a={"groups": [G1], "allow": {"groups": ["get"]}},
        b={"groups": [G1, G2], "allow": {"network-zones": ["get"]}},
    )
    assert e.roles(_who(G1)) == {"a", "b"}
    assert e.permitted(_who(G1)) == {("groups", "get"), ("network-zones", "get")}
    assert e.permitted(_who(G2)) == {("network-zones", "get")}


# --- deny ----------------------------------------------------------------------------------


def test_deny_in_one_role_removes_what_another_allows(engine: Engine) -> None:
    # security-analyst denies `get-apps`; helpdesk allows it.
    assert ("groups", "get-apps") in engine.permitted(_who(HELPDESK))
    both = _who(HELPDESK, ANALYSTS)
    assert ("groups", "get-apps") not in engine.permitted(both)
    assert engine.check(both, "groups", "get-apps", {"group": GROUP}) is FORBIDDEN
    assert engine.permitted(both) == engine.permitted(_who(ANALYSTS))


def test_deny_beats_a_named_sensitive_command_and_include_sensitive(registry: Registry) -> None:
    e = _engine(
        registry,
        a={
            "groups": [G1],
            "allow": {"*": ["*"], "groups": ["list-roles"]},
            "include_sensitive": ["*"],
        },
        b={"groups": [G2], "allow": {"groups": ["get"]}, "deny": {"groups": ["list-roles"]}},
        c={"groups": [G3], "allow": {"groups": ["get"]}, "deny": {"*": ["*"]}},
    )
    assert e.permitted(_who(G1)) == _all(registry)
    assert e.permitted(_who(G1, G2)) == _all(registry) - {("groups", "list-roles")}
    assert e.check(_who(G1, G2), "groups", "list-roles", {"group": GROUP}) is FORBIDDEN
    assert e.permitted(_who(G1, G3)) == frozenset()
    assert e.permitted(_who(G3)) == frozenset()


def test_deny_also_removes_the_raised_grant(registry: Registry) -> None:
    e = _engine(
        registry,
        a={"groups": [G1], "allow": {"groups": ["list"]}},
        b={"groups": [G2], "allow": {"groups": ["get"]}, "deny": {"groups": ["list"]}},
    )
    assert e.check(_who(G1), "groups", "list", {"expand": "stats"}) is ALLOWED
    assert e.check(_who(G1, G2), "groups", "list", {"expand": "stats"}) is FORBIDDEN
    assert e.check(_who(G1, G2), "groups", "list", {}) is FORBIDDEN


# --- argument rules ------------------------------------------------------------------------


def test_naming_a_command_grants_its_raising_args(registry: Registry) -> None:
    e = _engine(registry, r={"groups": [G1], "allow": {"groups": ["list"]}})
    assert e.check(_who(G1), "groups", "list", {"expand": "stats"}) is ALLOWED


def test_raised_grant_comes_from_any_role(registry: Registry) -> None:
    # One role reaches `list` by wildcard, another names it: the union decides.
    e = _engine(
        registry,
        wide={"groups": [G1], "allow": {"groups": ["*"]}},
        named={"groups": [G2], "allow": {"groups": ["list"]}},
    )
    assert e.check(_who(G1), "groups", "list", {"expand": "stats"}) is FORBIDDEN
    assert e.check(_who(G1, G2), "groups", "list", {"expand": "stats"}) is ALLOWED
    # ... and only for the command that was named.
    assert e.check(_who(G1, G2), "groups", "list-rules", {}) is ALLOWED


def test_include_sensitive_in_another_domain_does_not_cover_the_raise(registry: Registry) -> None:
    e = _engine(
        registry,
        r={
            "groups": [G1],
            "allow": {"groups": ["*"], "network-zones": ["*"]},
            "include_sensitive": ["network-zones"],
        },
    )
    assert e.check(_who(G1), "groups", "list", {"expand": "stats"}) is FORBIDDEN


@pytest.mark.parametrize("value", [None, "", False, 0, [], "stats"])
def test_an_arg_counts_as_passed_whatever_its_value(engine: Engine, value: object) -> None:
    assert engine.check(_who(READERS), "groups", "list", {"expand": value}) is FORBIDDEN


def _with_rule(registry: Registry, grant: Grant, arg: str, rule: ArgRule) -> Registry:
    entry = registry.domains[grant[0]].commands[grant[1]].entry
    args = {**entry.args, arg: entry.args[arg].model_copy(update={"arg_rule": rule})}
    return _replace(
        registry, grant, entry=entry.model_copy(update={"args": MappingProxyType(args)})
    )


def test_forbidden_arg_is_refused_for_every_role(registry: Registry) -> None:
    reg = _with_rule(registry, ("groups", "list"), "sort_by", ArgRule(forbidden=True))
    e = _engine(
        reg,
        named={"groups": [G1], "allow": {"groups": ["list"]}},
        admin={"groups": [G2], "allow": {"*": ["*"]}, "include_sensitive": ["*"]},
    )
    for who in (_who(G1), _who(G2), _who(G1, G2)):
        assert e.check(who, "groups", "list", {"sort_by": "x"}) is FORBIDDEN
        assert e.check(who, "groups", "list", {"sort_order": "asc"}) is ALLOWED


def test_a_rule_the_engine_does_not_know_is_refused(registry: Registry) -> None:
    # A fourth rule form added to the model later must not pass by default.
    unknown = ArgRule.model_construct(forbidden=False, raises_sensitivity_to=None, reviewed=None)
    reg = _with_rule(registry, ("groups", "list"), "sort_by", unknown)
    e = _engine(reg, r={"groups": [G1], "allow": {"*": ["*"]}, "include_sensitive": ["*"]})
    assert e.check(_who(G1), "groups", "list", {"sort_by": "x"}) is FORBIDDEN


def test_unknown_arg_name_is_refused(engine: Engine) -> None:
    for name in ("nope", "Expand", "expand ", ""):
        assert engine.check(_who(ADMINS), "groups", "list", {name: "x"}) is FORBIDDEN


def test_unknown_command_and_domain_are_forbidden_not_errors(engine: Engine) -> None:
    for who in (_who(ADMINS), _who(STRANGERS)):
        assert engine.check(who, "groups", "nope", {}) is FORBIDDEN
        assert engine.check(who, "nope", "list", {}) is FORBIDDEN
        assert engine.check(who, "*", "*", {}) is FORBIDDEN
        assert engine.check(who, "groups", "*", {}) is FORBIDDEN


# --- capability gate -----------------------------------------------------------------------


def test_unavailable_lists_commands_with_no_granted_scope_set(pilot: Registry) -> None:
    policy = load_policy(PILOT, pilot)
    assert Engine(policy, pilot, ALL_SCOPES).unavailable == frozenset()
    assert Engine(policy, pilot, frozenset()).unavailable == _all(pilot)
    e = Engine(policy, pilot, frozenset({"okta.groups.read", "okta.users.read"}))
    assert e.unavailable == _groups(*GROUPS_SENSITIVE) | ZONES


def test_permitted_but_unavailable(pilot: Registry) -> None:
    e = Engine(load_policy(PILOT, pilot), pilot, frozenset({"okta.groups.read"}))
    who = _who(HELPDESK)
    # Still permitted, so help can say why it won't run.
    assert ("groups", "list-roles") in e.permitted(who)
    assert e.check(who, "groups", "list-roles", {"group": GROUP}) is UNAVAILABLE
    assert e.check(who, "network-zones", "list", {}) is UNAVAILABLE
    assert e.check(who, "groups", "get", {"group": GROUP}) is ALLOWED


def test_policy_is_decided_before_capability(pilot: Registry) -> None:
    # A caller without the grant can't tell an unavailable command from an available one.
    e = Engine(load_policy(PILOT, pilot), pilot, frozenset({"okta.groups.read"}))
    assert e.check(_who(READERS), "groups", "list-roles", {"group": GROUP}) is FORBIDDEN
    assert e.check(_who(READERS), "network-zones", "list", {}) is FORBIDDEN
    assert e.check(_who(STRANGERS), "network-zones", "list", {}) is FORBIDDEN
    none = Engine(load_policy(PILOT, pilot), pilot, frozenset())
    assert none.check(_who(READERS), "groups", "list", {"expand": "stats"}) is FORBIDDEN
    assert none.check(_who(READERS), "groups", "list", {"nope": 1}) is FORBIDDEN


def _scoped(registry: Registry, *sets: set[str]) -> Registry:
    return _replace(registry, ("groups", "get"), scope_sets=tuple(frozenset(s) for s in sets))


@pytest.mark.parametrize(
    ("sets", "granted", "available"),
    [
        # Every scope of a set is needed.
        ([{"a.read", "b.read"}], {"a.read"}, False),
        ([{"a.read", "b.read"}], {"a.read", "b.read", "c.read"}, True),
        # Any one set is enough.
        ([{"a.read"}, {"b.read", "c.read"}], {"a.read"}, True),
        ([{"a.read"}, {"b.read", "c.read"}], {"b.read", "c.read"}, True),
        ([{"a.read"}, {"b.read", "c.read"}], {"b.read"}, False),
        # No scope sets: nothing can satisfy it.
        ([], {"a.read"}, False),
        # `.read` does not stand in for `.manage` (getAerialConsent declares only that).
        ([{"okta.orgs.manage"}], {"okta.orgs.read"}, False),
        # Scope names are compared exactly.
        ([{"okta.groups.read"}], {"okta.groups.Read"}, False),
        ([{"okta.groups.read"}], {"okta.groups"}, False),
    ],
)
def test_capability_gate(
    registry: Registry, sets: list[set[str]], granted: set[str], available: bool
) -> None:
    reg = _scoped(registry, *sets)
    e = Engine(
        _policy(reg, r={"groups": [G1], "allow": {"groups": ["get"]}}), reg, frozenset(granted)
    )
    assert (("groups", "get") not in e.unavailable) is available
    assert e.check(_who(G1), "groups", "get", {"group": GROUP}) is (
        ALLOWED if available else UNAVAILABLE
    )


# --- memoization ---------------------------------------------------------------------------


def test_permitted_is_computed_once_per_role_set(engine: Engine) -> None:
    first = engine.permitted(_who(HELPDESK))
    assert engine.permitted(_who(HELPDESK, STRANGERS)) is first
    assert engine.permitted(_who(HELPDESK, READERS)) is not first


def test_cache_is_keyed_by_roles_not_groups(registry: Registry) -> None:
    e = _engine(
        registry,
        a={"groups": [G1, G2], "allow": {"groups": ["get"]}},
        b={"groups": [G3], "allow": {"groups": ["list"]}},
    )
    callers = [_who(G1), _who(G2), _who(G1, G2), _who(G1, STRANGERS), _who(G3), _who(G1, G3)]
    for who in callers * 3:
        e.permitted(who)
        e.check(who, "groups", "get", {})
        e.check(_who(STRANGERS, who.uid), "groups", "get", {})
    assert set(e._by_roles) == {frozenset({"a"}), frozenset({"b"}), frozenset({"a", "b"})}  # pyright: ignore[reportPrivateUsage]


def test_a_cached_answer_is_not_served_to_another_role_set(registry: Registry) -> None:
    e = _engine(
        registry,
        a={"groups": [G1], "allow": {"groups": ["get"]}},
        b={"groups": [G2], "allow": {"groups": ["list"]}},
    )
    for _ in range(2):
        assert e.permitted(_who(G1)) == {("groups", "get")}
        assert e.permitted(_who(G2)) == {("groups", "list")}
        assert e.permitted(_who(G1, G2)) == {("groups", "get"), ("groups", "list")}
        assert e.permitted(_who(G3)) == frozenset()


def test_engine_reads_only_the_principals_groups(engine: Engine) -> None:
    a = Principal(uid="00u1", sub="a@example.com", groups=frozenset({HELPDESK}))
    b = Principal(
        uid="00u2", sub="b@example.com", groups=frozenset({HELPDESK}), client_id="c", exp=1
    )
    assert engine.permitted(a) is engine.permitted(b)


# --- properties over generated policies ----------------------------------------------------

_POOL = (G1, G2, G3)


def _random_patterns(rng: random.Random, registry: Registry, *, empty_ok: bool) -> dict[str, Any]:
    if rng.random() < 0.15:
        return {"*": ["*"]}
    patterns: dict[str, Any] = {}
    for domain in registry.domains.values():
        roll = rng.random()
        if roll < 0.3:
            patterns[domain.name] = ["*"]
        elif roll < 0.6:
            names = sorted(domain.commands)
            patterns[domain.name] = rng.sample(names, rng.randint(1, len(names)))
            if rng.random() < 0.2:
                patterns[domain.name].append("*")
    if not patterns and not empty_ok:
        patterns["groups"] = ["get"]
    return patterns


def _random_role(rng: random.Random, registry: Registry, *, sensitive: bool) -> dict[str, Any]:
    role: dict[str, Any] = {
        "groups": rng.sample(_POOL, rng.randint(1, 2)),
        "allow": _random_patterns(rng, registry, empty_ok=False),
    }
    if deny := _random_patterns(rng, registry, empty_ok=True) if rng.random() < 0.6 else {}:
        role["deny"] = deny
    if sensitive and rng.random() < 0.5:
        role["include_sensitive"] = (
            ["*"]
            if rng.random() < 0.2
            else rng.sample(sorted(registry.domains), rng.randint(1, len(registry.domains)))
        )
    return role


def _cases(registry: Registry, *, sensitive: bool = True) -> Iterator[tuple[Policy, Engine]]:
    rng = random.Random(20261111)  # noqa: S311
    for _ in range(300):
        roles = {
            f"r{i}": _random_role(rng, registry, sensitive=sensitive)
            for i in range(rng.randint(1, 4))
        }
        policy = _policy(registry, **roles)
        yield policy, Engine(policy, registry, ALL_SCOPES)


def _principals() -> list[Principal]:
    return [
        _who(*combo, STRANGERS)
        for n in range(len(_POOL) + 1)
        for combo in itertools.combinations(_POOL, n)
    ]


def _arg_sets(command: Command) -> list[dict[str, object]]:
    """No args, each arg alone, and all of them."""
    names = list(command.entry.args)
    return [{}, *({n: "x"} for n in names), dict.fromkeys(names, "x")]


def _raising(command: Command, args: dict[str, object]) -> bool:
    return any(
        (rule := command.entry.args[a].arg_rule) is not None and rule.raises_sensitivity_to
        for a in args
    )


def _commands(registry: Registry) -> list[Command]:
    return [c for d in registry.domains.values() for c in d.commands.values()]


def test_property_deny_always_wins(registry: Registry) -> None:
    denied_something = 0
    for policy, engine in _cases(registry):
        for who in _principals():
            held = [policy.roles[n] for n in engine.roles(who)]
            denied = frozenset[Grant]().union(*(r.deny for r in held))
            denied_something += bool(denied)
            assert not denied & engine.permitted(who)
            for domain, name in denied:
                for args in _arg_sets(registry.domains[domain].commands[name]):
                    assert engine.check(who, domain, name, args) is FORBIDDEN
    assert denied_something > 500  # the generator does exercise deny


def test_property_no_role_means_nothing(registry: Registry) -> None:
    without = 0
    for policy, engine in _cases(registry):
        named = frozenset[str]().union(*(r.groups for r in policy.roles.values()))
        for who in _principals():
            if who.groups & named:
                continue
            without += 1
            assert engine.roles(who) == frozenset()
            assert engine.permitted(who) == frozenset()
            for command in _commands(registry):
                for args in _arg_sets(command):
                    assert engine.check(who, command.domain, command.name, args) is FORBIDDEN
    assert without >= 300


def test_property_wildcards_alone_never_yield_sensitive(registry: Registry) -> None:
    # No `include_sensitive` anywhere: whatever is reached only by a wildcard is `normal`
    # and is not callable with a raising argument.
    checked = 0
    for policy, engine in _cases(registry, sensitive=False):
        for who in _principals():
            held = [policy.roles[n] for n in engine.roles(who)]
            named = frozenset[Grant]().union(*(r.allow_raised for r in held))
            for command in _commands(registry):
                grant = (command.domain, command.name)
                if grant in named:
                    continue
                if command.sensitivity == "sensitive":
                    assert grant not in engine.permitted(who)
                for args in _arg_sets(command):
                    if command.sensitivity == "sensitive" or _raising(command, args):
                        checked += 1
                        assert engine.check(who, *grant, args) is FORBIDDEN
    assert checked > 10_000


def test_property_named_set_in_wildcard_only_policies_is_empty(registry: Registry) -> None:
    # Ties the property above to the file: with wildcards only and no `include_sensitive`,
    # nothing is "named", so the exemption there can't hide a leak.
    rng = random.Random(7)  # noqa: S311
    for _ in range(100):
        domains = rng.sample(sorted(registry.domains), rng.randint(1, len(registry.domains)))
        allow = {"*": ["*"]} if rng.random() < 0.3 else {d: ["*"] for d in domains}
        e = _engine(registry, r={"groups": [G1], "allow": allow})
        permitted = e.permitted(_who(G1))
        # `vault` is all sensitive, so a wildcard on it alone grants nothing.
        assert bool(permitted) == (allow != {"vault": ["*"]})
        for command in _commands(registry):
            grant = (command.domain, command.name)
            if command.sensitivity == "sensitive":
                assert grant not in permitted
            for args in _arg_sets(command):
                if command.sensitivity == "sensitive" or _raising(command, args):
                    assert e.check(_who(G1), *grant, args) is FORBIDDEN


def test_property_check_agrees_with_permitted(registry: Registry) -> None:
    for policy, engine in _cases(registry):
        for who in _principals():
            permitted = engine.permitted(who)
            held = [policy.roles[n] for n in engine.roles(who)]
            assert permitted <= frozenset[Grant]().union(*(r.allow for r in held))
            # `check` tests `permitted` first, so this holds the second line of defence.
            assert engine._effective(who).raised <= permitted  # pyright: ignore[reportPrivateUsage]
            for command in _commands(registry):
                grant = (command.domain, command.name)
                assert (engine.check(who, *grant, {}) is ALLOWED) == (grant in permitted)
                for args in _arg_sets(command):
                    if engine.check(who, *grant, args) is not FORBIDDEN:
                        assert grant in permitted
