"""The devices, device-assurance, device-posture and device-integrations registries (plan 5.6)."""

from typing import Any

import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.output import ScrubRules, load_scrub
from okta_mcp.exec.params import build_request
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.expression import scrubbed
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry
from okta_mcp.registry.schema import InvalidArguments, validate_args

ORG = "https://example.okta.com"
DEVICE = "guo4a5u7JHHhjXrMK0g4"
ACCOUNT = "dao3qgkIEKjhNZudR0g4"
G1 = "00g1devreader0000000"
DOMAINS = ("devices", "device-assurance", "device-posture", "device-integrations")
OS_ACCOUNTS = ("get-os-accounts", "get-os-account")


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.operation.operation_id for n, c in registry.domains[domain].commands.items()}


def test_commands(registry: Registry) -> None:
    assert _commands(registry, "devices") == {
        "list": "listDevices",
        "get": "getDevice",
        "get-users": "listDeviceUsers",
        "get-os-accounts": "listDeviceOSAccounts",
        "get-os-account": "getDeviceOSAccount",
    }
    assert _commands(registry, "device-assurance") == {
        "list": "listDeviceAssurancePolicies",
        "get": "getDeviceAssurancePolicy",
    }
    assert _commands(registry, "device-posture") == {
        "list": "listDevicePostureChecks",
        "get": "getDevicePostureCheck",
        "list-defaults": "listDefaultDevicePostureChecks",
    }
    assert _commands(registry, "device-integrations") == {
        "list": "listDeviceIntegrations",
        "get": "getDeviceIntegration",
    }


def test_classes(registry: Registry) -> None:
    for domain in DOMAINS:
        want = ("pii",) if domain == "devices" else ("org-config",)
        for cmd in registry.domains[domain].commands.values():
            assert cmd.entry.data_classes == want, (domain, cmd.name)
            assert cmd.sensitivity == "normal", (domain, cmd.name)


def test_normal_commands_return_no_scrubbed_field(registry: Registry) -> None:
    # V14 by the spec, as in plans 5.4 and 5.5: no declared field of a normal command is one
    # scrub.yaml redacts (a `strings` rule counts on a field without children). `get-users`
    # returns Okta users, whose `credentials` scrub.yaml redacts, so it is checked apart.
    rules = load_scrub()
    always = ScrubRules(paths=rules.paths)

    def string_hit(field: str, fields: set[str]) -> bool:
        keys = tuple(field.lower().split("."))
        leaf = not any(f.startswith(field + ".") for f in fields)
        return leaf and any(keys[-len(c) :] == c for c in rules.strings)

    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            response = cmd.operation.response
            fields = set(response.fields) | {f for v in response.item_fields.values() for f in v}
            hits = sorted(f for f in fields if scrubbed(f, always) or string_hit(f, fields))
            if cmd.name == "get-users":
                assert hits and all(h.startswith("user.credentials.") for h in hits), hits
                continue
            assert not hits, (cmd.domain, cmd.name, hits)


def test_scope_sets(registry: Registry) -> None:
    want = {
        "devices": "okta.devices.read",
        "device-assurance": "okta.deviceAssurance.read",
        "device-posture": "okta.devicePostureChecks.read",
        "device-integrations": "okta.deviceIntegrations.read",
    }
    for domain, scope in want.items():
        for cmd in registry.domains[domain].commands.values():
            assert {s for ss in cmd.scope_sets for s in ss} == {scope}, (domain, cmd.name)


@pytest.mark.parametrize(
    ("domain", "command", "arg", "good", "other_prefix"),
    [
        ("devices", "get", "device", DEVICE, "00u4a5u7JHHhjXrMK0g4"),
        ("device-assurance", "get", "policy", "dae3m8o4rWhwReDeM1c5", "00p3m8o4rWhwReDeM1c5"),
        (
            "device-integrations",
            "get",
            "integration",
            "dindyfy1f7Pv1eoVF0g4",
            "0oadyfy1f7Pv1eoVF0g4",
        ),
    ],
)
def test_id_shapes(
    registry: Registry, domain: str, command: str, arg: str, good: str, other_prefix: str
) -> None:
    cmd = registry.domains[domain].commands[command]
    validate_args(cmd, {arg: good})
    for bad in (other_prefix, good[:-1], f"{good}\n", f"{good}/x", "default", ".."):
        with pytest.raises(InvalidArguments, match=f"arg '{arg}'"):
            validate_args(cmd, {arg: bad})


def test_posture_check_id_keeps_out_the_default_segment(registry: Registry) -> None:
    # Only the character set: no spec example shows a built-in check's ID.
    cmd = registry.domains["device-posture"].commands["get"]
    assert "default" in cmd.operation.reserved["postureCheckId"]
    for bad in ("default", "DEFAULT", "Default", "dch3m8o4rWhwReDeM1c5/x", "a.b", "a-b", ".."):
        with pytest.raises(InvalidArguments, match="arg 'check'"):
            build_request(cmd, {"check": bad}, ORG)
    url, _ = build_request(cmd, {"check": "dch3m8o4rWhwReDeM1c5"}, ORG)
    assert url == f"{ORG}/api/v1/device-posture-checks/dch3m8o4rWhwReDeM1c5"


def test_os_account_urls(registry: Registry) -> None:
    devices = registry.domains["devices"].commands
    url, params = build_request(
        devices["get-os-account"], {"device": DEVICE, "account": ACCOUNT}, ORG
    )
    assert url == f"{ORG}/api/v1/devices/{DEVICE}/os-accounts/{ACCOUNT}"
    assert params == {}
    with pytest.raises(InvalidArguments, match="arg 'account'"):
        validate_args(devices["get-os-account"], {"device": DEVICE, "account": DEVICE})


def test_list_args(registry: Registry) -> None:
    listing = registry.domains["devices"].commands["list"]
    rule = listing.entry.args["search"].arg_rule
    assert rule is not None and rule.attribute_expression and not rule.attributes
    exposed = {a.param for a in listing.entry.args.values()}
    assert exposed == {"search", "expand"}
    assert {"fields", "after", "limit"} <= set(listing.operation.params)
    assert listing.entry.args["expand"].allowed_values == ("user", "userSummary")
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(listing, {"expand": "capabilities"})
    _, params = build_request(listing, {"expand": "userSummary"}, ORG)
    assert params == {"expand": "userSummary", "limit": "200"}
    assert listing.is_list and listing.entry.paginate == "link"


def test_os_account_expand_is_comma_joined_and_closed(registry: Registry) -> None:
    for name in OS_ACCOUNTS:
        cmd = registry.domains["devices"].commands[name]
        args: dict[str, Any] = {"device": DEVICE}
        if name == "get-os-account":
            args["account"] = ACCOUNT
        _, params = build_request(
            cmd, {**args, "expand": ["account_linked_enrollments", "offlineFactors"]}, ORG
        )
        assert params["expand"] == "account_linked_enrollments,offlineFactors", name
        with pytest.raises(InvalidArguments, match="arg 'expand'"):
            validate_args(cmd, {**args, "expand": ["capabilities"]})


def _engine(registry: Registry, role: dict[str, Any]) -> Engine:
    policy = build_policy({"version": 1, "roles": {"r": {"groups": [G1], **role}}}, registry)
    scopes = frozenset(
        s
        for d in registry.domains.values()
        for c in d.commands.values()
        for ss in c.scope_sets
        for s in ss
    )
    return Engine(policy, registry, scopes)


WHO = Principal(uid="00u1example000000000", sub="user@example.com", groups=frozenset({G1}))


def test_os_account_expand_raises_to_sensitive(registry: Registry) -> None:
    wildcard = _engine(registry, {"allow": {d: ["*"] for d in DOMAINS}})
    named = _engine(registry, {"allow": {"devices": list(OS_ACCOUNTS)}})
    opened = _engine(registry, {"allow": {"devices": ["*"]}, "include_sensitive": ["devices"]})
    for name in OS_ACCOUNTS:
        args: dict[str, Any] = {"device": DEVICE}
        if name == "get-os-account":
            args["account"] = ACCOUNT
        assert wildcard.check(WHO, "devices", name, args) is Verdict.ALLOWED, name
        # Any value, `users` included: the rule reads the argument's presence.
        for expand in (["users"], ["account_linked_enrollments", "offlineFactors"]):
            call = {**args, "expand": expand}
            assert wildcard.check(WHO, "devices", name, call) is Verdict.FORBIDDEN, name
            assert named.check(WHO, "devices", name, call) is Verdict.ALLOWED, name
            assert opened.check(WHO, "devices", name, call) is Verdict.ALLOWED, name


def test_wildcards_reach_every_command_without_expand(registry: Registry) -> None:
    e = _engine(registry, {"allow": {d: ["*"] for d in DOMAINS}})
    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            assert e.check(WHO, domain, cmd.name, {}) is not Verdict.FORBIDDEN, (domain, cmd.name)
    assert e.check(WHO, "devices", "list", {"expand": "user"}) is Verdict.ALLOWED
    # A device search needs `search_attributes`, whatever the allow.
    search = {"search": 'profile.serialNumber co "C02"'}
    assert e.check(WHO, "devices", "list", search) is Verdict.FORBIDDEN
    searcher = _engine(
        registry, {"allow": {"devices": ["list"]}, "search_attributes": ["profile.serialNumber"]}
    )
    assert searcher.check(WHO, "devices", "list", search) is Verdict.ALLOWED
    assert (
        searcher.check(WHO, "devices", "list", {"search": 'profile.sid co "S-1"'})
        is Verdict.FORBIDDEN
    )
