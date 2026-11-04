"""The packaged pilot registries (plan step 1.6): network-zones and groups."""

import pytest

from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.schema import InvalidArguments, validate_args
from okta_mcp.registry.spec import load_spec

PILOTS = ("groups", "network-zones")
# Path values §6.4 rejects; every pilot path param has an ID pattern, so the schema does too.
BAD_PATH_VALUES = [
    "",
    "..",
    "../x",
    "a/b",
    "a%2F..%2Fb",
    "a?b=c",
    "a#b",
    "a b",
    "a\x00b",
    "00g1emaKYZTWRYYRRTSK\n",
    "A" * 10_000,
]


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(load_spec())


def test_pilot_domains_cover_the_catalogue(registry: Registry) -> None:
    # Catalogue `groups search` is `list` with `q` (T1 D3).
    assert set(registry.domains["network-zones"].commands) == {"list", "get"}
    assert set(registry.domains["groups"].commands) == {
        "list",
        "get",
        "get-members",
        "get-apps",
        "get-owners",
        "list-rules",
        "get-rule",
        "list-roles",
        "get-role",
        "list-role-app-targets",
        "list-role-group-targets",
    }
    assert "q" in registry.domains["groups"].commands["list"].schema["properties"]


def test_every_pilot_path_param_has_a_pattern(registry: Registry) -> None:
    for domain in PILOTS:
        for cmd in registry.domains[domain].commands.values():
            for name, arg in cmd.entry.args.items():
                if arg.path_param is not None:
                    assert arg.pattern, f"{domain} {cmd.name}: {name}"


def test_sensitivity(registry: Registry) -> None:
    sensitive = {
        (d, c.name)
        for d in PILOTS
        for c in registry.domains[d].commands.values()
        if c.sensitivity == "sensitive"
    }
    assert sensitive == {
        ("groups", "list-roles"),
        ("groups", "get-role"),
        ("groups", "list-role-app-targets"),
        ("groups", "list-role-group-targets"),
    }


def test_free_form_args_raise_sensitivity(registry: Registry) -> None:
    for domain in PILOTS:
        for cmd in registry.domains[domain].commands.values():
            for arg in cmd.entry.args.values():
                if arg.param in ("filter", "search", "q"):
                    assert arg.arg_rule is not None
                    assert arg.arg_rule.raises_sensitivity_to == "sensitive"


def test_group_stats_expand_raises_sensitivity(registry: Registry) -> None:
    # `stats` carries `hasAdminPrivlege`, which the admin-roles commands keep sensitive.
    rule = registry.domains["groups"].commands["list"].entry.args["expand"].arg_rule
    assert rule is not None and rule.raises_sensitivity_to == "sensitive"


def test_spec_example_ids_pass(registry: Registry) -> None:
    groups = registry.domains["groups"].commands
    validate_args(
        registry.domains["network-zones"].commands["get"], {"zone": "nzowc1U5Jh5xuAK0o0g3"}
    )
    validate_args(groups["get"], {"group": "00g1emaKYZTWRYYRRTSK"})
    validate_args(groups["get-rule"], {"rule": "0pr3f7zMZZHPgUoWO0g4"})
    for role in ("JBCUYUC7IRCVGS27IFCE2SKO", "irb1qe6PGuMc7Oh8N0g4", "ra125eqBFpETrMwu80g4"):
        validate_args(groups["get-role"], {"group": "00g1emaKYZTWRYYRRTSK", "role": role})


@pytest.mark.parametrize(
    ("command", "arg", "value"),
    [
        ("get", "group", "Everyone"),
        ("get", "group", "00u1emaKYZTWRYYRRTSK"),
        ("get-rule", "rule", "00g1emaKYZTWRYYRRTSK"),
    ],
)
def test_wrong_id_kind_is_rejected(registry: Registry, command: str, arg: str, value: str) -> None:
    with pytest.raises(InvalidArguments, match=f"arg '{arg}' must match"):
        validate_args(registry.domains["groups"].commands[command], {arg: value})


@pytest.mark.parametrize("value", BAD_PATH_VALUES)
def test_path_injection_values_fail_validation(registry: Registry, value: str) -> None:
    group = "00g1emaKYZTWRYYRRTSK"
    for domain in PILOTS:
        for cmd in registry.domains[domain].commands.values():
            path_args = [n for n, a in cmd.entry.args.items() if a.path_param is not None]
            for name in path_args:
                args = {n: group if n == "group" else "JBCUYUC7IRCVGS27IFCE2SKO" for n in path_args}
                args[name] = value
                with pytest.raises(InvalidArguments, match=f"arg '{name}'"):
                    validate_args(cmd, args)


def test_expand_values_are_closed(registry: Registry) -> None:
    lst = registry.domains["groups"].commands["list"]
    validate_args(lst, {"expand": "stats"})
    with pytest.raises(InvalidArguments, match="must be one of: stats, app"):
        validate_args(lst, {"expand": "stats,app"})


def test_schema_snapshots(registry: Registry) -> None:
    groups = registry.domains["groups"].commands
    assert groups["get-members"].schema == {
        "type": "object",
        "properties": {
            "group": {"type": "string", "pattern": "^00g[A-Za-z0-9]{17}$"},
            "search": {"type": "string"},
            "expand": {"type": "string", "enum": ["group-rules", "login-status-info"]},
        },
        "additionalProperties": False,
        "required": ["group"],
    }
    assert groups["list-role-app-targets"].synopsis == "list-role-app-targets <group> <role>"
    assert groups["list"].synopsis == "list [options]"
